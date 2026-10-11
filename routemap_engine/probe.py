"""
The engine's own ICMP traceroute: the same probes, timing and output on
Windows, macOS and Linux, with no administrator rights.

WHY
---
The system tools differ in ways a map shows. Windows ``tracert`` probes with
ICMP and prints one address per hop, so a hop that answered from several
routers (ECMP) looks like one router. macOS and Linux ``traceroute`` default to
UDP probes, which many destinations ignore, and print every responder. The
same trace looked different on each platform (4 Oct 2026, orf.at on ODIN and a
Mac). This module sends the same ICMP echo probes everywhere: 30 hops, three
probes per hop, one second per reply, and records every responder.

HOW, PER PLATFORM
-----------------
* Windows: ``IcmpSendEcho`` (IPv4) and ``Icmp6SendEcho2`` (IPv6) from
  iphlpapi.dll, the API ``tracert`` itself uses, with the TTL or hop limit
  set per probe. No raw socket, no administrator rights.
* macOS: an unprivileged ICMP datagram socket (``SOCK_DGRAM``,
  ``IPPROTO_ICMP``; for IPv6 ``AF_INET6``, ``IPPROTO_ICMPV6``, which icmp6(4)
  allows "to receive time exceeded message for traceroute"). The kernel
  delivers echo replies and the routers' time exceeded messages to it.
* Linux: the same socket types, allowed when ``net.ipv4.ping_group_range``
  includes the user's group (the default on most desktop distributions, off
  on some servers; the same range governs ICMPv6 ping sockets,
  net/ipv4/ping.c ``ping_init_sock``). Routers' messages arrive on the
  socket's error queue (``IP_RECVERR``, ``IPV6_RECVERR``). When the range
  excludes the user, :func:`available` says why and the caller falls back to
  the system ``traceroute`` (UDP).

IPv6 (0.7.0): ICMPv6 echo request 128 and reply 129, time exceeded 3,
destination unreachable 1 (RFC 4443); the hop limit is IPV6_UNICAST_HOPS.

PATH DISCOVERY (0.7.0)
----------------------
:class:`FlowTransport` sends Paris-style probes for :mod:`multipath`. Every
probe of one flow carries the same identifier and the same checksum, while
the sequence number still names the probe: two payload bytes are set so the
checksum comes out at the flow's value (Augustin et al., IMC 2006, "Paris
traceroute"). Different flows differ in identifier and checksum, the fields
per-flow load balancers hash for ICMP. Measured on macOS 27 (10 Oct 2026):
the identifier, sequence and checksum set here arrive unchanged in routers'
time exceeded quotes. Linux sets the identifier itself (the socket's bound
"port") and computes the checksum over what it sends, so the payload is
computed for the identifier the kernel uses. Windows' ICMP API sets the
identifier and sequence itself and has no parameter for either, so it cannot
hold a flow; :func:`flow_available` says so.

OUTPUT
------
The text the BSD and Linux tools print with ``-n``, which the parser reads:

    traceroute to orf.at (194.232.104.139), 30 hops max, 40 byte packets
     1  192.0.2.1  3.512 ms  3.120 ms  3.301 ms
     7  62.115.186.138  61.913 ms
        62.115.112.222  62.004 ms  61.877 ms

A probe with no answer is ``*``. A responder different from the previous one
in the same hop starts a continuation line, as ECMP hops do in BSD output.
The trace stops after the hop in which the target answered.
"""
from __future__ import annotations

import errno
import ipaddress
import os
import secrets
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

MAX_HOPS = 30
QUERIES = 3
WAIT_SECONDS = 1.0
# Bounds for the -m, -q and -w values a caller or a setting asks for (RM-12):
# IP's TTL ceiling, and as many probes and seconds as any real use needs.
MAX_TTL = 255
MAX_QUERIES = 10
MAX_WAIT_SECONDS = 10.0
PAYLOAD = b"routemap-engine-probe" + b"\0" * 11      # 32 bytes, like tracert
FAMILIES = ("auto", "4", "6")
TOOL_NAME = "icmp"
# Ends the header line so the parser can name the tool (parse.PARSER_LABELS).
HEADER_MARK = "ICMP echo, routemap-engine built-in prober"


@dataclass
class Reply:
    address: str | None          # None: no answer within the wait
    rtt_ms: float | None
    reached: bool = False        # an echo reply from the target itself


class NoAddress(ValueError):
    """The target has no address in the family asked for."""


class NoRoute(NoAddress):
    """This machine has no route to the target's address family (typically:
    no IPv6 on this network). A NoAddress, so every caller that says "no
    address in that family" says this too."""


def check_route(dst: str) -> None:
    """Raise :class:`NoRoute` when the system has no route to *dst*: asked
    once, before the first probe, so a trace says why instead of failing on
    every probe. A UDP socket's connect picks the route and sends nothing."""
    try:
        _source_for(dst)
    except OSError as exc:
        raise NoRoute(f"This machine has no IPv{family_of(dst)} route to {dst} "
                      f"({exc.strerror or exc}). Is IPv{family_of(dst)} working on this network?") from None


def resolve(target: str, family: str = "auto") -> str:
    """The address to trace for *target*: the system's first choice
    (getaddrinfo order) for "auto", else the first address of family "4"
    or "6". Raises :class:`NoAddress` when there is none."""
    af = {"4": socket.AF_INET, "6": socket.AF_INET6}.get(str(family), socket.AF_UNSPEC)
    try:
        infos = socket.getaddrinfo(target, None, af, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        if af == socket.AF_UNSPEC:
            raise
        raise NoAddress(f"{target} has no IPv{family} address") from exc
    for fam, _t, _p, _c, sockaddr in infos:
        if fam in (socket.AF_INET, socket.AF_INET6):
            return str(ipaddress.ip_address(sockaddr[0].split("%")[0]))
    raise NoAddress(f"{target} has no IPv{family} address" if af != socket.AF_UNSPEC
                    else f"{target} has no address")


def family_of(addr: str) -> int:
    return 6 if ":" in addr else 4


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _pseudo(src: str, dst: str, length: int) -> bytes:
    """The IPv6 pseudo-header the ICMPv6 checksum covers (RFC 4443 2.3)."""
    return (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
            + struct.pack("!I3xB", length, 58))


def _echo(ident: int, seq: int, *, af: int = 4, payload: bytes = PAYLOAD, src: str | None = None,
          dst: str | None = None) -> bytes:
    kind = 128 if af == 6 else 8
    header = struct.pack("!BBHHH", kind, 0, 0, ident, seq)
    pseudo = _pseudo(src, dst, 8 + len(payload)) if af == 6 and src and dst else b""
    return struct.pack("!BBHHH", kind, 0, _checksum(pseudo + header + payload), ident, seq) + payload


def paris_payload(ident: int, seq: int, checksum: int, *, af: int = 4, src: str | None = None,
                  dst: str | None = None, tail: bytes = PAYLOAD[2:]) -> bytes:
    """A payload that makes an echo request with this identifier and sequence
    number carry *checksum*: two adjustable bytes, then *tail*. For IPv6 the
    checksum covers the pseudo-header, so *src* and *dst* are needed."""
    kind = 128 if af == 6 else 8
    pseudo = _pseudo(src, dst, 8 + 2 + len(tail)) if af == 6 else b""
    base = pseudo + struct.pack("!BBHHH", kind, 0, 0, ident, seq) + b"\0\0" + tail
    s0 = ~_checksum(base) & 0xFFFF            # the one's complement sum without the adjustment
    want = ~checksum & 0xFFFF
    adj = (want - s0) % 0xFFFF
    payload = struct.pack("!H", adj) + tail
    if _checksum(pseudo + struct.pack("!BBHHH", kind, 0, 0, ident, seq) + payload) != checksum:
        raise ValueError(f"no payload gives checksum {checksum:#06x}")   # only 0x0000 and 0xffff
    return payload


def _match_reply(raw: bytes, source: str, dst: str, seq: int) -> tuple[bool, bool]:
    """(accept, reached) for one ICMP or ICMPv6 message read from the socket (RM-10).

    The socket also sees replies meant for other programs and anything another
    host chooses to send, so a message counts only when it answers this probe:
    an echo reply from the target with this probe's sequence number, or an
    error that quotes at least 8 bytes of an echo request to the target with
    this sequence number. The identifier is not compared: Linux rewrites it."""
    source = source.split("%")[0]
    if family_of(dst) == 6:
        return _match_reply6(raw, source, dst, seq)
    # macOS includes the IP header; Linux gives the ICMP message alone.
    off = (raw[0] & 0x0F) * 4 if raw and raw[0] >> 4 == 4 else 0
    if len(raw) < off + 8:
        return False, False
    icmp_type = raw[off]
    if icmp_type == 0:                                   # echo reply: the target
        ok = source == dst and struct.unpack("!H", raw[off + 6:off + 8])[0] == seq
        return ok, ok
    if icmp_type in (11, 3):                             # time exceeded, unreachable
        inner = raw[off + 8:]
        if not inner or inner[0] >> 4 != 4:
            return False, False
        ihl = (inner[0] & 0x0F) * 4
        if ihl < 20 or len(inner) < ihl + 8:
            return False, False
        if inner[16:20] != socket.inet_aton(dst):        # quoted destination
            return False, False
        quoted = inner[ihl:ihl + 8]
        if quoted[0] != 8 or struct.unpack("!H", quoted[6:8])[0] != seq:
            return False, False
        return True, icmp_type == 3 and source == dst
    return False, False


def _match_reply6(raw: bytes, source: str, dst: str, seq: int) -> tuple[bool, bool]:
    """The same for ICMPv6 (RFC 4443): echo reply 129, time exceeded 3,
    destination unreachable 1. A socket gets the ICMPv6 message without the
    IPv6 header; an error quotes the 40-byte IPv6 header of the probe."""
    if len(raw) < 8:
        return False, False
    icmp_type = raw[0]
    if icmp_type == 129:
        ok = (ipaddress.ip_address(source) == ipaddress.ip_address(dst)
              and struct.unpack("!H", raw[6:8])[0] == seq)
        return ok, ok
    if icmp_type in (3, 1):
        inner = raw[8:]
        if len(inner) < 40 + 8 or inner[0] >> 4 != 6 or inner[6] != 58:
            return False, False
        if inner[24:40] != socket.inet_pton(socket.AF_INET6, dst):
            return False, False
        quoted = inner[40:48]
        if quoted[0] != 128 or struct.unpack("!H", quoted[6:8])[0] != seq:
            return False, False
        reached = icmp_type == 1 and ipaddress.ip_address(source) == ipaddress.ip_address(dst)
        return True, reached
    return False, False


# ------------------------------------------------------------------ POSIX ---

IP_RECVERR = 11
IPV6_RECVERR = 25
MSG_ERRQUEUE = 0x2000
SO_EE_ORIGIN_ICMP = 2
SO_EE_ORIGIN_ICMP6 = 3


def _icmp_socket(af: int) -> socket.socket:
    if af == 6:
        return socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)


def _set_hops(sock: socket.socket, af: int, ttl: int):
    if af == 6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
    else:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)


def _source_for(dst: str) -> str:
    """The source address the system would use for *dst*: a UDP socket's
    connect picks the route and sends nothing."""
    af = family_of(dst)
    with socket.socket(socket.AF_INET6 if af == 6 else socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.connect((dst, 9))
        return udp.getsockname()[0].split("%")[0]


def _read_errqueue(sock: socket.socket, af: int) -> tuple[bytes, str | None]:
    """Linux: (the probe the error is about, the router that sent it)."""
    try:
        sent, ancdata, _, _ = sock.recvmsg(512, 512, MSG_ERRQUEUE)
    except (BlockingIOError, OSError):
        return b"", None
    for level, kind, data in ancdata:
        if af == 4 and level == socket.IPPROTO_IP and kind == IP_RECVERR and len(data) >= 16 + 8:
            if struct.unpack("=IBBB", data[:7])[1] == SO_EE_ORIGIN_ICMP:
                return sent, socket.inet_ntoa(data[16 + 4:16 + 8])
        if af == 6 and level == socket.IPPROTO_IPV6 and kind == IPV6_RECVERR and len(data) >= 16 + 24:
            if struct.unpack("=IBBB", data[:7])[1] == SO_EE_ORIGIN_ICMP6:
                return sent, str(ipaddress.IPv6Address(data[16 + 8:16 + 24]))
    return sent, None


def _posix_probe(dst: str, ttl: int, seq: int, wait: float) -> Reply:
    af = family_of(dst)
    sock = _icmp_socket(af)
    try:
        _set_hops(sock, af, ttl)
        linux = sys.platform.startswith("linux")
        if linux:
            if af == 6:
                sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVERR, 1)
            else:
                sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
        ident = os.getpid() & 0xFFFF
        src = _source_for(dst) if af == 6 else None
        sock.setblocking(False)
        start = time.perf_counter()
        sock.sendto(_echo(ident, seq, af=af, src=src, dst=dst), (dst, 0))
        deadline = start + wait
        import select
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                return Reply(None, None)
            readable, _, errored = select.select([sock], [], [sock], left)
            if not readable and not errored:
                continue
            if linux:
                sent, offender = _read_errqueue(sock, af)
                # The kernel returns the request the error is about: only ours counts.
                if offender and len(sent) >= 8 and struct.unpack("!H", sent[6:8])[0] == seq:
                    return Reply(offender, (time.perf_counter() - start) * 1000)
            try:
                raw, addr = sock.recvfrom(2048)
            except (BlockingIOError, OSError):
                continue
            rtt = (time.perf_counter() - start) * 1000
            accept, reached = _match_reply(raw, addr[0], dst, seq)
            if accept:
                return Reply(addr[0].split("%")[0], rtt, reached=reached)
    finally:
        sock.close()


def _posix_available(af: int = 4) -> tuple[bool, str]:
    try:
        sock = _icmp_socket(af)
        sock.close()
        return True, ""
    except PermissionError:
        rng = ""
        try:
            with open("/proc/sys/net/ipv4/ping_group_range", encoding="ascii") as handle:
                rng = handle.read().strip()
        except OSError:
            pass
        return False, ("this system does not allow unprivileged ICMP sockets"
                       + (f" (net.ipv4.ping_group_range is {rng})" if rng else ""))
    except OSError as exc:
        return False, f"ICMP sockets are not available ({exc.strerror or exc})"


# ---------------------------------------------------------------- Windows ---

IP_SUCCESS = 0
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_DEST_PROT_UNREACHABLE = 11004
IP_DEST_PORT_UNREACHABLE = 11005
IP_REQ_TIMED_OUT = 11010
IP_TTL_EXPIRED_TRANSIT = 11013


def _windows_api():
    import ctypes
    from ctypes import wintypes

    class IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                    ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

    class ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_ulong),
                    ("RoundTripTime", ctypes.c_ulong), ("DataSize", ctypes.c_ushort),
                    ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                    ("Options", IP_OPTION_INFORMATION)]

    # System32 only: the default search would take a copy from the app folder first.
    lib = ctypes.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x800)  # LOAD_LIBRARY_SEARCH_SYSTEM32
    lib.IcmpCreateFile.restype = wintypes.HANDLE
    lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_uint32, ctypes.c_void_p, wintypes.WORD,
                                 ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p, wintypes.DWORD,
                                 wintypes.DWORD]
    lib.IcmpSendEcho.restype = wintypes.DWORD
    lib.Icmp6CreateFile.restype = wintypes.HANDLE
    lib.Icmp6SendEcho2.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.WORD,
                                   ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p, wintypes.DWORD,
                                   wintypes.DWORD]
    lib.Icmp6SendEcho2.restype = wintypes.DWORD
    return ctypes, lib, IP_OPTION_INFORMATION, ICMP_ECHO_REPLY


def _sockaddr_in6(addr: str) -> bytes:
    """struct sockaddr_in6 (28 bytes): family, port, flowinfo, address, scope."""
    return struct.pack("<HHI", socket.AF_INET6, 0, 0) + socket.inet_pton(socket.AF_INET6, addr) + b"\0" * 4


def _windows_status(status: int, address: str, dst: str, rtt: float) -> Reply:
    if status == IP_SUCCESS:
        return Reply(address, rtt, reached=True)
    if status == IP_TTL_EXPIRED_TRANSIT:                 # IP_HOP_LIMIT_EXCEEDED for IPv6: the same code
        return Reply(address, rtt)
    if status in (IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PROT_UNREACHABLE,
                  IP_DEST_PORT_UNREACHABLE):
        return Reply(address, rtt, reached=ipaddress.ip_address(address) == ipaddress.ip_address(dst))
    return Reply(None, None)


def _windows_probe(dst: str, ttl: int, seq: int, wait: float) -> Reply:
    if family_of(dst) == 6:
        return _windows_probe6(dst, ttl, wait)
    ctypes, lib, Options, EchoReply = _windows_api()
    handle = lib.IcmpCreateFile()
    try:
        options = Options(Ttl=ttl)
        request = ctypes.create_string_buffer(PAYLOAD, len(PAYLOAD))
        size = ctypes.sizeof(EchoReply) + len(PAYLOAD) + 8 + 64
        reply = ctypes.create_string_buffer(size)
        dest = struct.unpack("<I", socket.inet_aton(dst))[0]
        start = time.perf_counter()
        count = lib.IcmpSendEcho(handle, dest, request, len(PAYLOAD), ctypes.byref(options), reply, size,
                                 int(wait * 1000))
        # The same high-resolution clock as the POSIX probes. RoundTripTime is
        # whole milliseconds and was used at 10 ms and above, so every hop
        # past the access network read 26.000, 252.000 (ODIN, 4 Oct 2026).
        elapsed = (time.perf_counter() - start) * 1000
        if count == 0:
            return Reply(None, None)
        echo = EchoReply.from_buffer_copy(reply.raw[:ctypes.sizeof(EchoReply)])
        address = socket.inet_ntoa(struct.pack("<I", echo.Address))
        return _windows_status(echo.Status, address, dst, round(elapsed, 3))
    finally:
        lib.IcmpCloseHandle(handle)


# ICMPV6_ECHO_REPLY: IPV6_ADDRESS_EX (sin6_port USHORT, sin6_flowinfo ULONG,
# sin6_addr USHORT[8], sin6_scope_id ULONG; packed, ipexport.h pshpack1), then
# Status ULONG and RoundTripTime.
_V6_REPLY_ADDR = slice(6, 22)
_V6_REPLY_STATUS = slice(26, 30)
_V6_REPLY_SIZE = 34


def _windows_probe6(dst: str, ttl: int, wait: float) -> Reply:
    ctypes, lib, Options, _ = _windows_api()
    handle = lib.Icmp6CreateFile()
    try:
        options = Options(Ttl=ttl)
        request = ctypes.create_string_buffer(PAYLOAD, len(PAYLOAD))
        size = _V6_REPLY_SIZE + len(PAYLOAD) + 8 + 64
        reply = ctypes.create_string_buffer(size)
        src = ctypes.create_string_buffer(_sockaddr_in6(_source_for(dst)), 28)
        dest = ctypes.create_string_buffer(_sockaddr_in6(dst), 28)
        start = time.perf_counter()
        count = lib.Icmp6SendEcho2(handle, None, None, None, src, dest, request, len(PAYLOAD),
                                   ctypes.byref(options), reply, size, int(wait * 1000))
        elapsed = (time.perf_counter() - start) * 1000
        if count == 0:
            return Reply(None, None)
        raw = reply.raw
        address = str(ipaddress.IPv6Address(raw[_V6_REPLY_ADDR]))
        status = struct.unpack("<I", raw[_V6_REPLY_STATUS])[0]
        return _windows_status(status, address, dst, round(elapsed, 3))
    finally:
        lib.IcmpCloseHandle(handle)


def _windows_available(af: int = 4) -> tuple[bool, str]:
    try:
        _, lib, _, _ = _windows_api()
        handle = lib.Icmp6CreateFile() if af == 6 else lib.IcmpCreateFile()
        if not handle or handle == -1:
            return False, "Icmp6CreateFile failed" if af == 6 else "IcmpCreateFile failed"
        lib.IcmpCloseHandle(handle)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"the Windows ICMP API is not available ({exc})"


# ------------------------------------------------------------- path probes ---

@dataclass
class FlowAnswer:
    seq: int
    address: str
    reached: bool
    at: float                    # perf_counter() when read


def flow_checksum(flow: int) -> int:
    """The checksum flow *flow* carries: distinct per flow, never 0x0000 or 0xffff."""
    return 0x1000 + (flow * 0x0F1D) % 0xE000


WINDOWS_TCP_MIN_BUILD = 19041          # Windows 10 2004: TCP_FAIL_CONNECT_ON_ICMP_ERROR


def flow_available() -> tuple[bool, str]:
    """(usable, reason when not) for Paris-style path probes on this system:
    ICMP on macOS and Linux (:class:`FlowTransport`), TCP on Windows
    (:class:`TcpFlowTransport`, Windows 10 2004 or later)."""
    if sys.platform.startswith("win"):
        build = getattr(sys.getwindowsversion(), "build", 0) if hasattr(sys, "getwindowsversion") else 0
        if build < WINDOWS_TCP_MIN_BUILD:
            return False, (f"path discovery on Windows needs Windows 10 version 2004 or later "
                           f"(this is build {build})")
        return True, ""
    return _posix_available()


def flow_method() -> str:
    """The probe method path discovery uses on this system."""
    return TcpFlowTransport.METHOD if sys.platform.startswith("win") else FlowTransport.METHOD


# ------------------------------------------------- path probes, Windows TCP ---

TCP_FLOW_PORT = 443
# ws2ipdef.h. TCP_FAIL_CONNECT_ON_ICMP_ERROR makes connect fail on an ICMP
# error, and TCP_ICMP_ERROR_INFO then names the router that sent it
# (learn.microsoft.com, IPPROTO_TCP socket options; ICMP_ERROR_INFO,
# Windows 10 2004 or later). TCP_NOSYNRETRIES: one SYN per probe.
TCP_NOSYNRETRIES = 9
TCP_FAIL_CONNECT_ON_ICMP_ERROR = 18
TCP_ICMP_ERROR_INFO = 19
WSAEWOULDBLOCK, WSAECONNREFUSED, WSAEHOSTUNREACH = 10035, 10061, 10065


def parse_icmp_error_info(raw: bytes) -> tuple[str | None, int | None, int | None]:
    """(router address, ICMP type, ICMP code) from an ICMP_ERROR_INFO: a
    SOCKADDR_INET (28 bytes: family, then the IPv4 address at 4 or the IPv6
    address at 8), the protocol (4 bytes), the type and the code."""
    if not raw or len(raw) < 34:
        return None, None, None
    family = struct.unpack_from("<H", raw, 0)[0]
    if family == 2:
        address = socket.inet_ntoa(raw[4:8])
    elif family == 23:
        address = str(ipaddress.IPv6Address(raw[8:24]))
    else:
        return None, None, None
    return address, raw[32], raw[33]


class TcpFlowTransport:
    """Paris-style path probes on Windows, without administrator rights: a
    TCP connect per probe, the TTL set, the source port as the flow (a flow
    keeps its five-tuple; the TCP sequence number, which balancers do not
    hash, is Windows' own), no SYN retries. A router's time exceeded fails the
    connect and TCP_ICMP_ERROR_INFO names the router; the target answers with
    a connection or a refusal, either of which means reached (the connection
    is reset at once). Windows' ICMP API cannot do this: it sends identifier
    1 and a system-wide sequence number, so every probe is a different flow
    (measured, windows-2025, run 38033956629). This method passed on a real
    Windows 11 network (build 26200, 11 Oct 2026): 12 hops answered, and two
    source ports split at a per-flow balancer at hop 5.

    Probes and paths found over TCP can differ from ICMP ones: balancers
    spread TCP by its ports, and some routers answer TCP probes from
    another interface. Every result carries its method ("tcp-paris")."""

    METHOD = "tcp-paris"

    def __init__(self, dst: str, port: int = TCP_FLOW_PORT, *, socket_factory=None, clock=time.perf_counter,
                 select=None, expire_after: float = 3.0, source_for=None, windows: bool | None = None):
        import select as _select
        self.dst, self.port = dst, port
        self.af = family_of(dst)
        # Bound to the address the system routes *dst* from, never to every
        # interface: a probe must not leave from another adapter (a VPN or a
        # tailnet on a multi-homed machine).
        self.src = (source_for or _source_for)(dst)
        self.windows = sys.platform.startswith("win") if windows is None else windows
        self._socket = socket_factory or socket.socket
        self._clock = clock
        self._select = select or _select.select
        self._expire = expire_after
        self._base = 40000 + secrets.randbelow(10000)
        self._open: dict[int, tuple] = {}        # seq -> (socket, flow, sent at)
        self._kept: list[FlowAnswer] = []        # answers read while a flow was freed

    def sport(self, flow: int) -> int:
        return self._base + flow

    def send(self, flow: int, ttl: int, seq: int):
        # A five-tuple carries one connection at a time: a flow's earlier
        # probe is answered or expired before the next one goes out.
        while any(f == flow for _s, f, _t in self._open.values()):
            self._kept.extend(self._poll(0.05))
        v6 = self.af == 6
        sock = self._socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.src, self.sport(flow)))
            if v6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
            else:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            for name, value in self._tcp_options():
                sock.setsockopt(socket.IPPROTO_TCP, name, value)
            sock.setblocking(False)
            started = sock.connect_ex((self.dst, self.port))
            if started not in (0, WSAEWOULDBLOCK, errno.EINPROGRESS, errno.EWOULDBLOCK):
                raise OSError(started, "connect refused locally")
        except OSError:
            self._drop(sock)
            return
        self._open[seq] = (sock, flow, self._clock())

    def _tcp_options(self) -> tuple[tuple[int, int], ...]:
        """Windows: one SYN, and a router's ICMP error fails the connect.
        Elsewhere (the Linux lab that tests this class) one SYN only: there the
        option numbers above mean other things."""
        if self.windows:
            return ((TCP_NOSYNRETRIES, 1), (TCP_FAIL_CONNECT_ON_ICMP_ERROR, 1))
        syncnt = getattr(socket, "TCP_SYNCNT", None)
        return ((syncnt, 1),) if syncnt is not None else ()

    def _drop(self, sock):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def read(self, timeout: float) -> list[FlowAnswer]:
        if self._kept:
            out, self._kept = self._kept, []
            return out + self._poll(0.0)
        return self._poll(timeout)

    def _poll(self, timeout: float) -> list[FlowAnswer]:
        if not self._open:
            time.sleep(max(0.0, min(timeout, 0.05)))
            return []
        by_sock = {entry[0]: seq for seq, entry in self._open.items()}
        _, writable, failed = self._select([], list(by_sock), list(by_sock), max(0.0, timeout))
        now = self._clock()
        out: list[FlowAnswer] = []
        for sock in set(writable) | set(failed):
            seq = by_sock[sock]
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err in (0, WSAECONNREFUSED, errno.ECONNREFUSED):
                out.append(FlowAnswer(seq, self.dst, True, now))
            elif self.windows:
                try:
                    address, _kind, _code = parse_icmp_error_info(
                        sock.getsockopt(socket.IPPROTO_TCP, TCP_ICMP_ERROR_INFO, 64))
                except OSError:
                    address = None
                if address:
                    reached = ipaddress.ip_address(address) == ipaddress.ip_address(self.dst)
                    out.append(FlowAnswer(seq, address, reached, now))
            self._drop(sock)
            self._open.pop(seq, None)
        for seq, (sock, _flow, sent) in list(self._open.items()):
            if now - sent > self._expire:
                self._drop(sock)
                self._open.pop(seq, None)
        return out

    def close(self):
        for sock, _flow, _sent in self._open.values():
            self._drop(sock)
        self._open.clear()


class FlowTransport:
    """Paris-style probes for path discovery on macOS and Linux (see the module
    docstring). :meth:`send` sends one probe of flow *flow* at *ttl*;
    :meth:`read` returns the answers that have arrived, matched by sequence
    number. One socket per flow on Linux (the kernel's identifier is the
    socket's), one socket for all flows on macOS (the identifier is ours)."""

    METHOD = "icmp-paris"

    def __init__(self, dst: str):
        self.dst = dst
        self.af = family_of(dst)
        self.linux = sys.platform.startswith("linux")
        self.src = _source_for(dst) if self.af == 6 else None
        self._socks: dict[int, socket.socket] = {}
        self._idents: dict[int, int] = {}
        self._base = secrets.randbelow(0x8000)
        self._shared: socket.socket | None = None

    def _sock(self, flow: int) -> socket.socket:
        if not self.linux:
            if self._shared is None:
                self._shared = _icmp_socket(self.af)
                self._shared.setblocking(False)
            self._idents.setdefault(flow, (self._base + flow) & 0xFFFF)
            return self._shared
        sock = self._socks.get(flow)
        if sock is None:
            sock = _icmp_socket(self.af)
            if self.af == 6:
                sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVERR, 1)
                sock.bind(("::", 0))
            else:
                sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
                sock.bind(("0.0.0.0", 0))
            sock.setblocking(False)
            self._socks[flow] = sock
            self._idents[flow] = sock.getsockname()[1]
        return sock

    def ident(self, flow: int) -> int:
        self._sock(flow)
        return self._idents[flow]

    def packet(self, flow: int, seq: int) -> bytes:
        ident = self.ident(flow)
        payload = paris_payload(ident, seq, flow_checksum(flow), af=self.af, src=self.src, dst=self.dst)
        return _echo(ident, seq, af=self.af, payload=payload, src=self.src, dst=self.dst)

    def send(self, flow: int, ttl: int, seq: int):
        sock = self._sock(flow)
        _set_hops(sock, self.af, ttl)
        sock.sendto(self.packet(flow, seq), (self.dst, 0))

    def read(self, timeout: float) -> list[FlowAnswer]:
        import select
        socks = list(self._socks.values()) + ([self._shared] if self._shared else [])
        if not socks:
            return []
        readable, _, errored = select.select(socks, [], socks, max(0.0, timeout))
        now = time.perf_counter()
        out: list[FlowAnswer] = []
        for sock in set(readable) | set(errored):
            for _ in range(64):
                got = False
                if self.linux:
                    sent, offender = _read_errqueue(sock, self.af)
                    if offender and len(sent) >= 8:
                        out.append(FlowAnswer(struct.unpack("!H", sent[6:8])[0], offender, False, now))
                        got = True
                try:
                    raw, addr = sock.recvfrom(2048)
                except (BlockingIOError, OSError):
                    raw = None
                if raw:
                    got = True
                    seq = _answered_seq(raw, self.dst)
                    if seq is not None:
                        ok, reached = _match_reply(raw, addr[0], self.dst, seq)
                        if ok:
                            out.append(FlowAnswer(seq, addr[0].split("%")[0], reached, now))
                if not got:
                    break
        return out

    def close(self):
        for sock in list(self._socks.values()) + ([self._shared] if self._shared else []):
            sock.close()
        self._socks.clear()
        self._shared = None


def _answered_seq(raw: bytes, dst: str) -> int | None:
    """The sequence number a reply or an error answers, before matching it."""
    try:
        if family_of(dst) == 6:
            if raw[0] == 129:
                return struct.unpack("!H", raw[6:8])[0]
            return struct.unpack("!H", raw[8 + 40 + 6:8 + 40 + 8])[0]
        off = (raw[0] & 0x0F) * 4 if raw[0] >> 4 == 4 else 0
        if raw[off] == 0:
            return struct.unpack("!H", raw[off + 6:off + 8])[0]
        inner = raw[off + 8:]
        ihl = (inner[0] & 0x0F) * 4
        return struct.unpack("!H", inner[ihl + 6:ihl + 8])[0]
    except (IndexError, struct.error):
        return None


# ------------------------------------------------------------------ public ---

def available(family: int = 4) -> tuple[bool, str]:
    """(usable, reason when not) for the built-in ICMP prober on this system."""
    if sys.platform.startswith("win"):
        return _windows_available(family)
    return _posix_available(family)


def _probe(dst: str, ttl: int, seq: int, wait: float) -> Reply:
    if sys.platform.startswith("win"):
        return _windows_probe(dst, ttl, seq, wait)
    return _posix_probe(dst, ttl, seq, wait)


def format_hop(ttl: int, replies: list[Reply]) -> list[str]:
    """One hop as BSD traceroute -n prints it, with a continuation line for each
    change of responder (ECMP)."""
    lines: list[str] = []
    current = f"{ttl:>2} "
    last_addr: str | None = None
    started = False
    for reply in replies:
        if reply.address is None:
            current += " *"
            continue
        if reply.address != last_addr:
            if started and last_addr is not None:
                lines.append(current)
                current = "   "
            current += f" {reply.address}"
            last_addr = reply.address
        current += f"  {reply.rtt_ms:.3f} ms"
        started = True
    lines.append(current)
    return lines


def trace(target: str, *, max_hops: int = MAX_HOPS, queries: int = QUERIES, wait: float = WAIT_SECONDS,
          on_line: Callable[[str], None] | None = None, cancel: threading.Event | None = None,
          deadline: float | None = None, family: str = "auto") -> tuple[str, bool, bool]:
    """Trace *target* (a validated hostname or address) over IPv4 or IPv6
    (*family*: "auto", "4" or "6"). Returns (text, cancelled, timed_out)."""
    dst = resolve(target, family)
    check_route(dst)
    max_hops = max(1, min(int(max_hops), MAX_TTL))
    queries = max(1, min(int(queries), MAX_QUERIES))
    wait = max(0.1, min(float(wait), MAX_WAIT_SECONDS))
    out: list[str] = []

    def emit(line: str):
        out.append(line)
        if on_line is not None:
            try:
                on_line(line)
            except Exception:  # noqa: BLE001
                pass

    emit(f"traceroute to {target} ({dst}), {max_hops} hops max, {8 + len(PAYLOAD)} byte packets, {HEADER_MARK}"
         + (", IPv6" if family_of(dst) == 6 else ""))
    # A random start, so a reply cannot be guessed from the trace's position.
    seq = secrets.randbelow(0x10000)
    for ttl in range(1, max_hops + 1):
        if cancel is not None and cancel.is_set():
            return "\n".join(out) + "\n", True, False
        if deadline is not None and time.monotonic() > deadline:
            return "\n".join(out) + "\n", False, True
        replies = []
        for _ in range(queries):
            # Before every probe, not only every hop: Stop and the time limit
            # never wait for more than one probe.
            if cancel is not None and cancel.is_set():
                return "\n".join(out) + "\n", True, False
            if deadline is not None and time.monotonic() > deadline:
                return "\n".join(out) + "\n", False, True
            seq = (seq + 1) & 0xFFFF
            replies.append(_probe(dst, ttl, seq, wait))
        for line in format_hop(ttl, replies):
            emit(line)
        if any(r.reached for r in replies):
            break
    return "\n".join(out) + "\n", False, False
