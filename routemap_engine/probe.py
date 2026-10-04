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
* Windows: ``IcmpSendEcho`` from iphlpapi.dll, the API ``tracert`` itself
  uses, with the TTL set per probe. No raw socket, no administrator rights.
  IPv4 only; an IPv6 target falls back to ``tracert``.
* macOS: an unprivileged ICMP datagram socket (``SOCK_DGRAM``,
  ``IPPROTO_ICMP``). The kernel delivers echo replies and the routers' time
  exceeded messages to it.
* Linux: the same socket type, allowed when ``net.ipv4.ping_group_range``
  includes the user's group (the default on most desktop distributions, off
  on some servers). Routers' messages arrive on the socket's error queue
  (``IP_RECVERR``). When the range excludes the user, :func:`available` says
  why and the caller falls back to the system ``traceroute`` (UDP).

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

import ipaddress
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable

MAX_HOPS = 30
QUERIES = 3
WAIT_SECONDS = 1.0
PAYLOAD = b"routemap-engine-probe" + b"\0" * 11      # 32 bytes, like tracert
TOOL_NAME = "icmp"
# Ends the header line so the parser can name the tool (parse.PARSER_LABELS).
HEADER_MARK = "ICMP echo, routemap-engine built-in prober"


@dataclass
class Reply:
    address: str | None          # None: no answer within the wait
    rtt_ms: float | None
    reached: bool = False        # an echo reply from the target itself


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _echo(ident: int, seq: int) -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    return struct.pack("!BBHHH", 8, 0, _checksum(header + PAYLOAD), ident, seq) + PAYLOAD


# ------------------------------------------------------------------ POSIX ---

IP_RECVERR = 11
MSG_ERRQUEUE = 0x2000
SO_EE_ORIGIN_ICMP = 2


def _posix_probe(dst: str, ttl: int, seq: int, wait: float) -> Reply:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        linux = sys.platform.startswith("linux")
        if linux:
            sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
        ident = os.getpid() & 0xFFFF
        sock.setblocking(False)
        start = time.perf_counter()
        sock.sendto(_echo(ident, seq), (dst, 0))
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
                try:
                    _, ancdata, _, _ = sock.recvmsg(512, 512, MSG_ERRQUEUE)
                except BlockingIOError:
                    ancdata = []
                for level, kind, data in ancdata:
                    if level == socket.IPPROTO_IP and kind == IP_RECVERR and len(data) >= 16 + 8:
                        _errno, origin, icmp_type, _code = struct.unpack("=IBBB", data[:7])
                        if origin != SO_EE_ORIGIN_ICMP:
                            continue
                        offender = socket.inet_ntoa(data[16 + 4:16 + 8])
                        rtt = (time.perf_counter() - start) * 1000
                        return Reply(offender, rtt)
            try:
                raw, addr = sock.recvfrom(2048)
            except (BlockingIOError, OSError):
                continue
            rtt = (time.perf_counter() - start) * 1000
            # macOS includes the IP header; Linux gives the ICMP message alone.
            off = (raw[0] & 0x0F) * 4 if raw and raw[0] >> 4 == 4 else 0
            if len(raw) < off + 8:
                continue
            icmp_type = raw[off]
            if icmp_type == 0:                       # echo reply: the target
                return Reply(addr[0], rtt, reached=True)
            if icmp_type in (11, 3):                 # time exceeded, unreachable
                inner = raw[off + 8:]
                inner_off = (inner[0] & 0x0F) * 4 if inner and inner[0] >> 4 == 4 else 0
                quoted = inner[inner_off:inner_off + 8]
                if len(quoted) >= 8:
                    q_seq = struct.unpack("!H", quoted[6:8])[0]
                    if q_seq != seq:
                        continue                     # an earlier probe's late answer
                return Reply(addr[0], rtt, reached=icmp_type == 3 and addr[0] == dst)
    finally:
        sock.close()


def _posix_available() -> tuple[bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
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

    lib = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    lib.IcmpCreateFile.restype = wintypes.HANDLE
    lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_uint32, ctypes.c_void_p, wintypes.WORD,
                                 ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p, wintypes.DWORD,
                                 wintypes.DWORD]
    lib.IcmpSendEcho.restype = wintypes.DWORD
    return ctypes, lib, IP_OPTION_INFORMATION, ICMP_ECHO_REPLY


def _windows_probe(dst: str, ttl: int, seq: int, wait: float) -> Reply:
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
        rtt = round(elapsed, 3)
        if echo.Status == IP_SUCCESS:
            return Reply(address, rtt, reached=True)
        if echo.Status == IP_TTL_EXPIRED_TRANSIT:
            return Reply(address, rtt)
        if echo.Status in (IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PROT_UNREACHABLE,
                           IP_DEST_PORT_UNREACHABLE):
            return Reply(address, rtt, reached=address == dst)
        return Reply(None, None)
    finally:
        lib.IcmpCloseHandle(handle)


def _windows_available() -> tuple[bool, str]:
    try:
        _, lib, _, _ = _windows_api()
        handle = lib.IcmpCreateFile()
        if not handle or handle == -1:
            return False, "IcmpCreateFile failed"
        lib.IcmpCloseHandle(handle)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"the Windows ICMP API is not available ({exc})"


# ------------------------------------------------------------------ public ---

def available() -> tuple[bool, str]:
    """(usable, reason when not) for the built-in ICMP prober on this system."""
    if sys.platform.startswith("win"):
        return _windows_available()
    return _posix_available()


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
          deadline: float | None = None) -> tuple[str, bool, bool]:
    """Trace *target* (a validated hostname or address). Returns (text, cancelled,
    timed_out). IPv4 only; the caller handles IPv6 with the system tool."""
    dst = socket.gethostbyname(target)
    ipaddress.IPv4Address(dst)
    out: list[str] = []

    def emit(line: str):
        out.append(line)
        if on_line is not None:
            try:
                on_line(line)
            except Exception:  # noqa: BLE001
                pass

    emit(f"traceroute to {target} ({dst}), {max_hops} hops max, {8 + len(PAYLOAD)} byte packets, {HEADER_MARK}")
    seq = 0
    for ttl in range(1, max_hops + 1):
        if cancel is not None and cancel.is_set():
            return "\n".join(out) + "\n", True, False
        if deadline is not None and time.monotonic() > deadline:
            return "\n".join(out) + "\n", False, True
        replies = []
        for _ in range(queries):
            seq = (seq + 1) & 0xFFFF
            replies.append(_probe(dst, ttl, seq, wait))
        for line in format_hop(ttl, replies):
            emit(line)
        if any(r.reached for r in replies):
            break
    return "\n".join(out) + "\n", False, False
