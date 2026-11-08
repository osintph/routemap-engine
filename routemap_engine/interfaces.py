"""
This computer's network adapters, read from the operating system on every call.

WHY
---
Behind a VPN or a SASE client the route to a target goes through a tunnel
adapter, and what a trace measures is the path through it. Showing that needs
to know which adapter the route uses and what kind it is, and an interface
selector needs the list a user would see in Wireshark.

Everything here comes from what the OS reports at run time. There is no list
of products or adapter names: an adapter is labelled with the name its own
software registered, and classified from the OS's type fields only. Where
those give no clear answer it is "unclassified", never a guess.

HOW, PER PLATFORM (local OS calls only; nothing here touches the network)
-------------------------------------------------------------------------
* Windows: ``GetAdaptersAddresses`` (friendly name, description, index, type,
  tunnel type, state, addresses, gateways) and ``GetIfEntry2`` (the hardware
  interface flag). Tunnel when the type is tunnel, PPP or proprietary virtual,
  or a tunnel type is set; physical when the OS marks it as hardware and it is
  Ethernet, Wi-Fi or mobile.
* macOS: ``getifaddrs`` (addresses, flags), SystemConfiguration (display names
  and hardware types) and the ``NET_RT_DUMP`` routing table sysctl (gateways).
  Tunnel when point-to-point without a link address; physical when
  SystemConfiguration lists it as Ethernet, Wi-Fi or WWAN hardware.
* Linux: ``getifaddrs`` (addresses, flags), /sys/class/net (link type,
  ``tun_flags``, device type, the ``device`` link) and /proc/net/route and
  /proc/net/ipv6_route (gateways). Tunnel from the link type, ``tun_flags`` or
  the device type; physical when a ``device`` link exists.

BINDING (:class:`Binding`)
--------------------------
A probe leaves by the chosen adapter through the mechanism that forces egress,
not by its source address alone:

* Windows: ``IP_UNICAST_IF`` (index in network byte order) and
  ``IPV6_UNICAST_IF`` (host byte order) on sockets, per "IPPROTO_IP socket
  options" and "IPPROTO_IPV6 socket options". The ICMP API is not a socket:
  ``IcmpSendEcho2Ex`` and ``Icmp6SendEcho2`` take the source address, and the
  default strong host send model keeps a packet with that source on the
  adapter that owns it.
* macOS: ``IP_BOUND_IF`` (25) and ``IPV6_BOUND_IF`` (125), bsd/netinet/in.h
  and bsd/netinet6/in6.h in XNU.
* Linux: ``SO_BINDTODEVICE``, socket(7). Before kernel 5.7 it needs
  CAP_NET_RAW; without it :class:`NotForced` says the interface could not be
  forced, since a source address alone does not force egress there.

Privacy: adapter names, local addresses and gateways stay on this machine.
Log lines carry them only through ``logsafe.tag()``.
"""
from __future__ import annotations

import errno
import ipaddress
import logging
import os
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable

from routemap_engine.logsafe import tag

log = logging.getLogger("routemap_engine.interfaces")

PHYSICAL, TUNNEL, UNCLASSIFIED = "physical", "tunnel", "unclassified"
KINDS = (PHYSICAL, TUNNEL, UNCLASSIFIED)
# The hop-1 check after a run on a chosen adapter.
CONSISTENT, REDIRECTED, UNCONFIRMED, NO_ROUTE = "consistent", "redirected", "unconfirmed", "no_route"
CHECKS = (CONSISTENT, REDIRECTED, UNCONFIRMED, NO_ROUTE)

# ws2ipdef.h, the same number for both families.
IP_UNICAST_IF = IPV6_UNICAST_IF = 31
# bsd/netinet/in.h, bsd/netinet6/in6.h.
IP_BOUND_IF, IPV6_BOUND_IF = 25, 125
SO_BINDTODEVICE = 25                     # asm-generic/socket.h


class InterfaceError(ValueError):
    """The chosen adapter cannot be used: unknown, down, or no address of the
    family the target needs. ``str()`` says which, for the user."""


class NotForced(InterfaceError):
    """The system refused to force probes out of the chosen adapter. The run
    does not go ahead on the system route instead."""


@dataclass
class Adapter:
    id: str                 # what a setting stores: Windows' adapter GUID, the name elsewhere
    name: str               # the OS's own name: the friendly name, or en0, eth0
    description: str
    kind: str
    up: bool
    index: int
    index6: int = 0
    loopback: bool = False
    addresses: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)   # "192.0.2.10/24"
    gateways: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.name

    @property
    def selectable(self) -> bool:
        """Down and loopback adapters are listed but cannot carry a trace."""
        return self.up and not self.loopback


# ------------------------------------------------------------ classification ---

IF_TYPE_ETHERNET, IF_TYPE_PPP, IF_TYPE_LOOPBACK, IF_TYPE_PROP_VIRTUAL = 6, 23, 24, 53
IF_TYPE_IEEE80211, IF_TYPE_TUNNEL, IF_TYPE_WWANPP, IF_TYPE_WWANPP2 = 71, 131, 243, 244
_WIN_TUNNEL = (IF_TYPE_TUNNEL, IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL)
_WIN_PHYSICAL = (IF_TYPE_ETHERNET, IF_TYPE_IEEE80211, IF_TYPE_WWANPP, IF_TYPE_WWANPP2)


def classify_windows(if_type: int, tunnel_type: int, hardware: bool) -> str:
    if if_type in _WIN_TUNNEL or tunnel_type != 0:
        return TUNNEL
    if hardware and if_type in _WIN_PHYSICAL:
        return PHYSICAL
    return UNCLASSIFIED


_MAC_PHYSICAL = ("Ethernet", "IEEE80211", "WWAN")       # kSCNetworkInterfaceType*


def classify_macos(point_to_point: bool, has_link_address: bool, sc_type: str | None) -> str:
    if point_to_point and not has_link_address:
        return TUNNEL
    if sc_type in _MAC_PHYSICAL:
        return PHYSICAL
    return UNCLASSIFIED


# include/uapi/linux/if_arp.h: NONE (tun), PPP, TUNNEL (ipip), TUNNEL6, SIT, IPGRE, IP6GRE.
_ARPHRD_TUNNEL = (65534, 512, 768, 769, 776, 778, 823)
ARPHRD_LOOPBACK = 772


def classify_linux(arphrd: int, has_tun_flags: bool, devtype: str | None, has_device: bool) -> str:
    if arphrd in _ARPHRD_TUNNEL or has_tun_flags or devtype == "wireguard":
        return TUNNEL
    if has_device:
        return PHYSICAL
    return UNCLASSIFIED


# ---------------------------------------------------------------- getifaddrs ---

_IFF_UP, _IFF_LOOPBACK, _IFF_POINTOPOINT, _IFF_RUNNING = 0x1, 0x8, 0x10, 0x40
_AF_LINK = 18                            # macOS


def _prefix(mask: bytes) -> int:
    return sum(bin(b).count("1") for b in mask)


def _clean(addr: str) -> str:
    return addr.split("%")[0]


def _getifaddrs(bsd: bool, libc=None) -> dict[str, dict]:
    """Name -> {"flags", "link", "addresses", "networks"} from getifaddrs(3).
    A BSD sockaddr starts with a length byte and a family byte, Linux's with a
    native 16-bit family; the address is at 4 (IPv4) or 8 (IPv6) in both."""
    import ctypes

    class IfAddrs(ctypes.Structure):
        pass
    IfAddrs._fields_ = [("next", ctypes.POINTER(IfAddrs)), ("name", ctypes.c_char_p), ("flags", ctypes.c_uint),
                        ("addr", ctypes.c_void_p), ("netmask", ctypes.c_void_p), ("dst", ctypes.c_void_p),
                        ("data", ctypes.c_void_p)]
    lib = libc or ctypes.CDLL(None, use_errno=True)
    head = ctypes.POINTER(IfAddrs)()
    if lib.getifaddrs(ctypes.byref(head)) != 0:
        raise OSError(ctypes.get_errno(), "getifaddrs failed")
    out: dict[str, dict] = {}
    try:
        node = head
        while node:
            item = node.contents
            name = (item.name or b"").decode("utf-8", "replace")
            entry = out.setdefault(name, {"flags": 0, "link": False, "addresses": [], "networks": []})
            entry["flags"] |= item.flags
            if item.addr:
                family = ctypes.string_at(item.addr, 2)
                family = family[1] if bsd else struct.unpack("=H", family)[0]
                if family == socket.AF_INET:
                    addr = socket.inet_ntoa(ctypes.string_at(item.addr + 4, 4))
                    _add_address(entry, addr, _mask(item.netmask, 4, 4, bsd))
                elif family == socket.AF_INET6:
                    raw = ctypes.string_at(item.addr + 8, 16)
                    if raw[:2] == b"\xfe\x80":     # KAME embeds the scope in bytes 2 and 3
                        raw = raw[:2] + b"\0\0" + raw[4:]
                    _add_address(entry, str(ipaddress.IPv6Address(raw)), _mask(item.netmask, 8, 16, bsd))
                elif bsd and family == _AF_LINK:
                    entry["link"] = ctypes.string_at(item.addr, 8)[6] > 0     # sdl_alen
            node = item.next
    finally:
        lib.freeifaddrs(head)
    return out


def _mask(pointer, offset: int, size: int, bsd: bool) -> int | None:
    """The prefix length a netmask sockaddr holds. A BSD netmask may be cut
    short (its length byte counts only the bytes up to the last set one)."""
    import ctypes
    if not pointer:
        return None
    if bsd:
        length = ctypes.string_at(pointer, 1)[0]
        take = max(0, min(length - offset, size))
        return _prefix(ctypes.string_at(pointer + offset, take)) if take else 0
    return _prefix(ctypes.string_at(pointer + offset, size))


def _add_address(entry: dict, addr: str, prefix: int | None):
    entry["addresses"].append(addr)
    if prefix is not None:
        entry["networks"].append(f"{addr}/{prefix}")


# --------------------------------------------------------------------- Linux ---

def parse_proc_route(text: str) -> dict[str, list[str]]:
    """Interface -> IPv4 default gateways, from /proc/net/route."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4 or cols[1] != "00000000" or not int(cols[3], 16) & 0x2:     # RTF_GATEWAY
            continue
        out.setdefault(cols[0], []).append(socket.inet_ntoa(struct.pack("<I", int(cols[2], 16))))
    return out


def parse_proc_ipv6_route(text: str) -> dict[str, list[str]]:
    """Interface -> IPv6 default gateways, from /proc/net/ipv6_route."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 10 or cols[0] != "0" * 32 or cols[1] != "00" or cols[4] == "0" * 32:
            continue
        out.setdefault(cols[9], []).append(str(ipaddress.IPv6Address(bytes.fromhex(cols[4]))))
    return out


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _linux(root: str = "/sys/class/net", proc: str = "/proc/net", getifaddrs=None) -> list[Adapter]:
    addrs = (getifaddrs or (lambda: _getifaddrs(False)))()
    gateways = parse_proc_route(_read(os.path.join(proc, "route")) or "")
    for name, values in parse_proc_ipv6_route(_read(os.path.join(proc, "ipv6_route")) or "").items():
        gateways.setdefault(name, []).extend(values)
    out = []
    for name in sorted(os.listdir(root)):
        base = os.path.join(root, name)
        arphrd = int((_read(os.path.join(base, "type")) or "0").strip() or 0)
        uevent = _read(os.path.join(base, "uevent")) or ""
        devtype = next((line.split("=", 1)[1].strip() for line in uevent.splitlines()
                        if line.startswith("DEVTYPE=")), None)
        info = addrs.get(name) or {"flags": 0, "addresses": [], "networks": []}
        state = (_read(os.path.join(base, "operstate")) or "").strip()
        ifindex = int((_read(os.path.join(base, "ifindex")) or "0").strip() or 0)
        out.append(Adapter(name, name, devtype or "", classify_linux(
            arphrd, os.path.exists(os.path.join(base, "tun_flags")), devtype, os.path.exists(os.path.join(base, "device"))),
            state == "up" or (state == "unknown" and bool(info["flags"] & _IFF_UP)),
            ifindex, ifindex, arphrd == ARPHRD_LOOPBACK or bool(info["flags"] & _IFF_LOOPBACK),
            list(info["addresses"]), list(info["networks"]), gateways.get(name, [])))
    return out


# --------------------------------------------------------------------- macOS ---

_CTL_NET, _PF_ROUTE, _NET_RT_DUMP = 4, 17, 1
_RTF_GATEWAY = 0x2
_RTA_DST, _RTA_GATEWAY, _RTA_NETMASK = 0x1, 0x2, 0x4
_RT_MSGHDR = 92                          # struct rt_msghdr, bsd/net/route.h


def parse_route_dump(raw: bytes) -> dict[int, list[str]]:
    """Interface index -> default gateways, from a NET_RT_DUMP sysctl. Each
    message is a rt_msghdr followed by one sockaddr per bit of rtm_addrs, each
    padded to four bytes; a zero-length sockaddr still takes four."""
    out: dict[int, list[str]] = {}
    at = 0
    while at + _RT_MSGHDR <= len(raw):
        length, _version, _type, index, flags, addrs = struct.unpack_from("=HBBHxxii", raw, at)
        if length < _RT_MSGHDR:
            break
        if flags & _RTF_GATEWAY:
            found: dict[int, bytes] = {}
            cursor, end = at + _RT_MSGHDR, min(at + length, len(raw))
            for bit in (0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80):
                if not addrs & bit or cursor >= end:
                    continue
                size = raw[cursor]
                found[bit] = raw[cursor:cursor + size]
                cursor += (size + 3) & ~3 if size else 4
            gateway = _sockaddr_ip(found.get(_RTA_GATEWAY, b""))
            if gateway and _is_default(found.get(_RTA_DST, b""), found.get(_RTA_NETMASK, b"")):
                bucket = out.setdefault(index, [])
                if gateway not in bucket:
                    bucket.append(gateway)
        at += length
    return out


def _sockaddr_ip(sa: bytes) -> str | None:
    if len(sa) >= 8 and sa[1] == socket.AF_INET:
        return socket.inet_ntoa(sa[4:8])
    if len(sa) >= 24 and sa[1] == socket.AF_INET6:
        raw = sa[8:24]
        if raw[:2] == b"\xfe\x80":
            raw = raw[:2] + b"\0\0" + raw[4:]
        return str(ipaddress.IPv6Address(raw))
    return None


def _is_default(dst: bytes, mask: bytes) -> bool:
    ip = _sockaddr_ip(dst)
    if ip not in ("0.0.0.0", "::"):
        return False
    start = 8 if len(dst) > 1 and dst[1] == socket.AF_INET6 else 4
    return not any(mask[start:])


def _route_dump() -> bytes:
    import ctypes
    lib = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 6)(_CTL_NET, _PF_ROUTE, 0, 0, _NET_RT_DUMP, 0)
    size = ctypes.c_size_t(0)
    if lib.sysctl(mib, 6, None, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "route dump size failed")
    buf = ctypes.create_string_buffer(size.value + 4096)
    size = ctypes.c_size_t(len(buf))
    if lib.sysctl(mib, 6, buf, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "route dump failed")
    return buf.raw[:size.value]


def _system_configuration() -> dict[str, tuple[str, str]]:
    """BSD name -> (display name, kSCNetworkInterfaceType) from
    SCNetworkInterfaceCopyAll; empty when the framework gives nothing."""
    import ctypes
    from ctypes.util import find_library
    sc = ctypes.CDLL("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration")
    cf = ctypes.CDLL(find_library("CoreFoundation") or
                     "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    ref = ctypes.c_void_p
    for fn, args, res in ((sc.SCNetworkInterfaceCopyAll, [], ref), (sc.SCNetworkInterfaceGetBSDName, [ref], ref),
                          (sc.SCNetworkInterfaceGetLocalizedDisplayName, [ref], ref),
                          (sc.SCNetworkInterfaceGetInterfaceType, [ref], ref),
                          (cf.CFArrayGetCount, [ref], ctypes.c_long),
                          (cf.CFArrayGetValueAtIndex, [ref, ctypes.c_long], ref),
                          (cf.CFStringGetCString, [ref, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32], ctypes.c_bool),
                          (cf.CFRelease, [ref], None)):
        fn.argtypes, fn.restype = args, res

    def text(value) -> str:
        buf = ctypes.create_string_buffer(512)
        ok = value and cf.CFStringGetCString(value, buf, 512, 0x08000100)      # kCFStringEncodingUTF8
        return buf.value.decode("utf-8", "replace") if ok else ""

    array = sc.SCNetworkInterfaceCopyAll()
    if not array:
        return {}
    try:
        out = {}
        for i in range(cf.CFArrayGetCount(array)):
            item = cf.CFArrayGetValueAtIndex(array, i)
            bsd = text(sc.SCNetworkInterfaceGetBSDName(item))
            if bsd:
                out[bsd] = (text(sc.SCNetworkInterfaceGetLocalizedDisplayName(item)),
                            text(sc.SCNetworkInterfaceGetInterfaceType(item)))
        return out
    finally:
        cf.CFRelease(array)


def _macos(getifaddrs=None, system_configuration=None, route_dump=None, nametoindex=None) -> list[Adapter]:
    addrs = (getifaddrs or (lambda: _getifaddrs(True)))()
    try:
        names = (system_configuration or _system_configuration)()
    except (OSError, AttributeError):
        names = {}
    try:
        gateways = parse_route_dump((route_dump or _route_dump)())
    except OSError:
        gateways = {}
    out = []
    for name, info in sorted(addrs.items()):
        index = (nametoindex or socket.if_nametoindex)(name)
        display, sc_type = names.get(name, ("", None))
        flags = info["flags"]
        out.append(Adapter(name, name, display, classify_macos(bool(flags & _IFF_POINTOPOINT), info["link"], sc_type),
                           bool(flags & _IFF_UP) and bool(flags & _IFF_RUNNING), index, index,
                           bool(flags & _IFF_LOOPBACK), list(info["addresses"]), list(info["networks"]),
                           gateways.get(index, [])))
    return out


# ------------------------------------------------------------------- Windows ---

_GAA_SKIP_ANYCAST, _GAA_SKIP_MULTICAST, _GAA_SKIP_DNS, _GAA_INCLUDE_GATEWAYS = 0x2, 0x4, 0x8, 0x80
_ERROR_BUFFER_OVERFLOW = 111
_IF_OPER_UP = 1
_MIB_IF_ROW2_SIZE = 1352
_MIB_IF_ROW2_FLAGS = 1152                # InterfaceAndOperStatusFlags: HardwareInterface is bit 0
_SOCKADDR_INET_SIZE = 28
_MIB_IPFORWARD_ROW2_SIZE = 104


def _windows_structs():
    """The iptypes.h structures, written with fixed-size integers so their
    layout can be tested off Windows too."""
    import ctypes

    u32, u64, ptr = ctypes.c_uint32, ctypes.c_uint64, ctypes.c_void_p

    class SocketAddress(ctypes.Structure):
        _fields_ = [("sockaddr", ptr), ("length", ctypes.c_int32)]

    class Unicast(ctypes.Structure):
        pass
    Unicast._fields_ = [("Length", u32), ("Flags", u32), ("Next", ctypes.POINTER(Unicast)), ("Address", SocketAddress),
                        ("PrefixOrigin", u32), ("SuffixOrigin", u32), ("DadState", u32), ("ValidLifetime", u32),
                        ("PreferredLifetime", u32), ("LeaseLifetime", u32), ("OnLinkPrefixLength", ctypes.c_uint8)]

    class Gateway(ctypes.Structure):
        pass
    Gateway._fields_ = [("Length", u32), ("Reserved", u32), ("Next", ctypes.POINTER(Gateway)), ("Address", SocketAddress)]

    class Adapters(ctypes.Structure):
        pass
    Adapters._fields_ = [("Length", u32), ("IfIndex", u32), ("Next", ctypes.POINTER(Adapters)),
                         ("AdapterName", ctypes.c_char_p), ("FirstUnicastAddress", ctypes.POINTER(Unicast)),
                         ("FirstAnycastAddress", ptr), ("FirstMulticastAddress", ptr), ("FirstDnsServerAddress", ptr),
                         ("DnsSuffix", ctypes.c_wchar_p), ("Description", ctypes.c_wchar_p),
                         ("FriendlyName", ctypes.c_wchar_p), ("PhysicalAddress", ctypes.c_uint8 * 8),
                         ("PhysicalAddressLength", u32), ("Flags", u32), ("Mtu", u32), ("IfType", u32),
                         ("OperStatus", u32), ("Ipv6IfIndex", u32), ("ZoneIndices", u32 * 16), ("FirstPrefix", ptr),
                         ("TransmitLinkSpeed", u64), ("ReceiveLinkSpeed", u64), ("FirstWinsServerAddress", ptr),
                         ("FirstGatewayAddress", ctypes.POINTER(Gateway)), ("Ipv4Metric", u32), ("Ipv6Metric", u32),
                         ("Luid", u64), ("Dhcpv4Server", SocketAddress), ("CompartmentId", u32),
                         ("NetworkGuid", ctypes.c_uint8 * 16), ("ConnectionType", u32), ("TunnelType", u32)]
    return Adapters, Unicast, Gateway


def _win_sockaddr_ip(sa, length: int) -> str | None:
    """The address in a Windows SOCKADDR (AF_INET 2, AF_INET6 23), or None."""
    import ctypes
    if not sa or length < 8:
        return None
    family = struct.unpack("<H", ctypes.string_at(sa, 2))[0]
    if family == 2:
        return socket.inet_ntoa(ctypes.string_at(sa + 4, 4))
    if family == 23 and length >= 24:
        return str(ipaddress.IPv6Address(ctypes.string_at(sa + 8, 16)))
    return None


def parse_windows_adapters(first, hardware: Callable[[int], bool]) -> list[Adapter]:
    """Adapters from a GetAdaptersAddresses list; *hardware(luid)* asks GetIfEntry2."""
    out = []
    node = first
    while node:
        item = node.contents
        addresses, networks, gateways = [], [], []
        unicast = item.FirstUnicastAddress
        while unicast:
            u = unicast.contents
            addr = _win_sockaddr_ip(u.Address.sockaddr, u.Address.length)
            if addr:
                addresses.append(addr)
                networks.append(f"{addr}/{u.OnLinkPrefixLength}")
            unicast = u.Next
        gateway = item.FirstGatewayAddress
        while gateway:
            g = gateway.contents
            addr = _win_sockaddr_ip(g.Address.sockaddr, g.Address.length)
            if addr:
                gateways.append(addr)
            gateway = g.Next
        guid = (item.AdapterName or b"").decode("ascii", "replace")
        out.append(Adapter(guid, item.FriendlyName or guid, item.Description or "",
                           classify_windows(item.IfType, item.TunnelType, hardware(item.Luid)),
                           item.OperStatus == _IF_OPER_UP, item.IfIndex, item.Ipv6IfIndex,
                           item.IfType == IF_TYPE_LOOPBACK, addresses, networks, gateways))
        node = item.Next
    return out


def _windows_lib():
    import ctypes
    return ctypes.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x800)  # LOAD_LIBRARY_SEARCH_SYSTEM32


def _windows() -> list[Adapter]:
    import ctypes
    lib = _windows_lib()
    Adapters, _u, _g = _windows_structs()

    def hardware(luid: int) -> bool:
        row = ctypes.create_string_buffer(struct.pack("<Q", luid), _MIB_IF_ROW2_SIZE)
        return lib.GetIfEntry2(row) == 0 and bool(row.raw[_MIB_IF_ROW2_FLAGS] & 1)

    flags = _GAA_SKIP_ANYCAST | _GAA_SKIP_MULTICAST | _GAA_SKIP_DNS | _GAA_INCLUDE_GATEWAYS
    size = ctypes.c_uint32(32768)
    for _ in range(3):
        buf = ctypes.create_string_buffer(size.value)
        rc = lib.GetAdaptersAddresses(0, flags, None, buf, ctypes.byref(size))
        if rc != _ERROR_BUFFER_OVERFLOW:
            break
    if rc != 0:
        raise OSError(rc, "GetAdaptersAddresses failed")
    return parse_windows_adapters(ctypes.cast(buf, ctypes.POINTER(Adapters)), hardware)


# -------------------------------------------------------------------- public ---

def list_adapters() -> list[Adapter]:
    """Every adapter the OS reports now. Call it each time: VPN clients add
    and remove adapters while the app runs. Raises OSError when the OS call fails."""
    if sys.platform.startswith("win"):
        return _windows()
    if sys.platform == "darwin":
        return _macos()
    return _linux()


def find(adapters: Iterable[Adapter], wanted: str) -> Adapter | None:
    """The adapter a setting or a flag names: by id, then by OS name."""
    adapters = list(adapters)
    return next((a for a in adapters if a.id == wanted), None) or next(
        (a for a in adapters if a.name.casefold() == wanted.casefold()), None)


def _family(addr: str) -> int:
    return ipaddress.ip_address(addr).version


def source_on(adapter: Adapter, family: int) -> str | None:
    """The adapter's address to send *family* from: not a link-local one, which
    cannot leave the link."""
    return next((a for a in adapter.addresses
                 if _family(a) == family and not ipaddress.ip_address(a).is_link_local), None)


@dataclass
class Binding:
    """One chosen adapter, resolved for one target's address family."""
    adapter: Adapter
    source: str
    platform: str

    def apply(self, sock, family: int) -> None:
        """Force *sock* out of the adapter. Raises :class:`NotForced` when the
        system refuses."""
        try:
            if self.platform.startswith("win"):
                if family == 6:
                    sock.setsockopt(socket.IPPROTO_IPV6, IPV6_UNICAST_IF, self.adapter.index6 or self.adapter.index)
                else:
                    sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, socket.htonl(self.adapter.index))
            elif self.platform == "darwin":
                if family == 6:
                    sock.setsockopt(socket.IPPROTO_IPV6, IPV6_BOUND_IF, self.adapter.index)
                else:
                    sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, self.adapter.index)
            else:
                sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self.adapter.name.encode() + b"\0")
        except OSError as exc:
            log.info("event=interface_not_forced adapter=%s errno=%s", tag(self.adapter.name), exc.errno)
            if exc.errno in (errno.EPERM, errno.EACCES):
                raise NotForced(f"This system does not allow forcing probes out of {self.adapter.label} "
                                f"without more privileges. Nothing was sent.") from None
            raise NotForced(f"The system refused to send probes out of {self.adapter.label}. Nothing was sent.") from None


def bind(wanted: str, address: str, *, adapters: list[Adapter] | None = None,
         platform: str | None = None) -> Binding:
    """The :class:`Binding` for the adapter *wanted* and a target at *address*.
    Raises :class:`InterfaceError` when it cannot be used."""
    listed = list_adapters() if adapters is None else adapters
    adapter = find(listed, wanted)
    if adapter is None:
        raise InterfaceError(f"There is no network interface named {wanted} on this computer now.")
    if not adapter.selectable:
        raise InterfaceError(f"The interface {adapter.label} is down.")
    family = _family(address)
    source = source_on(adapter, family)
    if source is None:
        raise InterfaceError(f"The interface {adapter.label} has no IPv{family} address.")
    return Binding(adapter, source, platform or sys.platform)


def windows_route_exists(index: int, address: str, lib=None) -> bool:
    """GetBestRoute2 restricted to one interface. Windows has no equivalent of
    connecting a test socket for a bound interface: a VPN client can leave the
    adapter up with no usable route, and only this says so."""
    import ctypes
    lib = lib or _windows_lib()
    ip = ipaddress.ip_address(address)
    if ip.version == 4:
        dest = struct.pack("<HH4s20x", 2, 0, ip.packed)
    else:
        dest = struct.pack("<HHI16sI", 23, 0, 0, ip.packed, 0)
    target = ctypes.create_string_buffer(dest, _SOCKADDR_INET_SIZE)
    row = ctypes.create_string_buffer(_MIB_IPFORWARD_ROW2_SIZE)
    source = ctypes.create_string_buffer(_SOCKADDR_INET_SIZE)
    return lib.GetBestRoute2(None, index, None, target, 0, row, source) == 0


def route_exists(binding: Binding, address: str, *, socket_factory=None, windows_check=None) -> bool:
    """Whether the bound adapter has a route to *address*. Sends nothing.
    Raises :class:`NotForced` when the binding is refused."""
    family = _family(address)
    if binding.platform.startswith("win"):
        index = binding.adapter.index6 if family == 6 and binding.adapter.index6 else binding.adapter.index
        return (windows_check or windows_route_exists)(index, address)
    sock = (socket_factory or socket.socket)(socket.AF_INET6 if family == 6 else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        binding.apply(sock, family)
        try:
            sock.connect((address, 9))
        except OSError:
            return False
        return True
    finally:
        sock.close()


@dataclass
class InterfaceUse:
    """Which adapter a run went through, kept with its result. ``selected`` is
    True when the user chose it; ``check`` is the hop-1 check for such a run."""
    kind: str
    label: str
    selected: bool = False
    check: str | None = None
    redirected_by: str | None = None     # the adapter hop 1 belonged to, for REDIRECTED
    description: str = ""
    addresses: list[str] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)

    @classmethod
    def of(cls, adapter: Adapter, selected: bool = False, check: str | None = None,
           redirected_by: str | None = None) -> "InterfaceUse":
        return cls(adapter.kind, adapter.label, selected, check, redirected_by, adapter.description,
                   list(adapter.addresses), list(adapter.gateways))

    def to_export(self, include_addresses: bool = False) -> dict:
        """The block an export carries. Local addresses and gateways only when
        the user asked for them."""
        out = {"kind": self.kind, "label": self.label, "selected": self.selected, "check": self.check}
        if self.redirected_by:
            out["redirected_by"] = self.redirected_by
        if include_addresses:
            out.update(addresses=list(self.addresses), gateways=list(self.gateways))
        return out


def routed_source(address: str) -> str:
    """The source address the system would use for *address*: a UDP socket's
    connect picks the route and sends nothing."""
    family = _family(address)
    with socket.socket(socket.AF_INET6 if family == 6 else socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.connect((address, 9))
        return _clean(udp.getsockname()[0])


def adapter_for(address: str, adapters: list[Adapter], source_for: Callable[[str], str] = routed_source) -> Adapter | None:
    """The adapter that owns the source address the system routes *address* from."""
    source = ipaddress.ip_address(source_for(address))
    return next((a for a in adapters if any(ipaddress.ip_address(x) == source for x in a.addresses)), None)


def used_for(address: str, *, list_fn: Callable[[], list[Adapter]] = list_adapters,
             source_for: Callable[[str], str] = routed_source) -> InterfaceUse | None:
    """How the system routes to *address*, or None when that cannot be told.
    Never raises: losing this note must never fail a trace."""
    try:
        adapter = adapter_for(address, list_fn(), source_for)
    except Exception as exc:  # noqa: BLE001
        log.info("event=interface_detect_failed reason=%s", type(exc).__name__)
        return None
    return None if adapter is None else InterfaceUse.of(adapter)


def _reaches(adapter: Adapter, ip) -> bool:
    if any(ipaddress.ip_address(g) == ip for g in adapter.gateways):
        return True
    if ip.is_link_local:                 # every adapter shares fe80::/64
        return False
    return any(ip in ipaddress.ip_interface(n).network for n in adapter.networks)


def check_first_hop(adapter: Adapter, first_hop: Iterable[str], adapters: list[Adapter]) -> tuple[str, str | None]:
    """Did probes sent on *adapter* leave there, judged from who answered at
    hop 1? (:data:`CONSISTENT`, None) when it is that adapter's gateway or on
    its subnet, (:data:`REDIRECTED`, the other adapter's label) when it
    belongs to another adapter, otherwise (:data:`UNCONFIRMED`, None). Never
    proof of a direct path."""
    answered = [ipaddress.ip_address(_clean(a)) for a in first_hop if a]
    if not answered:
        return UNCONFIRMED, None
    if any(_reaches(adapter, ip) for ip in answered):
        return CONSISTENT, None
    for other in adapters:
        if other.id != adapter.id and other.selectable and any(_reaches(other, ip) for ip in answered):
            return REDIRECTED, other.label
    return UNCONFIRMED, None


def use_after_run(binding: Binding, first_hop: Iterable[str]) -> InterfaceUse:
    """The :class:`InterfaceUse` of a finished run on a chosen adapter."""
    try:
        adapters = list_adapters()
    except OSError:
        adapters = [binding.adapter]
    check, other = check_first_hop(binding.adapter, first_hop, adapters)
    return InterfaceUse.of(binding.adapter, True, check, other)


def on_local_subnet(address: str, adapters: Iterable[Adapter]) -> bool:
    """Whether *address* is directly on a network this computer is attached to."""
    ip = ipaddress.ip_address(address)
    for adapter in adapters:
        if not adapter.selectable:
            continue
        for net in adapter.networks:
            network = ipaddress.ip_interface(net).network
            if network.version == ip.version and network.prefixlen < network.max_prefixlen and ip in network:
                return True
    return False
