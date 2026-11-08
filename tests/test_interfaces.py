"""Adapters as the OS reports them, the per-OS binding, and the hop-1 check.
Every OS is exercised on every OS with mocked responses (the layouts use
fixed-size integers for that reason); the one call made for real is
list_adapters() on the machine running the test."""
import ctypes
import errno
import ipaddress
import logging
import pathlib
import socket
import struct
import sys

import pytest

from routemap_engine import interfaces as I
from routemap_engine import probe, runner

ENGINE = pathlib.Path(I.__file__).parent


def adapter(id="eth0", kind=I.PHYSICAL, up=True, index=7, index6=0, addresses=("192.0.2.10",),
            networks=("192.0.2.10/24",), gateways=("192.0.2.1",), loopback=False):
    return I.Adapter(id, id, "desc", kind, up, index, index6, loopback, list(addresses), list(networks), list(gateways))


# ---------------------------------------------------------- classification ---

@pytest.mark.parametrize("if_type,tunnel_type,hardware,want", [
    (I.IF_TYPE_TUNNEL, 0, False, I.TUNNEL), (I.IF_TYPE_PPP, 0, False, I.TUNNEL),
    (I.IF_TYPE_PROP_VIRTUAL, 0, False, I.TUNNEL), (I.IF_TYPE_ETHERNET, 14, True, I.TUNNEL),
    (I.IF_TYPE_ETHERNET, 0, True, I.PHYSICAL), (I.IF_TYPE_IEEE80211, 0, True, I.PHYSICAL),
    (I.IF_TYPE_WWANPP, 0, True, I.PHYSICAL), (I.IF_TYPE_WWANPP2, 0, True, I.PHYSICAL),
    # A virtual switch: Ethernet type, not hardware. The OS gives no clear answer.
    (I.IF_TYPE_ETHERNET, 0, False, I.UNCLASSIFIED), (I.IF_TYPE_LOOPBACK, 0, False, I.UNCLASSIFIED),
    (999, 0, True, I.UNCLASSIFIED)])
def test_windows_classification(if_type, tunnel_type, hardware, want):
    assert I.classify_windows(if_type, tunnel_type, hardware) == want


@pytest.mark.parametrize("p2p,link,sc,want", [
    (True, False, None, I.TUNNEL), (False, True, "Ethernet", I.PHYSICAL), (False, True, "IEEE80211", I.PHYSICAL),
    (False, True, "WWAN", I.PHYSICAL), (False, True, "Bridge", I.UNCLASSIFIED), (False, True, None, I.UNCLASSIFIED),
    (True, True, None, I.UNCLASSIFIED)])
def test_macos_classification(p2p, link, sc, want):
    assert I.classify_macos(p2p, link, sc) == want


@pytest.mark.parametrize("arphrd,tun,devtype,device,want", [
    (65534, False, None, False, I.TUNNEL), (512, False, None, False, I.TUNNEL), (768, False, None, False, I.TUNNEL),
    (776, False, None, False, I.TUNNEL), (778, False, None, False, I.TUNNEL), (1, True, None, False, I.TUNNEL),
    (1, False, "wireguard", False, I.TUNNEL), (1, False, None, True, I.PHYSICAL), (1, False, "bridge", False, I.UNCLASSIFIED),
    (772, False, None, False, I.UNCLASSIFIED)])
def test_linux_classification(arphrd, tun, devtype, device, want):
    assert I.classify_linux(arphrd, tun, devtype, device) == want


VENDORS = ("zscaler", "netskope", "globalprotect", "palo alto", "cloudflare", "tailscale", "openvpn", "fortinet",
           "forticlient", "anyconnect", "cisco", "pulse secure", "wintun", "tap-windows", "hyper-v", "vethernet",
           "utun", "nordvpn", "expressvpn", "mullvad", "zerotier")


@pytest.mark.parametrize("name", ["interfaces.py", "probe.py", "multipath.py", "runner.py", "watch.py"])
def test_no_adapter_or_vendor_name_is_hardcoded(name):
    text = (ENGINE / name).read_text("utf-8").lower().replace('devtype == "wireguard"', "")
    assert not [v for v in VENDORS + ("wireguard",) if v in text]


def test_list_adapters_runs_on_this_machine():
    adapters = I.list_adapters()
    assert adapters and all(a.kind in I.KINDS for a in adapters)
    assert any(a.loopback for a in adapters)
    for a in adapters:
        for addr in a.addresses + a.gateways:
            ipaddress.ip_address(addr)
        for net in a.networks:
            ipaddress.ip_interface(net)


# ------------------------------------------------------------- Linux, macOS ---

def test_linux_from_sysfs_and_proc(tmp_path):
    root, proc = tmp_path / "net", tmp_path / "proc"
    proc.mkdir()
    def dev(name, arphrd, index, state="up", device=False, tun=False, devtype=None):
        d = root / name
        d.mkdir(parents=True)
        (d / "type").write_text(f"{arphrd}\n")
        (d / "ifindex").write_text(f"{index}\n")
        (d / "operstate").write_text(f"{state}\n")
        (d / "uevent").write_text(f"INTERFACE={name}\n" + (f"DEVTYPE={devtype}\n" if devtype else ""))
        if device:
            (d / "device").mkdir()
        if tun:
            (d / "tun_flags").write_text("0x1001\n")
    dev("eth0", 1, 2, device=True)
    dev("tun0", 65534, 3, state="unknown", tun=True)
    dev("wg0", 65534, 4, state="unknown", devtype="wireguard")
    dev("lo", 772, 1, state="unknown")
    dev("eth1", 1, 5, state="down", device=True)
    (proc / "route").write_text("Iface\tDestination\tGateway\tFlags\nEth\n"
                                "eth0\t00000000\t010200C0\t0003\neth0\t000200C0\t00000000\t0001\n")
    (proc / "ipv6_route").write_text("0" * 32 + " 00 " + "0" * 32 + " 00 " + "20010db8" + "0" * 23 + "1 "
                                     "00000400 00000000 00000000 00450003 eth0\n")
    infos = {"eth0": {"flags": 0x41, "addresses": ["192.0.2.10"], "networks": ["192.0.2.10/24"]},
             "tun0": {"flags": 0x51, "addresses": ["198.51.100.2"], "networks": ["198.51.100.2/32"]}}
    found = {a.name: a for a in I._linux(str(root), str(proc), getifaddrs=lambda: infos)}
    assert found["eth0"].kind == I.PHYSICAL and found["eth0"].up and found["eth0"].index == 2
    assert found["eth0"].gateways == ["192.0.2.1", "2001:db8::1"]
    assert found["tun0"].kind == I.TUNNEL and found["tun0"].up
    assert found["wg0"].kind == I.TUNNEL and found["wg0"].description == "wireguard"
    assert found["lo"].loopback and not found["lo"].selectable
    assert not found["eth1"].up and not found["eth1"].selectable


def _sockaddr_in(ip):
    return struct.pack("=BBH4s8x", 16, socket.AF_INET, 0, socket.inet_aton(ip))


def _route_msg(index, flags, *sas, addrs=None):
    body = b""
    for sa in sas:
        body += sa + b"\0" * ((4 - len(sa) % 4) % 4) if sa else b"\0\0\0\0"
    head = struct.pack("=HBBHxxii", I._RT_MSGHDR + len(body), 5, 4, index, flags, addrs or 7)
    return head + b"\0" * (I._RT_MSGHDR - len(head)) + body


def test_route_dump_finds_default_gateways_only():
    raw = (_route_msg(11, 2, _sockaddr_in("0.0.0.0"), _sockaddr_in("192.0.2.1"), b"") +
           _route_msg(11, 2, _sockaddr_in("198.51.100.0"), _sockaddr_in("192.0.2.2"), struct.pack("=BBH4B", 7, 2, 0, 255, 255, 255, 0)) +
           _route_msg(20, 1, _sockaddr_in("0.0.0.0"), struct.pack("=BB6x", 20, 18), b""))
    assert I.parse_route_dump(raw) == {11: ["192.0.2.1"]}


def test_macos_combines_its_sources():
    infos = {"en0": {"flags": 0x41, "link": True, "addresses": ["192.0.2.10"], "networks": ["192.0.2.10/24"]},
             "utun4": {"flags": 0x51, "link": False, "addresses": ["198.51.100.2"], "networks": ["198.51.100.2/32"]},
             "bridge0": {"flags": 0x1, "link": True, "addresses": [], "networks": []}}
    found = {a.name: a for a in I._macos(getifaddrs=lambda: infos,
                                         system_configuration=lambda: {"en0": ("Wi-Fi", "IEEE80211"), "bridge0": ("Bridge", "Bridge")},
                                         route_dump=lambda: _route_msg(11, 2, _sockaddr_in("0.0.0.0"), _sockaddr_in("192.0.2.1"), b""),
                                         nametoindex={"en0": 11, "utun4": 20, "bridge0": 12}.__getitem__)}
    assert found["en0"].kind == I.PHYSICAL and found["en0"].description == "Wi-Fi" and found["en0"].gateways == ["192.0.2.1"]
    assert found["utun4"].kind == I.TUNNEL and found["utun4"].description == ""
    assert found["bridge0"].kind == I.UNCLASSIFIED and not found["bridge0"].up


def test_macos_without_system_configuration_still_lists():
    def boom():
        raise OSError("no framework")
    infos = {"en0": {"flags": 0x41, "link": True, "addresses": [], "networks": []}}
    found = I._macos(getifaddrs=lambda: infos, system_configuration=boom, route_dump=boom, nametoindex=lambda n: 3)
    assert found[0].kind == I.UNCLASSIFIED and found[0].gateways == []


def test_bsd_netmask_may_be_cut_short():
    short = ctypes.create_string_buffer(struct.pack("=BBH3B", 7, 2, 0, 255, 255, 255), 8)
    assert I._mask(ctypes.addressof(short), 4, 4, True) == 24
    empty = ctypes.create_string_buffer(b"\0" * 8)
    assert I._mask(ctypes.addressof(empty), 4, 4, True) == 0
    assert I._mask(None, 4, 4, True) is None


# ------------------------------------------------------------------ Windows ---

@pytest.mark.skipif(ctypes.sizeof(ctypes.c_void_p) != 8, reason="64-bit offsets")
def test_windows_structure_layout_matches_iptypes():
    A, U, G = I._windows_structs()
    assert (A.Next.offset, A.FriendlyName.offset, A.IfType.offset, A.OperStatus.offset) == (8, 72, 100, 104)
    assert (A.FirstGatewayAddress.offset, A.Luid.offset, A.TunnelType.offset) == (208, 224, 272)
    assert (U.Address.offset, U.OnLinkPrefixLength.offset) == (16, 56) and G.Address.offset == 16


def _win_v4(ip):
    return ctypes.create_string_buffer(struct.pack("<HH4s8x", 2, 0, socket.inet_aton(ip)), 16)


def _win_v6(ip):
    return ctypes.create_string_buffer(struct.pack("<HHI16sI", 23, 0, 0, ipaddress.IPv6Address(ip).packed, 0), 28)


def test_windows_list_is_parsed_with_the_os_fields():
    A, U, G = I._windows_structs()
    keep = []
    def sa(buf):
        keep.append(buf)
        return ctypes.addressof(buf), len(buf)

    def unicast(buf, prefix, nxt=None):
        node = U()
        node.Address.sockaddr, node.Address.length = sa(buf)
        node.OnLinkPrefixLength = prefix
        if nxt is not None:
            node.Next = ctypes.pointer(nxt)
        keep.append(node)
        return node

    gate = G()
    gate.Address.sockaddr, gate.Address.length = sa(_win_v4("192.0.2.1"))
    v6 = unicast(_win_v6("2001:db8::10"), 64)
    v4 = unicast(_win_v4("192.0.2.10"), 24, v6)
    hub = A(IfIndex=9, Ipv6IfIndex=9, IfType=I.IF_TYPE_ETHERNET, OperStatus=2, Luid=2, TunnelType=0,
            AdapterName=b"{bb}", FriendlyName="vSwitch", Description="A switch")
    tun = A(IfIndex=12, Ipv6IfIndex=12, IfType=I.IF_TYPE_ETHERNET, OperStatus=1, Luid=3, TunnelType=14,
            AdapterName=b"{cc}", FriendlyName="Corp tunnel", Description="Vendor adapter")
    eth = A(IfIndex=5, Ipv6IfIndex=5, IfType=I.IF_TYPE_ETHERNET, OperStatus=1, Luid=1, TunnelType=0,
            AdapterName=b"{aa}", FriendlyName="Ethernet", Description="Intel NIC")
    eth.FirstUnicastAddress, eth.FirstGatewayAddress = ctypes.pointer(v4), ctypes.pointer(gate)
    hub.Next, eth.Next = ctypes.pointer(tun), ctypes.pointer(hub)
    found = I.parse_windows_adapters(ctypes.pointer(eth), lambda luid: luid == 1)
    assert [a.id for a in found] == ["{aa}", "{bb}", "{cc}"]
    assert found[0].name == "Ethernet" and found[0].description == "Intel NIC" and found[0].kind == I.PHYSICAL
    assert found[0].addresses == ["192.0.2.10", "2001:db8::10"] and found[0].gateways == ["192.0.2.1"]
    assert found[0].networks == ["192.0.2.10/24", "2001:db8::10/64"]
    assert found[1].kind == I.UNCLASSIFIED and not found[1].up
    assert found[2].kind == I.TUNNEL and found[2].label == "Corp tunnel"


def test_windows_route_check_asks_for_that_interface_only():
    calls = []
    class Lib:
        def GetBestRoute2(self, luid, index, source, dest, opts, row, best):
            calls.append((luid, index, source, opts, dest.raw[:2], dest.raw[4:8]))
            return 1168 if index == 9 else 0
    assert I.windows_route_exists(5, "203.0.113.9", lib=Lib())
    assert not I.windows_route_exists(9, "203.0.113.9", lib=Lib())
    assert calls[0] == (None, 5, None, 0, struct.pack("<H", 2), socket.inet_aton("203.0.113.9"))


# ------------------------------------------------------------------ binding ---

class Sock:
    def __init__(self, fail=None):
        self.opts, self.fail, self.bound, self.closed = [], fail, None, False

    def setsockopt(self, level, name, value):
        if self.fail:
            raise self.fail
        self.opts.append((level, name, value))

    def connect(self, addr):
        self.connected = addr

    def close(self):
        self.closed = True


@pytest.mark.parametrize("platform,family,want", [
    ("win32", 4, (socket.IPPROTO_IP, 31, socket.htonl(7))), ("win32", 6, (socket.IPPROTO_IPV6, 31, 8)),
    ("darwin", 4, (socket.IPPROTO_IP, 25, 7)), ("darwin", 6, (socket.IPPROTO_IPV6, 125, 7)),
    ("linux", 4, (socket.SOL_SOCKET, 25, b"eth0\0")), ("linux", 6, (socket.SOL_SOCKET, 25, b"eth0\0"))])
def test_binding_uses_each_systems_mechanism(platform, family, want):
    b = I.Binding(adapter(index6=8), "192.0.2.10", platform)
    s = Sock()
    b.apply(s, family)
    assert s.opts == [want]


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES])
def test_refused_binding_says_not_forced_and_the_run_does_not_go_on(code):
    with pytest.raises(I.NotForced, match="more privileges"):
        I.Binding(adapter(), "192.0.2.10", "linux").apply(Sock(OSError(code, "no")), 4)


def test_bind_refuses_what_cannot_carry_the_trace():
    ok = adapter()
    down = adapter("down0", up=False)
    lo = adapter("lo", loopback=True)
    only_ll = adapter("ll0", addresses=("fe80::1",), networks=("fe80::1/64",))
    v4_only = adapter("v4", addresses=("192.0.2.1",))
    listed = [ok, down, lo, only_ll, v4_only]
    with pytest.raises(I.InterfaceError, match="no network interface named nope"):
        I.bind("nope", "203.0.113.9", adapters=listed)
    with pytest.raises(I.InterfaceError, match="down"):
        I.bind("down0", "203.0.113.9", adapters=listed)
    with pytest.raises(I.InterfaceError, match="down"):
        I.bind("lo", "203.0.113.9", adapters=listed)
    with pytest.raises(I.InterfaceError, match="no IPv6"):
        I.bind("ll0", "2001:db8::9", adapters=listed)
    with pytest.raises(I.InterfaceError, match="no IPv6"):
        I.bind("v4", "2001:db8::9", adapters=listed)
    assert I.bind("eth0", "203.0.113.9", adapters=listed, platform="linux").source == "192.0.2.10"
    assert I.find(listed, "ETH0") is ok


def test_route_exists_posix_and_windows():
    b = I.Binding(adapter(), "192.0.2.10", "linux")
    assert I.route_exists(b, "203.0.113.9", socket_factory=lambda f, t: Sock())
    class NoRoute(Sock):
        def connect(self, addr):
            raise OSError(errno.ENETUNREACH, "unreachable")
    assert not I.route_exists(b, "203.0.113.9", socket_factory=lambda f, t: NoRoute())
    win = I.Binding(adapter(index6=8), "192.0.2.10", "win32")
    seen = []
    assert I.route_exists(win, "2001:db8::9", windows_check=lambda i, a: seen.append((i, a)) or True)
    assert seen == [(8, "2001:db8::9")]


def test_a_chosen_adapter_without_a_route_raises_and_sends_nothing(monkeypatch):
    b = I.Binding(adapter(), "192.0.2.10", "linux")
    monkeypatch.setattr(I, "route_exists", lambda binding, dst: False)
    monkeypatch.setattr(probe, "_probe", lambda *a, **k: pytest.fail("a probe was sent"))
    with pytest.raises(probe.NoRouteOnInterface, match="eth0 has no route to 203.0.113.9.*any other adapter"):
        probe.trace("203.0.113.9", address="203.0.113.9", interface=b)


def test_used_for_never_raises():
    def boom():
        raise RuntimeError("bad day")
    assert I.used_for("203.0.113.9", list_fn=boom) is None
    assert I.used_for("203.0.113.9", list_fn=lambda: [adapter()], source_for=lambda a: "198.51.100.99") is None


def test_used_for_names_the_adapter_owning_the_routed_source():
    tun = adapter("utun9x", kind=I.TUNNEL, addresses=("198.51.100.2",), networks=("198.51.100.2/32",), gateways=())
    use = I.used_for("203.0.113.9", list_fn=lambda: [adapter(), tun], source_for=lambda a: "198.51.100.2")
    assert (use.kind, use.label, use.selected, use.check) == (I.TUNNEL, "utun9x", False, None)


def test_export_keeps_addresses_only_when_asked():
    use = I.InterfaceUse.of(adapter())
    assert use.to_export() == {"kind": I.PHYSICAL, "label": "eth0", "selected": False, "check": None}
    assert use.to_export(True)["addresses"] == ["192.0.2.10"] and use.to_export(True)["gateways"] == ["192.0.2.1"]


# ---------------------------------------------------------------- hop-1 check ---

@pytest.mark.parametrize("hop,want", [
    (["192.0.2.1"], (I.CONSISTENT, None)), (["192.0.2.77"], (I.CONSISTENT, None)),
    (["198.51.100.1"], (I.REDIRECTED, "tun0")), (["203.0.113.5"], (I.UNCONFIRMED, None)), ([], (I.UNCONFIRMED, None)),
    (["203.0.113.5", "192.0.2.1"], (I.CONSISTENT, None)), (["fe80::1"], (I.UNCONFIRMED, None))])
def test_first_hop_check(hop, want):
    tun = adapter("tun0", kind=I.TUNNEL, addresses=("198.51.100.2",), networks=("198.51.100.2/24",), gateways=())
    eth = adapter(networks=("192.0.2.10/24", "fe80::9/64"))
    assert I.check_first_hop(eth, hop, [eth, tun]) == want


def test_on_local_subnet_ignores_host_routes_and_down_adapters():
    tun = adapter("tun0", addresses=("198.51.100.2",), networks=("198.51.100.2/32",))
    down = adapter("d", up=False, networks=("203.0.113.1/24",))
    assert I.on_local_subnet("192.0.2.50", [adapter()])
    assert not I.on_local_subnet("198.51.100.2", [tun])
    assert not I.on_local_subnet("203.0.113.9", [down])
    assert not I.on_local_subnet("2001:db8::1", [adapter()])


# ------------------------------------------------------- the per-OS probers ---

class Options:
    def __init__(self, Ttl=0):
        self.Ttl = Ttl


class WinLib:
    def __init__(self):
        self.calls = []

    def IcmpCreateFile(self):
        return 1

    def Icmp6CreateFile(self):
        return 1

    def IcmpCloseHandle(self, handle):
        pass

    def IcmpSendEcho(self, *args):
        self.calls.append(("IcmpSendEcho", args))
        return 0

    def IcmpSendEcho2Ex(self, *args):
        self.calls.append(("IcmpSendEcho2Ex", args))
        return 0

    def Icmp6SendEcho2(self, *args):
        self.calls.append(("Icmp6SendEcho2", args))
        return 0


class Reply(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_ulong)]


@pytest.fixture
def winlib(monkeypatch):
    lib = WinLib()
    monkeypatch.setattr(probe, "_windows_api", lambda: (ctypes, lib, Options, Reply))
    monkeypatch.setattr(ctypes, "byref", lambda o: o)
    return lib


def test_windows_icmp_keeps_the_old_call_when_automatic(winlib):
    probe._windows_probe("203.0.113.9", 3, 1, 1.0)
    assert winlib.calls[0][0] == "IcmpSendEcho"


def test_windows_icmp_passes_the_source_when_bound(winlib):
    b = I.Binding(adapter(), "192.0.2.10", "win32")
    probe._windows_probe("203.0.113.9", 3, 1, 1.0, b)
    name, args = winlib.calls[0]
    assert name == "IcmpSendEcho2Ex"
    assert args[4] == struct.unpack("<I", socket.inet_aton("192.0.2.10"))[0]
    assert args[5] == struct.unpack("<I", socket.inet_aton("203.0.113.9"))[0]


def test_windows_icmp6_passes_the_adapter_source_when_bound(winlib, monkeypatch):
    monkeypatch.setattr(probe, "_source_for", lambda d: pytest.fail("asked the system route"))
    b = I.Binding(adapter(addresses=("2001:db8::10",)), "2001:db8::10", "win32")
    probe._windows_probe("2001:db8::9", 3, 1, 1.0, b)
    src = winlib.calls[0][1][4]
    assert ipaddress.IPv6Address(src.raw[8:24]) == ipaddress.IPv6Address("2001:db8::10")


class ProbeSock(Sock):
    def __init__(self):
        super().__init__()
        self.sent = []

    def bind(self, addr):
        self.bound = addr

    def setblocking(self, flag):
        pass

    def sendto(self, data, addr):
        self.sent.append(addr)

    def getsockname(self):
        return ("192.0.2.10", 1234)


@pytest.mark.parametrize("family,dst,src", [(4, "203.0.113.9", "192.0.2.10"), (6, "2001:db8::9", "2001:db8::10")])
def test_posix_icmp_probe_is_bound_and_uses_the_adapter_source(monkeypatch, family, dst, src):
    s = ProbeSock()
    monkeypatch.setattr(probe, "_icmp_socket", lambda af: s)
    monkeypatch.setattr(probe, "_source_for", lambda d: pytest.fail("asked the system route"))
    monkeypatch.setattr(sys, "platform", "darwin")
    import select
    monkeypatch.setattr(select, "select", lambda *a: ([], [], []))
    b = I.Binding(adapter(addresses=(src,)), src, "darwin")
    probe._posix_probe(dst, 2, 1, 0.01, b)
    assert s.bound == (src, 0) and s.sent == [(dst, 0)]
    assert s.opts[0][1] == (125 if family == 6 else 25)


def test_flow_transport_binds_before_it_sends(monkeypatch):
    created = []
    def factory(af):
        created.append(ProbeSock())
        return created[-1]
    monkeypatch.setattr(probe, "_icmp_socket", factory)
    monkeypatch.setattr(probe, "_source_for", lambda d: pytest.fail("asked the system route"))
    monkeypatch.setattr(sys, "platform", "darwin")
    t = probe.FlowTransport("203.0.113.9", binding=I.Binding(adapter(), "192.0.2.10", "darwin"))
    t.send(1, 3, 9)
    assert created[0].opts[0][1] == 25 and created[0].bound == ("192.0.2.10", 0)


def test_tcp_transport_applies_binding_before_bind():
    order = []
    class TcpSock(Sock):
        def setsockopt(self, level, name, value):
            order.append(("opt", name))
        def bind(self, addr):
            order.append(("bind", addr))
        def setblocking(self, flag):
            pass
        def connect_ex(self, addr):
            return 10035
        def getsockname(self):
            return ("192.0.2.10", 5000)
        def fileno(self):
            return 3
    b = I.Binding(adapter(), "192.0.2.10", "win32")
    t = probe.TcpFlowTransport("203.0.113.9", windows=True, socket_factory=lambda *a: TcpSock(), binding=b,
                               source_for=lambda d: pytest.fail("asked the system route"), no_retransmit=lambda s: True)
    assert t.send(0, 1, 1)
    names = [n for kind, n in order if kind == "opt"]
    assert names.index(31) < next(i for i, x in enumerate(order) if x[0] == "bind")
    assert ("bind", ("192.0.2.10", 0)) in order


def test_tcp_answer_says_how_the_connect_ended():
    class Conn:
        def __init__(self, err):
            self.err = err
        def getsockopt(self, level, name, *a):
            return self.err
        def setsockopt(self, *a):
            pass
        def close(self):
            pass
    t = probe.TcpFlowTransport("203.0.113.9", windows=True, socket_factory=lambda *a: None, clock=lambda: 1.0,
                               source_for=lambda d: "192.0.2.10", select=lambda r, w, x, timeout: ([], w, []))
    done, refused = Conn(0), Conn(probe.WSAECONNREFUSED)
    t._open = {1: (done, 0, 0.0), 2: (refused, 1, 0.0)}
    got = {a.seq: a.connect for a in t.read(0.1)}
    assert got == {1: "completed", 2: "refused"}


# ------------------------------------------------------------ run_trace wiring ---

def _mac(monkeypatch):
    monkeypatch.setattr(runner, "_platform", lambda: "linux")


@pytest.mark.parametrize("tool,flag", [(runner.TOOL_TRACEROUTE, "-i"), (runner.TOOL_MTR, "-I")])
def test_linux_system_tools_get_their_documented_flag(monkeypatch, tool, flag):
    _mac(monkeypatch)
    b = I.Binding(adapter(), "192.0.2.10", "linux")
    assert runner.with_interface(tool, ["x", "-n", "203.0.113.9"], b) == ["x", "-n", flag, "eth0", "203.0.113.9"]


@pytest.mark.parametrize("platform,tool", [("windows", runner.TOOL_TRACERT), ("macos", runner.TOOL_TRACEROUTE)])
def test_a_tool_that_cannot_force_the_adapter_is_refused(monkeypatch, platform, tool):
    monkeypatch.setattr(runner, "_platform", lambda: platform)
    with pytest.raises(I.NotForced, match="cannot be told"):
        runner.with_interface(tool, ["x", "203.0.113.9"], I.Binding(adapter(), "192.0.2.10", "linux"))


def _run_builtin(monkeypatch, text, **options):
    seen = {}
    def fake_trace(target, **kw):
        seen.update(kw)
        return text, False, False
    monkeypatch.setattr(probe, "available", lambda family=4: (True, ""))
    monkeypatch.setattr(probe, "trace", fake_trace)
    monkeypatch.setattr(runner, "pick_tool", lambda r: (runner.TOOL_ICMP, runner.TOOL_ICMP))
    return runner.run_trace("203.0.113.9", runner.TraceOptions(**options)), seen


TEXT = "traceroute to 203.0.113.9 (203.0.113.9), 30 hops max, 40 byte packets\n 1  192.0.2.1  1.0 ms\n 2  203.0.113.9  5.0 ms\n"


def test_automatic_run_is_not_given_an_interface(monkeypatch):
    monkeypatch.setattr(I, "used_for", lambda a: I.InterfaceUse("tunnel", "t0"))
    result, seen = _run_builtin(monkeypatch, TEXT)
    assert "interface" not in seen and result.interface.label == "t0" and result.interface.check is None


def test_chosen_interface_is_bound_and_checked_at_hop_one(monkeypatch):
    b = I.Binding(adapter(), "192.0.2.10", "linux")
    monkeypatch.setattr(probe, "bound_route", lambda i, d: b)
    monkeypatch.setattr(I, "list_adapters", lambda: [adapter()])
    result, seen = _run_builtin(monkeypatch, TEXT, interface="eth0")
    assert seen["interface"] is b
    assert result.interface.selected and result.interface.check == I.CONSISTENT


def test_redirected_run_names_the_other_adapter(monkeypatch):
    tun = adapter("tun0", kind=I.TUNNEL, addresses=("198.51.100.2",), networks=("198.51.100.2/24",), gateways=("198.51.100.1",))
    eth = adapter()
    monkeypatch.setattr(probe, "bound_route", lambda i, d: I.Binding(eth, "192.0.2.10", "linux"))
    monkeypatch.setattr(I, "list_adapters", lambda: [eth, tun])
    result, _ = _run_builtin(monkeypatch, TEXT.replace("192.0.2.1 ", "198.51.100.1 "), interface="eth0")
    assert result.interface.check == I.REDIRECTED and result.interface.redirected_by == "tun0"


def test_log_lines_carry_no_adapter_name(caplog):
    with caplog.at_level(logging.INFO, logger="routemap_engine.interfaces"):
        with pytest.raises(I.NotForced):
            I.Binding(adapter("secret-corp-adapter"), "192.0.2.10", "linux").apply(Sock(OSError(errno.EPERM, "x")), 4)
    assert "secret-corp-adapter" not in caplog.text and "h:" in caplog.text
