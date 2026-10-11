"""Path discovery on Windows with TCP (0.7.0, D3 option A): the transport,
the routers' answers through TCP_ICMP_ERROR_INFO, and the real Windows run
(tests/fixtures/odin_tcp_flowcheck.json) replayed: both paths found."""
import json
import pathlib
import socket
import struct

import pytest

from routemap_engine import multipath, probe
from routemap_engine.probe import FlowAnswer

ODIN = json.loads((pathlib.Path(__file__).parent / "fixtures" / "odin_tcp_flowcheck.json").read_text())


def info(address, kind=11, code=0):
    """An ICMP_ERROR_INFO as Windows returns it."""
    if ":" in address:
        sockaddr = struct.pack("<HHI", 23, 0, 0) + socket.inet_pton(socket.AF_INET6, address) + b"\0" * 4
    else:
        sockaddr = struct.pack("<HH", 2, 0) + socket.inet_aton(address) + b"\0" * 20
    return sockaddr + struct.pack("<i", 1 if ":" not in address else 58) + bytes([kind, code]) + b"\0\0"


def test_icmp_error_info_is_read_for_both_families():
    assert probe.parse_icmp_error_info(info("62.115.209.158")) == ("62.115.209.158", 11, 0)
    assert probe.parse_icmp_error_info(info("2001:db8::1", kind=3)) == ("2001:db8::1", 3, 0)
    assert probe.parse_icmp_error_info(b"\0" * 10) == (None, None, None)


class FakeSock:
    made = []

    def __init__(self, family, kind):
        self.family, self.opts, self.bound, self.connected, self.closed = family, [], None, None, False
        self.error, self.icmp = 0, b""
        FakeSock.made.append(self)

    def listen(self, *a):
        raise AssertionError("a probe socket must never listen")

    def accept(self, *a):
        raise AssertionError("a probe socket must never accept")

    def setsockopt(self, level, name, value):
        self.opts.append((level, name, value))

    def bind(self, addr):
        self.bound = addr

    def setblocking(self, flag):
        pass

    def connect_ex(self, addr):
        self.connected = addr
        return probe.WSAEWOULDBLOCK

    def getsockopt(self, level, name, size=None):
        if (level, name) == (socket.SOL_SOCKET, socket.SO_ERROR):
            return self.error
        return self.icmp

    def close(self):
        self.closed = True


def test_one_tcp_connect_per_probe_holding_the_flow_and_reading_the_router():
    FakeSock.made = []
    t = probe.TcpFlowTransport("193.99.144.80", windows=True, source_for=lambda d: "192.0.2.10", socket_factory=FakeSock, clock=lambda: 10.0,
                               select=lambda r, w, x, timeout: ([], w, []))
    t.send(0, 5, 101)
    t.send(1, 5, 102)
    t.send(2, 13, 103)
    a5, b5, a13 = FakeSock.made
    assert (a5.bound[1], b5.bound[1], a13.bound[1]) == (t.sport(0), t.sport(1), t.sport(2))  # flow = source port
    assert a5.connected == ("193.99.144.80", 443)
    assert (socket.IPPROTO_IP, socket.IP_TTL, 5) in a5.opts and (socket.IPPROTO_IP, socket.IP_TTL, 13) in a13.opts
    assert (socket.IPPROTO_TCP, probe.TCP_NOSYNRETRIES, 1) in a5.opts
    assert (socket.IPPROTO_TCP, probe.TCP_FAIL_CONNECT_ON_ICMP_ERROR, 1) in a5.opts
    a5.error, a5.icmp = probe.WSAEHOSTUNREACH, info("198.51.100.141")
    b5.error, b5.icmp = probe.WSAEHOSTUNREACH, info("198.51.100.143")
    a13.error = 0                                                          # connected: the target
    got = {a.seq: (a.address, a.reached) for a in t.read(1.0)}
    assert got == {101: ("198.51.100.141", False), 102: ("198.51.100.143", False), 103: ("193.99.144.80", True)}
    assert all(s.closed for s in FakeSock.made) and t._open == {}


def test_a_refused_connection_is_the_target_too():
    FakeSock.made = []
    t = probe.TcpFlowTransport("193.99.144.80", windows=True, source_for=lambda d: "192.0.2.10", socket_factory=FakeSock, clock=lambda: 1.0,
                               select=lambda r, w, x, timeout: ([], [], x))
    t.send(0, 30, 7)
    FakeSock.made[0].error = probe.WSAECONNREFUSED
    assert [(a.address, a.reached) for a in t.read(1.0)] == [("193.99.144.80", True)]


class OdinNetwork:
    """The Windows run, replayed: a per-flow balancer at hop 5 sends even
    source ports along flow A's routers and odd ones along flow B's. Silent
    hops stay silent. Flow B's routers past hop 13 were not measured; they do
    not answer here. Hop 6 on B answered once in 1,065.5 ms in the real run;
    here only the first probe there is that slow and later ones take 38 ms
    (an assumed ordinary reply for that router, so the median has company)."""

    def __init__(self):
        self.t, self.queue, self.slow_used = 1000.0, [], False
        self.METHOD = "tcp-paris"

    def clock(self):
        return self.t

    def send(self, flow, ttl, seq):
        side = "A" if flow % 2 == 0 else "B"
        if ttl == multipath.PING_HOPS:
            if side == "A":
                self.queue.append((self.t + 0.250, FlowAnswer(seq, ODIN["target"], True, self.t + 0.250)))
            return
        addr = ODIN["flows"][side].get(str(min(ttl, 13)))
        if ttl > 13 and side == "B":
            return
        if addr is None:
            return
        rtt = ODIN["rtt_ms"][side].get(str(ttl), 100.0)
        if side == "B" and ttl == 6:
            rtt = 1065.5 if not self.slow_used else 38.0
            self.slow_used = True
        rtt /= 1000.0
        reached = side == "A" and ttl >= 13
        self.queue.append((self.t + rtt, FlowAnswer(seq, addr, reached, self.t + rtt)))

    def read(self, timeout):
        due = [q for q in self.queue if q[0] <= self.t + timeout]
        self.queue = [q for q in self.queue if q[0] > self.t + timeout]
        self.t = max(self.t + (0 if due else timeout), max((d[0] for d in due), default=0))
        return [a for _, a in due]

    def close(self):
        pass


def test_the_real_windows_run_finds_both_paths_and_one_slow_reply_does_not_skew_latency():
    net = OdinNetwork()
    d = multipath.Discoverer("heise.de", ODIN["target"], net, clock=net.clock,
                             options=multipath.Options(wait=2.0)).run()
    assert d.method == "tcp-paris" and d.to_dict()["method"] == "tcp-paris" and d.to_dict()["port"] == 443
    assert len(d.paths) == 2
    by_hop5 = {p.hops[4]: p for p in d.paths}
    a, b = by_hop5["198.51.100.141"], by_hop5["198.51.100.143"]
    assert a.hops[8] == "5.56.18.114" and a.hops[9] == "82.98.102.19" and a.reached
    assert b.hops[5] == "62.115.209.158" and b.hops[11] == "82.98.102.1"
    assert b.rtt_ms[5] == pytest.approx(38.0)          # the 1,065.5 ms reply is one sample of many
    assert a.rtt_to_target_ms == pytest.approx(250.0)


def test_a_paths_latency_is_the_median_of_its_samples():
    assert multipath._median([31.5, 32.2, 1065.5]) == 32.2
    assert multipath._median([31.5, 1065.5]) == pytest.approx(548.5)     # two samples: no majority to lean on
    assert multipath._median([]) is None


def test_a_flow_is_never_two_connections_at_once():
    """One five-tuple, one connection: the second probe of a flow waits for
    the first's answer, which is still returned by the next read."""
    FakeSock.made = []
    now = [0.0]

    def select(r, w, x, timeout):
        now[0] += timeout
        for s in w:
            s.error, s.icmp = probe.WSAEHOSTUNREACH, info("198.51.100.141")
        return [], w, []
    t = probe.TcpFlowTransport("193.99.144.80", windows=True, source_for=lambda d: "192.0.2.10", socket_factory=FakeSock, clock=lambda: now[0], select=select)
    t.send(0, 5, 1)
    t.send(0, 6, 2)
    first, second = FakeSock.made
    assert first.bound == second.bound and first.closed and not second.closed
    assert [a.seq for a in t.read(0.1)] == [1, 2]


def test_a_connect_refused_locally_is_not_a_probe_in_flight():
    class Busy(FakeSock):
        def connect_ex(self, addr):
            return 10048                                   # WSAEADDRINUSE
    t = probe.TcpFlowTransport("193.99.144.80", windows=True, source_for=lambda d: "192.0.2.10", socket_factory=Busy, select=lambda r, w, x, timeout: ([], w, []))
    t.send(0, 5, 1)
    assert t._open == {} and t.read(0.1) == []


def test_a_tcp_discovery_is_labelled_tcp_once_analysed():
    import asyncio
    from routemap_engine import analyse_paths
    from routemap_engine.geo import Sources
    net = OdinNetwork()
    d = multipath.Discoverer("heise.de", ODIN["target"], net, clock=net.clock,
                             options=multipath.Options(wait=2.0)).run()
    route = asyncio.run(analyse_paths(d, None, sources=Sources(hoiho=None, ip_db=None, ptr=None)))
    assert route.parser_label == "Built-in TCP prober (port 443)"
    assert route.to_dict()["paths"]["method"] == "tcp-paris"


@pytest.mark.parametrize("dst,src", [("193.99.144.80", "192.0.2.10"), ("2a02:2e0:3fe:1001:302::", "2001:db8:5::10")])
def test_probes_are_bound_to_the_routes_own_address_never_to_every_interface(dst, src):
    """CodeQL py/bind-socket-all-network-interfaces: the bound address is the
    one the system routes the target from (a VPN or tailnet adapter on the
    same machine must not carry probes), with the flow's port; IPv4 and IPv6."""
    FakeSock.made = []
    asked = []
    t = probe.TcpFlowTransport(dst, windows=True, socket_factory=FakeSock,
                               source_for=lambda d: (asked.append(d), src)[1],
                               select=lambda r, w, x, timeout: ([], [], []))
    t.send(3, 7, 1)
    sock = FakeSock.made[0]
    assert asked == [dst] and sock.bound == (src, t.sport(3))
    assert sock.bound[0] not in ("", "0.0.0.0", "::")
    assert sock.family == (socket.AF_INET6 if ":" in dst else socket.AF_INET)


def test_the_route_source_is_what_the_system_would_use():
    """No mock: probe._source_for against loopback, both families."""
    t4 = probe.TcpFlowTransport("127.0.0.1", socket_factory=FakeSock)
    assert t4.src == "127.0.0.1"
    try:
        t6 = probe.TcpFlowTransport("::1", socket_factory=FakeSock)
    except OSError:
        pytest.skip("no IPv6 loopback here")
    assert t6.src == "::1"


def test_a_real_probe_socket_never_listens():
    """A real socket, a real connect to a closed loopback port: the probe
    socket is in SYN-SENT or closed, never LISTEN, and connects out."""
    import socket as s
    with s.socket() as finder:
        finder.bind(("127.0.0.1", 0))
        port = finder.getsockname()[1]
    t = probe.TcpFlowTransport("127.0.0.1", port=port)
    t.send(0, 64, 1)
    sock = next(iter(t._open.values()))[0]
    assert sock.getsockname()[0] == "127.0.0.1"
    try:
        listening = sock.getsockopt(s.SOL_SOCKET, s.SO_ACCEPTCONN)
    except (AttributeError, OSError):
        listening = None                     # macOS does not report it; Linux and Windows CI do
    assert listening in (0, None)
    got = []
    for _ in range(20):
        got += t.read(0.1)
        if got:
            break
    assert [(a.address, a.reached) for a in got] == [("127.0.0.1", True)]      # refused = the target
    t.close()
