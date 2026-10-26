"""Windows reserves TCP port ranges (Hyper-V, WSL 2, Docker Desktop, or an
administrator's netsh int ipv4 add excludedportrange), and a bind to a port
in one fails with WSAEACCES (10013). Up to 0.8.0 each Windows probe flow had
a fixed source port, 40000 plus a random base plus the flow, and the engine
CI's Windows runners refused such a port in 6 runs from 11 to 26 Oct 2026
("local failures 12" of 12, the error discarded).

Now a flow's port is the system's (a bind to port 0), kept for the flow's
later probes; a kept port refused later (another program took it) is
replaced once and the flow starts over from TTL 1; and a probe that never
leaves this machine says why, by error name and code."""
from __future__ import annotations

import pytest

from helpers import odin_net
from routemap_engine import multipath, probe

RESERVED = range(40000, 51000)            # every port 0.8.0 could pick, and more


def _refused():
    return PermissionError(10013, "An attempt was made to access a socket in a way forbidden by its access permissions")


class ReservedNet(odin_net.Net):
    """The replayed ODIN network on a computer whose reserved TCP ranges cover
    every fixed port; the system hands out ports outside them."""

    def __init__(self):
        super().__init__()
        self.next_port = 51000
        self.binds: list[int] = []

    def refuse_bind(self, addr):
        self.binds.append(addr[1])
        return _refused() if addr[1] in RESERVED else None


class StolenNet(odin_net.Net):
    """The replayed network, where another program takes flow 2's port after
    its first probe: the next bind of that port is refused, once."""

    def __init__(self):
        super().__init__()
        self.stolen: int | None = None
        self.asked: list[tuple[int, int]] = []

    def refuse_bind(self, addr):
        kept = self.transport.sport(2)
        if self.stolen is None and addr[1] != 0 and addr[1] == kept:
            self.stolen = addr[1]
            return _refused()
        return None

    def answer(self, sock):
        self.asked.append((self.flow(sock), sock.ttl))
        super().answer(sock)


def _discover(net):
    return multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                deadline=net.clock() + 3600).run()


def test_paths_on_a_computer_that_reserves_every_fixed_port_finds_the_paths():
    clean = _discover(odin_net.Net())
    net = ReservedNet()
    d = _discover(net)
    assert d.local_failures == 0 and d.stopped_by == clean.stopped_by != "local_error"
    assert [p.hops for p in d.paths] == [p.hops for p in clean.paths]
    assert net.binds and not any(port in RESERVED for port in net.binds)


def test_a_probe_that_never_leaves_says_why_by_error_name_and_code():
    class Refusing(ReservedNet):
        def refuse_bind(self, addr):
            return _refused()                      # every port, the system's too
    d = _discover(Refusing())
    assert d.stopped_by == "local_error" and d.local_failures == multipath.MAX_LOCAL_FAILURES
    assert d.local_failure_reasons == {"WSAEACCES 10013": multipath.MAX_LOCAL_FAILURES}
    assert d.stop_text == "stopped: this computer refused to send probes (WSAEACCES 10013)"
    wire = d.to_wire()
    assert wire["local_failure_reasons"] == {"WSAEACCES 10013": multipath.MAX_LOCAL_FAILURES}
    assert multipath.Discovery.from_wire(wire).local_failure_reasons == wire["local_failure_reasons"]
    wire["local_failure_reasons"] = {"192.0.2.10:40001 refused": 1}   # an agent's answer is checked
    with pytest.raises(ValueError):
        multipath.Discovery.from_wire(wire)


def test_a_flow_keeps_the_port_the_system_gave_it():
    net = ReservedNet()
    t = net.make_transport()
    seen = []
    for seq, ttl in enumerate((1, 2, 3)):
        assert t.send(4, ttl, seq + 1)
        sock = t._open[seq + 1][0]
        seen.append(sock.bound[1])
        t.forget(seq + 1)
    assert seen[0] == t.sport(4) and seen == [seen[0]] * 3 and seen[0] not in RESERVED
    assert t.flow_of(seen[0]) == 4


def test_a_kept_port_refused_once_gets_one_new_port_and_the_flow_starts_over():
    clean = _discover(odin_net.Net())
    net = StolenNet()
    d = _discover(net)
    assert net.stolen is not None and d.flows_restarted == 1 and d.local_failures == 0
    assert net.transport.sport(2) != net.stolen
    after = net.asked[[i for i, (f, _t) in enumerate(net.asked) if f == 2][1]:]
    assert (2, 1) in after                         # flow 2 was asked again from TTL 1
    assert len(d.paths) == len(clean.paths)
    for path in d.paths:                           # no path mixes two five-tuples' answers
        for f in path.flows:
            truth = odin_net.true_sequence(f)
            assert all(a is None or a == b for a, b in zip(path.hops, truth)), (path.id, f)
