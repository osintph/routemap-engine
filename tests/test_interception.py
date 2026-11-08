"""The TCP interception check of a Paths run: a SYN with TTL 1 or 2 must die at
a router. Mocked transports for the intercepted, the clean and the nearby-target
case; the split-route comparison; the check's place in the export and on the wire."""
import json

import pytest

from routemap_engine import model, multipath
from routemap_engine.probe import FlowAnswer

DST = "203.0.113.9"


class Lab:
    """A two-router path on a virtual clock. *connect[ttl]* is how the connect
    ends at that TTL ("completed", "refused"); *routers[ttl]* who answers a
    time exceeded, None for silence."""
    METHOD = "tcp-paris"
    ONE_PER_FLOW = True

    def __init__(self, connect=None, routers=None):
        self.connect = connect or {}
        self.routers = {1: "192.0.2.1", 2: "198.51.100.1"} if routers is None else routers
        self.t, self.queue, self.sent = 1000.0, [], []

    def clock(self):
        return self.t

    def send(self, flow, ttl, seq):
        self.sent.append((flow, ttl))
        at = self.t + 0.002
        how = self.connect.get(min(ttl, 3))
        if how:
            self.queue.append((at, FlowAnswer(seq, DST, True, at, how)))
        elif ttl >= 3:
            self.queue.append((at, FlowAnswer(seq, DST, True, at, "completed")))
        elif self.routers.get(ttl):
            self.queue.append((at, FlowAnswer(seq, self.routers[ttl], False, at)))
        return True

    def read(self, timeout):
        due = [q for q in self.queue if q[0] <= self.t + timeout]
        self.queue = [q for q in self.queue if q[0] > self.t + timeout]
        self.t += timeout if not due else 0.0
        if due:
            self.t = max(self.t, max(d[0] for d in due))
        return [a for _, a in due]

    def forget(self, seq):
        pass

    def close(self):
        pass


def run(lab, icmp=None, subnet=False):
    icmp = icmp if icmp is not None else {}
    return multipath.Discoverer("example.net", DST, lab, clock=lab.clock, check_interception=True, on_local_subnet=subnet,
                                icmp_check=lambda ttl: icmp.get(ttl),
                                options=multipath.Options(budget=200)).run()


def test_clean_path_is_not_intercepted():
    d = run(Lab(), {1: "192.0.2.1"})
    assert d.interception == {"checked": True, "intercepted": False, "condition": None, "guard": None, "split_hop1": None}


@pytest.mark.parametrize("how,ttl", [("completed", 1), ("completed", 2), ("refused", 1), ("refused", 2)])
def test_a_connect_ending_close_is_interception_and_named(how, ttl):
    d = run(Lab({ttl: how}))
    assert d.interception["intercepted"] is True
    assert d.interception["condition"] == f"connect_{how}_at_ttl_{ttl}"
    assert d.interception["guard"] is None


@pytest.mark.parametrize("how", ["completed", "refused"])
def test_both_endings_share_the_nearby_target_guards(how):
    subnet = run(Lab({1: how}), subnet=True).interception
    assert subnet["intercepted"] is False and subnet["guard"] == "target_on_local_subnet"
    assert subnet["condition"] == f"connect_{how}_at_ttl_1"
    echo = run(Lab({1: how}), {1: DST}).interception
    assert echo["intercepted"] is False and echo["guard"] == "icmp_echo_reached_target"
    assert run(Lab({2: how}), {1: "192.0.2.1", 2: DST}).interception["guard"] == "icmp_echo_reached_target"


def test_the_guard_looks_at_the_same_ttl():
    d = run(Lab({2: "completed"}), {1: DST, 2: None})
    assert d.interception["intercepted"] is True


def test_no_later_ttl_after_the_first_trigger():
    lab = Lab({1: "completed"})
    run(lab)
    assert (multipath.MAX_FLOWS, 2) not in lab.sent


def test_a_split_is_reported_only_when_both_protocols_answered():
    assert run(Lab(), {1: "198.51.100.200"}).interception["split_hop1"] == {"tcp": "192.0.2.1", "icmp": "198.51.100.200"}
    assert run(Lab(), {1: "192.0.2.1"}).interception["split_hop1"] is None
    assert run(Lab(), {1: None}).interception["split_hop1"] is None
    assert run(Lab(routers={1: None, 2: "198.51.100.1"}), {1: "192.0.2.1"}).interception["split_hop1"] is None


def test_an_answer_from_the_proxy_is_not_a_hop_one_router_for_the_split():
    d = run(Lab({1: "completed"}), {1: "192.0.2.1"})
    assert d.interception["split_hop1"] is None


def test_the_check_counts_in_the_budget_and_stays_outside_discovery_flows():
    plain, checked = Lab(), Lab()
    a = multipath.Discoverer("example.net", DST, plain, clock=plain.clock, options=multipath.Options(budget=200)).run()
    b = run(checked)
    assert b.probes_sent >= a.probes_sent + 4
    assert {f for f, t in checked.sent if f >= multipath.MAX_FLOWS} == set(multipath.INTERCEPTION_FLOWS)
    assert a.interception is None and "interception" not in a.to_dict()


def test_interception_reaches_the_schema_and_the_wire():
    d = run(Lab({1: "refused"}))
    jsonschema = pytest.importorskip("jsonschema")
    node = model.schema()["$defs"]["paths"]["properties"]["interception"]
    jsonschema.validate(d.to_dict()["interception"], node)
    back = multipath.Discovery.from_wire(json.loads(json.dumps(d.to_wire())))
    assert back.interception == d.interception


@pytest.mark.parametrize("bad", [{"condition": "something"}, {"guard": "x"}, {"split_hop1": "x"},
                                 {"split_hop1": {"tcp": "nope", "icmp": "192.0.2.1"}}, "x"])
def test_a_bad_interception_on_the_wire_is_refused(bad):
    wire = json.loads(json.dumps(run(Lab()).to_wire()))
    wire["interception"] = {**wire["interception"], **bad} if isinstance(bad, dict) else bad
    with pytest.raises((ValueError, KeyError, AttributeError)):
        multipath.Discovery.from_wire(wire)


def test_no_route_in_the_run_skips_the_hop_one_check(monkeypatch):
    from routemap_engine import interfaces as I, probe
    adapter = I.Adapter("eth0", "eth0", "", I.PHYSICAL, True, 7, 7, False, ["192.0.2.10"], ["192.0.2.10/24"], ["192.0.2.1"])
    binding = I.Binding(adapter, "192.0.2.10", "win32")
    lab = Lab()
    d = multipath.Discovery("example.net", DST, 4)
    d.stopped_by, d.local_failure_reasons = "local_error", {"WSAENETUNREACH 10051": 9}
    monkeypatch.setattr(multipath, "available", lambda: (True, ""))
    monkeypatch.setattr(probe, "bound_route", lambda i, a: binding)
    class Transport:
        METHOD = "tcp-paris"

        def __new__(cls, address, binding=None):
            return lab
    monkeypatch.setattr(probe, "flow_method", lambda: "tcp-paris")
    monkeypatch.setattr(probe, "TcpFlowTransport", Transport)
    monkeypatch.setattr(multipath, "icmp_checker", lambda a, binding=None: None)
    monkeypatch.setattr(multipath, "_on_local_subnet", lambda a: False)
    monkeypatch.setattr(multipath.Discoverer, "run", lambda self: d)
    monkeypatch.setattr(I, "use_after_run", lambda *a, **k: pytest.fail("hop-1 check ran"))
    got = multipath.discover("example.net", address=DST, interface="eth0")
    assert got.interface.check == I.NO_ROUTE and got.interface.selected
