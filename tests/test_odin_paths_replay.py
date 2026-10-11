"""The ODIN Paths run of 11 Oct 2026 (0.4.0-beta.1, FAIL), replayed through
the real Windows TCP prober (tests/helpers/odin_net.py). Each test is one of
the faults that run showed; each failed on the code that produced it."""
import asyncio

import pytest

from helpers import odin_net
from routemap_engine import analyse_paths, multipath
from routemap_engine.geo import Sources


def _run():
    net = odin_net.Net()
    progress = []
    import time
    from routemap_engine import probe
    try:
        d = multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                 deadline=net.clock() + 3600, on_progress=progress.append).run()
    finally:
        probe.time = time
    return net, d, progress


@pytest.fixture(scope="module")
def run():
    return _run()


def _truth(m):
    """The paths the replayed network has for flows 0..m-1, worked out here
    without the discoverer's code: distinct true sequences, merged only where
    one has a silent router and the other an answer."""
    seqs = sorted({odin_net.true_sequence(f) for f in range(m)}, key=repr)
    merged = []
    for s in seqs:
        for i, r in enumerate(merged):
            if len(r) == len(s) and all(a is None or b is None or a == b for a, b in zip(r, s)):
                merged[i] = tuple(a if a is not None else b for a, b in zip(r, s))
                break
        else:
            merged.append(s)
    return merged


def test_1_paths_differ_only_where_two_flows_got_different_answers(run):
    net, d, progress = run
    truth = _truth(d.flows_used)
    assert len(d.paths) == min(len(truth), multipath.MAX_PATHS), (len(d.paths), len(truth))
    for i, a in enumerate(d.paths):
        for b in d.paths[i + 1:]:
            assert any(x and y and x != y for x, y in zip(a.hops, b.hops)) or len(a.hops) != len(b.hops), \
                (a.id, b.id, "differ nowhere both answered")
    # The progress count is the same grouping, never a count of silences.
    assert max(p["paths"] for p in progress) <= len(truth)


def test_3_a_flow_ends_at_the_target_once(run):
    net, d, _ = run
    for p in d.paths:
        assert p.hops.count(odin_net.TARGET) == 1 and p.hops[-1] == odin_net.TARGET, (p.id, p.hops)
    ends = {len(p.hops) for p in d.paths}
    assert ends <= {13, 14, 15}
    rows = [line.split()[0] for line in d.trace_text().splitlines()[1:] if odin_net.TARGET in line]
    assert {int(r) for r in rows} == ends, rows


def test_5_time_stays_near_the_rate_cap(run):
    """1,500 probes at 20 a second is 75 s of sending; waits for silent
    probes overlap with sending. The 0.4.0-beta.1 run took 342 s for 1,453."""
    net, d, _ = run
    floor = d.probes_sent / multipath.MAX_RATE
    assert d.seconds <= floor * 1.6 + 20, (d.seconds, d.probes_sent)


def test_6_the_targets_reuse_limit_is_not_reported_as_loss(run):
    net, d, _ = run
    for p in d.paths:
        if p.reached:
            assert p.pings_sent == multipath.PATH_PINGS and p.pings_lost == 0, (p.id, p.pings_lost)
    assert d.local_failures == 0


def test_2_one_address_one_placement(run):
    """The IP database puts 62.115.153.153 in Chicago; between Frankfurt hops
    that is a detour the RTT rules out, on every row it appears on, main or
    path. Every address shows one placement in the whole run."""
    net, d, _ = run

    async def ip_db(addresses):
        out = {}
        for a in addresses:
            place = odin_net.PLACES.get(a)
            if a == "62.115.153.153":
                place = "Chicago, US"
            if place in odin_net.CITIES:
                lat, lon = odin_net.CITIES[place]
                out[a] = {"lat": lat, "lon": lon, "city": place.split(",")[0], "cc": place.split(", ")[-1]}
        return out
    route = asyncio.run(analyse_paths(d, (14.6, 121.0), sources=Sources(hoiho=None, ip_db=ip_db, ptr=None)))
    seen: dict[str, set] = {}
    for h in route.hops:
        seen.setdefault(h["address"], set()).add((h.get("place"), h.get("source")))
    for p in route.paths["paths"]:
        for h in p["located"]:
            if h.get("address"):
                seen.setdefault(h["address"], set()).add((h.get("place"), h.get("source")))
    split = {a: v for a, v in seen.items() if a and len(v) > 1}
    assert not split, split
    assert all(place != "Chicago, US" for place, _src in seen["62.115.153.153"]), seen["62.115.153.153"]


class _ShyTarget(odin_net.Net):
    """The replayed network, but the target ignores each flow's first two
    connection attempts (whatever the cause; on ODIN the target answered
    hops after the path's last router)."""

    def __init__(self):
        super().__init__()
        self.tries: dict[int, int] = {}

    def answer(self, sock):
        flow = sock.bound[1] - self.transport._base
        end = max(odin_net.PATHS[odin_net.letter_of(flow)])
        if sock.ttl >= end and sock.ttl != 64:
            self.tries[flow] = self.tries.get(flow, 0) + 1
            if self.tries[flow] <= 2:
                return
        super().answer(sock)


def test_3_silences_at_the_targets_hop_do_not_move_the_target():
    import time
    from routemap_engine import probe
    net = _ShyTarget()
    try:
        d = multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                 deadline=net.clock() + 3600).run()
    finally:
        probe.time = time
    true_ends = {max(odin_net.PATHS[odin_net.letter_of(f)]) for f in range(d.flows_used)}
    rows = {int(line.split()[0]) for line in d.trace_text().splitlines()[1:] if odin_net.TARGET in line}
    assert rows == true_ends, (rows, true_ends)
    for p in d.paths:
        assert p.hops.count(odin_net.TARGET) == 1, (p.id, p.hops)


class _Retransmits(odin_net.Net):
    """The 0.4.0-beta.2 test build on ODIN: the target ignored some first SYNs
    and Windows sent them again about 1 s later, so the answer came 1.25 s
    after the probe (13a 808.5 ms, 14a 1322.1 ms in the hop table, against
    about 250 ms for the paths)."""

    def __init__(self):
        super().__init__()
        self.seen: set[int] = set()

    def answer(self, sock):
        flow = sock.bound[1] - self.transport._base
        end = max(odin_net.PATHS[odin_net.letter_of(flow)])
        if sock.ttl >= end and flow % 3 == 0 and flow not in self.seen:
            self.seen.add(flow)
            sock.error, sock.ready_at = 0, self.clock.t + 1.25      # the retransmission answered
            return
        super().answer(sock)


def test_a_a_retransmitted_answer_does_not_time_the_hop():
    import time
    from routemap_engine import probe
    net = _Retransmits()
    try:
        d = multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                 deadline=net.clock() + 3600).run()
    finally:
        probe.time = time
    target_rtts = [r for (ttl, a), rs in d.rtts.items() if a == odin_net.TARGET for r in rs]
    assert target_rtts and max(target_rtts) <= 1000.0, sorted(target_rtts)[-5:]
    for line in d.trace_text().splitlines()[1:]:
        if odin_net.TARGET in line:
            assert all(float(x) < 1000 for x in __import__("re").findall(r"(\d+\.\d+) ms", line)), line
