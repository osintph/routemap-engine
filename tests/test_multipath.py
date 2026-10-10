"""Path discovery (0.7.0) on a simulated network and a virtual clock: the
paths a per-flow balancer offers are found at the promised confidence, each
with its own figures, inside the probe caps on every topology."""
import itertools
import random

import pytest

from routemap_engine import multipath, probe
from tests.helpers.lab import Lab

DST = "192.0.2.9"


def run(topology, *, seed=0, options=None, **lab_kw):
    lab = Lab(topology, seed=seed, **lab_kw)
    d = multipath.Discoverer("example.net", DST, lab, options=options, clock=lab.clock).run()
    return d, lab


def hops(prefix, n):
    return [f"{prefix}{i}" for i in range(1, n + 1)]


def test_the_stopping_rule_is_veitchs_table():
    assert [multipath.n_k(k) for k in range(1, 8)] == [9, 17, 24, 33, 42, 51, 60]
    assert multipath.MAX_FLOWS >= multipath.n_k(7)


def test_a_single_path_costs_nine_flows_per_hop_and_reports_one_path():
    d, lab = run(hops("r", 6) + [DST])
    assert [p.hops for p in d.paths] == [hops("r", 6) + [DST]]
    assert d.flows_used == 9
    discovery_probes = sum(1 for _, _, ttl in lab.sent if ttl != multipath.PING_HOPS)
    assert discovery_probes == 9 * 7
    assert d.paths[0].pings_sent == 10 and d.paths[0].loss_pct == 0.0 and d.stopped_by == "complete"


def test_each_path_is_one_responder_sequence_with_its_own_loss_and_rtt():
    topo = ["r1", "r2", ("branch", [["a1", "a2"], ["b1", "b2"]]), "r5", DST]
    d, _ = run(topo, seed=3, loss={})
    seqs = sorted(tuple(p.hops) for p in d.paths)
    assert seqs == [("r1", "r2", "a1", "a2", "r5", DST), ("r1", "r2", "b1", "b2", "r5", DST)]
    assert sum(len(p.flows) for p in d.paths) == d.flows_used
    for p in d.paths:
        assert p.rtt_to_target_ms is not None and len(p.rtt_ms) == len(p.hops)


def test_a_lossy_branch_shows_loss_on_its_own_path_only():
    """Loss at the destination behind one branch: the ping phase per path sees it there."""
    topo = ["r1", ("branch", [["a1"], ["b1"]]), DST]

    class Lossy(Lab):
        def send(self, flow, ttl, seq):
            if ttl == multipath.PING_HOPS and self.path(flow)[1] == "b1" and self.rng.random() < 0.5:
                self.sent.append((self.clock.t, flow, ttl))
                return
            super().send(flow, ttl, seq)
    lab = Lossy(topo, seed=11)
    d = multipath.Discoverer("example.net", DST, lab, clock=lab.clock).run()
    by_branch = {p.hops[1]: p for p in d.paths}
    assert by_branch["a1"].loss_pct == 0.0 and by_branch["b1"].loss_pct > 0


@pytest.mark.parametrize("k", [2, 3, 4, 5, 6, 7, 8])
def test_a_balanced_hop_is_found_with_95_percent_confidence(k):
    """Over many seeds (hash functions), every next hop of a k-way per-flow
    balancer is found at least 95% of the time (Veitch et al. bound all
    failure probabilities by 0.05; 300 runs leave room for sampling noise)."""
    runs, found = 300, 0
    nexts = [f"n{i}" for i in range(k)]
    for seed in range(runs):
        d, _ = run(["r1", ("flow", nexts), "r3", DST], seed=seed, options=multipath.Options(pings=0))
        found += set(d.responders[2]) == set(nexts)
    assert found / runs >= 0.95, f"{found}/{runs}"


def test_per_packet_balancing_is_labelled_and_does_not_split_paths():
    d, _ = run(["r1", ("packet", ["p1", "p2"]), "r3", DST], seed=5)
    assert d.per_packet_hops == [2]
    assert len(d.paths) == 1 and d.paths[0].hops[1] is None


def test_a_silent_router_does_not_make_paths_of_its_own():
    d, _ = run(["r1", "r2", ("flow", ["a", "b"]), "r4", DST], seed=2, loss={"r2": 0.3})
    assert len(d.paths) == 2 and all(p.hops[1] in ("r2", None) for p in d.paths)


def test_three_silent_hops_end_discovery():
    d, lab = run(["r1", "s2", "s3", "s4", "r5", DST], silent={"s2", "s3", "s4"})
    assert d.stopped_by == "gap" and max(t for _, _, t in lab.sent if t != multipath.PING_HOPS) == 4


def _topologies(n):
    rng = random.Random(42)
    for i in range(n):
        topo = []
        for h in range(rng.randint(3, 20)):
            kind = rng.random()
            if kind < 0.6:
                topo.append(f"h{h}")
            elif kind < 0.8:
                topo.append(("flow", [f"h{h}x{j}" for j in range(rng.randint(2, 9))]))
            elif kind < 0.9:
                topo.append(("branch", [[f"h{h}b{j}s{s}" for s in range(rng.randint(1, 3))]
                                        for j in range(rng.randint(2, 4))]))
            else:
                topo.append(("packet", [f"h{h}p{j}" for j in range(2)]))
        yield topo + [DST], {f"h{h}" for h in range(30) if rng.random() < 0.1}


def test_no_topology_ever_exceeds_20_probes_in_any_second_or_the_budget():
    for topo, silent in _topologies(60):
        for budget in (1500, 300):
            d, lab = run(topo, seed=len(topo), silent=silent, options=multipath.Options(budget=budget))
            times = [t for t, _, _ in lab.sent]
            assert len(times) == d.probes_sent <= budget
            j = 0
            for i, t in enumerate(times):
                while times[j] <= t - 1.0:
                    j += 1
                assert i - j + 1 <= 20, f"{i - j + 1} probes within one second"
            assert d.flows_used <= multipath.MAX_FLOWS


def test_caps_can_be_lowered_never_raised():
    o = multipath.Options(budget=10**6, rate=1000, max_hops=255, wait=60, pings=99).clamped()
    assert (o.budget, o.rate, o.max_hops, o.pings) == (1500, 20.0, 30, 10) and o.wait <= probe.MAX_WAIT_SECONDS
    assert multipath.Options(budget=200, rate=5).clamped().budget == 200


def test_cancel_stops_before_the_next_probe():
    import threading
    stop = threading.Event()
    lab = Lab(hops("r", 20) + [DST])
    seen = []

    def on_progress(p):
        seen.append(p)
        if p["ttl"] == 3:
            stop.set()
    d = multipath.Discoverer("example.net", DST, lab, clock=lab.clock, cancel=stop, on_progress=on_progress).run()
    assert d.stopped_by == "cancel" and max(t for _, _, t in lab.sent) == 3 and lab.closed


def test_a_flow_that_changes_its_fields_breaks_the_path_and_the_lab_shows_it():
    """Control: if a flow's header fields varied per probe (classic traceroute),
    the balancers would scatter it; the lab hashes the fields, not the flow id."""
    counter = itertools.count()
    lab = Lab(["r1", ("flow", ["a", "b", "c", "d"]), DST], seed=1,
              flow_fields=lambda flow: (1, next(counter)))
    assert len({lab.path(0)[1] for _ in range(40)}) > 1


def test_the_trace_text_lists_every_responder_and_parses_back():
    from routemap_engine import parse_trace
    d, _ = run(["r1", ("flow", ["192.0.2.21", "192.0.2.22"]), DST], seed=4)
    d.responders = {1: ["192.0.2.1"], **{k: v for k, v in d.responders.items() if k > 1}}
    d.rtts[(1, "192.0.2.1")] = [1.0]
    hop = parse_trace(d.trace_text()).hops[1]
    assert set(hop.addresses) == {"192.0.2.21", "192.0.2.22"}


def test_a_rate_limiting_router_does_not_make_the_discovery_add_flows_for_nothing():
    """Measured to heise.de (10 Oct 2026): a router answering about 1 probe in
    3 drew 25 flows on a single path. Over 200 hash seeds at that rate and
    worse, a single-path discovery never needs more than two growth rounds
    (17 flows); before the fix it reached 38 at 67% silence and 64 at 80%."""
    for loss in (0.67, 0.8):
        worst = max(run(["r1", "r2", "rl3", "r4", DST], seed=seed, loss={"rl3": loss},
                        options=multipath.Options(pings=0))[0].flows_used for seed in range(200))
        assert worst <= 17, (loss, worst)


def test_a_rate_limiting_balancer_still_shows_both_branches_most_of_the_time():
    """The price of the rule above, kept visible: with both branches answering
    a third of their probes, both are still found in at least 90% of runs."""
    found = sum(set(run(["r1", ("flow", ["a", "b"]), "r3", DST], seed=seed, loss={"a": 0.67, "b": 0.67},
                        options=multipath.Options(pings=0))[0].responders.get(2, [])) == {"a", "b"}
                for seed in range(200))
    assert found >= 180, found
