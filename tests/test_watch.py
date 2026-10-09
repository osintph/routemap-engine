"""Continuous mode, against a virtual clock and a scripted network.

Generalised over the classes the brief names: the statistics match a direct
computation over random samples; ECMP alternation is never a path change
however the addresses alternate; a real change is reported once, at the cycle
it began; sleep is a gap, never loss; no cycle ever probes faster than the
cap; the limits cannot be talked out of their ranges.
"""
import json
import random
import statistics
import threading

from concurrent.futures import Future

import pytest

from routemap_engine import geo, probe, watch


class SyncPool:
    """Runs each probe at the moment it is submitted, so a probe's recorded
    time is its send time (worker threads would run it a little later)."""

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, fn, *args):
        f = Future()
        try:
            f.set_result(fn(*args))
        except Exception as exc:  # noqa: BLE001
            f.set_exception(exc)
        return f


@pytest.fixture(autouse=True)
def synchronous_probes(request, monkeypatch):
    if not request.node.get_closest_marker("real_pool"):
        monkeypatch.setattr(watch, "ThreadPoolExecutor", SyncPool)


class Clock:
    def __init__(self):
        self.t = 1_791_500_000.0
        self.m = 1000.0
        self.lock = threading.Lock()

    def wall(self):
        return self.t

    def mono(self):
        return self.m

    def sleep(self, s):
        with self.lock:
            self.t += s
            self.m += s

    def jump(self, wall=0.0, mono=0.0):
        with self.lock:
            self.t += wall
            self.m += mono


class Net:
    """script(cycle, ttl) -> (address or None, rtt or None, reached)."""

    def __init__(self, clock, script, depth=6):
        self.clock, self.script, self.depth = clock, script, depth
        self.sends = []          # (mono time, ttl)
        self.cycle = 0
        self.lock = threading.Lock()

    def probe(self, dst, ttl, seq, wait):
        with self.lock:
            self.sends.append((self.clock.mono(), ttl))
            if ttl == 1:
                self.cycle += 1
            c = self.cycle
        addr, rtt, reached = self.script(c, ttl)
        return probe.Reply(addr, rtt, reached)


def straight(depth=6, loss=None, rtt=lambda c, t: 10.0 * t):
    loss = loss or {}

    def script(c, t):
        if t > depth:
            return None, None, False
        if random.random() < loss.get(t, 0.0):
            return None, None, False
        return f"192.0.2.{t}", rtt(c, t), t == depth
    return script


def run(script, *, cycles=50, interval=1.0, clock=None, on_cycle=None, **opts):
    clock = clock or Clock()
    net = Net(clock, script)
    w = watch.Watch("example.net", watch.WatchOptions(interval=interval, max_cycles=cycles, **opts),
                    probe_fn=net.probe, resolve=lambda _t: "192.0.2.6",
                    wall=clock.wall, mono=clock.mono, sleep=clock.sleep, on_cycle=on_cycle)
    return w, w.run(), net, clock


# ---------------------------------------------------------------- statistics --

def test_stats_match_a_direct_computation():
    rng = random.Random(9)
    for _ in range(200):
        values = [None if rng.random() < 0.2 else rng.uniform(1, 400) for _ in range(rng.randint(1, 80))]
        s = watch.HopStats()
        for v in values:
            s.add(v)
        got = [v for v in values if v is not None]
        assert s.sent == len(values) and s.received == len(got)
        assert s.loss_pct == pytest.approx(100 * (len(values) - len(got)) / len(values))
        if got:
            assert s.best == min(got) and s.worst == max(got) and s.last == got[-1]
            assert s.avg == pytest.approx(statistics.fmean(got))
            assert s.stdev == pytest.approx(statistics.pstdev(got), abs=1e-9)
        else:
            assert s.avg is None and s.stdev is None


def test_session_counts_every_probe():
    random.seed(1)
    _, s, _, _ = run(straight(loss={3: 0.4}), cycles=100)
    assert s.cycles == 100 and s.reached_hop == 6
    hops = {h["hop"]: h for h in s.hops()}
    assert all(h["sent"] == 100 for h in hops.values())
    assert 20 < hops[3]["loss_pct"] < 60 and hops[6]["loss_pct"] == 0


def test_intermediate_loss_is_rate_limiting_and_destination_loss_is_real():
    random.seed(2)
    _, s, _, _ = run(straight(loss={3: 0.5, 6: 0.1}), cycles=200)
    hops = {h["hop"]: h for h in s.hops()}
    assert geo.ANNOT_ICMP_LIMIT in hops[3]["annotations"]
    v = s.loss()
    assert v["reached"] and v["loss_pct"] == hops[6]["loss_pct"] > 0 and 3 in v["rate_limited"]


# -------------------------------------------------------------- path changes --

@pytest.mark.parametrize("pattern", ["every probe", "every other pair", "random"])
def test_ecmp_alternation_is_never_a_change(pattern):
    rng = random.Random(4)

    def script(c, t):
        if t == 4:
            pick = {"every probe": c % 2, "every other pair": (c // 2) % 2, "random": rng.random() < 0.5}[pattern]
            return ("198.51.100.1" if pick else "198.51.100.2"), 40.0, False
        return f"192.0.2.{t}", 10.0 * t, t == 6
    _, s, _, _ = run(script, cycles=300)
    assert s.changes == [], s.changes
    assert sorted(s.addresses[4]) == ["198.51.100.1", "198.51.100.2"]


def test_a_real_change_is_reported_once_at_the_cycle_it_began():
    def script(c, t):
        if t == 4:
            return ("198.51.100.9" if c > 100 else "198.51.100.1"), 40.0, False
        return f"192.0.2.{t}", 10.0 * t, t == 6
    _, s, _, _ = run(script, cycles=200)
    assert len(s.changes) == 1, s.changes
    ch = s.changes[0]
    assert ch["hop"] == 4 and ch["kind"] == "address" and ch["cycle"] == 101
    assert ch["old"] == ["198.51.100.1"] and ch["new"] == ["198.51.100.9"]
    assert ch["confirmed_cycle"] <= 101 + 2 * watch.WINDOW


def test_an_ecmp_pair_losing_one_member_is_a_change():
    def script(c, t):
        if t == 4:
            return ("198.51.100.1" if c % 2 or c > 120 else "198.51.100.2"), 40.0, False
        return f"192.0.2.{t}", 10.0 * t, t == 6
    _, s, _, _ = run(script, cycles=220)
    assert [(c["hop"], c["old"], c["new"]) for c in s.changes] == [
        (4, ["198.51.100.1", "198.51.100.2"], ["198.51.100.1"])]


def test_a_hop_that_goes_silent_and_comes_back():
    def script(c, t):
        if t == 3 and 80 < c <= 160:
            return None, None, False
        return f"192.0.2.{t}", 10.0 * t, t == 6
    _, s, _, _ = run(script, cycles=260)
    assert [c["kind"] for c in s.changes] == ["disappeared", "appeared"]


def test_the_destination_moving_is_a_change():
    def script(c, t):
        depth = 6 if c <= 100 else 5
        if t > depth:
            return None, None, False
        return f"192.0.2.{t}", 10.0 * t, t == depth
    _, s, _, _ = run(script, cycles=200)
    kinds = [c["kind"] for c in s.changes]
    assert "destination" in kinds and s.reached_hop == 5


def test_occasional_silence_at_a_rate_limited_hop_is_not_a_change():
    rng = random.Random(5)

    def script(c, t):
        if t == 3 and rng.random() < 0.4:
            return None, None, False
        return f"192.0.2.{t}", 10.0 * t, t == 6
    _, s, _, _ = run(script, cycles=400)
    assert s.changes == []


# ------------------------------------------------------------------- limits --

@pytest.mark.parametrize("asked,expected", [(0.0, 1.0), (0.2, 1.0), (-5, 1.0), (float("nan"), 1.0),
                                            ("x", 1.0), (2.5, 2.5), (1000, 60.0)])
def test_the_interval_cannot_go_below_one_second(asked, expected):
    assert watch.WatchOptions(interval=asked).clamped().interval == expected


@pytest.mark.parametrize("asked,expected", [(1, 300.0), (3600, 3600.0), (10**9, 8 * 3600.0)])
def test_session_length_is_bounded(asked, expected):
    assert watch.WatchOptions(duration=asked).clamped().duration == expected


@pytest.mark.parametrize("hops", [1, 6, 30])
@pytest.mark.parametrize("interval", [1.0, 2.0, 0.1])
def test_probes_never_exceed_the_rate_cap(hops, interval):
    def script(c, t):
        return f"192.0.2.{t}", 1.0, t == hops
    _, s, net, _ = run(script, cycles=20, interval=interval)
    times = sorted(t for t, _ in net.sends)
    for i in range(len(times)):
        window = [x for x in times[i:] if x - times[i] < 1.0]
        assert len(window) <= watch.MAX_RATE + 1e-9, (hops, interval, len(window))
    # And never more than one cycle per (clamped) interval.
    assert s.cycles == 20 and (net.sends[-1][0] - net.sends[0][0]) >= 19 * max(1.0, interval) - 1e-6


def test_silent_tail_is_probed_only_max_unknown_deep():
    def script(c, t):
        return (f"192.0.2.{t}", 10.0, False) if t <= 4 else (None, None, False)
    _, s, net, _ = run(script, cycles=10)
    first_cycle = net.sends[:30]
    later = net.sends[30:]
    assert max(t for _, t in first_cycle) == 30            # the first cycle finds the path
    assert later and max(t for _, t in later) == 4 + watch.MAX_UNKNOWN


def test_the_session_stops_at_its_duration():
    _, s, _, _ = run(straight(), cycles=None, duration=300)
    assert s.stopped_by == "duration" and s.cycles == 300


def test_ipv6_is_refused():
    clock = Clock()
    w = watch.Watch("example.net", probe_fn=lambda *a: probe.Reply(None, None),
                    resolve=lambda _t: "2001:db8::1", wall=clock.wall, mono=clock.mono, sleep=clock.sleep)
    with pytest.raises(ValueError, match="needs an IPv4 address"):
        w.run()


# -------------------------------------------------------------- sleep, pause --

@pytest.mark.parametrize("kind", ["sleep", "suspend"])
def test_sleep_or_suspend_is_a_gap_not_loss(kind):
    clock = Clock()

    def script(c, t):
        if c == 30 and t == 3:
            # The machine sleeps mid-cycle: wall time jumps; a suspended
            # process sees monotonic time jump too.
            clock.jump(wall=600, mono=600 if kind == "suspend" else 0)
            return None, None, False
        return f"192.0.2.{t}", 10.0 * t, t == 6
    _, s, _, _ = run(script, cycles=60, clock=clock)
    hops = {h["hop"]: h for h in s.hops()}
    assert all(h["loss_pct"] == 0 for h in hops.values()), hops
    assert len(s.gaps) == 1 and s.gaps[0]["to"] - s.gaps[0]["from"] >= 600
    assert s.cycles == 60 and all(h["sent"] == 60 for h in hops.values())


def test_pause_sends_nothing_and_reset_clears_the_counters():
    clock = Clock()
    seen = {"paused_sends": None}
    net = Net(clock, straight())
    w = None

    def on_cycle(s):
        if s.cycles == 10:
            w.pause()
            before = len(net.sends)
            # While paused, time passes but no probe is sent.
            for _ in range(5):
                clock.sleep(1)
            seen["paused_sends"] = len(net.sends) - before
            w.reset()
            w.resume()
    w = watch.Watch("example.net", watch.WatchOptions(max_cycles=20), probe_fn=net.probe,
                    resolve=lambda _t: "192.0.2.6", wall=clock.wall, mono=clock.mono, sleep=clock.sleep,
                    on_cycle=on_cycle)
    s = w.run()
    assert seen["paused_sends"] == 0
    assert all(h["sent"] == 10 for h in s.hops()) and len(s.resets) == 1


def test_stop_from_another_thread_ends_the_session():
    clock = Clock()
    net = Net(clock, straight())
    w = watch.Watch("example.net", probe_fn=net.probe, resolve=lambda _t: "192.0.2.6",
                    wall=clock.wall, mono=clock.mono, sleep=clock.sleep,
                    on_cycle=lambda s: w.stop() if s.cycles == 7 else None)
    s = w.run()
    assert s.cycles == 7 and s.stopped_by == "user"


# ------------------------------------------------------------------- export --

def test_the_session_is_json_and_keeps_raw_then_buckets(monkeypatch):
    monkeypatch.setattr(watch, "RAW_SECONDS", 120)
    _, s, _, _ = run(straight(), cycles=400)
    d = json.loads(json.dumps(s.to_dict()))
    assert d["cycles"] == 400 and d["stopped_by"] == "count" and d["reached_hop"] == 6
    six = d["samples"]["hops"]["6"]
    assert len(six["raw"]) == 120 and all(t < 120 for t, _ in six["raw"])
    assert sum(b["sent"] for b in six["buckets"]) == 400
    assert d["loss"]["reached"] and d["hops"][-1]["hop"] == 6


def test_only_new_addresses_need_placing():
    def script(c, t):
        if t == 4:
            return ("198.51.100.9" if c > 50 else "198.51.100.1"), 40.0, False
        return f"192.0.2.{t}", 10.0 * t, t == 6
    _, s, _, _ = run(script, cycles=100)
    placed = [{"hop": n, "addresses": [f"192.0.2.{n}"] if n != 4 else ["198.51.100.1"]} for n in range(1, 7)]
    new = watch.new_hops(s, placed)
    assert [(h.hop, h.addresses) for h in new] == [(4, ["198.51.100.9"])]


@pytest.mark.real_pool
def test_the_real_thread_pool_collects_every_reply():
    _, s, net, _ = run(straight(depth=8), cycles=25)
    assert s.cycles == 25 and s.reached_hop == 8
    assert all(h["sent"] == 25 and h["received"] == 25 for h in s.hops())
