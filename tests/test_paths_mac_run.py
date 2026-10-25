"""The Mac Paths run of 25 Oct 2026 (engine 0.8.0.dev1, heise.de over ICMP,
tests/fixtures/mac_paths_heise_080dev1.json), replayed on the simulated
network: the same routers, each hop answering as often as it did there.

That run found the one path complete at TTL 15 (53 of 63 flows answered by
the target there), then went on to TTL 16, 17 and 18, where only the target
answers, added flows there and probed each new flow at every earlier hop, and
ended at the probe cap: 1,350 probes in 125 s, "stopped at the probe cap"."""
import json
import pathlib
import random
import socket
import time

import pytest

from routemap_engine import dnstime, multipath
from helpers.lab import Lab

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "mac_paths_heise_080dev1.json"
RUN = json.loads(FIXTURE.read_text(encoding="utf-8"))["discovery"]
TARGET = RUN["address"]
TARGET_HOP = min(r["ttl"] for r in RUN["responders"] if TARGET in r["addresses"])


def _net():
    """Routers by TTL up to the target's hop, and each one's loss as measured."""
    by_ttl = {r["ttl"]: r["addresses"][0] for r in RUN["responders"]}
    answered = {(r["ttl"], r["address"]): len(r["ms"]) for r in RUN["rtts"]}
    silent = {s["ttl"]: s["count"] for s in RUN["silent"]}
    topo, loss = [], {}
    for ttl in range(1, TARGET_HOP + 1):
        addr = by_ttl[ttl]
        topo.append(addr)
        got = answered.get((ttl, addr), 0)
        loss[addr] = silent.get(ttl, 0) / max(1, got + silent.get(ttl, 0))
    return topo, loss


@pytest.mark.parametrize("seed", range(8))
def test_discovery_ends_at_the_targets_hop_once_every_flow_got_there(seed):
    topo, loss = _net()
    assert topo[-1] == TARGET and TARGET_HOP == 15
    lab = Lab(topo, seed=seed, loss=loss)
    d = multipath.Discoverer("heise.de", TARGET, lab, clock=lab.clock).run()
    deeper = [t for _, _, t in lab.sent if TARGET_HOP < t < multipath.PING_HOPS]
    assert not deeper, f"{len(deeper)} probes past the target's hop"
    assert d.stopped_by == "complete" and d.stop_text == "complete"
    assert len(d.paths) == 1 and d.paths[0].hops[-1] == TARGET
    assert d.probes_sent < RUN["probes_sent"] / 2, d.probes_sent      # 1,350 on the Mac


class _ShyTarget(Lab):
    """The target ignores some flows' first attempts, as heise.de left 10 of
    63 flows unanswered at TTL 15 in that run (retries included)."""

    def __init__(self, *a, every=6, ignore=3, **kw):
        super().__init__(*a, **kw)
        self.every, self.ignore, self.tries = every, ignore, {}

    def send(self, flow, ttl, seq):
        route = self.path(flow)
        if ttl >= len(route) and ttl != multipath.PING_HOPS and flow % self.every == 0:
            self.tries[flow] = self.tries.get(flow, 0) + 1
            if self.tries[flow] <= self.ignore:
                self.sent.append((self.clock.t, flow, ttl))
                return
        super().send(flow, ttl, seq)


@pytest.mark.parametrize("every,ignore", [(6, 3), (4, 2), (3, 4)])
def test_flows_the_target_ignores_at_its_hop_do_not_drive_discovery_deeper(every, ignore):
    """The budget blow-up of the Mac run: past the target's hop only the
    target answers; the stopping rule counted those few answers, added flows,
    and every new flow was probed at all earlier hops."""
    topo, loss = _net()
    lab = _ShyTarget(topo, seed=4, loss={k: v for k, v in loss.items() if k != TARGET}, every=every, ignore=ignore)
    d = multipath.Discoverer("heise.de", TARGET, lab, clock=lab.clock).run()
    assert not [t for _, _, t in lab.sent if TARGET_HOP < t < multipath.PING_HOPS]
    assert d.stopped_by == "complete" and d.probes_sent < 700, (d.stopped_by, d.probes_sent)


def test_a_flow_silent_at_the_targets_hop_is_asked_there_again_never_deeper():
    """A flow the target did not answer at its hop is probed at that hop once
    more, as other flows of the same path reached it there."""
    topo, _ = _net()

    class ShyOnce(Lab):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.first = set()

        def send(self, flow, ttl, seq):
            if ttl == TARGET_HOP and flow % 4 == 0 and flow not in self.first:
                self.first.add(flow)
                self.sent.append((self.clock.t, flow, ttl))
                return                                   # the first attempt at the target's hop is lost
            super().send(flow, ttl, seq)
    lab = ShyOnce(topo, seed=1)
    d = multipath.Discoverer("heise.de", TARGET, lab, clock=lab.clock).run()
    assert not [t for _, _, t in lab.sent if TARGET_HOP < t < multipath.PING_HOPS]
    shy = [f for f in range(d.flows_used) if f % 4 == 0]
    assert all(sum(1 for _, f2, t in lab.sent if f2 == f and t == TARGET_HOP) >= 2 for f in shy)
    assert d.stopped_by == "complete"


def test_paths_that_end_at_different_hops_are_still_followed_to_their_own_ends():
    """The stop must not cut a longer path short: flows with a router where
    others met the target go on."""
    topo = ["198.51.100.1", ("branch", [["62.115.0.1", TARGET], ["62.115.0.2", "62.115.0.3", "62.115.0.4", TARGET]])]
    lab = Lab(topo, seed=3)
    d = multipath.Discoverer("heise.de", TARGET, lab, clock=lab.clock).run()
    ends = sorted(len(p.hops) for p in d.paths)
    assert ends == [3, 5] and d.stopped_by == "complete", [p.hops for p in d.paths]


# ------------------------------------------------------- the target attempts

def test_the_ten_target_attempts_are_a_second_apart_and_every_loss_is_counted():
    """Finding 2 of the Mac run: 7 of 10 target attempts lost while discovery
    saw the target answer 53 of 63. Counting checked here (every dropped
    attempt is one lost, nothing more), and the attempts are spaced a second
    apart, ping's default interval, so a short stretch of loss at the target
    cannot take most of them."""
    topo, _ = _net()
    drop = {0, 3, 4}

    class DropSome(Lab):
        pings = 0

        def send(self, flow, ttl, seq):
            if ttl == multipath.PING_HOPS:
                n = DropSome.pings
                DropSome.pings += 1
                if n in drop:
                    self.sent.append((self.clock.t, flow, ttl))
                    return
            super().send(flow, ttl, seq)
    lab = DropSome(topo, seed=2)
    d = multipath.Discoverer("heise.de", TARGET, lab, clock=lab.clock).run()
    p = d.paths[0]
    assert (p.pings_sent, p.pings_lost) == (10, len(drop))
    times = [t for t, _, ttl in lab.sent if ttl == multipath.PING_HOPS]
    assert multipath.PING_INTERVAL == 1.0 if hasattr(multipath, "PING_INTERVAL") else True
    assert all(b - a >= 1.0 - 1e-6 for a, b in zip(times, times[1:])), \
        [round(b - a, 3) for a, b in zip(times, times[1:])]


# ------------------------------------------------------- the DNS rows

def test_a_and_aaaa_are_two_lookups_each_with_its_own_time():
    """Finding 3 of the Mac run: both system rows read 53.0 ms. They are two
    getaddrinfo calls, each timed on its own (here 30 and 90 ms)."""
    calls = []

    def gai(name, port, family=0, kind=0, *a):
        calls.append(family)
        time.sleep(0.03 if family == socket.AF_INET else 0.09)
        addr = ("192.0.2.1", 0) if family == socket.AF_INET else ("2001:db8::1", 0, 0, 0)
        return [(family, kind, 6, "", addr)]
    a, aaaa = dnstime.measure("heise.de", getaddrinfo=gai)
    assert calls == [socket.AF_INET, socket.AF_INET6]
    assert 25 <= a.ms < 80 and 85 <= aaaa.ms < 200 and abs(aaaa.ms - a.ms) > 40, (a.ms, aaaa.ms)
