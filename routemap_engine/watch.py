"""
Continuous mode: one target, probed again and again, mtr style.

Each cycle sends one ICMP echo probe per hop with the built-in prober's own
per-platform probe function, spaced evenly across the interval and never
faster than the rate cap, and waits for them together. Per hop it keeps sent,
received, loss, last, best, average, worst and jitter (the standard deviation,
by Welford's online method), the samples for a plot, and the path changes.

WHY THESE LIMITS
----------------
They follow mtr, the tool people compare this with:

* One cycle a second by default, and never faster: mtr's default interval is
  one second and only root may go below it ("The default value for this
  parameter is one second. The root user may choose values between zero and
  one", mtr(8); ui/mtr.c refuses "an interval < 1.0 seconds" without root).
  The engine never runs as root, so 1 s is the floor.
* Probes spread over the interval: mtr spaces them interval / hops apart
  (calc_deltatime in ui/net.c), so 30 hops at 1 s are 30 probes a second. That
  is the cap here, whatever the interval or the hop count.
* 1 s wait for each reply, as the single trace and mtr (WaitTime = 1.0).
* 5 s grace for late replies when a session ends (mtr's --gracetime default).
* After 5 silent hops in a row past the last that answered, no deeper hops are
  probed (mtr(8): --max-unknown "Default is 5"; ui/mtr.c sets 12; the smaller
  value sends fewer probes).
* A session stops by itself after an hour by default and 8 hours at most, so a
  forgotten window does not probe for days. mtr has no such limit; this one is
  ours.

PATH CHANGES
------------
A hop's answering addresses are compared over windows of WINDOW cycles, not
probe by probe: a router pair behind ECMP that alternates every probe gives
the same set in every window and is never a change. A change is reported when
the set of the last WINDOW cycles equals the set of the WINDOW cycles before
it (so it has held for 2 x WINDOW cycles) and differs from the hop's settled
set. Silence is the empty set, so a hop appearing or disappearing is a change
of the same kind. The destination moving to another hop count is a change too.

SLEEP AND SUSPEND
-----------------
When the machine sleeps or the process is stopped, the probes in flight did
not get a fair wait. A cycle whose wall time or monotonic time runs well past
its schedule is thrown away whole: nothing in it counts as sent or lost, the
plot shows a gap, and the session records the gap with its start and end.

IPv4 or IPv6 (0.7.0), as the built-in prober; ``WatchOptions.family``
chooses for a dual-stack name. RIPE Atlas is never used here.
"""
from __future__ import annotations

import ipaddress
import math
import secrets
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from routemap_engine import geo, probe
from routemap_engine.parse import Hop

INTERVAL_DEFAULT = 1.0
INTERVAL_MIN = 1.0
INTERVAL_MAX = 60.0
MAX_RATE = 30.0                  # probes a second, all hops together
WAIT = 1.0
GRACE = 5.0
MAX_UNKNOWN = 5
DURATION_DEFAULT = 3600.0
DURATION_MIN = 300.0
DURATION_MAX = 8 * 3600.0
WINDOW = 10                      # cycles per path-change window
RAW_SECONDS = 1800               # raw samples kept for the export
LIVE_SAMPLES = 3600              # raw samples kept per hop for the live plot
BUCKET_SECONDS = 60
# A cycle that ran this much past its schedule spanned a sleep or a suspend.
GAP_SLACK = 2.0


def _clamp(value, low, high, default):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(v):
        return default
    return max(low, min(high, v))


@dataclass
class WatchOptions:
    interval: float = INTERVAL_DEFAULT
    max_hops: int = probe.MAX_HOPS
    duration: float = DURATION_DEFAULT
    max_cycles: int | None = None
    family: str = "auto"                 # "auto", "4" or "6", as probe.resolve

    def clamped(self) -> "WatchOptions":
        """The same options with every value forced into its allowed range."""
        cycles = None if self.max_cycles is None else max(1, int(_clamp(self.max_cycles, 1, 10**9, 1)))
        return WatchOptions(interval=_clamp(self.interval, INTERVAL_MIN, INTERVAL_MAX, INTERVAL_DEFAULT),
                            max_hops=int(_clamp(self.max_hops, 1, probe.MAX_HOPS, probe.MAX_HOPS)),
                            duration=_clamp(self.duration, DURATION_MIN, DURATION_MAX, DURATION_DEFAULT),
                            max_cycles=cycles,
                            family=self.family if self.family in probe.FAMILIES else "auto")


# --------------------------------------------------------------- statistics ---

@dataclass
class HopStats:
    """Running figures for one hop. Welford's method: no history needed."""
    sent: int = 0
    received: int = 0
    last: float | None = None
    best: float | None = None
    worst: float | None = None
    mean: float = 0.0
    m2: float = 0.0

    def add(self, rtt: float | None) -> None:
        self.sent += 1
        if rtt is None:
            return
        self.received += 1
        self.last = rtt
        self.best = rtt if self.best is None else min(self.best, rtt)
        self.worst = rtt if self.worst is None else max(self.worst, rtt)
        delta = rtt - self.mean
        self.mean += delta / self.received
        self.m2 += delta * (rtt - self.mean)

    @property
    def loss_pct(self) -> float | None:
        return None if not self.sent else 100.0 * (self.sent - self.received) / self.sent

    @property
    def avg(self) -> float | None:
        return self.mean if self.received else None

    @property
    def stdev(self) -> float | None:
        """Population standard deviation of the answered RTTs (mtr's StDev)."""
        if not self.received:
            return None
        return math.sqrt(self.m2 / self.received)

    def to_dict(self) -> dict:
        def r(v):
            return None if v is None else round(v, 3)
        loss = self.loss_pct
        return {"sent": self.sent, "received": self.received,
                "loss_pct": None if loss is None else round(loss, 2),
                "last_ms": r(self.last), "best_ms": r(self.best), "avg_ms": r(self.avg),
                "worst_ms": r(self.worst), "stdev_ms": r(self.stdev)}


class Samples:
    """Plot data for one hop: a live ring, raw samples for the export's first
    RAW_SECONDS, and BUCKET_SECONDS buckets over the whole session."""

    def __init__(self):
        self.live: deque = deque(maxlen=LIVE_SAMPLES)    # (t, rtt or None)
        self.raw: list = []
        self.buckets: list[dict] = []

    def add(self, t: float, rtt: float | None) -> None:
        self.live.append((round(t, 3), None if rtt is None else round(rtt, 3)))
        if t < RAW_SECONDS:
            self.raw.append(self.live[-1])
        start = int(t // BUCKET_SECONDS) * BUCKET_SECONDS
        if not self.buckets or self.buckets[-1]["t"] != start:
            self.buckets.append({"t": start, "sent": 0, "lost": 0, "min_ms": None, "max_ms": None, "sum": 0.0})
        b = self.buckets[-1]
        b["sent"] += 1
        if rtt is None:
            b["lost"] += 1
        else:
            b["min_ms"] = rtt if b["min_ms"] is None else min(b["min_ms"], rtt)
            b["max_ms"] = rtt if b["max_ms"] is None else max(b["max_ms"], rtt)
            b["sum"] += rtt

    def to_dict(self) -> dict:
        buckets = []
        for b in self.buckets:
            got = b["sent"] - b["lost"]
            buckets.append({"t": b["t"], "sent": b["sent"], "lost": b["lost"],
                            "min_ms": b["min_ms"], "max_ms": b["max_ms"],
                            "mean_ms": None if not got else round(b["sum"] / got, 3)})
        return {"raw": [list(p) for p in self.raw], "buckets": buckets}


# ------------------------------------------------------------- path changes ---

class PathTracker:
    """Windowed comparison of answering-address sets per hop (see module docs)."""

    def __init__(self, window: int = WINDOW):
        self.window = window
        self.history: dict[int, deque] = {}
        self.settled: dict[int, frozenset] = {}
        self.first_seen: dict[tuple[int, str], int] = {}
        self.last_seen: dict[tuple[int, str], int] = {}
        self.reached: deque = deque(maxlen=2 * window)
        self.settled_reached: int | None = None

    def _window_sets(self, hop: int):
        h = self.history[hop]
        if len(h) < 2 * self.window:
            return None, None
        items = list(h)
        prev = frozenset(a for s in items[:self.window] for a in s)
        cur = frozenset(a for s in items[self.window:] for a in s)
        return prev, cur

    def add(self, cycle: int, at: float, answers: dict[int, set[str]], reached_hop: int | None,
            probed: int) -> list[dict]:
        changes = []
        for hop in range(1, probed + 1):
            got = frozenset(answers.get(hop) or ())
            for a in got:
                self.first_seen.setdefault((hop, a), cycle)
                self.last_seen[(hop, a)] = cycle
            self.history.setdefault(hop, deque(maxlen=2 * self.window)).append(got)
            prev, cur = self._window_sets(hop)
            if prev is None or prev != cur:
                continue
            if hop not in self.settled:
                self.settled[hop] = cur
                continue
            old = self.settled[hop]
            if cur == old:
                continue
            added, gone = sorted(cur - old), sorted(old - cur)
            # The cycle the new set began: the first sighting of an added
            # address, or the cycle after a vanished one was last seen.
            starts = [self.first_seen.get((hop, a), cycle) for a in added] + \
                     [self.last_seen.get((hop, a), cycle) + 1 for a in gone]
            kind = "appeared" if not old else "disappeared" if not cur else "address"
            changes.append({"cycle": min(starts) if starts else cycle, "confirmed_cycle": cycle,
                            "at": at, "hop": hop, "kind": kind, "old": sorted(old), "new": sorted(cur)})
            self.settled[hop] = cur
        self.reached.append(reached_hop)
        if len(self.reached) == self.reached.maxlen and len(set(self.reached)) == 1:
            value = self.reached[-1]
            if self.settled_reached is None:
                self.settled_reached = value
            elif value != self.settled_reached:
                changes.append({"cycle": cycle - 2 * self.window + 1, "confirmed_cycle": cycle, "at": at,
                                "hop": value, "kind": "destination", "old": self.settled_reached, "new": value})
                self.settled_reached = value
        return changes


# ------------------------------------------------------------------ session ---

ProbeFn = Callable[[str, int, int, float], probe.Reply]


@dataclass
class Session:
    target: str
    address: str
    options: WatchOptions
    started_wall: float
    cycles: int = 0
    stats: dict[int, HopStats] = field(default_factory=dict)
    samples: dict[int, Samples] = field(default_factory=dict)
    addresses: dict[int, list[str]] = field(default_factory=dict)
    changes: list[dict] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    reached_hop: int | None = None
    stopped_by: str | None = None
    ended_wall: float | None = None
    resets: list[float] = field(default_factory=list)

    def hops(self) -> list[dict]:
        """One dict per hop, in hop order, with the running figures and the
        0.5.0 loss annotations computed over them."""
        out = []
        last = self.reached_hop or (max(self.stats) if self.stats else 0)
        for n in sorted(h for h in self.stats if h <= last):
            entry = {"hop": n, "addresses": list(self.addresses.get(n, [])), "annotations": []}
            entry.update(self.stats[n].to_dict())
            entry["min_rtt_ms"] = entry["best_ms"]
            out.append(entry)
        geo.annotate(out)
        return out

    def loss(self) -> dict:
        return geo.loss_verdict(self.hops())

    def to_dict(self) -> dict:
        def iso(t):
            return None if t is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        hops = self.hops()
        for h in hops:
            h.pop("min_rtt_ms", None)
        return {"target": self.target, "address": self.address,
                "started": iso(self.started_wall), "ended": iso(self.ended_wall),
                "interval_s": self.options.interval, "max_hops": self.options.max_hops,
                "duration_limit_s": self.options.duration, "cycles": self.cycles,
                "stopped_by": self.stopped_by, "reached_hop": self.reached_hop,
                "hops": hops, "loss": geo.loss_verdict(self.hops()),
                "changes": [dict(c, at=iso(c["at"])) for c in self.changes],
                "gaps": [{"from": iso(g["from"]), "to": iso(g["to"]), "seconds": round(g["to"] - g["from"], 1)}
                         for g in self.gaps],
                "resets": [iso(t) for t in self.resets],
                "samples": {"resolution_s": self.options.interval, "raw_seconds": RAW_SECONDS,
                            "bucket_seconds": BUCKET_SECONDS,
                            "hops": {str(n): s.to_dict() for n, s in sorted(self.samples.items())}}}


class Watch:
    """Runs a session in the calling thread until stopped, the duration or the
    cycle count runs out, or the target cannot be probed.

    ``on_cycle(session)`` is called after every kept cycle, under no lock the
    caller must take; read the session there or after :meth:`run` returns.
    :meth:`pause`, :meth:`resume`, :meth:`stop` and :meth:`reset` are safe from
    any thread.
    """

    def __init__(self, target: str, options: WatchOptions | None = None, *,
                 on_cycle: Callable[[Session], None] | None = None,
                 probe_fn: ProbeFn | None = None, resolve: Callable[[str], str] | None = None,
                 wall: Callable[[], float] = time.time, mono: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] | None = None):
        self.options = (options or WatchOptions()).clamped()
        self.target = target
        self.on_cycle = on_cycle
        self.probe_fn = probe_fn or probe._probe
        self.resolve = resolve or (lambda target: probe.resolve(target, self.options.family))
        self.wall, self.mono = wall, mono
        self._stop = threading.Event()
        self._running = threading.Event()
        self._running.set()
        self._sleep = sleep or (lambda s: self._stop.wait(s))
        self._lock = threading.Lock()
        self._reset = False
        self.session: Session | None = None

    # controls
    def pause(self):
        self._running.clear()

    def resume(self):
        self._running.set()

    @property
    def paused(self) -> bool:
        return not self._running.is_set()

    def stop(self):
        self._stop.set()
        self._running.set()

    def reset(self):
        with self._lock:
            self._reset = True

    # the loop
    def run(self) -> Session:
        dst = str(ipaddress.ip_address(self.resolve(self.target)))
        opts = self.options
        s = self.session = Session(target=self.target, address=dst, options=opts, started_wall=self.wall())
        tracker = PathTracker()
        seq = secrets.randbelow(0x10000)
        start_mono, start_wall = self.mono(), self.wall()
        elapsed_active = 0.0
        workers = max(1, min(int(MAX_RATE), math.ceil(WAIT * MAX_RATE)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="watch-probe") as pool:
            while not self._stop.is_set():
                if not self._running.is_set():
                    paused_at_wall = self.wall()
                    while not self._running.is_set() and not self._stop.is_set():
                        self._running.wait(0.2)
                    # Time spent paused is not session time.
                    start_wall += self.wall() - paused_at_wall
                    continue
                if opts.max_cycles is not None and s.cycles >= opts.max_cycles:
                    s.stopped_by = "count"
                    break
                if elapsed_active >= opts.duration:
                    s.stopped_by = "duration"
                    break
                with self._lock:
                    if self._reset:
                        s.stats.clear()
                        s.samples.clear()
                        s.resets.append(self.wall())
                        self._reset = False
                depth = self._depth(s)
                spacing = max(opts.interval / depth, 1.0 / MAX_RATE)
                c_mono, c_wall = self.mono(), self.wall()
                futures = []
                for ttl in range(1, depth + 1):
                    if self._stop.is_set():
                        break
                    seq = (seq + 1) & 0xFFFF
                    futures.append((ttl, pool.submit(self.probe_fn, dst, ttl, seq, WAIT)))
                    if ttl < depth:
                        self._sleep(spacing)
                results = {}
                for ttl, f in futures:
                    try:
                        results[ttl] = f.result()
                    except Exception:  # noqa: BLE001 - a failed probe is an unanswered one
                        results[ttl] = probe.Reply(None, None)
                # The rest of the interval, so a cycle starts every `interval`.
                spent = self.mono() - c_mono
                if not self._stop.is_set() and spent < opts.interval:
                    self._sleep(opts.interval - spent)
                end_mono, end_wall = self.mono(), self.wall()
                budget = max(opts.interval, depth * spacing) + WAIT + GAP_SLACK
                if (end_mono - c_mono) > budget or (end_wall - c_wall) > budget:
                    # Slept or suspended: this cycle did not get a fair wait.
                    s.gaps.append({"from": c_wall, "to": end_wall})
                    continue
                if self._stop.is_set() and len(futures) < depth:
                    break
                s.cycles += 1
                elapsed_active += max(opts.interval, end_mono - c_mono)
                t = c_wall - start_wall          # a sample's time is its cycle's start
                answers: dict[int, set[str]] = {}
                reached = None
                for ttl in range(1, depth + 1):
                    r = results.get(ttl) or probe.Reply(None, None)
                    s.stats.setdefault(ttl, HopStats()).add(r.rtt_ms if r.address else None)
                    s.samples.setdefault(ttl, Samples()).add(t, r.rtt_ms if r.address else None)
                    if r.address:
                        answers[ttl] = {r.address}
                        known = s.addresses.setdefault(ttl, [])
                        if r.address not in known:
                            known.append(r.address)
                    if r.reached and reached is None:
                        reached = ttl
                if reached is not None:
                    s.reached_hop = reached if s.reached_hop is None else s.reached_hop
                s.changes.extend(tracker.add(s.cycles, end_wall, answers, reached, depth))
                if tracker.settled_reached is not None:
                    s.reached_hop = tracker.settled_reached
                if self.on_cycle is not None:
                    try:
                        self.on_cycle(s)
                    except Exception:  # noqa: BLE001 - the display must not stop the session
                        pass
            if self._stop.is_set() and s.stopped_by is None:
                s.stopped_by = "user"
        s.ended_wall = self.wall()
        return s

    def _depth(self, s: Session) -> int:
        """How many hops to probe this cycle: all of them the first time, then up
        to the destination once it has answered, else MAX_UNKNOWN past the
        deepest hop that answered."""
        opts = self.options
        if s.reached_hop is not None:
            return min(opts.max_hops, s.reached_hop)
        if not s.stats:
            return opts.max_hops        # the first cycle finds the path, as a single trace does
        answered = [h for h, st in s.stats.items() if st.received]
        deepest = max(answered) if answered else 0
        return min(opts.max_hops, max(deepest + MAX_UNKNOWN, min(opts.max_hops, MAX_UNKNOWN)))


# ------------------------------------------------------------------ placing ---

def as_hops(session: Session) -> list[Hop]:
    """The session's hops as parser Hops, for geo.resolve: every address that
    answered at each hop, with its best RTT and the running sent and lost."""
    out = []
    for entry in session.hops():
        h = Hop(hop=entry["hop"], addresses=list(entry["addresses"]),
                rtts_ms=[] if entry["best_ms"] is None else [entry["best_ms"]],
                sent=entry["sent"], lost=entry["sent"] - entry["received"])
        out.append(h)
    return out


def new_hops(session: Session, route_hops: list[dict]) -> list[Hop]:
    """Hops, or addresses at a hop, that the placed route does not have yet:
    the only ones that need geolocation after the first cycle."""
    placed = {h["hop"]: set(h.get("addresses") or []) for h in route_hops}
    out = []
    for h in as_hops(session):
        missing = [a for a in h.addresses if a not in placed.get(h.hop, set())]
        if missing:
            out.append(Hop(hop=h.hop, addresses=missing, rtts_ms=list(h.rtts_ms), sent=h.sent, lost=h.lost))
    return out
