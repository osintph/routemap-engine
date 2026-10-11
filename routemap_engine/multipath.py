"""
Path discovery: the paths a per-flow load balancer can send this machine's
packets along, each with its own loss and latency.

METHOD
------
* **One flow per probe stream (Paris traceroute).** Load balancers hash the
  five-tuple "as well as three other fields: the IP Type of Service (TOS), and
  the ICMP Code and Checksum fields" (Augustin et al., "Avoiding traceroute
  anomalies with Paris traceroute", IMC 2006). Every probe of one flow keeps
  its identifier and checksum (:class:`probe.FlowTransport`); the sequence
  number names the probe. Flow *f* = 0, 1, 2, ... differs from the others in
  both fields.
* **How many flows: the MDA stopping rule** (Augustin, Friedman, Teixeira,
  "Measuring load-balanced paths in the Internet", IMC 2007), with the table
  of Veitch et al., "Failure control in multipath route tracing", INFOCOM
  2009, Table I, at 95% (as MDA-Lite uses it, Vermeulen et al., IMC 2018):
  once k distinct responders have been seen at a hop, flows are added until
  n_k of them have answered there, n_1 = 9, n_2 = 17, n_3 = 24, ...
* **The same flows at every hop.** Flows 0 to M-1 are probed at every TTL and
  M grows only when a hop's stopping rule needs more; earlier hops are then
  probed for the new flows too. Each flow is then one complete hop-by-hop
  path, so a path's loss and latency are measured, not stitched together.
  This spends more probes than the MDA on single-path stretches; the caps
  below bound it.
* **Rate-limited routers.** A hop that answers less than half of its probes
  gets no more flows once a round of them showed no new responder: the
  stopping rule assumes every probe is answered, and more flows there would
  only spend the budget on silence.
* **Per-packet balancing.** When a hop shows a second responder, one flow is
  probed there five more times (the MDA's test: six probes of one flow that
  all return the same interface rule out per-packet balancing at 95%). If
  they differ, the hop is reported as balancing per packet and does not
  split paths.
* **Per-path loss and latency.** Each path's first flow is then pinged at the
  full hop limit, :data:`PATH_PINGS` times.

Paths found over ICMP are a lower bound: "some per-flow load balancers do not
perform load balancing on ICMP packets" (IMC 2007). Every UI says "at least".

CAPS (hard; tests/test_multipath.py checks them on generated topologies)
----
* :data:`MAX_RATE` probes per second, spaced evenly: 20, scamper's default
  ("-p pps ... By default, this value is 20", scamper(1)).
* :data:`MAX_PROBES` per discovery, path pings included: 1,500.
* :data:`MAX_FLOWS`: 64, enough for n_7 = 60, so up to 8 next hops at one hop.
* :data:`GAP_LIMIT` silent hops end the discovery: 3 (scamper tracelb's
  default gap limit).
* One probe in flight per (TTL, flow), :data:`MAX_HOPS` hops, :data:`WAIT`
  seconds per probe.

The engine has no global state here: a :class:`Discoverer` holds one run, with
its transport and clock passed in.
"""
from __future__ import annotations

import logging
import math
import secrets
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Protocol

from routemap_engine import probe
from routemap_engine.logsafe import tag

log = logging.getLogger("routemap_engine.multipath")

MAX_RATE = 20.0
MAX_PROBES = 1500
MAX_FLOWS = 64
GAP_LIMIT = 3
MAX_HOPS = 30
WAIT = 1.0
PATH_PINGS = 10
PER_PACKET_PROBES = 5
MAX_PATHS = 16
PING_HOPS = 64
# Veitch et al. 2009, Table I: flows needed after k responders, k = 1, 2, ...
N_K = (9, 17, 24, 33, 42, 51, 60, 70, 81, 91, 102, 113, 125, 136, 148, 161)
METHOD = "icmp-paris"
METHODS = ("icmp-paris", "tcp-paris")
LETTERS = "ABCDEFGHIJKLMNOP"


class Transport(Protocol):
    def send(self, flow: int, ttl: int, seq: int) -> None: ...
    def read(self, timeout: float) -> list[probe.FlowAnswer]: ...
    def close(self) -> None: ...


@dataclass
class Options:
    budget: int = MAX_PROBES
    rate: float = MAX_RATE
    max_hops: int = MAX_HOPS
    wait: float = WAIT
    pings: int = PATH_PINGS

    def clamped(self) -> "Options":
        """Every value inside its cap: a caller can lower a cap, never raise it."""
        def clamp(v, lo, hi, default):
            try:
                v = float(v)
            except (TypeError, ValueError):
                return default
            return default if math.isnan(v) else max(lo, min(hi, v))
        return Options(budget=int(clamp(self.budget, 50, MAX_PROBES, MAX_PROBES)),
                       rate=clamp(self.rate, 1.0, MAX_RATE, MAX_RATE),
                       max_hops=int(clamp(self.max_hops, 1, MAX_HOPS, MAX_HOPS)),
                       wait=clamp(self.wait, 0.1, probe.MAX_WAIT_SECONDS, WAIT),
                       pings=int(clamp(self.pings, 0, PATH_PINGS, PATH_PINGS)))


@dataclass
class Path:
    id: str
    flows: list[int]
    hops: list[str | None]                  # responder per TTL, from TTL 1
    rtt_ms: list[float | None]              # mean RTT per TTL over this path's flows
    reached: bool
    pings_sent: int = 0
    pings_lost: int = 0
    rtt_to_target_ms: float | None = None

    @property
    def loss_pct(self) -> float | None:
        return None if not self.pings_sent else round(100.0 * self.pings_lost / self.pings_sent, 1)

    def to_dict(self) -> dict:
        return {"id": self.id, "flows": list(self.flows), "hops": list(self.hops),
                "rtt_ms": [None if r is None else round(r, 3) for r in self.rtt_ms],
                "reached": self.reached, "sent": self.pings_sent, "lost": self.pings_lost,
                "loss_pct": self.loss_pct,
                "rtt_to_target_ms": None if self.rtt_to_target_ms is None else round(self.rtt_to_target_ms, 3)}


@dataclass
class Discovery:
    target: str
    address: str
    af: int
    paths: list[Path] = field(default_factory=list)
    responders: dict[int, list[str]] = field(default_factory=dict)   # TTL -> responders, first seen first
    rtts: dict[tuple[int, str], list[float]] = field(default_factory=dict)
    silent: dict[int, int] = field(default_factory=dict)              # TTL -> unanswered probes
    per_packet_hops: list[int] = field(default_factory=list)
    probes_sent: int = 0
    flows_used: int = 0
    paths_capped: bool = False
    stopped_by: str = "complete"          # complete | budget | cancel | deadline | gap | max_hops
    seconds: float = 0.0
    method: str = METHOD

    def to_dict(self) -> dict:
        return {"method": self.method, **({"port": probe.TCP_FLOW_PORT} if self.method == "tcp-paris" else {}),
                "at_least": True, "af": self.af,
                "paths": [p.to_dict() for p in self.paths], "per_packet_hops": list(self.per_packet_hops),
                "probes_sent": self.probes_sent, "flows": self.flows_used, "paths_capped": self.paths_capped,
                "stopped_by": self.stopped_by, "seconds": round(self.seconds, 1)}

    def trace_text(self) -> str:
        """BSD traceroute -n text with every responder of every hop, for the
        parser and the usual analysis (placement, AS path, annotations)."""
        last = max(self.responders) if self.responders else 0
        lines = [f"traceroute to {self.target} ({self.address}), {last} hops max, "
                 f"{8 + len(probe.PAYLOAD)} byte packets, {probe.HEADER_MARK}, paths"]
        for ttl in range(1, last + 1):
            replies = [probe.Reply(a, _median(self.rtts.get((ttl, a), []))) for a in self.responders.get(ttl, [])]
            if self.silent.get(ttl) or not replies:
                replies.append(probe.Reply(None, None))
            lines.extend(probe.format_hop(ttl, replies))
        return "\n".join(lines) + "\n"


def _median(values: list[float]) -> float | None:
    """The median: one slow ICMP reply (1,065 ms at a hop that otherwise
    answers in tens, the Windows TCP release check, hop 6) must not move a
    path's latency, and a mean would."""
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def n_k(k: int) -> int:
    """Flows that must answer at a hop with *k* responders before stopping."""
    return N_K[min(max(k, 1), len(N_K)) - 1]


class Clock(Protocol):
    def __call__(self) -> float: ...


class Discoverer:
    """One discovery run. *transport* sends and reads probes; *clock* gives
    seconds (``time.perf_counter`` for real runs, a virtual clock in tests)."""

    def __init__(self, target: str, address: str, transport: Transport, *,
                 options: Options | None = None, clock: Callable[[], float] = time.perf_counter,
                 cancel: threading.Event | None = None, deadline: float | None = None,
                 on_progress: Callable[[dict], None] | None = None):
        self.target, self.address = target, address
        self.t = transport
        self.o = (options or Options()).clamped()
        self.clock = clock
        self.cancel = cancel
        self.deadline = deadline
        self.on_progress = on_progress
        self.d = Discovery(target, address, probe.family_of(address),
                           method=getattr(transport, "METHOD", METHOD))
        self._seq = secrets.randbelow(0x10000)
        self._last_send: float | None = None
        self._pending: dict[int, tuple[int, int, float]] = {}       # seq -> (flow, ttl, sent at)
        self._result: dict[tuple[int, int], tuple[str | None, float | None, bool]] = {}
        self._reached_at: dict[int, int] = {}                        # flow -> TTL it reached
        self._stop: str | None = None
        self._started = clock()

    # ------------------------------------------------------------- probing
    def _stopping(self) -> bool:
        if self._stop:
            return True
        if self.cancel is not None and self.cancel.is_set():
            self._stop = "cancel"
        elif self.deadline is not None and self.clock() > self.deadline:
            self._stop = "deadline"
        return bool(self._stop)

    def _take(self, answers: list[probe.FlowAnswer]) -> list[tuple[int, int, str, float, bool]]:
        got = []
        for a in answers:
            entry = self._pending.pop(a.seq, None)
            if entry is None:
                continue                      # late, duplicate or someone else's
            flow, ttl, sent = entry
            got.append((flow, ttl, a.address, max(0.0, (a.at - sent) * 1000), a.reached))
        return got

    def _send(self, flow: int, ttl: int, collected: list) -> bool:
        """Send one probe, no faster than the rate cap; False when the budget
        or a stop condition says no."""
        if self.d.probes_sent >= self.o.budget:
            self._stop = self._stop or "budget"
            return False
        if self._stopping():
            return False
        # A hair over 1/rate, so no window of one second ever holds rate + 1
        # probes, whatever the clock's rounding (the cap is "at most 20").
        spacing = 1.0 / self.o.rate + 1e-4
        if self._last_send is not None:
            while True:
                left = self._last_send + spacing - self.clock()
                if left <= 0:
                    break
                collected.extend(self._take(self.t.read(left)))
        self._seq = (self._seq + 1) & 0xFFFF
        while self._seq in self._pending:
            self._seq = (self._seq + 1) & 0xFFFF
        now = self.clock()
        self.t.send(flow, ttl, self._seq)
        self._pending[self._seq] = (flow, ttl, now)
        self._last_send = now
        self.d.probes_sent += 1
        return True

    def _batch(self, items: list[tuple[int, int]]) -> list[tuple[int, int, str | None, float | None, bool]]:
        """Probe (flow, TTL) pairs; return (flow, TTL, address or None, RTT, reached)
        for each one sent, after its answer or its wait."""
        collected: list = []
        sent: list[tuple[int, int]] = []
        for flow, ttl in items:
            if any(f == flow and t == ttl for f, t, _ in self._pending.values()):
                self._drain_until_clear(flow, ttl, collected)
            if not self._send(flow, ttl, collected):
                break
            sent.append((flow, ttl))
        expiry = {s: self._pending[s][2] + self.o.wait for s in self._pending}
        while self._pending and not (self.cancel is not None and self.cancel.is_set()):
            now = self.clock()
            for s in [s for s, end in expiry.items() if end <= now and s in self._pending]:
                self._pending.pop(s)
            if not self._pending:
                break
            left = min(expiry[s] for s in self._pending) - now
            collected.extend(self._take(self.t.read(max(left, 0.0))))
        self._pending.clear()
        answered = {(f, t): (a, r, reached) for f, t, a, r, reached in collected}
        out = []
        for flow, ttl in sent:
            a, r, reached = answered.get((flow, ttl), (None, None, False))
            out.append((flow, ttl, a, r, reached))
        return out

    def _drain_until_clear(self, flow: int, ttl: int, collected: list):
        while any(f == flow and t == ttl for f, t, _ in self._pending.values()):
            now = self.clock()
            for s, (f, t, sent) in list(self._pending.items()):
                if sent + self.o.wait <= now:
                    self._pending.pop(s)
            collected.extend(self._take(self.t.read(0.05)))

    def _record(self, results):
        for flow, ttl, addr, rtt, reached in results:
            if addr is None:
                if (flow, ttl) not in self._result:
                    self._result[(flow, ttl)] = (None, None, False)
                continue
            self._result[(flow, ttl)] = (addr, rtt, reached)
            seen = self.d.responders.setdefault(ttl, [])
            if addr not in seen:
                seen.append(addr)
            self.d.rtts.setdefault((ttl, addr), []).append(rtt)
            if reached:
                self._reached_at[flow] = min(ttl, self._reached_at.get(flow, ttl))

    def _alive(self, flow: int, ttl: int) -> bool:
        """Whether *flow* still needs probing at *ttl* (it has not reached the
        target at an earlier TTL)."""
        at = self._reached_at.get(flow)
        return at is None or at >= ttl

    def _probe_flows_at(self, ttl: int, flows: range | list[int]):
        todo = [(f, ttl) for f in flows if (f, ttl) not in self._result and self._alive(f, ttl)]
        if not todo:
            return
        self._record(self._batch(todo))
        # One retry for probes a hop left unanswered while it answered others
        # (rate limiting, a lost reply), so a silence does not split a path.
        answered = any(self._result.get((f, ttl), (None,))[0] for f, _ in todo)
        retry = [(f, t) for f, t in todo if answered and self._result.get((f, t), (None,))[0] is None]
        if retry:
            for key in retry:
                self._result.pop(key, None)
            self._record(self._batch(retry))

    def _backfill(self, flows: range, upto: int):
        for ttl in range(1, upto):
            if self._stopping():
                return
            self._probe_flows_at(ttl, [f for f in flows if self._alive(f, ttl)])

    # ---------------------------------------------------------------- run
    def run(self) -> Discovery:
        d = self.d
        m = 0
        gap = 0
        try:
            for ttl in range(1, self.o.max_hops + 1):
                if self._stopping():
                    break
                want = max(m, n_k(1))
                per_packet_checked = False
                last_k = -1
                while True:
                    if want > m:
                        new = range(m, want)
                        m = want
                        self._backfill(new, ttl)
                    self._probe_flows_at(ttl, range(m))
                    at_hop = [self._result.get((f, ttl)) for f in range(m)]
                    responders = {r[0] for r in at_hop if r and r[0]}
                    answered = sum(1 for r in at_hop if r and r[0])
                    k = len(responders)
                    if k >= 2 and not per_packet_checked:
                        per_packet_checked = True
                        if self._per_packet(ttl):
                            d.per_packet_hops.append(ttl)
                            break
                    if k == 0 or self._stop:
                        break
                    need = n_k(k)
                    if answered >= need or m >= MAX_FLOWS:
                        break
                    # A router that answers less than half of its probes is
                    # rate limiting; more flows only buy more silence there, so
                    # growth stops once a round brought no new responder.
                    probed = sum(1 for r in at_hop if r is not None)
                    if answered * 2 < probed and k == last_k:
                        break
                    last_k = k
                    want = min(MAX_FLOWS, m + (need - answered))
                self._progress(ttl)
                alive = [f for f in range(m) if self._alive(f, ttl + 1)]
                silent = not any((self._result.get((f, ttl)) or (None,))[0] for f in range(m))
                gap = gap + 1 if silent else 0
                if self._stop:
                    break
                if not alive:
                    d.stopped_by = "complete"
                    break
                if gap >= GAP_LIMIT:
                    d.stopped_by = "gap"
                    break
            else:
                d.stopped_by = "max_hops"
            d.flows_used = m
            self._build_paths(m)
            if not self._stop:
                self._ping_paths()
        finally:
            self.t.close()
        if self._stop:
            d.stopped_by = self._stop
        d.seconds = self.clock() - self._started
        log.info("event=paths_done target=%s paths=%d probes=%d stopped_by=%s", tag(self.target),
                 len(d.paths), d.probes_sent, d.stopped_by)
        return d

    def _per_packet(self, ttl: int) -> bool:
        flow = next((f for f in range(MAX_FLOWS) if (self._result.get((f, ttl)) or (None,))[0]), None)
        if flow is None:
            return False
        first = self._result[(flow, ttl)][0]
        seen = {first}
        for _ in range(PER_PACKET_PROBES):
            res = self._batch([(flow, ttl)])
            if not res:
                break
            if res[0][2]:
                seen.add(res[0][2])
        return len(seen) > 1

    def _progress(self, ttl: int):
        if self.on_progress is None:
            return
        try:
            paths = len({tuple((self._result.get((f, t)) or (None,))[0] for t in range(1, ttl + 1))
                         for f in range(MAX_FLOWS) if (f, 1) in self._result})
            self.on_progress({"ttl": ttl, "paths": paths, "probes": self.d.probes_sent, "budget": self.o.budget})
        except Exception:  # noqa: BLE001 - the display must not stop the run
            pass

    def _build_paths(self, m: int):
        d = self.d
        last = max(d.responders) if d.responders else 0
        per_packet = set(d.per_packet_hops)
        seqs: dict[int, list[str | None]] = {}
        for f in range(m):
            end = min(last, self._reached_at.get(f, last))
            seqs[f] = [None if t in per_packet else (self._result.get((f, t)) or (None,))[0]
                       for t in range(1, end + 1)]
        # Group flows whose responders agree wherever both answered; a silence
        # matches anything, so a lost reply does not make a path of its own.
        groups: list[tuple[list[str | None], list[int]]] = []
        for f in sorted(seqs, key=lambda f: sum(x is None for x in seqs[f])):
            s = seqs[f]
            for rep, members in groups:
                if len(rep) == len(s) and all(a is None or b is None or a == b for a, b in zip(rep, s)):
                    members.append(f)
                    for i, x in enumerate(s):
                        if rep[i] is None:
                            rep[i] = x
                    break
            else:
                groups.append((list(s), [f]))
        for t in range(1, last + 1):
            d.silent[t] = sum(1 for f in range(m) if (f, t) in self._result and self._result[(f, t)][0] is None)
        groups.sort(key=lambda g: (-len(g[1]), g[1][0]))
        if len(groups) > MAX_PATHS:
            d.paths_capped = True
            groups = groups[:MAX_PATHS]
        for i, (rep, flows) in enumerate(groups):
            rtts = []
            for t in range(1, len(rep) + 1):
                vals = [self._result[(f, t)][1] for f in flows
                        if (f, t) in self._result and self._result[(f, t)][0] == rep[t - 1]]
                rtts.append(_median([v for v in vals if v is not None]))
            for t in per_packet:
                if t <= len(rep):
                    rep[t - 1] = None
            d.paths.append(Path(LETTERS[i], sorted(flows), rep, rtts,
                                reached=any(f in self._reached_at for f in flows)))

    def _ping_paths(self):
        d = self.d
        if not self.o.pings:
            return
        for path in d.paths:
            if not path.reached:
                continue
            flow = path.flows[0]
            rtts = []
            for _ in range(self.o.pings):
                res = self._batch([(flow, PING_HOPS)])
                if not res:
                    break
                path.pings_sent += 1
                _f, _t, addr, rtt, reached = res[0]
                if reached and addr:
                    rtts.append(rtt)
                else:
                    path.pings_lost += 1
            path.rtt_to_target_ms = _median(rtts)


def available() -> tuple[bool, str]:
    """Whether path discovery can run on this system, and why not."""
    return probe.flow_available()


def discover(target: str, *, family: str = "auto", options: Options | None = None,
             cancel: threading.Event | None = None, deadline: float | None = None,
             on_progress: Callable[[dict], None] | None = None) -> Discovery:
    """Discover the paths to *target* (a validated hostname or address) with
    the built-in Paris prober. Blocking: run it in a worker thread."""
    ok, why = available()
    if not ok:
        raise RuntimeError(why)
    address = probe.resolve(target, family)
    probe.check_route(address)
    transport = (probe.TcpFlowTransport(address) if probe.flow_method() == probe.TcpFlowTransport.METHOD
                 else probe.FlowTransport(address))
    return Discoverer(target, address, transport, options=options, cancel=cancel,
                      deadline=deadline, on_progress=on_progress).run()
