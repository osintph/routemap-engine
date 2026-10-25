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
* **Per-path loss and latency.** Each path is then asked at the full hop
  limit :data:`PATH_PINGS` times, on its flows in turn, rounds at least
  :data:`PING_INTERVAL` seconds apart.
* **The target's hop ends a path.** A hop where only the target answers adds
  no flows, and a flow silent where other flows of its path reached the
  target is asked there again (twice at most) and never deeper.

Paths found over ICMP are a lower bound: "some per-flow load balancers do not
perform load balancing on ICMP packets" (IMC 2007). Every UI says "at least".

CAPS (hard; tests/test_multipath.py checks them on generated topologies)
----
* :data:`MAX_RATE` probes per second, spaced evenly: 20, scamper's default
  ("-p pps ... By default, this value is 20", scamper(1)).
* :data:`MAX_PROBES` per discovery, path pings included: 1,500.
* :data:`MAX_FLOWS`: 64, enough for n_7 = 60, so up to 8 next hops at one hop.
* :data:`GAP_LIMIT` silent hops end the discovery: 5, the default of both
  scamper's trace ("By default, a gap limit of 5 hops is used", scamper(1))
  and RIPE Atlas's traceroute (``gaplimit= 5;`` in eperd/traceroute.c of
  ripe-atlas-software-probe). Until 0.8.0 it was 3, tracelb's default.
* **Then the target is asked anyway.** Every path, reached or not, gets its
  :data:`PATH_PINGS` attempts at the full hop limit, as RIPE Atlas sends a
  last-ditch probe with TTL 255 once its gap limit is reached
  (``state->lastditch= 1; state->hop= 255;``, same file) and scamper's gap
  action 2 does ("send last-ditch probes", scamper(1)). A path whose target
  answers only those is reached at :attr:`Discovery.final_hop`, the hop after
  the last one sent, with its silent stretch marked; "not reached" means the
  target was asked and did not answer.
* **TCP-silent networks (Windows).** Over TCP, each hop where no probe was
  answered gets one ICMP echo at the same TTL (the caller's ``icmp_check``),
  counted in the budget and the rate. When the silent stretch that ended the
  discovery answers ICMP, :attr:`Discovery.tcp_silent_from` says where: the
  routers there do not answer TCP probes, and a trace over ICMP can map on.
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
GAP_LIMIT = 5
MAX_HOPS = 30
WAIT = 1.0
PATH_PINGS = 10
# Seconds between two rounds of target attempts, at least: ping's default
# ("Wait wait seconds between sending each packet. The default is to wait for
# one second", ping(8)), so a short stretch of loss at the target cannot take
# most of the ten (Mac run, 25 Oct 2026: 7 of 10 lost while discovery had
# seen the target answer 53 of 63; heise.de answered 60 of 60 at 0.3 s and
# 1 s spacing when measured again the same evening).
PING_INTERVAL = 1.0
PER_PACKET_PROBES = 5
MAX_PATHS = 16
PING_HOPS = 64
# Veitch et al. 2009, Table I: flows needed after k responders, k = 1, 2, ...
N_K = (9, 17, 24, 33, 42, 51, 60, 70, 81, 91, 102, 113, 125, 136, 148, 161)
METHOD = "icmp-paris"
PROBER_MARK = "routemap-engine built-in prober"          # parse._ICMP_MARK reads it
METHODS = ("icmp-paris", "tcp-paris")
LETTERS = "ABCDEFGHIJKLMNOP"
ANNOT_FINAL_PROBE = "answered the final full-TTL probe"
FINAL_PROBE_DETAIL = ("after the silent hops that ended the discovery, the target was asked at the full hop "
                      "limit and answered; it is numbered after the last hop sent, and the hops in between "
                      "are unknown")
# The probe each method sends, for the trace text's header.
METHOD_MARKS = {"icmp-paris": "ICMP echo", "tcp-paris": "TCP SYN to port {port}"}
STOP_TEXT = {"complete": "complete", "budget": "stopped at the probe cap", "cancel": "stopped by the user",
             "deadline": "stopped at the time limit", "max_hops": "stopped at the hop limit",
             "local_error": "stopped: this computer refused to send probes"}


class Transport(Protocol):
    """Sends and reads one flow's probes. Optional, used when present:
    ``forget(seq)`` drops a probe the discoverer stopped waiting for;
    ``ready_at(flow)`` is the earliest clock time the flow may send again (a
    TCP flow just after it reached the target); ``send`` returning False means
    the probe never left this machine (a local socket error)."""
    def send(self, flow: int, ttl: int, seq: int) -> bool | None: ...
    def read(self, timeout: float) -> list[probe.FlowAnswer]: ...
    def close(self) -> None: ...


# A run of local send failures this long stops the discovery: the system is
# refusing the probes, and retrying would only spin.
MAX_LOCAL_FAILURES = 20


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
    reached_by: str | None = None           # "discovery", "full_ttl" (only the final attempts answered) or None
    silent: list[int] | None = None         # [first, last] TTL of the silent stretch before a full-TTL answer

    @property
    def loss_pct(self) -> float | None:
        return None if not self.pings_sent else round(100.0 * self.pings_lost / self.pings_sent, 1)

    def to_dict(self) -> dict:
        return {"id": self.id, "flows": list(self.flows), "hops": list(self.hops),
                "rtt_ms": [None if r is None else round(r, 3) for r in self.rtt_ms],
                "reached": self.reached, "sent": self.pings_sent, "lost": self.pings_lost,
                "loss_pct": self.loss_pct,
                "rtt_to_target_ms": None if self.rtt_to_target_ms is None else round(self.rtt_to_target_ms, 3),
                "reached_by": self.reached_by, "silent": None if self.silent is None else list(self.silent)}


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
    stopped_by: str = "complete"          # complete | budget | cancel | deadline | gap | max_hops | local_error
    local_failures: int = 0               # probes this machine failed to send (not network loss)
    budget: int = MAX_PROBES              # the cap on every probe sent, the target attempts included
    discovery_probes: int = 0             # probes sent before the target attempts
    seconds: float = 0.0
    method: str = METHOD
    max_hops: int = MAX_HOPS
    silent_stop: list[int] | None = None  # [first, last] TTL of the silent hops that ended it (stopped_by "gap")
    final_hop: int | None = None          # where a full-TTL answer after silent hops is numbered
    icmp_checks: dict[int, str | None] = field(default_factory=dict)   # TTL -> ICMP check answer (TCP runs)
    tcp_silent_from: int | None = None    # first TTL of a stretch silent to TCP whose ICMP check answered
    tcp_silent_by: str | None = None      # who answered that ICMP check: "router" or "target"
    ping_interval: float | None = None    # seconds between rounds of target attempts, at least

    @property
    def stop_text(self) -> str:
        """Why the discovery ended, in words: "stopped after 5 silent hops (3 to 7)"."""
        if self.stopped_by == "gap" and self.silent_stop:
            a, b = self.silent_stop
            return f"stopped after {b - a + 1} silent hops ({a} to {b})"
        return STOP_TEXT.get(self.stopped_by, self.stopped_by)

    def to_dict(self) -> dict:
        return {"method": self.method, **({"port": probe.TCP_FLOW_PORT} if self.method == "tcp-paris" else {}),
                "at_least": True, "af": self.af,
                "paths": [p.to_dict() for p in self.paths], "per_packet_hops": list(self.per_packet_hops),
                "probes_sent": self.probes_sent, "flows": self.flows_used, "paths_capped": self.paths_capped,
                "local_failures": self.local_failures, "budget": self.budget,
                "discovery_probes": self.discovery_probes,
                "stopped_by": self.stopped_by, "stop_text": self.stop_text, "seconds": round(self.seconds, 1),
                "max_hops": self.max_hops, "silent_stop": None if self.silent_stop is None else list(self.silent_stop),
                "final_hop": self.final_hop, "tcp_silent_from": self.tcp_silent_from,
                "tcp_silent_by": self.tcp_silent_by,
                "ping_interval": self.ping_interval,
                "icmp_checks": [{"ttl": t, "address": a} for t, a in sorted(self.icmp_checks.items())],
                "resolved": {"name": self.target, "address": self.address, "family": self.af}}

    def to_wire(self) -> dict:
        """Everything :func:`routemap_engine.analyse_paths` reads, as JSON: a
        discovery measured on a remote agent travels in this shape and is
        rebuilt with :meth:`from_wire`."""
        out = self.to_dict()
        out.update(target=self.target, address=self.address,
                   responders=[{"ttl": t, "addresses": list(a)} for t, a in sorted(self.responders.items())],
                   rtts=[{"ttl": t, "address": a, "ms": [round(x, 3) for x in v if x is not None]}
                         for (t, a), v in sorted(self.rtts.items())],
                   silent=[{"ttl": t, "count": n} for t, n in sorted(self.silent.items())])
        return out

    @classmethod
    def from_wire(cls, data: dict) -> "Discovery":
        """Rebuild a discovery from :meth:`to_wire`, checking every field: the
        data came from another machine. Raises ValueError on anything else."""
        import ipaddress

        def addr(v, none_ok=False):
            if v is None and none_ok:
                return None
            if not isinstance(v, str) or len(v) > 45:
                raise ValueError("bad address")
            return str(ipaddress.ip_address(v))

        def ttl(v, top=PING_HOPS):
            if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= top:
                raise ValueError("bad TTL")
            return v

        def num(v):
            if v is None:
                return None
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not 0 <= v < 1e7:
                raise ValueError("bad number")
            return float(v)

        if not isinstance(data, dict):
            raise ValueError("not a discovery")
        from routemap_engine.target import validate_target
        address = addr(data.get("address"))
        d = cls(validate_target(str(data.get("target") or address)), address, probe.family_of(address))
        method = data.get("method")
        if method not in METHODS:
            raise ValueError("bad method")
        d.method = method
        for item in data.get("responders") or []:
            d.responders[ttl(item["ttl"])] = [addr(a) for a in item["addresses"]][:MAX_FLOWS]
        for item in data.get("rtts") or []:
            d.rtts[(ttl(item["ttl"]), addr(item["address"]))] = [num(x) for x in item["ms"]][:MAX_PROBES]
        for item in data.get("silent") or []:
            d.silent[ttl(item["ttl"])] = int(num(item["count"]) or 0)
        paths = data.get("paths") or []
        if not isinstance(paths, list) or len(paths) > MAX_PATHS:
            raise ValueError("bad paths")
        for i, pd in enumerate(paths):
            hops = [addr(a, True) for a in pd["hops"]][:MAX_HOPS + 1]
            rtts = [num(r) for r in pd["rtt_ms"]][:MAX_HOPS + 1]
            reached_by = pd.get("reached_by")
            if reached_by not in ("discovery", "full_ttl", None):
                raise ValueError("bad reached_by")
            silent = pd.get("silent")
            d.paths.append(Path(LETTERS[i], [int(num(f)) for f in pd["flows"]][:MAX_FLOWS], hops, rtts,
                                reached=bool(pd["reached"]), pings_sent=int(num(pd.get("sent")) or 0),
                                pings_lost=int(num(pd.get("lost")) or 0),
                                rtt_to_target_ms=num(pd.get("rtt_to_target_ms")), reached_by=reached_by,
                                silent=[ttl(silent[0]), ttl(silent[1])] if silent else None))
        d.per_packet_hops = [ttl(t) for t in data.get("per_packet_hops") or []]
        for key in ("probes_sent", "flows", "local_failures", "budget", "discovery_probes"):
            value = int(num(data.get(key)) or 0)
            setattr(d, "flows_used" if key == "flows" else key, value)
        d.paths_capped = bool(data.get("paths_capped"))
        stopped = data.get("stopped_by")
        if stopped not in ("complete", "budget", "cancel", "deadline", "gap", "max_hops", "local_error"):
            raise ValueError("bad stopped_by")
        d.stopped_by = stopped
        d.seconds = num(data.get("seconds")) or 0.0
        d.max_hops = ttl(data.get("max_hops") or MAX_HOPS, MAX_HOPS)
        stop = data.get("silent_stop")
        d.silent_stop = [ttl(stop[0]), ttl(stop[1])] if stop else None
        d.final_hop = None if data.get("final_hop") is None else ttl(data["final_hop"], MAX_HOPS + 1)
        d.tcp_silent_from = None if data.get("tcp_silent_from") is None else ttl(data["tcp_silent_from"])
        d.ping_interval = num(data.get("ping_interval"))
        if data.get("tcp_silent_by") not in (None, "router", "target"):
            raise ValueError("bad tcp_silent_by")
        d.tcp_silent_by = data.get("tcp_silent_by")
        d.icmp_checks = {ttl(c["ttl"]): addr(c["address"], True) for c in data.get("icmp_checks") or []}
        return d

    def trace_text(self) -> str:
        """BSD traceroute -n text with every responder of every hop, for the
        parser and the usual analysis (placement, AS path, annotations)."""
        last = max(self.responders) if self.responders else 0
        # The probe actually sent and the configured hop limit, never the last
        # hop that answered (0.7.1 printed "ICMP echo" and "2 hops max" for a
        # TCP run that stopped on silence), and why the discovery ended.
        mark = METHOD_MARKS.get(self.method, self.method).format(port=probe.TCP_FLOW_PORT)
        size = f"{8 + len(probe.PAYLOAD)} byte packets, " if self.method == "icmp-paris" else ""
        lines = [f"traceroute to {self.target} ({self.address}), {self.max_hops} hops max, {size}{mark}, "
                 f"{PROBER_MARK}, paths, {self.stop_text}"]
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


def _compatible(a: list[str | None], b: list[str | None], target: str) -> bool:
    """Whether two flows' hop sequences are one path: they differ only where
    both got an answer and the answers differ. A silence matches anything. A
    flow that reached the target ends there, so a longer flow that has a
    router at or past that TTL took another path."""
    for x, y in zip(a, b):
        if x is not None and y is not None and x != y:
            return False
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    if short and short[-1] == target:
        return all(x is None or x == target for x in long_[len(short) - 1:])
    return True


def group_flows(seqs: dict[int, list[str | None]], target: str) -> list[tuple[list[str | None], list[int]]]:
    """Flows grouped into paths by :func:`_compatible`; each group's sequence
    fills one member's silences with another's answers and ends at the
    target, once. The best-answered flows seed the groups, so a silence never
    seeds a path of its own."""
    groups: list[tuple[list[str | None], list[int]]] = []
    for f in sorted(seqs, key=lambda f: (sum(x is None for x in seqs[f]), f)):
        s = seqs[f]
        for rep, members in groups:
            if _compatible(rep, s, target):
                members.append(f)
                merged = [x if x is not None else y for x, y in zip(rep, s)]
                longer = rep if len(rep) >= len(s) else s
                merged += longer[len(merged):]
                if target in merged:
                    merged = merged[:merged.index(target) + 1]
                rep[:] = merged
                break
        else:
            groups.append((list(s), [f]))
    return groups


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
                 on_progress: Callable[[dict], None] | None = None,
                 icmp_check: Callable[[int], str | None] | None = None):
        """*icmp_check(ttl)* sends one ICMP echo to the target with that TTL
        and returns the address that answered, or None: given for TCP runs, so
        a stretch silent to TCP can be told from routers that answer nothing."""
        self.target, self.address = target, address
        self.icmp_check = icmp_check
        self.t = transport
        self.o = (options or Options()).clamped()
        self.clock = clock
        self.cancel = cancel
        self.deadline = deadline
        self.on_progress = on_progress
        self.d = Discovery(target, address, probe.family_of(address),
                           method=getattr(transport, "METHOD", METHOD), budget=self.o.budget,
                           max_hops=self.o.max_hops)
        self._seq = secrets.randbelow(0x10000)
        self._last_send: float | None = None
        self._pending: dict[int, tuple[int, int, float]] = {}       # seq -> (flow, ttl, sent at)
        self._result: dict[tuple[int, int], tuple[str | None, float | None, bool]] = {}
        self._reached_at: dict[int, int] = {}                        # flow -> TTL it reached
        self._stop: str | None = None
        self._local_run = 0
        # Each path's ten target attempts come out of the same budget: the
        # discovery stops early enough to leave them, so a run that reaches
        # the cap still measures every path alike (ODIN, test build 4: "6 of
        # 7" beside a note promising ten).
        self._pinging = False
        self._ping_reserve = min(self.o.pings * MAX_PATHS, self.o.budget // 3)
        self._ended: set[int] = set()       # flows that ended at their path's target hop
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
            rtt = max(0.0, (a.at - sent) * 1000)
            # Later than the wait, the answer is to a retransmission (Windows
            # sends a SYN again after about 1 s): it still answered, but the
            # time says nothing about the path.
            got.append((flow, ttl, a.address, None if rtt > self.o.wait * 1000 else rtt, a.reached))
        return got

    def _send(self, flow: int, ttl: int, collected: list) -> bool:
        """Send one probe, no faster than the rate cap; False when the budget
        or a stop condition says no."""
        if self.d.probes_sent >= self.o.budget:
            self._stop = self._stop or "budget"
            return False
        if not self._pinging and self.d.probes_sent >= self.o.budget - self._ping_reserve:
            self._stop = self._stop or "budget"   # the rest is the path pings' share
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
        ready_at = getattr(self.t, "ready_at", None)
        if ready_at is not None:
            while not self._stopping():
                left = ready_at(flow) - self.clock()
                if left <= 0:
                    break
                collected.extend(self._take(self.t.read(min(left, 0.05))))
        self._seq = (self._seq + 1) & 0xFFFF
        while self._seq in self._pending:
            self._seq = (self._seq + 1) & 0xFFFF
        now = self.clock()
        if self.t.send(flow, ttl, self._seq) is False:
            self.d.local_failures += 1
            self._local_run += 1
            if self._local_run >= MAX_LOCAL_FAILURES:
                self._stop = "local_error"
            return None
        self._local_run = 0
        self._pending[self._seq] = (flow, ttl, now)
        self._last_send = now
        self.d.probes_sent += 1
        return True

    def _batch(self, items: list[tuple[int, int]]) -> list[tuple[int, int, str | None, float | None, bool]]:
        """Probe (flow, TTL) pairs; return (flow, TTL, address or None, RTT, reached)
        for each one sent, after its answer or its wait."""
        collected: list = []
        sent: list[tuple[int, int]] = []
        # A transport that carries one probe per flow at a time (TCP: one
        # connection per five-tuple) gets a flow's next probe only once the
        # earlier one is answered or given up; the others go out meanwhile.
        one_per_flow = getattr(self.t, "ONE_PER_FLOW", False)
        queue = list(items)
        while queue:
            busy = {(f, t) for f, t, _ in self._pending.values()}
            busy_flows = {f for f, _t in busy} if one_per_flow else set()
            pick = next((i for i, (f, t) in enumerate(queue) if (f, t) not in busy and f not in busy_flows), None)
            if pick is None:
                now = self.clock()
                for s, (f, t, at) in list(self._pending.items()):
                    if at + self.o.wait <= now:
                        self._pending.pop(s)
                        self._forget(s)
                collected.extend(self._take(self.t.read(0.05)))
                if self._stopping():
                    break
                continue
            flow, ttl = queue.pop(pick)
            ok = self._send(flow, ttl, collected)
            if ok is None:
                if self._stop:
                    break
                continue                      # never left this machine: not a probe, not a loss
            if not ok:
                break
            sent.append((flow, ttl))
        expiry = {s: self._pending[s][2] + self.o.wait for s in self._pending}
        while self._pending and not (self.cancel is not None and self.cancel.is_set()):
            now = self.clock()
            for s in [s for s, end in expiry.items() if end <= now and s in self._pending]:
                self._pending.pop(s)
                self._forget(s)
            if not self._pending:
                break
            left = min(expiry[s] for s in self._pending) - now
            collected.extend(self._take(self.t.read(max(left, 0.0))))
        for s in list(self._pending):
            self._forget(s)
        self._pending.clear()
        answered = {(f, t): (a, r, reached) for f, t, a, r, reached in collected}
        out = []
        for flow, ttl in sent:
            a, r, reached = answered.get((flow, ttl), (None, None, False))
            out.append((flow, ttl, a, r, reached))
        return out

    def _forget(self, seq: int):
        """The discoverer stopped waiting for *seq*: the transport drops it too,
        so a flow's next probe never waits on a probe nobody will read."""
        forget = getattr(self.t, "forget", None)
        if forget is not None:
            forget(seq)

    def _drain_until_clear(self, flow: int, ttl: int, collected: list):
        while any(f == flow and t == ttl for f, t, _ in self._pending.values()):
            now = self.clock()
            for s, (f, t, sent) in list(self._pending.items()):
                if sent + self.o.wait <= now:
                    self._pending.pop(s)
                    self._forget(s)
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
        target at an earlier TTL, nor ended at the target's hop of its path)."""
        if flow in self._ended:
            return False
        at = self._reached_at.get(flow)
        return at is None or at >= ttl

    def _probe_items(self, todo: list[tuple[int, int]]):
        todo = [(f, t) for f, t in todo if (f, t) not in self._result and self._alive(f, t)]
        if not todo:
            return
        self._record(self._batch(todo))
        # One retry for probes a hop left unanswered while it answered others
        # (rate limiting, a lost reply), so a silence does not split a path.
        answered = {t for f, t in todo if self._result.get((f, t), (None,))[0]}
        retry = [(f, t) for f, t in todo if t in answered and self._result.get((f, t), (None,))[0] is None
                 and self._alive(f, t)]
        if retry:
            for key in retry:
                self._result.pop(key, None)
            self._record(self._batch(retry))

    def _probe_flows_at(self, ttl: int, flows: range | list[int]):
        self._probe_items([(f, ttl) for f in flows])

    def _backfill(self, flows: range, upto: int):
        """New flows at every earlier hop, in one batch: hop by hop across the
        flows, so a flow's probes are spread out and no hop waits for the
        previous one's silences."""
        if self._stopping():
            return
        self._probe_items([(f, t) for t in range(1, upto) for f in flows])

    def _check_icmp(self, ttl: int):
        """One ICMP echo at *ttl* for a hop silent to every TCP probe, inside
        the budget (the pings' share excepted) and the rate cap."""
        if self.icmp_check is None or ttl in self.d.icmp_checks or self._stopping():
            return
        if self.d.probes_sent >= self.o.budget - self._ping_reserve:
            return
        spacing = 1.0 / self.o.rate + 1e-4
        if self._last_send is not None:
            while (left := self._last_send + spacing - self.clock()) > 0:
                self.t.read(left)             # nothing is pending between hops; this only waits
        self._last_send = self.clock()
        self.d.probes_sent += 1
        try:
            self.d.icmp_checks[ttl] = self.icmp_check(ttl)
        except Exception:  # noqa: BLE001 - a failed check is no answer, never a failed run
            self.d.icmp_checks[ttl] = None

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
                    if responders and responders <= {self.address}:
                        # Only the target answers here: the stopping rule is
                        # about routers, and counting the few flows that got
                        # this far added flows and probed each at every
                        # earlier hop (Mac run, 25 Oct 2026: 1,350 probes for
                        # a path complete at TTL 15).
                        break
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
                self._end_at_target(ttl, m)
                self._progress(ttl)
                alive = [f for f in range(m) if self._alive(f, ttl + 1)]
                silent = not any((self._result.get((f, ttl)) or (None,))[0] for f in range(m))
                gap = gap + 1 if silent else 0
                if silent:
                    self._check_icmp(ttl)
                if self._stop:
                    break
                if not alive:
                    d.stopped_by = "complete"
                    break
                if gap >= GAP_LIMIT:
                    d.stopped_by = "gap"
                    d.silent_stop = [ttl - gap + 1, ttl]
                    break
            else:
                d.stopped_by = "max_hops"
            d.flows_used = m
            if not self._stop:
                self._settle_reach(m)
            self._build_paths(m)
            d.discovery_probes = d.probes_sent
            if self._stop in (None, "budget"):
                budget_hit = self._stop == "budget"
                self._stop, self._pinging = None, True
                self._ping_paths()
                self._final_answers()
                if budget_hit and self._stop is None:
                    self._stop = "budget"
            self._tcp_silence()
        finally:
            self.t.close()
        if self._stop:
            d.stopped_by = self._stop
        d.seconds = self.clock() - self._started
        log.info("event=paths_done target=%s paths=%d probes=%d stopped_by=%s", tag(self.target),
                 len(d.paths), d.probes_sent, d.stopped_by)
        return d

    def _end_at_target(self, ttl: int, m: int):
        """Flows that were silent at the TTL where other flows of the same
        path reached the target: asked there again (twice at most), then never
        probed deeper. A flow with a router at that TTL is on another path and
        goes on."""
        reached = {g: r for g, r in self._reached_at.items() if r <= ttl}
        if not reached:
            return

        def same_path(f: int, g: int, r: int) -> bool:
            for t in range(1, r):
                a = (self._result.get((f, t)) or (None,))[0]
                b = (self._result.get((g, t)) or (None,))[0]
                if a is not None and b is not None and a != b:
                    return False
            return True
        todo: list[tuple[int, int]] = []
        for f in range(m):
            if f in self._reached_at or f in self._ended:
                continue
            for g, r in reached.items():
                if (f, r) in self._result and self._result[(f, r)][0] is None and same_path(f, g, r):
                    todo.append((f, r))
                    break
        ended = [f for f, _r in todo]
        for _ in range(2):
            if not todo or self._stopping():
                break
            for key in todo:
                self._result.pop(key, None)
            self._record(self._batch(todo))
            for f, r in todo:
                self._result.setdefault((f, r), (None, None, False))
            todo = [(f, r) for f, r in todo if f not in self._reached_at]
        self._ended.update(ended)

    def _per_packet(self, ttl: int) -> bool:
        # A router's answer, not the target's: probing a flow that reached a TCP
        # target again at once would only meet the target's reuse limit.
        answered = [f for f in range(MAX_FLOWS) if (self._result.get((f, ttl)) or (None,))[0]]
        flow = next((f for f in answered if not self._result[(f, ttl)][2]), answered[0] if answered else None)
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
            paths = len(group_flows(self._sequences(range(MAX_FLOWS), ttl), self.address))
            self.on_progress({"ttl": ttl, "paths": paths, "probes": self.d.probes_sent, "budget": self.o.budget})
        except Exception:  # noqa: BLE001 - the display must not stop the run
            pass

    def _sequences(self, flows, upto: int | None = None) -> dict[int, list[str | None]]:
        """Each probed flow's responders from TTL 1, ending at the TTL it
        reached the target (or at *upto*, or the last TTL probed)."""
        per_packet = set(self.d.per_packet_hops)
        last = max((t for (_f, t) in self._result), default=0)
        if upto is not None:
            last = min(last, upto)
        out = {}
        for f in flows:
            if (f, 1) not in self._result:
                continue
            end = min(last, self._reached_at.get(f, last))
            out[f] = [None if t in per_packet else (self._result.get((f, t)) or (None,))[0]
                      for t in range(1, end + 1)]
            while out[f] and out[f][-1] is None and f not in self._reached_at:
                out[f].pop()
        return out

    def _settle_reach(self, m: int):
        """A flow that reached the target only after silent hops past its last
        router: probe the first of those hops again (twice at most). A TCP
        target ignores a repeated connection attempt from the same port for a
        moment, so the silence may have been the target, and then that is
        where the path ends; otherwise the silences stand."""
        todo: dict[int, tuple[int, int]] = {}            # flow -> (first silent TTL, reach)
        for f in range(m):
            reach = self._reached_at.get(f)
            if reach is None:
                continue
            last_router = max((t for t in range(1, reach) if (self._result.get((f, t)) or (None,))[0]), default=0)
            if last_router + 1 < reach:
                todo[f] = (last_router + 1, reach)
        for _ in range(2):                               # all flows in one round, twice at most
            if not todo or self._stopping():
                return
            for f, (first, _reach) in todo.items():
                self._result.pop((f, first), None)
            self._record(self._batch([(f, first) for f, (first, _reach) in todo.items()]))
            for f, (first, reach) in list(todo.items()):
                if self._reached_at.get(f) == first:
                    for t in range(first + 1, reach + 1):
                        self._result.pop((f, t), None)
                    del todo[f]

    def _rebuild_hops(self):
        """Responders and RTTs per hop from each flow's final answers, so a
        target answer a settled flow made at a later TTL is not a hop."""
        d = self.d
        d.responders, d.rtts = {}, {}
        for (f, t), (addr, rtt, _reached) in sorted(self._result.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            if t == PING_HOPS or addr is None or t > self._reached_at.get(f, t):
                continue
            seen = d.responders.setdefault(t, [])
            if addr not in seen:
                seen.append(addr)
            if rtt is not None:
                d.rtts.setdefault((t, addr), []).append(rtt)

    def _build_paths(self, m: int):
        d = self.d
        self._rebuild_hops()
        last = max(d.responders) if d.responders else 0
        per_packet = set(d.per_packet_hops)
        groups = group_flows(self._sequences(range(m)), self.address)
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
        """Every path pinged :data:`PATH_PINGS` times at the full hop limit,
        reached or not (a path that never reached the target is asked too, so
        "not reached" is an answer), one round across all paths at a time and
        each round on the path's next flow, so no flow is probed back to back
        (a TCP target ignores a quick repeat from the same port) and the waits
        overlap."""
        d = self.d
        if not self.o.pings:
            return
        reached = list(d.paths)
        rtts: dict[str, list[float]] = {p.id: [] for p in reached}
        d.ping_interval = PING_INTERVAL
        last_round: float | None = None
        for r in range(self.o.pings):
            if self._stopping():
                break
            if last_round is not None:
                while (left := last_round + PING_INTERVAL - self.clock()) > 0 and not self._stopping():
                    self.t.read(left)         # nothing is pending between rounds; this only waits
            last_round = self.clock()
            owner = {p.flows[r % len(p.flows)]: p for p in reached}
            for flow, _ttl, addr, rtt, ok in self._batch([(f, PING_HOPS) for f in owner]):
                path = owner[flow]
                path.pings_sent += 1
                if ok and addr:
                    if rtt is not None:
                        rtts[path.id].append(rtt)
                else:
                    path.pings_lost += 1
        for p in reached:
            p.rtt_to_target_ms = _median(rtts[p.id])
            if p.reached:
                p.reached_by = "discovery"
            elif p.pings_sent > p.pings_lost:
                p.reached, p.reached_by = True, "full_ttl"

    def _final_answers(self):
        """Paths reached only by the full-TTL attempts: the target is numbered
        :attr:`Discovery.final_hop`, the hop after the last one sent (as RIPE
        Atlas numbers the answer to its TTL 255 probe), each path's silent
        stretch is marked, and the main hop list shows the target there."""
        d = self.d
        late = [p for p in d.paths if p.reached_by == "full_ttl"]
        if not late:
            return
        sent = max((t for (_f, t) in self._result if t != PING_HOPS), default=0)
        d.final_hop = min(sent, MAX_HOPS) + 1
        for p in late:
            last = max((i + 1 for i, a in enumerate(p.hops) if a is not None), default=0)
            p.hops = p.hops[:last] + [None] * (d.final_hop - 1 - last) + [self.address]
            p.rtt_ms = p.rtt_ms[:last] + [None] * (d.final_hop - 1 - last) + [p.rtt_to_target_ms]
            p.silent = [last + 1, d.final_hop - 1] if d.final_hop - 1 > last else None
        seen = d.responders.setdefault(d.final_hop, [])
        if self.address not in seen:
            seen.append(self.address)
        d.rtts.setdefault((d.final_hop, self.address), []).extend(
            p.rtt_to_target_ms for p in late if p.rtt_to_target_ms is not None)

    def _tcp_silence(self):
        d = self.d
        d.tcp_silent_from, d.tcp_silent_by = tcp_silence(d)


def tcp_silence(d: Discovery) -> tuple[int | None, str | None]:
    """Where TCP probes went unanswered while the ICMP check at the same TTL
    was answered, and by whom: (first TTL of the silent stretch that ended the
    discovery, "router" or "target"), or (None, None).

    "router": routers there answer ICMP but not TCP probes; a trace over
    ICMP can map on. "target": the target itself answered ICMP at that TTL,
    so the routers in front of it were all found, and only its TCP service
    stayed silent until the full-TTL attempts; something in front of the
    target that answers for it, a firewall or load balancer, is the likely
    reading (ODIN, heise.de, 25 Oct 2026: TCP silent at 15 to 19, every
    ICMP check there answered by 193.99.144.80, the full-TTL attempt
    reached it)."""
    if not d.silent_stop:
        return None, None
    answer = d.icmp_checks.get(d.silent_stop[0])
    if not answer:
        return None, None
    return d.silent_stop[0], ("target" if answer == d.address else "router")


def available() -> tuple[bool, str]:
    """Whether path discovery can run on this system, and why not."""
    return probe.flow_available()


def discover(target: str, *, family: str = "auto", options: Options | None = None,
             cancel: threading.Event | None = None, deadline: float | None = None,
             on_progress: Callable[[dict], None] | None = None, address: str | None = None) -> Discovery:
    """Discover the paths to *target* (a validated hostname or address) with
    the built-in Paris prober. Blocking: run it in a worker thread. *address*
    is the target's address when the caller has resolved it already (the
    address it shows, :func:`routemap_engine.dnstime.resolve_target`); otherwise
    it is resolved here, once."""
    ok, why = available()
    if not ok:
        raise RuntimeError(why)
    address = address or probe.resolve(target, family)
    probe.check_route(address)
    tcp = probe.flow_method() == probe.TcpFlowTransport.METHOD
    transport = probe.TcpFlowTransport(address) if tcp else probe.FlowTransport(address)
    return Discoverer(target, address, transport, options=options, cancel=cancel,
                      deadline=deadline, on_progress=on_progress,
                      icmp_check=icmp_checker(address) if tcp else None).run()


def icmp_checker(address: str, wait: float = WAIT) -> Callable[[int], str | None] | None:
    """One ICMP echo to *address* at a given TTL with the built-in prober
    (Windows' ICMP function, no administrator rights), or None where the
    prober cannot run for that family."""
    if not probe.available(probe.family_of(address))[0]:
        return None
    seq = [secrets.randbelow(0x10000)]

    def check(ttl: int) -> str | None:
        seq[0] = (seq[0] + 1) & 0xFFFF
        return probe._probe(address, ttl, seq[0], wait).address
    return check
