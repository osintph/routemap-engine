"""
Placing hops while the trace is still running.

The tool prints one hop at a time, a second or more apart. Waiting for it to
finish before placing anything leaves the map empty for a minute. So each line
is folded into the trace as it arrives, and every hop that is new, or whose data
changed, is placed at once with exactly the same rules as a finished trace:
hostname first (PTR to fill a missing name, Hoiho, the carrier site code), the
IP database as the fallback, and the RTT bound on every candidate.

What a single hop cannot know is decided once the tool exits, in
:meth:`ProgressiveTrace.finish`: a hop that turned out to have answered from more
than one router (ECMP continuation lines arrive after the hop's first line) is
placed again with all its routers, and the annotations that compare hops with
each other (asymmetric return path, ICMP rate limiting, the silent tail) are
computed over the whole path. Nothing else is redone.

The parser is the ordinary one, run over the text received so far. A trace is
at most a few kilobytes, so re-parsing per line costs nothing and there is no
second, incremental parser to keep in step with the first.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Callable

from routemap_engine import geo
from routemap_engine.model import Route, origin_block
from routemap_engine.parse import PARSER_LABELS, Hop, TraceParseError, parse_trace

log = logging.getLogger("routemap_engine.progressive")

# CAIDA asks for at most one request a second. A trace prints about one hop a
# second, so placing hop by hop could exceed that; this spaces the calls out.
HOIHO_MIN_INTERVAL_SECONDS = 1.0


def _signature(hop: Hop) -> tuple:
    return (tuple(hop.addresses), tuple(hop.hostnames), hop.min_rtt_ms, hop.sent, hop.lost)


def _spaced(source, interval: float):
    """Wrap an async source so calls start at least *interval* seconds apart."""
    if source is None:
        return None
    state = {"last": 0.0}
    lock = asyncio.Lock()

    async def call(items):
        async with lock:
            loop = asyncio.get_running_loop()
            wait = state["last"] + interval - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
            state["last"] = loop.time()
        return await source(items)

    return call


class ProgressiveTrace:
    """Feed lines in; get each hop placed as soon as it can be.

    ``on_hop(entry)`` is called with each placed hop dict (the same shape as a
    hop in :meth:`Route.to_dict`), possibly more than once for the same hop
    number when its data changes. Call :meth:`feed` from any thread; the async
    methods run on one event loop.
    """

    def __init__(self, origin: tuple[float, float] | None, sources: geo.Sources,
                 on_hop: Callable[[dict], None] | None = None,
                 progress: geo.ProgressFn | None = None):
        self.origin = origin
        self.sources = geo.Sources(
            hoiho=_spaced(sources.hoiho, HOIHO_MIN_INTERVAL_SECONDS),
            ip_db=sources.ip_db, ptr=sources.ptr, hoiho_budget=sources.hoiho_budget,
            ip_db_budget=sources.ip_db_budget, ptr_budget=sources.ptr_budget)
        self.on_hop = on_hop
        self.progress = progress
        self.text = ""
        self.parsed = None
        self.placed: dict[int, dict] = {}       # hop number -> located entry
        self.placed_sig: dict[int, tuple] = {}  # hop number -> signature it was placed with
        self.hops: dict[int, Hop] = {}          # latest parse of each hop

    # ------------------------------------------------------------- input ---
    def feed(self, line: str) -> list[Hop]:
        """Add one line of tool output. Returns hops that are new or changed."""
        self.text += line.rstrip("\r\n") + "\n"
        try:
            parsed = parse_trace(self.text)
        except TraceParseError:
            return []
        self.parsed = parsed
        changed = []
        for hop in parsed.hops:
            self.hops[hop.hop] = hop
            if self.placed_sig.get(hop.hop) != _signature(hop):
                changed.append(hop)
        return changed

    # ----------------------------------------------------------- placing ---
    async def place(self, hop: Hop) -> dict:
        """Locate one hop now, with the full source order and the RTT bound."""
        single = Hop(hop=hop.hop, addresses=list(hop.addresses), hostnames=list(hop.hostnames),
                     rtts_ms=list(hop.rtts_ms), sent=hop.sent, lost=hop.lost, codes=list(hop.codes))
        signature = _signature(hop)
        result = await geo.resolve([single], self.origin, self.sources, self.progress)
        entry = result["hops"][0]
        # Annotations need the whole path; they are added in finish().
        entry["annotations"] = [a for a in entry["annotations"] if a == geo.ANNOT_LOCAL
                                or a == geo.ANNOT_RTT_IMPOSSIBLE]
        entry.pop("annotation_details", None)
        # The signature is the parsed hop's, before PTR added a name to the copy,
        # so the next re-parse of the same text does not look like a change.
        self.placed[hop.hop] = entry
        self.placed_sig[hop.hop] = signature
        if result.get("hoiho_ruleset_date"):
            self.ruleset = result["hoiho_ruleset_date"]
        if self.on_hop is not None:
            try:
                self.on_hop(entry)
            except Exception as exc:  # noqa: BLE001
                log.warning("on_hop callback raised: %s", exc)
        return entry

    def snapshot(self) -> dict:
        """The route so far, as a Route-shaped dict (hops in order)."""
        hops = [self.placed[n] for n in sorted(self.placed)]
        parser = self.parsed.parser if self.parsed else "traceroute"
        return {"parser": parser, "parser_label": PARSER_LABELS.get(parser, parser),
                "target": self.parsed.target if self.parsed else None,
                "warnings": [], "hoiho_ruleset_date": getattr(self, "ruleset", None),
                "origin": origin_block(self.origin, hops), "hops": hops}

    async def finish(self) -> Route:
        """After the tool exits: place what changed (ECMP), annotate the path."""
        if self.parsed is None:
            self.parsed = parse_trace(self.text)  # raises TraceParseError on junk
        for hop in self.parsed.hops:
            if self.placed_sig.get(hop.hop) != _signature(hop):
                await self.place(hop)
        located = [self.placed[h.hop] for h in self.parsed.hops if h.hop in self.placed]
        for entry in located:
            entry.pop("annotation_details", None)
        # The same two passes as geo.resolve, so a live trace ends where the
        # one-shot analysis of its text ends.
        geo.annotate(geo.neighbour_check(located))
        return Route(parser=self.parsed.parser,
                     parser_label=PARSER_LABELS.get(self.parsed.parser, self.parsed.parser),
                     target=self.parsed.target, warnings=list(self.parsed.warnings),
                     hoiho_ruleset_date=getattr(self, "ruleset", None),
                     origin=origin_block(self.origin, located), hops=located)
