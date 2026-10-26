"""
The route model: what one analysed trace is, and the one function that makes it.

``analyse(trace_text | hops, origin) -> Route`` is the engine's front door. The
FalconEye tab, the desktop window, the CLI and the JSON export all read a
:class:`Route` and nothing else, so there is exactly one place a hop can be
placed and exactly one shape a renderer has to understand.

THE SHAPE IS A CONTRACT
-----------------------
:meth:`Route.to_dict` is byte-for-byte the body FalconEye's
``POST /api/routemap/analyze`` has returned since v3.35.0, because the FalconEye
frontend and its MCP tool both read it. ``route.schema.json`` next to this file
describes it, and a test validates real analyses against that schema, so a
field cannot be added, renamed or dropped without the schema (and the reader of
this comment) noticing.

Each hop is a plain dict rather than a class for the same reason: it is the
JSON object the renderers already consume, and a parallel class would be a
second definition to keep in step with the first.
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
from dataclasses import dataclass, field
from importlib import resources

from routemap_engine import cities, geo
from routemap_engine.parse import PARSER_LABELS, Hop, ParsedTrace, TraceParseError, parse_trace

log = logging.getLogger("routemap_engine.model")

# Where the path starts, and how we know.
ORIGIN_SUPPLIED = "supplied"     # the caller gave coordinates
ORIGIN_FIRST_HOP = "first-hop"   # no origin: anchored on the first located hop
ORIGIN_NONE = "none"             # no origin and nothing located


@dataclass
class Route:
    parser: str
    parser_label: str
    target: str | None
    warnings: list[str]
    hoiho_ruleset_date: str | None
    origin: dict
    hops: list[dict] = field(default_factory=list)
    # Path discovery (0.7.0): multipath.Discovery.to_dict() plus each path's
    # located hops. None for an ordinary trace, and then not in to_dict(), so
    # FalconEye's output is unchanged.
    paths: dict | None = None
    # 0.8.0, each None unless the caller measured it, and then not in
    # to_dict(): the address traced (dnstime.Resolved), the DNS timing rows
    # (dnstime.Lookup) and the port tests (ports.PortsResult).
    resolved: dict | None = None
    dns: list | None = None
    ports: dict | None = None

    def to_dict(self) -> dict:
        """The JSON object, keys in the order FalconEye has always sent them."""
        out = {
            "parser": self.parser,
            "parser_label": self.parser_label,
            "target": self.target,
            "warnings": list(self.warnings),
            "hoiho_ruleset_date": self.hoiho_ruleset_date,
            "origin": dict(self.origin),
            "hops": [dict(h) for h in self.hops],
        }
        if self.paths is not None:
            out["paths"] = copy.deepcopy(self.paths)
        for key in ("resolved", "dns", "ports"):
            if getattr(self, key) is not None:
                out[key] = copy.deepcopy(getattr(self, key))
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "Route":
        """Rebuild a Route from :meth:`to_dict` output (history, JSON import)."""
        return cls(parser=data["parser"], parser_label=data["parser_label"],
                   target=data.get("target"), warnings=list(data.get("warnings") or []),
                   hoiho_ruleset_date=data.get("hoiho_ruleset_date"),
                   origin=dict(data.get("origin") or {}),
                   hops=[dict(h) for h in data.get("hops") or []],
                   paths=copy.deepcopy(data["paths"]) if isinstance(data.get("paths"), dict) else None,
                   resolved=copy.deepcopy(data["resolved"]) if isinstance(data.get("resolved"), dict) else None,
                   dns=copy.deepcopy(data["dns"]) if isinstance(data.get("dns"), list) else None,
                   ports=copy.deepcopy(data["ports"]) if isinstance(data.get("ports"), dict) else None)

    @property
    def loss(self) -> dict:
        """The route's loss, :func:`geo.loss_verdict` over the hops.

        Computed, not stored: :meth:`to_dict` is FalconEye's contract and does
        not carry it, and a Route rebuilt from an older export or the history
        gets the verdict too.
        """
        return geo.loss_verdict(self.hops)

    @property
    def placed(self) -> list[dict]:
        """Hops with a location on the map."""
        return [h for h in self.hops if h.get("lat") is not None]

    @property
    def unplaced(self) -> list[dict]:
        """Hops with no location, each carrying its ``reason``."""
        return [h for h in self.hops if h.get("lat") is None]


def schema() -> dict:
    """The JSON Schema for :meth:`Route.to_dict`."""
    text = resources.files("routemap_engine").joinpath("route.schema.json").read_text("utf-8")
    return json.loads(text)


def normalise_origin(lat, lon) -> tuple[float, float] | None:
    """A caller-supplied origin, or None. Out of range is no origin, not an error.

    Rounded to two decimal places (about a kilometre): the bound has a 300 km
    tolerance, so more precision buys nothing and says more about the user.
    """
    if lat is None or lon is None:
        return None
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    return (round(lat, 2), round(lon, 2))


def origin_block(origin: tuple[float, float] | None, located: list[dict]) -> dict:
    """What the route says about where the path starts.

    With no origin the first located hop is the anchor of last resort, labelled
    as such. Never anybody's server location.
    """
    if origin is None:
        anchor = geo.first_located(located)
        if anchor is None:
            return {"lat": None, "lon": None, "label": None, "source": ORIGIN_NONE}
        city = cities.nearest(*anchor)
        return {"lat": anchor[0], "lon": anchor[1],
                "label": (city or {}).get("display"), "source": ORIGIN_FIRST_HOP}
    city = cities.nearest(*origin)
    return {"lat": origin[0], "lon": origin[1],
            "label": (city or {}).get("display") or f"{origin[0]}, {origin[1]}",
            "source": ORIGIN_SUPPLIED}


def _parsed(trace) -> ParsedTrace:
    if isinstance(trace, ParsedTrace):
        return trace
    if isinstance(trace, str):
        return parse_trace(trace)
    hops = list(trace or [])
    if not all(isinstance(h, Hop) for h in hops):
        raise TypeError("analyse() takes trace text, a ParsedTrace or a list of Hop")
    return ParsedTrace(parser="hops", hops=hops)


async def analyse(trace, origin: tuple[float, float] | None = None, *,
                  sources: geo.Sources | None = None,
                  progress: geo.ProgressFn | None = None,
                  origin_slack_km: float = geo.SLACK_KM,
                  destination: str | None = None) -> Route:
    """Parse (if needed), locate and annotate one trace.

    *trace* is traceroute/tracert/mtr text, a :class:`ParsedTrace`, or a list
    of :class:`Hop`. *origin* is ``(lat, lon)`` or None. *sources* defaults to
    the live network sources; pass ``geo.OFFLINE`` to contact nothing.
    *progress* is told when each source starts and finishes. *destination* is
    the address traced (by default the one the banner names; mtr prints
    none), so a destination that answered too fast for its registered place
    is placed as anycast (:func:`geo.place_anycast`).

    Raises :class:`TraceParseError` for text that is not a trace and for a
    trace with no hops, and ValueError for an origin outside the globe.
    """
    if origin is not None:
        checked = normalise_origin(*origin)
        if checked is None:
            raise ValueError(f"origin {origin!r} is not a latitude, longitude pair")
        origin = (float(origin[0]), float(origin[1]))

    parsed = _parsed(trace)
    if not parsed.hops:
        raise TraceParseError("No hops were found in that trace.")

    resolved = await geo.resolve(parsed.hops, origin, sources=sources, progress=progress,
                                 slack_km=origin_slack_km)
    located = geo.place_anycast(resolved["hops"], origin, destination or geo.destination_of(parsed.target))
    one_place_per_address(located, [], _named(parsed.hops))
    geo.share_inferred(geo.place_by_neighbours(located, origin), origin)
    return Route(
        parser=parsed.parser,
        parser_label=PARSER_LABELS.get(parsed.parser, parsed.parser),
        target=parsed.target,
        warnings=list(parsed.warnings),
        hoiho_ruleset_date=resolved["hoiho_ruleset_date"],
        origin=origin_block(origin, located),
        hops=located,
    )


# What a path's located hop keeps: where it is and how it was placed.
PATH_HOP_FIELDS = ("hop", "address", "hostname", "lat", "lon", "place", "cc", "source",
                   "ip_provider", "precision", "min_rtt_ms", "avg_rtt_ms", "reason")


# ip_provider and precision are optional in a path's hop, absent unless set.
_REQUIRED_PATH_FIELDS = tuple(k for k in PATH_HOP_FIELDS if k not in ("ip_provider", "precision"))
_PLACE_KEYS = ("lat", "lon", "place", "cc", "source", "ip_provider", "precision")


def one_place_per_address(main: list[dict], paths: list[list[dict]], named: dict[str, str] | None = None) -> None:
    """One address, one placement in a run. The same router answers at
    several hops and on several paths, each judged with its own RTT and
    neighbours; a placement any of them rules out (the round trip, or a
    detour its neighbours exclude) is ruled out for all, and otherwise every
    row shows the same place. *named* maps an address to the hostname it was
    printed or resolved with. Edits the rows in place."""
    named = named or {}
    rows: dict[str, list[dict]] = {}
    sources: dict[str, list[dict]] = {}
    # A path's rows come first, and a main row only counts as evidence when
    # one router answered its hop, or when the name that placed it is known
    # to be its address's own: otherwise, with several routers, its hostname
    # can be another router's (the first name found at the hop), and so its
    # placement too.
    for entry in [h for path in paths for h in path] + main:
        if entry.get("address"):
            rows.setdefault(entry["address"], []).append(entry)
            if len(entry.get("addresses") or [entry["address"]]) == 1 or \
                    (entry.get("hostname") and named.get(entry["address"]) == entry["hostname"]):
                sources.setdefault(entry["address"], []).append(entry)
    for addr, entries in rows.items():
        evidence = sources.get(addr) or []
        rejected = next((e for e in evidence if geo.ANNOT_RTT_IMPOSSIBLE in (e.get("annotations") or [])
                         or str(e.get("reason") or "").startswith(geo.ANNOT_RTT_IMPOSSIBLE)), None)
        if rejected is not None:
            for e in entries:
                for key in ("lat", "lon", "place", "cc", "distance_km", "rtt_budget_km"):
                    if key in e:
                        e[key] = None
                e["source"] = geo.SOURCE_UNRESOLVED
                e["reason"] = rejected.get("reason")
                if "annotations" in e and geo.ANNOT_RTT_IMPOSSIBLE not in e["annotations"]:
                    e["annotations"] = list(e["annotations"]) + [geo.ANNOT_RTT_IMPOSSIBLE]
            continue
        placed = next((e for e in evidence if e.get("lat") is not None), None)
        if placed is None:
            for e in entries:                       # nothing places this router: no borrowed place
                if len(e.get("addresses") or [e["address"]]) > 1 and e.get("lat") is not None:
                    for key in ("lat", "lon", "place", "cc", "distance_km", "rtt_budget_km"):
                        if key in e:
                            e[key] = None
                    e["source"], e["hostname"] = geo.SOURCE_UNRESOLVED, None
                    e.pop("ip_provider", None)
                    e.pop("precision", None)
            continue
        for e in entries:
            if len(e.get("addresses") or [e["address"]]) > 1:
                e["hostname"] = placed.get("hostname") or named.get(addr)   # the router it is placed by
            for key in _PLACE_KEYS:
                if placed.get(key) is not None:
                    e[key] = placed[key]
                elif key in ("ip_provider", "precision"):
                    e.pop(key, None)                 # optional: absent, never null
                else:
                    e[key] = None


async def analyse_paths(discovery, origin: tuple[float, float] | None = None, *,
                        sources: geo.Sources | None = None,
                        progress: geo.ProgressFn | None = None) -> Route:
    """Locate a path discovery (:class:`multipath.Discovery`): the Route of
    every responder at every hop, as for any trace, plus ``paths`` with each
    path's own located hops. Every source is asked once; each path is placed
    from the same answers, so a path costs no extra lookups."""
    if origin is not None:
        if normalise_origin(*origin) is None:
            raise ValueError(f"origin {origin!r} is not a latitude, longitude pair")
        origin = (float(origin[0]), float(origin[1]))
    parsed = parse_trace(discovery.trace_text())
    if not parsed.hops:
        raise TraceParseError("No hops were found in that trace.")
    hoiho_records, ruleset, ip_records, names = await geo.gather_records(parsed.hops, sources, progress)
    located = geo.place_anycast(geo.annotate(geo.neighbour_check(geo.locate_hops(parsed.hops, hoiho_records,
                                                                                 ip_records, origin))),
                                origin, discovery.address)
    out = discovery.to_dict()

    def locate_sequence(seq: list[str | None], rtts: list[float | None]) -> list[dict]:
        hops = []
        for ttl, (addr, rtt) in enumerate(zip(seq, rtts), start=1):
            hop = Hop(hop=ttl, sent=1, lost=0 if addr else 1)
            if addr:
                hop.add_address(addr)
                if names.get(addr):
                    hop.add_named(names[addr], addr)
                if rtt is not None:
                    hop.rtts_ms.append(round(rtt, 3))
            hops.append(hop)
        placed = geo.place_anycast(geo.neighbour_check(geo.locate_hops(hops, hoiho_records, ip_records, origin)),
                                   origin, discovery.address) if hops else []
        return [{k: h.get(k) for k in PATH_HOP_FIELDS if k in _REQUIRED_PATH_FIELDS or h.get(k) is not None}
                for h in placed]

    for path, entry in zip(discovery.paths, out["paths"]):
        entry["located"] = locate_sequence(path.hops, path.rtt_ms)
    # A per-packet hop is on no path row (it does not split paths), and its
    # main row has several routers, which one_place_per_address does not take
    # as evidence; 0.7.1 placed none of them (ODIN, 12 Oct 2026, hop 11
    # 62.115.132.229, placed in Frankfurt by every earlier run). Each router
    # there is placed as the one router of that hop on the first path, with
    # that path's neighbours.
    out["per_packet"] = []
    base = discovery.paths[0] if discovery.paths else None
    for ttl in discovery.per_packet_hops:
        group = []
        for addr in discovery.responders.get(ttl, []):
            if base is None or ttl > len(base.hops):
                continue
            seq, rtts = list(base.hops), list(base.rtt_ms)
            seq[ttl - 1] = addr
            rtts[ttl - 1] = _median_of(discovery.rtts.get((ttl, addr), []))
            group += [h for h in locate_sequence(seq, rtts) if h.get("hop") == ttl]
        out["per_packet"].append({"hop": ttl, "located": group})
    one_place_per_address(located, [entry["located"] for entry in out["paths"]]
                          + [g["located"] for g in out["per_packet"]], dict(names))
    every = [located] + [entry["located"] for entry in out["paths"]]
    for rows in every:
        geo.place_by_neighbours(rows, origin)
    geo.share_inferred([h for rows in every for h in rows] + [h for g in out["per_packet"] for h in g["located"]],
                       origin)
    if discovery.final_hop is not None:
        _mark_final_probe(located, [entry["located"] for entry in out["paths"]], discovery.final_hop)
    label = PARSER_LABELS.get(parsed.parser, parsed.parser)
    if out.get("method") == "tcp-paris":
        # The trace text is written in the ICMP prober's format; the probes were TCP.
        label = f"Built-in TCP prober (port {out.get('port')})"
    return Route(parser=parsed.parser, parser_label=label,
                 target=discovery.target, warnings=list(parsed.warnings), hoiho_ruleset_date=ruleset,
                 origin=origin_block(origin, located), hops=located, paths=out)


def _named(hops: list[Hop]) -> dict[str, str]:
    """Address to hostname, for the pairs the trace or reverse DNS gave."""
    return {addr: name for hop in hops for name, addr in hop.named.items()}


def _median_of(values: list[float]) -> float | None:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


def _mark_final_probe(main: list[dict], paths: list[list[dict]], number: int) -> None:
    """The target's row at :attr:`multipath.Discovery.final_hop`: the answer to
    the full-TTL attempts after a silent stretch, annotated as such."""
    from routemap_engine import multipath
    for entry in main + [h for path in paths for h in path]:
        if entry.get("hop") == number and "annotations" in entry:
            if multipath.ANNOT_FINAL_PROBE not in entry["annotations"]:
                entry["annotations"] = list(entry["annotations"]) + [multipath.ANNOT_FINAL_PROBE]
                details = entry.setdefault("annotation_details", [])
                details.append(f"{multipath.ANNOT_FINAL_PROBE}: {multipath.FINAL_PROBE_DETAIL}")


def analyse_paths_sync(discovery, origin: tuple[float, float] | None = None, *,
                       sources: geo.Sources | None = None,
                       progress: geo.ProgressFn | None = None) -> Route:
    """:func:`analyse_paths` for callers without an event loop."""
    return asyncio.run(analyse_paths(discovery, origin, sources=sources, progress=progress))


def analyse_sync(trace, origin: tuple[float, float] | None = None, *,
                 sources: geo.Sources | None = None,
                 progress: geo.ProgressFn | None = None) -> Route:
    """:func:`analyse` for callers without an event loop (CLI, GUI worker thread)."""
    return asyncio.run(analyse(trace, origin, sources=sources, progress=progress))
