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
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "Route":
        """Rebuild a Route from :meth:`to_dict` output (history, JSON import)."""
        return cls(parser=data["parser"], parser_label=data["parser_label"],
                   target=data.get("target"), warnings=list(data.get("warnings") or []),
                   hoiho_ruleset_date=data.get("hoiho_ruleset_date"),
                   origin=dict(data.get("origin") or {}),
                   hops=[dict(h) for h in data.get("hops") or []],
                   paths=copy.deepcopy(data["paths"]) if isinstance(data.get("paths"), dict) else None)

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
                  origin_slack_km: float = geo.SLACK_KM) -> Route:
    """Parse (if needed), locate and annotate one trace.

    *trace* is traceroute/tracert/mtr text, a :class:`ParsedTrace`, or a list
    of :class:`Hop`. *origin* is ``(lat, lon)`` or None. *sources* defaults to
    the live network sources; pass ``geo.OFFLINE`` to contact nothing.
    *progress* is told when each source starts and finishes.

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
    located = resolved["hops"]
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
                   "min_rtt_ms", "avg_rtt_ms", "reason")


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
    located = geo.annotate(geo.neighbour_check(geo.locate_hops(parsed.hops, hoiho_records, ip_records,
                                                               origin)))
    out = discovery.to_dict()
    for path, entry in zip(discovery.paths, out["paths"]):
        hops = []
        for ttl, (addr, rtt) in enumerate(zip(path.hops, path.rtt_ms), start=1):
            hop = Hop(hop=ttl, sent=1, lost=0 if addr else 1)
            if addr:
                hop.add_address(addr)
                if names.get(addr):
                    hop.add_hostname(names[addr])
                if rtt is not None:
                    hop.rtts_ms.append(round(rtt, 3))
            hops.append(hop)
        placed = geo.locate_hops(hops, hoiho_records, ip_records, origin) if hops else []
        entry["located"] = [{k: h.get(k) for k in PATH_HOP_FIELDS} for h in placed]
    return Route(parser=parsed.parser, parser_label=PARSER_LABELS.get(parsed.parser, parsed.parser),
                 target=discovery.target, warnings=list(parsed.warnings), hoiho_ruleset_date=ruleset,
                 origin=origin_block(origin, located), hops=located, paths=out)


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
