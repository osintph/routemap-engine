"""
The Route Map engine. Pure Python: nothing in this package imports Qt.

    from routemap.engine import analyse_sync, run_trace, TraceOptions

    result = run_trace("heise.de", TraceOptions(on_line=print))
    route = analyse_sync(result.text, origin=(14.6, 121.0))
    route.to_dict()          # the JSON route model, see route.schema.json

FalconEye imports this package for its Route Map tab, so anything added here
ships to a web server as well as to the desktop app.
"""
from routemap.engine.cache import MemoryCache, NullCache, SqliteCache
from routemap.engine.geo import OFFLINE, Sources, default_sources
from routemap.engine.model import (Route, analyse, analyse_sync, normalise_origin,
                                   origin_block, schema)
from routemap.engine.parse import Hop, ParsedTrace, TraceParseError, parse_trace
from routemap.engine.runner import (TraceOptions, TraceResult, TraceToolMissing,
                                    available_tools, install_hint, run_trace)
from routemap.engine.target import InvalidTarget, validate_target

__all__ = [
    "Hop", "InvalidTarget", "MemoryCache", "NullCache", "OFFLINE", "ParsedTrace",
    "Route", "Sources", "SqliteCache", "TraceOptions", "TraceParseError",
    "TraceResult", "TraceToolMissing", "analyse", "analyse_sync",
    "available_tools", "default_sources", "install_hint", "normalise_origin",
    "origin_block", "parse_trace", "run_trace", "schema", "validate_target",
]
