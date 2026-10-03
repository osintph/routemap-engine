"""The engine's front door: analyse() -> Route, its JSON shape, and its rules.

The Route's dict is a contract with every renderer (FalconEye's tab and MCP
tool, the desktop window, the JSON export), so it is validated against the
published schema for every real fixture, both offline and with sources that
answer.
"""
import asyncio
import pathlib
import re

import jsonschema
import pytest

from routemap.engine import (OFFLINE, Route, Sources, TraceParseError, analyse,
                             analyse_sync, geo, schema)
from routemap.engine.parse import Hop

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "routemap"
ENGINE = pathlib.Path(__file__).resolve().parents[1] / "routemap" / "engine"
MANILA = (14.6, 121.0)
ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.txt"))


async def _no_ptr(addresses):
    return {}


async def _fake_ip(addresses):
    # Every public address "is" in Singapore: plausible for some hops, and
    # impossible for the fast ones, so both accepted and rejected candidates
    # appear in the output the schema has to describe.
    return {a: {"lat": 1.29, "lon": 103.85, "city": "Singapore", "cc": "SG"}
            for a in addresses}


async def _fake_hoiho(hostnames):
    records = {h: {"located": False, "lat": None, "lng": None, "place": None,
                   "st": None, "cc": None, "match_strs": [], "match_meanings": []}
               for h in hostnames}
    for h in hostnames:
        if "as6453" in h:
            records[h] = {"located": True, "lat": 37.34, "lng": -121.89,
                          "place": "San Jose", "st": "CA", "cc": "US",
                          "match_strs": ["sanjose"], "match_meanings": ["place"]}
    return records, "2024-08"


ANSWERING = Sources(hoiho=_fake_hoiho, ip_db=_fake_ip, ptr=_no_ptr)


@pytest.mark.parametrize("name", ALL_FIXTURES)
@pytest.mark.parametrize("sources", [OFFLINE, ANSWERING], ids=["offline", "answering"])
def test_every_fixture_produces_a_route_the_schema_accepts(name, sources):
    text = (FIXTURES / name).read_text()
    route = analyse_sync(text, MANILA, sources=sources)
    jsonschema.validate(route.to_dict(), schema())


def test_the_route_keys_are_the_ones_falconeye_has_always_sent():
    route = analyse_sync((FIXTURES / "heise_traceroute.txt").read_text(), MANILA,
                         sources=OFFLINE)
    assert list(route.to_dict()) == ["parser", "parser_label", "target", "warnings",
                                     "hoiho_ruleset_date", "origin", "hops"]


def test_offline_still_places_the_carrier_legs():
    """The site-code table is offline, so it works with every source off."""
    route = analyse_sync((FIXTURES / "heise_traceroute.txt").read_text(), MANILA,
                         sources=OFFLINE)
    places = {h["hop"]: h["place"] or "" for h in route.hops}
    assert "Hong Kong" in places[6] and "Frankfurt" in places[10]
    assert route.origin["label"].startswith("Manila")
    assert route.origin["source"] == "supplied"


def test_a_route_survives_a_round_trip_through_json():
    route = analyse_sync((FIXTURES / "amazon_mtr.txt").read_text(), MANILA,
                         sources=ANSWERING)
    again = Route.from_dict(route.to_dict())
    assert again.to_dict() == route.to_dict()
    assert {h["hop"] for h in again.placed} | {h["hop"] for h in again.unplaced} == \
        {h["hop"] for h in route.hops}


def test_text_that_is_not_a_trace_is_an_error_not_an_empty_route():
    with pytest.raises(TraceParseError):
        analyse_sync("this is not a traceroute", MANILA, sources=OFFLINE)


def test_an_origin_off_the_globe_is_refused():
    with pytest.raises(ValueError):
        analyse_sync((FIXTURES / "heise_traceroute.txt").read_text(), (91.0, 0.0),
                     sources=OFFLINE)


def test_no_origin_anchors_on_the_first_located_hop_and_says_so():
    route = analyse_sync((FIXTURES / "heise_traceroute.txt").read_text(), None,
                         sources=OFFLINE)
    assert route.origin["source"] == "first-hop"


def test_a_hop_list_is_accepted_as_well_as_text():
    hops = [Hop(hop=1, addresses=["192.168.1.1"], rtts_ms=[1.0], sent=3),
            Hop(hop=2, addresses=["62.115.112.222"],
                hostnames=["sng-b6-link.ip.twelve99.net"], rtts_ms=[58.0], sent=3)]
    route = analyse_sync(hops, MANILA, sources=OFFLINE)
    assert route.parser == "hops"
    assert route.hops[1]["source"] == geo.SOURCE_SITE_CODE


def test_progress_reports_every_source_once_started_and_once_finished():
    events = []
    text = (FIXTURES / "heise_traceroute.txt").read_text()
    analyse_sync(text, MANILA, sources=ANSWERING,
                 progress=lambda source, state, detail: events.append((source, state)))
    for source in ("hoiho", "ip-db"):
        assert (source, "started") in events and (source, "done") in events
    analyse_sync(text, MANILA, sources=OFFLINE,
                 progress=lambda source, state, detail: events.append((source, state)))
    assert ("hoiho", "off") in events and ("ip-db", "off") in events


def test_a_hung_source_is_cut_off_by_its_budget_and_reported():
    async def hangs(*args):
        await asyncio.sleep(3600)

    events = []
    sources = Sources(hoiho=hangs, ip_db=hangs, ptr=hangs,
                      hoiho_budget=0.2, ip_db_budget=0.2, ptr_budget=0.2)
    hops = [Hop(hop=1, addresses=["62.115.1.1"], rtts_ms=[5.0], sent=3)]
    route = asyncio.run(analyse(hops, MANILA, sources=sources,
                                progress=lambda s, st, d: events.append((s, st))))
    assert route.hops[0]["source"] == "unresolved" and route.hops[0]["reason"]
    assert {("hoiho", "timeout"), ("ip-db", "timeout"), ("reverse-dns", "timeout")} <= set(events)


def test_a_progress_listener_that_raises_does_not_fail_the_trace():
    def broken(*args):
        raise RuntimeError("listener bug")

    route = analyse_sync((FIXTURES / "heise_traceroute.txt").read_text(), MANILA,
                         sources=ANSWERING, progress=broken)
    assert route.hops


# ---------- structural rules ----------

def test_the_engine_never_imports_qt():
    """FalconEye installs this package on a web server."""
    offenders = []
    for path in ENGINE.rglob("*.py"):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if re.match(r"\s*(from|import)\s+(PySide\d?|PyQt\d?|shiboken\d?)\b", line):
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, f"Qt imported in the engine: {offenders}"


def test_the_engine_keeps_no_mutable_global_configuration():
    """`global` is allowed only for the lazily loaded, read-only bundled tables."""
    allowed = {"cities.py", "sitecodes.py"}
    offenders = []
    for path in ENGINE.rglob("*.py"):
        if path.name in allowed:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if re.match(r"\s*global\s", line):
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, f"module-level state written at runtime: {offenders}"
