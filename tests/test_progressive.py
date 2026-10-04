"""Progressive placement must end exactly where a one-shot analysis ends.

Every fixture is fed line by line, each changed hop is placed as it arrives,
and finish() must produce the same route as analyse() on the whole text. Any
difference would mean the live map and the final map disagree.
"""
import asyncio
import pathlib

import pytest

from routemap_engine import analyse, geo
from routemap_engine.progressive import ProgressiveTrace

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "routemap"
MANILA = (14.6, 121.0)


async def _ptr(addresses):
    return {a: "sng-b6-link.ip.twelve99.net" for a in addresses if a.startswith("62.115.")}


async def _hoiho(hostnames):
    return ({h: {"located": "as6453" in h, "lat": 37.34 if "as6453" in h else None,
                 "lng": -121.89 if "as6453" in h else None, "place": "San Jose" if "as6453" in h else None,
                 "st": None, "cc": "US" if "as6453" in h else None, "match_strs": [], "match_meanings": []}
             for h in hostnames}, "2024-08")


async def _ipdb(addresses):
    # Some city-level answers and one country-only answer, like the real database.
    # The country-only one sits near its San Jose neighbours: an answer across
    # an ocean from both, at the same RTT, is rejected by the neighbour check.
    out = {}
    for a in addresses:
        out[a] = ({"lat": 36.8, "lon": -119.4, "city": None, "cc": "US"} if a.endswith((".146", ".38", ".3")) else
                  {"lat": 1.29, "lon": 103.85, "city": "Singapore", "cc": "SG"})
    return out


SOURCES = geo.Sources(hoiho=_hoiho, ip_db=_ipdb, ptr=_ptr)


def _progressive(text):
    async def go():
        seen = []
        trace = ProgressiveTrace(MANILA, SOURCES, on_hop=lambda e: seen.append(e["hop"]))
        trace.sources = geo.Sources(hoiho=_hoiho, ip_db=_ipdb, ptr=_ptr)  # no spacing in tests
        for line in text.splitlines():
            for hop in trace.feed(line):
                await trace.place(hop)
        return await trace.finish(), seen
    return asyncio.run(go())


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.txt")))
def test_progressive_ends_where_the_one_shot_analysis_ends(name):
    text = (FIXTURES / name).read_text()
    route, seen = _progressive(text)
    expected = asyncio.run(analyse(text, MANILA, sources=SOURCES))
    assert route.to_dict() == expected.to_dict()
    assert seen, "no hop was placed while the trace was arriving"


def test_each_hop_is_placed_as_its_line_arrives_not_at_the_end():
    text = (FIXTURES / "heise_traceroute.txt").read_text()

    async def go():
        trace = ProgressiveTrace(MANILA, geo.OFFLINE)
        placed_after = {}
        for index, line in enumerate(text.splitlines()):
            for hop in trace.feed(line):
                await trace.place(hop)
            placed_after[index] = len(trace.placed)
        return placed_after

    placed_after = asyncio.run(go())
    assert placed_after[1] == 1 and placed_after[8] == 8


def test_an_ecmp_continuation_line_replaces_the_hop_with_both_routers():
    lines = ["traceroute to heise.de (193.99.144.80), 30 hops max",
             " 8  mei-b6-link.ip.twelve99.net (62.115.140.54)  195.442 ms",
             "    sng-b6-link.ip.twelve99.net (62.115.139.44)  58.302 ms  58.711 ms"]

    async def go():
        trace = ProgressiveTrace(MANILA, geo.OFFLINE)
        trace.feed(lines[0])
        for hop in trace.feed(lines[1]):
            await trace.place(hop)
        first = dict(trace.placed[8])
        changed = trace.feed(lines[2])
        route = await trace.finish()
        return first, changed, route

    first, changed, route = asyncio.run(go())
    assert first["place"] is None or "Singapore" not in (first["place"] or "")
    assert [h.hop for h in changed] == [8]
    assert "Singapore" in route.hops[0]["place"]
    assert route.hops[0]["addresses"] == ["62.115.140.54", "62.115.139.44"]


def test_a_country_only_answer_is_marked_as_such():
    route, _ = _progressive((FIXTURES / "amazon_traceroute.txt").read_text())
    country = [h for h in route.hops if h.get("precision") == "country"]
    assert country and all(h["source"] == "ip-db" and h["place"] == "US" for h in country)
    assert all("precision" not in h for h in route.hops if h["source"] != "ip-db")
