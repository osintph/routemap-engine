"""A real reverse trace (RIPE Atlas measurement 221303797, the 0.7.0 release
check): the final TTL 255 answer, the lookups on Atlas hops, and the physics
check from the probe's own position. tests/fixtures/atlas_221303797.json is
RIPE's result with the measured host's address replaced."""
import asyncio
import json
import pathlib

import jsonschema
import pytest

from routemap_engine import OFFLINE, Sources, analyse, atlas, geo, parse_trace, schema

DATA = json.loads((pathlib.Path(__file__).parent / "fixtures" / "atlas_221303797.json").read_text())
RESULT, PROBE = DATA["result"], DATA["probe"]
ORIGIN = (PROBE["lat"], PROBE["lon"])


def test_the_final_ttl_255_answer_is_the_next_hop_and_says_so():
    """RIPE's results page shows this answer as hop 22; the engine showed 255."""
    assert atlas.final_probe(RESULT) == 22
    hops = parse_trace(atlas.to_trace_text(RESULT)).hops
    assert [h.hop for h in hops] == list(range(1, 23))
    assert hops[-1].addresses == ["198.51.100.76"] and hops[-1].min_rtt_ms == 154.032
    route = asyncio.run(analyse(atlas.to_trace_text(RESULT), ORIGIN, sources=OFFLINE))
    atlas.mark_final_probe(route, atlas.final_probe(RESULT))
    last = route.hops[-1]
    assert last["hop"] == 22 and atlas.ANNOT_FINAL_PROBE in last["annotations"]
    assert any("TTL 255" in d for d in last["annotation_details"])
    assert all(atlas.ANNOT_FINAL_PROBE not in h["annotations"] for h in route.hops[:-1])
    jsonschema.validate(route.to_dict(), schema())


def test_a_result_without_the_final_probe_keeps_its_numbers():
    plain = dict(RESULT, result=[h for h in RESULT["result"] if h["hop"] != 255])
    assert atlas.final_probe(plain) is None
    assert parse_trace(atlas.to_trace_text(plain)).hops[-1].hop == 21


def test_reverse_dns_and_hoiho_run_on_atlas_hops():
    """Atlas results carry no names: every public hop is asked for its PTR
    name, and Hoiho is asked about every name found (it has no rule for
    OVH's or Deutsche Telekom's, so the IP database places them)."""
    asked = {}

    async def ptr(addresses):
        asked["ptr"] = sorted(addresses)
        return {"94.23.122.136": "be101.sbg-g1-nc5.fr.eu", "217.5.67.42": "f-eh4-i.F.DE.NET.DTAG.DE"}

    async def hoiho(names):
        asked["hoiho"] = sorted(names)
        return {n: {"located": False} for n in names}, "2024-08"

    async def ip_db(addresses):
        return {}
    route = asyncio.run(analyse(atlas.to_trace_text(RESULT), ORIGIN, sources=Sources(hoiho=hoiho, ip_db=ip_db, ptr=ptr)))
    public = {a for h in RESULT["result"] for r in h.get("result", []) if (a := r.get("from"))} - {"198.51.100.76"}
    assert set(asked["ptr"]) == public
    assert asked["hoiho"] == ["be101.sbg-g1-nc5.fr.eu", "f-eh4-i.F.DE.NET.DTAG.DE"]
    assert {h["hostname"] for h in route.hops if h.get("hostname")} == set(asked["hoiho"])


# Where the IP database put hops 1 to 4 in the release-check run.
LEIHGESTERN, WISSEN = (50.5332, 8.6838), (50.7826, 7.7353)


async def _ip(addresses):
    where = {"82.98.65.251": LEIHGESTERN, **{a: WISSEN for a in ("82.98.102.180", "82.98.103.3", "82.98.102.55")}}
    return {a: {"lat": where[a][0], "lon": where[a][1], "city": "x", "cc": "DE"} for a in addresses if a in where}


def test_a_probe_position_rejects_what_its_round_trip_cannot_reach():
    """Hop 1 answered in 0.406 ms: 40.6 km at most, and the IP database put
    it 48 km from probe 7036. From the probe's own position (5 km of slack)
    that is rejected; hops 2 to 4 (1.0 to 1.3 ms, 98 km away) are physically
    possible and stay. With the 300 km meant for a public-IP origin, hop 1
    passed, which is what the release check showed."""
    text = atlas.to_trace_text(RESULT)
    sources = Sources(hoiho=None, ip_db=_ip, ptr=None)
    d = geo.haversine_km(*ORIGIN, *LEIHGESTERN)
    assert 45.6 < d < 7.7 + 40.6
    strict = asyncio.run(analyse(text, ORIGIN, sources=sources, origin_slack_km=atlas.PROBE_SLACK_KM)).hops
    assert strict[0]["lat"] is None and geo.ANNOT_RTT_IMPOSSIBLE in (strict[0]["reason"] or "")
    assert [h["lat"] is not None for h in strict[1:4]] == [True, True, True]
    loose = asyncio.run(analyse(text, ORIGIN, sources=sources)).hops
    assert loose[0]["lat"] is not None


@pytest.mark.parametrize("slack", [atlas.PROBE_SLACK_KM, geo.SLACK_KM])
def test_the_allowance_is_the_only_difference(slack):
    assert geo.max_distance_km(0.406, slack) == pytest.approx(40.6 + slack)


OVH_NAMES = {"94.23.122.136": "be101.sbg-g1-nc5.fr.eu", "91.121.215.221": "be102.mil-ava1-sbb2-nc5.it.eu",
             "57.128.121.192": "mil-ava1-sbb1-8k.it.eu", "57.128.234.60": "be102.mrs-mrs1-sbb1-8k.fr.eu",
             "103.5.15.5": "sin1-sgcs2-g1-nc5.sgp.asia"}


def test_ovh_hops_are_placed_by_ovhs_own_site_names_and_pass_the_round_trip_check():
    """The release check placed OVH's backbone by the IP database in London,
    Warsaw and Hong Kong; OVH's own router names (its weathermap) put them in
    Strasbourg, Milan, Marseille and Singapore, and each placement is inside
    what its round trip allows from probe 7036."""
    async def ptr(addresses):
        return {a: OVH_NAMES[a] for a in addresses if a in OVH_NAMES}

    async def ip_db(addresses):
        wrong = {"94.23.122.136": (51.5, -0.12), "91.121.215.221": (51.51, -0.09), "57.128.234.60": (52.23, 21.01)}
        return {a: {"lat": p[0], "lon": p[1], "city": "x", "cc": "GB"} for a, p in wrong.items() if a in addresses}
    route = asyncio.run(analyse(atlas.to_trace_text(RESULT), ORIGIN, origin_slack_km=atlas.PROBE_SLACK_KM,
                                sources=Sources(hoiho=None, ip_db=ip_db, ptr=ptr)))
    by_hop = {h["hop"]: h for h in route.hops}
    expected = {11: "Strasbourg", 12: "Milan", 13: "Milan", 14: "Marseille", 16: "Singapore"}
    for hop, city in expected.items():
        h = by_hop[hop]
        assert h["source"] == "site-code" and h["place"].startswith(city), h
        assert h["distance_km"] <= h["rtt_budget_km"], h


def test_ovhs_large_data_centres_are_placed_by_their_own_names():
    """Gravelines, Erith, Beauharnois and Vint Hill are in the bundled town
    list (GeoNames) and their routers in the site-code table (OVH's
    weathermap); placed from Frankfurt, each inside its round trip."""
    names = {"141.94.30.1": "be102.lil2-gra1-sbb1-nc5.fr.eu", "213.186.32.253": "be101.lon1-eri1-g1-nc5.uk.eu",
             "198.27.73.204": "be102.bhs-g1-nc5.qc.ca", "178.32.135.211": "vl1332.was1-vin1-g1-nc5.wa.us"}
    text = ("traceroute to x (178.32.135.211), 30 hops max\n"
            " 1  141.94.30.1  9.0 ms\n 2  213.186.32.253  12.0 ms\n"
            " 3  198.27.73.204  88.0 ms\n 4  178.32.135.211  95.0 ms\n")

    async def ptr(addresses):
        return {a: names[a] for a in addresses if a in names}
    route = asyncio.run(analyse(text, ORIGIN, origin_slack_km=atlas.PROBE_SLACK_KM,
                                sources=Sources(hoiho=None, ip_db=None, ptr=ptr)))
    got = {h["hop"]: h for h in route.hops}
    for hop, place in {1: "Gravelines, FR", 2: "Erith, GB", 3: "Beauharnois, CA", 4: "Vint Hill, US"}.items():
        h = got[hop]
        assert h["source"] == "site-code" and h["place"] == place, h
        assert h["distance_km"] <= h["rtt_budget_km"], h


def test_the_four_places_are_in_the_town_list():
    from routemap_engine import cities
    for name, cc in (("Gravelines", "FR"), ("Beauharnois", "CA"), ("Erith", "GB"), ("Vint Hill Park", "US")):
        assert any(c["name"] == name and c["cc"] == cc for c in cities.search(name)), name

