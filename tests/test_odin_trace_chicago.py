"""ODIN, 12 Oct 2026, a normal Trace to heise.de (ICMP) with the 0.4.0-beta.2
test build (tests/fixtures/odin_trace_040b2t3.txt; the tester's home and ISP
hops 1 to 5 are documentation addresses, minimum RTTs and names as shown).
Hop 12, 62.115.153.153, sits between Frankfurt at 201.2 ms (hop 11) and
Frankfurt at 247.0 ms (hop 13); the IP database says Chicago, and the map
drew Frankfurt > Chicago > Frankfurt (DE > US > DE)."""
import asyncio
import pathlib

from routemap_engine import analyse, osint
from routemap_engine.geo import ANNOT_RTT_IMPOSSIBLE, Sources

TEXT = (pathlib.Path(__file__).parent / "fixtures" / "odin_trace_040b2t3.txt").read_text()
PTR = {"62.115.137.184": "sng-b7-link.ip.twelve99.net", "62.115.139.44": "sng-b6-link.ip.twelve99.net",
       "62.115.140.54": "mei-b6-link.ip.twelve99.net", "62.115.136.250": "ffm-bb2-link.ip.twelve99.net",
       "62.115.132.229": "ffm-b16-link.ip.twelve99.net",
       "62.115.153.153": "plusline-ic-323934.ip.twelve99-cust.net", "82.98.102.1": "te2-2.c301.f.de.plusline.net",
       "193.99.144.80": "redirector.heise.de"}
IPDB = {"198.51.100.46": (14.58, 121.04, "Mandaluyong", "PH"), "198.51.100.143": (14.55, 121.02, "Makati City", "PH"),
        "62.115.153.153": (41.88, -87.63, "Chicago", "US"),
        "82.98.102.1": (50.11, 8.68, "Frankfurt am Main", "DE"), "82.98.103.3": (50.11, 8.68, "Frankfurt am Main", "DE"),
        "212.19.61.13": (50.11, 8.68, "Frankfurt am Main", "DE"), "193.99.144.80": (52.37, 9.73, "Hanover", "DE")}


async def _ip_db(addresses):
    return {a: {"lat": v[0], "lon": v[1], "city": v[2], "cc": v[3]} for a, v in IPDB.items() if a in addresses}


async def _ptr(addresses):
    return {a: n for a, n in PTR.items() if a in addresses}


def _route():
    return asyncio.run(analyse(TEXT, (14.68, 121.04), sources=Sources(hoiho=None, ip_db=_ip_db, ptr=_ptr)))


def test_a_hop_its_next_neighbour_rules_out_is_not_placed():
    """Through hop 12 to hop 13 in Frankfurt and back costs at least the
    detour Frankfurt > Chicago > Frankfurt one way: about 70 ms more than hop
    11. Hop 13 is 45.8 ms past hop 11, so hop 12 is not in Chicago, however
    slowly hop 12 itself answered (281 ms)."""
    route = _route()
    hop = next(h for h in route.hops if h["hop"] == 12)
    chicago = [c for c in hop["candidates"] if c["source"] == "ip-db"]
    assert chicago and not any(c["accepted"] for c in chicago), hop
    assert any(ANNOT_RTT_IMPOSSIBLE in (c.get("why") or "") and "hop 13" in c["why"] for c in chicago)
    # 0.8.0: between two Frankfurt hops, it is placed there as inferred.
    assert hop["source"] == "neighbours" and hop["place"].startswith("Frankfurt"), hop


def test_the_countries_do_not_go_to_the_us_and_back():
    countries = [c["cc"] for c in osint.jurisdictions(_route().to_dict())]
    assert "US" not in countries and countries[-1] == "DE", countries
