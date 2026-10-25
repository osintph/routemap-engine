"""At a hop where several routers answered, a row placed by a hostname shows
the address that hostname belongs to, and no row shows one router's name next
to another's address.

ODIN, 26 Oct 2026 (Phase 2 test build), Paths to heise.de: hop 11 was
answered by 62.115.132.229 (ffm-b16-link.ip.twelve99.net), 62.115.153.153
(plusline-ic-323934.ip.twelve99-cust.net, Arelion's link to Plus.line, no
site code) and 62.115.132.227. Listed with 62.115.153.153 first, the row was
placed in Frankfurt by ffm-b16-link's site code but kept 62.115.153.153 as
its address; that router's own rejection (DB-IP: Chicago, 6,964 km from hop
10 and back by hop 12) then cleared the row. The table read "62.115.153.153,
ffm-b16-link, not placed", with the database location in the reason.

The names are the routers' reverse DNS as asked on 26 Oct 2026; the database
answers are DB-IP Lite City 2026-10's for those addresses."""
import asyncio
import copy
import itertools
import json
import pathlib

import pytest

from routemap_engine import geo, model, multipath

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "odin_080dev1_run.json"
NAMES = {
    "62.115.186.136": "sto-b9-link.ip.twelve99.net", "62.115.139.180": "sto-bb1-link.ip.twelve99.net",
    "62.115.139.186": "sto-bb2-link.ip.twelve99.net", "62.115.143.29": "ffm-bb1-link.ip.twelve99.net",
    "62.115.138.105": "ffm-bb2-link.ip.twelve99.net", "62.115.139.173": "kbn-bb6-link.ip.twelve99.net",
    "62.115.136.151": "adm-bb1-link.ip.twelve99.net", "62.115.136.52": "adm-bb2-link.ip.twelve99.net",
    "62.115.137.223": "ffm-bb2-link.ip.twelve99.net", "62.115.132.229": "ffm-b16-link.ip.twelve99.net",
    "62.115.132.227": "ffm-b16-link.ip.twelve99.net", "62.115.120.241": "ffm-bb1-link.ip.twelve99.net",
    "62.115.114.95": "ffm-bb2-link.ip.twelve99.net",
    "62.115.153.153": "plusline-ic-323934.ip.twelve99-cust.net", "82.98.102.1": "te2-2.c301.f.de.plusline.net",
    "193.99.144.80": "redirector.heise.de",
}
DBIP = {
    "62.115.153.153": {"lat": 41.8761, "lon": -87.6316, "city": "Chicago", "cc": "US", "provider": "dbip"},
    "82.98.102.1": {"lat": 50.1111, "lon": 8.66105, "city": "Frankfurt am Main", "cc": "DE", "provider": "dbip"},
    "82.98.102.79": {"lat": 50.1111, "lon": 8.66105, "city": "Frankfurt am Main", "cc": "DE", "provider": "dbip"},
    "82.98.103.3": {"lat": 50.1111, "lon": 8.66105, "city": "Frankfurt am Main", "cc": "DE", "provider": "dbip"},
    "193.99.144.80": {"lat": 52.3861, "lon": 9.80954, "city": "Hanover", "cc": "DE", "provider": "dbip"},
}
MANILA = (14.5995, 120.9842)


async def _ptr(addrs):
    return {a: NAMES[a] for a in addrs if a in NAMES}


async def _ip_db(addrs):
    return {a: dict(DBIP[a]) for a in addrs if a in DBIP}


SOURCES = geo.Sources(ptr=_ptr, ip_db=_ip_db)


def _route(order):
    data = copy.deepcopy(json.loads(FIXTURE.read_text())["discovery"])
    next(r for r in data["responders"] if r["ttl"] == 11)["addresses"] = list(order)
    return model.analyse_paths_sync(multipath.Discovery.from_wire(data), MANILA, sources=SOURCES).to_dict()


def _rows(route):
    yield from route["hops"]
    for p in route["paths"]["paths"]:
        yield from p["located"]


@pytest.mark.parametrize("order", list(itertools.permutations(["62.115.132.229", "62.115.153.153",
                                                                "62.115.132.227"])))
def test_a_row_shows_the_router_its_hostname_names(order):
    route = _route(order)
    for row in _rows(route):
        if row.get("hostname") and row.get("address"):
            assert NAMES.get(row["address"]) == row["hostname"], (row["hop"], row["address"], row["hostname"])
    hop11 = next(h for h in route["hops"] if h["hop"] == 11)
    assert hop11["source"] == geo.SOURCE_SITE_CODE and hop11["place"] == "Frankfurt, DE"
    assert hop11["address"] in ("62.115.132.229", "62.115.132.227")


def test_traceroute_text_pairs_each_name_with_its_address():
    """The same class in text a tool printed: a hop with two routers, the one
    without a site code first."""
    text = ("traceroute to heise.de (193.99.144.80), 30 hops max, 60 byte packets\n"
            " 1  sto-b9-link.ip.twelve99.net (62.115.186.136)  180.1 ms\n"
            " 2  ffm-bb2-link.ip.twelve99.net (62.115.138.105)  205.0 ms\n"
            " 3  plusline-ic-323934.ip.twelve99-cust.net (62.115.153.153)  206.1 ms"
            "  ffm-b16-link.ip.twelve99.net (62.115.132.229)  205.9 ms\n"
            " 4  te2-2.c301.f.de.plusline.net (82.98.102.1)  206.4 ms\n")
    route = asyncio.run(model.analyse(text, MANILA, sources=geo.Sources(ip_db=_ip_db))).to_dict()
    hop3 = route["hops"][2]
    assert hop3["source"] == geo.SOURCE_SITE_CODE and hop3["address"] == "62.115.132.229"
    assert hop3["hostname"] == "ffm-b16-link.ip.twelve99.net"
