"""A hop no source places, between two placed hops in one city, is placed in
that city as inferred from its neighbours.

ODIN, 26 Oct 2026 (Phase 2 test build), Paths to heise.de: 62.115.153.153
(plusline-ic-323934.ip.twelve99-cust.net, Arelion's link to Plus.line) has
no site code, and DB-IP's Chicago is ruled out by the RTT; the hops either
side are in Frankfurt (ffm-b16-link by site code, 82.98.102.1 by DB-IP).
The data are tests/fixtures/odin_080dev1_run.json and the Mac run of 25 Oct
(tests/fixtures/mac_paths_heise_080dev1.json), with the names and database
answers of tests/test_named_rows.py."""
import asyncio
import copy
import json
import pathlib

import pytest

from routemap_engine import analyse, geo, model, multipath

from test_named_rows import DBIP, MANILA, NAMES, SOURCES

HERE = pathlib.Path(__file__).parent / "fixtures"
PLUSLINE = "62.115.153.153"


def _route(name):
    data = json.loads((HERE / name).read_text())["discovery"]
    return model.analyse_paths_sync(multipath.Discovery.from_wire(data), MANILA, sources=SOURCES).to_dict()


def _rows(route):
    yield "main", route["hops"]
    for p in route["paths"]["paths"]:
        yield p["id"], p["located"]


def _sides(rows, index):
    """The first answered rows either side with another address."""
    me = rows[index]["address"]

    def ok(e):
        return e.get("min_rtt_ms") is not None and e.get("address") and e["address"] != me
    return (next((e for e in reversed(rows[:index]) if ok(e)), None), next((e for e in rows[index + 1:] if ok(e)), None))


@pytest.mark.parametrize("name", ["odin_080dev1_run.json", "mac_paths_heise_080dev1.json"])
def test_the_plusline_link_is_placed_in_frankfurt_by_its_neighbours(name):
    """Inferred where both neighbours are placed in Frankfurt, and as one
    router has one place in a run, on its other rows too (ODIN path K:
    Copenhagen, a silent hop, then the link, then Frankfurt)."""
    route = _route(name)
    rows = [(where, i, rs) for where, rs in _rows(route) for i, r in enumerate(rs) if r.get("address") == PLUSLINE]
    assert rows
    direct = 0
    for where, i, rs in rows:
        row = rs[i]
        before, after = _sides(rs, i)
        direct += all(e is not None and (e.get("place") or "").startswith("Frankfurt") for e in (before, after))
        assert row["source"] == geo.SOURCE_NEIGHBOURS, (where, row["hop"], row.get("reason"))
        assert row["place"] in ("Frankfurt, DE", "Frankfurt am Main, DE")
        assert row["reason"].startswith("inferred from neighbours: between hop ")
        assert geo.ANNOT_RTT_IMPOSSIBLE not in (row.get("annotations") or [])
    assert direct >= 1
    main = next(h for h in route["hops"] if h.get("address") == PLUSLINE)
    assert "the IP database's Chicago, US is ruled out" in main["reason"]
    seen = {(r["place"], r["source"]) for _w, i, rs in rows for r in [rs[i]]}
    assert len(seen) == 1                                  # one router, one place


def test_the_export_validates():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((pathlib.Path(geo.__file__).parent / "route.schema.json").read_text())
    jsonschema.validate(_route("odin_080dev1_run.json"), schema)


def _trace(before, after, rtt="281.0"):
    return ("traceroute to heise.de (193.99.144.80), 30 hops max, 60 byte packets\n"
            f" 1  {before[0]} ({before[1]})  279.0 ms\n"
            f" 2  plusline-ic-323934.ip.twelve99-cust.net ({PLUSLINE})  {rtt} ms\n"
            f" 3  {after[0]} ({after[1]})  280.5 ms\n")


FFM = ("ffm-b16-link.ip.twelve99.net", "62.115.132.229")
PLUS = ("te2-2.c301.f.de.plusline.net", "82.98.102.1")
STO = ("sto-bb2-link.ip.twelve99.net", "62.115.139.186")


async def _ip_db(addrs):
    return {a: dict(DBIP[a]) for a in addrs if a in DBIP}


def _hop2(text):
    return asyncio.run(analyse(text, MANILA, sources=geo.Sources(ip_db=_ip_db))).to_dict()["hops"][1]


def test_a_trace_infers_it_too():
    hop = _hop2(_trace(FFM, PLUS))
    assert hop["source"] == geo.SOURCE_NEIGHBOURS and hop["place"] == "Frankfurt, DE"   # the site code's place


def test_neighbours_in_two_cities_infer_nothing():
    assert _hop2(_trace(STO, PLUS))["source"] == geo.SOURCE_UNRESOLVED


def test_a_place_the_hop_s_own_rtt_rules_out_is_not_inferred():
    assert _hop2(_trace(FFM, PLUS, rtt="5.0"))["source"] == geo.SOURCE_UNRESOLVED


def test_an_inferred_hop_is_no_neighbour_for_the_next():
    text = ("traceroute to heise.de (193.99.144.80), 30 hops max, 60 byte packets\n"
            f" 1  {FFM[0]} ({FFM[1]})  279.0 ms\n"
            f" 2  plusline-ic-323934.ip.twelve99-cust.net ({PLUSLINE})  281.0 ms\n"
            " 3  62.115.0.9  281.2 ms\n"
            f" 4  {PLUS[0]} ({PLUS[1]})  280.5 ms\n")
    hops = asyncio.run(analyse(text, MANILA, sources=geo.Sources(ip_db=_ip_db))).to_dict()["hops"]
    assert [h["source"] for h in hops[1:3]] == [geo.SOURCE_UNRESOLVED, geo.SOURCE_UNRESOLVED]
