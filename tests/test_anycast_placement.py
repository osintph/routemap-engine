"""A destination that answered faster than the place it is registered at
allows is placed as anycast, near the origin, instead of being left
unplaced.

ODIN and the Mac, 26 Oct 2026 (Phase 2 test build): bbc.com's Fastly address
151.101.0.81 answered in 5 to 10 ms from Manila; DB-IP Lite registers it in
Montreal. The summary said "likely anycast, served from near Quezon City",
the table said "not placed, RTT rules out location" and the map drew the hop
hollow. The traces below are synthetic (documentation addresses for the home
network); the DB-IP answer is DB-IP Lite City 2026-10's for 151.101.0.81."""
import asyncio

import pytest

from routemap_engine import analyse, geo, multipath
from routemap_engine.model import analyse_paths_sync
from routemap_engine.progressive import ProgressiveTrace

MANILA = (14.5995, 120.9842)
DEST = "151.101.0.81"
MONTREAL = {"lat": 45.5019, "lon": -73.5674, "city": "Montreal", "cc": "CA", "provider": "dbip"}
ROUTER = "62.115.0.1"                  # synthetic: a router DB-IP would also put in Montreal, at 4 ms


async def _ip_db(addrs):
    return {a: dict(MONTREAL) for a in addrs if a in (DEST, ROUTER)}


SOURCES = geo.Sources(ip_db=_ip_db)
TRACEROUTE = (f"traceroute to bbc.com ({DEST}), 30 hops max, 60 byte packets\n"
              " 1  198.51.100.1  1.0 ms\n 2  198.51.100.2  3.0 ms\n"
              f" 3  {ROUTER}  4.0 ms\n 4  {DEST}  5.2 ms  6.0 ms  9.8 ms\n")
MTR = ("Start: 2026-10-26T06:00:00+0800\n"
       "HOST: x                    Loss%   Snt   Last   Avg  Best  Wrst StDev\n"
       "  1.|-- 198.51.100.1         0.0%     3    1.0   1.0   1.0   1.0   0.0\n"
       "  2.|-- 198.51.100.2          0.0%     3    3.0   3.0   3.0   3.0   0.0\n"
       f"  3.|-- {ROUTER}         0.0%     3    4.0   4.0   4.0   4.0   0.0\n"
       f"  4.|-- {DEST}        0.0%     3    5.2   6.0   5.2   9.8   1.0\n")


def _check(hops):
    dest = [h for h in hops if h.get("address") == DEST]
    assert dest and all(h["source"] == geo.SOURCE_ANYCAST for h in dest), [(h["hop"], h["source"]) for h in dest]
    for h in dest:
        assert h["lat"] is not None and h["place"] == "Quezon City, NCR, PH"
        assert geo.ANNOT_RTT_IMPOSSIBLE not in (h.get("annotations") or [])
    router = [h for h in hops if h.get("address") == ROUTER]
    assert all(h["source"] == geo.SOURCE_UNRESOLVED for h in router)     # a router is a wrong record, not anycast


def test_a_trace_places_its_destination_as_anycast():
    route = asyncio.run(analyse(TRACEROUTE, MANILA, sources=SOURCES)).to_dict()
    _check(route["hops"])
    dest = route["hops"][-1]
    assert dest["reason"].startswith("likely anycast, served from near Quezon City, NCR, PH (registered in "
                                     "Montreal")
    assert "but answered in 5 ms" in dest["reason"]


def test_mtr_text_needs_the_address_traced():
    assert asyncio.run(analyse(MTR, MANILA, sources=SOURCES)).to_dict()["hops"][-1]["source"] == \
        geo.SOURCE_UNRESOLVED
    _check(asyncio.run(analyse(MTR, MANILA, sources=SOURCES, destination=DEST)).to_dict()["hops"])


def test_the_progressive_trace_ends_the_same_way():
    async def go():
        trace = ProgressiveTrace(MANILA, SOURCES)
        trace.destination = DEST
        for line in MTR.splitlines():
            for hop in trace.feed(line):
                await trace.place(hop)
        return await trace.finish()
    _check(asyncio.run(go()).to_dict()["hops"])


def test_no_origin_no_anycast():
    route = asyncio.run(analyse(TRACEROUTE, None, sources=SOURCES)).to_dict()
    assert route["hops"][-1]["source"] == geo.SOURCE_IP_DB        # nothing to rule it out


def test_a_path_discovery_places_it_on_every_path():
    d = multipath.Discovery(target="bbc.com", address=DEST, af=4, method="icmp-paris")
    for ttl, addr, rtt in ((1, "198.51.100.1", 1.0), (2, "100.64.0.1", 3.0), (3, ROUTER, 4.0), (4, DEST, 5.2)):
        d.responders[ttl] = [addr]
        d.rtts[(ttl, addr)] = [rtt]
    d.paths = [multipath.Path("A", [0], ["198.51.100.1", "100.64.0.1", ROUTER, DEST], [1.0, 3.0, 4.0, 5.2],
                              reached=True, reached_by="discovery")]
    route = analyse_paths_sync(d, MANILA, sources=SOURCES).to_dict()
    _check(route["hops"])
    _check(route["paths"]["paths"][0]["located"])


def test_the_route_validates_against_the_schema():
    import json
    import pathlib
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((pathlib.Path(geo.__file__).parent / "route.schema.json").read_text())
    jsonschema.validate(asyncio.run(analyse(TRACEROUTE, MANILA, sources=SOURCES)).to_dict(), schema)
