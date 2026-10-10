"""A path discovery becomes a Route (0.7.0): every responder placed as in
any trace, each path with its own located hops, from one set of lookups, and
the schema accepts it. An ordinary route keeps FalconEye's keys exactly."""
import asyncio

import jsonschema

from routemap_engine import OFFLINE, Sources, analyse_paths, multipath, schema
from tests.helpers.lab import Lab
from tests.test_engine_api import _fake_hoiho, _no_ptr

DST = "193.99.144.80"
TOPO = ["192.168.1.1", "100.64.0.1", ("branch", [["62.115.186.138", "62.115.112.222"],
                                                 ["62.115.113.10", "62.115.112.222"]]), DST]


def discovery(seed=1):
    lab = Lab(TOPO, seed=seed)
    return multipath.Discoverer("heise.de", DST, lab, clock=lab.clock).run()


def test_every_path_is_located_and_the_schema_accepts_it():
    calls = []

    async def ip(addresses):
        calls.append(sorted(addresses))
        return {a: {"lat": 50.1, "lon": 8.7, "city": "Frankfurt", "cc": "DE"} for a in addresses}
    route = asyncio.run(analyse_paths(discovery(), (14.6, 121.0),
                                      sources=Sources(hoiho=_fake_hoiho, ip_db=ip, ptr=_no_ptr)))
    data = route.to_dict()
    jsonschema.validate(data, schema())
    paths = data["paths"]["paths"]
    assert len(paths) == 2 and data["paths"]["at_least"] is True
    for p in paths:
        assert [h["address"] for h in p["located"]] == p["hops"]
        assert p["located"][0]["source"] == "local" and p["located"][1]["source"] == "local"
    assert len(calls) == 1          # one lookup for every path


def test_an_offline_paths_route_round_trips():
    from routemap_engine import Route
    route = asyncio.run(analyse_paths(discovery(), sources=OFFLINE))
    again = Route.from_dict(route.to_dict())
    assert again.to_dict() == route.to_dict() and again.paths["flows"] >= 9


def test_an_ordinary_route_has_no_paths_key():
    from routemap_engine import analyse_sync
    route = analyse_sync("traceroute to x (192.0.2.9), 30 hops max\n 1  192.0.2.9  1.0 ms\n", sources=OFFLINE)
    assert route.paths is None and "paths" not in route.to_dict()
