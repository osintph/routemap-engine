"""Reverse traces via RIPE Atlas (0.7.0): the probe is near the destination
and never in the user's own network, the target is the user's public address
of the traced family, the cost is the verified 60 credits, and nothing is
created without explicit consent."""
import asyncio
import json

import httpx
import pytest

from routemap_engine import atlas
from tests.test_atlas_credits import _ripe_cost

DEST = (52.37, 9.73)        # Hannover, where heise.de is located


def probe(pid, asn_v4=None, asn_v6=None, cc="DE", lat=50.1, lon=8.7):
    return {"id": pid, "asn_v4": asn_v4, "asn_v6": asn_v6, "country_code": cc,
            "geometry": {"type": "Point", "coordinates": [lon, lat]}}


class Recorder:
    def __init__(self, by_query):
        self.by_query, self.calls = by_query, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        self.calls.append((request.method, request.url.path, params,
                           json.loads(request.content) if request.content else None))
        if request.method == "POST":
            return httpx.Response(201, json={"measurements": [77]})
        for key, value in params.items():
            if (key, value) in self.by_query:
                return httpx.Response(200, json={"results": self.by_query[(key, value)]})
        return httpx.Response(200, json={"results": []})


def client(rec):
    return atlas.Atlas("k", transport=httpx.MockTransport(rec))


def test_reverse_probe_is_in_the_destination_as_nearest_and_never_in_the_users():
    rec = Recorder({("asn_v4", "12306"): [probe(1, 12306, lat=48.1, lon=11.6),       # Munich
                                          probe(2, 12306, lat=52.4, lon=9.7),        # Hannover
                                          probe(3, 3320, lat=52.37, lon=9.73)]})     # user's AS, closest
    chosen = asyncio.run(client(rec).select_reverse_probe(12306, "DE", DEST, user_asn=3320, af=4))
    assert chosen["id"] == 2
    _, path, params, _ = rec.calls[0]
    assert path.endswith("/probes/") and params["status"] == "1" and params["tags"] == "system-ipv4-works"


def test_an_ipv6_reverse_trace_looks_for_ipv6_probes():
    rec = Recorder({("asn_v6", "12306"): [probe(5, asn_v6=12306)]})
    chosen = asyncio.run(client(rec).select_reverse_probe(12306, "DE", DEST, user_asn=None, af=6))
    assert chosen["id"] == 5 and rec.calls[0][2]["tags"] == "system-ipv6-works"


def test_reverse_falls_back_to_the_country_then_creates_nothing():
    rec = Recorder({("country_code", "DE"): [probe(9, 680)]})
    assert asyncio.run(client(rec).select_reverse_probe(12306, "de", DEST, user_asn=3320))["id"] == 9
    empty = Recorder({})
    with pytest.raises(atlas.AtlasUnavailable) as err:
        asyncio.run(client(empty).select_reverse_probe(12306, "DE", DEST, user_asn=3320))
    assert err.value.kind == "noprobe" and "AS12306 or DE" in err.value.message
    assert not [c for c in empty.calls if c[0] == "POST"]


@pytest.mark.parametrize("ip,af", [("193.99.144.80", 4), ("2a02:2e0:3fe:1001:302::", 6)])
def test_reverse_targets_the_public_ip_of_the_traced_family(ip, af):
    rec = Recorder({})
    assert asyncio.run(client(rec).create_reverse(ip, 4242, consent=True)) == 77
    body = rec.calls[-1][3]
    d = body["definitions"][0]
    assert (d["target"], d["af"], d["paris"], d["resolve_on_probe"]) == (ip, af, atlas.REVERSE_PARIS, False)
    assert body["probes"] == [{"type": "probes", "value": "4242", "requested": 1}] and body["is_oneoff"]


def test_reverse_costs_60_credits_from_the_body_sent():
    rec = Recorder({})
    asyncio.run(client(rec).create_reverse("193.99.144.80", 1, consent=True))
    assert _ripe_cost(rec.calls[-1][3]) == atlas.TRACEROUTE_CREDITS == 60


@pytest.mark.parametrize("consent", [False, None, 1, "yes", [True]])
def test_no_reverse_measurement_without_explicit_consent(consent):
    rec = Recorder({})
    with pytest.raises(atlas.AtlasUnavailable) as err:
        asyncio.run(client(rec).create_reverse("193.99.144.80", 1, consent=consent))
    assert err.value.kind == "consent" and rec.calls == []


@pytest.mark.parametrize("ip", ["192.168.1.10", "100.64.3.4", "2001:db8::1", "fe80::1", "not-an-ip"])
def test_a_reverse_trace_never_targets_a_private_address(ip):
    rec = Recorder({})
    with pytest.raises(atlas.AtlasUnavailable):
        asyncio.run(client(rec).create_reverse(ip, 1, consent=True))
    assert rec.calls == []
