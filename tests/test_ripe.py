"""The RIPEstat client and the Atlas baseline, replayed from recorded answers.

Fixtures: tests/fixtures/ripe/*.json, real responses recorded once and trimmed.
Nothing here reaches the network: httpx.MockTransport answers every request,
and a test fails if a request leaves without sourceapp or the User-Agent.
"""
import asyncio
import datetime as dt
import json
import pathlib

import httpx
import pytest

from routemap_engine import baseline, ripe
from routemap_engine.cache import MemoryCache

FIX = pathlib.Path(__file__).parent / "fixtures" / "ripe"
STAT = json.loads((FIX / "ripestat.json").read_text())
ATLAS = json.loads((FIX / "atlas.json").read_text())
UA = "routemap-engine-tests"


def _stat_transport(log, fail=()):
    def handler(request: httpx.Request):
        log.append(request)
        assert request.headers["user-agent"] == UA
        assert request.url.params.get("sourceapp") == "routemap-test"
        name = request.url.path.split("/")[2]
        if name in fail:
            return httpx.Response(503)
        if name == "rpki-validation" and request.url.params["resource"] == "AS12306":
            return httpx.Response(200, json=STAT["rpki-validation-unknown"])
        return httpx.Response(200, json=STAT[name])
    return httpx.MockTransport(handler)


def _client(log, **kw):
    return ripe.RipeStat(user_agent=UA, sourceapp="routemap-test", transport=_stat_transport(log, kw.pop("fail", ())),
                         **kw)


def test_every_endpoint_parses_its_recorded_answer():
    log = []
    c = _client(log)

    async def run():
        return (await c.network_info("62.115.112.222"), await c.rir("62.115.112.222"),
                await c.rpki("62.115.0.0/16", 1299), await c.rpki("193.99.144.0/24", 12306),
                await c.ris_paths("193.99.144.0/24"), await c.visibility("193.99.144.0/24"),
                await c.bgp_updates("193.99.144.0/24"), await c.as_overview(1299),
                await c.as_neighbours(1299), await c.abuse("62.115.112.222"))
    ni, rir, rp, rp2, paths, vis, ups, ov, nb, ab = asyncio.run(run())
    assert ni["prefix"] and 1299 in ni["asns"]
    assert rir == "RIPE NCC"
    assert rp == "valid" and rp2 in {"unknown", "valid", "invalid", "invalid_asn", "invalid_length"}
    assert paths and all(isinstance(a, int) for p in paths for a in p)
    assert 0 < vis["share"] <= 1 and vis["seeing"] <= vis["total"]
    assert ups is not None
    assert ov["holder"] and nb["upstream"] > 0 and nb["kind"] == "transit"
    assert ab and all("@" in a for a in ab)
    assert len(log) == 10


def test_a_failed_endpoint_is_none_and_never_raises():
    log = []
    c = _client(log, fail=("rpki-validation", "looking-glass"))
    assert asyncio.run(c.rpki("62.115.0.0/16", 1299)) is None
    assert asyncio.run(c.ris_paths("193.99.144.0/24")) is None


def test_a_timeout_is_none():
    async def slow(request):
        await asyncio.sleep(5)
        return httpx.Response(200, json={})
    c = ripe.RipeStat(user_agent=UA, sourceapp="x", transport=httpx.MockTransport(slow), timeout=0.05)
    assert asyncio.run(c.as_overview(1299)) is None


def test_answers_are_cached_per_endpoint_and_expire():
    log, clock = [], [1000.0]
    c = _client(log, cache=MemoryCache(), now=lambda: clock[0])
    asyncio.run(c.as_overview(1299))
    asyncio.run(c.as_overview(1299))
    assert len(log) == 1
    clock[0] += ripe.TTL["as-overview"] + 1
    asyncio.run(c.as_overview(1299))
    assert len(log) == 2


def test_ris_agreement_counts_suffix_matches_and_names_the_first_divergence():
    paths = [[3333, 1299, 12306], [6939, 1299, 12306], [174, 3356, 12306]]
    assert ripe.ris_agreement([1299, 12306], paths)["agree"] == 2
    out = ripe.ris_agreement([4775, 6453, 12306], paths)
    # 4775 leads and no RIS path carries it (an access network): the
    # divergence is named at the transit, 6453, where BGP would not go.
    assert out["agree"] == 0 and out["differs_at"] == 6453 and out["origin_asns"] == [12306]
    assert ripe.ris_agreement([], paths)["agree"] == 0


def test_update_timeline_bins_and_bursts():
    end = dt.datetime(2026, 10, 4, 12, 0, tzinfo=dt.timezone.utc)
    ts = [(end - dt.timedelta(minutes=m)).strftime("%Y-%m-%dT%H:%M:%S") for m in [5] * 12 + [60 * 30]]
    bins = ripe.hourly_bins(ts, end)
    assert len(bins) == 48 and bins[-1] == 12 and sum(bins) == 13
    assert ripe.update_burst(ts, end) == 12
    assert ripe.update_burst(ts[:3], end) is None


def test_recorded_update_timestamps_all_land_in_the_window():
    rec = STAT["bgp-updates"]["data"]
    end = dt.datetime.fromisoformat(rec["end"])
    assert sum(ripe.hourly_bins([u["timestamp"] for u in rec["updates"]], end)) == len(rec["updates"])


# ------------------------------------------------------------------- Atlas ---

def _atlas_transport(log):
    def handler(request: httpx.Request):
        log.append(request)
        path = request.url.path
        if path.endswith("/anchors/"):
            return httpx.Response(200, json=ATLAS[f"anchors-{request.url.params['country']}"])
        if path.endswith("/latest/"):
            return httpx.Response(200, json=ATLAS["latest"])
        if path.endswith("/measurements/"):
            return httpx.Response(200, json=ATLAS["measurements"])
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_baseline_picks_the_nearest_anchors_and_sends_no_coordinates():
    log = []
    b = baseline.Baseline(user_agent=UA, transport=_atlas_transport(log), cache=MemoryCache())
    exp = ATLAS["expect"]
    value = asyncio.run(b.typical((14.5995, 120.9842), "PH", tuple(exp["dest_coords"]), "DE"))
    assert value["src"]["fqdn"] == exp["src"] and value["dst"]["fqdn"] == exp["dst"]
    assert value["msm"] == exp["msm"] and value["ms"] == round(min(r["min"] for r in ATLAS["latest"]), 1)
    sent = " ".join(str(r.url) for r in log)
    assert "14.5995" not in sent and "120.98" not in sent
    n = len(log)
    asyncio.run(b.typical((14.5995, 120.9842), "PH", tuple(exp["dest_coords"]), "DE"))
    assert len(log) == n, "the second ask is answered from the cache"
    assert baseline.delta_text(value, 255.0, "Manila", "Frankfurt").startswith("typical Manila to Frankfurt: about ")


def test_baseline_is_none_when_atlas_fails():
    b = baseline.Baseline(user_agent=UA, transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    assert asyncio.run(b.typical((14.6, 121.0), "PH", (50.1, 8.7), "DE")) is None


def test_ris_agreement_skips_the_access_network_ris_never_sees():
    """A real home trace starts in the ISP's AS (here 64500), which no RIS peer
    path carries; it reported "differs after AS64500" for a path RIS agrees with."""
    paths = [[3333, 1299, 12306], [6939, 1299, 12306]]
    out = ripe.ris_agreement([64500, 1299, 12306], paths)
    assert out["agree"] == 2 and out["differs_at"] is None and out["compared_from"] == 1299
    assert ripe.ris_agreement([64500, 64501], paths)["agree"] == 0



def test_a_failure_records_why_and_the_slow_endpoints_retry():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(503)
    c = ripe.RipeStat(user_agent=UA, sourceapp="x", transport=httpx.MockTransport(handler))
    assert asyncio.run(c.ris_paths("193.99.144.0/24")) is None
    assert c.errors["looking-glass"] == "RIPEstat answered HTTP 503"
    assert len(calls) == 2, "looking-glass is retried once"
    assert asyncio.run(c.as_overview(1299)) is None and len(calls) == 3, "a fast endpoint is not retried"


def test_a_timeout_says_how_long_it_waited():
    async def slow(request):
        await asyncio.sleep(5)
        return httpx.Response(200, json={})
    c = ripe.RipeStat(user_agent=UA, sourceapp="x", transport=httpx.MockTransport(slow), timeout=0.05)
    old = dict(ripe.SLOW)
    ripe.SLOW.clear()
    try:
        assert asyncio.run(c.as_overview(1299)) is None
    finally:
        ripe.SLOW.update(old)
    assert c.errors["as-overview"].startswith("RIPEstat did not answer within")
