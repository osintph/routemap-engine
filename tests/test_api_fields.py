"""Fields that come from Hoiho and RIPEstat are checked before the engine
passes them on (RM-01 step 5): a country code is two letters, the ruleset date
is YYYY-MM, a prefix is a network, and names are short plain text."""
import asyncio

import httpx

from routemap_engine import geo, hoiho, ripe

MARKUP = '<img src="\\\\host\\share\\x.png"><a href="file:///etc">AS1299</a>'


def test_a_hoiho_match_carries_only_well_formed_fields():
    record = hoiho.match_to_record({"lat": 50.1, "lng": 8.7, "cc": MARKUP, "place": MARKUP + "x" * 500,
                                    "st": MARKUP, "iata": MARKUP, "locode": MARKUP, "clli": MARKUP})
    assert record["cc"] is None
    for key in ("place", "st", "iata", "locode", "clli"):
        value = record[key]
        assert value is None or ("<" not in value and len(value) <= 80), (key, value)
    good = hoiho.match_to_record({"lat": 50.1, "lng": 8.7, "cc": "de", "place": "Frankfurt am Main"})
    assert good["cc"] == "DE" and good["place"] == "Frankfurt am Main"


def test_the_hoiho_ruleset_date_is_a_month_or_nothing():
    def answer(request):
        return httpx.Response(200, json={"summary": {"ruleset_date": MARKUP}, "matches": []})

    client = hoiho.Hoiho()

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as c:
            return await client.post_batch(c, ["a.example.net"])
    _records, ruleset = asyncio.run(go())
    assert ruleset is None


def test_a_ripestat_prefix_must_be_a_network():
    def answer(request):
        return httpx.Response(200, json={"data": {"prefix": MARKUP, "asns": [1299]}})
    stat = ripe.RipeStat(user_agent="t", sourceapp="t", transport=httpx.MockTransport(answer))
    assert asyncio.run(stat.network_info("192.0.2.1")) is None

    def good(request):
        return httpx.Response(200, json={"data": {"prefix": "62.115.0.0/16", "asns": [1299]}})
    stat = ripe.RipeStat(user_agent="t", sourceapp="t", transport=httpx.MockTransport(good))
    assert asyncio.run(stat.network_info("62.115.1.1"))["prefix"] == "62.115.0.0/16"


def test_an_ip_database_answer_carries_only_well_formed_fields():
    def answer(request):
        return httpx.Response(200, json={"data": {"located_resources": [{"locations": [
            {"latitude": 50.1, "longitude": 8.7, "city": MARKUP, "country": MARKUP}]}]}})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as c:
            return await geo._ip_geolocate_one(c, asyncio.Semaphore(1), "62.115.1.1", "t", 5.0)
    hit = asyncio.run(go())
    assert hit["cc"] is None and (hit["city"] is None or "<" not in hit["city"])


def test_a_cached_hoiho_record_is_checked_on_the_way_out(monkeypatch):
    from routemap_engine.cache import MemoryCache

    async def no_network(self, client, names):
        return {}, None
    monkeypatch.setattr(hoiho.Hoiho, "post_batch", no_network)
    cache = MemoryCache()
    cache.set("ffm-b2.example.net", {"located": True, "lat": 50.1, "lng": 8.7, "cc": MARKUP, "place": MARKUP,
                                      "ruleset_date": MARKUP, "match_strs": [MARKUP]})
    records, ruleset = asyncio.run(hoiho.Hoiho(cache=cache).lookup(["ffm-b2.example.net"]))
    rec = records["ffm-b2.example.net"]
    assert rec["cc"] is None and "<" not in (rec["place"] or "") and rec["ruleset_date"] is None
    assert all("<" not in s for s in rec["match_strs"]) and ruleset is None
