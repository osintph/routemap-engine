"""0.3.1 fixes from the ODIN test (4 Oct 2026), each for the class of bug."""
import asyncio
import ctypes
import datetime as dt

import httpx
import pytest

from routemap_engine import analyse_sync, hoiho, parse_trace, probe, ripe
from routemap_engine.cache import MemoryCache


# 1. Every probe's RTT comes from the same high-resolution clock ------------

@pytest.mark.parametrize("api_ms,elapsed_ms", [(0, 0.412), (5, 5.271), (26, 26.384), (252, 252.716)])
def test_windows_rtt_is_measured_not_the_apis_whole_milliseconds(monkeypatch, api_ms, elapsed_ms):
    """The Windows API's RoundTripTime is whole milliseconds; it was used from
    10 ms up, so every hop past the access network read 26.000, 252.000."""
    class Options(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                    ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

    class Echo(ctypes.Structure):
        _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong),
                    ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                    ("Options", Options)]

    class Lib:
        def IcmpCreateFile(self):
            return 1

        def IcmpCloseHandle(self, handle):
            return 1

        def IcmpSendEcho(self, handle, dest, req, size, opts, reply, reply_size, timeout):
            echo = Echo(Address=0x0102000A, Status=probe.IP_TTL_EXPIRED_TRANSIT, RoundTripTime=api_ms)
            ctypes.memmove(reply, ctypes.addressof(echo), ctypes.sizeof(echo))
            return 1

    monkeypatch.setattr(probe, "_windows_api", lambda: (ctypes, Lib(), Options, Echo))
    ticks = iter([100.0, 100.0 + elapsed_ms / 1000])
    monkeypatch.setattr(probe.time, "perf_counter", lambda: next(ticks))
    reply = probe._windows_probe("1.1.1.1", 5, 1, 1.0)
    assert reply.address == "10.0.2.1"
    assert reply.rtt_ms == pytest.approx(elapsed_ms, abs=1e-6)


# 2. A trace the built-in prober ran is labelled as such ---------------------

def test_the_built_in_prober_is_labelled_on_every_platform():
    lines = [f"traceroute to x (1.1.1.1), 30 hops max, 40 byte packets, {probe.HEADER_MARK}"]
    lines += probe.format_hop(1, [probe.Reply("192.0.2.1", 1.234)] * 3)
    route = analyse_sync("\n".join(lines) + "\n", (14.6, 121.0), sources=__import__("routemap_engine").OFFLINE)
    assert route.parser == "icmp" and route.parser_label == "Built-in ICMP prober"
    plain = "traceroute to x (1.1.1.1), 30 hops max, 40 byte packets\n 1  192.0.2.1  1.0 ms\n"
    assert parse_trace(plain).parser == "traceroute", "system traceroute keeps its own name"


# 3. When RIS paths disagree, say where -------------------------------------

def test_disagreeing_ris_paths_say_where_they_leave_the_trace():
    """heise.de: 40 of 310 agreed and differs_at was null, so the UI could not
    say where the other 270 went."""
    dp = [64500, 1299, 12306]
    paths = [[3333, 1299, 12306]] * 2 + [[6939, 3356, 12306]] * 5 + [[174, 12306]] * 3 + [[7018, 9999]]
    out = ripe.ris_agreement(dp, paths)
    assert out["agree"] == 2 and out["total"] == 11
    assert out["diverge"][0] == {"joins_at": 12306, "via": 3356, "instead_of": 1299, "paths": 5}
    assert out["diverge"][1] == {"joins_at": 12306, "via": 174, "instead_of": 1299, "paths": 3}
    assert {"joins_at": None, "via": 9999, "instead_of": None, "paths": 1} in out["diverge"]


# 4. Hours RIPEstat has no data for yet are not zeros ------------------------

def test_hours_after_ripestats_data_horizon_are_not_reported_as_quiet():
    end = dt.datetime(2026, 10, 4, 11, 24, tzinfo=dt.timezone.utc)
    horizon = "2026-10-04T07:59:56"

    def handler(request):
        return httpx.Response(200, json={"data": {"query_endtime": horizon,
                                                  "updates": [{"timestamp": "2026-10-04T07:43:23"}]}})
    c = ripe.RipeStat(user_agent="t", sourceapp="t", transport=httpx.MockTransport(handler))
    window = asyncio.run(c.bgp_update_window("193.99.144.0/24", end=end))
    assert window["until"] == dt.datetime(2026, 10, 4, 7, 59, 56, tzinfo=dt.timezone.utc)
    bins = ripe.hourly_bins(window["timestamps"], end, until=window["until"])
    assert bins[-3:] == [None, None, None] and bins[-4] == 1, bins[-6:]
    assert ripe.hourly_bins(window["timestamps"], end)[-3:] == [0, 0, 0], "without a horizon nothing is hidden"


# 5. The Hoiho ruleset date is always reported -------------------------------

def _client(sent, ruleset="2024-08"):
    async def post(self, url, **kwargs):
        sent.extend(kwargs.get("json") or [])

        class R:
            status_code = 200

            @staticmethod
            def json():
                return {"summary": {"ruleset_date": ruleset}, "matches": []}
        return R()
    return post


def test_answers_from_the_cache_still_report_their_ruleset(monkeypatch):
    sent = []
    monkeypatch.setattr("httpx.AsyncClient.post", _client(sent))
    client = hoiho.Hoiho(cache=MemoryCache())
    names = ["ae1.fra10.example.net", "xe-0.hkg1.example.net"]
    _, first = asyncio.run(client.lookup(names))
    asked = list(sent)
    _, again = asyncio.run(client.lookup(names))
    assert first == again == "2024-08"
    assert sent == asked, "the second lookup was all cache and sent nothing"


def test_with_nothing_cached_the_date_is_asked_with_a_placeholder_only(monkeypatch):
    sent = []
    monkeypatch.setattr("httpx.AsyncClient.post", _client(sent))
    client = hoiho.Hoiho(cache=MemoryCache())
    client.cache.set("ae1.fra10.example.net", dict(hoiho.UNMATCHED))     # an old cache entry, no date
    _, ruleset = asyncio.run(client.lookup(["ae1.fra10.example.net"]))
    assert ruleset == "2024-08" and sent == [hoiho.RULESET_PROBE]
