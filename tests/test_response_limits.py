"""No answer from an API is read past a fixed size (RM-12), over the class:
every client the engine makes goes through one helper that enforces it."""
import asyncio
import pathlib
import re

import httpx
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "routemap_engine"


def test_no_module_makes_its_own_http_client():
    offenders = []
    for py in ROOT.glob("*.py"):
        if py.name == "httpclient.py":
            continue
        for n, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"httpx\.(Async)?Client\(", line):
                offenders.append(f"{py.name}:{n}")
    assert not offenders, f"use httpclient.client(): {offenders}"


BIG = b'{"data": "' + b"x" * 3_000_000 + b'"}'


def huge(request):
    return httpx.Response(200, content=BIG)


def huge_chunked(request):
    async def body():
        for i in range(0, len(BIG), 65536):
            yield BIG[i:i + 65536]
    return httpx.Response(200, stream=_Gen(body()))


class _Gen(httpx.AsyncByteStream):
    def __init__(self, gen):
        self.gen = gen

    async def __aiter__(self):
        async for chunk in self.gen:
            yield chunk


@pytest.mark.parametrize("handler", [huge, huge_chunked])
def test_an_oversized_answer_is_refused(handler):
    from routemap_engine import httpclient

    async def go():
        async with httpclient.client(transport=httpx.MockTransport(handler)) as c:
            await c.get("https://example.invalid/")
    with pytest.raises(httpclient.ResponseTooLarge):
        asyncio.run(go())


def test_a_normal_answer_reads_as_before():
    from routemap_engine import httpclient

    async def go():
        async with httpclient.client(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json={"data": {"ok": True}}))) as c:
            return (await c.get("https://example.invalid/")).json()
    assert asyncio.run(go()) == {"data": {"ok": True}}


def test_ripestat_treats_an_oversized_answer_as_unavailable():
    from routemap_engine import ripe
    stat = ripe.RipeStat(user_agent="test", sourceapp="test", transport=httpx.MockTransport(huge))
    assert asyncio.run(stat.network_info("192.0.2.1")) is None
    assert "network-info" in stat.errors
