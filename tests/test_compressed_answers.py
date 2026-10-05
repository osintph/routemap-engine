"""0.4.1's 2 MB cap counted the bytes on the wire, so a compressed answer
(1.31 MB of gzip) decoded to 300 MB through httpclient.client(). The engine
now asks for no encoding and refuses an answer that comes encoded anyway;
nothing decoded past the cap ever reaches the caller. Over the class: every
encoding httpx can decode, with and without Content-Length, and a server
that ignores the request."""
import asyncio
import gzip
import zlib

import httpx
import pytest

from routemap_engine import httpclient

DECODED = b"\0" * (httpclient.MAX_RESPONSE_BYTES * 3)


def _deflate(data: bytes) -> bytes:
    return zlib.compress(data)


ENCODINGS = {"gzip": gzip.compress, "deflate": _deflate, "x-gzip": gzip.compress}
try:  # br, when httpx can decode it here
    import brotli  # type: ignore[import-not-found]
    ENCODINGS["br"] = brotli.compress
except ImportError:
    pass


def _fetch(handler):
    async def go():
        async with httpclient.client(transport=httpx.MockTransport(handler)) as c:
            r = await c.get("https://stat.ripe.net/data/x")
            return r.content
    return asyncio.run(go())


@pytest.mark.parametrize("encoding", sorted(ENCODINGS))
@pytest.mark.parametrize("with_length", [True, False], ids=["length", "no-length"])
def test_an_encoded_answer_is_refused_whatever_the_wire_size(encoding, with_length):
    body = ENCODINGS[encoding](DECODED)
    assert len(body) < httpclient.MAX_RESPONSE_BYTES          # small on the wire
    asked = []

    def handler(request):
        asked.append(request.headers.get("accept-encoding"))
        headers = {"content-encoding": encoding}
        if not with_length:
            async def chunks():     # the async client reads an async stream
                yield body
            return httpx.Response(200, headers=headers, content=chunks())
        return httpx.Response(200, headers={**headers, "content-length": str(len(body))}, content=body)

    with pytest.raises(httpx.TransportError):
        content = _fetch(handler)
        assert len(content) <= httpclient.MAX_RESPONSE_BYTES, f"{len(content)} decoded bytes reached the caller"
    assert asked == ["identity"]


def test_every_request_asks_for_no_encoding_even_when_the_caller_sets_one():
    seen = []

    async def go():
        async with httpclient.client(transport=httpx.MockTransport(
                lambda r: seen.append(r.headers.get("accept-encoding")) or httpx.Response(200, json={})),
                headers={"Accept-Encoding": "gzip"}) as c:
            await c.get("https://a.example/", headers={"accept-encoding": "br"})
            await c.get("https://a.example/")
    asyncio.run(go())
    assert seen == ["identity", "identity"]


def test_an_identity_answer_reads_as_before():
    assert _fetch(lambda r: httpx.Response(200, headers={"content-encoding": "identity"}, json={"ok": 1})) \
        == b'{"ok":1}'
