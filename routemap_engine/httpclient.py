"""The one way the engine makes an HTTP client: httpx with a cap on how much
of an answer is read.

Every API the engine calls (Hoiho, RIPEstat, RIPE Atlas, the IP database)
answers in a few kilobytes. An answer larger than MAX_RESPONSE_BYTES is
refused while it arrives, before it is held in memory: from Content-Length
when the server gives one, and by counting otherwise. The cap is a response
hook rather than a transport, so httpx's own transport (and with it TLS
verification and any proxy from the environment) stays as it is.

The count is of the bytes on the wire, which equal the decoded bytes only when
nothing is compressed: in 0.4.1 a 1.31 MB gzip answer decoded to 300 MB. So
every request asks for no encoding (Accept-Encoding: identity, whatever the
caller set), and an answer that is encoded anyway is refused before a byte of
it is decoded.
"""
from __future__ import annotations

import httpx

MAX_RESPONSE_BYTES = 2_000_000


class ResponseTooLarge(httpx.TransportError):
    """The answer was larger than the engine reads from any API."""


class UnexpectedEncoding(httpx.TransportError):
    """The answer was compressed although the request asked for no encoding."""


class _Capped(httpx.AsyncByteStream):
    def __init__(self, inner, limit: int):
        self._inner, self._limit = inner, limit

    async def __aiter__(self):
        total = 0
        async for chunk in self._inner:
            total += len(chunk)
            if total > self._limit:
                raise ResponseTooLarge(f"the answer was larger than {self._limit} bytes")
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


async def _identity(request: httpx.Request) -> None:
    request.headers["Accept-Encoding"] = "identity"


def _cap(limit: int):
    async def hook(response: httpx.Response) -> None:
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            await response.aclose()
            raise UnexpectedEncoding(f"the answer is {encoding}-encoded; only plain answers are read")
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > limit:
            await response.aclose()
            raise ResponseTooLarge(f"the answer says it is {length} bytes; the limit is {limit}")
        response.stream = _Capped(response.stream, limit)
    return hook


def client(*, max_bytes: int = MAX_RESPONSE_BYTES, **kwargs) -> httpx.AsyncClient:
    """httpx.AsyncClient(**kwargs) that reads at most *max_bytes* of an answer."""
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    hooks["request"] = [*hooks.get("request", []), _identity]
    hooks["response"] = [*hooks.get("response", []), _cap(max_bytes)]
    return httpx.AsyncClient(event_hooks=hooks, **kwargs)
