"""The one way the engine makes an HTTP client: httpx with a cap on how much
of an answer is read.

Every API the engine calls (Hoiho, RIPEstat, RIPE Atlas, the IP database)
answers in a few kilobytes. An answer larger than MAX_RESPONSE_BYTES is
refused while it arrives, before it is held in memory: from Content-Length
when the server gives one, and by counting otherwise. The cap is a response
hook rather than a transport, so httpx's own transport (and with it TLS
verification and any proxy from the environment) stays as it is.
"""
from __future__ import annotations

import httpx

MAX_RESPONSE_BYTES = 2_000_000


class ResponseTooLarge(httpx.TransportError):
    """The answer was larger than the engine reads from any API."""


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


def _cap(limit: int):
    async def hook(response: httpx.Response) -> None:
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > limit:
            await response.aclose()
            raise ResponseTooLarge(f"the answer says it is {length} bytes; the limit is {limit}")
        response.stream = _Capped(response.stream, limit)
    return hook


def client(*, max_bytes: int = MAX_RESPONSE_BYTES, **kwargs) -> httpx.AsyncClient:
    """httpx.AsyncClient(**kwargs) that reads at most *max_bytes* of an answer."""
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    hooks["response"] = [*hooks.get("response", []), _cap(max_bytes)]
    return httpx.AsyncClient(event_hooks=hooks, **kwargs)
