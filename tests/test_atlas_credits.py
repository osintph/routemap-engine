"""Atlas credits: what a trace costs, and what the balance says when it cannot be read.

The cost is derived from the measurement :meth:`Atlas.create` actually sends,
with RIPE's published formula, so a change to the definition (packets, size,
one-off) that is not matched in TRACEROUTE_CREDITS fails here. Formula and the
one-off doubling: https://atlas.ripe.net/docs/getting-started/credits
"""
import asyncio
import json

import httpx
import pytest

from routemap_engine import atlas


def _sent_body() -> dict:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(201, json={"measurements": [1]})

    client = atlas.Atlas("k", transport=httpx.MockTransport(handler))
    asyncio.run(client.create("example.net", 1))
    return seen["body"]


def _ripe_cost(body: dict) -> int:
    total = 0
    for d in body["definitions"]:
        assert d["type"] == "traceroute"
        packets = d.get("packets", 3)
        size = d.get("size", 48)
        unit = 10 * packets * (int(size / 1500) + 1)
        probes = sum(p.get("requested", 1) for p in body["probes"])
        total += unit * probes * (2 if body.get("is_oneoff") else 1)
    return total


def test_cost_constant_matches_what_is_sent():
    assert atlas.TRACEROUTE_CREDITS == _ripe_cost(_sent_body())


def test_one_trace_is_sixty_credits():
    assert atlas.TRACEROUTE_CREDITS == 60


def _balance(response=None, exc=None):
    def handler(request):
        assert request.url.path.endswith("/credits/")
        assert request.headers["Authorization"] == "Key k"
        if exc is not None:
            raise exc
        return response

    return asyncio.run(atlas.Atlas("k", transport=httpx.MockTransport(handler)).balance())


def test_balance_ok_carries_ripes_numbers():
    b = _balance(httpx.Response(200, json={"current_balance": 1234, "estimated_daily_income": 21600,
                                           "estimated_daily_expenditure": 60}))
    assert (b.state, b.current, b.daily_income, b.daily_expenditure) == ("ok", 1234, 21600, 60)
    assert b.after() == 1234 - atlas.TRACEROUTE_CREDITS


@pytest.mark.parametrize("status", [401, 403])
def test_refusal_is_no_permission_with_ripes_reason(status):
    b = _balance(httpx.Response(status, json={"error": {"detail": "The provided API key does not exist",
                                                        "status": status}}))
    assert b.state == "no_permission" and b.current is None
    assert "does not exist" in b.message


@pytest.mark.parametrize("status", [401, 403])
def test_refusal_without_a_body_is_still_no_permission(status):
    b = _balance(httpx.Response(status, text="nope"))
    assert b.state == "no_permission" and b.message


@pytest.mark.parametrize("exc", [httpx.ConnectError("x"), httpx.ReadTimeout("x"),
                                 asyncio.TimeoutError(), OSError("x")])
def test_network_failure_is_unavailable(exc):
    b = _balance(exc=exc)
    assert b.state == "unavailable" and b.current is None and b.after() is None


@pytest.mark.parametrize("response", [
    httpx.Response(500, json={}),
    httpx.Response(429, json={}),
    httpx.Response(200, text="not json"),
    httpx.Response(200, json=[]),
    httpx.Response(200, json={}),
    httpx.Response(200, json={"current_balance": "lots"}),
    httpx.Response(200, json={"current_balance": True}),
])
def test_unusable_answer_is_unavailable_not_success(response):
    b = _balance(response)
    assert b.state == "unavailable" and b.current is None
