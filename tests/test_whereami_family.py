"""The origin lookup asks over the traced family (0.7.0): a dual-stack
machine's IPv6 trace gets its IPv6 public address, never the IPv4 one."""
import asyncio

import httpx
import pytest

from routemap_engine import httpclient, whereami


@pytest.mark.parametrize("family,local", [(4, "0.0.0.0"), (6, "::")])
def test_whereami_asks_over_the_traced_family(monkeypatch, family, local):
    seen = {}
    real = httpclient.client

    def fake_client(**kw):
        seen["transport"] = kw.get("transport")
        answer = "193.99.144.80" if family == 4 else "2a02:2e0:3fe:1001:302::"
        return real(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"data": {"ip": answer}})))
    monkeypatch.setattr(httpclient, "client", fake_client)
    addr = asyncio.run(whereami.public_ip(family=family))
    assert (":" in addr) == (family == 6)
    assert seen["transport"]._pool._local_address == local


def test_an_answer_in_the_other_family_is_refused(monkeypatch):
    real = httpclient.client
    monkeypatch.setattr(httpclient, "client", lambda **kw: real(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"data": {"ip": "193.99.144.80"}}))))
    with pytest.raises(ValueError, match="IPv6"):
        asyncio.run(whereami.public_ip(family=6))


def test_without_a_family_any_transport_is_used(monkeypatch):
    seen = {}
    real = httpclient.client

    def fake_client(**kw):
        seen.update(kw)
        return real(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"data": {"ip": "1.1.1.1"}})))
    monkeypatch.setattr(httpclient, "client", fake_client)
    assert asyncio.run(whereami.public_ip()) == "1.1.1.1" and "transport" not in seen
