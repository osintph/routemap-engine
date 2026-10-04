"""
Internet exchange points: a hop inside an IXP's peering LAN prefix is labelled
with the exchange ("via Equinix HK").

OFF, and shipped without data. PeeringDB's prefix list is the natural source,
but its Acceptable Use Policy does not allow reproducing or redistributing the
data without permission; a request has been drafted (docs/peeringdb-request.md
in the app repository). Until a source the app may ship exists, ENABLED stays
False and :func:`label_hops` does nothing.
"""
from __future__ import annotations

import ipaddress

ENABLED = False


def label_hops(route: dict, prefixes: list[dict] | None) -> dict:
    """Add ``ixp`` (exchange name) to hops whose address falls in one of
    *prefixes* ([{"prefix": "...", "name": "..."}]). A no-op while disabled."""
    if not ENABLED or not prefixes:
        return route
    nets = []
    for p in prefixes:
        try:
            nets.append((ipaddress.ip_network(p["prefix"], strict=False), p["name"]))
        except (KeyError, ValueError):
            continue
    for hop in route.get("hops") or []:
        for addr in hop.get("addresses") or []:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            match = next((name for net, name in nets if ip in net), None)
            if match:
                hop["ixp"] = match
                break
    return route
