"""
Where this machine is, approximately, when the user has not said.

One provider, the one the IP geolocation fallback already uses: RIPEstat.
``whats-my-ip`` returns the address the request came from (which RIPEstat sees
anyway, because the request came from it), and the MaxMind GeoLite view places
that address at city level. Two requests to one service, nothing else.

The answer is approximate, and wrong on a VPN or a Tor exit, which every UI
that shows it says next to it.

FAMILY (0.7.0): a dual-stack machine has a public IPv4 and a public IPv6
address, and RIPEstat reports whichever the request happened to use. A trace
over IPv6 needs the IPv6 one (its origin, and the target of a reverse trace),
so ``family`` binds the request to an IPv4 or IPv6 local address. When the user sets an origin (a city, coordinates
or a point on the map) none of this runs.
"""
from __future__ import annotations

import ipaddress
import logging

from routemap_engine import cities, geo, httpclient
from routemap_engine.logsafe import tag

log = logging.getLogger("routemap_engine.whereami")

WHATS_MY_IP = "https://stat.ripe.net/data/whats-my-ip/data.json"
NETWORK_INFO = "https://stat.ripe.net/data/network-info/data.json"
APPROXIMATE_NOTE = "approximate; wrong on a VPN or exit node"


class OriginUnknown(RuntimeError):
    """The public address could not be found or placed."""


def _transport(family: int | None):
    """A transport that connects only over IPv4 (4) or IPv6 (6); None for either."""
    if family not in (4, 6):
        return None
    import httpx
    return httpx.AsyncHTTPTransport(local_address="::" if family == 6 else "0.0.0.0")


async def public_ip(*, user_agent: str = geo.DEFAULT_USER_AGENT,
                    timeout: float = geo.DEFAULT_HTTP_TIMEOUT, sourceapp: str | None = None,
                    family: int | None = None) -> str:
    transport = _transport(family)
    async with httpclient.client(**({"transport": transport} if transport else {})) as client:
        response = await client.get(WHATS_MY_IP, timeout=timeout,
                                    params={"sourceapp": sourceapp} if sourceapp else None,
                                    headers={"User-Agent": user_agent})
    response.raise_for_status()
    addr = str(((response.json() or {}).get("data") or {}).get("ip") or "").strip()
    ip = ipaddress.ip_address(addr)  # raises on garbage
    if family in (4, 6) and ip.version != family:
        raise ValueError(f"asked for the IPv{family} address and got an IPv{ip.version} one")
    return addr


async def locate_me(*, user_agent: str = geo.DEFAULT_USER_AGENT,
                    timeout: float = geo.DEFAULT_HTTP_TIMEOUT, sourceapp: str | None = None,
                    family: int | None = None) -> dict:
    """{"ip", "lat", "lon", "cc", "label"} for this machine, city level.

    Coordinates are rounded to one decimal (about 10 km), which is all the
    physics bound needs and no more than the city label already says.
    """
    try:
        addr = await public_ip(user_agent=user_agent, timeout=timeout, sourceapp=sourceapp, family=family)
    except Exception as exc:
        raise OriginUnknown(f"could not find this machine's public address: {exc}") from exc
    records = await geo.ip_geolocate([addr], user_agent=user_agent, timeout=timeout,
                                     sourceapp=sourceapp)
    record = records.get(addr)
    if not record:
        log.info("event=origin_lookup ip=%s result=none", tag(addr))
        raise OriginUnknown("the IP database has no location for this machine's address")
    lat, lon = round(record["lat"], 1), round(record["lon"], 1)
    city = cities.nearest(lat, lon)
    log.info("event=origin_lookup ip=%s result=ok", tag(addr))
    return {"ip": addr, "lat": lat, "lon": lon, "cc": record.get("cc"),
            "label": (city or {}).get("display") or f"{lat}, {lon}"}


async def asn_of(addr: str, *, user_agent: str = geo.DEFAULT_USER_AGENT,
                 timeout: float = geo.DEFAULT_HTTP_TIMEOUT, sourceapp: str | None = None) -> int | None:
    """The origin AS of *addr*, for picking a RIPE Atlas probe on the same network."""
    try:
        async with httpclient.client() as client:
            response = await client.get(NETWORK_INFO, params=geo._ripestat_params(addr, sourceapp),
                                        timeout=timeout, headers={"User-Agent": user_agent})
        asns = ((response.json() or {}).get("data") or {}).get("asns") or []
        return int(asns[0]) if asns else None
    except Exception as exc:  # noqa: BLE001
        log.warning("network-info lookup failed for %s: %s", tag(addr), exc)
        return None
