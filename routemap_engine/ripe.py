"""
One client for every RIPEstat call beyond geolocation: network info, RIR, RPKI
validity, the RIS control-plane view, prefix visibility, BGP update activity,
AS overview, AS neighbours and abuse contacts.

Rules, the same as every engine source:
  - one client, so rate limiting and caching are in one place;
  - every request carries ``sourceapp`` and the caller's User-Agent;
  - every call has a hard timeout and returns None on any failure, which the
    caller shows as "unavailable"; nothing here can fail a trace;
  - answers are cached through the caller's cache (``get``/``set``), keyed by
    endpoint and resource, with per-endpoint lifetimes below;
  - only public addresses, prefixes and AS numbers are ever sent.

Data: RIPE NCC RIPEstat (https://stat.ripe.net), under the RIPEstat Service
Terms and Conditions.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import time

import httpx

from routemap_engine.logsafe import tag

log = logging.getLogger(__name__)

BASE = "https://stat.ripe.net/data/{}/data.json"
DEFAULT_TIMEOUT = 8.0
MAX_CONCURRENT = 4
MIN_INTERVAL_S = 0.15           # between request starts, across the client

# Cache lifetimes, seconds. Routing data moves; registration data barely does.
TTL = {
    "network-info": 7 * 86400, "rir": 30 * 86400, "rpki-validation": 6 * 3600,
    "looking-glass": 3600, "routing-status": 3600, "bgp-updates": 1800,
    "as-overview": 7 * 86400, "asn-neighbours": 86400, "abuse-contact-finder": 7 * 86400,
}

UNAVAILABLE = "unavailable"


class RipeStat:
    def __init__(self, *, user_agent: str, sourceapp: str, cache=None,
                 timeout: float = DEFAULT_TIMEOUT, transport: httpx.AsyncBaseTransport | None = None,
                 now=time.time):
        self.user_agent, self.sourceapp, self.cache = user_agent, sourceapp, cache
        self.timeout = timeout
        self._transport = transport
        self._sem = asyncio.Semaphore(MAX_CONCURRENT)
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._now = now

    # ---------------------------------------------------------------- plumbing ---
    def _key(self, endpoint: str, params: dict) -> str:
        return "ripestat:" + endpoint + ":" + "&".join(f"{k}={params[k]}" for k in sorted(params))

    def _cached(self, key: str, endpoint: str):
        if self.cache is None:
            return None
        hit = self.cache.get(key)
        if hit and self._now() - hit.get("t", 0) <= TTL.get(endpoint, 3600):
            return hit.get("data")
        return None

    async def _pace(self):
        async with self._lock:
            wait = self._last + MIN_INTERVAL_S - self._now()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = self._now()

    async def call(self, endpoint: str, **params) -> dict | None:
        """The ``data`` member of one RIPEstat answer, or None."""
        key = self._key(endpoint, params)
        hit = self._cached(key, endpoint)
        if hit is not None:
            return hit
        query = {**params, "sourceapp": self.sourceapp}
        try:
            async with self._sem:
                await self._pace()
                async with httpx.AsyncClient(transport=self._transport, timeout=self.timeout,
                                             headers={"User-Agent": self.user_agent}) as client:
                    response = await asyncio.wait_for(
                        client.get(BASE.format(endpoint), params=query), timeout=self.timeout + 1)
            response.raise_for_status()
            data = response.json().get("data")
        except Exception as exc:  # noqa: BLE001 - any failure is "unavailable"
            log.warning("event=routemap_ripestat_failed endpoint=%s resource=%s error=%s",
                        endpoint, tag(str(params.get("resource", ""))), type(exc).__name__)
            return None
        if not isinstance(data, dict):
            return None
        if self.cache is not None:
            try:
                self.cache.set(key, {"t": self._now(), "data": data})
            except Exception as exc:  # noqa: BLE001
                log.warning("event=routemap_ripestat_cache_failed error=%s", exc)
        return data

    # ---------------------------------------------------------------- endpoints ---
    async def network_info(self, addr: str) -> dict | None:
        """{"prefix": "62.115.0.0/16", "asns": [1299]} for a public address."""
        d = await self.call("network-info", resource=addr)
        if not d or not d.get("prefix"):
            return None
        return {"prefix": d["prefix"], "asns": [int(a) for a in d.get("asns") or [] if str(a).isdigit()]}

    async def rir(self, addr: str) -> str | None:
        d = await self.call("rir", resource=addr)
        rows = (d or {}).get("rirs") or []
        return rows[0].get("rir") if rows and isinstance(rows[0], dict) else None

    async def rpki(self, prefix: str, asn: int) -> str | None:
        """"valid", "invalid", "invalid_asn", "invalid_length" or "unknown" (no ROA)."""
        d = await self.call("rpki-validation", resource=f"AS{asn}", prefix=prefix)
        return (d or {}).get("status")

    async def ris_paths(self, prefix: str) -> list[list[int]] | None:
        """AS paths RIPE's route collectors see for *prefix* now."""
        d = await self.call("looking-glass", resource=prefix)
        if d is None:
            return None
        out = []
        for rrc in d.get("rrcs") or []:
            for peer in rrc.get("peers") or []:
                path = [int(x) for x in str(peer.get("as_path") or "").split() if x.isdigit()]
                if path:
                    out.append(path)
        return out

    async def visibility(self, prefix: str) -> dict | None:
        """{"seeing": 324, "total": 324, "share": 1.0} for the prefix's family."""
        d = await self.call("routing-status", resource=prefix)
        v = (d or {}).get("visibility") or {}
        fam = v.get("v6") if ":" in prefix else v.get("v4")
        if not fam or not fam.get("total_ris_peers"):
            return None
        seeing, total = int(fam.get("ris_peers_seeing") or 0), int(fam["total_ris_peers"])
        return {"seeing": seeing, "total": total, "share": seeing / total}

    async def bgp_updates(self, prefix: str, hours: int = 48,
                          end: _dt.datetime | None = None) -> list[str] | None:
        """ISO timestamps of BGP updates for *prefix* over the last *hours*."""
        end = end or _dt.datetime.now(_dt.timezone.utc)
        start = end - _dt.timedelta(hours=hours)
        d = await self.call("bgp-updates", resource=prefix,
                            starttime=start.strftime("%Y-%m-%dT%H:%M"),
                            endtime=end.strftime("%Y-%m-%dT%H:%M"))
        if d is None:
            return None
        return [u.get("timestamp") for u in d.get("updates") or [] if u.get("timestamp")]

    async def as_overview(self, asn: int) -> dict | None:
        d = await self.call("as-overview", resource=f"AS{asn}")
        if not d:
            return None
        return {"holder": d.get("holder"), "announced": bool(d.get("announced"))}

    async def as_neighbours(self, asn: int) -> dict | None:
        d = await self.call("asn-neighbours", resource=f"AS{asn}")
        counts = (d or {}).get("neighbour_counts")
        if not counts:
            return None
        left, right = int(counts.get("left") or 0), int(counts.get("right") or 0)
        return {"upstream": left, "downstream": right, "kind": "transit" if right > 0 else "stub"}

    async def abuse(self, addr: str) -> list[str] | None:
        d = await self.call("abuse-contact-finder", resource=addr)
        if d is None:
            return None
        return [c for c in d.get("abuse_contacts") or [] if isinstance(c, str)]


# ---------------------------------------------------------------- comparisons ---

def ris_agreement(data_plane: list[int], paths: list[list[int]]) -> dict:
    """Compare the trace's AS path (data plane) with RIS paths (control plane).

    ``agree`` counts RIS paths that contain the data-plane path's ASNs as one
    consecutive run (the trace usually starts below where RIS peers sit, so a
    suffix match is what agreement means). When none does, ``differs_at`` is
    the first data-plane ASN whose next hop no RIS path shows.
    """
    dp = [a for a in data_plane if a]
    out = {"agree": 0, "total": len(paths), "differs_at": None, "origin_asns": sorted({p[-1] for p in paths if p})}
    if not dp or not paths:
        return out

    def contains(path):
        n = len(dp)
        return any(path[i:i + n] == dp for i in range(len(path) - n + 1))

    out["agree"] = sum(1 for p in paths if contains(p))
    if out["agree"] == 0:
        pairs = {(p[i], p[i + 1]) for p in paths for i in range(len(p) - 1)}
        for a, b in zip(dp, dp[1:]):
            if (a, b) not in pairs:
                out["differs_at"] = a
                break
    return out


def update_burst(timestamps: list[str], at: _dt.datetime, window_minutes: int = 30,
                 threshold: int = 10) -> int | None:
    """The number of updates within *window_minutes* of *at*, if it is a burst."""
    near = 0
    for ts in timestamps or []:
        try:
            t = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        if t.tzinfo is None:
            t = t.replace(tzinfo=_dt.timezone.utc)
        if abs((t - at).total_seconds()) <= window_minutes * 60:
            near += 1
    return near if near >= threshold else None


def hourly_bins(timestamps: list[str], end: _dt.datetime, hours: int = 48) -> list[int]:
    """Update counts per hour, oldest first, for the timeline."""
    bins = [0] * hours
    for ts in timestamps or []:
        try:
            t = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        if t.tzinfo is None:
            t = t.replace(tzinfo=_dt.timezone.utc)
        k = int((end - t).total_seconds() // 3600)
        if 0 <= k < hours:
            bins[hours - 1 - k] += 1
    return bins
