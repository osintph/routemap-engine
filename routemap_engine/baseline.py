"""
Typical latency between two regions, from RIPE Atlas anchor measurements.

"Typical Manila to Frankfurt: about 205 ms; measured 255 ms" needs a reference
that is neither the user's own trace nor a guess. RIPE Atlas anchors ping each
other continuously in the public "anchoring mesh"; their results are open data
and reading them costs no credits and needs no key.

HOW REGIONS AND ANCHORS ARE CHOSEN
----------------------------------
A region is a country. The source anchor is the anchor in the origin's country
nearest the origin; the target anchor is the anchor in the destination's
country nearest the destination's placement. The nearest-anchor choice uses
the anchors' published coordinates and happens here: only the two country
codes and the target anchor's public name are sent to RIPE Atlas, never the
user's coordinates or the trace's target.

The figure is the lowest RTT in the latest round of the target anchor's mesh
ping measurement, as seen from the source anchor's probe. Answers are cached
per anchor pair for a day.

Data: RIPE NCC RIPE Atlas (https://atlas.ripe.net), public measurements.
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from routemap_engine import geo

log = logging.getLogger(__name__)

BASE = "https://atlas.ripe.net/api/v2"
TIMEOUT = 12.0
TTL_SECONDS = 86400


class Baseline:
    def __init__(self, *, user_agent: str, cache=None, timeout: float = TIMEOUT,
                 transport: httpx.AsyncBaseTransport | None = None, now=time.time):
        self.user_agent, self.cache, self.timeout = user_agent, cache, timeout
        self._transport, self._now = transport, now
        self.error: str | None = None      # why the last typical() returned None

    async def _get(self, client, path, **params):
        r = await asyncio.wait_for(client.get(f"{BASE}{path}", params=params), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    async def _anchors(self, client, cc: str) -> list[dict]:
        key = f"atlas-anchors:{cc.upper()}"
        if self.cache is not None:
            hit = self.cache.get(key)
            if hit and self._now() - hit.get("t", 0) <= TTL_SECONDS:
                return hit["anchors"]
        body = await self._get(client, "/anchors/", country=cc.upper(), page_size=200)
        anchors = []
        for a in body.get("results") or []:
            if a.get("is_disabled"):
                continue
            geom = a.get("geometry") or {}
            coords = geom.get("coordinates") or [None, None]
            if coords[0] is None:
                continue
            anchors.append({"id": a["id"], "fqdn": a.get("fqdn"), "city": a.get("city"),
                            "probe": a.get("probe"), "lat": coords[1], "lon": coords[0]})
        if self.cache is not None:
            self.cache.set(key, {"t": self._now(), "anchors": anchors})
        return anchors

    @staticmethod
    def nearest(anchors: list[dict], lat: float, lon: float) -> dict | None:
        return min(anchors, key=lambda a: geo.haversine_km(lat, lon, a["lat"], a["lon"]), default=None)

    async def typical(self, origin: tuple[float, float], origin_cc: str,
                      dest: tuple[float, float], dest_cc: str) -> dict | None:
        """{"ms", "src", "dst", "msm"} or None when Atlas cannot say (``error`` says why)."""
        self.error = None
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self.timeout,
                                         headers={"User-Agent": self.user_agent}) as client:
                src_list = await self._anchors(client, origin_cc)
                dst_list = await self._anchors(client, dest_cc)
                src, dst = self.nearest(src_list, *origin), self.nearest(dst_list, *dest)
                if not src or not dst or src["id"] == dst["id"]:
                    self.error = ("RIPE Atlas has no anchor in " + (origin_cc if not src else dest_cc)
                                  if not src or not dst else "both ends are nearest the same RIPE Atlas anchor")
                    return None
                key = f"atlas-baseline:{src['id']}:{dst['id']}"
                if self.cache is not None:
                    hit = self.cache.get(key)
                    if hit and self._now() - hit.get("t", 0) <= TTL_SECONDS:
                        return hit["value"]
                found = await self._get(client, "/measurements/", target=dst["fqdn"], type="ping", af=4,
                                        status=2, is_public="true", page_size=20)
                mesh = [m for m in found.get("results") or []
                        if m.get("target") == dst["fqdn"] and "Mesh" in (m.get("description") or "")]
                if not mesh:
                    self.error = "RIPE Atlas lists no anchor mesh measurement to that anchor"
                    return None
                msm = mesh[0]["id"]
                latest = await self._get(client, f"/measurements/{msm}/latest/", probe_ids=src["probe"])
                rtts = [r.get("min") for r in latest or [] if isinstance(r.get("min"), (int, float)) and r["min"] > 0]
                if not rtts:
                    self.error = "the anchor mesh has no recent result between these anchors"
                    return None
                value = {"ms": round(min(rtts), 1), "msm": msm,
                         "src": {"fqdn": src["fqdn"], "city": src["city"]},
                         "dst": {"fqdn": dst["fqdn"], "city": dst["city"]}}
                if self.cache is not None:
                    self.cache.set(key, {"t": self._now(), "value": value})
                return value
        except asyncio.TimeoutError:
            self.error = f"RIPE Atlas did not answer within {self.timeout:.0f} s"
        except httpx.HTTPStatusError as exc:
            self.error = f"RIPE Atlas answered HTTP {exc.response.status_code}"
        except Exception as exc:  # noqa: BLE001 - "unavailable", never a failed trace
            self.error = f"RIPE Atlas could not be reached ({type(exc).__name__})"
        log.warning("event=routemap_atlas_baseline_failed error=%s", self.error)
        return None


def delta_text(baseline: dict | None, measured_ms: float | None, origin_label: str, dest_label: str) -> str | None:
    """'typical Manila to Frankfurt: about 205 ms; measured 255 ms'."""
    if not baseline or measured_ms is None:
        return None
    return (f"typical {origin_label} to {dest_label}: about {baseline['ms']:.0f} ms; "
            f"measured {measured_ms:.0f} ms")
