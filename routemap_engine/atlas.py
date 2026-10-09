"""
RIPE Atlas, with the user's own key: one traceroute from a probe near them.

The desktop counterpart of FalconEye's Atlas client (app/routemap/atlas.py),
with the server-only parts left there: no instance credit cap, no shared probe
cache, no configuration read from the environment. The key is passed in.

WHAT IS SENT TO RIPE, AND WHAT IS NOT
-------------------------------------
Sent: the target, in the measurement definition, and the probe selection
criteria (an AS number, or a two-letter country code). The user's coordinates
are never sent: there is deliberately no ``radius=`` probe filter, and the
"distance from you" figure is computed here from the probe's own published
coordinates.

A measurement is PUBLIC. RIPE Atlas publishes one-off measurements, including
the target, the probe and the result. The desktop app asks the user to
acknowledge that before the first Atlas trace, and nothing here can make it
untrue.

RESULTS GO THROUGH THE PARSER
-----------------------------
A result is rendered as Unix traceroute text (:func:`to_trace_text`) and parsed
like a pasted trace: one parser, one set of fixtures, one place for a format bug.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Callable

import httpx

from routemap_engine import geo, httpclient
from routemap_engine.logsafe import tag

log = logging.getLogger("routemap_engine.atlas")

BASE_URL = "https://atlas.ripe.net/api/v2"
# What one trace here costs. RIPE's formula for a traceroute result is
# 10 * N * (int(S/1500) + 1), 30 with the defaults, and "a one-off measurement
# result is twice as expensive than a periodic measurement result"
# (https://atlas.ripe.net/docs/getting-started/credits). :meth:`Atlas.create`
# asks for one probe, three packets, the default size and is_oneoff: 60.
TRACEROUTE_CREDITS = 60
DEFAULT_TIMEOUT_SECONDS = 150.0


class AtlasUnavailable(Exception):
    """Atlas cannot run this trace. ``kind``: auth | credits | noprobe | failed."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass(frozen=True)
class Balance:
    """The account's credits as RIPE reports them.

    ``state`` is "ok" (the numbers are RIPE's), "no_permission" (RIPE answered
    and refused: the key is unknown, expired, or lacks the "credits read"
    permission; ``message`` carries RIPE's own reason) or "unavailable" (no
    usable answer: network failure, timeout, a malformed or unexpected
    response). Only "ok" carries numbers. Field names are those of
    GET /api/v2/credits/ (https://atlas.ripe.net/docs/apis/rest-api-reference/
    credits/credits_retrieve).
    """

    state: str
    current: int | None = None
    daily_income: int | None = None
    daily_expenditure: int | None = None
    message: str = ""

    def after(self, cost: int = TRACEROUTE_CREDITS) -> int | None:
        """The balance once a measurement costing *cost* has run."""
        return None if self.current is None else self.current - cost


def _count(value) -> int | None:
    try:
        return None if value is None or isinstance(value, bool) else int(value)
    except (TypeError, ValueError):
        return None


def to_trace_text(result: dict) -> str:
    """Render one Atlas traceroute result as Unix traceroute output."""
    target = result.get("dst_name") or result.get("dst_addr") or "target"
    dst = result.get("dst_addr") or ""
    lines = [f"traceroute to {target} ({dst}), 30 hops max, 60 byte packets"]
    for hop in result.get("result") or []:
        number = hop.get("hop")
        if number is None:
            continue
        parts = []
        for probe in hop.get("result") or []:
            if "x" in probe:
                parts.append("*")
                continue
            rtt, addr = probe.get("rtt"), probe.get("from")
            if rtt is None or not addr:
                parts.append("*")
                continue
            name = probe.get("name")
            label = f"{name} ({addr})" if name and name != addr else addr
            parts.append(f"{label}  {float(rtt):.3f} ms")
        lines.append(f"{number:>2}  " + "  ".join(parts) if parts else f"{number:>2}  * * *")
    return "\n".join(lines) + "\n"


class Atlas:
    def __init__(self, key: str, *, user_agent: str = geo.DEFAULT_USER_AGENT,
                 base_url: str = BASE_URL, description: str = "routemap-engine traceroute",
                 transport: httpx.AsyncBaseTransport | None = None):
        if not key or not key.strip():
            raise AtlasUnavailable("auth", "No RIPE Atlas API key is set. Add one in Settings.")
        self.key = key.strip()
        self.user_agent = user_agent
        self.base_url = base_url.rstrip("/")
        # Published by RIPE with the measurement, so it names the tool, not the user.
        self.description = description
        self._transport = transport

    def _client(self, authenticated: bool = True) -> httpx.AsyncClient:
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Key {self.key}"
        extra = {} if self._transport is None else {"transport": self._transport}
        return httpclient.client(base_url=self.base_url, headers=headers, timeout=20.0, **extra)

    async def probes(self, params: dict) -> list[dict]:
        # Probe lists are public; the key is not sent where it is not needed.
        async with self._client(authenticated=False) as client:
            response = await client.get("/probes/", params=params)
        if response.status_code != 200:
            return []
        out = []
        for item in (response.json() or {}).get("results") or []:
            coords = (item.get("geometry") or {}).get("coordinates") or []
            lat = lon = None
            if len(coords) == 2:
                try:
                    lon, lat = float(coords[0]), float(coords[1])
                except (TypeError, ValueError):
                    lat = lon = None
            out.append({"id": item.get("id"), "asn": item.get("asn_v4") or item.get("asn_v6"),
                        "country": item.get("country_code"), "lat": lat, "lon": lon})
        return [p for p in out if p.get("id")]

    async def select_probe(self, asn: int | None, country: str | None,
                           origin: tuple[float, float] | None) -> dict:
        """The user's own network first, their country next; nearest first.

        *origin* only ranks candidates, here. It is never sent.
        """
        candidates: list[dict] = []
        if asn:
            candidates = await self.probes({"asn_v4": asn, "status": 1, "page_size": 100})
        if not candidates and country:
            candidates = await self.probes({"country_code": country.upper(), "status": 1,
                                            "page_size": 100})
        if not candidates:
            raise AtlasUnavailable(
                "noprobe", "No connected RIPE Atlas probe was found on your network or in "
                           "your country, so an Atlas trace would not describe your path.")
        if origin is not None:
            for probe in candidates:
                probe["distance_km"] = (None if probe["lat"] is None else round(
                    geo.haversine_km(origin[0], origin[1], probe["lat"], probe["lon"]), 1))
            candidates.sort(key=lambda p: (p["distance_km"] is None, p["distance_km"] or 0.0))
        return candidates[0]

    async def balance(self) -> Balance:
        """The account's credits. Never raises: a source that fails tells the
        caller which way it failed and contributes nothing else."""
        try:
            async with self._client() as client:
                response = await asyncio.wait_for(client.get("/credits/"), timeout=20.0)
        except Exception as exc:  # noqa: BLE001 - a budget run out is "unavailable"
            log.warning("event=atlas_balance_failed error=%s", type(exc).__name__)
            return Balance("unavailable", message="RIPE Atlas did not answer.")
        if response.status_code in (401, 403):
            detail = ""
            try:
                detail = str(((response.json() or {}).get("error") or {}).get("detail") or "")[:200]
            except Exception:  # noqa: BLE001
                pass
            return Balance("no_permission", message=detail or "RIPE Atlas refused to show the balance.")
        if response.status_code != 200:
            return Balance("unavailable", message=f"RIPE Atlas answered HTTP {response.status_code}.")
        try:
            body = response.json() or {}
        except Exception:  # noqa: BLE001
            body = None
        current = _count(body.get("current_balance")) if isinstance(body, dict) else None
        if current is None:
            return Balance("unavailable", message="RIPE Atlas sent no balance.")
        return Balance("ok", current=current,
                       daily_income=_count(body.get("estimated_daily_income")),
                       daily_expenditure=_count(body.get("estimated_daily_expenditure")))

    async def create(self, target: str, probe_id: int, af: int = 4) -> int:
        body = {
            "definitions": [{
                "type": "traceroute", "af": af, "target": target,
                "description": self.description, "protocol": "ICMP",
                "resolve_on_probe": True, "paris": 0, "first_hop": 1, "max_hops": 30,
                "packets": 3,
            }],
            "probes": [{"type": "probes", "value": str(probe_id), "requested": 1}],
            "is_oneoff": True,
        }
        async with self._client() as client:
            response = await client.post("/measurements/", json=body)
        if response.status_code in (200, 201):
            try:
                measurement = int((response.json() or {}).get("measurements")[0])
            except Exception as exc:
                raise AtlasUnavailable("failed", "RIPE Atlas did not return a measurement id") from exc
            log.info("event=atlas_measurement id=%s probe=%s target=%s",
                     measurement, probe_id, tag(target))
            return measurement
        detail = ""
        try:
            detail = str((response.json() or {}).get("error") or "")[:200]
        except Exception:  # noqa: BLE001
            pass
        lowered = detail.lower()
        if response.status_code in (401, 403) and "credit" not in lowered and "balance" not in lowered:
            raise AtlasUnavailable(
                "auth", "RIPE Atlas refused the key. Check it in Settings: it needs the "
                        "\"schedule a new measurement\" permission and must not have expired.")
        if response.status_code in (402, 403):
            raise AtlasUnavailable("credits", "RIPE Atlas refused the measurement; the account "
                                              "is probably out of credits.")
        raise AtlasUnavailable("failed", f"RIPE Atlas refused the measurement "
                                         f"(HTTP {response.status_code}). {detail}".strip())

    async def history(self, target: str, limit: int = 5) -> list[dict]:
        """The user's own earlier traceroute measurements to *target*, newest
        first, as [{"msm", "when", "probe", "text"}]: a baseline for path diff
        that spends no credits. Only the target is sent (with the key), which
        RIPE already holds for these measurements."""
        out: list[dict] = []
        try:
            async with self._client() as client:
                r = await asyncio.wait_for(client.get("/measurements/my/", params={
                    "target": target, "type": "traceroute", "sort": "-start_time",
                    "page_size": limit}), timeout=20.0)
                if r.status_code != 200:
                    return []
                for m in (r.json().get("results") or [])[:limit]:
                    res = await asyncio.wait_for(client.get(f"/measurements/{m['id']}/results/"), timeout=20.0)
                    rows = res.json() if res.status_code == 200 else []
                    if rows:
                        out.append({"msm": m["id"], "when": m.get("start_time"), "probe": rows[0].get("prb_id"),
                                    "text": to_trace_text(rows[0])})
        except Exception as exc:  # noqa: BLE001 - no history is not an error
            log.warning("event=routemap_atlas_history_failed error=%s", type(exc).__name__)
        return out

    async def wait(self, measurement_id: int, timeout: float = DEFAULT_TIMEOUT_SECONDS,
                   on_wait: Callable[[float], None] | None = None) -> str:
        """Poll until the measurement has a result; return it as trace text."""
        deadline = time.monotonic() + timeout
        started = time.monotonic()
        delay = 3.0
        async with self._client(authenticated=False) as client:
            while time.monotonic() < deadline:
                await asyncio.sleep(delay)
                delay = min(delay * 1.4, 10.0)
                if on_wait is not None:
                    try:
                        on_wait(time.monotonic() - started)
                    except Exception:  # noqa: BLE001
                        pass
                try:
                    response = await client.get(f"/measurements/{measurement_id}/results/")
                    results = response.json() if response.status_code == 200 else []
                except Exception:  # noqa: BLE001
                    continue
                if results:
                    return to_trace_text(results[0])
        raise AtlasUnavailable("failed", "The Atlas measurement did not return a result in time.")
