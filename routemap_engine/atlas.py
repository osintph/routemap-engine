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

A REVERSE trace (0.7.0, :meth:`Atlas.create_reverse`) is the one exception:
its target is the user's own public IP address, so that address is sent to
RIPE and published with the measurement. It runs only with ``consent=True``,
which the app passes only after the user agreed to exactly that. Its probe is
chosen in the destination's network, then the destination's country, never
in the user's own AS.

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
# How long to wait for a one-off traceroute's result. RIPE waits 4,000 ms per
# packet (response_timeout's default, POST /measurements/ schema), 3 packets a
# hop, up to 30 hops, so a path whose routers stay silent can take about
# 360 s; measurement 221303797 took 141 s, close to the 150 s this was.
DEFAULT_TIMEOUT_SECONDS = 420.0
# RIPE's schema for a traceroute definition (the POST /measurements/ reference
# at atlas.ripe.net/docs, read 10 Oct 2026): "paris" is 0 to 64, default 16,
# "The number of paris traceroute variations to try. Zero disables paris
# traceroute"; "size" defaults to 48. The credit formula has no paris term,
# so a reverse trace costs the same 60.
REVERSE_PARIS = 16
REVERSE_DESCRIPTION = "routemap-engine reverse traceroute"
# How long the probe waits for each reply on a reverse trace, in ms. RIPE's
# schema: response_timeout 1 to 60,000, default 4,000 ("Response timeout for
# one packet"). A silent hop costs 3 packets times this, so 2,000 halves the
# wait on a path whose routers do not answer (measurement 221303797: 10 silent
# hops, about 120 s at 4,000) and is still more than 6 times its slowest reply
# (300 ms). A reply slower than 2 s is counted as silent. No effect on cost.
REVERSE_RESPONSE_TIMEOUT_MS = 2000
# How far a probe may be from its published position, for the physics check:
# RIPE asks hosts to set it "roughly correct" (a neighbourhood will do) and
# adds an obfuscation "with a certain maximum distance added, which may not be
# precisely 1km" (RIPE NCC, ripe-atlas list, March 2021). The 300 km of
# geo.SLACK_KM is for an origin guessed from a public IP; a probe's own
# position is much better than that: about a kilometre of obfuscation and a
# few for a host who set the neighbourhood. Measurement 221303797: hop 1
# answered in 0.406 ms, which allows 40.6 km, and the IP database placed it
# 48.3 km from the probe; with 300 km of slack that passed, and any slack over
# 7.7 km would still pass it. The cost of a small slack: a host who set only
# the city can see hops near the probe left unplaced (with the reason), never
# placed somewhere the round trip cannot reach.
PROBE_SLACK_KM = 5.0
# The TTL Atlas uses for its last probe after a run of silent hops; RIPE's
# results page numbers that answer as the hop after the last one sent
# (measurement 221303797: hops 1 to 21, then 255, shown as hop 22).
FINAL_PROBE_TTL = 255
ANNOT_FINAL_PROBE = "answered the final TTL 255 probe"
FINAL_PROBE_DETAIL = ("RIPE Atlas sends one last probe with TTL 255 after a run of silent hops; this "
                      "answer came from it, so it is numbered after the last hop sent and the hops in "
                      "between are unknown.")


class AtlasUnavailable(Exception):
    """Atlas cannot run this trace. ``kind``: auth | credits | noprobe | failed."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass(frozen=True)
class Balance:
    """The account's credits as RIPE reports them.

    ``state`` is one of:

    * "ok": the numbers are RIPE's.
    * "bad_key": RIPE answered 401. The key is missing, unknown or expired,
      so it cannot schedule a measurement either.
    * "no_permission": RIPE answered 403. The key is valid but lacks the
      "credits read" permission; a measurement may still be allowed.
    * "unavailable": no usable answer (network failure, timeout, a malformed
      or unexpected response).

    ``message`` carries RIPE's own reason for "bad_key" and "no_permission". Only "ok" carries numbers. Field names are those of
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


def final_probe(result: dict) -> int | None:
    """The hop number the answer to Atlas's final TTL 255 probe gets (the hop
    after the last one sent, as RIPE's results page numbers it), or None when
    the result has no such answer."""
    numbers = [h.get("hop") for h in result.get("result") or [] if isinstance(h.get("hop"), int)]
    if not numbers or numbers[-1] != FINAL_PROBE_TTL:
        return None
    sent = [n for n in numbers[:-1] if n < FINAL_PROBE_TTL]
    return (max(sent) if sent else 0) + 1


def mark_final_probe(route, number: int | None) -> None:
    """Annotate hop *number* of *route* (a Route or its dict) as the answer to
    the final TTL 255 probe, so the table, the map, the PDF and the JSON say
    why its number follows a gap."""
    if number is None:
        return
    hops = route.hops if hasattr(route, "hops") else (route.get("hops") or [])
    for hop in hops:
        if hop.get("hop") == number:
            if ANNOT_FINAL_PROBE not in hop.setdefault("annotations", []):
                hop["annotations"].append(ANNOT_FINAL_PROBE)
                hop.setdefault("annotation_details", []).append(f"{ANNOT_FINAL_PROBE}: {FINAL_PROBE_DETAIL}")


def to_trace_text(result: dict) -> str:
    """Render one Atlas traceroute result as Unix traceroute output. The answer
    to the final TTL 255 probe is numbered as the hop after the last one sent
    (:func:`final_probe`), as RIPE's own results page does."""
    target = result.get("dst_name") or result.get("dst_addr") or "target"
    dst = result.get("dst_addr") or ""
    final = final_probe(result)
    lines = [f"traceroute to {target} ({dst}), 30 hops max, 60 byte packets"]
    for hop in result.get("result") or []:
        number = hop.get("hop")
        if number is None:
            continue
        if final is not None and number == FINAL_PROBE_TTL:
            number = final
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
                        "asn_v4": item.get("asn_v4"), "asn_v6": item.get("asn_v6"),
                        "country": item.get("country_code"), "lat": lat, "lon": lon})
        return [p for p in out if p.get("id")]

    @staticmethod
    def _query(af: int, **criteria) -> dict:
        """A probe search: connected probes whose IPv4 or IPv6 works, as RIPE's
        system tags say ("at least one successful ping result for any one of a
        selection of baseline targets", re-assessed every four hours)."""
        return {**criteria, "status": 1, "tags": f"system-ipv{6 if af == 6 else 4}-works", "page_size": 100}

    @staticmethod
    def _rank(candidates: list[dict], position: tuple[float, float] | None) -> list[dict]:
        if position is not None:
            for probe in candidates:
                probe["distance_km"] = (None if probe["lat"] is None else round(
                    geo.haversine_km(position[0], position[1], probe["lat"], probe["lon"]), 1))
            candidates.sort(key=lambda p: (p["distance_km"] is None, p["distance_km"] or 0.0))
        return candidates

    async def select_probe(self, asn: int | None, country: str | None,
                           origin: tuple[float, float] | None, af: int = 4) -> dict:
        """The user's own network first, their country next; nearest first.

        *origin* only ranks candidates, here. It is never sent.
        """
        candidates: list[dict] = []
        if asn:
            candidates = await self.probes(self._query(af, **{f"asn_v{6 if af == 6 else 4}": asn}))
        if not candidates and country:
            candidates = await self.probes(self._query(af, country_code=country.upper()))
        if not candidates:
            raise AtlasUnavailable(
                "noprobe", "No connected RIPE Atlas probe was found on your network or in "
                           "your country, so an Atlas trace would not describe your path.")
        return self._rank(candidates, origin)[0]

    async def select_reverse_probe(self, dest_asn: int | None, dest_country: str | None,
                                   dest_position: tuple[float, float] | None, *,
                                   user_asn: int | None, af: int = 4) -> dict:
        """A probe in the destination's network, else in its country, nearest
        the destination's located position first; never one in the user's own
        AS, whose trace back would not start near the destination."""
        key = f"asn_v{6 if af == 6 else 4}"

        def usable(found: list[dict]) -> list[dict]:
            return [p for p in found if not (user_asn and p.get(key) == user_asn)]
        candidates: list[dict] = []
        if dest_asn:
            candidates = usable(await self.probes(self._query(af, **{key: dest_asn})))
        if not candidates and dest_country:
            candidates = usable(await self.probes(self._query(af, country_code=dest_country.upper())))
        if not candidates:
            where = " or ".join(x for x in (f"AS{dest_asn}" if dest_asn else "",
                                            (dest_country or "").upper()) if x) or "the destination's network"
            raise AtlasUnavailable("noprobe", f"No connected RIPE Atlas probe was found in {where}, "
                                              "so there is nothing to trace back from. No credits were spent.")
        return self._rank(candidates, dest_position)[0]

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
            if response.status_code == 401:
                return Balance("bad_key", message=detail or "RIPE Atlas did not accept the key.")
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

    async def create_reverse(self, public_ip: str, probe_id: int, *, consent: bool) -> int:
        """A traceroute from *probe_id* back to the user's *public_ip*. RIPE
        publishes it, with that address as the target, so it runs only when
        the caller passes ``consent=True`` (exactly True, not a truthy value)."""
        if consent is not True:
            raise AtlasUnavailable("consent", "A reverse trace publishes your public IP address. "
                                              "It needs your agreement first.")
        from routemap_engine import netaddr
        if netaddr.is_private_ip(public_ip):
            raise AtlasUnavailable("failed", "That is not a public address, so RIPE Atlas cannot trace to it.")
        af = 6 if ":" in public_ip else 4
        return await self.create(public_ip, probe_id, af, paris=REVERSE_PARIS, description=REVERSE_DESCRIPTION,
                                 resolve_on_probe=False, response_timeout=REVERSE_RESPONSE_TIMEOUT_MS)

    async def create(self, target: str, probe_id: int, af: int = 4, *, paris: int = 0,
                     description: str | None = None, resolve_on_probe: bool = True,
                     response_timeout: int | None = None) -> int:
        body = {
            "definitions": [{
                "type": "traceroute", "af": af, "target": target,
                "description": description or self.description, "protocol": "ICMP",
                "resolve_on_probe": resolve_on_probe, "paris": paris, "first_hop": 1, "max_hops": 30,
                "packets": 3,
            }],
            "probes": [{"type": "probes", "value": str(probe_id), "requested": 1}],
            "is_oneoff": True,
        }
        if response_timeout is not None:
            body["definitions"][0]["response_timeout"] = max(1, min(60_000, int(response_timeout)))
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
        return to_trace_text(await self.wait_result(measurement_id, timeout, on_wait))

    async def wait_result(self, measurement_id: int, timeout: float = DEFAULT_TIMEOUT_SECONDS,
                          on_wait: Callable[[float], None] | None = None) -> dict:
        """Poll until the measurement has a result; return RIPE's result object
        (for :func:`to_trace_text` and :func:`final_probe`)."""
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
                    return results[0]
        raise AtlasUnavailable("failed", "The Atlas measurement did not return a result in time.")
