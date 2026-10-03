"""
CAIDA Hoiho client: router hostname -> location, for the Route Map tab.

WHY HOSTNAME FIRST
------------------
An IP geolocation database tells you where a prefix is *registered*, which for
backbone transit is wherever the carrier filed it: a Tata or Arelion router in
the middle of an undersea path routinely geolocates to the operator's
headquarters country, thousands of kilometres from where the packet actually
turned around. The router's own hostname is better evidence, because it is the
carrier's own operational label for the site the box is in:
``if-bundle-2-2.qcore2.sqn-sanjose.as6453.net`` is in San Jose because Tata's
naming scheme says so.

CAIDA's Hoiho (Holistic Orthography of Internet Hostname Observations) is the
published work that turns that intuition into per-operator regexes with a
measured error rate, and api.hoiho.caida.org serves the extracted rules. So
Hoiho is asked first and the IP database is the fallback, not the other way
round.

WHAT THE API ACTUALLY IS
------------------------
Implemented against the OpenAPI document at https://api.hoiho.caida.org/openapi.json
(read 2026-10-03, ruleset_date 2024-08), not against assumptions:

  POST /lookups             body: a JSON array of hostname strings
  GET  /lookups/{hostname}  one hostname

Both answer with the same ``LookupResponse``::

    {"summary": {"ruleset_date": "2024-08",
                 "hostnames_requested": 9, "hostnames_matched": 3},
     "matches": [{"hostname": ..., "match_strs": ["sanjose"],
                  "match_meanings": ["place"], "cc": "US", "place": "San Jose",
                  "st": "CA", "lat": "37.339390", "lng": "-121.894960"}],
     "errors": null}

Three things about that shape drive the code below:

1. ``lat`` and ``lng`` are **strings**, and every field except ``hostname`` is
   nullable. A match can carry a ``place`` and no coordinates at all.
2. A hostname with no rule is simply **absent from** ``matches``. There is no
   per-hostname "no match" entry, so the request list is what tells you a
   hostname was asked about, and ``matches`` is keyed back by ``hostname``.
3. Garbage input is not an error: a batch containing ``""`` and
   ``"not a hostname"`` answered 200 with those hostnames silently unmatched.
   So an empty ``matches`` means "no rule", never "something went wrong", and
   nothing here treats it as a failure.

The description field says "Please limit to 1 request/sec. Use POST for bulk
requests", which is the whole reason this batches: one trace is one request.

CACHING, AND WHAT IS IN THE CACHE
---------------------------------
Router hostnames only, in whatever :mod:`routemap.engine.cache` object the
caller passes (30 days by default). A hostname is cached whether or not it
matched, because the misses are the common case and re-asking for them every
time would be most of the traffic sent to CAIDA for no new information.

Nothing else from a trace is stored. ``routemap.engine.parse.is_routable_hostname``
is the gate: a private hop, a LAN label like ``_gateway`` or ``router``,
and anything address-shaped never reaches this module, so it is neither sent to
CAIDA nor written to the cache.

NO MODULE STATE
---------------
Everything that varies between callers (base URL, timeout, User-Agent, cache)
lives on a :class:`Hoiho` instance. FalconEye builds one from its own config;
the desktop app builds one from its settings.
"""
from __future__ import annotations

import asyncio
import logging
import math

import httpx

from routemap.__about__ import REPO_URL, USER_AGENT_PRODUCT
from routemap.engine.cache import Cache, NullCache
from routemap.engine.logsafe import tag
from routemap.engine.parse import is_routable_hostname

log = logging.getLogger("routemap.engine.hoiho")

DEFAULT_BASE_URL = "https://api.hoiho.caida.org"
DEFAULT_TIMEOUT_SECONDS = 12.0
DEFAULT_USER_AGENT = f"{USER_AGENT_PRODUCT} (+{REPO_URL}; traceroute geolocation)"

# One trace is at most 30 hops, so a single POST covers a whole trace. The cap
# exists for the batch path (several traces, or a retry) rather than for one
# request, and the sleep between chunks is the 1 request/sec the API asks for.
BATCH_SIZE = 32
INTER_BATCH_SLEEP_SECONDS = 1.0


def _coord(raw) -> float | None:
    """One coordinate from the API's string field, or None if unusable."""
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return value


def match_to_record(match: dict) -> dict:
    """One ``HostnameInfo`` as the record we cache and return.

    ``located`` is the question callers actually ask, and it is False for a
    match that named a place but carried no coordinates: there is nothing to put
    on a map, and the distinction matters because such a hostname must fall
    through to the IP database rather than be treated as placed.
    """
    lat = _coord(match.get("lat"))
    lng = _coord(match.get("lng"))
    located = (
        lat is not None and lng is not None
        and -90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0
    )
    return {
        "located": located,
        "lat": lat if located else None,
        "lng": lng if located else None,
        "place": match.get("place") or None,
        "st": match.get("st") or None,
        "cc": match.get("cc") or None,
        "iata": match.get("iata") or None,
        "locode": match.get("locode") or None,
        "clli": match.get("clli") or None,
        # The substring the rule fired on and what it was read as ("sanjose" /
        # "place"). Shown in the UI because it is the evidence for the claim:
        # an operator can see that a hop was placed in San Jose because the
        # hostname literally says sanjose.
        "match_strs": [str(s) for s in (match.get("match_strs") or [])][:8],
        "match_meanings": [str(s) for s in (match.get("match_meanings") or [])][:8],
    }


UNMATCHED = {"located": False, "lat": None, "lng": None, "place": None,
             "st": None, "cc": None, "iata": None, "locode": None,
             "clli": None, "match_strs": [], "match_meanings": []}


def routable(hostnames) -> list[str]:
    """The hostnames that may leave the machine, de-duplicated, in order."""
    wanted, seen = [], set()
    for name in hostnames:
        name = (name or "").strip().strip(".")
        if not name or name in seen or not is_routable_hostname(name):
            continue
        seen.add(name)
        wanted.append(name)
    return wanted


class Hoiho:
    """A configured Hoiho client. Cheap to build; holds no connection."""

    def __init__(self, *, base_url: str = DEFAULT_BASE_URL,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS,
                 user_agent: str = DEFAULT_USER_AGENT,
                 cache: Cache | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.user_agent = user_agent
        self.cache = cache if cache is not None else NullCache()

    async def post_batch(self, client: httpx.AsyncClient,
                         hostnames: list[str]) -> tuple[dict, str | None]:
        """One POST /lookups. Returns (records by hostname, ruleset_date).

        Never raises: an unreachable or unhappy API means this source did not
        answer, and the caller falls through to the IP database.
        """
        try:
            response = await client.post(
                f"{self.base_url}/lookups",
                json=hostnames,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent, "Accept": "application/json"},
            )
        except Exception as exc:
            log.warning("hoiho POST exception for %d hostnames: %s", len(hostnames), exc)
            return {}, None
        if response.status_code != 200:
            log.warning("hoiho POST returned %s for %d hostnames",
                        response.status_code, len(hostnames))
            return {}, None
        try:
            body = response.json()
        except Exception:
            log.warning("hoiho POST returned a non-JSON body")
            return {}, None
        if not isinstance(body, dict):
            return {}, None

        summary = body.get("summary") or {}
        ruleset = summary.get("ruleset_date") if isinstance(summary, dict) else None

        records: dict[str, dict] = {}
        for match in (body.get("matches") or []):
            if not isinstance(match, dict):
                continue
            hostname = match.get("hostname")
            if not isinstance(hostname, str) or not hostname:
                continue
            records[hostname] = match_to_record(match)

        # A hostname absent from matches has no rule. Recorded as an explicit
        # unmatched entry so it is cached as an answer rather than re-asked forever.
        for hostname in hostnames:
            records.setdefault(hostname, dict(UNMATCHED))
        return records, str(ruleset) if ruleset else None

    async def lookup(self, hostnames: list[str]) -> tuple[dict, str | None]:
        """Locate every hostname in *hostnames*. Returns (records, ruleset_date).

        Cache first, then one POST per :data:`BATCH_SIZE` for whatever is left.
        Hostnames that :func:`is_routable_hostname` rejects are dropped here and
        never leave the process.
        """
        wanted = routable(hostnames)
        if not wanted:
            return {}, None

        records: dict[str, dict] = {}
        missing: list[str] = []
        for name in wanted:
            cached = self.cache.get(name)
            if cached is None:
                missing.append(name)
                continue
            cached = dict(cached)
            cached["cached"] = True
            records[name] = cached

        if not missing:
            return records, None

        ruleset: str | None = None
        async with httpx.AsyncClient() as client:
            for index in range(0, len(missing), BATCH_SIZE):
                chunk = missing[index:index + BATCH_SIZE]
                if index:
                    await asyncio.sleep(INTER_BATCH_SLEEP_SECONDS)
                fetched, chunk_ruleset = await self.post_batch(client, chunk)
                ruleset = ruleset or chunk_ruleset
                for name, record in fetched.items():
                    self.cache.set(name, record)
                    stored = dict(record)
                    stored["cached"] = False
                    records[name] = stored

        matched = sum(1 for r in records.values() if r.get("located"))
        log.info("event=hoiho_lookup asked=%d cached=%d located=%d ruleset=%s",
                 len(wanted), len(wanted) - len(missing), matched, ruleset or "-")
        return records, ruleset

    async def lookup_one(self, hostname: str) -> dict | None:
        """One hostname. Used by tests and the CLI's diagnostics."""
        records, _ = await self.lookup([hostname])
        record = records.get((hostname or "").strip().strip("."))
        if record is None:
            log.info("event=hoiho_miss hostname=%s", tag(hostname))
        return record
