"""
What a located route says beyond places: RTT steps, the AS path, the countries
transited, and an anycast note. Pure functions over the route model (the dict
from ``Route.to_dict()``), so the desktop app and FalconEye share one answer.

Nothing here contacts the network. ASN data comes in from the caller:
:func:`enrich_offline` adds it from a DB-IP Lite ASN file, and the RIPEstat
client (``routemap_engine.ripe``) fills what the file does not know.
"""
from __future__ import annotations

import ipaddress

from routemap_engine import cities, geo

# RTT step classification for drawing lines between placed hops.
QUIET_MS = 15.0
HOT_MS = 60.0
STEP_QUIET, STEP_WARM, STEP_HOT, STEP_UNKNOWN = "quiet", "warm", "hot", "unknown"

# Content networks that answer from many places (anycast). The note only says
# "likely", and only when the physics or the operator points that way.
KNOWN_CDN_ASNS = {
    13335: "Cloudflare", 20940: "Akamai", 16625: "Akamai", 54113: "Fastly", 15169: "Google",
    396982: "Google Cloud", 8075: "Microsoft", 32934: "Meta", 2906: "Netflix", 714: "Apple",
    15133: "Edgio", 22822: "Edgio", 16509: "Amazon", 14618: "Amazon", 209242: "Cloudflare",
    60068: "CDN77", 12222: "Akamai", 21342: "Akamai", 30675: "Fastly",
}


def _placed(route: dict) -> list[dict]:
    return [h for h in route.get("hops") or [] if h.get("lat") is not None]


def _addresses(hop: dict) -> list[str]:
    return [a for a in (hop.get("addresses") or []) if a]


# ------------------------------------------------------------------ RTT steps ---

def classify_step(step_ms: float | None, quiet_ms: float = QUIET_MS, hot_ms: float = HOT_MS) -> str:
    if step_ms is None:
        return STEP_UNKNOWN
    if step_ms < quiet_ms:
        return STEP_QUIET
    return STEP_HOT if step_ms >= hot_ms else STEP_WARM


def step_intensity(step_ms: float | None, quiet_ms: float = QUIET_MS, hot_ms: float = HOT_MS) -> float:
    """0 at or below the quiet threshold, 1 at or above the hot one, linear between."""
    if step_ms is None or step_ms < quiet_ms:
        return 0.0
    if hot_ms <= quiet_ms:
        return 1.0
    return max(0.0, min(1.0, (step_ms - quiet_ms) / (hot_ms - quiet_ms)))


def rtt_steps(route: dict, quiet_ms: float = QUIET_MS, hot_ms: float = HOT_MS) -> list[dict]:
    """One segment per line drawn: from the origin (or the previous placed
    group) to each placed group, with the RTT step and its class.

    Consecutive hops at the same place form one group; its RTT is the lowest
    minimum RTT in it. A group with no RTT gets an unknown step, and the next
    step is measured from the last group that had one.
    """
    groups: list[dict] = []
    for hop in _placed(route):
        key = (round(hop["lat"], 3), round(hop["lon"], 3))
        if groups and groups[-1]["key"] == key:
            groups[-1]["hops"].append(hop["hop"])
            if hop.get("min_rtt_ms") is not None:
                prev = groups[-1]["rtt"]
                groups[-1]["rtt"] = hop["min_rtt_ms"] if prev is None else min(prev, hop["min_rtt_ms"])
            continue
        groups.append({"key": key, "lat": hop["lat"], "lon": hop["lon"], "hops": [hop["hop"]],
                       "rtt": hop.get("min_rtt_ms")})
    origin = route.get("origin") or {}
    start = (origin.get("lat"), origin.get("lon")) if origin.get("lat") is not None else None
    last_rtt = 0.0 if start else None
    out = []
    for g in groups:
        step = (g["rtt"] - last_rtt) if (g["rtt"] is not None and last_rtt is not None) else None
        out.append({"from": start, "to": (g["lat"], g["lon"]), "hops": g["hops"], "rtt_ms": g["rtt"],
                    "step_ms": None if step is None else round(step, 3),
                    "class": classify_step(step, quiet_ms, hot_ms),
                    "intensity": step_intensity(step, quiet_ms, hot_ms)})
        start = (g["lat"], g["lon"])
        if g["rtt"] is not None:
            last_rtt = g["rtt"]
    return out


# ------------------------------------------------------------------- ASN data ---

def enrich_offline(route: dict, asn_db) -> dict:
    """Add ``asn``, ``as_org`` and ``as_network`` to every hop with a public
    address the offline ASN database knows (first matching address). Returns
    the same dict. *asn_db* is an :class:`~routemap_engine.offline.OfflineAsn`
    or anything with ``lookup(addr) -> AsnRecord | None``."""
    for hop in route.get("hops") or []:
        for addr in _addresses(hop):
            rec = asn_db.lookup(addr) if asn_db is not None else None
            if rec:
                hop["asn"], hop["as_org"], hop["as_network"] = rec.asn, rec.org, rec.network
                hop.setdefault("asn_source", "dbip")
                break
    return route


def as_path(route: dict) -> list[dict]:
    """Ordered unique ASNs along the route, with the hops each covers.

    A hop with no ASN (local, silent, unknown) does not break a run; an ASN
    that reappears after another one is listed again, since that is what the
    packets did.
    """
    out: list[dict] = []
    for hop in route.get("hops") or []:
        asn = hop.get("asn")
        if not asn:
            continue
        if out and out[-1]["asn"] == asn:
            out[-1]["hops"].append(hop["hop"])
            continue
        out.append({"asn": asn, "org": hop.get("as_org") or "", "hops": [hop["hop"]]})
    return out


def as_path_text(path: list[dict], short: bool = True) -> str:
    """'AS1299 Arelion > AS12306 Plus.line'."""
    def name(org: str) -> str:
        if not short or not org:
            return org
        return org.split()[0].rstrip(",")
    return " > ".join(f"AS{p['asn']}" + (f" {name(p['org'])}" if p["org"] else "") for p in path)


# -------------------------------------------------------------- jurisdictions ---

def jurisdictions(route: dict, sensitive: set[str] | frozenset = frozenset()) -> list[dict]:
    """Countries transited, in order, from placed public hops.

    Consecutive hops in the same country merge. A placement known only to a
    country is marked ``country_only`` (the database's guess, not a city), and
    a country in *sensitive* (ISO codes) is marked ``sensitive``.
    """
    sens = {c.upper() for c in sensitive}
    out: list[dict] = []
    for hop in _placed(route):
        if hop.get("source") == geo.SOURCE_LOCAL:
            continue
        cc = (hop.get("cc") or "").upper()
        if not cc:
            continue
        country_only = hop.get("precision") == geo.PRECISION_COUNTRY
        if out and out[-1]["cc"] == cc:
            out[-1]["hops"].append(hop["hop"])
            out[-1]["country_only"] = out[-1]["country_only"] and country_only
            continue
        out.append({"cc": cc, "hops": [hop["hop"]], "country_only": country_only,
                    "sensitive": cc in sens})
    return out


# -------------------------------------------------------------------- anycast ---

def _plausible_region(origin: tuple[float, float], budget_km: float) -> str | None:
    """The most populous bundled city within *budget_km* of the origin."""
    for row in cities._table():          # sorted by population, largest first
        city = cities._as_dict(row)
        if geo.haversine_km(origin[0], origin[1], city["lat"], city["lon"]) <= budget_km:
            return city["display"]
    return None


def anycast_note(route: dict, destination_registered: tuple[float, float] | None = None) -> str | None:
    """'likely anycast, served from <region>' for the destination, or None.

    Said when the destination's ASN is a known content network, or when its
    minimum RTT is too low for the place it is registered at (the IP database
    location, passed as *destination_registered*). The region is the largest
    city the measured RTT can reach from the origin.
    """
    hops = route.get("hops") or []
    answered = [h for h in hops if h.get("min_rtt_ms") is not None]
    if not answered:
        return None
    dest = answered[-1]
    origin = route.get("origin") or {}
    if origin.get("lat") is None:
        return None
    o = (origin["lat"], origin["lon"])
    budget = geo.max_distance_km(dest["min_rtt_ms"])
    reason = None
    if dest.get("asn") in KNOWN_CDN_ASNS:
        reason = f"{KNOWN_CDN_ASNS[dest['asn']]} network"
    if destination_registered is not None:
        d = geo.haversine_km(o[0], o[1], destination_registered[0], destination_registered[1])
        if d > budget:
            reason = f"registered {d:,.0f} km away, but answered in {dest['min_rtt_ms']:.0f} ms"
    if not reason:
        return None
    region = _plausible_region(o, budget)
    return f"likely anycast, served from near {region}" + f" ({reason})" if region else \
        f"likely anycast ({reason})"


def is_public(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return geo.classify_address(addr) == "public"
