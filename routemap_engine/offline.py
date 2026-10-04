"""
Offline IP databases: DB-IP Lite City and DB-IP Lite ASN (CC BY 4.0).

The engine never downloads them; a caller passes the file paths it has. Both
are MaxMind DB files, read with the ``maxminddb`` package (Apache-2.0), which is
an optional dependency: ``pip install routemap-engine[offline]``.

Attribution required by the licence: "IP Geolocation by DB-IP"
(https://db-ip.com). :data:`ATTRIBUTION` is that text.

Only public addresses are looked up, the same rule as every online source.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from routemap_engine.logsafe import tag

log = logging.getLogger(__name__)

ATTRIBUTION = "IP Geolocation by DB-IP"
ATTRIBUTION_URL = "https://db-ip.com"
PROVIDER_DBIP = "dbip"
PROVIDER_RIPESTAT = "ripestat"


def _open(path):
    try:
        import maxminddb
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError("the offline databases need the 'maxminddb' package: "
                           "pip install routemap-engine[offline]") from exc
    return maxminddb.open_database(str(path))


def _public(addr: str) -> bool:
    from routemap_engine.netaddr import is_private_ip
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not is_private_ip(addr)


class OfflineCity:
    """DB-IP Lite City: address -> {lat, lon, city, cc, provider}."""

    def __init__(self, path):
        self.path = str(path)
        self._db = _open(path)
        meta = self._db.metadata()
        self.build_epoch = meta.build_epoch
        self.database_type = meta.database_type

    def lookup_one(self, addr: str) -> dict | None:
        if not _public(addr):
            return None
        try:
            rec = self._db.get(addr)
        except ValueError:
            return None
        if not rec or "location" not in rec:
            return None
        lat, lon = rec["location"].get("latitude"), rec["location"].get("longitude")
        if lat is None or lon is None:
            return None
        from routemap_engine.geo import is_sentinel
        if is_sentinel(lat, lon):
            return None
        city = ((rec.get("city") or {}).get("names") or {}).get("en")
        cc = (rec.get("country") or {}).get("iso_code")
        return {"lat": float(lat), "lon": float(lon), "city": city, "cc": cc,
                "provider": PROVIDER_DBIP}

    async def __call__(self, addresses: list[str]) -> dict:
        """The :class:`~routemap_engine.geo.Sources` ``ip_db`` signature."""
        out = {}
        for addr in dict.fromkeys(addresses):
            rec = self.lookup_one(addr)
            if rec:
                out[addr] = rec
        log.info("event=routemap_offline_city asked=%d found=%d", len(set(addresses)), len(out))
        return out


@dataclass(frozen=True)
class AsnRecord:
    asn: int
    org: str
    network: str          # the database range containing the address, not the BGP prefix

    def to_dict(self) -> dict:
        return {"asn": self.asn, "org": self.org, "network": self.network}


class OfflineAsn:
    """DB-IP Lite ASN: address -> AS number, AS organisation, containing range."""

    def __init__(self, path):
        self.path = str(path)
        self._db = _open(path)
        self.build_epoch = self._db.metadata().build_epoch

    def lookup(self, addr: str) -> AsnRecord | None:
        if not _public(addr):
            return None
        try:
            rec, plen = self._db.get_with_prefix_len(addr)
        except ValueError:
            return None
        if not rec or "autonomous_system_number" not in rec:
            return None
        network = ipaddress.ip_network(f"{addr}/{plen}", strict=False)
        return AsnRecord(int(rec["autonomous_system_number"]),
                         str(rec.get("autonomous_system_organization") or ""), str(network))


def layered_ip_db(offline, online):
    """One ``ip_db`` source from two tiers: *offline* (DB-IP Lite City) first,
    then *online* (RIPEstat) only for the addresses the file did not answer.
    Either may be None: without the file every public address goes online,
    and with online lookups off nothing does. Each answer carries
    ``provider``, so the route says which tier placed a hop."""
    async def ip_db(addresses: list[str]) -> dict:
        found: dict = {}
        if offline is not None:
            found.update(await offline(addresses))
        missing = [a for a in dict.fromkeys(addresses) if a not in found]
        if online is not None and missing:
            try:
                answered = dict(await online(missing) or {})
            except Exception as exc:  # noqa: BLE001 - a failed tier contributes nothing
                log.warning("event=routemap_ip_db_online_failed error=%s", type(exc).__name__)
                answered = {}
            for rec in answered.values():
                rec.setdefault("provider", PROVIDER_RIPESTAT)
            found.update(answered)
        return found
    return ip_db


def describe(addr: str) -> str:
    """For logs: the address hashed, never in the clear."""
    return tag(addr)
