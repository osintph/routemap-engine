"""
DNS response timing (0.8.0): how long the target's name takes to resolve, and
the one address the trace then goes to.

WHAT IS MEASURED
----------------
* **The system resolver.** One ``getaddrinfo`` for IPv4 (A) and one for IPv6
  (AAAA), each timed. The operating system's resolver may answer from its
  cache and does not say whether it did, so authoritative and cached are
  "not stated" (None) for these rows.
* **Each resolver the caller names** (the user's own list; none by default):
  one A and one AAAA query over UDP port 53, recursion desired, timed to the
  first answer. Recorded: the response code, the AA bit ("the responding name
  server is an authority for the domain name in question section", RFC 1035
  4.1.1) and the answer's TTL ("the time interval (in seconds) that the
  resource record may be cached", RFC 1035 4.1.3). A recursive resolver does
  not state whether it answered from its cache, so ``cached`` stays None. A
  truncated answer (TC, RFC 1035 4.1.1) is asked once more over TCP.
* **The traced address** (:func:`resolve_target`): resolved once, with the
  system resolver in its own order, and recorded, so the address shown is the
  address traced. A system tool is then given the address, not the name, and
  cannot resolve the name to another address of a CDN on its own.

PRIVACY AND BUDGET
------------------
Queries go to the system resolver and to the addresses the caller passes,
nowhere else; resolvers are IP addresses only (:func:`validate_resolver`), so
naming one causes no lookup of its own. Plain DNS is not encrypted. Every
query has :data:`QUERY_TIMEOUT` and the whole step :data:`BUDGET`; a query the
budget no longer covers is not sent and contributes nothing, and a failed
resolver never fails the trace. Names are logged only through ``logsafe.tag``.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

from routemap_engine.logsafe import tag
from routemap_engine.target import validate_target

log = logging.getLogger("routemap_engine.dnstime")

QUERY_TIMEOUT = 2.0          # seconds per query
BUDGET = 5.0                 # seconds for the whole DNS step
MAX_RESOLVERS = 8
SYSTEM = "system"
TYPES = ("A", "AAAA")
_FAMILY = {"A": socket.AF_INET, "AAAA": socket.AF_INET6}


class InvalidResolver(ValueError):
    """Not an IP address a DNS query can be sent to."""


@dataclass
class Lookup:
    resolver: str                       # "system" or the resolver's address
    type: str                           # "A" or "AAAA"
    ms: float | None                    # time to the first answer; None when none came
    addresses: list[str] = field(default_factory=list)
    rcode: str | None = None            # NOERROR, NXDOMAIN, ...; None for the system resolver
    aa: bool | None = None              # the AA bit; None when the resolver cannot say (system)
    cached: bool | None = None          # never stated by these resolvers; kept so the field is explicit
    ttl: int | None = None
    error: str | None = None            # "no answer in 2 s", "no IPv6 address", ...
    tcp: bool = False                   # asked again over TCP after a truncated answer

    def to_dict(self) -> dict:
        out = asdict(self)
        out["ms"] = None if self.ms is None else round(self.ms, 1)
        return out


@dataclass
class Resolved:
    name: str
    address: str
    family: int
    by: str = SYSTEM                    # "system", or "literal" when the target was an address

    def to_dict(self) -> dict:
        return asdict(self)


def validate_resolver(raw: str) -> str:
    """The canonical address of a resolver the user typed, or InvalidResolver.
    Private addresses (a resolver on the LAN) are allowed; loopback is allowed too
    (a local caching resolver). Multicast and unspecified are not."""
    try:
        addr = ipaddress.ip_address((raw or "").strip())
    except ValueError:
        raise InvalidResolver(f"{raw!r} is not an IP address; give the resolver's address, such as 9.9.9.9")
    if addr.is_multicast or addr.is_unspecified:
        raise InvalidResolver(f"{addr} cannot answer DNS queries")
    return str(addr)


def _is_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def resolve_target(target: str, family: str = "auto", *, getaddrinfo=socket.getaddrinfo) -> Resolved:
    """The address to trace for *target*, resolved once (the system's first
    choice for "auto", else the first of family "4" or "6"). Raises
    ``probe.NoAddress`` as :func:`probe.resolve` does."""
    from routemap_engine import probe
    name = validate_target(target)
    if _is_literal(name):
        return Resolved(name, name, probe.family_of(name), "literal")
    address = probe.resolve(name, family, getaddrinfo=getaddrinfo)
    return Resolved(name, address, probe.family_of(address))


def _system_lookup(name: str, rtype: str, getaddrinfo, clock) -> Lookup:
    started = clock()
    try:
        infos = getaddrinfo(name, None, _FAMILY[rtype], socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        return Lookup(SYSTEM, rtype, None, error=_gai_text(exc, rtype))
    ms = (clock() - started) * 1000
    seen: list[str] = []
    for fam, _t, _p, _c, sockaddr in infos:
        if fam == _FAMILY[rtype]:
            addr = str(ipaddress.ip_address(sockaddr[0].split("%")[0]))
            if addr not in seen:
                seen.append(addr)
    return Lookup(SYSTEM, rtype, ms, addresses=seen, error=None if seen else f"no {rtype} answer")


def _gai_text(exc: Exception, rtype: str) -> str:
    if isinstance(exc, socket.gaierror) and exc.errno in (getattr(socket, "EAI_NONAME", -2),
                                                          getattr(socket, "EAI_NODATA", -5)):
        return f"no {rtype} record"
    return f"lookup failed ({exc.__class__.__name__})"


def _dnspython_query(name: str, rtype: str, server: str, timeout: float, clock, port: int = 53) -> Lookup:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
    query = dns.message.make_query(name, rtype)          # recursion desired by default
    started = clock()
    tcp = False
    try:
        response = dns.query.udp(query, server, timeout=timeout, port=port)
        if response.flags & dns.flags.TC:
            tcp = True
            left = max(0.1, timeout - (clock() - started))
            response = dns.query.tcp(query, server, timeout=left, port=port)
    except dns.exception.Timeout:
        return Lookup(server, rtype, None, error=f"no answer in {timeout:g} s")
    except (OSError, dns.exception.DNSException) as exc:
        return Lookup(server, rtype, None, error=f"query failed ({exc.__class__.__name__})")
    ms = (clock() - started) * 1000
    wanted = dns.rdatatype.from_text(rtype)
    addresses, ttls = [], []
    for rrset in response.answer:
        if rrset.rdtype == wanted:
            ttls.append(rrset.ttl)
            addresses += [r.address for r in rrset if r.address not in addresses]
    return Lookup(server, rtype, ms, addresses=addresses, rcode=dns.rcode.to_text(response.rcode()),
                  aa=bool(response.flags & dns.flags.AA), ttl=min(ttls) if ttls else None, tcp=tcp)


def measure(target: str, resolvers: list[str] | tuple[str, ...] = (), *,
            getaddrinfo=socket.getaddrinfo, query: Callable | None = None,
            clock: Callable[[], float] = time.perf_counter, budget: float = BUDGET,
            query_timeout: float = QUERY_TIMEOUT, system: bool = True, port: int = 53) -> list[Lookup]:
    """Time the target's A and AAAA lookups through the system resolver and
    each of *resolvers*, within *budget* seconds in all. A literal address has
    nothing to resolve: no lookups."""
    name = validate_target(target)
    if _is_literal(name):
        return []
    servers = [validate_resolver(r) for r in list(resolvers)[:MAX_RESOLVERS]]
    if query is None:
        def query(n, t, srv, timeout, clk):
            return _dnspython_query(n, t, srv, timeout, clk, port=port)
    started = clock()
    out: list[Lookup] = []
    if system:
        for rtype in TYPES:
            out.append(_system_lookup(name, rtype, getaddrinfo, clock))
    for server in servers:
        for rtype in TYPES:
            left = budget - (clock() - started)
            if left <= 0.05:
                log.info("event=dns_budget_spent target=%s", tag(name))
                return out
            try:
                out.append(query(name, rtype, server, min(query_timeout, left), clock))
            except Exception as exc:  # noqa: BLE001 - a broken resolver contributes nothing
                log.info("event=dns_query_failed target=%s error=%s", tag(name), exc.__class__.__name__)
    log.info("event=dns_timed target=%s lookups=%d", tag(name), len(out))
    return out
