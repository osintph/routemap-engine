# routemap-engine

Hostname-first, physics-checked traceroute geolocation, in pure Python.

Feeding each traceroute hop's IP address to a geolocation database draws a path
that crosses oceans it never crossed, because a backbone router's address is
registered wherever its operator filed the prefix. This engine reads the
router's own hostname first (CAIDA Hoiho's published naming rules, then a
carrier site-code table built from each carrier's own router list), uses an IP
database only as a fallback, and rejects any location the measured round trip
could not have reached (about 100 km per millisecond of the fastest probe, plus
300 km of slack). Hops it cannot place are reported with the reason.

It powers the Route Map tab in [FalconEye](https://github.com/osintph/falconeye).

```bash
pip install routemap-engine
```

```python
from routemap_engine import analyse_sync, OFFLINE, run_trace, TraceOptions

route = analyse_sync(open("trace.txt").read(), origin=(14.6, 121.0))
route.to_dict()                       # schema: routemap_engine/route.schema.json

analyse_sync(text, None, sources=OFFLINE)          # contacts nothing
result = run_trace("example.com", TraceOptions(on_line=print))   # system traceroute
```

- **Parsers**: Windows `tracert` (with or without `-d`), Unix `traceroute`
  (with or without `-n`, ECMP continuation lines), `mtr --report`.
- **Sources** are passed in (`default_sources(...)` or your own callables);
  each runs under a hard time budget and losing one never fails a trace.
- **Progressive placement**: `progressive.ProgressiveTrace` places each hop as
  its line arrives and ends with exactly the result of a one-shot analysis.
- **No global configuration**; a pluggable cache for Hoiho answers.

### Beyond places (0.3.0)

```python
from routemap_engine import offline, osint, ripe, baseline, diff, default_sources

city = offline.OfflineCity("dbip-city-lite-2026-10.mmdb")    # pip install routemap-engine[offline]
asn = offline.OfflineAsn("dbip-asn-lite-2026-10.mmdb")
route = analyse_sync(text, origin, sources=default_sources(offline_city=city)).to_dict()
osint.enrich_offline(route, asn)                  # asn, as_org, as_network per hop
osint.as_path(route); osint.jurisdictions(route, {"SG"}); osint.anycast_note(route)
osint.rtt_steps(route, quiet_ms=15, hot_ms=60)    # one segment per drawn line, classed
stat = ripe.RipeStat(user_agent=..., sourceapp=..., cache=...)   # rate-limited, cached, None on failure
diff.diff_routes(old_route, new_route)["summary"]
```

- **Offline tiers**: DB-IP Lite City answers first; the online IP database is
  asked only for what it missed. Every IP database placement records
  `ip_provider` (`dbip` or `ripestat`).
- **Neighbour check**: a database placement between two placed hops in one
  area is rejected when the RTT rose too little to pay for the detour.
- **Anycast**: a destination that answered faster than its registered place
  allows is placed at the largest city the RTT reaches (counted from the
  last placed hop before it, with only the RTT added past that hop), with
  source `anycast` and the reason "likely anycast, served from near
  ...". Pass `destination=` to `analyse` (or set
  `ProgressiveTrace.destination`) when the trace text names no address, as
  mtr's does not.
- **Inferred from neighbours**: a hop no source places, between two placed
  hops in one city, is placed in that city with source `neighbours` (an
  inference, not an answer about the router).
- **RIPEstat client**: prefix, RIR, RPKI, RIS paths and visibility, BGP
  updates, AS overview and neighbours, abuse contacts; `ripe.ris_agreement`
  compares the trace's AS path with what RIS sees.
- **Atlas baseline**: typical latency between two countries from the public
  anchoring mesh (no key, no credits); `atlas.Atlas.history` lists the user's
  own earlier traceroutes.
- **Path diff** aligned by place, with a written summary.
- **Exchange points** (`ixp`): present, off, and shipped without data.
- **Continuous mode** (`watch`): one target probed again and again, mtr style,
  with the built-in ICMP prober: per-hop sent, loss, last, best, average, worst
  and jitter, plot samples, path changes over 10-cycle windows (so ECMP
  alternation is not a change) and sleep gaps that never count as loss. One
  cycle a second at most, 30 probes a second at most, an hour by default and 8
  hours at most; IPv4 only. It probes from the machine it runs on, so it is
  for the desktop app and the CLI, not for a web server.

### Probes and remote agents (0.8.0)

```python
from routemap_engine import agent, dnstime, multipath, ports, run_trace, TraceOptions

resolved = dnstime.resolve_target("example.com")           # the one address the trace goes to
rows = dnstime.measure("example.com", ["9.9.9.9"])          # A and AAAA: system resolver, then 9.9.9.9
run_trace("example.com", TraceOptions(address=resolved.address))   # the tool gets the address, not the name
ports.check_ports(resolved.address, "443, 80, 22", server_name="example.com")
multipath.discover("example.com", address=resolved.address)
```

- **DNS timing** (`dnstime`): time to the first answer for A and AAAA, through
  the system resolver and the resolvers you name (IP addresses only), with
  the response code, the AA bit and the TTL where the resolver gives them.
  2 s per query, 5 s for the whole step.
- **Port tests** (`ports`): one TCP connection attempt per port, at most 32
  ports and 4 at a time, open (with connect time), closed (reset) or
  filtered (no answer); a TLS handshake time for 443 and the ports you mark.
  A reachability check for one target, not a port scanner: ranges are
  refused.
- **Paths** (`multipath`) stop after 5 silent hops (scamper's and RIPE
  Atlas's default), then ask the target at full TTL on every path, so "not
  reached" means the target was asked and did not answer. Over TCP (Windows)
  one ICMP echo per silent hop tells a network that does not answer TCP
  probes (`tcp_silent_from`) from routers that answer nothing. Each TCP
  flow's source port is the system's (a bind to port 0), kept for the flow,
  so a port another program holds is never asked for; a flow whose kept
  port is refused later gets one new port and starts over
  (`flows_restarted`). A probe that never leaves this computer is counted in
  `local_failures`, with its error name and code in `local_failure_reasons`
  (`{"WSAEACCES 10013": 3}`).
- **Remote agents** (`agent`): `routemap-engine agent 1 hello|trace|paths|ports`
  runs one measurement on the machine it is started on and prints JSON
  lines. Route Map runs it on a server over the user's own SSH access, one
  command per trace; nothing listens on a port and nothing keeps running.
  Install it on the server with `pip install routemap-engine` (Python 3.11 or
  later) and check it with `routemap-engine agent 1 hello`. With
  `--place ip` the server's place is looked up at RIPEstat (which then sees
  the server's address); only the place is printed, never the address.

## What is sent where

| Source | Sends | To |
|---|---|---|
| PTR | public hop addresses that have no name | the system resolver |
| Hoiho | public router hostnames | api.hoiho.caida.org |
| IP database | public hop addresses (only those DB-IP Lite City did not place, when the caller passes it) | stat.ripe.net |
| `ripe.RipeStat` | public addresses, prefixes, AS numbers | stat.ripe.net |
| `baseline.Baseline` | two country codes and an anchor name | atlas.ripe.net |
| `watch.Watch` | ICMP echo probes with rising TTL, one per hop per cycle | the target, and the routers on the way |
| `dnstime.measure` | the target's name (A and AAAA queries) | the system resolver, and each resolver the caller names |
| `ports.check_ports` | one TCP connection attempt per port, and a TLS ClientHello with the target's name for TLS ports | the target's address |
| `multipath.discover` | ICMP echo probes (macOS, Linux) or TCP SYNs to port 443 (Windows) with rising TTL, plus one ICMP echo per hop silent to TCP | the target, and the routers on the way |
| `agent` with `--place ip` | the server's own address, as for this machine's origin | stat.ripe.net |

Private, CGNAT and reserved addresses are never looked up. Each upstream has its
own terms: CAIDA's Acceptable Use Agreement for publicly accessible datasets
(cite "The CAIDA UCSD Hoiho" in publications), and the RIPEstat Service Terms
and Conditions, whose Article 3.3 requires RIPE NCC's written permission for
commercial use. Any source can be switched off.

## Data

- `routemap_engine/data/cities.tsv`: GeoNames cities15000, CC BY 4.0.
- DB-IP Lite City and ASN are not bundled; callers pass the files. Licence CC
  BY 4.0, attribution "IP Geolocation by DB-IP" (`offline.ATTRIBUTION`).
- `routemap_engine/data/site_codes.tsv`: generated from each carrier's own
  published router list; see `routemap_engine/data/README.md` to add a carrier.

## Licence

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests need the
[Contributor Licence Agreement](CLA.md), signed once with a comment, and may be
declined.
