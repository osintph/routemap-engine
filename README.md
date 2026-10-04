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
- **RIPEstat client**: prefix, RIR, RPKI, RIS paths and visibility, BGP
  updates, AS overview and neighbours, abuse contacts; `ripe.ris_agreement`
  compares the trace's AS path with what RIS sees.
- **Atlas baseline**: typical latency between two countries from the public
  anchoring mesh (no key, no credits); `atlas.Atlas.history` lists the user's
  own earlier traceroutes.
- **Path diff** aligned by place, with a written summary.
- **Exchange points** (`ixp`): present, off, and shipped without data.

## What is sent where

| Source | Sends | To |
|---|---|---|
| PTR | public hop addresses that have no name | the system resolver |
| Hoiho | public router hostnames | api.hoiho.caida.org |
| IP database | public hop addresses (only those DB-IP Lite City did not place, when the caller passes it) | stat.ripe.net |
| `ripe.RipeStat` | public addresses, prefixes, AS numbers | stat.ripe.net |
| `baseline.Baseline` | two country codes and an anchor name | atlas.ripe.net |

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
