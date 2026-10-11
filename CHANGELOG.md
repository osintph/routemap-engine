# Changelog

Keep a Changelog format; this project uses Semantic Versioning.

## [0.7.0] - 2026-10-11

Published 2026-10-11 to PyPI and GitHub Releases.

### Added

- **Path discovery on Windows**, without administrator rights: TCP probes
  to port 443, one TCP connect per probe with the TTL set and the source port
  as the flow; a router's "time exceeded" is read through
  `TCP_ICMP_ERROR_INFO` (Windows 10 version 2004 or later). Every discovery
  says its method, `icmp-paris` or `tcp-paris` (with the port), in
  `Discovery.method` and in `route.paths.method`. Checked on a real Windows
  11 network: 12 hops answered, and two flows split at a per-flow balancer.
- A path's latency is the median of its samples, so one slow reply does not
  move it.
- **Path discovery, `routemap_engine.multipath`.** `discover(target)` finds
  the paths a per-flow load balancer can send this machine's packets along,
  each with its own per-hop latency and, from ten pings of one of its flows,
  its own loss and latency to the target. Paris traceroute keeps every probe
  of a flow on one path (its identifier and checksum stay fixed, two payload
  bytes absorb the sequence number; Augustin et al., IMC 2006); flows are
  added at each hop until the MDA stopping rule is met at 95% (Veitch et
  al., INFOCOM 2009, Table I: 9 flows for one responder, 17 for two, ...);
  per-packet balancing is detected with the MDA's six-probe test and does
  not split paths. Paths found over ICMP are a lower bound (`at_least`).
- **Hard caps for discovery**, which a caller can lower and never raise: 20
  probes a second (scamper's default rate), 1,500 probes per discovery with
  the pings, 64 flows, 3 silent hops, 30 hops. A router that answers fewer
  than half its probes draws no more flows once a round found nothing new.
- **`analyse_paths(discovery)`** places every responder as any trace and each
  path's own hops from the same answers, so a path costs no extra lookups.
  `Route.paths` and the schema's `paths` field carry the result; an ordinary
  route has no `paths` key, so its output is unchanged.
- **IPv6 in the built-in prober** on macOS, Linux (ICMPv6 datagram sockets,
  IPV6_UNICAST_HOPS, IPV6_RECVERR) and Windows (`Icmp6SendEcho2`), and in
  continuous mode, which refused IPv6 before.
- **A chosen address family.** `TraceOptions.family` and `WatchOptions.family`
  ("auto", "4", "6"); `probe.resolve()` follows getaddrinfo's order for
  "auto". The system tools are held to the same family: `-4`/`-6` for
  tracert, Linux traceroute and mtr, `traceroute6 -I` on macOS (its
  traceroute has no IPv6).
- **Reverse traces via RIPE Atlas.** `Atlas.select_reverse_probe()` picks a
  connected probe in the destination's AS, then its country, nearest the
  destination and never in the user's own AS; `Atlas.create_reverse()`
  traces back to the user's public address, runs only with `consent=True`,
  refuses a private address, and costs the same 60 credits (Paris on, 16
  variations, RIPE's default).
- `whereami.public_ip(family=)` and `locate_me(family=)` ask over IPv4 or
  IPv6, so a dual-stack machine gets the address of the traced family.
- **Atlas's final TTL 255 probe** is numbered as the hop after the last one
  sent, as RIPE's results page does (`atlas.final_probe`, used by
  `to_trace_text`), and `atlas.mark_final_probe` annotates it "answered the
  final TTL 255 probe" (a new annotation in the schema). Found in a real
  reverse trace (measurement 221303797), where it showed as hop 255.
- The bundled town list has four more places, from the same GeoNames dumps
  and licence, where OVH has data centres: Gravelines, Beauharnois, Erith
  (cities500) and Vint Hill Park (US; GeoNames has no populated place named
  Vint Hill).
- `Atlas.wait_result()` returns RIPE's result object; `wait()` still returns
  the text.
- **The physics check takes the origin's own uncertainty**:
  `analyse(origin_slack_km=)`, `geo.resolve(slack_km=)`,
  `geo.locate_hops(slack_km=)`. 300 km (`geo.SLACK_KM`) stays the default,
  for an origin guessed from a public IP; a RIPE Atlas probe's published
  position gets `atlas.PROBE_SLACK_KM`, 5 km. In measurement 221303797 the
  IP database put hop 1 (0.406 ms, so at most 40.6 km) 48 km from the probe,
  and 300 km of slack let it through.
- **OVHcloud in the carrier site-code table**, from OVH's own network
  weathermap: 40 site codes (Strasbourg, Milan, Marseille, Singapore, and
  the large data centres Gravelines, Erith, Beauharnois and Vint Hill, ...).
  A name family two cities share (`nyc`: OVH's Newark and New York) names
  no site.
  In the real reverse trace OVH's backbone was placed by the IP database in
  London, Warsaw and Hong Kong; its router names put it in Strasbourg, Milan,
  Marseille and Singapore, each inside its round trip. Site codes may carry
  digits (OVH's metro codes, `sin1`). `sitegen --only CARRIER` refreshes one
  carrier and keeps the others' rows.
- **Reverse traces ask for 2,000 ms per reply** (`response_timeout`, RIPE's
  default 4,000): a silent hop costs 6 s instead of 12. The cost is unchanged.
- `probe.NoRoute` (a `NoAddress`): a trace, path discovery or Live on a
  machine with no route for the family says so once, before the first probe.

### Changed
- **Special-purpose addresses follow the IANA registries row by row** and no
  longer depend on the Python version's tables: 2001:1::3 (DNS-SD SRP
  anycast) is now looked up, 192.88.99.0/24 (the deprecated 6to4 relay
  block) no longer is. Every registry row is tested.
- `Atlas.select_probe()` and `select_reverse_probe()` ask only for probes
  RIPE marks as working over the traced family (`system-ipv4-works`,
  `system-ipv6-works`); `select_probe()` takes `af`.
- `geo.resolve()` is now `gather_records()` plus placement; its result is
  unchanged.
- `Atlas.wait()` waits up to 420 s (was 150 s): RIPE waits 4 s per packet,
  3 packets a hop, up to 30 hops, so a path with silent routers can take
  about 360 s. Measurement 221303797 took 141 s.

## [0.6.0] - 2026-10-10

Published 2026-10-10 to PyPI and GitHub Releases.

### Added
- **Continuous mode, `routemap_engine.watch`.** `Watch(target, WatchOptions)`
  probes one target again and again with the built-in prober's own
  per-platform probe function, one probe per hop per cycle, spaced evenly
  across the interval, mtr style, and keeps per hop: sent, received, loss,
  last, best, average, worst and jitter (population standard deviation, by
  Welford's method). Pause, resume, stop and reset are safe from any thread.
- **Limits that follow mtr** and cannot be set outside their range: one
  cycle a second by default and never faster (mtr's default, and its floor
  without root, mtr(8) and ui/mtr.c); at most 30 probes a second (what mtr
  sends on a 30-hop path, ui/net.c calc_deltatime); a 1 s wait for each
  reply; 5 s grace at the end (mtr's --gracetime); no deeper than 5 silent
  hops past the last that answered (mtr(8) --max-unknown "Default is 5";
  ui/mtr.c sets 12, the smaller value sends fewer probes); the first cycle
  probes every hop to find the path. A session stops after an hour by
  default and 8 hours at most.
- **Path changes** compare a hop's answering addresses over the last 10
  cycles with the 10 before: ECMP alternation between the same routers is
  never a change, a new set is reported once with the cycle it began, and a
  hop appearing, disappearing or the destination moving are changes too.
- **Sleep and suspend** are gaps: a cycle that ran well past its schedule,
  by wall or monotonic time, is dropped whole, counted neither as sent nor as
  lost, and recorded with its start and end.
- **Plot data**: a live ring of 3,600 samples per hop, raw samples for the
  first 30 minutes and one-minute buckets for the whole session in
  `Session.to_dict()`, with the hops, the 0.5.0 loss verdict over the
  running figures, the changes, the gaps and the resets.
- `watch.new_hops()` lists only the hops or addresses a placed route does not
  have yet, so a caller geolocates once and then only what is new.

### Changed
- **Small destination loss is no longer rounded to 0%.** `loss_verdict`'s
  sentence gives one decimal under 10% ("0.5% loss persists to the
  destination"), whole percent above. `loss_pct` is unchanged.

IPv4 only, as the built-in prober. Continuous mode never uses RIPE Atlas.

## [0.5.0] - 2026-10-09

Published 2026-10-09 to PyPI and GitHub Releases.

### Changed
- **An Atlas traceroute costs 60 credits, not 30.** RIPE's traceroute formula,
  10 * N * (int(S/1500) + 1), gives 30 with the defaults, and "a one-off
  measurement result is twice as expensive than a periodic measurement result"
  (<https://atlas.ripe.net/docs/getting-started/credits>). The engine asks for
  one probe, three packets, the default size and a one-off measurement, so
  `atlas.TRACEROUTE_CREDITS` is 60. A test now derives the cost from the
  measurement `create()` sends.
- **`Atlas.balance()` says why a balance is missing (breaking).** It returns
  an `atlas.Balance` instead of `int | None`: state `"ok"` with
  `current_balance` and RIPE's estimated daily income and expenditure;
  `"bad_key"` when RIPE answers 401 (the key is missing, unknown or expired,
  so it cannot schedule a measurement either); `"no_permission"` when RIPE
  answers 403 (a valid key without "credits read"); `"unavailable"` for a
  network failure, a timeout or an unusable answer. The refusals carry RIPE's
  own reason. It never raises. Nothing in the engine called it before.

### Added
- **`geo.loss_verdict()` and a `"loss"` key in `resolve()`'s result.** Only the
  loss measured at the destination counts as the route's loss. Hops marked as
  ICMP rate limiting are listed by number, and a destination that never
  answered gives "unknown", never 0%. The per-hop rule is unchanged and now
  stated in `geo`'s docstring: loss at a hop is rate limiting when the best
  later hop that answered shows less of it, so two rate-limiting routers on
  one path do not hide each other.
- **`Route.loss`**, the same verdict computed from the route's hops, so a
  Route rebuilt from an older export or the history has it too.
  `Route.to_dict()` is unchanged: it is FalconEye's API body and does not
  carry the verdict.
- `Atlas(..., transport=)` for tests.

## [0.4.2] - 2026-10-05

A security fix for 0.4.1. Update from 0.4.1 to this release.

### Security
- **The 2 MB cap on API answers in 0.4.1 could be bypassed.** It counted the
  bytes as they arrived, before decompression, so a compressed answer decoded
  to far more than the cap: 1.31 MB of gzip read as 300 MB through
  `httpclient.client()`. A server that answers with a compressed body could
  exhaust the memory of the process that calls it. Every request now asks for
  an uncompressed answer (`Accept-Encoding: identity`, whatever the caller
  sets), and an answer that arrives compressed anyway is refused before any of
  it is decoded (`httpclient.UnexpectedEncoding`). Uncompressed answers are
  capped at 2 MB as before.

### Changed
- Release path: the tests and the SBOM tool install from hash locks, each
  release file gets a build provenance attestation and the release a CycloneDX
  SBOM, the CLA check runs through GitHub's own `actions/github-script`, and
  every workflow job has only the permissions it needs.

## [0.4.1] - 2026-10-05

Security fixes from a review of the app, the engine and the site. No change to
what a correct trace or a well-formed answer produces.

### Security
- The parser refuses a line longer than 1,000 characters, and its patterns no
  longer backtrack: a 2,000-character banner line took 7 s and a longer one
  minutes, which hung a window or a server that parses pasted text. Every
  pattern now finishes in well under a millisecond on its worst case
  (`MAX_LINE_CHARS`).
- Trace tools are run from the system's own folders only. On Windows,
  `tracert.exe` comes from System32 (found through `GetSystemDirectoryW`); the
  current folder and PATH are no longer searched, so a `tracert.cmd` in the
  working folder is never run. On macOS and Linux the system folders come
  before PATH, and PATH's empty or relative entries are skipped
  (`runner.tool_path`).
- The Windows ICMP API (`iphlpapi.dll`) is loaded from System32 only, not from
  the application's folder.
- The built-in prober accepts only replies to its own probe: an echo reply
  must come from the target with the probe's sequence number, and an ICMP
  error must quote the whole echo request to the target with that sequence
  number. Sequence numbers start at a random value. Forged or stray replies on
  the same network no longer add hops or end a trace early.
- The prober's hop count, probes per hop and wait are clamped to 255, 10 and
  10 s, and Stop and the time limit are checked before every probe.
- No answer from an API is read past 2 MB, whether or not the server says how
  long it is: every HTTP client the engine makes now comes from
  `httpclient.client()`.
- Fields from Hoiho and RIPEstat are checked before they are passed on, also
  when they come from the cache: a country code is two letters, the Hoiho
  ruleset date is a month (YYYY-MM), a prefix is a network, and names are short
  plain text without markup characters (`clean`).
- dnspython 2.6.1 or newer (CVE-2023-29483).

### Changed
- Releases are built from fixed inputs: every GitHub Action is pinned to a
  commit, the release job installs only from `requirements/release.txt` (hashes
  for every package), and the wheel is built without an isolated environment.
  The tests run the same locked install on every push.

## [0.4.0] - 2026-10-05

A minor release, not a patch: `ripe.hourly_bins` can return None for an hour,
`diff.diff_routes` gains `not_reached`, and the route schema gains the parser
value `icmp`. (Prepared as 0.3.1, which was never published.)

### Added
- `probe`: the engine's own ICMP traceroute, the same on Windows, macOS and
  Linux: 30 hops, three probes per hop, one second per reply, every
  responding router listed (BSD-style continuation lines, which the parser
  already reads). No administrator rights: Windows uses the system ICMP API
  (`IcmpSendEcho`, as `tracert` does); macOS and Linux use unprivileged ICMP
  datagram sockets (on Linux only where `net.ipv4.ping_group_range` allows
  them). IPv4 only; an IPv6 target falls back to the system tool.
- `runner`: the built-in prober is the tool `icmp`, first in `auto` wherever
  it can run; `icmp_status()` says why when it cannot. `tracert`,
  `traceroute` and `mtr` stay available.
- `osint.origin_check(route)`: for a trace run where the origin claims to be,
  reports a first public hop under 10 ms whose confident placement the
  origin's RTT bound rejected, with the nearby city to offer as a fix. Never
  changes the origin itself.
- `RipeStat.errors` and `Baseline.error`: why the last call failed, for the
  caller to show instead of an empty section.

### Fixed (from testing on Windows with real routers, 4 Oct 2026)
- Built-in prober RTTs on Windows: every probe is now timed with the same
  high-resolution clock as on macOS and Linux. The Windows API's own round
  trip time is whole milliseconds and was used from 10 ms up, so every hop
  past the access network read as a whole millisecond.
- A trace from the built-in prober is labelled "Built-in ICMP prober"
  (parser `icmp`; the route schema gains that value) on every platform,
  instead of "Unix traceroute".
- The live view (`ProgressiveTrace.snapshot`) names the built-in prober from
  the trace header before the first hop has parsed, instead of falling back
  to "Unix traceroute" until it does.
- The per-platform probe test (a real trace with the built-in prober on
  Windows, macOS and Linux runners) expects the parser name `icmp`; it still
  asserted `traceroute` and failed on all three although the traces succeeded.
- `ripe.ris_agreement` says where the disagreeing RIS paths leave the
  trace's path (`diverge`: where they join it, through which AS, how many),
  also when some paths agree; `differs_at` was only set when none did.
- `RipeStat.bgp_update_window` returns how far RIPEstat's data reaches
  (`until`, from its `query_endtime`; its route-collector data runs a few
  hours behind), and `ripe.hourly_bins(..., until=)` marks the hours after it
  as not yet available (None) instead of 0.
- The Hoiho ruleset date is always reported: answers served from the cache
  carry the date they were made with, and when nothing records one, the API
  is asked with a placeholder name that carries no user data.

### Changed
- RIPEstat: `looking-glass` and `bgp-updates` wait up to 20 s and
  `routing-status` up to 15 s, each with one retry; the other endpoints keep
  8 s and no retry.
- `ripe.ris_agreement` compares from the first AS any RIS path carries (the
  user's own access network never appears in RIS paths), while at least two
  ASNs remain; the result says where it started (`compared_from`).
- The neighbour check judges a run of consecutive database placements at
  the same point as one detour (a router that answered twice).
- `diff.diff_routes`: whether the destination answered is judged by the
  target address, so places a run did not reach are reported as "not
  reached" (`not_reached`), not as gone; the first hops placed at the origin
  (the access network) are left out of the comparison.
- DB-IP Lite City names drop district suffixes ("Frankfurt am Main
  (Innenstadt I)" becomes "Frankfurt am Main").

### Unchanged
- `analyse`, `resolve` and the route schema behave as in 0.3.0 apart from the
  new parser value `icmp` and the neighbour-check and DB-IP name changes above.

## [0.3.0] - 2026-10-04

### Added
- `offline`: DB-IP Lite City and DB-IP Lite ASN readers (CC BY 4.0, "IP
  Geolocation by DB-IP"), behind the optional `offline` extra (`maxminddb`).
  The engine never downloads them; the caller passes the files.
- `default_sources(offline_city=...)`: the City file answers first and the
  online IP database is asked only for what it missed. Every IP database
  placement now says which tier answered (`ip_provider`: `dbip` or
  `ripestat`); the route schema gains that field.
- `osint`: RTT step classification with caller-set thresholds (15 ms quiet,
  60 ms hot by default), AS path, countries transited with sensitive and
  country-only flags, and a "likely anycast" note.
- `ripe`: one RIPEstat client (network info, RIR, RPKI, RIS paths,
  visibility, BGP updates, AS overview, neighbours, abuse contacts) with
  rate limiting, caching, `sourceapp`, a hard timeout per call, and None for
  any failure; plus RIS agreement and the 48 hour update timeline.
- `baseline`: typical latency between two countries from RIPE Atlas anchor
  mesh measurements (public, no key, no credits); only country codes and the
  anchor name are sent.
- `atlas.Atlas.history`: the user's own earlier traceroutes to a target.
- `diff`: compare two routes by place, not hop number, with a written summary;
  a run that ends in silence is not reported as lost hops.
- `ixp`: exchange point labelling, off and shipped without data until a
  source the engine may redistribute exists.

### Changed
- Neighbour check: an IP database placement between two placed hops in one
  area is rejected when its minimum RTT rose too little to pay for the
  detour. Found comparing DB-IP with RIPEstat on the bundled traces: DB-IP
  places heise's hop 12 in Chicago, between two Frankfurt hops, with an RTT
  rise of 46 ms against the 70 ms the round trip needs. Hostname placements
  are not checked this way. Runs in both `resolve` and the progressive path.

### Unchanged
- `analyse` and the existing route fields keep their meaning.

## [0.2.2] - 2026-10-04

### Changed

- Comments and examples no longer quote the maintainer's home network: the
  router name, LAN and carrier-NAT addresses and the ISP's first hops are
  documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  with generic names. No code changes; behaviour is identical to 0.2.1.

## [0.2.1] - 2026-10-03

### Added

- `sourceapp` on every RIPEstat call (`geo.ip_geolocate`, `whereami.locate_me`,
  `whereami.public_ip`, `whereami.asn_of`): RIPEstat asks regular users to
  identify their application with it. Optional; nothing changes when it is not
  passed.

## [0.2.0] - 2026-10-03

First release as its own package, `routemap-engine` (import `routemap_engine`),
split out of the Route Map desktop app's repository with its history.

### Added

- Progressive placement: `progressive.ProgressiveTrace` places each hop as its
  line of tool output arrives, with the full source order and the RTT bound,
  and leaves only ECMP cleanup and the path-wide annotations to the end. Its
  final route is identical to a one-shot `analyse()` of the same text.
- Hops placed only to country level (the IP database had no city) carry
  `"precision": "country"`, so no renderer draws a country centroid as a city.

### Changed

- The import name is `routemap_engine` (was `routemap.engine`).

## [0.1.0-beta.1] and [0.1.0.dev1]

Tagged in the combined repository before the split; see the history. 0.1.0.dev1
is the extraction from FalconEye v3.35.3 that FalconEye v3.36.0 pinned.
