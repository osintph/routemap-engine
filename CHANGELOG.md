# Changelog

Keep a Changelog format; this project uses Semantic Versioning.

## [0.8.2] - 2026-10-29

### Fixed

- **Watch kept a healthy cycle out when the system clock stepped**
  ([#24](https://github.com/osintph/routemap-engine/issues/24), reported on
  Bluesky by sasame-mcp.bsky.social). A cycle that overran its budget on the
  wall clock was recorded as a sleep gap, so an NTP or other time sync step,
  or a manual change of the clock, with probing running normally dropped that
  cycle from the statistics. On Linux and macOS `time.monotonic()` stops
  during suspend, so the wall clock was the only sign of a sleep there. A
  cycle is now a gap only when it overruns on a clock that keeps counting
  through suspend (`clock_gettime(CLOCK_BOOTTIME)` on Linux,
  `clock_gettime(CLOCK_MONOTONIC)` on macOS, `time.monotonic()` on Windows,
  where it already counts sleep) or on the monotonic clock (a stopped
  process). Placement and the map were never affected.
- The README said Watch was IPv4 only; it has run over IPv6 too since 0.7.0.

### Added

- **`Session.clock_steps`**, and `clock_steps` in `Session.to_dict()`: one
  entry per cycle in which the wall clock moved at least 1 s more or less
  than the suspend-inclusive clock, `{"at": "2026-10-29T06:02:07Z",
  "seconds": 5.0}` (negative when the clock was set back). The cycle is kept.
  No other key of the JSON changes.
- **`Session.clock_fallback`**, and `clock_fallback` in the JSON (null, or
  why): where the suspend-inclusive clock is missing, or a read of it fails
  (at the start or later), the session falls back to the old two-clock rule
  instead of stopping, says why once ("the clock that counts through suspend
  could not be read (OSError 22)") and logs it once. A clock change can then
  show as a gap, as before 0.8.2.
- `Watch(..., boot=...)` injects the suspend-inclusive clock like `wall` and
  `mono`; `watch.suspend_clock()` returns the platform's. A caller that
  injects `wall` and `mono` without `boot` keeps the old rule, silently.
- Gaps, path changes and clock steps in a live session carry their position on
  the plot (`t_from`/`t_to`, `t`), and the live plot samples are placed by
  elapsed time on the suspend-inclusive clock, so a kept step leaves no blank
  stretch and no overlap. The exported sample times stay on the wall clock,
  and the JSON leaves the plot positions out.

## [0.8.1] - 2026-10-26

Published 2026-10-26 to PyPI and GitHub Releases.

### Fixed

- **Paths on Windows when a probe's port is taken.** Each flow of the
  Windows TCP prober had a fixed source port, 40000 plus a random base plus
  the flow (40000 to 50009), and Windows refuses a bind to a port another
  program holds with exclusive use, with WSAEACCES (10013); 69 of those
  ports were held on a CI runner. Such a flow never sent a probe, its paths
  were missing, and 20 refusals in a row ended the run with "this computer
  refused to send probes". A flow's port is now the system's (a bind to
  port 0), kept for its later probes; a kept port refused later (another
  program took it) is replaced once and the flow is probed again from
  TTL 1, so no path mixes the answers of two source ports. A port range
  reserved with `netsh int ipv4 add excludedportrange` was not the cause: a
  bind inside one was not refused.
- **A probe that never leaves says why.** `Discovery.local_failure_reasons`
  counts those probes by error name and code (`{"WSAEACCES 10013": 20}`; no
  address or port), the stop text names the commonest ("stopped: this
  computer refused to send probes (WSAEACCES 10013)"), and
  `flows_restarted` counts the flows started over. Both are in the JSON
  schema and in a remote agent's answer. The error was discarded before.
- The DNS timing tests' local server binds TCP to a port the system assigns
  (the number the system gave its UDP socket could be held over TCP).

### Changed

- CI and release tooling: certifi 2026.10.19
  ([GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2))
  and filelock 4.2.1
  ([GHSA-v4x8-3wr5-3wq8](https://github.com/advisories/GHSA-v4x8-3wr5-3wq8),
  [GHSA-9vhv-jxww-xfm5](https://github.com/advisories/GHSA-9vhv-jxww-xfm5),
  [GHSA-567q-5qvw-pf92](https://github.com/advisories/GHSA-567q-5qvw-pf92))
  in the release, test and SBOM locks; actions/upload-artifact 7.0.2 and
  download-artifact 8.0.2, pinned by commit. The wheel's own requirements
  are unchanged.
- Windows CI prints the runner's reserved ranges and the ports in use
  where 0.8.0 fixed its flows, checks that a port held with exclusive use
  refuses a bind with WSAEACCES, reserves a range and checks the system
  never hands out a port in it, and runs Paths with it in place: every
  probe sent, the target reached.

## [0.8.0] - 2026-10-26

Published 2026-10-26 to PyPI and GitHub Releases.

### Added

- **DNS response timing** (`routemap_engine.dnstime`): the target's A and
  AAAA lookups timed through the system resolver and through each resolver
  the caller names (IP addresses only, none by default), with the response
  code, the AA bit and the TTL where the resolver states them. 2 s per query,
  5 s for the step; a resolver that does not answer contributes nothing.
- **One resolution per trace.** `dnstime.resolve_target` resolves the target
  once; `TraceOptions(address=...)` and `multipath.discover(address=...)`
  trace that address, and the system tools (traceroute, tracert, mtr) are
  given the address instead of the name, so the address shown is the address
  traced. `TraceResult.address` and `route.resolved` record it.
- **Port tests** (`routemap_engine.ports`): one TCP connection attempt per
  port to the traced address, at most 32 ports, 4 at a time; open with
  connect time, closed (reset), filtered (no answer or unreachable); TLS
  handshake time for 443 and the ports marked. Ranges are refused.
- **Remote agents** (`routemap_engine.agent`, the `routemap-engine` command):
  `routemap-engine agent 1 hello|trace|paths|ports` measures on the machine
  it runs on and prints JSON lines; the client side builds a validated,
  shell-quoted command and the ssh argument list (`-T`, `BatchMode=yes`,
  `ConnectTimeout`, `--` before the destination), reads the answer within
  8 MB in all and 1 MB per line and checks every field. The agent's place
  can be looked up on the server; its address is never printed.
  `agent.mask_first_hops` hides an agent trace's first hops in the server
  provider's network (no address, name or place): the private hops, then the
  public hops in the AS of the first public hop, never fewer than the first
  two public hops, never the target. `python -m routemap_engine`
  works too.
- `Discovery.to_wire` and `from_wire`: a path discovery measured elsewhere,
  rebuilt with every field checked.
- `route.schema.json`: `resolved`, `dns`, `ports`, hop `masked`, and the new
  Paths fields below.
- Classifiers for Python 3.11, 3.12 and 3.13.
- **Anycast destinations are placed.** When the destination answered faster
  than its registered location allows from the origin, it is placed at the
  largest city the RTT reaches, counted from the last placed hop before it
  with only the RTT added past that hop (from Manila the whole 8 ms reaches
  Shantou; past a Pasig hop at 7.9 ms it reaches Quezon City). The source is
  the new `anycast`, the reason "likely anycast, served from near X
  (registered in Y, N km away, but answered in M ms, D ms past hop H (P))"
  (`geo.place_anycast`). Only the destination: a
  router that answers too fast keeps "not placed". `analyse(destination=...)`
  and `ProgressiveTrace.destination` name the address traced where the text
  does not (mtr); a traceroute or tracert banner's address is used
  otherwise. bbc.com's Fastly address answered in 5 to 10 ms from Manila,
  is registered in Montreal and was left unplaced.
- **Hops inferred from their neighbours.** A hop no source places (no
  hostname rule, no database place the RTT allows), between two hops placed
  by a source within 50 km of each other, is placed there with the new
  source `neighbours` and a reason starting "inferred from neighbours"
  (`geo.place_by_neighbours`). Its own RTT must allow the place; a router
  that answers at several hops in a row is judged as one; an inferred hop
  is never a neighbour for another; and, one router one place, the place
  carries to the router's other rows in the run. 62.115.153.153
  (plusline-ic, Arelion's link to Plus.line, no site code, DB-IP's Chicago
  ruled out) is now placed in Frankfurt between two Frankfurt hops.

### Changed

- **CI traces nothing live.** The macOS probe job now probes loopback, as
  the Windows job does; it traced heise.de from the runner before.

- **Paths stop after 5 silent hops** (was 3), scamper trace's and RIPE
  Atlas's default.
- **Every path is asked at full TTL**, reached or not: after a silent stop
  the target attempts still run, and a path whose target answers only them
  is reached at `final_hop`, the hop after the last one sent, with its
  silent stretch in `silent` and the hop annotated "answered the final
  full-TTL probe" (as RIPE Atlas sends a last probe with TTL 255). "Not
  reached" now means the target was asked and did not answer.
- **A path ends at its target's hop.** A hop where only the target answers
  adds no flows, and a flow silent where other flows of its path reached the
  target is asked there again (twice at most) and never deeper. A Mac run to
  heise.de, complete at TTL 15, had gone on to TTL 18 and stopped at the
  probe cap (1,350 probes, 125 s); the same route now completes in about 450
  probes.
- **Target attempts are at least 1 s apart** (`ping_interval`, ping's
  default interval), so a short stretch of loss at the target cannot take
  most of the ten. They went out as fast as the target answered before.
- **The Paths trace text header** names the probe sent ("TCP SYN to port
  443" or "ICMP echo"), the configured hop limit and why the discovery
  ended (`stop_text`: "stopped after 5 silent hops (3 to 7)"). It said "ICMP
  echo" and "2 hops max" for a TCP run that stopped on silence.

### Fixed

- **Networks silent to TCP probes are named.** Over TCP, one ICMP echo per
  hop where no TCP probe was answered, within the budget and the rate; when
  the stretch that ended the discovery answers ICMP, `tcp_silent_from` says
  from which hop (bbc.com over Converge, 0.4.0-beta.2).
- **A target that answers ICMP for itself is not blamed on the routers.**
  `tcp_silent_by` says who answered the ICMP check where TCP went silent:
  "router" (the network does not answer TCP probes) or "target" (the target
  answered ICMP there and its TCP service only at full TTL; something in
  front of it, a firewall or load balancer, is the likely reading). ODIN,
  heise.de: TCP silent at 15 to 19, every ICMP check answered by the target.
- **Port tests on Windows**: Windows' own time-out (WSAETIMEDOUT, 10060) is
  "filtered", not "error". Windows sends one SYN, as before: with
  retransmissions on it also retries after a reset, and a closed port no
  longer read "closed" within the wait. It then gives up after about 1 s, so
  the reason says how long it really waited and `wait_used` gives the
  longest such wait.
- **An empty system AAAA row no longer claims the record is missing**:
  "system resolver returned no IPv6 address (this computer may have no
  IPv6)", and likewise for IPv4.
- **Routers at a per-packet hop keep their place.** They are on no path row
  and their hop's main row has several routers, so nothing placed them
  (62.115.132.229 at hop 11 of the 12 Oct ODIN run, placed in Frankfurt by
  every earlier run). Each is now placed on its own (`paths.per_packet`).
- **The schema knows the Paths full-TTL annotation.** "answered the final
  full-TTL probe" was missing from `route.schema.json` (it listed only
  Atlas's "answered the final TTL 255 probe"), so a Paths export with a
  full-TTL answer did not validate.
- **A row placed by a hostname shows that hostname's router.** At a hop
  several routers answered, the row kept the hop's first address whatever
  name placed it, so it could read "62.115.153.153, ffm-b16-link" (another
  router's name), and that address's own rejection then cleared the row.
  `Hop.named` keeps each hostname with the address it was printed or
  resolved with; a hostname placement takes that address, an IP database
  placement takes that address's own name (or none), and such a row counts
  as evidence for its address (ODIN, heise.de, 26 Oct 2026: hop 11 placed
  in Frankfurt by ffm-b16-link's site code, then shown unplaced).

## [0.7.1] - 2026-10-12

Published 2026-10-12 to PyPI and GitHub Releases.

### Fixed

Path discovery, from the first real run on Windows (ODIN, 11 Oct 2026):

- **Paths differ only where two flows got answers from different
  addresses.** A flow whose target answer came hops late, or a silent hop,
  no longer makes a path of its own; the progress count uses the same rule.
- **One address, one placement in a run.** Path rows get the neighbour
  check the main rows get, and a placement any row rules out is ruled out
  for all (62.115.153.153 was Chicago on some rows, Frankfurt or nothing on
  others).
- **A flow ends at the target once.** When the target answers only after
  silent hops past a flow's last router, that hop is probed again to settle
  where the target is.
- **Within the rate caps, nothing waits in line.** The TCP prober gives up a
  probe when the discoverer does (a flow's next probe waited up to 3 s
  before), a batch sends whichever flow is free, new flows are probed at all
  earlier hops in one round, and the path pings go round-robin. The ODIN
  replay: 1,210 probes in 110 s; 0.7.0 took 384 s for 1,178.
- **A TCP target's quick-repeat limit is not path loss.** heise.de ignored a
  second connection attempt from one source port 0.25 s after the first
  completed (9 of 9) and answered at 1 s (10 of 10). A TCP flow now waits
  1.5 s after it reached the target, and pings rotate over a path's flows.
- A probe this machine failed to send is counted in `local_failures`, not as
  loss.
- A run that reaches the probe cap still gives every path its ten target
  attempts: the discovery stops early enough to leave them their share, and
  the total, target attempts included, never passes the cap. `budget` and
  `discovery_probes` record the cap and the discovery's own share.
- A path's hops get their AS number from the offline database (they have
  one `address`, which the lookup did not read).
- A Trace hop the next placed hop rules out is not placed (the detour it
  implies must show in the next hop's RTT); one address, one placement, in
  Trace too; a hop several routers answered is placed by its own router.
- Windows: SYN retransmissions are switched off with `SIO_TCP_INITIAL_RTO`
  (`TCP_NOSYNRETRIES` did not stop them), and an answer later than the probe
  wait is not timed.

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
