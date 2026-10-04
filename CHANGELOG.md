# Changelog

Keep a Changelog format; this project uses Semantic Versioning.

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
