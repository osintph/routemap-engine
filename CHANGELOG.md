# Changelog

Keep a Changelog format; this project uses Semantic Versioning.

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
