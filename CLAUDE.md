# routemap-engine: working rules

Public, AGPL-3.0. FalconEye and the Route Map desktop app depend on it.

- No em dashes anywhere; `tests/test_no_em_dashes.py` enforces it.
- No Qt, no GUI, no packaging, no secrets, nothing from the desktop app.
- No global mutable configuration: sources, caches and User-Agents are passed in.
- User-supplied values in logs go through `logsafe.tag()`; a test sweeps for it.
- Run `TZ='Asia/Manila' date` before any date in CHANGELOG or release notes.
- Releases: bump `routemap_engine/__about__.py`, CHANGELOG entry, annotated tag
  `vX.Y.Z`; the release workflow publishes to PyPI by trusted publishing.
