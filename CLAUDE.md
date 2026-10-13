# routemap-engine: working rules

Public, AGPL-3.0. FalconEye and the Route Map desktop app depend on it.

- No em dashes anywhere; `tests/test_no_em_dashes.py` enforces it.
- No Qt, no GUI, no packaging, no secrets, nothing from the desktop app.
- No global mutable configuration: sources, caches and User-Agents are passed in.
- User-supplied values in logs go through `logsafe.tag()`; a test sweeps for it.
- Run `TZ='Asia/Manila' date` before any date in CHANGELOG or release notes.
- Releases: bump `routemap_engine/__about__.py`, CHANGELOG entry, annotated tag
  `vX.Y.Z`; the release workflow publishes to PyPI by trusted publishing.

## Standing orders (all my repos)

Effective for every session, in addition to the rules above.

- Every change ships with `upgrade.sh`, `provision.sh` and all documentation
  updated in the same release: README, the runbook and `docs/`, `.env.example`,
  CHANGELOG, the in-app privacy and help text, the MCP docs, and the GitHub release
  notes (whichever of these the repo has). The report lists what was changed. A
  release that misses any of these is incomplete and must not be cut.
- Never install anything by hand on a server to make a test pass. If it is not
  installed by the scripts, it does not exist.
- Never change SSH, sshd or SSH firewall settings on any server unless the owner
  explicitly asks for that specific change.
- One brief, one release. No follow-up fix releases.
- No em dashes anywhere. Use `vi` for any file-editing command. Review pages and
  screenshots are private claude.ai artifacts only, never public. Briefs,
  screenshots and review pages never go into git.

- No em dashes or en dashes anywhere, including your own reports, chat replies and
  commit messages. Use a comma, a colon, parentheses or a plain hyphen instead.
  Check every reply before sending.
