# Route Map data files

Two bundled tables. Neither is queried over the network at runtime: the point of
both is that the engine can answer "where is this" without telling anyone else
what it is asking about.

## `cities.tsv`

GeoNames `cities15000` (every populated place above 15,000 people), trimmed to
seven columns and sorted by population descending, plus four smaller places
where OVHcloud has data centres, from the same GeoNames dumps and licence:
Gravelines (3014816), Beauharnois (5896495) and Erith (2649937) from
`cities500.zip`, and Vint Hill Park (4791235) from `US.zip`. GeoNames has no
populated place named Vint Hill; its park record is the place OVH names.
34,156 rows.

Used for the origin picker's city search and as the one source of city
coordinates in the feature, including for `site_codes.tsv`.

**Licence: Creative Commons Attribution 4.0.** From
<https://download.geonames.org/export/dump/readme.txt>, checked 2026-10-03:
"This work is licensed under a Creative Commons Attribution 4.0 License, see
https://creativecommons.org/licenses/by/4.0/". Attribution is carried in the
file header, in `routemap_engine/cities.py` (`ATTRIBUTION`, which every user
interface shows next to the origin picker), and in the repository README. If you
remove it from one of those, the others still satisfy the licence; do not remove
it from all of them.

Columns: `name`, `asciiname`, `cc`, `admin1`, `lat`, `lon`, `population`.
`asciiname` is empty when it equals `name`; `admin1` is empty unless the
country uses an alphabetic subdivision code (so US and CA have one, PH does
not).

To refresh it, download `cities15000.zip` from the URL above and re-run the
trimming step documented in FalconEye's CHANGELOG entry for v3.35.0, where
this file was first built.

## `site_codes.tsv`

The site code a carrier embeds in its own router hostnames, mapped to the city
that carrier says the site is in. This is the `site-code` geolocation source.

**Generated.** Do not hand-edit it. Run:

```bash
python -m routemap_engine.sitegen --dry-run   # show what would change
python -m routemap_engine.sitegen             # rewrite the table
```

Columns: `carrier`, `code`, `city`, `cc`, `lat`, `lon`, `source_ref`. The
`source_ref` ties each row to a source named in the file's own header.

### Why this table is narrow on purpose

A three-letter string in a hostname is not evidence. `lax` appears inside
"relaxed"; customer hostnames are full of city-ish fragments that mean nothing.
So the rule is never "this hostname contains a code", it is "this carrier, in
its own backbone namespace, names this site this way":

- A pattern applies only under that carrier's backbone zones, listed in
  `CARRIERS` in `routemap_engine/sitecodes.py`.
- Customer-facing zones are excluded there. A customer interconnect is named
  after the customer, not the site: `plusline-ic-323934.ip.twelve99-cust.net`
  is Plus.line's interconnect, and reading `plusline` as a site code would be
  wrong.
- A code the carrier uses for two different cities is dropped at build time
  rather than guessed at. Arelion's `ewr` covers both New York City and
  Piscataway facilities, so there is no `ewr` row.
- A city the bundled GeoNames table cannot resolve is dropped and reported, not
  approximated. Arelion's Bettembourg PoP has no row for that reason.

A site-code location is still only a claim. It goes through the same RTT
physics bound as every other source in `routemap_engine/geo.py`: if the hostname
says Hong Kong and the round trip cannot reach Hong Kong, the hop is not placed
in Hong Kong.

### The carriers in it

- **Arelion (AS1299, Twelve99)**: the router list its looking glass embeds,
  <https://lg.twelve99.net/>, router short name to "City (facility)".
- **OVHcloud (AS16276)**: OVH's network weathermap,
  <http://weathermap.ovh.net/> (the https address does not answer). Its menu
  names every PoP and data centre with its city (`pop_mrs` "Marseille",
  `core_sxb1-sbg` "Strasbourg", `pop_ava1` "Milan AVA1"), and each map draws
  that site's routers by name. A map also draws neighbouring routers, so a
  router counts for a site only when its name starts with that site's code
  (first or second part, `mil-ava1-sbb1-8k` on "Milan AVA1"); maps labelled
  only "AZ n" are skipped. The site code is the router name's first part. A
  name family that is the main family of two cities' maps names no site
  (`nyc` is OVH's Newark and its New York; `sjo` was also left out this way).
  Hostnames are read only under OVH zones seen in a real trace: `.fr.eu`,
  `.it.eu`, `.sgp.asia` (RIPE Atlas measurement 221303797), `.uk.eu`,
  `.qc.ca`, `.wa.us`, `.ny.us` (traces to OVH's speed-test hosts, 11 Oct
  2026); another zone is added when it is seen. Gravelines, Beauharnois, Erith and Vint Hill are in
  `cities.tsv` for this (see above); Limburg is GeoNames' "Limburg an der
  Lahn". Refresh one carrier without touching the others:
  `python -m routemap_engine.sitegen --only ovh`.

### Adding a carrier

1. Find the carrier's **own published** router list: a looking glass that names
   its nodes, an operator network page, PeeringDB facility data, or equivalent.
   A list you inferred from traceroutes you have seen is not a source. If you
   cannot point at a published mapping, the carrier does not go in the table.
2. Add an entry to `CARRIERS` in `routemap_engine/sitegen.py` with a `fetch()`
   returning `{router_name: "City (facility)"}`, a `code_of()` that turns a
   router name into its site code, and `source_ref` / `source_url` /
   `source_kind` describing where it came from.
3. Add the matching entry to `CARRIERS` in `routemap_engine/sitecodes.py`, naming
   the backbone `suffixes` and any customer `exclude` zones.
4. Run the generator. Resolve or accept every line it prints under
   "NOT INCLUDED" before trusting the result.
5. Add a test case to `tests/test_sitecodes.py`: at least one
   hostname that must resolve and one that must not.

Current sources:

| `source_ref` | Carrier | Source |
|---|---|---|
| `arelion-lg` | Arelion (AS1299, Twelve99) | Operator looking glass router list, <https://lg.twelve99.net/> |
