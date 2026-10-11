"""The carrier site-code table: narrow on purpose.

The danger with reading location out of a hostname is over-reach. A three
letter string is not evidence: "lax" is inside "relaxed", and customer
hostnames are full of city-ish fragments that mean nothing. So most of this
file is about what must NOT match.

See routemap_engine/data/README.md for how to add a carrier.
"""
import pathlib
import re

import pytest

from routemap_engine import sitecodes

DATA = pathlib.Path(sitecodes.DATA_FILE)


# ---------- the table itself ----------

def test_the_table_ships_and_is_not_empty():
    assert DATA.exists(), f"{DATA} is missing; run python -m routemap_engine.sitegen"
    assert sitecodes.count() > 50


def test_every_row_is_well_formed_and_cites_a_source():
    seen = set()
    for line in DATA.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split("\t")
        assert len(parts) == 7, f"malformed row: {line!r}"
        carrier, code, city, cc, lat, lon, source_ref = parts
        assert carrier in sitecodes.CARRIERS, f"row for unknown carrier {carrier!r}"
        # Letters, then letters or digits (OVH's metro codes: "sin1", "bom1"),
        # the same rule sitecodes.lookup applies.
        assert re.fullmatch(r"[a-z][a-z0-9]{1,5}", code), f"implausible site code {code!r}"
        assert city.strip(), f"row {code!r} has no city"
        assert re.fullmatch(r"[A-Z]{2}", cc), f"row {code!r} has no country code"
        assert -90 <= float(lat) <= 90 and -180 <= float(lon) <= 180
        assert source_ref.strip(), f"row {code!r} cites no source"
        assert (carrier, code) not in seen, f"duplicate row for {carrier}/{code}"
        seen.add((carrier, code))


def test_the_header_names_the_source_of_every_source_ref():
    header = "\n".join(l for l in DATA.read_text(encoding="utf-8").splitlines()
                       if l.startswith("#"))
    refs = {line.split("\t")[6] for line in DATA.read_text(encoding="utf-8").splitlines()
            if not line.startswith("#") and line.strip()}
    for ref in refs:
        assert ref in header, (
            f"rows cite source_ref {ref!r} but the file header does not say "
            f"where that came from. Every claim in this table has to be traceable.")


def test_a_carrier_in_the_table_is_declared_in_the_module():
    """The data file and the matching rules cannot drift apart."""
    carriers = {line.split("\t")[0] for line in DATA.read_text(encoding="utf-8").splitlines()
                if not line.startswith("#") and line.strip()}
    assert carriers <= set(sitecodes.CARRIERS)
    for carrier, spec in sitecodes.CARRIERS.items():
        assert spec["suffixes"], f"{carrier} declares no backbone zone"


# ---------- what must resolve ----------

@pytest.mark.parametrize("hostname,city", [
    ("hnk-b4-link.ip.twelve99.net", "Hong Kong"),
    ("hnk-b3-link.ip.twelve99.net", "Hong Kong"),
    ("sng-b6-link.ip.twelve99.net", "Singapore"),
    ("mei-b6-link.ip.twelve99.net", "Marseille"),
    ("prs-bb2-link.ip.twelve99.net", "Paris"),
    ("ffm-bb2-link.ip.twelve99.net", "Frankfurt"),
    ("ffm-b16-link.ip.twelve99.net", "Frankfurt"),
])
def test_arelion_backbone_hostnames_resolve(hostname, city):
    """The five legs CAIDA Hoiho's 2024-08 ruleset cannot place."""
    record = sitecodes.lookup(hostname)
    assert record is not None, f"{hostname} did not resolve"
    assert city in record["place"]
    assert record["source_ref"], "the match does not say where the claim came from"


def test_case_and_trailing_dot_do_not_matter():
    assert sitecodes.lookup("HNK-B4-Link.IP.Twelve99.NET.") is not None


@pytest.mark.parametrize("hostname,city", [
    # OVH's backbone, as reverse DNS named it in RIPE Atlas measurement
    # 221303797; the cities are OVH's own weathermap labels for these sites.
    ("be101.sbg-g1-nc5.fr.eu", "Strasbourg"),
    ("be102.mil-ava1-sbb2-nc5.it.eu", "Milan"),
    ("mil-ava1-sbb1-8k.it.eu", "Milan"),
    ("be102.mrs-mrs1-sbb1-8k.fr.eu", "Marseille"),
    ("sin1-sgcs2-g1-nc5.sgp.asia", "Singapore"),
    # OVH's large data centres, as reverse DNS named their routers in traces
    # to OVH's speed-test hosts there (11 Oct 2026).
    ("be102.lil2-gra1-sbb1-nc5.fr.eu", "Gravelines"),
    ("be101.lon1-eri1-g1-nc5.uk.eu", "Erith"),
    ("be102.bhs-g1-nc5.qc.ca", "Beauharnois"),
    ("vl1332.was1-vin1-g1-nc5.wa.us", "Vint Hill"),
    # The IPv6 release check (vps-c117642c to heise.de, 11 Oct 2026), hop 9.
    ("be104.fra-fra15-sbb2-8k.de.eu", "Frankfurt"),
    # A trace to OVH's Mumbai speed-test host, through Hillsboro.
    ("pdx1-hil1-vac1-a75-1-firewall.ovh.us", "Hillsboro"),
])
def test_ovh_backbone_hostnames_resolve(hostname, city):
    record = sitecodes.lookup(hostname)
    assert record is not None and record["place"].startswith(city), record
    assert record["carrier"] == "OVHcloud (AS16276)" and record["source_ref"] == "ovh-weathermap"


@pytest.mark.parametrize("hostname", [
    "sbg-g1-nc5.example.com",          # OVH's naming outside OVH's zones proves nothing
    "relaxed.fr.eu",                   # no router name shape
    "www.fr.eu",
    "foo-bar1.fr.eu",                  # not a site OVH publishes
    "be101.mad-x-sbb1-8k.es.eu",       # a zone not seen in a real trace yet
    # "nyc" is OVH's name family for both Newark (nyc-ny1) and New York
    # (nyc-ny9): it names no site.
    "nyc-ny9-sbb1-8k.ny.us",
    "nyc-ny1-sbb1-8k.ny.us",
    # OVH customer and VPS names carry no site code.
    "vks19366.ip-103-5-15.asia",
    "ns1008304.ip-135-148-100.us",
    "foo-bar.ovh.us",
    "be101.lon1-eri1-g1-nc5.uk.eu.example.com",
    "be102.bhs-g1-nc5.qc.ca.example.net",
])
def test_ovh_names_outside_its_rule_do_not_resolve(hostname):
    assert sitecodes.lookup(hostname) is None, hostname


# ---------- what must NOT resolve ----------

@pytest.mark.parametrize("hostname", [
    # Customer interconnect: named for the customer, not the site. Reading
    # "plusline" as a site code is the exact over-reach this table avoids.
    "plusline-ic-323934.ip.twelve99-cust.net",
    "man-ic-123456.ip.twelve99-cust.net",
    # Other carriers: their naming scheme is not Arelion's.
    "if-bundle-2-2.qcore2.sqn-sanjose.as6453.net",
    "te2-2.c301.f.de.plusline.net",
    "edge-46.isp.example.net",
    # A city-ish fragment in an unrelated zone proves nothing.
    "lax-something.example.com",
    "hnk-b4-link.example.com",
    # "relaxed" contains "lax". It is not a site code.
    "relaxed.ip.twelve99.net",
    # Not a code at all.
    "www.twelve99.net",
    "",
])
def test_these_must_never_be_read_as_a_site_code(hostname):
    assert sitecodes.lookup(hostname) is None, (
        f"{hostname!r} was read as a site code; the table is over-reaching")


def test_an_ambiguous_code_is_absent_rather_than_guessed():
    """Arelion uses 'ewr' for both New York City and Piscataway facilities.

    The generator drops a code that maps to two cities instead of picking one.
    """
    assert ("arelion", "ewr") not in sitecodes.table()
    assert sitecodes.lookup("ewr-b13-link.ip.twelve99.net") is None
