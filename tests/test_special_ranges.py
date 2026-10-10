"""Nothing that is not globally reachable is ever looked up, for IPv6 as well
as IPv4: every row of the IANA special-purpose registries, not a few examples.

The registries are vendored in tests/fixtures/iana/ as IANA publishes them
(CSV, retrieved 2026-10-10 from
https://www.iana.org/assignments/iana-ipv6-special-registry/ and
https://www.iana.org/assignments/iana-ipv4-special-registry/).

For every row the test samples the first, last and middle address and expects
the answer of the most specific row containing it (2001::/23 is not reachable,
2001:1::1/128 inside it is). "N/A" (Teredo, 6to4: another host's address
inside) and a blank (deprecated blocks) count as not reachable. One engine
choice overrides the registry: the NAT64 well-known prefix is globally
reachable, but its addresses stand for an IPv4 host behind a translator, so
the engine never looks them up (since 0.1).

The answer must not depend on the Python version: the stdlib's tables changed
in 3.12.4 and 3.13, and the engine supports 3.11 to 3.13.
"""
import csv
import ipaddress
import pathlib

import pytest

from routemap_engine.netaddr import is_private_ip

IANA = pathlib.Path(__file__).parent / "fixtures" / "iana"
OVERRIDES = {"64:ff9b::/96": False}
CONTROLS = [("2a02:2e0::/32", True), ("2001:4860::/32", True), ("ff00::/8", False),
            ("194.232.104.0/24", True), ("1.1.1.0/24", True), ("224.0.0.0/4", False)]


def _rows():
    rows = []
    for name in ("iana-ipv6-special-registry-1.csv", "iana-ipv4-special-registry-1.csv"):
        with open(IANA / name, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                reachable = row["Globally Reachable"].split("[")[0].strip() == "True"
                for block in row["Address Block"].split("[")[0].split(","):
                    block = block.strip()
                    rows.append((block, OVERRIDES.get(block, reachable)))
    return rows


ROWS = _rows()
NETS = [(ipaddress.ip_network(b), r) for b, r in ROWS + CONTROLS]


def _expected(addr):
    ip = ipaddress.ip_address(addr)
    best = max((n for n in NETS if n[0].version == ip.version and ip in n[0]), key=lambda n: n[0].prefixlen)
    return best[1]


def _samples(block):
    net = ipaddress.ip_network(block)
    first, last = int(net.network_address), int(net.broadcast_address)
    return sorted({str(ipaddress.ip_address(v)) for v in (first, first + (last - first) // 2, last)})


def test_the_vendored_registries_are_complete():
    assert len([b for b, _ in ROWS if ":" in b]) >= 25 and len([b for b, _ in ROWS if "." in b]) >= 25


@pytest.mark.parametrize("block", [b for b, _ in ROWS + CONTROLS])
def test_no_special_purpose_block_is_ever_looked_up(block):
    for addr in _samples(block):
        assert is_private_ip(addr) is (not _expected(addr)), f"{addr} in {block}"


def test_ipv4_mapped_ipv6_follows_the_ipv4_answer():
    assert is_private_ip("::ffff:192.168.1.1") and not is_private_ip("::ffff:194.232.104.139")
