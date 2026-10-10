"""
Whether an address is on the public internet.

The engine's one answer to "may this address be looked up anywhere". Since
0.7.0 it follows the IANA special-purpose registries for IPv4 and IPv6
explicitly, row by row, instead of the stdlib's ``is_private``: the stdlib's
tables changed in Python 3.12.4 and 3.13, so the same address got a different
answer on different Pythons, and none of them knew the newest blocks
(3fff::/20, 5f00::/16, 2001:1::3). tests/test_special_ranges.py checks every
registry row against a vendored copy of the registries.

Beyond the registries, never looked up: CGNAT (100.64.0.0/10, the second or
third hop of most consumer traces, which would place the user's own ISP
wherever the carrier registered the block), the NAT64 well-known prefix (an
IPv4 host behind a translator), Teredo and 6to4 (another host's address
inside), and multicast.

FalconEye's ``app.utils.safe_fetch.is_private_ip`` was the original of this
function; it has not followed the 0.7.0 tables yet.
"""
import ipaddress

# Globally reachable blocks inside larger blocks that are not (IANA "True").
_REACHABLE = tuple(ipaddress.ip_network(n) for n in (
    "2001:1::1/128", "2001:1::2/128", "2001:1::3/128", "2001:3::/32", "2001:4:112::/48",
    "2001:20::/28", "2001:30::/28", "2620:4f:8000::/48",
    "192.0.0.9/32", "192.0.0.10/32", "192.31.196.0/24", "192.52.193.0/24", "192.175.48.0/24",
))

# Never looked up: the registries' "False", "N/A" and deprecated rows, plus
# the engine's own additions named in the module docstring.
_NOT_REACHABLE = tuple(ipaddress.ip_network(n) for n in (
    "::1/128", "::/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "100:0:0:1::/64", "2001::/23", "2001::/32", "2001:2::/48", "2001:10::/28", "2001:db8::/32",
    "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
))


def is_private_ip(addr: str) -> bool:
    """True if *addr* must not be looked up (private, loopback, link-local, ...).

    Fails closed: an unparseable address counts as private.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True

    # Unwrap ::ffff:a.b.c.d to get the real IPv4 address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if any(ip in net for net in _REACHABLE if net.version == ip.version):
        return False
    if any(ip in net for net in _NOT_REACHABLE if net.version == ip.version):
        return True
    # Anything the stdlib still flags (a future block, before this table knows it).
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified)
