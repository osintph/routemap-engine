"""
Whether an address is on the public internet.

The engine's one answer to "may this address be looked up anywhere". It covers
the ranges the stdlib flags miss: CGNAT (100.64.0.0/10), 0.0.0.0/8 and the NAT64
prefix. CGNAT matters here specifically, because a carrier-NAT hop is the second
or third hop of most consumer traces, and geolocating it would place the user's
own ISP wherever the carrier registered that block.

Kept identical to FalconEye's ``app.utils.safe_fetch.is_private_ip``, which is
where it was written and tested first.
"""
import ipaddress

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


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

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        if ip in _CGNAT or ip in _THIS_NETWORK:
            return True
    elif isinstance(ip, ipaddress.IPv6Address):
        if ip in _NAT64:
            return True

    return False
