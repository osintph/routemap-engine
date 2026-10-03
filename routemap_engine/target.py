"""
What may be traced: a hostname or an IP address, and nothing else.

The target ends up in two dangerous places. On the desktop it is an argument to
a traceroute subprocess, and a value starting with "-" would be read as a flag.
In FalconEye it is interpolated into a command a human is told to paste into
their own shell, which makes the page a place where attacker-supplied text can
become someone else's shell command. So this is not a reachability check, it is
a check that the value is a hostname and only a hostname.

Allowlist, not denylist: letters, digits, dot and hyphen for a hostname (each
label starting with a letter or digit, so never "-"), plus the parsed form of an
IP address. Everything else is refused, which covers the shell metacharacters
(; | & $ ` ( ) < > newline, quotes, backslash, space) without having to
enumerate them and without depending on having enumerated them all.
"""
from __future__ import annotations

import ipaddress
import re

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z][A-Za-z0-9-]{0,62}$")
# A single label with no dot ("localhost", an internal short name) is refused:
# it cannot be a public traceroute target and accepting it only widens what can
# be printed or executed.

MAX_TARGET_LENGTH = 253


class InvalidTarget(ValueError):
    """The target is not a plain hostname or IP address."""


def validate_target(raw: str) -> str:
    """Return the canonical target, or raise :class:`InvalidTarget`.

    The returned value is what may be passed to a tool or printed into a
    command. A caller must use this result and never the raw input.
    """
    text = (raw or "").strip()
    if not text:
        raise InvalidTarget("give a hostname or IP address to trace to")
    if len(text) > MAX_TARGET_LENGTH:
        raise InvalidTarget(f"the target is longer than {MAX_TARGET_LENGTH} characters")

    # An IP address first, so the hostname rules never have to reason about
    # colons, zone ids or dotted-quad edge cases.
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise InvalidTarget("that address is not a traceroute target")
        return str(address)

    if not _HOSTNAME_RE.match(text):
        raise InvalidTarget(
            "the target must be a hostname such as example.com or an IP address, "
            "with no scheme, path, port, spaces or shell characters")
    return text.lower()
