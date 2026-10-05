"""Fields that come from other people's services are checked here before the
engine passes them on (RM-01 step 5). Whatever an API answers, a country code
is two letters, a ruleset date is a month, a prefix is a network, and a name is
short plain text. Anything else becomes None, which callers already treat as
"not known"."""
from __future__ import annotations

import ipaddress
import re
import unicodedata

MAX_TEXT = 80
_CC = re.compile(r"[A-Za-z]{2}")
_MONTH = re.compile(r"\d{4}-(0[1-9]|1[0-2])")


def country(value) -> str | None:
    """"DE" for "de"; None for anything that is not two letters."""
    return value.upper() if isinstance(value, str) and _CC.fullmatch(value) else None


def month(value) -> str | None:
    """A ruleset date such as "2024-08", or None."""
    return value if isinstance(value, str) and _MONTH.fullmatch(value) else None


def prefix(value) -> str | None:
    """A network in its canonical form ("62.115.0.0/16"), or None."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def text(value, limit: int = MAX_TEXT) -> str | None:
    """A short name: printable characters only, no markup characters, at most
    *limit* long. None for anything that is not a non-empty string."""
    if not isinstance(value, str):
        return None
    kept = "".join(ch for ch in value if unicodedata.category(ch)[0] != "C" and ch not in "<>")
    kept = " ".join(kept.split())[:limit]
    return kept or None
