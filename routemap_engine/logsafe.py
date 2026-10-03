"""
Short, non-reversible tags for user-supplied values in log lines.

A trace describes the path from the user's own machine, and an origin says
where the user is. Neither belongs in a log in the clear: on a server (FalconEye
imports this engine) a log is retained by somebody else, and on a desktop a log
is a file a support request may ask the user to attach.

``tag()`` gives correlation without identification:

- sha256 over a **per-process random salt** plus the value, first 12 hex chars.
- The salt never leaves memory and is regenerated on every start, so tags
  cannot be correlated across runs and a captured log cannot be brute-forced
  back to an address by anyone who does not have the running process. A 32-bit
  search over IPv4 is trivial *without* a salt, which is the whole reason one
  is here.
- Stable within a process, so the lines belonging to one trace share a tag.

The salt is the one piece of module state in the engine, and it is
deliberately process-wide: it carries no configuration and nothing can set it.
"""
import hashlib
import os

_SALT = os.urandom(16)

_EMPTY = "-"
_LEN = 12


def tag(value) -> str:
    """A short stable tag for *value*, or ``"-"`` when there is nothing to tag.

    Prefixed ``h:`` so a reader can tell at a glance that the field is a hash
    and not a truncated identifier.
    """
    if value is None:
        return _EMPTY
    text = str(value).strip()
    if not text:
        return _EMPTY
    digest = hashlib.sha256(_SALT + text.encode("utf-8", "replace")).hexdigest()
    return "h:" + digest[:_LEN]
