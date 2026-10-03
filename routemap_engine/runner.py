"""
Running a traceroute on this machine.

``run_trace(target, options) -> trace_text`` shells out to the system's own
tool, so the trace starts where the user is. The engine has no raw sockets of
its own and never asks for elevated privileges.

HOW THE TOOL IS RUN
-------------------
* An argument list, never a shell. The target goes through
  :func:`routemap.engine.target.validate_target` first, which accepts only a
  hostname or an IP address, so it can be neither a flag ("-x") nor anything a
  shell would interpret.
* Output is streamed line by line to ``on_line`` as the tool prints it, so a
  slow trace is visibly running rather than frozen.
* A ``cancel`` event stops the tool, and a wall-clock ``timeout`` bounds the
  whole run. Both keep whatever the tool printed so far, which the parser can
  still read.

DEFAULT FLAGS, AND WHY
----------------------
  tracert -h 30 -w 1000          30 hops, one second per reply instead of four
  traceroute -m 30 -q 3 -w 1     30 hops, three probes (the physics bound wants a
                                 minimum of several), one second per reply
  mtr --report-wide --show-ips -c 3 -m 30
                                 the report shape the parser reads, with
                                 addresses shown next to names

These are the commands FalconEye has shown its users since v3.35.0, so a trace
run here and a trace pasted there come out the same. Every flag is overridable.

PRIVILEGES
----------
None of the defaults needs admin on any platform. Two cases do, and the engine
says so rather than escalating:

* ``traceroute -I`` (ICMP probes) and ``-T`` (TCP) need root on Linux and
  macOS. :data:`PRIVILEGED_FLAGS` lists them so the settings screen can warn.
* ``mtr`` on macOS needs root (Homebrew's mtr cannot open its raw socket
  without it), so mtr is only offered there when it can actually run.
"""
from __future__ import annotations

import locale
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from routemap.engine.target import validate_target

TOOL_TRACERT = "tracert"
TOOL_TRACEROUTE = "traceroute"
TOOL_MTR = "mtr"
TOOLS = (TOOL_TRACERT, TOOL_TRACEROUTE, TOOL_MTR)

DEFAULT_FLAGS = {
    TOOL_TRACERT: ["-h", "30", "-w", "1000"],
    TOOL_TRACEROUTE: ["-m", "30", "-q", "3", "-w", "1"],
    TOOL_MTR: ["--report-wide", "--show-ips", "-c", "3", "-m", "30"],
}

# Flags that switch a tool to a probe type needing raw sockets, per tool.
PRIVILEGED_FLAGS = {
    TOOL_TRACEROUTE: {"-I": "ICMP probes", "-T": "TCP probes", "--icmp": "ICMP probes",
                      "--tcp": "TCP probes"},
    TOOL_TRACERT: {},
    TOOL_MTR: {},
}

# A trace that has not finished in this long is not going to.
DEFAULT_TIMEOUT_SECONDS = 180.0


class TraceToolMissing(RuntimeError):
    """No usable traceroute tool is installed. ``str()`` says what to install."""


@dataclass
class TraceOptions:
    tool: str = "auto"                     # "auto" or one of TOOLS
    flags: list[str] | None = None         # None: DEFAULT_FLAGS[tool]
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    cancel: threading.Event | None = None
    on_line: Callable[[str], None] | None = None
    # Extra environment, merged over os.environ. Tests use it; nothing else needs to.
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class TraceResult:
    text: str
    tool: str
    argv: list[str]
    returncode: int | None
    cancelled: bool = False
    timed_out: bool = False
    seconds: float = 0.0


def _platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _mtr_usable() -> bool:
    """mtr needs root on macOS; elsewhere its mtr-packet helper is setuid."""
    if _platform() == "macos":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    return True


def available_tools() -> dict[str, str]:
    """Installed, usable tools for this platform: name -> executable path."""
    found = {}
    plat = _platform()
    candidates = [TOOL_TRACERT] if plat == "windows" else [TOOL_TRACEROUTE, TOOL_MTR]
    for name in candidates:
        path = shutil.which(name)
        if not path and plat != "windows":
            # Common sbin locations that are not always on a desktop PATH.
            for directory in ("/usr/sbin", "/sbin", "/usr/local/sbin", "/opt/homebrew/sbin"):
                probe = os.path.join(directory, name)
                if os.access(probe, os.X_OK):
                    path = probe
                    break
        if not path:
            continue
        if name == TOOL_MTR and not _mtr_usable():
            continue
        found[name] = path
    return found


def install_hint() -> str:
    """Exactly what to install on this platform when nothing is available."""
    plat = _platform()
    if plat == "windows":
        return ("tracert.exe was not found. It ships with every Windows install in "
                "C:\\Windows\\System32; check that folder is on PATH.")
    if plat == "macos":
        return ("traceroute was not found. It ships with macOS in /usr/sbin; check "
                "that /usr/sbin is on PATH.")
    return ("No traceroute tool was found. Install one: "
            "sudo apt install traceroute (Debian, Ubuntu), "
            "sudo dnf install traceroute (Fedora), "
            "sudo pacman -S traceroute (Arch). "
            "mtr is optional and gives per-hop loss: sudo apt install mtr-tiny.")


def pick_tool(requested: str = "auto") -> tuple[str, str]:
    """(tool name, executable path) for *requested*, or TraceToolMissing."""
    tools = available_tools()
    if requested and requested != "auto":
        if requested not in TOOLS:
            raise ValueError(f"unknown trace tool {requested!r}")
        if requested not in tools:
            if requested == TOOL_MTR and _platform() == "macos" and shutil.which("mtr"):
                raise TraceToolMissing(
                    "mtr needs administrator rights on macOS, so it is not used. "
                    "Choose traceroute in Settings.")
            raise TraceToolMissing(f"{requested} is not installed. {install_hint()}")
        return requested, tools[requested]
    for name in (TOOL_TRACERT, TOOL_TRACEROUTE, TOOL_MTR):
        if name in tools:
            return name, tools[name]
    raise TraceToolMissing(install_hint())


def privileged_flags_in(tool: str, flags: list[str]) -> list[str]:
    """Which of *flags* need administrator rights, described for the UI."""
    table = PRIVILEGED_FLAGS.get(tool, {})
    return [f"{flag} ({table[flag]})" for flag in flags if flag in table]


def build_argv(tool: str, executable: str, target: str, flags: list[str] | None = None) -> list[str]:
    """The exact argument list. The target is validated here, last, every time."""
    canonical = validate_target(target)
    chosen = list(DEFAULT_FLAGS[tool] if flags is None else flags)
    for flag in chosen:
        if not isinstance(flag, str) or "\x00" in flag or "\n" in flag:
            raise ValueError(f"unusable flag {flag!r}")
    if canonical.startswith("-"):  # cannot happen after validation; belt and braces
        raise ValueError("target looks like a flag")
    return [executable, *chosen, canonical]


def _decode(raw: bytes) -> str:
    # tracert prints in the console's OEM code page, not UTF-8. The preferred
    # encoding is right for every tool on every platform we ship; "replace"
    # keeps a stray byte from losing the line.
    encoding = locale.getpreferredencoding(False) or "utf-8"
    if _platform() == "windows":
        try:
            import ctypes
            encoding = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:  # noqa: BLE001
            pass
    try:
        return raw.decode(encoding, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def run_trace(target: str, options: TraceOptions | None = None) -> TraceResult:
    """Run one trace and return what the tool printed.

    Blocking: call it from a worker thread in the GUI. ``options.on_line`` is
    called from this thread for every line as it arrives.
    """
    options = options or TraceOptions()
    tool, executable = pick_tool(options.tool)
    argv = build_argv(tool, executable, target, options.flags)

    env = dict(os.environ)
    env.update(options.env)
    # Ask the Unix tools for untranslated output; the parser reads English.
    if _platform() != "windows":
        env["LC_ALL"] = "C"

    creationflags = 0
    if _platform() == "windows":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    started = time.monotonic()
    process = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        shell=False, env=env, creationflags=creationflags)

    lines: list[str] = []
    cancelled = timed_out = False

    def _watchdog():
        nonlocal cancelled, timed_out
        while process.poll() is None:
            if options.cancel is not None and options.cancel.is_set():
                cancelled = True
                process.kill()
                return
            if time.monotonic() - started > options.timeout:
                timed_out = True
                process.kill()
                return
            time.sleep(0.1)

    watcher = threading.Thread(target=_watchdog, name="routemap-trace-watchdog", daemon=True)
    watcher.start()

    assert process.stdout is not None
    for raw in iter(process.stdout.readline, b""):
        line = _decode(raw).rstrip("\r\n")
        lines.append(line)
        if options.on_line is not None:
            try:
                options.on_line(line)
            except Exception:  # noqa: BLE001 - a broken listener must not kill the trace
                pass
    process.stdout.close()
    returncode = process.wait()
    watcher.join(timeout=1.0)

    text = "\n".join(lines).strip("\n") + "\n" if lines else ""
    return TraceResult(text=text, tool=tool, argv=argv, returncode=returncode,
                       cancelled=cancelled, timed_out=timed_out,
                       seconds=round(time.monotonic() - started, 2))
