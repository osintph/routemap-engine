"""
Remote agents (0.8.0): a trace measured on a server the user controls, over
the user's own SSH access, and shown with the server as its origin.

The agent is this engine's CLI (``routemap-engine agent 1 ...``) on the
server. There is no daemon and no listening port: the app runs the user's
ssh client once per trace, the agent measures, prints JSON lines on stdout
and exits. This module holds both ends of that exchange.

THE SERVER SIDE (:func:`serve`)
-------------------------------
One action per run: ``hello`` (version and what this server can probe),
``trace``, ``paths`` or ``ports``. Every run that has a target times its DNS
lookups with the server's own resolver (and the resolvers named), resolves
the target once and probes that address. With ``--place ip`` the server's
place is looked up the way Route Map finds this computer's (RIPEstat, so
RIPEstat sees the server's address); only the place is printed, never the
address, so the app never holds it. The server's own name is taken out of the
tool output too (mtr prints it as "HOST:"). ``--stop-on-eof``: the run stops when its
stdin closes (the app closed the ssh session), besides its own deadline.

THE CLIENT SIDE (:func:`ssh_argv`, :func:`read_run`)
---------------------------------------------------
* sshd runs the command "via the user's shell using its -c option"
  (sshd(8)), so every argument is validated against a fixed character set
  and then shell-quoted; nothing else reaches the remote shell.
* The destination is a Host from the user's ssh config or user@host. One
  that starts with "-" is refused, and "--" ends ssh's options before it.
* ``-T`` ("Disable pseudo-terminal allocation", ssh(1)), ``BatchMode=yes``
  ("user interaction such as password prompts and host key confirmation
  requests will be disabled", ssh_config(5)) and ``ConnectTimeout``: an
  unknown host key or a locked key fails at once. One connection per run,
  never a retry.
* The agent's output is read with hard caps (:data:`MAX_OUTPUT`,
  :data:`MAX_LINE`) and every field is checked; it came from another machine.

MASKING (:func:`mask_first_hops`)
---------------------------------
An agent trace starts in the server provider's network. Those first hops are
masked by default: listed, but with no address, name or place. The provider's
hops are the private ones first, then the public ones in the AS of the first
public hop, and never fewer than the first two public hops.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import shlex
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import IO, Callable, Iterable

from routemap_engine import __about__, dnstime, multipath, ports as portsmod, probe, runner
from routemap_engine.target import InvalidTarget, validate_target

PROTOCOL = 1
ACTIONS = ("hello", "trace", "paths", "ports")
MAX_OUTPUT = 8 * 1024 * 1024          # bytes read from one agent run, in all
MAX_LINE = 1024 * 1024                # bytes in one JSON line
MAX_DEADLINE = 600.0                  # seconds an agent run may take
CONNECT_TIMEOUT = 15
DEFAULT_COMMAND = "routemap-engine"
MASKED_SOURCE = "unresolved"
ANNOT_MASKED = "agent's provider network, hidden"
MASKED_DETAIL = ("the first hops of a trace from an agent are its server provider's routers; they are "
                 "listed without address, name or place (Settings > Agents > Show first hops)")

_DEST_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@%:\[\]-]{0,252}")
_COMMAND_RE = re.compile(r"(~/)?[A-Za-z0-9_./+-]{1,200}")


class AgentError(RuntimeError):
    """An agent run that could not be used; ``str()`` says why, for the user."""


# =================================================================== client

def validate_destination(raw: str) -> str:
    """An ssh destination: a Host alias or user@host, never an option."""
    text = raw or ""
    if not text or text.startswith("-") or not _DEST_RE.fullmatch(text):
        raise AgentError("the SSH destination must be a Host from your ssh config or user@host, "
                         "with no spaces and not starting with '-'")
    return text


def validate_command(raw: str | None) -> str:
    """The engine's command on the server: a path or a name, no shell syntax."""
    text = (raw or DEFAULT_COMMAND).strip()
    if text.startswith("-") or not _COMMAND_RE.fullmatch(text) or ".." in text.split("/"):
        raise AgentError("the engine command must be a plain path such as routemap-engine or "
                         "~/.local/bin/routemap-engine")
    return text


def _quote_command(command: str) -> str:
    if command.startswith("~/"):
        return "~/" + shlex.quote(command[2:])        # the tilde stays unquoted so the shell expands it
    return shlex.quote(command)


def remote_command(action: str, *, command: str | None = None, target: str | None = None,
                   family: str = "auto", resolvers: Iterable[str] = (), dns: bool = True,
                   ports: Iterable[int] | str | None = None, tls_ports: Iterable[int] | str | None = None,
                   wait: float | None = None, deadline: float | None = None, place_from_ip: bool = False,
                   budget: int | None = None) -> str:
    """The one command line sent to the server, every argument validated and
    quoted. Raises AgentError or InvalidTarget before anything runs."""
    if action not in ACTIONS:
        raise AgentError(f"unknown agent action {action!r}")
    args = [str(PROTOCOL), action]
    if action != "hello":
        if target is None:
            raise AgentError("a remote run needs a target")
        args += ["--target", validate_target(target)]
        if family not in probe.FAMILIES:
            raise AgentError("family must be auto, 4 or 6")
        args += ["--family", family]
        for r in resolvers:
            args += ["--resolver", dnstime.validate_resolver(r)]
        if not dns:
            args.append("--no-dns")
        if ports is not None:
            args += ["--ports", ",".join(str(p) for p in portsmod.parse_ports(ports))]
        if tls_ports:
            args += ["--tls", ",".join(str(p) for p in portsmod.parse_ports(tls_ports))]
        if wait is not None:
            args += ["--wait", f"{max(0.2, min(float(wait), portsmod.MAX_WAIT)):g}"]
        if deadline is not None:
            args += ["--deadline", f"{max(1.0, min(float(deadline), MAX_DEADLINE)):g}"]
        if budget is not None:
            args += ["--budget", str(int(max(50, min(int(budget), multipath.MAX_PROBES))))]
        args.append("--stop-on-eof")
    if place_from_ip:
        args += ["--place", "ip"]
    return " ".join([_quote_command(validate_command(command)), "agent"] + [shlex.quote(a) for a in args])


def ssh_argv(ssh: str, destination: str, command_line: str, *, connect_timeout: int = CONNECT_TIMEOUT) -> list[str]:
    """The ssh client's argument list: the user's own ssh, its own keys and
    config, no prompts, one connection."""
    return [ssh, "-T", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={int(connect_timeout)}",
            "--", validate_destination(destination), command_line]


@dataclass
class AgentRun:
    """What one agent run returned, every field checked."""
    hello: dict | None = None
    origin: dict | None = None                     # {"lat", "lon", "label", "cc"}; never an address
    result: dict | None = None
    lines: list[str] = field(default_factory=list)  # the tool's output lines as they arrived
    error: str | None = None


def _check_lookup(item: dict) -> dict:
    if not isinstance(item, dict):
        raise ValueError("bad DNS row")
    out = {"resolver": item.get("resolver") if item.get("resolver") == dnstime.SYSTEM
           else dnstime.validate_resolver(str(item.get("resolver"))),
           "type": item.get("type") if item.get("type") in dnstime.TYPES else None,
           "ms": _num(item.get("ms")), "addresses": [str(ipaddress.ip_address(a)) for a in item.get("addresses") or []][:64],
           "rcode": _short(item.get("rcode")), "aa": _bool(item.get("aa")), "cached": _bool(item.get("cached")),
           "ttl": None if item.get("ttl") is None else int(_num(item["ttl"])), "error": _short(item.get("error")),
           "tcp": bool(item.get("tcp"))}
    if out["type"] is None:
        raise ValueError("bad DNS type")
    return out


def _check_ports(block: dict) -> dict:
    if not isinstance(block, dict) or not isinstance(block.get("results"), list):
        raise ValueError("bad ports block")
    rows = []
    for r in block["results"][:portsmod.MAX_PORTS]:
        state = r.get("state")
        if state not in ("open", "closed", "filtered", "error"):
            raise ValueError("bad port state")
        rows.append({"port": portsmod.parse_ports([r.get("port")])[0], "state": state, "reason": _short(r.get("reason")),
                     "connect_ms": _num(r.get("connect_ms")), "tls_ms": _num(r.get("tls_ms")),
                     "tls_version": _short(r.get("tls_version")), "tls_error": _short(r.get("tls_error"))})
    return {"address": str(ipaddress.ip_address(block.get("address"))), "cap": portsmod.MAX_PORTS,
            "parallel": portsmod.PARALLEL, "wait": _num(block.get("wait")), "seconds": _num(block.get("seconds")),
            "results": rows}


def _check_resolved(block) -> dict:
    if not isinstance(block, dict):
        raise ValueError("bad resolved block")
    address = str(ipaddress.ip_address(block.get("address")))
    return {"name": validate_target(str(block.get("name") or address)), "address": address,
            "family": probe.family_of(address), "by": "literal" if block.get("by") == "literal" else dnstime.SYSTEM}


def _num(v):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v < 1e7:
        raise ValueError("bad number")
    return float(v)


def _bool(v):
    return None if v is None else bool(v)


def _short(v, limit: int = 200):
    if v is None:
        return None
    return str(v)[:limit]


def _check_result(msg: dict) -> dict:
    kind = msg.get("kind")
    out: dict = {"kind": kind}
    if kind not in ("trace", "paths", "ports"):
        raise ValueError("bad result kind")
    out["resolved"] = _check_resolved(msg.get("resolved"))
    out["dns"] = [_check_lookup(x) for x in (msg.get("dns") or [])[:2 * (dnstime.MAX_RESOLVERS + 1)]]
    if msg.get("ports") is not None:
        out["ports"] = _check_ports(msg["ports"])
    if kind == "trace":
        text = msg.get("trace_text")
        if not isinstance(text, str) or len(text) > MAX_LINE:
            raise ValueError("bad trace text")
        out["trace_text"] = text
        out["tool"] = msg.get("tool") if msg.get("tool") in runner.TOOLS else None
    if kind == "paths":
        out["discovery"] = multipath.Discovery.from_wire(msg.get("discovery"))
    return out


def _check_origin(msg: dict) -> dict:
    lat, lon = _coord(msg.get("lat"), 90), _coord(msg.get("lon"), 180)
    return {"lat": round(lat, 1), "lon": round(lon, 1), "label": _short(msg.get("label"), 120),
            "cc": _short(msg.get("cc"), 2)}


def _coord(v, bound):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not -bound <= v <= bound:
        raise ValueError("bad coordinate")
    return float(v)


def read_run(stream: IO[bytes], *, on_line: Callable[[str], None] | None = None,
             on_progress: Callable[[dict], None] | None = None) -> AgentRun:
    """Read one agent run's stdout to its end, within the caps. Lines that are
    not this protocol are ignored (a login banner, say); a field that fails
    its check makes the whole run an error, never a partial result."""
    run = AgentRun()
    total = 0
    while True:
        raw = stream.readline(MAX_LINE + 1)
        if not raw:
            break
        total += len(raw)
        if total > MAX_OUTPUT:
            run.error = f"the agent sent more than {MAX_OUTPUT // (1024 * 1024)} MB; the run was stopped"
            return run
        if len(raw) > MAX_LINE:
            run.error = "the agent sent a line longer than 1 MB; the run was stopped"
            return run
        try:
            msg = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if not isinstance(msg, dict):
            continue
        kind = msg.get("type")
        try:
            if kind == "hello":
                if msg.get("protocol") != PROTOCOL:
                    run.error = (f"the agent speaks protocol {msg.get('protocol')!r}; this version needs "
                                 f"protocol {PROTOCOL} (routemap-engine {__about__.__version__.rsplit('.', 1)[0]}.x)")
                    return run
                run.hello = {"engine": _short(msg.get("engine"), 40), "protocol": PROTOCOL,
                             "platform": _short(msg.get("platform"), 40), "python": _short(msg.get("python"), 20),
                             "can": {k: bool(v) for k, v in (msg.get("can") or {}).items()
                                     if k in ("icmp4", "icmp6", "paths")},
                             "paths_reason": _short(msg.get("paths_reason")),
                             "tools": [t for t in msg.get("tools") or [] if t in runner.TOOLS]}
            elif kind == "line":
                text = _short(msg.get("text"), 2000) or ""
                run.lines.append(text)
                if on_line is not None:
                    on_line(text)
            elif kind == "progress":
                if on_progress is not None:
                    on_progress({k: int(_num(msg.get(k)) or 0) for k in ("ttl", "paths", "probes", "budget")})
            elif kind == "origin":
                run.origin = _check_origin(msg)
            elif kind == "result":
                run.result = _check_result(msg)
            elif kind == "error":
                run.error = _short(msg.get("message"), 500) or "the agent reported an error"
        except (ValueError, KeyError, TypeError, InvalidTarget) as exc:
            run.error = f"the agent's answer did not check out ({exc}); nothing from it is shown"
            run.result = None
            return run
    if run.hello is None and run.error is None:
        run.error = "the agent sent no answer (is routemap-engine 0.8 installed on the server?)"
    return run


# ================================================================== masking

MASK_MIN_PUBLIC = 2                   # never fewer public hops masked than this


def mask_first_hops(route: dict) -> list[str]:
    """Mask the leading hops of an agent trace that are the server provider's
    network, in place: the private hops, then the public hops in the AS of the
    first public hop, and never fewer than the first :data:`MASK_MIN_PUBLIC`
    public hops (when the AS is unknown, or a host resells another network,
    the floor still covers the provider's edge). The target is never masked.
    Returns the addresses masked, for the tool text (:func:`mask_text`)."""
    hops = route.get("hops") or []
    target = ((route.get("paths") or {}).get("resolved") or route.get("resolved") or {}).get("address")
    masked: list[str] = []
    numbers: list[int] = []
    provider_asn = None
    public_seen = 0
    for hop in hops:
        addrs = list(hop.get("addresses") or ([hop["address"]] if hop.get("address") else []))
        if target and target in addrs:
            break
        public = [a for a in addrs if _is_public(a)]
        if public:
            asn = hop.get("asn")
            if public_seen == 0:
                provider_asn = asn
            elif public_seen >= MASK_MIN_PUBLIC and (provider_asn is None or asn != provider_asn):
                break
            public_seen += 1
        # A private hop never ends the stretch: providers number their core
        # privately between public edges (vps-e7d7933f, 25 Oct 2026: the
        # gateway at hop 1, seven private hops, the provider's next public
        # router at hop 9).
        masked += [a for a in addrs if a not in masked]
        numbers.append(hop.get("hop"))
    # Silent hops at the end of the masked run belong to whatever follows.
    while numbers and not any(h.get("addresses") or h.get("address") for h in hops if h.get("hop") == numbers[-1]):
        numbers.pop()
    for hop in hops:
        if hop.get("hop") in numbers:
            _blank(hop)
    for path in (route.get("paths") or {}).get("paths") or []:
        for hop in path.get("located") or []:
            if hop.get("hop") in numbers or hop.get("address") in masked:
                _blank(hop)
    for group in (route.get("paths") or {}).get("per_packet") or []:
        for hop in group.get("located") or []:
            if hop.get("address") in masked:
                _blank(hop)
    return masked


def _is_public(addr: str) -> bool:
    from routemap_engine.netaddr import is_private_ip
    return not is_private_ip(addr)


def _blank(hop: dict) -> None:
    for key in ("address", "hostname", "lat", "lon", "place", "cc", "distance_km", "rtt_budget_km", "asn",
                "as_org", "as_network", "carrier", "site_code", "source_ref", "reason", "ixp"):
        if key in hop:
            hop[key] = None
    for key in ("addresses", "hostnames", "candidates", "match_strs", "match_meanings"):
        if key in hop:
            hop[key] = []
    for key in ("precision", "ip_provider", "asn_source"):
        hop.pop(key, None)
    hop["source"] = MASKED_SOURCE
    hop["masked"] = True
    if "annotations" in hop:
        hop["annotations"] = [ANNOT_MASKED]
        hop["annotation_details"] = [f"{ANNOT_MASKED}: {MASKED_DETAIL}"]


def mask_text(text: str, addresses: Iterable[str]) -> str:
    """*text* with each masked address, and a hostname printed before it,
    replaced by "hidden"."""
    for addr in sorted(set(addresses), key=len, reverse=True):
        esc = re.escape(addr)
        text = re.sub(rf"\S+ \({esc}\)", "hidden", text)
        text = re.sub(rf"\[{esc}\]", "[hidden]", text)
        text = re.sub(rf"(?<![\w.:]){esc}(?![\w.:])", "hidden", text)
    return text


# =================================================================== server

def _emit(out: IO[str], lock: threading.Lock, msg: dict) -> None:
    with lock:
        out.write(json.dumps(msg, separators=(",", ":")) + "\n")
        out.flush()


def _hello() -> dict:
    ok4, _ = probe.available(4)
    ok6, _ = probe.available(6)
    paths_ok, why = multipath.available()
    return {"type": "hello", "engine": __about__.__version__, "protocol": PROTOCOL, "platform": sys.platform,
            "python": ".".join(map(str, sys.version_info[:3])), "can": {"icmp4": ok4, "icmp6": ok6, "paths": paths_ok},
            "paths_reason": why or None, "tools": sorted(runner.available_tools())}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=f"{__about__.NAME} agent", description="Run one measurement for Route Map "
                                "on this machine and print it as JSON lines.")
    p.add_argument("protocol", type=int, help=f"protocol version (this engine speaks {PROTOCOL})")
    p.add_argument("action", choices=ACTIONS)
    p.add_argument("--target")
    p.add_argument("--family", choices=probe.FAMILIES, default="auto")
    p.add_argument("--resolver", action="append", default=[])
    p.add_argument("--no-dns", action="store_true")
    p.add_argument("--ports")
    p.add_argument("--tls")
    p.add_argument("--wait", type=float, default=portsmod.WAIT)
    p.add_argument("--deadline", type=float, default=runner.DEFAULT_TIMEOUT_SECONDS)
    p.add_argument("--budget", type=int, default=multipath.MAX_PROBES)
    p.add_argument("--place", choices=("ip", "none"), default="none")
    p.add_argument("--stop-on-eof", action="store_true")
    return p


def serve(argv: list[str], *, out: IO[str] | None = None, stdin: IO | None = None) -> int:
    """Run ``routemap-engine agent ...``: one action, JSON lines on *out*."""
    out = out or sys.stdout
    lock = threading.Lock()
    args = build_parser().parse_args(argv)
    if args.protocol != PROTOCOL:
        _emit(out, lock, {"type": "hello", "engine": __about__.__version__, "protocol": PROTOCOL})
        _emit(out, lock, {"type": "error", "message": f"protocol {args.protocol} asked for; this engine "
                                                       f"speaks {PROTOCOL}"})
        return 2
    _emit(out, lock, _hello())
    cancel = threading.Event()
    if args.stop_on_eof:
        source = stdin or sys.stdin

        def watch():
            try:
                while source.read(1024):
                    pass
            except (OSError, ValueError):
                pass
            cancel.set()
        threading.Thread(target=watch, name="routemap-agent-stdin", daemon=True).start()
    if args.place == "ip":
        _emit_origin(out, lock)
    if args.action == "hello":
        return 0
    try:
        return _measure(args, out, lock, cancel)
    except (InvalidTarget, portsmod.InvalidPorts, dnstime.InvalidResolver, probe.NoAddress) as exc:
        _emit(out, lock, {"type": "error", "message": str(exc)})
        return 2
    except Exception as exc:  # noqa: BLE001 - the app shows the reason; the agent never hangs
        _emit(out, lock, {"type": "error", "message": f"{exc.__class__.__name__}: {exc}"[:500]})
        return 1


def _emit_origin(out, lock) -> None:
    from routemap_engine import whereami
    try:
        me = asyncio.run(whereami.locate_me())
    except Exception as exc:  # noqa: BLE001
        _emit(out, lock, {"type": "line", "text": f"agent place not found: {exc.__class__.__name__}"})
        return
    _emit(out, lock, {"type": "origin", "lat": me["lat"], "lon": me["lon"], "label": me.get("label"),
                      "cc": me.get("cc")})                    # never me["ip"]


_HOST_LINE = re.compile(r"^(\s*HOST:\s+)\S+", re.M)


def _without_own_name(text: str) -> str:
    """*text* without this machine's own name: mtr's report starts with
    "HOST: <this machine>" (vps-e7d7933f, 25 Oct 2026), and a server's name
    can lead to its address, which the agent never sends."""
    text = _HOST_LINE.sub(r"\1agent", text)
    import socket
    own = {n for n in (socket.gethostname(), socket.gethostname().split(".")[0]) if len(n) > 2}
    for name in sorted(own, key=len, reverse=True):
        text = re.sub(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", "agent", text)
    return text


def _measure(args, out, lock, cancel: threading.Event) -> int:
    target = validate_target(args.target or "")
    deadline = max(1.0, min(args.deadline, MAX_DEADLINE))
    started = time.monotonic()
    resolvers = [dnstime.validate_resolver(r) for r in args.resolver]
    lookups = [] if args.no_dns else dnstime.measure(target, resolvers)
    resolved = dnstime.resolve_target(target, args.family)
    result: dict = {"type": "result", "kind": args.action, "resolved": resolved.to_dict(),
                    "dns": [x.to_dict() for x in lookups]}
    if args.ports or args.action == "ports":
        chosen = portsmod.parse_ports(args.ports or portsmod.DEFAULT_PORTS)
        tls = portsmod.parse_ports(args.tls) if args.tls else portsmod.DEFAULT_TLS_PORTS
        result["ports"] = portsmod.check_ports(resolved.address, chosen, tls_ports=tls, wait=args.wait,
                                               server_name=target).to_dict()
    left = deadline - (time.monotonic() - started)
    if args.action == "trace":
        tr = runner.run_trace(target, runner.TraceOptions(
            family=args.family, address=resolved.address, timeout=max(1.0, left), cancel=cancel,
            on_line=lambda line: _emit(out, lock, {"type": "line", "text": _without_own_name(line)})))
        result.update(trace_text=_without_own_name(tr.text), tool=tr.tool, cancelled=tr.cancelled,
                      timed_out=tr.timed_out)
    elif args.action == "paths":
        ok, why = multipath.available()
        if not ok:
            _emit(out, lock, {"type": "error", "message": f"path discovery cannot run on this server: {why}"})
            return 2
        d = multipath.discover(target, family=args.family, address=resolved.address,
                               options=multipath.Options(budget=args.budget), cancel=cancel,
                               deadline=time.perf_counter() + max(1.0, left),
                               on_progress=lambda p: _emit(out, lock, {"type": "progress", **p}))
        result["discovery"] = d.to_wire()
    _emit(out, lock, result)
    return 0
