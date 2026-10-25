"""
Port tests (0.8.0): one TCP connection attempt per chosen port to the traced
address, from this machine, timed. A reachability check for one target, not
a port scanner: single ports only (no ranges), at most :data:`MAX_PORTS`, at
most :data:`PARALLEL` at a time, no administrator rights (an ordinary
``connect``).

STATES (Nmap's definitions, Nmap Reference Guide, "Port Scanning Basics")
------
* **open**: "an application is actively accepting TCP connections". The
  connect time runs from the attempt to the established connection.
* **closed**: the port is reachable "but there is no application listening
  on it": the target answered with a reset ("If the connection does not
  exist (CLOSED), then a reset is sent in response to any incoming segment
  except another reset", RFC 9293 3.5.2).
* **filtered**: "packet filtering prevents its probes from reaching the
  port": no answer within the wait, or an ICMP unreachable (reason says which).

One attempt per port: on Windows exactly one SYN (SIO_TCP_INITIAL_RTO, as the
Paths prober), and a router's ICMP error fails the attempt at once
(TCP_FAIL_CONNECT_ON_ICMP_ERROR); macOS and Linux may resend the SYN inside
the wait, as their connect does.

TLS: for 443 and the ports the caller marks, a TLS handshake right after the
connection, server name set to the target's name, timed from ClientHello to
the finished handshake, then closed. Certificates are not checked: the time
says nothing about the certificate, and nothing is sent after the handshake.
"""
from __future__ import annotations

import errno
import logging
import select
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field

from routemap_engine.logsafe import tag

log = logging.getLogger("routemap_engine.ports")

MAX_PORTS = 32
PARALLEL = 4
DEFAULT_PORTS = (443, 80, 22, 25, 53, 3389)
DEFAULT_TLS_PORTS = (443,)
WAIT = 3.0
MAX_WAIT = 10.0

_REFUSED = {errno.ECONNREFUSED, 10061}                                   # WSAECONNREFUSED
_UNREACHABLE = {errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051}     # WSAEHOSTUNREACH, WSAENETUNREACH
_IN_PROGRESS = {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN, 10035}


class InvalidPorts(ValueError):
    """The port list cannot be tested; ``str()`` says why, for the user."""


def parse_ports(value, *, cap: int = MAX_PORTS) -> list[int]:
    """Ports from "443, 80 22" or an iterable of numbers, in order, without
    repeats. Ranges ("1-1024") and more than *cap* ports are refused: this is
    a reachability check, not a port scanner."""
    tokens = value.replace(",", " ").split() if isinstance(value, str) else list(value)
    out: list[int] = []
    for tok in tokens:
        text = str(tok).strip()
        if "-" in text or ":" in text:
            raise InvalidPorts(f"{text!r} is a range; list single ports (this is not a port scanner)")
        if not text.isdigit():
            raise InvalidPorts(f"{text!r} is not a port number")
        port = int(text)
        if not 1 <= port <= 65535:
            raise InvalidPorts(f"{port} is not a port number (1 to 65535)")
        if port not in out:
            out.append(port)
    if not out:
        raise InvalidPorts("give at least one port, such as 443")
    if len(out) > cap:
        raise InvalidPorts(f"{len(out)} ports; at most {cap} per test")
    return out


@dataclass
class PortResult:
    port: int
    state: str                         # open | closed | filtered | error
    reason: str | None = None          # "no answer in 3 s", "unreachable", "reset", ...
    connect_ms: float | None = None    # open ports only
    tls_ms: float | None = None
    tls_version: str | None = None
    tls_error: str | None = None

    def to_dict(self) -> dict:
        out = asdict(self)
        for k in ("connect_ms", "tls_ms"):
            out[k] = None if out[k] is None else round(out[k], 1)
        return out


@dataclass
class PortsResult:
    address: str
    results: list[PortResult] = field(default_factory=list)
    wait: float = WAIT
    cap: int = MAX_PORTS
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return {"address": self.address, "cap": self.cap, "parallel": PARALLEL, "wait": self.wait,
                "seconds": round(self.seconds, 1), "results": [r.to_dict() for r in self.results]}

    @property
    def open_count(self) -> int:
        return sum(1 for r in self.results if r.state == "open")


def _windows_options(sock) -> None:
    from routemap_engine import probe
    try:
        sock.setsockopt(socket.IPPROTO_TCP, probe.TCP_FAIL_CONNECT_ON_ICMP_ERROR, 1)
    except OSError:
        pass
    probe.no_syn_retransmissions(sock)


def _one(address: str, port: int, wait: float, tls: bool, server_name: str | None,
         windows: bool, clock) -> PortResult:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if windows:
            _windows_options(sock)
        sock.setblocking(False)
        started = clock()
        rc = sock.connect_ex((address, port))
        if rc not in _IN_PROGRESS:
            return _failed(port, rc)
        if rc != 0:
            _, writable, failed = select.select([], [sock], [sock], wait)
            if not writable and not failed:
                return PortResult(port, "filtered", f"no answer in {wait:g} s")
            rc = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if rc != 0:
                return _failed(port, rc)
        result = PortResult(port, "open", connect_ms=(clock() - started) * 1000)
        if tls:
            _tls(sock, result, wait, server_name, clock)
        return result
    except OSError as exc:
        return _failed(port, exc.errno or -1)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _failed(port: int, rc: int) -> PortResult:
    if rc in _REFUSED:
        return PortResult(port, "closed", "reset")
    if rc in _UNREACHABLE:
        return PortResult(port, "filtered", "unreachable")
    return PortResult(port, "error", f"connection failed (error {rc})")


def _tls(sock, result: PortResult, wait: float, server_name: str | None, clock) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE                     # timing only; nothing is said about the certificate
    sock.setblocking(True)
    sock.settimeout(wait)
    started = clock()
    try:
        tls = ctx.wrap_socket(sock, server_hostname=server_name, do_handshake_on_connect=False)
        tls.do_handshake()
        result.tls_ms = (clock() - started) * 1000
        result.tls_version = tls.version()
    except (ssl.SSLError, OSError) as exc:
        result.tls_error = "no TLS handshake in time" if isinstance(exc, TimeoutError | socket.timeout) \
            else f"TLS handshake failed ({exc.__class__.__name__})"


def check_ports(address: str, ports, *, tls_ports=DEFAULT_TLS_PORTS, wait: float = WAIT,
               server_name: str | None = None, windows: bool | None = None,
               clock=time.perf_counter) -> PortsResult:
    """Test *ports* on *address* (an IP address, the one traced), at most
    :data:`PARALLEL` at a time, each with *wait* seconds. *server_name* is
    sent as the TLS server name (the target's hostname; None for an address)."""
    import ipaddress
    address = str(ipaddress.ip_address(address))
    chosen = parse_ports(ports)
    tls_set = set(parse_ports(tls_ports)) if tls_ports else set()
    wait = max(0.2, min(float(wait), MAX_WAIT))
    windows = sys.platform.startswith("win") if windows is None else windows
    if server_name:
        try:
            import ipaddress as _ip
            _ip.ip_address(server_name)
            server_name = None                           # SNI carries names only (RFC 6066 section 3)
        except ValueError:
            pass
    started = clock()
    with ThreadPoolExecutor(max_workers=PARALLEL, thread_name_prefix="routemap-port") as pool:
        results = list(pool.map(lambda p: _one(address, p, wait, p in tls_set, server_name, windows, clock),
                                chosen))
    out = PortsResult(address, results, wait=wait, seconds=clock() - started)
    log.info("event=ports_tested target=%s ports=%d open=%d", tag(address), len(results), out.open_count)
    return out
