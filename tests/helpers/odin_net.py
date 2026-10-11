"""The ODIN network of 11 Oct 2026 (tests/fixtures/odin_paths_040b1.txt),
replayed through the real Windows TCP flow prober on a virtual clock.

The 16 paths A to P are read from the printed table, hop by hop. Where a
path printed no router at a hop, that path's router there never answers.
Each path ends at its printed target hop, but no later than one hop after
its last router and never before hop 13, the fewest hops any path printed:
D, F, K, L and M printed the target at 17 after 82.98.103.3 at 13 (they end
at 14), G at 15, and P at 13 after silent hops 10 to 12. The later target
rows (15 to 21) were the silences this replay must not reproduce. The home router (hop 1) answers every other probe, as it did (50%).
The target ignores a connection attempt on a flow that completed one less
than 1 s before (heise.de, measured the same day). Flows are spread over the
16 paths by a hash of the flow number, as a per-flow balancer spreads ports.
"""
from __future__ import annotations

import hashlib
import inspect
import pathlib
import re
import socket

from routemap_engine import probe

FIXTURE = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "odin_paths_040b1.txt"
TARGET = "193.99.144.80"
LETTERS = "ABCDEFGHIJKLMNOP"
ROW = re.compile(r"^\s*(\d+)([a-z]?)\s{2}(.*?)\s+(\d+\.\d+\.\d+\.\d+|\*)\s*(\d+\.\d)?")
IP = re.compile(r"\d+\.\d+\.\d+\.\d+")
CITIES = {"Manila, PH": (14.6, 121.0), "Hong Kong, HK": (22.3, 114.2), "Singapore, SG": (1.29, 103.85),
          "Marseille, FR": (43.3, 5.37), "Frankfurt, DE": (50.11, 8.68), "Frankfurt am Main, DE": (50.11, 8.68),
          "Lappersdorf, DE": (49.05, 12.09), "Hanover, DE": (52.37, 9.73), "Chicago, US": (41.88, -87.63)}


def parse():
    """{letter: {ttl: (address, rtt_ms)}} and {address: printed place} from the table."""
    rows = []
    for line in FIXTURE.read_text().splitlines():
        if line.startswith("#") or not ROW.match(line) or line.startswith("Path"):
            continue
        m = ROW.match(line)
        ttl, sub, middle, addr, rtt = int(m.group(1)), m.group(2), m.group(3), m.group(4), m.group(5)
        tokens = middle.split()
        letters = []
        for tok in tokens:
            if tok == "all":
                letters = list(LETTERS)
                break
            if len(tok) == 1 and tok in LETTERS:
                letters.append(tok)
            else:
                break
        place = " ".join(tokens[len(letters) if letters != list(LETTERS) or "all" not in tokens else 1:]).strip()
        rows.append((ttl, sub, letters, addr, float(rtt) if rtt else None, place))
    has_subs = {ttl for ttl, sub, *_ in rows if sub}
    paths = {x: {} for x in LETTERS}
    places = {}
    for ttl, sub, letters, addr, rtt, place in rows:
        if addr != "*" and place and addr not in places:
            places[addr] = place
        if ttl in has_subs and not sub:
            continue
        for x in letters:
            if addr != "*":
                paths[x].setdefault(ttl, (addr, rtt))
    shortest = min(t for x in LETTERS for t, (a, _r) in paths[x].items() if a == TARGET)
    for x in LETTERS:
        hops = paths[x]
        printed = min(t for t, (a, _r) in hops.items() if a == TARGET)
        last_router = max(t for t, (a, _r) in hops.items() if a != TARGET)
        end = min(printed, max(last_router + 1, shortest))
        paths[x] = {t: v for t, v in hops.items() if t < end}
        paths[x][end] = (TARGET, 250.0)
        paths[x][1] = ("198.51.100.1", 1.4)          # one home router; it answers every other probe
    return paths, places


PATHS, PLACES = parse()


def letter_of(flow: int) -> str:
    return LETTERS[int.from_bytes(hashlib.sha256(f"odin:{flow}".encode()).digest()[:4], "big") % 16]


def true_sequence(flow: int) -> tuple:
    hops = PATHS[letter_of(flow)]
    end = max(hops)
    return tuple(hops[t][0] if t in hops else None for t in range(1, end + 1))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += max(0.0, seconds)


class Net:
    def __init__(self):
        self.clock = Clock()
        self.transport = None
        self.home_counter = 0
        self.connected_at: dict[int, float] = {}
        self.refused_reuse = 0

    def socket(self, family, kind):
        return _Sock(self)

    def select(self, r, w, x, timeout):
        now = self.clock.t
        due = [s for s in w if s.ready_at is not None]
        soonest = min((s.ready_at for s in due), default=None)
        if soonest is None or soonest > now + timeout:
            self.clock.t = now + max(timeout, 0.0)
            return [], [], []
        self.clock.t = max(now, soonest)
        return [], [s for s in due if s.ready_at <= self.clock.t], []

    def answer(self, sock):
        flow = sock.bound[1] - self.transport._base
        hops = PATHS[letter_of(flow)]
        end = max(hops)
        now = self.clock.t
        if sock.ttl >= end:
            last = self.connected_at.get(flow)
            if last is not None and now - last < 1.0:
                self.refused_reuse += 1
                return                                    # ignored: a quick repeat from the same port
            self.connected_at[flow] = now + 0.25
            sock.error, sock.ready_at = 0, now + 0.25
            return
        hop = hops.get(sock.ttl)
        if hop is None:
            return                                        # this path's router here never answers
        if sock.ttl == 1:
            self.home_counter += 1
            if self.home_counter % 2 == 0:
                return
        addr, rtt = hop
        sock.error, sock.icmp = probe.WSAEHOSTUNREACH, _info(addr)
        sock.ready_at = now + (rtt or 50.0) / 1000.0

    def make_transport(self):
        kw = dict(windows=True, source_for=lambda d: "192.0.2.10", socket_factory=self.socket,
                  clock=self.clock, select=self.select, expire_after=3.0)
        if "sleep" in inspect.signature(probe.TcpFlowTransport.__init__).parameters:
            kw["sleep"] = self.clock.sleep
        else:                                         # the 0.4.0-beta.1 transport slept for real
            import types
            probe.time = types.SimpleNamespace(sleep=self.clock.sleep, perf_counter=self.clock,
                                               monotonic=self.clock, time=__import__("time").time)
        self.transport = probe.TcpFlowTransport(TARGET, **kw)
        return self.transport


class _Sock:
    def __init__(self, net):
        self.net, self.ttl, self.bound, self.error, self.icmp, self.ready_at = net, 64, None, None, b"", None

    def setsockopt(self, level, name, value):
        if (level, name) == (socket.IPPROTO_IP, socket.IP_TTL):
            self.ttl = value

    def bind(self, addr):
        self.bound = addr

    def setblocking(self, flag):
        pass

    def connect_ex(self, addr):
        self.net.answer(self)
        return probe.WSAEWOULDBLOCK

    def getsockopt(self, level, name, size=None):
        if (level, name) == (socket.SOL_SOCKET, socket.SO_ERROR):
            return self.error
        return self.icmp

    def close(self):
        self.ready_at = None


def _info(address):
    import struct
    return struct.pack("<HH", 2, 0) + socket.inet_aton(address) + b"\0" * 20 + struct.pack("<i", 1) + bytes([11, 0]) + b"\0\0"
