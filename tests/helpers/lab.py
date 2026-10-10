"""A simulated network for path discovery, on a virtual clock.

A topology is a list, one entry per TTL from 1:
  "a"                          one router
  ("flow", ["a", "b"])         a per-flow choice made here (hash of flow and TTL)
  ("branch", [["a1", "a2"], ["b1", "b2"]])   one choice per flow for several hops
  ("packet", ["a", "b"])       a per-packet choice (random per probe)
The last entry's router is the destination and answers as "reached".

Balancers hash the flow's header fields (identifier and checksum), so the
simulation also proves a flow stays on one path only if its fields do.
"""
from __future__ import annotations

import hashlib
import random

from routemap_engine import probe


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Lab:
    def __init__(self, topology, *, seed=0, latency_ms=5.0, silent=(), loss=None, flow_fields=None):
        self.topology = topology
        self.seed = seed
        self.rng = random.Random(seed)
        self.clock = Clock()
        self.latency = latency_ms / 1000.0
        self.silent = set(silent)            # routers that never answer
        self.loss = loss or {}               # router -> probability an answer is lost
        self.flow_fields = flow_fields or (lambda flow: (0x4000 + flow, probe.flow_checksum(flow)))
        self.queue = []                      # (due, FlowAnswer)
        self.sent = []                       # (time, flow, ttl)
        self.closed = False

    def _hash(self, flow, salt):
        ident, csum = self.flow_fields(flow)
        h = hashlib.sha256(f"{self.seed}:{salt}:{ident}:{csum}".encode()).digest()
        return int.from_bytes(h[:4], "big")

    def path(self, flow):
        out, branch = [], None
        for i, hop in enumerate(self.topology):
            if isinstance(hop, str):
                out.append(hop)
            elif hop[0] == "flow":
                out.append(hop[1][self._hash(flow, i) % len(hop[1])])
            elif hop[0] == "packet":
                out.append(hop)              # chosen per probe
            elif hop[0] == "branch":
                b = hop[1][self._hash(flow, f"b{i}") % len(hop[1])]
                out.extend(b)
        return out

    # transport
    def send(self, flow, ttl, seq):
        self.sent.append((self.clock.t, flow, ttl))
        route = self.path(flow)
        hop = route[min(ttl, len(route)) - 1]
        if isinstance(hop, tuple):
            hop = self.rng.choice(hop[1])
        reached = ttl >= len(route)
        if hop in self.silent or self.rng.random() < self.loss.get(hop, 0.0):
            return
        rtt = self.latency * min(ttl, len(route)) * (1 + 0.05 * self.rng.random())
        self.queue.append((self.clock.t + rtt, probe.FlowAnswer(seq, hop, reached, self.clock.t + rtt)))

    def read(self, timeout):
        end = self.clock.t + max(0.0, timeout)
        due = sorted(q for q in self.queue if q[0] <= end)
        if due:
            first = due[0][0]
            ready = [q for q in self.queue if q[0] <= first]
            self.queue = [q for q in self.queue if q[0] > first]
            self.clock.t = max(self.clock.t, first)
            return [a for _, a in ready]
        self.clock.t = end
        return []

    def close(self):
        self.closed = True
