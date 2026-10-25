"""A network silent to TCP probes from one hop on, replayed through the real
Windows TCP flow prober on a virtual clock (the same simulated sockets as
odin_net).

Shaped like run 2 of the 0.5.0-beta.1 brief (ODIN, bbc.com over Converge,
AS17639, 0.4.0-beta.2): hops 1 and 2 answer TCP probes, hops 3 onward do not,
an ICMP echo at the same TTL is answered by every router, and the target
answers a TCP connection at any TTL from its own hop on. The real run's
addresses are not used; the fixture from the tester's capture replaces the
parameters here when it arrives.
"""
from __future__ import annotations

import inspect

from helpers import odin_net
from routemap_engine import probe

TARGET = "151.101.0.81"


class SilentNet(odin_net.Net):
    def __init__(self, *, tcp_silent_from: int = 3, target_hop: int = 10, icmp_answers: bool = True,
                 target_answers: bool = True, icmp_target_from: int | None = None):
        super().__init__()
        self.tcp_silent_from = tcp_silent_from
        self.target_hop = target_hop
        self.icmp_answers = icmp_answers
        self.target_answers = target_answers
        self.icmp_target_from = icmp_target_from        # the target answers ICMP from this TTL on
        self.routers = {t: (f"198.51.100.{t}" if t < 3 else f"203.0.113.{t}") for t in range(1, target_hop)}
        self.icmp_sent: list[int] = []

    def answer(self, sock):
        now = self.clock.t
        flow = sock.bound[1] - self.transport._base
        if sock.ttl >= self.target_hop:
            if not self.target_answers:
                return
            last = self.connected_at.get(flow)
            if last is not None and now - last < 1.0:
                return                                    # a quick repeat from the same port
            self.connected_at[flow] = now + 0.03
            sock.error, sock.ready_at = 0, now + 0.03
            return
        if sock.ttl >= self.tcp_silent_from:
            return                                        # these routers do not answer TCP probes
        sock.error, sock.icmp = probe.WSAEHOSTUNREACH, odin_net._info(self.routers[sock.ttl])
        sock.ready_at = now + 0.002 * sock.ttl

    def icmp_check(self, ttl: int) -> str | None:
        self.icmp_sent.append(ttl)
        if ttl >= self.target_hop or (self.icmp_target_from is not None and ttl >= self.icmp_target_from):
            return TARGET
        return self.routers[ttl] if self.icmp_answers else None

    def make_transport(self):
        kw = dict(windows=True, source_for=lambda d: "192.0.2.10", socket_factory=self.socket,
                  clock=self.clock, select=self.select, expire_after=3.0, sleep=self.clock.sleep)
        if "no_retransmit" in inspect.signature(probe.TcpFlowTransport.__init__).parameters:
            kw["no_retransmit"] = lambda sock: True
        self.transport = probe.TcpFlowTransport(TARGET, **kw)
        return self.transport
