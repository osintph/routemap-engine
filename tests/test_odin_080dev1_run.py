"""The ODIN engine check of 25 Oct 2026 (Windows 11, Python 3.14.3, engine
0.8.0.dev1 at 9e15dea; tests/fixtures/odin_080dev1_run.json, sanitized).

1. Ports 22, 25, 53 and 3389 came back "error 10060" (WSAETIMEDOUT), and the
   run took 1.0 s of a 3 s wait: with one SYN, Windows gave up after its
   initial RTO.
2. The system resolver's AAAA row said "no AAAA record" for names that have
   one (tests/test_dnstime.py covers the wording).
3. heise.de: TCP silent at TTL 15 to 19, every ICMP check there answered by
   the target itself, the full-TTL attempt reached it; the header blamed the
   routers."""
import errno
import json
import pathlib

import pytest

from routemap_engine import multipath, ports, probe
from helpers import silent_net

RUN = json.loads((pathlib.Path(__file__).parent / "fixtures" / "odin_080dev1_run.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------- 1. ports

class _WindowsTimeOut:
    """A socket whose connect Windows itself gives up on after *after* seconds
    with WSAETIMEDOUT, as the four ports of the ODIN run did."""

    def __init__(self, clock, after):
        self.clock, self.after = clock, after

    def __call__(self, family, kind):
        return self

    def setsockopt(self, *a):
        pass

    def setblocking(self, flag):
        pass

    def connect_ex(self, addr):
        return 10035                                   # WSAEWOULDBLOCK

    def getsockopt(self, level, name, *a):
        return 10060                                   # WSAETIMEDOUT

    def close(self):
        pass


@pytest.mark.parametrize("port", [r["port"] for r in RUN["ports"]["results"] if r["state"] == "error"])
def test_windows_time_out_is_filtered_and_says_how_long_it_waited(monkeypatch, port):
    now = [0.0]
    sock = _WindowsTimeOut(lambda: now[0], 1.0)
    monkeypatch.setattr(ports.socket, "socket", sock)

    def select(r, w, x, timeout):
        now[0] += 1.0                                   # Windows gave up after about 1 s
        return [], [], list(x)
    monkeypatch.setattr(ports.select, "select", select)
    r = ports._one(RUN["ports"]["address"], port, 3.0, False, None, False, lambda: now[0])
    assert (r.state, r.reason) == ("filtered", "no answer (the system gave up after 1.0 s)"), r
    assert r.waited == 1.0


def test_a_time_out_at_the_end_of_the_wait_reads_as_the_wait():
    for rc in (10060, errno.ETIMEDOUT):
        assert ports._failed(22, rc).state == "filtered"
        assert ports._failed(22, rc, 3.0, 3.0).to_dict()["reason"] == "no answer in 3 s"


def test_windows_sends_one_syn_and_the_result_says_the_wait_it_really_used(monkeypatch):
    """Windows retries after a reset when SYN retransmissions are on (a closed
    port read "filtered" on Windows CI, 25 Oct 2026), so it keeps one SYN; it
    then gives up after about 1 s, and the result says so instead of 3 s."""
    called = []
    monkeypatch.setattr(probe, "no_syn_retransmissions", lambda sock, *a: called.append(sock) or True)

    class Sock:
        def setsockopt(self, *a):
            pass
    ports._windows_options(Sock())
    assert len(called) == 1
    res = ports.PortsResult("151.101.64.81", [ports.PortResult(22, "filtered", "no answer (the system gave up "
                                                                   "after 1.0 s)", waited=1.02),
                                              ports.PortResult(443, "open", connect_ms=10.2)], wait=3.0)
    out = res.to_dict()
    assert out["wait"] == 3.0 and out["wait_used"] == 1.0 and out["results"][0]["waited"] == 1.0


# ------------------------------------------------------------- 3. TCP silence

def test_the_runs_silence_was_answered_by_the_target_not_by_routers():
    d = multipath.Discovery.from_wire(RUN["discovery"])
    assert multipath.tcp_silence(d) == (15, "target")


def test_a_target_answering_icmp_while_its_tcp_service_waits_for_full_ttl():
    """The run's shape: routers answer TCP to hop 14, the target answers ICMP
    from hop 15, and TCP only at full TTL."""
    net = silent_net.SilentNet(tcp_silent_from=15, target_hop=64, icmp_target_from=15)
    d = multipath.Discoverer("heise.de", silent_net.TARGET, net.make_transport(), clock=net.clock,
                             deadline=net.clock() + 3600, icmp_check=net.icmp_check).run()
    out = d.to_dict()
    assert (out["tcp_silent_from"], out.get("tcp_silent_by")) == (15, "target")
    assert all(p.reached_by == "full_ttl" for p in d.paths)


def test_routers_answering_icmp_keep_the_router_case():
    net = silent_net.SilentNet(tcp_silent_from=3, target_hop=10)
    d = multipath.Discoverer("bbc.com", silent_net.TARGET, net.make_transport(), clock=net.clock,
                             deadline=net.clock() + 3600, icmp_check=net.icmp_check).run()
    assert (d.to_dict()["tcp_silent_from"], d.to_dict().get("tcp_silent_by")) == (3, "router")
