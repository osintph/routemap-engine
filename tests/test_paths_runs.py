"""The two Windows runs behind the 0.5.0-beta.1 Paths fixes, replayed through
the real Windows TCP prober.

Run 1: the released 0.4.0-beta.2 zip on ODIN, heise.de, 12 Oct 2026
(tests/fixtures/odin_paths_040b2rel.txt). Run 2: bbc.com over Converge, TCP
silent from hop 3 (tests/helpers/silent_net.py until the tester's capture
becomes its fixture)."""
import asyncio
import pathlib
import random

import pytest

from helpers import odin_net, silent_net
from routemap_engine import analyse_paths, multipath
from routemap_engine.geo import Sources

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _discover(net, **kw):
    return multipath.Discoverer("bbc.com", silent_net.TARGET, net.make_transport(), clock=net.clock,
                                deadline=net.clock() + 3600, **kw).run()


# ----------------------------------------------------------------- run 2

def test_run2_the_target_behind_tcp_silence_is_reached_and_the_silence_named():
    net = silent_net.SilentNet(tcp_silent_from=3, target_hop=10)
    d = _discover(net, icmp_check=net.icmp_check)
    assert d.stopped_by == "gap" and d.silent_stop == [3, 7]
    assert d.paths and all(p.reached and p.reached_by == "full_ttl" for p in d.paths)
    assert d.tcp_silent_from == 3 and net.icmp_sent == [3, 4, 5, 6, 7]
    head = d.trace_text().splitlines()[0]
    assert "TCP SYN to port 443" in head and "30 hops max" in head and "stopped after 5 silent hops (3 to 7)" in head
    assert d.final_hop == 8


def test_run2_silent_routers_that_also_ignore_icmp_are_not_blamed_on_tcp():
    net = silent_net.SilentNet(tcp_silent_from=3, target_hop=10, icmp_answers=False)
    d = _discover(net, icmp_check=net.icmp_check)
    assert d.tcp_silent_from is None and all(p.reached for p in d.paths)


def test_run2_a_target_that_ignores_tcp_is_asked_and_reported_not_reached():
    net = silent_net.SilentNet(tcp_silent_from=3, target_hop=10, target_answers=False)
    d = _discover(net, icmp_check=net.icmp_check)
    assert all(not p.reached and p.pings_sent == multipath.PATH_PINGS for p in d.paths)


@pytest.mark.parametrize("silent_from,target_hop", [(2, 6), (3, 10), (4, 20), (6, 12)])
def test_run2_shape_generalised(silent_from, target_hop):
    net = silent_net.SilentNet(tcp_silent_from=silent_from, target_hop=target_hop)
    d = _discover(net, icmp_check=net.icmp_check)
    reachable_in_discovery = target_hop - silent_from < multipath.GAP_LIMIT
    assert all(p.reached for p in d.paths)
    if reachable_in_discovery:
        assert d.stopped_by == "complete" and all(p.reached_by == "discovery" for p in d.paths)
    else:
        assert d.tcp_silent_from == silent_from and all(p.reached_by == "full_ttl" for p in d.paths)


# ----------------------------------------------------------------- run 1

def _with_fixture(name):
    saved = (odin_net.FIXTURE, odin_net.PATHS, odin_net.PLACES, set(odin_net.UNREACHED))
    odin_net.FIXTURE = FIXTURES / name
    odin_net.PATHS, odin_net.PLACES = odin_net.parse()
    return saved


def _restore(saved):
    odin_net.FIXTURE, odin_net.PATHS, odin_net.PLACES = saved[:3]
    odin_net.UNREACHED.clear()
    odin_net.UNREACHED.update(saved[3])


class _PerPacketAt11(odin_net.Net):
    """Run 1's hop 11: per-packet balancing, every packet to either router."""
    ROUTERS = ("62.115.132.229", "62.115.132.227")

    def __init__(self):
        super().__init__()
        self.rng = random.Random(11)

    def answer(self, sock):
        flow = self.flow(sock)
        if sock.ttl == 11 and max(odin_net.PATHS[odin_net.letter_of(flow)]) > 11:
            sock.error, sock.icmp = odin_net.probe.WSAEHOSTUNREACH, odin_net._info(self.rng.choice(self.ROUTERS))
            sock.ready_at = self.clock.t + 0.22
            return
        super().answer(sock)


def test_run1_every_path_is_asked_and_hop_11_keeps_frankfurt():
    """Run 1 printed hop 11 (62.115.132.229, per-packet) with no place, while
    the earlier ODIN runs placed it in Frankfurt; and its unreached paths had
    never been asked at full TTL."""
    earlier = _with_fixture("odin_paths_040b2t3.txt")
    places = dict(odin_net.PLACES)
    _restore(earlier)
    saved = _with_fixture("odin_paths_040b2rel.txt")
    try:
        places.update(odin_net.PLACES)
        net = _PerPacketAt11()
        d = multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                 deadline=net.clock() + 3600).run()
    finally:
        _restore(saved)
    assert 11 in d.per_packet_hops
    assert all(p.pings_sent == multipath.PATH_PINGS for p in d.paths), [(p.id, p.pings_sent) for p in d.paths]

    async def ip_db(addresses):
        out = {}
        for a in addresses:
            place = places.get(a)
            if place in odin_net.CITIES:
                lat, lon = odin_net.CITIES[place]
                out[a] = {"lat": lat, "lon": lon, "city": place.split(",")[0], "cc": place.split(", ")[-1]}
        return out
    route = asyncio.run(analyse_paths(d, (14.6, 121.0), sources=Sources(hoiho=None, ip_db=ip_db, ptr=None)))
    group = next(g for g in route.paths["per_packet"] if g["hop"] == 11)
    by_addr = {h["address"]: h.get("place") for h in group["located"]}
    assert by_addr.get("62.115.132.229", "").startswith("Frankfurt"), by_addr


def test_helpers_read_fixtures_as_utf8_on_every_platform():
    """Windows CI (PR 15): run 1's fixture holds the CLI's curly quotes, and a
    helper that read it with the platform default (cp1252) failed there."""
    import re
    helpers = pathlib.Path(__file__).parent / "helpers"
    bare = [f"{p.name}:{n}" for p in sorted(helpers.glob("*.py"))
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if re.search(r"\.read_text\(\s*\)|open\([^)]*['\"]r['\"]\s*\)", line)]
    assert not bare, bare
