"""Paths over silent stretches (0.8.0), on generated networks: the Converge
run of 0.4.0-beta.2 (bbc.com over AS17639, TCP probes unanswered from hop 3,
the target "not reached; last answer hop 2" after 3 silent hops, while an
ICMP trace on the same machine reached it in 10 hops) is one instance of each
class tested here. Every test failed on engine 0.7.1 (main 6b478e4)."""
import asyncio
import random

import pytest

from routemap_engine import analyse_paths, multipath
from routemap_engine.geo import Sources
from helpers.lab import Lab

DST = "151.101.0.81"


def run(topology, *, silent=(), icmp=None, seed=0, options=None):
    lab = Lab(topology, seed=seed, silent=silent)
    check = None
    if icmp is not None:
        def check(ttl):
            # The router a probe of flow 0 meets at *ttl*, if ICMP gets an answer from it.
            route = lab.path(0)
            hop = route[min(ttl, len(route)) - 1]
            return hop if isinstance(hop, str) and icmp(hop) else None
    extra = {} if check is None else {"icmp_check": check}     # 0.7.1 had no such argument
    d = multipath.Discoverer("bbc.com", DST, lab, options=options, clock=lab.clock, **extra).run()
    return d, lab


def silent_net(first: int, length: int, total: int):
    """Routers r1.. r{total}, the target after them; hops first..first+length-1 never answer."""
    routers = [f"r{i}" for i in range(1, total + 1)]
    silent = {f"r{i}" for i in range(first, first + length)}
    return routers + [DST], silent


SHAPES = [(first, length) for first in (1, 2, 3, 6) for length in (1, 3, 4, 5, 6, 8)]


@pytest.mark.parametrize("first,length", SHAPES, ids=[f"from{f}x{n}" for f, n in SHAPES])
def test_a_target_behind_any_silent_stretch_is_asked_and_reached(first, length):
    """D1, D2: whatever the stretch, the target is asked at full TTL and, as it
    answers, every path is reached; none reads "not reached"."""
    topo, silent = silent_net(first, length, first + length + 2)
    d, lab = run(topo, silent=silent)
    assert any(t == multipath.PING_HOPS for _, _, t in lab.sent), "the target was never asked"
    assert d.paths and all(p.reached for p in d.paths), [(p.id, p.reached) for p in d.paths]


@pytest.mark.parametrize("length", [5, 6, 8])
def test_a_stretch_of_five_or_more_stops_discovery_and_marks_the_gap(length):
    """D2, D3: five silent hops end the discovery, the header says so, and the
    target's full-TTL answer is numbered after the last hop sent."""
    topo, silent = silent_net(3, length, 3 + length + 2)
    d, _ = run(topo, silent=silent)
    assert d.stopped_by == "gap" and d.silent_stop == [3, 7]
    assert "stopped after 5 silent hops (3 to 7)" in d.trace_text().splitlines()[0]
    assert d.final_hop == 8
    for p in d.paths:
        assert p.reached_by == "full_ttl" and p.silent == [3, 7] and p.hops[-1] == DST and len(p.hops) == 8
    rows = {int(line.split()[0]) for line in d.trace_text().splitlines()[1:] if DST in line}
    assert rows == {8}


@pytest.mark.parametrize("length", [1, 2, 3, 4])
def test_fewer_than_five_silent_hops_do_not_stop_discovery(length):
    """D3: 3 or 4 silent hops ended 0.7.1's discovery; now the routers after them are found."""
    topo, silent = silent_net(3, length, 3 + length + 2)
    d, _ = run(topo, silent=silent)
    assert d.stopped_by == "complete" and d.silent_stop is None
    after = f"r{3 + length}"
    assert after in d.responders.get(3 + length, []), d.responders


def test_a_target_that_never_answers_is_not_reached_but_was_asked():
    topo, silent = silent_net(3, 6, 10)
    d, lab = run(topo, silent=silent | {DST})
    pings = [t for _, _, t in lab.sent if t == multipath.PING_HOPS]
    assert len(pings) == multipath.PATH_PINGS * len(d.paths)
    assert all(not p.reached and p.pings_sent == multipath.PATH_PINGS and p.pings_lost == p.pings_sent
               for p in d.paths)


@pytest.mark.parametrize("from_hop", [2, 3, 5])
def test_a_network_silent_to_tcp_but_answering_icmp_is_named(from_hop):
    """D4: TCP silent from hop N on, one ICMP check per silent hop, answered: named."""
    topo, silent = silent_net(from_hop, 7, from_hop + 8)
    d, lab = run(topo, silent=silent, icmp=lambda hop: True)
    assert d.tcp_silent_from == from_hop
    assert sorted(d.icmp_checks) == list(range(from_hop, from_hop + 5))
    # The checks are probes: counted, and never over the rate.
    assert d.probes_sent == len(lab.sent) + len(d.icmp_checks)


def test_routers_that_answer_nothing_are_not_called_tcp_silent():
    topo, silent = silent_net(3, 7, 11)
    d, _ = run(topo, silent=silent, icmp=lambda hop: False)
    assert d.tcp_silent_from is None and set(d.icmp_checks.values()) == {None}


def test_no_icmp_check_runs_without_a_checker():
    topo, silent = silent_net(3, 7, 11)
    d, _ = run(topo, silent=silent)
    assert d.icmp_checks == {} and d.tcp_silent_from is None


def test_the_header_names_the_method_and_the_hop_limit_not_the_last_answer():
    """D5: 0.7.1 wrote "2 hops max" and "ICMP echo" for a TCP run that stopped on silence."""
    topo, silent = silent_net(3, 7, 11)

    class Tcp(Lab):
        METHOD = "tcp-paris"
    lab = Tcp(topo, silent=silent)
    d = multipath.Discoverer("bbc.com", DST, lab, clock=lab.clock).run()
    head = d.trace_text().splitlines()[0]
    assert "30 hops max" in head and "TCP SYN to port 443" in head and "ICMP" not in head, head
    assert d.to_dict()["resolved"] == {"name": "bbc.com", "address": DST, "family": 4}


def test_generated_silences_never_break_the_caps():
    rng = random.Random(7)
    for _ in range(40):
        total = rng.randint(4, 20)
        first = rng.randint(1, total - 1)
        topo, silent = silent_net(first, rng.randint(1, total - first), total)
        for budget in (1500, 200):
            d, lab = run(topo, silent=silent, icmp=lambda hop: rng.random() < 0.5,
                         options=multipath.Options(budget=budget))
            assert d.probes_sent <= budget


# ------------------------------------------------- D7: per-packet placement

PLACES = {"62.115.132.229": (50.11, 8.68, "Frankfurt", "DE"), "62.115.132.227": (50.11, 8.68, "Frankfurt", "DE"),
          "62.115.124.60": (50.11, 8.68, "Frankfurt", "DE"), "80.81.192.1": (50.11, 8.68, "Frankfurt", "DE"),
          "5.56.18.114": (49.05, 12.09, "Lappersdorf", "DE"), "62.115.122.27": (43.3, 5.37, "Marseille", "FR")}


async def _ip_db(addresses):
    return {a: {"lat": PLACES[a][0], "lon": PLACES[a][1], "city": PLACES[a][2], "cc": PLACES[a][3]}
            for a in addresses if a in PLACES}


@pytest.mark.parametrize("routers", [["62.115.132.229", "62.115.132.227"],
                                     ["62.115.132.229", "62.115.132.227", "62.115.124.60"],
                                     ["5.56.18.114", "62.115.122.27"]], ids=["two", "three", "far-apart"])
def test_every_router_at_a_per_packet_hop_keeps_its_place(routers):
    """D7 (run 1, hop 11 62.115.132.229 unplaced): a per-packet hop's routers
    are on no path row, and its main row has several addresses, so 0.7.1 had
    no evidence left and placed none of them."""
    topo = ["80.81.192.1", ("packet", routers), "62.115.124.60", DST]
    d, _ = run(topo, seed=5)
    assert d.per_packet_hops == [2]
    route = asyncio.run(analyse_paths(d, (50.0, 8.6), sources=Sources(hoiho=None, ip_db=_ip_db, ptr=None)))
    entries = [h for h in route.hops if h.get("hop") == 2]
    entries += [h for p in route.paths["paths"] for h in p["located"] if h.get("hop") == 2]
    entries += [h for g in route.paths.get("per_packet", []) for h in g["located"]]
    placed = {h["address"]: h.get("place") for h in entries if h.get("address") and h.get("lat") is not None
              and len(h.get("addresses") or [h["address"]]) == 1}
    seen = set(d.responders[2])
    assert seen and all(placed.get(a) for a in seen), (seen, placed)
