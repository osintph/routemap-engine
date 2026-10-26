"""The ODIN Paths run of 11 Oct 2026 (0.4.0-beta.1, FAIL), replayed through
the real Windows TCP prober (tests/helpers/odin_net.py). Each test is one of
the faults that run showed; each failed on the code that produced it."""
import asyncio

import pytest

from helpers import odin_net
from routemap_engine import analyse_paths, multipath
from routemap_engine.geo import Sources


def _run():
    net = odin_net.Net()
    progress = []
    import time
    from routemap_engine import probe
    try:
        d = multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                 deadline=net.clock() + 3600, on_progress=progress.append).run()
    finally:
        probe.time = time
    return net, d, progress


@pytest.fixture(scope="module")
def run():
    return _run()


def _truth(m):
    """The paths the replayed network has for flows 0..m-1, worked out here
    without the discoverer's code: distinct true sequences, merged only where
    one has a silent router and the other an answer."""
    seqs = sorted({odin_net.true_sequence(f) for f in range(m)}, key=repr)
    merged = []
    for s in seqs:
        for i, r in enumerate(merged):
            if len(r) == len(s) and all(a is None or b is None or a == b for a, b in zip(r, s)):
                merged[i] = tuple(a if a is not None else b for a, b in zip(r, s))
                break
        else:
            merged.append(s)
    return merged


def test_1_paths_differ_only_where_two_flows_got_different_answers(run):
    net, d, progress = run
    truth = _truth(d.flows_used)
    assert len(d.paths) == min(len(truth), multipath.MAX_PATHS), (len(d.paths), len(truth))
    for i, a in enumerate(d.paths):
        for b in d.paths[i + 1:]:
            assert any(x and y and x != y for x, y in zip(a.hops, b.hops)) or len(a.hops) != len(b.hops), \
                (a.id, b.id, "differ nowhere both answered")
    # The progress count is the same grouping, never a count of silences.
    assert max(p["paths"] for p in progress) <= len(truth)


def test_3_a_flow_ends_at_the_target_once(run):
    net, d, _ = run
    for p in d.paths:
        assert p.hops.count(odin_net.TARGET) == 1 and p.hops[-1] == odin_net.TARGET, (p.id, p.hops)
    ends = {len(p.hops) for p in d.paths}
    assert ends <= {13, 14, 15}
    rows = [line.split()[0] for line in d.trace_text().splitlines()[1:] if odin_net.TARGET in line]
    assert {int(r) for r in rows} == ends, rows


def test_5_time_stays_near_the_rate_cap(run):
    """1,500 probes at 20 a second is 75 s of sending; waits for silent
    probes overlap with sending. The 0.4.0-beta.1 run took 342 s for 1,453."""
    net, d, _ = run
    floor = d.probes_sent / multipath.MAX_RATE
    assert d.seconds <= floor * 1.6 + 20, (d.seconds, d.probes_sent)


def test_6_the_targets_reuse_limit_is_not_reported_as_loss(run):
    net, d, _ = run
    for p in d.paths:
        if p.reached:
            assert p.pings_sent == multipath.PATH_PINGS and p.pings_lost == 0, (p.id, p.pings_lost)
    assert d.local_failures == 0


def test_2_one_address_one_placement(run):
    """The IP database puts 62.115.153.153 in Chicago; between Frankfurt hops
    that is a detour the RTT rules out, on every row it appears on, main or
    path. Every address shows one placement in the whole run."""
    net, d, _ = run

    async def ip_db(addresses):
        out = {}
        for a in addresses:
            place = odin_net.PLACES.get(a)
            if a == "62.115.153.153":
                place = "Chicago, US"
            if place in odin_net.CITIES:
                lat, lon = odin_net.CITIES[place]
                out[a] = {"lat": lat, "lon": lon, "city": place.split(",")[0], "cc": place.split(", ")[-1]}
        return out
    route = asyncio.run(analyse_paths(d, (14.6, 121.0), sources=Sources(hoiho=None, ip_db=ip_db, ptr=None)))
    seen: dict[str, set] = {}
    for h in route.hops:
        seen.setdefault(h["address"], set()).add((h.get("place"), h.get("source")))
    for p in route.paths["paths"]:
        for h in p["located"]:
            if h.get("address"):
                seen.setdefault(h["address"], set()).add((h.get("place"), h.get("source")))
    split = {a: v for a, v in seen.items() if a and len(v) > 1}
    assert not split, split
    assert all(place != "Chicago, US" for place, _src in seen["62.115.153.153"]), seen["62.115.153.153"]


class _ShyTarget(odin_net.Net):
    """The replayed network, but the target ignores each flow's first two
    connection attempts (whatever the cause; on ODIN the target answered
    hops after the path's last router)."""

    def __init__(self):
        super().__init__()
        self.tries: dict[int, int] = {}

    def answer(self, sock):
        flow = self.flow(sock)
        end = max(odin_net.PATHS[odin_net.letter_of(flow)])
        if sock.ttl >= end and sock.ttl != 64:
            self.tries[flow] = self.tries.get(flow, 0) + 1
            if self.tries[flow] <= 2:
                return
        super().answer(sock)


def test_3_silences_at_the_targets_hop_do_not_move_the_target():
    import time
    from routemap_engine import probe
    net = _ShyTarget()
    try:
        d = multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                 deadline=net.clock() + 3600).run()
    finally:
        probe.time = time
    true_ends = {max(odin_net.PATHS[odin_net.letter_of(f)]) for f in range(d.flows_used)}
    rows = {int(line.split()[0]) for line in d.trace_text().splitlines()[1:] if odin_net.TARGET in line}
    assert rows == true_ends, (rows, true_ends)
    for p in d.paths:
        assert p.hops.count(odin_net.TARGET) == 1, (p.id, p.hops)


class _Retransmits(odin_net.Net):
    """The 0.4.0-beta.2 test build on ODIN: the target ignored some first SYNs
    and Windows sent them again about 1 s later, so the answer came 1.25 s
    after the probe (13a 808.5 ms, 14a 1322.1 ms in the hop table, against
    about 250 ms for the paths)."""

    def __init__(self):
        super().__init__()
        self.seen: set[int] = set()

    def answer(self, sock):
        flow = self.flow(sock)
        end = max(odin_net.PATHS[odin_net.letter_of(flow)])
        if sock.ttl >= end and flow % 3 == 0 and flow not in self.seen:
            self.seen.add(flow)
            sock.error, sock.ready_at = 0, self.clock.t + 1.25      # the retransmission answered
            return
        super().answer(sock)


def test_a_a_retransmitted_answer_does_not_time_the_hop():
    import time
    from routemap_engine import probe
    net = _Retransmits()
    try:
        d = multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                 deadline=net.clock() + 3600).run()
    finally:
        probe.time = time
    target_rtts = [r for (ttl, a), rs in d.rtts.items() if a == odin_net.TARGET for r in rs]
    assert target_rtts and max(target_rtts) <= 1000.0, sorted(target_rtts)[-5:]
    for line in d.trace_text().splitlines()[1:]:
        if odin_net.TARGET in line:
            assert all(float(x) < 1000 for x in __import__("re").findall(r"(\d+\.\d+) ms", line)), line


def test_2_a_hop_with_several_routers_is_placed_by_its_own_router():
    """A merged row's first hostname can be another router's (the first name
    found at the hop); its placement must come from its own address's rows.
    The ODIN run 3 replay, every address: one placement."""
    import pathlib
    import time
    from routemap_engine import probe
    saved = (odin_net.FIXTURE, odin_net.PATHS, odin_net.PLACES, set(odin_net.UNREACHED))
    odin_net.FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "odin_paths_040b2t3.txt"
    odin_net.PATHS, odin_net.PLACES = odin_net.parse()
    try:
        net = odin_net.Net()
        try:
            d = multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                     deadline=net.clock() + 3600).run()
        finally:
            probe.time = time
        names = {"62.115.140.40": "mei-b6-link.ip.twelve99.net", "62.115.139.44": "sng-b6-link.ip.twelve99.net",
                 "62.115.137.184": "sng-b7-link.ip.twelve99.net"}

        async def ptr(addresses):
            return {a: n for a, n in names.items() if a in addresses}

        async def ip_db(addresses):
            out = {}
            for a in addresses:
                place = odin_net.PLACES.get(a)
                if place in odin_net.CITIES:
                    lat, lon = odin_net.CITIES[place]
                    out[a] = {"lat": lat, "lon": lon, "city": place.split(",")[0], "cc": place.split(", ")[-1]}
            return out
        route = asyncio.run(analyse_paths(d, (14.68, 121.04), sources=Sources(hoiho=None, ip_db=ip_db, ptr=ptr)))
    finally:
        odin_net.FIXTURE, odin_net.PATHS, odin_net.PLACES = saved[:3]
        odin_net.UNREACHED.clear()
        odin_net.UNREACHED.update(saved[3])
    seen: dict[str, set] = {}
    for h in route.hops + [x for p in route.paths["paths"] for x in p["located"]]:
        if h.get("address"):
            seen.setdefault(h["address"], set()).add((h.get("place"), h.get("source")))
    assert not {a: v for a, v in seen.items() if len(v) > 1}
    assert seen["62.115.140.40"] == {("Marseille, FR", "site-code")}, seen["62.115.140.40"]


def test_8_a_paths_hop_keeps_the_ip_databases_provider(run):
    """The app labels an IP database placement by provider ("ip-db (DB-IP)");
    a path's hop lost it and read "RIPEstat, online" beside its own row."""
    net, d, _ = run

    async def ip_db(addresses):
        return {a: {"lat": 50.11, "lon": 8.68, "city": "Frankfurt", "cc": "DE", "provider": "dbip"}
                for a in addresses if a.startswith("82.98.")}
    route = asyncio.run(analyse_paths(d, (14.6, 121.0), sources=Sources(hoiho=None, ip_db=ip_db, ptr=None)))
    located = [h for p in route.paths["paths"] for h in p["located"] if (h.get("address") or "").startswith("82.98.")]
    assert located and all(h.get("ip_provider") == "dbip" for h in located if h.get("source") == "ip-db")


def test_a_a_paths_hops_get_their_asn_from_the_offline_database():
    """ODIN test build 4: the Paths view showed no AS numbers at all; a
    path's hop has one ``address``, and the enrichment read only
    ``addresses``."""
    from types import SimpleNamespace
    from routemap_engine import osint

    class Db:
        def lookup(self, addr):
            if not addr.startswith("62.115."):
                return None
            return SimpleNamespace(asn=1299, org="Arelion Sweden AB", network="62.115.0.0/16")
    located = [{"hop": 7, "address": "62.115.112.222"}, {"hop": 8, "address": None}]
    osint.enrich_offline({"hops": located}, Db())
    assert located[0]["asn"] == 1299 and "asn" not in located[1]


def _replay(fixture, **options):
    import pathlib
    import time
    from routemap_engine import probe
    saved = (odin_net.FIXTURE, odin_net.PATHS, odin_net.PLACES, set(odin_net.UNREACHED))
    odin_net.FIXTURE = pathlib.Path(__file__).parent / "fixtures" / fixture
    odin_net.PATHS, odin_net.PLACES = odin_net.parse()
    try:
        net = odin_net.Net()
        try:
            return multipath.Discoverer("heise.de", odin_net.TARGET, net.make_transport(), clock=net.clock,
                                        deadline=net.clock() + 3600,
                                        options=multipath.Options(**options)).run()
        finally:
            probe.time = time
    finally:
        odin_net.FIXTURE, odin_net.PATHS, odin_net.PLACES = saved[:3]
        odin_net.UNREACHED.clear()
        odin_net.UNREACHED.update(saved[3])


def test_b_a_run_that_reaches_the_cap_still_gives_every_path_its_ten_attempts():
    """ODIN test build 4 read "6 of 7", "7 of 7", "3 of 7" beside a note
    promising ten: the budget ran out during the pings. The discovery now
    leaves the pings their share, inside the same cap."""
    d = _replay("odin_paths_040b2t4.txt", budget=1300)
    assert d.stopped_by == "budget" and d.probes_sent <= 1300
    reached = [p for p in d.paths if p.reached]
    assert reached and all(p.pings_sent == multipath.PATH_PINGS for p in reached), \
        [(p.id, p.pings_sent) for p in reached]


@pytest.mark.parametrize("budget", [1500, 1300, 900])
def test_every_probe_sent_stays_within_the_cap(budget):
    """ODIN test build 5 printed "stopped at the 1,450-probe cap": the total
    sent, under a cap of 1,500. Discovery plus target attempts never pass the
    cap; discovery's own share is recorded apart."""
    d = _replay("odin_paths_040b2t4.txt", budget=budget)
    assert d.probes_sent <= budget and d.budget == budget
    assert d.discovery_probes <= d.probes_sent
    pings = sum(p.pings_sent for p in d.paths)
    assert d.probes_sent == d.discovery_probes + pings
    if d.stopped_by == "budget":
        assert d.discovery_probes <= budget - min(multipath.PATH_PINGS * multipath.MAX_PATHS, budget // 3)
