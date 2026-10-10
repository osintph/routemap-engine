"""Path discovery for real (CI): on Linux through a per-flow load balancer
built in network namespaces (tests/helpers/paths_lab.sh), over IPv4 and
IPv6; on macOS to the internet. Runs only when the job sets the variables."""
import os

import pytest

from routemap_engine import multipath, probe

LAB = os.environ.get("ROUTEMAP_PATHS_LAB")
INTERNET = os.environ.get("ROUTEMAP_PATHS_TARGET")


@pytest.mark.skipif(not LAB, reason="the namespace lab runs in CI on Linux")
@pytest.mark.parametrize("target,branches", [
    ("10.78.9.9", {"10.78.2.2", "10.78.3.2"}),
    ("fd78:9::9", {"fd78:2::2", "fd78:3::2"}),
])
def test_both_paths_through_a_per_flow_balancer_are_found(target, branches):
    d = multipath.discover(target)
    assert {p.hops[1] for p in d.paths} == branches, d.to_dict()
    assert all(p.hops[0] in ("10.78.0.2", "fd78::2") and p.hops[-1] == target for p in d.paths)
    assert all(p.reached and p.pings_sent == 10 and p.pings_lost == 0 for p in d.paths)
    assert d.per_packet_hops == [] and d.probes_sent <= multipath.MAX_PROBES


@pytest.mark.skipif(not LAB, reason="the namespace lab runs in CI on Linux")
@pytest.mark.parametrize("target", ["10.78.9.9", "fd78:9::9"])
def test_every_flow_stays_on_one_branch_and_flows_spread_over_both(target):
    """Paris holds the hashed fields: six probes of one flow take one branch,
    and different flows take both."""
    import time
    t = probe.FlowTransport(target)
    branch_of = {}
    try:
        seq = 100
        for flow in range(12):
            seen = set()
            for _ in range(6):
                seq += 1
                t.send(flow, 2, seq)
                end = time.perf_counter() + 1.0
                while time.perf_counter() < end:
                    got = [a for a in t.read(end - time.perf_counter()) if a.seq == seq]
                    if got:
                        seen.add(got[0].address)
                        break
            assert len(seen) == 1, (flow, seen)
            branch_of[flow] = seen.pop()
    finally:
        t.close()
    assert len(set(branch_of.values())) == 2, branch_of


@pytest.mark.skipif(not INTERNET, reason="an internet run happens in CI on macOS")
def test_a_real_discovery_stays_inside_its_caps():
    ok, why = multipath.available()
    assert ok, why
    d = multipath.discover(INTERNET, options=multipath.Options(budget=600))
    assert d.paths and d.probes_sent <= 600 and d.flows_used >= 9
    print(d.to_dict())
