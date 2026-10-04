"""The built-in ICMP prober: its output format, and (in CI, per platform) a
real run. The live part runs only when ROUTEMAP_PROBE_TARGET is set:
  macOS runner: a real trace to the internet;
  Linux runner: a trace through a router built in network namespaces;
  Windows runner: a trace to loopback (the runner's network drops ICMP)."""
import os

import pytest

from routemap_engine import parse_trace, probe
from routemap_engine.probe import Reply


def test_a_hop_with_two_responders_is_printed_as_bsd_ecmp_and_parsed_back():
    lines = probe.format_hop(7, [Reply("62.115.186.138", 61.9), Reply("62.115.112.222", 62.0),
                                 Reply("62.115.112.222", 61.877)])
    assert lines == [" 7  62.115.186.138  61.900 ms", "    62.115.112.222  62.000 ms  61.877 ms"]
    text = "traceroute to x (1.1.1.1), 30 hops max, 40 byte packets\n" + "\n".join(lines) + "\n"
    hop = parse_trace(text).hops[0]
    assert hop.addresses == ["62.115.186.138", "62.115.112.222"] and len(hop.rtts_ms) == 3


def test_silent_probes_and_a_silent_hop():
    assert probe.format_hop(3, [Reply(None, None)] * 3) == [" 3  * * *"]
    assert probe.format_hop(12, [Reply(None, None), Reply("82.98.102.1", 258.3), Reply(None, None)]) == \
        ["12  * 82.98.102.1  258.300 ms *"]


def test_the_same_defaults_as_the_system_tools():
    from routemap_engine.runner import DEFAULT_FLAGS, TOOL_ICMP, TOOL_TRACEROUTE
    assert DEFAULT_FLAGS[TOOL_ICMP] == DEFAULT_FLAGS[TOOL_TRACEROUTE] == ["-m", "30", "-q", "3", "-w", "1"]
    assert (probe.MAX_HOPS, probe.QUERIES, probe.WAIT_SECONDS) == (30, 3, 1.0)


@pytest.mark.skipif(not os.environ.get("ROUTEMAP_PROBE_TARGET"), reason="live probe runs in CI per platform")
def test_a_real_trace_with_the_built_in_prober():
    target = os.environ["ROUTEMAP_PROBE_TARGET"]
    ok, why = probe.available()
    assert ok, why
    text, cancelled, timed_out = probe.trace(target, max_hops=int(os.environ.get("ROUTEMAP_PROBE_HOPS", "30")))
    print(text)
    parsed = parse_trace(text)
    assert parsed.parser == "icmp" and parsed.hops and not cancelled and not timed_out
    expect = int(os.environ.get("ROUTEMAP_PROBE_MIN_HOPS", "1"))
    answered = [h for h in parsed.hops if h.addresses]
    assert len(answered) >= expect, text
    if os.environ.get("ROUTEMAP_PROBE_ROUTER"):
        assert parsed.hops[0].addresses == [os.environ["ROUTEMAP_PROBE_ROUTER"]], "the router's time exceeded"
        assert parsed.hops[-1].addresses == [target], "the target's echo reply"
