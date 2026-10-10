"""The built-in prober over IPv6, for real (CI): through the Linux namespace
lab, and to loopback on macOS and Windows (on Windows this also checks the
ICMPV6_ECHO_REPLY layout: the address read back must be ::1)."""
import os

import pytest

from routemap_engine import parse_trace, probe

TARGET6 = os.environ.get("ROUTEMAP_PROBE_TARGET6")


@pytest.mark.skipif(not TARGET6, reason="the live IPv6 probe runs in CI per platform")
def test_a_real_ipv6_trace_with_the_built_in_prober():
    ok, why = probe.available(6)
    assert ok, why
    text, cancelled, timed_out = probe.trace(TARGET6, max_hops=6, family="6")
    assert not cancelled and not timed_out, text
    hops = parse_trace(text).hops
    assert hops[-1].addresses == [str(__import__("ipaddress").ip_address(TARGET6))], text
    assert len(hops) == int(os.environ.get("ROUTEMAP_PROBE_HOPS6", "1")), text
