"""Real sockets on Windows with a reserved TCP port range in place, as on a
computer running Hyper-V, WSL 2 or Docker Desktop (CI reserves one with
netsh int ipv4 add excludedportrange, store=active, and names it in
ROUTEMAP_RESERVED_PORTS). Up to 0.8.0 the Windows prober bound each flow to
a fixed port from 40000 on, inside such a range. Prints what it saw (-s)."""
import os
import socket
import sys

import pytest

from routemap_engine import multipath, probe

RESERVED = os.environ.get("ROUTEMAP_RESERVED_PORTS")
pytestmark = pytest.mark.skipif(sys.platform != "win32" or not RESERVED,
                                reason="CI reserves a TCP port range on its Windows runner")


def _range():
    first, last = (int(x) for x in RESERVED.split("-"))
    return first, last


def test_windows_refuses_a_bind_inside_the_reserved_range_with_wsaeacces():
    first, last = _range()
    port = first + (last - first) // 2
    with socket.socket() as s, pytest.raises(OSError) as caught:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))                # what 0.8.0 did for a flow
    reason = probe.error_reason(caught.value)
    print(f"\nbind of a reserved port ({first} to {last}): {reason}, winerror "
          f"{getattr(caught.value, 'winerror', None)}, errno {caught.value.errno}")
    assert reason == "WSAEACCES 10013"


def test_paths_with_the_range_reserved_sends_every_probe_and_reaches_the_target():
    first, last = _range()
    t = probe.TcpFlowTransport("127.0.0.1")
    d = multipath.Discoverer("127.0.0.1", "127.0.0.1", t).run()
    kept = sorted(t._ports.values())
    print(f"\nPaths to 127.0.0.1 with {first} to {last} reserved: {len(d.paths)} path(s), "
          f"{d.probes_sent} probes, local failures {d.local_failures} {d.local_failure_reasons}, "
          f"flows restarted {d.flows_restarted}, ports {kept[0]} to {kept[-1]}, {d.stop_text}")
    assert d.method == "tcp-paris" and d.local_failures == 0 and d.local_failure_reasons == {}
    assert d.paths and all(p.reached for p in d.paths), d.to_dict()
    assert kept and not any(first <= port <= last for port in kept)
