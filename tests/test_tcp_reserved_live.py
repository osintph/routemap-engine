"""Real sockets on Windows: which fixed source ports Windows refuses. Up to
0.8.0 the Windows prober bound each flow to a fixed port, 40000 plus a random
base plus the flow, with SO_REUSEADDR, and the engine CI's Windows runners
refused one now and then ("local failures 12" of 12, the error discarded).

The first CI run of 0.8.1 (26 Oct 2026) showed that a port range reserved
with netsh int ipv4 add excludedportrange is not what refused them: the
runner reserves no range there, and an SO_REUSEADDR bind into a reserved
range was not refused. A port another socket holds with exclusive use is
refused (WSAEACCES), and 0.8.0's ports overlap Windows' dynamic range
(49152 on), where other programs' connections hold ports. Either way the
system's own choice, a bind to port 0, is never refused. Prints what it saw
(-s). CI reserves a range and names it in ROUTEMAP_RESERVED_PORTS."""
import os
import socket
import sys

import pytest

from routemap_engine import multipath, probe

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows sockets")
RESERVED = os.environ.get("ROUTEMAP_RESERVED_PORTS")


def _bind(port, reuse=True):
    """What a bind to 127.0.0.1:*port* gets: "ok" or the error's name and code."""
    with socket.socket() as s:
        if reuse:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError as exc:
            return probe.error_reason(exc)
    return "ok"


def test_a_fixed_port_another_socket_holds_exclusively_is_refused_with_wsaeacces():
    with socket.socket() as holder:
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        got = _bind(port)                          # what 0.8.0 did for a flow
    print(f"\nSO_REUSEADDR bind of a port another socket holds exclusively: {got}")
    assert got == "WSAEACCES 10013"


@pytest.mark.skipif(not RESERVED, reason="CI reserves a TCP port range on its Windows runner")
def test_the_system_never_hands_out_a_reserved_port():
    first, last = (int(x) for x in RESERVED.split("-"))
    middle = first + (last - first) // 2
    print(f"\nbind inside the reserved range {first} to {last}: with SO_REUSEADDR {_bind(middle)}, "
          f"without {_bind(middle, reuse=False)}")
    given = []
    for _ in range(200):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            given.append(s.getsockname()[1])
    assert not any(first <= p <= last for p in given)


@pytest.mark.skipif(not RESERVED, reason="CI reserves a TCP port range on its Windows runner")
def test_paths_with_a_range_reserved_sends_every_probe_and_reaches_the_target():
    first, last = (int(x) for x in RESERVED.split("-"))
    t = probe.TcpFlowTransport("127.0.0.1")
    d = multipath.Discoverer("127.0.0.1", "127.0.0.1", t).run()
    kept = sorted(t._ports.values())
    print(f"\nPaths to 127.0.0.1 with {first} to {last} reserved: {len(d.paths)} path(s), "
          f"{d.probes_sent} probes, local failures {d.local_failures} {d.local_failure_reasons}, "
          f"flows restarted {d.flows_restarted}, ports {kept[0]} to {kept[-1]}, {d.stop_text}")
    assert d.method == "tcp-paris" and d.local_failures == 0 and d.local_failure_reasons == {}
    assert d.paths and all(p.reached for p in d.paths), d.to_dict()
    assert kept and not any(first <= port <= last for port in kept)
