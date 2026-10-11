"""The Windows TCP flow prober's sockets on a real multi-homed host: the CI
runner (its own uplink, plus a link into the namespace lab). Probes to the
lab's target must leave from the lab link's address, never another one.
Runs when CI has started tests/helpers/tcp_listener.py in the target
namespace (ROUTEMAP_TCP_LAB_LOG)."""
import json
import os
import subprocess
import time

import pytest

from routemap_engine import probe

LOG = os.environ.get("ROUTEMAP_TCP_LAB_LOG")
PORT = int(os.environ.get("ROUTEMAP_TCP_LAB_PORT", "8443"))
pytestmark = pytest.mark.skipif(not LOG, reason="needs the namespace lab and its TCP listener (CI, Linux)")


def _host_addresses() -> set[str]:
    data = json.loads(subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, check=True).stdout)
    return {a["local"] for i in data for a in i.get("addr_info", []) if a.get("scope") == "global"}


@pytest.mark.parametrize("dst", ["10.78.9.9", "fd78:9::9"])
def test_probes_leave_from_the_routed_interface_not_another(dst):
    addresses = _host_addresses()
    routed = probe._source_for(dst)
    family = [a for a in addresses if (":" in a) == (":" in dst)]
    assert routed in family and len(family) >= 2, f"not multi-homed for this family: {family}"
    before = open(LOG).read().splitlines() if os.path.exists(LOG) else []
    t = probe.TcpFlowTransport(dst, port=PORT)
    t.send(5, 64, 1)
    sock = next(iter(t._open.values()))[0]
    assert sock.getsockname()[:2] == (routed, t.sport(5))
    with open(f"/proc/net/tcp{'6' if ':' in dst else ''}") as table:      # never LISTEN (state 0A)
        assert not [r for r in table.read().splitlines()[1:]
                    if int(r.split()[1].split(":")[1], 16) == t.sport(5) and r.split()[3] == "0A"]
    got = []
    end = time.monotonic() + 5
    while not got and time.monotonic() < end:
        got = t.read(0.2)
    assert [(a.address, a.reached) for a in got] == [(dst, True)]
    time.sleep(0.3)
    new = open(LOG).read().splitlines()[len(before):]
    peers = {line.split()[0] for line in new}
    assert peers == {routed}, (peers, addresses)
    assert {line.split()[1] for line in new} == {str(t.sport(5))}
    assert not peers & (set(family) - {routed})
    t.close()
