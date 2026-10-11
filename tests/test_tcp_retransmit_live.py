"""Windows, real sockets: a probe socket sends one SYN. A connect to a
blackholed address (192.0.2.1, TEST-NET-1) with the prober's options gives
up within a few seconds; with retransmissions on it took 21.0 s (CI,
11 Oct 2026)."""
import socket
import sys
import time

import pytest

from routemap_engine import probe

pytestmark = pytest.mark.skipif(not sys.platform.startswith("win"), reason="the Windows TCP prober's option")


def test_one_syn_then_give_up():
    s = socket.socket()
    assert probe.no_syn_retransmissions(s), "Windows refused SIO_TCP_INITIAL_RTO"
    s.settimeout(30)
    t = time.perf_counter()
    with pytest.raises(OSError):
        s.connect(("192.0.2.1", 443))
    elapsed = time.perf_counter() - t
    s.close()
    print(f"\nblackhole connect with no SYN retransmissions: gave up after {elapsed:.1f} s")
    assert elapsed < 5.0, elapsed
