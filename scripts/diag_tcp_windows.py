"""Diagnostics for the Windows TCP flow prober, run on the CI Windows runner
(probe job). Prints measurements; asserts nothing.

1. Does the no-SYN-retry option stop retransmissions? A connect to a
   blackholed address (192.0.2.1, TEST-NET-1) with our options: how long
   until Windows gives up, against a plain socket.
2. Does a port answer after an earlier attempt from it died unanswered? A
   probe at TTL 2 (it dies in the runner's network), given up after 1 s,
   then the same port at TTL 64 to the target; against fresh ports.
"""
import socket
import statistics
import struct
import sys
import time

from routemap_engine import probe


def blackhole(options: bool) -> float:
    s = socket.socket()
    if options:
        s.setsockopt(socket.IPPROTO_TCP, probe.TCP_NOSYNRETRIES, 1)
        s.setsockopt(socket.IPPROTO_TCP, probe.TCP_FAIL_CONNECT_ON_ICMP_ERROR, 1)
    s.settimeout(30)
    t = time.perf_counter()
    try:
        s.connect(("192.0.2.1", 443))
        r = "connected?!"
    except OSError as e:
        r = f"winerror {getattr(e, 'winerror', None) or e.errno}"
    elapsed = time.perf_counter() - t
    s.close()
    print(f"blackhole connect, {'with' if options else 'without'} our options: gave up after {elapsed:.1f} s ({r})",
          flush=True)
    return elapsed


def answers(dst: str, after_dead: bool, n: int = 10) -> None:
    t = probe.TcpFlowTransport(dst, reuse_gap=0.0)
    got, rtts, seq = 0, [], 0
    for flow in range(n):
        if after_dead:
            seq += 1
            t.send(flow, 2, seq)
            end = time.perf_counter() + 1.0
            while time.perf_counter() < end:
                t.read(0.05)
            t.forget(seq)
        seq += 1
        sent = time.perf_counter()
        t.send(flow, 64, seq)
        end = sent + 3.0
        while time.perf_counter() < end:
            hit = [a for a in t.read(0.02) if a.seq == seq]
            if hit:
                got += 1
                rtts.append((hit[0].at - sent) * 1000)
                break
        t.forget(seq)
        time.sleep(0.2)
    t.close()
    med = f", median {statistics.median(rtts):.0f} ms, slowest {max(rtts):.0f} ms" if rtts else ""
    print(f"{dst}: {'after an unanswered TTL 2 attempt' if after_dead else 'fresh ports'}: "
          f"{got} of {n} answered within 3 s{med}", flush=True)


if __name__ == "__main__":
    print(sys.version, sys.platform, flush=True)
    blackhole(True)
    blackhole(False)
    for dst in ("1.1.1.1", "193.99.144.80"):
        answers(dst, after_dead=False)
        answers(dst, after_dead=True)
