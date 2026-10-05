"""The built-in prober believes only replies to its own probe (RM-10), and its
-m/-q/-w values and Stop are bounded per probe (RM-12)."""
import socket
import struct
import threading

import pytest

from routemap_engine import probe

TARGET, ROUTER, STRANGER = "192.0.2.9", "198.51.100.1", "203.0.113.7"


def icmp(kind, seq, ident=0x1234, payload=b""):
    return struct.pack("!BBHHH", kind, 0, 0, ident, seq) + payload


def ipv4(dst, src="192.0.2.50"):
    return bytes([0x45, 0, 0, 28, 0, 0, 0, 0, 1, 1, 0, 0]) + socket.inet_aton(src) + socket.inet_aton(dst)


def error(kind, quoted_dst, quoted_type, seq, quoted_len=8):
    inner = ipv4(quoted_dst) + struct.pack("!BBHHH", quoted_type, 0, 0, 0x1234, seq)[:quoted_len]
    return struct.pack("!BBHI", kind, 0, 0, 0) + inner


class FakeSocket:
    """Delivers the queued (packet, source) pairs, then nothing."""
    queue: list = []

    def __init__(self, *a, **k):
        self.sent = []

    def setsockopt(self, *a):
        pass

    def setblocking(self, flag):
        pass

    def sendto(self, data, addr):
        FakeSocket.sent_seq = struct.unpack("!H", data[6:8])[0]

    def recvfrom(self, size):
        if not FakeSocket.queue:
            raise BlockingIOError
        build, source = FakeSocket.queue.pop(0)
        return build(FakeSocket.sent_seq), (source, 0)

    def close(self):
        pass


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setattr(probe.socket, "socket", FakeSocket)
    monkeypatch.setattr(probe.sys, "platform", "darwin")
    import select
    monkeypatch.setattr(select, "select", lambda r, w, x, t: (r, [], []))
    return FakeSocket


def answer(fake, *packets):
    fake.queue = list(packets)
    return probe._posix_probe(TARGET, ttl=5, seq=4242, wait=0.15)


@pytest.mark.parametrize("label,packet", [
    ("echo reply from someone else", (lambda s: icmp(0, s), STRANGER)),
    ("echo reply for another probe", (lambda s: icmp(0, s + 1), TARGET)),
    ("time exceeded with 4 quoted bytes", (lambda s: error(11, TARGET, 8, s, quoted_len=4), ROUTER)),
    ("time exceeded quoting another destination", (lambda s: error(11, STRANGER, 8, s), ROUTER)),
    ("time exceeded quoting something not an echo", (lambda s: error(11, TARGET, 17, s), ROUTER)),
    ("time exceeded for another probe", (lambda s: error(11, TARGET, 8, s + 7), ROUTER)),
])
def test_forged_or_foreign_replies_are_ignored(fake, label, packet):
    reply = answer(fake, packet)
    assert reply.address is None and not reply.reached, label


def test_genuine_replies_still_count(fake):
    hop = answer(fake, (lambda s: error(11, TARGET, 8, s), ROUTER))
    assert hop.address == ROUTER and not hop.reached
    end = answer(fake, (lambda s: icmp(0, s), TARGET))
    assert end.address == TARGET and end.reached
    late_then_real = answer(fake, (lambda s: icmp(0, s), STRANGER), (lambda s: error(11, TARGET, 8, s), ROUTER))
    assert late_then_real.address == ROUTER


def test_flags_are_clamped_and_stop_is_checked_before_every_probe(monkeypatch):
    stop, probes = threading.Event(), []

    def fake_probe(dst, ttl, seq, wait):
        probes.append((ttl, seq, wait))
        if len(probes) == 2:
            stop.set()
        return probe.Reply(None, None)

    monkeypatch.setattr(probe, "_probe", fake_probe)
    monkeypatch.setattr(probe.socket, "gethostbyname", lambda host: TARGET)
    text, cancelled, _ = probe.trace(TARGET, max_hops=100_000, queries=1_000, wait=1e9, cancel=stop)
    assert cancelled and len(probes) == 2, "Stop waits for no more than one probe"
    assert "255 hops max" in text.splitlines()[0]
    assert all(wait <= probe.MAX_WAIT_SECONDS for _t, _s, wait in probes)


def test_sequence_numbers_do_not_start_at_one(monkeypatch):
    firsts = set()
    for _ in range(4):
        seen = []
        monkeypatch.setattr(probe, "_probe", lambda d, t, s, w: seen.append(s) or probe.Reply(TARGET, 1.0, True))
        monkeypatch.setattr(probe.socket, "gethostbyname", lambda host: TARGET)
        probe.trace(TARGET, max_hops=1, queries=1)
        firsts.add(seen[0])
    assert firsts != {1} and len(firsts) > 1
