"""IPv6 in the built-in prober, and the Paris flow fields path discovery
depends on (0.7.0)."""
import socket
import struct

import pytest

from routemap_engine import probe

DST6, ROUTER6, SRC6 = "2001:db8:9::9", "2001:db8:1::1", "2001:db8:50::50"
DST4 = "192.0.2.9"


def _fields(packet):
    kind, code, csum, ident, seq = struct.unpack("!BBHHH", packet[:8])
    return kind, code, csum, ident, seq


def _valid(packet, af, src=None, dst=None):
    pseudo = probe._pseudo(src, dst, len(packet)) if af == 6 else b""
    return probe._checksum(pseudo + packet) == 0


@pytest.mark.parametrize("af", [4, 6])
def test_one_flow_keeps_one_checksum_while_its_sequence_numbers_change(af):
    src, dst = (SRC6, DST6) if af == 6 else (None, DST4)
    for flow in (0, 1, 7, 63):
        want = probe.flow_checksum(flow)
        seen = set()
        for seq in (0, 1, 2, 0x7FFF, 0xFFFF, 12345):
            payload = probe.paris_payload(0x4242, seq, want, af=af, src=src, dst=dst)
            pkt = probe._echo(0x4242, seq, af=af, payload=payload, src=src, dst=dst)
            kind, code, csum, ident, got_seq = _fields(pkt)
            assert (kind, code, ident, got_seq) == ((128 if af == 6 else 8), 0, 0x4242, seq)
            assert csum == want and _valid(pkt, af, src, dst)
            seen.add(pkt[:4])                      # type, code, checksum: what balancers hash
        assert len(seen) == 1


def test_every_flow_id_has_its_own_checksum_and_never_an_unusable_one():
    sums = [probe.flow_checksum(f) for f in range(64)]
    assert len(set(sums)) == 64 and all(s not in (0, 0xFFFF) for s in sums)


@pytest.mark.parametrize("af", [4, 6])
def test_the_transport_keeps_identifier_and_checksum_per_flow_and_varies_them_between_flows(af, monkeypatch):
    monkeypatch.setattr(probe.sys, "platform", "darwin")
    monkeypatch.setattr(probe, "_source_for", lambda dst: SRC6)
    t = probe.FlowTransport(DST6 if af == 6 else DST4)
    monkeypatch.setattr(t, "_sock", lambda flow: t._idents.setdefault(flow, (t._base + flow) & 0xFFFF))
    flows = {}
    for flow in range(4):
        heads = {probe.FlowTransport.packet(t, flow, seq)[:6] for seq in range(1, 40)}
        assert len(heads) == 1                     # type, code, checksum, identifier: constant
        flows[flow] = heads.pop()
    assert len(set(flows.values())) == 4


def time_exceeded6(quoted_dst, quoted_type, seq, next_header=58):
    inner = (bytes([0x60, 0, 0, 0]) + struct.pack("!HBB", 8, next_header, 1)
             + socket.inet_pton(socket.AF_INET6, SRC6) + socket.inet_pton(socket.AF_INET6, quoted_dst)
             + struct.pack("!BBHHH", quoted_type, 0, 0, 0x1234, seq))
    return struct.pack("!BBHI", 3, 0, 0, 0) + inner


def test_icmpv6_replies_match_by_type_and_the_quoted_ipv6_header():
    m = probe._match_reply
    assert m(time_exceeded6(DST6, 128, 77), ROUTER6, DST6, 77) == (True, False)
    assert m(time_exceeded6(DST6, 128, 78), ROUTER6, DST6, 77) == (False, False)      # another probe
    assert m(time_exceeded6("2001:db8::7", 128, 77), ROUTER6, DST6, 77) == (False, False)  # another target
    assert m(time_exceeded6(DST6, 8, 77), ROUTER6, DST6, 77) == (False, False)       # not an echo request
    assert m(time_exceeded6(DST6, 128, 77, next_header=17), ROUTER6, DST6, 77) == (False, False)
    reply = struct.pack("!BBHHH", 129, 0, 0, 0x1234, 77)
    assert m(reply, DST6, DST6, 77) == (True, True)
    assert m(reply, ROUTER6, DST6, 77) == (False, False)
    assert m(reply, DST6 + "%en0", DST6, 77) == (True, True)                          # scoped source
    assert m(struct.pack("!BBHHH", 0, 0, 0, 0x1234, 77), DST6, DST6, 77) == (False, False)  # ICMPv4 type
    unreach = bytearray(time_exceeded6(DST6, 128, 77)); unreach[0] = 1
    assert m(bytes(unreach), DST6, DST6, 77) == (True, True)


class RecordingSocket:
    def __init__(self, family):
        self.family, self.opts, self.sent = family, [], []

    def setsockopt(self, level, name, value):
        self.opts.append((level, name, value))

    def setblocking(self, flag):
        pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, n):
        raise BlockingIOError

    def recvmsg(self, *a):
        raise BlockingIOError

    def fileno(self):
        return -1

    def close(self):
        pass


def test_v6_probes_set_the_hop_limit_and_send_a_valid_icmpv6_echo(monkeypatch):
    made = []
    monkeypatch.setattr(probe, "_icmp_socket", lambda af: made.append(RecordingSocket(af)) or made[-1])
    monkeypatch.setattr(probe, "_source_for", lambda dst: SRC6)
    monkeypatch.setattr("select.select", lambda r, w, x, t: ([], [], []))
    assert probe._posix_probe(DST6, 7, 4242, 0.01) == probe.Reply(None, None)
    sock = made[0]
    assert sock.family == 6
    assert (socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 7) in sock.opts
    assert not any(level == socket.IPPROTO_IP and name == socket.IP_TTL for level, name, _ in sock.opts)
    data, addr = sock.sent[0]
    assert addr[0] == DST6 and data[0] == 128 and _valid(data, 6, SRC6, DST6)


def test_a_dual_stack_name_follows_the_chosen_family(monkeypatch):
    answers = {socket.AF_UNSPEC: [(socket.AF_INET6, 0, 0, "", ("2a02:2e0:3fe:1001:302::", 0, 0, 0)),
                                  (socket.AF_INET, 0, 0, "", ("193.99.144.80", 0))],
               socket.AF_INET: [(socket.AF_INET, 0, 0, "", ("193.99.144.80", 0))],
               socket.AF_INET6: [(socket.AF_INET6, 0, 0, "", ("2a02:2e0:3fe:1001:302::", 0, 0, 0))]}
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, af, kind: answers[af])
    assert probe.resolve("heise.de") == "2a02:2e0:3fe:1001:302::"          # the system's order
    assert probe.resolve("heise.de", "4") == "193.99.144.80"
    assert probe.resolve("heise.de", "6") == "2a02:2e0:3fe:1001:302::"


def test_a_name_without_the_asked_family_says_so(monkeypatch):
    def gai(host, port, af, kind):
        if af == socket.AF_INET6:
            raise socket.gaierror(socket.EAI_NONAME, "no address")
        return [(socket.AF_INET, 0, 0, "", ("192.0.2.1", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    with pytest.raises(probe.NoAddress, match="no IPv6 address"):
        probe.resolve("v4only.example", "6")


def test_windows_says_why_it_cannot_hold_a_flow(monkeypatch):
    monkeypatch.setattr(probe.sys, "platform", "win32")
    ok, why = probe.flow_available()
    assert not ok and "identifier and sequence number" in why
