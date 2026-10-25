"""DNS response timing (0.8.0) against a DNS server in this process: answers,
the AA bit, truncation then TCP, silence within the budget; the system
resolver through a fake getaddrinfo. Nothing leaves this machine."""
import logging
import socket
import socketserver
import struct
import threading

import dns.flags
import dns.message
import dns.rrset
import pytest

from routemap_engine import dnstime, probe


class _Server:
    """UDP and TCP on 127.0.0.1, one port. *mode*: "answer", "aa", "truncate"
    (UDP says TC, TCP answers) or "silent"."""

    def __init__(self, mode="answer"):
        self.mode = mode
        self.udp_queries = self.tcp_queries = 0
        outer = self

        def reply(data, tcp):
            q = dns.message.from_wire(data)
            r = dns.message.make_response(q)
            name, rtype = q.question[0].name, q.question[0].rdtype
            if outer.mode == "truncate" and not tcp:
                r.flags |= dns.flags.TC
                return r.to_wire()
            text = "151.101.0.81" if rtype == 1 else "2a04:4e42::81"
            r.answer.append(dns.rrset.from_text(name, 212, "IN", "A" if rtype == 1 else "AAAA", text))
            if outer.mode == "aa":
                r.flags |= dns.flags.AA
            return r.to_wire()

        class Udp(socketserver.BaseRequestHandler):
            def handle(self):
                outer.udp_queries += 1
                if outer.mode == "silent":
                    return
                data, sock = self.request
                sock.sendto(reply(data, False), self.client_address)

        class Tcp(socketserver.BaseRequestHandler):
            def handle(self):
                outer.tcp_queries += 1
                n = struct.unpack("!H", self.request.recv(2))[0]
                out = reply(self.request.recv(n), True)
                self.request.sendall(struct.pack("!H", len(out)) + out)

        self.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Udp)
        self.port = self.udp.server_address[1]
        self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), Tcp)
        for srv in (self.udp, self.tcp):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def close(self):
        for srv in (self.udp, self.tcp):
            srv.shutdown()
            srv.server_close()


@pytest.fixture
def server(request):
    srv = _Server(getattr(request, "param", "answer"))
    yield srv
    srv.close()


def _gai(answers):
    def getaddrinfo(name, port, family=0, kind=0, *a):
        if family not in answers:
            raise socket.gaierror(socket.EAI_NONAME, "no such name")
        return [(family, kind, 6, "", (a, 0) if family == socket.AF_INET else (a, 0, 0, 0)) for a in answers[family]]
    return getaddrinfo


GAI = _gai({socket.AF_INET: ["151.101.0.81", "151.101.64.81"], socket.AF_INET6: ["2a04:4e42::81"]})


def test_the_system_resolver_is_timed_for_a_and_aaaa_and_says_nothing_it_cannot_know():
    rows = dnstime.measure("bbc.com", getaddrinfo=GAI)
    assert [(r.resolver, r.type) for r in rows] == [("system", "A"), ("system", "AAAA")]
    assert rows[0].addresses == ["151.101.0.81", "151.101.64.81"] and rows[0].ms is not None
    assert all(r.aa is None and r.cached is None and r.rcode is None for r in rows)


def test_an_empty_family_says_what_the_system_returned_not_that_the_record_is_missing():
    """ODIN, 25 Oct 2026: "no AAAA record" for bbc.com and heise.de, which have
    AAAA records; Windows gives a computer without IPv6 no IPv6 address."""
    rows = dnstime.measure("bbc.com", getaddrinfo=_gai({socket.AF_INET: ["151.101.64.81"]}))
    assert rows[1].type == "AAAA" and rows[1].ms is None
    assert rows[1].error == "system resolver returned no IPv6 address (this computer may have no IPv6)"
    rows = dnstime.measure("v6only.example", getaddrinfo=_gai({socket.AF_INET6: ["2001:db8::1"]}))
    assert rows[0].error == "system resolver returned no IPv4 address"
    assert not any("record" in (r.error or "") for r in rows)


def test_a_named_resolver_reports_rcode_ttl_and_addresses(server):
    rows = dnstime.measure("bbc.com", ["127.0.0.1"], getaddrinfo=GAI, port=server.port)
    named = [r for r in rows if r.resolver == "127.0.0.1"]
    assert [r.type for r in named] == ["A", "AAAA"]
    assert named[0].rcode == "NOERROR" and named[0].ttl == 212 and named[0].addresses == ["151.101.0.81"]
    assert named[0].aa is False and named[0].cached is None and not named[0].tcp


@pytest.mark.parametrize("server", ["aa"], indirect=True)
def test_the_aa_bit_is_reported_when_set(server):
    rows = dnstime.measure("bbc.com", ["127.0.0.1"], getaddrinfo=GAI, port=server.port, system=False)
    assert all(r.aa is True for r in rows)


@pytest.mark.parametrize("server", ["truncate"], indirect=True)
def test_a_truncated_answer_is_asked_again_over_tcp(server):
    rows = dnstime.measure("bbc.com", ["127.0.0.1"], getaddrinfo=GAI, port=server.port, system=False)
    assert all(r.tcp and r.addresses for r in rows) and server.tcp_queries == 2


@pytest.mark.parametrize("server", ["silent"], indirect=True)
def test_a_silent_resolver_costs_its_timeout_and_the_budget_bounds_the_step(server):
    import time
    started = time.perf_counter()
    rows = dnstime.measure("bbc.com", ["127.0.0.1", "127.0.0.1"], getaddrinfo=GAI, port=server.port,
                           query_timeout=0.3, budget=0.8, system=False)
    took = time.perf_counter() - started
    assert took < 1.3, took
    assert rows and all(r.ms is None and r.error and "no answer" in r.error for r in rows)
    assert len(rows) < 4                               # the budget left the last query unsent


def test_a_literal_address_has_nothing_to_resolve():
    assert dnstime.measure("151.101.0.81", ["9.9.9.9"], getaddrinfo=lambda *a: pytest.fail("looked up")) == []
    r = dnstime.resolve_target("151.101.0.81")
    assert (r.address, r.by) == ("151.101.0.81", "literal")


def test_resolve_target_is_one_system_lookup_in_its_order(monkeypatch):
    calls = []

    def gai(name, port, family=0, kind=0, *a):
        calls.append(family)
        return [(socket.AF_INET, kind, 0, "", ("151.101.192.81", 0)), (socket.AF_INET, kind, 0, "", ("151.101.0.81", 0))]
    r = dnstime.resolve_target("bbc.com", getaddrinfo=gai)
    assert (r.name, r.address, r.family, r.by) == ("bbc.com", "151.101.192.81", 4, "system") and len(calls) == 1


@pytest.mark.parametrize("raw", ["dns.google", "9.9.9.9; rm", "", "224.0.0.1", "0.0.0.0", "-1"])
def test_resolvers_are_addresses_only(raw):
    with pytest.raises(dnstime.InvalidResolver):
        dnstime.validate_resolver(raw)


@pytest.mark.parametrize("raw", ["9.9.9.9", "10.0.0.53", "2620:fe::fe", "127.0.0.53"])
def test_private_and_local_resolvers_are_allowed(raw):
    assert dnstime.validate_resolver(raw) == raw


def test_only_the_named_resolvers_are_asked(monkeypatch):
    asked = []

    def query(name, rtype, server, timeout, clock):
        asked.append(server)
        return dnstime.Lookup(server, rtype, 1.0)
    dnstime.measure("bbc.com", ["9.9.9.9", "1.1.1.1"], getaddrinfo=GAI, query=query)
    assert asked == ["9.9.9.9", "9.9.9.9", "1.1.1.1", "1.1.1.1"]


def test_the_target_never_appears_in_a_log_line(caplog, server):
    caplog.set_level(logging.DEBUG, logger="routemap_engine")
    dnstime.measure("secret-target.example", ["127.0.0.1"], getaddrinfo=GAI, port=server.port)
    assert caplog.records and "secret-target" not in caplog.text
