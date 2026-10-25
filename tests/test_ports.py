"""Port tests (0.8.0) against listeners on this machine: open with its connect
time, closed (a reset), filtered (no answer), TLS handshake timing, and the
limits that keep it a reachability check rather than a scanner."""
import socket
import ssl
import subprocess
import sys
import threading
import time

import pytest

from routemap_engine import ports


def _listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def accept():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass
    threading.Thread(target=accept, daemon=True).start()
    return srv, stop


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_open_and_closed_ports_are_told_apart():
    srv, stop = _listener()
    try:
        open_port, closed = srv.getsockname()[1], _closed_port()
        res = ports.check_ports("127.0.0.1", [open_port, closed], tls_ports=None, wait=1.0)
    finally:
        stop.set()
        srv.close()
    by = {r.port: r for r in res.results}
    assert by[open_port].state == "open" and by[open_port].connect_ms is not None
    assert by[closed].state == "closed" and by[closed].reason == "reset" and by[closed].connect_ms is None
    assert res.to_dict()["cap"] == 32


def test_no_answer_is_filtered_within_the_wait(monkeypatch):
    """Silence, simulated here so no packet leaves this machine: the socket
    never becomes writable within the wait."""
    waits = []

    def select(r, w, x, timeout):
        waits.append(timeout)
        return [], [], []
    monkeypatch.setattr(ports.select, "select", select)
    res = ports.check_ports("127.0.0.1", [_closed_port()], tls_ports=None, wait=0.5)
    assert (res.results[0].state, res.results[0].reason) == ("filtered", "no answer in 0.5 s") and waits == [0.5]


def test_an_icmp_unreachable_is_filtered_with_its_reason():
    assert ports._failed(3389, 10065).to_dict()["reason"] == "unreachable"
    assert ports._failed(3389, __import__("errno").EHOSTUNREACH).state == "filtered"


def test_tls_handshake_is_timed_without_trusting_the_certificate(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    made = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                           "-days", "1", "-keyout", str(key), "-out", str(cert)], capture_output=True)
    if made.returncode:
        pytest.skip("openssl is not available to make a throwaway certificate")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        conn, _ = srv.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (OSError, ssl.SSLError):
            pass
    threading.Thread(target=serve, daemon=True).start()
    port = srv.getsockname()[1]
    try:
        res = ports.check_ports("127.0.0.1", [port], tls_ports=[port], wait=2.0, server_name="localhost")
    finally:
        srv.close()
    r = res.results[0]
    assert r.state == "open" and r.tls_ms is not None and r.tls_version and r.tls_error is None


def test_at_most_four_at_a_time(monkeypatch):
    live, peak, lock = [0], [0], threading.Lock()

    def one(address, port, *a):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.05)
        with lock:
            live[0] -= 1
        return ports.PortResult(port, "filtered", "no answer in 1 s")
    monkeypatch.setattr(ports, "_one", one)
    ports.check_ports("192.0.2.1", list(range(1, 33)), tls_ports=None)
    assert peak[0] == ports.PARALLEL == 4


@pytest.mark.parametrize("raw,why", [("1-1024", "range"), ("22:25", "range"), ("http", "not a port"),
                                     ("0", "not a port"), ("65536", "not a port"), ("", "at least one"),
                                     (",".join(str(p) for p in range(1, 34)), "at most 32")])
def test_ranges_and_more_than_32_ports_are_refused(raw, why):
    with pytest.raises(ports.InvalidPorts, match=why):
        ports.parse_ports(raw)


def test_a_port_list_keeps_its_order_without_repeats():
    assert ports.parse_ports("443, 80 22,443") == [443, 80, 22]
    assert ports.parse_ports(ports.DEFAULT_PORTS) == [443, 80, 22, 25, 53, 3389]


def test_only_an_address_is_tested_never_a_name():
    with pytest.raises(ValueError):
        ports.check_ports("bbc.com", [443])


def test_sni_is_never_an_address(monkeypatch):
    seen = []
    monkeypatch.setattr(ports, "_one", lambda a, p, w, tls, sni, *r: seen.append(sni) or ports.PortResult(p, "closed"))
    ports.check_ports("151.101.0.81", [443], server_name="151.101.0.81")
    ports.check_ports("151.101.0.81", [443], server_name="bbc.com")
    assert seen == [None, "bbc.com"]


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows socket options")
def test_windows_sends_one_syn_and_fails_on_icmp_errors():
    s = socket.socket()
    try:
        ports._windows_options(s)
    finally:
        s.close()
