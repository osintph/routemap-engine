"""Remote agents (0.8.0): the command that reaches the server's shell, the
ssh argument list, the agent's own output, the checks on what comes back,
and the masking of the server provider's first hops. Nothing here opens an
SSH connection or sends a packet."""
import io
import json
import os
import random
import shlex
import shutil
import stat
import subprocess
import sys
import threading

import pytest

from routemap_engine import agent, analyse_paths_sync, multipath, ports, runner
from routemap_engine.geo import Sources
from routemap_engine.target import InvalidTarget
from helpers.lab import Lab

DST = "151.101.0.81"
OFFLINE = Sources(hoiho=None, ip_db=None, ptr=None)


# ------------------------------------------------------- the remote command

def test_a_remote_command_is_the_engine_agent_with_quoted_validated_arguments():
    line = agent.remote_command("trace", target="BBC.com", resolvers=["9.9.9.9"], ports="443,22", deadline=90)
    assert shlex.split(line) == ["routemap-engine", "agent", "1", "trace", "--target", "bbc.com", "--family", "auto",
                                 "--resolver", "9.9.9.9", "--ports", "443,22", "--deadline", "90", "--stop-on-eof"]


HOSTILE = ["bbc.com; rm -rf ~", "$(id)", "`id`", "a|b", "a&&b", "a>b", "'quoted'", '"dq"', "a\nb", "-oProxyCommand=x",
           "--target", "a b", "*", "~root", "a\\b", "bbc.com#x", "\x00"]


@pytest.mark.parametrize("bad", HOSTILE, ids=[f"h{i}" for i in range(len(HOSTILE))])
def test_shell_syntax_in_any_argument_is_refused_before_ssh_runs(bad):
    for kw in ({"target": bad}, {"target": "bbc.com", "resolvers": [bad]}, {"target": "bbc.com", "ports": bad},
               {"target": "bbc.com", "command": bad}):
        with pytest.raises((agent.AgentError, InvalidTarget, ports.InvalidPorts, ValueError)):
            agent.remote_command("trace", **kw)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="needs a POSIX shell")
def test_whatever_passes_validation_reaches_the_shell_as_literal_arguments():
    """A POSIX shell, as sshd uses it (-c), splits the command back into
    exactly the arguments built; random targets and options never become
    shell syntax."""
    rng = random.Random(3)
    alphabet = "abcdefghij.-0123456789:"
    for _ in range(300):
        target = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 20)))
        try:
            line = agent.remote_command("ports", target=target, ports=[rng.randint(1, 65535)])
        except (agent.AgentError, InvalidTarget, ValueError):
            continue
        out = subprocess.run(["/bin/sh", "-c", line.replace("routemap-engine", "printf '%s\\n'", 1)],
                             capture_output=True, text=True, check=True).stdout.splitlines()
        assert out == shlex.split(line)[1:]


def test_a_command_under_home_keeps_its_tilde_unquoted():
    line = agent.remote_command("hello", command="~/.local/bin/routemap-engine")
    assert line.startswith("~/") and shlex.split(line)[0] == "~/.local/bin/routemap-engine"
    for bad in ("~root/x", "../x", "x/../y", "-x", "a b", "x;y"):
        with pytest.raises(agent.AgentError):
            agent.validate_command(bad)


def test_ssh_gets_fixed_options_and_never_an_option_for_a_destination():
    argv = agent.ssh_argv("/usr/bin/ssh", "fra-vps", "routemap-engine agent 1 hello")
    assert argv == ["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "--", "fra-vps",
                    "routemap-engine agent 1 hello"]
    assert agent.ssh_argv("ssh", "ubuntu@lab.example.net", "x")[-2] == "ubuntu@lab.example.net"
    for bad in ("-oProxyCommand=touch /tmp/x", "", "a b", "host;id", "host\n", "-p 22 host"):
        with pytest.raises(agent.AgentError):
            agent.ssh_argv("ssh", bad, "x")


# ------------------------------------------------------- the agent's output

def _serve(argv, stdin=None):
    out = io.StringIO()
    rc = agent.serve(argv, out=out, stdin=stdin)
    return rc, out.getvalue().encode()


def test_hello_names_the_engine_the_protocol_and_what_this_machine_can_probe():
    rc, raw = _serve(["1", "hello"])
    run = agent.read_run(io.BytesIO(raw))
    assert rc == 0 and run.error is None and run.hello["protocol"] == 1 and set(run.hello["can"]) == {"icmp4", "icmp6", "paths"}


def test_another_protocol_is_refused_plainly():
    rc, raw = _serve(["2", "hello"])
    assert rc == 2 and "speaks 1" in raw.decode()


def _no_dns(monkeypatch, address=DST):
    from routemap_engine import dnstime
    monkeypatch.setattr(dnstime, "measure", lambda *a, **kw: [dnstime.Lookup("system", "A", 4.0, [address])])
    monkeypatch.setattr(dnstime, "resolve_target", lambda t, f="auto", **kw: dnstime.Resolved(t, address, 4))


def test_a_remote_trace_round_trips_through_the_checks(monkeypatch):
    _no_dns(monkeypatch)
    text = f"traceroute to bbc.com ({DST}), 30 hops max, 40 byte packets\n 1  203.0.113.1  1.0 ms\n 2  {DST}  2.0 ms\n"

    def fake_trace(target, options):
        assert options.address == DST
        for line in text.splitlines():
            options.on_line(line)
        return runner.TraceResult(text=text, tool="traceroute", argv=[], returncode=0, address=DST)
    monkeypatch.setattr(runner, "run_trace", fake_trace)
    rc, raw = _serve(["1", "trace", "--target", "bbc.com"])
    lines = []
    run = agent.read_run(io.BytesIO(raw), on_line=lines.append)
    assert rc == 0 and run.error is None, run.error
    assert run.result["trace_text"] == text and run.result["resolved"]["address"] == DST and lines[0].startswith("traceroute")
    assert run.result["dns"][0]["addresses"] == [DST]


def test_remote_paths_rebuild_into_the_same_route(monkeypatch):
    _no_dns(monkeypatch, "192.0.2.9")
    lab = Lab(["198.51.100.1", ("flow", ["203.0.113.5", "203.0.113.6"]), "203.0.113.9", "192.0.2.9"], seed=4)
    local = multipath.Discoverer("example.net", "192.0.2.9", lab, clock=lab.clock).run()
    monkeypatch.setattr(multipath, "available", lambda: (True, ""))
    monkeypatch.setattr(multipath, "discover", lambda *a, **kw: local)
    rc, raw = _serve(["1", "paths", "--target", "example.net"])
    run = agent.read_run(io.BytesIO(raw))
    assert rc == 0 and run.error is None, run.error
    remote = run.result["discovery"]
    a = analyse_paths_sync(local, None, sources=OFFLINE).to_dict()
    b = analyse_paths_sync(remote, None, sources=OFFLINE).to_dict()
    a["paths"].pop("seconds"), b["paths"].pop("seconds")
    assert a == b


def test_remote_ports(monkeypatch):
    _no_dns(monkeypatch)
    monkeypatch.setattr(ports, "check_ports", lambda address, chosen, **kw: ports.PortsResult(
        address, [ports.PortResult(p, "open", connect_ms=9.0) for p in chosen]))
    rc, raw = _serve(["1", "ports", "--target", "bbc.com", "--ports", "443,80"])
    run = agent.read_run(io.BytesIO(raw))
    assert [r["port"] for r in run.result["ports"]["results"]] == [443, 80]


def test_the_agents_place_never_carries_its_address(monkeypatch):
    from routemap_engine import whereami

    async def locate_me(**kw):
        return {"ip": "203.0.113.77", "lat": 50.11, "lon": 8.68, "cc": "DE", "label": "Frankfurt am Main, DE"}
    monkeypatch.setattr(whereami, "locate_me", locate_me)
    rc, raw = _serve(["1", "hello", "--place", "ip"])
    assert b"203.0.113.77" not in raw
    run = agent.read_run(io.BytesIO(raw))
    assert run.origin == {"lat": 50.1, "lon": 8.7, "label": "Frankfurt am Main, DE", "cc": "DE"}


def test_a_closed_session_stops_the_run(monkeypatch):
    _no_dns(monkeypatch)
    seen = {}

    def fake_trace(target, options):
        seen["stopped"] = options.cancel.wait(5)
        return runner.TraceResult(text="", tool="icmp", argv=[], returncode=0, cancelled=True, address=DST)
    monkeypatch.setattr(runner, "run_trace", fake_trace)
    r, w = os.pipe()
    os.close(w)                                      # the app closed the session
    with os.fdopen(r) as stdin:
        _serve(["1", "trace", "--target", "bbc.com", "--stop-on-eof"], stdin=stdin)
    assert seen["stopped"] is True


# ------------------------------------------------------- what comes back

def _lines(*msgs):
    return io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in msgs))


HELLO = {"type": "hello", "engine": "0.8.0", "protocol": 1}
GOOD = {"type": "result", "kind": "trace", "resolved": {"name": "bbc.com", "address": DST, "family": 4},
        "dns": [], "trace_text": "x\n", "tool": "icmp"}


def test_a_login_banner_is_ignored():
    raw = b"Welcome to Ubuntu\n" + _lines(HELLO, GOOD).getvalue()
    assert agent.read_run(io.BytesIO(raw)).result["trace_text"] == "x\n"


@pytest.mark.parametrize("broken", [
    {**GOOD, "resolved": {"name": "bbc.com", "address": "not-an-ip", "family": 4}},
    {**GOOD, "resolved": {"name": "bbc.com; id", "address": DST, "family": 4}},
    {**GOOD, "dns": [{"resolver": "evil", "type": "A", "ms": 1, "addresses": []}]},
    {**GOOD, "dns": [{"resolver": "system", "type": "A", "ms": -5, "addresses": []}]},
    {**GOOD, "trace_text": 7},
    {**GOOD, "kind": "shell"},
    {**GOOD, "ports": {"address": DST, "results": [{"port": 99999, "state": "open"}]}},
    {**GOOD, "ports": {"address": DST, "results": [{"port": 443, "state": "pwned"}]}},
    {"type": "origin", "lat": 500, "lon": 0},
    {"type": "result", "kind": "paths", "resolved": GOOD["resolved"], "dns": [], "discovery": {"address": "x"}},
], ids=[f"b{i}" for i in range(10)])
def test_one_bad_field_discards_the_whole_answer(broken):
    run = agent.read_run(_lines(HELLO, broken))
    assert run.result is None and run.error and "did not check out" in run.error


def test_output_caps():
    long_line = b'{"type":"line","text":"' + b"x" * (agent.MAX_LINE + 10) + b'"}\n'
    assert "longer than 1 MB" in agent.read_run(io.BytesIO(_lines(HELLO).getvalue() + long_line)).error
    many = _lines(HELLO).getvalue() + (b'{"type":"line","text":"' + b"y" * 1000 + b'"}\n') * 9000
    assert "more than 8 MB" in agent.read_run(io.BytesIO(many)).error


def test_silence_and_a_wrong_protocol_are_errors():
    assert "no answer" in agent.read_run(io.BytesIO(b"")).error
    assert "protocol" in agent.read_run(_lines({"type": "hello", "protocol": 9})).error


# ------------------------------------------------------- the whole chain

@pytest.mark.skipif(sys.platform.startswith("win") or not shutil.which("sh"), reason="needs a POSIX shell")
def test_the_whole_chain_through_a_fake_ssh_and_a_real_shell(tmp_path):
    """ssh_argv -> an ssh stand-in that does what sshd does with the command
    (the user's shell, -c) -> the real engine CLI -> read_run."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shim = bindir / "routemap-engine"
    shim.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -m routemap_engine \"$@\"\n")
    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nshift\nexec /bin/sh -c \"$1\"\n")
    for f in (shim, fake_ssh):
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
    line = agent.remote_command("hello")
    env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
               PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    proc = subprocess.run(agent.ssh_argv(str(fake_ssh), "fra-vps", line), capture_output=True, env=env, timeout=60)
    run = agent.read_run(io.BytesIO(proc.stdout))
    assert run.error is None, (run.error, proc.stderr[-500:])
    assert run.hello["engine"].startswith("0.8")


# ------------------------------------------------------- masking

def _hop(n, addr, asn=None, place="Frankfurt am Main, DE"):
    return {"hop": n, "address": addr, "addresses": [addr] if addr else [], "hostname": f"h{n}.example.net" if addr else None,
            "hostnames": [], "lat": 50.1 if addr else None, "lon": 8.7 if addr else None, "place": place if addr else None,
            "cc": "DE", "source": "ip-db", "asn": asn, "annotations": [], "sent": 3, "lost": 0}


def _route(hops):
    return {"hops": hops, "resolved": {"name": "bbc.com", "address": DST, "family": 4}}


def test_the_providers_first_hops_are_masked_and_the_rest_kept():
    route = _route([_hop(1, "10.0.0.1"), _hop(2, "100.64.0.1"), _hop(3, "51.68.0.2", 16276), _hop(4, None),
                    _hop(5, "51.68.0.9", 16276), _hop(6, "62.115.1.1", 1299), _hop(7, DST, 54113)])
    masked = agent.mask_first_hops(route)
    assert masked == ["10.0.0.1", "100.64.0.1", "51.68.0.2", "51.68.0.9"]
    for h in route["hops"][:5]:
        assert h["masked"] and h["address"] is None and h["addresses"] == [] and h["place"] is None \
            and h["lat"] is None and h["hostname"] is None and h["asn"] is None
    assert route["hops"][5]["address"] == "62.115.1.1" and not route["hops"][5].get("masked")
    assert route["hops"][6]["address"] == DST


@pytest.mark.parametrize("asns", [(None, None, None), (16276, 1299, 1299), (16276, 16276, 1299)],
                         ids=["unknown", "other-as-second", "same-as"])
def test_never_fewer_than_the_first_two_public_hops_are_masked(asns):
    hops = [_hop(1, "10.0.0.1")] + [_hop(i + 2, a, asn) for i, (a, asn) in
                                     enumerate(zip(("51.68.0.2", "62.115.1.1", "62.115.1.9"), asns))]
    route = _route(hops + [_hop(5, DST, 54113)])
    masked = agent.mask_first_hops(route)
    assert masked[:3] == ["10.0.0.1", "51.68.0.2", "62.115.1.1"]
    assert ("62.115.1.9" in masked) == (asns[2] == asns[0] and asns[0] is not None)


def test_the_floor_stops_at_the_target():
    route = _route([_hop(1, "51.68.0.2", 16276), _hop(2, DST, 54113)])
    assert agent.mask_first_hops(route) == ["51.68.0.2"] and route["hops"][1]["address"] == DST


def test_silent_hops_inside_the_providers_stretch_are_masked_and_trailing_ones_are_not():
    route = _route([_hop(1, "51.68.0.2", 16276), _hop(2, None), _hop(3, "51.68.0.9", 16276), _hop(4, None),
                    _hop(5, "62.115.1.1", 1299), _hop(6, DST)])
    agent.mask_first_hops(route)
    assert [h["hop"] for h in route["hops"] if h.get("masked")] == [1, 2, 3]


def test_the_target_is_never_masked():
    route = _route([_hop(1, DST, 54113)])
    assert agent.mask_first_hops(route) == [] and route["hops"][0]["address"] == DST


def test_masked_addresses_leave_the_tool_text():
    text = (" 1  gw.example.net (203.0.113.2)  1.0 ms\n 2  203.0.113.9  2.0 ms\n"
            "  3     5 ms     5 ms     5 ms  r.example.net [203.0.113.21]\n 4  62.115.1.1  9 ms\n")
    out = agent.mask_text(text, ["203.0.113.2", "203.0.113.9", "203.0.113.21"])
    assert "203.0.113" not in out and "gw.example.net" not in out and "62.115.1.1" in out
    assert agent.mask_text("x 203.0.113.21 y", ["203.0.113.2"]) == "x 203.0.113.21 y"


def test_the_engine_command_line(capsys):
    from routemap_engine import cli
    assert cli.main(["--version"]) == 0 and capsys.readouterr().out.startswith("routemap-engine 0.8")
    assert cli.main([]) == 2 and "usage" in capsys.readouterr().err
    assert cli.main(["agent", "1", "hello"]) == 0 and '"protocol":1' in capsys.readouterr().out


@pytest.mark.parametrize("asn", [16276, None], ids=["as-known", "as-unknown"])
def test_private_hops_between_the_providers_public_hops_do_not_end_the_stretch(asn):
    """The shape of a real agent trace (an OVH VPS, 25 Oct 2026): the server's
    gateway, seven private hops, the provider's next public router, a private
    hop, then the next network. The gateway alone would have been masked."""
    hops = [_hop(1, "51.68.0.1", asn)] + [_hop(i, f"10.29.0.{i}") for i in range(2, 9)]
    hops += [_hop(9, "51.68.15.4", asn), _hop(10, "10.200.8.135"), _hop(11, "27.111.228.116", 64512),
             _hop(12, "81.95.15.70", 33891), _hop(13, DST, 54113)]
    route = _route(hops)
    masked = agent.mask_first_hops(route)
    assert [h["hop"] for h in route["hops"] if h.get("masked")] == list(range(1, 11))
    assert "51.68.0.1" in masked and "51.68.15.4" in masked and route["hops"][10]["address"] == "27.111.228.116"


def test_the_agents_own_name_never_leaves_it(monkeypatch):
    """mtr's report names the machine it runs on ("HOST: vps-e7d7933f" on the
    first real agent run); a server's name can lead to its address."""
    import socket
    _no_dns(monkeypatch)
    monkeypatch.setattr(socket, "gethostname", lambda: "vps-0a1b2c3d.vps.example.net")
    text = ("Start: 2026-10-25T09:05:48+0000\nHOST: vps-0a1b2c3d.vps.example.net   Loss%   Snt\n"
            "  1.|-- _gateway (51.68.0.1)  0.0%  3  0.2\n  2.|-- vps-0a1b2c3d (51.68.0.9)  0.0%  3  0.3\n")

    def fake_trace(target, options):
        for line in text.splitlines():
            options.on_line(line)
        return runner.TraceResult(text=text, tool="mtr", argv=[], returncode=0, address=DST)
    monkeypatch.setattr(runner, "run_trace", fake_trace)
    rc, raw = _serve(["1", "trace", "--target", "bbc.com"])
    assert b"vps-0a1b2c3d" not in raw and b"HOST: agent" in raw
