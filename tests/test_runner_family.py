"""Every trace tool is held to the address family the engine resolved
(0.7.0): a dual-stack name is traced over the family the user chose, and the
system tools get their own flag for it."""
import pytest

from routemap_engine import probe, runner


@pytest.mark.parametrize("plat,tool,family,expected", [
    ("windows", runner.TOOL_TRACERT, 6, ["tracert.exe", "-h", "30", "-6", "x"]),
    ("windows", runner.TOOL_TRACERT, 4, ["tracert.exe", "-h", "30", "-4", "x"]),
    ("linux", runner.TOOL_TRACEROUTE, 6, ["/usr/bin/traceroute", "-m", "30", "-6", "x"]),
    ("linux", runner.TOOL_MTR, 6, ["/usr/bin/mtr", "-m", "30", "-6", "x"]),
    ("linux", runner.TOOL_MTR, 4, ["/usr/bin/mtr", "-m", "30", "-4", "x"]),
    ("macos", runner.TOOL_TRACEROUTE, 4, ["/usr/sbin/traceroute", "-m", "30", "x"]),
    ("macos", runner.TOOL_TRACEROUTE, 6, ["/usr/sbin/traceroute6", "-m", "30", "-I", "x"]),
])
def test_system_tools_get_the_family_flag_and_macos_uses_traceroute6(monkeypatch, plat, tool, family, expected):
    monkeypatch.setattr(runner, "_platform", lambda: plat)
    monkeypatch.setattr(runner, "tool_path", lambda name: f"/usr/sbin/{name}")
    exe = {"windows": "tracert.exe", "linux": f"/usr/bin/{tool}", "macos": "/usr/sbin/traceroute"}[plat]
    assert runner.with_family(tool, [exe, "-" + ("h" if tool == runner.TOOL_TRACERT else "m"), "30", "x"],
                              family) == expected


def test_the_built_in_prober_traces_the_resolved_family(monkeypatch):
    seen = {}
    monkeypatch.setattr(runner, "pick_tool", lambda requested="auto": (runner.TOOL_ICMP, runner.TOOL_ICMP))
    monkeypatch.setattr(probe, "resolve", lambda target, family="auto": "2001:db8::9" if family != "4" else "192.0.2.9")
    monkeypatch.setattr(probe, "available", lambda family=4: (True, ""))

    def fake_trace(target, **kw):
        seen.update(kw)
        return "traceroute to x (2001:db8::9), 30 hops max\n 1  2001:db8::9  1.0 ms\n", False, False
    monkeypatch.setattr(probe, "trace", fake_trace)
    runner.run_trace("dual.example", runner.TraceOptions(family="6"))
    assert seen["family"] == "6"
    runner.run_trace("dual.example", runner.TraceOptions(family="4"))
    assert seen["family"] == "4"


def test_without_an_ipv6_prober_the_system_tool_runs_with_its_ipv6_flag(monkeypatch):
    ran = {}
    monkeypatch.setattr(runner, "_platform", lambda: "linux")
    monkeypatch.setattr(runner, "pick_tool", lambda requested="auto": (
        (runner.TOOL_ICMP, runner.TOOL_ICMP) if requested == "auto" else (runner.TOOL_TRACEROUTE, "/usr/bin/traceroute")))
    monkeypatch.setattr(probe, "resolve", lambda target, family="auto": "2001:db8::9")
    monkeypatch.setattr(probe, "available", lambda family=4: (family == 4, "no ICMPv6 sockets"))

    class Done(Exception):
        pass

    def popen(argv, **kw):
        ran["argv"] = argv
        raise Done
    monkeypatch.setattr(runner.subprocess, "Popen", popen)
    with pytest.raises(Done):
        runner.run_trace("dual.example")
    assert ran["argv"][0] == "/usr/bin/traceroute" and ran["argv"][-2:] == ["-6", "2001:db8::9"]


@pytest.mark.parametrize("plat,tool,exe", [("linux", runner.TOOL_TRACEROUTE, "/usr/bin/traceroute"),
                                           ("linux", runner.TOOL_MTR, "/usr/bin/mtr"),
                                           ("windows", runner.TOOL_TRACERT, "tracert.exe"),
                                           ("macos", runner.TOOL_TRACEROUTE, "/usr/sbin/traceroute")])
@pytest.mark.parametrize("family,address", [("4", "151.101.0.81"), ("6", "2a04:4e42::81")])
def test_every_system_tool_is_given_the_resolved_address_never_the_name(monkeypatch, plat, tool, exe,
                                                                        family, address):
    """0.8.0: a tool given the name resolves it again, and a CDN name can then
    answer with another address than the one the app shows."""
    ran = {}
    monkeypatch.setattr(runner, "_platform", lambda: plat)
    monkeypatch.setattr(runner, "tool_path", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(runner, "pick_tool", lambda requested="auto": (tool, exe))
    monkeypatch.setattr(probe, "resolve", lambda target, family="auto", **kw: address)

    class Done(Exception):
        pass

    def popen(argv, **kw):
        ran["argv"] = argv
        raise Done
    monkeypatch.setattr(runner.subprocess, "Popen", popen)
    with pytest.raises(Done):
        runner.run_trace("bbc.com", runner.TraceOptions(family=family))
    assert ran["argv"][-1] == address and "bbc.com" not in ran["argv"], ran["argv"]
    ran.clear()
    with pytest.raises(Done):
        runner.run_trace("bbc.com", runner.TraceOptions(address=address))
    assert ran["argv"][-1] == address


def test_the_built_in_prober_traces_the_callers_address(monkeypatch):
    seen = {}
    monkeypatch.setattr(runner, "pick_tool", lambda requested="auto": (runner.TOOL_ICMP, runner.TOOL_ICMP))
    monkeypatch.setattr(probe, "resolve", lambda *a, **kw: pytest.fail("resolved again"))
    monkeypatch.setattr(probe, "available", lambda family=4: (True, ""))

    def fake_trace(target, **kw):
        seen.update(kw, target=target)
        return "traceroute to bbc.com (151.101.0.81), 30 hops max\n 1  151.101.0.81  1.0 ms\n", False, False
    monkeypatch.setattr(probe, "trace", fake_trace)
    result = runner.run_trace("bbc.com", runner.TraceOptions(address="151.101.0.81"))
    assert seen["address"] == "151.101.0.81" and seen["target"] == "bbc.com" and result.address == "151.101.0.81"
