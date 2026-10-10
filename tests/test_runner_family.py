"""Every trace tool is held to the address family the engine resolved
(0.7.0): a dual-stack name is traced over the family the user chose, and the
system tools get their own flag for it."""
import pytest

from routemap_engine import probe, runner


@pytest.mark.parametrize("plat,tool,family,expected", [
    ("windows", runner.TOOL_TRACERT, 6, ["tracert.exe", "-6", "-h", "30", "x"]),
    ("windows", runner.TOOL_TRACERT, 4, ["tracert.exe", "-4", "-h", "30", "x"]),
    ("linux", runner.TOOL_TRACEROUTE, 6, ["/usr/bin/traceroute", "-6", "-m", "30", "x"]),
    ("linux", runner.TOOL_MTR, 6, ["/usr/bin/mtr", "-6", "-m", "30", "x"]),
    ("linux", runner.TOOL_MTR, 4, ["/usr/bin/mtr", "-4", "-m", "30", "x"]),
    ("macos", runner.TOOL_TRACEROUTE, 4, ["/usr/sbin/traceroute", "-m", "30", "x"]),
    ("macos", runner.TOOL_TRACEROUTE, 6, ["/usr/sbin/traceroute6", "-I", "-m", "30", "x"]),
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
    assert ran["argv"][:2] == ["/usr/bin/traceroute", "-6"]
