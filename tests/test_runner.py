"""Running the trace locally: argument lists, streaming, cancel and timeout.

The tool is replaced by tests/helpers/fake_trace_tool.py run under this Python,
so the behaviour is the same on every CI runner. The real-tool run is a
separate, opt-in test (ROUTEMAP_REAL_TRACE=1) because it needs the network.
"""
import os
import pathlib
import sys
import threading
import time

import pytest

from routemap.engine import runner
from routemap.engine.parse import parse_trace
from routemap.engine.target import InvalidTarget

HERE = pathlib.Path(__file__).resolve().parent
FAKE = str(HERE / "helpers" / "fake_trace_tool.py")
FIXTURE = str(HERE / "fixtures" / "routemap" / "heise_traceroute.txt")


@pytest.fixture
def fake_tool(monkeypatch):
    monkeypatch.setattr(runner, "pick_tool",
                        lambda requested="auto": (runner.TOOL_TRACEROUTE, sys.executable))


def _opts(delay="0", **kwargs):
    return runner.TraceOptions(flags=[FAKE, FIXTURE, delay], **kwargs)


def test_the_defaults_are_the_commands_falconeye_shows():
    assert runner.DEFAULT_FLAGS["tracert"] == ["-h", "30", "-w", "1000"]
    assert runner.DEFAULT_FLAGS["traceroute"] == ["-m", "30", "-q", "3", "-w", "1"]
    assert runner.DEFAULT_FLAGS["mtr"][-4:] == ["-c", "3", "-m", "30"]


def test_the_argument_list_ends_with_the_canonical_target():
    argv = runner.build_argv("traceroute", "/usr/sbin/traceroute", "  Heise.DE ")
    assert argv == ["/usr/sbin/traceroute", "-m", "30", "-q", "3", "-w", "1", "heise.de"]


@pytest.mark.parametrize("target", ["-q", "--help", "heise.de; id", "$(id)", "a b"])
def test_a_target_that_could_be_a_flag_or_a_command_never_reaches_the_tool(target, fake_tool):
    with pytest.raises(InvalidTarget):
        runner.run_trace(target, _opts())


def test_a_trace_streams_its_lines_as_they_arrive(fake_tool):
    seen = []
    started = time.monotonic()
    result = runner.run_trace("heise.de", _opts(
        delay="0.05", on_line=lambda line: seen.append((time.monotonic() - started, line))))
    assert result.returncode == 0 and not result.cancelled
    assert seen[0][1].startswith("traceroute to heise.de")
    # The first line arrived well before the last: streamed, not buffered.
    assert seen[-1][0] - seen[0][0] > 0.3
    # And what was streamed is what the parser reads.
    parsed = parse_trace(result.text)
    assert parsed.parser == "traceroute" and len(parsed.hops) == 16


def test_cancel_stops_the_tool_and_keeps_what_it_printed(fake_tool):
    cancel = threading.Event()
    lines = []

    def on_line(line):
        lines.append(line)
        if len(lines) == 3:
            cancel.set()

    result = runner.run_trace("heise.de", _opts(delay="0.2", cancel=cancel, on_line=on_line))
    assert result.cancelled
    assert 3 <= len(result.text.splitlines()) < 17


def test_a_timeout_bounds_the_whole_run(fake_tool):
    result = runner.run_trace("heise.de", _opts(delay="0.5", timeout=1.0))
    assert result.timed_out
    assert result.seconds < 5


def test_a_broken_listener_does_not_kill_the_trace(fake_tool):
    def broken(line):
        raise RuntimeError("listener bug")

    result = runner.run_trace("heise.de", _opts(on_line=broken))
    assert len(parse_trace(result.text).hops) == 16


def test_no_tool_says_exactly_what_to_install(monkeypatch):
    monkeypatch.setattr(runner, "available_tools", lambda: {})
    with pytest.raises(runner.TraceToolMissing) as excinfo:
        runner.pick_tool("auto")
    assert str(excinfo.value) == runner.install_hint()
    assert "install" in str(excinfo.value).lower() or "PATH" in str(excinfo.value)


def test_privileged_probe_types_are_named_not_escalated():
    assert runner.privileged_flags_in("traceroute", ["-I", "-m", "30"]) == ["-I (ICMP probes)"]
    assert runner.privileged_flags_in("traceroute", runner.DEFAULT_FLAGS["traceroute"]) == []


def test_the_tool_is_never_run_through_a_shell():
    source = pathlib.Path(runner.__file__).read_text()
    assert "shell=False" in source
    assert "shell=True" not in source


@pytest.mark.skipif(os.environ.get("ROUTEMAP_REAL_TRACE") != "1",
                    reason="set ROUTEMAP_REAL_TRACE=1 to run a real traceroute")
def test_a_real_trace_with_the_system_tool():
    target = os.environ.get("ROUTEMAP_REAL_TARGET", "1.1.1.1")
    result = runner.run_trace(target, runner.TraceOptions(timeout=150))
    assert result.text.strip(), f"{result.argv} printed nothing"
    parsed = parse_trace(result.text)
    assert parsed.hops, result.text
