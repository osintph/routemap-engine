"""Trace tools come from the system's own folders, never from the current
folder or an earlier PATH entry (RM-03), on every platform."""
import os
import stat

import pytest

from routemap_engine import runner


def _exe(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\necho planted\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def planted(tmp_path, monkeypatch):
    """A working folder and an early PATH entry, both holding every tool name."""
    work, early = tmp_path / "work", tmp_path / "early"
    for folder in (work, early):
        for name in ("tracert", "tracert.exe", "tracert.cmd", "tracert.bat", "traceroute", "mtr"):
            _exe(folder / name)
    monkeypatch.chdir(work)
    monkeypatch.setenv("PATH", os.pathsep.join([".", str(early), os.environ.get("PATH", "")]))
    monkeypatch.setattr(runner, "icmp_status", lambda: (False, "test"))
    return work, early


def test_windows_runs_tracert_from_system32_only(planted, tmp_path, monkeypatch):
    system32 = tmp_path / "Windows" / "System32"
    real = _exe(system32 / "tracert.exe")
    monkeypatch.setattr(runner, "_platform", lambda: "windows")
    monkeypatch.setattr(runner, "_system32", lambda: str(system32), raising=False)
    assert runner.available_tools()[runner.TOOL_TRACERT] == str(real)
    real.unlink()
    assert runner.TOOL_TRACERT not in runner.available_tools(), "no fallback to PATH or the current folder"


@pytest.mark.parametrize("plat", ["macos", "linux"])
def test_unix_prefers_the_system_folders_to_path(planted, tmp_path, monkeypatch, plat):
    system = tmp_path / "usr" / "sbin"
    real = _exe(system / "traceroute")
    monkeypatch.setattr(runner, "_platform", lambda: plat)
    monkeypatch.setattr(runner, "SYSTEM_TOOL_DIRS", (str(system),), raising=False)
    found = runner.available_tools()[runner.TOOL_TRACEROUTE]
    assert found == str(real)
    work, early = planted
    assert not found.startswith((str(work), str(early)))


def test_the_windows_icmp_api_is_loaded_from_system32_only(monkeypatch):
    """ctypes' default search would take an iphlpapi.dll from the app's own
    folder first (hardening 6). LOAD_LIBRARY_SEARCH_SYSTEM32 is 0x800."""
    import ctypes

    from routemap_engine import probe
    calls = []

    class FakeLib:
        def __getattr__(self, name):
            return type("Fn", (), {})()

    def fake_windll(name, **kwargs):
        calls.append((name, kwargs))
        return FakeLib()

    monkeypatch.setattr(ctypes, "WinDLL", fake_windll, raising=False)
    probe._windows_api()
    assert calls and all(kw.get("winmode") == 0x800 for _name, kw in calls), calls
