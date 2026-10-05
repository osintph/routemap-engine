"""What the release builds from is fixed: every action by commit (RM-07),
every package by hash, and no dependency floor that admits a known CVE (RM-16)."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def test_every_action_is_pinned_to_a_commit():
    loose = []
    for wf in WORKFLOWS:
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = re.match(r"\s*(?:-\s*)?uses:\s*([^\s#]+)", line)
            if m and not m.group(1).startswith("./") and not re.search(r"@[0-9a-f]{40}$", m.group(1)):
                loose.append(f"{wf.name}:{n} {m.group(1)}")
    assert WORKFLOWS and not loose, loose


def test_the_release_installs_only_hashed_packages_and_builds_without_fetching():
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    installs = re.findall(r"pip install[^\n]*", release)
    assert installs and all("--require-hashes" in i or "--no-deps" in i for i in installs), installs
    assert "python -m build --no-isolation" in release
    lock = (ROOT / "requirements" / "release.txt").read_text(encoding="utf-8")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==", lock, flags=re.M)
    assert len(pins) >= 10 and lock.count("--hash=sha256:") >= len(pins)


def test_no_dependency_floor_admits_cve_2023_29483():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    floor = re.search(r'"dnspython>=([0-9.]+)"', pyproject).group(1)
    assert tuple(map(int, floor.split("."))) >= (2, 6, 1), floor
    locked = re.search(r"^dnspython==([0-9.]+)", (ROOT / "requirements" / "release.txt").read_text(), re.M).group(1)
    assert tuple(map(int, locked.split("."))) >= (2, 6, 1)
