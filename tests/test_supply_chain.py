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


def _job_runs(workflow: str, job: str) -> list[str]:
    """The one-line `run:` commands of *job*, in order."""
    text = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    body = re.search(rf"^  {job}:\n(.*?)(?=^  \S|\Z)", text, flags=re.M | re.S)
    assert body, f"{workflow} has no job {job}"
    return re.findall(r"^\s*- run: (.+)$", body.group(1), flags=re.M)


def test_the_release_tests_and_ships_the_wheel_it_built_from_the_lock():
    """Every install on the release path is the hashed lock or the wheel just
    built from it: never an editable install (its backend hook needs packages
    outside the lock) and never the source tree, so the tests run against the
    file that is published. The release-lock job in tests.yml runs the same
    commands, so a broken release path shows on a push, not first on a tag."""
    release = _job_runs("release.yml", "build")
    for runs in (release, _job_runs("tests.yml", "release-lock")):
        installs = [r for r in runs if "pip install" in r]
        assert installs == ["python -m pip install --require-hashes -r requirements/release.txt",
                            "python -m pip install --no-deps dist/*.whl"], installs
        order = [next(i for i, r in enumerate(runs) if key in r)
                 for key in ("--require-hashes", "python -m build --no-isolation", "dist/*.whl", "pytest")]
        assert order == sorted(order), runs
        assert not any(r.startswith("python -m pytest") for r in runs), "python -m puts the checkout first on sys.path"
    shared = [r for r in release if "pip install" in r or "build" in r or "pytest" in r]
    lock = [r for r in _job_runs("tests.yml", "release-lock") if "pip install" in r or "build" in r or "pytest" in r]
    assert shared == lock, (shared, lock)


def test_no_dependency_floor_admits_cve_2023_29483():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    floor = re.search(r'"dnspython>=([0-9.]+)"', pyproject).group(1)
    assert tuple(map(int, floor.split("."))) >= (2, 6, 1), floor
    locked = re.search(r"^dnspython==([0-9.]+)", (ROOT / "requirements" / "release.txt").read_text(), re.M).group(1)
    assert tuple(map(int, locked.split("."))) >= (2, 6, 1)
