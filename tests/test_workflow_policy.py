"""What every workflow must do (RM-04, hardening 5, 7 and 10).

- no archived or third-party CLA action, and no workflow may start others
  (actions: write);
- every checkout leaves no token behind (persist-credentials: false);
- the workflow itself grants at most read access, and every job states its own;
- the release workflows never run twice at once (a concurrency group);
- container images are pinned by digest;
- secrets are named, never inherited, and a job that installs packages sees
  none: a compromised dependency cannot read a deploy or signing key;
- every pip install is hash-checked (--require-hashes) or installs no
  dependencies (--no-deps), and nothing is fetched from a moving URL without a
  pinned SHA-256;
- release files get build provenance and an SBOM.
"""
import pathlib
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
RELEASE_WORKFLOWS = {"release.yml"}
ids = [p.name for p in WORKFLOWS]


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _steps(doc):
    for name, job in (doc.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            yield name, job, step


def _text(step):
    return step.get("run") or ""


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_no_archived_cla_action_and_no_workflow_starts_others(wf):
    text = wf.read_text(encoding="utf-8")
    assert "contributor-assistant/" not in text
    assert not re.search(r"^\s*actions:\s*write\b", text, flags=re.M)


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_every_checkout_leaves_no_token_behind(wf):
    loose = [job for job, _, step in _steps(_load(wf)) if str(step.get("uses", "")).startswith("actions/checkout@")
             and (step.get("with") or {}).get("persist-credentials") is not False]
    assert not loose, loose


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_permissions_are_read_only_at_the_top_and_stated_per_job(wf):
    doc = _load(wf)
    top = doc.get("permissions")
    assert top is not None and (top == {} or all(v in ("read", "none") for v in top.values())), top
    jobs = doc.get("jobs") or {}
    missing = [n for n, j in jobs.items() if "permissions" not in j and "uses" not in j]
    assert not missing, f"jobs without their own permissions: {missing}"


@pytest.mark.parametrize("wf", [p for p in WORKFLOWS if p.name in RELEASE_WORKFLOWS], ids=lambda p: p.name)
def test_release_workflows_never_run_twice_at_once(wf):
    conc = _load(wf).get("concurrency")
    assert conc and conc.get("cancel-in-progress") is False, conc


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_container_images_are_pinned_by_digest(wf):
    images = re.findall(r"""image:\s*["']?([^"'\s}]+)""", wf.read_text(encoding="utf-8"))
    loose = [i for i in images if "@sha256:" not in i]
    assert not loose, loose


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_secrets_are_named_and_never_reach_a_package_install(wf):
    text = wf.read_text(encoding="utf-8")
    assert "secrets: inherit" not in text
    for name, job in (_load(wf).get("jobs") or {}).items():
        body = yaml.safe_dump(job)
        installs = any("pip install" in _text(s) for s in job.get("steps") or [])
        assert not (installs and "secrets." in body), f"job {name} installs packages and sees a secret"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_every_pip_install_is_hash_checked_or_dependency_free(wf):
    loose = []
    for job, _, step in _steps(_load(wf)):
        for line in _text(step).splitlines():
            if re.search(r"\bpip install\b", line) and "--require-hashes" not in line and "--no-deps" not in line:
                loose.append(f"{job}: {line.strip()}")
    assert not loose, loose


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_nothing_is_fetched_from_a_moving_url_unchecked(wf):
    for job, _, step in _steps(_load(wf)):
        run = _text(step)
        assert "/continuous/" not in run, f"{job}: a download from a moving 'continuous' tag"
        if re.search(r"\bcurl\b[^\n]*\s-o\s|Invoke-WebRequest", run):
            assert re.search(r"sha256sum -c|Get-FileHash|SHA256", run), f"{job}: a download without a SHA-256 check"


def test_every_lock_is_fully_hashed():
    for lock in (ROOT / "requirements").glob("*.txt"):
        text = lock.read_text(encoding="utf-8")
        pins = re.findall(r"^([A-Za-z0-9_.-]+)==", text, flags=re.M)
        assert pins, lock
        blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text)
        unhashed = [b.split("==")[0] for b in blocks if "==" in b and "--hash=sha256:" not in b]
        assert not unhashed, (lock.name, unhashed)


def test_dependabot_watches_the_locks_and_the_actions():
    cfg = _load(ROOT / ".github" / "dependabot.yml")
    seen = {(u["package-ecosystem"], u["directory"]) for u in cfg["updates"]}
    assert {("pip", "/requirements"), ("github-actions", "/")} <= seen, seen
    assert all(u["schedule"]["interval"] == "weekly" for u in cfg["updates"])


def test_release_files_get_provenance_and_an_sbom():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert re.search(r"uses: actions/attest-build-provenance@[0-9a-f]{40}", text)
    assert "cyclonedx-json" in text and "sbom/*" in text
    job = _load(ROOT / ".github" / "workflows" / "release.yml")["jobs"]["github-release"]["permissions"]
    assert job.get("id-token") == "write" and job.get("attestations") == "write"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_cla_script():
    result = subprocess.run(["node", "--test", "tests/node/"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
