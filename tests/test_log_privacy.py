"""No engine log line writes a user-supplied value in the clear.

Ported from FalconEye's structural rule. A trace describes the user's own path
(the routers between them and their target) and an origin says where they are.
Every such value in a log call goes through logsafe.tag() or is measured
(len(), a count) rather than written.
"""
import pathlib
import re

ENGINE = pathlib.Path(__file__).resolve().parents[1] / "routemap" / "engine"

USER_VALUES = ("hostname", "addr", "address", "target", "trace_text", "text",
               "origin", "city", "client_ip", "ip")


def _log_blocks(path):
    lines = path.read_text().split("\n")
    i = 0
    while i < len(lines):
        if re.search(r"\blog\.(debug|info|warning|error|critical|exception)\(", lines[i]):
            depth = lines[i].count("(") - lines[i].count(")")
            j, block = i + 1, [lines[i]]
            while j < len(lines) and depth > 0:
                block.append(lines[j])
                depth += lines[j].count("(") - lines[j].count(")")
                j += 1
            yield i + 1, "\n".join(block)
            i = max(j, i + 1)
        else:
            i += 1


def test_the_sweep_covers_the_engine():
    names = {p.name for p in ENGINE.glob("*.py")}
    assert {"geo.py", "hoiho.py", "model.py", "runner.py"} <= names


def test_no_engine_log_call_passes_a_user_value_in_the_clear():
    offenders = []
    for path in sorted(ENGINE.rglob("*.py")):
        for lineno, block in _log_blocks(path):
            for name in USER_VALUES:
                bare = re.search(rf"(?<![\w.(]){name}\s*[,)]", block)
                fstr = re.search(rf"\{{\s*{name}\s*[}}:!]", block)
                if not (bare or fstr):
                    continue
                if f"tag({name}" in block or f"len({name}" in block:
                    continue
                offenders.append(f"{path.name}:{lineno} passes {name!r} unhashed")
    assert not offenders, "\n".join(offenders)
