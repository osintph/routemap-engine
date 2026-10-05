"""The parser stays fast on hostile input (RM-02), over the class: every
pattern in the module against worst-case lines, and whole pastes."""
import re
import subprocess
import sys
import time

import pytest

from routemap_engine import parse
from routemap_engine.parse import TraceParseError, parse_trace

MAX_LINE_CHARS = getattr(parse, "MAX_LINE_CHARS", 1000)

PREFIXES = ["", "Tracing route to a", "traceroute to a", " 1  ", "  1.|-- a", "  ", "   |`|-- ",
            "HOST: ", "  1  a (", " 1  <1 ms"]
FILLERS = [" ", "a", "1", "a ", "1 ", "1.", "* ", ". ", "|", "|`", " ms", "(", "x(", "ms 1 ", "\t", "1 ms "]
SUFFIXES = ["", "b", "!", "(", "]", " x"]


def worst_lines(length: int):
    for p in PREFIXES:
        for f in FILLERS:
            for s in SUFFIXES:
                body = f * ((length - len(p) - len(s)) // len(f) + 1)
                yield (p + body)[: length - len(s)] + s


def test_every_parser_pattern_is_fast_on_worst_case_lines():
    patterns = {name: v for name, v in vars(parse).items() if isinstance(v, re.Pattern)}
    assert len(patterns) >= 10
    for name, pat in patterns.items():
        for line in worst_lines(MAX_LINE_CHARS):
            start = time.perf_counter()
            pat.match(line)
            pat.search(line)
            for _ in pat.finditer(line):
                pass
            took = time.perf_counter() - start
            assert took < 0.5, f"{name} took {took:.2f} s on {line[:40]!r}..."


def test_a_line_longer_than_any_real_hop_line_is_refused():
    with pytest.raises(TraceParseError, match="line"):
        parse_trace(" 1  a.example (192.0.2.1)  1.0 ms\n" + "Tracing route to a" + " " * MAX_LINE_CHARS + "b\n")


@pytest.mark.parametrize("text", [
    "Tracing route to a" + " " * 200_000 + "b",
    " 1" + " " * 200_000 + "x",
    "traceroute to a (192.0.2.1)\n" + "  " + "1 ms " * 40_000,
    "  1.|-- " + "a " * 100_000,
])
def test_a_hostile_paste_is_refused_or_parsed_in_a_moment(text):
    code = ("import sys; from routemap_engine.parse import parse_trace, TraceParseError\n"
            "t = sys.stdin.read()\n"
            "try: parse_trace(t)\nexcept TraceParseError: pass\n")
    start = time.perf_counter()
    try:
        subprocess.run([sys.executable, "-c", code], input=text, text=True, timeout=5, check=True)
    except subprocess.TimeoutExpired:
        pytest.fail("parse_trace was still running after 5 s")
    assert time.perf_counter() - start < 5
