"""No em dashes anywhere in the tree: code, docs, data, UI strings."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "venv", "build", "dist", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {".py", ".md", ".txt", ".tsv", ".json", ".toml", ".yml", ".yaml",
                 ".cfg", ".ini", ".spec", ".sh", ".ps1", ".iss", ".qss", ".html", ""}
EM_DASH = chr(0x2014)


def test_there_are_no_em_dashes():
    offenders = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or SKIP_DIRS & set(path.relative_to(ROOT).parts):
            continue
        if path.suffix not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if EM_DASH in line:
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}")
    assert not offenders, "em dashes found:\n  " + "\n  ".join(offenders)
