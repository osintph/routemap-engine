"""No socket in the engine binds to every interface (CodeQL
py/bind-socket-all-network-interfaces): a probe must leave from the address
the system routes its target from, never a VPN's or a tailnet's. Sweeps the
whole package, so a new prober cannot bring the bug back."""
import ast
import pathlib

import routemap_engine

WILDCARDS = {"", "0.0.0.0", "::", "0:0:0:0:0:0:0:0", "::0"}


def _binds():
    root = pathlib.Path(routemap_engine.__file__).parent
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(), str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "bind":
                yield path.name, node


def test_no_bind_to_a_wildcard_address():
    found = []
    for name, call in _binds():
        found.append(name)
        if call.args and isinstance(call.args[0], ast.Tuple) and call.args[0].elts:
            host = call.args[0].elts[0]
            assert not (isinstance(host, ast.Constant) and host.value in WILDCARDS), \
                f"{name}:{call.lineno} binds to every interface"
            assert not isinstance(host, ast.IfExp), f"{name}:{call.lineno}: bind to a computed literal"
    assert found, "the sweep found no bind call at all; it is not looking in the right place"


def test_the_sweep_catches_the_old_code():
    """The sweep, run on the bind calls this fix replaced, reports both."""
    old = ('sock.bind(("::" if v6 else "0.0.0.0", port))\n'
           'sock.bind(("0.0.0.0", 0))\n')
    calls = [n for n in ast.walk(ast.parse(old)) if isinstance(n, ast.Call)]
    flagged = [c for c in calls if isinstance(c.args[0].elts[0], ast.IfExp)
               or (isinstance(c.args[0].elts[0], ast.Constant) and c.args[0].elts[0].value in WILDCARDS)]
    assert len(flagged) == 2
