"""
``routemap-engine``: the engine's command line. One subcommand for now,
``agent``, which a Route Map app runs on a server over the user's own SSH
access (:mod:`routemap_engine.agent`). Route Map's own CLI (``routemap-cli``)
is the tool for people; this one prints JSON lines for a program.

    routemap-engine --version
    routemap-engine agent 1 hello
    routemap-engine agent 1 trace --target example.com
"""
from __future__ import annotations

import sys

from routemap_engine import __about__


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] in (["--version"], ["-V"]):
        print(f"{__about__.NAME} {__about__.__version__}")
        return 0
    if argv[:1] == ["agent"]:
        from routemap_engine import agent
        return agent.serve(argv[1:])
    print(f"usage: {__about__.NAME} --version | {__about__.NAME} agent 1 {{hello,trace,paths,ports}} [options]\n"
          f"The agent prints JSON lines for Route Map; see {__about__.REPO_URL}#remote-agents",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
