#!/bin/bash
# Compiles the hash locks (uv 0.9.2 on PATH, or UV=/path/to/uv):
#   release.txt  the release job's install and build (Linux, Python 3.12)
#   tests.txt    the test jobs (Windows, macOS, Linux; Python 3.11 to 3.13)
#   audit.txt    pip-audit, for the release's SBOM
# Every file has a SHA-256. Dependabot (.github/dependabot.yml) proposes updates.
set -euo pipefail
cd "$(dirname "$0")/.."
UV="${UV:-uv}"
"$UV" --version | grep -q '^uv 0\.9\.2' || { echo "compile.sh: needs uv 0.9.2 (got: $("$UV" --version))" >&2; exit 1; }
"$UV" pip compile --generate-hashes --quiet --python-version 3.12 --python-platform x86_64-manylinux_2_28 \
  requirements/release.in -o requirements/release.txt
"$UV" pip compile --generate-hashes --quiet --universal --python-version 3.11 requirements/tests.in -o requirements/tests.txt
"$UV" pip compile --generate-hashes --quiet --universal --python-version 3.11 requirements/audit.in -o requirements/audit.txt
