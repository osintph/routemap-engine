"""Stands in for traceroute in the runner tests.

Prints a real fixture line by line, sleeping between lines so a test can see
that output streams rather than arriving at the end. The last argument is the
target, exactly as the real tool receives it, and it is echoed in the banner so
a test can check the argument list.

    fake_trace_tool.py FIXTURE DELAY_SECONDS TARGET
"""
import pathlib
import sys
import time

fixture, delay, target = sys.argv[1], float(sys.argv[2]), sys.argv[-1]
lines = pathlib.Path(fixture).read_text().splitlines()
print(f"traceroute to {target} ({target}), 30 hops max, 60 byte packets", flush=True)
for line in lines:
    if line.lower().startswith("traceroute to"):
        continue
    print(line, flush=True)
    time.sleep(delay)
