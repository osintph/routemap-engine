"""One real IPv6 trace, and an IPv6 path discovery where the system allows
it, with the engine from this checkout or this commit (0.7.0 release check).
Run by a person, never by CI.

    python real_ipv6_trace.py [TARGET]

Sends ICMPv6 probes to TARGET and the routers on the way (at most 20 a
second for the discovery, 600 probes at most), and asks the usual lookups
(CAIDA Hoiho, RIPEstat) where the hops are. Nothing else leaves the machine.
"""
from __future__ import annotations

import sys

from routemap_engine import __about__, analyse_sync, multipath, probe, runner


def main(target: str) -> int:
    print(f"routemap-engine {__about__.__version__}, module {__about__.__file__}, platform {sys.platform}")
    try:
        dest = probe.resolve(target, "6")
    except probe.NoAddress as exc:
        print(f"FAIL: {exc}")
        return 2
    ok, why = probe.available(6)
    print(f"Target {target} -> {dest}; built-in ICMPv6 prober: {'yes' if ok else 'no, ' + why}")
    try:
        result = runner.run_trace(target, runner.TraceOptions(family="6", on_line=print))
    except probe.NoAddress as exc:
        print(f"RESULT trace: FAIL: {exc}")
        return 2
    print(f"-- tool {result.tool} {' '.join(result.argv[1:])}, exit {result.returncode}, {result.seconds} s")
    route = analyse_sync(result.text)
    reached = any(h.get("address") == dest for h in route.hops)
    for h in route.hops:
        rtt = h.get("min_rtt_ms")
        print(f"{h['hop']:>3}  {h.get('address') or '*':<40} {(h.get('place') or '')[:28]:<28} "
              f"{h.get('source') or '':<10} {'' if rtt is None else f'{rtt:.1f}':>8}")
    print(f"RESULT trace: {'PASS' if reached else 'FAIL'}: {len(route.hops)} hops, target "
          f"{'reached' if reached else 'not reached'} over IPv6 with {result.tool}")
    ok, why = multipath.available()
    if not ok:
        print(f"Path discovery: not on this system ({why})")
        return 0 if reached else 1
    d = multipath.discover(target, family="6", options=multipath.Options(budget=600))
    print(f"RESULT paths: at least {len(d.paths)} path(s), {d.flows_used} flows, {d.probes_sent} probes, "
          f"{d.seconds:.0f} s, stopped by {d.stopped_by}, per-packet hops {d.per_packet_hops}")
    for p in d.paths:
        print(f"  {p.id}: {len(p.flows)} flows, RTT to target {p.rtt_to_target_ms}, loss {p.loss_pct}%")
    return 0 if reached else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "heise.de"))
