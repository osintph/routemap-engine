"""One real reverse trace via RIPE Atlas, with the engine from this checkout
or this commit (0.7.0 release check). Run by a person, never by CI.

    python real_reverse_trace.py [TARGET]

The RIPE Atlas key is read from the environment variable ROUTEMAP_ATLAS_KEY
or typed at a hidden prompt. It is sent only to atlas.ripe.net, never
printed, never written anywhere.

What it does, in order, and what leaves the machine:
1. Resolves TARGET and asks RIPEstat for this machine's public IP of the
   same family, both networks' AS numbers and the target's location.
2. Picks a connected Atlas probe in the target's AS (else its country),
   nearest the target, never in this machine's AS, and reads the balance.
   Nothing is scheduled yet and no credits are spent.
3. Prints the plan: the probe, the public IP that would be published, the
   cost. Only if you type "publish" does it schedule the measurement, which
   RIPE NCC publishes with your public IP as its target, for 60 credits.
4. Waits for the result and prints it, placed on the map's terms.
"""
from __future__ import annotations

import asyncio
import getpass
import os
import sys

from routemap_engine import __about__, analyse, atlas, geo, probe, whereami

UA = f"routemap-engine/{__about__.__version__} (release check; +https://github.com/osintph/routemap-engine)"
SOURCEAPP = "routemap-engine-release-check"


async def main(target: str) -> int:
    print(f"routemap-engine {__about__.__version__}, module {__about__.__file__}")
    dest = probe.resolve(target)
    af = probe.family_of(dest)
    print(f"Target {target} -> {dest} (IPv{af})")
    key = os.environ.get("ROUTEMAP_ATLAS_KEY") or getpass.getpass("RIPE Atlas API key (not shown, not stored): ")
    me = await whereami.public_ip(user_agent=UA, sourceapp=SOURCEAPP, family=af)
    dest_asn = await whereami.asn_of(dest, user_agent=UA, sourceapp=SOURCEAPP)
    my_asn = await whereami.asn_of(me, user_agent=UA, sourceapp=SOURCEAPP)
    located = (await geo.ip_geolocate([dest], user_agent=UA, sourceapp=SOURCEAPP)).get(dest) or {}
    pos = (located["lat"], located["lon"]) if located.get("lat") is not None else None
    print(f"Your public IPv{af}: {me} (AS{my_asn}); target AS{dest_asn}, {located.get('cc') or '?'}, "
          f"located at {pos}")
    client = atlas.Atlas(key, user_agent=UA, description="routemap-engine reverse traceroute (release check)")
    try:
        chosen = await client.select_reverse_probe(dest_asn, located.get("cc"), pos, user_asn=my_asn, af=af)
    except atlas.AtlasUnavailable as exc:
        print(f"No probe: {exc.message}")
        return 2
    balance = await client.balance()
    print(f"Probe #{chosen['id']} AS{chosen.get('asn')} {chosen.get('country')}, "
          f"{chosen.get('distance_km')} km from the target's located position")
    print(f"Balance: {balance.state}" + (f", {balance.current:,} credits" if balance.current is not None else ""))
    if balance.state == "bad_key":
        print(f"RIPE Atlas did not accept the key ({balance.message}). Nothing scheduled.")
        return 4
    print()
    print("RIPE Atlas measurements are public. This one would publish your public IP address,")
    print(f"{me}, as its target, and cost {atlas.TRACEROUTE_CREDITS} credits. Route Map cannot remove it afterwards.")
    if input('Type "publish" to schedule it, anything else to stop: ').strip() != "publish":
        print("Nothing scheduled, no credits spent.")
        return 0
    try:
        msm = await client.create_reverse(me, int(chosen["id"]), consent=True)
    except atlas.AtlasUnavailable as exc:
        print(f"RIPE Atlas refused it ({exc.kind}): {exc.message}")
        return 3
    print(f"Measurement {msm}: https://atlas.ripe.net/measurements/{msm}/  (waiting, usually 30 to 90 s)")
    text = await client.wait(msm, on_wait=lambda t: print(f"  waiting {t:.0f} s", flush=True))
    print(text)
    origin = (chosen["lat"], chosen["lon"]) if chosen.get("lat") is not None else None
    route = await analyse(text, origin)
    print(f"{'#':>3}  {'address':<40} {'place':<28} {'source':<10} {'min ms':>8}")
    for h in route.hops:
        rtt = h.get("min_rtt_ms")
        print(f"{h['hop']:>3}  {h.get('address') or '*':<40} {(h.get('place') or '')[:28]:<28} "
              f"{h.get('source') or '':<10} {'' if rtt is None else f'{rtt:.1f}':>8}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "heise.de")))
