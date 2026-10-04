"""
Compare two located routes to the same target: what moved, what is gone, what
is new, where the RTT changed, and whether the destination still answers.

Hops are aligned by where they were placed, not by hop number: one extra hop
early in a path shifts every later number, and a comparison by number would
report the whole tail as changed. Local hops are left out of the alignment.
"""
from __future__ import annotations

import difflib

RTT_CHANGE_MS = 20.0


def _seq(route: dict) -> list[dict]:
    out: list[dict] = []
    for h in route.get("hops") or []:
        if h.get("lat") is None or h.get("source") == "local":
            continue
        place = h.get("place") or f"{h['lat']:.2f},{h['lon']:.2f}"
        rtt = h.get("min_rtt_ms")
        if out and out[-1]["place"] == place:
            out[-1]["hops"].append(h["hop"])
            if rtt is not None:
                out[-1]["rtt"] = rtt if out[-1]["rtt"] is None else min(out[-1]["rtt"], rtt)
            if h.get("asn") and not out[-1]["asn"]:
                out[-1]["asn"] = h["asn"]
            continue
        out.append({"place": place, "hops": [h["hop"]], "rtt": rtt, "asn": h.get("asn")})
    return out


def _trailing_silent(route: dict) -> int:
    n = 0
    for h in reversed(route.get("hops") or []):
        if h.get("min_rtt_ms") is None:
            n += 1
        else:
            break
    return n


def _last_answer(route: dict) -> dict | None:
    answered = [h for h in route.get("hops") or [] if h.get("min_rtt_ms") is not None]
    return answered[-1] if answered else None


def diff_routes(old: dict, new: dict, rtt_threshold_ms: float = RTT_CHANGE_MS) -> dict:
    """{"changes": [...], "old_marks": {hop: mark}, "new_marks": {hop: mark}, "summary": str}

    Marks: "removed" (old side), "added" or "moved" (new side), "rtt" (RTT
    changed by at least *rtt_threshold_ms*), "asn" (same place, different
    ASN), "silent" (new side, the unanswered tail).
    """
    a, b = _seq(old), _seq(new)
    sm = difflib.SequenceMatcher(a=[x["place"] for x in a], b=[x["place"] for x in b], autojunk=False)
    ops = sm.get_opcodes()
    unreached = _trailing_silent(new) > 0 and _trailing_silent(old) == 0
    changes, old_marks, new_marks = [], {}, {}
    for k, (tag, i1, i2, j1, j2) in enumerate(ops):
        if tag == "delete" and unreached and k == len(ops) - 1:
            continue    # not gone: the new trace did not get that far
        if tag in ("delete", "replace"):
            for x in a[i1:i2]:
                for n in x["hops"]:
                    old_marks[n] = "removed"
        if tag in ("insert", "replace"):
            for x in b[j1:j2]:
                for n in x["hops"]:
                    new_marks[n] = "added" if tag == "insert" else "moved"
        if tag == "delete":
            changes.append({"kind": "removed", "places": [x["place"] for x in a[i1:i2]],
                            "old_hops": [n for x in a[i1:i2] for n in x["hops"]]})
        elif tag == "insert":
            changes.append({"kind": "added", "places": [x["place"] for x in b[j1:j2]],
                            "new_hops": [n for x in b[j1:j2] for n in x["hops"]]})
        elif tag == "replace":
            changes.append({"kind": "moved", "old_places": [x["place"] for x in a[i1:i2]],
                            "new_places": [x["place"] for x in b[j1:j2]]})
        else:
            for x, y in zip(a[i1:i2], b[j1:j2]):
                if x["rtt"] is not None and y["rtt"] is not None and abs(y["rtt"] - x["rtt"]) >= rtt_threshold_ms:
                    changes.append({"kind": "rtt", "place": y["place"], "old_ms": x["rtt"], "new_ms": y["rtt"],
                                    "old_hops": x["hops"], "new_hops": y["hops"]})
                    for n in y["hops"]:
                        new_marks.setdefault(n, "rtt")
                if x["asn"] and y["asn"] and x["asn"] != y["asn"]:
                    changes.append({"kind": "asn", "place": y["place"], "old_asn": x["asn"], "new_asn": y["asn"]})
                    for n in y["hops"]:
                        new_marks.setdefault(n, "asn")
    silent = _trailing_silent(new)
    if silent:
        for h in (new.get("hops") or [])[-silent:]:
            new_marks[h["hop"]] = "silent"
    return {"changes": changes, "old_marks": old_marks, "new_marks": new_marks,
            "summary": summary(old, new, a, b, ops, changes, unreached)}


def summary(old, new, a, b, ops, changes, unreached) -> str:
    same = [x["place"] for tag, i1, i2, j1, j2 in ops if tag == "equal" for x in a[i1:i2]]
    parts = []
    if same:
        first = list(dict.fromkeys(same))
        parts.append("Same path through " + ", ".join(first[:4]) + (" and more" if len(first) > 4 else "") + ".")
    sentences = []
    for c in changes:
        if c["kind"] == "removed":
            what = " and ".join(c["places"])
            sentences.append(f"{what} {'is' if len(c['places']) == 1 else 'are'} gone "
                             f"(hop{'s' if len(c['old_hops']) > 1 else ''} "
                             f"{_span(c['old_hops'])} then)")
        elif c["kind"] == "added":
            sentences.append("New: " + ", ".join(c["places"]) + f" (hop{'s' if len(c['new_hops']) > 1 else ''} {_span(c['new_hops'])})")
        elif c["kind"] == "moved":
            sentences.append(", ".join(c["old_places"]) + " then, " + ", ".join(c["new_places"]) + " now")
        elif c["kind"] == "rtt":
            sentences.append(f"{c['place']}: RTT {c['old_ms']:.0f} ms then, {c['new_ms']:.0f} ms now")
        elif c["kind"] == "asn":
            sentences.append(f"{c['place']}: AS{c['old_asn']} then, AS{c['new_asn']} now")
    if sentences:
        parts.append("; ".join(s[:1].upper() + s[1:] for s in sentences) + ".")
    elif not unreached:
        parts.append("No placement changed, and no RTT moved by 20 ms or more.")
    lo, ln = _last_answer(old), _last_answer(new)
    if unreached and ln:
        silent = _trailing_silent(new)
        total = len(new.get("hops") or [])
        parts.append(f"The destination did not answer this time: hops {total - silent + 1} to {total} are silent; "
                     f"last answer {ln['min_rtt_ms']:.0f} ms at hop {ln['hop']}"
                     + (f", against {lo['min_rtt_ms']:.0f} ms at hop {lo['hop']} then." if lo else "."))
    elif lo and ln and abs(ln["min_rtt_ms"] - lo["min_rtt_ms"]) >= RTT_CHANGE_MS:
        parts.append(f"Destination RTT {lo['min_rtt_ms']:.0f} ms then, {ln['min_rtt_ms']:.0f} ms now.")
    return " ".join(parts)


def _span(hops: list[int]) -> str:
    return str(hops[0]) if len(hops) == 1 else f"{hops[0]} to {hops[-1]}"
