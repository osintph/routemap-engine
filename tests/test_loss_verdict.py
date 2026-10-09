"""The route's loss: only what persists to the destination counts.

Generalised over the class of misreading, not one trace: across many random
paths, the reported loss is the destination's own, never a figure taken from a
hop on the way, and every hop whose loss is gone further down is named as rate
limiting.
"""
import random

from routemap_engine import geo


def _hop(n, loss, answered=True):
    return {"hop": n, "addresses": [f"192.0.2.{n}"] if answered else [], "loss_pct": loss,
            "min_rtt_ms": None if not answered else 10.0 + n, "annotations": []}


def _verdict(hops):
    return geo.loss_verdict(geo.annotate(hops))


def test_middle_loss_gone_at_the_end_is_no_loss():
    v = _verdict([_hop(1, 0.0), _hop(2, 40.0), _hop(3, 0.0)])
    assert v["loss_pct"] == 0.0 and v["reached"] and v["rate_limited"] == [2]
    assert v["text"].startswith("No loss to the destination.") and "hop 2 " in v["text"]


def test_loss_that_persists_is_the_destinations_figure():
    v = _verdict([_hop(1, 0.0), _hop(2, 20.0), _hop(3, 20.0)])
    assert v["loss_pct"] == 20.0 and v["rate_limited"] == []
    assert v["text"] == "20% loss persists to the destination."


def test_rate_limiting_upstream_of_real_loss_is_not_added_to_it():
    v = _verdict([_hop(1, 60.0), _hop(2, 10.0), _hop(3, 10.0)])
    assert v["loss_pct"] == 10.0 and v["rate_limited"] == [1]


def test_silent_destination_means_unknown_not_zero():
    v = _verdict([_hop(1, 0.0), _hop(2, 30.0), _hop(3, 0.0), _hop(4, 100.0, answered=False)])
    assert v["loss_pct"] is None and not v["reached"] and v["last_hop"] == 3
    assert "unknown" in v["text"]


def test_nothing_answered():
    assert _verdict([])["loss_pct"] is None
    assert _verdict([_hop(1, 100.0, answered=False)])["text"].startswith("No hop answered")


def test_no_loss_figures_at_all_is_not_called_lossless():
    v = _verdict([_hop(1, None), _hop(2, None)])
    assert v["loss_pct"] is None


def test_locate_result_carries_the_verdict():
    import asyncio
    from routemap_engine import parse
    trace = parse.parse_trace("traceroute to x (192.0.2.9), 30 hops max\n"
                              " 1  192.0.2.1  1.0 ms  1.1 ms  1.2 ms\n")
    out = asyncio.run(geo.resolve(trace.hops, None, geo.OFFLINE))
    assert out["loss"] == geo.loss_verdict(out["hops"])


def test_random_paths_report_only_destination_loss():
    rng = random.Random(20261009)
    for _ in range(2000):
        n = rng.randint(1, 12)
        hops = []
        for i in range(1, n + 1):
            r = rng.random()
            if r < 0.1:
                hops.append(_hop(i, 100.0, answered=False))
            else:
                hops.append(_hop(i, rng.choice([0.0, 0.0, 0.0, 10.0, 33.3, 50.0, 66.7])))
        v = _verdict(hops)
        last = hops[-1]
        if last["addresses"] and last["loss_pct"] < 100.0:
            assert v["reached"] and v["loss_pct"] == last["loss_pct"]
        else:
            assert v["loss_pct"] is None and not v["reached"]
        for h in hops:
            if h["hop"] in v["rate_limited"]:
                later = [x["loss_pct"] for x in hops[h["hop"]:] if x["addresses"] and x["loss_pct"] < 100.0]
                assert later and min(later) < h["loss_pct"]
