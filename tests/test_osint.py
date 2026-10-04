"""ASN, AS path, jurisdictions, RTT steps, anycast, diff, offline tiers, IXP flag.

No network: the offline databases are stand-ins with the maxminddb reader's
interface, and every route comes from the bundled fixtures analysed offline.
"""
import asyncio
import pathlib

import pytest

from routemap_engine import analyse_sync, diff, geo, ixp, offline, osint

FIX = pathlib.Path(__file__).parent / "fixtures" / "routemap"
ORIGIN = (14.5995, 120.9842)


class FakeReader:
    """The two maxminddb calls the engine uses, over a dict of /24s."""
    def __init__(self, table):
        self.table = table

    def _find(self, addr):
        key = ".".join(addr.split(".")[:3])
        return self.table.get(key)

    def get(self, addr):
        return self._find(addr)

    def get_with_prefix_len(self, addr):
        rec = self._find(addr)
        return (rec, 24) if rec else (None, 0)


def _asn_db(table):
    db = offline.OfflineAsn.__new__(offline.OfflineAsn)
    db._db, db.path, db.build_epoch = FakeReader(table), "fake", 0
    return db


def _city_db(table):
    db = offline.OfflineCity.__new__(offline.OfflineCity)
    db._db, db.path, db.build_epoch, db.database_type = FakeReader(table), "fake", 0, "DBIP-City-Lite"
    return db


def _route(name="heise_traceroute.txt"):
    return analyse_sync((FIX / name).read_text(), ORIGIN, sources=geo.OFFLINE).to_dict()


# ---------------------------------------------------------------- RTT steps ---

@pytest.mark.parametrize("step,cls", [(None, "unknown"), (0, "quiet"), (14.9, "quiet"),
                                      (15, "warm"), (59.9, "warm"), (60, "hot"), (250, "hot")])
def test_step_classes_cover_every_boundary(step, cls):
    assert osint.classify_step(step) == cls


def test_thresholds_are_parameters_not_constants():
    assert osint.classify_step(30, quiet_ms=40, hot_ms=100) == "quiet"
    assert osint.step_intensity(70, quiet_ms=40, hot_ms=100) == pytest.approx(0.5)


@pytest.mark.parametrize("name", sorted(p.name for p in FIX.glob("*.txt")))
def test_every_fixture_gives_one_segment_per_placed_group_and_never_a_negative_class(name):
    route = _route(name)
    steps = osint.rtt_steps(route)
    placed = [h for h in route["hops"] if h.get("lat") is not None]
    assert sum(len(s["hops"]) for s in steps) == len(placed)
    for s in steps:
        assert s["class"] in {"quiet", "warm", "hot", "unknown"}
        assert 0.0 <= s["intensity"] <= 1.0


# ----------------------------------------------------------------- AS path ---

def test_as_path_merges_runs_and_keeps_a_return_to_an_earlier_asn():
    route = {"hops": [{"hop": 1, "asn": 1}, {"hop": 2}, {"hop": 3, "asn": 1}, {"hop": 4, "asn": 2, "as_org": "Two Net"},
                      {"hop": 5, "asn": 1}]}
    path = osint.as_path(route)
    assert [p["asn"] for p in path] == [1, 2, 1]
    assert path[0]["hops"] == [1, 3]
    assert osint.as_path_text(path) == "AS1 > AS2 Two > AS1"


def test_offline_asn_never_looks_up_a_private_or_documentation_address():
    seen = []

    class Spy(FakeReader):
        def get_with_prefix_len(self, addr):
            seen.append(addr)
            return super().get_with_prefix_len(addr)
    db = _asn_db({})
    db._db = Spy({})
    for addr in ("192.168.1.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "127.0.0.1", "fe80::1", "not-an-ip"):
        assert db.lookup(addr) is None
    assert seen == []


@pytest.mark.parametrize("name", sorted(p.name for p in FIX.glob("*.txt")))
def test_enrich_offline_only_annotates_hops_with_a_public_address(name):
    route = _route(name)
    table = {".".join(a.split(".")[:3]): {"autonomous_system_number": 64500 + i, "autonomous_system_organization": "X"}
             for i, h in enumerate(route["hops"]) for a in h.get("addresses") or [] if a.count(".") == 3}
    osint.enrich_offline(route, _asn_db(table))
    for h in route["hops"]:
        if h.get("asn"):
            assert any(osint.is_public(a) for a in h["addresses"])
            assert h["as_network"].endswith("/24")


# ----------------------------------------------------------- jurisdictions ---

def test_jurisdictions_merge_skip_local_and_flag_sensitive_and_country_only():
    route = {"hops": [
        {"hop": 1, "lat": 1, "lon": 1, "source": "local", "cc": "PH"},
        {"hop": 2, "lat": 1, "lon": 1, "source": "hoiho", "cc": "PH"},
        {"hop": 3, "lat": 1, "lon": 1, "source": "hoiho", "cc": "ph"},
        {"hop": 4, "lat": 2, "lon": 2, "source": "ip-db", "cc": "SG", "precision": "country"},
        {"hop": 5, "lat": 3, "lon": 3, "source": "hoiho", "cc": "DE"},
    ]}
    j = osint.jurisdictions(route, {"sg"})
    assert [x["cc"] for x in j] == ["PH", "SG", "DE"]
    assert j[0]["hops"] == [2, 3]
    assert j[1] == {"cc": "SG", "hops": [4], "country_only": True, "sensitive": True}


# ----------------------------------------------------------------- anycast ---

def _anycast_route(rtt, asn=None):
    return {"origin": {"lat": ORIGIN[0], "lon": ORIGIN[1]},
            "hops": [{"hop": 1, "min_rtt_ms": 1.0}, {"hop": 2, "min_rtt_ms": rtt, "asn": asn}]}


def test_anycast_note_for_a_destination_too_fast_for_where_it_is_registered():
    note = osint.anycast_note(_anycast_route(3.0), destination_registered=(37.4, -122.1))
    assert note and note.startswith("likely anycast, served from near ") and "PH" in note


def test_anycast_note_for_a_known_content_network_and_silence_otherwise():
    assert "Cloudflare" in osint.anycast_note(_anycast_route(3.0, 13335))
    assert osint.anycast_note(_anycast_route(250.0), destination_registered=(50.1, 8.7)) is None
    assert osint.anycast_note({"hops": [{"hop": 1}]}) is None


# -------------------------------------------------------------- offline tiers ---

def test_offline_city_answers_public_addresses_and_tags_the_provider():
    db = _city_db({"8.8.8": {"location": {"latitude": 37.4, "longitude": -122.1},
                             "city": {"names": {"en": "Mountain View"}}, "country": {"iso_code": "US"}}})
    out = asyncio.run(db(["8.8.8.8", "192.168.1.1", "9.9.9.9"]))
    assert out == {"8.8.8.8": {"lat": 37.4, "lon": -122.1, "city": "Mountain View", "cc": "US", "provider": "dbip"}}


def test_layered_source_asks_online_only_for_what_the_file_missed_and_survives_online_failure():
    calls = []

    async def off(addrs):
        calls.append(("offline", list(addrs)))
        return {a: {"lat": 2, "lon": 2, "city": "B", "cc": "DE", "provider": "dbip"} for a in addrs if a == "2.2.2.2"}

    async def online(addrs):
        calls.append(("online", list(addrs)))
        return {a: {"lat": 1, "lon": 1, "city": "A", "cc": "AU"} for a in addrs}

    async def broken(addrs):
        raise RuntimeError("down")

    out = asyncio.run(offline.layered_ip_db(off, online)(["1.1.1.1", "2.2.2.2"]))
    assert out["1.1.1.1"]["provider"] == "ripestat" and out["2.2.2.2"]["provider"] == "dbip"
    assert calls == [("offline", ["1.1.1.1", "2.2.2.2"]), ("online", ["1.1.1.1"])]
    assert asyncio.run(offline.layered_ip_db(off, broken)(["1.1.1.1", "2.2.2.2"])).keys() == {"2.2.2.2"}
    calls.clear()
    asyncio.run(offline.layered_ip_db(off, None)(["1.1.1.1"]))
    assert calls == [("offline", ["1.1.1.1"])], "online lookups off: nothing goes online"
    assert asyncio.run(offline.layered_ip_db(None, online)(["1.1.1.1"]))["1.1.1.1"]["provider"] == "ripestat"


def test_the_placement_records_which_tier_answered():
    trace = (FIX / "heise_traceroute.txt").read_text()

    async def tier(addrs):
        return {a: {"lat": ORIGIN[0], "lon": ORIGIN[1], "city": "Manila", "cc": "PH", "provider": "dbip"} for a in addrs}
    route = analyse_sync(trace, ORIGIN, sources=geo.Sources(ip_db=tier)).to_dict()
    placed = [h for h in route["hops"] if h["source"] == "ip-db"]
    assert placed and all(h["ip_provider"] == "dbip" for h in placed)


# -------------------------------------------------------------------- diff ---

def _hop(n, place, rtt, asn=None):
    return {"hop": n, "lat": 0 if place else None, "lon": 0, "place": place, "min_rtt_ms": rtt, "source": "hoiho", "asn": asn}


def test_diff_aligns_by_place_so_an_inserted_hop_does_not_shift_the_rest():
    old = {"hops": [_hop(1, "A", 5), _hop(2, "B", 10), _hop(3, "C", 20)]}
    new = {"hops": [_hop(1, "A", 5), _hop(2, "X", 7), _hop(3, "B", 10), _hop(4, "C", 21)]}
    d = diff.diff_routes(old, new)
    assert [c["kind"] for c in d["changes"]] == ["added"]
    assert d["new_marks"] == {2: "added"}


def test_diff_does_not_call_hops_gone_when_the_new_run_ended_in_silence():
    old = {"hops": [_hop(1, "A", 5), _hop(2, "B", 10), _hop(3, "C", 20)]}
    new = {"hops": [_hop(1, "A", 5), _hop(2, None, None), _hop(3, None, None)]}
    d = diff.diff_routes(old, new)
    assert not [c for c in d["changes"] if c["kind"] == "removed"]
    assert d["new_marks"] == {2: "silent", 3: "silent"}
    assert "did not answer this time" in d["summary"]


def test_diff_reports_rtt_and_asn_changes_at_the_same_place():
    old = {"hops": [_hop(1, "A", 5, 1), _hop(2, "B", 10, 2)]}
    new = {"hops": [_hop(1, "A", 50, 1), _hop(2, "B", 12, 3)]}
    kinds = sorted(c["kind"] for c in diff.diff_routes(old, new)["changes"])
    assert kinds == ["asn", "rtt"]


@pytest.mark.parametrize("name", sorted(p.name for p in FIX.glob("*.txt")))
def test_a_route_compared_with_itself_has_no_changes(name):
    route = _route(name)
    d = diff.diff_routes(route, route)
    assert d["changes"] == [] and d["old_marks"] == {}
    assert "\u2014" not in d["summary"]


# --------------------------------------------------------------------- IXP ---

def test_ixp_labelling_is_off_and_does_nothing_while_off():
    assert ixp.ENABLED is False
    route = {"hops": [{"hop": 1, "addresses": ["203.0.113.5"]}]}
    ixp.label_hops(route, [{"prefix": "203.0.113.0/24", "name": "Example IX"}])
    assert "ixp" not in route["hops"][0]


def test_ixp_labelling_when_switched_on(monkeypatch):
    monkeypatch.setattr(ixp, "ENABLED", True)
    route = {"hops": [{"hop": 1, "addresses": ["203.0.113.5"]}, {"hop": 2, "addresses": ["198.51.100.1"]}]}
    ixp.label_hops(route, [{"prefix": "203.0.113.0/24", "name": "Example IX"}, {"prefix": "bad"}])
    assert route["hops"][0]["ixp"] == "Example IX" and "ixp" not in route["hops"][1]


@pytest.mark.parametrize("name", sorted(p.name for p in FIX.glob("*.txt")))
def test_an_enriched_route_still_matches_the_schema(name):
    jsonschema = pytest.importorskip("jsonschema")
    from routemap_engine import schema
    route = _route(name)
    table = {".".join(a.split(".")[:3]): {"autonomous_system_number": 64500, "autonomous_system_organization": "X"}
             for h in route["hops"] for a in h.get("addresses") or [] if a.count(".") == 3}
    osint.enrich_offline(route, _asn_db(table))
    assert any(h.get("asn") for h in route["hops"])
    jsonschema.validate(route, schema())
