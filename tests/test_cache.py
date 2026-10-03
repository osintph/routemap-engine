"""The Hoiho answer caches: TTL honoured, nothing shared between instances."""
import time

from routemap.engine.cache import MemoryCache, NullCache, SqliteCache


def test_the_null_cache_remembers_nothing():
    cache = NullCache()
    cache.set("a.example.net", {"located": False})
    assert cache.get("a.example.net") is None


def test_memory_cache_expires_and_is_per_instance():
    one, two = MemoryCache(ttl_seconds=0.2), MemoryCache()
    one.set("a.example.net", {"located": True})
    assert one.get("a.example.net") == {"located": True}
    assert two.get("a.example.net") is None
    time.sleep(0.3)
    assert one.get("a.example.net") is None


def test_memory_cache_hands_out_copies():
    cache = MemoryCache()
    cache.set("a.example.net", {"match_strs": []})
    cache.get("a.example.net")["match_strs"].append("tampered")
    assert cache.get("a.example.net") == {"match_strs": []}


def test_sqlite_cache_persists_expires_and_clears(tmp_path):
    path = tmp_path / "sub" / "cache.sqlite3"
    cache = SqliteCache(path, ttl_seconds=0.3)
    cache.set("a.example.net", {"located": True, "lat": 1.0})
    assert SqliteCache(path).get("a.example.net") == {"located": True, "lat": 1.0}
    assert len(cache) == 1
    time.sleep(0.4)
    assert cache.get("a.example.net") is None
    assert cache.clear() == 1 and len(cache) == 0
