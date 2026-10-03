"""
Where the engine keeps answers it may reuse.

Only one kind of answer is cached: what CAIDA Hoiho said about a router
hostname. A hostname is cached whether or not it matched, because the misses
are the common case and re-asking for them on every trace would be most of the
traffic sent to CAIDA for no new information. Nothing else from a trace is
stored by the engine: not the text, not the addresses, not the origin.

The engine does not decide where the cache lives. A caller passes any object
with ``get(key)`` and ``set(key, value)``; the TTL is the cache's business.
Three are provided:

  NullCache     nothing is kept (the default when no cache is passed)
  MemoryCache   for one process, with a TTL
  SqliteCache   one file on disk, with a TTL, for the desktop app's config dir

FalconEye passes its own, backed by the application database, so its existing
``route_map_hostname_cache`` table keeps working unchanged.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Protocol

# Thirty days, the window Hoiho answers are trusted for. The ruleset itself is
# dated (2024-08 at the time of writing) and changes rarely.
DEFAULT_TTL_SECONDS = 30 * 24 * 3600


class Cache(Protocol):
    def get(self, key: str) -> dict | None: ...

    def set(self, key: str, value: dict) -> None: ...


class NullCache:
    """Remembers nothing."""

    def get(self, key: str) -> dict | None:
        return None

    def set(self, key: str, value: dict) -> None:
        return None


class MemoryCache:
    """A dict with a TTL. Thread-safe, per instance, never global."""

    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS):
        self.ttl_seconds = float(ttl_seconds)
        self._lock = threading.Lock()
        self._data: dict[str, tuple[float, str]] = {}

    def get(self, key: str) -> dict | None:
        with self._lock:
            hit = self._data.get(key)
            if hit is None:
                return None
            stored_at, blob = hit
            if time.time() - stored_at > self.ttl_seconds:
                del self._data[key]
                return None
        return json.loads(blob)

    def set(self, key: str, value: dict) -> None:
        # Stored serialised, so a caller mutating what it got back cannot
        # change what the next caller gets.
        blob = json.dumps(value)
        with self._lock:
            self._data[key] = (time.time(), blob)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class SqliteCache:
    """One SQLite file, one table, a TTL enforced on read.

    A connection per call: the desktop app reads this from a worker thread and
    the CLI from the main one, and SQLite connections are not shareable across
    threads by default.
    """

    TABLE = "hostname_cache"

    def __init__(self, path: str | Path, ttl_seconds: float = DEFAULT_TTL_SECONDS):
        self.path = Path(path)
        self.ttl_seconds = float(ttl_seconds)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {self.TABLE} ("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL, stored_at REAL NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)

    def get(self, key: str) -> dict | None:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    f"SELECT value, stored_at FROM {self.TABLE} WHERE key = ?",
                    (key,)).fetchone()
        except sqlite3.Error:
            return None
        if row is None or time.time() - row[1] > self.ttl_seconds:
            return None
        try:
            return json.loads(row[0])
        except ValueError:
            return None

    def set(self, key: str, value: dict) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    f"INSERT OR REPLACE INTO {self.TABLE} (key, value, stored_at) "
                    "VALUES (?, ?, ?)", (key, json.dumps(value), time.time()))
        except sqlite3.Error:
            # A cache that cannot be written is a cache miss next time, not a
            # failed trace.
            return None

    def clear(self) -> int:
        """Delete every entry. Returns how many there were."""
        with self._connect() as conn:
            count = conn.execute(f"SELECT COUNT(*) FROM {self.TABLE}").fetchone()[0]
            conn.execute(f"DELETE FROM {self.TABLE}")
        return int(count)

    def __len__(self) -> int:
        with self._connect() as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM {self.TABLE}").fetchone()[0])
