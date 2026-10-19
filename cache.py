"""A small SQLite cache for enrichment results.

Each row is keyed by (source, indicator_type, indicator) and holds the
EnrichmentResult as JSON plus the time it was stored. Rows older than the
TTL are ignored and get overwritten by the next successful lookup.

Only successful results are cached. Errors, rate limits, and skips are not,
so a temporary failure never hides a real result for 24 hours.
"""

import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from models import EnrichmentResult, IndicatorType

DEFAULT_CACHE_PATH = Path(__file__).parent / "enrichment_cache.sqlite3"
DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24 hours


class Cache:
    def __init__(
        self,
        path: Path | str | None = None,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ):
        # `clock` returns the current time in seconds. Tests pass a fake clock
        # to check expiry without actually waiting.
        self.path = Path(path) if path is not None else DEFAULT_CACHE_PATH
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._create_table()

    def get(
        self, source: str, indicator_type: IndicatorType, indicator: str
    ) -> EnrichmentResult | None:
        """Return a fresh cached result (with cached=True), or None on a miss."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT result_json, stored_at FROM enrichment_cache"
                    " WHERE source = ? AND indicator_type = ? AND indicator = ?",
                    (source, indicator_type, _normalize(indicator)),
                ).fetchone()
        except sqlite3.Error:
            return None  # A broken cache should slow us down, not crash triage.

        if row is None:
            return None

        result_json, stored_at = row
        if self.clock() - stored_at >= self.ttl_seconds:
            return None  # Expired.

        try:
            result = EnrichmentResult.model_validate_json(result_json)
        except ValidationError:
            return None  # Stored by an incompatible older version; treat as a miss.
        return result.model_copy(update={"cached": True})

    def put(self, result: EnrichmentResult) -> None:
        """Store a result, but only if the lookup actually succeeded."""
        if not result.succeeded():
            return

        # Store the raw enrichment only. `cached` and `verdict` describe how
        # the result was used, not what the API said.
        clean = result.model_copy(update={"cached": False, "verdict": None})
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO enrichment_cache"
                    " (source, indicator_type, indicator, result_json, stored_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        result.source,
                        result.indicator_type,
                        _normalize(result.indicator),
                        clean.model_dump_json(),
                        self.clock(),
                    ),
                )
        except sqlite3.Error:
            pass  # Failing to cache is not worth failing the triage over.

    def get_or_lookup(
        self,
        source: str,
        indicator_type: IndicatorType,
        indicator: str,
        lookup: Callable[[str], EnrichmentResult],
    ) -> EnrichmentResult:
        """Return the cached result if there is one, otherwise call `lookup` and cache it."""
        cached = self.get(source, indicator_type, indicator)
        if cached is not None:
            return cached

        result = lookup(indicator)
        self.put(result)
        return result

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # A new connection per operation keeps this safe to use from multiple
        # threads later (e.g. FastAPI).
        conn = sqlite3.connect(self.path)
        try:
            with conn:  # Commits on success, rolls back on error.
                yield conn
        finally:
            conn.close()  # sqlite3's own `with` does not close the connection.

    def _create_table(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS enrichment_cache ("
                    " source TEXT NOT NULL,"
                    " indicator_type TEXT NOT NULL,"
                    " indicator TEXT NOT NULL,"
                    " result_json TEXT NOT NULL,"
                    " stored_at REAL NOT NULL,"
                    " PRIMARY KEY (source, indicator_type, indicator))"
                )
        except sqlite3.Error:
            pass  # get() and put() will also fail quietly; lookups still work.


def _normalize(indicator: str) -> str:
    """Make "ABC.example." and "abc.example" share one cache entry."""
    return indicator.strip().lower().rstrip(".")
