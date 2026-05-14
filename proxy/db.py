"""
PromptGuard audit database — asyncpg-backed PostgreSQL storage.

Falls back gracefully when DATABASE_URL is unset or asyncpg is unavailable,
so development and CI environments work without a live database.
"""
from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("promptguard.db")

try:
    import asyncpg as _asyncpg
    _HAS_ASYNCPG = True
except ImportError:
    _asyncpg = None       # type: ignore[assignment]
    _HAS_ASYNCPG = False

_pool = None   # asyncpg.Pool | None

_DDL = """
CREATE TABLE IF NOT EXISTS audit_events (
    id            BIGSERIAL PRIMARY KEY,
    ts            BIGINT,
    url           TEXT,
    l1_verdict    TEXT,
    l1_score      REAL,
    l1_matches    JSONB,
    l2_label      TEXT,
    l2_score      REAL,
    l2_verdict    TEXT,
    final_verdict TEXT,
    latency_ms    REAL,
    created_at    TIMESTAMPTZ DEFAULT NOW()
)
"""

_INSERT = """
INSERT INTO audit_events
    (ts, url, l1_verdict, l1_score, l1_matches,
     l2_label, l2_score, l2_verdict, final_verdict, latency_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
"""


async def init() -> None:
    """Create connection pool and ensure schema exists.
    Silently skips when DATABASE_URL is unset or asyncpg is missing."""
    global _pool
    url = os.getenv("DATABASE_URL", "")
    if not url or not _HAS_ASYNCPG:
        return
    try:
        _pool = await _asyncpg.create_pool(url, min_size=1, max_size=5)
        async with _pool.acquire() as conn:
            await conn.execute(_DDL)
        logger.info("DB pool ready ✅")
    except Exception as exc:
        logger.warning("DB init failed, falling back to jsonl: %s", exc)
        _pool = None


async def close() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def write(record: dict) -> bool:
    """Insert one audit record. Returns True on success, False when DB unavailable."""
    if not _pool:
        return False
    try:
        await _pool.execute(
            _INSERT,
            record.get("ts"),
            record.get("url"),
            record.get("l1_verdict"),
            record.get("l1_score"),
            json.dumps(record.get("l1_matches", [])),
            record.get("l2_label"),
            record.get("l2_score"),
            record.get("l2_verdict"),
            record.get("final_verdict"),
            record.get("latency_ms"),
        )
        return True
    except Exception as exc:
        logger.warning("DB write failed, falling back to jsonl: %s", exc)
        return False
