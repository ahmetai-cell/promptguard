"""
PromptGuard audit database — asyncpg-backed PostgreSQL storage (Supabase).

Falls back gracefully when DATABASE_URL is unset or asyncpg is unavailable,
so development and CI environments work without a live database.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

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
    embed_score   REAL,
    embed_category TEXT,
    l2_verdict    TEXT,
    final_verdict TEXT,
    latency_ms    REAL,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_events (final_verdict);
"""

_INSERT = """
INSERT INTO audit_events
    (ts, url, l1_verdict, l1_score, l1_matches,
     l2_label, l2_score, embed_score, embed_category,
     l2_verdict, final_verdict, latency_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
"""


async def init() -> None:
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
            record.get("embed_score", 0.0),
            record.get("embed_category", ""),
            record.get("l2_verdict"),
            record.get("final_verdict"),
            record.get("latency_ms"),
        )
        return True
    except Exception as exc:
        logger.warning("DB write failed, falling back to jsonl: %s", exc)
        return False


async def get_totals() -> dict:
    """Aggregate totals from audit_events. Returns zeros if DB unavailable."""
    if not _pool:
        return {"blocked": 0, "warned": 0, "allowed": 0, "total": 0}
    try:
        row = await _pool.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE final_verdict = 'BLOCK')  AS blocked,
                COUNT(*) FILTER (WHERE l1_verdict    = 'WARN'
                                   AND final_verdict = 'ALLOW')  AS warned,
                COUNT(*) FILTER (WHERE final_verdict = 'ALLOW'
                                   AND l1_verdict    != 'WARN')  AS allowed,
                COUNT(*)                                          AS total
            FROM audit_events
        """)
        return dict(row)
    except Exception as exc:
        logger.warning("get_totals failed: %s", exc)
        return {"blocked": 0, "warned": 0, "allowed": 0, "total": 0}


async def get_daily(days: int = 7) -> list[dict]:
    """Per-day blocked/warned counts for last `days` days."""
    if not _pool:
        return []
    try:
        rows = await _pool.fetch("""
            SELECT
                DATE(created_at AT TIME ZONE 'UTC') AS day,
                COUNT(*) FILTER (WHERE final_verdict = 'BLOCK') AS blocked,
                COUNT(*) FILTER (WHERE l1_verdict = 'WARN')     AS warned
            FROM audit_events
            WHERE created_at >= NOW() - ($1 || ' days')::INTERVAL
            GROUP BY day
            ORDER BY day ASC
        """, str(days))
        return [{"day": str(r["day"]), "blocked": r["blocked"], "warned": r["warned"]} for r in rows]
    except Exception as exc:
        logger.warning("get_daily failed: %s", exc)
        return []


async def get_top_categories(days: int = 30, limit: int = 10) -> list[dict]:
    """Top attack categories from l1_matches JSONB field."""
    if not _pool:
        return []
    try:
        rows = await _pool.fetch("""
            SELECT
                split_part(tag, ':', 2) AS category,
                COUNT(*)                AS count
            FROM audit_events,
                 LATERAL jsonb_array_elements_text(l1_matches) AS tag
            WHERE created_at >= NOW() - ($1 || ' days')::INTERVAL
              AND final_verdict = 'BLOCK'
              AND tag LIKE '%:%'
            GROUP BY category
            ORDER BY count DESC
            LIMIT $2
        """, str(days), limit)
        return [{"category": r["category"], "count": r["count"]} for r in rows]
    except Exception as exc:
        logger.warning("get_top_categories failed: %s", exc)
        return []
