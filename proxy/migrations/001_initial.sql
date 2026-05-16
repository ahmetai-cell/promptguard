-- PromptGuard audit schema
-- Run once on a fresh database (idempotent via IF NOT EXISTS)

CREATE TABLE IF NOT EXISTS audit_events (
    id             BIGSERIAL PRIMARY KEY,
    ts             BIGINT,
    url            TEXT,
    l1_verdict     TEXT,
    l1_score       REAL,
    l1_matches     JSONB,
    l2_label       TEXT,
    l2_score       REAL,
    embed_score    REAL,
    embed_category TEXT,
    l2_verdict     TEXT,
    final_verdict  TEXT,
    latency_ms     REAL,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_created  ON audit_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_verdict  ON audit_events (final_verdict);
