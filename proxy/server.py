"""
PromptGuard L2 Proxy — FastAPI

Receives WARN events from the browser extension (L1),
runs the DeBERTa classifier, and returns a final verdict.

POST /events   — main analysis endpoint (called by logger.js)
GET  /health   — liveness check
GET  /stats    — session counters
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import db
from classifier import get_classifier
from embedder import get_embedder
from normalizer import normalize

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("promptguard.proxy")

AUDIT_LOG = Path(os.getenv("AUDIT_LOG", "audit.jsonl"))
L2_BLOCK_THRESHOLD = float(os.getenv("L2_BLOCK_THRESHOLD", "0.80"))
_RL_WINDOW = 60.0   # sliding window in seconds


# ─── Auth ─────────────────────────────────────────────────────────────────────

def _verify_token(request: Request) -> bool:
    """Return True if auth passes. Auth is disabled when PG_TOKEN env var is unset."""
    token = os.getenv("PG_TOKEN", "")
    if not token:
        return True
    header = request.headers.get("X-PG-Token", "")
    return secrets.compare_digest(header, token)


# ─── Rate limiter (sliding window, in-memory, per IP) ─────────────────────────

_rl_buckets: dict[str, list[float]] = defaultdict(list)


def _check_rate(ip: str) -> bool:
    """Return False if this IP has exceeded the rate limit."""
    limit = int(os.getenv("RATE_LIMIT_MAX", "100"))
    now = time.monotonic()
    bucket = _rl_buckets[ip]
    cutoff = now - _RL_WINDOW
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= limit:
        return False
    bucket.append(now)
    return True


# ─── Audit log — DB primary, jsonl fallback ───────────────────────────────────

async def _write_audit(record: dict) -> None:
    if await db.write(record):
        return
    try:
        with AUDIT_LOG.open("a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:
        logger.warning("Audit log write failed: %s", exc)


# ─── App lifespan ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI):
    await db.init()
    yield
    await db.close()


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PromptGuard L2 Proxy",
    description="Semantic analysis layer for browser-flagged prompts.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ─── In-memory session stats ──────────────────────────────────────────────────

_stats: dict[str, int] = defaultdict(int)


# ─── Models ───────────────────────────────────────────────────────────────────

class L1Event(BaseModel):
    ts: int
    verdict: str                        # L1 verdict ("WARN" expected)
    score: float                        # L1 score
    matches: list[str] = Field(default_factory=list)
    url: str = ""
    prompt: Optional[str] = None       # actual user text — needed for L2
    ua: Optional[str] = None


class L2Response(BaseModel):
    l1_verdict: str
    l1_score: float
    l2_verdict: str                     # "BLOCK" | "ALLOW"
    l2_label: str                       # "INJECTION" | "LEGITIMATE"
    l2_score: float
    embed_score: float = 0.0            # cosine similarity to nearest attack centroid
    embed_category: str = ""            # closest attack category
    final_verdict: str                  # authoritative decision
    latency_ms: float


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.post("/events", response_model=L2Response)
async def analyze_event(event: L1Event, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"

    if not _check_rate(ip):
        _stats["rate_limited"] += 1
        return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})

    if not _verify_token(request):
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    t0 = time.perf_counter()

    _stats["received"] += 1

    # If no prompt text, trust L1 verdict as-is
    if not event.prompt or not event.prompt.strip():
        _stats["no_prompt"] += 1
        final = "BLOCK" if event.verdict == "BLOCK" else "ALLOW"
        return L2Response(
            l1_verdict=event.verdict,
            l1_score=event.score,
            l2_verdict="ALLOW",
            l2_label="LEGITIMATE",
            l2_score=0.0,
            final_verdict=final,
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        )

    clean_prompt = normalize(event.prompt)

    clf = get_classifier()
    result = clf.classify(clean_prompt)

    emb_result = get_embedder().score(clean_prompt)

    deberta_block = result.is_injection and result.score >= L2_BLOCK_THRESHOLD
    embed_block   = emb_result.is_injection

    l2_verdict = "BLOCK" if (deberta_block or embed_block) else "ALLOW"

    # Final: BLOCK if either L1 was already BLOCK, or L2 says BLOCK
    final_verdict = "BLOCK" if (event.verdict == "BLOCK" or l2_verdict == "BLOCK") else "ALLOW"

    _stats[f"l2_{l2_verdict.lower()}"] += 1
    _stats[f"final_{final_verdict.lower()}"] += 1

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    audit_record = {
        "ts": event.ts,
        "url": event.url,
        "l1_verdict": event.verdict,
        "l1_score": event.score,
        "l1_matches": event.matches,
        "l2_label": result.label,
        "l2_score": result.score,
        "embed_score": emb_result.score,
        "embed_category": emb_result.category,
        "l2_verdict": l2_verdict,
        "final_verdict": final_verdict,
        "latency_ms": latency_ms,
    }
    await _write_audit(audit_record)

    logger.info(
        "L1=%s(%.2f) DeBERTa=%s(%.2f) Embed=%.2f(%s) → %s [%.0fms]",
        event.verdict, event.score,
        result.label, result.score,
        emb_result.score, emb_result.category or "-",
        final_verdict, latency_ms,
    )

    return L2Response(
        l1_verdict=event.verdict,
        l1_score=event.score,
        l2_verdict=l2_verdict,
        l2_label=result.label,
        l2_score=result.score,
        embed_score=emb_result.score,
        embed_category=emb_result.category,
        final_verdict=final_verdict,
        latency_ms=latency_ms,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "model": "ProtectAI/deberta-v3-base-prompt-injection-v2"}


@app.get("/stats")
async def stats():
    return dict(_stats)
