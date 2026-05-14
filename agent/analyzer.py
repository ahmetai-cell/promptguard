"""
PromptGuard Agent — Analyzer

Reads audit.jsonl, detects:
  - FP candidates: L1 fired but L2 said LEGITIMATE with high confidence
  - FN candidates: need HackaPrompt dataset (handled in evaluator.py)
  - Pattern-level FP rate: which patterns cause the most false alarms

Output: AnalysisReport dataclass
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


# ─── Data models ─────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    ts: int
    url: str
    l1_verdict: str
    l1_score: float
    l1_matches: list[str]
    l2_label: str
    l2_score: float
    l2_verdict: str
    final_verdict: str
    latency_ms: float
    prompt: str | None = None


@dataclass
class PatternFPStats:
    pattern_id: str          # e.g. "P030"
    tag: str                 # e.g. "output-control"
    total_fires: int         # how many times it triggered
    fp_fires: int            # how many times L2 said LEGITIMATE
    fp_rate: float           # fp_fires / total_fires


@dataclass
class AnalysisReport:
    total_entries: int
    fp_candidates: list[AuditEntry]      # L1 blocked, L2 said legitimate
    disagreement_rate: float             # % of entries where L1 and L2 disagree
    pattern_fp_stats: list[PatternFPStats]
    high_fp_patterns: list[str]          # pattern IDs with FP rate > threshold
    summary: str


# ─── Loader ──────────────────────────────────────────────────────────────────

def load_audit(path: str | Path) -> list[AuditEntry]:
    p = Path(path)
    if not p.exists():
        return []

    entries = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            entries.append(AuditEntry(
                ts=d.get("ts", 0),
                url=d.get("url", ""),
                l1_verdict=d.get("l1_verdict", ""),
                l1_score=float(d.get("l1_score", 0)),
                l1_matches=d.get("l1_matches", []),
                l2_label=d.get("l2_label", ""),
                l2_score=float(d.get("l2_score", 0)),
                l2_verdict=d.get("l2_verdict", ""),
                final_verdict=d.get("final_verdict", ""),
                latency_ms=float(d.get("latency_ms", 0)),
                prompt=d.get("prompt"),
            ))
        except (KeyError, ValueError, json.JSONDecodeError):
            continue
    return entries


# ─── Core analysis ───────────────────────────────────────────────────────────

def analyze(
    audit_path: str | Path,
    fp_confidence_threshold: float = 0.85,
    high_fp_rate_threshold: float = 0.30,
) -> AnalysisReport:
    """
    fp_confidence_threshold: L2 must say LEGITIMATE with >= this confidence
                             to count as a FP candidate
    high_fp_rate_threshold:  patterns with FP rate above this are flagged
    """
    entries = load_audit(audit_path)

    if not entries:
        return AnalysisReport(
            total_entries=0,
            fp_candidates=[],
            disagreement_rate=0.0,
            pattern_fp_stats=[],
            high_fp_patterns=[],
            summary="No audit entries found.",
        )

    # FP candidates: L1 said WARN or BLOCK, L2 said LEGITIMATE confidently
    fp_candidates = [
        e for e in entries
        if e.l1_verdict in ("WARN", "BLOCK")
        and e.l2_label == "LEGITIMATE"
        and e.l2_score >= fp_confidence_threshold
    ]

    # Disagreement rate
    disagreements = sum(
        1 for e in entries
        if (e.l1_verdict in ("WARN", "BLOCK")) != (e.l2_verdict == "BLOCK")
    )
    disagreement_rate = disagreements / len(entries) if entries else 0.0

    # Per-pattern FP stats
    pattern_total: dict[str, int] = defaultdict(int)
    pattern_fp: dict[str, int] = defaultdict(int)
    pattern_tag: dict[str, str] = {}

    for e in entries:
        if e.l1_verdict not in ("WARN", "BLOCK"):
            continue
        for match in e.l1_matches:
            # match format: "P030:output-control"
            parts = match.split(":", 1)
            pid = parts[0]
            tag = parts[1] if len(parts) > 1 else ""
            pattern_total[pid] += 1
            pattern_tag[pid] = tag
            if e.l2_label == "LEGITIMATE" and e.l2_score >= fp_confidence_threshold:
                pattern_fp[pid] += 1

    pattern_fp_stats = []
    for pid, total in pattern_total.items():
        fp_count = pattern_fp.get(pid, 0)
        fp_rate = fp_count / total if total > 0 else 0.0
        pattern_fp_stats.append(PatternFPStats(
            pattern_id=pid,
            tag=pattern_tag.get(pid, ""),
            total_fires=total,
            fp_fires=fp_count,
            fp_rate=round(fp_rate, 3),
        ))

    pattern_fp_stats.sort(key=lambda x: x.fp_rate, reverse=True)
    high_fp_patterns = [
        s.pattern_id for s in pattern_fp_stats
        if s.fp_rate >= high_fp_rate_threshold and s.total_fires >= 3
    ]

    summary = _build_summary(
        total=len(entries),
        fp_count=len(fp_candidates),
        disagreement_rate=disagreement_rate,
        high_fp_patterns=high_fp_patterns,
        pattern_fp_stats=pattern_fp_stats,
    )

    return AnalysisReport(
        total_entries=len(entries),
        fp_candidates=fp_candidates,
        disagreement_rate=round(disagreement_rate, 3),
        pattern_fp_stats=pattern_fp_stats,
        high_fp_patterns=high_fp_patterns,
        summary=summary,
    )


def _build_summary(
    total: int,
    fp_count: int,
    disagreement_rate: float,
    high_fp_patterns: list[str],
    pattern_fp_stats: list[PatternFPStats],
) -> str:
    lines = [
        f"Total audit entries analyzed: {total}",
        f"FP candidates (L1 fired, L2 said legitimate): {fp_count} ({fp_count/total*100:.1f}%)" if total else "FP candidates: 0",
        f"L1-L2 disagreement rate: {disagreement_rate*100:.1f}%",
    ]

    if high_fp_patterns:
        lines.append(f"High-FP patterns (>30% false alarm rate): {', '.join(high_fp_patterns)}")
    else:
        lines.append("No patterns with high FP rate detected.")

    if pattern_fp_stats:
        lines.append("\nTop patterns by FP rate:")
        for s in pattern_fp_stats[:5]:
            lines.append(
                f"  {s.pattern_id} ({s.tag}): {s.fp_fires}/{s.total_fires} FP "
                f"({s.fp_rate*100:.0f}%)"
            )

    return "\n".join(lines)


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "proxy/audit.jsonl"
    report = analyze(path)
    print(report.summary)
    print(f"\nFP candidate prompts:")
    for e in report.fp_candidates[:5]:
        print(f"  [{e.l1_verdict} {e.l1_score:.2f}] L2={e.l2_label} {e.l2_score:.2f} | {e.prompt[:80] if e.prompt else '(no prompt)'}...")
