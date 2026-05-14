"""
PromptGuard Agent — Pattern Proposer

Takes FN examples (missed injections) or FP-heavy patterns,
calls Claude API, and proposes:
  - New regex patterns for FN gaps
  - Severity adjustments for FP-heavy patterns

Output is a PatternProposal list — never auto-applied, always
reviewed as a GitHub PR.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

import anthropic

MODEL = "claude-sonnet-4-6"

_CLIENT: anthropic.Anthropic | None = None


def _client() -> anthropic.Anthropic:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = anthropic.Anthropic()
    return _CLIENT


# ─── Data models ─────────────────────────────────────────────────────────────

@dataclass
class NewPatternProposal:
    kind: str              # "new_pattern"
    pattern_id: str        # e.g. "P038"
    regex: str             # raw regex string
    severity: float        # 0.0–1.0
    tag: str               # e.g. "override"
    rationale: str         # why this pattern catches the FN
    example_prompt: str    # the FN example it targets


@dataclass
class SeverityAdjustment:
    kind: str              # "severity_adjustment"
    pattern_id: str        # existing pattern to adjust
    current_severity: float
    proposed_severity: float
    rationale: str


Proposal = NewPatternProposal | SeverityAdjustment


# ─── System prompt ────────────────────────────────────────────────────────────

_SYSTEM = """You are a security engineer specializing in prompt injection detection.
You analyze failed detections (false negatives) and over-triggering patterns (false positives)
in a browser-based LLM firewall.

Your job is to propose precise regex patterns and severity adjustments.

Rules:
- Patterns must be in Python/JavaScript compatible regex syntax
- Patterns must be specific enough to avoid new false positives
- Severity 0.90+ = near-certain attack, 0.50-0.75 = suspicious, 0.40-0.50 = weak signal
- Always provide a rationale
- Respond ONLY with valid JSON — no markdown, no explanation outside JSON

Response format:
[
  {
    "kind": "new_pattern",
    "pattern_id": "P038",
    "regex": "your\\\\s+true\\\\s+(self|nature|identity)",
    "severity": 0.85,
    "tag": "persona",
    "rationale": "Catches 'reveal your true self' persona injection variants",
    "example_prompt": "..."
  },
  {
    "kind": "severity_adjustment",
    "pattern_id": "P030",
    "current_severity": 0.60,
    "proposed_severity": 0.45,
    "rationale": "Triggers on legitimate requests like 'always begin with a greeting'"
  }
]"""


# ─── Proposer ────────────────────────────────────────────────────────────────

def propose_for_fn(
    fn_examples: list[str],
    next_pattern_id: str = "P038",
) -> list[Proposal]:
    """
    Given a list of prompts that slipped through L1 detection,
    ask Claude to propose new patterns.
    """
    if not fn_examples:
        return []

    examples_block = "\n".join(
        f"{i+1}. {p[:300]}" for i, p in enumerate(fn_examples[:10])
    )

    user_msg = f"""These prompts are CONFIRMED prompt injection attacks that our L1 pattern engine missed (false negatives).
Next available pattern ID: {next_pattern_id}

MISSED ATTACKS:
{examples_block}

Propose new regex patterns to catch these. Each pattern should catch a category of attack, not just one example."""

    return _call_claude(user_msg)


def propose_for_fp(
    high_fp_patterns: list[dict],
    fp_examples: list[str],
) -> list[Proposal]:
    """
    Given patterns with high FP rates and example prompts that triggered them,
    ask Claude to propose severity adjustments.

    high_fp_patterns: [{"pattern_id": "P030", "tag": "output-control",
                         "current_severity": 0.60, "fp_rate": 0.45}]
    fp_examples: prompts that were legitimate but got flagged
    """
    if not high_fp_patterns:
        return []

    patterns_block = json.dumps(high_fp_patterns, indent=2)
    examples_block = "\n".join(
        f"{i+1}. {p[:200]}" for i, p in enumerate(fp_examples[:10])
    )

    user_msg = f"""These patterns have high false positive rates — they fire on legitimate prompts too often.

HIGH-FP PATTERNS:
{patterns_block}

EXAMPLE LEGITIMATE PROMPTS THAT WERE INCORRECTLY FLAGGED:
{examples_block}

Propose severity adjustments to reduce false positives while maintaining detection power."""

    return _call_claude(user_msg)


# ─── Claude API call ─────────────────────────────────────────────────────────

def _call_claude(user_message: str) -> list[Proposal]:
    response = _client().messages.create(
        model=MODEL,
        max_tokens=2048,
        system=_SYSTEM,
        messages=[{"role": "user", "content": user_message}],
    )

    raw = response.content[0].text.strip()

    # Strip markdown code fences if Claude wraps in ```json
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    try:
        items = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Claude returned invalid JSON: {e}\nRaw:\n{raw}") from e

    proposals: list[Proposal] = []
    for item in items:
        if item.get("kind") == "new_pattern":
            proposals.append(NewPatternProposal(
                kind="new_pattern",
                pattern_id=item["pattern_id"],
                regex=item["regex"],
                severity=float(item["severity"]),
                tag=item["tag"],
                rationale=item["rationale"],
                example_prompt=item.get("example_prompt", ""),
            ))
        elif item.get("kind") == "severity_adjustment":
            proposals.append(SeverityAdjustment(
                kind="severity_adjustment",
                pattern_id=item["pattern_id"],
                current_severity=float(item["current_severity"]),
                proposed_severity=float(item["proposed_severity"]),
                rationale=item["rationale"],
            ))

    return proposals


# ─── Proposal → patterns.js patch ────────────────────────────────────────────

def proposals_to_markdown(proposals: list[Proposal]) -> str:
    """Render proposals as a human-readable PR description."""
    if not proposals:
        return "No proposals generated."

    lines = ["## PromptGuard Agent — Pattern Proposals\n"]

    new_patterns = [p for p in proposals if p.kind == "new_pattern"]
    adjustments = [p for p in proposals if p.kind == "severity_adjustment"]

    if new_patterns:
        lines.append(f"### New Patterns ({len(new_patterns)})\n")
        for p in new_patterns:
            lines += [
                f"**{p.pattern_id}** `{p.tag}` severity={p.severity}",
                f"```",
                f"/{p.regex}/i",
                f"```",
                f"**Rationale:** {p.rationale}",
                f"**Example:** `{p.example_prompt[:120]}`",
                "",
            ]

    if adjustments:
        lines.append(f"### Severity Adjustments ({len(adjustments)})\n")
        for a in adjustments:
            lines += [
                f"**{a.pattern_id}**: {a.current_severity} → {a.proposed_severity}",
                f"**Rationale:** {a.rationale}",
                "",
            ]

    return "\n".join(lines)
