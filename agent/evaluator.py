"""
PromptGuard Agent — Evaluator

Measures L1 detection engine precision/recall against a labeled dataset.
Supports HackaPrompt format (CSV/JSONL) and inline test fixtures.

KPI targets (from roadmap):
  Precision >= 0.80
  Recall    >= 0.70
  FP rate   <= 0.05
"""

from __future__ import annotations

import csv
import json
import re
import sys
import os
from dataclasses import dataclass
from pathlib import Path

# ─── Inline JS evaluation ────────────────────────────────────────────────────
# We call the Node.js detector directly to avoid duplicating pattern logic.
# Fallback: pure Python re-implementation for CI environments without Node.

def _eval_with_node(text: str) -> dict:
    """Run the JS detector via Node and return {verdict, score, matches}."""
    import subprocess, json as _json, tempfile, os

    # Small inline runner
    runner = """
import { analyzeText } from './extension/detector/index.js';
const text = process.argv[1];
const result = analyzeText(text);
console.log(JSON.stringify(result));
"""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".mjs", delete=False, dir="/tmp"
    ) as f:
        f.write(runner)
        tmp = f.name

    try:
        repo_root = Path(__file__).parent.parent
        r = subprocess.run(
            ["node", "--input-type=module"],
            input=f"import {{ analyzeText }} from '{repo_root}/extension/detector/index.js';\n"
                  f"const result = analyzeText({json.dumps(text)});\n"
                  f"console.log(JSON.stringify(result));\n",
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            return _json.loads(r.stdout.strip())
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    return _eval_python_fallback(text)


def _eval_python_fallback(text: str) -> dict:
    """Python re-implementation of the L1 scoring for environments without Node."""
    BLOCK_THRESHOLD = 0.75
    WARN_THRESHOLD = 0.45

    PATTERNS = [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", 0.95),
        (r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", 0.95),
        (r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", 0.90),
        (r"you\s+are\s+now\s+(an?\s+)?(new|different|another|unrestricted|free)", 0.85),
        (r"from\s+now\s+on\s+(you\s+are|act\s+as|behave\s+as)", 0.85),
        (r"your\s+(new\s+)?(instructions?|directives?|rules?|role)\s+(are|is)\s*:", 0.80),
        (r"override\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)", 0.95),
        (r"bypass\s+(the\s+)?(safety|content|ethical|security)\s+(filter|check|guard|policy)", 0.90),
        (r"act\s+as\s+(an?\s+)?(jailbreak|dan|evil|hacker|unrestricted|unfiltered|malicious)", 0.95),
        (r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(jailbreak|dan|evil|hacker|unrestricted)", 0.95),
        (r"\bDAN\b.*\b(mode|version|persona|jailbreak)\b", 0.95),
        (r"jailbreak\s+(mode|activated|enabled|prompt)", 0.95),
        (r"you\s+(have\s+)?(no\s+)?(restrictions?|limits?|rules?|guidelines?|ethics?)", 0.80),
        (r"\[SYSTEM\]|\[INST\]|\[PROMPT\]|\<\|system\|\>", 0.75),
        (r"repeat\s+(your\s+)?(system|initial|original|hidden)\s+(prompt|instructions?|message)", 0.90),
        (r"print\s+(your\s+)?(system|initial|original|hidden)\s+(prompt|instructions?)", 0.90),
        (r"reveal\s+(your\s+)?(system|initial|original|confidential|secret)\s+(prompt|instructions?)", 0.90),
        (r"what\s+(is|are|were)\s+(your|the)\s+(system\s+)?instructions?", 0.70),
        (r"show\s+(me\s+)?(your\s+)?(full\s+)?(system\s+)?(prompt|context|configuration)", 0.70),
        (r"<!--.*inject|inject.*-->", 0.85),
        (r"\[INJECT\]|\[HIJACK\]|\[OVERRIDE\]", 0.90),
        (r"<<<.*>>>|{{.*injection.*}}", 0.80),
        (r"translate\s+this\s+to\s+english.*ignore", 0.85),
        (r"the\s+following\s+is\s+a\s+(new\s+)?(task|instruction|command|directive)", 0.65),
        (r"end\s+of\s+(system\s+)?(prompt|instructions?|context).*new\s+(task|instruction)", 0.85),
        (r"\bSTOP\b.*\bSTART\b|\bEND\b.*\bBEGIN\b", 0.60),
        (r"complete\s+the\s+following\s+(harmful|illegal|unethical|dangerous)", 0.85),
        (r"do\s+not\s+(follow|adhere\s+to)\s+(your|the)\s+(safety|ethical|content)\s+(guidelines?|policy|rules?)", 0.90),
        (r"respond\s+only\s+(in|with|using)\s+(json|xml|code|raw)\s+(without|no|ignoring)", 0.50),
        (r"always\s+begin\s+your\s+response\s+with\s+(sure|yes|of\s+course|i\s+will)", 0.60),
        (r"give\s+(me\s+)?(your|the|all)\s+(api\s+key|secret|password|token|credential)", 0.90),
        (r"leak\s+(the\s+)?(api\s+key|credentials?|secrets?|tokens?)", 0.95),
        (r"developer\s+mode\s+(on|enabled|activated)", 0.85),
        (r"maintenance\s+mode|debug\s+mode\s+(on|enabled)", 0.70),
        (r"sudo\s+(mode|override|all|ignore)", 0.80),
        (r"base64.*decode.*instruction|decode.*following.*base64", 0.85),
        (r"execute\s+(this|the\s+following)\s+(command|instruction|code)", 0.75),
    ]

    matches = []
    max_sev = 0.0
    for pattern, sev in PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern[:20])
            if sev > max_sev:
                max_sev = sev

    score = max_sev
    if len(matches) > 1:
        score = min(1.0, score + len(matches) * 0.04)

    verdict = "BLOCK" if score >= BLOCK_THRESHOLD else "WARN" if score >= WARN_THRESHOLD else "ALLOW"
    return {"verdict": verdict, "score": round(score, 3), "matches": matches}


# ─── Dataset loader ───────────────────────────────────────────────────────────

@dataclass
class LabeledSample:
    text: str
    label: int    # 1 = injection, 0 = legitimate


def load_hackaprompt(path: str | Path, max_samples: int = 2000) -> list[LabeledSample]:
    """
    Loads HackaPrompt dataset.
    Expected CSV columns: prompt, label  (label: 1=injection, 0=legitimate)
    Also supports JSONL: {"prompt": "...", "label": 1}
    """
    p = Path(path)
    samples: list[LabeledSample] = []

    if p.suffix == ".jsonl":
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            samples.append(LabeledSample(
                text=d.get("prompt", d.get("text", "")),
                label=int(d.get("label", d.get("injected", 0))),
            ))
            if len(samples) >= max_samples:
                break
    else:
        with open(p, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                text = row.get("prompt") or row.get("text") or ""
                label = int(row.get("label") or row.get("injected") or 0)
                samples.append(LabeledSample(text=text, label=label))
                if len(samples) >= max_samples:
                    break

    return samples


# ─── Evaluation ──────────────────────────────────────────────────────────────

@dataclass
class EvalResult:
    total: int
    tp: int           # correctly blocked injection
    fp: int           # legitimate blocked (false alarm)
    tn: int           # correctly allowed legitimate
    fn: int           # missed injection
    precision: float
    recall: float
    fp_rate: float
    f1: float
    fn_examples: list[str]    # missed attack prompts (for proposer)
    fp_examples: list[str]    # legitimate prompts incorrectly flagged


def evaluate(
    dataset_path: str | Path | None = None,
    samples: list[LabeledSample] | None = None,
    use_node: bool = True,
) -> EvalResult:
    if samples is None:
        if dataset_path is None:
            raise ValueError("Provide dataset_path or samples")
        samples = load_hackaprompt(dataset_path)

    tp = fp = tn = fn = 0
    fn_examples: list[str] = []
    fp_examples: list[str] = []

    for s in samples:
        eval_fn = _eval_with_node if use_node else _eval_python_fallback
        result = eval_fn(s.text)
        detected = result["verdict"] in ("WARN", "BLOCK")

        if s.label == 1 and detected:
            tp += 1
        elif s.label == 1 and not detected:
            fn += 1
            fn_examples.append(s.text)
        elif s.label == 0 and detected:
            fp += 1
            fp_examples.append(s.text)
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return EvalResult(
        total=total,
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        fp_rate=round(fp_rate, 4),
        f1=round(f1, 4),
        fn_examples=fn_examples[:50],
        fp_examples=fp_examples[:50],
    )


def kpi_check(result: EvalResult) -> dict[str, bool]:
    """Check whether evaluation results meet roadmap KPI targets."""
    return {
        "precision_ok": result.precision >= 0.80,
        "recall_ok": result.recall >= 0.70,
        "fp_rate_ok": result.fp_rate <= 0.05,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        print("Usage: python evaluator.py <dataset.csv|jsonl>")
        sys.exit(1)

    result = evaluate(dataset_path=path, use_node=False)
    kpi = kpi_check(result)

    print(f"Total samples : {result.total}")
    print(f"Precision     : {result.precision:.4f}  {'✅' if kpi['precision_ok'] else '❌'} (target ≥0.80)")
    print(f"Recall        : {result.recall:.4f}  {'✅' if kpi['recall_ok'] else '❌'} (target ≥0.70)")
    print(f"FP Rate       : {result.fp_rate:.4f}  {'✅' if kpi['fp_rate_ok'] else '❌'} (target ≤0.05)")
    print(f"F1            : {result.f1:.4f}")
    print(f"TP={result.tp}  FP={result.fp}  TN={result.tn}  FN={result.fn}")
