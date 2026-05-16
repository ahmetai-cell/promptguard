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
        (r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|preceding|former)\s+(instructions?|prompts?|context|orders?|tasks?|rules?|directives?)", 0.95),
        (r"disregard\s+(all\s+)?(the\s+)?(previous|prior|above|preceding|former)\s+(instructions?|prompts?|context|orders?|tasks?|rules?)", 0.95),
        (r"forget\s+(all\s+)?(about\s+)?(the\s+)?(previous|prior|above|preceding)\s+(instructions?|prompts?|context|tasks?|assignments?|information|orders?)", 0.90),
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
        # P038-P042: gap-fill patterns
        (r"forget\s+everything\s+(before|above|prior|previous)", 0.90),
        (r"(leave|put|set)\s+(all\s+)?(the\s+)?(previous|prior|above|preceding)\s+(information|instructions?|context|tasks?)\s+(behind|aside|away)", 0.85),
        (r"now\s+(you\s+are|we\s+start|let.s\s+start|start)\s+(over|fresh|again|anew)", 0.70),
        (r"\b(stop|enough|done)\b.{0,40}\bnow\s+(focus|help|do|write|tell|give|show)\b", 0.65),
        (r"now\s+(you\s+are|act\s+as)\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)?[,.\s]", 0.75),
        # P043-P046: German language attacks
        (r"vergiss\s+(alle?|die|alle?\s+vorherigen?)\s+(aufgaben?|anweisungen?|angaben?|informationen?|instructions?)", 0.95),
        (r"ignoriere\s+(alle?\s+)?(vorherigen?|bisherigen?)\s+(anweisungen?|aufgaben?|angaben?)", 0.95),
        (r"stell\s+dir\s+vor.{0,20}(böse|evil|böser|schlechte?|unrestricted)", 0.90),
        (r"nun\s+folgen?\s+(neue?|andere?)\s+(aufgaben?|anweisungen?|instructions?)", 0.85),
        # P047-P048: Spanish language attacks
        (r"olvid[ae]\s+(todo|todas?|los?)\s*(lo\s+que|que)?\s*(dij|anteri|antes?|previo)", 0.90),
        (r"ignora\s+(todas?\s+las?)?\s*(instrucciones?|anteriores?|previas?)", 0.90),
        # P049-P050: Direct command injection / bypass
        (r"^(stop|halt|pause)\s*[-–—:]\s*(write|say|tell|output|print|respond)", 0.80),
        (r"despite\s+what\s+(you.ve\s+been\s+told|your\s+instructions?)", 0.85),
        # P051-P054: English gap-fill (simple forget/ignore/task-switch)
        (r"forget\s+(everything|all)\b", 0.80),
        (r"ignore\s+(the\s+)?(above|previous)\b", 0.85),
        (r"now\s+new\s+(instructions?|tasks?|directives?|commands?)\s+follow", 0.75),
        (r"concentrate\s+(?:only\s+)?on\s+(?:your\s+)?new\s+task", 0.70),
        # P055-P062: German extended coverage
        (r"ignorier(?:en|e|st|t)\s+(?:sie\s+)?(?:(?:die|alle?)\s+)?(?:obigen?|vorangehenden?|vorangegangenen?|vorherigen?|alle)\s*(?:anweisungen?|ausführungen?|befehle?|aufgaben?|angaben?|hinweise?)?", 0.95),
        (r"vergiss\s+(?:alles|alle\s+auftr[äa]ge?|alles\s+davor|alles\s+bisherige|alle\s+angaben?)", 0.90),
        (r"(?:jetzt|nun)\s+bist\s+du\s+\w", 0.80),
        (r"nun\s+folgen?\s+(?:weitere|neue|andere)\s+(?:aufgaben?|anweisungen?|befehle?|instructions?)", 0.85),
        (r"(?:alle?\s+)?(?:vorangegangenen?|vorangehenden?|vorherigen?|bisherigen?)\s+(?:aufgaben?|anweisungen?|auftr[äa]ge?)\s+(?:aus\s+dem\s+kopf|hinter\s+sich)", 0.85),
        (r"(?:lassen\s+sie|lass)\s+(?:alle?\s+)?(?:vorherigen?|bisherigen?|vorangegangenen?|alle)\s+\S+\s+hinter\s+sich", 0.85),
        (r"ignorieren\s+sie\s+(?:die\s+)?obigen?\s+anweisungen?", 0.95),
        (r"nun\s+(?:bitte\s+)?(?:helfen\s+sie|hilf)\s+(?:mir\s+)?(?:mit|bei)\s+(?:folgender?|neuer?|dieser?)", 0.75),
        # P063-P073: English/German gap-fill round 2
        (r"ignore\s+your\s+(instructions?|rules?|guidelines?|directives?|orders?)", 0.90),
        (r"\b(stop|enough|done|erledigt|gen[üu]gt)\b.{0,60}\bnow\s+(?:please\s+|come\s+on\s*[,.]?\s*)?(help|assist|focus|do|write|tell|give|show)\b", 0.65),
        (r"remove\s+(?:all\s+)?(?:previous\s+)?(?:tasks?|instructions?|information)\s+(?:from|out\s+of)\s+(?:your\s+)?(?:head|mind|memory)", 0.85),
        (r"DO\s+NOT\s+ANSWER\s+(?:THIS|THE)\s+QUESTION", 0.80),
        (r"\bdu\s+bist\s+(?:jetzt\s+)?[A-Z\xc4\xd6\xdc][a-z\xe4\xf6\xfc\xdf]+\b", 0.65),
        (r"(?:obigen?|vorherigen?|vorangehenden?)\s+\w+(?:\s+\w+)?\s+ignorier", 0.90),
        (r"\b(?:ACHTUNG|STOPP?)\b.{0,60}\b(?:hilf|frag|antworte|beantworte|schreib)", 0.75),
        (r"from\s+now\s+(?:on\s+)?(?:known\s+as|you\s+are|act\s+as|behave\s+as|called)", 0.80),
        (r"olvid[ae]\s+todo\s+(?:lo\s+)?(?:que\s+)?(?:dij|digo|decia|dec[íi]a|te\s+)", 0.90),
        (r"(?:bitte\s+)?hilf\s+(?:mir\s+)?(?:nun|jetzt)\s+(?:mit|bei)\s+(?:folgender?|neuer?|dieser?|weiterer?)", 0.75),
        (r"\bANTWORTE\s+(?:IM\s+STIL|NUR|JETZT|ALS|SO)\b", 0.70),
        # P074-P082: Round 3 gap-fill
        (r"olvid[ae]\s+(?:todas?\s+las?\s+)?instrucciones?\b", 0.90),
        (r"ignore\s+all\s+(?:provided|given|the)\s+(?:context|information|instructions?|articles?|documents?)", 0.85),
        (r"drop\s+(?:all\s+)?(?:your\s+)?instructions?\b", 0.85),
        (r"forget\s+about\s+everything\b", 0.80),
        (r"answer\s+by\s+your\s+own\s+knowledge\s+and\s+not\s+by\s+the", 0.75),
        (r"your\s+instructions?\s+are\s+now\s+to\b", 0.80),
        (r"\bzaboravi\s+(?:sve\s+)?(?:instrukcij|upute|pravil|naredbe)", 0.90),
        (r"now\s+(?:you\s+)?act\s+as\s+(?:two|multiple|both|three|several)\s+\w+", 0.75),
        (r"Sie\s+als\s+(?:Linux|Debattierer|[A-ZÄÖÜ]\w+(?:-\w+)?)\s+(?:fung|ager|handl|auftreten?)", 0.80),
        # P083-P092: Round 4 - multilingual + novel vectors
        (r"oubliez?\s+toutes?\s+les?\s+instructions?\b", 0.95),
        (r"abweichend\s+(zu|von)\s+(vorherigen?|bisherigen?)\s+(instruktionen?|anweisungen?)", 0.85),
        (r"additional\s+instruction\s*[-:–—]", 0.75),
        (r"abandon\s+(?:all\s+)?(?:your\s+)?(?:thoughts?|instructions?|rules?|guidelines?|beliefs?)", 0.80),
        (r"repeat\s+after\s+me\b", 0.70),
        (r"DO\s+NOT\s+(?:LOOK|READ|USE)\s+(?:IN\s+|AT\s+)?(?:THE\s+)?(?:DOCUMENTS?|ARTICLES?|CONTEXT|PROVIDED)", 0.80),
        (r"you\s+are\s+now\s+[A-Z]\w*[Bb]ot\b", 0.85),
        (r"disregarding\s+(?:the\s+)?(?:articles?|documents?|context|instructions?)", 0.85),
        (r"tienes\s+que\s+olvid|olvidar?\s+(todo|todos?)\s+(?:lo\s+)?que", 0.90),
        (r"role[- ]?playing\s+as\s+(?:a\s+)?[a-zA-Z]", 0.75),
        # P093-P102: Round 5 - remaining gaps
        (r"alle\s+(?:vorherigen?|bisherigen?)\s+\w+(?:\s+\w+)?.{0,100}(?:irrelevant|unnötig|egal|falsch)\b", 0.80),
        (r"\bInstruction\s*:\s*(?=[A-Z][a-z]|\w+\s+\w)", 0.70),
        (r"pretend\s+you\s+(?:can|could|have|are\s+able\s+to)\s+(?:access|know|see|use|ignore)", 0.70),
        (r"ich\s+brauche\s+deine\s+(?:hilfe|unterst[üu]tzung)\s+bei\s+(?:einer?|der)\s+(?:weiteren?|neuen?|n[äa]chsten?)\s+aufgabe", 0.70),
        (r"include\s+(?:that\s+)?.{0,40}\s+in\s+your\s+(?:answer|response|reply)\b", 0.65),
        (r"USE\s+ALSO\s+INFORMATION\s+IN\s+THE\s+PROMPT", 0.70),
        (r"(?:sentences?|text)\s+before\s+(?:the\s+)?(?:text|this)\b", 0.65),
        (r"(?:ignore|disregard)\s+(?:the\s+)?(?:provided|given|above)\s+(?:articles?|documents?|context|texts?)", 0.85),
        (r"\bodo\s+(?:everything|anything)\s+(?:I|you|we)\s+(?:say|tell|ask|want)", 0.75),
        (r"you\s+are\s+(?:the\s+)?[A-Z]\w+(?:wire|post|times|news|online|bot|gpt)\b", 0.80),
        # P103-P112: Round 6 - final gaps
        (r"ignore\s+all\s+(?:your\s+)?(?:instructions?|rules?|guidelines?|directives?)\b", 0.90),
        (r"ignore\s+(?:everything|all)\b", 0.80),
        (r"change\s+(?:your|the|my)\s+instructions?\s+to\b", 0.80),
        (r"(?:[A-Za-z]\s+){6,}[A-Za-z]", 0.65),
        (r"[Зз]абудьте\s+(?:все\s+)?(?:инструкции|правила|задания)", 0.95),
        (r"imagine\s+you\s+(?:are|were|could\s+be)\s+(?:a\s+|the\s+|an\s+)", 0.65),
        (r"\$Documents?\s*:", 0.65),
        (r"I\s+want\s+you\s+to\s+act\s+as\s+(?:a|an)\s+\w+", 0.65),
        (r"(?:Input|Eingabe):\s*\S+\s+(?:Output|Ausgabe):\s*\S+.{0,300}(?:Input|Eingabe):", 0.75),
        (r"Ich\s+m[öo]chte,?\s+dass\s+Sie\s+als\s+\S+(?:\s+\S+)?\s+(?:fung|ager|tätig|agier)", 0.80),
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
    import argparse
    parser = argparse.ArgumentParser(description="PromptGuard KPI Evaluator")
    parser.add_argument("dataset", nargs="?", help="Path to labeled dataset (CSV/JSONL)")
    parser.add_argument("--ci", action="store_true",
                        help="Exit 1 if any KPI target is missed (for CI regression guard)")
    args = parser.parse_args()

    if not args.dataset:
        parser.print_help()
        sys.exit(1)

    result = evaluate(dataset_path=args.dataset, use_node=True)
    kpi = kpi_check(result)

    print(f"Total samples : {result.total}")
    print(f"Precision     : {result.precision:.4f}  {'✅' if kpi['precision_ok'] else '❌'} (target ≥0.80)")
    print(f"Recall        : {result.recall:.4f}  {'✅' if kpi['recall_ok'] else '❌'} (target ≥0.70)")
    print(f"FP Rate       : {result.fp_rate:.4f}  {'✅' if kpi['fp_rate_ok'] else '❌'} (target ≤0.05)")
    print(f"F1            : {result.f1:.4f}")
    print(f"TP={result.tp}  FP={result.fp}  TN={result.tn}  FN={result.fn}")

    if args.ci and not all(kpi.values()):
        failed = [k for k, v in kpi.items() if not v]
        print(f"\n❌ CI FAIL — KPI targets missed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)

    if args.ci:
        print("\n✅ All KPI targets met")
