"""
L2 classifier — ProtectAI/deberta-v3-base-prompt-injection-v2

Loads once at startup, runs inference synchronously.
Model outputs: INJECTION (malicious) | LEGITIMATE (benign)
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger(__name__)

MODEL_ID = os.getenv(
    "CLASSIFIER_MODEL",
    "ProtectAI/deberta-v3-base-prompt-injection-v2",
)
MAX_LENGTH = int(os.getenv("CLASSIFIER_MAX_LENGTH", "512"))


@dataclass
class ClassifierResult:
    label: str        # "INJECTION" | "LEGITIMATE"
    score: float      # confidence [0, 1]
    is_injection: bool


class PromptClassifier:
    def __init__(self) -> None:
        self._pipe = None

    def _load(self):
        if self._pipe is not None:
            return
        try:
            from transformers import pipeline
            logger.info("Loading classifier model: %s", MODEL_ID)
            self._pipe = pipeline(
                "text-classification",
                model=MODEL_ID,
                device=-1,          # CPU; set CLASSIFIER_DEVICE=0 for GPU
                truncation=True,
                max_length=MAX_LENGTH,
            )
            logger.info("Classifier model loaded.")
        except Exception as exc:
            logger.error("Failed to load classifier: %s", exc)
            raise RuntimeError(f"Classifier load failed: {exc}") from exc

    def classify(self, text: str) -> ClassifierResult:
        self._load()

        if not text or not text.strip():
            return ClassifierResult(label="LEGITIMATE", score=1.0, is_injection=False)

        raw = self._pipe(text)[0]
        label: str = raw["label"].upper()
        score: float = float(raw["score"])

        return ClassifierResult(
            label=label,
            score=score,
            is_injection=(label == "INJECTION"),
        )


@lru_cache(maxsize=1)
def get_classifier() -> PromptClassifier:
    """Singleton — one model instance per process."""
    clf = PromptClassifier()
    clf._load()
    return clf
