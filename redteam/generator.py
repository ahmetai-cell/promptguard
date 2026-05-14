"""
Generates adversarial variants by crossing base payloads with obfuscation techniques.
"""
from __future__ import annotations

from typing import Iterator

from .payloads import PAYLOADS
from .obfuscator import ALL_TECHNIQUES


def generate(
    categories: list[str] | None = None,
    techniques: list[str] | None = None,
    include_clean: bool = True,
) -> Iterator[dict]:
    """
    Yield attack variant dicts: {category, technique, text}.

    Args:
        categories:    subset of PAYLOADS keys; None = all categories
        techniques:    subset of technique names; None = all techniques
        include_clean: if True, yield the original (un-obfuscated) payload first
    """
    cats   = categories or list(PAYLOADS.keys())
    techs  = {name: fn for name, fn in ALL_TECHNIQUES
               if techniques is None or name in techniques}

    for cat in cats:
        if cat not in PAYLOADS:
            continue
        for payload in PAYLOADS[cat]:
            if include_clean:
                yield {"category": cat, "technique": "clean", "text": payload}

            for name, fn in techs.items():
                try:
                    obf = fn(payload)
                    if obf != payload:   # skip no-ops
                        yield {"category": cat, "technique": name, "text": obf}
                except Exception:
                    pass
