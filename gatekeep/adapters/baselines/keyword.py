"""가장 단순한 기준선 — 주입 상투어 정규식 목록 (자체 작성, 제3자 아님)."""
from __future__ import annotations

import re

from ...application.ports import TextGuard

PATTERNS = [
    r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts?|messages?)",
    r"disregard (all |any )?(the )?(previous|prior|above) ",
    r"forget (all |everything|your) (previous |prior )?(instructions|rules)",
    r"you are now",
    r"system prompt",
    r"new instructions?:",
    r"do anything now|\bDAN\b",
    r"jailbreak",
]


class KeywordFilter(TextGuard):
    name = "keyword-filter"

    def __init__(self):
        self._pats = [re.compile(p, re.I) for p in PATTERNS]

    def flags(self, text: str) -> bool:
        return any(p.search(text) for p in self._pats)
