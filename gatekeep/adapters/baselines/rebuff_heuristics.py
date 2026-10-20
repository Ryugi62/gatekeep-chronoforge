"""Rebuff 휴리스틱 탐지(Apache-2.0)를 같은 수식 그대로 돌린다. 점수 0 이하로 확정된 부분문자열은 비싼 유사도 계산을 건너뛴다(결과 동일)."""
from __future__ import annotations

from difflib import SequenceMatcher

from ...application.ports import TextGuard
from .third_party import rebuff_detect_pi_heuristics as rb

_MAX_MATCHED = 5


class RebuffHeuristics(TextGuard):
    name = "rebuff-heuristics"

    def __init__(self, threshold: float = 0.75):
        self.threshold = threshold
        seen = set()
        self._keywords = []
        for k in rb.generate_injection_keywords():
            n = rb.normalize_string(k)
            if n not in seen:
                seen.add(n)
                self._keywords.append((n, n.split(" ")))

    def score(self, text: str) -> float:
        normalized = rb.normalize_string(text)
        best = 0.0
        for kw, parts in self._keywords:
            for sub in rb.get_input_substrings(normalized, len(parts)):
                matched = rb.get_matched_words_score(sub, parts, _MAX_MATCHED)
                if matched <= best:  # 유사도 항은 빼기만 하므로 best 를 못 넘는다
                    continue
                adjusted = matched - SequenceMatcher(None, sub, kw).ratio() * (1 / (_MAX_MATCHED * 2))
                if adjusted > best:
                    best = adjusted
        return best

    def flags(self, text: str) -> bool:
        return self.score(text) >= self.threshold
