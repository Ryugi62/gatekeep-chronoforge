from __future__ import annotations

from typing import Any, Dict


class AuditLog:
    def write(self, record: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError


class TextGuard:
    """텍스트를 보고 주입 여부를 판정하는 기존 가드레일의 공통 모양 (비교 대상용)."""

    name = "text-guard"

    def flags(self, text: str) -> bool:  # pragma: no cover
        raise NotImplementedError
