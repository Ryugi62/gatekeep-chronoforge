"""도메인 모델 — 프레임워크·I/O를 모른다 (SPEC §2 유비쿼터스 언어)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Tuple


class Risk(Enum):
    READ = "READ"
    SENSITIVE_READ = "SENSITIVE_READ"
    OUTBOUND = "OUTBOUND"
    MONEY = "MONEY"
    DESTRUCTIVE = "DESTRUCTIVE"
    STATE_CHANGE = "STATE_CHANGE"


class Action(Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


def _walk_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _walk_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _walk_strings(v)


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)

    def string_values(self) -> List[str]:
        return list(_walk_strings(self.args))


@dataclass(frozen=True)
class Task:
    user_request: str
    allowed_tools: FrozenSet[str]
    untrusted_texts: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    risks: Dict[str, Risk]
    max_amount: float
    sandbox_root: str

    def risk_of(self, tool: str) -> Optional[Risk]:
        return self.risks.get(tool)


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class Verdict:
    action: Action
    call: ToolCall
    evidences: Tuple[Evidence, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK
