"""data/cases.jsonl 케이스 → 도메인 객체 변환 (어댑터)."""
from __future__ import annotations

import json
from typing import Dict, List

from ..domain.model import Policy, Task, ToolCall
from .tool_registry import build_policy


def load_cases(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def policy_for(cases: List[Dict], max_amount: float = 1000.0, sandbox_root: str = "/workspace") -> Policy:
    names = {c_["tool"] for c in cases for c_ in c["calls"]} | {t for c in cases for t in c["allowed_tools"]}
    return build_policy(sorted(names), max_amount, sandbox_root)


def task_of(case: Dict) -> Task:
    return Task(user_request=case["user_request"], allowed_tools=frozenset(case["allowed_tools"]),
                untrusted_texts=(case["untrusted_content"],) if case["untrusted_content"] else (),
                cited_sources=(case["untrusted_content"],) if case.get("cited") and case["untrusted_content"] else ())


def calls_of(case: Dict) -> List[ToolCall]:
    return [ToolCall(c["tool"], c.get("args", {})) for c in case["calls"]]
