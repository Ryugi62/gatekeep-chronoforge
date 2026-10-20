"""동작 관문 — 에이전트의 도구 상자를 감싸 호출 직전에 검문한다. 차단되면 도구 본체는 실행되지 않는다."""
from __future__ import annotations

from typing import Any, Callable, Dict

from ..application.guard import GuardToolCall
from ..domain.model import Task, ToolCall, Verdict


class ToolCallBlocked(Exception):
    def __init__(self, verdict: Verdict):
        self.verdict = verdict
        why = "; ".join("%s %s" % (e.rule_id, e.reason) for e in verdict.evidences)
        super().__init__("차단: %s — %s" % (verdict.call.tool, why))


class GatedToolbox:
    def __init__(self, tools: Dict[str, Callable[..., Any]], guard: GuardToolCall, task: Task):
        self.tools, self.guard, self.task = tools, guard, task

    def call(self, name: str, **kwargs: Any) -> Any:
        verdict = self.guard.execute(ToolCall(name, kwargs), self.task)
        if verdict.blocked:
            raise ToolCallBlocked(verdict)
        return self.tools[name](**kwargs)
