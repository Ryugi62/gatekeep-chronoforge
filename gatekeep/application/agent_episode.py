"""실제 LLM 에이전트 한 판(에피소드) — 모델이 부르는 도구 호출을 GateKeep이 검문하고, 막히면 본체를 실행하지 않고 모델에게 알린다.
GateKeep 자체는 LLM을 쓰지 않는다. 여기서 LLM은 검문 대상(공격받는 에이전트)이고 `AgentSession` 포트 뒤에 있다."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, List, Optional, Set

from ..domain.model import Action, Task, ToolCall
from .guard import GuardToolCall


@dataclass(frozen=True)
class Turn:
    calls: List[ToolCall] = field(default_factory=list)
    text: str = ""


@dataclass(frozen=True)
class ToolResult:
    tool: str
    content: str


class AgentSession:
    """에이전트 모델과의 대화 한 판 (포트). 어댑터(예: Gemini)가 구현한다."""

    def send_user(self, text: str) -> Turn:  # pragma: no cover
        raise NotImplementedError

    def send_tool_results(self, results: List[ToolResult]) -> Turn:  # pragma: no cover
        raise NotImplementedError


@dataclass
class CallRecord:
    tool: str
    args: Dict[str, Any]
    verdicts: Dict[str, str]  # 검문 방식 이름 → ALLOW/CONFIRM/BLOCK (모든 방식이 같은 호출을 판정)
    rules: Dict[str, List[str]]
    executed: bool


@dataclass
class EpisodeTrace:
    calls: List[CallRecord] = field(default_factory=list)
    final_text: str = ""
    stopped: str = "done"  # done | max_steps


def run_episode(session: AgentSession, guards: Dict[str, GuardToolCall], live: str, task: Task,
                tools: Dict[str, Callable[..., Any]], reading_tools: Set[str], max_steps: int = 8,
                cited: bool = False) -> EpisodeTrace:
    """guards 전부가 모든 호출을 판정해 기록하고, 모델에게 되돌리는 실제 차단은 live 이름의 판정을 따른다.
    reading_tools가 돌려준 글은 신뢰할 수 없는 글로 Task에 더해진다(런타임이 출처를 안다). 확인 대기(CONFIRM)도 실행하지 않는다."""
    trace = EpisodeTrace()
    turn = session.send_user(task.user_request)
    steps = 0
    while turn.calls:
        if steps >= max_steps:
            trace.stopped = "max_steps"
            return trace
        results: List[ToolResult] = []
        for call in turn.calls:
            steps += 1
            if call.tool not in tools:
                trace.calls.append(CallRecord(call.tool, call.args, {n: "BLOCK" for n in guards}, {n: ["unknown-tool"] for n in guards}, False))
                results.append(ToolResult(call.tool, "Error: no such tool."))
                continue
            verdicts = {n: g.execute(call, task) for n, g in guards.items()}
            v = verdicts[live]
            executed = v.action is Action.ALLOW
            trace.calls.append(CallRecord(call.tool, call.args, {n: x.action.value for n, x in verdicts.items()},
                                          {n: [e.rule_id for e in x.evidences] for n, x in verdicts.items()}, executed))
            if executed:
                out = str(tools[call.tool](**call.args))
                if call.tool in reading_tools and out:
                    task = replace(task, untrusted_texts=task.untrusted_texts + (out,),
                                   cited_sources=task.cited_sources + ((out,) if cited else ()))
                results.append(ToolResult(call.tool, out))
            else:
                why = "; ".join("%s %s" % (e.rule_id, e.reason) for e in v.evidences)
                kind = "held for user confirmation" if v.action is Action.CONFIRM else "blocked by GateKeep"
                results.append(ToolResult(call.tool, "Call %s (%s). The tool was not run." % (kind, why)))
        turn = session.send_tool_results(results)
    trace.final_text = turn.text
    return trace
