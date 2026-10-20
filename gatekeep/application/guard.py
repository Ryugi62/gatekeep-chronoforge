from __future__ import annotations

from dataclasses import replace

from ..domain.checkpoint import Checkpoint
from ..domain.intent import extract_allowed_tools
from ..domain.model import Policy, Task, ToolCall, Verdict
from .ports import AuditLog


class GuardToolCall:
    """유스케이스: 도구 호출 직전 검문 → Verdict → 감사 기록 1줄."""

    def __init__(self, checkpoint: Checkpoint, policy: Policy, audit: AuditLog, derive_scope: bool = False):
        """derive_scope=True: 선언된 허용 목록(오라클) 대신 사용자 요청 문장에서 허용 도구를 뽑아 R1에 쓴다 (SPEC 5-12)."""
        self.checkpoint, self.policy, self.audit, self.derive_scope = checkpoint, policy, audit, derive_scope

    def execute(self, call: ToolCall, task: Task) -> Verdict:
        if self.derive_scope:
            task = replace(task, allowed_tools=extract_allowed_tools(task.user_request, self.policy))
        verdict = self.checkpoint.inspect(call, task, self.policy)
        self.audit.write({
            "verdict": verdict.action.value,
            "tool": call.tool,
            "scope": "derived" if self.derive_scope else "declared",
            "allowed": sorted(task.allowed_tools),
            "args": call.args,
            "evidence": [{"rule_id": e.rule_id, "reason": e.reason, "detail": e.detail} for e in verdict.evidences],
        })
        return verdict
