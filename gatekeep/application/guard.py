from __future__ import annotations

from ..domain.checkpoint import Checkpoint
from ..domain.model import Policy, Task, ToolCall, Verdict
from .ports import AuditLog


class GuardToolCall:
    """유스케이스: 도구 호출 직전 검문 → Verdict → 감사 기록 1줄."""

    def __init__(self, checkpoint: Checkpoint, policy: Policy, audit: AuditLog):
        self.checkpoint, self.policy, self.audit = checkpoint, policy, audit

    def execute(self, call: ToolCall, task: Task) -> Verdict:
        verdict = self.checkpoint.inspect(call, task, self.policy)
        self.audit.write({
            "verdict": verdict.action.value,
            "tool": call.tool,
            "args": call.args,
            "evidence": [{"rule_id": e.rule_id, "reason": e.reason, "detail": e.detail} for e in verdict.evidences],
        })
        return verdict
