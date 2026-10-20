from __future__ import annotations

from typing import Sequence

from .model import Action, Policy, Task, ToolCall, Verdict
from .rules import (AmountLimit, OutOfScope, PathEscape, Rule, SecretEgress,
                    TaintedDestination, UnknownTool)


class Checkpoint:
    def __init__(self, rules: Sequence[Rule]):
        self.rules = tuple(rules)

    def inspect(self, call: ToolCall, task: Task, policy: Policy) -> Verdict:
        evidences = tuple(e for e in (r.check(call, task, policy) for r in self.rules) if e is not None)
        if not evidences:
            return Verdict(Action.ALLOW, call, evidences)
        hard = any(not e.confirm for e in evidences)
        return Verdict(Action.BLOCK if hard else Action.CONFIRM, call, evidences)


def default_checkpoint() -> Checkpoint:
    return Checkpoint([UnknownTool(), OutOfScope(), TaintedDestination(), AmountLimit(), PathEscape(), SecretEgress()])
