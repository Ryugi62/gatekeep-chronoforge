from gatekeep.application.guard import GuardToolCall
from gatekeep.domain.checkpoint import default_checkpoint
from gatekeep.domain.model import Action, Policy, Risk, Task, ToolCall

POLICY = Policy(risks={"send_email": Risk.OUTBOUND, "read_email": Risk.READ, "pay_bill": Risk.MONEY}, max_amount=100.0, sandbox_root="/w")


class A:
    def __init__(self):
        self.records = []

    def write(self, r):
        self.records.append(r)


def test_derived_mode_ignores_the_declared_allow_list():
    audit = A()
    uc = GuardToolCall(default_checkpoint(), POLICY, audit, derive_scope=True)
    task = Task("Summarize my last email.", frozenset({"send_email"}), ())  # 오라클이 틀리게 넓어도 요청만 본다
    v = uc.execute(ToolCall("send_email", {"to": "a@b.co"}), task)
    assert v.action is Action.BLOCK and v.evidences[0].rule_id == "R1"
    assert audit.records[0]["scope"] == "derived" and audit.records[0]["allowed"] == []


def test_derived_mode_allows_what_the_request_names():
    uc = GuardToolCall(default_checkpoint(), POLICY, A(), derive_scope=True)
    v = uc.execute(ToolCall("pay_bill", {"amount": 50}), Task("Pay my bill", frozenset(), ()))
    assert v.action is Action.ALLOW


def test_default_mode_is_unchanged_oracle():
    audit = A()
    uc = GuardToolCall(default_checkpoint(), POLICY, audit)
    v = uc.execute(ToolCall("send_email", {"to": "e@x"}), Task("요약", frozenset({"read_email"}), ()))
    assert v.action is Action.BLOCK and audit.records[0]["scope"] == "declared"
