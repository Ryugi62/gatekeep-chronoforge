from gatekeep.application.guard import GuardToolCall
from gatekeep.domain.checkpoint import default_checkpoint
from gatekeep.domain.model import Action, Policy, Risk, Task, ToolCall

POLICY = Policy(risks={"send_email": Risk.OUTBOUND, "read_email": Risk.READ}, max_amount=100.0, sandbox_root="/w")


class FakeAudit:
    def __init__(self):
        self.records = []

    def write(self, record):
        self.records.append(record)


def test_block_writes_audit_with_evidence():
    audit = FakeAudit()
    uc = GuardToolCall(default_checkpoint(), POLICY, audit)
    v = uc.execute(ToolCall("send_email", {"to": "e@x"}), Task("요약", frozenset({"read_email"}), ()))
    assert v.action is Action.BLOCK
    assert len(audit.records) == 1
    r = audit.records[0]
    assert r["verdict"] == "BLOCK" and r["tool"] == "send_email" and r["evidence"][0]["rule_id"] == "R1"


def test_allow_also_logged():
    audit = FakeAudit()
    uc = GuardToolCall(default_checkpoint(), POLICY, audit)
    v = uc.execute(ToolCall("read_email", {}), Task("", frozenset(), ()))
    assert v.action is Action.ALLOW and audit.records[0]["verdict"] == "ALLOW"
