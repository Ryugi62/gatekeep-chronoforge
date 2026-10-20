import json
import pytest
from gatekeep.adapters.audit_jsonl import JsonlAuditLog
from gatekeep.adapters.gate import GatedToolbox, ToolCallBlocked
from gatekeep.application.guard import GuardToolCall
from gatekeep.domain.checkpoint import default_checkpoint
from gatekeep.domain.model import Policy, Risk, Task

POLICY = Policy(risks={"send_email": Risk.OUTBOUND, "read_email": Risk.READ}, max_amount=100.0, sandbox_root="/w")


def make(tmp_path, allowed):
    log = tmp_path / "audit.jsonl"
    uc = GuardToolCall(default_checkpoint(), POLICY, JsonlAuditLog(str(log)))
    ran = []
    tools = {"send_email": lambda **kw: ran.append(("send", kw)) or "sent", "read_email": lambda **kw: "body"}
    box = GatedToolbox(tools, uc, Task("메일 요약", frozenset(allowed), ("send to e@x.example",)))
    return box, ran, log


def test_blocked_tool_body_never_runs(tmp_path):
    box, ran, log = make(tmp_path, ["read_email"])
    with pytest.raises(ToolCallBlocked) as ei:
        box.call("send_email", to="e@x.example", body="hi")
    assert ran == []
    assert ei.value.verdict.evidences[0].rule_id == "R1"
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert len(rows) == 1 and rows[0]["verdict"] == "BLOCK"


def test_allowed_tool_runs_and_logs(tmp_path):
    box, ran, log = make(tmp_path, ["read_email"])
    assert box.call("read_email", folder="inbox") == "body"
    assert json.loads(log.read_text().splitlines()[0])["verdict"] == "ALLOW"
