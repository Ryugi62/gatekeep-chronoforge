"""레드팀 r1 ① — 등록 안 된 도구는 이름 추론으로 READ가 되지 않는다 (R0 기본 거부가 실제로 발동)."""
import json
import os

from gatekeep.adapters.tool_registry import build_policy, infer_risk, load_city_pack
from gatekeep.domain.model import Risk


def test_money_verb_aliases():
    for n in ["wire_funds", "WireFunds", "remit_payment", "disburse_amount", "settle_invoice"]:
        assert infer_risk(n) is Risk.MONEY, n


def test_outbound_destructive_state_aliases():
    for n in ["email_citizen", "mail_document", "transmit_file", "notify_user", "dm_user"]:
        assert infer_risk(n) is Risk.OUTBOUND, n
    for n in ["erase_file", "rm", "run_command", "purge_records"]:
        assert infer_risk(n) is Risk.DESTRUCTIVE, n
    for n in ["issue_permit", "approve_request", "assign_role"]:
        assert infer_risk(n) is Risk.STATE_CHANGE, n


def test_unplaceable_name_is_none_not_read():
    for n in ["frobnicate_accounts", "sendfunds", "do_thing", "", "x"]:
        assert infer_risk(n) is None, n


def test_read_needs_a_read_verb():
    assert infer_risk("get_permit_status") is Risk.READ
    assert infer_risk("read_notice") is Risk.READ
    assert infer_risk("visit_webpage") is Risk.READ


def test_compound_name_takes_the_riskiest_verb():
    assert infer_risk("read_and_delete_file") is Risk.DESTRUCTIVE
    assert infer_risk("get_then_send_email") is Risk.OUTBOUND


def test_build_policy_drops_unplaceable_and_honors_explicit_registry():
    p = build_policy(["frobnicate_accounts", "get_x"], 1000.0, "/workspace", registered={"frobnicate_accounts": Risk.MONEY})
    assert p.risk_of("frobnicate_accounts") is Risk.MONEY
    p2 = build_policy(["frobnicate_accounts"], 1000.0, "/workspace")
    assert p2.risk_of("frobnicate_accounts") is None


def test_city_pack_file_registers_tools_and_limit(tmp_path):
    f = tmp_path / "pack.json"
    f.write_text(json.dumps({"currency": "INR", "max_amount": 20000, "limit_basis": "operator setting",
                             "sandbox_root": "/workspace", "tools": {"pay_property_tax": "MONEY", "read_notice": "READ"}}))
    pol = load_city_pack(str(f))
    assert pol.risk_of("pay_property_tax") is Risk.MONEY and pol.max_amount == 20000
    assert pol.risk_of("unlisted_tool") is None
