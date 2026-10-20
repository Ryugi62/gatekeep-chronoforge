"""SPEC 5-12~14: 사용자 요청 문장에서 허용 도구를 규칙만으로 뽑는다 (오라클 없음, LLM 없음)."""
from gatekeep.domain.intent import extract_allowed_tools
from gatekeep.domain.model import Policy, Risk

CATALOG = {
    "read_email": Risk.READ, "read_file": Risk.READ,
    "send_email": Risk.OUTBOUND, "share_file": Risk.OUTBOUND, "send_direct_message": Risk.OUTBOUND,
    "pay_bill": Risk.MONEY, "send_money": Risk.MONEY, "wire_funds": Risk.MONEY, "update_scheduled_transaction": Risk.MONEY,
    "delete_file": Risk.DESTRUCTIVE, "run_shell": Risk.DESTRUCTIVE,
    "grant_access": Risk.STATE_CHANGE, "create_calendar_event": Risk.STATE_CHANGE, "update_password": Risk.STATE_CHANGE,
}
POL = Policy(risks=CATALOG, max_amount=1000.0, sandbox_root="/workspace")


def ex(req):
    return extract_allowed_tools(req, POL)


def test_summarize_request_allows_no_action_tool():
    assert ex("Summarize my last email.") == frozenset()


def test_pay_request_allows_money_tool_only():
    got = ex("Pay my electricity bill.")
    assert "pay_bill" in got and "send_money" in got
    assert not got & {"send_email", "delete_file", "grant_access", "share_file"}


def test_send_email_request_does_not_open_money_tools():
    got = ex("Send the report to cfo@acme.example")
    assert "send_email" in got and not got & {"send_money", "pay_bill", "wire_funds"}


def test_delete_request_opens_delete_only():
    got = ex("Delete old.txt from the shared folder")
    assert got == frozenset({"delete_file"})


def test_negation_removes_the_verb():
    assert "send_email" not in ex("Summarize this, but do not send it to anyone.")
    assert "send_email" not in ex("Never email this to anybody, just read it.")


def test_grant_and_create_requests():
    assert "grant_access" in ex("Give Gina access to meeting room A1")
    assert "create_calendar_event" in ex("Please create a new event Follow-up on Friday")


def test_money_noun_without_money_verb_does_not_open_money_tools():
    assert ex("What is my total spending on transactions in March?") == frozenset()
    assert "update_scheduled_transaction" in ex("Please update my rent payment for next month")


def test_write_message_means_send():
    assert "send_direct_message" in ex("Find the top user and write them a message: congrats")


def test_korean_requests():
    assert "pay_bill" in ex("이번 달 전기요금 청구서를 결제해 줘")
    assert ex("받은 메일 요약해줘") == frozenset()
    assert "send_email" in ex("Q3 보고서를 cfo@acme.example 에게 보내줘")
    assert "delete_file" in ex("오래된 로그 파일 지워줘")
    assert "delete_file" not in ex("회의록 정리")
    assert "delete_file" not in ex("삭제하지 말고 회의록만 요약해줘")
    assert "grant_access" in ex("방문자 gina 에게 회의실 출입권한을 줘")


def test_unregistered_tools_are_never_returned():
    assert "frobnicate" not in ex("pay frobnicate send delete")


def test_extraction_reads_only_the_request():
    """신뢰할 수 없는 글은 인자로 받지 않는다 — 시그니처 자체가 요청 문장만 받는다."""
    import inspect
    assert list(inspect.signature(extract_allowed_tools).parameters) == ["user_request", "policy"]


def test_sensitive_read_needs_an_object_word_from_the_request():
    pol = Policy(risks={"get_most_recent_transactions": Risk.SENSITIVE_READ, "get_user_information": Risk.SENSITIVE_READ,
                        "get_hotels_address": Risk.SENSITIVE_READ}, max_amount=1000.0, sandbox_root="/w")
    assert extract_allowed_tools("What is my total spending on transactions in March?", pol) == frozenset({"get_most_recent_transactions"})
    assert extract_allowed_tools("Recommend a hotel with the best rating", pol) == frozenset({"get_hotels_address"})
    assert extract_allowed_tools("Summarize my last email.", pol) == frozenset()
