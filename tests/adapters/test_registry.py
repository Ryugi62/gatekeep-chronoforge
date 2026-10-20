from gatekeep.adapters.tool_registry import infer_risk, build_policy
from gatekeep.domain.model import Risk


def test_infer_money_outbound_destructive():
    assert infer_risk("BankManagerTransferFunds") is Risk.MONEY
    assert infer_risk("pay_bill") is Risk.MONEY
    assert infer_risk("GmailSendEmail") is Risk.OUTBOUND
    assert infer_risk("The23andMeShareData") is Risk.OUTBOUND
    assert infer_risk("GitHubDeleteRepository") is Risk.DESTRUCTIVE
    assert infer_risk("TerminalExecute") is Risk.DESTRUCTIVE
    assert infer_risk("AugustSmartLockGrantGuestAccess") is Risk.STATE_CHANGE


def test_infer_reads_public_vs_sensitive():
    assert infer_risk("GmailReadEmail") is Risk.READ
    assert infer_risk("AmazonGetProductDetails") is Risk.READ
    assert infer_risk("AmazonViewSavedAddresses") is Risk.SENSITIVE_READ
    assert infer_risk("NortonIdentitySafeSearchPasswords") is Risk.SENSITIVE_READ


def test_build_policy_covers_names():
    p = build_policy(["GmailSendEmail", "web_search"], max_amount=500.0, sandbox_root="/workspace")
    assert p.risk_of("GmailSendEmail") is Risk.OUTBOUND and p.risk_of("web_search") is Risk.READ


def test_infer_snake_case_agent_tools():
    assert infer_risk("send_money") is Risk.MONEY
    assert infer_risk("schedule_transaction") is Risk.MONEY
    assert infer_risk("send_direct_message") is Risk.OUTBOUND
    assert infer_risk("reserve_hotel") is Risk.STATE_CHANGE
    assert infer_risk("add_user_to_channel") is Risk.STATE_CHANGE
    assert infer_risk("get_most_recent_transactions") is Risk.SENSITIVE_READ
    assert infer_risk("read_channel_messages") is Risk.READ
    assert infer_risk("search_emails") is Risk.READ
