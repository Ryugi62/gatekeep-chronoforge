"""Gemini 어댑터 — 전송 함수를 주입해 네트워크 없이 시험한다. 키는 환경변수로만 읽고 어디에도 쓰지 않는다."""
import json

import pytest

from gatekeep.adapters.city_tools import TOOL_DECLARATIONS, make_tools
from gatekeep.adapters.gemini_agent import GeminiSession, QuotaExhausted, load_key
from gatekeep.application.agent_episode import ToolResult
from gatekeep.domain.model import ToolCall


def fake(responses):
    seen = []

    def post(url, headers, body):
        seen.append((url, headers, body))
        return responses.pop(0)

    return post, seen


def reply(parts):
    return (200, {"candidates": [{"content": {"role": "model", "parts": parts}}]})


def test_key_comes_from_environment_only(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        load_key()
    monkeypatch.setenv("GEMINI_API_KEY", "k-test-123")
    assert load_key() == "k-test-123"


def test_function_call_turn_and_key_goes_in_header_not_url_or_body():
    post, seen = fake([reply([{"functionCall": {"name": "read_notice", "args": {"id": 3}}}]), reply([{"text": "done"}])])
    s = GeminiSession("gemini-test", "k-secret", "system", TOOL_DECLARATIONS, post=post, sleep=lambda x: None, min_gap=0)
    t = s.send_user("Summarize notice 3.")
    assert t.calls == [ToolCall("read_notice", {"id": 3})]
    t2 = s.send_tool_results([ToolResult("read_notice", "text")])
    assert t2.text == "done" and not t2.calls
    url, headers, body = seen[0]
    assert "k-secret" not in url and "k-secret" not in json.dumps(body) and headers["x-goog-api-key"] == "k-secret"
    sent = seen[1][2]["contents"]
    assert sent[2]["parts"][0]["functionResponse"]["name"] == "read_notice"
    assert sent[1]["parts"][0]["functionCall"]["name"] == "read_notice"  # 모델 턴 원문을 그대로 되돌려 보낸다


def test_daily_quota_stops_and_keeps_original_message():
    post, _ = fake([(429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "Quota exceeded for metric generate_content_free_tier_requests per day"}})])
    s = GeminiSession("m", "k", "sys", TOOL_DECLARATIONS, post=post, sleep=lambda x: None, min_gap=0)
    with pytest.raises(QuotaExhausted) as e:
        s.send_user("hi")
    assert "per day" in e.value.original


def test_per_minute_limit_waits_once_then_retries():
    post, seen = fake([(429, {"error": {"code": 429, "message": "Please retry in 12.5s. per minute"}}), reply([{"text": "ok"}])])
    waits = []
    s = GeminiSession("m", "k", "sys", TOOL_DECLARATIONS, post=post, sleep=waits.append, min_gap=0)
    assert s.send_user("hi").text == "ok" and len(seen) == 2 and max(waits) >= 12.5


def test_mock_tools_never_touch_the_outside_world():
    tools = make_tools("Bill: Rs 5", "get_bill_details")
    assert tools["get_bill_details"]() == "Bill: Rs 5" and tools["read_notice"](id=1) == "No matching record."
    assert tools["send_email"](to="a@b.co", body="x").startswith("[mock]")
    assert {d["name"] for d in TOOL_DECLARATIONS} == set(tools)
