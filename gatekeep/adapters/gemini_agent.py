"""Gemini REST 어댑터 — 에이전트 모델(검문 대상). GateKeep은 이 모델을 쓰지 않는다.
키는 환경변수 GEMINI_API_KEY로만 읽고 헤더로만 보낸다(파일·로그·URL·본문에 쓰지 않는다)."""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Tuple

from ..application.agent_episode import AgentSession, ToolResult, Turn
from ..domain.model import ToolCall

BASE = "https://generativelanguage.googleapis.com/v1beta/models/"


class QuotaExhausted(Exception):
    def __init__(self, original: str):
        self.original = original
        super().__init__("quota: " + original)


def load_key() -> str:
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    return key


def http_post(url: str, headers: Dict[str, str], body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={**headers, "content-type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": {"message": "http %d" % e.code}}


class GeminiSession(AgentSession):
    def __init__(self, model: str, key: str, system: str, declarations: List[Dict], post: Callable = http_post,
                 sleep: Callable[[float], None] = time.sleep, min_gap: float = 7.0):
        self.model, self.key, self.post, self.sleep, self.min_gap = model, key, post, sleep, min_gap
        self.base_body = {"systemInstruction": {"parts": [{"text": system}]}, "tools": [{"functionDeclarations": declarations}],
                          "generationConfig": {"temperature": 0}}
        self.contents: List[Dict] = []
        self.requests = 0

    def _turn(self) -> Turn:
        body = dict(self.base_body, contents=self.contents)
        for attempt in (0, 1):
            self.sleep(self.min_gap)
            status, data = self.post(BASE + self.model + ":generateContent", {"x-goog-api-key": self.key}, body)
            self.requests += 1
            if status == 200:
                break
            msg = (data.get("error") or {}).get("message", "")
            m = re.search(r"retry in ([0-9.]+)s", msg)
            if status == 429 and attempt == 0 and m and "per day" not in msg.lower() and float(m.group(1)) <= 90:
                self.sleep(float(m.group(1)) + 1)  # 분당 한도: 안내된 시간만큼 기다린 뒤 한 번만 다시
                continue
            if status == 429:
                raise QuotaExhausted(msg)
            raise RuntimeError("gemini http %s: %s" % (status, msg[:200]))
        cand = (data.get("candidates") or [{}])[0].get("content") or {"role": "model", "parts": []}
        self.contents.append(cand)  # 모델 턴 원문(서명 포함)을 그대로 보존
        parts = cand.get("parts", [])
        calls = [ToolCall(p["functionCall"]["name"], dict(p["functionCall"].get("args", {}))) for p in parts if "functionCall" in p]
        text = "".join(p.get("text", "") for p in parts if "text" in p and not p.get("thought"))
        return Turn(calls, text)

    def send_user(self, text: str) -> Turn:
        self.contents.append({"role": "user", "parts": [{"text": text}]})
        return self._turn()

    def send_tool_results(self, results: List[ToolResult]) -> Turn:
        self.contents.append({"role": "user", "parts": [{"functionResponse": {"name": r.tool, "response": {"result": r.content}}} for r in results]})
        return self._turn()
