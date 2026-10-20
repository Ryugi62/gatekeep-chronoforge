"""Rule — ToolCall 1건을 Task·Policy와 대조해 Evidence를 내거나 None(침묵)."""
from __future__ import annotations

import posixpath
import re
from typing import List, Optional

from .model import Evidence, Policy, Risk, Task, ToolCall

DEST_KEYS = {
    "to", "cc", "bcc", "recipient", "recipients", "receiver", "email", "address", "account",
    "account_number", "payee", "target", "url", "destination", "user", "guest", "guest_ids",
    "username", "phone_number", "channel", "participants", "user_email", "emails",
}
AMOUNT_KEYS = {"amount", "value", "total", "sum"}
PATH_KEYS = {"path", "paths", "file", "file_path", "filepath", "target_path", "directory", "dir", "item_path"}
CMD_KEYS = {"command", "cmd", "script", "shell"}
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S{6,}"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
]
DANGEROUS_SHELL = [
    re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(/|~|\$HOME|\*)"),
    re.compile(r"(curl|wget)[^|;]*\|\s*(sudo\s+)?(sh|bash|zsh)\b"),
    re.compile(r"\bdd\s+if="),
    re.compile(r"\bmkfs(\.\w+)?\b"),
    re.compile(r"chmod\s+-R\s+7{3}\s+/"),
    re.compile(r":\(\)\s*\{"),
]


class Rule:
    id = "R?"

    def check(self, call: ToolCall, task: Task, policy: Policy) -> Optional[Evidence]:  # pragma: no cover
        raise NotImplementedError


def _args_by_key(call: ToolCall, keys) -> List[str]:
    out: List[str] = []
    for k, v in call.args.items():
        if k.lower() in keys:
            out.extend(ToolCall(call.tool, {"v": v}).string_values())
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out.append(str(v))
    return out


class UnknownTool(Rule):
    id = "R0"

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) is None:
            return Evidence(self.id, "등록되지 않은 도구는 기본 거부", call.tool)
        return None


class OutOfScope(Rule):
    id = "R1"

    def check(self, call, task, policy):
        risk = policy.risk_of(call.tool)
        if risk is None or risk is Risk.READ:
            return None
        if call.tool not in task.allowed_tools:
            return Evidence(self.id, "사용자 요청 범위 밖 도구 %s(%s)" % (call.tool, risk.value), call.tool)
        return None


class TaintedDestination(Rule):
    id = "R2"
    RISKS = (Risk.OUTBOUND, Risk.MONEY, Risk.STATE_CHANGE)

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) not in self.RISKS:
            return None
        request = task.user_request.lower()
        untrusted = "\n".join(task.untrusted_texts).lower()
        for value in _args_by_key(call, DEST_KEYS):
            v = value.strip().lower()
            if len(v) < 4:
                continue
            if v in untrusted and v not in request:
                return Evidence(self.id, "목적지가 신뢰할 수 없는 글에서만 나옴", value)
        return None


def _parse_amount(text: str) -> Optional[float]:
    m = re.search(r"-?\d[\d,]*(\.\d+)?", text.replace("$", ""))
    if not m:
        return None
    try:
        return float(m.group(0).replace(",", ""))
    except ValueError:
        return None


class AmountLimit(Rule):
    id = "R3"

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) is not Risk.MONEY:
            return None
        request = task.user_request.replace(",", "")
        for raw in _args_by_key(call, AMOUNT_KEYS):
            amount = _parse_amount(raw)
            if amount is None or amount <= policy.max_amount:
                continue
            said = {("%g" % amount), ("%d" % amount) if amount == int(amount) else ("%g" % amount)}
            if any(s in request for s in said):
                continue
            return Evidence(self.id, "상한 %g 초과 금액이 사용자 요청에 없음" % policy.max_amount, raw)
        return None


class PathEscape(Rule):
    id = "R4"

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) is not Risk.DESTRUCTIVE:
            return None
        root = policy.sandbox_root.rstrip("/")
        for p in _args_by_key(call, PATH_KEYS):
            if p.startswith("~") or ".." in p.split("/"):
                return Evidence(self.id, "작업 폴더 밖 경로", p)
            norm = posixpath.normpath(p)
            if not norm.startswith(root + "/"):
                return Evidence(self.id, "작업 폴더 %s 밖 경로" % root, p)
        for cmd in _args_by_key(call, CMD_KEYS):
            for pat in DANGEROUS_SHELL:
                if pat.search(cmd):
                    return Evidence(self.id, "위험 셸 명령", cmd)
        return None


class SecretEgress(Rule):
    id = "R5"

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) is not Risk.OUTBOUND:
            return None
        for s in call.string_values():
            for pat in SECRET_PATTERNS:
                if pat.search(s):
                    return Evidence(self.id, "외부 전송 인자에 비밀 값", pat.pattern[:30])
        return None
