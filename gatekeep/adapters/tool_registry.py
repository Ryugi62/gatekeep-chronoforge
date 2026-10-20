"""도구 이름 → Risk 추론 (낯선 도구 목록용). 운영에서는 도구를 명시 등록하는 것이 원칙이고, 추론은 공개 벤치의 수백 개 도구를 덮기 위한 휴리스틱이다."""
from __future__ import annotations

import re
from typing import Dict, Iterable

from ..domain.model import Policy, Risk

_MONEY = {"transfer", "pay", "withdraw", "deposit", "place", "purchase", "checkout", "refund", "buy", "sell"}
_OUTBOUND = {"send", "share", "post", "upload", "publish", "forward", "reply"}
_DESTRUCTIVE = {"delete", "remove", "execute", "exec", "shell", "move", "leave", "disable", "wipe", "format", "drop", "terminate", "kill"}
_STATE = {"grant", "unlock", "update", "manage", "create", "schedule", "go", "give", "autofill", "generate", "set", "change", "revoke", "cancel", "enable", "download", "dispatch", "fill", "reserve", "book", "add", "invite", "append", "reschedule"}
_MONEY_NOUNS = {"money", "funds", "payment", "payments", "transaction", "transactions", "bill", "bills"}
_READ_VERBS = {"get", "search", "read", "navigate", "list", "view", "fetch", "find", "show", "check", "lookup", "access"}
_SENSITIVE = {"location", "history", "password", "passwords", "patient", "genetic", "payment", "address", "addresses", "account",
              "holdings", "prescription", "prescriptions", "health", "record", "records", "personalinfo", "phone", "payees", "payee",
              "linked", "saved", "orders", "access", "log", "data", "clinical", "ssn", "credentials", "info", "transactions", "balance", "iban", "scheduled"}


def _words(name: str):
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).replace("_", " ")
    return [w.lower() for w in spaced.split()]


def infer_risk(name: str) -> Risk:
    """이름에서 처음 나오는 동사가 등급을 정한다 (앱이름·동사·목적어 순서 관례)."""
    words = _words(name)
    for w in words:
        for group, risk in ((_MONEY, Risk.MONEY), (_OUTBOUND, Risk.OUTBOUND), (_DESTRUCTIVE, Risk.DESTRUCTIVE), (_STATE, Risk.STATE_CHANGE)):
            if w in group:
                if risk in (Risk.OUTBOUND, Risk.STATE_CHANGE) and any(x in _MONEY_NOUNS for x in words):
                    return Risk.MONEY
                return risk
        if w in _READ_VERBS:
            break
    if any(w in _SENSITIVE for w in words):
        return Risk.SENSITIVE_READ
    return Risk.READ


def build_policy(tool_names: Iterable[str], max_amount: float, sandbox_root: str) -> Policy:
    risks: Dict[str, Risk] = {n: infer_risk(n) for n in tool_names}
    return Policy(risks=risks, max_amount=max_amount, sandbox_root=sandbox_root)
