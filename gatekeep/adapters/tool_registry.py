"""도구 → Risk. 원칙은 명시 등록(도시 서비스 팩 JSON)이고, 이름 추론은 공개 벤치의 수백 개 도구를 덮기 위한 보조 휴리스틱이다.
이름에서 동사를 못 찾거나 읽기 동사도 없으면 None — 도메인 R0이 기본 거부한다 (「모르는 도구는 읽기」가 아니다)."""
from __future__ import annotations

import json
import re
from typing import Dict, Iterable, Optional

from ..domain.model import Policy, Risk

_MONEY = {"transfer", "pay", "withdraw", "deposit", "place", "purchase", "checkout", "refund", "buy", "sell",
          "wire", "remit", "disburse", "settle", "donate", "tip", "charge", "debit", "credit"}
_OUTBOUND = {"send", "share", "post", "upload", "publish", "forward", "reply",
             "email", "mail", "notify", "message", "dm", "text", "transmit", "broadcast", "export", "submit", "tweet", "sms", "whatsapp"}
_DESTRUCTIVE = {"delete", "remove", "execute", "exec", "shell", "move", "leave", "disable", "wipe", "format", "drop", "terminate", "kill",
                "erase", "rm", "rmdir", "unlink", "purge", "truncate", "overwrite", "destroy", "trash", "run", "command", "sudo"}
_STATE = {"grant", "unlock", "update", "manage", "create", "schedule", "go", "give", "autofill", "generate", "set", "change", "revoke",
          "cancel", "enable", "download", "dispatch", "fill", "reserve", "book", "add", "invite", "append", "reschedule",
          "issue", "approve", "assign", "register", "enroll", "authorize", "install", "reset", "rename"}
_MONEY_NOUNS = {"money", "funds", "payment", "payments", "transaction", "transactions", "bill", "bills", "invoice", "invoices", "amount"}
_READ_VERBS = {"get", "search", "read", "navigate", "list", "view", "fetch", "find", "show", "check", "lookup", "access",
               "visit", "browse", "describe", "query", "retrieve", "load", "inspect", "summarize", "display", "count", "calculate", "compute"}
_SENSITIVE = {"location", "history", "password", "passwords", "patient", "genetic", "payment", "address", "addresses", "account",
              "holdings", "prescription", "prescriptions", "health", "record", "records", "personalinfo", "phone", "payees", "payee",
              "linked", "saved", "orders", "access", "log", "data", "clinical", "ssn", "credentials", "info", "transactions", "balance", "iban", "scheduled"}
_CONJ = {"and", "then"}


def _words(name: str):
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).replace("_", " ")
    return [w.lower() for w in spaced.split()]


def infer_risk(name: str) -> Optional[Risk]:
    """이름에서 처음 나오는 동사가 등급을 정한다 (앱이름·동사·목적어 순서 관례).
    읽기 동사가 먼저 나오면 뒤 낱말은 목적어로 본다. 단 and/then이 든 복합 이름은 가장 위험한 동사를 따른다.
    행동 동사도 읽기 동사도 없으면 None."""
    words = _words(name)
    compound = any(w in _CONJ for w in words)
    found = []
    for w in words:
        for group, risk in ((_MONEY, Risk.MONEY), (_OUTBOUND, Risk.OUTBOUND), (_DESTRUCTIVE, Risk.DESTRUCTIVE), (_STATE, Risk.STATE_CHANGE)):
            if w in group:
                if risk in (Risk.OUTBOUND, Risk.STATE_CHANGE) and any(x in _MONEY_NOUNS for x in words):
                    risk = Risk.MONEY
                if not compound:
                    return risk
                found.append(risk)
                break
        else:
            if w in _READ_VERBS and not compound:
                break
    if found:
        for r in (Risk.MONEY, Risk.DESTRUCTIVE, Risk.OUTBOUND, Risk.STATE_CHANGE):
            if r in found:
                return r
    if not any(w in _READ_VERBS for w in words):
        return None
    if any(w in _SENSITIVE for w in words):
        return Risk.SENSITIVE_READ
    return Risk.READ


def build_policy(tool_names: Iterable[str], max_amount: float, sandbox_root: str,
                 registered: Optional[Dict[str, Risk]] = None) -> Policy:
    risks: Dict[str, Risk] = {}
    for n in tool_names:
        r = infer_risk(n)
        if r is not None:
            risks[n] = r
    risks.update(registered or {})
    return Policy(risks=risks, max_amount=max_amount, sandbox_root=sandbox_root)


def load_city_pack(path: str) -> Policy:
    """도시 서비스 팩 JSON — 도구 등록 + 송금 상한(설정값, limit_basis에 근거 한 줄) + 작업 폴더. 목록에 없는 도구는 추론 없이 None."""
    with open(path, encoding="utf-8") as f:
        pack = json.load(f)
    risks = {name: Risk[level] for name, level in pack["tools"].items()}
    return Policy(risks=risks, max_amount=float(pack["max_amount"]), sandbox_root=pack.get("sandbox_root", "/workspace"))
