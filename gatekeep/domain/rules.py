"""Rule — ToolCall 1건을 Task·Policy와 대조해 Evidence를 내거나 None(침묵)."""
from __future__ import annotations

import functools
import posixpath
import re
from typing import List, Optional, Tuple

from .model import Evidence, Policy, Risk, Task, ToolCall

# 인자 이름은 고정 목록이 아니라 「토큰」 패턴: snake_case·camelCase·하이픈을 쪼갠 낱말 중 하나가 맞으면 해당 종류로 본다.
DEST_TOKENS = {"to", "cc", "bcc", "recipient", "recipients", "receiver", "payee", "email", "emails", "mail", "url", "uri", "link",
               "address", "account", "acct", "iban", "beneficiary", "beneficiaries", "destination", "dest", "target", "phone",
               "user", "guest", "guests", "username", "channel", "participants", "participant", "handle", "vpa", "upi"}
DEST_SUBSTR = ("iban", "account", "beneficiar", "recipient", "receiver", "payee", "email", "url", "vpa", "destination")
AMOUNT_TOKENS = {"amount", "amt", "value", "total", "sum", "price", "cost", "fee"}
PATH_TOKENS = {"path", "paths", "file", "files", "filepath", "filename", "dir", "directory", "folder", "target", "location", "src", "source"}
CMD_TOKENS = {"command", "cmd", "script", "shell", "bash", "exec", "commandline"}
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S{6,}"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
]
# 시민 식별번호 형식 (Aadhaar 12자리 · PAN 10자) — 시민이 요청에 직접 쓴 값은 제외
AADHAAR = re.compile(r"(?:^|[^\d])(\d{4}[ -]?\d{4}[ -]?\d{4})(?!\d)")
PAN = re.compile(r"(?:^|[^A-Za-z0-9])([A-Z]{5}\d{4}[A-Z])(?![A-Za-z0-9])")
DANGEROUS_SHELL = [
    re.compile(r"\brm\s+(?:-{1,2}[A-Za-z][A-Za-z-]*\s+)+(?:/|~|\$\{?HOME\}?|\*|\./\*|\.\.?(?:\s|$))"),
    re.compile(r"(curl|wget)[^|;]*\|\s*(sudo\s+)?(sh|bash|zsh)\b"),
    re.compile(r"\bdd\s+if="),
    re.compile(r"\bmkfs(\.\w+)?\b"),
    re.compile(r"chmod\s+-R\s+7{3}\s+/"),
    re.compile(r":\(\)\s*\{"),
    re.compile(r"\bfind\b[^|;]*\s-delete\b"),
    re.compile(r"\bshred\b"),
    re.compile(r">\s*/dev/sd"),
]
EMAIL_SHAPE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
URL_SHAPE = re.compile(r"https?://\S+")
IBAN_SHAPE = re.compile(r"[A-Za-z]{2}\d{2}[A-Za-z0-9]{10,30}")


def key_tokens(key: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t]


def _key_has(key: str, tokens, substrs=()) -> bool:
    if any(t in tokens for t in key_tokens(key)):
        return True
    low = key.lower()
    return any(s in low for s in substrs)


def norm(text: str) -> str:
    """목적지 비교용 정규화: 소문자, 공백·하이픈·밑줄 제거."""
    return re.sub(r"[\s\-_]+", "", text.lower())


def _loose_pattern(nv: str) -> str:
    return r"[\s\-_]*".join(re.escape(ch) for ch in nv)


@functools.lru_cache(maxsize=4096)
def _compiled(pattern: str):
    return re.compile(pattern)


def in_text_loose(value: str, text: str) -> bool:
    """값이 글 안 어딘가에 (공백·하이픈 사이에 끼어도) 나오는가 — 신뢰할 수 없는 글 쪽 판정(넓게 잡는다)."""
    nv = norm(value)
    return bool(nv) and _compiled(_loose_pattern(nv)).search(text.lower()) is not None


def in_text_token(value: str, text: str) -> bool:
    """값 전체가 하나의 토큰으로 나오는가 — 사용자 요청 쪽 판정. 긴 번호의 일부(앞뒤가 영숫자)는 일치가 아니다."""
    nv = norm(value)
    if not nv:
        return False
    pat = r"(?:^|[^a-z0-9\-_])" + _loose_pattern(nv) + r"(?:$|[^a-z0-9\-_])"
    return _compiled(pat).search(text.lower()) is not None


class Rule:
    id = "R?"

    def check(self, call: ToolCall, task: Task, policy: Policy) -> Optional[Evidence]:  # pragma: no cover
        raise NotImplementedError


PATH_NOT = {"id", "ids"}  # file_id·dir_id 같은 식별자는 경로가 아니다


def _args_by_key(call: ToolCall, tokens, substrs=(), exclude=()) -> List[str]:
    out: List[str] = []
    for k, v in call.args.items():
        if exclude and any(t in exclude for t in key_tokens(k)):
            continue
        if _key_has(k, tokens, substrs):
            out.extend(ToolCall(call.tool, {"v": v}).string_values())
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out.append(str(v))
    return out


def _destinations(call: ToolCall) -> List[str]:
    out = _args_by_key(call, DEST_TOKENS, DEST_SUBSTR)
    for k, v in call.args.items():  # 키 이름이 낯설어도 값 전체가 메일·URL·IBAN 모양이면 목적지로 본다
        if _key_has(k, DEST_TOKENS, DEST_SUBSTR):
            continue
        for s in ToolCall(call.tool, {"v": v}).string_values():
            t = s.strip()
            if EMAIL_SHAPE.fullmatch(t) or URL_SHAPE.fullmatch(t) or IBAN_SHAPE.fullmatch(norm(t).upper()):
                out.append(s)
    return out


class UnknownTool(Rule):
    id = "R0"

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) is None:
            return Evidence(self.id, "등록되지 않았고 이름으로 추론되지도 않는 도구는 기본 거부", call.tool)
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


def _only_cited(task: Task, holders: List[str]) -> bool:
    """값이 나온 신뢰할 수 없는 글이 전부 사용자가 근거로 가리킨 문서인가."""
    return bool(holders) and all(h in task.cited_sources for h in holders)


class TaintedDestination(Rule):
    id = "R2"
    RISKS = (Risk.OUTBOUND, Risk.MONEY, Risk.STATE_CHANGE)

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) not in self.RISKS:
            return None
        soft: Optional[Evidence] = None
        for value in _destinations(call):
            if len(norm(value)) < 4:
                continue
            holders = [u for u in task.untrusted_texts if in_text_loose(value, u)]
            if not holders or in_text_token(value, task.user_request):
                continue
            if _only_cited(task, holders):
                soft = soft or Evidence(self.id, "목적지가 사용자가 가리킨 문서에서만 나옴 — 사용자 확인 필요", value, True)
                continue
            return Evidence(self.id, "목적지가 신뢰할 수 없는 글에서만 나옴", value)
        return soft


def _parse_amount(text: str) -> Optional[float]:
    m = re.search(r"-?\d[\d,]*(\.\d+)?", text.replace("$", ""))
    if not m:
        return None
    try:
        return float(m.group(0).replace(",", ""))
    except ValueError:
        return None


def _said(amount: float, text: str) -> bool:
    t = text.replace(",", "")
    forms = {("%g" % amount), ("%d" % amount) if amount == int(amount) else ("%g" % amount)}
    return any(re.search(r"(?:^|[^\d.])" + re.escape(f) + r"(?!\d)", t) for f in forms)


class AmountLimit(Rule):
    id = "R3"

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) is not Risk.MONEY:
            return None
        soft: Optional[Evidence] = None
        for raw in _args_by_key(call, AMOUNT_TOKENS):
            amount = _parse_amount(raw)
            if amount is None or amount <= policy.max_amount or _said(amount, task.user_request):
                continue
            holders = [u for u in task.untrusted_texts if _said(amount, u)]
            if _only_cited(task, holders):
                soft = soft or Evidence(self.id, "상한 %g 초과 금액이 사용자가 가리킨 문서에서만 나옴 — 사용자 확인 필요" % policy.max_amount, raw, True)
                continue
            return Evidence(self.id, "상한 %g 초과 금액이 사용자 요청에 없음" % policy.max_amount, raw)
        return soft


class PathEscape(Rule):
    id = "R4"

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) is not Risk.DESTRUCTIVE:
            return None
        root = policy.sandbox_root.rstrip("/")
        for p in _args_by_key(call, PATH_TOKENS, exclude=PATH_NOT):
            if p.startswith("~") or ".." in p.split("/"):
                return Evidence(self.id, "작업 폴더 밖 경로", p)
            norm_p = posixpath.normpath(p)
            if not norm_p.startswith(root + "/"):
                return Evidence(self.id, "작업 폴더 %s 밖 경로" % root, p)
        for cmd in _args_by_key(call, CMD_TOKENS):
            for pat in DANGEROUS_SHELL:
                if pat.search(cmd):
                    return Evidence(self.id, "위험 셸 명령", cmd)
        return None


class SecretEgress(Rule):
    id = "R5"

    def check(self, call, task, policy):
        if policy.risk_of(call.tool) is not Risk.OUTBOUND:
            return None
        req_digits = re.sub(r"[ -]", "", task.user_request)
        for s in call.string_values():
            for pat in SECRET_PATTERNS:
                if pat.search(s):
                    return Evidence(self.id, "외부 전송 인자에 비밀 값", pat.pattern[:30])
            for m in AADHAAR.finditer(s):
                if re.sub(r"[ -]", "", m.group(1)) not in req_digits:
                    return Evidence(self.id, "외부 전송 인자에 시민 식별번호(Aadhaar 형식)", "aadhaar-12-digit")
            for m in PAN.finditer(s):
                if m.group(1) not in task.user_request:
                    return Evidence(self.id, "외부 전송 인자에 시민 식별번호(PAN 형식)", "pan-format")
        return None
