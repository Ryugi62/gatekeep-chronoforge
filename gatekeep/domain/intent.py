"""요청 기반 허용 도구 추출 — 오라클 없이 사용자 요청 문장만으로 R1의 허용 목록을 만든다 (SPEC 5-12~14).

규칙만 쓴다: 동사 사전(의미 묶음 PAY·SEND·DELETE·GRANT·UPDATE·CREATE·CANCEL·RUN) + 부정 표현 + 도구 이름 낱말.
학습·LLM·네트워크 없음. 입력은 사용자 요청 문장과 정책(등록된 도구)뿐이다 — 신뢰할 수 없는 글은 받지 않는다.
도구가 요청의 동사 묶음과 하나라도 겹쳐야 허용된다. 돈 관련 도구는 요청에 송금 동사가 있거나(또는 행동 동사 + 돈 명사)일 때만."""
from __future__ import annotations

import re
from typing import Dict, FrozenSet, List, Set

from .model import Policy, Risk

PAY, SEND, DELETE, GRANT, UPDATE, CREATE, CANCEL, RUN = "PAY", "SEND", "DELETE", "GRANT", "UPDATE", "CREATE", "CANCEL", "RUN"

EN: Dict[str, Set[str]] = {}


def _add(concept: str, words: str):
    for w in words.split():
        EN.setdefault(w, set()).add(concept)


_add(PAY, "pay paid transfer wire remit settle refund purchase buy bought checkout donate withdraw deposit reimburse")
_add(SEND, "send sent forward reply respond share notify dm submit upload publish broadcast export post tweet")
_add(DELETE, "delete remove erase wipe trash purge clear discard destroy drop clean unlink truncate overwrite")
_add(GRANT, "grant give unlock invite add assign authorize approve allow enable")
_add(UPDATE, "update change edit modify set rename reschedule adjust reset replace")
_add(CREATE, "create schedule book reserve make register issue generate add enroll set setup")
_add(CANCEL, "cancel revoke disable terminate stop unsubscribe leave remove")
_add(RUN, "run execute exec shell command launch test build compile install")

MONEY_NOUNS = {"money", "funds", "fund", "payment", "payments", "transaction", "transactions", "bill", "bills", "invoice", "invoices",
               "amount", "rent", "fee", "fees", "tax", "taxes", "fine", "fare", "cash", "salary", "refund", "deposit"}
KO_MONEY_NOUNS = ("청구서", "요금", "세금", "월세", "관리비", "계약금", "대금", "견적서", "송금", "이체")
MESSAGE_NOUNS = {"message", "email", "mail", "note", "reply", "dm"}
WRITE_VERBS = {"write", "compose", "draft", "leave", "drop"}
NEGATORS = {"not", "dont", "don't", "never", "without", "no", "cannot", "can't", "won't", "shouldn't", "avoid", "nor", "didn't"}
VERB_LEAD = {"to", "please", "and", "then", "can", "could", "will", "would", "should", "must", "also", "just", "pls"} | NEGATORS
ADJ_NOUNS = {"folder", "drive", "inbox", "calendar", "file", "files", "doc", "docs", "document", "link", "account", "channel", "mail", "email", "emails", "items"}
AMOUNT_RE = re.compile(r"(?:[$₹€]\s?\d|\b\d[\d,]*(?:\.\d+)?\s?(?:usd|inr|eur|dollars?|rupees?|rs|원)\b)", re.I)

KO = (  # (낱말 조각, 개념)
    ("결제", PAY), ("이체", PAY), ("송금", PAY), ("납부", PAY), ("지불", PAY), ("입금", PAY),
    ("보내", SEND), ("발송", SEND), ("공유", SEND), ("전달", SEND), ("회신", SEND),
    ("지워", DELETE), ("지우", DELETE), ("삭제", DELETE), ("비워", DELETE), ("제거", DELETE),
    ("돌려", RUN), ("실행", RUN),
    ("수정", UPDATE), ("변경", UPDATE), ("바꿔", UPDATE), ("고쳐", UPDATE),
    ("등록", CREATE), ("생성", CREATE), ("만들어", CREATE),
    ("취소", CANCEL), ("해지", CANCEL),
)
KO_NEG = ("지 마", "지마", "말고", "말아", "금지", "하지 않")
FILE_CUES = ("폴더", "파일", "캐시", "임시", "다운로드", "로그")


def _lookup(tok: str) -> Set[str]:
    cands = [tok]
    for suf, rep in (("ies", "y"), ("ied", "y"), ("es", ""), ("ed", ""), ("ing", ""), ("ing", "e"), ("s", ""), ("d", "")):
        if tok.endswith(suf) and len(tok) - len(suf) >= 2:
            c = tok[: len(tok) - len(suf)] + rep
            cands.append(c)
            if len(c) > 2 and c[-1] == c[-2]:
                cands.append(c[:-1])
    for c in cands:
        if c in EN:
            return EN[c]
    return set()


def request_concepts(request: str):
    """요청 문장 → (동사 묶음 집합, 돈 명사 있음). 규칙만."""
    text = request.lower()
    toks = re.findall(r"[a-z']+", text)
    found: Set[str] = set()
    for i, tok in enumerate(toks):
        concepts = _lookup(tok)
        if tok in ("email", "mail"):
            if i == 0 or toks[i - 1] in VERB_LEAD:
                concepts = {SEND}
            else:
                concepts = set()
        if tok in ("message", "dm") and not (i + 1 < len(toks) and toks[i + 1] in {"them", "him", "her", "us", "everyone", "all"}):
            concepts = set()
        if tok in WRITE_VERBS and any(t in MESSAGE_NOUNS for t in toks[i + 1:i + 5]):
            concepts = {SEND}
        if tok.endswith("ed") or tok == "sent":  # 「shared folder」 「sent items」: 뒤에 명사가 바로 오면 형용사
            if i + 1 < len(toks) and toks[i + 1] in ADJ_NOUNS:
                continue
        if not concepts:
            continue
        window = toks[max(0, i - 3):i]
        if any(w in NEGATORS for w in window) or toks[max(0, i - 2):i] == ["instead", "of"]:
            continue
        found |= concepts
    for stem, concept in KO:
        for m in re.finditer(re.escape(stem), request):
            tail = request[m.end():m.end() + 12]
            if any(n in tail for n in KO_NEG):
                continue
            found.add(concept)
    if "알려" in request and ("메일" in request or "에게" in request or "한테" in request or "@" in request):
        found.add(SEND)
    if "권한" in request and any(k in request for k in ("줘", "주세요", "부여", "허용", "열어")):
        found.add(GRANT)
    if "정리" in request and any(c in request for c in FILE_CUES):
        found.add(DELETE)
    money = any(t in MONEY_NOUNS for t in toks) or any(n in request for n in KO_MONEY_NOUNS) or bool(AMOUNT_RE.search(request))
    if SEND in found and money:
        found.add(PAY)
    return found, money


def _name_words(name: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).replace("_", " ").replace("-", " ")
    return [w.lower() for w in spaced.split()]


def tool_concepts(name: str):
    """도구 이름 → (동사 묶음 집합, 이름에 돈 명사 있음). 돈 명사가 있으면 send·transfer·place 같은 동사는 송금(PAY)으로 본다."""
    words = _name_words(name)
    money = any(w in MONEY_NOUNS for w in words)
    out: Set[str] = set()
    for w in words:
        cs = _lookup(w)
        if money and SEND in cs:
            cs = (cs - {SEND}) | {PAY}
        out |= cs
    return out, money


GENERIC_NAME_WORDS = {"get", "search", "read", "list", "view", "fetch", "find", "show", "check", "lookup", "access", "all", "most", "recent",
                      "in", "for", "of", "the", "and", "to", "by", "per", "with", "user", "users", "current", "available", "visit", "browse"}


def _stem(w: str) -> str:
    return w[:-1] if w.endswith("s") and len(w) > 3 else w


def _object_words(name: str) -> Set[str]:
    return {_stem(w) for w in _name_words(name) if w not in GENERIC_NAME_WORDS}


def extract_allowed_tools(user_request: str, policy: Policy) -> FrozenSet[str]:
    """등록된 도구 중, 사용자 요청의 동사 묶음과 겹치는 읽기 외 도구만 허용 목록으로 돌려준다."""
    req, req_money = request_concepts(user_request)
    allowed = set()
    for name, risk in policy.risks.items():
        if risk is Risk.READ:
            continue
        if risk is Risk.SENSITIVE_READ:  # 민감 읽기는 도구 이름의 대상 낱말이 요청에도 나올 때만 (동사 묶음이 없는 도구라서)
            if _object_words(name) & {_stem(t) for t in re.findall(r"[a-z]+", user_request.lower())}:
                allowed.add(name)
            continue
        tc, tool_money = tool_concepts(name)
        if not (tc & req):
            continue
        if tool_money and PAY not in req and not req_money:
            continue
        allowed.add(name)
    return frozenset(allowed)
