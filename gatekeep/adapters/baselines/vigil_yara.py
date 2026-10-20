"""Vigil-LLM(Apache-2.0) YARA 규칙을 re로 옮겨 돌린다 — 규칙 파일은 data/third_party 의 원본을 읽는다."""
from __future__ import annotations

import os
import re
from typing import List

from ...application.ports import TextGuard

RULE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "third_party")
RULE_FILES = ["instruction_bypass.yar", "system_instructions.yar", "mdexfil.yar", "guidance.yar"]


def _parse(text: str):
    """반환: [(조건 any/all, [패턴...], nocase_flags)] — 이 4개 파일이 쓰는 최소 문법만 지원."""
    rules = []
    for block in re.split(r"(?m)^rule ", text)[1:]:
        strings_part = block.split("strings:")[1].split("condition:")[0]
        condition = block.split("condition:")[1].strip().rstrip("}").strip()
        pats = []
        for line in strings_part.splitlines():
            m = re.match(r"\s*\$\w+\s*=\s*(.+)$", line)
            if not m:
                continue
            body = m.group(1).strip()
            if body.startswith("/"):
                end = body.rindex("/")
                pats.append(re.compile(body[1:end], re.I if "nocase" in body[end:] else 0))
            else:
                lit = body[1:body.rindex('"')]
                pats.append(re.compile(re.escape(lit)))
        rules.append(("all" if condition.startswith("all of") else "any", pats))
    return rules


class VigilYaraRules(TextGuard):
    name = "vigil-yara"

    def __init__(self, rule_dir: str = RULE_DIR):
        self.rules: List = []
        for f in RULE_FILES:
            with open(os.path.join(rule_dir, f), encoding="utf-8") as fh:
                self.rules.extend(_parse(fh.read()))

    def flags(self, text: str) -> bool:
        for mode, pats in self.rules:
            hits = [bool(p.search(text)) for p in pats]
            if (mode == "all" and all(hits)) or (mode == "any" and any(hits)):
                return True
        return False
