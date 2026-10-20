"""SPEC S10: 코드 고정 뒤에 쓴 미접촉 세트 — 모양·출처·문장 겹침 0·고정 커밋 표기. 차단율 통과선은 두지 않고 있는 그대로 낸다."""
import json
import os
import re

from gatekeep.infrastructure.bench import holdout_section, scope_mode_results

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
D = lambda n: os.path.join(ROOT, "data", n)
HOLD, PACK = D("city_holdout.jsonl"), D("city_pack.json")


def rows(p):
    return [json.loads(x) for x in open(p, encoding="utf-8")]


def sentences(r):
    text = r["user_request"] + " " + (r["untrusted_content"] or "")
    return {s.strip().lower() for s in re.split(r"(?<=[.!?])\s+", text) if len(s.strip()) > 12}


def test_holdout_shape():
    r = rows(HOLD)
    atk = [x for x in r if x["label"] == "attack"]
    assert len(atk) >= 15 and len([x for x in r if x["label"] == "benign"]) >= 10
    assert len({x["id"] for x in r}) == len(r) and all(x["source"] == "city-holdout" for x in r)
    assert all(x["untrusted_content"] and x.get("content_tool") for x in atk)  # 간접 주입 + 글을 돌려주는 도구


def test_holdout_has_no_sentence_overlap_with_development_sets():
    dev = rows(D("cases.jsonl")) + rows(D("city_attacks.jsonl")) + rows(D("redteam_cases.jsonl"))
    seen = set()
    for x in dev:
        seen |= sentences(x) | {x["user_request"].strip().lower()}
    for x in rows(HOLD):
        assert not (sentences(x) & seen), x["id"]
        assert x["user_request"].strip().lower() not in seen, x["id"]


def test_meta_names_the_frozen_commit():
    m = json.load(open(D("city_holdout.meta.json")))
    assert m["code_frozen_at"] == "30336c9" and m["attacks"] >= 15 and m["benign"] >= 10


def test_domain_code_unchanged_since_freeze():
    """고정 이후 도메인·응용·도구 등록·도시 팩이 바뀌지 않았다(바뀌면 이 세트는 개발 세트로 강등)."""
    import subprocess
    out = subprocess.run(["git", "diff", "--stat", "30336c9", "--", "gatekeep/domain", "gatekeep/application",
                          "gatekeep/adapters/tool_registry.py", "data/city_pack.json"], cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        return  # git 없는 환경(압축본)에서는 건너뛴다
    assert out.stdout.strip() == "", out.stdout


def test_both_modes_report_counts_consistently():
    res = scope_mode_results(HOLD, pack_path=PACK)
    for mode in ("oracle", "derived"):
        r = res[mode]
        assert r["attack_n"] >= 15 and r["benign_n"] >= 10
        assert len(r["miss_ids"]) == r["attack_n"] - r["attack_blocked"] and len(r["fp_ids"]) == r["benign_blocked"]


def test_holdout_section_lists_misses_and_states_freeze():
    res = {"holdout": scope_mode_results(HOLD, pack_path=PACK), "holdout_cases": rows(HOLD)}
    text = "\n".join(holdout_section(res))
    assert "30336c9" in text and "미접촉" in text and "오라클 R1" in text and "자동 추출 R1" in text
