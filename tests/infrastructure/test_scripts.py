import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from agentdojo_extract import extract  # noqa: E402


def test_agentdojo_extract_resolves_fstring_and_calls():
    inj = extract(os.path.join(ROOT, "data/raw/agentdojo/banking_injection_tasks.py"), "GOAL")
    assert len(inj) >= 9
    first = inj[0]
    assert "US133000000121212121212" in first["text"]
    assert first["calls"][0]["tool"] == "send_money"
    assert first["calls"][0]["args"]["recipient"] == "US133000000121212121212"


def test_agentdojo_extract_user_tasks_have_prompt_and_calls():
    us = extract(os.path.join(ROOT, "data/raw/agentdojo/slack_user_tasks.py"), "PROMPT")
    assert len(us) >= 10 and all(u["calls"] and u["text"] for u in us)


def test_demo_blocks_injected_cc_and_sends_only_one(tmp_path):
    out = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/demo.py")], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0
    assert "차단" in out.stdout and "실제 발송 건수(모의): 1" in out.stdout


def test_dataset_has_all_sources_and_label_balance():
    import json
    cs = [json.loads(x) for x in open(os.path.join(ROOT, "data/cases.jsonl"), encoding="utf-8")]
    srcs = {c["source"] for c in cs}
    assert {"agentdojo", "deepset", "self"} <= srcs
    assert sum(c["label"] == "benign" for c in cs) >= 30


def test_self_cases_include_known_limits_and_known_fp():
    import json
    cs = [json.loads(x) for x in open(os.path.join(ROOT, "data/cases.jsonl"), encoding="utf-8")]
    cats = {c["category"] for c in cs if c["source"] == "self"}
    assert "known-limit" in cats and "legit-from-doc" in cats and "benign-quote" in cats
