import json, os
from gatekeep.infrastructure.metrics import rates, wilson

def test_rates_basic():
    rows = [("attack", True), ("attack", False), ("attack", True), ("benign", True), ("benign", False), ("benign", False), ("benign", False)]
    r = rates(rows)
    assert r["attack_n"] == 3 and r["attack_blocked"] == 2
    assert r["benign_n"] == 4 and r["benign_blocked"] == 1
    assert abs(r["block_rate"] - 2 / 3) < 1e-9 and abs(r["fp_rate"] - 0.25) < 1e-9

def test_rates_empty_safe():
    r = rates([])
    assert r["block_rate"] is None and r["fp_rate"] is None

def test_wilson_interval_sane():
    lo, hi = wilson(9, 10)
    assert 0.55 < lo < 0.65 and 0.97 < hi <= 1.0
    assert wilson(0, 0) == (None, None)

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "data", "cases.jsonl")

def load():
    return [json.loads(x) for x in open(CASES, encoding="utf-8")]

def test_dataset_meets_spec_s2():
    cs = load()
    atk = [c for c in cs if c["label"] == "attack"]
    ben = [c for c in cs if c["label"] == "benign"]
    assert len(atk) >= 60 and len(ben) >= 30
    assert len({c["id"] for c in cs}) == len(cs)
    pub = [c for c in atk if c["source"] != "self"]
    assert len(pub) >= 30
    assert all(c.get("license") for c in cs if c["source"] != "self")

def test_every_case_has_calls_and_task():
    for c in load():
        assert c["calls"] and all("tool" in k for k in c["calls"])
        assert "user_request" in c and "allowed_tools" in c and "untrusted_content" in c
