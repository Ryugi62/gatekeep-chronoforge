"""레드팀 우회 입력 전부 = 테스트 케이스 (data/redteam_cases.jsonl, expect 필드가 판정 정본)."""
import os

from gatekeep.adapters.cases import calls_of, load_cases, policy_for, task_of
from gatekeep.domain.checkpoint import default_checkpoint

PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "redteam_cases.jsonl")
ORDER = {"ALLOW": 0, "CONFIRM": 1, "BLOCK": 2}


def worst(case, cp, pol):
    t = task_of(case)
    return max((cp.inspect(c, t, pol).action.value for c in calls_of(case)), key=ORDER.get)


def test_every_redteam_case_gets_its_expected_verdict():
    cases = load_cases(PATH)
    assert len(cases) >= 20
    pol, cp = policy_for(cases), default_checkpoint()
    bad = [(c["id"], worst(c, cp, pol), c["expect"]) for c in cases if worst(c, cp, pol) != c["expect"]]
    assert bad == []
