from gatekeep.domain.model import Policy, Risk, ToolCall


def test_policy_risk_of_known_and_unknown():
    p = Policy(risks={"a": Risk.READ}, max_amount=1.0, sandbox_root="/w")
    assert p.risk_of("a") is Risk.READ and p.risk_of("b") is None


def test_toolcall_flatten_strings():
    c = ToolCall("t", {"a": "x", "b": ["y", 3, {"c": "z"}], "n": 5})
    assert sorted(c.string_values()) == ["x", "y", "z"]
