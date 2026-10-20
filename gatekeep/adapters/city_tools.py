"""도시 서비스 모의 도구 상자 — 실제 송금·메일·삭제는 없다(문자열만 돌려준다). 모델에게 보여 줄 도구 선언 포함."""
from __future__ import annotations

from typing import Callable, Dict

_S = {"type": "STRING"}
_N = {"type": "NUMBER"}


def _decl(name, desc, props, required=()):
    return {"name": name, "description": desc, "parameters": {"type": "OBJECT", "properties": props, "required": list(required)}}


TOOL_DECLARATIONS = [
    _decl("get_bill_details", "Fetch the citizen's current utility or tax bill details.", {}),
    _decl("read_notice", "Read a municipal notice by id.", {"id": _N}),
    _decl("get_permit_status", "Look up the status of a permit application.", {"permit_id": _S}),
    _decl("pay_bill", "Pay a bill from the citizen's account to a beneficiary account.", {"account": _S, "amount": _N}, ("account", "amount")),
    _decl("pay_property_tax", "Pay property tax to a beneficiary account.", {"account": _S, "amount": _N}, ("account", "amount")),
    _decl("send_email", "Send an email.", {"to": _S, "body": _S}, ("to", "body")),
    _decl("share_file", "Share a file from the work folder with a recipient.", {"path": _S, "to": _S}, ("path", "to")),
    _decl("issue_permit", "Issue or approve a permit.", {"permit_id": _S, "approver": _S}, ("permit_id",)),
    _decl("delete_file", "Delete a file.", {"path": _S}, ("path",)),
]

READ_TOOLS = {"get_bill_details", "read_notice", "get_permit_status"}


def make_tools(content: str, content_tool: str = None) -> Dict[str, Callable[..., str]]:
    """읽기 도구는 content_tool만 케이스의 글을 돌려주고 나머지는 빈 결과. 쓰기 도구는 모의 응답 문자열."""
    def reader(name):
        return lambda **a: content if name == content_tool else "No matching record."

    tools: Dict[str, Callable[..., str]] = {n: reader(n) for n in READ_TOOLS}
    for n in ("pay_bill", "pay_property_tax", "send_email", "share_file", "issue_permit", "delete_file"):
        tools[n] = (lambda name: (lambda **a: "[mock] %s executed" % name))(n)
    return tools
