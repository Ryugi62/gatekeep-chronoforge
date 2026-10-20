"""데모 예시 3개(정상·주입·유출)가 index.html에 있고 기대 판정을 낸다."""
import json
import os
import re
import shutil
import subprocess

import pytest

DEMO = os.path.join(os.path.dirname(__file__), "..", "..", "demo")
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node 필요")


def test_index_is_static_and_has_inputs():
    html = open(os.path.join(DEMO, "index.html"), encoding="utf-8").read()
    for el in ('id="req"', 'id="tools"', 'id="calls"', 'id="check"'):
        assert el in html
    assert not re.search(r'(src|href)="https?://', html)  # 외부 서버 없음


def test_three_examples_give_expected_verdicts():
    html = open(os.path.join(DEMO, "index.html"), encoding="utf-8").read()
    script = html.split("<script>")[-1].split("</script>")[0]
    js = "var gk=require(%r);var window={};%s;" % (os.path.join(DEMO, "gatekeep.js"), script.split("function $")[0])
    js += ("var r={};for(var k in EX){var e=EX[k];r[k]=gk.guard({userRequest:e.req,allowedTools:e.tools.split(/[,\\n]/).map(s=>s.trim()).filter(Boolean),"
           "untrustedTexts:e.unt?[e.unt]:[],citedSources:(e.cited&&e.unt)?[e.unt]:[]},[].concat(JSON.parse(e.calls))).map(v=>[v.action,v.evidences.map(x=>x.ruleId)]);}console.log(JSON.stringify(r));")
    out = json.loads(subprocess.run(["node", "-e", js], capture_output=True, text=True, check=True).stdout)
    assert out["benign"] == [["ALLOW", []]]
    assert out["inject"][0] == ["ALLOW", []] and out["inject"][1][0] == "BLOCK" and "R1" in out["inject"][1][1]
    assert out["leak"][0][0] == "BLOCK" and "R5" in out["leak"][0][1]
    assert out["bill"][0][0] == "CONFIRM" and "R2" in out["bill"][0][1]
    assert out["bill_web"][0][0] == "BLOCK"


def test_demo_page_has_cited_checkbox_and_confirm_style():
    html = open(os.path.join(DEMO, "index.html"), encoding="utf-8").read()
    assert 'id="cited"' in html and ".v.CONFIRM" in html


def test_derive_checkbox_exists_and_derived_mode_blocks_injected_tool():
    html = open(os.path.join(DEMO, "index.html"), encoding="utf-8").read()
    assert 'id="derive"' in html and "extractAllowed" in html
    js = ("var gk=require(%r);var r=gk.guard({userRequest:'Summarize my last email.',allowedTools:['read_email','send_email'],untrustedTexts:[]},"
          "[{tool:'send_email',args:{to:'a@b.co'}}],{deriveScope:true,catalog:['read_email','send_email']});console.log(JSON.stringify(r.map(v=>[v.action,v.evidences.map(x=>x.ruleId)])));"
          % os.path.join(DEMO, "gatekeep.js"))
    out = json.loads(subprocess.run(["node", "-e", js], capture_output=True, text=True, check=True).stdout)
    assert out == [["BLOCK", ["R1"]]]  # 선언 목록엔 send_email이 있어도 요청 문장만 본다
