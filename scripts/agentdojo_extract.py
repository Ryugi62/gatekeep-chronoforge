"""AgentDojo(MIT) 의 injection_tasks.py / user_tasks.py 를 ast 로 읽어 (목표 문장·정답 도구 호출)을 뽑는다. 코드를 실행·import 하지 않는다."""
import ast

UNK = "<?>"


class Ev:
    def __init__(self, module_env, class_env):
        self.m, self.c = module_env, class_env

    def val(self, n):
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Name):
            return self.c.get(n.id, self.m.get(n.id, UNK))
        if isinstance(n, ast.Attribute):
            if isinstance(n.value, ast.Name) and n.value.id in ("self", "cls"):
                return self.c.get(n.attr, UNK)
            return UNK
        if isinstance(n, ast.JoinedStr):
            return "".join(str(self.val(p.value)) if isinstance(p, ast.FormattedValue) else str(p.value) for p in n.values)
        if isinstance(n, ast.Dict):
            return {self.val(k): self.val(v) for k, v in zip(n.keys, n.values) if k is not None}
        if isinstance(n, (ast.List, ast.Tuple)):
            return [self.val(e) for e in n.elts]
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            a, b = self.val(n.left), self.val(n.right)
            if isinstance(a, str) and isinstance(b, str):
                return a + b
            if isinstance(a, list) and isinstance(b, list):
                return a + b
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub):
            v = self.val(n.operand)
            return -v if isinstance(v, (int, float)) else UNK
        return UNK


def _has_unk(v):
    if v == UNK:
        return True
    if isinstance(v, dict):
        return any(_has_unk(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_unk(x) for x in v)
    return isinstance(v, str) and UNK in v


def _calls(fn, ev):
    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "FunctionCall":
            kw = {k.arg: k.value for k in node.keywords}
            name = ev.val(kw["function"]) if "function" in kw else UNK
            args = ev.val(kw["args"]) if "args" in kw else {}
            if _has_unk(args) and "placeholder_args" in kw:
                args = ev.val(kw["placeholder_args"])
            out.append({"tool": name, "args": args if isinstance(args, dict) else {}})
    return out


def extract(path, text_field):
    """반환: [{id, text, calls}] — text_field = GOAL(공격) 또는 PROMPT(사용자 과제)"""
    tree = ast.parse(open(path, encoding="utf-8").read())
    module_env = {}
    out = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            module_env[node.targets[0].id] = Ev(module_env, {}).val(node.value)
        if isinstance(node, ast.ClassDef):
            cenv = {}
            ev = Ev(module_env, cenv)
            fn = None
            for st in node.body:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    cenv[st.targets[0].id] = ev.val(st.value)
                elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
                    cenv[st.target.id] = ev.val(st.value)
                elif isinstance(st, ast.FunctionDef) and st.name == "ground_truth":
                    fn = st
            text = cenv.get(text_field)
            if isinstance(text, str) and fn is not None:
                calls = _calls(fn, ev)
                if calls:
                    out.append({"id": node.name, "text": text.strip(), "calls": calls})
    return out
