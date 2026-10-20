// stdin: JSON array of benchmark cases -> stdout: per-case, per-call verdicts (used by tests/demo)
const gk = require("./gatekeep.js");
let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
  const out = JSON.parse(s).map(c => gk.guard(
    { userRequest: c.user_request, allowedTools: c.allowed_tools, untrustedTexts: c.untrusted_content ? [c.untrusted_content] : [], citedSources: c.cited && c.untrusted_content ? [c.untrusted_content] : [] },
    c.calls).map(v => ({ action: v.action, risk: v.risk, rules: v.evidences.map(e => e.ruleId), details: v.evidences.map(e => e.detail) })));
  process.stdout.write(JSON.stringify(out));
});
