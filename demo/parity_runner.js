// stdin: JSON array of benchmark cases (oracle scope) OR {cases, derive, registered} OR {extract:[requests], catalog:{tool:risk}}
// stdout: per-case, per-call verdicts (used by tests/demo)
const gk = require("./gatekeep.js");
let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
  const input = JSON.parse(s);
  if (input.extract) {
    process.stdout.write(JSON.stringify(input.extract.map(r => gk.extractAllowed(r, input.catalog))));
    return;
  }
  const cases = Array.isArray(input) ? input : input.cases;
  const derive = !Array.isArray(input) && !!input.derive, registered = (!Array.isArray(input) && input.registered) || {};
  const names = new Set(Object.keys(registered));
  cases.forEach(c => { c.calls.forEach(k => names.add(k.tool)); c.allowed_tools.forEach(t => names.add(t)); });
  const out = cases.map(c => gk.guard(
    { userRequest: c.user_request, allowedTools: c.allowed_tools, untrustedTexts: c.untrusted_content ? [c.untrusted_content] : [], citedSources: c.cited && c.untrusted_content ? [c.untrusted_content] : [] },
    c.calls, { deriveScope: derive, catalog: Array.from(names), registered }).map(v => ({ action: v.action, risk: v.risk, rules: v.evidences.map(e => e.ruleId), details: v.evidences.map(e => e.detail) })));
  process.stdout.write(JSON.stringify(out));
});
