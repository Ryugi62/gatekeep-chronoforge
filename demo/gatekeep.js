/* GateKeep rules 1:1 JS port of gatekeep/domain (rules.py, checkpoint.py) and
   gatekeep/adapters/tool_registry.py. No network, no server. Parity with the Python
   domain is enforced by tests/demo/test_demo_parity.py on all 146 benchmark cases. */
(function (root) {
  "use strict";
  var DEST_KEYS = new Set(["to","cc","bcc","recipient","recipients","receiver","email","address","account","account_number","payee","target","url","destination","user","guest","guest_ids","username","phone_number","channel","participants","user_email","emails"]);
  var AMOUNT_KEYS = new Set(["amount","value","total","sum"]);
  var PATH_KEYS = new Set(["path","paths","file","file_path","filepath","target_path","directory","dir","item_path"]);
  var CMD_KEYS = new Set(["command","cmd","script","shell"]);
  var SECRET_PATTERNS = [
    /AKIA[0-9A-Z]{16}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /\bsk-[A-Za-z0-9]{20,}/,
    /\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S{6,}/i,
    /ghp_[A-Za-z0-9]{30,}/
  ];
  var SECRET_NAMES = ["AKIA[0-9A-Z]{16}","-----BEGIN [A-Z ]*PRIVATE KEY-----","\\bsk-[A-Za-z0-9]{20,}","(?i)\\b(password|passwd|pwd|secret|api[_-]?key|token)\\s*[=:]\\s*\\S{6,}","ghp_[A-Za-z0-9]{30,}"];
  var DANGEROUS_SHELL = [
    /\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(\/|~|\$HOME|\*)/,
    /(curl|wget)[^|;]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/,
    /\bdd\s+if=/,
    /\bmkfs(\.\w+)?\b/,
    /chmod\s+-R\s+7{3}\s+\//,
    /:\(\)\s*\{/
  ];

  var MONEY = new Set(["transfer","pay","withdraw","deposit","place","purchase","checkout","refund","buy","sell"]);
  var OUTBOUND = new Set(["send","share","post","upload","publish","forward","reply"]);
  var DESTRUCTIVE = new Set(["delete","remove","execute","exec","shell","move","leave","disable","wipe","format","drop","terminate","kill"]);
  var STATE = new Set(["grant","unlock","update","manage","create","schedule","go","give","autofill","generate","set","change","revoke","cancel","enable","download","dispatch","fill","reserve","book","add","invite","append","reschedule"]);
  var MONEY_NOUNS = new Set(["money","funds","payment","payments","transaction","transactions","bill","bills"]);
  var READ_VERBS = new Set(["get","search","read","navigate","list","view","fetch","find","show","check","lookup","access"]);
  var SENSITIVE = new Set(["location","history","password","passwords","patient","genetic","payment","address","addresses","account","holdings","prescription","prescriptions","health","record","records","personalinfo","phone","payees","payee","linked","saved","orders","access","log","data","clinical","ssn","credentials","info","transactions","balance","iban","scheduled"]);

  function words(name) {
    var spaced = name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/_/g, " ");
    return spaced.split(/\s+/).filter(Boolean).map(function (w) { return w.toLowerCase(); });
  }
  function inferRisk(name) {
    var ws = words(name);
    var groups = [[MONEY, "MONEY"], [OUTBOUND, "OUTBOUND"], [DESTRUCTIVE, "DESTRUCTIVE"], [STATE, "STATE_CHANGE"]];
    for (var i = 0; i < ws.length; i++) {
      var w = ws[i];
      for (var g = 0; g < groups.length; g++) {
        if (groups[g][0].has(w)) {
          var risk = groups[g][1];
          if ((risk === "OUTBOUND" || risk === "STATE_CHANGE") && ws.some(function (x) { return MONEY_NOUNS.has(x); })) return "MONEY";
          return risk;
        }
      }
      if (READ_VERBS.has(w)) break;
    }
    if (ws.some(function (w) { return SENSITIVE.has(w); })) return "SENSITIVE_READ";
    return "READ";
  }

  function walkStrings(v, out) {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach(function (x) { walkStrings(x, out); });
    else if (v && typeof v === "object") Object.keys(v).forEach(function (k) { walkStrings(v[k], out); });
    return out;
  }
  function argsByKey(call, keys) {
    var out = [];
    Object.keys(call.args || {}).forEach(function (k) {
      if (keys.has(k.toLowerCase())) {
        var v = call.args[k];
        walkStrings(v, out);
        if (typeof v === "number") out.push(String(v));
      }
    });
    return out;
  }
  function cpLen(s) { return Array.from(s).length; }

  function fmtG(x) { // Python "%g"
    if (x === 0) return "0";
    var exp = Math.floor(Math.log10(Math.abs(x)));
    var p = x.toPrecision(6);
    exp = parseInt(Number(x).toExponential(5).split("e")[1], 10);
    if (exp < -4 || exp >= 6) {
      var m = x.toExponential(5).split("e");
      var mant = m[0].indexOf(".") >= 0 ? m[0].replace(/0+$/, "").replace(/\.$/, "") : m[0];
      var e = parseInt(m[1], 10);
      return mant + "e" + (e < 0 ? "-" : "+") + (Math.abs(e) < 10 ? "0" : "") + Math.abs(e);
    }
    p = x.toFixed(Math.max(0, 5 - exp));
    return p.indexOf(".") >= 0 ? p.replace(/0+$/, "").replace(/\.$/, "") : p;
  }
  function parseAmount(text) {
    var m = /-?\d[\d,]*(\.\d+)?/.exec(text.replace(/\$/g, ""));
    if (!m) return null;
    var n = parseFloat(m[0].replace(/,/g, ""));
    return isNaN(n) ? null : n;
  }
  function normpath(p) { // posixpath.normpath
    if (p === "") return ".";
    var initial = p.charAt(0) === "/" ? 1 : 0;
    if (initial && p.slice(0, 2) === "//" && p.charAt(2) !== "/") initial = 2;
    var comps = p.split("/"), out = [];
    comps.forEach(function (c) {
      if (c === "" || c === ".") return;
      if (c !== ".." || (!initial && !out.length) || (out.length && out[out.length - 1] === "..")) out.push(c);
      else if (out.length) out.pop();
    });
    var r = out.join("/");
    if (initial) r = "/".repeat(initial) + r;
    return r || ".";
  }

  var rules = [
    { id: "R0", name: "UnknownTool", check: function (c, t, pol) {
      if (!pol.riskOf(c.tool)) return ev("R0", "Unregistered tool: denied by default", c.tool);
      return null; } },
    { id: "R1", name: "OutOfScope", check: function (c, t, pol) {
      var r = pol.riskOf(c.tool);
      if (!r || r === "READ") return null;
      if (t.allowedTools.indexOf(c.tool) < 0) return ev("R1", "Tool outside the user's request: " + c.tool + " (" + r + ")", c.tool);
      return null; } },
    { id: "R2", name: "TaintedDestination", check: function (c, t, pol) {
      var r = pol.riskOf(c.tool);
      if (["OUTBOUND", "MONEY", "STATE_CHANGE"].indexOf(r) < 0) return null;
      var req = t.userRequest.toLowerCase(), unt = t.untrustedTexts.join("\n").toLowerCase();
      var vals = argsByKey(c, DEST_KEYS);
      for (var i = 0; i < vals.length; i++) {
        var v = vals[i].trim().toLowerCase();
        if (cpLen(v) < 4) continue;
        if (unt.indexOf(v) >= 0 && req.indexOf(v) < 0) return ev("R2", "Destination appears only in untrusted text", vals[i]);
      }
      return null; } },
    { id: "R3", name: "AmountLimit", check: function (c, t, pol) {
      if (pol.riskOf(c.tool) !== "MONEY") return null;
      var req = t.userRequest.replace(/,/g, "");
      var vals = argsByKey(c, AMOUNT_KEYS);
      for (var i = 0; i < vals.length; i++) {
        var a = parseAmount(vals[i]);
        if (a === null || a <= pol.maxAmount) continue;
        var said = [fmtG(a), Number.isInteger(a) ? String(a) : fmtG(a)];
        if (said.some(function (s) { return req.indexOf(s) >= 0; })) continue;
        return ev("R3", "Amount above the limit " + fmtG(pol.maxAmount) + " and not stated in the user request", vals[i]);
      }
      return null; } },
    { id: "R4", name: "PathEscape", check: function (c, t, pol) {
      if (pol.riskOf(c.tool) !== "DESTRUCTIVE") return null;
      var root = pol.sandboxRoot.replace(/\/+$/, "");
      var ps = argsByKey(c, PATH_KEYS);
      for (var i = 0; i < ps.length; i++) {
        var p = ps[i];
        if (p.charAt(0) === "~" || p.split("/").indexOf("..") >= 0) return ev("R4", "Path outside the working folder", p);
        if (normpath(p).indexOf(root + "/") !== 0) return ev("R4", "Path outside the working folder " + root, p);
      }
      var cs = argsByKey(c, CMD_KEYS);
      for (var j = 0; j < cs.length; j++)
        for (var k = 0; k < DANGEROUS_SHELL.length; k++)
          if (DANGEROUS_SHELL[k].test(cs[j])) return ev("R4", "Dangerous shell command", cs[j]);
      return null; } },
    { id: "R5", name: "SecretEgress", check: function (c, t, pol) {
      if (pol.riskOf(c.tool) !== "OUTBOUND") return null;
      var ss = walkStrings(c.args || {}, []);
      for (var i = 0; i < ss.length; i++)
        for (var k = 0; k < SECRET_PATTERNS.length; k++)
          if (SECRET_PATTERNS[k].test(ss[i])) return ev("R5", "Secret value in an outbound argument", SECRET_NAMES[k].slice(0, 30));
      return null; } }
  ];
  function ev(id, reason, detail) { return { ruleId: id, reason: reason, detail: detail }; }

  function makePolicy(maxAmount, sandboxRoot) {
    return { maxAmount: maxAmount, sandboxRoot: sandboxRoot, riskOf: function (tool) { return typeof tool === "string" && tool ? inferRisk(tool) : null; } };
  }
  function inspect(call, task, policy) {
    var evs = [];
    rules.forEach(function (r) { var e = r.check(call, task, policy); if (e) evs.push(e); });
    return { action: evs.length ? "BLOCK" : "ALLOW", tool: call.tool, risk: policy.riskOf(call.tool), evidences: evs };
  }
  // Task: {userRequest, allowedTools:[...], untrustedTexts:[...]}; calls: [{tool,args}]
  function guard(task, calls, opts) {
    opts = opts || {};
    var pol = makePolicy(opts.maxAmount === undefined ? 1000 : opts.maxAmount, opts.sandboxRoot || "/workspace");
    return calls.map(function (c) { return inspect({ tool: c.tool, args: c.args || {} }, task, pol); });
  }

  var api = { guard: guard, inferRisk: inferRisk, rules: rules.map(function (r) { return { id: r.id, name: r.name }; }) };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.GateKeep = api;
})(typeof self !== "undefined" ? self : this);
