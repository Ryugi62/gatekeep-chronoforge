/* GateKeep rules 1:1 JS port of gatekeep/domain (rules.py, checkpoint.py) and
   gatekeep/adapters/tool_registry.py. No network, no server. Parity with the Python
   domain is enforced by tests/demo/test_demo_parity.py on all 146 benchmark cases and the red-team set. */
(function (root) {
  "use strict";
  var DEST_TOKENS = new Set(["to","cc","bcc","recipient","recipients","receiver","payee","email","emails","mail","url","uri","link","address","account","acct","iban","beneficiary","beneficiaries","destination","dest","target","phone","user","guest","guests","username","channel","participants","participant","handle","vpa","upi"]);
  var DEST_SUBSTR = ["iban","account","beneficiar","recipient","receiver","payee","email","url","vpa","destination"];
  var AMOUNT_TOKENS = new Set(["amount","amt","value","total","sum","price","cost","fee"]);
  var PATH_TOKENS = new Set(["path","paths","file","files","filepath","filename","dir","directory","folder","target","location","src","source"]);
  var PATH_NOT = new Set(["id","ids"]);
  var CMD_TOKENS = new Set(["command","cmd","script","shell","bash","exec","commandline"]);
  var SECRET_PATTERNS = [
    /AKIA[0-9A-Z]{16}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /\bsk-[A-Za-z0-9]{20,}/,
    /\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S{6,}/i,
    /ghp_[A-Za-z0-9]{30,}/
  ];
  var SECRET_NAMES = ["AKIA[0-9A-Z]{16}","-----BEGIN [A-Z ]*PRIVATE KEY-----","\\bsk-[A-Za-z0-9]{20,}","(?i)\\b(password|passwd|pwd|secret|api[_-]?key|token)\\s*[=:]\\s*\\S{6,}","ghp_[A-Za-z0-9]{30,}"];
  var AADHAAR = /(?:^|[^\d])(\d{4}[ -]?\d{4}[ -]?\d{4})(?!\d)/g;
  var PAN = /(?:^|[^A-Za-z0-9])([A-Z]{5}\d{4}[A-Z])(?![A-Za-z0-9])/g;
  var DANGEROUS_SHELL = [
    /\brm\s+(?:-{1,2}[A-Za-z][A-Za-z-]*\s+)+(?:\/|~|\$\{?HOME\}?|\*|\.\/\*|\.\.?(?:\s|$))/,
    /(curl|wget)[^|;]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/,
    /\bdd\s+if=/,
    /\bmkfs(\.\w+)?\b/,
    /chmod\s+-R\s+7{3}\s+\//,
    /:\(\)\s*\{/,
    /\bfind\b[^|;]*\s-delete\b/,
    /\bshred\b/,
    />\s*\/dev\/sd/
  ];
  var EMAIL_SHAPE = /^[\w.+-]+@[\w-]+\.[\w.]+$/, URL_SHAPE = /^https?:\/\/\S+$/, IBAN_SHAPE = /^[A-Za-z]{2}\d{2}[A-Za-z0-9]{10,30}$/;

  var MONEY = new Set(["transfer","pay","withdraw","deposit","place","purchase","checkout","refund","buy","sell","wire","remit","disburse","settle","donate","tip","charge","debit","credit"]);
  var OUTBOUND = new Set(["send","share","post","upload","publish","forward","reply","email","mail","notify","message","dm","text","transmit","broadcast","export","submit","tweet","sms","whatsapp"]);
  var DESTRUCTIVE = new Set(["delete","remove","execute","exec","shell","move","leave","disable","wipe","format","drop","terminate","kill","erase","rm","rmdir","unlink","purge","truncate","overwrite","destroy","trash","run","command","sudo"]);
  var STATE = new Set(["grant","unlock","update","manage","create","schedule","go","give","autofill","generate","set","change","revoke","cancel","enable","download","dispatch","fill","reserve","book","add","invite","append","reschedule","issue","approve","assign","register","enroll","authorize","install","reset","rename"]);
  var MONEY_NOUNS = new Set(["money","funds","payment","payments","transaction","transactions","bill","bills","invoice","invoices","amount"]);
  var READ_VERBS = new Set(["get","search","read","navigate","list","view","fetch","find","show","check","lookup","access","visit","browse","describe","query","retrieve","load","inspect","summarize","display","count","calculate","compute"]);
  var SENSITIVE = new Set(["location","history","password","passwords","patient","genetic","payment","address","addresses","account","holdings","prescription","prescriptions","health","record","records","personalinfo","phone","payees","payee","linked","saved","orders","access","log","data","clinical","ssn","credentials","info","transactions","balance","iban","scheduled"]);
  var CONJ = new Set(["and","then"]);

  function words(name) {
    var spaced = name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/_/g, " ");
    return spaced.split(/\s+/).filter(Boolean).map(function (w) { return w.toLowerCase(); });
  }
  // Returns a risk string, or null when the name cannot be placed (R0 then denies the call).
  function inferRisk(name) {
    var ws = words(name);
    var compound = ws.some(function (w) { return CONJ.has(w); });
    var groups = [[MONEY, "MONEY"], [OUTBOUND, "OUTBOUND"], [DESTRUCTIVE, "DESTRUCTIVE"], [STATE, "STATE_CHANGE"]];
    var found = [];
    for (var i = 0; i < ws.length; i++) {
      var w = ws[i], matched = false;
      for (var g = 0; g < groups.length; g++) {
        if (groups[g][0].has(w)) {
          var risk = groups[g][1];
          if ((risk === "OUTBOUND" || risk === "STATE_CHANGE") && ws.some(function (x) { return MONEY_NOUNS.has(x); })) risk = "MONEY";
          if (!compound) return risk;
          found.push(risk); matched = true; break;
        }
      }
      if (!matched && READ_VERBS.has(w) && !compound) break;
    }
    if (found.length) {
      var order = ["MONEY", "DESTRUCTIVE", "OUTBOUND", "STATE_CHANGE"];
      for (var o = 0; o < order.length; o++) if (found.indexOf(order[o]) >= 0) return order[o];
    }
    if (!ws.some(function (w) { return READ_VERBS.has(w); })) return null;
    if (ws.some(function (w) { return SENSITIVE.has(w); })) return "SENSITIVE_READ";
    return "READ";
  }

  function keyTokens(key) {
    return key.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[^A-Za-z0-9]+/).filter(Boolean).map(function (t) { return t.toLowerCase(); });
  }
  function keyHas(key, tokens, substrs) {
    if (keyTokens(key).some(function (t) { return tokens.has(t); })) return true;
    var low = key.toLowerCase();
    return (substrs || []).some(function (s) { return low.indexOf(s) >= 0; });
  }
  function norm(t) { return t.toLowerCase().replace(/[\s\-_]+/g, ""); }
  function esc(ch) { return ch.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&"); }
  function loosePattern(nv) { return Array.from(nv).map(esc).join("[\\s\\-_]*"); }
  function inTextLoose(value, text) {
    var nv = norm(value);
    return nv.length > 0 && new RegExp(loosePattern(nv)).test(text.toLowerCase());
  }
  function inTextToken(value, text) {
    var nv = norm(value);
    if (!nv) return false;
    return new RegExp("(?:^|[^a-z0-9\\-_])" + loosePattern(nv) + "(?:$|[^a-z0-9\\-_])").test(text.toLowerCase());
  }

  function walkStrings(v, out) {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach(function (x) { walkStrings(x, out); });
    else if (v && typeof v === "object") Object.keys(v).forEach(function (k) { walkStrings(v[k], out); });
    return out;
  }
  function argsByKey(call, tokens, substrs, exclude) {
    var out = [];
    Object.keys(call.args || {}).forEach(function (k) {
      if (exclude && keyTokens(k).some(function (t) { return exclude.has(t); })) return;
      if (keyHas(k, tokens, substrs)) {
        var v = call.args[k];
        walkStrings(v, out);
        if (typeof v === "number") out.push(String(v));
      }
    });
    return out;
  }
  function destinations(call) {
    var out = argsByKey(call, DEST_TOKENS, DEST_SUBSTR);
    Object.keys(call.args || {}).forEach(function (k) {
      if (keyHas(k, DEST_TOKENS, DEST_SUBSTR)) return;
      walkStrings(call.args[k], []).forEach(function (s) {
        var t = s.trim();
        if (EMAIL_SHAPE.test(t) || URL_SHAPE.test(t) || IBAN_SHAPE.test(norm(t).toUpperCase())) out.push(s);
      });
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

  function onlyCited(t, holders) {
    return holders.length > 0 && holders.every(function (h) { return t.citedSources.indexOf(h) >= 0; });
  }
  function said(a, text) {
    var t = text.replace(/,/g, "");
    var forms = [fmtG(a), Number.isInteger(a) ? String(a) : fmtG(a)];
    return forms.some(function (f) { return new RegExp("(?:^|[^\\d.])" + esc(f) + "(?!\\d)").test(t); });
  }
  function matches(re, s) { var out = [], m; re.lastIndex = 0; while ((m = re.exec(s)) !== null) out.push(m[1]); return out; }

  var rules = [
    { id: "R0", name: "UnknownTool", check: function (c, t, pol) {
      if (!pol.riskOf(c.tool)) return ev("R0", "Not registered and not inferable from its name: denied by default", c.tool);
      return null; } },
    { id: "R1", name: "OutOfScope", check: function (c, t, pol) {
      var r = pol.riskOf(c.tool);
      if (!r || r === "READ") return null;
      if (t.allowedTools.indexOf(c.tool) < 0) return ev("R1", "Tool outside the user's request: " + c.tool + " (" + r + ")", c.tool);
      return null; } },
    { id: "R2", name: "TaintedDestination", check: function (c, t, pol) {
      var r = pol.riskOf(c.tool);
      if (["OUTBOUND", "MONEY", "STATE_CHANGE"].indexOf(r) < 0) return null;
      var soft = null, vals = destinations(c);
      for (var i = 0; i < vals.length; i++) {
        if (cpLen(norm(vals[i])) < 4) continue;
        var holders = t.untrustedTexts.filter(function (u) { return inTextLoose(vals[i], u); });
        if (!holders.length || inTextToken(vals[i], t.userRequest)) continue;
        if (onlyCited(t, holders)) { soft = soft || ev("R2", "Destination appears only in a document the user pointed to: user confirmation needed", vals[i], true); continue; }
        return ev("R2", "Destination appears only in untrusted text", vals[i]);
      }
      return soft; } },
    { id: "R3", name: "AmountLimit", check: function (c, t, pol) {
      if (pol.riskOf(c.tool) !== "MONEY") return null;
      var soft = null, vals = argsByKey(c, AMOUNT_TOKENS);
      for (var i = 0; i < vals.length; i++) {
        var a = parseAmount(vals[i]);
        if (a === null || a <= pol.maxAmount || said(a, t.userRequest)) continue;
        var holders = t.untrustedTexts.filter(function (u) { return said(a, u); });
        if (onlyCited(t, holders)) { soft = soft || ev("R3", "Amount above the limit " + fmtG(pol.maxAmount) + " appears only in a document the user pointed to: user confirmation needed", vals[i], true); continue; }
        return ev("R3", "Amount above the limit " + fmtG(pol.maxAmount) + " and not stated in the user request", vals[i]);
      }
      return soft; } },
    { id: "R4", name: "PathEscape", check: function (c, t, pol) {
      if (pol.riskOf(c.tool) !== "DESTRUCTIVE") return null;
      var root = pol.sandboxRoot.replace(/\/+$/, "");
      var ps = argsByKey(c, PATH_TOKENS, null, PATH_NOT);
      for (var i = 0; i < ps.length; i++) {
        var p = ps[i];
        if (p.charAt(0) === "~" || p.split("/").indexOf("..") >= 0) return ev("R4", "Path outside the working folder", p);
        if (normpath(p).indexOf(root + "/") !== 0) return ev("R4", "Path outside the working folder " + root, p);
      }
      var cs = argsByKey(c, CMD_TOKENS);
      for (var j = 0; j < cs.length; j++)
        for (var k = 0; k < DANGEROUS_SHELL.length; k++)
          if (DANGEROUS_SHELL[k].test(cs[j])) return ev("R4", "Dangerous shell command", cs[j]);
      return null; } },
    { id: "R5", name: "SecretEgress", check: function (c, t, pol) {
      if (pol.riskOf(c.tool) !== "OUTBOUND") return null;
      var reqDigits = t.userRequest.replace(/[ -]/g, "");
      var ss = walkStrings(c.args || {}, []);
      for (var i = 0; i < ss.length; i++) {
        for (var k = 0; k < SECRET_PATTERNS.length; k++)
          if (SECRET_PATTERNS[k].test(ss[i])) return ev("R5", "Secret value in an outbound argument", SECRET_NAMES[k].slice(0, 30));
        var ad = matches(AADHAAR, ss[i]);
        for (var a = 0; a < ad.length; a++)
          if (reqDigits.indexOf(ad[a].replace(/[ -]/g, "")) < 0) return ev("R5", "Citizen ID number in an outbound argument (Aadhaar format)", "aadhaar-12-digit");
        var pn = matches(PAN, ss[i]);
        for (var q = 0; q < pn.length; q++)
          if (t.userRequest.indexOf(pn[q]) < 0) return ev("R5", "Citizen ID number in an outbound argument (PAN format)", "pan-format");
      }
      return null; } }
  ];
  function ev(id, reason, detail, confirm) { return { ruleId: id, reason: reason, detail: detail, confirm: !!confirm }; }

  function makePolicy(maxAmount, sandboxRoot, registered) {
    registered = registered || {};
    return { maxAmount: maxAmount, sandboxRoot: sandboxRoot, riskOf: function (tool) {
      if (typeof tool !== "string" || !tool) return null;
      return Object.prototype.hasOwnProperty.call(registered, tool) ? registered[tool] : inferRisk(tool); } };
  }
  function inspect(call, task, policy) {
    var evs = [];
    rules.forEach(function (r) { var e = r.check(call, task, policy); if (e) evs.push(e); });
    var hard = evs.some(function (e) { return !e.confirm; });
    return { action: !evs.length ? "ALLOW" : (hard ? "BLOCK" : "CONFIRM"), tool: call.tool, risk: policy.riskOf(call.tool), evidences: evs };
  }
  // Task: {userRequest, allowedTools:[...], untrustedTexts:[...]}; calls: [{tool,args}]
  function guard(task, calls, opts) {
    opts = opts || {};
    var pol = makePolicy(opts.maxAmount === undefined ? 1000 : opts.maxAmount, opts.sandboxRoot || "/workspace", opts.registered);
    task = { userRequest: task.userRequest, allowedTools: task.allowedTools, untrustedTexts: task.untrustedTexts || [], citedSources: task.citedSources || [] };
    return calls.map(function (c) { return inspect({ tool: c.tool, args: c.args || {} }, task, pol); });
  }

  var api = { guard: guard, inferRisk: inferRisk, rules: rules.map(function (r) { return { id: r.id, name: r.name }; }) };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.GateKeep = api;
})(typeof self !== "undefined" ? self : this);
