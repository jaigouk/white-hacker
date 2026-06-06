"""Generate the labeled eval corpus (T-7.1) — deterministic, reviewable, reproducible.

Each case is a paired (vulnerable_variant, benign_lookalike) plus a target.md and a label.json.
The vulnerable variant carries a `SINK` marker comment on the dangerous line; the generator finds
that line so the label's `vulnerable.line` is always accurate. Re-run to regenerate:

    uv run python evals/corpus/generate.py

OWASP-Benchmark-style: small representative snippets (detection fixtures, not run). Phase 9 grows
this toward >=100 and mixes in real CVE pre/post-fix anchors.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES_DIR = HERE / "cases"

# (id, language, ext, category, severity, owasp, desc, vulnerable, benign)
# The vulnerable snippet marks its dangerous line with a `SINK` comment.
C = [
    # ---- Python: injection / deserialization / crypto / authz ----
    ("py-sqli", "python", "py", "injection", "HIGH", ["A03:2025"],
     "SQL built from a request param.",
     'def get_user(db, uid):\n    q = "SELECT * FROM users WHERE id = \'%s\'" % uid  # SINK sqli\n    return db.execute(q).fetchone()\n',
     'def get_user(db, uid):\n    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()\n'),
    ("py-cmdi", "python", "py", "injection", "HIGH", ["A03:2025"],
     "Shell command built from user input.",
     'import subprocess\ndef ping(host):\n    return subprocess.run(f"ping -c1 {host}", shell=True)  # SINK cmdi\n',
     'import subprocess\ndef ping(host):\n    return subprocess.run(["ping", "-c1", host])\n'),
    ("py-pathtraversal", "python", "py", "injection", "HIGH", ["A01:2025"],
     "User path opened without containment.",
     'def read(name):\n    return open("/data/" + name).read()  # SINK path-traversal\n',
     'import os\ndef read(name):\n    p = os.path.realpath("/data/" + name)\n    assert p.startswith("/data/")\n    return open(p).read()\n'),
    ("py-ssti", "python", "py", "injection", "HIGH", ["A03:2025"],
     "User data rendered as a template.",
     'from jinja2 import Template\ndef render(name):\n    return Template("Hi " + name).render()  # SINK ssti\n',
     'from jinja2 import Template\ndef render(name):\n    return Template("Hi {{ n }}").render(n=name)\n'),
    ("py-pickle", "python", "py", "deserialization", "HIGH", ["A08:2025"],
     "Untrusted bytes deserialized with pickle.",
     'import pickle\ndef load(blob):\n    return pickle.loads(blob)  # SINK insecure-deserialization\n',
     'import json\ndef load(blob):\n    return json.loads(blob)\n'),
    ("py-yaml", "python", "py", "deserialization", "HIGH", ["A08:2025"],
     "yaml.load on untrusted input.",
     'import yaml\ndef load(s):\n    return yaml.load(s)  # SINK insecure-deserialization\n',
     'import yaml\ndef load(s):\n    return yaml.safe_load(s)\n'),
    ("py-weakhash", "python", "py", "crypto", "MEDIUM", ["A02:2025"],
     "Password hashed with MD5.",
     'import hashlib\ndef hpw(pw):\n    return hashlib.md5(pw.encode()).hexdigest()  # SINK weak-hash\n',
     'import bcrypt\ndef hpw(pw):\n    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())\n'),
    ("py-hardcoded-secret", "python", "py", "crypto", "HIGH", ["A02:2025"],
     "Hardcoded API key in source.",
     'API_KEY = "sk-live-abcd1234deadbeefabcd1234"  # SINK hardcoded-secret\ndef client():\n    return API_KEY\n',
     'import os\ndef client():\n    return os.environ["API_KEY"]\n'),
    ("py-ssrf", "python", "py", "ssrf", "HIGH", ["A01:2025"],
     "Server fetches a user-supplied URL.",
     'import requests\ndef fetch(url):\n    return requests.get(url).text  # SINK ssrf\n',
     'import requests\nALLOW = {"api.internal"}\ndef fetch(url):\n    from urllib.parse import urlparse\n    assert urlparse(url).hostname in ALLOW\n    return requests.get(url).text\n'),
    ("py-xxe", "python", "py", "injection", "MEDIUM", ["A05:2025"],
     "XML parsed with external entities enabled.",
     'import lxml.etree as ET\ndef parse(xml):\n    p = ET.XMLParser(resolve_entities=True)  # SINK xxe\n    return ET.fromstring(xml, p)\n',
     'import lxml.etree as ET\ndef parse(xml):\n    p = ET.XMLParser(resolve_entities=False, no_network=True)\n    return ET.fromstring(xml, p)\n'),
    ("py-ldap", "python", "py", "injection", "MEDIUM", ["A03:2025"],
     "LDAP filter built from user input.",
     'def search(conn, user):\n    return conn.search_s("dc=x", 2, "(uid=" + user + ")")  # SINK ldap-injection\n',
     'from ldap.filter import escape_filter_chars as esc\ndef search(conn, user):\n    return conn.search_s("dc=x", 2, "(uid=" + esc(user) + ")")\n'),
    ("py-bola", "python", "py", "AuthN/AuthZ", "HIGH", ["API1:2023"],
     "Object fetched by id without an owner check.",
     'def get_order(db, order_id, session):\n    return db.orders.find(order_id)  # SINK bola\n',
     'def get_order(db, order_id, session):\n    return db.orders.find(order_id, owner=session.user_id)\n'),
    # ---- JS / TS ----
    ("js-cmdi", "javascript", "js", "injection", "HIGH", ["A03:2025"],
     "child_process.exec with a shell string.",
     'const cp = require("child_process");\nfunction run(name){\n  return cp.execSync(`echo ${name}`);  // SINK cmdi\n}\n',
     'const cp = require("child_process");\nfunction run(name){\n  return cp.execFileSync("echo", [name]);\n}\n'),
    ("js-xss", "javascript", "js", "xss", "HIGH", ["A03:2025"],
     "User data assigned to innerHTML.",
     'function show(el, name){\n  el.innerHTML = name;  // SINK xss\n}\n',
     'function show(el, name){\n  el.textContent = name;\n}\n'),
    ("js-ssrf", "javascript", "js", "ssrf", "HIGH", ["A01:2025"],
     "fetch of a user-supplied URL.",
     'async function proxy(url){\n  return await fetch(url);  // SINK ssrf\n}\n',
     'const ALLOW = new Set(["api.internal"]);\nasync function proxy(url){\n  if(!ALLOW.has(new URL(url).hostname)) throw new Error("blocked");\n  return await fetch(url);\n}\n'),
    ("js-sqli", "javascript", "js", "injection", "HIGH", ["A03:2025"],
     "SQL string concatenation.",
     'function find(db, id){\n  return db.query("SELECT * FROM t WHERE id = " + id);  // SINK sqli\n}\n',
     'function find(db, id){\n  return db.query("SELECT * FROM t WHERE id = $1", [id]);\n}\n'),
    ("js-bopla", "javascript", "js", "AuthN/AuthZ", "HIGH", ["API3:2023"],
     "Mass assignment of a request body to a model.",
     'function update(user, body){\n  Object.assign(user, body);  // SINK mass-assignment\n  return user.save();\n}\n',
     'function update(user, body){\n  user.name = body.name; user.email = body.email;\n  return user.save();\n}\n'),
    ("js-open-redirect", "javascript", "js", "AuthN/AuthZ", "LOW", ["A01:2025"],
     "Redirect to a user-controlled URL.",
     'function go(res, next){\n  res.redirect(next);  // SINK open-redirect\n}\n',
     'const OK = new Set(["/home","/dash"]);\nfunction go(res, next){\n  res.redirect(OK.has(next) ? next : "/home");\n}\n'),
    ("ts-jwt-none", "typescript", "ts", "AuthN/AuthZ", "HIGH", ["API2:2023"],
     "JWT verified without pinning the algorithm.",
     'import jwt from "jsonwebtoken";\nexport function check(t: string, k: string){\n  return jwt.verify(t, k);  // SINK jwt-alg-confusion\n}\n',
     'import jwt from "jsonwebtoken";\nexport function check(t: string, k: string){\n  return jwt.verify(t, k, { algorithms: ["RS256"] });\n}\n'),
    ("js-cors", "javascript", "js", "config", "MEDIUM", ["A05:2025"],
     "Reflected Origin with credentials.",
     'function cors(req, res){\n  res.set("Access-Control-Allow-Origin", req.headers.origin);  // SINK cors-reflect\n  res.set("Access-Control-Allow-Credentials", "true");\n}\n',
     'const ALLOW = new Set(["https://app.example"]);\nfunction cors(req, res){\n  const o = req.headers.origin;\n  if(ALLOW.has(o)){ res.set("Access-Control-Allow-Origin", o); res.set("Access-Control-Allow-Credentials","true"); }\n}\n'),
    # ---- Go ----
    ("go-cmdi", "go", "go", "injection", "HIGH", ["A03:2025"],
     "exec via sh -c with user input.",
     'package m\nimport "os/exec"\nfunc Run(host string) ([]byte, error) {\n\treturn exec.Command("sh", "-c", "ping "+host).Output()  // SINK cmdi\n}\n',
     'package m\nimport "os/exec"\nfunc Run(host string) ([]byte, error) {\n\treturn exec.Command("ping", "-c1", host).Output()\n}\n'),
    ("go-sqli", "go", "go", "injection", "HIGH", ["A03:2025"],
     "SQL built with Sprintf.",
     'package m\nimport ("database/sql"; "fmt")\nfunc Find(db *sql.DB, id string) *sql.Row {\n\treturn db.QueryRow(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))  // SINK sqli\n}\n',
     'package m\nimport "database/sql"\nfunc Find(db *sql.DB, id string) *sql.Row {\n\treturn db.QueryRow("SELECT * FROM t WHERE id=$1", id)\n}\n'),
    ("go-ssrf", "go", "go", "ssrf", "HIGH", ["A01:2025"],
     "http.Get of a user URL.",
     'package m\nimport "net/http"\nfunc Fetch(url string) (*http.Response, error) {\n\treturn http.Get(url)  // SINK ssrf\n}\n',
     'package m\nimport ("net/http"; "net/url")\nfunc Fetch(raw string) (*http.Response, error) {\n\tu, _ := url.Parse(raw)\n\tif u.Host != "api.internal" { return nil, http.ErrAbortHandler }\n\treturn http.Get(raw)\n}\n'),
    ("go-pathtraversal", "go", "go", "injection", "HIGH", ["A01:2025"],
     "User path joined and read.",
     'package m\nimport ("os"; "path/filepath")\nfunc Read(name string) ([]byte, error) {\n\treturn os.ReadFile(filepath.Join("/data", name))  // SINK path-traversal\n}\n',
     'package m\nimport ("os"; "path/filepath"; "strings")\nfunc Read(name string) ([]byte, error) {\n\tp := filepath.Clean(filepath.Join("/data", name))\n\tif !strings.HasPrefix(p, "/data/") { return nil, os.ErrPermission }\n\treturn os.ReadFile(p)\n}\n'),
    ("go-weakrng", "go", "go", "crypto", "MEDIUM", ["A02:2025"],
     "Token from math/rand.",
     'package m\nimport ("math/rand"; "fmt")\nfunc Token() string {\n\treturn fmt.Sprintf("%d", rand.Int())  // SINK weak-rng\n}\n',
     'package m\nimport ("crypto/rand"; "encoding/hex")\nfunc Token() string {\n\tb := make([]byte, 16); rand.Read(b); return hex.EncodeToString(b)\n}\n'),
    # ---- AI / LLM / MCP / Agentic ----
    ("py-llm05-rce", "python", "py", "improper-output-handling", "HIGH", ["LLM05:2025"],
     "Model output executed in a shell.",
     'import subprocess\ndef act(model_out):\n    return subprocess.run(model_out, shell=True)  # SINK improper-output-handling\n',
     'import subprocess, json\nALLOWED = {"list", "status"}\ndef act(model_out):\n    a = json.loads(model_out)["action"]\n    assert a in ALLOWED\n    return subprocess.run(["agentctl", a])\n'),
    ("py-llm05-ssrf", "python", "py", "improper-output-handling", "HIGH", ["LLM05:2025"],
     "Model-chosen URL fetched (output->SSRF).",
     'import requests\ndef act(model_url):\n    return requests.get(model_url).text  # SINK improper-output-handling\n',
     'import requests\nALLOW = {"api.internal"}\ndef act(model_url):\n    from urllib.parse import urlparse\n    assert urlparse(model_url).hostname in ALLOW\n    return requests.get(model_url).text\n'),
    ("py-prompt-injection", "python", "py", "prompt-injection", "MEDIUM", ["LLM01:2025"],
     "Untrusted retrieved content concatenated into the prompt (architectural design note).",
     'def build(system, retrieved):\n    return system + "\\n" + retrieved  # SINK prompt-injection (untrusted concat into instructions)\n',
     'def build(system, retrieved):\n    return system + "\\n<untrusted>\\n" + spotlight(retrieved) + "\\n</untrusted>"\n\ndef spotlight(x):\n    return x.replace("<", "&lt;")\n'),
    ("py-excessive-agency", "python", "py", "excessive-agency", "HIGH", ["LLM06:2025"],
     "High-impact tool invoked with no human gate.",
     'def on_decision(agent_out):\n    return wire_transfer(agent_out["to"], agent_out["amount"])  # SINK excessive-agency\n',
     'def on_decision(agent_out, approve):\n    if not approve(agent_out): raise PermissionError("human gate required")\n    return wire_transfer(agent_out["to"], agent_out["amount"])\n'),
    ("py-mcp-tokenpassthrough", "python", "py", "tool-poisoning", "HIGH", ["MCP01:2025"],
     "MCP tool forwards the caller's token downstream.",
     'import requests\ndef call(incoming_token, path):\n    return requests.get(f"https://api/{path}", headers={"Authorization": f"Bearer {incoming_token}"})  # SINK mcp-token-passthrough\n',
     'import requests\ndef call(incoming_token, path, mint):\n    tok = mint(audience="https://api")\n    return requests.get(f"https://api/{path}", headers={"Authorization": f"Bearer {tok}"})\n'),
    ("py-rag-poisoning", "python", "py", "rag-poisoning", "MEDIUM", ["LLM08:2025"],
     "Unauthenticated write into the vector store.",
     'def ingest(store, doc):\n    store.add(doc)  # SINK rag-poisoning (no provenance check)\n',
     'def ingest(store, doc, trusted):\n    if not trusted(doc.source): raise ValueError("untrusted source")\n    store.add(doc)\n'),
    ("py-data-exfil", "python", "py", "data-exfil", "HIGH", ["LLM02:2025"],
     "Private data posted to a model-chosen URL.",
     'import requests\ndef run(secret, model_url):\n    requests.post(model_url, data=secret)  # SINK data-exfil\n',
     'def run(secret, model_url):\n    raise RuntimeError("no model-controlled egress of secrets")\n'),
]

# --- programmatic per-language variants to grow the FROZEN corpus to >=100 -------------------
# OWASP-Benchmark-style: a sink family templated across languages, numbered variants (@N). Real
# small snippets; the `SINK` marker locates the labeled line. EXT per language.
_EXT = {"python": "py", "javascript": "js", "go": "go"}
# family -> (category, severity, owasp, {lang: (vuln_template, clean_template)})   @N = variant index
_FAMILIES = {
    "sqli": ("injection", "HIGH", ["A03:2025"], {
        "python": ('def q@N(db, v):\n    return db.execute("SELECT * FROM t@N WHERE c = \'" + v + "\'")  # SINK sqli\n',
                   'def q@N(db, v):\n    return db.execute("SELECT * FROM t@N WHERE c = ?", (v,))\n'),
        "javascript": ('function q@N(db, v){ return db.query("SELECT * FROM t@N WHERE c=" + v); }  // SINK sqli\n',
                       'function q@N(db, v){ return db.query("SELECT * FROM t@N WHERE c=$1", [v]); }\n'),
        "go": ('package m\nimport ("database/sql"; "fmt")\nfunc Q@N(db *sql.DB, v string) *sql.Row {\n\treturn db.QueryRow(fmt.Sprintf("SELECT * FROM t@N WHERE c=%s", v))  // SINK sqli\n}\n',
               'package m\nimport "database/sql"\nfunc Q@N(db *sql.DB, v string) *sql.Row {\n\treturn db.QueryRow("SELECT * FROM t@N WHERE c=$1", v)\n}\n'),
    }),
    "cmdi": ("injection", "HIGH", ["A03:2025"], {
        "python": ('import subprocess\ndef run@N(host):\n    return subprocess.run("ping " + host, shell=True)  # SINK cmdi\n',
                   'import subprocess\ndef run@N(host):\n    return subprocess.run(["ping", host])\n'),
        "javascript": ('const cp=require("child_process");\nfunction run@N(x){ return cp.execSync("echo "+x); }  // SINK cmdi\n',
                       'const cp=require("child_process");\nfunction run@N(x){ return cp.execFileSync("echo",[x]); }\n'),
        "go": ('package m\nimport "os/exec"\nfunc Run@N(h string) ([]byte, error) {\n\treturn exec.Command("sh", "-c", "ping "+h).Output()  // SINK cmdi\n}\n',
               'package m\nimport "os/exec"\nfunc Run@N(h string) ([]byte, error) {\n\treturn exec.Command("ping", h).Output()\n}\n'),
    }),
    "ssrf": ("ssrf", "HIGH", ["A01:2025"], {
        "python": ('import requests\ndef fetch@N(url):\n    return requests.get(url).text  # SINK ssrf\n',
                   'import requests\nALLOW={"api.internal"}\ndef fetch@N(url):\n    from urllib.parse import urlparse\n    assert urlparse(url).hostname in ALLOW\n    return requests.get(url).text\n'),
        "javascript": ('async function fetch@N(u){ return await fetch(u); }  // SINK ssrf\n',
                       'const OK=new Set(["api.internal"]);\nasync function fetch@N(u){ if(!OK.has(new URL(u).hostname)) throw new Error("x"); return await fetch(u); }\n'),
        "go": ('package m\nimport "net/http"\nfunc Fetch@N(u string) (*http.Response, error) {\n\treturn http.Get(u)  // SINK ssrf\n}\n',
               'package m\nimport ("net/http"; "net/url")\nfunc Fetch@N(raw string) (*http.Response, error) {\n\tu,_:=url.Parse(raw); if u.Host!="api.internal" { return nil, http.ErrAbortHandler }\n\treturn http.Get(raw)\n}\n'),
    }),
    "pathtraversal": ("injection", "HIGH", ["A01:2025"], {
        "python": ('def read@N(name):\n    return open("/data/" + name).read()  # SINK path-traversal\n',
                   'import os\ndef read@N(name):\n    p=os.path.realpath("/data/"+name)\n    assert p.startswith("/data/")\n    return open(p).read()\n'),
        "go": ('package m\nimport ("os"; "path/filepath")\nfunc Read@N(n string) ([]byte, error) {\n\treturn os.ReadFile(filepath.Join("/data", n))  // SINK path-traversal\n}\n',
               'package m\nimport ("os"; "path/filepath"; "strings")\nfunc Read@N(n string) ([]byte, error) {\n\tp:=filepath.Clean(filepath.Join("/data", n)); if !strings.HasPrefix(p,"/data/") { return nil, os.ErrPermission }\n\treturn os.ReadFile(p)\n}\n'),
    }),
    "weakhash": ("crypto", "MEDIUM", ["A02:2025"], {
        "python": ('import hashlib\ndef h@N(pw):\n    return hashlib.md5(pw.encode()).hexdigest()  # SINK weak-hash\n',
                   'import bcrypt\ndef h@N(pw):\n    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())\n'),
        "javascript": ('const c=require("crypto");\nfunction h@N(pw){ return c.createHash("md5").update(pw).digest("hex"); }  // SINK weak-hash\n',
                       'const b=require("bcrypt");\nfunction h@N(pw){ return b.hashSync(pw,12); }\n'),
    }),
    "xss": ("xss", "HIGH", ["A03:2025"], {
        "javascript": ('function show@N(el, s){ el.innerHTML = s; }  // SINK xss\n',
                       'function show@N(el, s){ el.textContent = s; }\n'),
    }),
    "deser": ("deserialization", "HIGH", ["A08:2025"], {
        "python": ('import pickle\ndef load@N(b):\n    return pickle.loads(b)  # SINK insecure-deserialization\n',
                   'import json\ndef load@N(b):\n    return json.loads(b)\n'),
    }),
    "open-redirect": ("AuthN/AuthZ", "LOW", ["A01:2025"], {
        "javascript": ('function go@N(res, next){ res.redirect(next); }  // SINK open-redirect\n',
                       'const OK=new Set(["/home"]);\nfunction go@N(res, next){ res.redirect(OK.has(next)?next:"/home"); }\n'),
        "python": ('def go@N(redirect, nxt):\n    return redirect(nxt)  # SINK open-redirect\n',
                   'OK={"/home"}\ndef go@N(redirect, nxt):\n    return redirect(nxt if nxt in OK else "/home")\n'),
    }),
}
_VARIANTS_PER = 4  # numbered variants per (family, language)


def _build_variants() -> list:
    out = []
    for fam, (cat, sev, owasp, langs) in _FAMILIES.items():
        for lang, (vt, ct) in langs.items():
            for n in range(1, _VARIANTS_PER + 1):
                cid = f"{lang[:2]}-{fam}-{n:02d}"
                out.append((cid, lang, _EXT[lang], cat, sev, list(owasp),
                            f"{fam} variant {n} ({lang}).",
                            vt.replace("@N", str(n)), ct.replace("@N", str(n))))
    return out


# --- named CVE regression anchors (si-08 6.1) — representative class snippets tagged with the CVE ---
_CVE_ANCHORS = [
    ("cve-2026-22807-vllm-deser", "python", "py", "deserialization", "HIGH", ["CVE-2026-22807", "A08:2025"],
     "Regression anchor CVE-2026-22807 (vLLM): untrusted object deserialized in an inference server path.",
     'import pickle\ndef load_request(blob):\n    return pickle.loads(blob)  # SINK CVE-2026-22807 insecure-deserialization\n',
     'import json\ndef load_request(blob):\n    return json.loads(blob)\n'),
    ("cve-2026-22778-vllm-ssrf", "python", "py", "ssrf", "HIGH", ["CVE-2026-22778", "A01:2025"],
     "Regression anchor CVE-2026-22778 (vLLM): server fetches a user-supplied model/url.",
     'import requests\ndef pull_model(url):\n    return requests.get(url).content  # SINK CVE-2026-22778 ssrf\n',
     'import requests\nALLOW={"models.internal"}\ndef pull_model(url):\n    from urllib.parse import urlparse\n    assert urlparse(url).hostname in ALLOW\n    return requests.get(url).content\n'),
    ("cve-2025-68664-langchain-llm05", "python", "py", "improper-output-handling", "HIGH", ["CVE-2025-68664", "LLM05:2025"],
     "Regression anchor CVE-2025-68664 (LangChain): model output executed (improper output handling).",
     'def run_tool(llm_out):\n    return eval(llm_out)  # SINK CVE-2025-68664 improper-output-handling\n',
     'import json, ast\ndef run_tool(llm_out):\n    return ast.literal_eval(json.loads(llm_out)["expr"])\n'),
]


def sink_line(content: str) -> int:
    for i, line in enumerate(content.splitlines(), start=1):
        if "SINK" in line:
            return i
    raise ValueError("no SINK marker")


def all_cases() -> list:
    """The full frozen set: hand-written distinct cases + per-language variants + CVE anchors."""
    return list(C) + _build_variants() + list(_CVE_ANCHORS)


def main() -> int:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    cases = all_cases()
    ids = []
    for cid, lang, ext, cat, sev, owasp, desc, vuln, clean in cases:
        d = CASES_DIR / cid
        d.mkdir(parents=True, exist_ok=True)
        vfile = f"vulnerable_variant.{ext}"
        bfile = f"benign_lookalike.{ext}"
        (d / vfile).write_text(vuln)
        (d / bfile).write_text(clean)
        (d / "target.md").write_text(f"# {cid}\n\n- **language:** {lang}\n- **category:** {cat}\n- {desc}\n")
        label = {
            "case_id": cid, "language": lang, "category": cat, "severity": sev, "owasp": owasp,
            "vulnerable": {"file": vfile, "line": sink_line(vuln)},
            "benign_lookalike": {"file": bfile},
            "note": desc,
        }
        (d / "label.json").write_text(json.dumps(label, indent=2) + "\n")
        ids.append(cid)
    # freeze marker: enumerate the locked case ids (Phase 9 T-9.1)
    (CASES_DIR.parent / "LOCKED").write_text(
        "# FROZEN eval corpus — locked case ids (Phase 9 T-9.1).\n"
        "# Agent-write-blocked by confine_self_writes (T-8.4); edits go through promote_finding.py\n"
        "# run by the human/CI identity. Regenerate with corpus/generate.py.\n"
        + "\n".join(sorted(ids)) + "\n")
    print(f"generated {len(ids)} cases under {CASES_DIR}; wrote LOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
