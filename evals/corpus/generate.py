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


def sink_line(content: str) -> int:
    for i, line in enumerate(content.splitlines(), start=1):
        if "SINK" in line:
            return i
    raise ValueError("no SINK marker")


def main() -> int:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for cid, lang, ext, cat, sev, owasp, desc, vuln, clean in C:
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
        written += 1
    print(f"generated {written} cases under {CASES_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
