# lang-python — Python-specific sinks & secure patterns

> Loaded on demand when `SCAN-PLAN.json` lists `python`. Pattern-first; core categories in
> [`core-checklist.md`](core-checklist.md). AI/ML deser sinks here cross-reference
> [`ai-llm.md`](ai-llm.md) when `ai_pass` is set.

## Native capability tools (examples, swappable)
- **SCA:** `pip-audit` (advisory DB, low FP) → OSV-Scanner as fallback.
- **SAST:** `ruff` rule set `S` (fast, Bandit-derived) + `bandit` (framework/AI rules) + Opengrep.
- Floor: Read/Grep/Glob + this file (`tool_assisted:false`).

## SQL injection
The ORM is safe until you reach for raw escape hatches with interpolated input.
```python
# DANGEROUS — any of these with user input
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")        # f-string
cursor.execute("... WHERE name = '%s'" % name)                 # % / .format
Model.objects.raw(f"SELECT ... WHERE x={v}")                   # Django .raw()
Model.objects.extra(where=[f"col = {v}"])                      # Django .extra()
session.execute(text(f"SELECT ... {v}"))                       # SQLAlchemy text()

# SAFE — parameter binding (driver escapes)
cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
session.execute(text("SELECT ... WHERE x = :v"), {"v": v})
```

## SSTI — server-side template injection (Jinja2)
User-controlled data must be a template **variable**, never part of the template **string**.
Rendering request data as a template is RCE (e.g. **CVE-2025-23211**, Tandoor Recipes: user recipe
content fed to Jinja rendering → arbitrary command execution).
```python
# DANGEROUS — request data becomes the template source
render_template_string("Hello " + request.args["name"])

# SAFE — fixed template, data passed as a context variable (auto-escaped)
render_template("hello.html", name=request.args["name"])
```

## Insecure deserialization / arbitrary code on load
Never natively deserialize untrusted input. These are RCE primitives:
```python
# DANGEROUS
pickle.loads(untrusted)                 # arbitrary __reduce__ execution
yaml.load(untrusted)                    # full loader == code exec
torch.load(untrusted)                   # pickle under the hood
AutoModel.from_pretrained(x, trust_remote_code=True)   # runs repo-supplied code

# SAFE
json.loads(untrusted)                   # data-only
yaml.safe_load(untrusted)               # SafeLoader, no object construction
torch.load(untrusted, weights_only=True)
# load only from pinned, provenance-verified model sources; trust_remote_code=False
```

## `eval` / `exec` / dynamic import
`eval`, `exec`, `compile`, `__import__`, `getattr(obj, user_str)` on untrusted input are direct code
/ attribute-traversal sinks. Replace with explicit dispatch tables / `ast.literal_eval` for literals.

## XXE — use defusedxml
Stdlib XML parsers resolve external entities by default. Parse untrusted XML with
`defusedxml` (`defusedxml.ElementTree`), or disable DTD/external-entity resolution explicitly.

## Config & framework
- `DEBUG = True` (Django/Flask) in production → interactive debugger / info leak. Flag if reachable
  in a prod path.
- `SECRET_KEY`/credentials hard-coded; `ALLOWED_HOSTS = ['*']`; `MD5`/`sha1` for passwords (use
  `secrets`/`hashlib` with a KDF, e.g. `argon2`/`bcrypt`).
- `random` for tokens → use `secrets`.

## What to grep for
`execute(f"` / `execute("... %` · `.raw(` / `.extra(` / `text(f"` · `render_template_string` ·
`pickle.load` / `yaml.load(` (no `safe_`) / `torch.load(` / `trust_remote_code=True` · `eval(` /
`exec(` / `__import__(` · `etree.parse`/`minidom` on untrusted xml · `DEBUG = True` · `verify=False`
in `requests` · `subprocess` with `shell=True`.
