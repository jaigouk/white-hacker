# research:lang-ts-py

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:lang-ts-py`

## 2026 Language-Specific Security Review Notes

These notes are tuned for an automated white-hat review agent. Each section pairs a **DANGEROUS** sink with a **SAFE** rewrite so the agent can grep, flag, and suggest fixes deterministically. Severity reflects the 2025-2026 threat landscape (RSC RCE, npm worms, SSTI, DNS-rebinding SSRF).

### A. TypeScript / JavaScript (Node backend + React/Vue/Next frontend)

#### A1. XSS sinks (frontend + SSR)
The big three to grep: `dangerouslySetInnerHTML`, `v-html`, and raw `.innerHTML`/`.outerHTML`/`insertAdjacentHTML`. Also flag `eval`, `Function()`, `setTimeout("string")`, `document.write`, `$(...).html()`, Angular `bypassSecurityTrust*`, and `ref.innerHTML = userInput`. SSR makes this worse: server-rendered unsanitized HTML executes in every visitor's session.

```jsx
// DANGEROUS — React
<div dangerouslySetInnerHTML={{ __html: userBio }} />
// SAFE — sanitize first (DOMPurify), or just render as text {userBio}
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userBio) }} />
```
```vue
<!-- DANGEROUS — Vue --> <div v-html="comment"></div>
<!-- SAFE --> <div>{{ comment }}</div>   <!-- or v-html with DOMPurify.sanitize(comment) -->
```
Flag DOMPurify used with permissive config (`ADD_TAGS`, `ALLOW_UNKNOWN_PROTOCOLS`, `ADD_ATTR: ['onclick']`). For server-side sanitization prefer `isomorphic-dompurify`. Treat `href={userUrl}` / `src` as XSS too (`javascript:` URIs) — validate the scheme is `http(s)`.

#### A2. Prototype pollution
2025-2026 kept this alive: **CVE-2025-13465** (lodash `_.unset`/`_.omit` crafted paths, fixed 4.17.23) and **CVE-2026-2950** (incomplete fix, still pollutes via non-string keys) ([Snyk](https://security.snyk.io/vuln/SNYK-JS-LODASH-15053838), [GHSA](https://github.com/advisories/GHSA-xxjr-mmjv-4gpg)); **CVE-2025-57820** in `devalue` (SvelteKit's serializer). Flag any recursive merge/`set`/`deepClone` that walks attacker-controlled keys.

```js
// DANGEROUS — recursive merge of untrusted JSON, no key guard
function merge(t, s){ for (const k in s){ if (typeof s[k]==='object') merge(t[k]=t[k]||{}, s[k]); else t[k]=s[k]; } }
merge({}, JSON.parse(req.body));   // __proto__ / constructor / prototype poison the chain

// SAFE — block dangerous keys + null-prototype + Map for lookups
const BAD = new Set(["__proto__","constructor","prototype"]);
function merge(t, s){ for (const k of Object.keys(s)){ if (BAD.has(k)) continue;
  if (s[k] && typeof s[k]==='object') merge(t[k]=t[k]||Object.create(null), s[k]); else t[k]=s[k]; } }
```
Defenses the agent should recommend: `Object.create(null)` for dictionaries, `Map` instead of object as a key/value store, JSON Schema validation (ajv) on request bodies, `Object.freeze(Object.prototype)` at boot, and `--disable-proto=delete` Node flag. Pin lodash >= 4.17.23 (and note 13465's fix was incomplete per 2026-2950).

#### A3. SSRF (Node fetch/axios/undici/request)
SSRF in 2025-2026 is dominated by **DNS rebinding / TOCTOU bypasses** of naive IP checks — the validation lookup and the actual connect resolve the hostname twice; attacker flips the answer to `169.254.169.254` (AWS IMDS), `100.100.100.200` (Alibaba), `metadata.google.internal`, or RFC1918/loopback/IPv6 link-local ([windshock](https://windshock.github.io/en/post/2025-06-25-ssrf-defense/), [Craft CMS GHSA](https://github.com/craftcms/cms/security/advisories/GHSA-gp2f-7wcm-5fhx)).

```js
// DANGEROUS — fetch attacker URL directly (and check-then-use is also bypassable)
const r = await fetch(req.query.url);            // → http://169.254.169.254/latest/meta-data/

// SAFE(r) — allowlist host, pin the resolved IP, reject private ranges, block redirects
import dns from "node:dns/promises"; import ipaddr from "ipaddr.js";
const u = new URL(req.query.url);
if (!ALLOW_HOSTS.has(u.hostname) || u.protocol !== "https:") throw new Error("blocked");
const { address } = await dns.lookup(u.hostname);          // resolve once
if (ipaddr.parse(address).range() !== "unicast") throw new Error("private IP");
await fetch(u, { redirect: "manual",                       // do not auto-follow redirects
  // connect to the *pinned* address to defeat rebinding (custom undici dispatcher / lookup)
});
```
Agent checklist: deny `redirect: "follow"` to user URLs, block all RFC1918/loopback/link-local/IPv6 ULA, prefer IMDSv2, and pin DNS. Naive blocklists and a single `dns.lookup` before request are insufficient.

#### A4. Command / path injection (`child_process`, `fs`)
```js
// DANGEROUS — shell interpolation
import { exec } from "node:child_process";
exec(`convert ${userFile} out.png`);                       // ; rm -rf, $(...), backticks
// SAFE — execFile/spawn with arg array, shell:false (default)
import { execFile } from "node:child_process";
execFile("convert", [userFile, "out.png"], { shell: false });
```
```js
// DANGEROUS — path traversal
fs.readFile(path.join(BASE, req.params.name));             // name = ../../etc/passwd
// SAFE — resolve + confine to base
const p = path.resolve(BASE, req.params.name);
if (!p.startsWith(BASE + path.sep)) throw new Error("traversal");
```
Flag any `exec`/`execSync` with template strings, `spawn(..., {shell:true})`, and `fs`/`createReadStream` paths built from user input without a `startsWith(base)` confinement check. Note `%2e%2e`/null-byte/unicode normalization bypasses — normalize then confine.

#### A5. Unsafe eval / dynamic code
Flag `eval`, `new Function`, `vm.runInThisContext`, string `setTimeout/setInterval`, and `require(userInput)`/dynamic `import(userInput)`. Replace with `JSON.parse` for data and explicit dispatch maps for behavior. For sandboxing untrusted code, the old `vm2` is **abandoned with known escapes** — recommend `isolated-vm` or out-of-process sandboxing instead.

#### A6. Next.js / SSR / server actions & API routes (2025-2026 CVEs)
- **CVE-2025-29927 (CVSS 9.1)** — middleware auth bypass via the `x-middleware-subrequest` header; self-hosted apps before 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 are bypassable. Strip the header at the proxy and never rely on middleware as the *only* authz layer ([ProjectDiscovery](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass), [Vercel postmortem](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass)).
- **CVE-2025-66478 / CVE-2025-55182 "React2Shell" (CVSS 10.0)** — RSC protocol deserialization RCE in App Router on Next 15.x/16.x (and late 14.3 canaries); actively exploited by China-nexus groups within days. Upgrade to 15.0.5/15.1.9/.../16.0.7 and **rotate all secrets** if it ran unpatched ([Next.js advisory](https://nextjs.org/blog/CVE-2025-66478), [Akamai](https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce)).

```ts
// DANGEROUS — server action trusts client, authz only in middleware
"use server";
export async function deleteUser(id: string){ await db.user.delete({ where:{ id } }); }
// SAFE — re-check session + authorize inside every server action / route handler
"use server";
export async function deleteUser(id: string){
  const session = await auth();
  if (!session?.user || !can(session.user, "delete", id)) throw new Error("forbidden");
  await db.user.delete({ where:{ id } });
}
```
Agent rules: every `"use server"` action and `route.ts` handler must independently authenticate + authorize and validate input (zod); never treat middleware/headers as a trust boundary; pin patched Next/React versions.

#### A7. npm supply chain (2025-2026 is the worst era yet)
The **Shai-Hulud** self-replicating worm (Sept 2025), **Shai-Hulud 2.0** (Nov-Dec 2025, 25k+ repos / pre-install execution), and **Mini Shai-Hulud** (May 2026, first to hit npm *and* PyPI simultaneously) steal npm/GitHub/cloud tokens via `preinstall`/`postinstall` scripts and re-publish to the maintainer's other packages ([Unit42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/), [Microsoft 2.0](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/), [Wiz](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)). Agent checklist:
- Flag lifecycle scripts in deps; run CI installs with `npm ci --ignore-scripts` (or `--foreground-scripts` to audit).
- Require a committed lockfile, `npm audit signatures`, and pinned versions (no floating `^`/`latest` for sensitive deps).
- Detect newly published versions and exfil patterns (`curl`/`webhook.site`/`TruffleHog`/`process.env` dumps in install scripts).
- Recommend least-privilege, short-lived npm publish tokens + 2FA, and OIDC trusted publishing.

### B. Python (FastAPI / Django / Flask)

#### B1. SQL injection (raw queries / ORM escapes)
ORMs are safe *until* someone drops to raw SQL. Flag f-strings/`%`/`.format()`/`+` inside `cursor.execute`, Django `.raw()`/`.extra()`/`RawSQL`, SQLAlchemy `text()` with interpolation.
```python
# DANGEROUS
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
User.objects.extra(where=[f"name = '{name}'"])              # Django extra() = classic sink
db.execute(text(f"SELECT * FROM t WHERE id = {tid}"))       # SQLAlchemy
# SAFE — bound parameters everywhere
cursor.execute("SELECT * FROM users WHERE email = %s", [email])
User.objects.filter(name=name)                              # ORM
db.execute(text("SELECT * FROM t WHERE id = :id"), {"id": tid})
```
Note: table/column names can't be bound — validate them against an allowlist.

#### B2. Command injection (`subprocess`, `os.system`)
```python
# DANGEROUS
os.system(f"ping {host}")
subprocess.run(f"convert {f} out.png", shell=True)          # shell=True + interpolation
# SAFE — arg list, shell=False (default), shlex.quote only if a shell is unavoidable
subprocess.run(["ping", "-c", "1", host], check=True, shell=False)
```
Flag `os.system`, `os.popen`, `commands.*`, `subprocess.*(shell=True)`, and any string-built command. If a shell is truly required, `shlex.quote()` each argument — but prefer the list form.

#### B3. SSTI in Jinja (Flask/FastAPI/Django templates)
Live example: **CVE-2025-23211** (Tandoor Recipes Jinja2 SSTI → RCE) ([OffSec](https://www.offsec.com/blog/cve-2025-23211/)). The root cause is *user input concatenated into the template source*, not into the context.
```python
# DANGEROUS — user controls template text → {{7*7}}, {{ cycler.__init__.__globals__.os.popen('id').read() }}
return render_template_string("Hello " + request.args["name"])
# SAFE — fixed template, user data as a *context variable* (auto-escaped)
return render_template("hello.html", name=request.args["name"])
```
For user-authored templates (email/CMS), use a sandboxed/locked mini-language (Jinja `SandboxedEnvironment`, or Liquid/Mustache) — never plain Jinja. Django: never `mark_safe`/`|safe`/`format_html` on untrusted data, and don't disable `autoescape`.

#### B4. Insecure deserialization (`pickle`, `yaml.load`, `marshal`)
```python
# DANGEROUS — arbitrary code on load
data = pickle.loads(request.body)                           # __reduce__ → RCE
cfg  = yaml.load(open(f))                                   # full loader = RCE
# SAFE
cfg  = yaml.safe_load(open(f))                              # SafeLoader only
# for cross-process data use JSON; never unpickle untrusted bytes
```
Flag `pickle.load(s)`, `cPickle`, `dill`, `shelve`, `jsonpickle`, `yaml.load` without `Loader=SafeLoader`, `marshal.loads`, and ML-specific sinks: `torch.load` (use `weights_only=True`), `joblib.load`, and `trust_remote_code=True` on Hugging Face models.

#### B5. Path traversal
```python
# DANGEROUS
open(os.path.join(BASE, request.args["name"]))             # ../../etc/passwd
# SAFE — resolve + confine
p = (Path(BASE) / name).resolve()
if not str(p).startswith(str(Path(BASE).resolve()) + os.sep): abort(403)
```
Flag `send_file`/`send_from_directory`/`FileResponse`/`open` with user paths lacking a realpath-confinement check.

#### B6. Authz, secrets, dangerous stdlib
- **Authz:** FastAPI/Flask/DRF endpoints must enforce object-level checks (IDOR/BOLA is OWASP API #1) — flag handlers that fetch by user-supplied id without an ownership/role check. Don't trust JWT claims without verifying signature + `aud`/`exp` (`jwt.decode(..., verify=False)` or `algorithms` allowing `none`/`HS`-vs-`RS` confusion is a finding).
- **Secrets:** flag hardcoded keys/tokens, `DEBUG=True` in prod (Django leaks tracebacks/SECRET_KEY context), and secrets in source/`.env` committed to git.
- **Dangerous stdlib/eval:** `eval`, `exec`, `compile`, `__import__`, `input()` on Py2; SSRF-prone `urllib.request.urlopen`/`requests.get` with user URLs (apply the SSRF defenses from A3 — DNS pinning + private-range block); `tempfile.mktemp`; weak crypto (`hashlib.md5`/`sha1` for passwords — use `bcrypt`/`argon2`); `random` for tokens (use `secrets`); `xml.etree`/`lxml` without `defusedxml` (XXE/billion-laughs); `tarfile.extractall`/`zipfile.extractall` on untrusted archives (Zip-Slip — Python 3.12+ offers `filter='data'`).

### C. AI / LLM project specifics (cross-language)
Prompt Injection is **LLM01** and still #1 in the **OWASP Top 10 for LLM Applications 2026** ([genai.owasp.org](https://genai.owasp.org/llm-top-10/)). The agent should treat LLM output as untrusted input to downstream sinks: never feed model output to `eval`/`exec`/`os.system`/SQL/`child_process` without validation or sandboxing (cf. LangChain `LLMMathChain`→`exec` RCE). Flag `PythonREPLTool`, unsandboxed code-exec tools, `trust_remote_code=True`, over-broad tool/agent permissions (excessive agency), and unbounded tool scopes. Constrain outputs with strict schemas, human-in-the-loop for state-changing actions, and least-privilege tool credentials.

## Key takeaways

- Next.js has two 2025-2026 critical CVEs an agent must check: CVE-2025-29927 (x-middleware-subrequest auth bypass, self-hosted < 15.2.3) and CVE-2025-66478 / React CVE-2025-55182 'React2Shell' (CVSS 10.0 RSC deserialization RCE in App Router on Next 15.x/16.x). Rule: never trust middleware as the sole authz layer; re-authorize inside every server action and route handler; pin patched versions; rotate secrets if React2Shell ran unpatched.
- npm supply chain is the dominant 2025-2026 ecosystem threat: Shai-Hulud (Sept 2025), Shai-Hulud 2.0 (Nov-Dec 2025, pre-install execution, 25k+ repos), and Mini Shai-Hulud (May 2026, first joint npm+PyPI worm). Flag lifecycle scripts, require lockfiles, use `npm ci --ignore-scripts` in CI, `npm audit signatures`, and least-privilege/OIDC publish tokens.
- XSS detection is identical in spirit across frameworks: grep dangerouslySetInnerHTML (React), v-html (Vue), innerHTML/insertAdjacentHTML/document.write (vanilla), bypassSecurityTrust* (Angular). Safe pattern = render as text or DOMPurify.sanitize; also validate href/src schemes to block javascript: URIs. SSR amplifies impact.
- Prototype pollution is still active in 2026: lodash CVE-2025-13465 (_.unset/_.omit, fixed 4.17.23) and CVE-2026-2950 (incomplete fix), plus devalue CVE-2025-57820. Detect recursive merge/set over attacker keys; recommend blocking __proto__/constructor/prototype, Object.create(null), Map, ajv schema validation, and Node --disable-proto.
- SSRF in 2026 centers on DNS-rebinding / TOCTOU bypasses of naive IP checks; a single dns.lookup-before-fetch is insufficient. Defense = host allowlist + resolve-once-and-pin-the-IP + reject RFC1918/loopback/link-local/IPv6-ULA + block redirect-follow on user URLs + prefer IMDSv2. Applies identically to Python urllib/requests.
- Command/path injection rules are symmetric across languages: flag shell-string interpolation (Node exec/execSync template strings, spawn shell:true; Python os.system/os.popen/subprocess shell=True). Safe = arg-array execFile/spawn or subprocess.run([...]) with shell=False. Path access must resolve then confine with startsWith(base) and account for encoded/unicode/null-byte traversal.
- Python SQLi only appears when code escapes the ORM: flag f-strings/%/format/+ inside cursor.execute, Django .raw()/.extra()/RawSQL, SQLAlchemy text() interpolation. Safe = bound parameters (%s / :name) and ORM filters; allowlist any dynamic table/column names since they cannot be bound.
- SSTI root cause is user input concatenated into template *source* (render_template_string + request data), not passed as context — see CVE-2025-23211 (Tandoor Jinja2 SSTI RCE). Safe = fixed template + user data as auto-escaped context var; for user-authored templates use SandboxedEnvironment or a logic-less language, and avoid mark_safe/|safe/autoescape-off in Django.
- Insecure deserialization sinks for Python: pickle/cPickle/dill/jsonpickle/shelve, yaml.load without SafeLoader, marshal.loads, plus ML-specific torch.load (use weights_only=True), joblib.load, and trust_remote_code=True. Safe = yaml.safe_load and JSON for cross-process data; never unpickle untrusted bytes. The same worm era now hits PyPI, so this couples with supply-chain checks.
- Unsafe dynamic execution to flag generically: JS eval/new Function/vm.runInThisContext/string-setTimeout/require(userInput); Python eval/exec/compile/__import__. vm2 is abandoned with known sandbox escapes — recommend isolated-vm or out-of-process isolation rather than in-process sandboxes.
- Authz/secrets must be checked per-handler regardless of stack: enforce object-level ownership (IDOR/BOLA = OWASP API #1) on every FastAPI/Flask/DRF/Next route and server action; verify JWT signature + aud/exp and reject alg:none/HS-RS confusion; flag hardcoded secrets, Django DEBUG=True in prod, weak crypto (md5/sha1 for passwords), random instead of secrets, and XML parsing without defusedxml.
- For AI/LLM projects, treat model output as untrusted input to downstream sinks (LLM01 Prompt Injection is still #1 in OWASP LLM Top 10 2026): never pipe LLM output into eval/exec/shell/SQL without validation or sandboxing (cf. LangChain LLMMathChain->exec RCE), flag PythonREPLTool / unsandboxed code-exec tools / trust_remote_code, constrain with strict output schemas, and require human-in-the-loop for state-changing tool calls under least privilege.

## Sources

- https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
- https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/
- https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
- https://www.reversinglabs.com/blog/shai-hulud-worm-npm
- https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass
- https://vercel.com/blog/postmortem-on-next-js-middleware-bypass
- https://nextjs.org/blog/CVE-2025-66478
- https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce
- https://security.snyk.io/vuln/SNYK-JS-LODASH-15053838
- https://github.com/advisories/GHSA-xxjr-mmjv-4gpg
- https://security.snyk.io/vuln/SNYK-JS-LODASH-15869619
- https://security.snyk.io/vuln/SNYK-JS-DEVALUE-12205530
- https://windshock.github.io/en/post/2025-06-25-ssrf-defense/
- https://github.com/craftcms/cms/security/advisories/GHSA-gp2f-7wcm-5fhx
- https://owasp.org/www-community/pages/controls/SSRF_Prevention_in_Nodejs
- https://www.offsec.com/blog/cve-2025-23211/
- https://semgrep.dev/docs/cheat-sheets/python-command-injection
- https://www.sourcery.ai/vulnerabilities/python-django-security-injection-sql-django-orm-sql-injection-raw-sql
- https://genai.owasp.org/llm-top-10/
- https://genai.owasp.org/llmrisk/llm01-prompt-injection/

