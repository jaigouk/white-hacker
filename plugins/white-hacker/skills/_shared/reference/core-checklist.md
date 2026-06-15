# Core security checklist (language-agnostic)

> Loaded on demand by `sec-vuln-scan` (discovery) and `sec-triage`. The 11 root-cause categories
> below apply to **every** language; per-language detail lives in `lang-*.md`, AI in `ai-llm.md`,
> APIs in `api.md`, infra in `infra.md`. Mapped to **OWASP Top 10 for Web 2025**. Categories and
> exclusions are config-extendable (`config/custom-scan-instructions.example.md`).
>
> For each finding: identify the **source** (attacker-controlled input), the **sink** (dangerous
> operation), and whether data reaches the sink **unsanitized across a trust boundary**. No
> source→sink path = not a finding. Severity is decided in triage (`severity-rubric.md`), never here.

Category tags (for tooling): `injection` `AuthN/AuthZ` `ssrf` `open-redirect` `crypto`
`deserialization` `xss` `config` `supply-chain` `error` `data-exposure` `resource`.

---

# 1. Injection  — `injection`  (OWASP A03:2025 Injection)
User-controlled data interpreted as code/query/markup.
- **SQL/NoSQL:** string-built queries; require parameterized queries / bound params. No string concat,
  f-strings, `%`, `.format`, template literals in query text.
- **Command:** user input in `exec`/`system`/`ProcessBuilder`/`child_process` — especially with a
  shell (`sh -c`, `shell:true`). Pass argv arrays, never a shell string.
- **LDAP / XPath / NoSQL operators / header / SMTP** injection.
- **XXE:** XML parsers with external entities / DTDs enabled — disable them.
- **Template (SSTI):** user input used as the *template*, not template *data* (Jinja
  `render_template_string`, Handlebars, Thymeleaf, SpEL, Velocity).
- **Path traversal:** user input in file paths (`../`, absolute, null bytes, UNC). Canonicalize and
  confirm the result stays under an allowed base; prefer rooted-open APIs.
- Rule: **data is never the code/query/template/path string.**

# 2. Authentication & Authorization  — `AuthN/AuthZ`  (OWASP A01:2025 Broken Access Control)
The dominant real-world class. Default-deny; re-verify the authenticated principal **server-side**
on every object and function.
- **BOLA / IDOR:** object accessed by id without an ownership/tenant check.
- **BFLA:** privileged function callable by an under-privileged role (missing role gate).
- **BOPLA / mass-assignment:** request binds fields the user shouldn't set (inbound DTO allowlist;
  outbound response DTO to avoid over-exposure).
- **JWT:** hard-pin the expected `alg` (reject `none`/alg-confusion), allowlist `kid`/`jku`/`x5u`,
  verify `exp`/`nbf`/`iss`/`aud`, validate signature against a trusted key.
- **Sessions:** rotation on privilege change, idle/absolute expiry, secure/httponly/samesite cookies.
- **AuthN:** credential stuffing controls, secure password storage (see crypto), MFA bypass.

# 2a. Open redirect  — `open-redirect`  (CWE-601)
User-controlled URL used as a redirect target (`redirect(userInput)`, `Location:` header, `sendRedirect`).
- **Report as LOW** when the target is attacker-controlled (an absolute/external URL derived from user
  input) — a real phishing / OAuth-token-theft vector. Use the `open-redirect` category, NOT `AuthN/AuthZ`.
- **Not a finding** when the redirect is same-origin / relative-only, or validated against an allowlist
  of paths/hosts (see exclusion-rules).

# 3. Server-Side Request Forgery  — `ssrf`  (folded into A01:2025; treat first-class)
Server makes a request to a user-influenced URL/host.
- Host **allowlist** (not blocklist); resolve DNS once and pin the IP used.
- A host-allowlist check **immediately before the fetch is a sufficient mitigation — a guarded fetch is
  NOT a finding.** Only flag a fetch where no allowlist/validation gates the user URL before the request.
- Block RFC1918 / loopback / link-local / `169.254.169.254` (metadata) across **all encodings**
  (decimal, octal, hex, IPv6-mapped, `[::]`).
- Re-resolve and re-check **every redirect hop** (DNS rebinding).
- Prefer IMDSv2; never reflect raw user URLs into server-side fetchers.

# 4. Cryptography & secrets  — `crypto`  (A02:2025 Security Misconfiguration incl. crypto)
- **Hardcoded credentials / keys / tokens** in code, config, or history → category **`crypto`** (a
  secrets failure), NOT `config`.
- Weak algorithms: MD5/SHA1 for passwords (use argon2/bcrypt/scrypt); ECB; static IV/nonce.
- CSPRNG: use `secrets`/`crypto.randomBytes`/`SecureRandom`, never `random`/`Math.random` for tokens.
- TLS/cert validation disabled or hostname checks bypassed.
- Key storage/rotation; secrets in env not source; secrets never logged.

# 5. Insecure deserialization / RCE  — `deserialization`  (A08:2025 Software & Data Integrity)
Native deserialization of untrusted input → RCE.
- Python `pickle`/`yaml.load`(unsafe)/`torch.load`(without `weights_only`); Java
  `ObjectInputStream` without a filter, Jackson default typing; .NET `BinaryFormatter`; PHP
  `unserialize`; Ruby `Marshal.load`; Node `node-serialize`/unsafe `vm`.
- Rule: **never natively deserialize untrusted bytes** — use data-only formats with schema validation.

# 6. Cross-site scripting / output handling  — `xss`  (A03:2025 Injection)
Untrusted data rendered into a browser/markup context without context-correct escaping.
- Framework escape hatches: `dangerouslySetInnerHTML`, `v-html`, `innerHTML`/`outerHTML`,
  `bypassSecurityTrust*`, `Markup`/`|safe`, `document.write`.
- Sanitize with a vetted sanitizer (DOMPurify) for rich HTML; validate `href`/`src` schemes
  (block `javascript:`/`data:`); separate code from data in all output contexts.

# 7. Security configuration, headers & CORS  — `config`  (A02:2025 Security Misconfiguration)
- Headers: HSTS, CSP (nonce + `strict-dynamic`), `X-Content-Type-Options: nosniff`, COOP/COEP/CORP,
  frame-ancestors / `X-Frame-Options`.
- **CORS:** reflected-Origin with credentials, `*` with credentials, `null` origin allowed,
  unanchored regex origin match.
- Debug endpoints / verbose errors enabled in prod; default credentials; directory listing;
  permissive file permissions; dangerous framework defaults.

# 8. Supply chain  — `supply-chain`  (A03:2025 Software Supply Chain Failures — new in 2025)
- Lockfiles required and committed; pin transitive deps.
- Install-time lifecycle-script abuse (npm/pip postinstall) — prefer `npm ci --ignore-scripts`.
- Pin GitHub Actions to a **commit SHA**; pin container base images by **digest**.
- Typosquatting / dependency-confusion; verify signatures/provenance (SLSA, Sigstore) where available.
- **Environment-gated destructive sink** (geofencing / deadman-switch): a locale/TZ/region or token-response read GATING a `child_process`/`exec`/`rm -rf ~` sink — flag as a gate+sink CORRELATION, not a lone-sink HIGH (AISEC-SUPPLY-CHAIN-003; wh-5ox.8 deps-scan S6).
- The tool the agent *uses* must itself be pinned/verified (ADR-006).
- **Static-vs-EDR boundary:** runtime/host indicators (file-write-hash telemetry, live C2 DNS,
  `/proc/<pid>/mem` scraping) are OUT of static-source scope → route to a host/CI check, never claim
  as static coverage (see `sec-threat-model/SKILL.md` "Scope boundary"; ADR-024 egress-allowlist).

# 9. Error handling & exceptional conditions  — `error`  (A10:2025 Mishandling of Exceptional Conditions — new)
- **Fail-open:** auth/validation that defaults to allow on exception/timeout.
- Swallowed exceptions hiding security-relevant failures.
- Stack traces / internal detail leaked to clients (see also data-exposure).
- Inconsistent error paths that bypass checks.

# 10. Sensitive data exposure  — `data-exposure`  (A02:2025 / A04:2025)
- PII / secrets / tokens in logs, error messages, analytics, or responses.
- Over-broad API responses (return only what the caller may see).
- Sensitive data unencrypted at rest / in transit.
- Debug/admin endpoints exposing internals; verbose 500s.

# 11. Unrestricted resource consumption  — `resource`  (advisory-tier)
> Reported only with a concrete algorithmic-complexity or amplification impact — **not** as HIGH on
> its own (see `exclusion-rules.md`).
- Missing pagination / body / upload / array-size caps.
- GraphQL query depth/complexity limits.
- ReDoS (catastrophic-backtracking regex on user input); zip-bomb / decompression bombs.
- Unbounded recursion / loops / allocations driven by external input.

---

## How discovery uses this
Sweep each attack-surface partition against these categories; for every candidate record
`{file, line, category, source, sink, why-reachable}`. Keep recall high — report unproven
candidates flagged as such; triage decides severity and prunes false positives.
