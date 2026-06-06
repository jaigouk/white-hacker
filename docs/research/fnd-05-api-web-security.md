# research:api-web-security

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:api-web-security`

## API & Web Application Security Review Checklists (current as of June 2026)

### Standards baseline: what's current in 2026

Two distinct OWASP standards anchor a 2026 review, with different update cadences:

| Standard | Current edition | Status (2026) |
|---|---|---|
| **OWASP Top 10** (web apps) | **2025** | Announced Nov 2025 at Global AppSec DC; finalized early 2026. Use this, not 2021. |
| **OWASP API Security Top 10** | **2023** | Still current — a separate project with its own cycle; **no 2025/2026 edition has shipped**. Beware blog posts titled "API Top 10 2026" — they restate the 2023 list. |

**OWASP Top 10:2025 list** ([owasp.org/Top10/2025](https://owasp.org/Top10/2025/)): A01 Broken Access Control · A02 Security Misconfiguration · A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Security Logging and Alerting Failures · A10 Mishandling of Exceptional Conditions.

**Key 2021→2025 deltas a reviewer must internalize** ([equixly](https://equixly.com/blog/2025/12/01/owasp-top-10-2025-vs-2021/), [gitlab](https://about.gitlab.com/blog/2025-owasp-top-10-whats-changed-and-why-it-matters/)):
- **SSRF is no longer its own category** — folded into **A01 Broken Access Control**. Still review it as a first-class check.
- **Vulnerable & Outdated Components → A03 Software Supply Chain Failures** (broadened to build/CI-CD/artifact provenance, not just CVE-tracked deps).
- **A10 Mishandling of Exceptional Conditions** is **new** (24 CWEs: improper error handling, "fail open" logic, swallowed exceptions).
- **Security Misconfiguration jumped #5→#2**; Crypto #2→#4; Injection #3→#5 (XSS lives here); Insecure Design #4→#6.

**API Top 10 2023** ([owasp.org/API-Security](https://owasp.org/API-Security/)): API1 BOLA · API2 Broken Authentication · API3 BOPLA · API4 Unrestricted Resource Consumption · API5 BFLA · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8 Security Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs.

---

### Per-category review checklist (language-agnostic)

**1. Broken Object-Level Authorization / IDOR (API1, A01)**
- [ ] Every endpoint taking an object ID (path, query, body, GraphQL node) re-checks that the *authenticated principal* owns/may access that object — not just "is logged in."
- [ ] Authorization happens server-side at the data layer, never inferred from a client-supplied `userId`/`tenantId` in the request.
- [ ] No reliance on unguessable IDs (UUIDs) as the *only* control.
- [ ] Multi-tenant queries are always scoped by tenant in the WHERE clause / ORM filter.
- [ ] GraphQL resolvers enforce per-node authorization (introspection lets attackers enumerate the schema).

**2. Broken Function-Level Authorization (API5)**
- [ ] Admin/privileged routes verify *role*, not just authentication; check for missing guards on `PUT/DELETE/PATCH` variants of a readable `GET`.
- [ ] Default-deny: new routes are inaccessible unless explicitly granted.
- [ ] No authorization-by-obscurity (hidden admin paths, undocumented HTTP verbs).

**3. Broken Authentication (API2, A07)**
- JWT pitfalls ([PortSwigger](https://portswigger.net/web-security/jwt), [pentesterlab](https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide)):
  - [ ] Verification **hard-codes the expected algorithm** (e.g. `['RS256']`); never trusts `alg` from the token header — blocks `alg:none` and **RS256→HS256 confusion** (public key used as HMAC secret).
  - [ ] `kid`/`jku`/`x5u` header params are allowlisted, never used directly in DB queries, file paths, or URL fetches (kid injection → SQLi/SSRF/path traversal).
  - [ ] HMAC secrets ≥ 32 random bytes (crack-resistance).
  - [ ] `exp`, `iss`, `aud`, `nbf` are validated; tokens are short-lived; revocation/rotation exists.
- General: [ ] Password hashing uses bcrypt/scrypt/argon2 (not MD5/SHA). [ ] Brute-force/credential-stuffing protection on login, MFA, password reset. [ ] OAuth2/OIDC: `state` (CSRF) and PKCE present; redirect URIs strictly allowlisted (no open redirect / wildcard); `nonce` validated; tokens not leaked in URLs/logs. [ ] Session cookies are `HttpOnly`, `Secure`, `SameSite`; session fixation prevented (rotate ID on login); logout invalidates server-side.

**4. BOPLA — Mass Assignment + Excessive Data Exposure (API3)** ([apisec](https://www.apisec.ai/blog/understanding-broken-object-property-level-authorization-bopla-prevent-mass-assignment-and-excessive-data-exposure), [OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)):
- [ ] **Inbound (mass assignment):** request bodies are not auto-bound to ORM/domain models. Use DTOs / explicit field **allowlists**; sensitive props (`role`, `isAdmin`, `balance`, `verified`) are never settable from request input.
- [ ] **Outbound (excessive exposure):** responses are serialized via explicit DTOs/view models, not `return user`. No password hashes, tokens, internal IDs, PII leaked. GraphQL enforces field-level authorization.
- [ ] Hard to spot in review — check *both directions* on every model-backed endpoint.

**5. Unrestricted Resource Consumption + Rate Limiting (API4, API6)**
- [ ] Rate limiting / throttling per user, IP, and API key on auth, search, and expensive endpoints.
- [ ] Pagination enforced with max page size; no client-controlled unbounded `limit`.
- [ ] Caps on request body size, file upload size, array/batch lengths, GraphQL query depth/complexity.
- [ ] Resource-intensive ops (regex, image/PDF processing, exports) have timeouts; protections against ReDoS and zip/XML bombs.
- [ ] Sensitive business flows (signup, purchase, coupon, OTP) have anti-automation (CAPTCHA, device/behavioral checks) — **API6**.

**6. SSRF (API7; under A01 in 2025)** ([OWASP SSRF cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)):
- [ ] Any feature fetching a user-supplied URL/host (webhooks, image proxy, PDF render, import-from-URL, SSO metadata) uses a **strict allowlist** of hostnames/domains.
- [ ] Resolve hostname to IP **at request time** and verify it's in-allowlist / not in private ranges (RFC1918, loopback, link-local) — re-resolve **on every redirect hop** to defeat **DNS rebinding**.
- [ ] Block cloud metadata `169.254.169.254` (and IPv6 `fd00:ec2::254`) including decimal/hex/octal encodings; enforce **IMDSv2** (session tokens, hop limit) and deny-by-default egress (K8s NetworkPolicy).
- [ ] Disable unused URL schemes (`file://`, `gopher://`, `dict://`); don't echo raw upstream response/errors to the client.

**7. Injection (A05)**
- [ ] SQL/NoSQL via parameterized queries / prepared statements / ORM bindings — never string concatenation.
- [ ] OS command exec avoids shell; uses arg arrays + allowlists. No `eval`/dynamic code on user input.
- [ ] Output encoding contextual for XSS (HTML/attr/JS/URL); templating auto-escaping not disabled (`| safe`, `dangerouslySetInnerHTML`, `v-html`).
- [ ] LDAP, XPath, header/CRLF, template (SSTI), and ORM-injection sinks reviewed.

**8. Security Misconfiguration (A02, API8) & Headers/CSP**
- [ ] Debug/verbose errors & stack traces off in prod; default creds removed; admin consoles not exposed.
- [ ] Security headers present ([OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/), [CSP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)): **HSTS** (long max-age + preload), **CSP** (prefer **nonce + `strict-dynamic`** over `unsafe-inline`/wildcards), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and the cross-origin trio **COOP/COEP/CORP**.
- [ ] TLS only; secure cookie flags; directory listing off; cloud storage buckets not public.

**9. CORS misconfiguration** ([PortSwigger CORS](https://portswigger.net/web-security/cors), [Intigriti](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities)):
- [ ] **Never reflect arbitrary `Origin` + `Access-Control-Allow-Credentials: true`** (equivalent to disabling same-origin policy).
- [ ] No `Access-Control-Allow-Origin: *` on credentialed/authenticated APIs.
- [ ] `null` origin never allowed (reachable from sandboxed iframes / `data:`).
- [ ] Origin allowlist uses exact match — regexes escape `.` and anchor (`^…$`) to stop `evil-yoursite.com` / `yoursite.com.evil.com` bypasses.

**10. Insecure Deserialization & Software/Data Integrity (A08)** ([OWASP](https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization)):
- [ ] No native deserialization of untrusted input (Java `readObject`, Python `pickle`/`yaml.load`, PHP `unserialize`, .NET `BinaryFormatter`) — prefer JSON with schema validation.
- [ ] If unavoidable: type allowlists / look-ahead deserialization; integrity-check (signatures) serialized blobs.
- [ ] Auto-updates/plugins/CI artifacts verify signatures (supply-chain integrity, ties to A03).

**11. File upload** ([OWASP File Upload cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)):
- [ ] Validate by **magic-byte/content signature**, not just extension or client `Content-Type` (trivially spoofed) — watch for **polyglots**.
- [ ] Allowlist extensions; generate server-side random filenames; strip path components (no traversal).
- [ ] Store **outside webroot** / in object storage; serve with forced `Content-Disposition: attachment` + `nosniff`; never execute uploads.
- [ ] Enforce size limits; AV/CDR scanning; re-encode images to strip embedded payloads.

**12. Mishandling of Exceptional Conditions (A10, new 2025)**
- [ ] No "fail open" — auth/authz errors deny by default.
- [ ] Exceptions are not silently swallowed; errors don't leak internals to clients.
- [ ] Resource cleanup (connections, locks, temp files) in finally/defer; timeouts on all external calls.

**13. Supply chain (A03), inventory (API9), unsafe consumption (API10), logging (A09)**
- [ ] Dependencies pinned + SCA-scanned; lockfiles committed; SBOM available; CI/CD secrets and build steps reviewed.
- [ ] All API versions/hosts inventoried; deprecated/`/test`/`/v1` endpoints retired (API9).
- [ ] Third-party API responses validated/sanitized like user input; TLS verified; timeouts set (API10).
- [ ] Security events (authn, authz failures, privilege changes) logged without secrets/PII; logs tamper-resistant and monitored/alerted (A09).


## Key takeaways

- Use OWASP Top 10:2025 (finalized early 2026) for web apps, but keep OWASP API Security Top 10 2023 for APIs — the API project has NOT shipped a 2025/2026 edition, so distrust blog posts claiming an 'API Top 10 2026'.
- In the 2025 web list, SSRF was merged into A01 Broken Access Control and 'Vulnerable & Outdated Components' became A03 Software Supply Chain Failures; an agent should still run SSRF and dependency checks as first-class items regardless of category labels.
- Two genuinely new 2025 categories matter for any-language review: A03 Software Supply Chain Failures (CI/CD, build, artifact provenance) and A10 Mishandling of Exceptional Conditions (fail-open logic, swallowed exceptions, error leakage).
- Authorization is the dominant risk class across both standards (BOLA/IDOR, BFLA, BOPLA, A01) — the highest-value generic check is: every object/function access re-verifies the authenticated principal's permission server-side, scoped by owner/tenant, default-deny.
- JWT review is language-agnostic and high-signal: enforce a hard-coded expected algorithm (kills alg:none and RS256→HS256 confusion), allowlist kid/jku/x5u, require strong secrets, and validate exp/iss/aud.
- BOPLA/mass-assignment must be checked in BOTH directions — inbound (DTO/field allowlist, never auto-bind to models) and outbound (explicit response DTOs, no over-exposure) — and it's easy to miss in review because nothing looks 'missing'.
- SSRF defense is now cloud-centric: allowlist hosts, re-resolve DNS each redirect hop (DNS rebinding), block 169.254.169.254 in all encodings + IPv6, and enforce IMDSv2 / default-deny egress.
- CORS is a frequent, mechanical finding: flag reflected-Origin + Allow-Credentials:true, wildcard on credentialed APIs, allowed null origin, and unescaped/unanchored origin regexes.
- Security Misconfiguration rose to #2 in 2025 — a generic agent should check security headers (HSTS, CSP with nonce+strict-dynamic, nosniff, COOP/COEP/CORP), disabled debug/verbose errors, and removed default creds on every project type.
- Resource-consumption checks (rate limiting, pagination caps, body/upload/array size limits, GraphQL depth/complexity, ReDoS/zip-bomb guards) apply to backend and AI/LLM services alike and map to API4/API6.
- File-upload and deserialization checks are framework-agnostic: validate by magic bytes not Content-Type/extension, store outside webroot, never execute uploads; and never natively deserialize untrusted input (pickle/yaml.load/readObject/BinaryFormatter).
- For an agent spanning TS/Go/Python/Java and backend/frontend/AI, structure findings around root-cause categories (authz, authn, input handling, SSRF, config/headers, supply chain, error handling) rather than language-specific sinks, then map to the specific 2025/2023 OWASP IDs for reporting.

## Sources

- https://owasp.org/Top10/2025/
- https://owasp.org/Top10/2025/0x00_2025-Introduction/
- https://owasp.org/www-project-top-ten/
- https://owasp.org/API-Security/
- https://equixly.com/blog/2025/12/01/owasp-top-10-2025-vs-2021/
- https://about.gitlab.com/blog/2025-owasp-top-10-whats-changed-and-why-it-matters/
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://portswigger.net/web-security/jwt
- https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide
- https://www.apisec.ai/blog/understanding-broken-object-property-level-authorization-bopla-prevent-mass-assignment-and-excessive-data-exposure
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://portswigger.net/web-security/cors
- https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities
- https://owasp.org/www-project-secure-headers/
- https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/

