# API security appendix — OWASP API Security Top 10 (2023)

> Loaded on demand when `sec-detect` finds a web/back-end framework (`reference_appendices`
> includes `api.md`). Complements `core-checklist.md` — this file is the **API-shaped** view of
> authorization, consumption, and third-party trust. Pattern-first (dangerous → safe). ≤400 lines.
>
> **Edition caveat (load-bearing).** The current OWASP **API Security Top 10 is the 2023 edition**
> — a separate OWASP project from the web Top 10, on its own cycle. **No 2025 or 2026 API edition
> has shipped.** **Distrust** any blog or checklist titled "API Top 10 2026" / "2025" — they restate
> the **2023** list. IDs below are therefore `APIx:2023`. (The web Top 10 *did* refresh to 2025; for
> web-layer categories see `core-checklist.md`. SSRF lives in `core-checklist.md` §3 — **don't
> duplicate it here**; API7:2023 just cross-links it.)
>
> **The one check that catches most API bugs:** every object and every function access must
> **re-verify the authenticated principal server-side, scoped by owner/tenant, default-deny.**
> Authorization (authZ — *who may touch this object/function*) is distinct from authentication
> (authN — *who are you*, API2): a logged-in user is not an authorized one.

Category tags: `AuthN/AuthZ` `data-exposure` `resource` `ssrf` `config` `supply-chain`.

---

# API1:2023 — Broken Object Level Authorization (BOLA / IDOR)  — `AuthN/AuthZ`
The #1 API risk. An endpoint takes an object id (path / query / body / GraphQL node) and acts on
it **without checking the caller owns or may access that object**.
- **Dangerous:** `GET /orders/{id}` → `db.orders.find(id)` returning the row to anyone logged in;
  trusting a client-supplied `userId`/`tenantId`/`accountId` from the request to scope the query.
- **Safe:** re-derive the principal from the session/token server-side and scope the lookup to it —
  `where id = :id AND owner_id = :session_user` (or the ORM/tenant filter). Default-deny.
- Unguessable ids (UUIDs) are **not** an access control — still authorize.
- Multi-tenant: the tenant scope belongs in the `WHERE`/ORM filter, never inferred from input.
- GraphQL: enforce **per-node** authorization in resolvers (introspection enumerates the graph).

# API2:2023 — Broken Authentication  — `AuthN/AuthZ`
Weaknesses in *proving identity* (distinct from authZ above). See `core-checklist.md` §2 for the
full JWT/session detail; the API-specific high-signal checks:
- **JWT:** hard-pin the expected `alg` (reject `alg:none` and RS256→HS256 confusion); allowlist
  `kid`/`jku`/`x5u` (never use them raw in DB/path/URL); validate `exp`/`iss`/`aud`/`nbf`.
- Credential-stuffing / brute-force protection on login, token, OTP, and password-reset endpoints.
- OAuth2/OIDC: `state` + PKCE present; redirect URIs **exact-match** allowlisted; tokens never in
  URLs/logs. Tokens short-lived with revocation/rotation.

# API3:2023 — Broken Object Property Level Authorization (BOPLA)  — `AuthN/AuthZ` `data-exposure`
Authorization at the **property** level — check **both directions**; easy to miss because nothing
looks "missing" in the code.
- **Inbound (mass assignment):** request bodies auto-bound to ORM/domain models let a caller set
  fields they shouldn't (`role`, `isAdmin`, `balance`, `verified`, `email_verified`).
  - **Safe:** bind to an explicit **DTO / field allowlist**; never `Model(**request.json)` /
    `Object.assign(entity, req.body)` / `@ModelAttribute` over the whole entity.
- **Outbound (excessive data exposure):** returning the whole record leaks props the caller may not
  see (password hashes, tokens, internal ids, other-tenant PII).
  - **Safe:** serialize through an explicit response DTO / view model — not `return user`. GraphQL:
    field-level authorization.

# API4:2023 — Unrestricted Resource Consumption  — `resource`
No limits → cost/DoS (and amplifies wallet-drain on metered upstreams). Advisory-tier severity
unless a concrete amplification/complexity impact is shown (`exclusion-rules.md`).
- Rate-limit / throttle per user + IP + API key on auth, search, and expensive endpoints.
- Enforce pagination with a **max page size**; reject client-controlled unbounded `limit`.
- Cap request-body size, file-upload size, array/batch length, and GraphQL query depth/complexity.
- Timeouts on resource-intensive ops (regex → ReDoS, image/PDF/export, zip/XML bombs).

# API5:2023 — Broken Function Level Authorization (BFLA)  — `AuthN/AuthZ`
A privileged **function/route** is callable by an under-privileged role (missing role/permission
gate) — the function-level twin of BOLA.
- **Dangerous:** guarding the `GET` but not the `PUT`/`PATCH`/`DELETE` sibling; hidden admin paths
  relying on obscurity; admin verbs reachable without a role check.
- **Safe:** **default-deny** — a new route is inaccessible unless explicitly granted a role; check
  *role/permission*, not merely "is authenticated"; treat every HTTP verb as a distinct function.

# API6:2023 — Unrestricted Access to Sensitive Business Flows  — `resource`
Business logic abused via automation even when each request is individually authorized
(bulk signup, purchase/scalping, coupon/referral farming, OTP/SMS pumping).
- Identify the flow's business cost; add anti-automation proportionate to it (CAPTCHA, device
  fingerprint, behavioral/velocity checks, per-account quotas) — not just generic rate limits.

# API7:2023 — Server Side Request Forgery (SSRF)  — `ssrf`
The server fetches a user-influenced URL/host. **Cross-links `core-checklist.md` §3 — do not
duplicate the detection detail.** API-context entry points: webhooks, image/PDF proxies,
import-from-URL, SSO/OIDC metadata fetch. (In the web Top 10:2025 SSRF folded into A01; still
first-class.) Core rule: host **allowlist**, pin resolved IP, block metadata `169.254.169.254` in
all encodings, re-resolve every redirect hop.

# API8:2023 — Security Misconfiguration  — `config`
See `core-checklist.md` §7 for headers/CORS. API-specific:
- Verbose errors / stack traces returned to clients; debug routes live in prod; default creds.
- Missing/misconfigured CORS on credentialed APIs (reflected `Origin` + `Allow-Credentials:true`,
  `*` with credentials, allowed `null` origin, unanchored origin regex).
- Unnecessary HTTP methods enabled; TLS not enforced; permissive object-storage/bucket policy.

# API9:2023 — Improper Inventory Management  — `config` `data-exposure`
Shadow / zombie / deprecated endpoints widen the surface.
- All API versions + hosts inventoried; `/v1`, `/test`, `/internal`, `/debug`, beta endpoints
  retired or access-controlled; non-prod environments not internet-exposed with prod data.
- Documentation reflects what's actually deployed (undocumented endpoints are unguarded ones).

# API10:2023 — Unsafe Consumption of APIs  — `supply-chain` `data-exposure`
Trusting **third-party API responses** more than user input.
- **Dangerous:** piping an upstream/partner response straight into a sink (DB, HTML, exec, file
  path) or following its redirects blindly.
- **Safe:** validate/sanitize third-party data like user input; verify TLS; set timeouts; don't
  follow arbitrary redirects to unvalidated hosts; isolate the integration's blast radius.

---

## How discovery / triage uses this
For an API endpoint, walk **API1 → API10** as the partition checklist. The highest-yield finds are
the authorization trio (**BOLA / BFLA / BOPLA**) — for each object- or function-touching handler,
ask: *is the authenticated principal re-verified server-side, scoped to owner/tenant, default-deny?*
Record `{file, line, category, source, sink, why-reachable}` and map to the `APIx:2023` id for the
report. Severity is decided in triage (`severity-rubric.md`), never here.
