# lang-typescript — TS/JS-specific sinks & secure patterns

> Loaded on demand when `SCAN-PLAN.json` lists `typescript`/`javascript`. Pattern-first; core
> categories in [`core-checklist.md`](core-checklist.md). CVE ids re-verified 2026-06-06
> (`docs/research/spike-04-phase2-cve-currency.md`) — they are evidence, the pattern is the lesson.

## Native capability tools (examples, swappable)
- **SCA:** `npm audit` / `pnpm audit` (native gate) → OSV-Scanner as fallback.
- **SAST:** Opengrep + `eslint-plugin-security` (advisory).
- Floor: Read/Grep/Glob + this file (`tool_assisted:false`).

## Framework version gates (SCA-style, check the manifest)
- **Next.js middleware authorization bypass — CVE-2025-29927.** A spoofed internal
  `x-middleware-subrequest` header skips middleware entirely, bypassing auth/authz done there.
  Fixed in **15.2.3** (also 14.2.25 / 13.5.9 / 12.3.5). If `next` < these, flag HIGH; mitigate by
  stripping the header at the proxy. Architectural note: don't make middleware your *only* authz
  layer — re-check authorization in the route/handler.
- **React2Shell — CVE-2025-55182** (React; **CVE-2025-66478** is the Next.js downstream tracker,
  *rejected as a duplicate* of -55182). Unsafe deserialization in the React Server Components
  "Flight" protocol → **unauthenticated RCE** (CVSS 10.0, exploited in the wild). Affects RSC / Next
  App Router. Patched Next.js: 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7. If the
  app uses RSC/App Router below a patched line, flag HIGH.

## Prototype pollution
Merging/assigning attacker-controlled keys into objects can poison `Object.prototype`.
```ts
// DANGEROUS — keys from untrusted JSON reach __proto__/constructor.prototype
function merge(dst, src) { for (const k in src) dst[k] = src[k]; }
merge({}, JSON.parse(req.body));

// SAFE — block dangerous keys, use a null-proto object / Map, freeze prototypes
if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
const safe = Object.create(null);
```
Library gates (check manifest): **lodash** `_.unset`/`_.omit` — **CVE-2025-13465** (≤4.17.22) and its
array-path bypass **CVE-2026-2950** (≤4.17.23); fixed **4.18.0**. **devalue** `parse`
prototype-pollution — **CVE-2025-57820**.

## Code-execution sinks
`eval`, `new Function(str)`, `vm.runInThisContext`, `vm.runInNewContext` on untrusted input are RCE.
The `vm` module is **not** a security sandbox. **`vm2` is abandoned** and must not be used as an
isolation boundary — use `isolated-vm` (or a real OS/container sandbox).

## Command injection
```ts
// DANGEROUS — shell parses interpolated input
import { exec } from "node:child_process";
exec(`convert ${userInput} out.png`);            // also: spawn(cmd, {shell:true})

// SAFE — argv array, shell:false (default for execFile/spawn)
import { execFile } from "node:child_process";
execFile("convert", [userFile, "out.png"]);
```

## XSS / output handling (framework sinks)
`dangerouslySetInnerHTML` (React), `v-html` (Vue), `[innerHTML]`/`bypassSecurityTrust*` (Angular),
`el.innerHTML =`, `document.write`. Render as text or sanitize with DOMPurify; validate `href`/`src`
schemes (block `javascript:`). Auto-escaped output **without** a raw-HTML hatch is exclusion-listed —
don't report it.

## What to grep for
`next` version in `package.json` · `x-middleware-subrequest` · RSC/App Router usage with old `next` ·
`for (const k in` / `Object.assign(target, userInput)` / `__proto__` · `lodash` `.unset`/`.omit` +
version · `eval(` / `new Function(` / `vm2` · `exec(\`` / `shell: true` · `dangerouslySetInnerHTML` /
`v-html` / `.innerHTML =` · `verify`/TLS disabled in fetch agents.

## Deprecated
<details><summary>Legacy guidance (do not apply as current)</summary>

- `vm2` was once recommended as a JS sandbox; it is **abandoned** and broken — never cite it as a
  fix. Use `isolated-vm` or OS-level isolation instead.
</details>
