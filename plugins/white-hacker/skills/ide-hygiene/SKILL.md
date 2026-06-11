---
name: ide-hygiene
description: >
  Floor scan of the developer's HOST-LEVEL editor extensions — a blind spot for
  dependency-level SCA (deps-scan), since an editor extension is not a project
  dependency. Enumerates installed extensions (editor CLI, on-disk fallback),
  pin/verifies (publisher, name, version) against the watchlist `extension` block,
  and greps each activation entry for the two-tier trojan shape (env-credential
  probe + second-stage fetch-and-exec). Offline, stdlib-only; degrades clean when
  no editor is present.
when_to_use: >
  During discovery on a dev workstation review (or a supply-chain / IDE-compromise
  threat model — the Nx-Console / TeamPCP / "Carnage" trojanized-extension class).
  Run alongside deps-scan: deps-scan covers project dependencies, ide-hygiene covers
  the editor's own extensions. Not for project source files (that is the other
  scanners) and not a confirmed-compromise verdict — it emits triage candidates only.
---

# ide-hygiene — editor-extension hygiene floor (pin/verify + activation grep)

Find a **trojanized editor extension** behind the **ide-hygiene capability** — never a hard
dependency on one editor (ADR-015). A malicious extension (the Nx-Console / TeamPCP /
"Carnage" class) ships a valid marketplace version, installs without error, and runs
arbitrary code on `activate`. None of that is visible to `deps-scan`: an editor extension
is **not a project dependency** — it lives **host-level** under the user's editor profile,
outside any scanned repo. `scripts/ext_scan.py` is the floor that covers that gap. It is
**offline** (zero network), **static** (reads only on-disk manifests + activation entries),
emits **low/medium/high-confidence `tool_assisted:false`** candidates, and — like every
floor stage — **NEVER blocks**. Triage + a human decide.

> Writes findings merged into `VULN-FINDINGS.json` (the same finding-schema contract as
> every other stage). The DATA — *which* extensions are bad — is the **watchlist
> `extension` block** (wh-k6l populates the rows); this skill is the **mechanism** and
> hardcodes no specific package name/version.

## The three tiers (best signal first, then degrade)
1. **Enumerate** installed extensions — the **editor CLI** when present
   (`code --list-extensions --show-versions` → `publisher.name@version` lines), else the
   **on-disk fallback** `~/.vscode/extensions/*/package.json` (VS Code's documented per-user
   layout). The manifest is authoritative; the folder name (`publisher.name-version`) fills
   any missing field. A dir whose manifest is unparseable is skipped (its metadata can't be
   trusted for pin/verify). Pure stdlib; **NEVER raises**.
2. **Pin/verify** — `ext_scan.scan(watchlist=...)` matches each `(publisher.name, version)`
   against the watchlist `extension` rows (`watchlist-entry-schema.json:57-70`:
   `marketplace`/`id`/`bad_versions`). An explicit `bad_versions` list → exactly those
   versions are bad; an empty/absent list → the whole-extension wildcard `"*"` (any
   installed version). Match is **version-AWARE and EXACT** — a watchlisted extension at a
   *different* version is NOT flagged (never a Python substring, which would re-admit a
   false positive). → **HIGH** candidate, category `ide-extension`.
3. **Activation-code grep** (the tier the spec omits) — read each extension's activation
   entry (`extension.js` / `out/extension.js` / …, byte-capped) and flag the **two-tier
   trojan shape**: a **Tier A env-credential probe** (`process.env.*TOKEN/SECRET/KEY/…`,
   `~/.aws`/`~/.ssh`/`~/.npmrc`/`~/.claude`) **AND** a **Tier B second-stage fetch-and-exec**
   (`fetch(...) … eval` incl. the `.then(eval)` callback idiom, `eval(await fetch())`,
   `child_process` of an `https?://` payload). **One tier alone is benign** (an extension
   legitimately reads env or fetches; the *combination* is the tell). → **MEDIUM**
   candidate, category `ide-extension-activation`. Lower confidence than a watchlist match —
   it is a heuristic, not a confirmed match.

Selection is keyed off the watchlist + the on-disk layout; the editor is swappable, the
three-tier ladder is the contract.

## Host-level finding locator (the design wrinkle)
`finding-schema.json` `file` is guarded `^[^/~]` — review output is committed to a **public**
repo, so an absolute / `~` path would **leak the host's machine layout** AND fails schema
validation. An extension lives **outside** the scanned repo, so it has **no repo-relative
path**. The locator is therefore the stable **marketplace identifier**
`ext:<publisher>.<name>@<version>` (e.g. `ext:acme.trojan-lint@9.9.9`): it is the canonical
id of the finding, passes `^[^/~]`, and carries **no host path**. The on-disk directory is
used only to READ the manifest/activation file — it is **NEVER emitted**.

## Degrade-clean (ADR-003 — mirrors deps-scan S8 `malware-db`)
No editor CLI reachable AND no on-disk extensions dir → record **`ide-hygiene`** in
`summary.tools_unavailable`, emit **zero findings**, **NEVER raise / block**. A
present-but-empty editor is NOT "unavailable". `watchlist=None`/`[]` → the pin/verify tier
finds nothing (DATA is wh-k6l's job); the activation grep still runs. Always
`tool_assisted:false` (this is the floor); confidence capped via
`degradation.cap_floor_confidence`. Rule 5: every function is a deterministic pure function —
no LLM, no RNG, no network.

```bash
# run the floor against an extensions dir (offline) and validate the candidates
cd plugins/white-hacker/skills/ide-hygiene/scripts
uv run --with jsonschema python -c "import sys; sys.path[:0]=['.','../../_shared/scripts']; \
  import json, ext_scan, validate_findings as vf; \
  d=ext_scan.scan(watchlist=[]); print(vf.validate(d)); print(json.dumps(d['summary'], indent=2))"
```

## This skill hosts a second arm later (leave room)
wh-5ox.3 adds `config_persist_scan.py` (IDE/agent config-persistence: `tasks.json`
`folderOpen` autorun, `.claude` `SessionStart`) to this same skill dir, behind the same
ide-hygiene capability. Keep `ext_scan.py` self-contained so the two arms compose.

## Verification criteria (definition of done)
- [x] `scripts/ext_scan.py` enumerates extensions (editor CLI → on-disk
  `~/.vscode/extensions/*/package.json` fallback), pure stdlib, never raises
  (`tests/test_ext_scan.py::test_enumerate_*`).
- [x] Pin/verify against the watchlist `extension` block: a bad-version match → a HIGH
  `ide-extension` finding; a good/clean version → NO finding; wildcard `bad_versions:[]` →
  any installed version flagged; an unrelated/empty watchlist → nothing (both directions,
  Policy 9). No package name/version hardcoded (do-not-copy gate).
- [x] Activation-grep tier: env-cred-probe + fetch-and-exec → a MEDIUM
  `ide-extension-activation` candidate; a benign entry OR a single tier alone → nothing.
- [x] No editor present → `ide-hygiene` in `summary.tools_unavailable`, zero findings,
  never raises (deps-scan S8 degrade mirror).
- [x] Every emitted `file`/`first_link` is the `ext:` identifier and passes `^[^/~]` (no
  absolute/`~`/`/Users`/`/home`); every emitted doc is schema-valid
  (`validate_findings.validate(doc) == []`).

Gate commands:
```bash
uv run --project plugins/white-hacker/skills/ide-hygiene/scripts \
  --with jsonschema --with pytest pytest plugins/white-hacker/skills/ide-hygiene/scripts/tests -q
uv run python packaging/validate_manifest.py .
```
