# Loading the white-hacker plugin — developer & dogfood guide

How to make the shipped plugin (`plugins/white-hacker/`) actually load so that
`subagent_type: white-hacker` resolves, `/white-hacker:security-review` is available, and the
in-wave **dogfood** / **wh-sml** hook live-test can run. There are two load methods and they
differ in one way that matters for development: **live vs snapshot.**

> Verified 2026-06-12 against Claude Code 2.1.78. Plugin install/cache semantics are
> version-specific — re-verify if the `claude plugin` CLI behaviour changes. Companion to
> `README.md` § Install & onboarding and `docs/ARCHITECTURE.md` §8 (Distribution).

## TL;DR

| Method | Works on | Picks up working-tree edits? | Use it for |
|--------|----------|------------------------------|------------|
| **A. `--plugin-dir`** | CLI only | **Yes — live** (on session restart) | iterating on the plugin's own code |
| **B. local-marketplace install** | CLI **and** the desktop app | **No — snapshot copy** (needs a refresh) | running a stable build; the desktop app |

Why this matters: the `white-hacker` subagent is **plugin-scope, the lowest precedence**
(ADR-029). If neither method has loaded it, it is simply absent from the agent registry — the
dogfood then cannot run and must be reported **DEFERRED**, never silently skipped (Policy 12).

The team-mode flag is independent of both methods: set
`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` (shell, or the `env` block in `settings.json`) to
enable `SendMessage` between teammates — see `docs/team-mode.md`.

## Option A — `--plugin-dir` (live; CLI; recommended for development)

```bash
claude --plugin-dir ./plugins/white-hacker
```

Loads the plugin straight from the working tree. There is no hot reload — **restart the session**
to pick up edits — but no copy and no extra step: the next session runs your latest code. This is
how the repo dogfoods its own agent (`README.md` § Dev / dogfood loop). **CLI only — the desktop
app has no `--plugin-dir` equivalent.**

## Option B — local-marketplace install (works in the desktop app; snapshot)

The desktop app's **Code** tab runs the same engine and reads the same `.claude/settings.json` /
`.claude/settings.local.json`, but it has **no `--plugin-dir` flag**. Load the plugin through this
repo's bundled local marketplace (`.claude-plugin/marketplace.json` → marketplace
`white-hacker-marketplace`, plugin `white-hacker`):

```bash
# from the repo root:
claude plugin marketplace add "$(pwd)" --scope local
claude plugin install white-hacker@white-hacker-marketplace --scope local
claude plugin list        # verify: white-hacker → enabled
```

Then open this project in the desktop **Code** tab — the plugin is loaded.

Notes:
- **A bare `.` is rejected** (`Invalid marketplace source format. Try: owner/repo, https://…, or
  ./path`). Pass an absolute path; `"$(pwd)"` from the repo root is the machine-agnostic form.
- **`--scope`** chooses where the registration is declared: `user` (global
  `~/.claude/settings.json`), `project` (`.claude/settings.json`), or `local`
  (`.claude/settings.local.json`). **In this repo both project and local settings files are
  gitignored** (see `.gitignore`), so the absolute local-path marketplace source written into them
  does **not** leak into the public repo. `local` is the idiomatic scope for a machine-specific
  local-path registration.

### The catch: a marketplace install is a SNAPSHOT, not a live link

`claude plugin install` **copies** the whole payload into Claude Code's version-keyed plugin cache
(`~/.claude/plugins/cache/<marketplace>/white-hacker/<version>/`). It is a copy of the source taken
at install time — the cached files are distinct from the working tree (different inodes), not a
symlink or reference. Consequences:

- **Editing `plugins/white-hacker/` does not change what the installed plugin runs.**
- The cache is keyed by the `plugin.json` `version`, so `claude plugin update` may be a **no-op if
  the version string is unchanged**. To pull edits in, either:
  - bump `version` in `plugins/white-hacker/.claude-plugin/plugin.json`, then
    `claude plugin update white-hacker`; **or**
  - `claude plugin uninstall …` + `claude plugin install …` to force a fresh copy.

For this reason, **prefer Option A (`--plugin-dir`) while actively developing the plugin**, and use
Option B for running a stable build or when you specifically need the desktop app.

## Which do I need, when?

| Situation | Method |
|-----------|--------|
| Iterating on the plugin's own code (skills, hooks, agent) | **A** — `--plugin-dir` (sees edits on restart) |
| In-wave dogfood / `wh-sml` hook live-test of **in-flight** code | **A** — so the reviewer sees the latest source |
| Running white-hacker on *other* code while you work | **B** — or A |
| Desktop app (**Code** tab) | **B** only (no `--plugin-dir` there) |

Both can coexist: the desktop app reads the Option-B install; a CLI session can still use
`--plugin-dir`. They do not conflict.

## Uninstall / undo (Option B)

```bash
claude plugin uninstall white-hacker@white-hacker-marketplace
claude plugin marketplace remove white-hacker-marketplace
```

This reverts the `extraKnownMarketplaces` + `enabledPlugins` entries in `.claude/settings.local.json`.
The cached copy under `~/.claude/plugins/cache/` can be left in place or removed.

## References

- `README.md` § Install & onboarding (the `install.sh` vendor lane + local plugin registration),
  § Dev / dogfood loop
- `docs/ARCHITECTURE.md` §8 — Distribution (dev-vs-payload split; one definition, three carriers)
- `docs/team-mode.md` — the `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` teammate mode
- `docs/ARD.md` — ADR-017 (plugin mechanism: manifest, namespacing, dev-vs-payload),
  ADR-028 (manual install / local registration is the current distribution),
  ADR-029 (one white-hacker; `--plugin-dir` is the dogfood path; plugin-scope = lowest precedence)
