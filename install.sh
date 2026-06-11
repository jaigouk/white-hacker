#!/usr/bin/env bash
# white-hacker installer — pinned + verified, curl|bash-safe, run from your target project.
#
#   curl -fsSL https://raw.githubusercontent.com/jaigouk/white-hacker/HEAD/install.sh | bash
#   # review first (recommended): download, read, then run.
#
# Lanes:
#   (default) --vendor  copy the pinned payload into THIS project's .claude/ — self-contained,
#                       committed, CI-runnable, no per-user plugin install. Re-run at a new tag to refresh.
#   --plugin            install via the Claude Code plugin marketplace (ADR-017) — auto-updates with
#                       `claude plugin update`, identity canonical, shared across your projects.
#
# Version: defaults to the LATEST RELEASE TAG (override with WH_REF=<tag|sha> or --ref <tag>).
# Platform: macOS or Linux (any arch). Detects the host; refuses elsewhere.
# Python: white-hacker's skills are STDLIB-ONLY and run via `uv run --project` in ISOLATED venvs —
#         NO Python packages are installed into your project. The only runtime prereq is `uv`; if it's
#         absent the installer installs it (PINNED, via the cross-platform astral installer) and
#         provisions Python. uv injects test deps (jsonschema/pytest) ephemerally via `uv run --with`.
# Security (ADR-006 — the agent that scans supply chains must not be a supply-chain victim):
#         pins a tag, verifies a GPG-signed tag when present, and fetches NOTHING unpinned.
#
# The whole body lives in functions; main() runs on the LAST line, so a truncated `curl|bash`
# download defines functions but executes nothing.
set -euo pipefail

WH_REPO="${WH_REPO:-https://github.com/jaigouk/white-hacker}"
WH_SLUG="${WH_SLUG:-jaigouk/white-hacker}"
WH_MARKETPLACE="white-hacker-marketplace"
WH_PLUGIN="white-hacker"
# Fail-CLOSED vendor manifest: the consumer/inner-loop skills shipped into a target (ADR-022). A new
# skill is excluded by default until added here. EXCLUDED: sec-learn, sec-kb-refresh (outer-loop
# producers — they edit the KB behind the eval keep-or-revert gate, dev-repo only). Keep this list in
# sync with CONSUMER_SKILLS in install/scrub_vendored.py.
WH_VENDOR_SKILLS="_shared ai-attack-kb ai-llm-review deps-scan sec-detect sec-init sec-patch sec-policy sec-report sec-threat-model sec-triage sec-vuln-scan secrets-scan"

LANE="vendor"; DRYRUN=0; UNATTENDED="${WH_UNATTENDED:-0}"; WH_REF="${WH_REF:-}"; TARGET="$PWD"
UV_VERSION="${UV_VERSION:-0.11.2}"   # pinned uv to install if absent (ADR-006); override via env
OS=""; ARCH=""; CLONE=""             # CLONE is global so the EXIT trap can clean it up

c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
log()  { printf '%s %s\n' "$(c '1;36' '==>')" "$*" >&2; }   # stderr: never pollute $(clone_pinned)
warn() { printf '%s %s\n' "$(c '1;33' 'warning:')" "$*" >&2; }
die()  { printf '%s %s\n' "$(c '1;31' 'error:')" "$*" >&2; exit 1; }
run()  { if [ "$DRYRUN" = 1 ]; then printf '   [dry-run] %s\n' "$*"; else eval "$*"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }
fetch() { if have curl; then curl -fsSL "$1"; elif have wget; then wget -qO- "$1"; else die "need curl or wget to fetch $1"; fi; }

detect_os() {
  case "$(uname -s)" in
    Darwin) OS=macos;; Linux) OS=linux;;
    *) die "unsupported OS '$(uname -s)' — white-hacker installs on macOS or Linux only";;
  esac
  ARCH="$(uname -m)"
  log "host: $OS/$ARCH"
}

usage() {
  cat <<EOF
white-hacker installer
  --vendor          (default) copy the pinned payload into ./.claude/
  --plugin          install via the Claude Code plugin marketplace (auto-updates)
  --ref <tag|sha>   pin a specific ref (default: latest release tag)
  --target <dir>    target project (default: current dir)
  --dry-run         print actions, change nothing
  --unattended      no prompts (fail instead of asking)
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do case "$1" in
    --vendor) LANE=vendor;; --plugin) LANE=plugin;;
    --ref) WH_REF="${2:?--ref needs a value}"; shift;;
    --target) TARGET="${2:?--target needs a value}"; shift;;
    --dry-run) DRYRUN=1;; --unattended) UNATTENDED=1;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument: $1 (see --help)";;
  esac; shift; done
}

resolve_ref() {
  [ -n "$WH_REF" ] && { printf '%s' "$WH_REF"; return; }
  local t="" api="https://api.github.com/repos/${WH_SLUG}/releases/latest"
  if   have curl; then t="$(curl -fsSL "$api" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  elif have wget; then t="$(wget -qO- "$api" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"; fi
  [ -n "$t" ] || t="$(git ls-remote --tags --refs --sort=-v:refname "$WH_REPO" 2>/dev/null | sed -n 's#.*refs/tags/##p' | head -1)"
  [ -n "$t" ] || die "no release tag found — cut a stable tag (e.g. v0.1.0) first, or pass --ref <tag>"
  printf '%s' "$t"
}

clone_pinned() {  # echoes the temp clone dir; caller traps cleanup
  # NB: the clone runs even under --dry-run (it's an ephemeral temp dir, trap-cleaned, so it changes
  # nothing the user keeps) — the vendor/plugin steps need the payload to preview what they'd copy.
  local ref="$1" tmp; tmp="$(mktemp -d)"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$ref" "$WH_REPO" "$tmp" 2>/dev/null \
    || die "could not clone $WH_REPO at pinned ref '$ref' (does the tag exist? is the repo reachable?)"
  # ADR-006 verify: prefer a GPG-signed tag; warn (don't hard-block) if unsigned / signer key absent.
  if git -C "$tmp" cat-file -t "$ref" 2>/dev/null | grep -q '^tag$'; then
    if git -C "$tmp" verify-tag "$ref" >/dev/null 2>&1; then log "signed tag $ref verified (GPG)"
    else warn "tag $ref is not a verifiable signed tag — proceeding on the pinned ref"; fi
  fi
  printf '%s' "$tmp"
}

ensure_uv() {
  if have uv; then log "uv $(uv --version 2>/dev/null | awk '{print $2}') present (skills run isolated via uv)"; return; fi
  warn "uv not found — required to run white-hacker's (stdlib-only) skills; uv also provisions Python."
  if [ "$DRYRUN" = 1 ]; then log "[dry-run] would install uv ${UV_VERSION} (official astral installer, $OS/$ARCH)"; return; fi
  if [ "$UNATTENDED" != 1 ]; then
    printf '   install uv %s now? (official astral installer; %s/%s) [Y/n] ' "$UV_VERSION" "$OS" "$ARCH"
    read -r a </dev/tty 2>/dev/null || a=y
    case "$a" in n|N) die "uv is required — install it (https://docs.astral.sh/uv/) then re-run";; esac
  fi
  have curl || have wget || die "need curl or wget to install uv (install one, or install uv manually)"
  log "installing uv ${UV_VERSION} ($OS/$ARCH) via the official installer…"
  # pinned uv (ADR-006); the astral installer is cross-platform (macOS + Linux, multi-arch) + idempotent
  fetch "https://astral.sh/uv/${UV_VERSION}/install.sh" | sh
  # surface uv to THIS run (astral default ~/.local/bin; older/cargo ~/.cargo/bin)
  export PATH="${XDG_BIN_HOME:-$HOME/.local/bin}:$HOME/.cargo/bin:$PATH"
  have uv || die "uv installed but not on PATH — open a new shell (or add ~/.local/bin to PATH) and re-run"
  log "uv $(uv --version 2>/dev/null | awk '{print $2}') installed"
}

vendor() {  # $1 = pinned clone, $2 = target
  local src="$1/plugins/${WH_PLUGIN}" dst="$2/.claude"
  [ -d "$src" ] || die "payload not found in clone (plugins/${WH_PLUGIN}) — wrong ref?"
  log "vendor: copy pinned payload ($WH_REF) -> $dst"
  run "mkdir -p '$dst/agents' '$dst/skills'"
  # the agent identity is often project-CUSTOMIZED — back it up before overwriting (never silent clobber)
  if [ -e "$dst/agents/white-hacker.md" ]; then
    run "mv '$dst/agents/white-hacker.md' '$dst/agents/white-hacker.md.bak.$(date +%s 2>/dev/null || echo old)'"
    warn "your existing white-hacker.md was backed up (.bak.*) — it may be project-customized; diff/restore it if you meant to keep yours (or adopt the generic agent + a /white-hacker:sec-init companion)."
  fi
  run "cp '$src/agents/white-hacker.md' '$dst/agents/white-hacker.md'"   # only OUR agent; leaves your others
  # skills: copy ONLY the consumer/inner-loop manifest (fail-closed), excluding venvs/caches
  # (stdlib-only; uv recreates venvs on first run). Producers stay in the source repo (ADR-022).
  local name s
  for name in $WH_VENDOR_SKILLS; do
    s="$src/skills/$name"
    [ -d "$s" ] || { warn "manifest skill not in payload: $name (skipped)"; continue; }
    if [ -e "$dst/skills/$name" ] && [ "$DRYRUN" != 1 ]; then
      run "mv '$dst/skills/$name' '$dst/skills/$name.bak.$(date +%s 2>/dev/null || echo old)'"   # idempotent backup
    fi
    run "rsync -a --exclude '.venv' --exclude '__pycache__' --exclude '.pytest_cache' '$s/' '$dst/skills/$name/' 2>/dev/null || cp -R '$s' '$dst/skills/$name'"
  done
  # Deliberately DO NOT vendor plugins/.../commands/ — they are PLUGIN-lane entry points:
  #  (1) Claude Code only scans .claude/commands/ (a commands-white-hacker/ dir is never loaded);
  #  (2) they delegate via ${CLAUDE_PLUGIN_ROOT}, which is unset outside an installed plugin;
  #  (3) /security-review shadows the built-in and /sec-patch duplicates the sec-patch SKILL.
  # In the vendor lane you invoke the agent (.claude/agents/white-hacker.md) directly; its skills
  # auto-load from .claude/skills/. (The --plugin lane is where /white-hacker:* commands belong.)
  # keep recreated skill venvs out of the repo
  if [ "$DRYRUN" != 1 ] && ! grep -qxF '.venv/' "$2/.gitignore" 2>/dev/null; then echo '.venv/' >> "$2/.gitignore"; fi
  # Scrub dev/outer-loop content from the vendored copy: deterministic marker-based section-strip +
  # neuter, then a leakage assertion (install/scrub_vendored.py; ADR-022). Source tree is untouched.
  local scrubber="$1/install/scrub_vendored.py"
  if [ "$DRYRUN" = 1 ]; then
    log "[dry-run] would scrub the vendored payload ($scrubber)"
  elif [ -f "$scrubber" ] && have uv; then
    log "scrub: strip dev/outer-loop references from the vendored copy"
    uv run --no-project python "$scrubber" "$dst" >&2 \
      || warn "scrub reported surviving dev-repo references (above) — review $dst before committing."
  else
    warn "scrubber not found in clone (install/scrub_vendored.py) or uv absent — vendored payload NOT scrubbed; it may carry dev-repo references."
  fi
  warn "confinement hooks are plugin-lane-only (they resolve \${CLAUDE_PLUGIN_ROOT}) and are intentionally omitted here — with the outer-loop skills excluded there is nothing for them to confine. Use --plugin if you want them."
  # Onboarding handoff (vendor lane only): land the user on a confirmed project profile by offering to
  # run the sec-init onboarding now. NON-FATAL throughout (set -e safe, :24) — a missing claude, a
  # declined prompt, or a nonzero claude exit must NOT fail the install (guarded with || true / explicit
  # branches). Mirrors ensure_uv's /dev/tty pattern (:108-111); claude presence modelled on the plugin
  # lane's `command -v claude` check. sec-init writes <target>/.white-hacker/project-profile.json (it is NOT reimplemented
  # here — we only launch it; plugins/white-hacker/skills/sec-init/scripts/init_profile.py:332).
  local onboard="run the white-hacker sec-init onboarding — detect this project's stack (language, package manager, build/test) and confirm the .white-hacker/project-profile.json companion with me."
  if [ "$DRYRUN" = 1 ]; then
    log "[dry-run] would offer to run onboarding"
  elif command -v claude >/dev/null 2>&1 && [ "$UNATTENDED" != 1 ]; then
    printf '   Run white-hacker onboarding now (detect stack + confirm the project profile)? [Y/n] '
    read -r a </dev/tty 2>/dev/null || a=n   # no controlling tty -> default SKIP (print the manual step), never a doomed interactive spawn (ADR-007)
    case "$a" in
      n|N) log "skipped onboarding — run it later in Claude Code here";;
      *)   claude "$onboard" </dev/tty || true;;
    esac
  else
    log "to onboard: open Claude Code in $2 and ask to run the white-hacker sec-init onboarding — it detects your stack (language, package manager, build/test) and writes .white-hacker/project-profile.json."
  fi
}

plugin() {  # $1 = pinned clone (used as a LOCAL pinned marketplace)
  command -v claude >/dev/null 2>&1 || die "the 'claude' CLI is required for --plugin"
  log "plugin: register pinned marketplace + install ${WH_PLUGIN}"
  run "claude plugin marketplace add '$1' 2>/dev/null || claude plugin marketplace add '$WH_REPO'"
  run "claude plugin install '${WH_PLUGIN}@${WH_MARKETPLACE}'"
  warn "restart Claude Code to load the plugin."
}

main() {
  parse_args "$@"
  detect_os
  have git || die "git is required (install git, or use a git-bundled environment)"
  [ -d "$TARGET" ] || die "target not a directory: $TARGET"
  WH_REF="$(resolve_ref)"; log "white-hacker @ $(c '1;32' "$WH_REF")  lane=$LANE  target=$TARGET${DRYRUN:+}"
  [ "$DRYRUN" = 1 ] && log "(dry-run — nothing will change)"
  ensure_uv
  CLONE="$(clone_pinned "$WH_REF")"; trap 'rm -rf "${CLONE:-}"' EXIT
  case "$LANE" in
    vendor) vendor "$CLONE" "$TARGET";;
    plugin) plugin "$CLONE";;
  esac
  if [ "$LANE" = plugin ]; then
    cat <<EOF

$(c '1;32' '✓') white-hacker installed ($WH_REF, plugin lane). Restart Claude Code, then:
   /white-hacker:security-review   # run the review (thin entry -> the agent's inner loop)
   /white-hacker:sec-patch         # opt-in remediation (writes diffs to ./PATCHES, never applies)
Update later: claude plugin update ${WH_PLUGIN}
EOF
  else
    cat <<EOF

$(c '1;32' '✓') white-hacker vendored into $TARGET/.claude ($WH_REF).
   - agent:  .claude/agents/white-hacker.md   (a project subagent — the behavioral source of truth)
   - skills: .claude/skills/*                 (inner loop: threat-model -> discovery -> triage ->
                                                report; + secrets-scan / deps-scan / ai-llm-review;
                                                opt-in sec-patch). No slash commands in this lane.
   - onboard: run the sec-init onboarding (offered above, or anytime in Claude Code here) to detect
              your stack and write .white-hacker/project-profile.json — the agent reads it to tailor
              the review to your language / package manager / build + test.
In a Claude Code session here, just ask, e.g.:
   "run a white-hacker security review on my working-tree diff"
Claude delegates to the white-hacker subagent. Commit .claude/ to share it / run it in CI.
Refresh later: re-run this installer (picks up the latest release tag).
EOF
  fi
}

main "$@"
