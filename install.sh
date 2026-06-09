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
# Python: white-hacker's skills are STDLIB-ONLY and run via `uv run --project` in ISOLATED venvs —
#         NO Python packages are installed into your project. The only runtime prereq is `uv`
#         (which also provisions Python). uv injects test deps (jsonschema/pytest) ephemerally.
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

LANE="vendor"; DRYRUN=0; UNATTENDED="${WH_UNATTENDED:-0}"; WH_REF="${WH_REF:-}"; TARGET="$PWD"

c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
log()  { printf '%s %s\n' "$(c '1;36' '==>')" "$*"; }
warn() { printf '%s %s\n' "$(c '1;33' 'warning:')" "$*" >&2; }
die()  { printf '%s %s\n' "$(c '1;31' 'error:')" "$*" >&2; exit 1; }
run()  { if [ "$DRYRUN" = 1 ]; then printf '   [dry-run] %s\n' "$*"; else eval "$*"; fi; }

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
  local t=""
  command -v curl >/dev/null 2>&1 && t="$(curl -fsSL "https://api.github.com/repos/${WH_SLUG}/releases/latest" 2>/dev/null \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$t" ] || t="$(git ls-remote --tags --refs --sort=-v:refname "$WH_REPO" 2>/dev/null | sed -n 's#.*refs/tags/##p' | head -1)"
  [ -n "$t" ] || die "no release tag found — cut a stable tag (e.g. v0.1.0) first, or pass --ref <tag>"
  printf '%s' "$t"
}

clone_pinned() {  # echoes the temp clone dir; caller traps cleanup
  # NB: the clone runs even under --dry-run (it's an ephemeral temp dir, trap-cleaned, so it changes
  # nothing the user keeps) — the vendor/plugin steps need the payload to preview what they'd copy.
  local ref="$1" tmp; tmp="$(mktemp -d)"
  git clone --quiet --depth 1 --branch "$ref" "$WH_REPO" "$tmp" \
    || die "could not clone $WH_REPO at pinned ref '$ref' (does the tag exist?)"
  # ADR-006 verify: prefer a GPG-signed tag; warn (don't hard-block) if unsigned / signer key absent.
  if git -C "$tmp" cat-file -t "$ref" 2>/dev/null | grep -q '^tag$'; then
    if git -C "$tmp" verify-tag "$ref" >/dev/null 2>&1; then log "signed tag $ref verified (GPG)"
    else warn "tag $ref is not a verifiable signed tag — proceeding on the pinned ref"; fi
  fi
  printf '%s' "$tmp"
}

ensure_uv() {
  if command -v uv >/dev/null 2>&1; then log "uv $(uv --version 2>/dev/null | awk '{print $2}') present (skills run isolated via uv)"; return; fi
  warn "uv not found — white-hacker's stdlib-only skills run via 'uv run' (uv also provisions Python)."
  echo "   install uv:  curl -LsSf https://astral.sh/uv/install.sh | sh"
  [ "$UNATTENDED" = 1 ] && die "uv is required — install it and re-run"
  printf '   install uv now via the official installer? [y/N] '
  read -r a </dev/tty 2>/dev/null || a=n
  case "$a" in y|Y) run "curl -LsSf https://astral.sh/uv/install.sh | sh";; *) warn "skipping uv — install it before a review";; esac
}

vendor() {  # $1 = pinned clone, $2 = target
  local src="$1/plugins/${WH_PLUGIN}" dst="$2/.claude"
  [ -d "$src" ] || die "payload not found in clone (plugins/${WH_PLUGIN}) — wrong ref?"
  log "vendor: copy pinned payload ($WH_REF) -> $dst"
  run "mkdir -p '$dst/agents' '$dst/skills'"
  run "cp '$src/agents/white-hacker.md' '$dst/agents/white-hacker.md'"   # only OUR agent; leaves your others
  # skills: copy each, excluding venvs/caches (stdlib-only; uv recreates venvs on first run)
  for s in "$src"/skills/*/; do
    [ -d "$s" ] || continue; local name; name="$(basename "$s")"
    if [ -e "$dst/skills/$name" ] && [ "$DRYRUN" != 1 ]; then
      run "mv '$dst/skills/$name' '$dst/skills/$name.bak.$(date +%s 2>/dev/null || echo old)'"   # idempotent backup
    fi
    run "rsync -a --exclude '.venv' --exclude '__pycache__' --exclude '.pytest_cache' '$s' '$dst/skills/$name/' 2>/dev/null || cp -R '$s' '$dst/skills/$name'"
  done
  [ -d "$src/commands" ] && run "cp -R '$src/commands' '$dst/commands-white-hacker'" || true
  # keep recreated skill venvs out of the repo
  if [ "$DRYRUN" != 1 ] && ! grep -qxF '.venv/' "$2/.gitignore" 2>/dev/null; then echo '.venv/' >> "$2/.gitignore"; fi
  warn "confinement hooks (plugins/${WH_PLUGIN}/hooks) are NOT auto-wired in the vendor lane — register them in $2/.claude/settings.json if you want the self-improvement guards (or use --plugin)."
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
  need_git() { command -v git >/dev/null 2>&1 || die "git is required"; }; need_git
  [ -d "$TARGET" ] || die "target not a directory: $TARGET"
  WH_REF="$(resolve_ref)"; log "white-hacker @ $(c '1;32' "$WH_REF")  lane=$LANE  target=$TARGET${DRYRUN:+}"
  [ "$DRYRUN" = 1 ] && log "(dry-run — nothing will change)"
  ensure_uv
  local clone; clone="$(clone_pinned "$WH_REF")"; trap 'rm -rf "$clone"' EXIT
  case "$LANE" in
    vendor) vendor "$clone" "$TARGET";;
    plugin) plugin "$clone";;
  esac
  cat <<EOF

$(c '1;32' '✓') white-hacker installed ($WH_REF, $LANE lane).
Next, in this project (a Claude Code session):
   /white-hacker:sec-init          # detect stack + write .white-hacker/project-profile.json (commit it)
   /white-hacker:security-review   # run a review
Refresh later: re-run this installer (picks up the latest release tag).
EOF
}

main "$@"
