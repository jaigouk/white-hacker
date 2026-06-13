"""propose_policy (T-11.6): generate a SECURITY.md PROPOSAL → PATCHES/ only.

A target repo may ship no `SECURITY.md`, or an incomplete one. This module proposes a
best-practice policy DRAFT — and ONLY a draft. It NEVER auto-applies, NEVER pushes, and
NEVER writes audit history. A human reviews and applies whatever lands in `PATCHES/`
(the capability-removed path; ADR-010/016). Resolves spike-08 F1/F5.

Decision tree:
  * ABSENT  (gap["present"] is False): emit the best-practice skeleton template verbatim;
            action="create".
  * PRESENT (gap["present"] is True):  read the EXISTING SECURITY.md as an UNTRUSTED STRING,
            APPEND a best-practice block for each section in gap["missing_sections"] to the
            END of the file (never modify/reorder existing lines, so the maintainer's
            contact / supported-versions / scope survive VERBATIM); action="modify"; also
            compute a unified diff (original -> merged).

SECURITY POSTURE — the existing SECURITY.md is attacker-influenceable markdown and the agent
is an injection target (Agents Rule of Two). This module therefore:
  * treats the existing body as DATA: it only reads it and CONCATENATES strings; it never
    executes, evals, or "follows" the content, and never derives behavior from it;
  * appends ONLY generator-authored, static best-practice prose — it NEVER injects scan
    results, CVEs, findings, or audit history into the proposal (a SECURITY.md is a
    forward-looking policy, not an audit log);
  * confines every write to `<repo>/PATCHES/` via `_patches_path`, which RAISES on a path
    separator or "..", so output can NEVER escape PATCHES/ — and it NEVER touches the
    repo's real SECURITY.md.

stdlib + difflib. Reuses the T-11.3 parser (`parse_policy`), which reuses the T-11.2
detector — single source of truth for section detection / locate.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import difflib

# Make parse_policy (this dir) + the _shared detector importable both under pytest (the
# conftest shim) AND when this file is run directly as a CLI.
_HERE = Path(__file__).parent
_SHARED_SCRIPTS = _HERE.parent.parent / "_shared" / "scripts"
for _p in (str(_HERE), str(_SHARED_SCRIPTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import parse_policy as pp  # noqa: E402  (path shim above must run first)

_TEMPLATE_PATH = _HERE / "security-md.template.md"
_PROPOSAL_NAME = "proposed-SECURITY.md"
_PATCH_NAME = "proposed-SECURITY.md.patch"

# Canonical section headings, keyed by parse_policy's section keys. The headings MUST match
# parse_policy's SECTION_PATTERNS so a re-parse detects every section we add (single source
# of truth — verified by test_template_parses_back_as_a_complete_policy).
SECTION_TITLES: dict[str, str] = {
    "supported_versions": "Supported Versions",
    "reporting": "Reporting a Vulnerability",
    "response_timeline": "Response Timeline",
    "coordinated_disclosure": "Coordinated Disclosure",
    "scope": "Scope",
    "safe_harbor": "Safe Harbor",
    "acknowledgments": "Acknowledgments / Contact",
}

# Best-practice body for each appendable section (generator-authored, static prose only —
# NO scan results / CVEs / audit history). `supported_versions` includes a markdown table so
# pd.has_supported_versions detects it on a re-parse.
_SECTION_BODIES: dict[str, str] = {
    "supported_versions": (
        "Which releases currently receive security fixes. Edit the table to match your "
        "project.\n\n"
        "| Version | Supported |\n"
        "|---------|-----------|\n"
        "| x.y.z   | ✅        |\n"
        "| < x.y   | ❌        |\n"
    ),
    "reporting": (
        "<!-- TODO: replace the PLACEHOLDER channel below with your real private "
        "reporting channel. -->\n\n"
        "Please report security issues **privately** — do **not** open a public "
        "issue.\n\n"
        "- **PLACEHOLDER private channel — TODO: choose ONE and fill it in:**\n"
        "  - GitHub Private Vulnerability Reporting (Security tab), or\n"
        "  - email `security@PLACEHOLDER.example` (TODO: set a real, monitored address), "
        "or\n"
        "  - a dedicated reporting form (TODO: add the URL).\n\n"
        "Please include impact, affected versions, and clear reproduction steps or a "
        "proof of concept.\n"
    ),
    "response_timeline": (
        "We aim to:\n\n"
        "- acknowledge your report within **48 hours** (TODO: confirm you can meet "
        "this), then\n"
        "- provide an initial assessment / triage within **7 days**, and\n"
        "- agree a coordinated fix and disclosure window of up to **90 days**.\n"
    ),
    "coordinated_disclosure": (
        "We follow coordinated (responsible) disclosure: please keep the issue "
        "confidential until a fix is released and the embargo ends. We will work with you "
        "on the disclosure schedule and may extend the embargo by mutual agreement for "
        "complex fixes.\n"
    ),
    "scope": (
        "Describe what is in and out of scope (TODO: edit for your project).\n\n"
        "- **In scope:** the first-party code in this repository.\n"
        "- **Out of scope:** third-party dependencies (report those upstream) and "
        "test/CI infrastructure, unless a finding affects shipped behavior.\n"
    ),
    "safe_harbor": (
        "We support good-faith security research. We will not pursue legal action "
        "against researchers who follow this policy, avoid privacy violations and service "
        "disruption, and give us a reasonable opportunity to remediate before any public "
        "disclosure.\n"
    ),
    "acknowledgments": (
        "We credit researchers who responsibly disclose issues (with their permission). "
        "For questions about this policy, contact the channel listed under **Reporting a "
        "Vulnerability** above (TODO: confirm this is the right contact for policy "
        "questions).\n"
    ),
}


def _patches_path(repo_root, name: str) -> Path:
    """Return `<repo_root>/PATCHES/<name>`; RAISE ValueError if `name` could escape PATCHES/.

    `name` must be a bare filename: no path separator (os.sep / os.altsep, "/" or "\\"),
    and no ".." token. This is a hard data-layer guard so the proposal can NEVER be written
    outside `<repo_root>/PATCHES/`.
    """
    if not name or name in (".", ".."):
        raise ValueError(f"unsafe proposal name: {name!r}")
    # Reject any path separator (forward, back, or OS-specific) and any parent token.
    separators = {os.sep, "/", "\\"}
    if os.altsep:
        separators.add(os.altsep)
    if any(sep in name for sep in separators):
        raise ValueError(f"proposal name must not contain a path separator: {name!r}")
    if ".." in name:
        raise ValueError(f"proposal name must not contain '..': {name!r}")
    return Path(repo_root) / "PATCHES" / name


def _safe_write(path: Path, text: str) -> None:
    """Write `text` to `path` WITHOUT following a symlink (TOCTOU-resistant, O_NOFOLLOW).

    Path.write_text follows symlinks: an attacker-committed symlink at the output path
    would let the write escape PATCHES/ (clobbering e.g. the real SECURITY.md). os.open
    with O_NOFOLLOW makes the open itself fail (ELOOP) if the final path component is a
    symlink, so the write can NEVER traverse one. On platforms lacking O_NOFOLLOW the flag
    is 0 (best-effort); the explicit is_symlink() pre-check in `propose` still refuses.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:  # ELOOP when the path is a symlink (O_NOFOLLOW) -> refuse.
        raise ValueError(f"refusing to write through a symlink: {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def _ensure_patches_dir(root: Path) -> Path:
    """Return `<root>/PATCHES`, creating it as a real dir; RAISE if it is a symlink.

    A symlinked PATCHES (or a symlink anywhere on the way) would let every output escape
    the repo. We refuse to follow it: if PATCHES exists and is a symlink -> ValueError;
    otherwise mkdir(exist_ok=True) (which does NOT follow/replace an existing symlink).
    """
    patches = root / "PATCHES"
    if patches.is_symlink():
        raise ValueError(f"refusing to use a symlinked PATCHES directory: {patches}")
    patches.mkdir(exist_ok=True)
    return patches


def _assert_not_symlink(path: Path) -> None:
    """RAISE if `path` exists and is a symlink — never clobber a file through a link."""
    if path.is_symlink():
        raise ValueError(f"refusing to overwrite a symlink: {path}")


def _template() -> str:
    """The best-practice skeleton template (the ABSENT-policy draft), read verbatim."""
    return _TEMPLATE_PATH.read_text(encoding="utf-8")


def _section_block(key: str) -> str:
    """A leading-newline-separated `## <Title>` block for one missing section."""
    return f"\n## {SECTION_TITLES[key]}\n\n{_SECTION_BODIES[key]}"


def _append_missing(existing: str, missing: list[str]) -> tuple[str, list[str]]:
    """Append a best-practice block for each missing section to the END of `existing`.

    Existing lines are NEVER modified or reordered — `existing` is a verbatim prefix of the
    result — so the maintainer's contact / versions / scope are preserved exactly. Only
    sections we have a canonical block for are added (defensive; all seven keys are mapped).
    Returns (merged_text, added_keys).
    """
    added: list[str] = []
    merged = existing
    # Ensure the existing body ends with a newline before we append, without rewriting it.
    if merged and not merged.endswith("\n"):
        merged = merged + "\n"
    for key in missing:
        if key not in _SECTION_BODIES:
            continue
        merged = merged + _section_block(key)
        added.append(key)
    return merged, added


def propose(repo_root, now=None) -> dict:
    """Generate a SECURITY.md proposal under `<repo_root>/PATCHES/`. Never touches the repo.

    Returns {action, out_path, diff_path, missing_added}:
      * ABSENT  -> action="create": writes the template; diff_path=None; missing_added=all
                   seven section keys (the whole skeleton is "added").
      * PRESENT -> action="modify": reads the existing SECURITY.md as untrusted DATA, appends
                   the missing sections, writes the merged draft AND a unified diff
                   (original -> merged) to `proposed-SECURITY.md.patch`.
    The real SECURITY.md is never written.
    """
    root = Path(repo_root)
    gap = pp.parse_policy(root, now=now)

    # Confine writes to <root>/PATCHES/, refusing a symlinked PATCHES (would escape the repo)
    # and never creating the dir by FOLLOWING a symlink.
    _ensure_patches_dir(root)
    out_path = _patches_path(root, _PROPOSAL_NAME)
    _assert_not_symlink(out_path)

    if not gap["present"]:
        content = _template()
        _safe_write(out_path, content)
        return {
            "action": "create",
            "out_path": str(out_path),
            "diff_path": None,
            "missing_added": list(pp.SECTION_KEYS),
        }

    # PRESENT: read the existing policy as an UNTRUSTED STRING (string ops only). Reuse the
    # parser's located path so we read exactly the file it detected, and the shared capped
    # reader (F2) so an oversized attacker-influenceable SECURITY.md cannot exhaust memory.
    md_rel = gap["path"]
    original = pp.pd.read_capped(root / md_rel)

    merged, added = _append_missing(original, gap["missing_sections"])

    _safe_write(out_path, merged)

    diff_path = _patches_path(root, _PATCH_NAME)
    _assert_not_symlink(diff_path)
    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            merged.splitlines(keepends=True),
            fromfile=f"a/{md_rel}",
            tofile=f"b/{md_rel}",
        )
    )
    _safe_write(diff_path, diff)

    return {
        "action": "modify",
        "out_path": str(out_path),
        "diff_path": str(diff_path),
        "missing_added": added,
    }


def main(argv: list[str]) -> int:
    """CLI: propose a SECURITY.md draft for the given repo root. Exit 0 on success.

    Usage: propose_policy.py <repo_root>   (defaults to cwd).
    Prints a short human summary (action + the PATCHES/ paths written). Writes only to
    PATCHES/; never applies, never pushes.
    """
    repo_root = Path(argv[0]) if argv else Path.cwd()
    result = propose(repo_root)
    print(f"action: {result['action']}")
    print(f"proposal: {result['out_path']}")
    if result["diff_path"]:
        print(f"diff: {result['diff_path']}")
    print(f"sections added: {', '.join(result['missing_added']) or '(none)'}")
    print("NOTE: draft written to PATCHES/ only — review and apply by hand; never pushed.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
