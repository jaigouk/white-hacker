"""Tests for sec-policy's policy PROPOSAL generator (T-11.6).

Design (spike-08 F1/F5 + ADR-010/016): generate a SECURITY.md PROPOSAL written ONLY to
PATCHES/ — a HUMAN applies it; the agent never auto-applies, never pushes, and never writes
audit history into the policy.

  * ABSENT policy  -> emit the best-practice skeleton template (action="create").
  * PRESENT policy -> read the existing SECURITY.md as an UNTRUSTED STRING (string ops only),
    APPEND only the missing best-practice sections to the END, preserving every
    maintainer-declared fact (contact / supported-versions / scope) VERBATIM
    (action="modify"); also emit a unified diff.

SECURITY POSTURE — the existing SECURITY.md is attacker-influenceable (the agent is an
injection target, Agents Rule of Two). The generator treats it as DATA: it only concatenates
strings, never executes/follows content, and never injects scan results / CVEs / audit
history into the proposal. Output can NEVER escape PATCHES/ (path-separator / ".." guard).

Run: uv run --project plugins/white-hacker/skills/sec-policy/scripts --with pytest \
       pytest plugins/white-hacker/skills/sec-policy/scripts/tests -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

import propose_policy as prop

# The canonical best-practice section headings (must match parse_policy's keys).
SECTION_KEYS = (
    "supported_versions",
    "reporting",
    "response_timeline",
    "coordinated_disclosure",
    "scope",
    "safe_harbor",
    "acknowledgments",
)


def _write_md(root: Path, body: str, rel: str = "SECURITY.md") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


# === ABSENT repo -> draft (create) ==========================================
def test_absent_repo_proposes_full_template_to_patches(tmp_path: Path):
    result = prop.propose(tmp_path)

    assert result["action"] == "create"
    assert result["diff_path"] is None
    out = Path(result["out_path"])
    assert out.exists()
    # Lands under <repo>/PATCHES/.
    assert out == tmp_path / "PATCHES" / "proposed-SECURITY.md"

    body = out.read_text(encoding="utf-8")
    # Every best-practice section heading is present.
    for heading in (
        "## Supported Versions",
        "## Reporting a Vulnerability",
        "## Response Timeline",
        "## Coordinated Disclosure",
        "## Scope",
        "## Safe Harbor",
        "## Acknowledgments",
    ):
        assert heading in body, f"missing best-practice heading: {heading!r}"


def test_absent_repo_has_commitment_caution_and_flagged_placeholder(tmp_path: Path):
    prop.propose(tmp_path)
    body = (tmp_path / "PATCHES" / "proposed-SECURITY.md").read_text(encoding="utf-8")

    # The commitment caution: this template commits the maintainer; review before merging.
    low = body.lower()
    assert "commit" in low and "review before merging" in low

    # A clearly FLAGGED placeholder contact + a TODO to fill it in.
    assert "TODO" in body
    assert "PLACEHOLDER" in body


def test_absent_repo_does_not_write_real_security_md(tmp_path: Path):
    prop.propose(tmp_path)
    # Only the PATCHES/ proposal exists; no real SECURITY.md anywhere.
    for rel in (
        "SECURITY.md",
        ".github/SECURITY.md",
        "docs/SECURITY.md",
        "SECURITY.markdown",
    ):
        assert not (tmp_path / rel).exists(), f"generator wrote a real policy: {rel}"


def test_template_parses_back_as_a_complete_policy(tmp_path: Path):
    # The proposed draft, re-parsed by parse_policy, should detect ALL seven sections —
    # the headings we emit must match the detector's patterns (single source of truth).
    import parse_policy as pp

    prop.propose(tmp_path)
    draft = (tmp_path / "PATCHES" / "proposed-SECURITY.md").read_text(encoding="utf-8")
    sections = pp.detect_sections(draft)
    assert all(sections[k] is True for k in SECTION_KEYS), sections
    # And the template prose carries no injection markers of its own.
    assert pp.injection_suspected(draft) is False


# === PRESENT repo -> merged draft preserving facts verbatim =================
EXISTING_POLICY = """\
# Security Policy

## Supported Versions
| Version | Supported |
|---------|-----------|
| 1.2.x   | ✅        |
| 1.1.x   | ❌        |

## Reporting a Vulnerability
Please email security@acme.example to report a vulnerability privately.

## Scope
Only the acme-core service and its first-party SDKs are in scope; vendored deps go upstream.
"""


def test_present_repo_action_modify_and_preserves_facts_verbatim(tmp_path: Path):
    _write_md(tmp_path, EXISTING_POLICY)
    result = prop.propose(tmp_path)

    assert result["action"] == "modify"
    out = Path(result["out_path"])
    assert out == tmp_path / "PATCHES" / "proposed-SECURITY.md"
    merged = out.read_text(encoding="utf-8")

    # Maintainer-declared facts survive VERBATIM (exact substrings).
    assert "security@acme.example" in merged
    assert "1.2.x" in merged
    assert "| 1.2.x   | ✅        |" in merged
    assert (
        "Only the acme-core service and its first-party SDKs are in scope; "
        "vendored deps go upstream." in merged
    )


def test_present_repo_appends_missing_sections(tmp_path: Path):
    _write_md(tmp_path, EXISTING_POLICY)
    result = prop.propose(tmp_path)

    added = set(result["missing_added"])
    # Existing: supported_versions, reporting, scope. So these must be added:
    assert "response_timeline" in added
    assert "coordinated_disclosure" in added
    assert "safe_harbor" in added
    assert "acknowledgments" in added
    # Already-present sections are NOT re-added.
    assert "supported_versions" not in added
    assert "reporting" not in added
    assert "scope" not in added

    merged = Path(result["out_path"]).read_text(encoding="utf-8")
    assert "## Safe Harbor" in merged
    assert "## Response Timeline" in merged


def test_present_repo_does_not_modify_or_reorder_existing_lines(tmp_path: Path):
    _write_md(tmp_path, EXISTING_POLICY)
    result = prop.propose(tmp_path)
    merged = Path(result["out_path"]).read_text(encoding="utf-8")

    # The original block is preserved as a contiguous prefix — nothing modified/reordered.
    assert merged.startswith(EXISTING_POLICY)


def test_present_repo_writes_a_patch_diff(tmp_path: Path):
    _write_md(tmp_path, EXISTING_POLICY)
    result = prop.propose(tmp_path)

    assert result["diff_path"] is not None
    diff = Path(result["diff_path"])
    assert diff == tmp_path / "PATCHES" / "proposed-SECURITY.md.patch"
    assert diff.exists()
    diff_text = diff.read_text(encoding="utf-8")
    # A unified diff that ADDS the new sections (only additions, no deletions of facts).
    assert "## Safe Harbor" in diff_text
    assert "+## Safe Harbor" in diff_text
    # No deletion line touches the maintainer contact.
    for line in diff_text.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            assert "security@acme.example" not in line


def test_present_repo_does_not_overwrite_real_security_md(tmp_path: Path):
    real = _write_md(tmp_path, EXISTING_POLICY)
    prop.propose(tmp_path)
    # The real SECURITY.md is byte-for-byte untouched.
    assert real.read_text(encoding="utf-8") == EXISTING_POLICY


# === PATCHES-only confinement ================================================
def test_patches_path_is_within_patches_dir(tmp_path: Path):
    p = prop._patches_path(tmp_path, "proposed-SECURITY.md")
    assert p == tmp_path / "PATCHES" / "proposed-SECURITY.md"
    # The resolved path is inside <repo>/PATCHES/.
    assert str(p.resolve()).startswith(str((tmp_path / "PATCHES").resolve()))


def test_patches_path_rejects_parent_traversal(tmp_path: Path):
    with pytest.raises(ValueError):
        prop._patches_path(tmp_path, "../evil.md")


def test_patches_path_rejects_path_separator(tmp_path: Path):
    with pytest.raises(ValueError):
        prop._patches_path(tmp_path, "a/b.md")


def test_patches_path_rejects_dotdot_token(tmp_path: Path):
    with pytest.raises(ValueError):
        prop._patches_path(tmp_path, "..")


# === no audit history / no scan results injected =============================
def test_no_scan_results_or_audit_history_injected_absent(tmp_path: Path):
    prop.propose(tmp_path)
    body = (tmp_path / "PATCHES" / "proposed-SECURITY.md").read_text(encoding="utf-8")
    low = body.lower()
    # Scan-result / audit-history phrasing must never appear. (The bare English word
    # "finding" is fine in policy prose — we ban the scan-result phrase, not the word.)
    for banned in ("cve-", "vulnerability found", "audit log", "scan result"):
        assert banned not in low, f"audit/scan text leaked into proposal: {banned!r}"


def test_no_scan_results_or_audit_history_injected_present(tmp_path: Path):
    _write_md(tmp_path, EXISTING_POLICY)
    result = prop.propose(tmp_path)
    merged = Path(result["out_path"]).read_text(encoding="utf-8")
    # Only the appended (generator-authored) block is checked for banned content; the
    # existing body is the maintainer's, preserved verbatim.
    appended = merged[len(EXISTING_POLICY):].lower()
    for banned in ("cve-", "vulnerability found", "audit log", "scan result"):
        assert banned not in appended, f"audit/scan text injected: {banned!r}"


# === F1 (HIGH): symlink write-escape — never write THROUGH a symlink ==========
# An attacker can commit a symlink at PATCHES/proposed-SECURITY.md (or make PATCHES
# itself a symlink) so that Path.write_text, which FOLLOWS symlinks, clobbers a file
# OUTSIDE <repo>/PATCHES/ (e.g. the real SECURITY.md or any host file). propose() must
# REFUSE rather than follow the link. _patches_path only validates the name string, not
# the on-disk path, so these are the load-bearing regression tests for the fix.
def test_symlink_proposal_file_targets_real_security_md_is_refused(tmp_path: Path):
    # A real SECURITY.md the attacker wants to clobber via the symlink.
    real = _write_md(tmp_path, EXISTING_POLICY)
    real_before = real.read_bytes()

    patches = tmp_path / "PATCHES"
    patches.mkdir()
    # The output proposal file is a symlink pointing AT the real SECURITY.md.
    link = patches / "proposed-SECURITY.md"
    link.symlink_to(real)

    with pytest.raises(ValueError):
        prop.propose(tmp_path)

    # The real SECURITY.md is BYTE-for-byte unchanged (never written through the link).
    assert real.read_bytes() == real_before


def test_symlink_patches_dir_to_outside_is_refused(tmp_path: Path):
    # PATCHES is a symlink to a directory OUTSIDE the repo; a naive mkdir(exist_ok=True)
    # would follow it and writes would land outside the repo.
    outside = tmp_path / "outside"
    outside.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PATCHES").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError):
        prop.propose(repo)

    # Nothing was written into the outside dir through the symlinked PATCHES.
    assert list(outside.iterdir()) == []


def test_symlink_patch_diff_file_is_refused(tmp_path: Path):
    # PRESENT repo path: the .patch output is a symlink to an outside file -> refuse.
    _write_md(tmp_path, EXISTING_POLICY)
    outside = tmp_path / "outside.txt"
    outside.write_text("ORIGINAL", encoding="utf-8")
    outside_before = outside.read_bytes()

    patches = tmp_path / "PATCHES"
    patches.mkdir()
    (patches / "proposed-SECURITY.md.patch").symlink_to(outside)

    with pytest.raises(ValueError):
        prop.propose(tmp_path)

    assert outside.read_bytes() == outside_before


def test_happy_path_writes_regular_files_not_symlinks(tmp_path: Path):
    # Regression: with no symlink, propose() still works and emits REGULAR files.
    _write_md(tmp_path, EXISTING_POLICY)
    result = prop.propose(tmp_path)
    out = Path(result["out_path"])
    diff = Path(result["diff_path"])
    assert out.is_file() and not out.is_symlink()
    assert diff.is_file() and not diff.is_symlink()
    # The PATCHES dir itself is a real directory, not a symlink.
    assert (tmp_path / "PATCHES").is_dir()
    assert not (tmp_path / "PATCHES").is_symlink()


# === CLI =====================================================================
def test_main_absent_repo_exits_zero_and_writes(tmp_path: Path, capsys):
    rc = prop.main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "create" in out
    assert (tmp_path / "PATCHES" / "proposed-SECURITY.md").exists()


def test_main_present_repo_reports_modify(tmp_path: Path, capsys):
    _write_md(tmp_path, EXISTING_POLICY)
    rc = prop.main([str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "modify" in out
    assert (tmp_path / "PATCHES" / "proposed-SECURITY.md.patch").exists()
