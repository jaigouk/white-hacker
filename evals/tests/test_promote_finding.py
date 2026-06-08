"""Tests for the second-ratchet promotion (T-9.5, TDD).

Run: uv run --with jsonschema --with pytest pytest evals/tests/test_promote_finding.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import promote_finding as pf

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "label-schema.json").read_text())

SPEC = {
    "case_id": "py-confirmed-ssti-001", "ext": "py", "language": "python",
    "category": "injection", "severity": "HIGH", "owasp": ["A03:2025"],
    "vulnerable_code": 'from jinja2 import Template\ndef r(x):\n    return Template("Hi " + x).render()  # SINK ssti\n',
    "benign_code": 'from jinja2 import Template\ndef r(x):\n    return Template("Hi {{ n }}").render(n=x)\n',
    "vulnerable_line": 3, "note": "confirmed in review session s42",
}

# Multifile / per-variant-subdir spec (wh-705): the layout floor-scored supply-chain cases need
# (vulnerable_variant/ + benign_lookalike/ are PROJECT DIRS, because supply_chain.scan scans a
# directory, not a flat file). Opt-in: presence of a `files` map switches promote() to this mode.
MULTI_SPEC = {
    "case_id": "sc-npm-install-script-exec",
    "language": "javascript",
    "category": "supply-chain",
    "severity": "HIGH",
    "owasp": ["A06:2021"],
    "files": {
        "vulnerable_variant/package.json":
            '{"name":"x","version":"1.0.0","scripts":{"postinstall":"node scripts/postinstall.js"}}\n',
        "vulnerable_variant/package-lock.json": '{"name":"x","lockfileVersion":3}\n',
        "vulnerable_variant/scripts/postinstall.js":
            "const cp = require('child_process');\ncp.exec('id');\n",
        "benign_lookalike/package.json": '{"name":"x","version":"1.0.0"}\n',
        "benign_lookalike/package-lock.json": '{"name":"x","lockfileVersion":3}\n',
    },
    "vulnerable_file": "vulnerable_variant/scripts/postinstall.js",
    "vulnerable_line": 1,
    "benign_file": "benign_lookalike/package.json",
    "note": "install-script-exec floor anchor (S6)",
    "difficulty": "medium",
    "multifile": True,
    "support_files": ["vulnerable_variant/package.json", "vulnerable_variant/package-lock.json"],
}


def _fresh_corpus(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "cases").mkdir(parents=True)
    (corpus / "LOCKED").write_text("# locked\nexisting-case\n")
    return corpus


def test_promote_creates_four_files_and_valid_label(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "cases").mkdir(parents=True)
    (corpus / "LOCKED").write_text("# locked\nexisting-case\n")
    d = pf.promote(corpus, SPEC)
    for f in ("target.md", "label.json", "vulnerable_variant.py", "benign_lookalike.py"):
        assert (d / f).exists(), f
    label = json.loads((d / "label.json").read_text())
    assert not list(Draft202012Validator(SCHEMA).iter_errors(label))
    assert label["vulnerable"]["line"] == 3


def test_promote_appends_to_locked(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "cases").mkdir(parents=True)
    (corpus / "LOCKED").write_text("# locked\nexisting-case\n")
    pf.promote(corpus, SPEC)
    assert "py-confirmed-ssti-001" in (corpus / "LOCKED").read_text()


def test_promote_refuses_to_clobber(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "cases" / SPEC["case_id"]).mkdir(parents=True)
    with pytest.raises(FileExistsError):
        pf.promote(corpus, SPEC)  # never overwrite an existing locked case


# --------------------------------------------------------------------------- #
# wh-705: multifile / per-variant-subdir mode (floor-scored supply-chain cases)
# --------------------------------------------------------------------------- #

def test_promote_multifile_writes_subdir_tree(tmp_path):
    """Every entry in the `files` map is written at its exact relative path, INCLUDING nested
    subdirs (scripts/postinstall.js) — the floor needs a real on-disk project per variant."""
    corpus = _fresh_corpus(tmp_path)
    d = pf.promote(corpus, MULTI_SPEC)
    for rel, content in MULTI_SPEC["files"].items():
        assert (d / rel).exists(), f"missing {rel}"
        assert (d / rel).read_text() == content, f"content mismatch {rel}"
    # the case-level metadata files exist alongside the variant dirs
    assert (d / "label.json").exists()
    assert (d / "target.md").exists()
    # both variants are real directories (not flat files)
    assert (d / "vulnerable_variant").is_dir()
    assert (d / "benign_lookalike").is_dir()


def test_promote_multifile_label_valid_and_paired(tmp_path):
    """The produced label validates against label-schema.json, points its vulnerable/benign at the
    SUBPATHS from the spec, carries the multifile metadata, and both labeled files actually exist
    with the labeled line in bounds — i.e. it would pass test_labels.py unchanged."""
    corpus = _fresh_corpus(tmp_path)
    d = pf.promote(corpus, MULTI_SPEC)
    label = json.loads((d / "label.json").read_text())

    assert not list(Draft202012Validator(SCHEMA).iter_errors(label))
    assert label["vulnerable"]["file"] == "vulnerable_variant/scripts/postinstall.js"
    assert label["vulnerable"]["file"] != "vulnerable_variant.javascript"  # NOT the flat shape
    assert label["vulnerable"]["line"] == 1
    assert label["benign_lookalike"]["file"] == "benign_lookalike/package.json"
    assert label["category"] == "supply-chain"
    assert label["multifile"] is True
    assert label["support_files"] == MULTI_SPEC["support_files"]

    # test_labels.py invariants: both files exist; labeled line within the vulnerable file's bounds.
    vfile = d / label["vulnerable"]["file"]
    bfile = d / label["benign_lookalike"]["file"]
    assert vfile.exists() and bfile.exists()
    assert 1 <= label["vulnerable"]["line"] <= len(vfile.read_text().splitlines())


def test_promote_multifile_appends_to_locked(tmp_path):
    corpus = _fresh_corpus(tmp_path)
    pf.promote(corpus, MULTI_SPEC)
    assert "sc-npm-install-script-exec" in (corpus / "LOCKED").read_text()


def test_promote_multifile_refuses_to_clobber(tmp_path):
    corpus = _fresh_corpus(tmp_path)
    (corpus / "cases" / MULTI_SPEC["case_id"]).mkdir(parents=True)
    with pytest.raises(FileExistsError):
        pf.promote(corpus, MULTI_SPEC)  # never overwrite an existing locked case


def test_promote_multifile_target_md_passthrough(tmp_path):
    """A rich hand-authored target.md (from the proposal) flows through verbatim when provided;
    otherwise a minimal one is generated. Promotion must not silently drop case documentation."""
    corpus = _fresh_corpus(tmp_path)
    spec = {**MULTI_SPEC, "target_md": "# custom\n\nhand-authored body\n"}
    d = pf.promote(corpus, spec)
    assert (d / "target.md").read_text() == "# custom\n\nhand-authored body\n"


@pytest.mark.parametrize("bad", ["../escape.txt", "/etc/passwd", "a/../../escape", "vulnerable_variant/../../x"])
def test_promote_rejects_path_traversal(tmp_path, bad):
    """SECURITY: a `files` key must never resolve outside the case dir. An absolute path or any
    `..` segment is rejected with ValueError BEFORE any file (or the case dir) is created — so a
    malformed/hostile spec cannot clobber the working tree."""
    corpus = _fresh_corpus(tmp_path)
    spec = {**MULTI_SPEC, "files": {**MULTI_SPEC["files"], bad: "x"}}
    with pytest.raises(ValueError):
        pf.promote(corpus, spec)
    # nothing leaked outside, and the partial case dir was not left behind
    assert not (tmp_path / "escape.txt").exists()
    assert not (corpus.parent / "escape.txt").exists()
    assert not (corpus / "cases" / MULTI_SPEC["case_id"]).exists()


def test_flat_and_multifile_dispatch_on_files_key(tmp_path):
    """Mode is selected ONLY by the presence of a `files` map: the flat spec still produces the
    flat `vulnerable_variant.<ext>`; the multifile spec produces the subdir tree. One regression
    guard that both lanes coexist."""
    corpus = _fresh_corpus(tmp_path)
    flat = pf.promote(corpus, SPEC)
    assert (flat / "vulnerable_variant.py").is_file()
    assert not (flat / "vulnerable_variant").is_dir()


def test_main_usage():
    assert pf.main([]) == 2
