"""Tests for the tool-detection PoC. Run: `uv run --with pytest pytest -q`.

Covers the happy path AND edge cases (empty repo, multi-language,
ts-vs-js disambiguation, infra detection, and graceful degradation when
a scanner category has no installed tool).
"""
from __future__ import annotations

from pathlib import Path

import detect_tools as dt


# --- language detection ---------------------------------------------------
def test_detects_go(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    assert dt.detect_languages(tmp_path) == ["go"]


def test_detects_python_variants(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    assert dt.detect_languages(tmp_path) == ["python"]


def test_typescript_beats_javascript(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "tsconfig.json").write_text("{}")
    # both signals present -> typescript only, never plain javascript
    assert dt.detect_languages(tmp_path) == ["typescript"]


def test_plain_javascript_without_tsconfig(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    assert dt.detect_languages(tmp_path) == ["javascript"]


def test_multi_language_repo(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    (tmp_path / "pom.xml").write_text("<project/>")
    assert dt.detect_languages(tmp_path) == ["go", "java", "python"]


def test_empty_repo_has_no_languages(tmp_path: Path):
    assert dt.detect_languages(tmp_path) == []


# --- infra detection ------------------------------------------------------
def test_detects_dockerfile_and_actions(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert dt.detect_infra(tmp_path) == ["docker", "github-actions"]


# --- available-tool detection (injected `which`) --------------------------
def _which_only(*present: str):
    present_set = set(present)
    return lambda name: f"/usr/bin/{name}" if name in present_set else None


def test_available_tools_filters_to_installed():
    which = _which_only("trivy", "govulncheck")
    assert dt.detect_available_tools(which) == ["govulncheck", "trivy"]


# --- scan-plan assembly + graceful degradation ----------------------------
def test_plan_picks_best_signal_first(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    which = _which_only("opengrep", "govulncheck", "gitleaks")
    plan = dt.build_scan_plan(tmp_path, which)
    assert plan.category_tool["sast"] == "opengrep"      # "*" tool serves go
    assert plan.category_tool["sca"] == "govulncheck"    # native go gate preferred
    assert plan.category_tool["secrets"] == "gitleaks"
    assert plan.degraded is False


def test_plan_degrades_when_category_tool_missing(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    # only a secrets tool installed; sast + sca have nothing
    which = _which_only("gitleaks")
    plan = dt.build_scan_plan(tmp_path, which)
    assert plan.category_tool["sast"] is None
    assert plan.category_tool["sca"] is None
    assert "sast" in plan.degraded_categories
    assert "sca" in plan.degraded_categories
    assert plan.degraded is True
    # the contract: we degrade, we never crash
    assert plan.to_dict()["fallback"].startswith("read-grep-glob")


def test_sca_tool_language_match(tmp_path: Path):
    # python repo with only govulncheck (go-only) installed -> sca cannot use it
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    which = _which_only("govulncheck")
    plan = dt.build_scan_plan(tmp_path, which)
    assert plan.category_tool["sca"] is None  # govulncheck doesn't serve python
    assert "sca" in plan.degraded_categories


def test_iac_category_only_when_infra_present(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    which = _which_only("trivy")
    plan_no_infra = dt.build_scan_plan(tmp_path, which)
    assert "iac" not in plan_no_infra.category_tool  # skipped, no Dockerfile/CI

    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    plan_infra = dt.build_scan_plan(tmp_path, which)
    assert plan_infra.category_tool["iac"] == "trivy"
