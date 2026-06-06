"""T-2.3 — SCAN-PLAN.json schema tests.

Locks the schema to the actual `detect_tools.py` emitter (so the two can't drift)
and covers the negative cases the plan calls out: missing `degraded`, unknown
capability key, and that an empty repo's plan is still valid. Also meta-validates
the schema as draft 2020-12.

Run: `uv run --with jsonschema --with pytest pytest .claude/skills/sec-detect/scripts/tests/test_scan_plan_schema.py`
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import detect_tools as dt
import validate_scan_plan as vsp


def _plan_dict(tmp_path: Path, *tools: str) -> dict:
    which = lambda name: f"/usr/bin/{name}" if name in set(tools) else None
    return dt.build_scan_plan(tmp_path, which).to_dict()


# --- the schema itself is well-formed -------------------------------------
def test_schema_is_valid_draft_2020_12():
    Draft202012Validator.check_schema(vsp.load_schema())


# --- emitter output validates (the lock) ----------------------------------
def test_emitter_output_validates_ai_backend(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=['fastapi','langchain']\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    plan = _plan_dict(tmp_path, "opengrep", "trivy", "promptfoo")
    assert vsp.validate(plan) == []


def test_emitter_output_validates_multi_language(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\nrequire github.com/gin-gonic/gin v1\n")
    (tmp_path / "package.json").write_text('{"dependencies":{"next":"15.2.3"}}')
    (tmp_path / "tsconfig.json").write_text("{}")
    plan = _plan_dict(tmp_path, "opengrep", "govulncheck", "gitleaks")
    assert vsp.validate(plan) == []


def test_empty_repo_plan_is_valid(tmp_path: Path):
    # no langs, no tools — still a structurally valid (fully degraded) plan.
    plan = _plan_dict(tmp_path)
    assert vsp.validate(plan) == []
    assert plan["languages"] == []
    assert plan["ai_pass"] is False


# --- negative cases --------------------------------------------------------
def test_missing_degraded_is_rejected(tmp_path: Path):
    plan = _plan_dict(tmp_path, "opengrep")
    del plan["degraded"]
    errors = vsp.validate(plan)
    assert errors and any("degraded" in e for e in errors)


def test_unknown_capability_key_is_rejected(tmp_path: Path):
    plan = _plan_dict(tmp_path, "opengrep")
    plan["category_tool"]["totally-made-up"] = "foo"
    assert vsp.validate(plan) != []


def test_unknown_degraded_capability_is_rejected(tmp_path: Path):
    plan = _plan_dict(tmp_path)
    plan["degraded"] = ["not-a-capability"]
    assert vsp.validate(plan) != []


def test_additional_root_property_is_rejected(tmp_path: Path):
    plan = _plan_dict(tmp_path, "opengrep")
    plan["surprise"] = True
    assert vsp.validate(plan) != []


def test_wrong_type_ai_pass_is_rejected(tmp_path: Path):
    plan = _plan_dict(tmp_path, "opengrep")
    plan["ai_pass"] = "yes"  # must be boolean
    assert vsp.validate(plan) != []
