"""Tests for sec-detect's language/framework/tool detection.

Two layers:
  * the original PoC behaviour (language + infra + tool detection + degradation) —
    these are the ≥12 ported tests that must keep passing;
  * the Phase-2 additions (framework fingerprint, ai_pass trigger, ai-redteam
    capability, reference-appendix selection, SCAN-PLAN dict shape).

Run: `uv run --with pytest pytest .claude/skills/sec-detect/scripts/`
"""
from __future__ import annotations

from pathlib import Path

import detect_tools as dt


# === ported PoC tests: language detection =================================
def test_detects_go(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    assert dt.detect_languages(tmp_path) == ["go"]


def test_detects_python_variants(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    assert dt.detect_languages(tmp_path) == ["python"]


def test_typescript_beats_javascript(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "tsconfig.json").write_text("{}")
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


# === ported PoC tests: infra detection ====================================
def test_detects_dockerfile_and_actions(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert dt.detect_infra(tmp_path) == ["docker", "github-actions"]


# === ported PoC tests: available-tool detection (injected which) ==========
def _which_only(*present: str):
    present_set = set(present)
    return lambda name: f"/usr/bin/{name}" if name in present_set else None


def test_available_tools_filters_to_installed():
    which = _which_only("trivy", "govulncheck")
    assert dt.detect_available_tools(which) == ["govulncheck", "trivy"]


# === ported PoC tests: scan-plan assembly + graceful degradation ==========
def test_plan_picks_best_signal_first(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    which = _which_only("opengrep", "govulncheck", "gitleaks")
    plan = dt.build_scan_plan(tmp_path, which)
    assert plan.category_tool["sast"] == "opengrep"
    assert plan.category_tool["sca"] == "govulncheck"
    assert plan.category_tool["secrets"] == "gitleaks"
    assert plan.degraded is False


def test_plan_degrades_when_category_tool_missing(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    which = _which_only("gitleaks")
    plan = dt.build_scan_plan(tmp_path, which)
    assert plan.category_tool["sast"] is None
    assert plan.category_tool["sca"] is None
    assert "sast" in plan.degraded_categories
    assert "sca" in plan.degraded_categories
    assert plan.degraded is True
    assert plan.to_dict()["fallback"].startswith("read-grep-glob")


def test_sca_tool_language_match(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    which = _which_only("govulncheck")
    plan = dt.build_scan_plan(tmp_path, which)
    assert plan.category_tool["sca"] is None  # govulncheck doesn't serve python
    assert "sca" in plan.degraded_categories


def test_iac_category_only_when_infra_present(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    which = _which_only("trivy")
    plan_no_infra = dt.build_scan_plan(tmp_path, which)
    assert "iac" not in plan_no_infra.category_tool

    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    plan_infra = dt.build_scan_plan(tmp_path, which)
    assert plan_infra.category_tool["iac"] == "trivy"


# === Phase-2: framework fingerprint =======================================
def test_fingerprints_next_and_react(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"next": "15.2.3", "react": "19.0.0"}}'
    )
    (tmp_path / "tsconfig.json").write_text("{}")
    frameworks = dt.detect_frameworks(tmp_path)
    assert "next" in frameworks
    assert "react" in frameworks


def test_fingerprints_python_web_frameworks(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("Django==5.1\ndjangorestframework\n")
    assert "django" in dt.detect_frameworks(tmp_path)


def test_fingerprints_go_router(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        "module x\n\nrequire github.com/gin-gonic/gin v1.10.0\n"
    )
    assert "gin" in dt.detect_frameworks(tmp_path)


def test_fingerprints_java_spring(tmp_path: Path):
    (tmp_path / "pom.xml").write_text(
        "<project><dependency><artifactId>spring-boot-starter-security"
        "</artifactId></dependency></project>"
    )
    frameworks = dt.detect_frameworks(tmp_path)
    assert "spring-boot" in frameworks
    assert "spring-security" in frameworks


def test_no_frameworks_in_empty_repo(tmp_path: Path):
    assert dt.detect_frameworks(tmp_path) == []


# === Phase-2: ai_pass trigger =============================================
def test_ai_pass_true_for_python_langchain(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("langchain==0.3.0\nfastapi\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is True
    assert "langchain" in plan.frameworks


def test_ai_pass_true_for_typescript_stack(tmp_path: Path):
    # AI deps in a non-Python stack still flip ai_pass (e.g. a TS LangChain app).
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@anthropic-ai/sdk": "^0.30.0", "express": "^4.19.0"}}'
    )
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is True
    assert "anthropic" in plan.frameworks


def test_ai_pass_false_without_ai_deps(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\nrequire github.com/go-chi/chi v5\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is False


# === Phase-2: ai-redteam capability is conditional on ai_pass =============
def test_ai_redteam_category_only_when_ai_pass(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask\n")  # no AI deps
    plan_no_ai = dt.build_scan_plan(tmp_path, _which_only("promptfoo"))
    assert "ai-redteam" not in plan_no_ai.category_tool

    (tmp_path / "requirements.txt").write_text("flask\nopenai\n")
    plan_ai = dt.build_scan_plan(tmp_path, _which_only("promptfoo"))
    assert plan_ai.category_tool["ai-redteam"] == "promptfoo"


def test_ai_redteam_degrades_to_floor_when_no_tool(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("transformers\ntorch\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())  # nothing installed
    assert plan.category_tool["ai-redteam"] is None
    assert "ai-redteam" in plan.degraded_categories


# === Phase-2: reference-appendix selection ================================
def test_appendices_for_python_ai_backend(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("fastapi\nlangchain\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    appendices = plan.reference_appendices
    assert "lang-python.md" in appendices  # language
    assert "api.md" in appendices          # fastapi is a web framework
    assert "ai-llm.md" in appendices       # ai_pass


def test_appendices_include_infra_when_dockerfile(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert "infra.md" in plan.reference_appendices
    assert "lang-go.md" in plan.reference_appendices


def test_javascript_maps_to_typescript_appendix(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4"}}')
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert "lang-typescript.md" in plan.reference_appendices


# === Phase-2: SCAN-PLAN dict shape (locks emitter ↔ schema) ===============
def test_to_dict_has_required_scan_plan_keys(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=['fastapi']\n")
    d = dt.build_scan_plan(tmp_path, _which_only("opengrep")).to_dict()
    for key in ("schema_version", "languages", "infra", "frameworks",
                "available_tools", "ai_pass", "category_tool", "degraded",
                "reference_appendices", "fallback"):
        assert key in d, f"missing {key}"
    assert isinstance(d["degraded"], list)
    assert isinstance(d["ai_pass"], bool)
