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
    # ADR-027: inject admitted tools (trivy/govulncheck removed from SCANNER_PREFERENCE);
    # the assertion (only-installed-known-scanners, sorted) is unchanged.
    which = _which_only("osv-scanner", "gitleaks")
    assert dt.detect_available_tools(which) == ["gitleaks", "osv-scanner"]


# === ported PoC tests: scan-plan assembly + graceful degradation ==========
def test_plan_picks_best_signal_first(tmp_path: Path):
    # ADR-027: admitted per-category tools for a Go repo (gosec serves go, osv-scanner
    # serves *, gitleaks serves *) — each is first-in-list for its capability, so the
    # best-signal-first + all-caps-covered (degraded is False) intent is unchanged.
    (tmp_path / "go.mod").write_text("module x\n")
    which = _which_only("gosec", "osv-scanner", "gitleaks")
    plan = dt.build_scan_plan(tmp_path, which)
    assert plan.category_tool["sast"] == "gosec"
    assert plan.category_tool["sca"] == "osv-scanner"
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
    # ADR-027: cargo-audit (admitted, serves rust) replaces govulncheck as the
    # language-mismatch case — installed but does NOT serve python → sca degrades.
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    which = _which_only("cargo-audit")
    plan = dt.build_scan_plan(tmp_path, which)
    assert plan.category_tool["sca"] is None  # cargo-audit doesn't serve python
    assert "sca" in plan.degraded_categories


def test_iac_category_only_when_infra_present(tmp_path: Path):
    # ADR-027: checkov (admitted, fills hadolint's Dockerfile slot) replaces trivy as
    # the installed IaC tool; the conditional-category intent is unchanged.
    (tmp_path / "go.mod").write_text("module x\n")
    which = _which_only("checkov")
    plan_no_infra = dt.build_scan_plan(tmp_path, which)
    assert "iac" not in plan_no_infra.category_tool

    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    plan_infra = dt.build_scan_plan(tmp_path, which)
    assert plan_infra.category_tool["iac"] == "checkov"


# RETIRED (ADR-027): test_iac_prefers_checkov_over_trivy_when_both_present asserted
# the wh-d5b *interim* demotion of Trivy below Checkov ("returns when cleared"). ADR-027
# makes the Trivy removal PERMANENT — Trivy can never be installed/selected, so a
# Checkov-beats-Trivy ordering test is moot. Trivy-absent is now pinned in the lock
# (test_registry_lock.py::test_trivy_absent_from_every_category).


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


# === Phase-4 (T-4.6): MCP detection flips ai_pass on its own ==============
def test_ai_pass_true_for_mcp_only_python(tmp_path: Path):
    # An MCP-only repo (no langchain/openai/anthropic) must still flip ai_pass.
    (tmp_path / "requirements.txt").write_text("mcp==1.10.0\nhttpx\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is True
    assert "mcp" in plan.frameworks
    assert "ai-llm.md" in plan.reference_appendices


def test_ai_pass_true_for_mcp_npm_sdk(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "^1.10.0", "express": "^4"}}'
    )
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is True
    assert "mcp" in plan.frameworks


def test_ai_pass_true_for_fastmcp(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=['fastmcp>=2']\n")
    assert dt.build_scan_plan(tmp_path, _which_only()).ai_pass is True


def test_mcp_token_not_overmatched(tmp_path: Path):
    # An unrelated dependency containing the substring "mcp" must NOT flip ai_pass.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"some-mcp-helper": "^1", "express": "^4"}}'
    )
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is False
    assert "mcp" not in plan.frameworks


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
    d = dt.build_scan_plan(tmp_path, _which_only("bandit")).to_dict()
    for key in ("schema_version", "languages", "infra", "frameworks",
                "available_tools", "ai_pass", "category_tool", "degraded",
                "reference_appendices", "fallback", "kernel_adjacency"):
        assert key in d, f"missing {key}"
    assert isinstance(d["degraded"], list)
    assert isinstance(d["ai_pass"], bool)


# === wh-a49 (spike-10 T-A): kernel/container trust-boundary awareness ======
# ADVISORY altitude (ADR-018): deterministic detection only — NO CVSS, NEVER a
# VULN-FINDINGS entry. Each invariant pins == expected AND != the wrong value
# (Rule 9). Markers: "ebpf", "kernel-module", "privileged-container".

# --- eBPF marker ---
def test_kernel_adjacency_ebpf_bpf_c_file(tmp_path: Path):
    (tmp_path / "tracer.bpf.c").write_text("// SEC(\"tracepoint\")\n")
    markers = dt.detect_kernel_adjacency(tmp_path)
    assert "ebpf" in markers          # == expected
    assert "kernel-module" not in markers  # != the wrong class
    assert "privileged-container" not in markers


def test_kernel_adjacency_ebpf_go_mod_libbpf(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        "module x\n\nrequire github.com/cilium/ebpf v0.16.0\n"
    )
    markers = dt.detect_kernel_adjacency(tmp_path)
    assert "ebpf" in markers
    assert markers == ["ebpf"]  # only the eBPF class, nothing spurious


def test_kernel_adjacency_ebpf_bpf2go(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        "module x\n\nrequire github.com/aquasecurity/libbpfgo v0.7.0\n"
    )
    assert "ebpf" in dt.detect_kernel_adjacency(tmp_path)


def test_kernel_adjacency_ebpf_bpftrace_script(tmp_path: Path):
    (tmp_path / "trace.bt").write_text("tracepoint:syscalls:sys_enter_open { @[comm] = count(); }\n")
    assert dt.detect_kernel_adjacency(tmp_path) == ["ebpf"]


# --- kernel-module marker ---
def test_kernel_adjacency_kbuild(tmp_path: Path):
    (tmp_path / "Kbuild").write_text("obj-m += foo.o\n")
    markers = dt.detect_kernel_adjacency(tmp_path)
    assert "kernel-module" in markers
    assert "ebpf" not in markers


def test_kernel_adjacency_makefile_obj_m(tmp_path: Path):
    (tmp_path / "Makefile").write_text("obj-m += hello.o\n\nall:\n\tmake -C /lib/modules\n")
    assert dt.detect_kernel_adjacency(tmp_path) == ["kernel-module"]


def test_kernel_adjacency_ko_file(tmp_path: Path):
    (tmp_path / "driver.ko").write_bytes(b"\x7fELF")
    assert "kernel-module" in dt.detect_kernel_adjacency(tmp_path)


def test_kernel_adjacency_dkms_conf(tmp_path: Path):
    (tmp_path / "dkms.conf").write_text('PACKAGE_NAME="foo"\nPACKAGE_VERSION="1.0"\n')
    assert dt.detect_kernel_adjacency(tmp_path) == ["kernel-module"]


def test_plain_makefile_without_obj_m_is_not_kernel_module(tmp_path: Path):
    # A normal app Makefile must NOT be misread as a kernel module.
    (tmp_path / "Makefile").write_text("build:\n\tgo build ./...\ntest:\n\tgo test ./...\n")
    assert dt.detect_kernel_adjacency(tmp_path) == []


# --- privileged-container marker ---
def test_kernel_adjacency_compose_privileged(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: x\n    privileged: true\n"
    )
    markers = dt.detect_kernel_adjacency(tmp_path)
    assert "privileged-container" in markers
    assert "ebpf" not in markers


def test_kernel_adjacency_k8s_privileged_pod(tmp_path: Path):
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: c\n"
        "    securityContext:\n      privileged: true\n"
    )
    assert dt.detect_kernel_adjacency(tmp_path) == ["privileged-container"]


def test_kernel_adjacency_k8s_host_namespaces(tmp_path: Path):
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
        "      hostPID: true\n      hostNetwork: true\n"
    )
    assert "privileged-container" in dt.detect_kernel_adjacency(tmp_path)


def test_kernel_adjacency_k8s_hostpath(tmp_path: Path):
    (tmp_path / "vol.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nspec:\n  volumes:\n  - name: h\n"
        "    hostPath:\n      path: /\n"
    )
    assert "privileged-container" in dt.detect_kernel_adjacency(tmp_path)


def test_kernel_adjacency_cap_sys_admin(tmp_path: Path):
    (tmp_path / "pod.yaml").write_text(
        "spec:\n  containers:\n  - securityContext:\n      capabilities:\n"
        "        add: [CAP_SYS_ADMIN]\n"
    )
    assert "privileged-container" in dt.detect_kernel_adjacency(tmp_path)


# --- negative: plain app repo -> empty (the key advisory invariant) ---
def test_plain_app_repo_has_no_kernel_adjacency(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\nrequire github.com/go-chi/chi v5\n")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\nUSER 10001\n")
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
        "      securityContext:\n        runAsNonRoot: true\n"
    )
    assert dt.detect_kernel_adjacency(tmp_path) == []  # == empty


def test_empty_repo_has_no_kernel_adjacency(tmp_path: Path):
    assert dt.detect_kernel_adjacency(tmp_path) == []


# --- combined repo: multiple marker classes, sorted + deduped ---
def test_kernel_adjacency_multiple_classes_sorted(tmp_path: Path):
    (tmp_path / "probe.bpf.c").write_text("// ebpf\n")
    (tmp_path / "Kbuild").write_text("obj-m += m.o\n")
    (tmp_path / "docker-compose.yml").write_text("services:\n  a:\n    privileged: true\n")
    markers = dt.detect_kernel_adjacency(tmp_path)
    assert markers == ["ebpf", "kernel-module", "privileged-container"]  # sorted, deduped


# --- the field is additive on ScanPlan / to_dict + populated in build_scan_plan ---
def test_scan_plan_populates_kernel_adjacency(tmp_path: Path):
    (tmp_path / "tracer.bpf.c").write_text("// ebpf\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.kernel_adjacency == ["ebpf"]
    assert plan.to_dict()["kernel_adjacency"] == ["ebpf"]


def test_scan_plan_kernel_adjacency_default_empty(tmp_path: Path):
    # Always emitted, empty list when no markers (advisory metadata, not a finding).
    (tmp_path / "go.mod").write_text("module x\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.kernel_adjacency == []
    d = plan.to_dict()
    assert d["kernel_adjacency"] == []
    assert isinstance(d["kernel_adjacency"], list)


# === wh-7u7: AI-agent-infra advisory ======================================
# ADVISORY altitude: deterministic file-presence + bounded depth-capped tree walk.
# Returns a sorted subset of {".claude","agents","mcp.json","skill","nested-ai-manifest"}.
# NOT a finding (no CVSS). Drives ai_pass_advisory (derived in to_dict() only).
# Rule 9: each invariant pins == expected AND != the wrong value.

# --- detect_ai_agent_infra unit tests ---

def test_detect_ai_agent_infra_dot_claude_dir(tmp_path: Path):
    (tmp_path / ".claude").mkdir()
    result = dt.detect_ai_agent_infra(tmp_path)
    assert ".claude" in result                   # == expected
    assert "nested-ai-manifest" not in result    # != the wrong class


def test_detect_ai_agent_infra_agents_dir(tmp_path: Path):
    (tmp_path / "agents").mkdir()
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "agents" in result                    # == expected
    assert ".claude" not in result               # != the wrong class


def test_detect_ai_agent_infra_mcp_json_file(tmp_path: Path):
    (tmp_path / "mcp.json").write_text('{"mcpServers": {}}')
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "mcp.json" in result                  # == expected
    assert "nested-ai-manifest" not in result    # != the wrong class


def test_detect_ai_agent_infra_skill_file_in_subdir(tmp_path: Path):
    subdir = tmp_path / "plugins" / "some-skill"
    subdir.mkdir(parents=True)
    (subdir / "my.skill").write_text("skill content")
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "skill" in result                     # == expected
    assert ".claude" not in result               # != the wrong class


def test_detect_ai_agent_infra_nested_ai_manifest(tmp_path: Path):
    # AI-SDK manifest in a SUBDIR (not root) must be detected.
    subdir = tmp_path / "services" / "ml-api"
    subdir.mkdir(parents=True)
    (subdir / "requirements.txt").write_text("langchain==0.3.0\nhttpx\n")
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "nested-ai-manifest" in result        # == expected
    assert ".claude" not in result               # != the wrong class


def test_detect_ai_agent_infra_root_manifest_not_nested(tmp_path: Path):
    # Root-level AI manifest is already handled by ai_pass — must NOT trigger
    # nested-ai-manifest (that would be a false double-count).
    (tmp_path / "requirements.txt").write_text("langchain==0.3.0\n")
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "nested-ai-manifest" not in result    # root is NOT nested
    assert result == []                          # nothing else either


def test_detect_ai_agent_infra_non_ai_nested_repo(tmp_path: Path):
    # Non-AI nested manifest must NOT trigger.
    subdir = tmp_path / "services" / "web"
    subdir.mkdir(parents=True)
    (subdir / "requirements.txt").write_text("flask==3.0\ngunicorn\n")
    result = dt.detect_ai_agent_infra(tmp_path)
    assert result == []                          # no over-trigger
    assert "nested-ai-manifest" not in result    # != wrong value


def test_detect_ai_agent_infra_venv_exclusion(tmp_path: Path):
    # AI-SDK manifest INSIDE .venv/ must NOT be detected (binding resource AC).
    venv_lib = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    venv_lib.mkdir(parents=True)
    (venv_lib / "requirements.txt").write_text("langchain==0.3.0\n")
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "nested-ai-manifest" not in result    # pruned, not detected
    assert result == []                          # no false positive


def test_detect_ai_agent_infra_returns_sorted(tmp_path: Path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / "agents").mkdir()
    (tmp_path / "mcp.json").write_text("{}")
    result = dt.detect_ai_agent_infra(tmp_path)
    assert result == sorted(result)              # always sorted
    assert len(result) == 3                      # all three markers present


def test_detect_ai_agent_infra_empty_repo(tmp_path: Path):
    assert dt.detect_ai_agent_infra(tmp_path) == []


# --- advisory integration: build_scan_plan + to_dict ----------------------

def test_advisory_false_when_ai_pass_true(tmp_path: Path):
    # Root AI-SDK dep → ai_pass True → no advisory needed.
    (tmp_path / "requirements.txt").write_text("langchain==0.3.0\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is True                              # == expected (unchanged)
    assert plan.to_dict()["ai_pass_advisory"] is False       # != True (no advisory)


def test_advisory_true_for_nested_ai_repo(tmp_path: Path):
    # AI-SDK manifest only in a SUBDIR (root has none) — THE FIX for F-008.
    subdir = tmp_path / "services" / "ml-api"
    subdir.mkdir(parents=True)
    (subdir / "requirements.txt").write_text("langchain==0.3.0\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is False                                   # unchanged
    assert "nested-ai-manifest" in plan.ai_agent_infra             # == expected
    assert plan.to_dict()["ai_pass_advisory"] is True              # THE FIX


def test_advisory_true_for_dot_claude_repo(tmp_path: Path):
    # .claude/ agent-config dir present, no AI-SDK manifest anywhere.
    (tmp_path / ".claude").mkdir()
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is False                                   # unchanged
    assert ".claude" in plan.ai_agent_infra                        # == expected
    assert plan.to_dict()["ai_pass_advisory"] is True              # advisory fires


def test_advisory_false_for_plain_repo(tmp_path: Path):
    # Non-AI nested dep, no .claude/agents/mcp.json → no over-trigger.
    subdir = tmp_path / "services" / "web"
    subdir.mkdir(parents=True)
    (subdir / "requirements.txt").write_text("flask==3.0\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_agent_infra == []                               # no markers
    assert plan.to_dict()["ai_pass_advisory"] is False             # no over-trigger


def test_advisory_venv_exclusion_binding(tmp_path: Path):
    # Binding resource AC: AI inside .venv/ must NOT trigger the advisory.
    venv_lib = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    venv_lib.mkdir(parents=True)
    (venv_lib / "requirements.txt").write_text("langchain==0.3.0\n")
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert "nested-ai-manifest" not in plan.ai_agent_infra         # pruned
    assert plan.to_dict()["ai_pass_advisory"] is False             # no false positive


def test_to_dict_always_has_ai_agent_infra_and_advisory_keys(tmp_path: Path):
    # Both keys always present regardless of detected infra (like kernel_adjacency).
    (tmp_path / "go.mod").write_text("module x\n")
    d = dt.build_scan_plan(tmp_path, _which_only()).to_dict()
    assert "ai_agent_infra" in d                                   # always present
    assert "ai_pass_advisory" in d                                  # always present
    assert isinstance(d["ai_agent_infra"], list)                   # correct type
    assert isinstance(d["ai_pass_advisory"], bool)                 # correct type
    assert d["ai_agent_infra"] != "MISSING"                        # != wrong value


# --- F-1 fix: is_file() guard + bounded 64 KiB read (wh-7u7 Phase-5) ------
# CWE-400 / DoS: untrusted repos can commit symlinks-to-devices or multi-GB
# manifests; the read must be capped and special files must be skipped.

def test_detect_ai_agent_infra_token_within_read_cap_detected(tmp_path: Path):
    # Normal manifest with AI token near the top — still detected after the fix.
    subdir = tmp_path / "svc"
    subdir.mkdir()
    (subdir / "requirements.txt").write_text("langchain==0.3.0\nhttpx\n")
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "nested-ai-manifest" in result    # == expected (token in cap window)
    assert ".claude" not in result           # != wrong class


def test_detect_ai_agent_infra_token_beyond_read_cap_not_detected(tmp_path: Path):
    # AI token placed ONLY beyond the 64 KiB read cap must NOT be detected.
    # RED before fix (unbounded read finds it); GREEN after fix (capped read skips it).
    subdir = tmp_path / "svc"
    subdir.mkdir()
    padding = "# " + "x" * 65535 + "\n"  # pushes token past 64 KiB offset
    (subdir / "requirements.txt").write_text(padding + "langchain==0.3.0\n")
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "nested-ai-manifest" not in result  # beyond cap → NOT detected
    assert result == []                        # no false positive


def test_detect_ai_agent_infra_special_file_skipped(tmp_path: Path):
    # A FIFO masquerading as requirements.txt must be skipped — NOT read (hangs).
    # is_file() returns False for FIFOs, broken symlinks, and character devices.
    import os as _os
    import pytest as _pytest
    if not hasattr(_os, "mkfifo"):
        _pytest.skip("os.mkfifo not available on this platform")
    subdir = tmp_path / "svc"
    subdir.mkdir()
    fifo_path = subdir / "requirements.txt"
    _os.mkfifo(str(fifo_path))
    # If the is_file() guard is missing this call hangs; with the fix it returns.
    result = dt.detect_ai_agent_infra(tmp_path)
    assert "nested-ai-manifest" not in result  # == expected (FIFO skipped)
    assert result == []                        # != any marker accidentally set


# --- DEFECT-1: advisory suppression when ai_pass=True and infra present ----
# Mutation guard: `(not ai_pass) and bool(infra)` → `bool(infra)` would make
# advisory True even when the AI pass is already running — this test catches it.

def test_advisory_suppressed_when_ai_pass_true_and_infra_present(tmp_path: Path):
    # Root AI-SDK dep flips ai_pass=True; .claude/ also detected.
    # Advisory must be False — the AI pass already runs, no advisory needed.
    (tmp_path / "requirements.txt").write_text("langchain==0.3.0\n")
    (tmp_path / ".claude").mkdir()
    plan = dt.build_scan_plan(tmp_path, _which_only())
    assert plan.ai_pass is True                              # == expected
    assert ".claude" in plan.ai_agent_infra                 # infra also detected
    assert plan.to_dict()["ai_pass_advisory"] is False      # suppressed (mutation guard)


# --- wh-e1d: _read_manifest_text is_file() guard + bounded 64 KiB read ------
# Same DoS class as wh-7u7 F-1 (CWE-400), but for the ROOT-level manifest reader
# shared by _match_signals (frameworks) and detect_kernel_adjacency
# (Makefile/go.mod). One guard hardens every caller. The read MUST be capped and
# non-regular paths (FIFO/device/dir) MUST be skipped, never blocking/raising.

def test_read_manifest_text_caps_at_read_cap(tmp_path: Path):
    # A manifest larger than the cap is read ONLY up to _AI_MANIFEST_READ_CAP,
    # lowercased. Pin both directions (Policy 9): == capped prefix, != full text.
    head = "Django==5.1\n"
    body = "x" * (dt._AI_MANIFEST_READ_CAP + 4096)
    (tmp_path / "requirements.txt").write_text(head + body)
    text = dt._read_manifest_text(tmp_path, "requirements.txt")
    full = (head + body).lower()
    assert text == full[: dt._AI_MANIFEST_READ_CAP]    # == capped prefix
    assert text != full                                # != unbounded read
    assert len(text) == dt._AI_MANIFEST_READ_CAP       # exactly the cap


def test_frameworks_token_within_cap_detected(tmp_path: Path):
    # django token near the top (within the cap window) → still detected after fix.
    (tmp_path / "requirements.txt").write_text("django==5.1\n" + "x" * 70000)
    assert "django" in dt.detect_frameworks(tmp_path)   # == expected (in cap)


def test_frameworks_token_beyond_cap_not_detected(tmp_path: Path):
    # django token placed ONLY beyond the 64 KiB cap → NOT detected.
    # RED before fix (unbounded read finds it); GREEN after (capped read skips it).
    padding = "# " + "x" * dt._AI_MANIFEST_READ_CAP + "\n"
    (tmp_path / "requirements.txt").write_text(padding + "django==5.1\n")
    assert "django" not in dt.detect_frameworks(tmp_path)  # beyond cap → miss
    assert dt.detect_frameworks(tmp_path) == []            # no false positive


def test_read_manifest_text_skips_fifo_without_hanging(tmp_path: Path):
    # A FIFO masquerading as a manifest must return '' instantly, never block.
    # is_file() is False for FIFOs; without the guard read_text() blocks forever.
    import os as _os
    import threading
    import pytest as _pytest
    if not hasattr(_os, "mkfifo"):
        _pytest.skip("os.mkfifo not available on this platform")
    _os.mkfifo(str(tmp_path / "go.mod"))

    result: dict[str, str] = {}

    def _call() -> None:
        result["text"] = dt._read_manifest_text(tmp_path, "go.mod")

    # Watchdog thread + join-timeout: a missing guard FAILS FAST here instead of
    # hanging the whole suite (the daemon thread is abandoned at process exit).
    worker = threading.Thread(target=_call, daemon=True)
    worker.start()
    worker.join(timeout=5.0)
    assert not worker.is_alive(), "read blocked on a FIFO (missing is_file guard)"
    assert result["text"] == ""    # == expected (special file skipped)


def test_read_manifest_text_skips_directory(tmp_path: Path):
    # A directory named like a manifest is not a regular file → ''.
    (tmp_path / "go.mod").mkdir()
    assert dt._read_manifest_text(tmp_path, "go.mod") == ""   # == expected


def test_read_manifest_text_small_manifest_unchanged(tmp_path: Path):
    # Regression: a normal small manifest is read in full and lowercased.
    (tmp_path / "go.mod").write_text(
        "module X\nrequire github.com/Gin-Gonic/gin v1\n"
    )
    text = dt._read_manifest_text(tmp_path, "go.mod")
    assert text == "module x\nrequire github.com/gin-gonic/gin v1\n"  # full + lower
    assert "gin-gonic/gin" in text                                    # token kept
