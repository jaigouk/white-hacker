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
    d = dt.build_scan_plan(tmp_path, _which_only("opengrep")).to_dict()
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
