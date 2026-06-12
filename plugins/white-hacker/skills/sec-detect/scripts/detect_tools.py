"""Language + framework + security-tool detection → SCAN-PLAN.json emitter.

Promoted from `docs/research/poc-tool-detection/detect_tools.py` (the spike that
verified the two core assumptions) and extended for Phase 2 with:
  * a **framework fingerprint** layer (read manifest *contents*, not just names),
  * an **`ai_pass`** trigger when AI/LLM deps are present (drives `ai-llm-review`),
  * an **`ai-redteam`** capability that only appears when `ai_pass` is set, and
  * a **SCAN-PLAN.json**-shaped `to_dict()` (the artifact `sec-vuln-scan` consumes).

Design invariants (ADR-003, ADR-015):
  * depend on a **capability** (sast/sca/secrets/iac/ai-redteam), never a brand;
  * discover what is installed at runtime — `which` is injectable for hermetic tests;
  * **never block** on a missing tool: degrade to the Read/Grep/Glob floor and record
    the category under `degraded` so downstream caps confidence.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA_VERSION = "1.0"

# --- manifest signal file -> language -------------------------------------
# Order matters only for reporting; detection is set-based.
MANIFEST_SIGNALS: dict[str, str] = {
    "go.mod": "go",
    "go.sum": "go",
    "tsconfig.json": "typescript",
    "package.json": "javascript",  # upgraded to typescript if tsconfig present
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "Pipfile": "python",
    "uv.lock": "python",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "Cargo.toml": "rust",
}

# IaC / CI layers are always in scope when present (scanned regardless of lang).
INFRA_SIGNALS: dict[str, str] = {
    "Dockerfile": "docker",
    ".github/workflows": "github-actions",
}

# --- framework fingerprint (read manifest CONTENTS) -----------------------
# name -> (manifest filenames to read, substring tokens searched case-insensitively).
# Tokens are matched against the raw lowercased manifest text — robust enough for a
# fingerprint and hermetic (no TOML/JSON/XML parser needed, no parse-failure on junk).
FRAMEWORK_SIGNALS: dict[str, tuple[set[str], tuple[str, ...]]] = {
    # TS / JS
    "next": ({"package.json"}, ('"next"',)),
    "react": ({"package.json"}, ('"react"',)),
    "vue": ({"package.json"}, ('"vue"',)),
    "angular": ({"package.json"}, ('"@angular/core"',)),
    "express": ({"package.json"}, ('"express"',)),
    "fastify": ({"package.json"}, ('"fastify"',)),
    "nestjs": ({"package.json"}, ('"@nestjs/core"',)),
    # Python
    "django": ({"requirements.txt", "pyproject.toml", "Pipfile"}, ("django",)),
    "flask": ({"requirements.txt", "pyproject.toml", "Pipfile"}, ("flask",)),
    "fastapi": ({"requirements.txt", "pyproject.toml", "Pipfile"}, ("fastapi",)),
    # Go (module import paths in go.mod)
    "gin": ({"go.mod"}, ("gin-gonic/gin",)),
    "chi": ({"go.mod"}, ("go-chi/chi",)),
    "echo": ({"go.mod"}, ("labstack/echo",)),
    # Java (Maven/Gradle coordinates)
    "spring-boot": ({"pom.xml", "build.gradle", "build.gradle.kts"}, ("spring-boot",)),
    # both the direct module (spring-security-*) and the Boot starter imply usage.
    "spring-security": ({"pom.xml", "build.gradle", "build.gradle.kts"},
                        ("spring-security", "spring-boot-starter-security")),
    "jackson": ({"pom.xml", "build.gradle", "build.gradle.kts"}, ("jackson",)),
}

# AI/LLM deps — presence flips `ai_pass` and pulls in the ai-llm.md appendix +
# the ai-redteam capability. Detected for ANY stack (e.g. a TS LangChain app).
AI_FRAMEWORK_SIGNALS: dict[str, tuple[set[str], tuple[str, ...]]] = {
    "langchain": ({"requirements.txt", "pyproject.toml", "Pipfile", "package.json"}, ("langchain",)),
    "transformers": ({"requirements.txt", "pyproject.toml", "Pipfile"}, ("transformers",)),
    "torch": ({"requirements.txt", "pyproject.toml", "Pipfile"}, ("torch",)),
    "openai": ({"requirements.txt", "pyproject.toml", "Pipfile", "package.json"}, ("openai",)),
    "anthropic": ({"requirements.txt", "pyproject.toml", "Pipfile", "package.json"}, ("anthropic",)),
    # MCP (Model Context Protocol). An MCP repo is an AI surface even without an LLM SDK,
    # so it must flip ai_pass on its own. Tokens are precise to avoid matching the bare
    # substring "mcp" inside unrelated names: the npm SDK, the `modelcontextprotocol`
    # string, fastmcp, and the Python `mcp` package in its pinned/extra/quoted forms.
    "mcp": ({"requirements.txt", "pyproject.toml", "Pipfile", "package.json"},
            ("modelcontextprotocol", "@modelcontextprotocol/sdk", "fastmcp",
             '"mcp"', "mcp==", "mcp>=", "mcp~=", "mcp[")),
}

# --- AI-agent-infra advisory constants (wh-7u7) ---------------------------
# Directories pruned from the bounded tree walk (resource discipline: a dev
# machine may run on-access EDR; every touched file is scanned — see CLAUDE.md).
_PRUNE_DIRS: frozenset[str] = frozenset({
    ".venv", "node_modules", ".git", "__pycache__",
    "dist", "build", ".pytest_cache", ".mypy_cache",
})

# Manifest file names that may carry nested AI-SDK declarations.
# (Derived from AI_FRAMEWORK_SIGNALS keys — keep in sync.)
_AI_NESTED_MANIFEST_NAMES: frozenset[str] = frozenset(
    fname
    for files, _tokens in AI_FRAMEWORK_SIGNALS.values()
    for fname in files
)

# All token strings extracted from AI_FRAMEWORK_SIGNALS (lowercased at match time).
_AI_NESTED_TOKENS: tuple[str, ...] = tuple(
    tok
    for _files, tokens in AI_FRAMEWORK_SIGNALS.values()
    for tok in tokens
)

# Depth cap for the bounded walk (relative to root).  Keeps the walk from
# descending into deeply-nested build artefacts not covered by _PRUNE_DIRS.
_AI_INFRA_MAX_DEPTH: int = 5

# Maximum bytes read from a nested manifest when scanning for AI-SDK tokens.
# AI-SDK tokens appear near the top of requirements.txt / pyproject.toml /
# package.json, so 64 KiB is more than sufficient.  Capping the read protects
# against DoS via multi-GB committed manifests (CWE-400, F-1, wh-7u7 Phase-5).
_AI_MANIFEST_READ_CAP: int = 65536  # 64 KiB

# Backend/web frameworks → the API appendix (OWASP API Top 10) is applicable.
WEB_FRAMEWORKS: frozenset[str] = frozenset(
    {"next", "express", "fastify", "nestjs", "django", "flask", "fastapi",
     "gin", "chi", "echo", "spring-boot"}
)

# language -> the per-language reference appendix loaded on demand.
LANG_APPENDIX: dict[str, str] = {
    "go": "lang-go.md",
    "python": "lang-python.md",
    "typescript": "lang-typescript.md",
    "javascript": "lang-typescript.md",  # JS shares the TS appendix
    "java": "lang-java.md",
}

# --- per-category scanner preference (best signal first) ------------------
# Each entry: category -> ordered list of (tool, languages-it-serves|"*").
# Admissibility governs WHICH tools sit here (ADR-025: MIT/Apache-2.0-only license
# gate + local/no-default-telemetry egress gate) and ADR-027 (Trivy permanently
# removed — TeamPCP, does not return). The executable twin of
# `_shared/reference/tool-registry.md`; `test_registry_lock.py` keeps them in sync.
#
# NOT wired here on purpose:
#   * cross-language SAST engine — no MIT/Apache one exists in 2026 (Opengrep/Semgrep
#     are LGPL-2.1); the SAST default is per-language linters + the floor (ADR-025 §4).
#     Wiring a cross-language engine is the gated SAST-default flip — a NAMED follow-up
#     measured on a Java-inclusive corpus, deliberately NOT done here (ADR-027 §6).
#   * Grype/Syft (image/SBOM) — registry-listed but never auto-selected by this static
#     filesystem default (no surprise docker/image pull — ADR-007); explicit scope only.
SCANNER_PREFERENCE: dict[str, list[tuple[str, str]]] = {
    # Per-language MIT/Apache linters + the floor (ADR-025 §4 supersedes ADR-011's
    # cross-language Opengrep default). Java taint is floor-only (no admissible Java
    # SAST after find-sec-bugs/SpotBugs LGPL drop — ADR-025 §3).
    "sast": [("gosec", "go"), ("bandit", "python"), ("ruff", "python"),
             ("eslint-plugin-security", "typescript")],
    # Trivy + govulncheck (BSD-3) dropped; cargo-audit (MIT/Apache dual) added.
    "sca": [("pip-audit", "python"), ("osv-scanner", "*"),
            ("cargo-audit", "rust")],
    # trufflehog (AGPL-3.0) dropped; detect-secrets (Apache-2.0) added.
    "secrets": [("gitleaks", "*"), ("detect-secrets", "*")],
    # Trivy + hadolint (GPL-3.0) dropped; Checkov first (covers Dockerfile in
    # hadolint's slot) + actionlint/zizmor for GH Actions.
    "iac": [("checkov", "*"), ("actionlint", "github-actions"),
            ("zizmor", "github-actions")],
    # ai-redteam is only assembled when ai_pass is set (see build_scan_plan).
    "ai-redteam": [("promptfoo", "*"), ("garak", "*")],
}

# Categories whose relevance is conditional on something in the repo.
_CONDITIONAL_CATEGORIES = {"iac", "ai-redteam"}

# --- kernel/container trust-boundary awareness (spike-10 T-A, ADR-018) -----
# ADVISORY altitude: this is informational SCAN-PLAN metadata that DRIVES an
# agent advisory note (like the absent-SECURITY.md hygiene note) — it is NOT a
# finding (no CVSS, never a VULN-FINDINGS.json entry). It recognizes that a repo
# ships kernel-adjacent / privileged-container code so the agent can route
# attention to specialist tooling. **NO kernel/eBPF memory-safety auditing**
# (Rule 5: that is fuzzer/specialist work, out of this review's scope — spike-10
# F2/F6). Detection is deterministic file-presence + light content scan only.

# eBPF go.mod import-path tokens (matched case-insensitively in go.mod text).
_EBPF_GOMOD_TOKENS: tuple[str, ...] = (
    "libbpf",
    "cilium/ebpf",
    "aquasecurity/libbpfgo",
    "bpf2go",
)
# Privileged-container markers in compose / k8s YAML (matched case-insensitively).
_PRIVILEGED_CONTAINER_TOKENS: tuple[str, ...] = (
    "privileged:",
    "hostpid",
    "hostnetwork",
    "hostpath",
    "cap_sys_admin",
)


@dataclass
class ScanPlan:
    languages: list[str]
    infra: list[str]
    frameworks: list[str]
    available_tools: list[str]
    ai_pass: bool = False
    # category -> chosen tool, or None when nothing is installed (degraded)
    category_tool: dict[str, str | None] = field(default_factory=dict)
    degraded_categories: list[str] = field(default_factory=list)
    reference_appendices: list[str] = field(default_factory=list)
    # ADVISORY trust-boundary markers (spike-10 T-A, ADR-018): informational
    # metadata that drives an agent advisory note — NOT a finding, no CVSS.
    kernel_adjacency: list[str] = field(default_factory=list)
    # ADVISORY AI-agent-infra markers (wh-7u7): informational metadata for repos
    # that carry AI-agent infrastructure (agent configs, nested AI-SDK manifests,
    # MCP config, skill files) but whose ROOT manifests have no AI-SDK dep — so
    # manifest-driven ai_pass stays False.  NOT a finding, no CVSS.
    ai_agent_infra: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        return bool(self.degraded_categories)

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "languages": self.languages,
            "infra": self.infra,
            "frameworks": self.frameworks,
            "available_tools": self.available_tools,
            "ai_pass": self.ai_pass,
            "category_tool": self.category_tool,
            # `degraded` is the LIST of categories with no installed tool.
            "degraded": self.degraded_categories,
            "reference_appendices": self.reference_appendices,
            "fallback": "read-grep-glob heuristic pass (confidence capped)",
            # Always emitted; empty list when no kernel-adjacent markers found.
            "kernel_adjacency": self.kernel_adjacency,
            # Always emitted; empty list when no AI-agent-infra markers found.
            "ai_agent_infra": self.ai_agent_infra,
            # Derived advisory: True only when ai_pass is False but AI-agent infra
            # IS present (e.g. .claude/ dir, nested AI-SDK manifest, skill files).
            # When ai_pass is already True the AI pass already runs — no advisory.
            "ai_pass_advisory": (not self.ai_pass) and bool(self.ai_agent_infra),
        }


def detect_languages(root: Path) -> list[str]:
    """Return sorted unique languages detected from manifest files in `root`."""
    found: set[str] = set()
    for signal, lang in MANIFEST_SIGNALS.items():
        if (root / signal).exists():
            found.add(lang)
    # package.json + tsconfig.json => typescript, not plain javascript
    if "typescript" in found:
        found.discard("javascript")
    return sorted(found)


def detect_infra(root: Path) -> list[str]:
    found: set[str] = set()
    for signal, label in INFRA_SIGNALS.items():
        if (root / signal).exists():
            found.add(label)
    return sorted(found)


def _iter_files(root: Path):
    """Yield regular files under `root` (recursive), skipping unreadable trees."""
    try:
        for p in root.rglob("*"):
            if p.is_file():
                yield p
    except OSError:
        return


def detect_kernel_adjacency(root: Path) -> list[str]:
    """Sorted marker classes for kernel-adjacent / privileged-container code.

    ADVISORY only (spike-10 T-A, ADR-018): deterministic file-presence + light
    content scan. Returns a subset of {"ebpf", "kernel-module",
    "privileged-container"} — informational metadata that drives an agent
    advisory note, NOT a finding (no CVSS, never a VULN-FINDINGS.json entry).
    **No memory-safety verdicts** (Rule 5).

    - ebpf: a `*.bpf.c` file, OR libbpf/cilium/ebpf/aquasecurity/libbpfgo/bpf2go
      in `go.mod`, OR a bpftrace (`*.bt`) script.
    - kernel-module: a `Kbuild` file, `obj-m` in a `Makefile`, a `*.ko`, or
      `dkms.conf`.
    - privileged-container: `privileged:` in a docker-compose file, OR k8s
      `privileged: true` / hostPID / hostNetwork / hostPath / `CAP_SYS_ADMIN`
      in a YAML manifest.
    """
    markers: set[str] = set()

    # --- kernel-module: exact-name signals (no content read needed) ---
    if (root / "Kbuild").exists() or (root / "dkms.conf").exists():
        markers.add("kernel-module")

    # `obj-m` in a Makefile is the canonical out-of-tree module build line.
    makefile = root / "Makefile"
    if makefile.is_file() and "obj-m" in _read_manifest_text(root, "Makefile"):
        markers.add("kernel-module")

    # --- eBPF: go.mod import paths ---
    gomod = _read_manifest_text(root, "go.mod")
    if gomod and any(tok in gomod for tok in _EBPF_GOMOD_TOKENS):
        markers.add("ebpf")

    # --- file-suffix + content signals (single recursive walk) ---
    for path in _iter_files(root):
        name = path.name.lower()
        if name.endswith(".bpf.c") or name.endswith(".bt"):
            markers.add("ebpf")
            continue
        if name.endswith(".ko"):
            markers.add("kernel-module")
            continue
        if name.endswith((".yml", ".yaml")):
            try:
                with path.open(encoding="utf-8", errors="ignore") as fh:
                    text = fh.read(_AI_MANIFEST_READ_CAP).lower()
            except (OSError, ValueError):
                continue
            if any(tok in text for tok in _PRIVILEGED_CONTAINER_TOKENS):
                markers.add("privileged-container")

    return sorted(markers)


def detect_ai_agent_infra(root: Path) -> list[str]:
    """Sorted marker classes for AI-agent-infrastructure signals.

    ADVISORY only (wh-7u7): deterministic file-presence + bounded, pruned tree
    walk.  Returns a sorted subset of:
      ``{".claude", "agents", "mcp.json", "skill", "nested-ai-manifest"}``

    This is informational SCAN-PLAN metadata that drives ``ai_pass_advisory``
    in ``to_dict()`` — NOT a finding (no CVSS, never a VULN-FINDINGS.json entry).
    ``ai_pass`` itself (manifest-driven, root-only) is **unchanged**.

    Markers:
    - ``.claude``: a ``.claude/`` directory at repo root (agent-config repo).
    - ``agents``: an ``agents/`` directory at repo root.
    - ``mcp.json``: an ``mcp.json`` file at repo root.
    - ``skill``: any ``*.skill`` file found in the bounded tree walk.
    - ``nested-ai-manifest``: a NESTED (non-root) ``pyproject.toml``,
      ``requirements.txt``, ``Pipfile``, or ``package.json`` whose lowercased text
      contains at least one AI-SDK token from ``AI_FRAMEWORK_SIGNALS``.  Root
      manifests are already handled by ``ai_pass``; this class is specifically for
      sub-directory manifests (e.g. a monorepo service or a plugin).

    Resource discipline: the walk uses ``os.walk`` with in-place pruning of
    ``_PRUNE_DIRS`` (never descends into ``.venv``, ``node_modules``, etc.) and a
    depth cap of ``_AI_INFRA_MAX_DEPTH`` relative to root.  An AI SDK installed
    inside ``.venv/`` is therefore never detected — only repo-committed manifests
    count.
    """
    markers: set[str] = set()

    # --- simple root-level presence checks (no walk needed) ---
    if (root / ".claude").is_dir():
        markers.add(".claude")
    if (root / "agents").is_dir():
        markers.add("agents")
    if (root / "mcp.json").is_file():
        markers.add("mcp.json")

    # --- bounded, pruned tree walk for skill files + nested AI manifests ---
    for dirpath_str, dirnames, filenames in os.walk(root):
        dirpath = Path(dirpath_str)
        # Depth relative to root (root itself is depth 0).
        try:
            rel_parts = dirpath.relative_to(root).parts
        except ValueError:
            continue
        current_depth = len(rel_parts)

        # Prune unwanted directories in-place; cap recursion depth.
        if current_depth >= _AI_INFRA_MAX_DEPTH:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]

        is_root_level = current_depth == 0

        for filename in filenames:
            # skill-file detection (any depth, pruned).
            if filename.endswith(".skill"):
                markers.add("skill")

            # Nested AI-manifest detection: skip root level (handled by ai_pass).
            if is_root_level:
                continue
            if filename in _AI_NESTED_MANIFEST_NAMES:
                filepath = dirpath / filename
                # F-1 / CWE-400 guard: is_file() returns False for FIFOs,
                # character devices, broken symlinks, and directories — all
                # of which would block or misbehave on open()/read().
                if not filepath.is_file():
                    continue
                try:
                    with filepath.open(encoding="utf-8", errors="ignore") as fh:
                        text = fh.read(_AI_MANIFEST_READ_CAP).lower()
                except (OSError, ValueError):
                    continue
                if any(tok.lower() in text for tok in _AI_NESTED_TOKENS):
                    markers.add("nested-ai-manifest")

    return sorted(markers)


def _read_manifest_text(root: Path, filename: str) -> str:
    """Lowercased contents of a manifest, or '' if absent/unreadable."""
    p = root / filename
    # F-1 / CWE-400 guard (mirrors detect_ai_agent_infra): is_file() returns
    # False for FIFOs, character devices, broken symlinks, and directories — all
    # of which would block or misbehave on open()/read(); the bounded read caps a
    # multi-GB committed manifest at 64 KiB (tokens sit near the top).
    if not p.is_file():
        return ""
    try:
        with p.open(encoding="utf-8", errors="ignore") as fh:
            return fh.read(_AI_MANIFEST_READ_CAP).lower()
    except (OSError, ValueError):
        return ""


def _match_signals(root: Path, signals: dict[str, tuple[set[str], tuple[str, ...]]]) -> list[str]:
    """Return sorted framework names whose tokens appear in their manifest(s)."""
    # Read each needed manifest at most once.
    wanted: set[str] = set()
    for files, _tokens in signals.values():
        wanted |= files
    texts = {f: _read_manifest_text(root, f) for f in wanted}

    hits: set[str] = set()
    for name, (files, tokens) in signals.items():
        blob = "".join(texts[f] for f in files)
        if blob and any(tok.lower() in blob for tok in tokens):
            hits.add(name)
    return sorted(hits)


def detect_frameworks(root: Path) -> list[str]:
    """Application + AI frameworks fingerprinted from manifest contents."""
    return sorted(set(_match_signals(root, FRAMEWORK_SIGNALS))
                  | set(_match_signals(root, AI_FRAMEWORK_SIGNALS)))


def detect_ai_frameworks(root: Path) -> list[str]:
    """Just the AI/LLM frameworks (presence => ai_pass)."""
    return _match_signals(root, AI_FRAMEWORK_SIGNALS)


def reference_appendices(languages: list[str], frameworks: list[str],
                         infra: list[str], ai_pass: bool) -> list[str]:
    """The on-demand `reference/*.md` appendices this repo should load."""
    appendices: set[str] = set()
    for lang in languages:
        if lang in LANG_APPENDIX:
            appendices.add(LANG_APPENDIX[lang])
    if any(fw in WEB_FRAMEWORKS for fw in frameworks):
        appendices.add("api.md")
    if infra:
        appendices.add("infra.md")
    if ai_pass:
        appendices.add("ai-llm.md")
    return sorted(appendices)


def detect_available_tools(which=shutil.which) -> list[str]:
    """Which known scanners are on PATH. `which` is injectable for testing."""
    tools = {t for prefs in SCANNER_PREFERENCE.values() for t, _ in prefs}
    return sorted(t for t in tools if which(t) is not None)


def _serves(tool_langs: str, languages: list[str], infra: list[str]) -> bool:
    if tool_langs == "*":
        return True
    return tool_langs in languages or tool_langs in infra


def build_scan_plan(root: Path, which=shutil.which) -> ScanPlan:
    languages = detect_languages(root)
    infra = detect_infra(root)
    frameworks = detect_frameworks(root)
    ai_pass = bool(detect_ai_frameworks(root))
    available = detect_available_tools(which)
    available_set = set(available)

    category_tool: dict[str, str | None] = {}
    degraded: list[str] = []
    for category, prefs in SCANNER_PREFERENCE.items():
        # Skip conditional categories that don't apply to this repo.
        if category == "iac" and not infra:
            continue
        if category == "ai-redteam" and not ai_pass:
            continue
        chosen = None
        for tool, tool_langs in prefs:
            if tool in available_set and _serves(tool_langs, languages, infra):
                chosen = tool
                break
        category_tool[category] = chosen
        if chosen is None:
            degraded.append(category)

    return ScanPlan(
        languages=languages,
        infra=infra,
        frameworks=frameworks,
        available_tools=available,
        ai_pass=ai_pass,
        category_tool=category_tool,
        degraded_categories=degraded,
        reference_appendices=reference_appendices(languages, frameworks, infra, ai_pass),
        kernel_adjacency=detect_kernel_adjacency(root),
        ai_agent_infra=detect_ai_agent_infra(root),
    )


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    print(json.dumps(build_scan_plan(target).to_dict(), indent=2))
