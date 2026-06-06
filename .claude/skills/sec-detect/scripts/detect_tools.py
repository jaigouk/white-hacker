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
SCANNER_PREFERENCE: dict[str, list[tuple[str, str]]] = {
    "sast": [("opengrep", "*"), ("semgrep", "*"),
             ("gosec", "go"), ("bandit", "python")],
    "sca": [("govulncheck", "go"), ("pip-audit", "python"),
            ("osv-scanner", "*"), ("trivy", "*")],
    "secrets": [("gitleaks", "*"), ("trufflehog", "*")],
    "iac": [("trivy", "*"), ("checkov", "*"), ("hadolint", "docker")],
    # ai-redteam is only assembled when ai_pass is set (see build_scan_plan).
    "ai-redteam": [("promptfoo", "*"), ("garak", "*")],
}

# Categories whose relevance is conditional on something in the repo.
_CONDITIONAL_CATEGORIES = {"iac", "ai-redteam"}


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


def _read_manifest_text(root: Path, filename: str) -> str:
    """Lowercased contents of a manifest, or '' if absent/unreadable."""
    p = root / filename
    try:
        return p.read_text(encoding="utf-8", errors="ignore").lower()
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
    )


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    print(json.dumps(build_scan_plan(target).to_dict(), indent=2))
