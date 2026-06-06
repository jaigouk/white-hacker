"""PoC: language + security-tool detection with graceful degradation.

Verifies two plan assumptions:
  1. We can auto-detect a repo's language(s)/ecosystem from manifest files
     (the `sec-detect` skill premise).
  2. We can detect which scanners are installed and *degrade gracefully*
     to a Read/Grep/Glob heuristic pass when a category has no tool
     (the "never block on a missing tool" assumption).

This is a spike, not the final implementation — but it ships with tests.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

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

# --- per-category scanner preference (best signal first) ------------------
# Each entry: category -> ordered list of (tool, languages-it-serves|"*").
SCANNER_PREFERENCE: dict[str, list[tuple[str, str]]] = {
    "sast": [("opengrep", "*"), ("semgrep", "*"),
             ("gosec", "go"), ("bandit", "python")],
    "sca": [("govulncheck", "go"), ("pip-audit", "python"),
            ("osv-scanner", "*"), ("trivy", "*")],
    "secrets": [("gitleaks", "*"), ("trufflehog", "*")],
    "iac": [("trivy", "*"), ("checkov", "*"), ("hadolint", "docker")],
}


@dataclass
class ScanPlan:
    languages: list[str]
    infra: list[str]
    available_tools: list[str]
    # category -> chosen tool, or None when nothing is installed (degraded)
    category_tool: dict[str, str | None] = field(default_factory=dict)
    degraded_categories: list[str] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        return bool(self.degraded_categories)

    def to_dict(self) -> dict:
        return {
            "languages": self.languages,
            "infra": self.infra,
            "available_tools": self.available_tools,
            "category_tool": self.category_tool,
            "degraded_categories": self.degraded_categories,
            "degraded": self.degraded,
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
    available = detect_available_tools(which)
    available_set = set(available)

    category_tool: dict[str, str | None] = {}
    degraded: list[str] = []
    for category, prefs in SCANNER_PREFERENCE.items():
        # iac category only relevant if infra present
        if category == "iac" and not infra:
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
        available_tools=available,
        category_tool=category_tool,
        degraded_categories=degraded,
    )


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    print(json.dumps(build_scan_plan(target).to_dict(), indent=2))
