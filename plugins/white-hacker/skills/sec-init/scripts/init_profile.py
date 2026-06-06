"""sec-init: project-detecting onboarding → a GATED, project-scope companion profile.

Spike-07 (F4) + ADR-017: onboarding runs detection + a threat-model seed ONCE and
persists a committed, **project-scope companion** the generic white-hacker agent
consumes. It **never** rewrites the shipped identity (ADR-004): the JSON Schema's
top-level `additionalProperties: false` structurally rejects any identity/posture/
tool-scope/output-contract key, so an init pass cannot override who the agent is.

What the companion specializes (and ONLY this):
  * detected languages + frameworks (from `sec-detect`'s manifest fingerprint),
  * present security capabilities (sast/sca/secrets/iac/ai-redteam) backed by an
    installed tool, plus the capabilities with no tool (`tools_unavailable`),
  * which per-language appendices to load (lang-go/-python/-typescript/-java),
  * whether the AI/LLM review pass applies (LLM deps present),
  * a threat-model SEED (assets / entry_points / trust_boundaries — possibly empty),
  * the scoring standard — **default null ("ask"); must be human-confirmed, never
    hardcoded**.

Detection is **reused, not reinvented**: this module imports `detect_tools` from the
sibling `sec-detect` skill (the conftest shim puts it on `sys.path`; the CLI path also
inserts it explicitly). stdlib + jsonschema only.

Injection-safety: every generated STRING is a FACTUAL statement, never imperative,
because this profile may later feed a SessionStart `additionalContext`, and imperative
phrasing trips Claude's prompt-injection defenses (white-hacker is itself an injection
target — Agents Rule of Two). `write_profile` refuses to write a non-factual or
schema-invalid profile.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import jsonschema

# Make the sibling sec-detect's detect_tools importable even outside pytest
# (the conftest shim only applies under pytest). Insert its scripts dir on path.
_HERE = Path(__file__).resolve().parent
_SEC_DETECT_SCRIPTS = _HERE.parent.parent / "sec-detect" / "scripts"
if str(_SEC_DETECT_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SEC_DETECT_SCRIPTS))

import detect_tools as dt  # noqa: E402  (path shim above must run first)

SCHEMA_VERSION = "1.0"
SCHEMA_PATH = _HERE / "project_profile_schema.json"

# language -> the per-language appendix STEM the companion lists. We strip the
# ".md" extension from sec-detect's LANG_APPENDIX so the values are appendix
# identifiers (lang-go/lang-python/lang-typescript/lang-java), matching ADR-017.
_LANG_TO_APPENDIX_STEM: dict[str, str] = {
    lang: appendix.removesuffix(".md")
    for lang, appendix in dt.LANG_APPENDIX.items()
}

# Map each known capability (sast/sca/secrets/iac/ai-redteam) to "present" when at
# least one of its preferred tools is installed. Reuses sec-detect's preference map.
_CAPABILITIES: tuple[str, ...] = tuple(dt.SCANNER_PREFERENCE.keys())

# Imperative markers — a string starting with one of these is an instruction, not a
# fact. Used to keep generated text injection-safe (factual SessionStart context).
_IMPERATIVE_RE = re.compile(
    r"^(always|never|you must|ignore|disregard|do not)\b",
    re.IGNORECASE,
)


def is_factual(text: str) -> bool:
    """True when `text` reads as a factual statement (not an imperative instruction).

    False if it begins with an imperative marker (always/never/you must/ignore/
    disregard/do not). Empty/whitespace strings are treated as factual (vacuously).
    """
    return not bool(_IMPERATIVE_RE.match(text.strip()))


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _present_and_unavailable_capabilities(plan: "dt.ScanPlan") -> tuple[list[str], list[str]]:
    """Split capabilities into present (a tool is installed) vs unavailable.

    Reuses the ScanPlan: `category_tool[cap]` is the chosen tool (or None when the
    capability applies but no tool is installed → degraded). Conditional capabilities
    (iac/ai-redteam) only appear in `category_tool` when they apply to the repo, so
    they are neither claimed present nor flagged unavailable when not applicable.
    """
    present: list[str] = []
    unavailable: list[str] = []
    for cap in _CAPABILITIES:
        if cap not in plan.category_tool:
            continue  # capability does not apply to this repo
        if plan.category_tool[cap] is not None:
            present.append(cap)
        else:
            unavailable.append(cap)
    return sorted(present), sorted(unavailable)


def _load_appendices(languages: list[str]) -> list[str]:
    """Per-language appendix stems derived from detected languages (deduped, sorted)."""
    stems = {
        _LANG_TO_APPENDIX_STEM[lang]
        for lang in languages
        if lang in _LANG_TO_APPENDIX_STEM
    }
    return sorted(stems)


def _generated_note(repo_root: Path) -> str:
    """A FACTUAL one-line provenance statement (never imperative)."""
    return (
        "This project-scope companion profile was generated by sec-init from detected "
        "manifests and installed tools; it specializes detection facts only and does "
        "not contain agent identity, posture, or tool-scope."
    )


def build_profile(repo_root) -> dict:
    """Build the project-scope companion profile for `repo_root`.

    Reuses `detect_tools.build_scan_plan` for languages, frameworks, ai_pass, and
    installed tools → capabilities. Derives load_appendices from languages.
    scoring_standard defaults to None (must be human-confirmed). The threat-model seed
    starts as empty lists when nothing is derivable from static signals.
    """
    root = Path(repo_root)
    plan = dt.build_scan_plan(root)
    present, unavailable = _present_and_unavailable_capabilities(plan)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_note": _generated_note(root),
        "detected_langs": list(plan.languages),
        "frameworks": list(plan.frameworks),
        "present_capabilities": present,
        "tools_unavailable": unavailable,
        "load_appendices": _load_appendices(plan.languages),
        "ai_pass": bool(plan.ai_pass),
        # Severity scoring standard is intentionally NOT inferred: it is an org policy
        # decision (CVSS vs a bug-bar) the human confirms. null == "ask".
        "scoring_standard": None,
        "threat_model_seed": {
            "assets": [],
            "entry_points": [],
            "trust_boundaries": [],
        },
    }


def validate_profile(profile: dict) -> list[str]:
    """Validate `profile` against the committed schema. Returns [] when valid.

    additionalProperties:false at the top level means any shipped-identity key (e.g.
    posture, tools, tool-scope) yields a validation error here.
    """
    schema = _load_schema()
    validator = jsonschema.Draft7Validator(schema)
    return [e.message for e in sorted(validator.iter_errors(profile), key=str)]


def _string_fields(profile: dict):
    """Yield every string value reachable in the profile (for the factual check)."""
    for value in profile.values():
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for v in value.values():
                if isinstance(v, str):
                    yield v
                elif isinstance(v, list):
                    yield from (x for x in v if isinstance(x, str))
        elif isinstance(value, list):
            yield from (x for x in value if isinstance(x, str))


def profile_path(repo_root) -> Path:
    """The committed companion location in the TARGET repo."""
    return Path(repo_root) / ".white-hacker" / "project-profile.json"


def write_profile(repo_root, profile: dict) -> Path:
    """Validate, then write the profile as pretty JSON. Refuse anything unsafe.

    Raises ValueError when the profile is schema-invalid OR when any string value is
    imperative rather than factual (injection-safety, since this may feed a SessionStart
    additionalContext).
    """
    errors = validate_profile(profile)
    if errors:
        raise ValueError(f"refusing to write schema-invalid profile: {errors}")

    non_factual = [s for s in _string_fields(profile) if not is_factual(s)]
    if non_factual:
        raise ValueError(
            "refusing to write profile with imperative (non-factual) string values "
            f"(may trip prompt-injection defenses): {non_factual}"
        )

    out = profile_path(repo_root)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    return out


def main(argv: list[str]) -> int:
    """CLI: build + validate + write the companion profile for the given repo root.

    Usage: init_profile.py <repo_root>   (defaults to cwd). Exit 0 on success, 1 on error.
    """
    repo_root = Path(argv[0]) if argv else Path.cwd()
    profile = build_profile(repo_root)
    errors = validate_profile(profile)
    if errors:
        print(f"profile validation failed: {errors}", file=sys.stderr)
        return 1
    try:
        out = write_profile(repo_root, profile)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(str(out))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
