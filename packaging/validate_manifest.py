#!/usr/bin/env python3
"""Validate the canonical Claude Code plugin + marketplace layout (stdlib only).

This is the "floor" validator for white-hacker's distribution packaging (T-10.2). It
enforces the rules verified in docs/research/spike-07-agent-distribution-and-init-2026-06.md
(canonical Anthropic plugins-reference docs):

  1. Marketplace manifest at <repo>/.claude-plugin/marketplace.json with required top-level
     fields: "name" (kebab-case), "owner" (object with "name"), "plugins" (non-empty array).
  2. Each plugins[] entry has required "name" (kebab-case) + "source". A *string* source MUST
     start with "./" (relative) and resolve to an existing directory that contains
     .claude-plugin/plugin.json. (Object sources -- github/git/url/npm -- are accepted as-is;
     this floor validator does not fetch the network.)
  3. Each plugin manifest at <plugin-dir>/.claude-plugin/plugin.json has required "name"
     (kebab-case: ^[a-z0-9]+(-[a-z0-9]+)*$).
  4. PLACEMENT RULE (load-bearing): inside ANY ".claude-plugin/" directory the only allowed
     entry is plugin.json (and marketplace.json at the marketplace root). Component directories
     (commands, agents, skills, hooks, output-styles, themes, monitors) MUST NOT exist inside a
     ".claude-plugin/" directory -- they belong at the plugin root.

Stdlib only (json, pathlib, re) so it runs anywhere with zero external deps.

CLI:
    python validate_manifest.py [repo_root]   # default: cwd
Exit 0 if valid, 1 otherwise.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

KEBAB = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Component directories that belong at the PLUGIN ROOT, never inside .claude-plugin/.
COMPONENT_DIRS = {
    "commands",
    "agents",
    "skills",
    "hooks",
    "output-styles",
    "themes",
    "monitors",
}

PLUGIN_MANIFEST_REL = pathlib.Path(".claude-plugin") / "plugin.json"
MARKETPLACE_MANIFEST_REL = pathlib.Path(".claude-plugin") / "marketplace.json"


# --------------------------------------------------------------------------- #
# loaders
# --------------------------------------------------------------------------- #
def _load_json(path: pathlib.Path) -> tuple[object | None, str | None]:
    """Return (obj, None) on success, or (None, error_message) on failure."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, f"file not found: {path}"
    except OSError as exc:  # pragma: no cover - unusual fs error
        return None, f"could not read {path}: {exc}"
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path}: {exc}"


def load_marketplace(repo_root) -> dict:
    """Load and return the marketplace manifest dict (raises on read/parse error)."""
    path = pathlib.Path(repo_root) / MARKETPLACE_MANIFEST_REL
    return json.loads(path.read_text(encoding="utf-8"))


def load_plugin(plugin_dir) -> dict:
    """Load and return a plugin manifest dict (raises on read/parse error)."""
    path = pathlib.Path(plugin_dir) / PLUGIN_MANIFEST_REL
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# placement rule
# --------------------------------------------------------------------------- #
def find_misplaced_components(repo_root) -> list[str]:
    """Return paths of component dirs wrongly nested under any ".claude-plugin/" dir.

    Walks every ".claude-plugin" directory in the tree and reports any immediate (or deeper)
    subdirectory whose name is in COMPONENT_DIRS. The only legitimate entries inside a
    ".claude-plugin/" directory are plugin.json / marketplace.json (files, not dirs).
    """
    root = pathlib.Path(repo_root)
    misplaced: list[str] = []
    for cp_dir in root.rglob(".claude-plugin"):
        if not cp_dir.is_dir():
            continue
        for child in cp_dir.rglob("*"):
            if child.is_dir() and child.name in COMPONENT_DIRS:
                misplaced.append(str(child))
    return sorted(misplaced)


# --------------------------------------------------------------------------- #
# plugin validation
# --------------------------------------------------------------------------- #
def validate_plugin(plugin_dir) -> list[str]:
    """Validate a single plugin directory. Returns a list of error strings (empty == valid)."""
    plugin_dir = pathlib.Path(plugin_dir)
    errors: list[str] = []
    manifest_path = plugin_dir / PLUGIN_MANIFEST_REL

    obj, err = _load_json(manifest_path)
    if err is not None:
        if not manifest_path.exists():
            errors.append(f"missing plugin manifest: {manifest_path} (expected .claude-plugin/plugin.json)")
        else:
            errors.append(err)
        return errors

    if not isinstance(obj, dict):
        errors.append(f"plugin manifest {manifest_path} must be a JSON object")
        return errors

    name = obj.get("name")
    if name is None:
        errors.append(f"plugin manifest {manifest_path} missing required field 'name'")
    elif not isinstance(name, str) or not KEBAB.match(name):
        errors.append(f"plugin manifest {manifest_path} 'name' must be kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$), got {name!r}")

    return errors


# --------------------------------------------------------------------------- #
# marketplace validation
# --------------------------------------------------------------------------- #
def _validate_entry(repo_root: pathlib.Path, idx: int, entry: object) -> list[str]:
    errors: list[str] = []
    where = f"plugins[{idx}]"

    if not isinstance(entry, dict):
        return [f"{where} must be an object"]

    name = entry.get("name")
    if name is None:
        errors.append(f"{where} missing required field 'name'")
    elif not isinstance(name, str) or not KEBAB.match(name):
        errors.append(f"{where} 'name' must be kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$), got {name!r}")

    if "source" not in entry:
        errors.append(f"{where} missing required field 'source'")
        return errors

    source = entry["source"]
    if isinstance(source, str):
        if not source.startswith("./"):
            errors.append(f"{where} string 'source' must be relative and start with './', got {source!r}")
            return errors
        plugin_dir = (repo_root / source).resolve()
        if not plugin_dir.is_dir():
            errors.append(f"{where} 'source' {source!r} does not resolve to an existing directory")
            return errors
        manifest = plugin_dir / PLUGIN_MANIFEST_REL
        if not manifest.exists():
            errors.append(f"{where} 'source' {source!r} directory is missing .claude-plugin/plugin.json")
            return errors
        # cascade: validate the referenced plugin manifest too
        for e in validate_plugin(plugin_dir):
            errors.append(f"{where} -> {e}")
    elif isinstance(source, dict):
        # object source (github / git / url / npm) -- not fetched by the floor validator.
        if "source" not in source and "url" not in source and "repo" not in source:
            errors.append(f"{where} object 'source' must declare one of 'source'/'url'/'repo'")
    else:
        errors.append(f"{where} 'source' must be a relative string ('./...') or an object")

    return errors


def validate_marketplace(repo_root) -> list[str]:
    """Validate the marketplace manifest + all referenced plugins + the placement rule.

    Returns a list of error strings (empty == valid). Never raises on bad input.
    """
    repo_root = pathlib.Path(repo_root)
    errors: list[str] = []
    manifest_path = repo_root / MARKETPLACE_MANIFEST_REL

    obj, err = _load_json(manifest_path)
    if err is not None:
        if not manifest_path.exists():
            errors.append(f"missing marketplace manifest: {manifest_path} (expected .claude-plugin/marketplace.json)")
        else:
            errors.append(err)
        return errors

    if not isinstance(obj, dict):
        return [f"marketplace manifest {manifest_path} must be a JSON object"]

    # required: name (kebab-case)
    name = obj.get("name")
    if name is None:
        errors.append("marketplace missing required field 'name'")
    elif not isinstance(name, str) or not KEBAB.match(name):
        errors.append(f"marketplace 'name' must be kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$), got {name!r}")

    # required: owner (object with name)
    owner = obj.get("owner")
    if owner is None:
        errors.append("marketplace missing required field 'owner'")
    elif not isinstance(owner, dict):
        errors.append("marketplace 'owner' must be an object with a 'name'")
    elif not owner.get("name"):
        errors.append("marketplace 'owner' must contain a non-empty 'name'")

    # required: plugins (non-empty array)
    plugins = obj.get("plugins")
    if plugins is None:
        errors.append("marketplace missing required field 'plugins'")
    elif not isinstance(plugins, list):
        errors.append("marketplace 'plugins' must be an array")
    elif len(plugins) == 0:
        errors.append("marketplace 'plugins' must be a non-empty array")
    else:
        for idx, entry in enumerate(plugins):
            errors.extend(_validate_entry(repo_root, idx, entry))

    # placement rule (applies across the whole repo tree)
    for path in find_misplaced_components(repo_root):
        errors.append(f"component directory wrongly placed under .claude-plugin/: {path}")

    return errors


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    repo_root = pathlib.Path(argv[0]) if argv else pathlib.Path.cwd()

    errors = validate_marketplace(repo_root)
    if errors:
        print(f"INVALID: {len(errors)} error(s) in {repo_root}", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: plugin/marketplace layout valid in {repo_root}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
