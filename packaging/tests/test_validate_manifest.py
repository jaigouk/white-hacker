"""TDD tests for the Claude Code plugin/marketplace layout validator (T-10.2).

Run: uv run --with pytest pytest packaging/tests/ -q   (from repo root)

These enforce the canonical layout rules verified in
docs/research/spike-07-agent-distribution-and-init-2026-06.md:

  1. Marketplace manifest at <repo>/.claude-plugin/marketplace.json with required
     top-level fields: name (kebab-case), owner (object with name), plugins (non-empty array).
  2. Each plugins[] entry has required name (kebab-case) + source; a string source MUST start
     with "./" and resolve to a dir containing .claude-plugin/plugin.json.
  3. Each plugin manifest at <plugin-dir>/.claude-plugin/plugin.json has required name (kebab-case).
  4. PLACEMENT RULE: inside ANY ".claude-plugin/" directory the only allowed entry is plugin.json
     (and marketplace.json at the marketplace root). Component dirs (commands, agents, skills,
     hooks, output-styles, themes, monitors) MUST NOT exist under a ".claude-plugin/" directory.
"""
from __future__ import annotations

import json
import pathlib

import validate_manifest as vm

# Repo root is two levels up from this test file: packaging/tests/ -> packaging/ -> <repo>
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


# ---------- helpers ----------------------------------------------------------

def _write_json(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))


def _make_plugin(plugin_dir: pathlib.Path, name: str = "demo-plugin") -> None:
    """Create a minimally-valid plugin: <plugin_dir>/.claude-plugin/plugin.json."""
    _write_json(plugin_dir / ".claude-plugin" / "plugin.json", {"name": name})


def _make_marketplace(repo: pathlib.Path, marketplace: dict) -> None:
    _write_json(repo / ".claude-plugin" / "marketplace.json", marketplace)


def _valid_marketplace(plugin_rel: str = "./plugins/demo-plugin", name: str = "demo-plugin") -> dict:
    return {
        "name": "demo-marketplace",
        "owner": {"name": "Tester"},
        "plugins": [{"name": name, "source": plugin_rel}],
    }


# ---------- the REAL repo manifests validate clean -----------------------------

def test_real_repo_marketplace_validates_clean():
    errors = vm.validate_marketplace(REPO_ROOT)
    assert errors == [], f"real repo marketplace should be valid, got: {errors}"


def test_real_repo_has_no_misplaced_components():
    assert vm.find_misplaced_components(REPO_ROOT) == []


def test_real_plugin_manifest_validates_clean():
    plugin_dir = REPO_ROOT / "plugins" / "white-hacker"
    assert vm.validate_plugin(plugin_dir) == []


def test_real_marketplace_name_is_kebab_and_lists_white_hacker():
    mp = vm.load_marketplace(REPO_ROOT)
    assert vm.KEBAB.match(mp["name"])
    names = [p["name"] for p in mp["plugins"]]
    assert "white-hacker" in names
    src = next(p["source"] for p in mp["plugins"] if p["name"] == "white-hacker")
    assert src == "./plugins/white-hacker"


def test_main_on_real_repo_returns_zero():
    assert vm.main([str(REPO_ROOT)]) == 0


# ---------- marketplace required-field edge cases ----------------------------

def test_missing_name_is_error(tmp_path):
    mp = _valid_marketplace()
    del mp["name"]
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    errors = vm.validate_marketplace(tmp_path)
    assert any("name" in e for e in errors)


def test_non_kebab_marketplace_name_is_error(tmp_path):
    mp = _valid_marketplace()
    mp["name"] = "Demo_Marketplace"  # underscores + caps -> not kebab
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    errors = vm.validate_marketplace(tmp_path)
    assert any("kebab" in e.lower() for e in errors)


def test_missing_owner_is_error(tmp_path):
    mp = _valid_marketplace()
    del mp["owner"]
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    errors = vm.validate_marketplace(tmp_path)
    assert any("owner" in e for e in errors)


def test_owner_without_name_is_error(tmp_path):
    mp = _valid_marketplace()
    mp["owner"] = {"email": "x@y.z"}  # no name
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    errors = vm.validate_marketplace(tmp_path)
    assert any("owner" in e for e in errors)


def test_empty_plugins_array_is_error(tmp_path):
    mp = _valid_marketplace()
    mp["plugins"] = []
    _make_marketplace(tmp_path, mp)
    errors = vm.validate_marketplace(tmp_path)
    assert any("plugins" in e for e in errors)


def test_missing_marketplace_file_is_error(tmp_path):
    errors = vm.validate_marketplace(tmp_path)
    assert any("marketplace.json" in e for e in errors)


def test_unparseable_marketplace_is_error(tmp_path):
    path = tmp_path / ".claude-plugin" / "marketplace.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not valid json")
    errors = vm.validate_marketplace(tmp_path)
    assert errors  # should not raise; should report a parse error
    assert any("json" in e.lower() or "parse" in e.lower() for e in errors)


# ---------- plugin-entry / source edge cases ---------------------------------

def test_entry_missing_name_is_error(tmp_path):
    mp = _valid_marketplace()
    del mp["plugins"][0]["name"]
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    errors = vm.validate_marketplace(tmp_path)
    assert any("name" in e for e in errors)


def test_entry_non_kebab_name_is_error(tmp_path):
    mp = _valid_marketplace(name="Demo Plugin")
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    errors = vm.validate_marketplace(tmp_path)
    assert any("kebab" in e.lower() for e in errors)


def test_entry_missing_source_is_error(tmp_path):
    mp = _valid_marketplace()
    del mp["plugins"][0]["source"]
    _make_marketplace(tmp_path, mp)
    errors = vm.validate_marketplace(tmp_path)
    assert any("source" in e for e in errors)


def test_string_source_not_relative_is_error(tmp_path):
    mp = _valid_marketplace(plugin_rel="plugins/demo-plugin")  # missing leading ./
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    errors = vm.validate_marketplace(tmp_path)
    assert any("./" in e for e in errors)


def test_string_source_unresolvable_dir_is_error(tmp_path):
    # source points at a path that does not exist
    mp = _valid_marketplace(plugin_rel="./plugins/nope")
    _make_marketplace(tmp_path, mp)
    errors = vm.validate_marketplace(tmp_path)
    assert any("nope" in e or "does not" in e.lower() or "missing" in e.lower() for e in errors)


def test_string_source_dir_without_plugin_json_is_error(tmp_path):
    # dir exists but has no .claude-plugin/plugin.json
    mp = _valid_marketplace(plugin_rel="./plugins/demo-plugin")
    _make_marketplace(tmp_path, mp)
    (tmp_path / "plugins" / "demo-plugin").mkdir(parents=True)  # no manifest inside
    errors = vm.validate_marketplace(tmp_path)
    assert any("plugin.json" in e for e in errors)


def test_valid_tmp_marketplace_has_no_errors(tmp_path):
    mp = _valid_marketplace()
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    assert vm.validate_marketplace(tmp_path) == []


# ---------- plugin manifest edge cases ---------------------------------------

def test_plugin_missing_manifest_is_error(tmp_path):
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    plugin_dir.mkdir(parents=True)
    errors = vm.validate_plugin(plugin_dir)
    assert any("plugin.json" in e for e in errors)


def test_plugin_missing_name_is_error(tmp_path):
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _write_json(plugin_dir / ".claude-plugin" / "plugin.json", {"version": "0.1.0"})
    errors = vm.validate_plugin(plugin_dir)
    assert any("name" in e for e in errors)


def test_plugin_non_kebab_name_is_error(tmp_path):
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _write_json(plugin_dir / ".claude-plugin" / "plugin.json", {"name": "Demo_Plugin"})
    errors = vm.validate_plugin(plugin_dir)
    assert any("kebab" in e.lower() for e in errors)


def test_plugin_unparseable_manifest_is_error(tmp_path):
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    path = plugin_dir / ".claude-plugin" / "plugin.json"
    path.parent.mkdir(parents=True)
    path.write_text("{nope")
    errors = vm.validate_plugin(plugin_dir)
    assert any("json" in e.lower() or "parse" in e.lower() for e in errors)


# ---------- PLACEMENT RULE (the load-bearing one) ----------------------------

def test_misplaced_component_under_claude_plugin_is_detected(tmp_path):
    # skills/ INSIDE .claude-plugin/ is illegal
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _make_plugin(plugin_dir)
    (plugin_dir / ".claude-plugin" / "skills").mkdir(parents=True)
    misplaced = vm.find_misplaced_components(tmp_path)
    assert any(".claude-plugin" in m and "skills" in m for m in misplaced)


def test_each_component_dir_under_claude_plugin_is_detected(tmp_path):
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _make_plugin(plugin_dir)
    for comp in ("commands", "agents", "skills", "hooks", "output-styles", "themes", "monitors"):
        (plugin_dir / ".claude-plugin" / comp).mkdir(parents=True)
    misplaced = vm.find_misplaced_components(tmp_path)
    found = {pathlib.Path(m).name for m in misplaced}
    assert found == vm.COMPONENT_DIRS


def test_component_dir_at_plugin_root_is_allowed(tmp_path):
    # the SAME dirs at the plugin ROOT are correct -> not flagged
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _make_plugin(plugin_dir)
    for comp in ("skills", "agents", "commands", "hooks"):
        (plugin_dir / comp).mkdir(parents=True)
    assert vm.find_misplaced_components(tmp_path) == []


def test_marketplace_validation_fails_when_component_misplaced(tmp_path):
    # the placement rule must also fail the overall marketplace validation
    mp = _valid_marketplace()
    _make_marketplace(tmp_path, mp)
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _make_plugin(plugin_dir)
    (plugin_dir / ".claude-plugin" / "skills").mkdir(parents=True)
    errors = vm.validate_marketplace(tmp_path)
    assert any("skills" in e and ".claude-plugin" in e for e in errors)


def test_plugin_json_alone_in_claude_plugin_is_allowed(tmp_path):
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _make_plugin(plugin_dir)
    assert vm.find_misplaced_components(tmp_path) == []


def test_main_returns_one_when_invalid(tmp_path):
    # missing everything -> CLI must exit non-zero
    assert vm.main([str(tmp_path)]) == 1


# ---------- UNKNOWN TOP-LEVEL KEY rejection (T-12.7 / QA-3 gap) ---------------
# The official `claude plugin validate` rejects unknown top-level keys (e.g. a stray
# `$schema`). The floor validator used to accept them. These pin the parity.

def test_plugin_unknown_top_level_key_schema_is_error(tmp_path):
    # a bogus `$schema` top-level key (the exact key that slipped past CI) must be rejected
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _write_json(
        plugin_dir / ".claude-plugin" / "plugin.json",
        {"name": "demo-plugin", "$schema": "https://example.com/schema.json"},
    )
    errors = vm.validate_plugin(plugin_dir)
    assert any("$schema" in e for e in errors), errors
    assert any("unknown" in e.lower() for e in errors), errors


def test_plugin_unknown_top_level_key_bogus_is_error(tmp_path):
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _write_json(
        plugin_dir / ".claude-plugin" / "plugin.json",
        {"name": "demo-plugin", "BOGUS_UNKNOWN_KEY": 1},
    )
    errors = vm.validate_plugin(plugin_dir)
    assert any("BOGUS_UNKNOWN_KEY" in e for e in errors), errors


def test_plugin_known_top_level_keys_are_allowed(tmp_path):
    # a manifest using only documented optional keys must stay clean
    plugin_dir = tmp_path / "plugins" / "demo-plugin"
    _write_json(
        plugin_dir / ".claude-plugin" / "plugin.json",
        {
            "name": "demo-plugin",
            "version": "0.1.0",
            "description": "x",
            "author": {"name": "Tester"},
            "license": "Apache-2.0",
            "repository": "https://example.com/repo",
            "keywords": ["a"],
        },
    )
    assert vm.validate_plugin(plugin_dir) == []


def test_marketplace_unknown_top_level_key_is_error(tmp_path):
    mp = _valid_marketplace()
    mp["$schema"] = "https://example.com/marketplace.schema.json"
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    errors = vm.validate_marketplace(tmp_path)
    assert any("$schema" in e for e in errors), errors
    assert any("unknown" in e.lower() for e in errors), errors


def test_marketplace_known_metadata_top_level_key_is_allowed(tmp_path):
    # `metadata` is a documented top-level marketplace key -> must NOT be flagged
    mp = _valid_marketplace()
    mp["metadata"] = {"pluginRoot": "./plugins", "description": "demo"}
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    assert vm.validate_marketplace(tmp_path) == []


def test_plugin_entry_extra_keys_are_still_allowed(tmp_path):
    # unknown-key rejection is scoped to the TWO top-level manifests only.
    # Plugin ENTRIES inside plugins[] may carry extra keys (category/tags/etc.) -> allowed.
    mp = _valid_marketplace()
    mp["plugins"][0]["category"] = "security"
    mp["plugins"][0]["tags"] = ["sast", "owasp"]
    mp["plugins"][0]["description"] = "demo"
    _make_marketplace(tmp_path, mp)
    _make_plugin(tmp_path / "plugins" / "demo-plugin")
    assert vm.validate_marketplace(tmp_path) == []


def test_real_repo_marketplace_has_no_unknown_top_level_keys():
    # the real repo must validate clean -- $schema was removed; metadata is allowed
    assert vm.validate_marketplace(".") == []
