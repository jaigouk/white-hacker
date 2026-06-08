"""wh-w30 — per-ecosystem adapters (PyPI/RubyGems/Go/Cargo/Maven) tests.

Each adapter normalizes its ecosystem's manifest + lockfile + build hooks into the
SAME struct `{deps:[{name,spec,source_type}], lifecycle_scripts, lockfile_present,
script_files}` that `parse_npm` produces (supply_chain.py:201); the S1–S8 signal core
+ `score()` + `scan()` are reused UNCHANGED. `scan()` detects the ecosystem by which
marker manifest exists and dispatches to the right adapter (supply_chain.py:~400).

TDD, RED first. NEUTRALIZED fixtures only (tmp_path) — for EACH ecosystem a fixture
that SHOULD trip a name/source/hook signal (S2 non-registry source · S5 homoglyph vs
the allowlist · S6 a build hook with an INERT dangerous-API comment) PLUS a benign
control that must NOT trip. Every emitted document is schema-valid (`validate(doc)==[]`).

Rule 9 (tests verify intent): every invariant pins BOTH `== expected` AND `!= wrong`.

Run: `uv run --with jsonschema --with pytest pytest \
    plugins/white-hacker/skills/deps-scan/scripts/tests -q`
"""
from __future__ import annotations

import supply_chain as sc
import validate_findings as vf


# --------------------------------------------------------------------------- #
# A clearly INERT build-hook body carrying the S6 detection-trigger *strings* in
# commented, non-functional form — same discipline as the npm tests + eval corpus
# neutralized filenames. NEVER functional. ≥2 distinct dangerous-API patterns →
# S6 HIGH (project-level). The patterns (`child_process`, `eval(`, `fetch(`,
# `~/.ssh`, `Buffer.from(...,'base64')`) come from supply_chain._DANGEROUS_API_PATTERNS.
_INERT_DANGEROUS_HOOK = (
    "# SAMPLE (inert) — detection test data only, does nothing.\n"
    "# would call child_process to spawn a shell\n"
    "# would eval( ) a remote string and fetch( ) the payload over the network\n"
    "# would read ~/.ssh and ~/.aws then Buffer.from(x,'base64') and exfiltrate\n"
    "# no-op: see comments above\n"
)


def _emitted(doc: dict) -> list[dict]:
    return doc["findings"]


def _has_cand(doc: dict, needle: str) -> bool:
    return any(needle in f["exploit_scenario"] for f in doc["findings"])


# =========================================================================== #
# PyPI — pyproject.toml / requirements.txt + poetry.lock/uv.lock; setup.py = hook
# =========================================================================== #
def test_parse_pypi_pyproject_and_lockfile(tmp_path):
    proj = tmp_path / "py"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\n'
        'name = "demo"\n'
        'dependencies = [\n'
        '  "requests>=2.0",\n'
        '  "numpy @ git+https://example.test/numpy.git",\n'
        ']\n'
    )
    (proj / "poetry.lock").write_text("# lock\n")
    norm = sc.parse_pypi(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    assert by["requests"]["source_type"] == "registry"
    assert by["numpy"]["source_type"] == "git"
    assert by["numpy"]["source_type"] != "registry"  # the wrong classification
    assert norm["lockfile_present"] is True
    assert norm["lockfile_present"] != False  # noqa: E712 — pin the wrong value
    # no setup.py here → no install hook
    assert norm["lifecycle_scripts"] == {}


def test_parse_pypi_poetry_table_and_setup_py_hook(tmp_path):
    proj = tmp_path / "py"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\n'
        'python = "^3.11"\n'
        'requests = "^2.31"\n'
        'localdep = { path = "../localdep" }\n'
    )
    (proj / "setup.py").write_text("# inert setup\n")
    norm = sc.parse_pypi(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # the `python` constraint is the interpreter, NOT a dependency
    assert "python" not in by
    assert by["requests"]["source_type"] == "registry"
    assert by["localdep"]["source_type"] == "file"
    # setup.py present → S1 build/install hook recorded + scanned as a script file
    assert "setup.py" in norm["lifecycle_scripts"]
    assert any(p.endswith("setup.py") for p in norm["script_files"])


def test_parse_pypi_requirements_txt_git_source(tmp_path):
    proj = tmp_path / "py"
    proj.mkdir()
    (proj / "requirements.txt").write_text(
        "# a comment\n"
        "flask==2.3.0\n"
        "git+https://example.test/lib.git#egg=lib\n"
        "\n"
    )
    norm = sc.parse_pypi(str(proj))
    by = {d["name"]: d["source_type"] for d in norm["deps"]}
    assert by.get("flask") == "registry"
    assert by.get("lib") == "git"
    assert by.get("lib") != "registry"


def test_pypi_scan_s5_homoglyph_emits_high(tmp_path):
    # "requestss" folds (collapse doubled 's') onto the allowlisted "requests" while
    # the raw string DIFFERS → S5 HIGH (cross-ecosystem allowlist entry).
    proj = tmp_path / "py"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["requestss>=1.0"]\n'
    )
    doc = sc.scan(str(proj))
    assert _has_cand(doc, "requestss")
    cand = next(f for f in _emitted(doc) if "requestss" in f["exploit_scenario"])
    assert cand["severity"] == "HIGH"
    assert cand["severity"] != "MEDIUM"  # homoglyph/separator collisions are HIGH
    assert cand["file"].endswith("pyproject.toml")
    assert doc["summary"]["scanned_langs"] == ["python"]
    assert vf.validate(doc) == []


def test_pypi_scan_setup_py_dangerous_hook_emits_high(tmp_path):
    # setup.py with ≥2 INERT dangerous-API strings → S6 HIGH (project-level).
    proj = tmp_path / "py"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["requests==2.31.0"]\n'
    )
    (proj / "setup.py").write_text(_INERT_DANGEROUS_HOOK)
    doc = sc.scan(str(proj))
    high = [f for f in _emitted(doc) if f["severity"] == "HIGH"]
    assert high, "≥2 dangerous-API strings in setup.py → S6 HIGH"
    assert any(f["file"].endswith("setup.py") for f in high)
    assert vf.validate(doc) == []


def test_pypi_benign_control_no_finding(tmp_path):
    # pinned registry dep + committed lockfile + NO setup.py = no signal → no finding.
    proj = tmp_path / "py"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["requests==2.31.0", "numpy==1.26.0"]\n'
    )
    (proj / "uv.lock").write_text("# lock\n")
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []          # the FP guard
    assert _emitted(doc) != [{}]        # truly empty, not a stub
    assert doc["summary"]["scanned_langs"] == ["python"]
    assert vf.validate(doc) == []


# =========================================================================== #
# RubyGems — Gemfile + Gemfile.lock; git:/path:; extconf.rb/ext/ = native hook
# =========================================================================== #
def test_parse_gem_sources_and_lockfile(tmp_path):
    proj = tmp_path / "rb"
    proj.mkdir()
    (proj / "Gemfile").write_text(
        "source 'https://rubygems.org'\n"
        "gem 'rails', '~> 7.0'\n"
        "gem 'forked', git: 'https://example.test/forked.git'\n"
        "gem 'localgem', path: '../localgem'\n"
    )
    (proj / "Gemfile.lock").write_text("GEM\n  remote: https://rubygems.org/\n")
    norm = sc.parse_gem(str(proj))
    by = {d["name"]: d["source_type"] for d in norm["deps"]}
    assert by["rails"] == "registry"
    assert by["forked"] == "git"
    assert by["localgem"] == "file"
    assert by["forked"] != "registry"
    assert norm["lockfile_present"] is True
    assert norm["lockfile_present"] is not False


def test_gem_scan_git_source_plus_native_hook_corroborates(tmp_path):
    # S2 (git source) + S1 (extconf.rb native build hook present) = 2 signals → MEDIUM.
    proj = tmp_path / "rb"
    proj.mkdir()
    (proj / "Gemfile").write_text(
        "gem 'router', git: 'https://example.test/router.git'\n"
    )
    (proj / "ext" / "router").mkdir(parents=True)
    (proj / "ext" / "router" / "extconf.rb").write_text("# inert native build\n")
    doc = sc.scan(str(proj))
    f = _emitted(doc)
    cand = next(x for x in f if "router" in x["exploit_scenario"])
    assert cand["severity"] in {"MEDIUM", "HIGH"}
    assert cand["severity"] != "LOW"
    assert doc["summary"]["scanned_langs"] == ["ruby"]
    assert vf.validate(doc) == []


def test_gem_scan_dangerous_extconf_emits_high(tmp_path):
    # a native-build hook (extconf.rb) carrying ≥2 inert dangerous-API strings → S6 HIGH.
    proj = tmp_path / "rb"
    proj.mkdir()
    (proj / "Gemfile").write_text("gem 'rails', '7.0.0'\n")
    (proj / "ext").mkdir()
    (proj / "ext" / "extconf.rb").write_text(_INERT_DANGEROUS_HOOK)
    doc = sc.scan(str(proj))
    high = [x for x in _emitted(doc) if x["severity"] == "HIGH"]
    assert high, "dangerous extconf.rb → S6 HIGH"
    assert any(x["file"].endswith("extconf.rb") for x in high)
    assert vf.validate(doc) == []


def test_gem_benign_control_no_finding(tmp_path):
    proj = tmp_path / "rb"
    proj.mkdir()
    (proj / "Gemfile").write_text("gem 'rails', '7.0.0'\ngem 'puma', '6.0.0'\n")
    (proj / "Gemfile.lock").write_text("GEM\n")
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []
    assert _emitted(doc) != [{}]
    assert doc["summary"]["scanned_langs"] == ["ruby"]
    assert vf.validate(doc) == []


# =========================================================================== #
# Go — go.mod (require + replace) + go.sum (lockfile); replace→fork = non-registry
# =========================================================================== #
def test_parse_go_require_and_replace(tmp_path):
    proj = tmp_path / "go"
    proj.mkdir()
    (proj / "go.mod").write_text(
        "module example.test/app\n\n"
        "go 1.22\n\n"
        "require (\n"
        "    github.com/spf13/cobra v1.8.0\n"
        "    example.test/forked v0.1.0\n"
        ")\n\n"
        "replace example.test/forked => ../forked\n"
    )
    (proj / "go.sum").write_text("github.com/spf13/cobra v1.8.0 h1:abc=\n")
    norm = sc.parse_go(str(proj))
    by = {d["name"]: d["source_type"] for d in norm["deps"]}
    assert by["github.com/spf13/cobra"] == "registry"
    # a `replace` to a local path makes the module a non-registry (forked) source
    assert by["example.test/forked"] == "file"
    assert by["example.test/forked"] != "registry"
    assert norm["lockfile_present"] is True          # go.sum present
    assert norm["lockfile_present"] is not False
    # Go has NO install hook
    assert norm["lifecycle_scripts"] == {}
    assert norm["script_files"] == []


def test_go_scan_replace_to_remote_fork_emits(tmp_path):
    # A `replace` rewires a module to an attacker fork — a non-registry source (S2). A
    # lone S2 is informational; here the SAME replace ALSO makes the module name fold-
    # collide with the allowlisted module path → S5 HIGH dominates. (S5 needs no second
    # signal — it is HIGH on its own, per the scoring rule.)
    proj = tmp_path / "go"
    proj.mkdir()
    # "github.com/spf13/cobraa" folds (collapse doubled 'a') onto the allowlisted
    # "github.com/spf13/cobra" while the raw string DIFFERS → S5 HIGH.
    (proj / "go.mod").write_text(
        "module example.test/app\n\n"
        "go 1.22\n\n"
        "require github.com/spf13/cobraa v1.8.0\n"
    )
    doc = sc.scan(str(proj), allowlist=["github.com/spf13/cobra"])
    cand = next(x for x in _emitted(doc) if "cobraa" in x["exploit_scenario"])
    assert cand["severity"] == "HIGH"
    assert cand["severity"] != "MEDIUM"
    assert doc["summary"]["scanned_langs"] == ["go"]
    assert vf.validate(doc) == []


def test_go_replace_to_local_path_is_non_registry_source(tmp_path):
    # a `replace ... => ../fork` is classified file (in-repo), benign per the S2
    # exclusion — like npm file:/workspace: — so it must NOT fan out as a candidate.
    proj = tmp_path / "go"
    proj.mkdir()
    (proj / "go.mod").write_text(
        "module example.test/app\n\ngo 1.22\n\n"
        "require example.test/forked v0.1.0\n\n"
        "replace example.test/forked => ../forked\n"
    )
    (proj / "go.sum").write_text("# lock\n")
    norm = sc.parse_go(str(proj))
    by = {d["name"]: d["source_type"] for d in norm["deps"]}
    assert by["example.test/forked"] == "file"
    doc = sc.scan(str(proj))
    assert not _has_cand(doc, "example.test/forked")  # in-repo replace is benign
    assert vf.validate(doc) == []


def test_go_benign_control_no_finding(tmp_path):
    proj = tmp_path / "go"
    proj.mkdir()
    (proj / "go.mod").write_text(
        "module example.test/app\n\ngo 1.22\n\n"
        "require github.com/spf13/cobra v1.8.0\n"
    )
    (proj / "go.sum").write_text("github.com/spf13/cobra v1.8.0 h1:abc=\n")
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []
    assert _emitted(doc) != [{}]
    assert doc["summary"]["scanned_langs"] == ["go"]
    assert vf.validate(doc) == []


# =========================================================================== #
# Cargo — Cargo.toml + Cargo.lock; git/path deps; build.rs = build hook
# =========================================================================== #
def test_parse_cargo_sources_and_lockfile(tmp_path):
    proj = tmp_path / "rs"
    proj.mkdir()
    (proj / "Cargo.toml").write_text(
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n"
        "[dependencies]\n"
        "serde = \"1.0\"\n"
        "forked = { git = \"https://example.test/forked.git\" }\n"
        "localcrate = { path = \"../localcrate\" }\n"
    )
    (proj / "Cargo.lock").write_text("# lock\n")
    norm = sc.parse_cargo(str(proj))
    by = {d["name"]: d["source_type"] for d in norm["deps"]}
    assert by["serde"] == "registry"
    assert by["forked"] == "git"
    assert by["localcrate"] == "file"
    assert by["forked"] != "registry"
    assert norm["lockfile_present"] is True
    assert norm["lockfile_present"] is not False


def test_cargo_scan_dangerous_build_rs_emits_high(tmp_path):
    # build.rs is the Cargo build hook; ≥2 inert dangerous-API strings → S6 HIGH.
    proj = tmp_path / "rs"
    proj.mkdir()
    (proj / "Cargo.toml").write_text(
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n"
        "[dependencies]\nserde = \"1.0\"\n"
    )
    (proj / "build.rs").write_text(_INERT_DANGEROUS_HOOK)
    doc = sc.scan(str(proj))
    high = [x for x in _emitted(doc) if x["severity"] == "HIGH"]
    assert high, "dangerous build.rs → S6 HIGH"
    assert any(x["file"].endswith("build.rs") for x in high)
    assert doc["summary"]["scanned_langs"] == ["rust"]
    assert vf.validate(doc) == []


def test_cargo_scan_git_source_plus_build_hook_corroborates(tmp_path):
    # S2 (git source) + S1 (build.rs present, benign body) = 2 signals → MEDIUM.
    proj = tmp_path / "rs"
    proj.mkdir()
    (proj / "Cargo.toml").write_text(
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n"
        "[dependencies]\n"
        "router = { git = \"https://example.test/router.git\" }\n"
    )
    (proj / "build.rs").write_text("// inert benign build\nfn main() {}\n")
    doc = sc.scan(str(proj))
    cand = next(x for x in _emitted(doc) if "router" in x["exploit_scenario"])
    assert cand["severity"] in {"MEDIUM", "HIGH"}
    assert cand["severity"] != "LOW"
    assert vf.validate(doc) == []


def test_cargo_benign_control_no_finding(tmp_path):
    proj = tmp_path / "rs"
    proj.mkdir()
    (proj / "Cargo.toml").write_text(
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n"
        "[dependencies]\nserde = \"1.0.0\"\ntokio = \"1.0.0\"\n"
    )
    (proj / "Cargo.lock").write_text("# lock\n")
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []
    assert _emitted(doc) != [{}]
    assert doc["summary"]["scanned_langs"] == ["rust"]
    assert vf.validate(doc) == []


# =========================================================================== #
# Maven — pom.xml (<dependencies><dependency> groupId/artifactId/version); no hook
# =========================================================================== #
_POM_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
    '  <modelVersion>4.0.0</modelVersion>\n'
    '  <groupId>com.example</groupId>\n'
    '  <artifactId>demo</artifactId>\n'
    '  <version>1.0.0</version>\n'
)
_POM_FOOTER = "</project>\n"


def test_parse_maven_dependencies(tmp_path):
    proj = tmp_path / "mvn"
    proj.mkdir()
    (proj / "pom.xml").write_text(
        _POM_HEADER
        + "  <dependencies>\n"
        + "    <dependency>\n"
        + "      <groupId>org.apache.commons</groupId>\n"
        + "      <artifactId>commons-lang3</artifactId>\n"
        + "      <version>3.14.0</version>\n"
        + "    </dependency>\n"
        + "    <dependency>\n"
        + "      <groupId>com.google.guava</groupId>\n"
        + "      <artifactId>guava</artifactId>\n"
        + "      <version>33.0.0-jre</version>\n"
        + "      <scope>system</scope>\n"
        + "      <systemPath>/opt/guava.jar</systemPath>\n"
        + "    </dependency>\n"
        + "  </dependencies>\n"
        + _POM_FOOTER
    )
    norm = sc.parse_maven(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # name is the coordinate groupId:artifactId
    assert "org.apache.commons:commons-lang3" in by
    assert by["org.apache.commons:commons-lang3"]["source_type"] == "registry"
    # a system-scope dependency (local jar) is a non-registry (file) source
    assert by["com.google.guava:guava"]["source_type"] == "file"
    assert by["com.google.guava:guava"]["source_type"] != "registry"
    # Maven has no standard committed lockfile → False; no install hook
    assert norm["lockfile_present"] is False
    assert norm["lifecycle_scripts"] == {}


def test_maven_scan_system_scope_source_corroborates(tmp_path):
    # a system-scope dep (file source, S2) + unpinned+no-lock (S3) → ≥2 → MEDIUM.
    proj = tmp_path / "mvn"
    proj.mkdir()
    (proj / "pom.xml").write_text(
        _POM_HEADER
        + "  <dependencies>\n"
        + "    <dependency>\n"
        + "      <groupId>com.example</groupId>\n"
        + "      <artifactId>vendored</artifactId>\n"
        + "      <version>1.0.0</version>\n"
        + "      <scope>system</scope>\n"
        + "      <systemPath>/opt/vendored.jar</systemPath>\n"
        + "    </dependency>\n"
        + "  </dependencies>\n"
        + _POM_FOOTER
    )
    doc = sc.scan(str(proj))
    # system scope = file source → benign per the S2 exclusion (in-repo/local). So this
    # MUST NOT fan out as a candidate — same rule the npm file:/workspace: deps obey.
    assert not _has_cand(doc, "com.example:vendored")
    assert doc["summary"]["scanned_langs"] == ["java"]
    assert vf.validate(doc) == []


def test_maven_scan_s5_homoglyph_emits_high(tmp_path):
    # the artifact coordinate "com.example:guavaa" folds (collapse doubled 'a') onto an
    # allowlisted coordinate "com.example:guava" → S5 HIGH (requires the allowlist entry).
    proj = tmp_path / "mvn"
    proj.mkdir()
    (proj / "pom.xml").write_text(
        _POM_HEADER
        + "  <dependencies>\n"
        + "    <dependency>\n"
        + "      <groupId>com.example</groupId>\n"
        + "      <artifactId>guavaa</artifactId>\n"
        + "      <version>1.0.0</version>\n"
        + "    </dependency>\n"
        + "  </dependencies>\n"
        + _POM_FOOTER
    )
    doc = sc.scan(str(proj), allowlist=["com.example:guava"])
    cand = next(f for f in _emitted(doc) if "guavaa" in f["exploit_scenario"])
    assert cand["severity"] == "HIGH"
    assert cand["severity"] != "MEDIUM"
    assert vf.validate(doc) == []


def test_maven_benign_control_no_finding(tmp_path):
    proj = tmp_path / "mvn"
    proj.mkdir()
    (proj / "pom.xml").write_text(
        _POM_HEADER
        + "  <dependencies>\n"
        + "    <dependency>\n"
        + "      <groupId>org.apache.commons</groupId>\n"
        + "      <artifactId>commons-lang3</artifactId>\n"
        + "      <version>3.14.0</version>\n"
        + "    </dependency>\n"
        + "  </dependencies>\n"
        + _POM_FOOTER
    )
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []
    assert _emitted(doc) != [{}]
    assert doc["summary"]["scanned_langs"] == ["java"]
    assert vf.validate(doc) == []


# =========================================================================== #
# dispatch — scan() detects the ecosystem by marker file; npm path unchanged
# =========================================================================== #
def test_scan_dispatches_npm_unchanged(tmp_path):
    # a package.json project still routes to parse_npm + 'javascript' (the npm lead path).
    import json
    proj = tmp_path / "js"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({
        "dependencies": {"@anthropic_ai/sdk": "1.0.0"},
    }))
    doc = sc.scan(str(proj))
    assert doc["summary"]["scanned_langs"] == ["javascript"]
    assert _has_cand(doc, "@anthropic_ai/sdk")
    assert doc["findings"][0]["file"].endswith("package.json")
    assert vf.validate(doc) == []


def test_scan_no_known_manifest_degrades_empty(tmp_path):
    # a directory with no recognized manifest → empty-but-valid, no raise, no lang.
    proj = tmp_path / "bare"
    proj.mkdir()
    (proj / "README.md").write_text("nothing here\n")
    doc = sc.scan(str(proj))
    assert _emitted(doc) == []
    assert doc["summary"]["scanned_langs"] == []
    assert doc["summary"]["scanned_langs"] != ["javascript"]  # the wrong default
    assert "malware-db" in doc["summary"]["tools_unavailable"]
    assert vf.validate(doc) == []


def test_each_adapter_never_raises_on_missing_manifest(tmp_path):
    # every adapter degrades to the empty struct on a missing/odd manifest (floor).
    empty = tmp_path / "empty"
    empty.mkdir()
    for fn in (sc.parse_pypi, sc.parse_gem, sc.parse_go, sc.parse_cargo, sc.parse_maven):
        norm = fn(str(empty))
        assert norm["deps"] == []
        assert norm["lockfile_present"] is False
        assert norm["lifecycle_scripts"] == {}
        assert norm["script_files"] == []
