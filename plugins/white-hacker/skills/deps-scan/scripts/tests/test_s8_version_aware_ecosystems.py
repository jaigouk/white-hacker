"""wh-7o1 — extend version-aware S8 beyond npm/Python.

wh-4k9 made S8 version-aware but resolved-version extraction covered only npm
(package-lock v1/v2/v3) and Python (poetry.lock/uv.lock + the name-stripped `==` pin).
This module pins the SAME version-aware quality for the repo's other first-class
ecosystems, each invariant verified through the REAL adapter / `scan()` (the wave-1a
lesson: direct-helper-only tests missed the adapter-shape Go FN):

  * Go — `_exact_pin` accepts a leading `v` and returns the string AS WRITTEN (OSV-Go
    version sets are v-prefixed, e.g. `v1.2.3`); ranges (`v1.x`, `>=v1.2`, a hyphen range)
    still yield None. go.mod `require` versions attach as `resolved` (the require version
    IS the selected version post `go mod tidy`).
  * Maven — `${prop}` version refs resolve against the SAME pom's `<properties>`; an
    unresolvable property or a BOM/parent-managed dep (no `<version>`) stays wildcard-only
    BY DESIGN (the parent pom may live outside the repo).
  * Ruby — Gemfile.lock `specs:` ("    name (1.2.3)") attaches `resolved`; an idiomatic
    `~> 1.2.3` range resolves to the locked version; no Gemfile.lock leaves it off.
  * Cargo — Cargo.lock `[[package]]` attaches `resolved` and is PREFERRED over the bare
    Cargo.toml spec (a bare spec semantically means a `^` RANGE — the full per-ecosystem
    exact-pin semantics is deferred to wh-5es RQ2's ecosystem key).
  * Pipfile.lock — JSON `default`/`develop` maps ("==1.2.3") attach `resolved` alongside
    the existing poetry/uv path.

Every new lockfile parser degrades on hostile input (malformed / garbage / non-dict
shapes → `{}` / no-attach, never raise) — the `_resolved_npm` tests are the pattern.

Rule 9 (tests verify intent): every invariant pins BOTH `== expected` AND `!= wrong`.

Run: `nice -n 10 uv run --project plugins/white-hacker/skills/deps-scan/scripts \
    --with jsonschema --with pytest pytest \
    plugins/white-hacker/skills/deps-scan/scripts/tests -q`
"""
from __future__ import annotations

import json
import pathlib

import supply_chain as sc

_BAD = "evil-pkg"  # the watchlisted compromised name (registry-style, ecosystem-agnostic)


def _scenarios(doc: dict) -> list[str]:
    return [f["exploit_scenario"] for f in doc["findings"]]


def _fired_s8(doc: dict, name: str) -> bool:
    return any(f"{name} @" in s and "S8" in s for s in _scenarios(doc))


# =========================================================================== #
# Go — _exact_pin accepts a leading `v` (return AS WRITTEN); go.mod require
#      versions attach as `resolved`. The FN: a known-bad Go module at its exact
#      listed bad version did NOT specific-match because _exact_pin('v1.2.3')→None.
# =========================================================================== #
_GO_MOD_BAD = "github.com/evil/mod"  # a v-prefixed Go module path (OSV-Go naming)


def _write_go(project_dir: pathlib.Path, requires: dict[str, str],
              replace: str = "", with_sum: bool = False) -> pathlib.Path:
    """A go.mod with a `require ( ... )` block; optional one `replace` line."""
    project_dir.mkdir(parents=True, exist_ok=True)
    lines = ["module example.test/app", "", "go 1.22", "", "require ("]
    for mod, ver in requires.items():
        lines.append(f"    {mod} {ver}")
    lines.append(")")
    if replace:
        lines += ["", replace]
    (project_dir / "go.mod").write_text("\n".join(lines) + "\n")
    if with_sum:
        (project_dir / "go.sum").write_text(
            f"{_GO_MOD_BAD} v1.2.3 h1:abc=\n"
        )
    return project_dir


def test_exact_pin_accepts_leading_v_returns_as_written():
    # OSV-Go version sets are v-prefixed; the manifest carries `v1.2.3` → return it AS
    # WRITTEN so the exact set membership (is_known_bad) matches.
    assert sc._exact_pin("v1.2.3") == "v1.2.3"          # == expected: v kept verbatim
    assert sc._exact_pin("v0.1.0") == "v0.1.0"
    assert sc._exact_pin("v2.5.0-rc.1") == "v2.5.0-rc.1"
    # != wrong: the leading v is NOT stripped (OSV-Go would then never match)
    assert sc._exact_pin("v1.2.3") != "1.2.3"


def test_exact_pin_rejects_v_prefixed_ranges():
    # a leading v on a RANGE is still a range → None (must never specific-match a db entry)
    assert sc._exact_pin("v1.x") is None                # == expected
    assert sc._exact_pin(">=v1.2") is None
    assert sc._exact_pin("v1.2.3 - v2.0.0") is None
    # != wrong: a range does NOT become an exact pin just by carrying a v
    assert sc._exact_pin("v1.x") != "v1.x"


def test_go_exact_require_version_flags_on_matching_db(tmp_path):
    # the FN inverts: a known-bad Go module at its exact listed bad version flags.
    proj = _write_go(tmp_path / "go", {_GO_MOD_BAD: "v1.2.3"})
    doc = sc.scan(str(proj), malware_db={_GO_MOD_BAD: {"v1.2.3"}})
    assert _fired_s8(doc, _GO_MOD_BAD) is True          # == expected


def test_go_exact_require_version_does_not_flag_on_other_version(tmp_path):
    proj = _write_go(tmp_path / "go", {_GO_MOD_BAD: "v1.2.3"})
    doc = sc.scan(str(proj), malware_db={_GO_MOD_BAD: {"v9.9.9"}})
    # != wrong: the required version is NOT the bad one → no flag (the probe inverts)
    assert _fired_s8(doc, _GO_MOD_BAD) is False


def test_parse_go_attaches_resolved_from_require_version(tmp_path):
    proj = _write_go(tmp_path / "go",
                     {_GO_MOD_BAD: "v1.2.3", "example.test/clean": "v0.4.0"})
    norm = sc.parse_go(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: the require version is attached as resolved (the selected version)
    assert by[_GO_MOD_BAD]["resolved"] == "v1.2.3"
    assert by["example.test/clean"]["resolved"] == "v0.4.0"
    # != wrong: resolved is the v-prefixed selected version, not stripped/None
    assert by[_GO_MOD_BAD]["resolved"] != "1.2.3"


def test_go_replace_directive_dep_resolved_unaffected(tmp_path):
    # a replace-directive dep carries a `=> ...` spec, not a plain version — the require
    # value still attaches as resolved for the OTHER (registry) dep; the replaced one is
    # not a registry version pin (its spec is the replace expression).
    proj = _write_go(
        tmp_path / "go",
        {_GO_MOD_BAD: "v1.2.3", "example.test/forked": "v0.1.0"},
        replace="replace example.test/forked => ../forked",
    )
    norm = sc.parse_go(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: the registry dep still resolves to its require version
    assert by[_GO_MOD_BAD]["resolved"] == "v1.2.3"
    # the replaced dep became a file source with a `=> ...` spec (NOT a version pin)
    assert by["example.test/forked"]["source_type"] == "file"
    assert by["example.test/forked"]["spec"].startswith("=>")
    # != wrong: the replace dep's spec is not a bare version that would mis-resolve
    assert by["example.test/forked"]["spec"] != "v0.1.0"


# =========================================================================== #
# Maven — resolve `${prop}` version refs against the SAME pom's <properties>;
#         a BOM/parent-managed dep (no <version>) or an unresolvable property stays
#         wildcard-only BY DESIGN (the parent pom may live outside the repo).
# =========================================================================== #
# the pom carries a namespace (xmlns) — _strip_ns / _mvn_child_text handle it (the same
# shape test_adapters.py uses); a property-versioned dependency is the centralized-version
# idiom that previously fell to wildcard-only.
_POM_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
    "  <modelVersion>4.0.0</modelVersion>\n"
    "  <groupId>com.example</groupId>\n"
    "  <artifactId>demo</artifactId>\n"
    "  <version>1.0.0</version>\n"
)
_POM_FOOTER = "</project>\n"
_MVN_BAD = "org.evil:evil-lib"  # groupId:artifactId coordinate (OSV-Maven naming)


def _write_pom(project_dir: pathlib.Path, body: str) -> pathlib.Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "pom.xml").write_text(_POM_HEADER + body + _POM_FOOTER)
    return project_dir


def test_parse_maven_resolves_property_version_to_resolved(tmp_path):
    proj = _write_pom(
        tmp_path / "mvn",
        "  <properties>\n"
        "    <evil.version>1.2.3</evil.version>\n"
        "  </properties>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.evil</groupId>\n"
        "      <artifactId>evil-lib</artifactId>\n"
        "      <version>${evil.version}</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n",
    )
    norm = sc.parse_maven(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: the ${evil.version} ref resolves against <properties> → resolved 1.2.3
    assert by[_MVN_BAD]["resolved"] == "1.2.3"
    # != wrong: resolved is the property VALUE, not the literal ${...} ref / the bad version
    assert by[_MVN_BAD]["resolved"] != "${evil.version}"


def test_maven_property_versioned_dep_flags_on_matching_db(tmp_path):
    proj = _write_pom(
        tmp_path / "mvn",
        "  <properties>\n"
        "    <evil.version>1.2.3</evil.version>\n"
        "  </properties>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.evil</groupId>\n"
        "      <artifactId>evil-lib</artifactId>\n"
        "      <version>${evil.version}</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n",
    )
    # == expected: the resolved property version specific-matches the db entry
    assert _fired_s8(sc.scan(str(proj), malware_db={_MVN_BAD: {"1.2.3"}}), _MVN_BAD)
    # != wrong: a non-matching db version does not flag the resolved property version
    assert not _fired_s8(sc.scan(str(proj), malware_db={_MVN_BAD: {"9.9.9"}}), _MVN_BAD)


def test_maven_unresolvable_property_stays_wildcard_only(tmp_path):
    # ${other.prop} has no matching <properties> entry → unresolved → wildcard-only.
    proj = _write_pom(
        tmp_path / "mvn",
        "  <properties>\n"
        "    <some.other>9.9.9</some.other>\n"
        "  </properties>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.evil</groupId>\n"
        "      <artifactId>evil-lib</artifactId>\n"
        "      <version>${missing.prop}</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n",
    )
    norm = sc.parse_maven(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: an unresolvable property leaves NO resolved key (stays the ${...} spec)
    assert "resolved" not in by[_MVN_BAD]
    assert by[_MVN_BAD]["spec"] == "${missing.prop}"
    # wildcard entry flags (whole package bad); a specific-version entry does NOT
    assert _fired_s8(sc.scan(str(proj), malware_db={_MVN_BAD: {"*"}}), _MVN_BAD)        # == expected
    assert not _fired_s8(sc.scan(str(proj), malware_db={_MVN_BAD: {"1.2.3"}}), _MVN_BAD)  # != wrong


def test_maven_bom_managed_no_version_stays_wildcard_only(tmp_path):
    # a parent/BOM-managed dep has NO <version> at all → spec '*' → wildcard-only BY DESIGN.
    proj = _write_pom(
        tmp_path / "mvn",
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.evil</groupId>\n"
        "      <artifactId>evil-lib</artifactId>\n"
        "    </dependency>\n"
        "  </dependencies>\n",
    )
    norm = sc.parse_maven(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    assert "resolved" not in by[_MVN_BAD]               # == expected: nothing to resolve
    assert by[_MVN_BAD]["spec"] == "*"
    assert _fired_s8(sc.scan(str(proj), malware_db={_MVN_BAD: {"*"}}), _MVN_BAD)        # == expected
    assert not _fired_s8(sc.scan(str(proj), malware_db={_MVN_BAD: {"1.2.3"}}), _MVN_BAD)  # != wrong


# =========================================================================== #
# Ruby — parse Gemfile.lock `specs:` ("    name (1.2.3)" — 4-space top-level; sub-deps
#        are 6-space and are NOT version pins) → `resolved` on the Gemfile dep. An
#        idiomatic `~> 1.2.3` range with no lockfile stays wildcard-only.
# =========================================================================== #
_GEM_BAD = "evil-gem"  # a RubyGems name


def _gemfile_lock(specs: dict[str, str], subdeps: list[str] | None = None) -> str:
    """A Gemfile.lock GEM/specs: block. Top-level gems are 4-space-indented with a
    parenthesized version; sub-dependencies (6-space) are name-only — NOT version pins."""
    lines = ["GEM", "  remote: https://rubygems.org/", "  specs:"]
    for name, ver in specs.items():
        lines.append(f"    {name} ({ver})")
        for sub in subdeps or []:
            lines.append(f"      {sub} (>= 0)")  # 6-space sub-dep, never a top-level pin
    lines += ["", "PLATFORMS", "  ruby", "", "DEPENDENCIES",
              *(f"  {n}" for n in specs)]
    return "\n".join(lines) + "\n"


def _write_gem(project_dir: pathlib.Path, gemfile: str,
               lock: str | None = None) -> pathlib.Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "Gemfile").write_text(gemfile)
    if lock is not None:
        (project_dir / "Gemfile.lock").write_text(lock)
    return project_dir


def test_parse_gem_attaches_resolved_from_gemfile_lock(tmp_path):
    proj = _write_gem(
        tmp_path / "rb",
        f"gem '{_GEM_BAD}', '~> 1.2'\ngem 'rails', '~> 7.0'\n",
        lock=_gemfile_lock({_GEM_BAD: "1.2.9", "rails": "7.1.3"},
                           subdeps=["actionpack"]),
    )
    norm = sc.parse_gem(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: the lockfile resolves the `~>` range to the exact locked version
    assert by[_GEM_BAD]["resolved"] == "1.2.9"
    assert by["rails"]["resolved"] == "7.1.3"
    # != wrong: resolved is the locked version, not the `~>` spec; sub-deps never pin
    assert by[_GEM_BAD]["resolved"] != "~> 1.2"
    assert "actionpack" not in by  # a 6-space sub-dep is not a top-level Gemfile dep


def test_gem_lockfile_resolved_flags_on_matching_db(tmp_path):
    proj = _write_gem(
        tmp_path / "rb",
        f"gem '{_GEM_BAD}', '~> 1.2'\n",
        lock=_gemfile_lock({_GEM_BAD: "1.2.9"}),
    )
    # == expected: resolved 1.2.9 specific-matches the db entry (the `~>` would not)
    assert _fired_s8(sc.scan(str(proj), malware_db={_GEM_BAD: {"1.2.9"}}), _GEM_BAD)
    # != wrong: a different locked-vs-db version does not flag
    assert not _fired_s8(sc.scan(str(proj), malware_db={_GEM_BAD: {"1.2.3"}}), _GEM_BAD)


def test_gem_no_lockfile_leaves_resolved_absent_wildcard_only(tmp_path):
    proj = _write_gem(tmp_path / "rb", f"gem '{_GEM_BAD}', '~> 1.2'\n")  # no Gemfile.lock
    norm = sc.parse_gem(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: no Gemfile.lock → NO resolved key (additive, optional)
    assert "resolved" not in by[_GEM_BAD]
    # an unresolved `~>` range: wildcard entry flags, a specific entry does NOT
    assert _fired_s8(sc.scan(str(proj), malware_db={_GEM_BAD: {"*"}}), _GEM_BAD)        # == expected
    assert not _fired_s8(sc.scan(str(proj), malware_db={_GEM_BAD: {"1.2.9"}}), _GEM_BAD)  # != wrong


def test_resolved_gem_hostile_lockfile_degrades_no_raise(tmp_path):
    # malformed / garbage Gemfile.lock content must degrade to {} (no resolved), never raise.
    for i, junk in enumerate(
        ("", "not a lockfile at all", "GEM\n  specs:\n    (((\n",
         "\x00\x01 binary garbage \xff")
    ):
        root = tmp_path / f"rb_{i}"
        _write_gem(root, f"gem '{_GEM_BAD}', '~> 1.2'\n", lock=junk)
        got = sc._resolved_gem(root)
        assert isinstance(got, dict)                    # == expected: a dict, never a raise
        assert _GEM_BAD not in got or isinstance(got.get(_GEM_BAD), str)


# =========================================================================== #
# Cargo — parse Cargo.lock `[[package]]` (defensive tomllib) → `resolved`, PREFERRED
#         over the bare Cargo.toml spec (a bare spec semantically means a `^` RANGE; the
#         full per-ecosystem exact-pin semantics is deferred to wh-5es RQ2's ecosystem key).
# =========================================================================== #
_CARGO_BAD = "evil-crate"  # a crates.io crate name


def _cargo_lock(name_to_version: dict[str, str]) -> str:
    """A Cargo.lock with an array of `[[package]]` name+version tables (TOML)."""
    blocks = ['version = 3', ""]
    for name, ver in name_to_version.items():
        blocks += [f'[[package]]', f'name = "{name}"', f'version = "{ver}"', ""]
    return "\n".join(blocks) + "\n"


def _write_cargo(project_dir: pathlib.Path, deps_block: str,
                 lock: str | None = None) -> pathlib.Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\n\n'
        "[dependencies]\n" + deps_block
    )
    if lock is not None:
        (project_dir / "Cargo.lock").write_text(lock)
    return project_dir


def test_parse_cargo_attaches_resolved_from_lock(tmp_path):
    proj = _write_cargo(
        tmp_path / "rs",
        f'{_CARGO_BAD} = "1.2.3"\nserde = "1.0"\n',
        lock=_cargo_lock({_CARGO_BAD: "1.9.0", "serde": "1.0.197"}),
    )
    norm = sc.parse_cargo(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: the lock resolves the crate to its locked version
    assert by[_CARGO_BAD]["resolved"] == "1.9.0"
    assert by["serde"]["resolved"] == "1.0.197"
    # != wrong: resolved is the locked version, NOT the bare manifest spec (which is a ^range)
    assert by[_CARGO_BAD]["resolved"] != "1.2.3"


def test_cargo_lock_resolved_preferred_over_bare_spec(tmp_path):
    # the bare Cargo.toml spec "1.2.3" is semantically ^1.2.3 (a range); the lock pins 1.9.0.
    # S8 must match the RESOLVED version, not the bare spec → db{1.9.0} flags, db{1.2.3} does NOT.
    proj = _write_cargo(
        tmp_path / "rs",
        f'{_CARGO_BAD} = "1.2.3"\n',
        lock=_cargo_lock({_CARGO_BAD: "1.9.0"}),
    )
    # == expected: the lockfile-resolved 1.9.0 is what flags (resolved wins over the spec)
    assert _fired_s8(sc.scan(str(proj), malware_db={_CARGO_BAD: {"1.9.0"}}), _CARGO_BAD)
    # != wrong: the bare manifest spec 1.2.3 is a RANGE, not a pin → must NOT flag
    assert not _fired_s8(sc.scan(str(proj), malware_db={_CARGO_BAD: {"1.2.3"}}), _CARGO_BAD)


def test_cargo_no_lock_leaves_resolved_absent(tmp_path):
    proj = _write_cargo(tmp_path / "rs", f'{_CARGO_BAD} = "1.2.3"\n')  # no Cargo.lock
    norm = sc.parse_cargo(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: no Cargo.lock → NO resolved key (additive, optional)
    assert "resolved" not in by[_CARGO_BAD]
    # != wrong: the additive key never corrupts the bare-spec dep shape
    assert by[_CARGO_BAD]["spec"] == "1.2.3"
    # ACCEPTED RESIDUAL (docstring-flagged): without a lockfile a bare Cargo spec is
    # semantically ^1.2.3 (a RANGE) but `_exact_pin` treats the plain literal as a pin, so
    # it specific-matches today. The full per-ecosystem fix (treat a bare crates.io spec as
    # a ^range) is wh-5es RQ2's ecosystem key — deferred, NOT in this ticket's scope. The
    # lockfile path (resolved wins) is the load-bearing AC and is pinned above.
    assert _fired_s8(sc.scan(str(proj), malware_db={_CARGO_BAD: {"1.2.3"}}), _CARGO_BAD)


def test_resolved_cargo_hostile_lockfile_degrades_no_raise(tmp_path):
    # malformed / non-TOML / non-dict-shaped Cargo.lock must degrade to {} (no resolved).
    for i, junk in enumerate(
        ("", "not toml = = =", "[[package]]\nname = 123\n",      # name not a str
         '[[package]]\nversion = "1.0"\n')                        # no name key
    ):
        root = tmp_path / f"rs_{i}"
        _write_cargo(root, f'{_CARGO_BAD} = "1.2.3"\n', lock=junk)
        got = sc._resolved_cargo(root)
        assert isinstance(got, dict)                    # == expected: a dict, never a raise
        assert _CARGO_BAD not in got                    # != wrong: garbage yields no pin


# =========================================================================== #
# Pipfile.lock — JSON (`default`/`develop` maps, versions like "==1.2.3") → `resolved`
#                in parse_pypi alongside the poetry/uv path (the ticket's "if trivial" item).
# =========================================================================== #
_PIP_BAD = "evil-pkg"


def _pipfile_lock(default: dict[str, str], develop: dict[str, str] | None = None) -> str:
    return json.dumps({
        "_meta": {"hash": {"sha256": "x"}},
        "default": {n: {"version": v} for n, v in default.items()},
        "develop": {n: {"version": v} for n, v in (develop or {}).items()},
    })


def _write_pipenv(project_dir: pathlib.Path, reqs: list[str],
                  lock: str | None = None) -> pathlib.Path:
    # a requirements.txt marker routes to parse_pypi; the Pipfile.lock supplies resolved.
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "requirements.txt").write_text("\n".join(reqs) + "\n")
    if lock is not None:
        (project_dir / "Pipfile.lock").write_text(lock)
    return project_dir


def test_parse_pypi_attaches_resolved_from_pipfile_lock(tmp_path):
    proj = _write_pipenv(
        tmp_path / "p", [f"{_PIP_BAD}>=1.0.0", "requests>=2.0"],
        lock=_pipfile_lock({_PIP_BAD: "==1.2.3"}, develop={"requests": "==2.31.0"}),
    )
    norm = sc.parse_pypi(str(proj))
    by = {d["name"]: d for d in norm["deps"]}
    # == expected: the Pipfile.lock `default`/`develop` version resolves (== stripped)
    assert by[_PIP_BAD]["resolved"] == "1.2.3"
    assert by["requests"]["resolved"] == "2.31.0"  # from the `develop` map
    # != wrong: resolved is the locked version, not the requirement range / the ==-prefixed form
    assert by[_PIP_BAD]["resolved"] != ">=1.0.0"
    assert by[_PIP_BAD]["resolved"] != "==1.2.3"


def test_pipfile_lock_resolved_flags_on_matching_db(tmp_path):
    proj = _write_pipenv(
        tmp_path / "p", [f"{_PIP_BAD}>=1.0.0"],
        lock=_pipfile_lock({_PIP_BAD: "==1.2.3"}),
    )
    # == expected: the resolved version specific-matches (the >= range alone would not)
    assert _fired_s8(sc.scan(str(proj), malware_db={_PIP_BAD: {"1.2.3"}}), _PIP_BAD)
    # != wrong: a non-matching db version does not flag
    assert not _fired_s8(sc.scan(str(proj), malware_db={_PIP_BAD: {"9.9.9"}}), _PIP_BAD)


def test_resolved_pipfile_hostile_lockfile_degrades_no_raise(tmp_path):
    # malformed / non-JSON / non-dict-shaped Pipfile.lock must degrade (no resolved), never raise.
    for i, junk in enumerate(
        ("", "not json {{{", "[1, 2, 3]",                         # not a JSON object
         '{"default": "not a map"}',                              # default not a dict
         '{"default": {"evil-pkg": "no version key"}}')           # entry not a dict
    ):
        root = tmp_path / f"p_{i}"
        _write_pipenv(root, [f"{_PIP_BAD}>=1.0.0"], lock=junk)
        norm = sc.parse_pypi(str(root))  # parse_pypi must never raise on a hostile lock
        by = {d["name"]: d for d in norm["deps"]}
        # == expected: a hostile Pipfile.lock leaves NO resolved key (degrade, not crash)
        assert "resolved" not in by[_PIP_BAD]
