"""wh-0c2 — Gradle floor adapter (build.gradle/.kts + libs.versions.toml + gradle.lockfile).

A Gradle-only Java/Android project previously got ZERO floor dep-extraction: `_DISPATCH`
mapped `java` to pom.xml/`parse_maven` only (supply_chain.py:840-848), so S1–S8 (incl. the
known-compromised watchlist) were blind for the majority of modern Java + all Android.

`parse_gradle` is the floor adapter — REGEX extraction over `build.gradle`/`.kts` lines,
NOT a Groovy/Kotlin parser (the `_GEM_RE` precedent, supply_chain.py:529 / parse_gem
:551-594). The dep `name` is the `group:artifact` coordinate — the SAME OSV Maven
ecosystem naming `parse_maven` emits (supply_chain.py:820), so S8 / the watchlist match the
same way for both Java build systems. The OPTIONAL `resolved` key (the strongest signal,
mirrors `_resolved_gem` supply_chain.py:536-548) carries the `gradle.lockfile` version.

Every invariant is driven THROUGH `scan()` / the real adapter (the public entry — same
discipline as test_s8_version_aware_ecosystems.py), NEUTRALIZED fixtures only (tmp_path).

Rule 9 (tests verify intent): every invariant pins BOTH `== expected` AND `!= wrong`.

Run: `nice -n 10 uv run --project plugins/white-hacker/skills/deps-scan/scripts \
    --with jsonschema --with pytest pytest \
    plugins/white-hacker/skills/deps-scan/scripts/tests -q`
"""
from __future__ import annotations

import supply_chain as sc
import validate_findings as vf

# A groupId:artifactId watchlist coordinate (OSV-Maven naming — what parse_gradle emits).
_BAD = "org.evil:evil-lib"


def _scenarios(doc: dict) -> list[str]:
    return [f["exploit_scenario"] for f in doc["findings"]]


def _fired_s8(doc: dict, name: str) -> bool:
    return any(f"{name} @" in s and "S8" in s for s in _scenarios(doc))


def _by_name(norm: dict) -> dict[str, dict]:
    return {d["name"]: d for d in norm["deps"]}


# =========================================================================== #
# AC1 — string-coordinate, map-form, and .kts declarations extract
#       name="group:artifact" (==/!= pairs).
# =========================================================================== #
def test_parse_gradle_string_coordinate_form(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "plugins { id 'java' }\n"
        "repositories { mavenCentral() }\n"
        "dependencies {\n"
        "    implementation 'org.apache.commons:commons-lang3:3.12.0'\n"
        "    api \"com.google.guava:guava:31.1-jre\"\n"
        "    testImplementation 'junit:junit:4.13.2'\n"
        "    compileOnly 'org.projectlombok:lombok:1.18.24'\n"
        "    runtimeOnly 'mysql:mysql-connector-java:8.0.30'\n"
        "}\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # == expected: the dep name is the FULL group:artifact coordinate (OSV-Maven naming)
    assert "org.apache.commons:commons-lang3" in by
    assert by["org.apache.commons:commons-lang3"]["spec"] == "3.12.0"
    assert by["org.apache.commons:commons-lang3"]["source_type"] == "registry"
    # != wrong: NOT the bare artifact id alone (that would miss the OSV-Maven ecosystem key)
    assert "commons-lang3" not in by
    assert by["org.apache.commons:commons-lang3"]["name"] != "commons-lang3"
    # all five configurations are recognized (double- AND single-quoted)
    assert "com.google.guava:guava" in by
    assert by["com.google.guava:guava"]["spec"] == "31.1-jre"
    assert "junit:junit" in by
    assert "org.projectlombok:lombok" in by
    assert "mysql:mysql-connector-java" in by


def test_parse_gradle_map_form(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation group: 'org.apache.commons', name: 'commons-lang3',"
        " version: '3.12.0'\n"
        "    api group: \"com.google.guava\", name: \"guava\", version: \"31.1-jre\"\n"
        "}\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # == expected: the map form reconstructs the SAME group:artifact coordinate
    assert "org.apache.commons:commons-lang3" in by
    assert by["org.apache.commons:commons-lang3"]["spec"] == "3.12.0"
    assert "com.google.guava:guava" in by
    assert by["com.google.guava:guava"]["spec"] == "31.1-jre"
    # != wrong: NOT only the name= token, NOT the group= token alone
    assert "commons-lang3" not in by
    assert "org.apache.commons" not in by


def test_parse_gradle_kts_string_coordinate_form(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle.kts").write_text(
        "plugins { java }\n"
        "dependencies {\n"
        '    implementation("org.apache.commons:commons-lang3:3.12.0")\n'
        '    testImplementation("junit:junit:4.13.2")\n'
        "}\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # == expected: the Kotlin-DSL function-call form extracts the same coordinate
    assert "org.apache.commons:commons-lang3" in by
    assert by["org.apache.commons:commons-lang3"]["spec"] == "3.12.0"
    assert "junit:junit" in by
    # != wrong: not the bare artifact
    assert "commons-lang3" not in by
    assert by["org.apache.commons:commons-lang3"]["name"] != "commons-lang3"


def test_gradle_dispatch_through_scan_string_coord(tmp_path):
    # the public entry must DISPATCH a build.gradle project to parse_gradle (java lang).
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        f"    implementation '{_BAD}:1.2.3'\n"
        "}\n"
    )
    doc = sc.scan(str(proj), malware_db={_BAD: {"1.2.3"}})
    # == expected: an exact-pinned string coordinate is version-aware S8-matched via scan()
    assert _fired_s8(doc, _BAD) is True
    # != wrong: a non-matching db version does not flag the exact pin
    assert _fired_s8(sc.scan(str(proj), malware_db={_BAD: {"9.9.9"}}), _BAD) is False
    # the document is schema-valid (floor invariant)
    assert vf.validate(doc) == []


def test_gradle_dispatch_through_scan_kts(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle.kts").write_text(
        "dependencies {\n"
        f'    implementation("{_BAD}:1.2.3")\n'
        "}\n"
    )
    doc = sc.scan(str(proj), malware_db={_BAD: {"1.2.3"}})
    assert _fired_s8(doc, _BAD) is True          # == expected: .kts dispatches too
    assert _fired_s8(sc.scan(str(proj), malware_db={_BAD: {"9.9.9"}}), _BAD) is False  # != wrong


# --------------------------------------------------------------------------- #
# QA Finding 1 (regression) — a URL-scheme local file (`file:/...`) must NOT be
# emitted as a phantom `registry` dep (which would wrongly expose it to S3). A
# `file:` coordinate is a local artifact (source_type 'file', S2-excluded); an
# `http:`/`https:` flat-dir URL is a non-registry remote and must not be 'registry'.
# --------------------------------------------------------------------------- #
def test_gradle_file_scheme_coord_not_registry(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'file:/path/to/lib.jar'\n"      # a local flat-dir artifact
        "    implementation 'org.apache.commons:commons-lang3:3.12.0'\n"  # a real coord
        "}\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # != wrong: the file: coordinate is NEVER a phantom 'registry' dep (the QA bug). It is
    # either dropped entirely OR classified as a local 'file' source (S2-excluded).
    file_dep = by.get("file:/path/to/lib.jar")
    assert file_dep is None or file_dep["source_type"] != "registry"
    if file_dep is not None:
        assert file_dep["source_type"] == "file"
    # == expected: a genuine group:artifact coordinate IS still 'registry' (pin both ways)
    assert by["org.apache.commons:commons-lang3"]["source_type"] == "registry"
    # a file: artifact, being non-registry, must not be S8-watchlistable as a registry dep:
    # scan() over the same tree degrades to a schema-valid document regardless.
    assert vf.validate(sc.scan(str(proj))) == []


def test_gradle_file_double_slash_scheme_not_registry(tmp_path):
    # `file://host/lib.jar` is comment-stripped at the first `//` to `... 'file:` (the
    # existing best-effort `//` line-comment strip), so it never completes as a coordinate
    # and is dropped — the load-bearing invariant is the SAME: no phantom 'registry' dep.
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'file://host/lib.jar'\n"
        "}\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # != wrong: NEITHER the full URL NOR the truncated `file:` head is a 'registry' dep
    for nm, d in by.items():
        assert d["source_type"] != "registry", f"{nm} wrongly registry"


# =========================================================================== #
# AC2 — a known-bad coordinate in gradle.lockfile flags S8 at the LOCKED version;
#       a safe locked version does not (wh-4k9 version-aware semantics).
# =========================================================================== #
def test_gradle_lockfile_resolved_attaches_locked_version(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    # the build script carries a RANGE (unresolvable on its own); the lockfile pins it.
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        f"    implementation '{_BAD}:+'\n"
        "}\n"
    )
    (proj / "gradle.lockfile").write_text(
        "# This is a Gradle generated file for dependency locking.\n"
        "# Manual edits can break the build and are not advised.\n"
        "# This file is expected to be part of source control.\n"
        f"{_BAD}:1.2.3=classpath,compileClasspath,runtimeClasspath\n"
        "empty=annotationProcessor\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # == expected: the lockfile version attaches as `resolved` (strongest signal)
    assert by[_BAD]["resolved"] == "1.2.3"
    assert sc.parse_gradle(str(proj)).get("lockfile_present") is True
    # != wrong: resolved is the LOCKED version, not the range spec / None
    assert by[_BAD]["resolved"] != "+"


def test_gradle_lockfile_known_bad_version_flags_s8(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        f"    implementation '{_BAD}:+'\n"      # a range — only the lockfile resolves it
        "}\n"
    )
    (proj / "gradle.lockfile").write_text(
        f"{_BAD}:1.2.3=classpath,runtimeClasspath\n"
    )
    # == expected: the locked bad version specific-matches the db → S8 fires
    assert _fired_s8(sc.scan(str(proj), malware_db={_BAD: {"1.2.3"}}), _BAD) is True


def test_gradle_lockfile_safe_locked_version_does_not_flag(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        f"    implementation '{_BAD}:+'\n"
        "}\n"
    )
    (proj / "gradle.lockfile").write_text(
        f"{_BAD}:4.5.6=classpath,runtimeClasspath\n"    # a DIFFERENT (safe) locked version
    )
    # != wrong: the db lists only 1.2.3 as bad; the locked 4.5.6 must NOT flag
    assert _fired_s8(sc.scan(str(proj), malware_db={_BAD: {"1.2.3"}}), _BAD) is False
    # == expected: but the SAME safe-locked dep DOES flag when the db marks 4.5.6 bad
    assert _fired_s8(sc.scan(str(proj), malware_db={_BAD: {"4.5.6"}}), _BAD) is True


# =========================================================================== #
# AC3 — a catalog-managed version resolves when the catalog defines it;
#       unresolvable → wildcard-only.
# =========================================================================== #
def test_gradle_catalog_version_resolves(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    gradle_dir = proj / "gradle"
    gradle_dir.mkdir()
    (gradle_dir / "libs.versions.toml").write_text(
        "[versions]\n"
        'commons = "3.12.0"\n'
        "\n"
        "[libraries]\n"
        'commons-lang3 = { module = "org.apache.commons:commons-lang3",'
        ' version.ref = "commons" }\n'
    )
    (proj / "build.gradle.kts").write_text(
        "dependencies {\n"
        "    implementation(libs.commons.lang3)\n"
        "}\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # == expected: libs.commons.lang3 resolves through the catalog to the module + version
    assert "org.apache.commons:commons-lang3" in by
    assert by["org.apache.commons:commons-lang3"]["spec"] == "3.12.0"
    # != wrong: the dep name is the resolved module, NOT the raw `libs.commons.lang3` alias
    assert "libs.commons.lang3" not in by
    assert by["org.apache.commons:commons-lang3"]["spec"] != "libs.commons.lang3"


def test_gradle_catalog_version_resolves_flags_s8(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    gradle_dir = proj / "gradle"
    gradle_dir.mkdir()
    (gradle_dir / "libs.versions.toml").write_text(
        "[versions]\n"
        'evil = "1.2.3"\n'
        "[libraries]\n"
        'evil-lib = { module = "org.evil:evil-lib", version.ref = "evil" }\n'
    )
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation libs.evil.lib\n"
        "}\n"
    )
    # == expected: the catalog-resolved exact version specific-matches the db → S8 fires
    assert _fired_s8(sc.scan(str(proj), malware_db={_BAD: {"1.2.3"}}), _BAD) is True
    # != wrong: a non-matching version does not flag the catalog-resolved dep
    assert _fired_s8(sc.scan(str(proj), malware_db={_BAD: {"9.9.9"}}), _BAD) is False


def test_gradle_catalog_unresolvable_alias_stays_wildcard_only(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    # NO gradle/libs.versions.toml on disk → the alias cannot be resolved → wildcard-only.
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation libs.evil.lib\n"
        "}\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # == expected: an unresolvable alias is recorded but carries NO resolved key + wildcard spec
    assert "resolved" not in by.get("libs.evil.lib", {})
    assert by.get("libs.evil.lib", {}).get("spec") == "*"
    # a "*" whole-package db entry flags; a specific-version entry does NOT (wh-4k9)
    db_alias = {"libs.evil.lib": {"*"}}
    assert _fired_s8(sc.scan(str(proj), malware_db=db_alias), "libs.evil.lib") is True   # == expected
    assert not _fired_s8(
        sc.scan(str(proj), malware_db={"libs.evil.lib": {"1.2.3"}}), "libs.evil.lib"
    )  # != wrong


# =========================================================================== #
# AC4 — build.gradle/.kts appear in script_files (S6/S7 coverage);
#       no lifecycle false-claims.
# =========================================================================== #
def test_gradle_build_script_in_script_files(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies { implementation 'org.apache.commons:commons-lang3:3.12.0' }\n"
    )
    norm = sc.parse_gradle(str(proj))
    # == expected: build.gradle is surfaced for the S6/S7 scan (arbitrary build-time code)
    assert any(p.endswith("build.gradle") for p in norm["script_files"])
    # != wrong: it is NOT claimed as an install lifecycle hook (S1 false-claim)
    assert norm["lifecycle_scripts"] == {}
    assert norm["lifecycle_scripts"] != {"build.gradle": "gradle build"}


def test_gradle_kts_build_script_in_script_files(tmp_path):
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle.kts").write_text(
        'dependencies { implementation("org.apache.commons:commons-lang3:3.12.0") }\n'
    )
    norm = sc.parse_gradle(str(proj))
    assert any(p.endswith("build.gradle.kts") for p in norm["script_files"])  # == expected
    assert norm["lifecycle_scripts"] == {}                                    # != wrong


def test_gradle_dangerous_build_script_fires_s6(tmp_path):
    # build.gradle is arbitrary code → an INERT body carrying ≥2 dangerous-API trigger
    # strings (commented, non-functional) must surface as an S6 project-level finding.
    proj = tmp_path / "gradle"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies { implementation 'org.apache.commons:commons-lang3:3.12.0' }\n"
        "// SAMPLE (inert) — detection test data only, does nothing.\n"
        "// would call child_process to spawn a shell and eval( ) a remote string\n"
        "// would fetch( ) the payload and read ~/.ssh then Buffer.from(x,'base64')\n"
    )
    doc = sc.scan(str(proj))
    # == expected: the dangerous build script surfaces an S6 candidate
    assert any("S6" in s for s in _scenarios(doc))
    # != wrong: a benign build script does NOT (regression control below proves the pair)
    benign = tmp_path / "benign"
    benign.mkdir()
    (benign / "build.gradle").write_text(
        "dependencies { implementation 'org.apache.commons:commons-lang3:3.12.0' }\n"
    )
    assert not any("S6" in s for s in _scenarios(sc.scan(str(benign))))


# =========================================================================== #
# AC5 — malformed/hostile gradle files never raise (degrade to empty struct).
# =========================================================================== #
def test_gradle_missing_manifest_degrades(tmp_path):
    proj = tmp_path / "empty"
    proj.mkdir()
    # No build.gradle at all → parse_gradle returns an empty-but-valid struct, never raises.
    norm = sc.parse_gradle(str(proj))
    assert norm["deps"] == []
    assert norm["lifecycle_scripts"] == {}
    assert norm["lockfile_present"] is False
    assert norm["script_files"] == []
    # != wrong: it is a dict, not None / not an exception
    assert norm != {}
    assert isinstance(norm, dict)


def test_gradle_garbage_manifest_never_raises(tmp_path):
    proj = tmp_path / "garbage"
    proj.mkdir()
    # hostile / odd content: unbalanced braces, binary noise, a half-written declaration.
    (proj / "build.gradle").write_text(
        "dependencies {{{ implementation '::::' \x00\x01\xef\n"
        "    implementation group: , name: , version:\n"
        "    api 'no-colon-here'\n"
        "}}}}\n"
    )
    (proj / "gradle.lockfile").write_text("=garbage\n:::\n\x00\n")
    gradle_dir = proj / "gradle"
    gradle_dir.mkdir()
    (gradle_dir / "libs.versions.toml").write_text("this is not = valid toml [[[\n")
    # == expected: a hostile manifest degrades to a valid struct, NEVER raises
    norm = sc.parse_gradle(str(proj))
    assert isinstance(norm, dict)
    assert isinstance(norm["deps"], list)
    # scan() over the same hostile tree also degrades to a schema-valid document
    doc = sc.scan(str(proj))
    assert vf.validate(doc) == []
    # != wrong: a single bare token (`api 'no-colon-here'`, no `:`) is DROPPED, never
    # emitted as a phantom dep — so it must not appear as a name in the struct.
    by = _by_name(norm)
    assert "no-colon-here" not in by


def test_gradle_emits_only_colon_coordinates(tmp_path):
    # The coordinate-emission invariant proven NON-vacuously (TL Issue 2): a fixture that
    # MIXES a valid `group:artifact:version` with a bare-token junk line yields ≥1 dep, and
    # EVERY emitted dep name is a real `group:artifact` coordinate — the junk is dropped.
    proj = tmp_path / "mixed"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'org.apache.commons:commons-lang3:3.12.0'\n"  # valid coord
        "    api 'no-colon-here'\n"                                       # bare token → drop
        "}\n"
    )
    by = _by_name(sc.parse_gradle(str(proj)))
    # == expected: at least one dep IS emitted (so the next assertion is not vacuous)
    assert len(by) >= 1
    assert "org.apache.commons:commons-lang3" in by
    # every emitted coordinate carries a `:` group:artifact separator — junk is excluded
    assert all(":" in name for name in by)
    # != wrong: the bare junk token is NOT among the emitted names
    assert "no-colon-here" not in by


def test_gradle_unicode_coordinate_does_not_crash(tmp_path):
    proj = tmp_path / "uni"
    proj.mkdir()
    (proj / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'org.exаmple:lib:1.0.0'\n"   # cyrillic 'а' homoglyph
        "}\n",
        encoding="utf-8",
    )
    doc = sc.scan(str(proj))
    assert vf.validate(doc) == []          # == expected: schema-valid even with homoglyphs
    assert isinstance(doc["findings"], list)  # != wrong: not an exception


# =========================================================================== #
# Verification — a real Android-style module (catalog + .kts) proves the floor
# produces value end-to-end (ADR-003: the floor must produce value).
# =========================================================================== #
def test_android_style_module_catalog_plus_kts_floor_value(tmp_path):
    proj = tmp_path / "android"
    proj.mkdir()
    gradle_dir = proj / "gradle"
    gradle_dir.mkdir()
    (gradle_dir / "libs.versions.toml").write_text(
        "[versions]\n"
        'core-ktx = "1.9.0"\n'
        'evil = "1.2.3"\n'
        "\n"
        "[libraries]\n"
        'androidx-core-ktx = { module = "androidx.core:core-ktx",'
        ' version.ref = "core-ktx" }\n'
        'evil-lib = { group = "org.evil", name = "evil-lib", version.ref = "evil" }\n'
    )
    (proj / "build.gradle.kts").write_text(
        "plugins {\n"
        '    id("com.android.application")\n'
        "}\n"
        "dependencies {\n"
        "    implementation(libs.androidx.core.ktx)\n"
        "    implementation(libs.evil.lib)\n"
        '    testImplementation("junit:junit:4.13.2")\n'
        "}\n"
    )
    norm = sc.parse_gradle(str(proj))
    by = _by_name(norm)
    # == expected: the floor produces real deps from a catalog-driven Android .kts module
    assert "androidx.core:core-ktx" in by
    assert by["androidx.core:core-ktx"]["spec"] == "1.9.0"
    assert "org.evil:evil-lib" in by
    assert by["org.evil:evil-lib"]["spec"] == "1.2.3"
    assert "junit:junit" in by
    # the .kts build script is on the S6/S7 surface
    assert any(p.endswith("build.gradle.kts") for p in norm["script_files"])
    # != wrong: the aliases are resolved to modules, not left as `libs.*`
    assert "libs.androidx.core.ktx" not in by
    assert "libs.evil.lib" not in by
    # end-to-end through scan(): the watchlisted catalog-resolved evil-lib flags S8
    doc = sc.scan(str(proj), malware_db={_BAD: {"1.2.3"}})
    assert _fired_s8(doc, _BAD) is True
    assert vf.validate(doc) == []
