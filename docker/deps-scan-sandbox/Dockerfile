# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Hardened sandbox for the white-hacker deps-scan supply-chain floor.
#
# The floor ingests UNTRUSTED package manifests + the OSSF malicious-packages
# snapshot. It is proven inert — pure Python stdlib (JSON parse + regex), NO install,
# NO exec, NO network. This image is DEFENSE-IN-DEPTH so that even a future regression
# or a hostile manifest cannot reach the host. Always run it with the lockdown flags in
# run.sh (--network none, --read-only, --cap-drop ALL, non-root). The native
# `uv run pytest` workflow is unchanged; this is an extra sealed lane.
#
# PIN the base image by digest before use (ADR-006 pin-and-verify):
#   docker buildx imagetools inspect python:3.13-slim --format '{{json .Manifest.Digest}}'
# then replace the tag below with  python:3.13-slim@sha256:<digest>.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.13-slim

# Test-only deps — the floor itself needs NONE (stdlib only). Pin in CI via a lock.
RUN pip install --no-cache-dir 'pytest~=8.3' 'jsonschema~=4.23' \
    && rm -rf /root/.cache /tmp/*

# Non-root runtime identity; no interactive login.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin sandbox

WORKDIR /work
# Copy ONLY the floor + its shared deps — never the working tree, secrets, .git, or the
# eval corpus. PRESERVE the `skills/<mod>/scripts` layout so the package conftest.py (which
# resolves _shared/sec-detect via `_here.parent.parent`) works unchanged. Build context is
# further trimmed by Dockerfile.dockerignore.
COPY plugins/white-hacker/skills/deps-scan/scripts   /work/skills/deps-scan/scripts
COPY plugins/white-hacker/skills/sec-detect/scripts  /work/skills/sec-detect/scripts
COPY plugins/white-hacker/skills/_shared/scripts     /work/skills/_shared/scripts
# reference/ dirs the floor + tests resolve via `__file__.parent.parent/reference`:
#   _shared/reference/finding-schema.json — validate_findings.load_schema() (NO fallback);
#   deps-scan/reference/ai-sdk-allowlist.json — full S4/S5 allowlist (else embedded fallback).
COPY plugins/white-hacker/skills/_shared/reference   /work/skills/_shared/reference
COPY plugins/white-hacker/skills/deps-scan/reference /work/skills/deps-scan/reference

# PYTHONPATH so the direct `scan` entrypoint (python supply_chain.py, no conftest) also
# resolves degradation/normalize_deps/malware_db/validate_findings/detect_tools.
ENV PYTHONPATH=/work/skills/_shared/scripts:/work/skills/sec-detect/scripts:/work/skills/deps-scan/scripts \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001

# Default: the OFFLINE supply-chain-floor + S8 test suite (incl. the S8 smoke test, wh-2v5).
# Two REPO-FIXTURE-bound tests are excluded — they scan committed demo projects under docs/research/
# via a `.git` repo-root walk, which the minimal sandbox image deliberately does not contain (they
# are gate regressions, not untrusted-input isolation; run them natively with `uv run … pytest`):
#   --ignore  test_normalize_deps.py  (the trusted-Trivy-report normalizer; docs/research/poc-trivy-sca)
#   --deselect test_demo_poc_scans_and_validates  (docs/research/poc-supply-chain)
ENTRYPOINT ["python", "-m", "pytest"]
# -p no:cacheprovider: the rootfs is --read-only (no writable cache dir) and the container is
# ephemeral (--rm), so disable pytest's cache to keep the run warning-free.
CMD ["/work/skills/deps-scan/scripts/tests", "-q", "-p", "no:cacheprovider", \
     "--ignore=/work/skills/deps-scan/scripts/tests/test_normalize_deps.py", \
     "-k", "not test_demo_poc_scans_and_validates"]
