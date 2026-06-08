#!/usr/bin/env bash
# Host helper to build + run the deps-scan floor in a SEALED container.
#
# The native `uv run pytest plugins/white-hacker/skills/deps-scan/scripts/tests` workflow is
# UNCHANGED and adds zero host risk (the floor is pure-stdlib, offline). This wrapper is the
# extra isolation lane for running the floor against UNTRUSTED manifests + a real OSSF malware
# snapshot, with NO path to the host: no network, read-only rootfs, all caps dropped, non-root.
set -euo pipefail

IMAGE="${WH_SANDBOX_IMAGE:-whitehacker/deps-scan-sandbox:local}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# Lockdown flags applied to EVERY run (Agents Rule of Two: untrusted input, never egress):
#   --network none           no network at all (no exfil, no fetch)
#   --read-only + tmpfs      immutable rootfs; only /tmp is writable (nosuid/nodev, capped)
#   --cap-drop ALL           drop every Linux capability
#   --security-opt …         no privilege escalation via setuid
#   --user 10001             non-root
#   --pids/--memory          bound a runaway/zip-bomb-style input
# shellcheck disable=SC2054  # commas below are inside tmpfs option values, not element separators
LOCKDOWN=(
  --rm
  --network none
  --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m
  --cap-drop ALL
  --security-opt no-new-privileges
  --user 10001:10001
  --pids-limit 256
  --memory 512m --memory-swap 512m
)

usage() { echo "usage: $(basename "$0") {build | test | scan <manifest-dir> [osv-snapshot-dir] | shell}"; exit 2; }

cmd="${1:-test}"
case "$cmd" in
  build)
    docker build -f "$HERE/Dockerfile" -t "$IMAGE" "$REPO"
    ;;
  test)
    # the offline deps-scan test suite (incl. the S8 smoke test) — sealed
    docker run "${LOCKDOWN[@]}" "$IMAGE"
    ;;
  scan)
    target="${2:-}"; [ -n "$target" ] || usage
    abs="$(cd "$target" && pwd)"
    snap="${3:-}"
    if [ -n "$snap" ]; then
      snapabs="$(cd "$snap" && pwd)"
      # S8 ACTIVE: load the (read-only) OSSF snapshot + scan the (read-only) manifest, network off
      docker run "${LOCKDOWN[@]}" \
        -v "$abs:/target:ro" -v "$snapabs:/db:ro" \
        --entrypoint python "$IMAGE" -c \
        'import json,supply_chain as sc,malware_db as m; print(json.dumps(sc.scan("/target", malware_db=m.load_malware_db("/db")), indent=2))'
    else
      # S8 degraded (no snapshot): floor still runs S1–S7
      docker run "${LOCKDOWN[@]}" \
        -v "$abs:/target:ro" \
        --entrypoint python "$IMAGE" /work/skills/deps-scan/scripts/supply_chain.py /target
    fi
    ;;
  shell)
    docker run "${LOCKDOWN[@]}" -it --entrypoint /bin/sh "$IMAGE"
    ;;
  *)
    usage
    ;;
esac
