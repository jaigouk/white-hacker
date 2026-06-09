#!/usr/bin/env bash
# ONE-TIME, network-ON, THROWAWAY container that clones + PINS the OSSF malicious-packages
# snapshot into a host dir you choose. This is DELIBERATELY separate from analysis:
#   - fetch  (this script): has network, NO untrusted analysis, just git over HTTPS
#   - analyze (run.sh scan): has the untrusted data, NO network (--network none)
# That split is the Agents Rule of Two — never hold untrusted input + egress at once.
#
# The OSSF repo is OSV *metadata* (JSON), not executable malware; nothing is installed or run.
# Only the osv/ tree is copied out (the part load_malware_db reads).
set -euo pipefail

PIN="${1:-}"; DEST="${2:-}"
[ -n "$PIN" ] && [ -n "$DEST" ] || { echo "usage: $(basename "$0") <commit-sha> <dest-dir>"; exit 2; }
# Input hygiene: $PIN is interpolated into the in-container script — require a bare 40-hex SHA
# so it cannot break out of the quoted git argument (no injection via a crafted "pin").
[[ "$PIN" =~ ^[0-9a-f]{40}$ ]] || { echo "error: <commit-sha> must be a 40-char lowercase hex SHA"; exit 2; }

mkdir -p "$DEST"; abs="$(cd "$DEST" && pwd)"

# Even this network-ON container is locked down: non-root (output owned by the operator, not root),
# read-only rootfs (only /out mount + a tmpfs HOME are writable), all caps dropped, bounded. PIN
# alpine/git by digest before real use (ADR-006):
#   docker buildx imagetools inspect alpine/git --format '{{json .Manifest.Digest}}'
docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 1g --memory-swap 1g \
  -v "$abs:/out" \
  --entrypoint sh \
  alpine/git \
  -ceu '
    rm -rf /out/.mp
    git clone --filter=blob:none "https://github.com/ossf/malicious-packages" /out/.mp
    cd /out/.mp
    git checkout "'"$PIN"'"
    test "$(git rev-parse HEAD)" = "'"$PIN"'" || { echo "PIN MISMATCH"; exit 1; }
    rm -rf /out/osv && cp -a /out/.mp/osv /out/osv
    rm -rf /out/.mp
    echo "'"$PIN"'" > /out/PINNED_SHA
  '
echo "OSSF osv/ pinned at $PIN -> $abs/osv"
echo "analyze (network-off): ./run.sh scan <manifest-dir> $abs/osv"
