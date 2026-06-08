# deps-scan sandbox — run the supply-chain floor against untrusted data, sealed

A dedicated, **opt-in** Docker lane for exercising the `deps-scan` supply-chain floor (incl. the
**S8** known-bad signal) against **untrusted package manifests** and the real
[`ossf/malicious-packages`](https://github.com/ossf/malicious-packages) snapshot — **without any
path to your host**.

## You do NOT need this for the normal test workflow

The floor is **inert by construction** — pure Python stdlib (JSON parse + regex), **no install, no
exec, no network, no subprocess**. The S8 smoke test (`test_s8_offline_smoke.py`) uses **synthetic**
package names and writes only to a temp dir. So the native flow stays fast and safe:

```bash
uv run --project plugins/white-hacker/skills/deps-scan/scripts --with pytest \
  pytest plugins/white-hacker/skills/deps-scan/scripts/tests -q     # 0 host risk
```

This sandbox is **defense-in-depth** for the parts that *are* worth isolating: cloning the real OSSF
repo, or pointing the floor at third-party malicious-package datasets. It changes nothing about the
native workflow.

## Threat model & hardening

The floor is the component that ingests untrusted input, so we run it under the **Agents Rule of
Two** — never hold untrusted input **and** egress at once:

| Control | Flag (`run.sh`) | Why |
|---|---|---|
| No network | `--network none` | no exfil, no fetch — untrusted data can't phone home |
| Immutable rootfs | `--read-only` + `--tmpfs /tmp` (nosuid,nodev,64m) | nothing persists; only capped scratch |
| No capabilities | `--cap-drop ALL` | no raw sockets, no mount, no ptrace |
| No privilege escalation | `--security-opt no-new-privileges` | setuid binaries can't elevate |
| Non-root | `--user 10001:10001` | container runs unprivileged |
| Bounded | `--pids-limit 256`, `--memory 512m` | a hostile/zip-bomb input can't exhaust the host |
| Read-only inputs | `-v <dir>:/target:ro`, `…:/db:ro` | the floor reads; it can never write your files |

The base image **must be pinned by digest** (ADR-006) before real use — see the `PIN` note in the
`Dockerfile` and `fetch-snapshot.sh` (both carry the `imagetools inspect` command). They ship on
floating tags so this repo stays buildable offline; pin `python:3.13-slim` and `alpine/git` by
`@sha256:…` before you trust the output.

## Usage

```bash
cd docker/deps-scan-sandbox
./run.sh build                       # build the image (pin the base digest first)
./run.sh test                        # the offline deps-scan test suite (incl. S8 smoke), sealed
./run.sh scan /path/to/project       # run the floor on a manifest dir (S8 degraded — no DB)
./run.sh scan /path/to/project /db/osv   # S8 ACTIVE against a pinned OSSF snapshot (both read-only)
./run.sh shell                       # poke around inside (network-off, read-only)
```

## Testing S8 against the real OSSF snapshot (wh-8qw)

The fetch (network) and the analysis (no network) are **separate steps** on purpose:

```bash
# 1) fetch + PIN once, in a throwaway network-on container (writes only the osv/ tree out)
./fetch-snapshot.sh 174a862b3aaa0fa690db4a57a9390d849841d984 ~/ossf-malware-db

# 2) analyze with the snapshot, network OFF, everything read-only
./run.sh scan /path/to/project ~/ossf-malware-db/osv
#   -> a package whose name is in the snapshot fires a HIGH S8 supply-chain finding
```

⚠ **Third-party malware *datasets*** (DataDog, pypi_malregistry) contain **live malware samples** —
only ever extract package **names/metadata** for fixtures; never install or execute them, and never
do so outside this sandbox.

## What `run.sh test` runs (and what it doesn't)

The sealed lane runs the **self-contained** supply-chain-floor + S8 suite (incl. the S8 smoke test).
Two tests are excluded because they scan committed demo projects under `docs/research/` via a `.git`
repo-root walk — they are gate regressions, not untrusted-input isolation, and the minimal image
deliberately omits the repo:

- `test_normalize_deps.py` (trusted-Trivy-report normalizer — `docs/research/poc-trivy-sca`) — `--ignore`d
- `test_demo_poc_scans_and_validates` (`docs/research/poc-supply-chain`) — `-k "not …"`

Run those two natively (`uv run --project … pytest`), where the repo + fixtures exist.

## Status / caveats

- Authored + adversarially reviewed (5-lens hardening pass). The default test lane was verified GREEN
  (**67 passed, 1 deselected**) by replicating the exact in-image file layout (only the COPYed dirs,
  `.venv` excluded) on Python 3.13 with the container's `PYTHONPATH` + `CMD`. **Not** `docker build`'d
  here (no daemon on the authoring host) — confirm with `./run.sh build && ./run.sh test`.
- **Pin the base image + `alpine/git` by digest** before real use (ADR-006) — the `Dockerfile` and
  `fetch-snapshot.sh` carry the exact `imagetools inspect` commands.
- BuildKit reads `Dockerfile.dockerignore` (co-located) because the build context is the repo root.
