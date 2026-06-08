# Spike-10: Linux kernel security — scope decision for white-hacker (2026-06)

> **Defensive-security context.** white-hacker is an authorized white-hat code-review agent. This
> spike is a **scope decision** — it concludes white-hacker should *not* audit kernel code — and
> references kernel-security threat-intel only to draw that boundary. No exploit code or attack
> methodology; CVE/advisory ids are cited for triage, and any forward-dated id should be spot-checked
> against its linked source before being relied on.

**Status:** RESOLVED
**Date:** 2026-06-08
**Confidence:** HIGH (kernel.org CVE policy + Google/OpenSSF/KSPP + arXiv sandbox-escape evidence
verified against primary sources; the scope boundary is our reasoned design call, consistent with
ADR-003/007/015 and Rule 5).
**Author:** white-hacker agent
**Related:** `sec-kb-refresh` (threat feeds — the kernel-LPE intel lives in researcher memory
`kernel-threat-landscape-2026`, NOT the app-review path); ADR-007 (static-analysis-only +
sandboxed PoC execution-safety); ADR-003 (graceful degradation); ADR-015 (capability layer, no
single-tool coupling); `sec-deps-scan` / SCA capability (module + DKMS supply-chain).

---

## Question

white-hacker is a code-review agent for **application** repos — TypeScript / Go / Python / Java
backends, frontends, and AI frameworks. It is **not** a kernel auditor. The 2026 Linux-kernel
security landscape is loud (a wave of LPE primitives, kernel.org-as-CNA CVE volume, eBPF verifier
bugs, AI-assisted discovery). The temptation is to "add kernel awareness." Resolve, decisively:

1. **What is the 2024–2026 kernel-security landscape**, and what about it is structurally relevant
   to an app-repo reviewer vs. just background noise? (kernel.org becoming a CVE CNA Feb-2024 and
   the resulting volume/triage problem; syzkaller/syzbot continuous fuzzing; hardening — KASLR,
   CFI/kCFI, lockdown, SELinux/AppArmor, Rust-for-Linux; the eBPF verifier surface.)

2. **Where does kernel security legitimately INTERSECT white-hacker's job?**
   (a) repos shipping **kernel-adjacent code** — eBPF programs (cilium/ebpf, libbpf, bpftrace),
   kernel modules, device drivers, raw syscalls;
   (b) **container-escape / privilege-boundary** concerns that tie to our own
   sandbox/execution-safety ADRs (ADR-007) when the agent runs untrusted or agent-generated code;
   (c) **supply-chain** of kernel modules / DKMS (our SCA capability).

3. **Where is it explicitly OUT OF SCOPE?** Should white-hacker audit kernel C for memory-safety
   bugs? (Argue from Rule 5 — "model only for judgment" — and our FP discipline.)

4. **Concrete recommendation:** does white-hacker add any kernel-aware **detection capability**?
   Or at most a small **awareness signal** (elevated-trust-boundary flag + pointer to specialist
   tools) when a reviewed repo contains eBPF / kernel-module / privileged-container code?

### Out of scope (this spike)
- Implementing any flag/signal (follow-up tickets in the Decision).
- Re-deriving the kernel-LPE intel itself (frozen in researcher memory `kernel-threat-landscape-2026`;
  that snapshot is **KB-refresh / threat-intel** input, a different arm than app review).

---

## Constraints on evidence
- Primary sources for policy/landscape: **kernel.org CVE docs**, **OpenSSF**, **KSPP**,
  **google/security-research** advisories, **syzkaller** docs, peer-reviewed / arXiv for
  sandbox-escape capability claims. Date every citation; trend claims use 2025–2026 sources.
- Keep the two arms distinct: **app-review** (this spike's subject — what white-hacker scans in a
  user's repo) vs. **threat-intel/KB-refresh** (the kernel-LPE wave, which the KB *may* ingest as
  background "new ways to hack" but which is NOT a per-repo detector).

---

## Findings

### F1 — The 2024–2026 landscape: high volume, low per-CVE signal, NOT an app-repo input
kernel.org became a **CVE CNA in mid-February 2024**; **any** commit that fixes a potential
security issue gets a CVE auto-assigned during the stable-release process. The official policy is
explicit that this is *deliberately* over-inclusive: *"almost any bug might be exploitable … the
possibility of exploitation is often not evident when the bug is fixed. Because of this, the CVE
assignment team is overly cautious and assign CVE numbers to any bugfix that they identify"* and
*"large numbers of assigned CVEs are not relevant for their systems"* (kernel.org CVE docs,
fetched 2026-06-08). Result: **4,325 kernel CVEs in 2024 (10.81% of all CVEs), 300+/week during
merge windows**, swamping NVD — which on **2026-04-15** formally moved to a triage model,
reclassifying ~29,000 backlog CVEs as "Not Scheduled" and enriching only the ~15–20% intersecting
KEV / federal / EO-14028 critical software (The New Stack; stingrai vuln-stats 2026, both fetched
2026-06-08). **Takeaway for us:** kernel CVEs are a *host/distro-patching* signal, not a
*source-code-of-an-app-repo* signal. white-hacker reviews application source; it does not own the
host kernel of the machine it runs on, and a kernel-CVE feed has no per-line mapping into a TS/Go/
Python/Java diff. This is firmly **threat-intel**, routed to `sec-kb-refresh` background at most.

### F2 — Kernel bug-finding is a specialist, dynamic discipline — the opposite of our method
The kernel's own defenses are **dynamic + specialist**, not LLM-static-review:
- **syzkaller/syzbot** = unsupervised coverage-guided **fuzzing** on ~25 instances / ~150–200 VMs,
  ~4,000 bugs reported and ~3,000 fixed; 2026 trend adds **LLM-assisted reproducer/patch repair**
  (syzkaller docs + LPC retrospective, fetched 2026-06-08; LLM-assist corroborated in researcher
  memory `kernel-threat-landscape-2026`).
- **eBPF verifier bugs** (e.g. **CVE-2026-43009**, disclosed 2026-05-01, fixed 6.19.12; same
  *class* as Google's earlier register-limit-tracking advisory **GHSA-hfqc-63c7-rj9f /
  CVE-2024-41003**) are found by **modified coverage-guided fuzzers (Buzzer)** finding invariant
  violations ("min > max" in register state), not by reading source (Google security-research
  advisory + Invicti + windowsnews, fetched 2026-06-08). The verifier *is itself* an in-kernel
  **static** analyzer — and even purpose-built kernel static analysis is repeatedly defeated by
  runtime divergence. An app-review LLM has **no plausible edge** here.
- **Hardening** (KASLR, **kCFI** since v6.1, lockdown LSM, SELinux `neveraudit`, **AppArmor AF_UNIX
  mediation mainlined in 6.17**, **Rust-for-Linux** drivers now in mainline eliminating UAF/OOB by
  construction) is **build-config + LSM-policy** work on the *kernel*, measured by tools like
  `kernel-hardening-checker` / KSPP recommended settings (ARMO 6.17 writeup, KSPP, kernel-hardening-
  checker repo, fetched 2026-06-08). None of this is an application-source-review task.
**Conclusion:** kernel memory-safety auditing is fuzzing + specialist-static-analyzer territory.
It collides head-on with **Rule 5** (model only for judgment; deterministic/specialist work stays
out of the LLM) and with our FP discipline — a HIGH-recall LLM pass over kernel C would generate
exactly the unfalsifiable noise the project is built to avoid.

### F3 — Where it DOES intersect (a): kernel-ADJACENT code in app repos → trust-boundary signal
App repos *do* sometimes ship kernel-adjacent code, and **here the relevant unit is the trust
boundary, not the kernel bug**:
- **eBPF in userspace projects** — `github.com/cilium/ebpf` (Go), libbpf+CO-RE, ebpf-go, bpftrace,
  Falco/Pixie-style tooling (ebpf.io applications; cilium/ebpf pkg.go.dev, fetched 2026-06-08).
  These load programs that run **in-kernel with elevated capability** (`CAP_BPF`/`CAP_SYS_ADMIN`).
  white-hacker can't and shouldn't verify the eBPF bytecode is verifier-safe — but it **can** note,
  as a code reviewer already does for any privileged surface, that this file crosses into a
  kernel-execution trust boundary: which capabilities are requested, whether program loading is
  gated by untrusted input, whether maps are world-readable. That is **ordinary
  privilege/authorization review** of the *userspace* code, which is squarely in scope — not kernel
  auditing.
- **Kernel modules / drivers / raw syscalls** in an otherwise-app repo — same framing: flag the
  elevated boundary, point at the right specialist, do **not** attempt memory-safety verdicts.

### F4 — Where it DOES intersect (b): container escape ↔ OUR OWN execution-safety (ADR-007)
The single most load-bearing intersection is **inward**, about the agent's own safety, already
settled by **ADR-007** (static-analysis-only by default; opt-in PoC detonation is
gVisor/Docker-sandboxed with egress locked to the model API). The 2026 evidence *reinforces* that
ADR rather than expanding white-hacker's review scope:
- **Shared-kernel containers leave every tenant exposed to a single kernel bug**; the 2026 LPE wave
  (Copy Fail / Dirty Frag / PinTheft / eBPF-verifier — see researcher memory) turns "a kernel CVE"
  into "container → host escape." gVisor reduces but does not eliminate host-syscall surface;
  microVMs (Firecracker/Kata) give hardware-enforced isolation **but** recent work shows even
  microVM isolation can be bypassed via operation-forwarding, and frontier LLMs have measurable
  container-sandbox-escape capability (arXiv 2603.02277, "Quantifying Frontier LLM Capabilities for
  Container Sandbox Escape"; Northflank / Edera isolation comparisons, all fetched 2026-06-08).
- **Implication:** this is **not** a new app-review detector — it's a reason the agent must keep its
  *own* untrusted-code execution behind the strongest practical boundary (ADR-007 already mandates
  gVisor/Docker; the 2026 data argues microVM is the safer ceiling for any future detonation host,
  and that shared-kernel CI runners are the weakest link). It belongs in the execution-safety ADR
  thread, not in `sec-detect`. This *inward* concern is a note for ADR-007's risk register; its
**outward mirror — the target repo's own `Dockerfile`/container config — is reviewed by the existing
`iac` capability** (see Scope decision §2), where the same shared-kernel fact is the rationale for the
infra.md hardening checklist. **No new app-repo capability either way.**

### F5 — Where it DOES intersect (c): module / DKMS supply-chain → existing SCA capability
A kernel **module** or **DKMS** package pulled by an app repo is a **dependency** like any other:
unsigned/unpinned out-of-tree modules, `modprobe.d` install lines, DKMS build scripts fetching
unpinned sources. This maps cleanly onto the **existing SCA/supply-chain capability** (ADR-015
capability layer; ADR-006 pinning) — it needs **no kernel-specific code**, just that the SCA path
recognize these as fetchable/installable artifacts subject to the same pin-and-verify rule. Plain
reuse, not a new capability.

### F6 — The decisive OUT-OF-SCOPE line
white-hacker **must not** audit kernel C / driver / eBPF-bytecode for memory-safety
(UAF/OOB/double-free/race) bugs. Grounds, all already binding:
- **Rule 5** — that work is fuzzing + specialist static analysis (deterministic/specialist), not
  LLM judgment; "if code [a fuzzer] can answer, code answers."
- **FP discipline** — kernel memory-safety review by an LLM is unfalsifiable at our precision bar;
  it manufactures the noise the recall/precision split (ADR-008) exists to suppress.
- **ADR-015 / floor** — our capability ports (SAST/SCA/secrets/IaC/AI-redteam) have **no** "kernel
  memory-safety" port and shouldn't grow one for a use case that isn't our target (app repos).
- **Capability honesty (ADR-003)** — claiming kernel-audit ability we can't back would violate the
  graceful-degradation / mark-`tool_assisted:false` honesty contract.

---

## Scope decision for white-hacker

**Verdict: NO new kernel code-review capability. YES a tiny, advisory, awareness-only
trust-boundary signal — and that is the ceiling.** Concretely:

1. **OUT OF SCOPE (hard line, no code):** auditing kernel/driver/module C or eBPF bytecode for
   memory-safety bugs; ingesting kernel-CVE feeds as a per-repo finding source; scoring kernel
   CVEs. These are fuzzer/specialist/host-patching concerns (F1, F2, F6). Kernel-LPE *intel* stays
   in the **KB-refresh / threat-intel** arm (researcher memory), never the app-review path.

2. **IN SCOPE via EXISTING mechanisms (reuse, no kernel-specific code):**
   - **Target `Dockerfile` / container config — the primary, concrete use case.** When the reviewed
     repo ships a `Dockerfile` or k8s/compose manifests, white-hacker **already** reviews them via the
     existing **`iac` capability** (`sec-detect` maps `Dockerfile`→`docker`, `detect_tools.py:43`;
     hardening rules in `_shared/reference/infra.md:8`). The kernel evidence in this spike supplies the
     **threat rationale** behind those checks: because containers **share the host kernel**, one kernel
     CVE turns a weakly-confined container into a **host escape** — so the infra.md checklist (run as
     non-root, drop `ALL` capabilities, no `--privileged`, no `hostPID/hostNetwork/hostPath`,
     digest-pinned base image, `allowPrivilegeEscalation:false`) **is** the mitigation. **No new
     capability** — kernel security enriches the *why* of the existing container/Dockerfile review,
     and a container running `--privileged`/`CAP_SYS_ADMIN` is the case where the eBPF/kernel-module
     awareness signal below most matters.
   - **Awareness signal (the only new behavior):** when a reviewed repo contains **eBPF programs /
     kernel modules / device drivers / privileged-container (`CAP_SYS_ADMIN`, `privileged: true`,
     hostPID/hostNetwork) config**, emit an **informational trust-boundary note** — "this code
     crosses into kernel-execution / elevated-privilege territory; verifier-safety and kernel
     memory-safety are out of this review's scope; use specialist tooling
     (syzkaller/Buzzer for kernel/eBPF, `kernel-hardening-checker`/KSPP for host config)." This is
     **advisory/informational, not a vuln finding** — the exact altitude as spike-08's
     absent-`SECURITY.md` hygiene note (ADR-018): no CVSS, never enters `VULN-FINDINGS.json`.
   - **Ordinary privilege/authorization review of the *userspace* loader code** around eBPF/modules
     (which capabilities, is loading gated by untrusted input, map permissions) — already in scope
     as standard authz review; the signal just *routes attention*, it does not add a verdict type.
   - **Module / DKMS supply-chain** → existing **SCA capability** (F5), pin-and-verify (ADR-006).

3. **INWARD (our own safety, not review scope):** the container-escape evidence (F4) is a
   **risk-register note for ADR-007**, reinforcing sandboxed-only execution and arguing microVM >
   shared-kernel for any future detonation host. No change to what white-hacker reports.

This keeps us honest (Rule 5, ADR-003), simple (Rule 2 — reuse SCA + the spike-08 advisory
pattern; one new detector signal, zero new capability port), and non-coupled (ADR-015).

**Confidence: HIGH.** Landscape + method facts verified against kernel.org/Google/OpenSSF/KSPP/
arXiv primary sources; the boundary is a direct application of standing ADRs and Rule 5.

### Proposed follow-up tickets
- **T-A · kernel-adjacency awareness signal (detector, advisory-only):** in the discovery/detect
  path, recognize eBPF (`cilium/ebpf`, `libbpf`, `*.bpf.c`, `bpftrace`), kernel modules
  (`*.ko` build, `Kbuild`/`Makefile` `obj-m`, DKMS), drivers, and privileged-container config;
  emit an **informational** trust-boundary note (no CVSS, not in `VULN-FINDINGS.json`), reusing the
  spike-08 / ADR-018 advisory channel. TDD over fixtures (repo with an eBPF prog; with a kernel
  module; with a privileged Pod spec; a plain app repo → no note). **No memory-safety verdicts.**
- **T-B · SCA recognizes module/DKMS artifacts:** confirm the SCA/supply-chain path treats
  out-of-tree modules + DKMS sources as pin-and-verify dependencies (ADR-006); add a fixture.
- **T-C · ADR-007 risk-register note:** append the 2026 container-escape evidence (shared-kernel
  exposure; microVM-bypass via operation-forwarding; frontier-LLM escape capability) to ADR-007's
  rationale, recommending microVM as the ceiling for any future PoC-detonation host. Doc-only.
- **T-D (optional) · KB-refresh routing:** ensure `sec-kb-refresh` files kernel-LPE intel as
  *background threat-intel* (a "new ways to hack hosts/containers" entry), explicitly **not** a
  per-repo app detector — preventing scope creep on the next refresh.

---

## Sources

**Kernel CVE policy / volume (the "not an app-repo input" argument):**
- [Linux Kernel — CVEs (process/cve.html)](https://docs.kernel.org/process/cve.html) — kernel CNA;
  "overly cautious … assign CVE numbers to any bugfix"; "large numbers … not relevant for their
  systems" (fetched 2026-06-08)
- [The New Stack — Linux kernel scale is swamping an already-flawed CVE system](https://thenewstack.io/linux-kernel-cve-system/) —
  kernel CNA Feb-2024; 4,325 CVEs in 2024 (10.81%); 300+/week in merge windows (fetched 2026-06-08)
- [stingrai — Vulnerability Statistics 2026](https://www.stingrai.io/blog/vulnerability-statistics-2026) —
  NVD triage model 2026-04-15; ~29,000 backlog "Not Scheduled"; 8–12 wk CVSS lag (fetched 2026-06-08)

**Kernel bug-finding is dynamic/specialist (the Rule-5 argument):**
- [google/syzkaller — syzbot docs](https://github.com/google/syzkaller/blob/master/docs/syzbot.md) ·
  [LPC'23 — Syzbot: 7 years of continuous kernel fuzzing](https://lpc.events/event/17/contributions/1521/) —
  coverage-guided fuzzing; ~4,000 reported / ~3,000 fixed (fetched 2026-06-08)
- [Google security-research — eBPF verifier register-limit-tracking advisory (GHSA-hfqc-63c7-rj9f / CVE-2024-41003)](https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f) —
  found via modified Buzzer fuzzer; verifier is a static analyzer defeated by runtime divergence (fetched 2026-06-08)
- [Invicti — eBPF Vulnerabilities: Ecosystem and Security Model](https://www.invicti.com/blog/web-security/ebpf-vulnerabilities-ecosystem-and-security-model) ·
  [CVE-2026-43009 (eBPF verifier, fixed 6.19.12)](https://windowsnews.ai/article/cve-2026-43009-how-a-linux-ebpf-verifier-flaw-threatens-wsl-and-what-you-must-do-now.417473) (fetched 2026-06-08)

**Hardening (kernel-config/LSM, not app-source review):**
- [KSPP — Recommended Settings](https://kspp.github.io/Recommended_Settings.html) ·
  [a13xp0p0v/kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker) (fetched 2026-06-08)
- [ARMO — Linux 6.17 security: new kernel hardening & mitigation controls](https://www.armosec.io/blog/linux-6-17-security-features/) —
  AppArmor AF_UNIX mediation mainlined; SELinux `neveraudit`; kCFI (fetched 2026-06-08)
- [Rust in the Linux Kernel 2026 — memory-safe drivers in mainline](https://www.programming-helper.com/tech/rust-in-the-linux-kernel-2026-memory-safe-drivers-future-kernel-development) (fetched 2026-06-08)

**Kernel-adjacent code in app repos (intersection a):**
- [ebpf.io — eBPF Applications Landscape](https://ebpf.io/applications/) ·
  [cilium/ebpf (Go) — pkg.go.dev](https://pkg.go.dev/github.com/cilium/ebpf) (fetched 2026-06-08)

**Container escape ↔ our execution-safety (intersection b / ADR-007):**
- [arXiv 2603.02277 — Quantifying Frontier LLM Capabilities for Container Sandbox Escape](https://arxiv.org/pdf/2603.02277) (fetched 2026-06-08)
- [Northflank — How to sandbox AI agents in 2026: MicroVMs, gVisor & isolation](https://northflank.com/blog/how-to-sandbox-ai-agents) ·
  [Edera — Kata vs Firecracker vs gVisor isolation compared](https://edera.dev/stories/kata-vs-firecracker-vs-gvisor-isolation-compared) (fetched 2026-06-08)

**Internal (not re-derived here):** researcher memory `kernel-threat-landscape-2026` (Apr–Jun 2026
LPE wave: Copy Fail / Dirty Frag / PinTheft / eBPF-verifier; AI-assisted discovery); ADR-003,
ADR-006, ADR-007, ADR-008, ADR-015, ADR-018 (`docs/ARD.md`).
