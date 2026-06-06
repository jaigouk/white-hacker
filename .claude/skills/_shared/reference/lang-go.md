# lang-go — Go-specific sinks & secure patterns

> Loaded on demand by `sec-vuln-scan` / `sec-triage` when `SCAN-PLAN.json` lists `go`.
> Pattern-first: the *shape* is the lesson; tool/CVE ids are evidence. Core categories live in
> [`core-checklist.md`](core-checklist.md); this appendix is the Go-flavoured sinks on top.

## Native capability tools (examples, swappable — see `tool-registry.md`)
- **SCA:** `govulncheck ./...` — reachability-aware, very low FP (only flags vulns whose vulnerable
  symbol is actually called). Best-signal SCA gate for Go.
- **SAST:** `gosec ./...` (taint in v2.x) + Opengrep with Go rules. `gosec` G115 (integer overflow on
  conversion) is **advisory** — confirm a real attacker-controlled size before reporting.
- Floor when neither is installed: Read/Grep/Glob + this file (mark `tool_assisted:false`).

## Path traversal — prefer `os.Root` (Go 1.24), not `filepath.Join`
`filepath.Join`/`filepath.Clean` do **not** contain traversal; `../` and absolute paths escape the
intended base. Go 1.24's `os.Root` / `os.OpenInRoot` enforce containment at the syscall level.
```go
// DANGEROUS — user-controlled name escapes baseDir via ../../etc/passwd
p := filepath.Join(baseDir, r.URL.Query().Get("name"))
data, _ := os.ReadFile(p)

// SAFE — os.Root confines all opens to baseDir (Go 1.24+)
root, err := os.OpenRoot(baseDir)
if err != nil { /* handle */ }
defer root.Close()
f, err := root.Open(r.URL.Query().Get("name")) // ../ and abs paths are rejected
```
If stuck pre-1.24: resolve, then verify the cleaned path is still prefixed by an absolute `baseDir`
(`strings.HasPrefix(filepath.Clean(p), base+string(os.PathSeparator))`) **and** reject symlinks.

## Command injection — never hand a string to a shell
`exec.Command` does **not** use a shell, so passing argv directly is safe; the bug is invoking
`sh -c` with interpolated input.
```go
// DANGEROUS — user input parsed by the shell
exec.Command("sh", "-c", "convert "+userInput).Run()

// SAFE — explicit argv, no shell; validate/allowlist the binary + flags
exec.Command("convert", userFile, "out.png").Run()
```
Grep for `"sh", "-c"`, `"bash", "-c"`, `exec.CommandContext(... -c ...)`.

## SSRF — resolve once, pin the IP, allowlist
Outbound requests to user-controlled URLs must block RFC1918/loopback/link-local and
`169.254.169.254` (IMDS) **in all encodings + IPv6**, and re-check on each redirect hop (DNS
rebinding). A path-only check is insufficient.
```go
// SAFE shape: custom DialContext that validates the *resolved* IP before connecting,
// CheckRedirect that re-validates each hop, and an explicit host allowlist. Prefer IMDSv2.
```

## Integer/length validation before allocation
`make([]byte, n)` with attacker-controlled `n` (e.g. a length field from the wire) is a memory-DoS
and, on 32-bit, an overflow. Validate bounds first; consider `go-safecast` for narrowing
conversions. (Pure memory-safety in safe Go without attacker-controlled reach is exclusion-listed —
require a real precondition.)

## SQL
`database/sql` is parameterized by default — the bug is string-built queries
(`fmt.Sprintf("... WHERE id=%s", id)` into `db.Query`). Use placeholders (`?`/`$1`); never
concatenate. `text/template` (not `html/template`) into HTML is an XSS sink.

## What to grep for
`filepath.Join` near request input · `"sh","-c"` / `"bash","-c"` · `fmt.Sprintf(`…`)` feeding
`db.Query`/`db.Exec` · `os.Getenv` secrets logged · `http.Get(`userURL`)` without IP validation ·
`make([]byte, ` with wire-derived length · `text/template` rendering HTML · `tls.Config{InsecureSkipVerify: true}`.
