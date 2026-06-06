# research:lang-go-java

> Source: workflow `white-hacker-research` (wycjclbk6), agent `research:lang-go-java`

## 2026 Language-Specific Security Review Notes: Go & Java

These notes are tuned for an automated white-hat review agent. Each finding lists what to grep for, why it's dangerous in 2026, and a DANGEROUS-vs-SAFE pair the agent can pattern-match.

---

## (a) Go — Backend / CLI / Services

### Tooling baseline (verify these run in CI)
- **govulncheck** (`golang.org/x/vuln/cmd/govulncheck@latest`, actively updated through 2026): the authoritative scanner. It does *call-graph* reachability analysis, so it only flags vulns whose vulnerable symbols are actually reachable — far less noise than naive SCA. Run `govulncheck ./...` and on built binaries. The Go vuln DB is updated continuously, so schedule it (weekly) in addition to per-PR ([go.dev](https://go.dev/doc/security/vuln/), [pkg.go.dev](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)).
- **gosec** (v2.23.0+, Feb 2026 added a **taint-analysis engine** and AST/SSA scanning; 50+ rules mapped to CWE/OWASP Top 10) ([github.com/securego/gosec](https://github.com/securego/gosec)). Note the agent should treat **G115** (integer-overflow conversion) findings as *needs-human-review* rather than auto-block — it's known for false positives and doesn't account for prior bounds checks ([gosec#1187](https://github.com/securego/gosec/issues/1187), [dev.to](https://dev.to/ccoveille/about-the-gosec-g115-drama-or-how-i-faced-back-integer-conversion-overflow-in-go-1302)).

### Command injection — `os/exec`
The Go stdlib does *not* invoke a shell, so passing args as separate slice elements is safe by construction. Danger appears only when code routes through `sh -c`.
```go
// DANGEROUS — user input concatenated into a shell string
exec.Command("sh", "-c", "ping " + userInput).Run()
// SAFE — program + discrete args, no shell
exec.CommandContext(ctx, "ping", "-c", "4", userHost).Run()
```
Also flag a **user-controlled program name** (the *first* arg) — stdlib arg protection does not cover that. Validate the binary against an allowlist. Note the historical `LookPath`/PATH issue ([go.dev/blog/path-security](https://go.dev/blog/path-security)) and the 2025 `LookPath` bug around `""`/`.`/`..` expansion ([golang/go#74466](https://github.com/golang/go/issues/74466)) — pin absolute paths for executables.

### Path traversal — `path/filepath` and the Go 1.24 `os.Root` API
Critical 2026 update: **`filepath.Clean` is NOT a security control** — it does not prevent traversal ([argemma.com](https://argemma.com/blog/go-filepath-clean/)). Go 1.24 introduced traversal-resistant APIs (`os.Root`, `os.OpenRoot`, `os.OpenInRoot`) using `openat`/dir-handle semantics, which also resist symlink escapes and TOCTOU races ([go.dev/blog/osroot](https://go.dev/blog/osroot)).
```go
// DANGEROUS — Join does not stop "../../etc/passwd"
f, _ := os.Open(filepath.Join(baseDir, userFilename))
// SAFE (Go 1.24+) — constrained to baseDir, blocks .. and symlink escape
f, err := os.OpenInRoot(baseDir, userFilename)
// ACCEPTABLE pre-1.24 — validate locality first
if !filepath.IsLocal(userFilename) { return errUnsafe } // Go 1.20+
```
Agent rule of thumb: **any `filepath.Join(base, <untrusted>)` followed by a file op is a finding** — recommend `os.Root`.

### SQL injection — `database/sql`
Parameterized queries auto-escape; string-built queries do not.
```go
// DANGEROUS — fmt.Sprintf into SQL
db.Query(fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name))
// SAFE — placeholders ($1 pg / ? mysql), value passed separately
db.Query("SELECT * FROM users WHERE name = $1", name)
```
Watch for ORMs (GORM `.Raw`/`.Where` with interpolation) and dynamic `ORDER BY`/identifiers — those can't be parameterized, so require an **allowlist of column names** ([snyk.io](https://snyk.io/articles/how-to-write-secure-go-code/)).

### SSRF — `net/http`
Any outbound request whose URL/host derives from user input is suspect (webhooks, image fetchers, URL previews).
```go
// DANGEROUS — fetches attacker-chosen host incl. 169.254.169.254, localhost, internal
resp, _ := http.Get(userURL)
```
SAFE pattern: parse the URL, resolve the host, **reject private/loopback/link-local/metadata ranges** (use `netip`/`net.IP.IsPrivate`, `IsLoopback`, `IsLinkLocalUnicast`), enforce an **allowlist of schemes (https only) and hosts**, and set a custom `DialContext` that re-checks the resolved IP to defeat DNS-rebinding/TOCTOU. Disable redirects or re-validate each hop via `CheckRedirect`.

### Unsafe template usage — `html/template` vs `text/template`
`html/template` is contextually auto-escaping (XSS-safe); `text/template` is **not** and must never render HTTP responses.
```go
// DANGEROUS — text/template to HTTP, or html/template bypass via template.HTML
text/template.New("p").Parse(tmpl)            // no escaping
out := template.HTML(userInput)               // explicitly opts out of escaping
// SAFE — html/template with values passed as data (auto-escaped per context)
html/template.Must(html/template.New("p").Parse(`<div>{{.User}}</div>`))
```
Flag **SSTI**: never build the template *string* from user input (`Parse(userInput)`); only the *data* should be user-controlled ([snyk.io SSTI](https://snyk.io/articles/understanding-server-side-template-injection-in-golang/)). Also flag `text/template` used to build SQL ([dev.to](https://dev.to/rohit20001221/sql-queries-in-golang-texttemplate-3l85)).

### Goroutine / resource bounds (DoS)
Per-request unbounded `go func()` (no `context` cancellation, no worker-pool/`semaphore.Weighted` cap) → goroutine leak / memory exhaustion. Flag: missing `r.Body` size limits (`http.MaxBytesReader`), missing server `ReadTimeout`/`WriteTimeout`/`IdleTimeout`, unbounded channel buffers, `io.ReadAll` on untrusted bodies, and decompression without size caps (zip/gzip bombs — pair with `os.Root` for extraction).

### Integer / slice issues
- **Integer overflow on conversion** (CWE-190): narrowing/`int↔uint` conversions on attacker-controlled sizes/lengths/counts. Recommend the `go-safecast` library for checked conversions ([go-safecast](https://github.com/ccoveille/go-safecast)). Treat gosec **G115** as advisory.
```go
// DANGEROUS — negative or huge value wraps / panics
buf := make([]byte, userLen)            // userLen from request; negative→panic, huge→OOM
n := int32(userInt64)                    // silent truncation
// SAFE — validate range before use
if userLen < 0 || userLen > maxLen { return errBad }
v, err := safecast.ToInt32(userInt64)
```
- **Slice bounds**: user-controlled offsets in `s[a:b]` → panic-based DoS; validate `0 <= a <= b <= len(s)`.

---

## (b) Java — Spring Boot / Jakarta

### Dependency CVEs to assert against (2025–2026)
- **Spring Security CVE-2025-41248 / Spring Framework CVE-2025-41249** (Sept 2025): annotation-detection flaw on **parameterized/generic** types causes `@PreAuthorize("hasRole('ADMIN')")` to be silently skipped → **authorization bypass**. Fixed in Spring Security **6.4.10 / 6.5.4**, Spring Framework **5.3.45 / 6.1.23 / 6.2.11** ([spring.io](https://spring.io/security/cve-2025-41248/), [socprime.com](https://socprime.com/blog/latest-threats/cve-2025-41248-and-cve-2025-41249-in-spring-framework/)).
- **Spring Cloud Gateway CVE-2025-41253**: **SpEL injection** via crafted headers → env-var/secret exposure, potential RCE when actuators misconfigured ([securityonline.info](https://securityonline.info/spring-patches-two-flaws-spel-injection-cve-2025-41253-leaks-secrets-stomp-csrf-bypasses-websocket-security/), [zeropath.com](https://zeropath.com/blog/cve-2025-41253-spring-cloud-gateway-spel-exposure)). CVE-2025-41254: STOMP CSRF bypass.
- **jackson-core CVE-2025-52999**: stack-overflow DoS via deeply nested input; fixed in **2.18.6 / 2.21.1 / 3.1.0** ([herodevs.com](https://www.herodevs.com/blog-posts/cve-2025-52999-denial-of-service-via-stack-overflow-in-jackson-core)).
- **Spring4Shell (CVE-2022-22965)** and **Log4Shell (CVE-2021-44228)** remain regression baselines — assert versions are above patched lines.
Tooling: **OWASP Dependency-Check**, **Snyk**, GitHub Dependabot, plus **CycloneDX SBOM** generation; static scanning via **Find Security Bugs** (SpotBugs) / Semgrep.

### Injection — JPA/JDBC & OS command
```java
// DANGEROUS — string-built JPQL/SQL
em.createQuery("FROM User u WHERE u.name = '" + name + "'");
stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
Runtime.getRuntime().exec("sh -c ping " + host);     // command injection
// SAFE — bind parameters / discrete args
em.createQuery("FROM User u WHERE u.name = :n").setParameter("n", name);
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setLong(1, id);
new ProcessBuilder("ping", "-c", "4", host).start(); // no shell, args discrete
```
Flag `@Query(nativeQuery=true)` with concatenation and dynamic sort/column names (allowlist).

### Insecure deserialization — Jackson & ObjectInputStream
```java
// DANGEROUS — polymorphic typing trusts attacker-supplied class names (CVE-2017-7525 lineage)
mapper.enableDefaultTyping();                 // or activateDefaultTyping(LaissezFaireSubTypeValidator)
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream()); ois.readObject();
// SAFE — no default typing; explicit allowlist validator if polymorphism truly needed
mapper.deactivateDefaultTyping();
PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
    .allowIfSubType("com.app.dto.").build();
mapper.activateDefaultTyping(ptv, DefaultTyping.NON_FINAL);
```
For native serialization that cannot be removed, set a **JEP 290 `ObjectInputFilter`** (allowlist + depth/array/byte limits) per-stream or JVM-wide (`jdk.serialFilter`), or context-specific via **JEP 415** ([openjdk.org/jeps/290](https://openjdk.org/jeps/290), [javacodegeeks 2026](https://www.javacodegeeks.com/2026/05/serialization-is-still-javas-biggest-attack-surface-what-jep-290-actually-did-and-what-it-didnt.html)). Serialization is still "Java's biggest attack surface" in 2026 — prefer JSON/DTOs over native serialization entirely.

### XXE — XML parsers
```java
// DANGEROUS — defaults allow external entities (file disclosure, SSRF)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// SAFE — disable DOCTYPE / external entities
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false); dbf.setExpandEntityReferences(false);
// StAX:
xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
```
Apply to `SAXParserFactory`, `XMLInputFactory`, `Transformer`, and **jackson-dataformat-xml** (CVE-2016-3720 lineage). Follow the OWASP XXE cheat sheet feature set ([find-sec-bugs.github.io](https://find-sec-bugs.github.io/bugs.htm)).

### SpEL / template injection
```java
// DANGEROUS — user input parsed as a SpEL expression → RCE
new SpelExpressionParser().parseExpression(userInput).getValue();
@PreAuthorize("hasRole('" + role + "')")        // dynamic SpEL in annotation
// SAFE — never parse untrusted SpEL; use a non-evaluating context or no expression at all
SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(fixedExpr).getValue(ctx, rootObj); // expr is a constant
```
Also flag Thymeleaf/Freemarker expressions built from user input, and SpEL reachable from `@Value`/Spring Cloud Gateway routes.

### Path traversal
```java
// DANGEROUS
new File(baseDir, userFilename);  Files.newInputStream(Paths.get(baseDir, userPath));
// SAFE — normalize and assert containment
Path base = Paths.get(baseDir).toRealPath();
Path resolved = base.resolve(userFilename).normalize();
if (!resolved.startsWith(base)) throw new SecurityException("traversal");
```

### Spring Security misconfiguration
Flag: `@PreAuthorize` on generic/parameterized types (CVE-2025-41248 pattern), `permitAll()` over-broad matchers, **disabled CSRF** without a stateless-API justification, **exposed Actuator** endpoints (`management.endpoints.web.exposure.include=*`, especially `/env`, `/heapdump`, `/jolokia`), `@CrossOrigin("*")` with credentials, missing method security (`@EnableMethodSecurity`), and authorization done in controllers instead of a central filter chain ([matproof.com](https://matproof.com/pentest/spring-boot)).

### Log4Shell-style logging
```java
// DANGEROUS — vulnerable Log4j2 evaluates ${jndi:ldap://...} in logged user input
log.info("login failed for " + username);   // on log4j-core < 2.17.1
// SAFE — patched version + parameterized logging + no message lookups
log.info("login failed for {}", sanitize(username)); // log4j-core >= 2.17.1 / 2.23.x
```
Assert **log4j-core ≥ 2.17.1** (JNDI lookups removed by default in 2.17+; 2.23.1 current in 2026) ([oligo.security](https://www.oligo.security/academy/log4j-vulnerability-history-detection-and-mitigation-2026-guide), [logging.apache.org](https://logging.apache.org/security.html)). Separately, flag **log/CRLF injection**: unsanitized `\n`/`\r` in log messages enabling forged log lines — neutralize newlines before logging untrusted data.

## Key takeaways

- Go: treat `filepath.Clean`/`filepath.Join(base, untrusted)` as NOT safe — recommend the Go 1.24 `os.Root`/`os.OpenInRoot` traversal-resistant APIs (also blocks symlink-escape and TOCTOU); use `filepath.IsLocal` as a fallback on pre-1.24.
- Go command injection only occurs via a shell (`sh -c`) or a user-controlled program name; flag those specifically, and recommend `exec.CommandContext` with discrete args plus an executable allowlist (note 2025 LookPath PATH bug).
- Go SSRF detection: any outbound request with a user-derived host; safe pattern requires resolved-IP allowlisting that rejects private/loopback/link-local/169.254.169.254 and re-checks on redirect/dial to defeat DNS rebinding.
- Run BOTH govulncheck (reachability-aware, low-noise, schedule weekly) and gosec v2.23+ (taint engine, CWE-mapped); treat gosec G115 integer-overflow findings as advisory/needs-review due to known false positives.
- Cross-language template rule: only DATA should be user-controlled, never the template/expression STRING — applies to Go `text/template` SSTI, Java SpEL `parseExpression(userInput)`, and Thymeleaf/Freemarker.
- Java authorization bypass is a live 2025 issue (CVE-2025-41248/41249): `@PreAuthorize` silently skipped on generic/parameterized types — assert Spring Security ≥ 6.4.10/6.5.4 and flag method-security annotations on generic supertypes.
- Java deserialization remains the top attack surface in 2026: flag Jackson `enableDefaultTyping`/`activateDefaultTyping` without a `PolymorphicTypeValidator`, and raw `ObjectInputStream.readObject` without a JEP 290 `ObjectInputFilter` (or JEP 415 context filter).
- XXE: default-configured `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`/`Transformer`/jackson-dataformat-xml is a finding — require disabling DOCTYPE and external general/parameter entities.
- Injection safe-pattern parity: Go `db.Query(..., $1)` and Java `PreparedStatement`/`em.setParameter` are safe; flag `fmt.Sprintf`/string-concat SQL, JPQL concat, `@Query(nativeQuery=true)` concat, and dynamic ORDER BY/column names (require allowlist).
- Logging: assert log4j-core ≥ 2.17.1 (Log4Shell), enforce parameterized logging (`{}` placeholders), and separately flag CRLF/log-injection from unsanitized newlines in untrusted log data.
- Resource-exhaustion/DoS checks span both: Go unbounded `go func()`/missing timeouts/`http.MaxBytesReader`/decompression caps; Java deep-nesting JSON DoS (jackson-core CVE-2025-52999, fix 2.18.6/2.21.1), exposed Actuator endpoints, and disabled CSRF.
- Integer/size safety in Go: validate attacker-controlled lengths/offsets before `make([]byte, n)` and slice expressions; recommend the go-safecast library for checked narrowing conversions (CWE-190).

## Sources

- https://go.dev/doc/security/vuln/
- https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
- https://github.com/securego/gosec
- https://github.com/securego/gosec/issues/1187
- https://dev.to/ccoveille/about-the-gosec-g115-drama-or-how-i-faced-back-integer-conversion-overflow-in-go-1302
- https://github.com/ccoveille/go-safecast
- https://go.dev/blog/osroot
- https://go.dev/blog/path-security
- https://github.com/golang/go/issues/74466
- https://argemma.com/blog/go-filepath-clean/
- https://semgrep.dev/docs/cheat-sheets/go-command-injection
- https://snyk.io/blog/understanding-go-command-injection-vulnerabilities/
- https://snyk.io/articles/how-to-write-secure-go-code/
- https://snyk.io/articles/understanding-server-side-template-injection-in-golang/
- https://dev.to/rohit20001221/sql-queries-in-golang-texttemplate-3l85
- https://spring.io/security/cve-2025-41248/
- https://socprime.com/blog/latest-threats/cve-2025-41248-and-cve-2025-41249-in-spring-framework/
- https://github.com/advisories/GHSA-8v5q-rhf3-jphm
- https://securityonline.info/spring-patches-two-flaws-spel-injection-cve-2025-41253-leaks-secrets-stomp-csrf-bypasses-websocket-security/
- https://zeropath.com/blog/cve-2025-41253-spring-cloud-gateway-spel-exposure
- https://www.herodevs.com/blog-posts/cve-2025-52999-denial-of-service-via-stack-overflow-in-jackson-core
- https://openjdk.org/jeps/290
- https://openjdk.org/jeps/415
- https://www.javacodegeeks.com/2026/05/serialization-is-still-javas-biggest-attack-surface-what-jep-290-actually-did-and-what-it-didnt.html
- https://find-sec-bugs.github.io/bugs.htm
- https://www.oligo.security/academy/log4j-vulnerability-history-detection-and-mitigation-2026-guide
- https://logging.apache.org/security.html
- https://matproof.com/pentest/spring-boot

