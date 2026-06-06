# lang-java — Java/JVM-specific sinks & secure patterns

> Loaded on demand when `SCAN-PLAN.json` lists `java`. Pattern-first; core categories in
> [`core-checklist.md`](core-checklist.md). CVE ids re-verified 2026-06-06
> (`docs/research/spike-04-phase2-cve-currency.md`).

## Native capability tools (examples, swappable)
- **SCA:** OSV-Scanner / Trivy on the lockfile (`pom.xml`, `gradle.lockfile`).
- **SAST:** Opengrep; `spotbugs` + `find-sec-bugs` **only if compiled bytecode is available**
  (source-only repos can't run it — fall back to PMD + Opengrep + this file).
- Floor: Read/Grep/Glob + this file (`tool_assisted:false`).

## Spring Security authorization-bypass version gate
- **CVE-2025-41248 (Spring Security) + CVE-2025-41249 (Spring Framework).** Method-security
  annotations (`@PreAuthorize`, etc.) are **not resolved** when declared on a method of a
  parameterized supertype with *unbounded generics* → the check is silently skipped → **authorization
  bypass**. Triggered with `@EnableMethodSecurity`. Fixed: **Spring Security 6.4.11 / 6.5.5**, Spring
  **Framework 6.2.11**. Affected: Spring Security 6.4.0–6.4.9 & 6.5.0–6.5.3; Framework
  5.3.x/6.1.x/6.2.x ranges. If versions are in range **and** secured methods live on generic
  interfaces/superclasses, flag HIGH; mitigation is to declare the secured method on the target class.

## Insecure deserialization
```java
// DANGEROUS — native deserialization of untrusted bytes == RCE gadget chains
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
Object o = ois.readObject();

// SAFER — install a strict allowlist filter (JEP 290); better: don't use native serialization
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.*;!*"));
```
Prefer a data format (JSON with a typed schema). For Jackson, see below.

## Jackson polymorphic typing
Default/polymorphic typing without a validator turns JSON into a deserialization-gadget sink.
```java
// DANGEROUS
mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance); // or enableDefaultTyping()

// SAFE — restrict to an allowlist via a PolymorphicTypeValidator, or avoid default typing
PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
    .allowIfSubType("com.example.model.").build();
mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
```
**DoS gate — CVE-2025-52999 (jackson-core):** deeply-nested JSON causes unbounded recursion →
`StackOverflowError` on any JSON endpoint (unauth). Fixed in **2.15.0** via `StreamReadConstraints`
(default max nesting 1000). Upgrade jackson-core ≥ 2.15.0.

## SpEL / expression injection
`parser.parseExpression(userInput).getValue()` is RCE. Never build a SpEL/OGNL/MVEL expression from
user input; use a fixed expression with bound variables, or drop expressions entirely.

## XXE — default factories resolve external entities
```java
// SAFE — disable DTDs/external entities on every parser factory
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```
Same for `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`.

## SQL
`@Query(nativeQuery = true)` with string concatenation, or `Statement` + concatenated SQL, is
injection. Use bound `:params` / `PreparedStatement` placeholders. Also: log4j-core ≥ 2.17.1
(post-Log4Shell), and never log untrusted input into a pattern that re-evaluates lookups.

## What to grep for
Spring version in `pom.xml`/`build.gradle` + `@PreAuthorize` on generic types · `readObject(` /
`ObjectInputStream` without `ObjectInputFilter` · `enableDefaultTyping`/`activateDefaultTyping` +
Jackson version · `parseExpression(` (SpEL) · `DocumentBuilderFactory`/`SAXParser` without
disallow-doctype · `@Query(nativeQuery = true)` with `+`/`String.format` · `Runtime.exec(` /
`ProcessBuilder` with concatenated input · `Cipher.getInstance("AES")` (ECB/no-mode) / `DES` / `MD5`.
