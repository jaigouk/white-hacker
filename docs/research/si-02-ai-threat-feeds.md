# Self-Improvement Research — si:ai-threat-feeds

> Source: workflow `self-improving-white-hacker-research` (w3b87zsau), agent `si:ai-threat-feeds`

## Feed List: Authoritative AI/LLM-Security Sources to Poll in 2026

This is a curated, URL-verified set of sources a self-improving white-hat security agent (Claude Code subagent + scheduled routine) should poll to keep its AI-attack knowledge current. It is grouped by type, with cadence and whether a **machine-readable feed** exists (the agent should prefer those for `WebFetch`/scheduled polling; HTML-only sources need an LLM-extraction step). All URLs were checked against live 2026 pages.

### 1. Frameworks & Taxonomies (authoritative, slow-moving — poll weekly/monthly)

| Source | URL | Cadence | Feed? | Covers |
|---|---|---|---|---|
| OWASP Top 10 for LLM Applications 2025 (current canonical list) | https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/ | Monthly | No (PDF/HTML) | LLM01 Prompt Injection … LLM10 Unbounded Consumption (full 2025 list below) |
| OWASP LLM Top 10 landing/archive (tracks revisions) | https://genai.owasp.org/llm-top-10/ | Monthly | No | Watch for a 2026 LLM revision; currently 2025 is canonical |
| OWASP **Top 10 for Agentic Applications for 2026** | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | Monthly | No | Autonomous-agent risks; released Dec 2025, "for 2026" |
| OWASP **Agentic AI Threats & Mitigations** (+ initiative hub) | https://genai.owasp.org/initiatives/agentic-security-initiative/ | Monthly | No | Threat-model reference, "Practical Guide to Securing Agentic Applications" |
| OWASP **Secure MCP Server Development** guide | https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/ | On release | No | MCP server hardening |
| OWASP **CheatSheet – Securely Using Third-Party MCP Servers 1.0** | https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/ | On release | No | Tool poisoning / rug-pull defenses |
| OWASP MCP Security Cheat Sheet (OWASP Cheat Sheet Series) | https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html | Monthly | GitHub repo has commits/RSS | MCP-specific controls |
| OWASP GenAI homepage / newsroom (catch new publications) | https://genai.owasp.org/ | Weekly | No | New publications, quarterly Solutions Landscapes |
| **MITRE ATLAS** matrix (human view) | https://atlas.mitre.org/ | Weekly | No (site) | 16 tactics, ~84 techniques incl. agentic + GenAI additions |
| **MITRE ATLAS data repo** (machine-readable) | https://github.com/mitre-atlas/atlas-data | Weekly | **YAML/STIX/JSON + GitHub releases/commits RSS** | Latest content **2026.05** (format v6.0.0). Poll `dist/ATLAS-latest.yaml` and `dist/stix-atlas.json` |
| NIST **AI RMF: Generative AI Profile (AI 600-1)** | https://www.nist.gov/itl/ai-risk-management-framework + PDF https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf | Quarterly | No | 12 GenAI risks + 200+ actions (July 2024 base, 2025 updates) |
| NIST **Cyber AI Profile** (NISTIR 8596, draft) | https://csrc.nist.gov/pubs/ir/8596/iprd | Monthly | CSRC News RSS (below) | New community profile mapping CSF to AI cyber risk |
| NIST **COSAIS** – SP 800-53 Control Overlays for Securing AI Systems | https://csrc.nist.gov/projects/cosais | Monthly | CSRC News RSS | Annotated outline Jan 2026; IPD expected 2026; agentic/GenAI overlays |
| **NIST CSRC News** feed (catch all NIST AI doc drops) | https://csrc.nist.gov/news (RSS: https://csrc.nist.gov/CSRC/media/feeds/news.xml) | Weekly | **RSS** | All NIST drafts/finals incl. AI |

**OWASP LLM Top 10 (2025) full list** for the agent's baseline knowledge: LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Supply Chain · LLM04 Data and Model Poisoning · LLM05 Improper Output Handling · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector and Embedding Weaknesses · LLM09 Misinformation · LLM10 Unbounded Consumption.

### 2. CVE / Advisory Feeds for AI Frameworks (machine-readable — poll daily)

These are the highest-value automated feeds. **OSV.dev** and the **GitHub Advisory Database REST API** both expose JSON and aggregate GHSA + PyPA, so the agent can poll programmatically with no scraping.

| Source | URL / endpoint | Cadence | Feed? |
|---|---|---|---|
| **OSV.dev** REST API (query by package/version) | https://api.osv.dev/v1/query (docs https://google.github.io/osv.dev/api/) | Daily | **JSON API** |
| OSV bulk export (all ecosystems / per-ecosystem zips) | `gs://osv-vulnerabilities/all.zip`; per-eco `gs://osv-vulnerabilities/PyPI/all.zip` (https://google.github.io/osv.dev/data/) | Daily | **JSON in GCS** |
| **GitHub Global Advisory DB** REST (filter by ecosystem) | https://api.github.com/advisories?ecosystem=pip&type=reviewed (docs https://docs.github.com/en/rest/security-advisories/global-advisories) | Daily | **JSON API**, no auth needed for public |
| GitHub Advisory DB web (browse/RSS-via-API) | https://github.com/advisories | Daily | via API |
| **PyPA Advisory Database** (source of pip GHSAs) | https://github.com/pypa/advisory-database | Daily | **OSV-format JSON + commits RSS** |
| **vLLM** security advisories | https://github.com/vllm-project/vllm/security/advisories | Daily | GitHub advisories API |
| LangChain / LlamaIndex / Ollama / HF Transformers / MCP servers | Query each via OSV `ecosystem:PyPI/npm` + `package:<name>` | Daily | via OSV/GitHub API |

Per-package query targets for the OSV/GitHub API: `langchain`, `langchain-core`, `langchain-community`, `llama-index`, `vllm`, `ollama` (npm + PyPI client), `transformers`, `huggingface_hub`, plus npm MCP packages (`@modelcontextprotocol/*`). **Recent high-signal 2026 examples to anchor on:** vLLM RCE via HF `auto_map` dynamic-module loading (CVE-2026-22807 / GHSA-2pc9-4j83-qjmr), vLLM `transformers_utils.get_config` RCE (GHSA-8fr4-5q9j-m8gm), vLLM malicious-video-URL RCE (CVE-2026-22778), and LangChain serialization-injection secret extraction (CVE-2025-68664 / GHSA-c67j-w6g6-q2cm).

### 3. Research Feeds (machine-readable — poll daily, filter with LLM)

| Source | URL | Cadence | Feed? |
|---|---|---|---|
| **arXiv cs.CR** (Cryptography & Security) RSS | http://rss.arxiv.org/rss/cs.CR | Daily (00:00 ET) | **RSS 2.0** |
| arXiv cs.CR Atom | http://rss.arxiv.org/atom/cs.CR | Daily | **Atom** |
| arXiv cs.CR recent (HTML fallback) | https://arxiv.org/list/cs.CR/recent | Daily | No |
| arXiv API (programmatic search, e.g. "prompt injection", "jailbreak", "agent hijack") | http://export.arxiv.org/api/query?search_query=all:prompt+injection | Daily | **Atom API** |

The agent should keyword-filter the cs.CR firehose for: *prompt injection, indirect injection, jailbreak, agent hijack, tool poisoning, RAG poisoning, lethal trifecta, MCP*. Notable 2025-2026 lines of work to track include indirect-injection brittleness in agentic LLMs, the "Promptware Kill Chain," skill-based prompt injection for coding agents (Skillject), and Anthropic/UK-AISI papers like "Agents Rule of Two" and "The Attacker Moves Second."

### 4. Practitioner Trackers, Blogs & Newsletters (mix — poll weekly)

| Source | URL | Cadence | Feed? |
|---|---|---|---|
| **Embrace The Red** (Johann Rehberger) | https://embracethered.com/blog/ (Atom: https://embracethered.com/blog/index.xml) | Weekly | **Atom/RSS** |
| Embrace The Red — "Month of AI Bugs" tag | https://embracethered.com/blog/tags/month-of-ai-bugs/ | On post | RSS via tag |
| **Simon Willison** — prompt-injection tag feed | https://simonwillison.net/tags/prompt-injection.atom | Daily | **Atom** |
| Simon Willison — LLMs tag feed | https://simonwillison.net/tags/llms.atom | Daily | **Atom** |
| Simon Willison — site feed | https://simonwillison.net/atom/everything/ | Daily | **Atom** |
| **AI Security Newsletter** (Tal Eliyahu, monthly digest) | https://github.com/TalEliyahu/AI-Security-Newsletter | Monthly | **GitHub commits/releases RSS** |
| **Microsoft Security Blog** (AI agent RCE, MSRC research) | https://www.microsoft.com/en-us/security/blog/ (RSS: https://www.microsoft.com/en-us/security/blog/feed/) | Weekly | **RSS** |
| **Microsoft MSRC Blog** | https://msrc.microsoft.com/blog/ | Weekly | RSS |
| **Anthropic Newsroom** (security research, red-team metrics) | https://www.anthropic.com/news | Weekly | No official feed (community feeds exist via github.com/Olshansk/rss-feeds) |
| **Google Online Security Blog** (GTIG, Project Zero adjacent) | https://security.googleblog.com/ (RSS: https://security.googleblog.com/feeds/posts/default) | Weekly | **RSS** |
| **HiddenLayer Innovation Hub** (lethal trifecta, agent attacks) | https://hiddenlayer.com/innovation-hub/ | Weekly | RSS likely |

### 5. MCP-Specific Security Advisories (poll weekly — emerging, fast-moving)

MCP threats (tool poisoning, rug pulls, confused deputy / OAuth consent bypass, npm supply-chain) accelerated through early–mid 2026. There is no single canonical MCP CVE feed yet, so combine the OWASP MCP cheat sheets (Section 1), npm/PyPI advisory queries for `@modelcontextprotocol/*` (Section 2), and these tracker pages:

| Source | URL | Cadence | Notes |
|---|---|---|---|
| OWASP MCP Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html | Monthly | Canonical control list |
| MCP defense-first architecture (Christian Schneider) | https://christian-schneider.net/blog/securing-mcp-defense-first-architecture/ | On update | Architecture patterns |
| UltraViolet Cyber MCP Threat Advisory (May 2026) | https://www.uvcyber.com/hubfs/ThreatAdvisory-MCP-Threats-27MAY26.pdf | One-off | Recent advisory snapshot |
| MITRE ATLAS agentic techniques (Zenity Labs collab) | https://github.com/mitre-atlas/atlas-data | Weekly | 14+ AI-agent techniques added Oct 2025 |

### Implementation notes for the Claude Code agent

- **Tier the polling with a scheduled routine (cron):** *daily* job for the JSON/RSS machine-readable feeds (OSV API, GitHub Advisory API, arXiv cs.CR RSS, ATLAS `dist/` files via raw GitHub, Simon Willison/Embrace-the-Red Atom); *weekly* job for HTML-only practitioner/vendor blogs and OWASP/NIST landing pages; *monthly* job for the framework PDFs.
- **Prefer feeds with structured output.** OSV (`api.osv.dev`), GitHub Advisories (`api.github.com/advisories`), arXiv RSS/Atom, ATLAS YAML/STIX, and the `.atom` blog feeds are directly parseable — store last-seen IDs/etags to diff. HTML-only sources (OWASP, Anthropic news, vendor blogs) need a `WebFetch` + LLM-extraction step into the agent's knowledge memory.
- **Anchor diffs on version numbers** you can check cheaply: OWASP LLM Top 10 (currently **2025**; watch for a 2026 revision), OWASP Agentic Top 10 (**2026**), MITRE ATLAS content (**2026.05**, format **6.0.0**), NIST AI 600-1, and the COSAIS/Cyber-AI-Profile draft status.
- **Maintain an allow-list of package names** for the OSV/GitHub queries so new CVEs in LangChain, LlamaIndex, vLLM, Ollama, Transformers, huggingface_hub, and `@modelcontextprotocol/*` are caught automatically.


## Key takeaways

- Tier polling by feed type: daily for machine-readable JSON/RSS (OSV API, GitHub Advisory API, arXiv cs.CR RSS, ATLAS dist/ YAML+STIX, .atom blogs), weekly for HTML vendor/practitioner blogs, monthly for framework PDFs — implement as a Claude Code scheduled cron routine.
- The two best fully-automatable CVE feeds are OSV.dev (api.osv.dev/v1/query + gs://osv-vulnerabilities bulk JSON) and the GitHub Global Advisory DB REST API (api.github.com/advisories?ecosystem=pip), both JSON and no-auth for public data; keep an allow-list of AI package names to query.
- Anchor knowledge-freshness checks on version strings the agent can cheaply diff: OWASP LLM Top 10 = 2025 (watch for 2026 revision), OWASP Agentic Top 10 = 2026, MITRE ATLAS content = 2026.05 / format 6.0.0, NIST AI 600-1, and COSAIS/Cyber-AI-Profile draft status.
- MITRE ATLAS exposes machine-readable YAML, STIX, and JSON in github.com/mitre-atlas/atlas-data (dist/ATLAS-latest.yaml, dist/stix-atlas.json) — poll the repo/releases instead of scraping atlas.mitre.org; it added agentic/GenAI techniques via the Zenity Labs collaboration.
- arXiv gives true feeds at http://rss.arxiv.org/rss/cs.CR (and /atom/cs.CR, plus the export.arxiv.org API) — pull the cs.CR firehose daily and LLM-filter for prompt injection, indirect injection, jailbreak, agent hijack, tool/RAG poisoning, lethal trifecta, MCP.
- Highest-signal practitioner Atom feeds: embracethered.com/blog/index.xml (Johann Rehberger, 'Month of AI Bugs') and simonwillison.net/tags/prompt-injection.atom + llms.atom — these surface new attack techniques fastest and are directly parseable.
- Vendor blogs worth a weekly RSS pull: Microsoft Security Blog (/security/blog/feed/) and MSRC for AI-agent RCE/CI-CD secret-exfil research, Google Online Security Blog (security.googleblog.com feed) for GTIG; Anthropic Newsroom (anthropic.com/news) has no official feed so needs WebFetch extraction or a community feed.
- MCP security has no single canonical CVE feed yet — combine OWASP's MCP cheat sheets (Secure MCP Server Development guide + Third-Party MCP CheatSheet + OWASP Cheat Sheet Series page), npm/PyPI OSV queries for @modelcontextprotocol/*, and ATLAS agentic techniques to cover tool poisoning, rug pulls, and confused-deputy/OAuth-consent-bypass.
- NIST AI security is moving fast in 2026 beyond AI 600-1: track the Cyber AI Profile (NISTIR 8596 draft) and COSAIS SP 800-53 Control Overlays (annotated outline Jan 2026, IPD expected 2026) via the CSRC News RSS feed rather than checking pages manually.
- Prefer feeds with stable IDs/etags and store last-seen markers to diff incrementally; for HTML-only authoritative sources (OWASP genai.owasp.org, Anthropic news), pair WebFetch with an LLM-extraction step that writes deltas into the agent's persistent security-knowledge memory.
- Use recent concrete CVEs as regression anchors when validating the pipeline: vLLM auto_map RCE (CVE-2026-22807), vLLM get_config RCE (GHSA-8fr4-5q9j-m8gm), vLLM video-URL RCE (CVE-2026-22778), LangChain serialization injection (CVE-2025-68664).
- OWASP GenAI Security Project also ships quarterly 'AI Security Solutions Landscape' reports and a FinBot Agentic CTF — useful for the agent to map detections/mitigations and to self-test attack knowledge against a live target.

## Sources

- https://genai.owasp.org/
- https://genai.owasp.org/llm-top-10/
- https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- https://genai.owasp.org/initiatives/agentic-security-initiative/
- https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/
- https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
- https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/
- https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- https://atlas.mitre.org/
- https://github.com/mitre-atlas/atlas-data
- https://www.nist.gov/itl/ai-risk-management-framework
- https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- https://csrc.nist.gov/projects/cosais
- https://csrc.nist.gov/pubs/ir/8596/iprd
- https://csrc.nist.gov/News/2025/nist-releases-prelim-draft-cyber-ai-profile
- https://google.github.io/osv.dev/api/
- https://google.github.io/osv.dev/data/
- https://osv.dev/
- https://docs.github.com/en/rest/security-advisories/global-advisories
- https://github.com/advisories
- https://github.com/pypa/advisory-database
- https://github.com/vllm-project/vllm/security/advisories
- https://github.com/advisories/GHSA-2pc9-4j83-qjmr
- https://github.com/advisories/GHSA-c67j-w6g6-q2cm
- https://www.ox.security/blog/cve-2026-22778-vllm-rce-vulnerability/
- http://rss.arxiv.org/rss/cs.CR
- https://info.arxiv.org/help/rss.html
- https://arxiv.org/list/cs.CR/recent
- https://embracethered.com/blog/
- https://embracethered.com/blog/tags/month-of-ai-bugs/
- https://simonwillison.net/tags/prompt-injection/
- https://simonw.substack.com/p/new-prompt-injection-papers-agents
- https://github.com/TalEliyahu/AI-Security-Newsletter
- https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/
- https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/
- https://www.anthropic.com/news
- https://security.googleblog.com/
- https://www.uvcyber.com/hubfs/ThreatAdvisory-MCP-Threats-27MAY26.pdf
- https://christian-schneider.net/blog/securing-mcp-defense-first-architecture/

