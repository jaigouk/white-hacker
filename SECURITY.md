# Security Policy

## Supported Versions

This project is pre-1.0; security fixes are applied to the latest release on `main`.

| Version | Supported |
|---------|-----------|
| latest release / `main` | ✅ |
| older pre-1.0 tags      | ❌ |

Pin to a released tag or commit and update to the latest release to receive security fixes.

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do **not** open a public issue.

Use **GitHub Private Vulnerability Reporting**:

- Go to the repository's **Security** tab → **Report a vulnerability**, or open
  <https://github.com/jaigouk/white-hacker/security/advisories/new>.

When reporting, please include:

- a description of the vulnerability and its impact,
- the affected version(s) and component(s),
- clear reproduction steps or a proof of concept.

## Response Timeline

As a small/solo-maintained project we aim to:

- acknowledge your report as soon as possible, typically within a few business days,
- provide an initial assessment and triage shortly after, and
- agree a coordinated fix and disclosure window of up to **90 days**.

## Coordinated Disclosure

We follow coordinated (responsible) disclosure: please keep the issue confidential until a fix
is released and the embargo ends. We will work with you on the disclosure schedule and may
extend the embargo by mutual agreement for complex fixes.

## Scope

- **In scope:** the first-party code in this repository — the `white-hacker` plugin payload
  (`plugins/white-hacker/`: the agent definition, skills, hooks, and scripts) and the
  supporting tooling (`packaging/`, `evals/`).
- **Out of scope:** third-party dependencies (report those to their upstream maintainers) and
  test/CI fixtures, unless a finding affects shipped behavior.

## Safe Harbor

We support good-faith security research. We will not pursue legal action against researchers who
follow this policy, make a good-faith effort to avoid privacy violations and service disruption,
and give us a reasonable opportunity to remediate before any public disclosure.

## Acknowledgments

We credit researchers who responsibly disclose issues (with their permission). For questions
about this policy, use the private reporting channel above.
