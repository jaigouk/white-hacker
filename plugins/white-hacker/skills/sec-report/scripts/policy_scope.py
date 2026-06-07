"""policy_scope (T-11.4): consume a present security policy's declared scope as UNTRUSTED DATA.

A target repo's SECURITY.md / security.txt may declare an "out of scope" list and a reporting
channel. Per ADR-018, that policy is attacker-influenceable and the white-hacker agent is itself
an injection target (Agents Rule of Two), so its declared scope is consumed as UNTRUSTED DATA:

  * declared scope is used ONLY to ADD an advisory boolean annotation to each finding —
    `out_of_scope_per_policy` — it NEVER drops a finding and NEVER changes or lowers severity.
    A malicious policy could otherwise "scope away" a real, exploitable HIGH; declared scope
    therefore can NEVER suppress a real HIGH. The triage gate / human decide on the bug; the
    policy only annotates;
  * the reporting line is rendered as a FACTUAL one-liner sourced from the policy's private
    channel enum (never an imperative the agent could be coerced into following).

stdlib only.
"""
from __future__ import annotations


def annotate_findings_with_scope(
    findings: list[dict], out_of_scope_terms: list[str]
) -> list[dict]:
    """Return a copy of `findings` with an advisory `out_of_scope_per_policy` boolean added.

    For each finding the flag is True iff its `file` OR its `category` contains any
    `out_of_scope_term` as a case-insensitive substring. The output has the SAME length and
    the SAME severities, in the same order: this function NEVER drops a finding and NEVER changes
    or lowers any severity. Declared scope is untrusted, so the annotation is advisory only and
    can never suppress a real HIGH. The input list/dicts are not mutated.
    """
    terms = [t.lower() for t in out_of_scope_terms if t]
    annotated: list[dict] = []
    for finding in findings:
        haystack = (
            str(finding.get("file") or "") + "\n" + str(finding.get("category") or "")
        ).lower()
        out_of_scope = any(term in haystack for term in terms)
        # Shallow copy preserves every original key (incl. severity) verbatim; we only ADD.
        new_finding = dict(finding)
        new_finding["out_of_scope_per_policy"] = out_of_scope
        annotated.append(new_finding)
    return annotated


def reporting_line(reporting_channel: str, path: str | None) -> str:
    """Render a FACTUAL one-line 'how to report' string sourced from the policy's channel.

    States a fact about the policy ("Report vulnerabilities via the channel declared in
    <path> (<channel>).") — it is descriptive, never an imperative directed at the agent.
    When `path` is None the source is named generically. Always a single line (no newlines).
    """
    where = path if path else "the project's security policy"
    return (
        f"Report vulnerabilities via the channel declared in {where} ({reporting_channel})."
    )
