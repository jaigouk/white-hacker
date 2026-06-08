"""Section-keyed Markdown patch-merge for sec-learn diffs (wh-0aq, si-10 borrowing #1).

A ~deterministic, stdlib-only, append-only merge (COLLEAGUE map #3 / si-10
`docs/research/si-10-living-kb-lightweight.md:58-62`). Keeps sec-learn's text mutations out of
the LLM path (Rule 5) and the merge reviewable:

  - Split both `base_md` and `patch_md` into level-2 (`##`) heading sections.
  - A patch section whose `##` heading MATCHES a base section REPLACES that base section in place.
  - A patch section with no matching heading is APPENDED after the base (append-only).
  - Any base preamble before the first `##` is preserved at the top.

No LLM, no network, no RNG — a pure function over two strings.
"""
from __future__ import annotations

_HEADING = "## "


def _split_sections(md: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (preamble, [(heading_line, section_text), ...]).

    `preamble` is everything before the first `## ` heading (may be ""). Each section_text
    includes its own heading line and trailing body verbatim (including line breaks).
    """
    lines = md.splitlines(keepends=True)
    preamble: list[str] = []
    sections: list[list[str]] = []
    current: list[str] | None = None
    for line in lines:
        if line.startswith(_HEADING):
            current = [line]
            sections.append(current)
        elif current is None:
            preamble.append(line)
        else:
            current.append(line)
    return "".join(preamble), [("".join(s).split("\n", 1)[0], "".join(s)) for s in sections]


def merge_markdown_patch(base_md: str, patch_md: str) -> str:
    """Merge `patch_md` into `base_md` keyed on level-2 (`##`) headings.

    Matching heading -> replace the base section; unmatched heading -> append. Base preamble
    preserved. Deterministic and order-stable.
    """
    preamble, base_sections = _split_sections(base_md)
    _, patch_sections = _split_sections(patch_md)

    headings = [h for h, _ in base_sections]
    merged: list[str] = [text for _, text in base_sections]
    for heading, text in patch_sections:
        if heading in headings:
            merged[headings.index(heading)] = text  # replace in place
        else:
            headings.append(heading)
            merged.append(text)  # append-only

    return preamble + "".join(merged)
