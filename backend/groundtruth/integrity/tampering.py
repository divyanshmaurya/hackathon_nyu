"""Was this document edited after it was produced?

A forged offer letter is rarely written from scratch. The efficient forgery is
to take a real offer letter -- often the forger's own, or one found online --
and replace the name, the salary and the date. That edit is cheap to make and
surprisingly hard to hide, because replacement text almost never inherits the
original's exact font, size and colour.

So we do not ask "does this look fake?". We ask a narrow, checkable question:
*within a single line of text, is one span typographically inconsistent with
its neighbours?* Consistency is the default in a document produced by one
system in one pass. Inconsistency is a fingerprint of intervention.

Two other edit signatures are detected here:

  - **Overlay patches.** Text drawn on top of other text, or on top of an
    opaque rectangle, which is how a value is "whited out" and replaced while
    the original often remains in the text stream underneath.
  - **Provenance mismatch.** The PDF's own Producer string, which says which
    software wrote the file. An offer letter from a real HR platform and one
    exported from a design tool have very different provenance.

Findings name what was observed, never what it proves. A mismatched font is
evidence of an edit, and edits have innocent explanations -- a recruiter
filling a template by hand produces the same signature as a forger. The
recruiter-facing wording says so.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from .findings import Finding, Layer, Severity
from .pdf_layers import Span, pymupdf

# Producer/Creator strings seen from systems that genuinely issue offer letters.
KNOWN_HR_PRODUCERS = re.compile(
    r"docusign|adobe\s*sign|hellosign|dropbox\s*sign|workday|greenhouse|lever|"
    r"icims|successfactors|bamboohr|rippling|gusto|justworks|deel|remote\.com|"
    r"ashby|smartrecruiters|jobvite|taleo|oracle|sap\b", re.I)

# Tools that produce fine documents but are not offer-letter systems. Their
# presence is context, not an accusation: plenty of real small employers send a
# Word export.
GENERIC_PRODUCERS = re.compile(
    r"microsoft|word|libreoffice|openoffice|pages|google|canva|photoshop|"
    r"illustrator|indesign|ilovepdf|smallpdf|pdfescape|sejda|foxit|"
    r"wkhtmltopdf|reportlab|tcpdf|fpdf|itext|skia|quartz|cairo", re.I)

MONEY = re.compile(r"[$€£]\s?[\d,]+(\.\d{2})?|\b\d{2,3},\d{3}\b|\bper\s+(annum|year|hour)\b", re.I)
DATEISH = re.compile(r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
                     r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2})\b", re.I)
NAMEISH = re.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b")

SENSITIVE_FIELD = "name, salary or date"


@dataclass
class _LineGroup:
    page: int
    spans: list[Span]
    y: float


def _group_lines(spans: list[Span]) -> list[_LineGroup]:
    """Group spans into visual lines by page and baseline proximity."""
    out: list[_LineGroup] = []
    for sp in spans:
        if sp.hidden or not sp.text.strip():
            continue
        y = round((sp.bbox[1] + sp.bbox[3]) / 2, 0)
        for g in out:
            if g.page == sp.page and abs(g.y - y) <= 2.5:
                g.spans.append(sp)
                break
        else:
            out.append(_LineGroup(sp.page, [sp], y))
    return out


def _what_field(text: str) -> str | None:
    if MONEY.search(text):
        return "a monetary amount"
    if DATEISH.search(text):
        return "a date"
    if NAMEISH.search(text):
        return "a personal or company name"
    return None


def _document_body_style(spans: list[Span]) -> tuple[str, float] | None:
    """The document's dominant body style, weighted by characters set in it.

    Anchoring on the *document* rather than the line is what makes short lines
    work. On "Dear <name>," a replaced 14-character name outweighs the 5
    characters around it, so a per-line vote elects the forgery as the norm and
    flags the original. The document-wide body font cannot be swung that way:
    a forger edits a field, not every paragraph.
    """
    styles: Counter = Counter()
    for sp in spans:
        if sp.hidden:
            continue
        body = sp.text.strip()
        if body:
            styles[(sp.font, round(sp.size, 1))] += len(body)
    if not styles:
        return None
    (font, size), _ = styles.most_common(1)[0]
    return font, size


def _same_family(a: str, b: str) -> bool:
    return a.split("-")[0].split(",")[0].lower() == b.split("-")[0].split(",")[0].lower()


def check_font_consistency(spans: list[Span]) -> list[Finding]:
    """Flag spans that deviate from the document's body style mid-line."""
    base = _document_body_style(spans)
    if base is None:
        return []
    body_font, body_size = base

    findings: list[Finding] = []

    for group in _group_lines(spans):
        if len(group.spans) < 2:
            continue

        # Only consider lines that are *mostly* body text. A heading set
        # entirely in another face is design, not an edit; a line mixing body
        # text with something else is where a substitution shows.
        on_style = [sp for sp in group.spans
                    if (sp.font, round(sp.size, 1)) == (body_font, body_size)]
        if not on_style:
            continue

        for sp in group.spans:
            font, size = sp.font, round(sp.size, 1)
            if (font, size) == (body_font, body_size):
                continue
            text = sp.text.strip()
            if len(text) < 2:
                continue

            same_family = _same_family(font, body_font)
            size_delta = abs(size - body_size)
            if same_family and size_delta < 0.6:
                continue  # ordinary bold/italic emphasis

            field = _what_field(text)
            if field and not same_family:
                sev, conf = Severity.HIGH, 0.8
            elif field:
                sev, conf = Severity.MEDIUM, 0.65
            elif not same_family and size_delta >= 1.0:
                sev, conf = Severity.MEDIUM, 0.55
            else:
                sev, conf = Severity.LOW, 0.4

            findings.append(Finding(
                code="DOC_FONT_INCONSISTENCY",
                title=("Text inconsistent with the document's body style"
                       + (f" — it contains {field}" if field else "")),
                severity=sev,
                layer=Layer.VISIBLE,
                detail=(
                    f"On page {group.page}, {text[:60]!r} is set in {font} at "
                    f"{size}pt, while this document's body text is {body_font} "
                    f"at {body_size}pt — and it sits on a line that is otherwise "
                    f"body text. A document produced in one pass by one system "
                    f"is typographically consistent. A mismatch means this text "
                    f"was placed separately."
                    + (f" It contains {field}, one of the fields most often "
                       f"altered when a document is reused." if field else "")
                    + " Filling a template by hand produces the same signature "
                      "as altering one, so this shows an edit — not who made it "
                      "or why."
                ),
                evidence=f"{text[:70]!r}  [{font} {size}pt]  vs body [{body_font} {body_size}pt]",
                location=f"page {group.page}",
                confidence=conf,
                remediation=(
                    "Confirm this value through a channel you chose — a phone "
                    "number you looked up yourself, not one from the document."
                ),
                meta={"span_font": font, "span_size": size,
                      "body_font": body_font, "body_size": body_size,
                      "field": field, "text": text[:120]},
            ))
    return findings


def check_overlays(spans: list[Span]) -> list[Finding]:
    """Detect text drawn on top of other text: the 'white-out and retype' edit."""
    findings: list[Finding] = []
    by_page: dict[int, list[Span]] = {}
    for sp in spans:
        if sp.text.strip():
            by_page.setdefault(sp.page, []).append(sp)

    for page, items in by_page.items():
        for i, a in enumerate(items):
            for b in items[i + 1:]:
                ax0, ay0, ax1, ay1 = a.bbox
                bx0, by0, bx1, by1 = b.bbox
                ox = min(ax1, bx1) - max(ax0, bx0)
                oy = min(ay1, by1) - max(ay0, by0)
                if ox <= 1 or oy <= 1:
                    continue
                area_a = max(1e-6, (ax1 - ax0) * (ay1 - ay0))
                area_b = max(1e-6, (bx1 - bx0) * (by1 - by0))
                overlap_frac = (ox * oy) / min(area_a, area_b)
                if overlap_frac < 0.6:
                    continue
                if a.text.strip() == b.text.strip():
                    continue  # duplicate render of the same string

                findings.append(Finding(
                    code="DOC_TEXT_OVERLAY",
                    title="Two different pieces of text occupy the same position",
                    severity=Severity.HIGH,
                    layer=Layer.VISIBLE,
                    detail=(
                        f"On page {page}, {a.text.strip()[:40]!r} and "
                        f"{b.text.strip()[:40]!r} are drawn over each other "
                        f"({overlap_frac:.0%} overlap). Only one is legible to a "
                        f"reader; both are extracted by software. This is the "
                        f"signature of a value being covered over and replaced."
                    ),
                    evidence=f"{a.text.strip()[:50]!r} ⟷ {b.text.strip()[:50]!r}",
                    location=f"page {page}",
                    confidence=0.85,
                    remediation="Both values are recoverable from the file. "
                                "Compare them before trusting either.",
                    meta={"a": a.text[:80], "b": b.text[:80],
                          "overlap": round(overlap_frac, 2)},
                ))
                if len(findings) >= 6:
                    return findings
    return findings


def check_provenance(metadata: dict) -> list[Finding]:
    """What software wrote this file, and is that plausible for an offer letter?"""
    producer = " ".join(str(metadata.get(k, "") or "") for k in ("producer", "creator"))
    if not producer.strip():
        return [Finding(
            code="DOC_NO_PROVENANCE",
            title="Document records no producing software",
            severity=Severity.LOW,
            layer=Layer.METADATA,
            detail=("This PDF carries no Producer or Creator string. Most tools "
                    "write one. Absence can mean the metadata was stripped, "
                    "which is itself a deliberate act, though some converters "
                    "simply omit it."),
            evidence="producer/creator: (empty)",
            confidence=0.5,
            remediation="Weigh alongside the other findings.",
        )]

    if KNOWN_HR_PRODUCERS.search(producer):
        return [Finding(
            code="DOC_HR_PROVENANCE",
            title="Produced by a recognised HR or e-signature platform",
            severity=Severity.INFO,
            layer=Layer.METADATA,
            detail=(f"The document reports being produced by {producer.strip()!r}, "
                    f"which is a system genuinely used to issue offer letters. "
                    f"This is a positive signal, but metadata can be forged — it "
                    f"is not proof."),
            evidence=producer.strip()[:120],
            confidence=0.6,
            remediation="Consistent with a real offer. Still confirm the sender.",
        )]

    if GENERIC_PRODUCERS.search(producer):
        return [Finding(
            code="DOC_GENERIC_PROVENANCE",
            title="Produced by general-purpose software, not an HR system",
            severity=Severity.LOW,
            layer=Layer.METADATA,
            detail=(f"This file reports being produced by {producer.strip()!r}. "
                    f"Real employers do sometimes send a Word or Pages export, "
                    f"so this is context rather than a problem — but a formal "
                    f"offer from a larger company usually comes through an "
                    f"e-signature platform."),
            evidence=producer.strip()[:120],
            confidence=0.5,
            remediation="Expect a countersigning link from a real platform. Ask "
                        "if none arrives.",
        )]
    return []
