"""Unicode-layer attacks on a document.

These are the attacks that survive copy-paste. A recruiter's ATS extracts text
from the PDF, hands it to a model, and the payload arrives intact because the
characters carrying it are ones no viewer renders.
"""

from __future__ import annotations

import re
import unicodedata

from .findings import Finding, Layer, Severity, escape_invisibles

# ---------------------------------------------------------------------------
# Character classes
# ---------------------------------------------------------------------------

# The Unicode Tag block. Every ASCII character has a mirror here. Text encoded
# in it is invisible in literally every renderer, but tokenizes normally for an
# LLM. This is the cleanest prompt-injection carrier that exists today, and
# there is no legitimate reason for it to appear in a resume.
TAG_BLOCK = range(0xE0000, 0xE0080)

ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "­": "SOFT HYPHEN",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
}

# Trojan Source. Bidi overrides let the visual order of a line differ from its
# logical order, so what a human reads and what a parser reads diverge.
BIDI_CONTROLS = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}

# Non-Latin codepoints that are visually identical to a Latin letter. Used to
# break exact-match keyword filters while looking normal to a human, and to
# spoof a company or domain name.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "А": "A", "В": "B", "Е": "E",
    "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "І": "I", "ј": "j",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "υ": "u",
    "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Η": "H",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T",
    "Χ": "X", "ԁ": "d", "ԛ": "q", "ɡ": "g",
}

_LATIN_WORD = re.compile(r"[A-Za-z]")


def decode_tag_block(text: str) -> str:
    """Decode Unicode Tag characters back to the ASCII they smuggle."""
    return "".join(
        chr(ord(ch) - 0xE0000) for ch in text if ord(ch) in TAG_BLOCK
    )


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _context(text: str, index: int, width: int = 60) -> str:
    lo = max(0, index - width)
    hi = min(len(text), index + width)
    return escape_invisibles(text[lo:hi])


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_tag_block(text: str) -> list[Finding]:
    hits = [(i, ch) for i, ch in enumerate(text) if ord(ch) in TAG_BLOCK]
    if not hits:
        return []

    payload = decode_tag_block(text)
    printable = "".join(c for c in payload if c.isprintable()).strip()

    return [
        Finding(
            code="UNICODE_TAG_SMUGGLING",
            title="Invisible text smuggled via Unicode Tag characters",
            severity=Severity.CRITICAL,
            layer=Layer.HIDDEN,
            detail=(
                f"Found {len(hits)} characters from the Unicode Tag block "
                "(U+E0000–U+E007F). These are invisible in every PDF viewer, "
                "browser and text editor, but are preserved verbatim when text "
                "is extracted and passed to a language model. There is no "
                "legitimate use of this block in a resume."
            ),
            evidence=(
                f"Decoded hidden payload: {printable!r}" if printable
                else f"{len(hits)} tag characters, no printable payload"
            ),
            location=f"line {_line_of(text, hits[0][0])}, char offset {hits[0][0]}",
            confidence=1.0,
            remediation=(
                "Treat as deliberate manipulation of automated screening. The "
                "decoded payload shows intent; review it before any decision."
            ),
            meta={"count": len(hits), "decoded_payload": payload},
        )
    ]


def check_zero_width(text: str) -> list[Finding]:
    counts: dict[str, int] = {}
    first: dict[str, int] = {}
    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            counts[ch] = counts.get(ch, 0) + 1
            first.setdefault(ch, i)
    if not counts:
        return []

    total = sum(counts.values())
    # A stray BOM or a few soft hyphens are normal artifacts of Word and of
    # copy-pasting from the web. A dense run is a carrier.
    if total <= 3 and set(counts) <= {"﻿", "­"}:
        severity, detail_suffix = Severity.INFO, (
            " This volume is consistent with ordinary word-processor output and "
            "is very likely benign."
        )
    elif total >= 20:
        severity, detail_suffix = Severity.HIGH, (
            " This density is not produced by normal editing; it is consistent "
            "with a deliberately encoded payload or with watermarking."
        )
    else:
        severity, detail_suffix = Severity.LOW, ""

    breakdown = ", ".join(f"{ZERO_WIDTH[c]}×{n}" for c, n in sorted(counts.items()))
    worst = max(counts, key=lambda c: counts[c])
    return [
        Finding(
            code="ZERO_WIDTH_CHARS",
            title="Zero-width characters present in document text",
            severity=severity,
            layer=Layer.HIDDEN,
            detail=(
                f"Found {total} zero-width or invisible formatting characters "
                f"({breakdown})." + detail_suffix
            ),
            evidence=_context(text, first[worst]),
            location=f"first at line {_line_of(text, first[worst])}",
            confidence=1.0,
            remediation=(
                "Low counts are usually harmless. Review only if paired with "
                "other integrity findings."
                if severity in (Severity.INFO, Severity.LOW)
                else "Extract and inspect the encoded sequence before proceeding."
            ),
            meta={"total": total, "breakdown": {ZERO_WIDTH[c]: n for c, n in counts.items()}},
        )
    ]


def check_bidi(text: str) -> list[Finding]:
    hits = [(i, ch) for i, ch in enumerate(text) if ch in BIDI_CONTROLS]
    if not hits:
        return []

    # Overrides are the dangerous subset; isolates appear legitimately in
    # documents that genuinely mix scripts (an Arabic or Hebrew name).
    overrides = [h for h in hits if h[1] in ("‭", "‮")]
    has_rtl_script = any(
        unicodedata.bidirectional(c) in ("R", "AL") for c in text
    )

    if overrides:
        sev = Severity.HIGH
    elif has_rtl_script:
        sev = Severity.INFO
    else:
        sev = Severity.MEDIUM

    names = ", ".join(sorted({BIDI_CONTROLS[ch] for _, ch in hits}))
    return [
        Finding(
            code="BIDI_CONTROL_CHARS",
            title="Bidirectional control characters present",
            severity=sev,
            layer=Layer.HIDDEN,
            detail=(
                f"Found {len(hits)} bidirectional control characters ({names}). "
                "These can make the visually rendered order of a line differ "
                "from the logical order that text extraction produces, so a "
                "human reviewer and an automated parser can read different "
                "content from the same line (the 'Trojan Source' technique)."
                + (
                    " This document also contains right-to-left script, so these "
                    "controls are most likely legitimate."
                    if sev is Severity.INFO else ""
                )
            ),
            evidence=_context(text, hits[0][0]),
            location=f"first at line {_line_of(text, hits[0][0])}",
            confidence=0.95,
            remediation=(
                "Compare the rendered PDF against the extracted text for the "
                "affected lines."
            ),
            meta={"count": len(hits), "overrides": len(overrides)},
        )
    ]


def check_homoglyphs(text: str) -> list[Finding]:
    """Flag non-Latin lookalikes only when they sit inside otherwise-Latin words.

    Scanning for the characters alone would flag every resume written in
    Russian or Greek. The attack signature is *mixing*: a single Cyrillic 'е'
    inside an otherwise ASCII word.
    """
    suspects: list[tuple[str, str, int]] = []  # (word, char, index)

    for match in re.finditer(r"\S+", text):
        word = match.group()
        mixed = [ch for ch in word if ch in HOMOGLYPHS]
        if not mixed:
            continue
        if not _LATIN_WORD.search(word):
            continue  # wholly non-Latin word: a real name, not an attack
        suspects.append((word, mixed[0], match.start()))

    if not suspects:
        return []

    sample = ", ".join(
        f"{w!r} (contains {unicodedata.name(c, '?')} posing as {HOMOGLYPHS[c]!r})"
        for w, c, _ in suspects[:4]
    )
    return [
        Finding(
            code="HOMOGLYPH_SUBSTITUTION",
            title="Non-Latin lookalike characters inside Latin words",
            severity=Severity.HIGH if len(suspects) > 2 else Severity.MEDIUM,
            layer=Layer.VISIBLE,
            detail=(
                f"{len(suspects)} word(s) mix Latin letters with visually "
                "identical characters from another script. A human sees a normal "
                "word; an exact-match keyword filter, a deduplication check or a "
                "domain comparison sees a different string. This is the standard "
                "technique for both filter evasion and brand impersonation."
            ),
            evidence=sample,
            location=f"first at line {_line_of(text, suspects[0][2])}",
            confidence=0.9,
            remediation=(
                "Normalise the text and re-run keyword matching. If the affected "
                "words are employer or domain names, treat as impersonation."
            ),
            meta={"count": len(suspects), "words": [w for w, _, _ in suspects[:20]]},
        )
    ]


def run_all(text: str) -> list[Finding]:
    return [
        *check_tag_block(text),
        *check_zero_width(text),
        *check_bidi(text),
        *check_homoglyphs(text),
    ]
