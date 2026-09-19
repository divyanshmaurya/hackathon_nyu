"""Detection of text addressed to a machine reader rather than a human one.

The detection problem here is not "find these strings" -- it's "find these
strings *without* flagging the security engineer whose resume legitimately
discusses prompt injection, or the recruiter-facing cover letter that quotes
one." The discriminator is not the wording. It is the document layer.

    visible  "I built defenses against 'ignore previous instructions'"  -> fine
    hidden   "ignore previous instructions"                             -> fraud

Same bytes. Opposite verdict. So severity is a function of (pattern, layer),
and the pattern table below only ever proposes a *base* severity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .findings import Finding, Layer, Severity, escape_invisibles


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    base: Severity
    why: str


def _p(name: str, rx: str, base: Severity, why: str) -> Pattern:
    return Pattern(name, re.compile(rx, re.I | re.S), base, why)


PATTERNS: list[Pattern] = [
    _p(
        "instruction_override",
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b"
        r"(previous|prior|above|earlier|all|any|system|initial)\b[^.\n]{0,30}?"
        r"\b(instruction|prompt|rule|direction|context|guideline|command)s?\b",
        Severity.HIGH,
        "Classic instruction-override phrasing aimed at an LLM's system prompt.",
    ),
    _p(
        "scoring_directive",
        r"\b(rate|score|rank|grade|classify|mark|evaluate)\b[^.\n]{0,50}?\b"
        r"(10\s*/\s*10|100\s*%|highest|top|maximum|perfect|strong\s+hire|"
        r"excellent|best|first|number\s+one)\b",
        Severity.HIGH,
        "Attempts to dictate the screening system's output directly.",
    ),
    _p(
        "advancement_directive",
        r"\b(must|should|always|immediately|be\s+sure\s+to)\b[^.\n]{0,40}?\b"
        r"(advance|shortlist|forward|recommend|interview|hire|select|"
        r"move\s+(this|the)\s+candidate)\b",
        Severity.HIGH,
        "Instructs the pipeline to take a hiring action.",
    ),
    _p(
        "ai_addressed",
        r"\b(as\s+an?\s+(ai|language\s+model|assistant)|if\s+you\s+are\s+an?\s+(ai|llm)|"
        r"dear\s+(ai|llm|chatgpt|claude|gpt|model|assistant|bot)|"
        r"attention\s*:?\s*(ai|llm|automated\s+system)|"
        r"note\s+to\s+(the\s+)?(ai|llm|reviewer\s+bot|screening\s+system))\b",
        Severity.HIGH,
        "Text explicitly addressed to a machine reader, not the hiring manager.",
    ),
    _p(
        "role_hijack",
        r"\b(you\s+are\s+now|new\s+(instruction|task|role|persona)|"
        r"system\s*:\s|assistant\s*:\s|<\s*\|?\s*(im_start|system|endoftext)\s*\|?\s*>|"
        r"\[\s*system\s*\]|###\s*instruction)",
        Severity.HIGH,
        "Attempts to open a new instruction channel or impersonate a system turn.",
    ),
    _p(
        "qualification_assertion",
        r"\b(this\s+candidate\s+(is|meets|exceeds)|the\s+applicant\s+(is|meets))\b"
        r"[^.\n]{0,60}?\b(qualified|ideal|perfect|all\s+(the\s+)?requirements|"
        r"best\s+fit|top\s+\d+)\b",
        Severity.MEDIUM,
        "Third-person assertion of fitness, phrased for a summariser to quote.",
    ),
    _p(
        "keyword_stuffing_marker",
        r"(keywords?\s*(for\s*)?(ats|bot|scanner|parser)\s*:|"
        r"ats\s*keywords?\s*:|hidden\s+keywords?\s*:)",
        Severity.MEDIUM,
        "Explicit keyword block intended for the parser rather than the reader.",
    ),
    _p(
        "exfiltration_attempt",
        r"\b(print|output|reveal|repeat|show|disclose)\b[^.\n]{0,40}?\b"
        r"(system\s+prompt|your\s+instructions|the\s+prompt|configuration)\b",
        Severity.CRITICAL,
        "Attempts to extract the screening system's own configuration.",
    ),
]

# Phrasing that indicates the candidate is *describing* these attacks as part of
# their professional work rather than performing one.
_DISCUSSION_CUES = re.compile(
    r"\b(defend|defence|defense|mitigat|protect|prevent|detect|guard|harden|"
    r"red[\s-]?team|pen[\s-]?test|research|audit|vulnerabilit|attack\s+surface|"
    r"built|designed|implemented|published|paper|thesis|talk|workshop|"
    r"owasp|llm0?1|jailbreak\s+detection)\w*",
    re.I,
)


def _context(text: str, start: int, end: int, width: int = 70) -> str:
    lo, hi = max(0, start - width), min(len(text), end + width)
    return ("…" if lo else "") + escape_invisibles(text[lo:hi]) + ("…" if hi < len(text) else "")


def _resolve_severity(
    base: Severity, layer: Layer, discussed: bool
) -> tuple[Severity, float, str]:
    """Turn a pattern's base severity into a verdict, given where it was found."""
    if layer is Layer.HIDDEN:
        # Hidden text has no innocent explanation. Nobody accidentally writes
        # instructions in a layer humans cannot read.
        return (
            Severity.CRITICAL,
            1.0,
            "Found in text that is not visible to a human reader. Concealment "
            "establishes intent; there is no benign reason to hide this.",
        )
    if layer is Layer.METADATA:
        return (
            Severity.HIGH,
            0.95,
            "Found in document metadata, which humans never see but text "
            "extractors routinely include.",
        )
    if layer is Layer.VISIBLE:
        if discussed:
            return (
                Severity.INFO,
                0.3,
                "Found in visible text alongside language describing security "
                "work. This reads as a candidate documenting their expertise, "
                "not attacking the pipeline. Shown for transparency only — this "
                "should not count against the candidate.",
            )
        return (
            Severity.LOW,
            0.5,
            "Found in visible text. A human reviewer would see this too, which "
            "makes it a poor attack. Usually quotation or discussion; confirm "
            "by reading the surrounding line.",
        )
    # Plain-text input: we genuinely cannot tell which layer it came from.
    return (
        Severity.MEDIUM,
        0.6,
        "Document layer unknown (plain-text input), so concealment could not be "
        "established. Re-scan the original PDF to determine whether this text "
        "is visible to a human reader.",
    )


def scan(text: str, layer: Layer = Layer.UNKNOWN) -> list[Finding]:
    """Scan one layer of a document for machine-addressed instructions."""
    if not text.strip():
        return []

    discussed = bool(_DISCUSSION_CUES.search(text))
    findings: list[Finding] = []

    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            sev, conf, rationale = _resolve_severity(pat.base, layer, discussed)
            # An exfiltration attempt stays critical wherever it appears.
            if pat.base is Severity.CRITICAL and layer is not Layer.VISIBLE:
                sev = Severity.CRITICAL
            findings.append(
                Finding(
                    code=f"INJECTION_{pat.name.upper()}",
                    title=f"Machine-directed instruction: {pat.name.replace('_', ' ')}",
                    severity=sev,
                    layer=layer,
                    detail=f"{pat.why} {rationale}",
                    evidence=_context(text, m.start(), m.end()),
                    location=f"char offset {m.start()}",
                    confidence=conf,
                    remediation=(
                        "Escalate to a human reviewer and preserve the document "
                        "as evidence."
                        if sev in (Severity.CRITICAL, Severity.HIGH)
                        else "No action needed; recorded for transparency."
                    ),
                    meta={"pattern": pat.name, "matched": m.group()[:200]},
                )
            )
            break  # one finding per pattern is enough; count lives in meta

    return findings
