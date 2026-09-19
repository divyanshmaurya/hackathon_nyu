"""The integrity axis: is this document weaponised?

Deterministic end to end. No model is consulted, so the output is stable,
reproducible, cheap, and defensible to a candidate who asks why they were
flagged. That last property is the one that matters: we can show them the
bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import injection, unicode_checks
from .findings import Finding, Layer, Severity
from .pdf_layers import PdfLayers, extract as extract_pdf


@dataclass
class IntegrityReport:
    verdict: str                      # clean | review | manipulated
    headline: str
    findings: list[Finding] = field(default_factory=list)
    hidden_text: str = ""
    visible_text: str = ""
    layers_available: bool = True
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "headline": self.headline,
            "max_severity": self.max_severity.value,
            "layers_available": self.layers_available,
            "hidden_text_preview": self.hidden_text[:500],
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }


def _hidden_text_finding(layers: PdfLayers) -> list[Finding]:
    """Report the existence of a hidden text layer, independent of content.

    Worth its own finding: hidden text that says nothing suspicious is still
    hidden text, and the recruiter should know the document has a second layer.
    """
    hidden_spans = [s for s in layers.spans if s.hidden]
    if not hidden_spans:
        return []

    content = " ".join(s.text for s in hidden_spans).strip()
    if not content:
        return []

    reason_counts: dict[str, int] = {}
    for s in hidden_spans:
        for r in s.reasons:
            key = r.split("(")[0].split("rgb")[0].strip().rstrip(":")
            reason_counts[key] = reason_counts.get(key, 0) + 1
    why = "; ".join(f"{k} ({n} span{'s' if n > 1 else ''})"
                    for k, n in sorted(reason_counts.items(), key=lambda kv: -kv[1]))

    words = len(content.split())
    severity = Severity.HIGH if words >= 8 else Severity.MEDIUM

    return [
        Finding(
            code="HIDDEN_TEXT_LAYER",
            title="Document contains text a human reader cannot see",
            severity=severity,
            layer=Layer.HIDDEN,
            detail=(
                f"{len(hidden_spans)} text span(s) totalling {words} words are "
                f"present in the document's text stream but are not rendered "
                f"visibly. Cause: {why}. Applicant tracking systems extract this "
                "text and pass it downstream exactly as if it were visible."
            ),
            evidence=content[:400] + ("…" if len(content) > 400 else ""),
            location=f"page(s) {sorted({s.page for s in hidden_spans})}",
            confidence=0.98,
            remediation=(
                "Read the hidden content above. Scanned documents with an OCR "
                "layer are a benign cause; a keyword block or instructions are "
                "not."
            ),
            meta={
                "span_count": len(hidden_spans),
                "word_count": words,
                "reasons": reason_counts,
            },
        )
    ]


def _decide(findings: list[Finding]) -> tuple[str, str]:
    worst = max((f.severity for f in findings), default=Severity.INFO)
    actionable = [f for f in findings if f.severity >= Severity.MEDIUM]

    if worst is Severity.CRITICAL:
        return (
            "manipulated",
            "This document contains concealed instructions aimed at automated "
            "screening. Concealment is deliberate — route to a human reviewer.",
        )
    if worst is Severity.HIGH:
        return (
            "manipulated",
            f"{len(actionable)} high-severity integrity issue(s) found, including "
            "content hidden from human readers. Review before scoring.",
        )
    if worst is Severity.MEDIUM:
        return (
            "review",
            "Minor document anomalies found. Most have benign explanations; "
            "confirm before treating as intentional.",
        )
    return (
        "clean",
        "No document manipulation detected. Note that this axis says nothing "
        "about whether the content is accurate — see Corroboration.",
    )


def scan_text(text: str, layer: Layer = Layer.UNKNOWN) -> IntegrityReport:
    """Scan a flat string. Used for pasted text and non-PDF inputs."""
    findings = [*unicode_checks.run_all(text), *injection.scan(text, layer)]
    verdict, headline = _decide(findings)
    return IntegrityReport(
        verdict=verdict,
        headline=headline,
        findings=sorted(findings, key=lambda f: (-f.severity.rank, f.code)),
        visible_text=text,
        layers_available=False,
        stats={"chars": len(text), "words": len(text.split())},
    )


def scan_pdf(path_or_bytes: str | bytes) -> IntegrityReport:
    """Full layer-aware scan of a PDF. This is the real entry point."""
    layers = extract_pdf(path_or_bytes)

    if not layers.available:
        return IntegrityReport(
            verdict="review",
            headline=layers.note,
            findings=[],
            layers_available=False,
        )

    findings: list[Finding] = []

    # Unicode attacks are layer-independent: scan the whole stream once.
    combined = "\n".join(
        t for t in (layers.visible_text, layers.hidden_text, layers.metadata_text) if t
    )
    findings += unicode_checks.run_all(combined)

    # Injection is layer-dependent: this is where severity is earned.
    findings += _hidden_text_finding(layers)
    findings += injection.scan(layers.hidden_text, Layer.HIDDEN)
    findings += injection.scan(layers.metadata_text, Layer.METADATA)
    findings += injection.scan(layers.visible_text, Layer.VISIBLE)

    verdict, headline = _decide(findings)

    return IntegrityReport(
        verdict=verdict,
        headline=headline,
        findings=sorted(findings, key=lambda f: (-f.severity.rank, f.code)),
        hidden_text=layers.hidden_text,
        visible_text=layers.visible_text,
        layers_available=True,
        stats={
            "pages": layers.page_count,
            "spans": len(layers.spans),
            "hidden_spans": sum(1 for s in layers.spans if s.hidden),
            "visible_words": len(layers.visible_text.split()),
            "hidden_words": len(layers.hidden_text.split()),
            "metadata_keys": sorted(k for k, v in layers.metadata.items() if v),
        },
    )
