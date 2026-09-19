"""Offer-letter tampering detection.

A forged offer letter is usually a real one with fields swapped. That edit
leaves a typographic fingerprint. The control document — a small employer
filling a template by hand — leaves the *same* fingerprint for an innocent
reason, so it is here as a release gate: the tool must report the edit without
escalating it to fraud.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from groundtruth.integrity import Severity, scan_pdf  # noqa: E402
from groundtruth.integrity.pdf_layers import extract  # noqa: E402
from groundtruth.integrity.tampering import (  # noqa: E402
    _document_body_style, check_font_consistency, check_provenance)

OFFERS = pathlib.Path(__file__).resolve().parents[2] / "samples" / "offers"


def spans_of(stem: str):
    return extract(str(OFFERS / f"{stem}.pdf")).spans


@pytest.mark.parametrize("stem", [
    "02_salary_tampered", "03_name_tampered", "04_whiteout_overlay",
])
def test_doctored_offers_are_flagged(stem):
    r = scan_pdf(str(OFFERS / f"{stem}.pdf"))
    assert r.verdict == "manipulated"
    assert r.max_severity >= Severity.HIGH


def test_genuine_offer_is_clean_with_positive_provenance():
    r = scan_pdf(str(OFFERS / "01_genuine_offer.pdf"))
    assert r.verdict == "clean"
    assert any(f.code == "DOC_HR_PROVENANCE" for f in r.findings)


def test_hand_filled_template_is_not_escalated_to_fraud():
    """Release gate: an innocent cause of the same signature stays low."""
    r = scan_pdf(str(OFFERS / "05_control_hand_filled.pdf"))
    assert r.verdict == "clean"
    assert r.max_severity < Severity.MEDIUM


def test_altered_salary_is_named_as_a_monetary_field():
    f = next(f for f in check_font_consistency(spans_of("02_salary_tampered"))
             if f.meta.get("field"))
    assert f.meta["field"] == "a monetary amount"
    assert "310,000" in f.meta["text"]
    assert f.severity is Severity.HIGH


def test_altered_name_is_identified_not_the_surrounding_text():
    """Regression: a per-line style vote elected the forged span as the norm
    and flagged the original 'Dear' instead. The baseline is document-wide."""
    findings = check_font_consistency(spans_of("03_name_tampered"))
    flagged = {f.meta["text"] for f in findings}
    assert any("Priya Raghavan" in t for t in flagged)
    assert not any(t.strip() == "Dear" for t in flagged)


def test_document_body_style_is_the_majority_face():
    font, size = _document_body_style(spans_of("01_genuine_offer"))
    assert font.startswith("Helvetica")
    assert size == pytest.approx(11.0, abs=0.1)


def test_overlay_recovers_both_values():
    r = scan_pdf(str(OFFERS / "04_whiteout_overlay.pdf"))
    f = next(f for f in r.findings if f.code == "DOC_TEXT_OVERLAY")
    # The covered original and the value typed over it are both recoverable.
    assert "295,000" in (f.meta["a"] + f.meta["b"])
    assert f.severity is Severity.HIGH


def test_findings_describe_the_edit_without_alleging_fraud():
    r = scan_pdf(str(OFFERS / "02_salary_tampered.pdf"))
    f = next(f for f in r.findings if f.code == "DOC_FONT_INCONSISTENCY")
    assert "not who made it or why" in f.detail
    for word in ("fraud", "forged", "fake", "scam"):
        assert word not in f.detail.lower()


def test_provenance_tiers():
    assert check_provenance({"producer": "DocuSign Envelope Generator"})[0].code \
        == "DOC_HR_PROVENANCE"
    assert check_provenance({"producer": "Canva"})[0].code == "DOC_GENERIC_PROVENANCE"
    assert check_provenance({})[0].code == "DOC_NO_PROVENANCE"


def test_resume_corpus_unaffected_by_tampering_checks():
    """The new checks run on every PDF; they must not disturb the resume gates."""
    resumes = pathlib.Path(__file__).resolve().parents[2] / "samples" / "resumes"
    for stem in ("01_clean", "07_control_security_engineer"):
        r = scan_pdf(str(resumes / f"{stem}.pdf"))
        assert r.verdict == "clean", f"{stem} regressed to {r.verdict}"
