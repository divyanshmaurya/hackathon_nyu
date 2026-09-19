"""Candidate-side tests: is the recruiter contacting you who they claim, and is
what they're asking for something a legitimate employer would ask?

As with the integrity axis, the negative controls are the release gates. This
tool exists to protect job seekers from predatory intermediaries — if it flags
ordinary recruiter outreach, it trains people to ignore it, and then it protects
nobody.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from groundtruth.integrity.findings import Severity  # noqa: E402
from groundtruth.outreach.domains import analyse, domain_of, registrable_parts  # noqa: E402
from groundtruth.outreach.practices import scan  # noqa: E402


# ------------------------------------------------------------------ parsing ---

@pytest.mark.parametrize("raw,expected", [
    ("recruiter@careers.google.com", "careers.google.com"),
    ("https://apply.acme.io/jobs/123?x=1", "apply.acme.io"),
    ("HR@Example.COM", "example.com"),
])
def test_domain_extraction(raw, expected):
    assert domain_of(raw) == expected


def test_two_part_suffix_handled():
    assert registrable_parts("careers.google.co.uk") == ("google", "co.uk")


# --------------------------------------------------------------- imitation ---

def test_verified_domain_matches():
    v = analyse("careers@google.com", "Google", known_domain="google.com")
    assert v.verdict == "matches_claim"
    assert v.max_severity is Severity.INFO


def test_subdomain_of_verified_domain_matches():
    v = analyse("hr@jobs.google.com", "Google", known_domain="google.com")
    assert v.verdict == "matches_claim"


def test_cyrillic_homoglyph_domain_is_critical():
    v = analyse("recruiter@gооgle.com", "Google")
    assert v.verdict == "lookalike"
    assert v.max_severity is Severity.CRITICAL
    assert any(f.code == "DOMAIN_CONFUSABLE_IMITATION" for f in v.findings)


def test_brand_in_subdomain_identifies_real_owner():
    v = analyse("hr@google.com.hiring-portal.xyz", "Google")
    f = next(f for f in v.findings if f.code == "DOMAIN_BRAND_IN_SUBDOMAIN")
    assert f.severity is Severity.CRITICAL
    # The whole point is telling the user who actually controls the domain.
    assert f.meta["registrable"] == "hiring-portal.xyz"


def test_combosquat_not_misreported_as_subdomain_attack():
    # Regression: the brand is in the registrable name here, not the subdomain.
    v = analyse("jobs@googlecareers.com", "Google")
    codes = {f.code for f in v.findings}
    assert "DOMAIN_COMBOSQUAT" in codes
    assert "DOMAIN_BRAND_IN_SUBDOMAIN" not in codes


def test_typosquat_detected():
    v = analyse("hr@gogle.com", "Google")
    assert any(f.code == "DOMAIN_TYPOSQUAT" for f in v.findings)


def test_disposable_mail_is_critical():
    v = analyse("hr@mailinator.com", "Meta")
    assert any(f.code == "DOMAIN_DISPOSABLE_MAIL" for f in v.findings)


def test_free_mail_is_flagged_but_not_called_fraud():
    v = analyse("recruiter@gmail.com", "Google")
    f = next(f for f in v.findings if f.code == "DOMAIN_FREE_MAIL")
    assert f.severity is Severity.HIGH
    # Small legitimate firms do this; the wording must not assert fraud.
    assert "not proof of fraud" in f.detail


def test_unrelated_agency_domain_is_medium_not_an_accusation():
    """An agency writing from its own domain is normal, not an attack."""
    v = analyse("talent@apexrecruiting.com", "Google")
    assert v.verdict == "unrelated"
    assert v.max_severity is Severity.MEDIUM


# --------------------------------------------------------------- practices ---

OPT_SCAM = """Congratulations! You have been selected for a role with a leading Fortune
500 client. No interview is required. We charge a one-time registration fee of $1,500.
Don't worry if you lack experience - we will create work experience letters for you so
your OPT requirements are met. You will be on bench until we find a client project;
salary starts once billing begins. Please share your SSN, passport copy and I-20 today.
Payment can be made via Zelle. This offer expires in 24 hours. Contact us on WhatsApp."""

LEGIT_DIRECT = """Hi Alex, I'm a recruiter at Datadog. I came across your GitHub and
wanted to ask if you'd be open to chatting about our Platform Engineering team. Happy to
share the job description and set up a 30-minute call next week. No pressure if the
timing isn't right."""

LEGIT_AGENCY = """Hi, I'm with Apex Recruiting. We're working with a client in fintech on
a backend role, contract-to-hire, $75-85/hr W2. Before I share the client name I'd need
you to confirm you're interested. Let me know and I'll send the full JD."""


def test_opt_consultancy_scam_is_caught_across_tiers():
    r = scan(OPT_SCAM)
    codes = {f.code for f in r.findings}
    assert r.max_severity is Severity.CRITICAL
    for expected in (
        "PRACTICE_FEE_TO_CANDIDATE",
        "PRACTICE_FABRICATED_EXPERIENCE",
        "PRACTICE_UNTRACEABLE_PAYMENT",
        "PRACTICE_PII_BEFORE_OFFER",
        "PRACTICE_NO_INTERVIEW_OFFER",
        "PRACTICE_UNPAID_BENCH",
        "PRACTICE_URGENCY_PRESSURE",
        "PRACTICE_OFF_CHANNEL_ONLY",
    ):
        assert expected in codes, f"missed {expected}"
    assert r.tiers["illegal"] >= 2


@pytest.mark.parametrize("text", [LEGIT_DIRECT, LEGIT_AGENCY])
def test_legitimate_outreach_is_not_flagged(text):
    """Release gate. Includes ordinary agency outreach: the tool must not smear
    every intermediary, or its warnings stop meaning anything."""
    r = scan(text)
    assert r.findings == [], [f.code for f in r.findings]


def test_pii_request_downgraded_once_an_offer_exists():
    post = ("Hi Priya, attached is your signed offer letter. To complete onboarding, "
            "please upload your SSN and a voided check through our Workday portal.")
    f = next(f for f in scan(post).findings if f.code == "PRACTICE_PII_BEFORE_OFFER")
    assert f.severity is Severity.LOW
    assert "normal onboarding" in f.detail


def test_visa_cost_shifting_is_flagged_as_illegal():
    r = scan("We will sponsor your H-1B; the $4,000 petition fee is paid by the candidate.")
    f = next(f for f in r.findings if f.code == "PRACTICE_VISA_COST_SHIFTED")
    assert f.meta["tier"] == "illegal"


def test_findings_are_ordered_illegal_first():
    r = scan(OPT_SCAM)
    tiers = [f.meta["tier"] for f in r.findings]
    assert tiers == sorted(tiers, key=lambda t: {"illegal": 0, "harmful": 1, "context": 2}[t])


def test_every_finding_tells_the_reader_what_to_do():
    for f in scan(OPT_SCAM).findings:
        assert f.remediation.strip(), f"{f.code} has no remediation"
