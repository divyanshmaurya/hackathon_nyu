"""End-to-end verification, transport honesty, and trace assembly."""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from groundtruth.corroborate.employer import verify_employer  # noqa: E402
from groundtruth.corroborate.transport import (  # noqa: E402
    CassetteTransport, CorroborationUnavailable, OfflineTransport)
from groundtruth.integrity.findings import Severity  # noqa: E402
from groundtruth.observability.prism import PrismRecorder, Trace  # noqa: E402
from groundtruth.verify import verify  # noqa: E402

CASSETTES = pathlib.Path(__file__).parent / "cassettes"

SCAM = """Congratulations! Selected for a role with a leading Fortune 500 client.
No interview required. One-time registration fee of $1,500. We will create work
experience letters so your OPT requirements are met. You'll be on bench until we find
a project. Share your SSN, passport and I-20 today. Pay via Zelle. Offer expires in
24 hours. Contact us on WhatsApp."""

LEGIT = """Hi Alex, I'm a recruiter at Datadog. I came across your GitHub and wondered
if you'd be open to chatting about our Platform Engineering team. Happy to set up a
30-minute call next week — no pressure if the timing isn't right."""


@pytest.fixture
def tape():
    return CassetteTransport(CASSETTES)


# ------------------------------------------------------------------ honesty ---

def test_offline_transport_refuses_rather_than_inventing():
    with pytest.raises(CorroborationUnavailable):
        OfflineTransport().search("anything")


def test_unchecked_employer_is_not_reported_as_clean():
    """The most dangerous bug this tool could have is saying 'looks fine' when
    it never actually looked."""
    e = verify_employer("Whoever", OfflineTransport())
    assert e.checked is False
    f = e.findings[0]
    assert f.code == "EMPLOYER_NOT_CHECKED"
    assert "not a clean result" in f.detail


def test_missing_cassette_raises_rather_than_returning_empty():
    with pytest.raises(CorroborationUnavailable):
        CassetteTransport(CASSETTES).search("a query never recorded")


# ------------------------------------------------------------- corroboration ---

def test_real_company_resolves_to_first_party_domain(tape):
    e = verify_employer("Datadog", tape)
    assert e.likely_domain == "datadoghq.com"  # not linkedin.com / bloomberg.com
    assert e.confidence > 0.5


def test_profile_only_entity_flagged_without_accusation(tape):
    e = verify_employer("Apex Global Consultancy Inc", tape)
    assert e.likely_domain is None
    f = next(f for f in e.findings if f.code == "EMPLOYER_NO_OWN_SITE")
    assert f.severity is Severity.MEDIUM
    assert "not proof of anything wrong" in f.detail


def test_absent_entity_is_high_severity(tape):
    e = verify_employer("Nexora Talent Partners LLC", tape)
    assert any(f.code == "EMPLOYER_NO_FOOTPRINT" and f.severity is Severity.HIGH
               for f in e.findings)


# --------------------------------------------------------------- end to end ---

def test_scam_outreach_leads_with_illegality(tape):
    v = verify("hr@apex-global-consultancy.top", SCAM,
               "Apex Global Consultancy Inc", transport=tape)
    assert v.max_severity is Severity.CRITICAL
    assert "not lawful" in v.headline
    # Visa holders get the specific advice that matters to them.
    assert "immigration attorney" in v.recommendation


def test_corroborated_domain_upgrades_sender_check(tape):
    """The whole point of running Tavily before the domain check."""
    v = verify("recruiter@datadoghq.com", LEGIT, "Datadog", transport=tape)
    assert v.employer.likely_domain == "datadoghq.com"
    assert v.domain.verdict == "matches_claim"
    assert v.max_severity is Severity.INFO


def test_lookalike_of_corroborated_domain_is_caught(tape):
    v = verify("careers@dataddoghq.com", "", "Datadog", transport=tape)
    assert v.domain.verdict != "matches_claim"
    assert v.max_severity >= Severity.HIGH


def test_clean_result_states_its_own_limits(tape):
    v = verify("recruiter@datadoghq.com", LEGIT, "Datadog", transport=tape)
    assert "not a guarantee" in v.recommendation


def test_verification_serialises(tape):
    d = verify("hr@x.top", SCAM, "Apex Global Consultancy Inc", transport=tape).to_dict()
    assert d["max_severity"] == "critical"
    assert d["trace"]["steps"]
    assert isinstance(d["finding_count"], int)


# ------------------------------------------------------------------- tracing ---

def test_trace_records_every_stage(tape):
    v = verify("hr@apex.top", SCAM, "Apex Global Consultancy Inc", transport=tape)
    labels = [s.label for s in v.trace.steps]
    assert "Parse outreach" in labels
    assert "Scan requested actions" in labels
    assert "Corroborate employer" in labels
    assert "Assess sender domain" in labels
    assert v.trace.steps[-1].step_type == "final_answer"


def test_prism_degrades_without_a_key_and_says_why(monkeypatch):
    monkeypatch.delenv("PRISMTRACE_API_KEY", raising=False)
    r = PrismRecorder()
    assert r.enabled is False
    t = r.submit(Trace().step("reasoning", "x"))
    assert "PRISMTRACE_API_KEY not set" in t.note
    assert t.submitted is False


def test_trace_steps_match_prism_schema(tape):
    v = verify("hr@apex.top", SCAM, "Apex Global Consultancy Inc", transport=tape)
    for s in v.trace.steps:
        d = s.to_prism()
        assert d["step_type"] in {"reasoning", "tool_call", "final_answer"}
        assert d["label"]
        if d["step_type"] == "tool_call":
            assert d["tool_name"], "PRISM requires tool_name on tool_call steps"


def test_single_label_host_has_no_trailing_dot(tape):
    """Regression: registrable_parts returns an empty suffix for IP literals and
    single-label hosts, and the join produced '127.0.0.1.'."""
    from groundtruth.corroborate.employer import _candidate_domains
    from groundtruth.corroborate.transport import SearchResult
    scores = _candidate_domains(
        [SearchResult("Home", "http://127.0.0.1:8777/", "x", 0.9)], "Northwind")
    assert all(not d.endswith(".") for d in scores)


def test_medium_findings_are_not_reported_as_nothing_alarming(tape):
    """Regression: MEDIUM matched no branch and fell through to the all-clear
    headline, so a 'worth a second look' result read as 'nothing found'."""
    v = verify("talent@apexrecruiting.com", "We have a role for you.", "Datadog",
               transport=tape)
    assert v.max_severity is Severity.MEDIUM
    assert "Nothing alarming" not in v.headline
    assert "second look" in v.headline
