"""Does the company contacting you exist, and is this its real domain?

This is the module that upgrades the rest of the system. On its own, the domain
check is heuristic: it can say "this resembles Google" but not "Google's actual
domain is google.com." Once Tavily establishes the company's real domain, the
same check becomes definitive — a sender either is on that domain or is not.

The ordering matters for the job seeker. The most useful single fact we can
give someone is not a risk score, it is: *here is the company's real address;
compare it yourself.*
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from ..integrity.findings import Finding, Layer, Severity
from ..outreach.domains import FREE_MAIL, domain_of, registrable_parts, _normalise
from .transport import CorroborationUnavailable, SearchResult, Transport

# Sites that describe companies but are never the company's own domain.
AGGREGATORS = {
    "linkedin.com", "glassdoor.com", "indeed.com", "crunchbase.com", "zoominfo.com",
    "bloomberg.com", "wikipedia.org", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "youtube.com", "reddit.com", "medium.com", "github.com",
    "trustpilot.com", "yelp.com", "bbb.org", "dnb.com", "pitchbook.com",
    "levels.fyi", "builtin.com", "wellfound.com", "angel.co", "ziprecruiter.com",
    "monster.com", "dice.com", "simplyhired.com", "jobs.lever.co", "greenhouse.io",
}


@dataclass
class EmployerEvidence:
    company: str
    likely_domain: str | None
    confidence: float
    checked: bool
    findings: list[Finding] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict:
        return {
            "company": self.company,
            "likely_domain": self.likely_domain,
            "confidence": round(self.confidence, 2),
            "checked": self.checked,
            "note": self.note,
            "sources": self.sources,
            "findings": [f.to_dict() for f in self.findings],
        }


def _f(code, title, sev, detail, evidence="", remediation="", conf=1.0, **meta) -> Finding:
    return Finding(code=code, title=title, severity=sev, layer=Layer.VISIBLE,
                   detail=detail, evidence=evidence, remediation=remediation,
                   confidence=conf, meta=meta)


def _candidate_domains(results: list[SearchResult], company: str) -> Counter:
    """Score domains by how likely each is to be the company's own site."""
    token = _normalise(company)
    scores: Counter = Counter()
    for r in results:
        d = domain_of(r.url)
        if not d:
            continue
        name, _ = registrable_parts(d)
        base = f"{name}.{registrable_parts(d)[1]}"
        if base in AGGREGATORS or d in AGGREGATORS or base in FREE_MAIL:
            continue
        weight = r.score or 0.5
        # A domain whose registrable name contains the company token is far
        # more likely to be the company itself than a news site mentioning it.
        if token and token in _normalise(name):
            weight += 1.5
        scores[base] += weight
    return scores


def verify_employer(company: str, transport: Transport) -> EmployerEvidence:
    """Establish whether `company` exists publicly and what its real domain is."""
    if not company or not company.strip():
        return EmployerEvidence(company, None, 0.0, False, note="No company name supplied.")

    query = f"{company} official website careers"
    try:
        results = transport.search(query, max_results=6)
    except CorroborationUnavailable as exc:
        return EmployerEvidence(
            company, None, 0.0, checked=False, note=str(exc),
            findings=[_f(
                "EMPLOYER_NOT_CHECKED",
                "We could not check whether this company exists",
                Severity.INFO,
                "Corroboration was unavailable for this run, so nothing was "
                "verified about this employer. This is not a clean result — it "
                "means the check did not happen.",
                evidence=str(exc),
                remediation="Search the company name yourself and compare the "
                            "domain against the sender's address.",
            )],
        )

    if not results:
        return EmployerEvidence(
            company, None, 0.0, checked=True,
            note="No search results.",
            findings=[_f(
                "EMPLOYER_NO_FOOTPRINT",
                f"No public web presence found for '{company}'",
                Severity.HIGH,
                f"A search for '{company}' returned nothing identifiable. Real "
                f"employers — including small ones — leave some public trace. An "
                f"organisation that cannot be found at all is one you cannot "
                f"verify anything else about.",
                evidence=f"query: {query} → 0 results",
                remediation="Ask for the company's registered legal name and "
                            "website, and search for it yourself.",
                conf=0.8,
            )],
        )

    scores = _candidate_domains(results, company)
    sources = [r.url for r in results[:6]]

    if not scores:
        return EmployerEvidence(
            company, None, 0.3, checked=True,
            sources=sources,
            note="Only aggregator/profile pages found; no first-party site.",
            findings=[_f(
                "EMPLOYER_NO_OWN_SITE",
                f"'{company}' appears only on third-party profile sites",
                Severity.MEDIUM,
                "We found mentions of this name, but no website the company "
                "itself appears to operate. Recruiting firms and shell entities "
                "frequently exist only as a LinkedIn page. It is not proof of "
                "anything wrong, but there is no first-party source to check "
                "against.",
                evidence="; ".join(sources[:3]),
                remediation="Ask for their website and confirm it is the same "
                            "organisation named in the outreach.",
                conf=0.7,
            )],
        )

    top, top_score = scores.most_common(1)[0]
    total = sum(scores.values()) or 1.0
    confidence = min(0.95, top_score / total)

    findings = [_f(
        "EMPLOYER_DOMAIN_IDENTIFIED",
        f"'{company}' appears to operate {top}",
        Severity.INFO,
        f"Public sources consistently associate '{company}' with the domain "
        f"'{top}'. Compare this against the address that contacted you — if "
        f"they differ, the sender is not writing from the company's own domain.",
        evidence=f"{top} (confidence {confidence:.0%}, from {len(sources)} sources)",
        remediation=f"Type {top} into your browser yourself. Do not click a "
                    f"link from the message.",
        conf=confidence,
        domain=top,
    )]

    return EmployerEvidence(company, top, confidence, checked=True,
                            findings=findings, sources=sources)
