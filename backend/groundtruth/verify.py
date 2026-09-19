"""One verification run over a piece of recruiter outreach.

Ties the four checks together in the order that is most useful to a job seeker,
and records the whole thing as a PRISM trajectory so the result stays
explainable after the fact.

Order is deliberate. Employer corroboration runs *before* the final domain
judgement, because knowing the company's real domain turns the sender check
from "this resembles Google" into "this is not Google's domain."
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .corroborate.employer import EmployerEvidence, verify_employer
from .corroborate.transport import Transport, default_transport
from .integrity.findings import Finding, Severity
from .integrity.scanner import IntegrityReport, scan_pdf
from .observability.prism import PrismRecorder, Trace
from .outreach.domains import DomainVerdict, analyse as analyse_domain
from .outreach.practices import PracticeReport, scan as scan_practices


@dataclass
class Verification:
    sender: str
    claimed_company: str | None
    domain: DomainVerdict | None = None
    practices: PracticeReport | None = None
    employer: EmployerEvidence | None = None
    document: IntegrityReport | None = None
    trace: Trace | None = None
    headline: str = ""
    recommendation: str = ""

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for part in (self.domain, self.practices, self.employer, self.document):
            if part is not None:
                out.extend(part.findings)
        return sorted(out, key=lambda f: -f.severity.rank)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sender": self.sender,
            "claimed_company": self.claimed_company,
            "headline": self.headline,
            "recommendation": self.recommendation,
            "max_severity": self.max_severity.value,
            "finding_count": len(self.findings),
            "domain": self.domain.to_dict() if self.domain else None,
            "practices": self.practices.to_dict() if self.practices else None,
            "employer": self.employer.to_dict() if self.employer else None,
            "document": self.document.to_dict() if self.document else None,
            "trace": self.trace.to_dict() if self.trace else None,
        }


def _summarise(v: Verification) -> tuple[str, str]:
    """Plain-language headline and next step. Never an accusation."""
    illegal = [f for f in v.findings if f.meta.get("tier") == "illegal"]
    critical = [f for f in v.findings if f.severity is Severity.CRITICAL]
    high = [f for f in v.findings if f.severity is Severity.HIGH]

    if illegal:
        return (
            f"This message asks you to do {len(illegal)} thing(s) that are not "
            "lawful for an employer to ask.",
            "Do not pay, sign, or send documents. Save this message. If you are "
            "on a student or work visa, speak to your school's international "
            "student office or an immigration attorney before replying — the "
            "consequences of these arrangements fall on you, not on them.",
        )
    if critical:
        return (
            f"{len(critical)} serious problem(s) found with who this is from or "
            "what it asks for.",
            "Do not reply or click links. If you think the company is real, "
            "contact them through a phone number or address you found yourself.",
        )
    if high:
        return (
            f"{len(high)} thing(s) here could not be verified or do not match "
            "normal hiring practice.",
            "Slow down and confirm independently before sending anything. A "
            "legitimate employer will wait.",
        )
    if any(f.code == "EMPLOYER_NOT_CHECKED" for f in v.findings):
        return (
            "Nothing alarming found — but the employer check did not run.",
            "Verify the company's website yourself and compare it to the "
            "sender's address.",
        )
    return (
        "Nothing alarming found in what we could check.",
        "This is not a guarantee. We checked the sender's domain, the employer's "
        "public presence, and what the message asks for — not whether the job or "
        "the person is real.",
    )


def verify(
    sender: str,
    message: str = "",
    claimed_company: str | None = None,
    document_path: str | None = None,
    transport: Transport | None = None,
    recorder: PrismRecorder | None = None,
) -> Verification:
    """Run every available check over one piece of outreach."""
    transport = transport or default_transport()
    recorder = recorder or PrismRecorder()
    trace = Trace()
    v = Verification(sender=sender, claimed_company=claimed_company, trace=trace)

    trace.step("reasoning", "Parse outreach",
               input_summary=f"sender={sender!r} company={claimed_company!r}",
               output_summary=f"{len(message)} chars of message text")

    # 1. What is the message asking for? Independent of who sent it.
    if message.strip():
        t0 = time.perf_counter()
        v.practices = scan_practices(message)
        trace.tool("groundtruth.practices", "Scan requested actions",
                   inp=f"{len(message)} chars",
                   out=f"{len(v.practices.findings)} finding(s), tiers={v.practices.tiers}",
                   ms=int((time.perf_counter() - t0) * 1000))

    # 2. Who does the company say it is, and does it exist?
    known_domain = None
    if claimed_company:
        t0 = time.perf_counter()
        v.employer = verify_employer(claimed_company, transport)
        known_domain = v.employer.likely_domain
        trace.tool("tavily.search", "Corroborate employer",
                   inp=claimed_company,
                   out=f"domain={known_domain} confidence={v.employer.confidence:.2f} "
                       f"checked={v.employer.checked}",
                   ms=int((time.perf_counter() - t0) * 1000),
                   status="success" if v.employer.checked else "error")

    # 3. Sender check, now upgraded by whatever step 2 established.
    t0 = time.perf_counter()
    v.domain = analyse_domain(sender, claimed_company, known_domain=known_domain)
    trace.tool("groundtruth.domains", "Assess sender domain",
               inp=f"{sender} vs {known_domain or claimed_company}",
               out=f"verdict={v.domain.verdict} severity={v.domain.max_severity.value}",
               ms=int((time.perf_counter() - t0) * 1000))

    # 4. If an offer letter was attached, check it for manipulation.
    if document_path:
        t0 = time.perf_counter()
        v.document = scan_pdf(document_path)
        trace.tool("groundtruth.integrity", "Inspect attached document",
                   inp=document_path,
                   out=f"verdict={v.document.verdict} "
                       f"findings={len(v.document.findings)}",
                   ms=int((time.perf_counter() - t0) * 1000))

    v.headline, v.recommendation = _summarise(v)
    trace.step("final_answer", "Summarise for the candidate",
               output_summary=f"{v.max_severity.value}: {v.headline}")

    recorder.submit(trace, final_status="success")
    return v
