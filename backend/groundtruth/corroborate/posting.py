"""Is this role actually listed where the company lists its roles?

The asymmetry that governs every severity here:

  **Finding the role is strong positive evidence.** A scammer cannot publish a
  job on the real company's careers site.

  **Not finding it proves almost nothing.** Roles get filled and delisted.
  Some are confidential. Agencies recruit for positions never posted publicly.
  Careers pages paginate, sit behind search, or live on a subdomain we did not
  guess. Every one of those is an ordinary, innocent reason for a miss.

Treating a miss as evidence of fraud would generate false accusations against
real employers constantly, so a miss is capped at MEDIUM and the wording says
plainly what it does and does not mean.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..integrity.findings import Finding, Layer, Severity
from ..outreach.domains import domain_of
from .browser import Browser, BrowsingUnavailable, RenderedPage

CAREERS_PATHS = ["/careers", "/jobs", "/careers/jobs", "/about/careers",
                 "/company/careers", "/work-with-us", "/join-us", "/opportunities"]

# Applicant tracking systems that host careers pages on the employer's behalf.
ATS_HOSTS = re.compile(
    r"(boards\.greenhouse\.io|job-boards\.greenhouse\.io|jobs\.lever\.co|"
    r"jobs\.ashbyhq\.com|\.myworkdayjobs\.com|\.icims\.com|apply\.workable\.com|"
    r"careers\.smartrecruiters\.com|jobs\.jobvite\.com|\.bamboohr\.com|"
    r"\.recruitee\.com|\.teamtailor\.com|\.personio\.de|\.rippling\.com)", re.I)

CAREERS_LINK = re.compile(r"\b(careers?|jobs?|join\s+us|work\s+(with|at)\s+us|"
                          r"open\s+(roles?|positions?)|we'?re\s+hiring|opportunities)\b", re.I)

STOPWORDS = {"senior", "junior", "staff", "principal", "lead", "head", "of", "the",
             "and", "a", "an", "i", "ii", "iii", "iv", "sr", "jr", "mid", "level"}


@dataclass
class PostingEvidence:
    company_domain: str
    role: str
    careers_url: str | None = None
    found: bool | None = None          # None == not established
    matched_text: str = ""
    checked: bool = False
    engine: str = ""
    findings: list[Finding] = field(default_factory=list)
    note: str = ""

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict:
        return {
            "company_domain": self.company_domain, "role": self.role,
            "careers_url": self.careers_url, "found": self.found,
            "matched_text": self.matched_text, "checked": self.checked,
            "engine": self.engine, "note": self.note,
            "findings": [f.to_dict() for f in self.findings],
        }


def _f(code, title, sev, detail, evidence="", remediation="", conf=1.0, **meta) -> Finding:
    return Finding(code=code, title=title, severity=sev, layer=Layer.VISIBLE,
                   detail=detail, evidence=evidence, remediation=remediation,
                   confidence=conf, meta=meta)


def role_tokens(role: str) -> set[str]:
    """Distinctive words in a job title, minus seniority noise.

    'Senior Software Engineer' and 'Software Engineer II' should match; matching
    on 'senior' alone would hit every listing on the page.
    """
    words = re.findall(r"[a-z0-9]+", role.lower())
    return {w for w in words if w not in STOPWORDS and len(w) > 2}


def role_present(page: RenderedPage, role: str) -> tuple[bool, str]:
    """Look for the role in rendered text and link labels."""
    tokens = role_tokens(role)
    if not tokens:
        return False, ""

    haystacks = [page.text] + [t for t, _ in page.links]
    needed = max(1, round(len(tokens) * 0.7))

    # Exact title match first: unambiguous and worth reporting verbatim.
    for line in page.text.splitlines():
        s = line.strip()
        if s and role.lower() in s.lower():
            return True, s[:140]
    for label, href in page.links:
        if role.lower() in label.lower():
            return True, f"{label[:100]} → {href}"

    # Otherwise require most distinctive tokens within one line or link label.
    for hay in haystacks:
        for line in hay.splitlines():
            low = line.lower()
            if sum(1 for t in tokens if t in low) >= needed and len(line.strip()) < 200:
                return True, line.strip()[:140]
    return False, ""


def find_careers_page(domain: str, browser: Browser,
                      base_url: str | None = None) -> tuple[RenderedPage | None, str]:
    """Locate the employer's careers page, following ATS links when present.

    `base_url` overrides the assumed https://<domain> origin. Real employers
    never need it; it exists so the check can be exercised against a local
    fixture without the test reaching the public internet.
    """
    last_error = ""
    home: RenderedPage | None = None
    origins = ([base_url.rstrip("/")] if base_url
               else [f"https://{domain}", f"https://www.{domain}"])

    # The homepage usually links to wherever careers actually live, including
    # third-party ATS hosts we would never guess by path.
    for candidate in (f"{o}/" for o in origins):
        try:
            home = browser.render(candidate, wait_ms=2000)
            break
        except BrowsingUnavailable as exc:
            last_error = str(exc)

    if home is not None:
        for label, href in home.links:
            if not href.startswith("http"):
                continue
            same_site = domain_of(href).endswith(domain_of(origins[0]))
            if ATS_HOSTS.search(href) or (CAREERS_LINK.search(label or "") and same_site):
                try:
                    return browser.render(href, wait_ms=3000), ""
                except BrowsingUnavailable as exc:
                    last_error = str(exc)

    for origin, path in ((o, p) for o in origins for p in CAREERS_PATHS):
        try:
            page = browser.render(f"{origin}{path}", wait_ms=3000)
            if page.status < 400:
                return page, ""
        except BrowsingUnavailable as exc:
            last_error = str(exc)
    return None, last_error


def check_posting(company_domain: str, role: str, browser: Browser,
                  base_url: str | None = None) -> PostingEvidence:
    """Check whether `role` appears on `company_domain`'s careers page."""
    ev = PostingEvidence(company_domain=company_domain, role=role,
                         engine=getattr(browser, "engine", "?"))
    if not company_domain or not role.strip():
        ev.note = "Need both a verified company domain and a role title."
        return ev

    page, err = find_careers_page(company_domain, browser, base_url)

    if page is None:
        ev.checked = False
        ev.note = err or "No careers page found."
        ev.findings = [_f(
            "POSTING_NOT_CHECKED",
            "We could not reach this company's careers page",
            Severity.INFO,
            "We could not load a careers page for this employer, so the role "
            "was not checked. This says nothing about the role — only that the "
            "check did not happen. Careers pages are often behind bot "
            "protection that blocks automated visits.",
            evidence=err[:200] or f"no careers page found at {company_domain}",
            remediation=f"Open https://{company_domain} yourself and look for "
                        f"their careers page.",
        )]
        return ev

    ev.checked = True
    ev.careers_url = page.final_url
    found, matched = role_present(page, role)
    ev.found, ev.matched_text = found, matched

    if found:
        ev.findings = [_f(
            "POSTING_FOUND",
            f"This role is listed on {company_domain}'s own careers page",
            Severity.INFO,
            f"A listing matching '{role}' appears on the careers page at "
            f"{page.final_url}. This is strong evidence the role is real: "
            f"nobody can publish a job on a company's own site but the company.",
            evidence=f"{matched}  ({page.final_url})",
            remediation="Apply through this page directly rather than through "
                        "the link you were sent.",
            matched=matched, url=page.final_url,
        )]
        return ev

    ev.findings = [_f(
        "POSTING_NOT_LISTED",
        f"This role is not listed on {company_domain}'s careers page",
        Severity.MEDIUM,
        f"We loaded the careers page at {page.final_url} and did not find a "
        f"listing matching '{role}'. This is worth knowing but is not evidence "
        f"of anything on its own: roles get filled and delisted, some are never "
        f"posted publicly, agencies recruit for unlisted positions, and listings "
        f"can sit behind search or pagination we did not reach.",
        evidence=f"searched {page.final_url} ({len(page.text.split())} words, "
                 f"{len(page.links)} links)",
        remediation=f"Ask the recruiter for the posting's URL on "
                    f"{company_domain}. A real role usually has one.",
        conf=0.6, url=page.final_url,
    )]
    return ev
