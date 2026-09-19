# Who Groundtruth is for

> **The underserved side of the hiring funnel is the job seeker — and the most
> underserved job seekers are international students on F-1/OPT.**
>
> They face the highest-consequence version of the trust problem, have the least
> leverage to refuse a bad arrangement, and are the only group for whom the harm
> arrives *years* after the decision that caused it.

---

## 1. The asymmetry

Most hiring-trust tooling protects employers. That makes commercial sense and it
leaves the actual victims unserved, because the people losing money and status
in this market are not companies.

Job scam losses reported to the FTC rose from [$90M in 2020 to $501M in
2024](https://cw33.com/news/local/job-scams-result-in-150-4-million-losses-ftc-reports/).
BBB employment-scam reports [doubled in 2025 to
23,234](https://theworlddata.com/employment-scam-statistics-in-us/). [One in
four people who job-hunted in 2025 reported falling victim to a hiring
scam](https://techbullion.com/job-scam-statistics-fbi-ftc-data/). And the tells
people were taught to look for are gone: scammers now send [AI-generated offer
letters and run deepfake video
interviews](https://techbullion.com/job-scam-statistics-fbi-ftc-data/).

Nobody builds for these people, because they cannot pay. That is precisely what
makes it the underserved sector.

## 2. Why F-1/OPT students are the sharpest case

The recruiting intermediary market contains legitimate firms and predatory ones,
and **a job seeker has no way to tell them apart.** For a domestic candidate
that asymmetry costs time and occasionally money. For an international student
it can cost their right to remain in the country.

The mechanism is well documented. Students finishing a degree have a hard
unemployment clock; those who cannot place in time turn to "consultancies" that
employ them on paper. Those firms [charge fees, underpay, or create fake
employment
records](https://www.boundless.com/blog/identify-h-1b-fraud-fake-opt-candidates).
Some charge [up to $2,000 for fabricated work experience, collect from 50+
students, and vanish](https://www.m9.news/usa-news/f1-student-scam-fake-job-companies/).
One operator alone [provided false employment verification to more than 2,500
F-1 students](https://www.boundless.com/blog/identify-h-1b-fraud-fake-opt-candidates).

Then the asymmetry completes itself. The consultancy keeps the money. The
student bears the consequence — and [students who did not knowingly participate
have faced arrest, detention and removal years
later](https://www.greatandhra.com/articles/special-articles/opt-under-fire-again-as-us-claims-major-student-visa-fraud/),
including people lawfully employed on an H-1B by the time it caught up with
them.

**Every part of that is deferred, invisible, and irreversible at the moment it
matters.** The student signs, believing it is normal, and finds out years later.
A verification tool has a narrow but real job here: move the information to the
moment of decision.

And the vector is specifically the intermediary chain — [most candidates with
forged credentials enter through a staffing firm sourced via a subcontractor,
"typically the party orchestrating the
scam."](https://www.boundless.com/blog/identify-h-1b-fraud-fake-opt-candidates)

## 3. What we will not do

We do not label organisations as scams. The tool reports:

- what is **verifiable** about the sender, and what is not, and
- what the message is **asking the candidate to do**, against three tiers:
  **illegal** (fee-charging, shifting H-1B costs to the worker, fabricating
  employment records), **harmful** (legal but transfers serious risk), and
  **context** (worth knowing, not wrong by itself).

This matters for accuracy, not just liability. Many intermediaries are
legitimate, and a tool that flags all of them teaches people to ignore it —
after which it protects nobody. Ordinary agency outreach returning *clean* is a
release gate in our test suite, alongside the scam cases.

Evidence, not accusation. Same discipline as the document-integrity axis: we
show the reader what we saw and let them decide.

## 4. Users

**Primary — international students on F-1/OPT.** Highest consequence, tightest
time pressure, least leverage. Reached through university international student
offices and career services, which already run scam-awareness programming and
have no tool to hand out. NYU alone has one of the largest international student
populations in the US.

**Secondary — new graduates and recently laid-off workers.** Same scams, lower
stakes, far larger population.

**Distribution partner — university career services and ISSS offices.** They
don't pay either, but they have the trust and the mailing list. A tool they can
recommend is worth more than an ad budget.

## 5. How this is sustainable

Being honest, since nobody here can pay:

The candidate-facing tool stays free. The same verification engine has a
paying customer on the other side — employers whose brand is being impersonated
have a direct financial reason to fund detection of domains impersonating them,
and to publish a verifiable signal candidates can check against. That is the
Side B "trust signal on a careers page" from the brief, and it funds the free
side.

We are not pretending the free side is a business. We are saying it is
reachable through one that is.

## 6. Adjacent things we are deliberately not building

- **Identity verification / liveness** — Persona and others do it well.
- **A scam blocklist** — stale within a week, and maintaining a list of named
  organisations is exactly the accusation posture we've ruled out.
- **Immigration advice** — we surface facts and tell people to talk to their
  ISSS office or an attorney. We are not a substitute for either.
