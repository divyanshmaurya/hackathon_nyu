# Groundtruth

**Verify who is recruiting you, before you hand over anything.**

NYU Hiring Trust Hackathon — **Side B: impersonation and candidate scams**

> 🤖 **Coding agents:** read [`CONTEXT.md`](CONTEXT.md) first for project
> history and reasoning, then [`CLAUDE.md`](CLAUDE.md) for the binding house
> rules.

---

## The problem

Hiring has a trust crisis on both sides. Most tooling protects employers,
because employers can pay. The people actually losing money and legal status
are job seekers.

Job scam losses reported to the FTC rose from [$90M in 2020 to $501M in
2024](https://cw33.com/news/local/job-scams-result-in-150-4-million-losses-ftc-reports/).
BBB employment-scam reports [doubled in 2025 to
23,234](https://theworlddata.com/employment-scam-statistics-in-us/). [One in
four people who job-hunted in 2025 reported falling victim to a hiring
scam](https://techbullion.com/job-scam-statistics-fbi-ftc-data/). Every tell
people were taught to look for is gone: scammers now send [AI-generated offer
letters and run deepfake video
interviews](https://techbullion.com/job-scam-statistics-fbi-ftc-data/).

**The sharpest case is international students on F-1/OPT.** Consultancies
charge them [up to $2,000 for fabricated work
experience](https://www.m9.news/usa-news/f1-student-scam-fake-job-companies/),
collect from dozens, and vanish. One operator alone [faked employment
verification for 2,500+ F-1
students](https://www.boundless.com/blog/identify-h-1b-fraud-fake-opt-candidates).
The consultancy keeps the money. The student [can be detained or removed years
later](https://www.greatandhra.com/articles/special-articles/opt-under-fire-again-as-us-claims-major-student-visa-fraud/)
— sometimes never having known the record was false.

Every part of that harm is **deferred, invisible, and irreversible at the
moment it matters.** The job of a verification tool is to move the information
to that moment.

## The thesis

> **Verification, not detection.**

We never ask *"was this written by AI?"* — unanswerable, getting worse monthly,
and it correlates with non-native English writing, so acting on it punishes
honest people. We ask *"is any of this real?"*, which gets **easier** as models
improve.

A model writes a flawless scam email in four seconds. It cannot make a domain
older than it is, forge a signature it lacks the key for, or publish a job on a
company's real careers page.

**Fabrication is cheap. Corroboration is expensive.**

## What it refuses to do

1. **Never labels an organisation a scam.** It reports what is verifiable and
   what a message asks of you. Tests assert the words "fraud", "fake" and
   "scam" never appear in specific findings.
2. **Never treats absence of evidence as evidence.** Every check distinguishes
   passed / failed / *did not run*. The offline paths raise rather than return
   empty.
3. **Never flags honest people.** Each detector ships with a benign control that
   must come back clean — a resume in Russian, an Arabic name, a security
   engineer who writes about prompt injection, a hand-filled offer template,
   ordinary agency outreach. These are release gates.

---

## What it does

Six independent checks, tiered by what they mean rather than blended into a
score.

| Check | Question | Powered by |
|---|---|---|
| **Sender impersonation** | Is this domain the company's, or a confusable imitation? | — |
| **Predatory practices** | What is this message asking you to *do*? | — |
| **Employer corroboration** | Does this company exist, and what is its real domain? | **Tavily** |
| **Document integrity** | Was this offer letter edited, or weaponised? | — |
| **Careers-page listing** | Is this role listed where the company lists roles? | **Solari** |
| **Signed attestation** | Did this genuinely come from the employer? | Ed25519 |

Every run is traced to **PRISM**, so "why was this flagged" stays answerable.

### Sender impersonation

```
careers@google.com  (verified)      matches_claim   info
recruiter@gооgle.com  (Cyrillic)    lookalike       CRITICAL  confusable imitation
hr@google.com.hiring-portal.xyz     lookalike       CRITICAL  → real owner: hiring-portal.xyz
jobs@googlecareers.com              lookalike       HIGH      combosquat
hr@gogle.com                        lookalike       HIGH      typosquat
talent@apexrecruiting.com           unrelated       MEDIUM    (not an accusation)
```

Homoglyph folding collapses `g00gle`, Cyrillic `gооgle` and `google` to one
skeleton. The brand-in-subdomain finding is the one that helps most: it names
who *actually* controls the mail.

### Predatory practices

Three strictly separated tiers, because conflating them is how a legal-but-bad
practice gets called fraud and a genuinely illegal one gets buried:

- **Not lawful for an employer to ask** — candidate fees, shifting H-1B costs to
  the worker, fabricated employment records, money-mule requests
- **Puts you at risk** — SSN or passport before an offer, unpaid "bench",
  untraceable payment, exclusivity before the client is named, submission
  without consent
- **Worth knowing** — unnamed employer, undisclosed rate

Timing matters: "send your SSN" is `CRITICAL` before an offer and `LOW` once a
signed offer is in the thread.

### Document integrity

The core idea: **severity is a function of which document layer text lives in,
not of the text itself.**

```
"ignore all previous instructions", hidden in 1pt white text  →  CRITICAL
"ignore all previous instructions", in a visible bullet       →  INFO
```

The second is a security engineer describing their job. Every naive keyword
detector flags them; we return clean. Also detects Unicode Tag-block ASCII
smuggling (invisible to every renderer, intact for every LLM), zero-width
carriers, Trojan-Source bidi, and homoglyph filter evasion.

**Forged offer letters** are usually real ones with fields swapped, and
replacement text rarely inherits the original font:

```
03_name_tampered.pdf    'Priya Raghavan'  [Courier 11.5pt]  vs body [Helvetica 11.0pt]
02_salary_tampered.pdf  '$310,000'        [Times-Roman 12pt] vs body [Helvetica 11.0pt]
04_whiteout_overlay.pdf 'salary will be $185,000' ⟷ '$295,000'   (both recoverable)
05_control_hand_filled.pdf                                        clean ← release gate
```

### Signed attestations

Employers publish an Ed25519 public key at
`https://company.com/.well-known/groundtruth.json` and sign their outreach.
**The trust anchor is the employer's domain, not us** — if this project
disappeared, every attestation stays verifiable. We are a format, not an
authority.

The property that makes it safe: a signature is **bound to the sender**.

```
a.chen@datadoghq.com          →  INFO      signed by datadoghq.com
hr@jobs.datadoghq.com         →  INFO      subdomain accepted
hr@careers-portal-intl.com    →  CRITICAL  "real signature — but not sent by them"
```

Same valid signature, opposite verdict. Without that binding, a leaked token
would let a scammer's message be labelled *"cryptographically signed by
datadoghq.com"* — the trust signal laundering a scam.

---

### The page itself

The result is not a score. It is an ordered account of what happened.

**Checks report live as they finish.** `POST /api/verify/stream` returns
newline-delimited JSON — one real event per check, emitted when that check
completes. This is built on `verify_iter()`, a generator; `verify()` drains it
and returns the whole result, so non-streaming callers are unaffected. Nothing
is replayed on a timer.

**A tick means evidence, not completion.** Green is reserved for checks that
confirmed something positive. A check that finished without confirming anything
stays neutral, because a green tick beside *"unverifiable"* tells the reader the
opposite of the truth. Skipped checks are shown rather than hidden, so "never
checked" stays distinguishable from "checked and clean".

**Every result ends with what to do now** — ordered steps, reporting links
([FTC](https://reportfraud.ftc.gov/), [IC3](https://www.ic3.gov/),
[BBB](https://www.bbb.org/scamtracker)), and a copy-to-clipboard report a
student can paste into an email to their international student office. When
something unlawful was asked for, the visa advice comes second and says why:
the consequences of a fabricated employment record fall on the student, not on
the consultancy.

### Public-surface hardening

The checks were always deterministic and honest about what they didn't check.
The *API in front of them* now carries the same discipline:

- **Rate limited** — 20 requests/minute per client by default
  (`RATE_LIMIT_PER_MINUTE`), so one caller can't burn through a shared Tavily
  or Solari quota alone.
- **Upload-capped** — documents are streamed and rejected past 15MB
  (`MAX_UPLOAD_MB`) instead of buffered into memory without limit.
- **No content in logs** — request logs carry method, path, status, timing and
  client IP; never the message, company, document, or attestation you sent.
- **Sanitized errors** — an unhandled failure returns a generic message, not a
  stack trace; the real error is logged server-side.
- **Security headers** on every response, and `/privacy` / `/terms` pages
  that describe actual behaviour rather than boilerplate.

None of this is multi-tenant yet — see `CONTEXT.md` §"The chosen path to a
paying customer" for what an institutional deployment (the intended buyer:
universities, ISSS offices, immigration law firms) still needs on top of this.

## Status

**153 tests passing.** All three sponsor integrations live-verified.

| Component | State |
|---|---|
| Document integrity + injection detection | ✅ |
| Offer-letter tampering | ✅ |
| Sender impersonation | ✅ |
| Predatory practices (3 tiers) | ✅ |
| Employer corroboration — **Tavily** | ✅ live |
| Careers-page check — **Solari** | ✅ live |
| Tracing — **PRISM** | ✅ live |
| Signed attestations | ✅ |
| Web UI (live progress, actions, reporting links) | ✅ |
| CLI (`verify` · `demo` · `keys` · `keygen` · `issue` · `prism-check`) | ✅ |
| Vercel deployment | ✅ (careers check excluded — see below) |
| Public-surface hardening (rate limits, upload caps, sanitized errors, security headers, legal pages) | ✅ |
| Multi-tenancy, accounts, billing (needed to actually sell this) | ⬜ not built |

```
$ python3 -m groundtruth.cli prism-check
  CREDENTIAL OK — credential valid, synthetic trace stored
  run 2907ea94 · 5 steps · verdict critical · Submitted to PRISM.
  live_connected=True  blocked_step=-  overall=connected
  LIVE CONNECTED
```

> **Note for CI and cloud build environments.** Some networks block the sponsor
> APIs with a **403 on CONNECT**. That is an egress policy, not a broken
> integration. Everything runs offline via recorded cassettes, local fixtures
> and local Chromium.

---

## Quickstart

```bash
git clone -b claude/tender-lovelace-4vgxta https://github.com/divyanshmaurya/hackathon_nyu
cd hackathon_nyu
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
python3 -m playwright install chromium     # only if not using Solari

cd backend && python3 -m pytest tests -q   # 153 passing
python3 -m uvicorn app:app --port 8000
```

Open <http://127.0.0.1:8000>. Five one-click examples; **"Signed by the
employer"** then **"Stolen signature"** is the strongest pair. Attach
`samples/offers/03_name_tampered.pdf` to see document forensics run alongside.

### Credentials

**In a gitignored `.env`, never in the repository.**

```bash
cp .env.example .env     # then fill it in
cd backend && python3 -m groundtruth.cli keys
```

Everything runs without keys: corroboration replays cassettes, tracing records
locally, the browser falls back to local Chromium. The loader refuses RTF files
(TextEdit's default) rather than parsing them into plausible garbage.

### API

| Endpoint | Returns |
|---|---|
| `POST /api/verify` | the complete result as JSON |
| `POST /api/verify/stream` | newline-delimited JSON, one event per check as it finishes |
| `GET /api/health` | which integrations are live, `can_browse`, and the active `rate_limit_per_minute` / `max_upload_mb` |
| `GET /privacy`, `GET /terms` | the legal pages, linked from the landing page footer |

### CLI

```bash
python3 -m groundtruth.cli demo                 # the built-in cases
python3 -m groundtruth.cli verify --from hr@example.com --company "Datadog" \
        --role "Senior Software Engineer" --check-posting
python3 -m groundtruth.cli keygen --domain yourcompany.com    # employer side
python3 -m groundtruth.cli issue  --domain yourcompany.com --key … --role … --recruiter …
python3 -m groundtruth.cli prism-check          # prove tracing end to end
```

---

## Layout

```
backend/groundtruth/
  integrity/      document forensics — layers, Unicode, injection, tampering
  outreach/       sender impersonation, predatory-practice detection
  corroborate/    Tavily employer lookup, Solari careers-page check, transports
  attest/         Ed25519 attestations, keys, domain-anchored resolution
  observability/  PRISM tracing and the setup verifier
  verify.py       orchestration
  cli.py          command line
backend/app.py    FastAPI service      backend/static/  candidate-facing UI
backend/tests/    153 tests + cassettes, fixtures, demo registry
samples/          adversarial + control corpora (resumes, offer letters)
api/ vercel.json  serverless deployment
```

## Documentation

| Document | Contents |
|---|---|
| [`CONTEXT.md`](CONTEXT.md) | **Handoff** — history, decisions, fixed bugs, what's next |
| [`CLAUDE.md`](CLAUDE.md) | House rules, binding on coding agents |
| [`docs/PRODUCT.md`](docs/PRODUCT.md) | Thesis, axes, architecture |
| [`docs/MARKET.md`](docs/MARKET.md) | Audience, citations, sustainability, non-goals |
| [`docs/ATTESTATION.md`](docs/ATTESTATION.md) | The trust signal and why it is domain-anchored |
| [`docs/SOLARI.md`](docs/SOLARI.md) | Careers-page verification, why a browser is required |
| [`docs/DEPLOY.md`](docs/DEPLOY.md) | Vercel and container hosts |

## Deployment

Vercel works — `vercel.json` and `api/index.py` are in place. The careers-page
check does not run there: `playwright` and `solari-browser` are ~277MB
together, over the 250MB function limit, and bundle browser drivers a
serverless function cannot execute anyway. The deployment says so rather than
failing obscurely (`/api/health` → `can_browse: false`).

For the complete product, use a container host — Render, Railway or Fly. See
[`docs/DEPLOY.md`](docs/DEPLOY.md).

## Built with

Python · FastAPI · PyMuPDF · cryptography (Ed25519) ·
**[Tavily](https://tavily.com)** · **[Solari](https://getsolari.com)** ·
**[PRISM](https://prism.blockconvey.com)** · Playwright
