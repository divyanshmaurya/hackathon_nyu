# Groundtruth

**Verify who is recruiting you, before you hand over anything.**
— NYU Hiring Trust Hackathon

> **Verification, not detection.**
> We never ask "was this written by AI?" — unanswerable, and it punishes honest
> people. We ask "is any of this real?", which gets *easier* as models improve.
> Fabrication is cheap; corroboration is expensive.

**Who it's for:** job seekers facing recruiter outreach they have no way to
check — sharpest for international students on F-1/OPT, where the consequence of
a bad intermediary isn't a wasted week, it's their immigration status. Students
are charged [up to $2,000 for fabricated work
experience](https://www.m9.news/usa-news/f1-student-scam-fake-job-companies/) by
firms that then vanish; one operator alone [faked employment verification for
2,500+ F-1
students](https://www.boundless.com/blog/identify-h-1b-fraud-fake-opt-candidates).
The consultancy keeps the money. The student [can be detained or removed years
later](https://www.greatandhra.com/articles/special-articles/opt-under-fire-again-as-us-claims-major-student-visa-fraud/)
— sometimes without ever knowing the record was false.

Every part of that harm is deferred and invisible at the moment of decision.
Our job is to move the information to that moment.

**What we refuse to do:** label anyone "a scam." We report what is *verifiable*
about a sender, and what the message is *asking you to do* — sorted into
illegal, harmful, and context. Many intermediaries are legitimate; a tool that
flags all of them protects nobody. *Ordinary agency outreach returning clean is
a test-suite release gate.*

- Thesis and architecture → [`docs/PRODUCT.md`](docs/PRODUCT.md)
- Audience, distribution, sustainability → [`docs/MARKET.md`](docs/MARKET.md)

## Status

| Component | State |
|---|---|
| **Document integrity** (offer letters, resumes) | ✅ |
| **Sender impersonation** (look-alike domains) | ✅ |
| **Predatory practice detection** (3 tiers) | ✅ |
| **Employer corroboration** — Tavily | ✅ code complete, cassette-replayed |
| **PRISM tracing** (trajectory per verification) | ✅ code complete, needs key |
| Solari (live careers-page check) | ⬜ next |
| Candidate-facing UI | ⬜ next |

**55 tests passing.** Run the demo:

```bash
pip install -r backend/requirements.txt
cd backend && python3 -m groundtruth.cli demo
```

### ⚠️ Sponsor APIs are blocked from this build environment

`api.tavily.com`, `api.prism.blockconvey.com` and `*.getsolari.com` all return
**403 from the egress proxy** — an organisation network policy, not a missing
key. The integrations are written against the real SDK signatures and run live
the moment they execute somewhere with network access.

To go live, on a machine with internet:

```bash
export TAVILY_API_KEY=tvly-...            # app.tavily.com/redeem/HIRINGHACK
export PRISMTRACE_API_KEY=...             # prism.blockconvey.com, coupon HACKBUILDER#3
export PRISMTRACE_PROJECT_ID=...
export GROUNDTRUTH_RECORD_DIR=backend/tests/cassettes   # records real responses
cd backend && python3 -m groundtruth.cli verify \
    --from careers@dataddoghq.com --company Datadog
```

Until then `CassetteTransport` replays fixtures through the identical code
path, and `OfflineTransport` **refuses** rather than reporting a clean result —
telling a job seeker "nothing found" when nothing was checked is the most
dangerous bug this tool could have, so it is a tested release gate.

## What works today

A fully deterministic scanner that detects weaponised resumes — and, just as
importantly, does not flag honest ones.

```
$ python3 -m pytest backend/tests -q
21 passed
```

| Sample | Verdict |
|---|---|
| `01_clean.pdf` | clean |
| `02_white_text_injection.pdf` | **manipulated** — white-on-white payload recovered |
| `03_tiny_font_injection.pdf` | **manipulated** — 0.6pt text |
| `04_offpage_injection.pdf` | **manipulated** — rendered outside the page |
| `05_render_mode_3.pdf` | **manipulated** — PDF invisible-text flag |
| `06_metadata_injection.pdf` | **manipulated** — payload in XMP metadata |
| `07_control_security_engineer.pdf` | clean ← *discusses prompt injection openly* |
| `08_keyword_stuffing.pdf` | **manipulated** — hidden ATS keyword block |

Row 7 is the one that matters commercially. That resume contains the string
*"ignore all previous instructions"* in plain sight, because the candidate
builds defences against it for a living. Every naive keyword detector flags
them. We return **clean**, because severity is a function of *which layer of
the document* the text lives in — concealment is what establishes intent.

```
same string, hidden in 1pt white text  ->  CRITICAL
same string, visible in a bullet point ->  INFO (shown, never counted against)
```

Also detects: Unicode Tag-block ASCII smuggling (invisible to every renderer,
intact for every LLM), zero-width carriers, Trojan-Source bidi overrides, and
homoglyph filter evasion — each with benign-case controls so a resume written
in Russian or carrying an Arabic name is never flagged.

## Quickstart

```bash
pip install -r backend/requirements.txt
python3 samples/make_samples.py          # regenerate the corpus
python3 -m pytest backend/tests -q
```

Scan a document:

```python
from groundtruth.integrity import scan_pdf

report = scan_pdf("samples/resumes/02_white_text_injection.pdf")
print(report.verdict)        # -> "manipulated"
print(report.hidden_text)    # -> the recovered payload
for f in report.findings:
    print(f.severity.value, f.code, f.evidence)
```

## Layout

```
backend/groundtruth/
  integrity/      # deterministic document forensics  [done]
    findings.py     evidence model + severity ordering
    unicode_checks.py  tag-block, zero-width, bidi, homoglyphs
    injection.py       layer-aware machine-directed instruction detection
    pdf_layers.py      splits what a human sees from what a parser sees
    scanner.py         orchestration + verdict
  claims/         # resume -> atomic checkable claims
  corroborate/    # Tavily · Solari · GitHub evidence gathering
  distinct/       # pool-level template-collapse analysis
  observability/  # PRISM tracing, guardrails, evaluators
samples/          # adversarial + control corpus
```

## Why this beats AI-detection where it counts

The clearest case is the one our customers are most afraid of. A North Korean
IT operative's resume is *excellent* — well written, plausible, correctly
targeted, often better than a real candidate's. Every AI-writing detector on
the market returns "human."

What breaks the cover is never the prose. It's corroboration: a GitHub account
with four months of history, an employer that resolves to no real domain, no
public footprint before 2024. Detection loses; verification wins. That is the
entire company.

## Design constraints

1. No AI-writing score. Ever.
2. No auto-reject — Groundtruth re-orders a queue and attaches evidence.
3. Three axes stay three axes; never blended into one number.
4. `UNVERIFIABLE` is grey, never red. Most honest people are hard to Google.
