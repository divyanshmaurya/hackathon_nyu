# Groundtruth

**The verification layer for staffing agencies.** — NYU Hiring Trust Hackathon

> **Verification, not detection.**
> We never ask "was this written by AI?" — unanswerable, and it punishes honest
> candidates. We ask "is any of this real?", which gets *easier* as models
> improve. Fabrication is cheap; corroboration is expensive.

**Who it's for:** small and mid-sized IT and contract staffing agencies — the
highest-risk node in the hiring funnel and the least-tooled participant in it.
They carry an enterprise's liability on a small business's budget: one
fraudulent submission doesn't cost a placement fee, it can cost the whole
client account. Meanwhile their clients have started writing verification
requirements into MSAs and auditing them on it, and the industry's worst-case
exposure — North Korean IT worker placement — is an OFAC problem, not an
embarrassment.

They are also the most *impersonated* party in hiring, because unsolicited
outreach from an unknown recruiter is their legitimate business motion. So the
same engine runs both ways for the same customer.

- Thesis and architecture → [`docs/PRODUCT.md`](docs/PRODUCT.md)
- Market, ICP, pricing, competition → [`docs/MARKET.md`](docs/MARKET.md)

---

## Status

| Component | State |
|---|---|
| **Integrity axis** (document forensics) | ✅ working, 21 tests passing |
| Claim extraction | ⬜ next |
| Corroboration (Tavily · Solari · GitHub) | ⬜ next |
| Distinctiveness (pool-level clustering) | ⬜ next |
| PRISM tracing / guardrails / evals | ⬜ next |
| Recruiter dossier UI | ⬜ next |

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
