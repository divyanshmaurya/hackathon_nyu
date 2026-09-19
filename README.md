# Groundtruth

**The verification layer for the hiring funnel.** — NYU Hiring Trust Hackathon

> **Verification, not detection.**
> We never ask "was this written by AI?" — that question is unanswerable and
> punishes honest candidates. We ask "is any of this real?", which gets *easier*
> as models get better. Fabrication is cheap; corroboration is expensive.

Full thesis: [`docs/PRODUCT.md`](docs/PRODUCT.md)

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

Row 7 is the one that matters. That resume contains the string
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

## Design constraints

1. No AI-writing score. Ever.
2. No auto-reject — Groundtruth re-orders a queue and attaches evidence.
3. Three axes stay three axes; never blended into one number.
4. `UNVERIFIABLE` is grey, never red. Most honest people are hard to Google.
