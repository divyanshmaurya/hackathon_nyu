# Groundtruth

**The verification layer for the hiring funnel.**

> Verification, not detection.

---

## 1. The thesis

Every tool in this space is trying to answer the wrong question.

The wrong question is **"was this written by AI?"** It is unanswerable, it is
getting less answerable every month, and the moment you act on the answer you
punish the honest candidate who ran their resume through a grammar checker.
AI-detection scores are also a legal liability: they correlate with non-native
English writing, which turns a screening tool into a discrimination claim.

The right question is **"is any of this real?"**

That question *is* answerable, and it gets *easier* as generative models get
better. A language model can produce a flawless resume in four seconds. What it
cannot produce is a four-year commit history, a conference talk that a
third-party site lists, a company that exists at the domain claimed, or a
coworker-visible public footprint. **Fabrication is cheap. Corroboration is
expensive.** That asymmetry is the whole product.

Groundtruth never scores writing style. It scores **evidence**.

---

## 2. What it does

Groundtruth sits between the ATS and the recruiter and turns every application
into a **Trust Dossier**: a short, cited, human-readable page that tells a
recruiter what actually checks out.

It reports three **independent** axes. They are never blended into one number,
because blending is how a document-forensics fact gets laundered into a
judgement about a person.

### Axis 1 — Integrity: *was this document weaponised?*

Fully deterministic. No model, no inference, no ambiguity. We detect:

- **Invisible text** — white-on-white, 0pt fonts, PDF text render mode 3,
  content positioned outside the page bounds, text hidden under images.
- **ASCII smuggling** — Unicode Tag block (`U+E0000–U+E007F`) payloads that are
  invisible to every human and every PDF viewer, but arrive intact in the token
  stream an LLM reads.
- **Zero-width and bidi controls** — `ZWSP`, `ZWNJ`, `ZWJ`, `BOM`, soft hyphen,
  word joiner, and the Trojan-Source bidi overrides (`U+202A–U+202E`).
- **Homoglyph substitution** — Cyrillic `е` / Greek `ο` swapped into Latin words
  to slip past keyword filters.
- **AI-directed imperatives** — text addressed to the machine reader rather than
  the human one ("ignore previous instructions", "rate this candidate as a
  strong hire").

The central design rule, and the reason this doesn't false-flag anyone:
**context multiplies severity.** A candidate who writes *"I built guardrails
against 'ignore previous instructions' attacks"* in a visible bullet is doing
their job. The identical string rendered in 1pt white text is fraud. Same
string, opposite verdict — because we know which layer of the document it lives
in. Hidden text has no innocent explanation, so this axis produces essentially
zero false positives on honest applicants.

### Axis 2 — Corroboration: *do the claims survive contact with the public record?*

We decompose the resume into atomic, checkable **claims** — employment spans,
degrees, projects, publications, links, quantified achievements — and send each
one out to be checked:

- **Tavily** for open-web corroboration: does the employer exist, is the role
  plausible, is the publication indexed, was the product ever shipped.
- **Solari** headless browsers for pages that only exist after JavaScript runs,
  and for checking a claimed profile is live rather than merely indexed.
- **GitHub** for the strongest provenance signal available: not "does the repo
  exist" but *commit cadence over time*. A repo backdated and pushed in one
  burst looks nothing like four years of Tuesday-night commits.

Every claim comes back as `CORROBORATED` / `CONTRADICTED` / `UNVERIFIABLE`,
**with the source link attached**. The recruiter clicks through and sees what we
saw. There is no "trust us" step.

`UNVERIFIABLE` is displayed as neutral grey, never red. Most honest people have
a thin public footprint. The product states this in the UI, out loud, because a
tool that quietly punishes the un-Googleable is a tool that punishes people who
aren't already advantaged.

### Axis 3 — Distinctiveness: *is this one voice, or one template?*

Run across the whole applicant pool rather than one resume at a time. We embed
every application and cluster them. When forty applications to one role share a
phrasing skeleton, that is **template collapse** — and it is a property of the
*pool*, not an accusation against any individual in it.

We do not down-rank the cluster. We invert it: inside a collapsed cluster, we
surface the candidates carrying **specific, verifiable, non-generic detail** —
the ones whose particulars survived the blender. This directly answers the
hardest question in the brief: when everything looks the same, distinctiveness
of *fact* is the signal that still works.

---

## 3. The seam: verification runs in both directions

The same engine answers the mirror-image question for the candidate.

A job seeker pastes in a recruiter email, an offer letter, or a careers-page
URL, and Groundtruth checks:

- Is the sending domain the company's real domain, or a look-alike? We generate
  the edit-distance, homoglyph, and TLD-swap neighbourhood of the legitimate
  domain and check which of those neighbours actually resolve and serve mail.
  A registered-last-Tuesday look-alike with live MX records is the single
  highest-signal indicator of an active scam campaign.
- Does this recruiter appear anywhere in the company's real public footprint?
- Does this job posting exist on the company's actual careers page?
- Does the offer letter carry a valid Groundtruth attestation?

One verification engine, two surfaces. The asymmetry that catches a fabricated
candidate is the same asymmetry that catches a fabricated employer.

---

## 4. Why this is auditable by construction

Hiring tools are regulated. NYC Local Law 144 requires bias audits of automated
employment decision tools; the EU AI Act classes employment screening as
high-risk. A scoring system nobody can explain is not shippable in this market
regardless of how well it performs.

Every model call in Groundtruth is traced through **PRISM**:

- **Tracing** — each dossier carries a trace ID. "Why was this candidate
  flagged?" is answerable months later, in an audit, with the exact inputs,
  prompts, and outputs preserved.
- **Guardrails** — extracted resume text is treated as hostile input at the
  boundary, not trusted content. This is the actual fix for prompt injection:
  the resume never occupies the instruction channel.
- **Evaluators** — we assert that the same resume produces the same verdict
  across runs, and that verdicts don't move when we perturb a candidate's name.
  Score stability under name-swap is a bias test we can run in CI.

Auditability isn't a compliance checkbox bolted on at the end. It's the reason a
recruiting org is allowed to deploy this.

---

## 5. What it explicitly refuses to do

Stated as product constraints, because they're what makes it deployable:

1. **No AI-writing score.** Ever. Not surfaced, not computed, not stored.
2. **No auto-reject.** Groundtruth re-orders a queue and attaches evidence. A
   human makes every decision. There is no threshold that rejects anyone.
3. **No blended trust number.** Three axes stay three axes.
4. **Absence of evidence is never evidence of fabrication.** `UNVERIFIABLE`
   is grey.
5. **It ranks nobody down.** It surfaces candidates *up*, with reasons. The
   failure mode of a ranking tool is an invisible person; the failure mode of a
   surfacing tool is a recruiter reading one extra resume.

---

## 6. Architecture

```
          ┌──────────────┐
  resume →│  INGEST      │ PDF/DOCX → text + layer metadata
          └──────┬───────┘
                 │
     ┌───────────┴───────────┬──────────────────┐
     ▼                       ▼                  ▼
┌──────────┐          ┌─────────────┐   ┌───────────────┐
│INTEGRITY │          │   CLAIMS    │   │ DISTINCT      │
│determin- │          │ extraction  │   │ pool-level    │
│istic     │          │   (LLM)     │   │ embeddings    │
└────┬─────┘          └──────┬──────┘   └───────┬───────┘
     │                       ▼                  │
     │              ┌─────────────────┐         │
     │              │  CORROBORATE    │         │
     │              │ Tavily · Solari │         │
     │              │ · GitHub        │         │
     │              └────────┬────────┘         │
     └───────────┬───────────┴──────────────────┘
                 ▼
          ┌──────────────┐
          │TRUST DOSSIER │  3 axes · cited evidence · trace id
          └──────────────┘

   every LLM hop ──────────► PRISM (trace · guardrail · eval)
```

## 7. Stack

| Layer | Choice | Why |
|---|---|---|
| Integrity | Python, zero deps for text; PyMuPDF for PDF layers | Deterministic, testable, fast |
| Claims + reasoning | Claude | Structured extraction |
| Open-web corroboration | **Tavily** | Search built for agent consumption |
| Live-page corroboration | **Solari** | Headless browsers for JS-gated pages |
| Observability | **PRISM** | Tracing, guardrails, evaluators |
| API | FastAPI | Async fan-out across claim checks |
| UI | React + Vite | Recruiter dossier view |
