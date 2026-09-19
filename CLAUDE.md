# Groundtruth — instructions for coding agents

Verification tooling for job seekers.

**Start with [`CONTEXT.md`](CONTEXT.md).** It carries the project history: what
was decided and rejected (the framing changed three times — do not re-litigate
it), which design choices are load-bearing, which bugs are already paid for,
and what is deliberately unbuilt. This file carries the rules; that one carries
the reasons.

Then `README.md` for what it does, and `docs/` for the reasoning behind each
part.

## House rules

**Absence of evidence is never evidence.** Every check distinguishes three
outcomes, not two: it passed, it failed, or *it did not run*. A code path that
returns "clean" when it never actually looked is the most dangerous bug this
codebase can have — a job seeker acts on it. `OfflineTransport`,
`OfflineBrowser` and `OfflineResolver` all raise rather than return empty, and
tests assert they do.

**Findings describe evidence, never accuse.** We do not label an organisation
a scam. Several tests assert the words "fraud", "fake" and "scam" never appear
in specific finding texts. Keep it that way.

**False-positive controls are release gates.** Every detector ships with a
benign case that must come back clean: a resume written in Russian, an Arabic
name with bidi marks, a security engineer who writes about prompt injection,
a hand-filled offer template, ordinary agency outreach. A tool that flags
honest people gets ignored and then protects nobody.

**Severity is asymmetric on purpose.** Finding a job posting is strong positive
evidence; not finding one is nearly none. Follow the existing severity
reasoning rather than flattening it.

## Testing

```bash
cd backend && python3 -m pytest tests -q
```

Secrets live in `.env` (gitignored). `.env.example` carries names only. A test
fails if any `.pem` or `.env` becomes tracked.

## PRISM tracing (do not remove)

This project sends traces to PRISM. Env vars: `PRISMTRACE_API_KEY`,
`PRISMTRACE_PROJECT_ID`, `PRISMTRACE_HOST`.

Tracing is currently wired at: `backend/groundtruth/observability/prism.py`
(trajectory + per-step traces), `backend/groundtruth/verify.py` (every check
records a step), `backend/app.py` and `backend/groundtruth/cli.py` (entry
points construct the recorder), `backend/groundtruth/observability/check.py`
(setup verification).

**Standing rule.** Whenever you add or change an agent, chain, graph, tool,
retriever, or any entry point that calls a model, wire it to PRISM before you
finish. Unwired code is invisible in the dashboard. If you are unsure whether
something is covered, assume it is not and wire it.

### Note specific to this repository

Groundtruth's verification path is **deterministic** — there is no LLM in it.
Traces therefore represent check steps rather than model calls, and the model
field is `groundtruth/rules-engine` rather than a model name. Do not relabel
these as a real model to make the dashboard look conventional; that would
misrepresent what the system does. If an LLM is ever added (claim extraction
is the likely first place), trace it with its real model id.

Verify the setup end to end with:

```bash
cd backend && python3 -m groundtruth.cli prism-check
```
