# Handoff context

**Read this first if you are a coding agent picking up this repository.**
`CLAUDE.md` has the house rules you must follow. This file has the history and
reasoning behind them — what was decided, what was tried and rejected, what is
half-built, and which mistakes are already paid for.

Branch: `claude/tender-lovelace-4vgxta` (the repository's default).
State when written: 139 tests passing, all six checks built, all three sponsor
integrations live-verified. Run `git log --oneline` for what has landed since —
commit messages here are written to explain *why*, not just what.

---

## 1. What this is

**Groundtruth — verify who is recruiting you, before you hand over anything.**

A candidate-side tool. A job seeker pastes in recruiter outreach — the sender
address, the message, optionally an offer letter PDF or a signed verification
code — and gets back a cited, tiered account of what is and is not verifiable
about it.

Built for the NYU Hiring Trust Hackathon, **Side B** of the brief
(impersonation and candidate scams). Side A work exists in the repo as
infrastructure, not as the product — see §3.

### The thesis, which governs every design decision

> We never ask "was this written by AI?" We ask "is any of this real?"

AI-detection is unanswerable, gets worse every month, and correlates with
non-native English writing — so acting on it means punishing honest people and
inviting a discrimination claim. Verification gets *easier* as models improve.
A model writes a flawless scam email in four seconds; it cannot make a domain
older than it is, or publish a job on a company's real careers page.

**Fabrication is cheap. Corroboration is expensive.** That asymmetry is the
product.

### Who it is for

Job seekers, sharpest for **international students on F-1/OPT**. They face the
only version of this harm that is deferred and irreversible: consultancies
charge them for fabricated work experience, vanish, and the student can be
detained or removed *years later* — sometimes never having known the record was
false. The information a verification tool provides has to arrive at the moment
of decision, because nothing else will.

Full market reasoning with citations: `docs/MARKET.md`.

---

## 2. Framing history — do not re-litigate this

The framing changed three times in one session. The final position is settled.
If you are tempted to revisit it, read this section first; the earlier framings
were considered and rejected for stated reasons.

| Framing | Status | Why it was dropped |
|---|---|---|
| Generic "hiring funnel" trust tool | rejected | Too broad to demo; no specific user |
| **Employer-side**: sell to staffing agencies | **rejected** | The user's call, and correct: agencies are frequently the *threat*, not the customer. Research supports it — most candidates with forged credentials enter through a staffing firm sourced via a subcontractor |
| **Candidate-side**: protect job seekers from predatory intermediaries | **CURRENT** | The underserved side. Nobody builds for them because they cannot pay, which is exactly what makes them underserved |

`docs/MARKET.md` was rewritten for the current framing. Any remaining reference
to selling to agencies is a bug.

---

## 3. What is built

All of this works and is tested. Nothing below is a stub.

### The six checks

| Check | Module | What it establishes |
|---|---|---|
| **Sender impersonation** | `outreach/domains.py` | Is the sending domain the company's, a confusable imitation, or unrelated? Homoglyph folding, typosquat, combosquat, brand-in-subdomain, punycode/IDN, disposable and free mail |
| **Predatory practices** | `outreach/practices.py` | What is the message *asking you to do*? Three tiers: **illegal** (candidate fees, shifting H-1B costs to the worker, fabricated employment records, money mule), **harmful** (PII before an offer, unpaid bench, untraceable payment, exclusivity before disclosure), **context** |
| **Employer corroboration** | `corroborate/employer.py` | Does the company exist, and what is its real domain? **Tavily** |
| **Document integrity** | `integrity/` | Hidden text, Unicode Tag smuggling, bidi, homoglyphs, machine-directed instructions, and post-production edits to offer letters |
| **Careers-page listing** | `corroborate/posting.py` | Is this role listed where the company lists roles? **Solari** |
| **Signed attestation** | `attest/` | Ed25519 signature verified against the *employer's own domain* |

### Orchestration and surfaces

- `verify.py` — runs the checks in a deliberate order and summarises them
- `app.py` + `static/index.html` — FastAPI service and the candidate-facing page.
  `POST /api/verify` returns a whole result; `POST /api/verify/stream` returns
  newline-delimited JSON, one real event per check as it finishes. The UI uses
  the streaming one. `verify_iter()` is the generator both are built on;
  `verify()` drains it, so non-streaming callers are unaffected
- `cli.py` — `verify`, `demo`, `keys`, `keygen`, `issue`, `prism-check`
- The page carries a hero stating the problem with cited figures, a live check
  list, and a closing "what to do now" block with reporting links and a
  copy-to-clipboard report for forwarding to a school's ISSS office
- `observability/` — PRISM tracing and the setup verifier

### Sponsor integrations — all three live-verified

Confirmed working against real endpoints from a developer machine:

```
$ python3 -m groundtruth.cli prism-check
  CREDENTIAL OK — credential valid, synthetic trace stored
  run 2907ea94 · 5 steps · verdict critical · Submitted to PRISM.
  live_connected=True  blocked_step=-  overall=connected
  LIVE CONNECTED
```

**Tavily** performs the employer lookup. **Solari** is the browser backend.
**PRISM** receives a trajectory plus per-step traces per verification.

> ⚠️ The cloud build environment cannot reach any of the three — its egress
> policy returns **403 on CONNECT** for `api.tavily.com`,
> `prism-api-prod.up.railway.app` and `*.getsolari.com`. That is a network
> policy, not a broken integration. Everything runs offline via cassettes,
> fixtures and local Chromium. Do not conclude an integration is broken from a
> 403 here; run it on a machine with egress.

---

## 4. Design decisions you should not undo

Each of these was reached deliberately. Several were bugs first.

**Severity is a function of document layer, not wording.** `"Ignore all
previous instructions"` is `CRITICAL` hidden in 1pt white text and `INFO` in a
security engineer's visible bullet. Concealment establishes intent; the string
does not. This is the single idea the integrity axis rests on.

**The font baseline for tampering is document-wide, never per-line.** A
per-line vote elects the forgery as the norm: on `Dear <name>,` a replaced
14-character name outweighs the five characters around it, so the tool flagged
`"Dear"` and returned *clean* for a doctored document.

**Attestations are bound to the sender.** A valid signature proves who
*issued* it, not who *sent the message carrying it*. Before this, a scammer on
an unrelated domain attaching a leaked token got the headline
*"cryptographically signed by datadoghq.com"* — the trust signal laundering a
scam. Found by attacking our own feature.

**Groundtruth is not the trust anchor.** Employers publish keys at
`/.well-known/groundtruth.json` on their own domain. If this project vanished,
every attestation stays verifiable. We are a format, not an authority. Do not
add a central directory.

**PRISM traces say `model="groundtruth/rules-engine"`.** The verification path
is deterministic — there is no LLM in it. Relabelling as a real model to make
the dashboard look conventional would misrepresent the system. Asserted by a
test.

**A tick means evidence, not completion — the same rule, in UI form.** The
live checklist shows green only for checks that confirmed something positive. A
check that finished without confirming anything stays neutral, and skipped
checks are shown rather than hidden. The first version put a green tick beside
*"unverifiable"*, which told the reader the opposite of the truth. If you touch
`markStage()` in `static/index.html`, keep this.

**Progress events are real.** `verify_iter()` yields as each check finishes and
the page renders those events. Replaying a finished result on a timer would
have been simpler and would have been theatre dressed as instrumentation — an
especially bad thing to ship in a product about verification.

**Absence of evidence is never evidence.** `OfflineTransport`,
`OfflineBrowser` and `OfflineResolver` raise rather than return empty. Reporting
"nothing found" when nothing was checked is the most dangerous bug available
here — a job seeker acts on it.

**Findings never accuse.** No organisation is labelled a scam. Tests assert the
words "fraud", "fake" and "scam" never appear in specific finding texts.

---

## 5. Bugs already found and fixed

Do not reintroduce these. Each has a regression test.

| Bug | Why it mattered |
|---|---|
| `Severity` subclasses `str`, so it inherited alphabetical ordering — `CRITICAL >= MEDIUM` was `False` | Every threshold check was inverted |
| PyMuPDF clips text outside the mediabox by default | Off-page injection payloads were dropped entirely |
| Render mode 3 surfaces as `alpha == 0`, not `char_flags` | Invisible text was read as visible |
| Per-line font vote (see §4) | Doctored documents returned clean |
| Hyphenated domains flagged as typosquats of themselves (`acme-robotics.com` vs "Acme Robotics") | Every hyphenated employer would be flagged. Fix: test the **raw** name — whether matching *required* deconfusion is what separates a real domain from a Cyrillic imitation |
| Attestation findings absent from the API response | UI rendered a CRITICAL verdict with the critical finding invisible |
| `registrable_parts` split IP literals into `("0","1")` | Nonsense comparisons against company names |
| A MEDIUM result matched no summary branch | "Worth a second look" read as "nothing alarming found" |
| Green tick shown beside a check that confirmed nothing | The UI said "verified" where the engine said "unverifiable" |
| `default_browser` claimed a backend without checking the client library was importable | Would fail at render time on serverless instead of up front |
| Unanchored `keys.*` gitignore pattern | Also matched `attest/keys.py` — real source, silently excluded |
| 15s PRISM flush on a 10s serverless cap | Would time out the response, losing both trace and answer |

---

## 6. What is not built

- **No LLM anywhere.** Deliberate. Claim extraction from resume text is the
  likely first place one belongs. If you add it, trace it with its real model id.
- **Cassettes are hand-written fixtures**, not recordings — labelled as such in
  `backend/tests/cassettes/README.md`. Replace them by running with
  `GROUNDTRUTH_RECORD_DIR` set on a machine with a Tavily key.
- **Careers-page check does not run on Vercel** — `playwright` + `solari-browser`
  are ~277MB, over the 250MB function limit. Reported honestly via
  `/api/health` → `can_browse: false`. See `docs/DEPLOY.md`.
- **No persistence.** Every verification is stateless. Uploaded documents are
  processed in a temp file and unlinked in a `finally` block.
- **No rate limiting or auth** on the API. Fine for a demo, not for public
  deployment.
- **The demo attestation** is for a fictional `datadoghq.com`. Regenerate with
  `backend/tests/registry/make_registry.py`.

### Sensible next steps

1. Record real Tavily cassettes to replace the synthetic ones.
2. Serve `/.well-known/groundtruth.json` from the app so the deployment
   dogfoods its own trust signal on whatever domain it runs on.
3. Claim extraction (the first legitimate LLM) → resume-side corroboration.
4. Rate limiting before any public deployment.

---

## 7. Running it

```bash
git clone -b claude/tender-lovelace-4vgxta https://github.com/divyanshmaurya/hackathon_nyu
cd hackathon_nyu
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
python3 -m playwright install chromium     # only if not using Solari

cd backend && python3 -m pytest tests -q   # 139 passing
python3 -m uvicorn app:app --port 8000     # http://127.0.0.1:8000
```

Credentials go in a **gitignored `.env`** at the repo root — never in the
repository. `cp .env.example .env`, fill in, then `python3 -m groundtruth.cli
keys` to confirm. The loader rejects RTF (TextEdit's default) rather than
parsing it into garbage, and normalises typographic quotes.

Everything runs without keys: corroboration replays cassettes, tracing records
locally, the browser falls back to local Chromium.

### Demo script

Five one-click examples in the web UI, in this order: **OPT consultancy
pitch** (11 findings, tiered) → **Ordinary recruiter** (clean — the
credibility move) → **Look-alike domain** → **Signed by the employer** →
**Stolen signature**.

The last two are the strongest beat: *the same valid signature, two senders,
opposite verdicts.*

For document forensics, attach `samples/offers/03_name_tampered.pdf` (caught —
`'Priya Raghavan' [Courier 11.5pt] vs body [Helvetica 11.0pt]`) and then
`05_control_hand_filled.pdf` (clean — an innocent cause of the same
fingerprint).

---

## 8. Where the reasoning lives

| Document | Contents |
|---|---|
| `CLAUDE.md` | House rules. Binding on agents |
| `docs/PRODUCT.md` | Thesis, three axes, architecture |
| `docs/MARKET.md` | Audience, citations, sustainability, non-goals |
| `docs/ATTESTATION.md` | Signed attestations, the four load-bearing properties |
| `docs/SOLARI.md` | Careers-page verification, why a browser is required |
| `docs/DEPLOY.md` | Vercel and container hosts |

Test files are the specification for their modules. The false-positive controls
in particular are release gates, not examples — read them before changing a
detector.
