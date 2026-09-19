# Careers-page verification (Solari)

**"Is this role actually listed where the company lists its roles?"** — the one
check a scammer cannot defeat.

They can forge an email, register a look-alike domain, doctor an offer letter,
and hold a convincing video call. They cannot post a job on the real company's
careers site. That makes this the most decisive signal available to a
candidate, and it is why the check exists.

## Why it needs a browser, demonstrated rather than asserted

Careers pages are almost universally client-rendered — a Greenhouse or Lever
embed, a Workday SPA, search that runs in JavaScript. An HTTP fetch returns an
empty shell, so a `requests.get` implementation concludes "no roles found" for
essentially every real employer. That is the exact false negative that would
make this feature harmful rather than useless.

The test fixture is built to prove this, and the first test asserts the premise
holds — otherwise the rest of the suite would pass against a static page and
demonstrate nothing:

```python
def test_fixture_listings_are_javascript_rendered(site):
    raw = urllib.request.urlopen(f"{site}/careers.html").read().decode()
    assert "Senior Robotics Engineer" not in raw.split("<script>")[0]
    assert "Senior Robotics Engineer" in raw   # present, but only in the script
```

## Why Solari specifically

Careers pages sit behind bot protection — Cloudflare, PerimeterX, Datadome —
which blocks plain headless Chromium. Managed stealth browsing is the specific
problem Solari exists to solve, so this is a real dependency rather than a
sponsor checkbox.

`solari-browser` speaks the Playwright wire protocol, which means one code path
runs against either backend:

| Backend | When | Notes |
|---|---|---|
| `SolariBrowser` | `SOLARI_API_KEY` set | managed, stealth, handles bot protection |
| `LocalBrowser` | local Playwright present | fine for development and unprotected sites |
| `OfflineBrowser` | neither | **refuses** rather than reporting an empty page |

Because the interface is shared, the *logic* is fully tested here against local
Chromium. Only the remote transport is unexercised — a much smaller untested
surface than the API integrations, where the call itself could not be made.

```bash
export SOLARI_API_KEY=slr_live_...    # console.getsolari.com, promo HRHACK2026-DHKB2CEH
python3 -m groundtruth.cli verify --from hr@example.com --company "Datadog" \
    --role "Senior Software Engineer" --check-posting
```

## The asymmetry that governs severity

**Finding the role is strong positive evidence** (`INFO`, and it takes over the
headline). Nobody can publish a job on a company's own site but the company.

**Not finding it proves almost nothing** (`MEDIUM`, capped). Roles get filled
and delisted. Some are never posted publicly. Agencies recruit for unlisted
positions. Listings sit behind search or pagination we did not reach. Every one
of those is an innocent, extremely common explanation.

Treating a miss as evidence of fraud would generate false accusations against
real employers constantly, so the finding says exactly that, and a test asserts
the words "fraud", "fake" and "scam" never appear in it.

**Failing to load the page is not a miss** (`INFO`). `POSTING_NOT_CHECKED` says
"this says nothing about the role — only that the check did not happen."

## Matching

Seniority words are stripped before matching, so *Senior Software Engineer*
matches *Software Engineer II* while "senior" alone does not hit every listing
on the page. Exact title matches are reported verbatim; otherwise 70% of the
distinctive tokens must appear within one line or link label.

The careers page itself is found by following the homepage's own links —
including to third-party ATS hosts (`boards.greenhouse.io`, `jobs.lever.co`,
`*.myworkdayjobs.com`, and others) that no path-guessing would ever reach —
falling back to common paths only if that fails.
