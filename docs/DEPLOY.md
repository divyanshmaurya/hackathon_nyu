# Deploying

## Vercel

Works, with one documented limitation.

### Setup

1. Import the GitHub repository at [vercel.com/new](https://vercel.com/new).
   `claude/tender-lovelace-4vgxta` is the repository's default branch, so it is
   picked up automatically. Leave the framework preset on **Other** — the
   `vercel.json` at the root handles routing.
2. Add the environment variables under **Settings → Environment Variables**:

   | Name | Required |
   |---|---|
   | `TAVILY_API_KEY` | for live employer corroboration |
   | `PRISMTRACE_API_KEY` | for tracing |
   | `PRISMTRACE_PROJECT_ID` | for tracing |
   | `PRISMTRACE_HOST` | if your PRISM brief names a host other than the SDK default |

   Without them the deployment still runs: corroboration replays recorded
   cassettes and tracing records locally.
3. Deploy. Confirm with `https://<your-app>.vercel.app/api/health`.

### What does not run on Vercel

**The careers-page check.** `playwright` and `solari-browser` are ~277MB
unzipped between them, over Vercel's 250MB serverless function limit, and both
bundle browser drivers that cannot execute in a serverless function anyway. The
root `requirements.txt` therefore excludes them.

The deployment does not pretend otherwise. `/api/health` reports
`"can_browse": false`, the web form disables that checkbox with an explanation,
and the check itself returns `POSTING_NOT_CHECKED` — which states that nothing
was verified, rather than implying the role is absent.

Everything else works: sender impersonation, predatory-practice detection,
employer corroboration, document forensics, and signed attestations.

Run the careers-page check locally instead:

```bash
cd backend && python3 -m groundtruth.cli verify \
    --from hr@example.com --company "Datadog" \
    --role "Senior Software Engineer" --check-posting
```

### Serverless timing

Vercel Hobby caps an invocation at 10 seconds. The PRISM client detects a
serverless environment and shrinks its request and flush budgets so telemetry
cannot time out the response itself. Verifications without the browser check
complete in roughly one to two seconds.

## A container host instead

If you want the whole product deployed, including careers-page checking, use a
host that runs a persistent container — Render, Railway or Fly. There is no
function size limit, no invocation cap, and the full
`backend/requirements.txt` installs:

```bash
pip install -r backend/requirements.txt
python -m playwright install chromium     # only if not using Solari
cd backend && uvicorn app:app --host 0.0.0.0 --port $PORT
```

Set the same environment variables. This is the better fit for the product;
Vercel is the better fit for a link you want to share today.
