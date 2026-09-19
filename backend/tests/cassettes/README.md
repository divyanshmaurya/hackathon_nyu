# Cassettes

Recorded Tavily responses, replayed so tests and demos run deterministically
and offline.

**The files here are hand-written fixtures in Tavily's response shape, not
recordings of live API calls.** The development environment's egress policy
blocks `api.tavily.com`, so no live response could be captured here. They
exercise the real parsing and scoring code paths, but they are not evidence
that the live integration has run.

To replace them with genuine recordings, on a machine with network access:

```bash
export TAVILY_API_KEY=tvly-...
export GROUNDTRUTH_RECORD_DIR=backend/tests/cassettes
python3 -m groundtruth.cli verify --company "Datadog" --from careers@datadoghq.com
```

`LiveTransport` writes each response to that directory keyed by query hash.
Delete the hand-written files once real ones exist.
