# Recruiting attestations

**A lightweight trust signal an employer can attach to outreach — where the
trust anchor is the employer's own domain, not Groundtruth.**

## Why this shape

The obvious way to build "verify this recruiter" is a directory: we hold the
list of real employers, candidates ask us. That makes us a trusted third party,
which means we are a single point of failure, a censorship surface, a
compromise target, and a business that must survive for its own past answers to
remain meaningful.

So the design inverts it. An employer generates an Ed25519 keypair and
publishes the **public** half on the domain candidates already know how to
check:

```
https://datadoghq.com/.well-known/groundtruth.json
```

Verification fetches that file **from the company's real domain** and checks
the signature against it. Groundtruth is never consulted. If this project
disappeared tomorrow, every attestation ever issued would remain verifiable,
because the only things involved are the employer's domain and public-key
cryptography. We are a format, not an authority.

## Employer side

```bash
python3 -m groundtruth.cli keygen --domain datadoghq.com --contact security@datadoghq.com
```

Writes `datadoghq.com.private.pem` (keep secret) and `groundtruth.json` (publish
at the well-known path). Then, per message:

```bash
python3 -m groundtruth.cli issue \
  --domain datadoghq.com --key datadoghq.com.private.pem \
  --role "Senior Software Engineer" --recruiter a.chen@datadoghq.com \
  --to alex@example.com
```

Emits `gt1.<payload>.<signature>` — about 420 characters, pasteable into an
email footer or an offer letter.

## Candidate side

Paste it into the web app, or:

```bash
python3 -m groundtruth.cli verify --from a.chen@datadoghq.com \
  --company Datadog --attestation "gt1.…" --me alex@example.com
```

## Four properties that are load-bearing

**1. A signature is bound to the sender.** This is the attack that nearly got
through. A valid attestation proves who *issued* it, not who *sent the message
carrying it*. Tokens travel in email; they can be leaked, forwarded or scraped.
Without binding, a scammer at `careers-portal-intl.com` attaching a genuine
leaked Datadog token would have their message labelled *"cryptographically
signed by datadoghq.com"* — the trust signal laundering the scam. So when the
issuer does not match the sender's domain, the result is `CRITICAL`, not
reassurance.

**2. The recipient's address is hashed, never carried.** A candidate can
confirm a token was issued for them, because they know their own address. A
token intercepted, forwarded or scraped reveals nothing about who it was for.
The hash is namespaced so the same address attested by two employers does not
produce the same digest — otherwise employers could correlate candidates.

**3. Attestations expire.** Recruiting outreach is a statement about a moment.
One that never expires is a credential waiting to be replayed at someone else
a year later. Default TTL is 30 days.

**4. A valid signature is not a good job offer.** Verification proves origin,
full stop. The UI says so in the same breath as the green result: *"The
signature confirms the message genuinely came from that domain. It does not
confirm the role, the pay, or that the recruiter has the authority they
claim."* A trust signal that gets read as broader endorsement than it is
becomes a tool for the next scammer patient enough to get one.

## What an absent attestation means

Nothing. Almost no employer publishes these today, and a tool that treated
absence as suspicious would flag essentially the entire legitimate job market.
A domain with no published keys returns a message saying so explicitly: *"Most
employers do not yet — this is not a sign of anything wrong."*

The signal is only ever positive evidence. It never counts against anyone.
