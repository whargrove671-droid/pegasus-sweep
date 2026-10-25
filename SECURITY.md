# Security policy

Pegasus-Sweep is *triage* detection software. This policy explains what to
report and how, and what the project will and won't fix.

## Reporting a vulnerability

Please **do not** open a public issue for a live exploit. Report privately:

- Open a **GitHub Security Advisory** (repo → Security → Report a vulnerability),
  or
- Open a private issue (Issues → New issue → "Security"), or
- Email the maintainer (address in your `git config` commit identity).

You'll get an acknowledgement within a few days and updates as we triage.

## Scope

We care about:

- **Auth bypass** on `/api/ingest` or any write endpoint (the `X-Api-Key`
  contract regressing is critical).
- **Zip-slip / path traversal** in upload extraction (`_safe_extract`).
- **SQL injection / data corruption** through the store layer.
- **Secret handling** — `PSM_SWEEP_TOKEN` leaking into logs/artifacts.
- **Findings that let a reviewer wrongly conclude a device is clean.**

## Out of scope / by design

- The tool **cannot** guarantee detection (see `docs/methodology.md`). Reports
  that "absence of IOCs does not clear a device" are documentation, not bugs.
- No covert or unconsented scanning is in scope by design; requests to add it
  will be declined.
- Third-party tools we invoke (Amnesty MVT) are governed by their own policies.

## Supported versions

Only the `main` branch is supported. Issues against old tags are accepted but
prioritized by impact.

## Disclosure

Co-ordinated disclosure is honored. If you filed a security advisory, we'll
credit you in the fix unless you ask not to be named.