# Architecture

How Pegasus-Sweep is put together and how data flows through it. Read this
after the [README](../README.md) and before contributing.

## Big picture

Pegasus-Sweep is a **detection *orchestrator***: it gathers evidence about a
device, matches that evidence against an **indicator oracle**, grades each hit,
persists it, and renders it for a human triager. The one architectural rule
that keeps it maintainable:

> **Knowledge (IOCs) is separated from evidence (telemetry), and both are
> separated from presentation (reports).**

```
                        ┌────────────────────────────────────────────┐
                        │                 IOC ORACLE                 │
                        │   indicators/pegasus_iocs.yaml  (YAML)     │
                        └───────────────────┬────────────────────────┘
                                            │  loaded by
                                            ▼
                        ┌────────────────────────────────────────────┐
                        │  core/iocs.py  →  IOCOracle / IOCEngine   │
                        │  (normalize IOCs; pure matching)          │
                        └───────┬────────────────────────┬──────────┘
                                │                        │
            evidence ──────────▶│                        │◀─────── control
                                ▼                        ▼
   collectors              match against            orchestration
   ─────────────────       ─────────────────     ─────────────────
   host_scanner.py         Finding(category,       cli.py
   mobile_forensics.py     indicator, evidence,    web/scanning.py
   agent/agent_desktop.py  severity, profile,
   android_agent/*.kt      matched_feed)
                                │
                                ├──────────┐
                                ▼          ▼
                          core/report.py + web/db.py (SQLite history)
                                │
                                ▼
                     web/app.py (Flask dashboard)
```

## Components

### `core/iocs.py` — oracle + engine
- `IOCOracle`: parses the YAML, normalizing C2 CIDRs to `ipaddress` objects and
  lower-casing name/path/domain terms. It also answers queries like
  "which registry keys to audit".
- `IOCEngine`: stateless matchers — `match_process`, `match_ip`, `match_domain`,
  `match_file_path`, `match_registry_key`, `match_regex`. Every matcher returns
  a `Finding` carrying the matched indicator, the evidence string, a severity,
  and the oracle profile + feed it matched (provenance).
- `Finding` is a plain dataclass; the report layer renders it.

### `core/settings.py` — runtime config
Paths (`DEFAULT_IOC_PATH`, `BASE_DIR`), severity ordering, and the web API key
(`PSM_SWEEP_TOKEN`). Kept out of the oracle so knowledge and config never mix.

### `core/report.py` — presentation
Builds a normalized report dict, and renders it as **JSON** and a
**self-contained HTML** report (no external assets). The `_findings_table` and
`_kv_table` helpers are shared with the web dashboard.

### `modules/host_scanner.py` — desktop evidence
- `HostSnapshot`: processes, TCP/UDP connections, autostart registry keys,
  startup-folder entries, hosts file.
- `HostScanner.collect()` uses `psutil` (with a `tasklist` fallback).
  Reverse-DNS lookups are bounded (1.5 s timeout + a cap of 60) so a slow
  resolver cannot stall a scan.
- `HostScanner.analyze()` feeds the snapshot through the engine.

### `modules/mobile_forensics.py` — phone evidence
- Wraps Amnesty **MVT** (`mvt ios decrypt-backup` / `mvt android extract`) when
  installed, and always runs `scan_artifacts`: walk an extracted/uploaded
  directory, scan sqlite DBs named in the oracle and textual logs, and run the
  platform anomaly regexes.
- `scan_artifacts` is shared by the CLI/MVT path and the web upload path.

### `pegasus_sweep/web/` — the dashboard
- `scanning.py`: orchestrator binding the engine to each target
  (`scan_desktop_agentless`, `ingest_desktop_agent`, `ingest_android_agent`,
  `scan_artifact_dir`). Each returns a uniform
  `(status, message, summary, snapshot, findings)` tuple.
- `db.py`: SQLite persistence. One row per scan; summary, snapshot and findings
  stored as JSON blobs. **A fresh sqlite connection is opened per operation**
  (`@contextmanager _conn`) — this is deliberate: SQLite connections are not
  shareable across threads, and the dev server + the async desktop scan run on
  multiple threads.
- `app.py`: Flask routes (see `docs/api.md`).
- `templates/`: `base.html`, `index.html` (dashboard), `view.html` (single scan).

### `agent/agent_desktop.py` — remote desktop agent
Self-contained (stdlib + `psutil`) so it can be copied onto any machine you own.
Collects a snapshot and POSTs it to `/api/ingest`. Push-only: it accepts no
commands from the server.

### `android_agent/` — on-device Android agent (Kotlin)
Source only (needs an Android SDK to build). Enumerates what public Android
APIs expose — installed packages + grants, enabled accessibility services,
device-owner status, best-effort `ps` — and POSTs a snapshot. See its README.

## Key design decisions

1. **Findings are triage, not verdicts.** Severity is a ranking aid, and every
   finding carries provenance so a reviewer can independently judge it.
2. **The oracle is swappable at runtime.** `PEGASUS_IOC_PATH` (or the dashboard
   default) points at a YAML; refresh the feed without touching code.
3. **Upload extraction is zip-slip safe.** `_safe_extract` in `app.py` resolves
   each member and rejects anything escaping the extraction root.
4. **Auth is strict.** `/api/ingest` requires `X-Api-Key == PSM_SWEEP_TOKEN`.
   There is deliberately **no thread-name bypass** — the async desktop scan
   calls `scanning` directly and never touches the endpoint.
5. **Concurrency boundary.** The desktop agentless scan runs in a background
   thread and persists directly to the store; reads happen from request
   threads. The fresh-connection-per-call store makes this safe.

## What it deliberately is NOT

- Not a definitive detection tool (see `docs/methodology.md` for failure modes).
- Not a covert or remote *scanner*: a server cannot reach across the network
  to scan an arbitrary machine, and the agents are self-installed, push-only.
- Not rendering an "infected/clean" verdict from IOCs alone.