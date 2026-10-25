# API reference

This document specifies the web dashboard's HTTP interface, the agent ingest
contract, scan-history semantics, and the CLI surface. URLs are relative to the
dashboard base URL (default `http://127.0.0.1:8097`).

## Authentication

Agent-facing (write) endpoints require a shared key:

- The server reads `PSM_SWEEP_TOKEN` (env var) at startup. Without it, it
  defaults to `change-me-psm` (development only).
- Agents send `X-Api-Key: <token>`. A missing or wrong key returns **401**.
- Page routes (`/`, `/scans`, `/scan/<id>`) are read-only views and bind to
  127.0.0.1 by default.

> Deploying beyond loopback: put the dashboard behind a reverse proxy with
> TLS, set a strong `PSM_SWEEP_TOKEN`, and never expose the token in logs.

## Endpoints

### `GET /` — dashboard (HTML)
### `GET /scans` — scan history (JSON)

```json
{ "scans": [
  { "id": 1, "target": "ios", "mode": "upload", "source_label": "ios_bkp.zip",
    "status": "done", "message": "Artifact scan ...", "created_at": "...",
    "summary": { "total_findings": 1, "by_severity": {"critical":0,"high":0,
                  "medium":1,"low":0,"info":0} },
    "findings": [ { "category": "ios_artifact", "indicator": "(?i)\\.sh\\.pkg",
                    "evidence": "...", "severity": "medium",
                    "profile": "0.1.0", "matched_feed": "" } ] }
] }
```

### `GET /scan/<id>` — single scan (HTML render)
Returns 404 when the id does not exist.

### `POST /scan/desktop` — start an agentless desktop scan (async)
Returns immediately with `{"queued":true,"target":"desktop"}`. The scan runs in
the background (~30–60 s) and a new row appears in `/scans` on completion.

### `POST /scan/<target>` — upload an acquisition for `target ∈ {ios, android}`
Multipart form with a `file` field (`.zip`, `.tgz`, `.tar`, or a raw `.db`).
Extraction is zip-slip protected. On success returns **302** to `/scan/<id>`.
A `running` row is created first and updated in place when done.

### `POST /api/ingest` — agent endpoint (requires `X-Api-Key`)
Accepts the snapshot from a desktop or Android agent.

## Agent ingest contract (`POST /api/ingest`)

Request:

```json
{
  "target": "desktop" | "android",
  "source_label": "string, shows in history, recommended",
  "snapshot": { "…": "…" }
}
```

### `desktop` snapshot
```json
{
  "hostname": "DESKTOP-…", "os": "Windows 10",
  "processes":       [ { "name": "explorer.exe", "exe": "C:\\Windows\\…" } ],
  "connections":     [ { "remote_ip": "203.0.113.9", "remote": "203.0.113.9:443",
                         "remote_host": "host.example.com", "pid": 1234 } ],
  "registry_keys":   [ "HKCU\\Software\\…\\Run\\foo = C:\\…" ],
  "startup_entries": [ "C:\\Users\\…\\Startup\\thing.exe" ],
  "hosts_entries":   [ "127.0.0.1 localhost" ]
}
```

### `android` snapshot
```json
{
  "os": "Android 14", "device": "Pixel 8",
  "packages": [ { "name": "com.app.example", "label": "App", "flags": 0,
                  "is_device_owner": false, "can_overlay": false,
                  "has_accessibility": false } ],
  "processes":       [ { "name": "system_server" } ],
  "services_abusing":[ { "id": "com.a/.svc", "class": "com.a.svc", "flags": 0 } ],
  "artifacts":       [ { "path": "/data/local/tmp/x.db", "content": "" } ]
}
```

Response (HTTP 200): `{ "scan_id": <id>, "summary": {…}, "findings": [ … ] }`

Matching logic is in `web/scanning.py` and is additive — it treats the snapshot
as the best available evidence, never as a guarantee.

## CLI

```bash
python -m pegasus_sweep.cli --iocs <yaml> --out <dir> --host
python -m pegasus_sweep.cli --mobile ios --mobile-source <backup> --out <dir>
python -m pegasus_sweep.cli --mobile android --mobile-source <image> --out <dir>
```

Writes `report.json` + `report.html` into `--out` and prints a JSON summary.

## Self-test

```bash
python -m pegasus_sweep.tests.test_detection
```

Does not require a phone or MVT; exercises the engine + report path.

## Error semantics

| HTTP | Meaning |
|------|---------|
| 400 | bad target / missing upload field |
| 401 | missing or wrong `X-Api-Key` |
| 404 | `/scan/<id>` not found |
| 413 | upload over 512 MB |
| 500 | upstream scan/extraction failure (message body contains the reason) |