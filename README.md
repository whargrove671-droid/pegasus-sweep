# Pegasus-Sweep

An **indicator-based triage toolkit** for checking whether a device may be
exposed to **commercial spyware** including NSO Group's **Pegasus**, Candiru's
**DevilsTongue**, Intellexa's **Predator**, and Paragon's **Graphite**. It covers **desktops, Android, and
iOS**, produces severity-graded findings backed by [Amnesty International's MVT](https://github.com/mvt-project/mvt)
for phone data, and exposes everything through a **multi-target web dashboard**.

> **BEFORE you trust any result, read `docs/methodology.md`.** This is a
> *triage* tool, not an oracle. A clean result does **not** prove a device is
> free of spyware. Vendors rotate C2 infrastructure and implants constantly.

## Credits & Attributions

This project builds upon the work of many security researchers and organizations.
**See [CREDITS.md](CREDITS.md) for complete attributions.**

Key sources:
- **Amnesty International Security Lab** — Pegasus IOCs, forensic methodology, STIX2 data
- **Citizen Lab** — Candiru/Paragon research, long-term surveillance tracking
- **The-NSO-Blacklist** — 6,643 NSO C2 domains/IPs, architecture docs
- **The-Candiru-Blocklist** — 57+ Candiru domains
- **The-Intellexa-Blocklist** — 516+ Predator domains
- **The-Paragon-Blacklist** — Graphite infrastructure
- **MVT Project** — Mobile Verification Toolkit (MIT license)

## Spyware Vendors Covered

| Vendor | Products | IOCs | Status |
|--------|----------|------|--------|
| **NSO Group** | Pegasus, Phantom, Chrysaor, Quadrant, Novalight, Circles | 81 processes, 5,168+ domains | Active |
| **Candiru** | DevilsTongue, Sourgum | 57+ domains | Active |
| **Intellexa** | Predator (Cytrox) | Multiple domains | Active |
| **Paragon** | Graphite | Tier 1/2 infrastructure | Active |
| **FinFisher** | FinSpy | Historical | Insolvent 2022 |
| **Hacking Team** | RCS | Historical | Rebranded |

**NSO Infection Vectors** (from leaked court documents):
- **Heaven** — First Android 0-click via WhatsApp (2018)
- **Erised** — Samsung-only WhatsApp 0-click (DNG exploit)
- **Eden** — WhatsApp-based vector
- **Hummingbird** — Umbrella term for WhatsApp 0-click family
- **iOS Covert** — iMessage-based 0-click

---

## Targets & how each one gets checked

| Target  | How the data is collected | What it checks |
|---------|---------------------------|----------------|
| **Desktop** | **agentless** (scan the host running the dashboard) **or** a small **agent** (`agent/agent_desktop.py`) you install on machines you own, which POSTs a snapshot to the dashboard | processes, outbound connections (IP + reverse-DNS) vs C2 ranges/domains, autostart/persistence, hosts file |
| **Android** | on-device **agent app** (`android_agent/`) posting packages/processes/accessibility/privileges, **and/or** an uploaded acquisition zip | package/process names, device-owner & overlay & accessibility abuse, sqlite/log anomaly scan |
| **iOS** | **upload an (decrypted) backup / extracted DB set**; server runs MVT + artifact scan | MVT indicators + sqlite/regex anomaly scan (SMS.db, MNT strings) |

Desktop scans happen **on** each desktop you run the agent on — a server cannot
reach across the network to scan an arbitrary machine (and we don't build
covert remote scanners). iOS exposes no web API for on-device inspection, so
backup upload + MVT is the only sound route. This is honest coverage, not magic.

## Documentation

- [docs/methodology.md](docs/methodology.md) — signal strengths, failure modes, and when to trust (or not trust) a result
- [docs/architecture.md](docs/architecture.md) — components, data flow, and key design decisions
- [docs/api.md](docs/api.md) — web endpoints, the agent ingest contract, and CLI reference
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup and contribution guide
- [SECURITY.md](SECURITY.md) — vulnerability reporting policy
- [CREDITS.md](CREDITS.md) — complete source attributions

## Quick start (web dashboard)

```bash
pip install -r requirements.txt
python -m pegasus_sweep.web.app        # → http://127.0.0.1:8097
```

From the dashboard: **Desktop** tab → Run desktop scan (~30–60 s);
**Android** / **iOS** tabs → upload an acquisition zip; **Agents** tab →
set up the desktop agent or build the Android agent app.

> Set a real token for the agent API: `export PSM_SWEEP_TOKEN='…'` (server),
> and hand the same value to each agent. Bind is 127.0.0.1 by default. If you
> expose it beyond loopback, serve HTTPS and use a strong token.

### API for agents
```
POST /api/ingest   Header: X-Api-Key: ***
Body: {"target":"desktop|android","source_label":"…","snapshot":{…}}
```
Returns `{scan_id, summary, findings}`. Every agent payload lands in `/scans`.

## CLI

```bash
# host-only scan -> JSON + HTML in reports/
python -m pegasus_sweep.cli --host --out reports

# phone via Amnesty MVT (requires `pip install mvt` + a device/backup)
python -m pegasus_sweep.cli --mobile ios    --mobile-source /path/to/backup --out reports
python -m pegasus_sweep.cli --mobile android --mobile-source /path/to/image --out reports

# self-test (no phone needed)
python -m pegasus_sweep.tests.test_detection
```

## Unified Daily Report (Windows)

For Windows hosts, run the unified daily report that combines all scans:

```bash
python scripts/unified_daily_report.py
```

This generates:
- HTML report: `unified_report_YYYYMMDD.html`
- JSON report: `unified_report_YYYYMMDD.json`
- Console summary with critical findings highlighted

Scheduled via cron (11:00 PM daily): `Daily Unified Spyware Report`

## Agents

- **Desktop agent** — `agent/agent_desktop.py`. Self-contained (psutil + stdlib);
  copy to any machine you own and run:
  ```bash
  python agent_desktop.py --server http://<dashboard>:8097 \
      --token "$PSM_SWEEP_TOKEN" --label laptop-name
  ```
- **Android agent** — `android_agent/`. Kotlin app (AGP 8.5); builds an APK you
  install on a device you control. Collects what public Android APIs expose
  (packages, grants, enabled accessibility services, best-effort process list)
  and POSTs to `/api/ingest`. Build steps in `android_agent/README.md`.
- **iOS** — no app; backup-upload path via the dashboard (see methodology for
  why an iOS app can't do this reliably).

## Project layout

```
pegasus_sweep/
  cli.py                 # command-line entry point
  core/                  # iocs.py, report.py, settings.py
  modules/               # host_scanner.py, mobile_forensics.py
  web/
    app.py               # Flask multi-target dashboard
    scanning.py          # orchestrator (desktop/android/iOS ingest + scan)
    db.py                # SQLite scan history
    templates/           # base, dashboard, scan view
  tests/test_detection.py# self-test
agent/agent_desktop.py   # standalone desktop agent
android_agent/           # Android agent app source (Kotlin/Gradle)
indicators/
  pegasus_iocs.yaml      # seed IOC oracle (see below!)
  pegasus_processes.yar  # YARA rules for 81 Pegasus processes
scripts/
  pegasus_scan.ps1       # PowerShell spyware detection
  pegasus_scan_wrapper.py # Python cron wrapper
  browser_history_scanner.py # Browser history scanner
  yara_scan_wrapper.py   # YARA process scanner
  unified_daily_report.py # Unified daily report
  refresh_iocs.py        # Daily IOC refresh
  block_c2_ips.ps1       # Windows Firewall C2 block rules
uploads/                 # (runtime) received acquisitions — gitignored
data/scans.db            # (runtime) scan history — gitignored
```

## The indicator oracle (IMPORTANT)

`indicators/pegasus_iocs.yaml` ships as a **small seed set** of publicly
documented *example* indicators with attribution. It is deliberately **not** a
current, comprehensive threat feed. For a real scan you must refresh it from:
- [Amnesty MVT](https://github.com/mvt-project/mvt/tree/main/mvt/ios/iocs)
- [Citizen Lab](https://citizenlab.ca) long-term surveillance research

Swap in a fresh YAML (same schema) — no code changes needed; the engine only
reads the oracle.

## How a result is produced

1. **Collect** evidence (host telemetry, agent snapshot, or uploaded artifacts).
2. **Match** against the oracle via `IOCEngine`.
3. **Grade** each finding `info → critical`; every finding carries the oracle
   profile + feed it matched.
4. **Persist** as a scan row (SQLite) and **render** in the dashboard with a
   per-finding evidence string for analyst triage.

## Hard limits (read before trusting a clean result)

- **Absence of a match ≠ non-infection.** Spyware rotates infrastructure fast.
- **Live telemetry is transient** — repeat scans across sessions.
- **Process-name matching is the weakest signal** — corroborate with network +
  persistence evidence.
- **Seed IOC list will miss and over-report.** Replace it fresh before relying
  on the output.
- Desktop scanning cannot clear a phone. Android/iOS checks reflect *what the
  OS lets an app/backup examiner see*, not a full sandbox escape detection.
- The **Android agent** and **upload scanning** here were exercised with
  synthetic fixtures; a real device/backup + MVT needs to be validated by a
  forensic examiner.

## Remediation guidance (if you get a hit)

1. Do **not** power off / factory-reset immediately — you'd destroy evidence.
2. Disable networking, preserve a forensic image/backup.
3. Engage a qualified incident responder / DFIR examiner; for high-risk persons
   follow Citizen Lab / Amnesty protocol.
4. After evidence is preserved, harden/wipe and reinstall.
5. Review your threat model; rotate credentials; isolate sensitive comms.

## License

[MIT](LICENSE) — free to use, modify, and distribute (attribution required).
This license applies to the original code and orchestration in this repository.

- The **seed IOC set** (`indicators/pegasus_iocs.yaml`) is a tiny set of
  publicly published example indicators; reuse it with attribution to the
  original public sources noted in the file.
- **Amnesty International MVT** is separately [MIT-licensed](https://github.com/mvt-project/mvt)
  and is invoked as an external tool, not vendored or redistributed here.
- **Third-party IOCs** remain the property of their original researchers;
  see [CREDITS.md](CREDITS.md) for complete attributions.
