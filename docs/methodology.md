# Security & detection methodology for Pegasus-Sweep

This document is the honest account of what this tool can and cannot establish,
and how the signals should be interpreted. **Read it before trusting a result.**

## 1. Why indicator matching is the wrong tool for a *decision*

Commercial spyware is an offensive, actively-maintained implant built by
well-funded vendors with large budgets. Its core design goal is to avoid the
exact signals this toolkit scans for. Consequences:

- **Constant rotation.** C2 domains, IPs, file paths, and process naming
  change over time. Any static indicator set (ours included) drifts stale.
- **Stealth by design.** A fully-armored spyware install may expose almost no
  file-system or naming artifacts detectable pre-compromise.
- **The platform asymmetry.** Pegasus primarily targets *phones* (iOS/Android).
  A Windows host scan — however thorough — says essentially nothing about a
  phone sitting next to it. Mobile coverage requires MVT-style forensic
  extraction.

Therefore every output here is a **candidate signal for human triage**, graded
by severity, never a machine verdict of "infected" / "clean."

## 2. Spyware vendors covered

This toolkit detects indicators from multiple commercial spyware vendors:

### NSO Group (Israel)
- **Pegasus** — flagship iOS/Android spyware
- **Phantom** — Windows-specific variant
- **Chrysaor** — Android variant
- **Quadrant** — surveillance tool
- **Novalight** — NSO tool
- **Circles** — location tracking

**Infection vectors** (from leaked NSO documents):
- **Heaven** — First Android 0-click via WhatsApp (2018)
- **Erised** — Samsung-only WhatsApp 0-click (DNG exploit)
- **Eden** — WhatsApp-based vector
- **Hummingbird** — Umbrella term for WhatsApp 0-click family
- **iOS Covert** — iMessage-based 0-click

### Candiru / Saito Tech Ltd (Israel)
- **DevilsTongue** — also known as Sand Cat, Caramel Tsunami, Sourgum

### Intellexa / Cytrox (Greece)
- **Predator** — Android/iOS spyware

### Paragon Solutions (Israel)
- **Graphite** — cloud-based spyware

### Historical vendors
- **FinFisher / Gamma Group** (FinSpy) — insolvent 2022
- **Hacking Team** (RCS) — rebranded as Memento Labs
- **Cyberbit** — Ethiopian dissident targeting
- **Sandvine** — DPI-deployed spyware
- **Dark Basin / BellTroX** — hack-for-hire
- **Stealth Falcon** — UAE dissident targeting

## 3. The detection pipeline

```
live telemetry  ──►  collect   ──►  match vs oracle  ──►  grade   ──►  report
(host)                (snapshot)       (IOCEngine)      (severity)
phone artifacts ──►  mvt extract ──►  sqlite/regex scan
```

Each step is deliberately separable so an analyst can inspect any stage.

## 4. Signal strength ordering (weak → strong)

1. **Process name only (weakest).** Names like "scout" / "tangerine monitor"
   are common words; a benign process can share a name. Never accept alone.
2. **File path substring.** Slightly stronger, still spoofable; medium.
3. **Autostart / persistence.** Medium — implants want persistence, so an
   unexpected autorun entry is notable regardless of the indicator list.
4. **Network C2 (strongest).** A live outbound connection to a documented C2
   IP/domain is the most corroborating single signal, and here it is matched
   conservatively (private IPs are excluded to reduce noise).
5. **Security product tampering (very strong).** Pegasus and similar spyware
   disable Windows Defender (WinDefend, Sense, WdNisSvc). If these services
   are stopped without explanation, investigate immediately.

## 5. Known failure modes (be explicit about these)

- **False negative from rotation:** indicator list is old → real C2 missed.
- **False negative from timing:** beacon sleeps / was not connected during the
  scan window. Mitigation: run repeatedly across hours/days.
- **False positive from substring matching:** "scout" can match benign names.
- **Reverse-DNS truncation:** `_reverse_lookup` is bounded (timeout + a cap of
  60 lookups) so a slow resolver can't stall a scan — but later connections get
  no hostname. IP-only matches still run against C2 CIDRs.
- **Zero-day implants:** This toolkit cannot detect previously unknown
  infection vectors or kernel-level implants.

## 6. What a defensible workflow looks like

1. Refresh the oracle from Amnesty MVT / Citizen Lab on the scan day.
2. Run multiple host scans spaced out (different network states).
3. For any phone: MVT full extraction, feed artifacts through the scan, and
   have a forensic examiner review the MVT findings log directly.
4. Never destroy evidence (no wipe/restart) before preservation.
5. Treat every positive as "requires investigation," every negative as "no
   signal observed within these windows," not "clean."

## 7. Agents & the web dashboard (trust & deployment)

The dashboard's value is consolidating scans from several machines/phones. That
means you are entrusting it with sensitive telemetry:

- **Run on loopback by default**; if bridged to a LAN or VPN, put it behind a
  reverse proxy with TLS and set a strong `PSM_SWEEP_TOKEN`.
- **Agents are push, not pull.** A desktop agent only sends a snapshot to *your*
  dashboard; it does not accept commands. Android agent likewise only posts.
- **An uploaded acquisition is evidence-grade.** Decrypt/preserve a copy before
  upload; the extraction directory under `uploads/` is the working copy.
- **Every finding has provenance** (oracle profile + matched feed) specifically
  so a reviewer can disagree with a verdict instead of trusting it blindly.

## 8. Ethics / authorization

Run this only on devices you own or are explicitly authorized to assess.
Spyware detection is defensive; misuse (e.g. examining someone's device
without consent) is unlawful and outside this tool's purpose.

## 9. IOC Sources

| Source | Type | Count |
|--------|------|-------|
| Amnesty International | Pegasus domains | 1,438 |
| Amnesty International | Pegasus processes | 81 |
| Amnesty International | Operator emails | 29 |
| The-NSO-Blacklist | NSO C2 domains/IPs | 6,643 |
| The-Candiru-Blocklist | Candiru domains | 57 |
| The-Intellexa-Blocklist | Predator domains | Multiple |
| The-Paragon-Blacklist | Graphite IPs/domains | Multiple |
| **Total unique domains** | | **5,168** |
| **Total unique IPs** | | **23** |
| **Total C2 servers** | | **243** |

## 10. Version history

- **v3.0.0** (2026-10-25): Multi-vendor expansion
  - Added Candiru (DevilsTongue/Sourgum) IOCs
  - Added Intellexa (Predator) IOCs
  - Added Paragon (Graphite) IOCs
  - Added historical vendors (FinFisher, Hacking Team, etc.)
  - 5,168 total domains, 243 C2 servers, 40+ product names
  - NSO infection vector names (Heaven, Erised, Eden, Hummingbird)

- **v2.0.0** (2026-10-25): NSO Group IOC expansion
  - 81 Pegasus process names from Amnesty STIX2
  - 18 NSO product names
  - 1,438 C2 domain patterns

- **v1.0.0** (2026-10-25): Initial release
  - Basic Pegasus detection
  - 8 scan categories
