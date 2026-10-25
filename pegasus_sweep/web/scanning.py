"""Scanning orchestrator.

Binds the IOC engine to each supported scan target so the web layer stays thin:

  * desktop agentless  -> HostScanner on this machine
  * desktop agent      -> remote snapshot delivered by a user-installed agent
  * android agent      -> on-device snapshot (packages/procs/accessibility/…)
  * ios / android       -> extracted-artifact directory (uploaded backup/acquish)

Every function returns (status, message, summary, snapshot, findings) so the
caller can persist one row.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pegasus_sweep.core.iocs import IOCEngine, Finding, merge_findings
from pegasus_sweep.core.settings import SEVERITY_ORDER, SEVERITY_RANK

log = logging.getLogger("pegasus_sweep.scanning")

DEFAULT_SEVERITIES = {s: 0 for s in SEVERITY_ORDER}


def _summary(findings: list[Finding]) -> dict[str, Any]:
    return {
        "total_findings": len(findings),
        "by_severity": {
            s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER
        },
    }


def _to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [f.to_dict() for f in findings]


# ---------------------------------------------------------------------------
# Desktop
# ---------------------------------------------------------------------------
def scan_desktop_agentless(engine: IOCEngine) -> tuple[str, str, dict, dict, list]:
    from pegasus_sweep.modules.host_scanner import HostScanner

    scanner = HostScanner(engine)
    snapshot = scanner.collect()
    findings = merge_findings(scanner.analyze(snapshot))
    return ("done", "Agentless desktop scan complete", _summary(findings),
            snapshot.to_dict(), _to_dicts(findings))


def ingest_desktop_agent(engine: IOCEngine, payload: dict[str, Any]) -> tuple[str, str, dict, dict, list]:
    """A remote desktop agent POSTs a host snapshot; we match it here."""
    snapshot = payload.get("snapshot", payload)  # accept both shapes
    findings: list[Finding] = []
    for proc in snapshot.get("processes", []):
        findings.extend(engine.match_process(proc.get("name", ""), proc.get("exe", "")))
        if proc.get("exe"):
            findings.extend(engine.match_file_path(proc["exe"]))
    for conn in snapshot.get("connections", []):
        ip = conn.get("remote_ip", "")
        if ip:
            findings.extend(engine.match_ip(ip))
        host = conn.get("remote_host", "")
        if host:
            findings.extend(engine.match_domain(host))
    for rk in snapshot.get("registry_keys", []):
        findings.extend(engine.match_registry_key(rk))
    findings = merge_findings(findings)
    return ("done", "Remote desktop agent report ingested", _summary(findings),
            snapshot, _to_dicts(findings))


# ---------------------------------------------------------------------------
# Android (on-device agent snapshot)
# ---------------------------------------------------------------------------
def ingest_android_agent(engine: IOCEngine, payload: dict[str, Any]) -> tuple[str, str, dict, dict, list]:
    """
    An on-device Android agent posts a JSON snapshot with at least one of:
      packages:  [ {name, label, signature_hash, is_device_owner, …} ]
      processes: [ {name, cmdline} ]
      services_abusing: [ {class, type(accessibility|overlay|device_admin), grants} ]
      artifacts: [ {path, content?} ]   # optional extracted db/log snippets

    We match package names, process names, and artifact file-path terms against
    the oracle, and run regex/anomaly checks over any provided artifact text.
    Access to runtime process lists on Android is restricted on modern OS
    versions — the agent reports what it can and this is treated as triage.
    """
    findings: list[Finding] = []
    snapshot = payload.get("snapshot", payload)

    for pkg in snapshot.get("packages", []):
        name = (pkg.get("name") or "").lower()
        if name:
            findings.extend(engine.match_process(name, ""))
            findings.extend(engine.match_file_path(pkg.get("path", "")))
        # device-owner + accessibility grants on a *curated* package is notable
        # but only low/medium without a known indicator — flagged via evidence.
        if pkg.get("is_device_owner") or pkg.get("device_admin"):
            findings.append(Finding(
                category="android_privileges",
                indicator=name,
                evidence=f"package {name} holds device-owner/admin grant",
                severity="medium",
                profile=engine.oracle.profile_version))

    for proc in snapshot.get("processes", []):
        findings.extend(engine.match_process(proc.get("name", ""), ""))

    for svc in snapshot.get("services_abusing", []):
        cls = (svc.get("class") or "").lower()
        if cls:
            findings.extend(engine.match_process(cls, ""))

    for art in snapshot.get("artifacts", []):
        path = (art.get("path") or "").lower()
        if path:
            findings.extend(engine.match_file_path(path))
        text = art.get("content") or ""
        if text:
            findings.extend(engine.match_regex(text, category="artifact", platform="android"))

    findings = merge_findings(findings)
    return ("done", "Android on-device agent report ingested", _summary(findings),
            snapshot, _to_dicts(findings))


# ---------------------------------------------------------------------------
# iOS / Android artifact (upload) scanning
# ---------------------------------------------------------------------------
def scan_artifact_dir(engine: IOCEngine, platform: str, directory: Path) -> tuple[str, str, dict, dict, list]:
    from pegasus_sweep.modules.mobile_forensics import mvt_installed, scan_artifacts

    scanned_dbs, findings = scan_artifacts(engine, directory, platform)
    findings = merge_findings(findings)
    msg = (f"Artifact scan of {platform} upload (mvt {'installed' if mvt_installed() else 'NOT installed'})"
           )
    snapshot = {"platform": platform, "scanned_dbs": [str(d) for d in scanned_dbs],
                "mvt_available": mvt_installed()}
    return ("done", msg, _summary(findings), snapshot, _to_dicts(findings))