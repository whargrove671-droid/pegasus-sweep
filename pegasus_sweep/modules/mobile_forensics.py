"""
Mobile forensics module.

The definitive way to check an actual phone for Pegasus is Amnesty
International's MVT (Mobile Verification Toolkit) — battle-tested, peer
reviewed, actively maintained. This module:

  * Detects whether MVT is installed (`pip install mvt`)
  * Runs the appropriate extraction/decryption command for iOS or Android
  * Feeds any extracted databases/logs through the IOC engine's regex +
    sqlite scanning to surface candidate artifacts.

IMPORTANT LIMITS (read before trusting a result):
  * Pegasus is a wartime-grade, actively rotating implant. Absence of a match
    is NOT proof of non-infection.
  * MVT's `--iocs` mode uses Amnesty's own IOCs. This tool adds its own regex
    layer on top but recommends pulling the live MVT IOC set.
  * iOS requires the device passcode & connected iPhone (libimobiledevice).
  * Android requires physical access / forensic image.
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("pegasus_sweep.mobile")


@dataclass
class MobileScanResult:
    mvt_available: bool
    platform: str
    ran_mvt: bool = False
    mvt_stdout: str = ""
    mvt_stderr: str = ""
    scanned_dbs: list[str] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict:
        import pegasus_sweep.core.iocs as _  # local import avoids circularity

        return {
            "mvt_available": self.mvt_available,
            "platform": self.platform,
            "ran_mvt": self.ran_mvt,
            "mvt_stdout": self.mvt_stdout[-4000:],
            "mvt_stderr": self.mvt_stderr[-4000:],
            "scanned_dbs": self.scanned_dbs,
            "findings": [f.to_dict() for f in self.findings],
        }


def mvt_installed() -> bool:
    return shutil.which("mvt") is not None


def build_mvt_command(platform: str, source: str, output_dir: Path, iocs: Path | None = None) -> list[str]:
    """Construct the mvt subcommand for a platform. Raise on unknown platform."""
    from pegasus_sweep.core import settings as s

    if platform == "ios":
        cmd = ["mvt", "ios", "decrypt-backup", source, str(output_dir)]
    elif platform == "android":
        cmd = ["mvt", "android", "extract", source, str(output_dir)]
    else:
        raise ValueError(f"Unsupported platform: {platform!r}")

    if iocs is not None:
        cmd += ["--iocs", str(iocs)]
    if s.MVT_REQUIRE_CONFIRMATION is False:  # set by user for batch runs
        # mvt asks to confirm iOS device connections; only suppress if configured
        cmd.append("--no-confirm")
    return cmd


def scan_phone(engine, platform: str, source: str, output_dir: Path,
               iocs: Path | None = None) -> MobileScanResult:
    """
    Run MVT extraction for the phone and post-process extracted artifacts.

    platform : "ios" | "android"
    source   : iOS backup dir / tar, or Android forensic image / odm / dir
    output   : dir to receive extracted artifacts
    """
    import subprocess

    result = MobileScanResult(mvt_available=mvt_installed(), platform=platform)

    if not result.mvt_available:
        log.warning("MVT not installed. Run: pip install mvt")
        return result

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_mvt_command(platform, source, output_dir, iocs)
    log.info("Running MVT: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        result.ran_mvt = True
        result.mvt_stdout = proc.stdout or ""
        result.mvt_stderr = proc.stderr or ""
        if proc.returncode != 0:
            log.warning("MVT exited with code %d", proc.returncode)
    except Exception as exc:
        result.mvt_stderr = f"Failed to launch MVT: {exc}"

    # Post-process extracted sqlite DBs + logs through the IOC oracle.
    scanned_dbs, artifacts = scan_artifacts(engine, output_dir, platform)
    result.scanned_dbs = scanned_dbs
    result.findings.extend(artifacts)
    return result


def scan_artifacts(engine, directory: Path, platform: str) -> tuple[list[str], list[Any]]:
    """Walk an extracted/extracted-on-disk artifact directory and return a
    (scanned_dbs, findings) pair by running sqlite + regex anomaly checks from
    the oracle. Shared by the web-app upload path (which may not use MVT) and
    the CLI/MVT path.
    """
    scanned_dbs: list[str] = []
    findings: list[Any] = []
    db_names = (engine.oracle.data.get(platform, {}).get("sqlite_databases_to_scan") or [])
    wanted = {d.lower() for d in db_names}

    for db in directory.rglob("*.db"):
        name = db.name.lower()
        if wanted and name not in wanted:
            continue
        scanned_dbs.append(str(db))
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            with conn:
                tables = [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")]
                for t in tables:
                    try:
                        rows = conn.execute(f'SELECT * FROM "{t}"').fetchall()
                    except sqlite3.DatabaseError:
                        continue
                    for row in rows:
                        for col in row:
                            if col is None:
                                continue
                            findings.extend(engine.match_regex(
                                str(col), category=f"db:{t}", platform=platform))
            conn.close()
        except Exception as exc:
            log.warning("Could not read DB %s: %s", db, exc)

    # Scan textual logs (android log_paths from oracle; ios not applicable)
    for logname in (engine.oracle.data.get(platform, {}).get("log_paths") or []):
        for lp in directory.rglob(logname):
            try:
                text = lp.read_text(encoding="utf-8", errors="ignore")
                findings.extend(
                    engine.match_regex(text, category=f"log:{logname}", platform=platform))
            except OSError:
                continue
    return scanned_dbs, findings