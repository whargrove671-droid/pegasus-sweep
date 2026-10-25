"""Pegasus-Sweep multi-target web dashboard (Flask).

Run:    python -m pegasus_sweep.web.app
Open:   http://127.0.0.1:8097

Targets
  * Desktop  — agentless (scan this box) OR a user-installed agent POST
  * Android  — on-device agent POST  and/or  an uploaded acquisition (zip)
  * iOS      — upload an (encrypted) backup / extracted DBs; server runs MVT +
               artifact scan

Auth
  The server binds to 127.0.0.1 only. Write/agent endpoints under /api require
  the key in PSM_SWEEP_TOKEN (or the built-in default). If you place this behind
  a reverse proxy or open it to a LAN, you MUST set a strong PSM_SWEEP_TOKEN and
  serve HTTPS. Page routes are read-only views.

Endpoints
  GET  /                dashboard
  GET  /scans           scan history (JSON for polling)
  GET  /scan/<int:id>   single scan (rendered)
  POST /scan/desktop    start an ASYNC agentless desktop scan
  POST /scan/ios        upload iOS backup/acquisition zip  (form: file)
  POST /scan/android    upload Android acquisition zip     (form: file)
  POST /api/ingest      agent endpoint: {target, snapshot}   Requires X-Api-Key
"""

from __future__ import annotations

import json
import logging
import re
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for

from pegasus_sweep.core import settings
from pegasus_sweep.core.iocs import IOCEngine, load_oracle
from pegasus_sweep.core.report import _BADGE, _findings_table, _kv_table
from pegasus_sweep.web.db import ScanStore
from pegasus_sweep.web import scanning

log = logging.getLogger("pegasus_sweep.web")

APP_KEY = __import__("pegasus_sweep.core.settings", fromlist=["PSM_SWEEP_TOKEN"]).PSM_SWEEP_TOKEN

UPLOADS = settings.BASE_DIR / "uploads"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB upload cap

_engine: IOCEngine | None = None
_store: ScanStore | None = None


def _get_engine() -> IOCEngine:
    global _engine
    if _engine is None:
        _engine = IOCEngine(load_oracle(settings.DEFAULT_IOC_PATH))
    return _engine


def _get_store() -> ScanStore:
    global _store
    if _store is None:
        _store = ScanStore()
    return _store


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _require_key():
    """Strict auth for agent ingest. No thread-name bypass — the async desktop
    scan calls Scanning directly and never hits this endpoint."""
    supplied = request.headers.get("X-Api-Key", "")
    if supplied != APP_KEY:
        return jsonify({"error": "invalid or missing X-Api-Key"}), 401
    return None


def _safe_extract(zf: zipfile.ZipFile, dest: Path):
    """Extract guarding against zip-slip path traversal."""
    dest = dest.resolve()
    for member in zf.infolist():
        target = (dest / member.filename).resolve()
        if not target.is_relative_to(dest):
            raise ValueError(f"unsafe zip entry: {member.filename}")
    zf.extractall(dest)


# ---------------------------------------------------------------------------
# pages
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    store = _get_store()
    recent = store.recent(limit=25)
    counts = store.counts_by_target()
    return render_template("index.html", recent=recent, counts=counts,
                           severities=settings.SEVERITY_ORDER)


@app.get("/scans")
def scans_json():
    store = _get_store()
    recent = store.recent(limit=100)
    for r in recent:
        r.pop("snapshot", None)
    return jsonify({"scans": recent})


@app.get("/scan/<int:scan_id>")
def scan_view(scan_id: int):
    store = _get_store()
    record = store.get(scan_id)
    if not record:
        return render_template("view.html", not_found=True), 404
    return render_template("view.html", record=record,
                           findings_html=_findings_table(record["findings"]),
                           badge=_BADGE, severities=settings.SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# scan triggers
# ---------------------------------------------------------------------------
@app.post("/scan/desktop")
def scan_desktop():
    """Async agentless desktop scan; runs in background, persists on completion."""
    def run():
        try:
            status, msg, summary, snapshot, findings = scanning.scan_desktop_agentless(
                _get_engine())
            _get_store().insert(target="desktop", mode="agentless",
                                source_label="this host", status=status, message=msg,
                                summary=summary, snapshot=snapshot, findings=findings)
        except Exception as exc:  # pragma: no cover
            log.exception("desktop scan failed")
            _get_store().insert(target="desktop", mode="agentless", source_label="this host",
                                status="error", message=str(exc))

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"queued": True, "target": "desktop"})


@app.post("/scan/<target>")
def scan_upload(target: str):
    """Upload an acquisition zip for iOS or Android and scan its artifacts."""
    if target not in ("ios", "android"):
        return jsonify({"error": "target must be ios|android"}), 400
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "multipart field 'file' required"}), 400

    scan_id = _get_store().insert(target=target, mode="upload", status="running",
                                  source_label=f.filename, message="extracting…")
    dest = UPLOADS / target / str(scan_id)
    try:
        dest.mkdir(parents=True, exist_ok=True)
        tmp = dest / "upload.tmp"
        f.save(tmp)
        if zipfile.is_zipfile(tmp):
            with zipfile.ZipFile(tmp) as zf:
                _safe_extract(zf, dest / "extract")
            (dest / "upload.tmp").unlink(missing_ok=True)
            scan_dir = dest / "extract"
        else:
            # single-file upload (e.g. a .db): keep as-is
            scan_dir = dest
            tmp.rename(scan_dir / f.filename)
        status, msg, summary, snapshot, findings = scanning.scan_artifact_dir(
            _get_engine(), target, scan_dir)
        _get_store().update(scan_id, status=status, message=msg, summary=summary,
                            snapshot=snapshot, findings=findings)
    except Exception as exc:  # pragma: no cover
        log.exception("upload scan failed")
        _get_store().update(scan_id, status="error", message=str(exc))
        return jsonify({"error": str(exc)}), 500
    return redirect(url_for("scan_view", scan_id=scan_id))


# ---------------------------------------------------------------------------
# agent ingest (desktop remote / android on-device) — requires X-Api-Key
# ---------------------------------------------------------------------------
@app.post("/api/ingest")
def ingest():
    denied = _require_key()
    if denied:
        return denied
    body = request.get_json(silent=True) or {}
    target = body.get("target")
    assignment = {
        "desktop": scanning.ingest_desktop_agent,
        "android": scanning.ingest_android_agent,
    }
    handler = assignment.get(target)
    if not handler:
        return jsonify({"error": f"unsupported target {target!r}; use desktop|android"}), 400
    status, msg, summary, snapshot, findings = handler(_get_engine(), body)
    sid = _get_store().insert(
        target=target, mode="agent", status=status, message=msg,
        source_label=body.get("source_label", "agent"), summary=summary,
        snapshot=snapshot, findings=findings)
    return jsonify({"scan_id": sid, "summary": summary, "findings": findings})


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "upload too large (max 512MB)"}), 413


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    print(f"[pegasus-sweep] dashboard at http://127.0.0.1:8097  (uploads -> {UPLOADS})")
    app.run(host="127.0.0.1", port=8097, debug=False)