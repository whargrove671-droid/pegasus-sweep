"""Report renderer: JSON + a self-contained HTML report (no external assets)."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from pegasus_sweep.core import settings
from pegasus_sweep.core.iocs import Finding


def _severity_rank(f: Finding) -> str:
    return settings.SEVERITY_RANK.get(f.severity, 0)


def build_report(host: dict[str, Any], mobile: dict[str, Any],
                 findings: Iterable[Finding]) -> dict[str, Any]:
    # dedupe by content (dataclass is eq=True so __hash__ is None; use a key set)
    seen: set[tuple[str, str, str]] = set()
    uniq: list[Finding] = []
    for f in findings:
        if not isinstance(f, Finding):
            continue
        key = (f.category, f.indicator, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    f_list = sorted(
        uniq,
        key=lambda x: (-settings.SEVERITY_RANK.get(x.severity, 0), x.category),
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "oracle_profile": {
            "version": host.get("oracle_version", ""),
            "provenance": host.get("oracle_provenance", ""),
        },
        "summary": {
            "total_findings": len(f_list),
            "by_severity": {s: sum(1 for f in f_list if f.severity == s)
                            for s in settings.SEVERITY_ORDER},
        },
        "host": host.get("snapshot", {}),
        "mobile": mobile,
        "findings": [f.to_dict() for f in f_list],
    }


def save_json(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


_CSS = """
:root{--bg:#0d1117;--card:#161b22;--txt:#e6edf3;--mut:#8b949e;
--crit:#ff7b72;--high:#f0883e;--med:#d29922;--low:#c9d1d9;--info:#58a6ff;}
*{box-sizing:border-box}body{background:var(--bg);color:var(--txt);
font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px}
h1{font-size:22px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #30363d;padding-bottom:6px}
.card{background:var(--card);border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}
.mut{color:var(--mut)}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #30363d}th{color:var(--mut)}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600}
.pill.critical{background:#ff7b7222;color:var(--crit)}.pill.high{background:#f0883e22;color:var(--high)}
.pill.medium{background:#d2992222;color:var(--med)}.pill.low{background:#c9d1d922;color:var(--low)}
.pill.info{background:#58a6ff22;color:var(--info)}
.ok{color:#3fb950;font-weight:700}
"""

_BADGE = '<span class="pill {sev}">{sev}</span>'


def _findings_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<p class="ok">&#10003; No indicator matches recorded.</p>'
    rows = ["<table><thead><tr><th>Sev</th><th>Category</th><th>Indicator</th>"
            "<th>Evidence</th><th>Feed</th></tr></thead><tbody>"]
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{_BADGE.format(sev=html.escape(f.get('severity','info')))}</td>"
            f"<td>{html.escape(f.get('category',''))}</td>"
            f"<td><code>{html.escape(f.get('indicator',''))}</code></td>"
            f"<td>{html.escape(f.get('evidence',''))}</td>"
            f"<td class='mut'>{html.escape(f.get('matched_feed','') or '-')}</td>"
            "</tr>"
        )
    rows.append("</tbody></table>")
    return "".join(rows)


def _kv_table(rows: dict[str, Any]) -> str:
    if not rows:
        return '<p class="mut">(no data)</p>'
    cells = ["<table><tbody>"]
    for k, v in rows.items():
        out = html.escape(str(v))
        if len(out) > 120:
            out = out[:117] + "&#8230;"
        cells.append(f"<tr><th>{html.escape(str(k))}</th><td><code>{out}</code></td></tr>")
    cells.append("</tbody></table>")
    return "".join(cells)


def to_html(report: dict[str, Any]) -> str:
    summary = report["summary"]
    mobile = report.get("mobile", {})
    sev_pills = " ".join(
        f'{_BADGE.format(sev=s)} {summary["by_severity"].get(s,0)}' for s in settings.SEVERITY_ORDER
    )
    mobile_status = ('<span class="ok">MVT operational</span>' if mobile.get("mvt_available")
                     else '<span style="color:var(--high)">MVT not installed — '
                          '<code>pip install mvt</code> required for phone checks</span>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Pegasus-Sweep report</title><style>{_CSS}</style></head><body>
<h1>&#128269; Pegasus-Sweep report</h1>
<div class="card"><h2>Summary</h2>
<p>{summary['total_findings']} finding(s): {sev_pills}</p>
<p class="mut">Generated {html.escape(report['generated_at'])} &middot;
Oracle v{html.escape(str(report['oracle_profile']['version']))}</p>
<p><b>Confidence notice:</b> matching on public indicators is a <i>triage</i>
signal, not a definitive verdict. Pegasus rotates infrastructure constantly and
Absence of matches does NOT clear a device. Validate all findings manually.</p>
</div>

<h2>Mobile forensics</h2>
<div class="card"><p>{mobile_status}</p>
<p class="mut">Platform: {html.escape(str(mobile.get('platform','-') or '-'))} &middot;
MVT run: {'yes' if mobile.get('ran_mvt') else 'no'}</p>
{_findings_table(mobile.get('findings', []))}</div>

<h2>Host telemetry</h2>
<div class="card">
<p class="mut">Running processes: {len(report.get('host',{}).get('processes',[]))} &middot;
Connections: {len(report.get('host',{}).get('connections',[]))} &middot;
Autostart keys: {len(report.get('host',{}).get('registry_keys',[]))} &middot;
Startup entries: {len(report.get('host',{}).get('startup_dir_entries',[]))} &middot;
hosts entries: {len(report.get('host',{}).get('hosts_entries',[]))}</p></div>

<h2>Findings</h2>
<div class="card">{_findings_table(report.get('findings', []))}</div>

<h2>Raw host snapshot</h2>
<div class="card"><details><summary>Processes ({len(report.get('host',{}).get('processes',[]))})</summary>
{_kv_table({p.get('pid',''): p.get('name','') for p in report.get('host',{}).get('processes',[])[:400]})}
</details>
<details><summary>Connections ({len(report.get('host',{}).get('connections',[]))})</summary>
{_kv_table({c.get('remote',''): c.get('remote_host','') + ' pid=' + c.get('pid','')
            for c in report.get('host',{}).get('connections',[])[:400]})}</details>
<details><summary>Autostart registry ({len(report.get('host',{}).get('registry_keys',[]))})</summary>
{_kv_table({str(i): k for i,k in enumerate(report.get('host',{}).get('registry_keys',[]))})}</details>
<details><summary>Startup dir entries ({len(report.get('host',{}).get('startup_dir_entries',[]))})</summary>
{_kv_table({str(i): e for i,e in enumerate(report.get('host',{}).get('startup_dir_entries',[]))})}</details>
</div>
</body></html>"""


def write_report_html(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_html(report), encoding="utf-8")
    return path