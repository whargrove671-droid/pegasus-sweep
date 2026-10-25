#!/usr/bin/env python3
"""Pegasus-Sweep desktop agent.

Collects a host telemetry snapshot (processes, outbound connections, autostart,
hosts file) from THIS machine and POSTs it to a Pegasus-Sweep dashboard's
`/api/ingest` endpoint. The dashboard then matches it against the indicator
oracle server-side.

Designed to be self-contained so it can be copied onto a remote desktop/pilot
host and run there — it only depends on `psutil` and the stdlib. It sends ONLY
the snapshot it gathers to the dashboard URL you specify. It does no remote
scanning: it runs locally on each machine you choose to run it on.

Usage:
    python agent_desktop.py --server http://127.0.0.1:8097 \
                            --token "YOUR_PSM_SWEEP_TOKEN" \
                            [--label hostname.bigcorp] [--json snapshot.json]

Exit code 0 on success, 2 on auth failure, 3 on network error.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Snapshot:
    hostname: str
    os: str
    processes: list[dict]
    connections: list[dict]
    registry_keys: list[str]
    startup_entries: list[str]
    hosts_entries: list[str]


# -- collection -------------------------------------------------------------
def _ptr(ip: str) -> str:
    if not ip or ip.startswith(("127.", "10.", "192.168.", "169.254.")):
        return ""
    socket.setdefaulttimeout(1.2)
    try:
        return socket.gethostbyaddr(ip)[0] or ""
    except Exception:
        return ""


def _collect() -> Snapshot:
    import psutil

    procs = []
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            procs.append({"pid": p.info["pid"], "name": p.info["name"] or "",
                          "exe": p.info["exe"] or ""})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    conns, lookups = [], 0
    for c in psutil.net_connections(kind="inet"):
        try:
            if not c.raddr:
                continue
            row = {"pid": c.pid or "", "remote_ip": c.raddr.ip,
                   "remote": f"{c.raddr.ip}:{c.raddr.port}", "remote_host": ""}
            if lookups < 60:
                lookups += 1
                row["remote_host"] = _ptr(c.raddr.ip)
            conns.append(row)
        except Exception:
            continue

    home = Path.home()
    reg = []
    try:
        import winreg
        for section in [(winreg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Run"),
                        (winreg.HKEY_LOCAL_MACHINE,
                         r"Software\Microsoft\Windows\CurrentVersion\Run")]:
            try:
                with winreg.OpenKey(*section) as k:
                    for i in range(winreg.QueryInfoKey(k)[0]):
                        name, val, _ = winreg.EnumValue(k, i)
                        reg.append(f"{section[1]}\\{name} = {val}")
            except FileNotFoundError:
                continue
    except ImportError:
        pass

    startup = []
    for d in {home / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"}:
        if d.is_dir():
            startup += [str(c) for c in d.iterdir()]

    hosts = []
    for hp in [Path("C:/Windows/system32/drivers/etc/hosts"), Path("/etc/hosts")]:
        try:
            if hp.exists():
                hosts = [l.strip() for l in hp.read_text(errors="ignore").splitlines()
                         if l.strip() and not l.strip().startswith("#")]
                break
        except OSError:
            continue

    return Snapshot(hostname=socket.gethostname() or platform.node(),
                    os=f"{platform.system()} {platform.release()}",
                    processes=procs, connections=conns,
                    registry_keys=reg, startup_entries=startup, hosts_entries=hosts)


# -- transport --------------------------------------------------------------
def _post(server: str, token: str, target: str, source_label: str, snapshot: dict) -> int:
    body = json.dumps({"target": target, "source_label": source_label,
                       "snapshot": snapshot}).encode("utf-8")
    req = urllib.request.Request(
        server.rstrip("/") + "/api/ingest",
        data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Api-Key": token})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.status
            payload = resp.read().decode("utf-8")
            print(payload)
            return 0 if status in (200, 201) else 2
    except urllib.error.HTTPError as e:
        print(f"[agent] HTTP {e.code}: {e.read().decode()}", file=__import__("sys").__stderr__)
        return 2 if e.code == 401 else 3
    except Exception as e:
        print(f"[agent] network error: {e}", file=__import__("sys").__stderr__)
        return 3


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--token", default=os.environ.get("PSM_SWEEP_TOKEN", ""))
    ap.add_argument("--label", default=socket.gethostname())
    ap.add_argument("--json", help="also write the snapshot to this JSON file")
    args = ap.parse_args()
    if not args.token:
        print("[agent] --token required (or set PSM_SWEEP_TOKEN)", file=__import__("sys").__stderr__)
        return 2

    snap = _collect()
    payload = asdict(snap)
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return _post(args.server, args.token, "desktop", args.label, payload)


if __name__ == "__main__":
    raise SystemExit(main())