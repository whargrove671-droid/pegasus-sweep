"""
Host telemetry scanner.

Collects live evidence from the machine the tool runs on and feeds it through
the IOC engine. This is a *triaging* layer: it surfaces candidate signals that
must be manually validated. A Pegasus *mobile* implant does not normally
persist on a Windows host, so a clean host scan does NOT clear a connected
phone — run the mobile forensics module for that.

Signal sources:
  1. Running processes (name + executable path)      -> process / file_path
  2. Active & listening TCP/UDP connections           -> network_c2
  3. Windows autostart registry keys & startup dirs  -> persistence
  4. hosts file inspection (DNS hijack sketch)
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("pegasus_sweep.host")


@dataclass
class HostSnapshot:
    processes: list[dict[str, str]] = field(default_factory=list)
    connections: list[dict[str, str]] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    startup_dir_entries: list[str] = field(default_factory=list)
    hosts_entries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "processes": self.processes,
            "connections": self.connections,
            "registry_keys": self.registry_keys,
            "startup_dir_entries": self.startup_dir_entries,
            "hosts_entries": self.hosts_entries,
        }


def _reverse_lookup(ip: str, timeout: float = 1.5) -> str:
    """Best-effort PTR (reverse DNS). Never fatal, bounded so a slow resolver
    cannot stall a full scan."""
    if not ip or ip.startswith(("127.", "10.", "192.168.", "169.254.")):
        return ""
    import socket as _socket

    _socket.setdefaulttimeout(timeout)
    try:
        return _socket.gethostbyaddr(ip)[0] or ""
    except Exception:
        return ""


class HostScanner:
    def __init__(self, engine):
        self.engine = engine

    def collect(self) -> HostSnapshot:
        return HostSnapshot(
            processes=self._collect_processes(),
            connections=self._collect_connections(),
            registry_keys=self._collect_registry(),
            startup_dir_entries=self._collect_startup_dirs(),
            hosts_entries=self._collect_hosts(),
        )

    def _collect_processes(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        try:
            import psutil

            for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    info = p.info
                    out.append(
                        {
                            "pid": str(info.get("pid", "")),
                            "name": info.get("name") or "",
                            "exe": info.get("exe") or "",
                            "cmdline": " ".join(info.get("cmdline") or []),
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:  # pragma: no cover - fallback path
            log.warning("psutil unavailable (%s); falling back to tasklist", exc)
            out = self._processes_tasklist_fallback()
        return out

    def _processes_tasklist_fallback(self) -> list[dict[str, str]]:
        import subprocess

        out: list[dict[str, str]] = []
        try:
            raw = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=30,
            ).stdout
            for line in raw.splitlines():
                parts = line.replace('"', "").split(",")
                if len(parts) >= 2:
                    out.append({"pid": parts[1], "name": parts[0], "exe": "", "cmdline": ""})
        except Exception:
            pass
        return out

    def _collect_connections(self, max_reverse: int = 60) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        try:
            import psutil

            lookups = 0
            for c in psutil.net_connections(kind="inet"):
                try:
                    laddr = c.laddr
                    raddr = c.raddr
                    if raddr:
                        row = {
                            "pid": str(c.pid or ""),
                            "status": str(c.status or ""),
                            "local": f"{laddr.ip}:{laddr.port}",
                            "remote": f"{raddr.ip}:{raddr.port}",
                            "remote_ip": raddr.ip,
                            "remote_host": "",
                        }
                        if lookups < max_reverse:
                            lookups += 1
                            row["remote_host"] = _reverse_lookup(raddr.ip)
                        out.append(row)
                except Exception:
                    continue
        except Exception as exc:  # pragma: no cover
            log.warning("Connection scan failed: %s", exc)
        return out

    def _collect_registry(self) -> list[str]:
        """Return present autostart registry keys under the oracle's paths."""
        found: list[str] = []
        try:
            import winreg
        except ImportError:
            log.warning("winreg not available (non-Windows); skipping registry.")
            return found

        sections = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for handle, subkey in sections:
            try:
                with winreg.OpenKey(handle, subkey) as key:
                    n = winreg.QueryInfoKey(key)[0]  # number of values
                    for i in range(n):
                        name, value, _ = winreg.EnumValue(key, i)
                        found.append(f"{subkey}\\{name} = {value}")
            except FileNotFoundError:
                continue
            except OSError as exc:
                log.warning("Registry read failed for %s: %s", subkey, exc)
        return found

    def _collect_startup_dirs(self) -> list[str]:
        found: list[str] = []
        home = Path.home()
        dirs = [
            home / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
            home / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
        ]
        for d in dict.fromkeys(dirs):
            if d.is_dir():
                for child in d.iterdir():
                    found.append(str(child))
        return found

    def _collect_hosts(self) -> list[str]:
        found: list[str] = []
        for p in [Path("C:/Windows/system32/drivers/etc/hosts"), Path("/etc/hosts")]:
            try:
                if p.exists():
                    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            found.append(line)
                    break
            except OSError:
                continue
        return found

    # -- analysis -------------------------------------------------------
    def analyze(self, snapshot: HostSnapshot) -> list[Any]:
        findings: list[Any] = []
        for proc in snapshot.processes:
            findings.extend(self.engine.match_process(proc["name"], proc["exe"]))
            if proc["exe"]:
                findings.extend(self.engine.match_file_path(proc["exe"]))
        for conn in snapshot.connections:
            ip = conn.get("remote_ip", "")
            if ip:
                findings.extend(self.engine.match_ip(ip))
            host = conn.get("remote_host", "")
            if host:
                findings.extend(self.engine.match_domain(host))
        for rk in snapshot.registry_keys:
            findings.extend(self.engine.match_registry_key(rk))
        return findings