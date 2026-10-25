"""
Pegasus-Sweep indicator engine.

Loads the IOC oracle (YAML) and provides matching helpers over runtime
telemetry so detector modules don't hard-code knowledge.

Design goals:
  * Separation of *knowledge* (IOCs) from *evidence* (collected telemetry).
  * Every finding is traceable back to a specific indicator + source label so
    an analyst (or downstream triage) can judge severity rather than trusting
    a magic "infected/clean" verdict.
  * Feeds are refreshable: swap in a newer YAML (e.g. generated from MVT's
    iocs/ or a commercial feed) without touching detector code.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

log = logging.getLogger("pegasus_sweep.iocs")


@dataclass
class IOCOracle:
    """Parsed, normalized knowledge base loaded from a YAML indicator set."""

    data: dict[str, Any]
    provenance: str = ""
    profile_version: str = ""
    sources: list[str] = field(default_factory=list)

    # normalized views
    c2_cidr_networks: list[ipaddress.IPv4Network] = field(default_factory=list)
    proc_names_low: list[str] = field(default_factory=list)
    file_path_terms: list[str] = field(default_factory=list)
    persistence_registry: list[str] = field(default_factory=list)
    persistence_dirs: list[str] = field(default_factory=list)

    def __post_init__(self):
        self._normalize()

    def _normalize(self):
        meta = self.data.get("meta", {})
        self.provenance = meta.get("provenance", "unknown")
        self.profile_version = str(meta.get("version", "?"))
        self.sources = list(meta.get("sources", []))

        # C2 CIDRs
        for key, cidrs in self.data.get("c2_cidrs", {}).items():
            for cidr in cidrs:
                try:
                    self.c2_cidr_networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    log.warning("Skipping malformed CIDR: %s", cidr)

        # process names
        for key, names in self.data.get("process", {}).items():
            if "name" in key:
                self.proc_names_low.extend([n.lower() for n in names])

        # flatten file path terms
        for group in self.data.get("file_paths", {}).values():
            if isinstance(group, list):
                self.file_path_terms.extend([p.lower() for p in group])

        self.persistence_registry = list(
            self.data.get("persistence", {}).get("windows_registry", [])
        )
        self.persistence_dirs = list(
            self.data.get("persistence", {}).get("startup_dirs", [])
        )


@dataclass
class Finding:
    """A single indicator match, always carrying provenance."""

    category: str          # e.g. "process", "network_c2", "file_path", "persistence"
    indicator: str         # the matched indicator value
    evidence: str          # where / what was seen
    severity: str          # info | low | medium | high | critical
    profile: str           # oracle provenance (profile version + name)
    matched_feed: str = "" # which feed/source group within the oracle matched

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "indicator": self.indicator,
            "evidence": self.evidence,
            "severity": self.severity,
            "profile": self.profile,
            "matched_feed": self.matched_feed,
        }


class IOCEngine:
    """Stateless matcher statically composed around an IOCOracle."""

    def __init__(self, oracle: IOCOracle):
        self.oracle = oracle

    # -- process matching ------------------------------------------------
    def match_process(self, process_name: str, process_path: str = "") -> list[Finding]:
        findings: list[Finding] = []
        name = (process_name or "").lower()
        if not name:
            return findings

        for n in self.oracle.proc_names_low:
            if n == name or n in name:
                severity = "low"  # name-only match: lean conservative
                findings.append(
                    Finding(
                        category="process",
                        indicator=n,
                        evidence=f"running process name {process_name!r}",
                        severity=severity,
                        profile=self.oracle.profile_version,
                    )
                )
        return findings

    # -- network matching ------------------------------------------------
    def match_ip(self, ip: str) -> list[Finding]:
        """Return C2 findings if ip falls inside any documented C2 CIDR."""
        findings: list[Finding] = []
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return findings
        if addr.is_private or addr.is_loopback:
            return findings
        for net in self.oracle.c2_cidr_networks:
            if addr in net:
                findings.append(
                    Finding(
                        category="network_c2",
                        indicator=str(net),
                        evidence=f"active connection to {ip} inside documented C2 range {net}",
                        severity="critical",  # corroborated by C2 range
                        profile=self.oracle.profile_version,
                    )
                )
        return findings

    def match_domain(self, domain: str) -> list[Finding]:
        """Case-insensitive hostname substring match against C2 domain feed."""
        findings: list[Finding] = []
        d = (domain or "").strip().lower()
        if not d:
            return findings
        for feed, domains in self.oracle.data.get("c2_domains", {}).items():
            if not isinstance(domains, list):
                continue
            for c2 in domains:
                c2 = c2.lower()
                if c2 and (c2 in d or d.endswith(c2)):
                    findings.append(
                        Finding(
                            category="network_c2",
                            indicator=c2,
                            evidence=f"connection/hostname {domain!r} matches C2 domain",
                            severity="critical",
                            profile=self.oracle.profile_version,
                            matched_feed=feed,
                        )
                    )
        return findings

    # -- file-path matching ---------------------------------------------
    def match_file_path(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        p = (path or "").lower()
        if not p:
            return findings
        for term in self.oracle.file_path_terms:
            if term and term in p:
                findings.append(
                    Finding(
                        category="file_path",
                        indicator=term,
                        evidence=f"path contains indicator term: {path!r}",
                        severity="medium",
                        profile=self.oracle.profile_version,
                    )
                )
        return findings

    # -- persistence matching (registry) ---------------------------------
    def match_registry_key(self, key_path: str) -> list[Finding]:
        findings: list[Finding] = []
        k = (key_path or "").lower()
        if not k:
            return findings
        for rk in self.oracle.persistence_registry:
            if rk and rk.lower() in k:
                findings.append(
                    Finding(
                        category="persistence",
                        indicator=rk,
                        evidence=f"autostart registry key present: {key_path}",
                        severity="medium",
                        profile=self.oracle.profile_version,
                    )
                )
        return findings

    # -- iOS / Android artifact scan -------------------------------------
    def match_regex(self, haystack: str, category: str, platform: str) -> list[Finding]:
        """Run the oracle's anomaly + MNT regexes for a platform over a haystack."""
        import re

        findings: list[Finding] = []
        if not haystack:
            return findings
        # consult regex-bearing keys the oracle defines for this platform
        patterns: list[str] = []
        platform_section = self.oracle.data.get(platform, {}) or {}
        for k, v in platform_section.items():
            if "regex" not in k:
                continue
            if isinstance(v, list):
                patterns.extend(p for p in v if isinstance(p, str))
            elif isinstance(v, dict):
                for sub in v.values():
                    if isinstance(sub, list):
                        patterns.extend(p for p in sub if isinstance(p, str))
        for pat in patterns:
            try:
                if re.search(pat, haystack, re.IGNORECASE):
                    findings.append(
                        Finding(
                            category=f"{platform}_artifact",
                            indicator=pat,
                            evidence=f"anomaly regex matched in {category}",
                            severity="medium",
                            profile=self.oracle.profile_version,
                        )
                    )
            except re.error:
                log.warning("Invalid regex in oracle: %s", pat)
        return findings


def load_oracle(path: Path | str) -> IOCOracle:
    path = Path(path)
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return IOCOracle(data=data)


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deduplicate findings by (category, indicator, evidence)."""
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.category, f.indicator, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out