"""Pegasus-Sweep CLI.

Usage examples:
  # host-only scan (this machine) with JSON + HTML report
  python -m pegasus_sweep scan --host --out reports/

  # scan an iOS backup (requires mvt installed)
  python -m pegasus_sweep scan --mobile ios --mobile-source /path/to/backup --out reports/

  # both
  python -m pegasus_sweep scan --host --mobile ios --mobile-source ...
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from pegasus_sweep.core import settings
from pegasus_sweep.core.iocs import IOCOracle, load_oracle, merge_findings
from pegasus_sweep.core.report import build_report, save_json, write_report_html
from pegasus_sweep.modules.host_scanner import HostScanner

log = logging.getLogger("pegasus_sweep")


def _make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pegasus-sweep", description=__doc__)
    p.add_argument("--iocs", type=Path, default=settings.DEFAULT_IOC_PATH,
                   help="Path to IOC oracle YAML")
    p.add_argument("--out", type=Path, default=settings.DEFAULT_OUTPUT_DIR,
                   help="Output directory for reports")
    p.add_argument("--host", action="store_true", help="Run host telemetry scan")
    p.add_argument("--mobile", choices=["ios", "android"],
                   help="Scan a phone via MVT (requires mvt installed)")
    p.add_argument("--mobile-source", type=str,
                   help="Path to iOS backup / Android image for mobile scan")
    p.add_argument("--no-host-report", action="store_true", help=argparse.SUPPRESS)
    return p


def _run_host(engine) -> tuple[dict, list]:
    scanner = HostScanner(engine)
    snapshot = scanner.collect()
    findings = merge_findings(scanner.analyze(snapshot))
    host = {
        "oracle_version": engine.oracle.profile_version,
        "oracle_provenance": engine.oracle.provenance,
        "snapshot": snapshot.to_dict(),
    }
    return host, findings


def _run_mobile(engine, platform: str, source: str, out: Path) -> dict:
    from pegasus_sweep.modules.mobile_forensics import scan_phone

    output = out / "mvt_extract"
    result = scan_phone(engine, platform, source, output)
    return result.to_dict()


def main(argv: list[str] | None = None) -> int:
    args = _make_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    oracle: IOCOracle = load_oracle(args.iocs)
    from pegasus_sweep.core.iocs import IOCEngine
    engine = IOCEngine(oracle)
    log.info("Loaded oracle v%s (%s)", oracle.profile_version, oracle.provenance)

    host, findings = {}, []
    if args.host:
        host, findings = _run_host(engine)
        log.info("Host scan complete: %d findings", len(findings))

    mobile = {}
    if args.mobile:
        if not args.mobile_source:
            log.error("--mobile requires --mobile-source")
            return 2
        mobile = _run_mobile(engine, args.mobile, args.mobile_source, args.out)

    report = build_report(host, mobile, findings)
    jpath = save_json(report, args.out / "report.json")
    hpath = write_report_html(report, args.out / "report.html")
    print(json.dumps(
        {"summary": report["summary"], "report_json": str(jpath), "report_html": str(hpath)},
        indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())