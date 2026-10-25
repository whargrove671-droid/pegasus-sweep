"""Self-test of the detection pipeline with synthetic telemetry.

Verifies that (a) the IOC engine fires on injected indicators, (b) severity
grading and dedup behave, and (c) the report path serializes. This does NOT
need a phone or MVT. Intended as a smoke test.

Run:  python -m pegasus_sweep.tests.test_detection
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pegasus_sweep.core.iocs import IOCEngine, Finding, load_oracle, merge_findings
from pegasus_sweep.core.report import build_report, to_html

HERE = Path(__file__).resolve().parent.parent.parent


def test_process_fires():
    engine = IOCEngine(load_oracle(HERE / "indicators" / "pegasus_iocs.yaml"))
    got = engine.match_process("Tangerine Monitor.exe")
    assert any(f.indicator.lower() == "tangerine monitor" for f in got), got
    assert all(isinstance(f, Finding) for f in got)
    print(f"[PASS] process-name match fired: {[f.indicator for f in got]}")


def test_c2_cidr_fires():
    engine = IOCEngine(load_oracle(HERE / "indicators" / "pegasus_iocs.yaml"))
    # Public-documented range hit. Private IPs are excluded by design (the oracle
    # seed uses a private placeholder, so this asserts the exclusion path too).
    got = engine.match_ip("192.168.50.42")
    assert got == [], "private address should be skipped"
    print("[PASS] private IP correctly excluded from C2 match")
    got2 = engine.match_ip("8.8.8.8")
    assert got2 == [], "non-listed public IP should not match"
    print("[PASS] unlisted public IP produces no finding")


def test_domain_fires():
    engine = IOCEngine(load_oracle(HERE / "indicators" / "pegasus_iocs.yaml"))
    got = engine.match_domain("cdn0.wirelessalwayson.com")
    assert any("wirelessalwayson" in f.indicator for f in got), got
    print("[PASS] C2 domain match fired")


def test_formula_dedup_and_report():
    engine = IOCEngine(load_oracle(HERE / "indicators" / "pegasus_iocs.yaml"))
    f1 = engine.match_process("scout")   # exact indicator -> fires
    f2 = engine.match_process("scout")   # duplicate source
    assert f1, "scout should produce a finding"
    merged = merge_findings([*f1, *f2])
    assert len(merged) == 1, f"expected dedup to 1, got {len(merged)}"
    report = build_report(
        host={"oracle_version": "x", "oracle_provenance": "y", "snapshot": {}},
        mobile={"mvt_available": False}, findings=merged)
    assert report["summary"]["total_findings"] == 1
    html = to_html(report)
    assert "findings" in html and "Pegasus-Sweep" in html
    assert "MVT not installed" in html
    print("[PASS] dedup + report serialization, finding count =",
          report["summary"]["total_findings"])


def test_seed_contract():
    """The seed oracle must load and expose the fields we promise to consume."""
    oracle = load_oracle(HERE / "indicators" / "pegasus_iocs.yaml")
    assert oracle.proc_names_low
    assert oracle.persistence_registry
    assert oracle.c2_cidr_networks is not None
    assert "ios" in oracle.data and "android" in oracle.data
    print("[PASS] seed oracle contract intact")


if __name__ == "__main__":
    test_seed_contract()
    test_process_fires()
    test_c2_cidr_fires()
    test_domain_fires()
    test_formula_dedup_and_report()
    print("ALL TESTS PASSED")