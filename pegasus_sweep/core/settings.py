"""Runtime settings for pegasus-sweep.

Kept separate from IOC data so knowledge and configuration don't mix.
"""

from __future__ import annotations

import os
from pathlib import Path

# Directory the tool ships with / reads indicators from (project root).
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_IOC_PATH = Path(
    os.environ.get("PEGASUS_IOC_PATH", BASE_DIR / "indicators" / "pegasus_iocs.yaml")
)
DEFAULT_OUTPUT_DIR = Path(
    os.environ.get("PEGASUS_OUTPUT_DIR", BASE_DIR / "reports")
)

# When False, mvt is invoked with --no-confirm (useful for scripted runs).
MVT_REQUIRE_CONFIRMATION = os.environ.get("PEGASUS_MVT_NO_CONFIRM", "0") == "0"

# API key required by web /api/ingest endpoints (set a strong value in prod).
PSM_SWEEP_TOKEN = os.environ.get("PSM_SWEEP_TOKEN", "change-me-psm")

# Regexes below are sanity guards, not capabilities.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}