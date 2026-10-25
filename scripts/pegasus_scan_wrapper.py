#!/usr/bin/env python3
"""
Pegasus / NSO Group Spyware Detection — Python Cron Wrapper
Calls the PowerShell scan script and formats output for Hermes cron delivery.
No external dependencies — stdlib only.
"""

import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

SCRIPT_PATH = Path(__file__).resolve().parent / "pegasus_scan.ps1"

def main():
    if not SCRIPT_PATH.exists():
        print(f"[ERROR] PowerShell script not found: {SCRIPT_PATH}", file=sys.stderr)
        sys.exit(2)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN")
    
    print(f"=== Pegasus Spyware Detection Scan ===")
    print(f"Host: {hostname}")
    print(f"Time: {timestamp}")
    print(f"Script: {SCRIPT_PATH}")
    print("=" * 50)

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        
        # Output stdout (the scan report)
        if result.stdout:
            print(result.stdout)
        
        # Output any stderr
        if result.stderr:
            print("--- STDERR ---", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
        
        print("=" * 50)
        print(f"Exit code: {result.returncode}")
        
        if result.returncode == 0:
            print("[STATUS] Clean - no Pegasus indicators detected")
        elif result.returncode == 1:
            print("[STATUS] Pegasus indicators found (see above) — investigate immediately")
        else:
            print(f"[STATUS] Scan completed with {result.returncode} findings")
        
        # Always exit 0 for successful scan runs (findings are reported, not errors)
        sys.exit(0)
        
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Scan timed out after 300 seconds", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"[ERROR] Failed to run scan: {e}", file=sys.stderr)
        sys.exit(4)

if __name__ == "__main__":
    main()
