#!/usr/bin/env python3
"""
YARA Spyware Process Scanner — Python Cron Wrapper
Runs YARA rules against running processes and reports matches.
Uses yara-python module. Process names only — no binary content scanning.
"""

import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

SCRIPT_DIR = Path(__file__).resolve().parent
YARA_RULES = SCRIPT_DIR / "pegasus_processes.yar"

def scan_processes_with_yara():
    """Scan running processes using YARA rules."""
    try:
        import yara
    except ImportError:
        print("[WARNING] yara-python not installed. Run: pip install yara-python")
        print("[INFO] Skipping YARA scan. PowerShell-based detection still active.")
        return 0, "yara not installed"
    
    # Compile rules
    try:
        rules = yara.compile(filepath=str(YARA_RULES))
    except Exception as e:
        print(f"[ERROR] Failed to compile YARA rules: {e}")
        return 2, f"compile error: {e}"
    
    # Get running processes
    matches = []
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name']
                
                # Scan process name only (no binary content — too many FPs)
                name_matches = rules.match(data=proc_name)
                if name_matches:
                    for match in name_matches:
                        matches.append({
                            'pid': proc.info['pid'],
                            'name': proc_name,
                            'rule': match.rule,
                            'type': 'process_name'
                        })
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
    except ImportError:
        print("[WARNING] psutil not installed. Run: pip install psutil")
        print("[INFO] Falling back to basic process list...")
        
        # Fallback: use tasklist
        result = subprocess.run(['tasklist'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if line.strip() and not line.startswith('Image Name'):
                parts = line.split()
                if parts:
                    proc_name = parts[0]
                    name_matches = rules.match(data=proc_name)
                    if name_matches:
                        for match in name_matches:
                            matches.append({
                                'name': proc_name,
                                'rule': match.rule,
                                'type': 'process_name'
                            })
    
    return len(matches), matches

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN")
    
    print(f"=== YARA Spyware Process Scan ===")
    print(f"Host: {hostname}")
    print(f"Time: {timestamp}")
    print(f"Rules: {YARA_RULES}")
    print("=" * 50)
    
    if not YARA_RULES.exists():
        print(f"[ERROR] YARA rules not found: {YARA_RULES}", file=sys.stderr)
        sys.exit(2)
    
    # Run YARA scan
    match_count, matches = scan_processes_with_yara()
    
    if isinstance(matches, str):
        # Error message
        print(f"[INFO] {matches}")
        sys.exit(0)
    
    print(f"\n[+] Scan complete. Matches found: {match_count}")
    
    if match_count > 0:
        print("\n!!! CRITICAL FINDINGS !!!")
        for match in matches:
            print(f"  [{match['rule']}] {match['name']} (PID:{match.get('pid', 'N/A')})")
        
        # Save results
        results_file = SCRIPT_DIR / f"yara_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        import json
        with open(results_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'hostname': hostname,
                'matches': matches,
                'total': match_count
            }, f, indent=2)
        print(f"\n[+] Results saved to: {results_file}")
        
        sys.exit(1)
    else:
        print("[CLEAN] No spyware process names detected.")
        sys.exit(0)

if __name__ == "__main__":
    main()
