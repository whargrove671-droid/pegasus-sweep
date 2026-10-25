#!/usr/bin/env python3
"""
Unified Daily Spyware Detection Report
Combines results from all scan types into a single comprehensive report.
Run at end of day to summarize all security findings.
"""

import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

def run_scan(script_name, description):
    """Run a scan script and capture results."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"{'='*60}")
    
    script_path = SCRIPT_DIR / script_name
    if not script_path.exists():
        return {
            'status': 'error',
            'error': f'Script not found: {script_path}',
            'findings': [],
            'summary': f'ERROR: {script_name} not found'
        }
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(SCRIPT_DIR)
        )
        
        output = result.stdout
        error = result.stderr
        exit_code = result.returncode
        
        # Parse findings from output
        findings = []
        critical_count = 0
        
        for line in output.split('\n'):
            if '[!]' in line or 'CRITICAL' in line or 'FINDINGS' in line:
                findings.append(line.strip())
                if 'CRITICAL' in line or '[SECURITY]' in line or 'PEGASUS' in line:
                    critical_count += 1
        
        return {
            'status': 'success' if exit_code in [0, 1] else 'error',
            'exit_code': exit_code,
            'output': output,
            'error': error,
            'findings': findings,
            'critical_count': critical_count,
            'summary': f'{description}: {len(findings)} findings ({critical_count} critical)'
        }
        
    except subprocess.TimeoutExpired:
        return {
            'status': 'timeout',
            'error': 'Scan timed out after 600 seconds',
            'findings': [],
            'summary': f'TIMEOUT: {description}'
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'findings': [],
            'summary': f'ERROR: {description} - {e}'
        }

def generate_html_report(results, timestamp, hostname):
    """Generate HTML report from scan results."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Unified Spyware Detection Report - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; }}
        .header h1 {{ margin: 0; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .critical {{ background: #ffebee; border-left: 4px solid #f44336; }}
        .warning {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
        .clean {{ background: #e8f5e9; border-left: 4px solid #4caf50; }}
        .scan-section {{ margin: 20px 0; padding: 15px; background: white; border-radius: 8px; }}
        .scan-title {{ font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
        .finding {{ padding: 8px; margin: 5px 0; background: #fafafa; border-left: 3px solid #ddd; font-family: monospace; font-size: 12px; }}
        .finding.critical {{ border-left-color: #f44336; background: #ffebee; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ flex: 1; padding: 15px; text-align: center; border-radius: 8px; }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ font-size: 14px; color: #666; }}
        pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; font-size: 11px; }}
        .collapsible {{ cursor: pointer; }}
        .content {{ display: none; }}
        .content.active {{ display: block; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Unified Spyware Detection Report</h1>
        <p>Host: {hostname} | Generated: {timestamp}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box summary">
            <div class="stat-number">{len(results)}</div>
            <div class="stat-label">Scans Run</div>
        </div>
        <div class="stat-box summary {'critical' if sum(r.get('critical_count', 0) for r in results) > 0 else 'clean'}">
            <div class="stat-number">{sum(r.get('critical_count', 0) for r in results)}</div>
            <div class="stat-label">Critical Findings</div>
        </div>
        <div class="stat-box summary {'warning' if sum(len(r.get('findings', [])) for r in results) > 0 else 'clean'}">
            <div class="stat-number">{sum(len(r.get('findings', [])) for r in results)}</div>
            <div class="stat-label">Total Findings</div>
        </div>
    </div>
"""
    
    for result in results:
        status_class = 'clean' if result['status'] == 'success' and result.get('critical_count', 0) == 0 else 'critical'
        if result['status'] == 'error' or result['status'] == 'timeout':
            status_class = 'warning'
        
        html += f"""
    <div class="scan-section {status_class}">
        <div class="scan-title collapsible" onclick="this.nextElementSibling.classList.toggle('active')">
            {result.get('name', 'Unknown Scan')} — {result.get('summary', 'No summary')}
        </div>
        <div class="content">
"""
        
        if result.get('findings'):
            html += "<h4>Findings:</h4>"
            for finding in result['findings'][:20]:  # Limit to 20 findings
                finding_class = 'critical' if 'CRITICAL' in finding or 'SECURITY' in finding else ''
                html += f'<div class="finding {finding_class}">{finding}</div>'
            if len(result['findings']) > 20:
                html += f'<div class="finding">... and {len(result["findings"]) - 20} more findings</div>'
        
        if result.get('error'):
            html += f"<h4>Errors:</h4><pre>{result['error'][:1000]}</pre>"
        
        if result.get('output'):
            html += f"<h4>Full Output:</h4><pre>{result['output'][:2000]}</pre>"
        
        html += """
        </div>
    </div>
"""
    
    html += """
    <div class="summary">
        <h3>Recommendations</h3>
        <ul>
"""
    
    # Add recommendations based on findings
    total_critical = sum(r.get('critical_count', 0) for r in results)
    if total_critical > 0:
        html += "<li><strong>CRITICAL:</strong> Investigate all critical findings immediately. Consider engaging a DFIR specialist.</li>"
    
    windefend_findings = [f for r in results for f in r.get('findings', []) if 'WinDefend' in f or 'Sense' in f or 'WdNisSvc' in f]
    if windefend_findings:
        html += "<li><strong>Security Services:</strong> Windows Defender services are stopped. Verify if intentional or investigate tampering.</li>"
    
    html += """
            <li>Run scans daily and review results promptly.</li>
            <li>Keep IOC database updated (daily refresh scheduled).</li>
            <li>For mobile devices, use MVT (Mobile Verification Toolkit).</li>
        </ul>
    </div>
    
    <script>
        // Auto-expand critical sections
        document.querySelectorAll('.scan-section.critical .content').forEach(el => el.classList.add('active'));
    </script>
</body>
</html>
"""
    
    return html

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_str = datetime.now().strftime("%Y%m%d")
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN")
    
    print(f"{'='*60}")
    print(f"Unified Daily Spyware Detection Report")
    print(f"Host: {hostname}")
    print(f"Time: {timestamp}")
    print(f"{'='*60}")
    
    # Define scans to run
    scans = [
        ('pegasus_scan_wrapper.py', 'Pegasus Spyware Detection'),
        ('browser_history_scanner.py', 'Browser History Spyware Scan'),
        ('yara_scan_wrapper.py', 'YARA Process Scan'),
    ]
    
    results = []
    
    for script, description in scans:
        result = run_scan(script, description)
        result['name'] = description
        results.append(result)
        print(f"Status: {result['status']} | Findings: {len(result.get('findings', []))}")
    
    # Generate summary
    total_findings = sum(len(r.get('findings', [])) for r in results)
    total_critical = sum(r.get('critical_count', 0) for r in results)
    
    print(f"\n{'='*60}")
    print(f"REPORT SUMMARY")
    print(f"{'='*60}")
    print(f"Total scans: {len(results)}")
    print(f"Total findings: {total_findings}")
    print(f"Critical findings: {total_critical}")
    
    # Generate HTML report
    html_report = generate_html_report(results, timestamp, hostname)
    html_path = SCRIPT_DIR / f"unified_report_{date_str}.html"
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    # Generate JSON report
    json_report = {
        'timestamp': timestamp,
        'hostname': hostname,
        'summary': {
            'total_scans': len(results),
            'total_findings': total_findings,
            'critical_findings': total_critical
        },
        'scans': results
    }
    
    json_path = SCRIPT_DIR / f"unified_report_{date_str}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_report, f, indent=2)
    
    print(f"\n[+] HTML report: {html_path}")
    print(f"[+] JSON report: {json_path}")
    
    # Print critical findings to console
    if total_critical > 0:
        print(f"\n{'='*60}")
        print(f"!!! CRITICAL FINDINGS REQUIRING ATTENTION !!!")
        print(f"{'='*60}")
        for result in results:
            if result.get('critical_count', 0) > 0:
                print(f"\n{result['name']}:")
                for finding in result.get('findings', [])[:10]:
                    if 'CRITICAL' in finding or 'SECURITY' in finding or 'PEGASUS' in finding:
                        print(f"  {finding}")
    
    return 0 if total_critical == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
