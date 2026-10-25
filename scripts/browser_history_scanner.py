#!/usr/bin/env python3
"""
Browser History Spyware Scanner — Python version
Scans Chrome, Edge, and Firefox history for 5,168+ known malicious domains.
Uses exact domain matching to avoid false positives.
No external dependencies — stdlib only.
"""

import json
import sqlite3
import shutil
import sys
import os
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
IOC_DB = SCRIPT_DIR / "comprehensive_spyware_iocs.json"

def load_malicious_domains():
    """Load malicious domains from IOC database."""
    with open(IOC_DB, 'r') as f:
        data = json.load(f)
    return set(data['domains'])

def extract_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return None

def is_malicious(url, malicious_domains):
    """Check if URL matches a malicious domain (exact match only)."""
    if not url:
        return None
    domain = extract_domain(url)
    if not domain:
        return None
    
    # Remove www. prefix for comparison
    check_domain = domain[4:] if domain.startswith('www.') else domain
    
    if check_domain in malicious_domains:
        return check_domain
    return None

def scan_chrome_history(db_path, browser_name, malicious_domains):
    """Scan Chrome/Edge history database."""
    findings = []
    
    if not os.path.exists(db_path):
        return findings
    
    # Copy locked database
    temp_db = os.path.join(os.environ.get('TEMP', '/tmp'), f'browser_scan_{browser_name}.db')
    try:
        shutil.copy2(db_path, temp_db)
    except PermissionError:
        print(f"  [{browser_name}] Database locked (browser running?), skipping")
        return findings
    
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time 
            FROM urls 
            ORDER BY last_visit_time DESC 
            LIMIT 100000
        """)
        
        for row in cursor.fetchall():
            url, title, visits, last_time = row
            matched = is_malicious(url, malicious_domains)
            if matched:
                # Convert Chrome timestamp
                chrome_epoch = 11644473600000000
                try:
                    unix_time = (last_time - chrome_epoch) / 1000000
                    visit_time = datetime.fromtimestamp(unix_time).isoformat()
                except:
                    visit_time = str(last_time)
                
                findings.append({
                    'browser': browser_name,
                    'url': url,
                    'title': title,
                    'visits': visits,
                    'visit_time': visit_time,
                    'matched_domain': matched,
                    'severity': 'CRITICAL'
                })
        
        conn.close()
    except sqlite3.Error as e:
        print(f"  [{browser_name}] SQLite error: {e}")
    finally:
        try:
            os.remove(temp_db)
        except:
            pass
    
    return findings

def scan_firefox_history(db_path, browser_name, malicious_domains):
    """Scan Firefox history database."""
    findings = []
    
    if not os.path.exists(db_path):
        return findings
    
    # Copy locked database
    temp_db = os.path.join(os.environ.get('TEMP', '/tmp'), f'browser_scan_{browser_name}.db')
    try:
        shutil.copy2(db_path, temp_db)
    except PermissionError:
        print(f"  [{browser_name}] Database locked (browser running?), skipping")
        return findings
    
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_date 
            FROM moz_places 
            ORDER BY last_visit_date DESC 
            LIMIT 100000
        """)
        
        for row in cursor.fetchall():
            url, title, visits, last_time = row
            matched = is_malicious(url, malicious_domains)
            if matched:
                # Firefox timestamp is microseconds since Unix epoch
                try:
                    unix_time = last_time / 1000000
                    visit_time = datetime.fromtimestamp(unix_time).isoformat()
                except:
                    visit_time = str(last_time)
                
                findings.append({
                    'browser': browser_name,
                    'url': url,
                    'title': title,
                    'visits': visits,
                    'visit_time': visit_time,
                    'matched_domain': matched,
                    'severity': 'CRITICAL'
                })
        
        conn.close()
    except sqlite3.Error as e:
        print(f"  [{browser_name}] SQLite error: {e}")
    finally:
        try:
            os.remove(temp_db)
        except:
            pass
    
    return findings

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN")
    
    print(f"=== Browser History Spyware Scan ===")
    print(f"Host: {hostname}")
    print(f"Time: {timestamp}")
    print("=" * 50)
    
    # Load malicious domains
    malicious_domains = load_malicious_domains()
    print(f"Loaded {len(malicious_domains)} malicious domains")
    
    all_findings = []
    
    # Chrome paths
    chrome_paths = [
        os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History'),
        os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Profile 1\History'),
        os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Profile 2\History'),
    ]
    
    for path in chrome_paths:
        print(f"\n[+] Scanning Chrome: {path}")
        findings = scan_chrome_history(path, "Chrome", malicious_domains)
        all_findings.extend(findings)
        if findings:
            print(f"    [!] Found {len(findings)} malicious visits!")
        else:
            print(f"    No malicious domains found")
    
    # Edge paths
    edge_paths = [
        os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History'),
        os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Profile 1\History'),
    ]
    
    for path in edge_paths:
        print(f"\n[+] Scanning Edge: {path}")
        findings = scan_chrome_history(path, "Edge", malicious_domains)
        all_findings.extend(findings)
        if findings:
            print(f"    [!] Found {len(findings)} malicious visits!")
        else:
            print(f"    No malicious domains found")
    
    # Firefox paths
    firefox_dir = os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles')
    if os.path.exists(firefox_dir):
        for profile in os.listdir(firefox_dir):
            places_db = os.path.join(firefox_dir, profile, 'places.sqlite')
            if os.path.exists(places_db):
                print(f"\n[+] Scanning Firefox: {places_db}")
                findings = scan_firefox_history(places_db, "Firefox", malicious_domains)
                all_findings.extend(findings)
                if findings:
                    print(f"    [!] Found {len(findings)} malicious visits!")
                else:
                    print(f"    No malicious domains found")
    
    # Summary
    print(f"\n{'=' * 50}")
    print(f"[SUMMARY]")
    print(f"  Total malicious visits found: {len(all_findings)}")
    
    if all_findings:
        print(f"\n!!! CRITICAL FINDINGS !!!")
        for f in all_findings:
            print(f"  [{f['browser']}] {f['matched_domain']}")
            print(f"    URL: {f['url']}")
            print(f"    Title: {f['title']}")
            print(f"    Visits: {f['visits']}")
            print(f"    Time: {f['visit_time']}")
            print()
        
        # Save to JSON
        output_file = SCRIPT_DIR / f"browser_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'hostname': hostname,
                'findings': all_findings,
                'total': len(all_findings)
            }, f, indent=2)
        print(f"[+] Results saved to: {output_file}")
        
        sys.exit(1)
    else:
        print("  No malicious domains found in browser history.")
        sys.exit(0)

if __name__ == '__main__':
    main()
