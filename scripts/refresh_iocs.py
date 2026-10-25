#!/usr/bin/env python3
"""
Daily IOC Refresh Script
Downloads latest spyware IOCs from multiple blocklist repositories.
Run as cron job to keep detection signatures current.
"""

import json
import urllib.request
import os
import sys
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

# Blocklist sources
SOURCES = {
    'nso_pegasus_hosts': 'https://raw.githubusercontent.com/0n1cOn3/The-NSO-Blacklist/main/hosts.txt',
    'nso_c2_servers': 'https://raw.githubusercontent.com/0n1cOn3/The-NSO-Blacklist/main/C2-hosts.txt',
    'candiru_hosts': 'https://raw.githubusercontent.com/0n1cOn3/The-Candiru-Blocklist/main/hosts.txt',
    'intellexa_hosts': 'https://raw.githubusercontent.com/0n1cOn3/The-Intellexa-Blocklist/main/hosts.txt',
    'paragon_hosts': 'https://raw.githubusercontent.com/0n1cOn3/The-Paragon-Blacklist/main/hosts.txt',
    'amnesty_stix2': 'https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2',
}

def download_file(url, timeout=30):
    """Download a file with timeout."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[ERROR] Failed to download {url}: {e}")
        return None

def parse_blocklist(content, source_name):
    """Parse blocklist content and extract domains/IPs."""
    domains = set()
    ips = set()
    c2_servers = set()
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Remove 0.0.0.0 prefix (Pi-hole format)
        if line.startswith('0.0.0.0 '):
            line = line[8:].strip()
        
        # Check for IP:port (C2 server)
        if ':' in line:
            parts = line.split(':')
            if len(parts) == 2 and parts[1].isdigit():
                c2_servers.add(line)
                ips.add(parts[0])
                continue
        
        # Check if IP address
        if all(c.isdigit() or c == '.' for c in line) and line.count('.') == 3:
            ips.add(line)
        elif '.' in line and ' ' not in line:
            domains.add(line.lower())
    
    return domains, ips, c2_servers

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"=== Spyware IOC Refresh ===")
    print(f"Time: {timestamp}")
    print(f"Script: {__file__}")
    print("=" * 50)
    
    all_domains = set()
    all_ips = set()
    all_c2_servers = set()
    stats = {}
    
    for name, url in SOURCES.items():
        print(f"\n[+] Fetching {name}...")
        content = download_file(url)
        if content:
            domains, ips, c2_servers = parse_blocklist(content, name)
            all_domains.update(domains)
            all_ips.update(ips)
            all_c2_servers.update(c2_servers)
            stats[name] = {
                'domains': len(domains),
                'ips': len(ips),
                'c2_servers': len(c2_servers)
            }
            print(f"    Domains: {len(domains)}, IPs: {len(ips)}, C2: {len(c2_servers)}")
        else:
            stats[name] = {'error': 'download failed'}
    
    # Load existing database for comparison
    db_path = SCRIPT_DIR / 'comprehensive_spyware_iocs.json'
    old_count = 0
    if db_path.exists():
        with open(db_path, 'r') as f:
            old_db = json.load(f)
            old_count = len(old_db.get('domains', []))
    
    # Build new database
    new_db = {
        'metadata': {
            'total_domains': len(all_domains),
            'total_ips': len(all_ips),
            'total_c2_servers': len(all_c2_servers),
            'previous_domains': old_count,
            'new_domains': len(all_domains) - old_count,
            'sources': list(SOURCES.keys()),
            'source_stats': stats,
            'updated': timestamp
        },
        'domains': sorted(all_domains),
        'ips': sorted(all_ips),
        'c2_servers': sorted(all_c2_servers)
    }
    
    # Save updated database
    with open(db_path, 'w') as f:
        json.dump(new_db, f, indent=2)
    
    print(f"\n{'=' * 50}")
    print(f"[SUMMARY]")
    print(f"  Total domains: {len(all_domains)} (was {old_count}, +{len(all_domains) - old_count})")
    print(f"  Total IPs: {len(all_ips)}")
    print(f"  Total C2 servers: {len(all_c2_servers)}")
    print(f"  Database saved: {db_path}")
    
    # Also update the PegasusSweep repo YAML
    repo_yaml = Path(r'C:\Users\Diamond\PegasusSweep\indicators\pegasus_iocs.yaml')
    if repo_yaml.exists():
        print(f"\n[+] Updating PegasusSweep repo YAML...")
        # Read existing YAML
        with open(repo_yaml, 'r') as f:
            yaml_content = f.read()
        
        # Update metadata version
        new_version = datetime.now().strftime("%Y.%m.%d")
        yaml_content = yaml_content.replace('version: 3.0.0', f'version: {new_version}')
        yaml_content = yaml_content.replace('updated: 2026-10-25', f'updated: {datetime.now().strftime("%Y-%m-%d")}')
        
        with open(repo_yaml, 'w') as f:
            f.write(yaml_content)
        print(f"    Updated version to {new_version}")
    
    print(f"\n[+] IOC refresh complete")
    return 0

if __name__ == '__main__':
    sys.exit(main())
