# Credits & Attributions

Pegasus-Sweep builds upon the work of many security researchers, organizations, and open-source projects. This file acknowledges their contributions.

---

## Primary IOC & Research Sources

### Amnesty International Security Lab
- **What**: Pegasus spyware IOCs, forensic methodology, STIX2 data
- **URL**: https://securitylab.amnesty.org
- **GitHub**: https://github.com/AmnestyTech/investigations
- **Contributions**:
  - 81 Pegasus process names (STIX2 format)
  - 1,438 C2 domains
  - 29 operator email addresses (Apple IDs)
  - Infection vector names: Heaven, Erised, Eden, Hummingbird
  - Internal NSO architecture from leaked court documents (2026)
- **License**: CC-BY 4.0 (https://creativecommons.org/licenses/by/4.0/)
- **Citation**: Amnesty International. "Forensic Methodology Report: How to catch NSO Group's Pegasus." July 2021. https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/

### Citizen Lab
- **What**: Long-term surveillance research, Candiru/Paragon IOCs
- **URL**: https://citizenlab.ca
- **Contributions**:
  - Candiru (DevilsTongue) domain IOCs
  - Paragon (Graphite) infrastructure analysis
  - NSO Group tracking and attribution
- **Key Reports**:
  - "Hooking Candiru: Another Mercenary Spyware Vendor Comes into Focus" (July 2021)
  - "Virtue or Vice? A First Look at Paragon's Proliferating Spyware Operations" (2024)
- **License**: Research publications (open access)

---

## Blocklist Repositories

### The-NSO-Blacklist
- **Author**: 0n1cOn3
- **URL**: https://github.com/0n1cOn3/The-NSO-Blacklist
- **What**: NSO Group Pegasus C2 domains and IPs
- **Contributions**:
  - 6,643 hosts (domains + IPs)
  - 243 C2 server IP:port pairs
  - Pegasus architecture documentation (from 2026 court case analysis)
- **License**: Not specified (assumed public domain for security research)

### The-Candiru-Blocklist
- **Author**: 0n1cOn3
- **URL**: https://github.com/0n1cOn3/The-Candiru-Blocklist
- **What**: Candiru (DevilsTongue/Sourgum) C2 domains
- **Contributions**: 57+ domains, 3 IPs
- **License**: Not specified

### The-Intellexa-Blocklist
- **Author**: 0n1cOn3
- **URL**: https://github.com/0n1cOn3/The-Intellexa-Blocklist
- **What**: Intellexa Predator (Cytrox) C2 domains
- **Contributions**: 516+ domains from Intellexa Leaks (2025)
- **License**: Not specified

### The-Paragon-Blacklist
- **Author**: 0n1cOn3
- **URL**: https://github.com/0n1cOn3/The-Paragon-Blacklist
- **What**: Paragon Graphite C2 infrastructure
- **Contributions**: Tier 1/2 infrastructure IPs and domains
- **License**: Not specified

### The-Spyware-Archive
- **Author**: 0n1cOn3
- **URL**: https://github.com/0n1cOn3/The-Spyware-Archive
- **What**: Historical spyware vendor IOCs
- **Contributions**:
  - Dark Basin/BellTroX (462 domains)
  - FinFisher (25 domains)
  - Hacking Team (historical)
  - Cyberbit, Sandvine, Stealth Falcon, Poison Carp, Nile Phish
- **License**: Not specified

---

## Mobile Verification Toolkit (MVT)

### MVT Project
- **What**: iOS/Android forensic analysis for Pegasus detection
- **URL**: https://github.com/mvt-project/mvt
- **Contributions**:
  - iOS forensic artifact detection
  - Android forensic analysis
  - Pegasus IOC integration
- **License**: MIT (https://github.com/mvt-project/mvt/blob/main/LICENSE)
- **Note**: MVT is invoked as an external tool, not vendored or redistributed.

---

## Additional Research Sources

### Microsoft Threat Intelligence (MSTIC)
- **What**: DevilsTongue/Sourgum analysis, Windows-specific IOCs
- **URL**: https://www.microsoft.com/security/blog
- **Key Report**: "Microsoft unveils new research on DevilsTongue malware" (July 2021)

### Google Threat Analysis Group (TAG)
- **What**: Android/iOS spyware analysis, zero-day tracking
- **URL**: https://blog.google/threat-analysis-group/
- **Contributions**: In-the-wild exploit analysis, vendor attribution

### Lookout Security
- **What**: Mobile threat intelligence, Pegasus analysis
- **URL**: https://www.lookout.com
- **Contributions**: Early Pegasus detection research

### Qihoo 360 / Other Vendors
- **What**: Additional IOCs and analysis
- **Contributions**: Supplementary indicators and validation

---

## Historical Vendor Research

### FinFisher / Gamma Group
- **Status**: Insolvent 2022
- **Research**: WikiLeaks Spy Files, various security researchers

### Hacking Team / Memento Labs
- **Status**: Rebranded after 2015 breach
- **Research**: Phineas Fisher breach, Citizen Lab analysis

### Dark Basin / BellTroX InfoTech
- **Research**: Citizen Lab "Dark Basin: Uncovering a Massive Hack-for-Hire Operation" (2020)

---

## Software Libraries & Tools

### Python Standard Library
- **What**: Core scripting, JSON/YAML processing, SQLite
- **URL**: https://www.python.org
- **License**: PSF License

### PowerShell
- **What**: Windows host scanning, registry analysis
- **URL**: https://github.com/PowerShell/PowerShell
- **License**: MIT

### YARA
- **What**: Pattern matching for process detection
- **URL**: https://github.com/VirusTotal/yara
- **License**: BSD 3-Clause

### psutil
- **What**: Python process and system monitoring
- **URL**: https://github.com/giampaolo/psutil
- **License**: BSD 3-Clause

### Flask
- **What**: Web dashboard framework
- **URL**: https://github.com/pallets/flask
- **License**: BSD 3-Clause

---

## Data Formats & Standards

### STIX 2.1
- **What**: Structured Threat Information Expression
- **URL**: https://oasis-open.github.io/cti-documentation/
- **Contributions**: IOC format standardization

---

## Ethical & Legal Framework

### Access Now
- **What**: Digital rights advocacy, spyware victim support
- **URL**: https://www.accessnow.org
- **Contributions**: Ethical guidelines for spyware research

### Electronic Frontier Foundation (EFF)
- **What**: Digital privacy and security research
- **URL**: https://www.eff.org
- **Contributions**: Legal framework for security research

---

## Disclaimer

This project aggregates publicly available indicators of compromise (IOCs) for defensive security purposes. All IOCs remain the property of their original researchers and organizations. This project claims no ownership over third-party indicators and provides attribution to the best of our ability.

If you believe your work has been used without proper attribution, please open an issue at: https://github.com/whargrove671-droid/pegasus-sweep/issues

---

## How to Contribute IOCs

If you have spyware IOCs to contribute:
1. Verify the IOCs are from public research or your own original research
2. Ensure you have rights to share the indicators
3. Submit via GitHub issue or pull request with source attribution
4. Include: vendor, product, indicator type, value, source URL, date

---

**Last Updated**: 2026-10-25
**Version**: 3.0.1
