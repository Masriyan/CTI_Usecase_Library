# Hunt for Ransomware Using File Hash Pivoting

## Metadata
- **Use Case ID:** THD-UC001
- **Category:** Threat Hunting & Detection
- **Difficulty:** Intermediate
- **Estimated Time:** 2-3 hours
- **Last Updated:** 2025-12-30

## Description
Ransomware attacks continue to be one of the most damaging threats facing organizations today. When security teams identify a suspicious file hash—whether from an alert, incident report, or threat feed—the ability to quickly pivot and uncover the full scope of related ransomware infrastructure is critical for rapid response and containment.

This use case demonstrates how to leverage file hash indicators to conduct comprehensive threat hunting across multiple threat intelligence platforms. By pivoting from a single hash to related files, infrastructure, malware families, and threat actor campaigns, analysts can build a complete picture of the ransomware threat landscape affecting their organization.

The workflow covers enrichment of file hashes, discovery of related indicators, infrastructure mapping, and translation of findings into actionable detections that can be deployed across security controls.

## Objectives
By completing this use case, you will:
- Enrich file hash indicators to identify ransomware families and variants
- Pivot to discover related malicious files, infrastructure, and attack patterns
- Map the full kill chain from initial infection to encryption payloads
- Generate actionable indicators (IOCs) for detection and hunting rules
- Create comprehensive threat intelligence reports for stakeholders

## Prerequisites

### Data Sources
- **File Hash Indicators** - MD5, SHA1, SHA256 hashes from alerts, incidents, or threat feeds
- **Threat Intelligence Feeds** - Commercial and open-source feeds with file reputation data
- **Malware Repositories** - VirusTotal, MalwareBazaar, Hybrid Analysis, Any.Run
- **Internal Telemetry** - EDR logs, network traffic, email gateway logs

### Tools & Platforms
- **VirusTotal** - File hash enrichment and relationship analysis
- **MalwareBazaar** - Malware sample database and hash lookup
- **Hybrid Analysis** - Automated malware sandbox analysis
- **YARA Rules** - Pattern matching for malware detection
- **MISP or OpenCTI** - Threat intelligence platform for IOC management

### Required Skills
- Understanding of malware analysis fundamentals
- Familiarity with file hash types (MD5, SHA1, SHA256)
- Basic knowledge of ransomware attack lifecycle
- Ability to interpret sandbox analysis reports
- Query writing for threat intelligence platforms

### Access Requirements
- VirusTotal API key (free or premium)
- Access to malware repositories (accounts may be required)
- Access to organizational SIEM/EDR platforms
- Permissions to create/modify detection rules

## Step-by-Step Workflow

### Step 1: Initial Hash Enrichment
**Objective:** Gather comprehensive intelligence about the suspicious file hash

**Actions:**
1. Submit the file hash to VirusTotal for initial enrichment
2. Review detection rate, malware family labels, and behavioral indicators
3. Document the hash type, file name, file size, and first/last seen dates
4. Identify the ransomware family attribution (e.g., LockBit, BlackCat, ALPHV)

**Example:**
```bash
# Using VirusTotal API
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f \
  --header 'x-apikey: YOUR_API_KEY'
```

**Output:** Basic file intelligence including AV detection names, file metadata, and behavioral tags

---

### Step 2: Extract Behavioral Indicators
**Objective:** Identify the malware's behavior patterns and capabilities

**Actions:**
1. Review the VirusTotal "Behavior" tab for sandbox execution results
2. Document network connections, file modifications, registry changes, and process execution
3. Identify C2 domains/IPs, encryption behaviors, and persistence mechanisms
4. Note any unique TTPs that can be used for detection

**Example:**
```
Key Behaviors to Extract:
- Network: C2 beaconing patterns, DNS requests, HTTP/HTTPS traffic
- File System: Ransom note paths, encrypted file extensions, dropped executables
- Registry: Persistence keys, service creation, auto-run modifications
- Process: Command-line arguments, parent-child relationships, injection techniques
```

**Output:** List of behavioral indicators and TTPs mapped to MITRE ATT&CK framework

---

### Step 3: Pivot to Related Files
**Objective:** Discover additional malware samples related to the original hash

**Actions:**
1. Use VirusTotal's "Relations" tab to find related files
2. Look for files with same PE import hash, same contacted domains, or same malware family
3. Query MalwareBazaar for similar samples using signature or tag searches
4. Download YARA rules associated with the ransomware family

**Example:**
```python
# Example VirusTotal API query for related files
import requests

hash_value = "44d88612fea8a8f36de82e1278abb02f"
url = f"https://www.virustotal.com/api/v3/files/{hash_value}/bundled_files"
headers = {"x-apikey": "YOUR_API_KEY"}

response = requests.get(url, headers=headers)
related_files = response.json()
```

**Output:** Collection of related file hashes, typically 10-50 additional samples

---

### Step 4: Infrastructure Mapping
**Objective:** Map the complete infrastructure supporting the ransomware campaign

**Actions:**
1. Extract all domains and IPs contacted by the malware samples
2. Use passive DNS to identify additional infrastructure
3. Look for patterns in domain registration (WHOIS), hosting providers, and SSL certificates
4. Identify infrastructure overlap with known ransomware operations

**Example:**
```bash
# Query for contacted URLs from VirusTotal
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{hash}/contacted_urls \
  --header 'x-apikey: YOUR_API_KEY'
```

**Output:** Network diagram showing C2 servers, distribution sites, payment portals, and data exfiltration infrastructure

---

### Step 5: Malware Family Clustering
**Objective:** Group related samples by ransomware family and variant

**Actions:**
1. Analyze commonalities across all discovered samples
2. Group by malware family labels, behavioral patterns, and code similarities
3. Identify specific variants or versions based on ransom note text, file extensions, or encryption methods
4. Cross-reference with public ransomware tracking databases

**Example:**
```
Clustering Criteria:
- Same ransom note template
- Same file extension pattern (e.g., .lockbit, .blackcat)
- Same encryption algorithm indicators
- Same C2 infrastructure pattern
- Same code signing certificate
```

**Output:** Organized clusters of malware variants with version/campaign attribution

---

### Step 6: Threat Actor Attribution
**Objective:** Link the ransomware activity to known threat actor groups

**Actions:**
1. Review threat intelligence reports for the identified ransomware family
2. Check for TTPs matching known ransomware-as-a-service (RaaS) operators
3. Look for victimology patterns, ransom demands, and negotiation tactics
4. Cross-reference infrastructure with known threat actor infrastructure

**Example:**
```
Attribution Factors:
- Ransomware family: LockBit 3.0
- Deployment method: Cobalt Strike beacon
- Target profile: Healthcare sector, North America
- Ransom amount: $500K - $2M USD
- Payment method: Monero cryptocurrency
- Known affiliates: TA505, Evil Corp
```

**Output:** Threat actor profile with confidence level and supporting evidence

---

### Step 7: Historical Analysis
**Objective:** Understand the timeline and evolution of the threat

**Actions:**
1. Chart the first seen and last seen dates for all related samples
2. Identify campaign waves and activity patterns
3. Track changes in TTPs, infrastructure, or targeting over time
4. Compare current activity to historical campaigns

**Example:**
```
Timeline Analysis:
- Campaign Start: 2024-06-15
- Peak Activity: 2024-08-20 to 2024-09-10
- Latest Sample: 2025-12-28
- Infrastructure Changes: C2 migration on 2024-10-01
- Variant Evolution: 3 major versions detected
```

**Output:** Timeline visualization showing campaign evolution and current threat status

---

### Step 8: Internal Hunting
**Objective:** Search internal telemetry for signs of related activity

**Actions:**
1. Query EDR/SIEM for all discovered file hashes
2. Search for network connections to identified C2 infrastructure
3. Hunt for behavioral patterns and TTPs in endpoint logs
4. Check email gateway logs for related phishing campaigns

**Example:**
```sql
-- Example SIEM query for file hash hunting
index=endpoint sourcetype=edr
| search
  (file_hash="44d88612fea8a8f36de82e1278abb02f" OR
   file_hash="a1b2c3d4e5f6..." OR
   file_hash="...")
| table _time, host, file_path, file_hash, process_name, user
| sort -_time
```

**Output:** List of any internal detections or historical activity matching the threat

---

### Step 9: Detection Rule Creation
**Objective:** Generate detection rules to identify current and future activity

**Actions:**
1. Create YARA rules for file-based detection
2. Write Sigma rules for behavioral detection
3. Develop network signatures for C2 communication patterns
4. Configure EDR rules for suspicious process behaviors

**Example:**
```yara
rule Ransomware_LockBit30_Variant {
    meta:
        description = "Detects LockBit 3.0 ransomware variants"
        author = "CTI Team"
        date = "2025-12-30"
        hash = "44d88612fea8a8f36de82e1278abb02f"

    strings:
        $ransom_note = "LockBit" ascii wide
        $extension = ".lockbit" ascii wide
        $c2_pattern = /https?:\/\/[a-z0-9]+\.onion/ ascii wide
        $crypto_api = "CryptEncrypt" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        2 of them
}
```

**Output:** Complete detection rule set ready for deployment

---

### Step 10: Intelligence Report Generation
**Objective:** Document findings and disseminate actionable intelligence

**Actions:**
1. Compile all IOCs into a structured format (STIX, JSON, CSV)
2. Write an executive summary of the threat, impact, and recommendations
3. Create technical appendix with detailed analysis and detection guidance
4. Distribute to stakeholders via TIP, email, or ticketing system

**Example:**
```markdown
# Ransomware Threat Intelligence Report
## Executive Summary
LockBit 3.0 ransomware variant detected. High confidence attribution
to LockBit RaaS affiliate. 47 related samples identified. C2
infrastructure active as of 2025-12-28. Recommend immediate hunting
and preventative controls.

## Key Findings
- Malware Family: LockBit 3.0
- Threat Actor: LockBit Affiliate (Unknown)
- Infrastructure: 8 C2 domains, 4 IP addresses
- Related Samples: 47 file hashes
- Internal Detections: None found
- Risk Level: HIGH

## Recommendations
1. Deploy detection rules immediately
2. Block C2 infrastructure at perimeter
3. Hunt internally for behavioral indicators
4. Review backup and recovery procedures
```

**Output:** Comprehensive intelligence report with IOCs, analysis, and recommendations

---

## Recommended CTI Products

### Primary Products
- **VirusTotal Enterprise** - Comprehensive file intelligence and relationship analysis
  - Assessment: [VirusTotal Enterprise](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#virustotal-enterprise)
  - Key Features: File hash lookup, behavioral analysis, relationship graphs, retrohunting capabilities

- **Recorded Future** - Threat intelligence aggregation with ransomware tracking
  - Assessment: [Recorded Future](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#recorded-future)
  - Key Features: Ransomware dashboards, actor profiling, infrastructure tracking

### Alternative/Complementary Products
- **Anomali ThreatStream** - Threat intelligence platform with IOC management
  - Assessment: [Anomali ThreatStream](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#anomali-threatstream)

- **ThreatConnect** - Collaborative threat intelligence with orchestration
  - Assessment: [ThreatConnect](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#threatconnect)

- **IBM X-Force Exchange** - Community-driven threat intelligence sharing
  - Assessment: [IBM X-Force Exchange](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#ibm-x-force-exchange)

### Open Source Options
- **MalwareBazaar** - Free malware sample repository with hash lookup
- **Hybrid Analysis** - Free automated malware analysis sandbox
- **MISP** - Open-source threat intelligence platform
- **Malware Traffic Analysis** - Public repository of malware traffic patterns

## Expected Outputs

### Deliverables
1. **IOC Collection**
   - Format: STIX 2.1, JSON, CSV
   - Content: File hashes, domains, IPs, URLs, YARA rules
   - Audience: SOC analysts, threat hunters, security engineers

2. **Detection Rules Package**
   - Format: YARA, Sigma, Snort, EDR-specific
   - Content: Multi-layer detection rules for ransomware variants
   - Audience: Detection engineers, SOC operations

3. **Threat Intelligence Report**
   - Format: PDF/Markdown
   - Content: Executive summary, technical analysis, IOCs, recommendations
   - Audience: Management, security leadership, incident response team

4. **Infrastructure Map**
   - Format: Visual diagram (Maltego, draw.io)
   - Content: C2 servers, distribution infrastructure, payment portals
   - Audience: Threat hunters, network security team

### Sample Output
```json
{
  "threat_report": {
    "id": "THD-UC001-20251230",
    "malware_family": "LockBit 3.0",
    "threat_actor": "LockBit Affiliate",
    "confidence": "high",
    "iocs": {
      "file_hashes": {
        "sha256": [
          "44d88612fea8a8f36de82e1278abb02f7fd2ad098f4d0f74f5b849c0c8b6a88a",
          "..."
        ]
      },
      "network": {
        "domains": ["malicious-c2.onion", "exfil-server.xyz"],
        "ips": ["185.220.101.45", "192.42.116.180"]
      }
    },
    "recommendations": [
      "Deploy YARA rules to all endpoints",
      "Block C2 infrastructure at firewall",
      "Conduct internal hunt for behavioral IOCs"
    ]
  }
}
```

## Success Metrics
- Number of related malware samples discovered (target: 20+ samples)
- Completeness of infrastructure mapping (C2 servers, distribution sites)
- Detection rule accuracy (low false positive rate < 1%)
- Time from initial hash to actionable intelligence (target: < 3 hours)
- Internal hunting coverage (% of estate scanned)

## Tips & Best Practices

### General Tips
- Always verify hash type (MD5, SHA1, SHA256) before submitting to platforms
- Use multiple threat intelligence sources to cross-validate findings
- Prioritize behavioral indicators over static signatures for better detection longevity
- Document your pivoting logic to create repeatable workflows
- Collaborate with malware analysis team for deep-dive sample analysis when needed

### Common Pitfalls to Avoid
- **Over-reliance on single source**: Always cross-reference findings across multiple platforms. VirusTotal may miss samples available in MalwareBazaar or Hybrid Analysis
- **Ignoring false positives**: Review AV vendor detections carefully; generic names like "Trojan.Generic" provide limited value
- **Missing infrastructure evolution**: Ransomware operators frequently change infrastructure; track historical patterns to anticipate future infrastructure
- **Neglecting internal hunting**: External intelligence is only valuable if you verify your environment is clean

### Optimization Strategies
- Create automated hash enrichment pipelines using APIs
- Build hash collection libraries organized by malware family
- Maintain a watchlist of known ransomware infrastructure for rapid response
- Develop template detection rules that can be quickly adapted for new variants
- Use retrohunting features to identify historical infections

### Automation Opportunities
- Automated hash submission to multiple platforms via API
- Scheduled queries for new samples matching ransomware family tags
- Automatic IOC extraction from analysis reports
- Integration with SOAR platforms for orchestrated response
- Automated detection rule deployment to security controls

## Real-World Application

### Industry Examples
- **Healthcare:** Hospital uses hash pivoting to discover ransomware deployment across multiple facilities after initial detection in one location
- **Financial Services:** Bank identifies complete LockBit campaign infrastructure by pivoting from single hash in phishing email attachment
- **Manufacturing:** Global manufacturer traces ransomware infection vector back to compromised third-party software update using hash analysis

### Case Study
In September 2024, a mid-size manufacturing company detected a suspicious executable during routine endpoint monitoring. The SOC analyst submitted the SHA256 hash to VirusTotal and identified it as a LockBit 3.0 dropper. Using the workflow outlined in this use case, the analyst:

1. Discovered 34 related samples through hash pivoting
2. Mapped 6 C2 servers and 3 data exfiltration sites
3. Identified the initial infection vector (phishing email with macro-enabled document)
4. Created YARA and Sigma rules that detected 3 additional compromised endpoints
5. Blocked all C2 infrastructure before encryption could execute

The proactive hunting prevented a potential ransomware event that could have cost $2M+ in downtime and recovery. The total analysis time was 2.5 hours, demonstrating the efficiency of structured hash pivoting workflows.

## Additional Resources

### Documentation
- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
- [MalwareBazaar API Guide](https://bazaar.abuse.ch/api/)
- [MITRE ATT&CK for Ransomware](https://attack.mitre.org/techniques/T1486/)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)

### Training Materials
- SANS FOR578: Cyber Threat Intelligence
- Recorded Future Analyst Certification
- VirusTotal Intelligence Training

### Community Resources
- Reddit: r/threatintel, r/malware
- Twitter: #CTI, #threatintel, #ransomware
- ID-Ransomware Community
- Ransomware.live tracking dashboard

## Related Use Cases
- [UC004: Hunt for C2 Beaconing Patterns](UC004-hunt-c2-beaconing-patterns.md) - Detecting command and control traffic
- [UC008: Track Malware Distribution Infrastructure](UC008-track-malware-distribution-infrastructure.md) - Mapping delivery mechanisms
- [Vulnerability Intelligence UC003: Map Vulnerabilities to Threat Actor TTPs](../vulnerability-intelligence/UC003-map-vulnerabilities-threat-actor-ttps.md) - Linking exploits to ransomware campaigns

## Version History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-30 | CTI Team | Initial creation |

---

## Appendix

### Glossary
- **File Hash**: Cryptographic fingerprint of a file (MD5, SHA1, SHA256)
- **Pivoting**: Using one indicator to discover related indicators
- **C2 (Command and Control)**: Infrastructure used by malware to communicate with operators
- **RaaS (Ransomware-as-a-Service)**: Business model where ransomware developers lease malware to affiliates
- **IOC (Indicator of Compromise)**: Artifact indicating a potential security incident
- **TTPs (Tactics, Techniques, and Procedures)**: Behavior patterns of threat actors

### Sample Queries/Scripts
```python
# Automated hash enrichment script
import requests
import json

def enrich_hash(file_hash, api_key):
    """Enrich file hash using VirusTotal API"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()

        # Extract key information
        results = {
            "hash": file_hash,
            "malicious_votes": data['data']['attributes']['last_analysis_stats']['malicious'],
            "malware_family": data['data']['attributes'].get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown'),
            "first_seen": data['data']['attributes']['first_submission_date'],
            "last_seen": data['data']['attributes']['last_analysis_date']
        }
        return results
    else:
        return None

# Usage
hash_value = "44d88612fea8a8f36de82e1278abb02f"
result = enrich_hash(hash_value, "YOUR_API_KEY")
print(json.dumps(result, indent=2))
```

### Workflow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                    Ransomware Hash Pivoting Workflow            │
└─────────────────────────────────────────────────────────────────┘

    [File Hash]
         │
         ▼
    ┌────────────────┐
    │ 1. Enrich Hash │ ──────► VirusTotal, MalwareBazaar
    └────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 2. Extract Behavior │ ──────► Sandbox Reports, TTPs
    └─────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │ 3. Pivot to Related  │ ──────► Related Hashes
    │      Files           │          (10-50 samples)
    └──────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │ 4. Map Infrastructure│ ──────► C2 Servers, Domains, IPs
    └──────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │ 5. Cluster Malware   │ ──────► Family/Variant Groups
    └──────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │ 6. Threat Attribution│ ──────► Actor Profile
    └──────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │ 7. Historical        │ ──────► Timeline Analysis
    │      Analysis        │
    └──────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │ 8. Internal Hunting  │ ──────► EDR/SIEM Queries
    └──────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │ 9. Create Detections │ ──────► YARA, Sigma, Snort
    └──────────────────────┘
         │
         ▼
    ┌──────────────────────┐
    │ 10. Generate Report  │ ──────► IOCs, Analysis, Recommendations
    └──────────────────────┘
```
