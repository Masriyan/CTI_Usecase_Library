# Track APT Infrastructure Using Passive DNS

## Metadata
- **Use Case ID:** THD-UC002
- **Category:** Threat Hunting & Detection
- **Difficulty:** Advanced
- **Estimated Time:** 3-4 hours
- **Last Updated:** 2025-12-30

## Description
Advanced Persistent Threat (APT) groups operate sophisticated attack infrastructure that evolves continuously to evade detection. While domains and IP addresses may change frequently, passive DNS (pDNS) data provides a historical record of DNS resolutions that reveals infrastructure patterns, relationships, and operational security mistakes made by threat actors.

This use case demonstrates how to leverage passive DNS data to track APT infrastructure over time, uncover hidden relationships between seemingly unrelated domains, identify infrastructure reuse patterns, and predict future attacker infrastructure. By analyzing DNS resolution history, registration patterns, and infrastructure evolution, analysts can build comprehensive maps of APT operations and develop proactive blocking strategies.

The workflow is particularly valuable for tracking state-sponsored groups, understanding long-term campaigns, and identifying early warning indicators before attacks reach target networks.

## Objectives
By completing this use case, you will:
- Master passive DNS queries to uncover historical infrastructure relationships
- Identify infrastructure patterns and clustering techniques used by APT groups
- Track domain registration and DNS configuration changes over time
- Develop predictive indicators based on infrastructure reuse patterns
- Create proactive blocking lists and early warning detections

## Prerequisites

### Data Sources
- **Passive DNS Databases** - Historical DNS resolution records (RiskIQ, Farsight DNSDB, VirusTotal)
- **WHOIS Records** - Domain registration information and registrant details
- **SSL Certificate Data** - Certificate transparency logs and SSL fingerprints
- **Threat Intelligence Feeds** - APT group infrastructure tracking feeds
- **Internal DNS Logs** - Organizational DNS query logs for hunting

### Tools & Platforms
- **RiskIQ PassiveTotal** - Comprehensive passive DNS and WHOIS platform
- **Farsight DNSDB** - Large-scale passive DNS database
- **VirusTotal** - Passive DNS relations and domain intelligence
- **Shodan/Censys** - Internet-wide scanning for infrastructure fingerprinting
- **Maltego** - Visual infrastructure mapping and relationship analysis

### Required Skills
- Understanding of DNS protocol and record types (A, AAAA, MX, NS, CNAME, TXT)
- Knowledge of APT tactics and infrastructure lifecycle
- Ability to identify infrastructure patterns and clustering
- Experience with WHOIS interpretation and domain analysis
- Data analysis skills for large datasets

### Access Requirements
- RiskIQ or Farsight DNSDB account with API access
- VirusTotal API key (premium recommended for historical data)
- Access to threat intelligence platforms
- WHOIS lookup capabilities (not rate-limited)
- Internal DNS logging and query access

## Step-by-Step Workflow

### Step 1: Seed IOC Collection
**Objective:** Gather initial known APT infrastructure indicators to begin investigation

**Actions:**
1. Identify the APT group you're tracking (e.g., APT29, APT28, Lazarus)
2. Collect known domains, IPs, and infrastructure from threat reports and feeds
3. Verify the attribution confidence and date ranges for each indicator
4. Organize seed IOCs by campaign or timeframe

**Example:**
```python
# Example seed IOC collection for APT29
seed_iocs = {
    "domains": [
        "diplomacy-gov.org",
        "state-department.info",
        "secure-auth-portal.net"
    ],
    "ips": [
        "185.86.149.135",
        "45.32.130.223"
    ],
    "campaign": "SolarWinds Supply Chain",
    "date_range": "2020-03-01 to 2020-12-31"
}
```

**Output:** Validated list of 5-10 seed indicators with attribution metadata

---

### Step 2: Initial Passive DNS Lookup
**Objective:** Retrieve historical DNS resolution data for seed indicators

**Actions:**
1. Query passive DNS for each seed domain to get all historical IP resolutions
2. Query reverse passive DNS for each IP to find all domains hosted on that IP
3. Record first seen and last seen dates for each resolution
4. Note any anomalies in resolution patterns (short-lived resolutions, unusual TTLs)

**Example:**
```bash
# Using RiskIQ PassiveTotal API
curl -u "API_EMAIL:API_KEY" \
  "https://api.passivetotal.org/v2/dns/passive?query=diplomacy-gov.org"

# Using Farsight DNSDB
curl -H "X-API-Key: YOUR_API_KEY" \
  "https://api.dnsdb.info/lookup/rrset/name/diplomacy-gov.org"
```

**Output:** Complete DNS resolution history showing all IPs associated with seed domains across time

---

### Step 3: Infrastructure Expansion via IP Pivoting
**Objective:** Discover additional APT infrastructure by pivoting on IP addresses

**Actions:**
1. For each IP discovered in Step 2, perform reverse passive DNS lookups
2. Filter results to identify suspicious or strategically named domains
3. Look for patterns like typosquatting, brand impersonation, or government mimicry
4. Identify domains that existed during the same timeframe as known APT activity

**Example:**
```python
# Reverse pDNS lookup logic
def expand_infrastructure(ip_address, pdns_client):
    """Find all domains that resolved to this IP"""
    domains = pdns_client.reverse_dns(ip_address)

    # Filter for suspicious patterns
    suspicious = []
    for domain in domains:
        if is_suspicious_pattern(domain):
            suspicious.append(domain)

    return suspicious

def is_suspicious_pattern(domain):
    """Identify APT naming patterns"""
    patterns = [
        'gov', 'state', 'department', 'security',
        'portal', 'auth', 'login', 'secure'
    ]
    return any(p in domain.lower() for p in patterns)
```

**Output:** Expanded set of 20-50 potentially related domains grouped by IP address

---

### Step 4: Temporal Clustering Analysis
**Objective:** Identify infrastructure clusters based on timing and co-location

**Actions:**
1. Create a timeline of all domain-to-IP resolutions
2. Identify domains that shared IPs during overlapping timeframes
3. Look for "fast flux" patterns where domains rapidly changed IPs
4. Cluster domains that appeared and disappeared in similar time windows

**Example:**
```
Timeline Analysis:
2020-03-15: diplomacy-gov.org → 185.86.149.135 (first seen)
2020-03-15: state-department.info → 185.86.149.135 (first seen)
2020-03-20: secure-auth-portal.net → 185.86.149.135 (first seen)
2020-05-10: All three domains → New IP 45.32.130.223
2020-06-15: diplomacy-gov.org (last seen)

Cluster Confidence: HIGH
Reason: Simultaneous deployment and migration patterns
```

**Output:** Temporal clusters of domains with confidence scores

---

### Step 5: WHOIS and Registration Analysis
**Objective:** Analyze domain registration patterns for infrastructure attribution

**Actions:**
1. Collect WHOIS records for all discovered domains
2. Identify shared registrant details (email, name, organization, phone)
3. Note privacy service usage and registrar patterns
4. Track registration date patterns and domain lifetime
5. Identify name servers and hosting provider patterns

**Example:**
```bash
# WHOIS lookup
whois diplomacy-gov.org

# Key fields to analyze:
# - Registrant Email (privacy-protected or unique pattern)
# - Registrar (common APT registrars: Namecheap, PDR)
# - Registration Date (bulk registration dates)
# - Name Servers (shared infrastructure)
```

**Output:** Registration pattern analysis showing shared infrastructure indicators

---

### Step 6: SSL Certificate Correlation
**Objective:** Use SSL certificate data to find additional related infrastructure

**Actions:**
1. Query SSL certificate transparency logs for discovered domains
2. Extract certificate serial numbers, issuers, and subject alternative names (SANs)
3. Search for other domains using identical or similar certificates
4. Identify shared certificate issuance patterns or self-signed certificates

**Example:**
```bash
# Using crt.sh for certificate transparency search
curl "https://crt.sh/?q=diplomacy-gov.org&output=json"

# Look for shared certificates
curl "https://crt.sh/?serial=ABC123XYZ&output=json"
```

**Output:** Network of domains linked by shared SSL certificates

---

### Step 7: Hosting Infrastructure Fingerprinting
**Objective:** Identify hosting patterns and infrastructure preferences

**Actions:**
1. Use Shodan/Censys to fingerprint discovered IP addresses
2. Identify hosting providers, ASNs, and geolocation patterns
3. Look for VPS providers commonly used by APT groups
4. Identify open ports, services, and server configurations
5. Note any operational security mistakes (open management panels, default configs)

**Example:**
```python
import shodan

api = shodan.Shodan('YOUR_API_KEY')
host = api.host('185.86.149.135')

print(f"Organization: {host.get('org')}")
print(f"Operating System: {host.get('os')}")
print(f"Open Ports: {host.get('ports')}")
print(f"Hostnames: {host.get('hostnames')}")
```

**Output:** Infrastructure fingerprint profile showing hosting patterns and technical details

---

### Step 8: Pattern-Based Infrastructure Prediction
**Objective:** Predict future APT infrastructure based on identified patterns

**Actions:**
1. Analyze domain naming conventions and generation algorithms
2. Identify IP range patterns and hosting provider preferences
3. Look for registrar and registration timing patterns
4. Create detection rules for predicted infrastructure characteristics

**Example:**
```
Identified Patterns:
1. Domain Pattern: [keyword]-[gov/org/department].[com/org/net]
2. Registrar: 90% Namecheap, 10% PDR Ltd
3. Hosting: BulletProof hosting in Netherlands, Moldova
4. Registration: Bulk registration on 15th of month
5. SSL: Let's Encrypt or self-signed certificates
6. Lifetime: 45-90 days average

Predictive Indicators:
- Monitor newly registered domains matching naming pattern
- Alert on domains registered via Namecheap in bulk
- Flag domains on Netherlands/Moldova VPS hosting
```

**Output:** Predictive intelligence profile for future infrastructure hunting

---

### Step 9: Internal Hunting with pDNS Intelligence
**Objective:** Search internal DNS logs for evidence of APT infrastructure contact

**Actions:**
1. Export all discovered domains and IPs to hunting list
2. Query internal DNS logs for historical lookups
3. Search proxy/firewall logs for connection attempts
4. Identify any endpoints that contacted malicious infrastructure
5. Correlate with email logs to identify initial infection vectors

**Example:**
```sql
-- SIEM query for DNS lookups to suspicious domains
index=dns
| search query IN (
    "diplomacy-gov.org",
    "state-department.info",
    "secure-auth-portal.net"
  )
| table _time, src_ip, query, answer, user
| sort -_time
```

**Output:** List of internal systems that contacted APT infrastructure with timestamps

---

### Step 10: Continuous Monitoring and Alerting
**Objective:** Establish ongoing monitoring for infrastructure evolution

**Actions:**
1. Create watchlists for discovered domains and IP ranges
2. Configure passive DNS monitoring alerts for infrastructure changes
3. Set up domain registration monitoring for predictive patterns
4. Integrate findings into TIP for automated enrichment
5. Schedule periodic re-analysis to track infrastructure evolution

**Example:**
```yaml
# Monitoring configuration
watchlist:
  name: "APT29 Infrastructure Tracking"
  domains:
    - "*.diplomacy-gov.org"
    - pattern: "[a-z]+-gov\\.org"
  ips:
    - "185.86.149.0/24"
  alerts:
    - new_dns_resolution
    - domain_registration_match
    - ssl_certificate_match
  notification:
    - email: cti-team@company.com
    - slack: #threat-intel
```

**Output:** Automated monitoring system for APT infrastructure tracking

---

## Recommended CTI Products

### Primary Products
- **RiskIQ PassiveTotal** - Industry-leading passive DNS and infrastructure analysis
  - Assessment: [RiskIQ PassiveTotal](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#riskiq-passivetotal)
  - Key Features: Passive DNS, WHOIS, SSL certificates, infrastructure tracking, visual pivoting

- **Farsight DNSDB** - Largest passive DNS database with historical depth
  - Assessment: [Farsight DNSDB](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#farsight-dnsdb)
  - Key Features: Real-time passive DNS, extensive historical data, API access

### Alternative/Complementary Products
- **VirusTotal** - Passive DNS relations and domain intelligence
  - Assessment: [VirusTotal Enterprise](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#virustotal-enterprise)

- **DomainTools** - WHOIS and domain registration intelligence
  - Assessment: [DomainTools](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#domaintools)

- **Recorded Future** - Threat intelligence with infrastructure tracking
  - Assessment: [Recorded Future](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#recorded-future)

### Open Source Options
- **SecurityTrails** - Free tier passive DNS lookups
- **Shodan** - Internet-wide scanning and host intelligence
- **Censys** - IPv4 scanning and certificate search
- **crt.sh** - Free SSL certificate transparency search

## Expected Outputs

### Deliverables
1. **Infrastructure Map**
   - Format: Maltego graph, visual diagram
   - Content: Complete network of APT domains, IPs, certificates, and relationships
   - Audience: Threat hunters, intelligence analysts, management

2. **IOC Package**
   - Format: STIX 2.1, CSV, JSON
   - Content: All discovered domains, IPs, and infrastructure indicators
   - Audience: SOC analysts, firewall administrators

3. **Pattern Analysis Report**
   - Format: PDF/Markdown document
   - Content: Infrastructure patterns, predictive indicators, monitoring recommendations
   - Audience: CTI team, security leadership

4. **Hunting Results**
   - Format: Incident tickets, SIEM reports
   - Content: Internal detections of APT infrastructure contact
   - Audience: Incident response, SOC

### Sample Output
```json
{
  "apt_infrastructure_analysis": {
    "threat_actor": "APT29 (Cozy Bear)",
    "analysis_date": "2025-12-30",
    "seed_indicators": 7,
    "discovered_indicators": 43,
    "confidence": "high",
    "infrastructure_clusters": [
      {
        "cluster_id": "C1",
        "domains": 15,
        "ips": 8,
        "timeframe": "2020-03-15 to 2020-06-15",
        "pattern": "Government impersonation domains"
      }
    ],
    "patterns": {
      "registrar": "Namecheap (87%)",
      "hosting": "Netherlands VPS (65%)",
      "domain_lifetime": "45-90 days average",
      "ssl": "Let's Encrypt (78%)"
    },
    "internal_detections": 2,
    "recommendations": [
      "Block all discovered infrastructure at perimeter",
      "Monitor for domain registration patterns",
      "Hunt for additional C2 beaconing"
    ]
  }
}
```

## Success Metrics
- Infrastructure expansion ratio: 5-10x from seed indicators
- Pattern identification confidence: >80% for key patterns
- Predictive indicator accuracy: >70% for future infrastructure
- Internal detection rate: Document all historical contacts
- Time to complete analysis: <4 hours for initial analysis

## Tips & Best Practices

### General Tips
- Start with high-confidence seed indicators from vetted threat reports
- Use multiple passive DNS sources to cross-validate findings
- Pay attention to infrastructure migration patterns—they reveal operational tempo
- Document your pivoting logic to create repeatable playbooks
- Visualize infrastructure relationships using graph tools like Maltego

### Common Pitfalls to Avoid
- **Shared hosting false positives**: VPS and shared hosting will show many unrelated domains on same IP—filter by timeframe and context
- **Privacy service noise**: WHOIS privacy services obscure registrant data; focus on registrar, timing, and technical patterns instead
- **Historical data overload**: Limit timeframe queries to relevant campaign periods to avoid overwhelming data
- **Attribution bias**: Verify infrastructure patterns match known APT TTPs before making attribution claims

### Optimization Strategies
- Create automated pDNS enrichment pipelines for new APT reports
- Maintain historical infrastructure databases for each tracked APT group
- Build pattern libraries for rapid identification of APT infrastructure
- Use machine learning for infrastructure clustering and pattern detection
- Integrate pDNS data with SIEM for real-time hunting

### Automation Opportunities
- Automated passive DNS lookups for new IOCs from threat feeds
- Scheduled infrastructure re-analysis to track evolution
- Automatic domain registration monitoring based on patterns
- SOAR integration for infrastructure blocking workflows
- Automated infrastructure map generation and updates

## Real-World Application

### Industry Examples
- **Government:** Defense contractor tracks Chinese APT infrastructure to identify targeting campaigns before intrusion attempts
- **Financial Services:** Bank uses pDNS analysis to discover North Korean Lazarus Group infrastructure targeting SWIFT systems
- **Technology:** Software company identifies Russian APT supply chain attack infrastructure through domain registration patterns
- **Energy:** Utility provider maps Iranian APT infrastructure to protect critical industrial control systems

### Case Study
In 2021, a major telecommunications provider's CTI team detected suspicious DNS queries to a domain impersonating a government portal. Using passive DNS analysis:

1. Initial seed: Single domain from internal DNS alert
2. pDNS expansion: Discovered 38 related domains across 12 IP addresses
3. Temporal analysis: Identified 3 distinct infrastructure clusters across 6 months
4. Registration analysis: Found shared registrar and bulk registration patterns
5. Predictive modeling: Created detection rules that identified 7 new domains 2 weeks before they were used in attacks
6. Internal hunting: Found 4 compromised endpoints that had contacted infrastructure

The proactive infrastructure tracking allowed the organization to block future attack waves and remediate compromises before data exfiltration occurred. The analysis was attributed to APT28 with high confidence and shared with ISACs, preventing attacks against 12 other organizations.

## Additional Resources

### Documentation
- [RiskIQ PassiveTotal Documentation](https://api.passivetotal.org/api/docs/)
- [Farsight DNSDB API Reference](https://docs.dnsdb.info/)
- [MITRE ATT&CK: Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [NIST Guide to Passive DNS](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-188.pdf)

### Training Materials
- SANS FOR578: Cyber Threat Intelligence (Module on Infrastructure Analysis)
- RiskIQ Analyst Certification
- "Tracking Threat Actors with pDNS" webinar series

### Community Resources
- APT Groups and Operations Google Sheets (public tracking)
- Twitter: #pDNS, #threatintel, #APTtracking
- FIRST Passive DNS SIG
- PassiveTotal Community Projects

## Related Use Cases
- [UC004: Hunt for C2 Beaconing Patterns](UC004-hunt-c2-beaconing-patterns.md) - Detecting command and control communications
- [UC005: Identify Phishing Domain Patterns](UC005-identify-phishing-domain-patterns.md) - Domain-based threat hunting
- [Strategic Intelligence UC003: Threat Actor Capability Evolution](../strategic-intelligence-reporting/UC003-threat-actor-capability-evolution.md) - Long-term APT tracking

## Version History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-30 | CTI Team | Initial creation |

---

## Appendix

### Glossary
- **Passive DNS (pDNS)**: Historical record of DNS query responses collected from DNS servers
- **Fast Flux**: Technique where malicious domains rapidly change IP addresses to evade blocking
- **Domain Generation Algorithm (DGA)**: Algorithm used to generate large numbers of domain names for C2
- **Certificate Transparency**: Public log of all SSL/TLS certificates issued
- **ASN (Autonomous System Number)**: Unique identifier for a network routing domain
- **SAN (Subject Alternative Name)**: SSL certificate field listing additional domains covered by the certificate

### Sample Queries/Scripts
```python
#!/usr/bin/env python3
"""
APT Infrastructure Tracker using Passive DNS
"""

import requests
import json
from datetime import datetime, timedelta

class PassiveDNSTracker:
    def __init__(self, api_key, api_email):
        self.api_key = api_key
        self.api_email = api_email
        self.base_url = "https://api.passivetotal.org/v2"

    def get_passive_dns(self, query):
        """Query passive DNS for a domain or IP"""
        url = f"{self.base_url}/dns/passive"
        params = {"query": query}
        response = requests.get(
            url,
            params=params,
            auth=(self.api_email, self.api_key)
        )
        return response.json() if response.status_code == 200 else None

    def get_reverse_dns(self, ip):
        """Get all domains that resolved to an IP"""
        return self.get_passive_dns(ip)

    def expand_infrastructure(self, seed_domain, depth=2):
        """Recursively expand infrastructure from seed domain"""
        discovered = {"domains": set(), "ips": set()}

        # Get IPs for seed domain
        pdns_data = self.get_passive_dns(seed_domain)
        if not pdns_data:
            return discovered

        for record in pdns_data.get("results", []):
            ip = record.get("resolve")
            if ip:
                discovered["ips"].add(ip)

                # Reverse lookup on IP
                reverse_data = self.get_reverse_dns(ip)
                if reverse_data:
                    for rev_record in reverse_data.get("results", []):
                        domain = rev_record.get("resolve")
                        if domain and domain != seed_domain:
                            discovered["domains"].add(domain)

        return discovered

    def cluster_by_timing(self, domains, time_window_days=30):
        """Cluster domains that appeared in similar timeframes"""
        clusters = []
        window = timedelta(days=time_window_days)

        for domain in domains:
            pdns_data = self.get_passive_dns(domain)
            if pdns_data:
                first_seen = pdns_data.get("firstSeen")
                # Clustering logic here...

        return clusters

# Usage example
tracker = PassiveDNSTracker("api_key", "api_email")
results = tracker.expand_infrastructure("diplomacy-gov.org")
print(f"Discovered {len(results['domains'])} domains and {len(results['ips'])} IPs")
```

### Workflow Diagram
```
┌──────────────────────────────────────────────────────────────────┐
│            APT Infrastructure Tracking via Passive DNS           │
└──────────────────────────────────────────────────────────────────┘

    [Seed IOCs]
    (Known APT Domains/IPs)
         │
         ▼
    ┌─────────────────────┐
    │ 1. Collect Seeds    │ ──────► Threat Reports, Feeds
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 2. pDNS Lookup      │ ──────► Historical DNS Data
    │   (Forward)         │
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 3. IP Pivoting      │ ──────► Reverse pDNS
    │   (Reverse)         │          (Find all domains on IPs)
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 4. Temporal         │ ──────► Timeline & Clusters
    │    Clustering       │
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 5. WHOIS Analysis   │ ──────► Registration Patterns
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 6. SSL Correlation  │ ──────► Certificate Transparency
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 7. Host Fingerprint │ ──────► Shodan/Censys
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 8. Pattern Analysis │ ──────► Predictive Indicators
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 9. Internal Hunting │ ──────► DNS/Proxy Logs
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 10. Continuous      │ ──────► Monitoring & Alerts
    │     Monitoring      │
    └─────────────────────┘
         │
         ▼
    [Infrastructure Map + IOCs + Detections]
```
