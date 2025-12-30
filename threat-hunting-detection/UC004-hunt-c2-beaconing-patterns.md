# Hunt for Command & Control (C2) Beaconing Patterns

## Metadata
- **Use Case ID:** THD-UC004
- **Category:** Threat Hunting & Detection
- **Difficulty:** Advanced
- **Estimated Time:** 4-5 hours
- **Last Updated:** 2025-12-30

## Description
Command and Control (C2) infrastructure is the backbone of modern cyber attacks, enabling threat actors to maintain persistent access, issue commands, and exfiltrate data from compromised systems. While attackers employ various evasion techniques, C2 communication often exhibits identifiable patterns—periodic beaconing intervals, consistent packet sizes, predictable jitter patterns, and distinctive protocol behaviors.

Detecting C2 beaconing requires analyzing network traffic metadata to identify statistical anomalies and patterns that deviate from normal user-initiated communications. Unlike human-driven traffic which is inherently irregular, automated C2 beacons tend to exhibit periodicity, consistency, and other mathematical signatures that can be detected through behavioral analysis.

This use case demonstrates advanced network traffic analysis techniques to identify C2 beaconing patterns, covering beacon interval analysis, statistical anomaly detection, JA3/JA4 fingerprinting, and DNS-based C2 detection. The workflow applies both signature-based and behavior-based approaches to uncover hidden C2 channels across multiple protocols.

## Objectives
By completing this use case, you will:
- Identify periodic beaconing patterns in network traffic metadata
- Detect statistical anomalies indicative of automated C2 communication
- Analyze DNS tunneling and domain generation algorithm (DGA) patterns
- Fingerprint C2 frameworks using TLS/SSL characteristics (JA3/JA4)
- Correlate network indicators with threat intelligence on known C2 infrastructure
- Build automated detection pipelines for continuous C2 hunting

## Prerequisites

### Data Sources
- **NetFlow/IPFIX Data** - Network flow records with timestamps, bytes, packets
- **DNS Logs** - All DNS queries and responses with timestamps
- **Proxy/Firewall Logs** - HTTP/HTTPS traffic with full URLs and headers
- **TLS/SSL Metadata** - JA3/JA4 fingerprints, certificate data
- **Packet Captures (PCAP)** - Deep packet inspection for suspected C2

### Tools & Platforms
- **SIEM Platform** - Splunk, Elastic, or Microsoft Sentinel for data aggregation
- **Network Analysis Tools** - Zeek (Bro), Suricata, Wireshark
- **C2 Detection Tools** - RITA (Real Intelligence Threat Analytics), AC-Hunter
- **Statistical Analysis** - Python with pandas, numpy, scipy for beacon analysis
- **Threat Intelligence Platforms** - VirusTotal, RiskIQ for infrastructure validation

### Required Skills
- Network traffic analysis and protocol understanding
- Statistical analysis and pattern recognition
- Familiarity with C2 frameworks (Cobalt Strike, Metasploit, Sliver)
- Python or similar scripting for data analysis
- Understanding of beaconing concepts and jitter calculations

### Access Requirements
- Access to network monitoring infrastructure (NetFlow, DNS, proxy logs)
- SIEM query permissions for large-scale data analysis
- Packet capture capabilities for deep inspection
- Threat intelligence platform API access

## Step-by-Step Workflow

### Step 1: Data Collection and Preparation
**Objective:** Aggregate relevant network data sources for analysis

**Actions:**
1. Collect NetFlow data for the analysis period (recommend 7-14 days)
2. Aggregate DNS query logs from all internal resolvers
3. Extract proxy logs with timestamps, destinations, and byte counts
4. Ensure timestamps are normalized to consistent timezone
5. Filter out known-good traffic (CDNs, updates, whitelisted domains)

**Example:**
```sql
-- Splunk query to aggregate netflow data
index=netflow earliest=-7d
| search NOT dest_ip IN (
    "cloudflare_ips", "office365_ips", "windows_update_ips"
)
| stats count, sum(bytes_out), values(dest_port)
  by src_ip, dest_ip, _time
| bin span=1h _time
```

**Output:** Clean dataset of network flows ready for beacon analysis

---

### Step 2: Beacon Interval Analysis
**Objective:** Identify connections with consistent, periodic timing patterns

**Actions:**
1. Calculate time deltas between consecutive connections to same destination
2. Identify connections with low standard deviation in interval timing (<20% jitter)
3. Filter for long-duration patterns (10+ connections over multiple hours)
4. Calculate beacon score based on regularity and consistency

**Example:**
```python
import pandas as pd
import numpy as np

def detect_beacons(df, jitter_threshold=0.2):
    """Detect beaconing based on connection intervals"""
    results = []

    # Group by source and destination
    for (src, dst), group in df.groupby(['src_ip', 'dest_ip']):
        if len(group) < 10:
            continue

        # Calculate intervals between connections
        group = group.sort_values('timestamp')
        intervals = group['timestamp'].diff().dt.total_seconds()

        # Statistical analysis
        mean_interval = intervals.mean()
        std_interval = intervals.std()
        coefficient_variation = std_interval / mean_interval if mean_interval > 0 else 0

        # Beacon detected if low variation
        if coefficient_variation < jitter_threshold:
            results.append({
                'src_ip': src,
                'dest_ip': dst,
                'mean_interval': mean_interval,
                'jitter': coefficient_variation,
                'connection_count': len(group),
                'beacon_score': 1 - coefficient_variation
            })

    return pd.DataFrame(results)
```

**Output:** List of connections with periodic beaconing characteristics

---

### Step 3: Statistical Anomaly Detection
**Objective:** Apply statistical methods to identify C2 communication anomalies

**Actions:**
1. Calculate packet size entropy and consistency
2. Analyze request/response size ratios (small requests, large responses = data exfil)
3. Identify connections with unusual duration patterns
4. Use Z-score analysis to find statistical outliers in traffic patterns

**Example:**
```python
def calculate_traffic_entropy(df):
    """Calculate entropy of packet sizes"""
    from scipy.stats import entropy

    results = []
    for (src, dst), group in df.groupby(['src_ip', 'dest_ip']):
        sizes = group['bytes'].values
        size_entropy = entropy(np.histogram(sizes, bins=20)[0])

        # Low entropy = consistent sizes = potential C2
        results.append({
            'src_ip': src,
            'dest_ip': dst,
            'size_entropy': size_entropy,
            'mean_size': sizes.mean(),
            'std_size': sizes.std()
        })

    return pd.DataFrame(results)
```

**Output:** Statistical anomaly scores for each connection

---

### Step 4: DNS-Based C2 Detection
**Objective:** Identify DNS tunneling and DGA (Domain Generation Algorithm) C2

**Actions:**
1. Calculate DNS query entropy (high entropy = DGA or tunneling)
2. Identify unusual query volumes to single domains
3. Detect long subdomain queries (potential DNS tunneling)
4. Analyze DNS response patterns (TXT records with encoded data)
5. Look for NXDomain patterns indicating DGA activity

**Example:**
```python
def detect_dns_anomalies(dns_logs):
    """Detect suspicious DNS patterns"""
    suspicious = []

    for domain, queries in dns_logs.groupby('query_name'):
        # Calculate domain entropy
        domain_entropy = calculate_domain_entropy(domain)

        # Check for DGA characteristics
        if domain_entropy > 4.0:  # High entropy
            suspicious.append({
                'domain': domain,
                'entropy': domain_entropy,
                'query_count': len(queries),
                'type': 'Potential DGA'
            })

        # Check for DNS tunneling
        if len(domain) > 50 and '.' in domain[:40]:
            suspicious.append({
                'domain': domain,
                'length': len(domain),
                'query_count': len(queries),
                'type': 'Potential DNS Tunneling'
            })

    return suspicious

def calculate_domain_entropy(domain):
    """Calculate Shannon entropy of domain string"""
    from collections import Counter
    from math import log2

    if not domain:
        return 0

    counts = Counter(domain)
    length = len(domain)
    entropy = -sum(count/length * log2(count/length)
                   for count in counts.values())
    return entropy
```

**Output:** List of suspicious DNS queries flagged for investigation

---

### Step 5: JA3/JA4 TLS Fingerprinting
**Objective:** Fingerprint C2 frameworks by their TLS handshake characteristics

**Actions:**
1. Extract JA3/JA4 hashes from TLS handshakes
2. Query threat intelligence feeds for known malicious JA3 signatures
3. Cluster unique JA3 hashes to identify rare or unusual TLS configurations
4. Correlate JA3 with destination IPs and domain reputation

**Example:**
```bash
# Using Zeek to extract JA3 fingerprints
zeek -C -r capture.pcap /path/to/ja3.zeek

# Analyze JA3 hashes
cat ssl.log | zeek-cut ja3 server_name | sort | uniq -c | sort -rn

# Query JA3 against threat intelligence
curl "https://sslbl.abuse.ch/intel/ja3_fingerprints.csv" | grep "YOUR_JA3_HASH"
```

**Output:** Identified malicious or suspicious TLS fingerprints

---

### Step 6: C2 Framework Behavior Profiling
**Objective:** Match observed patterns to known C2 framework signatures

**Actions:**
1. Compare detected beacon intervals to known C2 defaults (Cobalt Strike: 60s, Metasploit: varies)
2. Analyze HTTP/HTTPS URI patterns for C2 signatures (e.g., Cobalt Strike URLs)
3. Check User-Agent strings against C2 framework defaults
4. Look for protocol-specific artifacts (SMB beacons, DNS beacons)

**Example:**
```yaml
# C2 Framework Signatures
cobalt_strike:
  default_beacon: 60
  jitter: 0-50%
  user_agents:
    - "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"
  uri_patterns:
    - "/jquery-*.min.js"
    - "/updates.rss"

metasploit:
  protocols: [http, https, dns, smb]
  default_beacon: varies
  check-in: irregular

sliver:
  protocols: [http, https, dns, mtls]
  default_beacon: 10-60
  dns_pattern: "subdomain.domain.tld"
```

**Output:** Attributed C2 activity to specific frameworks

---

### Step 7: Geolocation and ASN Analysis
**Objective:** Identify suspicious destination geography and hosting

**Actions:**
1. Geolocate all destination IPs from suspected beaconing
2. Identify connections to high-risk countries or VPN/VPS providers
3. Analyze ASN ownership patterns (bulletproof hosting, VPS providers)
4. Flag connections to countries inconsistent with business operations

**Example:**
```python
import geoip2.database

def analyze_geo_risk(ip_address):
    """Analyze geographic risk of destination IP"""
    reader = geoip2.database.Reader('/path/to/GeoLite2-City.mmdb')
    response = reader.city(ip_address)

    risk_factors = []

    # High-risk countries
    if response.country.iso_code in ['KP', 'IR', 'SY']:
        risk_factors.append('High-risk country')

    # VPN/VPS hosting
    if response.traits.is_hosting_provider:
        risk_factors.append('VPS/Hosting provider')

    # Geographic anomaly
    if response.country.iso_code not in expected_countries:
        risk_factors.append('Unexpected geography')

    return risk_factors
```

**Output:** Geographic risk assessment for each destination

---

### Step 8: Long Connection Analysis
**Objective:** Identify persistent, long-duration connections indicative of C2

**Actions:**
1. Query for connections lasting >1 hour
2. Analyze data transfer patterns (bidirectional, low volume = C2)
3. Identify connections maintained outside business hours
4. Look for connections that survived network changes (IP changes, reboots)

**Example:**
```sql
-- Splunk query for long-lived connections
index=netflow
| stats earliest(_time) as start, latest(_time) as end,
  sum(bytes_in) as total_in, sum(bytes_out) as total_out
  by src_ip, dest_ip, dest_port
| eval duration = end - start
| where duration > 3600
| eval avg_bytes_per_min = (total_in + total_out) / (duration / 60)
| where avg_bytes_per_min < 1000
| sort -duration
```

**Output:** Long-duration, low-volume connections for investigation

---

### Step 9: Threat Intelligence Correlation
**Objective:** Validate suspected C2 against external threat intelligence

**Actions:**
1. Query destination IPs/domains against threat feeds
2. Check for known C2 infrastructure in VirusTotal, AlienVault OTX
3. Validate JA3 hashes against Abuse.ch SSL Blacklist
4. Cross-reference with recent threat reports and IOC feeds

**Example:**
```python
import requests

def validate_c2_ioc(ip_address, vt_api_key):
    """Validate suspected C2 IP against VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": vt_api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']

        if malicious_count > 3:
            return {
                'verdict': 'Malicious',
                'detections': malicious_count,
                'categories': data['data']['attributes'].get('categories', {})
            }

    return {'verdict': 'Unknown'}
```

**Output:** Threat intelligence validation results for each suspected C2

---

### Step 10: Automated Detection and Alerting
**Objective:** Create production detection rules and continuous monitoring

**Actions:**
1. Develop SIEM correlation rules combining multiple beacon indicators
2. Create network sensor signatures for identified C2 patterns
3. Configure automated alerting thresholds based on beacon scores
4. Build dashboards for ongoing C2 hunting visualization
5. Integrate with SOAR for automated investigation workflows

**Example:**
```yaml
# SIEM Detection Rule
name: "C2 Beaconing Detection"
description: "Detects periodic network beaconing indicative of C2"
severity: high

trigger:
  - beacon_interval_cv < 0.2
  - connection_count > 10
  - duration > 3600

enrichment:
  - geoip_lookup
  - threat_intel_check
  - ja3_fingerprint

actions:
  - create_alert
  - isolate_endpoint (if malicious_score > 80)
  - notify_soc_team

threshold: 1 occurrence per 24 hours
```

**Output:** Production-ready C2 detection pipeline

---

## Recommended CTI Products

### Primary Products
- **Darktrace** - AI-powered C2 detection with behavioral analytics
  - Assessment: [Darktrace](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#darktrace)
  - Key Features: Anomaly detection, beacon scoring, autonomous response

- **Vectra AI** - Network detection and response focused on C2 behavior
  - Assessment: [Vectra AI](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#vectra-ai)
  - Key Features: Beacon detection, hidden tunnel discovery, threat scoring

### Alternative/Complementary Products
- **ExtraHop Reveal(x)** - Network detection with real-time beaconing analysis
  - Assessment: [ExtraHop](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#extrahop)

- **Corelight** - Network visibility based on Zeek with C2 analytics
  - Assessment: [Corelight](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#corelight)

- **Cisco Stealthwatch** - NetFlow-based anomaly detection
  - Assessment: [Cisco Stealthwatch](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#cisco-stealthwatch)

### Open Source Options
- **RITA (Real Intelligence Threat Analytics)** - Open-source beacon detection framework
- **Zeek (Bro)** - Network monitoring with protocol analysis
- **Suricata** - IDS/IPS with C2 detection capabilities
- **Malcolm** - Network traffic analysis platform

## Expected Outputs

### Deliverables
1. **C2 Detection Report**
   - Format: PDF with executive summary and technical details
   - Content: Identified C2 channels, attribution, impact assessment
   - Audience: SOC management, incident response, CISO

2. **IOC Package**
   - Format: STIX 2.1, CSV, JSON
   - Content: C2 IPs, domains, JA3 hashes, beacon intervals
   - Audience: SOC analysts, firewall team, threat hunters

3. **Detection Rules**
   - Format: SIEM rules, IDS signatures, Python scripts
   - Content: Automated C2 detection logic
   - Audience: Detection engineers, SOC operations

4. **Network Traffic Analysis Dashboard**
   - Format: SIEM dashboard (Splunk, Kibana)
   - Content: Real-time beacon monitoring, statistical visualizations
   - Audience: SOC analysts, threat hunters

### Sample Output
```json
{
  "c2_hunting_results": {
    "analysis_period": "2025-12-23 to 2025-12-30",
    "total_flows_analyzed": 15000000,
    "suspected_c2_channels": 4,
    "detections": [
      {
        "src_ip": "10.50.30.142",
        "dest_ip": "185.220.101.45",
        "dest_domain": "unknown-cdn.xyz",
        "beacon_interval_mean": 59.8,
        "beacon_jitter": 0.05,
        "connection_count": 247,
        "duration_hours": 168,
        "c2_framework": "Cobalt Strike (suspected)",
        "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
        "threat_intel_verdict": "Malicious - Known C2",
        "confidence": "high",
        "actions_taken": [
          "Endpoint isolated",
          "Network blocked at firewall",
          "Incident INC-67890 created"
        ]
      }
    ]
  }
}
```

## Success Metrics
- C2 detection rate: >90% of known C2 frameworks
- False positive rate: <2% of beacon alerts
- Time to detection: <4 hours from C2 establishment
- Detection coverage: HTTP/S, DNS, SMB, custom protocols
- Automation rate: >80% of detection pipeline automated

## Tips & Best Practices

### General Tips
- Focus on metadata analysis (timing, sizes) before deep packet inspection for scalability
- Combine multiple weak signals (beacon timing + rare JA3 + suspicious geo) for high-confidence detections
- Baseline normal network behavior to reduce false positives from legitimate periodic connections
- Use statistical methods—C2 beacons are mathematical outliers
- Correlate network detections with endpoint telemetry for full attack context

### Common Pitfalls to Avoid
- **Legitimate beaconing services**: Software updates, cloud sync, monitoring agents beacon regularly—whitelist known-good services
- **Over-tuning for specific frameworks**: Attackers customize beacon timing; use flexible thresholds
- **Ignoring encrypted C2**: Focus on metadata (timing, sizes, JA3) for HTTPS C2 detection
- **Missing slow beacons**: Some C2 beacons hourly or daily; extend analysis windows appropriately

### Optimization Strategies
- Pre-filter known-good traffic (CDNs, update servers) to reduce analysis load
- Use sampling for large enterprises—analyze 10% of traffic statistically
- Implement tiered analysis: fast statistical checks first, deep inspection only for high-risk
- Cache threat intelligence lookups to avoid API rate limits
- Use machine learning models trained on your environment's baseline

### Automation Opportunities
- Automated NetFlow analysis pipelines running hourly
- Real-time beacon scoring integrated with SIEM
- Automatic JA3 fingerprint extraction and threat intel enrichment
- SOAR playbooks for C2 investigation and containment
- Continuous baseline updates using adaptive learning

## Real-World Application

### Industry Examples
- **Financial Services:** Bank detects APT using DNS tunneling for C2 over allowed port 53
- **Healthcare:** Hospital identifies Cobalt Strike beacon before ransomware deployment
- **Manufacturing:** Industrial facility discovers decade-old C2 channel using long connection analysis
- **Technology:** SaaS provider finds supply chain attack C2 using JA3 fingerprinting

### Case Study
A global financial institution's SOC noticed unusual NetFlow patterns during routine threat hunting. Statistical analysis revealed periodic communication patterns from a server in their development environment to an external IP in Eastern Europe.

Analysis findings:
1. Beacon interval: 58-62 seconds (mean: 60s, CV: 0.03)
2. Connection duration: 14 days continuous
3. Data transfer: 2-3 KB per beacon (consistent sizes)
4. JA3 hash: Matched known Cobalt Strike signature
5. Destination IP: Bulletproof hosting provider, known for malicious activity
6. No legitimate business justification for connection

Investigation revealed a compromised developer workstation that had established Cobalt Strike C2 two weeks prior. The low-and-slow beacon pattern had evaded signature-based detection. Using the beacon analysis techniques from this use case, the SOC:
- Detected the C2 channel through statistical anomaly analysis
- Isolated the compromised system within 30 minutes
- Blocked the C2 infrastructure at the perimeter
- Discovered lateral movement attempts to production systems (prevented)
- Identified the initial access vector (phishing email)

The detection prevented potential access to production banking systems and customer data. The beacon detection pipeline was subsequently automated, detecting 3 additional C2 channels in the following quarter.

## Additional Resources

### Documentation
- [MITRE ATT&CK Tactic: Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [RITA Documentation](https://github.com/activecm/rita)
- [JA3 Fingerprinting](https://github.com/salesforce/ja3)
- [Zeek Network Security Monitor](https://docs.zeek.org/)

### Training Materials
- SANS FOR572: Advanced Network Forensics
- "Hunting C2 with Beacon Analysis" - SANS Summit presentations
- Black Hat: "Network Beaconing Detection Techniques"

### Community Resources
- Twitter: #C2Detection, #ThreatHunting, #NetSec
- Reddit: r/netsec, r/blueteam
- Active Countermeasures community (RITA developers)
- Zeek community Slack

## Related Use Cases
- [UC002: Track APT Infrastructure Using Passive DNS](UC002-track-apt-infrastructure-passive-dns.md) - Infrastructure analysis
- [UC005: Identify Phishing Domain Patterns](UC005-identify-phishing-domain-patterns.md) - Domain-based detection
- [UC008: Track Malware Distribution Infrastructure](UC008-track-malware-distribution-infrastructure.md) - Delivery mechanism analysis

## Version History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-30 | CTI Team | Initial creation |

---

## Appendix

### Glossary
- **Beacon**: Periodic callback from compromised system to C2 server
- **Jitter**: Randomization applied to beacon intervals to evade detection
- **Coefficient of Variation (CV)**: Statistical measure of timing consistency (std dev / mean)
- **JA3/JA4**: TLS/SSL fingerprinting methods based on handshake parameters
- **DGA (Domain Generation Algorithm)**: Algorithm generating pseudo-random domains for C2
- **DNS Tunneling**: Encoding C2 data within DNS queries/responses

### Sample Queries/Scripts
```python
#!/usr/bin/env python3
"""
C2 Beacon Detection Script
"""

import pandas as pd
import numpy as np
from scipy import stats

class BeaconDetector:
    def __init__(self, jitter_threshold=0.2, min_connections=10):
        self.jitter_threshold = jitter_threshold
        self.min_connections = min_connections

    def analyze_netflow(self, netflow_df):
        """Main beacon detection function"""
        beacons = []

        # Group by source/destination pairs
        for (src, dst), group in netflow_df.groupby(['src_ip', 'dest_ip']):
            if len(group) < self.min_connections:
                continue

            # Calculate beacon score
            score = self._calculate_beacon_score(group)

            if score['is_beacon']:
                beacons.append({
                    'src_ip': src,
                    'dest_ip': dst,
                    **score
                })

        return pd.DataFrame(beacons)

    def _calculate_beacon_score(self, connections):
        """Calculate statistical beacon score"""
        # Sort by timestamp
        connections = connections.sort_values('timestamp')

        # Calculate intervals
        intervals = connections['timestamp'].diff().dt.total_seconds().dropna()

        if len(intervals) < 3:
            return {'is_beacon': False}

        # Statistical metrics
        mean_interval = intervals.mean()
        std_interval = intervals.std()
        cv = std_interval / mean_interval if mean_interval > 0 else 1

        # Size consistency
        sizes = connections['bytes'].values
        size_cv = sizes.std() / sizes.mean() if sizes.mean() > 0 else 1

        # Beacon determination
        is_beacon = (
            cv < self.jitter_threshold and
            len(connections) >= self.min_connections
        )

        return {
            'is_beacon': is_beacon,
            'mean_interval': mean_interval,
            'interval_cv': cv,
            'size_cv': size_cv,
            'connection_count': len(connections),
            'confidence': 1 - cv
        }

# Usage
detector = BeaconDetector(jitter_threshold=0.25, min_connections=10)
beacons = detector.analyze_netflow(netflow_data)
print(f"Detected {len(beacons)} potential C2 beacons")
```

### Workflow Diagram
```
┌─────────────────────────────────────────────────────────────┐
│              C2 Beaconing Detection Workflow                │
└─────────────────────────────────────────────────────────────┘

    [Network Traffic Data]
    (NetFlow, DNS, Proxy)
         │
         ▼
    ┌─────────────────────┐
    │ 1. Data Collection  │ ──────► Aggregate & Normalize
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 2. Beacon Interval  │ ──────► Calculate timing patterns
    │    Analysis         │          Low CV = beaconing
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 3. Statistical      │ ──────► Entropy, size analysis
    │    Anomaly          │          Z-scores, outliers
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 4. DNS C2 Detection │ ──────► DGA, tunneling patterns
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 5. TLS Fingerprint  │ ──────► JA3/JA4 analysis
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 6. C2 Framework     │ ──────► Match to known signatures
    │    Profiling        │
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 7. Geo/ASN Analysis │ ──────► Risk scoring
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 8. Long Connection  │ ──────► Persistent channels
    │    Analysis         │
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 9. TI Correlation   │ ──────► Validate against feeds
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 10. Automated       │ ──────► Production detections
    │     Detection       │
    └─────────────────────┘
         │
         ▼
    [C2 Detections + IOCs + Incident Response]
```
