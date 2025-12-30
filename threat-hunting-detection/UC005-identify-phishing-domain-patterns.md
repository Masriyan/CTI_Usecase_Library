# Identify Phishing Domain Patterns

## Metadata
- **Use Case ID:** THD-UC005
- **Category:** Threat Hunting & Detection
- **Difficulty:** Intermediate
- **Estimated Time:** 2-3 hours
- **Last Updated:** 2025-12-30

## Description
Phishing remains one of the most effective initial access vectors for cyber attackers, with threat actors continuously evolving their domain registration and hosting tactics to evade detection. Identifying phishing domains before they reach end users requires a combination of domain analysis, brand monitoring, certificate transparency tracking, and behavioral pattern recognition.

This use case demonstrates how to proactively hunt for phishing domains targeting your organization by analyzing newly registered domains, detecting typosquatting and homograph attacks, monitoring certificate issuance, and identifying hosting patterns consistent with phishing campaigns. The workflow combines automated scanning with threat intelligence to build comprehensive blocking lists before phishing emails reach inboxes.

## Objectives
By completing this use case, you will:
- Monitor newly registered domains for brand impersonation and typosquatting
- Detect homograph attacks using international domain names (IDNs)
- Leverage certificate transparency logs to identify suspicious SSL certificates
- Analyze domain registration patterns and hosting infrastructure
- Build proactive blocking lists for phishing domains
- Create early warning systems for emerging phishing campaigns

## Prerequisites

### Data Sources
- **Domain Registration Feeds** - Newly registered domain lists (WhoisXML API, DomainTools)
- **Certificate Transparency Logs** - SSL certificate issuance data (crt.sh, Censys)
- **DNS Data** - Passive DNS and active DNS resolution
- **URL/Domain Reputation Feeds** - PhishTank, OpenPhish, URLhaus
- **Email Gateway Logs** - Blocked/allowed URLs from email security

### Tools & Platforms
- **DomainTools** - Domain monitoring and WHOIS intelligence
- **URLScan.io** - Automated website scanning and analysis
- **PhishTank/OpenPhish** - Community phishing URL databases
- **Certificate Transparency Tools** - crt.sh, Censys
- **Python Libraries** - dnstwist for domain permutation generation

### Required Skills
- Understanding of DNS and domain registration processes
- Familiarity with phishing tactics and techniques
- Regular expression and pattern matching
- Basic web scraping and API integration
- Brand protection concepts

### Access Requirements
- Access to domain registration monitoring services
- Certificate transparency log access
- Email gateway query permissions
- Ability to configure DNS blocklists or proxy rules

## Step-by-Step Workflow

### Step 1: Define Brand Assets and Keywords
**Objective:** Catalog organizational brands, domains, and keywords to monitor

**Actions:**
1. List all official company domains, brands, and product names
2. Include common misspellings and variations
3. Define executive names and titles for executive impersonation monitoring
4. Create keyword list including industry-specific terms
5. Document international brand variations and translations

**Example:**
```yaml
brand_monitoring:
  primary_domains:
    - "company.com"
    - "companybrand.com"
    - "company-product.com"

  brand_keywords:
    - "company"
    - "companybrand"
    - "companyproduct"

  executives:
    - "John Smith CEO"
    - "Jane Doe CFO"

  products:
    - "SuperProduct"
    - "MegaService"

  common_misspellings:
    - "compnay"
    - "compamy"
```

**Output:** Comprehensive brand asset catalog for monitoring

---

### Step 2: Generate Domain Permutations
**Objective:** Create exhaustive list of potential phishing domain variations

**Actions:**
1. Use dnstwist or similar tools to generate typosquatting permutations
2. Include homograph variants using similar-looking characters
3. Generate subdomain variations (login.company.com vs company-login.com)
4. Create TLD variations (.com, .net, .org, .co, .io, etc.)
5. Add combosquatting patterns (company-secure.com, company-login.net)

**Example:**
```bash
# Using dnstwist to generate permutations
dnstwist --registered --format json company.com > permutations.json

# Generate homograph variants
dnstwist --format list --tld com,net,org --homograph company.com

# Common patterns
# Original: company.com
# Typosquatting: compnay.com, conpany.com
# Combosquatting: company-login.com, secure-company.com
# Homograph: comраny.com (Cyrillic 'а')
# TLD variation: company.net, company.co
```

**Output:** List of 200-500 potential phishing domain permutations

---

### Step 3: Monitor Newly Registered Domains
**Objective:** Track domain registrations matching brand patterns

**Actions:**
1. Query daily domain registration feeds (WhoisXML API, DomainTools)
2. Filter for domains containing brand keywords or similar strings
3. Calculate string similarity scores (Levenshtein distance)
4. Flag domains registered with privacy protection services
5. Track bulk registrations from same registrant

**Example:**
```python
import Levenshtein

def check_newly_registered(brand, new_domains):
    """Check new domains for brand similarity"""
    suspicious = []

    for domain in new_domains:
        # Calculate similarity
        similarity = Levenshtein.ratio(brand, domain.split('.')[0])

        if similarity > 0.75:  # 75% similar
            suspicious.append({
                'domain': domain,
                'similarity_score': similarity,
                'registration_date': domain.created_date,
                'registrar': domain.registrar,
                'privacy_protected': domain.has_privacy
            })

    return suspicious
```

**Output:** Daily list of suspicious newly registered domains

---

### Step 4: Certificate Transparency Monitoring
**Objective:** Detect SSL certificates issued for suspicious domains

**Actions:**
1. Monitor certificate transparency logs for brand-related certificates
2. Identify certificates with brand names in CN or SAN fields
3. Flag certificates from free providers (Let's Encrypt) on suspicious domains
4. Track certificate issuance velocity (multiple certs in short time)
5. Analyze certificate organizational details for impersonation

**Example:**
```bash
# Query crt.sh for certificates
curl -s "https://crt.sh/?q=%25company%25&output=json" | jq '.'

# Look for suspicious patterns
# - Free certificates on typosquat domains
# - Multiple SANs with variations of brand name
# - Recent issuance (last 7 days)
```

**Output:** List of suspicious SSL certificates for investigation

---

### Step 5: Active Domain Scanning
**Objective:** Analyze suspicious domains to confirm phishing intent

**Actions:**
1. Submit flagged domains to URLScan.io for automated scanning
2. Check for website content impersonating organization
3. Analyze HTML source for brand logo theft or content cloning
4. Identify web forms collecting credentials or PII
5. Screenshot suspicious sites for evidence collection

**Example:**
```python
import requests

def scan_suspicious_domain(domain):
    """Scan domain using URLScan.io API"""
    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": "YOUR_API_KEY"}
    data = {"url": f"http://{domain}"}

    response = requests.post(api_url, headers=headers, json=data)

    if response.status_code == 200:
        scan_id = response.json()['uuid']
        # Wait for scan to complete, then retrieve results
        results_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
        # ... fetch results
        return results_url

    return None
```

**Output:** Scan results with screenshots and content analysis

---

### Step 6: DNS and Hosting Analysis
**Objective:** Analyze infrastructure patterns of phishing domains

**Actions:**
1. Resolve domains to identify hosting infrastructure
2. Look for shared hosting patterns (multiple phishing domains on same IP)
3. Identify bulletproof hosting providers or known malicious ASNs
4. Check for fast-flux DNS patterns
5. Correlate with known phishing infrastructure from threat feeds

**Example:**
```python
import socket
import whois

def analyze_domain_infrastructure(domain):
    """Analyze hosting and registration patterns"""
    try:
        # DNS resolution
        ip = socket.gethostbyname(domain)

        # WHOIS lookup
        w = whois.whois(domain)

        analysis = {
            'domain': domain,
            'ip': ip,
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'name_servers': w.name_servers,
            'age_days': (datetime.now() - w.creation_date).days
        }

        # Flag risk factors
        if analysis['age_days'] < 7:
            analysis['risk_factors'] = ['Newly registered']

        return analysis

    except Exception as e:
        return None
```

**Output:** Infrastructure analysis identifying high-risk hosting patterns

---

### Step 7: Email Gateway Correlation
**Objective:** Identify phishing domains already reaching organizational inboxes

**Actions:**
1. Query email gateway logs for flagged domains
2. Search for emails containing newly identified suspicious domains
3. Identify users who received or clicked phishing links
4. Correlate with user-reported phishing emails
5. Track email sender patterns (spoofed addresses, free email providers)

**Example:**
```sql
-- SIEM query for email gateway logs
index=email_security
| search url IN (
    "suspicious-domain1.com",
    "suspicious-domain2.net"
  )
| stats count by recipient, subject, sender, action
| where action="delivered" OR action="clicked"
```

**Output:** List of internal exposures requiring incident response

---

### Step 8: Threat Intelligence Enrichment
**Objective:** Validate findings against community phishing databases

**Actions:**
1. Query PhishTank and OpenPhish for known phishing URLs
2. Check URLhaus for malware distribution via flagged domains
3. Lookup domains in VirusTotal for community reputation data
4. Cross-reference with AlienVault OTX phishing pulses
5. Validate against commercial threat feeds

**Example:**
```python
def check_phishing_databases(domain):
    """Check domain against phishing databases"""
    results = {}

    # PhishTank API check
    phishtank_url = f"http://checkurl.phishtank.com/checkurl/"
    data = {"url": f"http://{domain}", "format": "json"}
    # ... API call

    # URLhaus check
    urlhaus_url = f"https://urlhaus-api.abuse.ch/v1/url/"
    # ... API call

    return results
```

**Output:** Threat intelligence validation confirming phishing activity

---

### Step 9: Risk Scoring and Prioritization
**Objective:** Rank suspicious domains by likelihood and impact

**Actions:**
1. Calculate risk scores based on multiple factors
2. Prioritize domains with confirmed phishing content or active campaigns
3. Consider organizational impact (C-level targeting, customer-facing brands)
4. Weight recent activity higher than dormant domains
5. Create tiered response based on risk scores

**Example:**
```python
def calculate_phishing_risk_score(domain_analysis):
    """Calculate risk score for suspected phishing domain"""
    score = 0

    # Domain age (newer = higher risk)
    if domain_analysis.get('age_days', 365) < 7:
        score += 30

    # Brand similarity
    if domain_analysis.get('similarity_score', 0) > 0.85:
        score += 25

    # Active phishing content
    if domain_analysis.get('has_login_form'):
        score += 20

    # SSL certificate (free cert = suspicious)
    if 'Let\'s Encrypt' in domain_analysis.get('ssl_issuer', ''):
        score += 10

    # Email delivery confirmed
    if domain_analysis.get('emails_delivered', 0) > 0:
        score += 15

    # Threat intel confirmation
    if domain_analysis.get('ti_confirmed'):
        score += 30

    return min(score, 100)  # Cap at 100
```

**Output:** Prioritized list of phishing domains by risk score

---

### Step 10: Automated Blocking and Notification
**Objective:** Deploy protections and alert stakeholders

**Actions:**
1. Submit high-risk domains to DNS blocklists or proxy blacklists
2. Configure email gateway rules to block identified domains
3. Notify security operations and brand protection teams
4. Report confirmed phishing sites to registrars and hosting providers
5. Share IOCs with industry ISACs and threat sharing platforms

**Example:**
```python
def deploy_protections(phishing_domain, risk_score):
    """Automated blocking and notification"""

    if risk_score > 70:
        # High risk - immediate blocking
        dns_blacklist.add_domain(phishing_domain)
        email_gateway.block_domain(phishing_domain)
        soc_team.create_alert(domain=phishing_domain, severity="high")

        # Report to authorities
        report_to_phishtank(phishing_domain)
        report_to_registrar(phishing_domain)

    elif risk_score > 40:
        # Medium risk - monitoring and warning
        email_gateway.warn_on_domain(phishing_domain)
        threat_intel_platform.add_watchlist(phishing_domain)

    # Always document
    log_phishing_domain(phishing_domain, risk_score)
```

**Output:** Automated protection deployment and stakeholder notifications

---

## Recommended CTI Products

### Primary Products
- **DomainTools** - Comprehensive domain monitoring and brand protection
  - Assessment: [DomainTools](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#domaintools)
  - Key Features: Domain monitoring, WHOIS intelligence, brand protection alerts

- **RiskIQ Digital Footprint** - External threat detection and brand monitoring
  - Assessment: [RiskIQ](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#riskiq-passivetotal)
  - Key Features: Brand monitoring, certificate tracking, takedown assistance

### Alternative/Complementary Products
- **ZeroFOX** - Digital risk protection platform
  - Assessment: [ZeroFOX](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#zerofox)

- **Bolster** - Automated phishing detection and takedown
  - Assessment: [Bolster](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#bolster)

- **Recorded Future** - Threat intelligence with brand monitoring
  - Assessment: [Recorded Future](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#recorded-future)

### Open Source Options
- **dnstwist** - Domain permutation engine for typosquatting detection
- **URLScan.io** - Free automated website scanning
- **PhishTank** - Community phishing URL database
- **crt.sh** - Free certificate transparency search

## Expected Outputs

### Deliverables
1. **Phishing Domain Blocklist**
   - Format: CSV, STIX, DNS blocklist format
   - Content: Confirmed phishing domains with risk scores
   - Audience: Network security, email security, DNS admins

2. **Brand Monitoring Report**
   - Format: PDF with weekly/monthly summaries
   - Content: Newly detected phishing domains, trends, takedown status
   - Audience: Brand protection, legal, security leadership

3. **Incident Notifications**
   - Format: Email alerts, SIEM tickets
   - Content: High-risk phishing domains requiring immediate action
   - Audience: SOC, incident response, help desk

4. **Threat Intelligence Package**
   - Format: STIX 2.1, JSON
   - Content: Phishing IOCs, campaign analysis, infrastructure mapping
   - Audience: Threat hunters, CTI analysts

### Sample Output
```json
{
  "phishing_domain_analysis": {
    "scan_date": "2025-12-30",
    "domains_analyzed": 1247,
    "suspicious_domains": 23,
    "confirmed_phishing": 8,
    "detections": [
      {
        "domain": "company-login.net",
        "risk_score": 92,
        "similarity_to_brand": 0.88,
        "registration_date": "2025-12-28",
        "hosting_ip": "185.220.101.45",
        "ssl_certificate": "Let's Encrypt",
        "phishing_content": true,
        "login_form_detected": true,
        "brand_logo_theft": true,
        "threat_intel_confirmed": true,
        "actions_taken": [
          "Blocked at email gateway",
          "Added to DNS blocklist",
          "Reported to registrar",
          "Takedown requested"
        ],
        "exposure": {
          "emails_delivered": 5,
          "users_clicked": 2,
          "credentials_submitted": 0
        }
      }
    ]
  }
}
```

## Success Metrics
- Detection speed: Identify phishing domains within 24 hours of registration
- Coverage: Monitor 95%+ of brand permutations
- False positive rate: <10% of flagged domains
- Takedown success rate: >80% of confirmed phishing sites removed within 48 hours
- User exposure reduction: <5% of phishing emails reach inboxes

## Tips & Best Practices

### General Tips
- Automate daily monitoring—manual review doesn't scale
- Prioritize newly registered domains (<7 days old) for highest yield
- Combine multiple signals (similarity + new registration + SSL + content) for accuracy
- Build relationships with registrars and hosting providers for faster takedowns
- Monitor social media and messaging platforms for phishing link distribution

### Common Pitfalls to Avoid
- **Over-blocking legitimate domains**: Parking pages and fan sites may trigger false positives
- **Ignoring non-English phishing**: International domains and IDN homographs target global users
- **Missing subdomain phishing**: Compromised legitimate sites (e.g., wordpress-site.com/company-login)
- **Focusing only on lookalikes**: Attackers also use unrelated domains with convincing content

### Optimization Strategies
- Use machine learning models trained on historical phishing domains
- Implement automated screenshot comparison for visual brand impersonation
- Create regex libraries for common phishing URL patterns
- Leverage community databases to reduce analysis workload
- Build feedback loops from user-reported phishing to improve detection

### Automation Opportunities
- Daily automated domain registration monitoring
- Automatic URLScan.io submission for new suspicious domains
- SOAR playbooks for takedown request workflows
- Automated email gateway rule deployment
- Integration with SIEM for correlation with phishing email attempts

## Real-World Application

### Industry Examples
- **Financial Services:** Bank identifies 50+ phishing domains weekly, blocks before campaigns launch
- **Technology:** SaaS provider monitors customer brand impersonation for partner protection
- **Healthcare:** Hospital system detects executive impersonation domains used in BEC attacks
- **Retail:** E-commerce company protects customers from fake shopping sites during holidays

### Case Study
A major financial institution's brand protection team implemented proactive phishing domain monitoring using this workflow. Within the first month:

1. Identified 147 newly registered domains containing brand keywords
2. Confirmed 31 active phishing sites through automated scanning
3. Blocked all 31 domains at email gateway before phishing campaign began
4. Submitted takedown requests to registrars (average takedown: 18 hours)
5. Discovered one domain had already sent 200+ phishing emails (caught by email security)

Investigation of one high-risk domain revealed:
- Domain: secure-[bank]login.net (registered 2 days prior)
- Perfect clone of bank's login page with credential harvesting form
- Hosted on bulletproof hosting in Eastern Europe
- Let's Encrypt SSL certificate for appearance of legitimacy
- Email campaign targeting 5,000 customers (blocked by gateway rules)

The proactive monitoring prevented an estimated $2M+ in fraud losses and protected customer credentials. The bank's detection time improved from 5-7 days (reactive) to <24 hours (proactive), significantly reducing attack windows.

## Additional Resources

### Documentation
- [MITRE ATT&CK: Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)
- [ICANN: Combating Domain Name Abuse](https://www.icann.org/resources/pages/combating-malicious-use-2021-09-10-en)
- [Anti-Phishing Working Group (APWG)](https://apwg.org/)
- [dnstwist Documentation](https://github.com/elceef/dnstwist)

### Training Materials
- "Brand Protection in Cyber Threat Intelligence" - SANS webinars
- Phishing detection and response courses
- Domain registration and DNS security training

### Community Resources
- PhishTank community
- OpenPhish database
- Twitter: #phishing, #brandprotection, #threatintel
- Reddit: r/phishing, r/cybersecurity

## Related Use Cases
- [UC002: Track APT Infrastructure Using Passive DNS](UC002-track-apt-infrastructure-passive-dns.md) - Infrastructure tracking
- [UC006: Detect Credential Stuffing Using Breach Intelligence](UC006-detect-credential-stuffing-breach-intel.md) - Credential compromise
- [Strategic Intelligence UC002: Industry-Specific Threat Analysis](../strategic-intelligence-reporting/UC002-industry-specific-threat-analysis.md) - Phishing trends by sector

## Version History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-30 | CTI Team | Initial creation |

---

## Appendix

### Glossary
- **Typosquatting**: Registering misspelled versions of legitimate domains
- **Homograph Attack**: Using similar-looking characters from different alphabets (e.g., Cyrillic 'a' vs Latin 'a')
- **Combosquatting**: Combining legitimate brand with common words (secure-, login-, etc.)
- **IDN (Internationalized Domain Name)**: Domains using non-ASCII characters
- **Certificate Transparency**: Public log of all SSL certificates issued
- **Levenshtein Distance**: Measure of similarity between two strings

### Sample Queries/Scripts
```python
#!/usr/bin/env python3
"""
Phishing Domain Detection Script
"""

import dnstwist
import whois
from datetime import datetime, timedelta

class PhishingDomainHunter:
    def __init__(self, brand_domain):
        self.brand_domain = brand_domain

    def generate_permutations(self):
        """Generate typosquatting permutations"""
        return dnstwist.run(domain=self.brand_domain, registered=True)

    def check_new_registrations(self, domains, days=7):
        """Check for recently registered domains"""
        cutoff_date = datetime.now() - timedelta(days=days)
        new_domains = []

        for domain in domains:
            try:
                w = whois.whois(domain)
                if w.creation_date and w.creation_date > cutoff_date:
                    new_domains.append({
                        'domain': domain,
                        'created': w.creation_date,
                        'registrar': w.registrar
                    })
            except:
                pass

        return new_domains

    def hunt_phishing_domains(self):
        """Main hunting workflow"""
        # Generate permutations
        permutations = self.generate_permutations()

        # Check for new registrations
        suspicious = self.check_new_registrations(permutations)

        # Score and prioritize
        scored = [self.score_domain(d) for d in suspicious]
        scored.sort(key=lambda x: x['risk_score'], reverse=True)

        return scored

    def score_domain(self, domain_data):
        """Calculate risk score"""
        score = 0

        # Recent registration
        age = (datetime.now() - domain_data['created']).days
        if age < 7:
            score += 40

        # Add more scoring logic...

        domain_data['risk_score'] = score
        return domain_data

# Usage
hunter = PhishingDomainHunter("company.com")
results = hunter.hunt_phishing_domains()
print(f"Found {len(results)} suspicious domains")
```
