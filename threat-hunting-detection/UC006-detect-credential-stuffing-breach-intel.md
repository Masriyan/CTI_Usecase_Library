# Detect Credential Stuffing Using Breach Intelligence

## Metadata
- **Use Case ID:** THD-UC006
- **Category:** Threat Hunting & Detection
- **Difficulty:** Intermediate
- **Estimated Time:** 2-3 hours
- **Last Updated:** 2025-12-30

## Description
Credential stuffing attacks exploit the reality that users frequently reuse passwords across multiple services. When credentials from one breach are leaked or sold on underground forums, attackers use automated tools to test those credentials against numerous online services. These attacks can result in account takeovers, data breaches, fraud, and lateral movement within enterprise environments.

This use case demonstrates how to leverage breach intelligence databases and monitoring services to proactively identify compromised employee and customer credentials before they're exploited. By correlating organizational email addresses with breach data, analyzing authentication logs for stuffing patterns, and implementing protective measures, security teams can prevent account takeovers and reduce organizational risk.

The workflow covers breach database monitoring, credential exposure detection, authentication pattern analysis, and incident response for compromised accounts.

## Objectives
By completing this use case, you will:
- Monitor breach databases for organizational email addresses and domains
- Identify employees and customers with compromised credentials
- Detect active credential stuffing attacks in authentication logs
- Implement risk-based authentication controls for exposed accounts
- Establish proactive credential hygiene programs
- Build automated breach notification and remediation workflows

## Prerequisites

### Data Sources
- **Breach Intelligence Databases** - Have I Been Pwned (HIBP), Constella Intelligence, SpyCloud
- **Authentication Logs** - SSO, VPN, email, cloud services login attempts
- **Active Directory/IAM** - User account information and status
- **Dark Web Monitoring** - Credential sales and leak monitoring
- **SIEM Platform** - Aggregated security logs for pattern detection

### Tools & Platforms
- **Have I Been Pwned API** - Email and domain breach monitoring
- **Constella Intelligence** - Enterprise breach exposure monitoring
- **SpyCloud** - Automated credential exposure detection
- **Auth0/Okta** - Identity platforms with anomaly detection
- **1Password/Dashlane Business** - Password manager for remediation

### Required Skills
- Understanding of authentication mechanisms and protocols
- Log analysis and pattern recognition
- Familiarity with breach databases and dark web ecosystem
- Basic statistics for anomaly detection
- Incident response and user communication

### Access Requirements
- API access to breach monitoring services
- Read access to authentication and SSO logs
- Ability to reset passwords and enforce MFA
- Access to user directory for email enumeration
- Communication channels for user notifications

## Step-by-Step Workflow

### Step 1: Establish Baseline Email Inventory
**Objective:** Create comprehensive list of organizational email addresses to monitor

**Actions:**
1. Extract all active employee email addresses from Active Directory/IAM
2. Include service accounts, shared mailboxes, and distribution lists
3. Collect customer email addresses (if applicable for customer protection)
4. Document organizational email domains and subdomains
5. Identify VIP/high-value accounts requiring enhanced monitoring

**Example:**
```python
import ldap3

def get_organizational_emails():
    """Extract all email addresses from Active Directory"""
    server = ldap3.Server('ldap://domain-controller')
    conn = ldap3.Connection(server, user='user@domain', password='pass')
    conn.bind()

    conn.search(
        'dc=company,dc=com',
        '(mail=*)',
        attributes=['mail', 'title', 'department']
    )

    emails = []
    for entry in conn.entries:
        emails.append({
            'email': str(entry.mail),
            'title': str(entry.title),
            'department': str(entry.department),
            'is_vip': 'C-level' in str(entry.title) or 'VP' in str(entry.title)
        })

    return emails
```

**Output:** Inventory of all organizational email addresses with metadata

---

### Step 2: Domain and Email Breach Monitoring
**Objective:** Check organizational emails against breach databases

**Actions:**
1. Query Have I Been Pwned API for domain-wide breach exposure
2. Check individual VIP emails for specific breaches
3. Use enterprise breach monitoring services for comprehensive coverage
4. Track new breaches affecting organizational domain
5. Document breach details (date, compromised fields, breach source)

**Example:**
```python
import requests

def check_hibp_breach(email, api_key):
    """Check if email appears in breaches via HIBP API"""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        'hibp-api-key': api_key,
        'user-agent': 'Company-Breach-Monitoring'
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        breaches = response.json()
        return {
            'email': email,
            'breach_count': len(breaches),
            'breaches': [
                {
                    'name': b['Name'],
                    'breach_date': b['BreachDate'],
                    'data_classes': b['DataClasses'],
                    'is_verified': b['IsVerified']
                }
                for b in breaches
            ]
        }
    elif response.status_code == 404:
        return {'email': email, 'breach_count': 0}
    else:
        return None

# Domain-wide monitoring
def monitor_domain_breaches(domain, api_key):
    """Monitor all breaches affecting a domain"""
    url = f"https://haveibeenpwned.com/api/v3/breaches"
    headers = {'hibp-api-key': api_key}

    response = requests.get(url, headers=headers)
    breaches = response.json()

    # Filter for recent breaches
    recent_breaches = [
        b for b in breaches
        if domain.lower() in str(b.get('Domain', '')).lower()
    ]

    return recent_breaches
```

**Output:** List of exposed email addresses with breach details

---

### Step 3: Password Exposure Analysis
**Objective:** Determine severity of credential exposure

**Actions:**
1. Identify which data fields were compromised (password, hash type, PII)
2. Assess hash algorithm strength (MD5 vs bcrypt indicates crack likelihood)
3. Determine if plaintext passwords were exposed
4. Check for password + email + additional PII combinations
5. Prioritize accounts with plaintext or weak-hash password exposure

**Example:**
```python
def assess_exposure_severity(breach_data):
    """Calculate severity score for breach exposure"""
    score = 0

    data_classes = breach_data.get('data_classes', [])

    # Plaintext passwords (critical)
    if 'Passwords' in data_classes and 'plaintext' in str(breach_data):
        score += 50

    # Password hashes
    elif 'Passwords' in data_classes:
        hash_type = breach_data.get('hash_algorithm', 'unknown')
        if hash_type in ['MD5', 'SHA1']:
            score += 40  # Easily cracked
        elif hash_type in ['bcrypt', 'argon2']:
            score += 20  # Harder to crack

    # Additional sensitive data
    if 'Email addresses' in data_classes:
        score += 10
    if 'Security questions and answers' in data_classes:
        score += 15
    if 'Phone numbers' in data_classes:
        score += 10

    # Breach recency
    breach_date = breach_data.get('breach_date')
    days_old = (datetime.now() - datetime.strptime(breach_date, '%Y-%m-%d')).days
    if days_old < 30:
        score += 20
    elif days_old < 90:
        score += 10

    return min(score, 100)
```

**Output:** Risk-scored list of compromised accounts

---

### Step 4: Authentication Log Analysis
**Objective:** Detect active credential stuffing attempts in logs

**Actions:**
1. Query authentication logs for failed login patterns
2. Identify high-volume failed logins from distributed IPs (botnet indicators)
3. Look for successful logins following breach notifications
4. Detect credential testing patterns (single attempt per account across many accounts)
5. Correlate failed logins with breach-exposed accounts

**Example:**
```sql
-- SIEM query for credential stuffing patterns
index=authentication action=failure
| stats count, dc(src_ip) as unique_ips, values(user_agent)
  by user, _time
| bin span=1h _time
| where count > 5 AND unique_ips > 3
| join user [
    search index=breach_intel
    | table user, breach_name, breach_date
  ]
| table _time, user, count, unique_ips, breach_name
| sort -count
```

**Output:** List of accounts under active credential stuffing attack

---

### Step 5: Geographic and Behavioral Anomaly Detection
**Objective:** Identify impossible travel and behavioral anomalies

**Actions:**
1. Analyze login geolocation patterns for anomalies
2. Detect impossible travel scenarios (Paris then Tokyo 2 hours later)
3. Identify logins from high-risk countries or TOR exit nodes
4. Flag first-time logins from new devices/browsers for exposed accounts
5. Compare login times to normal user patterns

**Example:**
```python
from geopy.distance import geodesic
from datetime import datetime

def detect_impossible_travel(login_events):
    """Detect impossible travel between logins"""
    alerts = []

    # Sort by user and time
    login_events = sorted(login_events, key=lambda x: (x['user'], x['timestamp']))

    for i in range(1, len(login_events)):
        prev = login_events[i-1]
        curr = login_events[i]

        if prev['user'] != curr['user']:
            continue

        # Calculate distance
        distance = geodesic(
            (prev['latitude'], prev['longitude']),
            (curr['latitude'], curr['longitude'])
        ).km

        # Calculate time difference
        time_diff = (curr['timestamp'] - prev['timestamp']).total_seconds() / 3600

        # Average speed (km/h)
        speed = distance / time_diff if time_diff > 0 else 0

        # Flag if speed > 900 km/h (faster than commercial flight)
        if speed > 900:
            alerts.append({
                'user': curr['user'],
                'prev_location': f"{prev['city']}, {prev['country']}",
                'curr_location': f"{curr['city']}, {curr['country']}",
                'distance_km': distance,
                'time_hours': time_diff,
                'speed_kmh': speed,
                'alert': 'Impossible travel detected'
            })

    return alerts
```

**Output:** Alerts for anomalous authentication patterns

---

### Step 6: Dark Web Monitoring
**Objective:** Monitor underground forums for organizational credential sales

**Actions:**
1. Monitor dark web marketplaces for organizational domain mentions
2. Track paste sites (Pastebin, GitHub) for credential leaks
3. Monitor Telegram channels and forums for credential dumps
4. Identify new "combo lists" containing organizational emails
5. Purchase or acquire leaked credential files for analysis (if legally permissible)

**Example:**
```yaml
# Dark web monitoring configuration
monitoring_sources:
  forums:
    - "RaidForums"
    - "BreachForums"
    - "Exploit.in"

  paste_sites:
    - "Pastebin"
    - "GitHub Gists"
    - "Ghostbin"

  telegram_channels:
    - "@combos_channel"
    - "@leaks_database"

  keywords:
    - "company.com"
    - "@company.com"
    - "company employees"
    - "company database"

  alerts:
    email: "cti-team@company.com"
    severity: high
```

**Output:** Alerts for new credential leaks or sales

---

### Step 7: User Risk Scoring
**Objective:** Calculate overall risk score for each user account

**Actions:**
1. Combine breach exposure data with authentication anomalies
2. Weight factors: number of breaches, password exposure, failed logins, anomalies
3. Include user privilege level (admin accounts = higher risk)
4. Factor in account activity and criticality
5. Generate prioritized list for remediation

**Example:**
```python
def calculate_user_risk_score(user_data):
    """Calculate comprehensive user account risk score"""
    score = 0

    # Breach exposure
    breach_count = user_data.get('breach_count', 0)
    score += min(breach_count * 10, 40)

    # Password exposure severity
    if user_data.get('plaintext_password_exposed'):
        score += 30
    elif user_data.get('weak_hash_password_exposed'):
        score += 20

    # Recent failed login attempts
    failed_logins = user_data.get('failed_logins_7d', 0)
    if failed_logins > 20:
        score += 20
    elif failed_logins > 5:
        score += 10

    # Anomalous logins
    if user_data.get('impossible_travel_detected'):
        score += 25
    if user_data.get('login_from_high_risk_country'):
        score += 15

    # Account privilege
    if user_data.get('is_admin'):
        score *= 1.5  # Multiply existing score

    # MFA status
    if not user_data.get('mfa_enabled'):
        score += 20

    return min(int(score), 100)
```

**Output:** Risk-ranked list of user accounts

---

### Step 8: Automated Remediation Actions
**Objective:** Deploy protective measures for compromised accounts

**Actions:**
1. Trigger forced password resets for high-risk accounts
2. Enable or enforce MFA for exposed accounts
3. Revoke active sessions for compromised accounts
4. Implement step-up authentication for sensitive operations
5. Temporarily restrict access for actively attacked accounts

**Example:**
```python
def remediate_compromised_account(user, risk_score):
    """Automated remediation based on risk score"""

    if risk_score >= 80:
        # Critical - immediate action
        revoke_active_sessions(user)
        force_password_reset(user)
        enable_mfa_enforcement(user)
        notify_security_team(user, risk_score, urgency='critical')
        notify_user(user, message='immediate_reset_required')

    elif risk_score >= 50:
        # High - proactive protection
        force_password_reset(user)
        enable_mfa_enforcement(user)
        notify_user(user, message='security_notice')
        notify_manager(user)

    elif risk_score >= 30:
        # Medium - monitoring and notification
        flag_for_monitoring(user)
        notify_user(user, message='password_change_recommended')
        schedule_followup(user, days=7)

    else:
        # Low - awareness
        add_to_security_awareness_campaign(user)

    # Log all actions
    log_remediation(user, risk_score, actions_taken)
```

**Output:** Automated account protection deployment

---

### Step 9: User Notification and Training
**Objective:** Educate users about credential exposure and security

**Actions:**
1. Send personalized notifications to affected users
2. Provide clear instructions for password reset and MFA setup
3. Explain the breach and what data was compromised
4. Offer password manager licenses to encourage unique passwords
5. Track user compliance with remediation actions

**Example:**
```python
def notify_exposed_user(user_email, breach_details):
    """Send personalized breach notification"""
    email_template = f"""
    Subject: Important Security Notice - Credential Exposure

    Dear User,

    Our security team has identified that your email address ({user_email})
    was included in a data breach from {breach_details['breach_name']}.

    Compromised Data:
    {', '.join(breach_details['data_classes'])}

    Breach Date: {breach_details['breach_date']}

    REQUIRED ACTIONS:
    1. Reset your password immediately using this link: [LINK]
    2. Enable multi-factor authentication: [LINK]
    3. Review recent account activity for unauthorized access

    RECOMMENDATIONS:
    - Use unique passwords for every service
    - Consider using a password manager (free license available)
    - Never reuse your work password on personal sites

    Questions? Contact security@company.com

    - Security Team
    """

    send_email(user_email, email_template)
    log_notification(user_email, breach_details['breach_name'])
```

**Output:** User notifications and training materials distributed

---

### Step 10: Continuous Monitoring and Reporting
**Objective:** Establish ongoing credential exposure monitoring program

**Actions:**
1. Schedule daily breach database checks for organizational domain
2. Configure real-time alerts for new breach disclosures
3. Build dashboards tracking exposure metrics and remediation status
4. Generate monthly reports for security leadership
5. Measure program effectiveness (time to remediation, repeat exposures)

**Example:**
```python
# Monitoring schedule configuration
monitoring_schedule = {
    "daily": [
        "check_new_breaches_hibp",
        "analyze_authentication_logs",
        "update_user_risk_scores"
    ],
    "weekly": [
        "scan_dark_web_forums",
        "review_remediation_compliance",
        "generate_exposure_metrics"
    ],
    "monthly": [
        "executive_breach_report",
        "user_awareness_campaign",
        "program_effectiveness_review"
    ]
}

def generate_breach_metrics():
    """Generate program effectiveness metrics"""
    return {
        "total_exposed_accounts": count_exposed_accounts(),
        "remediated_accounts": count_remediated_accounts(),
        "remediation_rate": calculate_remediation_rate(),
        "average_time_to_remediation_hours": calculate_avg_remediation_time(),
        "repeat_exposures": count_repeat_exposures(),
        "mfa_adoption_rate": calculate_mfa_rate(),
        "active_stuffing_attempts_blocked": count_blocked_stuffing()
    }
```

**Output:** Continuous monitoring system with metrics and reporting

---

## Recommended CTI Products

### Primary Products
- **SpyCloud** - Automated breach exposure monitoring and remediation
  - Assessment: [SpyCloud](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#spycloud)
  - Key Features: Real-time breach alerts, automated remediation, dark web monitoring

- **Constella Intelligence** - Enterprise credential exposure detection
  - Assessment: [Constella Intelligence](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#constella-intelligence)
  - Key Features: Deep web monitoring, historical breach data, API integration

### Alternative/Complementary Products
- **Have I Been Pwned (Enterprise)** - Domain monitoring service
  - Assessment: [HIBP Enterprise](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#have-i-been-pwned)

- **Digital Shadows (Reliaquest)** - Digital risk protection with credential monitoring
  - Assessment: [Digital Shadows](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#digital-shadows)

- **RecordedFuture** - Threat intelligence with credential exposure tracking
  - Assessment: [Recorded Future](https://github.com/Masriyan/CTI-Product-Assesment-Matrix#recorded-future)

### Open Source Options
- **Have I Been Pwned API** - Free domain monitoring (with API key)
- **Dehashed** - Breach search engine (freemium)
- **IntelligenceX** - Data leak search engine
- **Leaked Password Databases** - Troy Hunt's password list

## Expected Outputs

### Deliverables
1. **Breach Exposure Report**
   - Format: PDF with executive summary
   - Content: Number of exposed accounts, breach details, risk analysis
   - Audience: CISO, security leadership, legal/compliance

2. **Remediation Dashboard**
   - Format: Real-time web dashboard
   - Content: Exposed accounts, remediation status, compliance tracking
   - Audience: SOC, identity team, help desk

3. **User Notifications**
   - Format: Email alerts
   - Content: Personalized breach notifications with remediation steps
   - Audience: Affected employees, customers

4. **IOC Package**
   - Format: CSV, STIX 2.1
   - Content: Exposed credentials (hashed), attacker IPs, user agents from stuffing attempts
   - Audience: SOC analysts, threat hunters

### Sample Output
```json
{
  "credential_exposure_analysis": {
    "analysis_date": "2025-12-30",
    "total_employees": 5000,
    "exposed_accounts": 347,
    "exposure_rate": "6.94%",
    "high_risk_accounts": 23,
    "breaches_affecting_org": [
      {
        "breach_name": "LinkedIn (2021)",
        "affected_employees": 142,
        "data_exposed": ["Email", "Passwords (SHA1)"],
        "breach_date": "2021-06-22"
      },
      {
        "breach_name": "Collection #1",
        "affected_employees": 98,
        "data_exposed": ["Email", "Passwords (plaintext)"],
        "breach_date": "2019-01-16"
      }
    ],
    "remediation_status": {
      "passwords_reset": 310,
      "mfa_enabled": 289,
      "pending_action": 37
    },
    "active_threats": {
      "stuffing_attempts_detected": 1247,
      "blocked_attempts": 1239,
      "successful_unauthorized_logins": 8
    },
    "actions_required": [
      "Force reset for 37 non-compliant users",
      "Investigate 8 successful unauthorized logins",
      "Deploy adaptive MFA for high-risk accounts"
    ]
  }
}
```

## Success Metrics
- Detection coverage: Monitor 100% of organizational email addresses
- Alert speed: Notify within 24 hours of new breach disclosure
- Remediation rate: >90% of exposed accounts remediated within 7 days
- MFA adoption: >95% of exposed accounts have MFA enabled
- Attack prevention: >95% of credential stuffing attempts blocked

## Tips & Best Practices

### General Tips
- Prioritize monitoring of privileged accounts (admins, executives, finance)
- Automate as much as possible—manual breach checking doesn't scale
- Combine breach data with behavioral analytics for comprehensive protection
- Use breach notifications as teachable moments for security awareness
- Implement password managers organization-wide to prevent reuse

### Common Pitfalls to Avoid
- **Alert fatigue**: Old breaches affect many users; focus on recent or high-severity exposures
- **Privacy concerns**: Handle breach data sensitively; don't over-share exposure details
- **Ignoring service accounts**: Compromised service accounts can cause massive damage
- **One-time remediation**: Users will continue to be exposed in new breaches; continuous monitoring is essential

### Optimization Strategies
- Integrate breach monitoring with IAM for automated remediation
- Use risk-based authentication to add friction only for risky logins
- Implement password complexity requirements that prevent breach password reuse
- Build breach data into user risk scoring for adaptive security controls
- Leverage SSO to reduce password sprawl and exposure surface

### Automation Opportunities
- Automated daily breach database checks
- Automatic password reset triggers for high-risk exposures
- SOAR playbooks for credential stuffing incident response
- Automated MFA enrollment for exposed accounts
- Integration with password managers for secure password generation

## Real-World Application

### Industry Examples
- **Financial Services:** Bank monitors 50,000 employee credentials, preventing account takeover fraud
- **Healthcare:** Hospital system detects compromised credentials before ransomware deployment
- **Technology:** SaaS provider monitors customer credentials to prevent account takeover
- **Government:** Agency protects classified access through continuous credential monitoring

### Case Study
A multinational corporation with 20,000 employees implemented comprehensive credential monitoring:

**Initial Scan Results:**
- 2,847 employees (14.2%) found in breach databases
- 412 with plaintext password exposure
- 87 administrative accounts exposed

**Immediate Actions:**
- Forced password resets for all 412 plaintext exposures within 24 hours
- Enabled MFA enforcement for all 87 admin accounts
- Deployed password manager licenses to all employees

**90-Day Results:**
- Detected and blocked 15,000+ credential stuffing attempts
- Zero successful account takeovers (down from 3-5/month)
- MFA adoption increased from 45% to 89%
- Repeat exposure rate dropped to 2% (users creating unique passwords)

**Prevented Incident:**
During the program, the team detected that a Finance VP's credentials from a 2019 breach were being actively tested. Automated remediation had forced a password reset 2 days prior. The credential stuffing attempts failed, preventing potential BEC fraud and wire transfer theft estimated at $500K+.

The program demonstrated clear ROI through prevented fraud, reduced help desk tickets from account lockouts, and improved overall security posture.

## Additional Resources

### Documentation
- [MITRE ATT&CK: Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [OWASP: Credential Stuffing Prevention](https://owasp.org/www-community/attacks/Credential_stuffing)
- [Have I Been Pwned API Documentation](https://haveibeenpwned.com/API/v3)
- [NIST: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

### Training Materials
- "Credential Stuffing Defense" - SANS webinars
- Identity and access management certifications (CISSP, CISM)
- Password security and breach response training

### Community Resources
- Have I Been Pwned community
- Dark web monitoring Telegram groups
- Twitter: #breachalert, #credentialstuffing, #identitysecurity
- Reddit: r/netsec, r/cybersecurity

## Related Use Cases
- [UC005: Identify Phishing Domain Patterns](UC005-identify-phishing-domain-patterns.md) - Related credential theft vectors
- [Strategic Intelligence UC005: Regulatory Compliance Threat Reporting](../strategic-intelligence-reporting/UC005-regulatory-compliance-threat-reporting.md) - Breach disclosure requirements

## Version History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-30 | CTI Team | Initial creation |

---

## Appendix

### Glossary
- **Credential Stuffing**: Automated injection of breached username/password pairs to gain unauthorized access
- **Combo List**: File containing username:password pairs from breaches
- **Impossible Travel**: Geographically impossible login pattern indicating compromised credentials
- **MFA (Multi-Factor Authentication)**: Authentication requiring two or more verification factors
- **Password Spray**: Attack trying common passwords against many accounts (reverse of credential stuffing)

### Sample Queries/Scripts
```bash
# Check if email is in HIBP breaches
curl -H "hibp-api-key: YOUR_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/user@company.com"

# Check domain for breaches
curl -H "hibp-api-key: YOUR_KEY" \
  "https://haveibeenpwned.com/api/v3/breaches"
```

### Workflow Diagram
```
┌──────────────────────────────────────────────────────────┐
│     Credential Stuffing Detection & Remediation          │
└──────────────────────────────────────────────────────────┘

    [Organizational Emails]
         │
         ▼
    ┌─────────────────────┐
    │ 1. Email Inventory  │ ──────► AD/IAM extraction
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 2. Breach Monitoring│ ──────► HIBP, SpyCloud
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 3. Exposure Analysis│ ──────► Severity assessment
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 4. Auth Log Analysis│ ──────► Detect active attacks
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 5. Anomaly Detection│ ──────► Impossible travel, etc.
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 6. Dark Web Monitor │ ──────► Forums, paste sites
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 7. Risk Scoring     │ ──────► Prioritize accounts
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 8. Auto Remediation │ ──────► Password reset, MFA
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 9. User Notification│ ──────► Training & awareness
    └─────────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ 10. Continuous      │ ──────► Monitoring & reporting
    │     Monitoring      │
    └─────────────────────┘
         │
         ▼
    [Protected Accounts + Metrics + Compliance]
```
