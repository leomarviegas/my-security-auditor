# MITRE ATT&CK Framework

This reference provides comprehensive guidance on using MITRE ATT&CK for threat modeling, detection engineering, adversary emulation, and finding attribution during security audits. ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is the globally-accessible knowledge base of adversary behavior based on real-world observations.

## Table of Contents
1. [ATT&CK Framework Overview](#1-attck-framework-overview)
2. [ATT&CK Matrices](#2-attck-matrices)
3. [Enterprise Tactics Detailed](#3-enterprise-tactics-detailed)
4. [Key Techniques for Web Audits](#4-key-techniques-for-web-audits)
5. [Cloud ATT&CK](#5-cloud-attck)
6. [Container ATT&CK](#6-container-attck)
7. [Mobile ATT&CK](#7-mobile-attck)
8. [ATT&CK for ICS](#8-attck-for-ics)
9. [MITRE D3FEND — Defensive Countermeasures](#9-mitre-d3fend)
10. [Adversary Emulation](#10-adversary-emulation)
11. [Detection Engineering with ATT&CK](#11-detection-engineering)
12. [Mapping Findings to ATT&CK](#12-mapping-findings-to-attck)
13. [ATT&CK Assessment Checklist](#13-attck-assessment-checklist)

---

## 1. ATT&CK Framework Overview

ATT&CK organizes adversary behavior into a structured taxonomy:

| Level | Definition | Example |
|-------|-----------|---------|
| Tactic | The adversary's goal or "why" | Initial Access |
| Technique | The method to achieve the tactic | Phishing (T1566) |
| Sub-technique | Specific variation of a technique | Spearphishing Attachment (T1566.001) |
| Procedure | Specific implementation by a threat actor | APT29 using HTA file in phishing email |

### Why ATT&CK matters for audits
- **Common language** — universal vocabulary for discussing attacker behavior
- **Evidence-based** — tied to real-world observations, not theoretical threats
- **Gap analysis** — identify which attacker techniques your defenses don't cover
- **Threat-informed defense** — prioritize defenses against likely adversaries
- **Adversary emulation** — test defenses against realistic attack chains

### ATT&CK terminology
| Term | Meaning |
|------|---------|
| Threat Group | Named adversary clusters (APT29, FIN7, Lazarus, etc.) |
| Software | Malware, tools, and utilities used by adversaries |
| Campaign | Grouped malicious activity with specific targeting and timeframe |
| Data Source | Information an organization collects that could detect a technique |
| Mitigation | Security concept or technology that prevents a technique |

---

## 2. ATT&CK Matrices

ATT&CK maintains distinct matrices for different technology domains:

| Matrix | Scope | When to use |
|--------|-------|-------------|
| Enterprise | Traditional IT (Windows, macOS, Linux, Network, Office 365, Azure AD, SaaS, IaaS) | Most security audits |
| Mobile | iOS and Android adversary behavior | Mobile app security audits |
| ICS | Industrial Control Systems / OT | Manufacturing, utilities, critical infrastructure |
| Cloud | AWS, Azure, GCP, Office 365, SaaS | Cloud-native applications |
| Containers | Docker, Kubernetes, container orchestration | Containerized workloads |

### ATT&CK Enterprise sub-matrices
- Pre-ATT&CK (merged into main matrix) — reconnaissance and resource development
- Network — network devices (switches, routers, firewalls)
- Office 365 — Microsoft 365 specific techniques
- Azure AD — Azure Active Directory / Entra ID
- Google Workspace — Google Workspace specific
- SaaS — generic SaaS platform techniques
- IaaS — generic cloud infrastructure techniques

---

## 3. Enterprise Tactics Detailed

ATT&CK for Enterprise has 14 tactics. Each represents a phase of the attack lifecycle.

### TA0043 — Reconnaissance
Gathering information for future operations.

| Technique ID | Name | Web audit relevance |
|--------------|------|-------------------|
| T1595 | Active Scanning | Port scans, vulnerability scans detected |
| T1592 | Gather Victim Host Information | Fingerprinting server/framework versions |
| T1589 | Gather Victim Identity Information | User enumeration via auth flows, email harvesting |
| T1590 | Gather Victim Network Information | DNS reconnaissance, network mapping |
| T1591 | Gather Victim Org Information | Employee data, business relationships |
| T1598 | Phishing for Information | Credential harvesting sites, social engineering |
| T1597 | Search Closed Sources | Dark web monitoring for leaks |
| T1596 | Search Open Technical Databases | Shodan, Censys, public certificate transparency |
| T1593 | Search Open Websites/Domains | GitHub for leaked secrets, company blogs |
| T1594 | Search Victim-Owned Websites | Parsing publicly available web content |

### TA0042 — Resource Development
Building attacker infrastructure.

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| T1583 | Acquire Infrastructure | Attacker setting up C2, phishing, or staging servers |
| T1586 | Compromise Accounts | Takeover of existing accounts for attacks |
| T1584 | Compromise Infrastructure | Using compromised legitimate infrastructure |
| T1587 | Develop Capabilities | Custom tool/malware development |
| T1588 | Obtain Capabilities | Acquiring exploits, certificates, tools |

### TA0001 — Initial Access
Getting into the target environment.

| Technique ID | Name | Web audit relevance |
|--------------|------|-------------------|
| T1190 | Exploit Public-Facing Application | **Primary relevance** — web vulnerabilities exploited for access |
| T1133 | External Remote Services | VPN, RDP, SSH exposed |
| T1566 | Phishing | Social engineering to capture credentials |
| T1078 | Valid Accounts | Using stolen/compromised credentials |
| T1091 | Replication Through Removable Media | USB attacks |
| T1200 | Hardware Additions | Physical access required |
| T1195 | Supply Chain Compromise | Compromising a dependency or vendor |
| T1199 | Trusted Relationship | Leveraging vendor/partner access |
| T1189 | Drive-by Compromise | Malicious web content |

### TA0002 — Execution
Running attacker code on the target.

| Technique ID | Name | Web relevance |
|--------------|------|---------------|
| T1059 | Command and Scripting Interpreter | RCE via web app vulnerability |
| T1059.007 | JavaScript | XSS payload execution |
| T1047 | Windows Management Instrumentation | Post-compromise execution |
| T1053 | Scheduled Task/Job | Persistence via scheduled execution |
| T1569 | System Services | Service-based execution |
| T1204 | User Execution | Social engineering for execution |
| T1609 | Container Administration Command | Container-based execution |
| T1610 | Deploy Container | Malicious container deployment |

### TA0003 — Persistence
Maintaining access across reboots and credential changes.

| Technique ID | Name | Web relevance |
|--------------|------|---------------|
| T1098 | Account Manipulation | Creating admin accounts, adding to groups |
| T1136 | Create Account | New account for persistence |
| T1505 | Server Software Component | Web shells, malicious plugins |
| T1505.003 | Web Shell | **Critical for web audits** — uploaded web shells |
| T1037 | Boot or Logon Initialization Scripts | Startup persistence |
| T1546 | Event Triggered Execution | Persistence via event handlers |

### TA0004 — Privilege Escalation
Gaining higher permissions.

| Technique ID | Name | Web relevance |
|--------------|------|---------------|
| T1548 | Abuse Elevation Control Mechanism | sudo abuse, UAC bypass |
| T1134 | Access Token Manipulation | Token theft and reuse |
| T1068 | Exploitation for Privilege Escalation | Kernel/service exploits |
| T1611 | Escape to Host | Container escape |
| T1484 | Domain Policy Modification | GPO manipulation |
| T1078 | Valid Accounts | Using higher-privileged stolen accounts |

### TA0005 — Defense Evasion
Avoiding detection.

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| T1562 | Impair Defenses | Disabling logs, AV, firewalls |
| T1070 | Indicator Removal | Log deletion, artifact cleanup |
| T1036 | Masquerading | Legitimate-looking names, paths |
| T1027 | Obfuscated Files or Information | Encoded payloads |
| T1140 | Deobfuscate/Decode Files | Runtime decoding |
| T1550 | Use Alternate Authentication Material | Pass-the-hash, token replay |

### TA0006 — Credential Access
Stealing credentials.

| Technique ID | Name | Web audit relevance |
|--------------|------|-------------------|
| T1110 | Brute Force | Password spraying, credential stuffing |
| T1555 | Credentials from Password Stores | Browser/keychain credential theft |
| T1212 | Exploitation for Credential Access | Vulnerability-based credential dump |
| T1187 | Forced Authentication | SMB/NTLM relay |
| T1606 | Forge Web Credentials | **Critical** — JWT tampering, cookie forging |
| T1056 | Input Capture | Keylogging, XSS-based credential capture |
| T1557 | Adversary-in-the-Middle | MitM on auth flows |
| T1040 | Network Sniffing | Plaintext credential capture |
| T1003 | OS Credential Dumping | LSASS dumping, /etc/shadow |
| T1528 | Steal Application Access Token | OAuth token theft |
| T1539 | Steal Web Session Cookie | **Critical for web** — session hijacking |

### TA0007 — Discovery
Learning about the environment.

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| T1087 | Account Discovery | Enumerating users |
| T1580 | Cloud Infrastructure Discovery | Cloud resource enumeration |
| T1538 | Cloud Service Dashboard | Cloud console access |
| T1526 | Cloud Service Discovery | Finding available cloud services |
| T1046 | Network Service Discovery | Port scanning from within |
| T1135 | Network Share Discovery | File share enumeration |
| T1201 | Password Policy Discovery | Learning password requirements |
| T1069 | Permission Groups Discovery | RBAC enumeration |
| T1082 | System Information Discovery | OS, hardware info |
| T1613 | Container and Resource Discovery | K8s API enumeration |

### TA0008 — Lateral Movement
Moving through the environment.

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| T1021 | Remote Services | SSH, RDP, WinRM |
| T1210 | Exploitation of Remote Services | Exploiting internal service vulnerabilities |
| T1534 | Internal Spearphishing | Using compromised accounts to phish others |
| T1570 | Lateral Tool Transfer | Moving tools between hosts |
| T1550 | Use Alternate Authentication Material | Reusing stolen tokens/hashes |

### TA0009 — Collection
Gathering data of interest.

| Technique ID | Name | Web relevance |
|--------------|------|---------------|
| T1530 | Data from Cloud Storage | S3/GCS/Blob bucket data |
| T1213 | Data from Information Repositories | Wiki, SharePoint, code repos |
| T1005 | Data from Local System | File collection |
| T1602 | Data from Configuration Repository | Config file collection |
| T1119 | Automated Collection | Scripted data gathering |
| T1056 | Input Capture | Form data, keystrokes |
| T1185 | Browser Session Hijacking | **Web relevant** — hijacking active sessions |

### TA0011 — Command and Control
Communicating with attacker infrastructure.

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| T1071 | Application Layer Protocol | HTTPS-based C2 |
| T1090 | Proxy | Proxying through compromised systems |
| T1568 | Dynamic Resolution | DGA, fast-flux |
| T1572 | Protocol Tunneling | DNS tunneling, ICMP tunneling |
| T1573 | Encrypted Channel | TLS/encrypted C2 |
| T1102 | Web Service | Using legitimate services (Dropbox, GitHub) as C2 |

### TA0010 — Exfiltration
Stealing data.

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| T1048 | Exfiltration Over Alternative Protocol | DNS, ICMP exfil |
| T1041 | Exfiltration Over C2 Channel | Through existing C2 |
| T1567 | Exfiltration Over Web Service | Via cloud services |
| T1029 | Scheduled Transfer | Time-based exfil |
| T1011 | Exfiltration Over Other Network Medium | Bluetooth, cellular |

### TA0040 — Impact
Damaging or disrupting.

| Technique ID | Name | Relevance |
|--------------|------|-----------|
| T1485 | Data Destruction | Wiping data |
| T1486 | Data Encrypted for Impact | Ransomware |
| T1565 | Data Manipulation | Tampering with data |
| T1491 | Defacement | Website defacement |
| T1561 | Disk Wipe | System destruction |
| T1499 | Endpoint Denial of Service | DoS |
| T1498 | Network Denial of Service | DDoS |
| T1529 | System Shutdown/Reboot | Availability impact |
| T1657 | Financial Theft | Monetary impact |

---

## 4. Key Techniques for Web Audits

These are the techniques most frequently relevant when mapping web audit findings:

| Finding type | ATT&CK Technique |
|-------------|-----------------|
| SQL Injection / XXE leading to RCE | T1190 (Exploit Public-Facing Application) + T1059 (Command/Scripting Interpreter) |
| Authentication bypass | T1190 + T1078 (Valid Accounts if credential theft follows) |
| IDOR / BOLA | T1190 + T1087 (Account Discovery) + T1213 (Data from Information Repositories) |
| XSS leading to session hijack | T1190 + T1539 (Steal Web Session Cookie) |
| JWT tampering | T1606 (Forge Web Credentials) |
| Credential stuffing feasibility | T1110.004 (Credential Stuffing) |
| Weak password policy | T1110.001 (Password Guessing) or T1110.003 (Password Spraying) |
| Exposed admin panel | T1190 + T1078 |
| File upload with RCE | T1190 + T1505.003 (Web Shell) |
| SSRF to cloud metadata | T1190 + T1552.005 (Credentials from Cloud Instance Metadata API) |
| CORS misconfiguration | T1557 (Adversary-in-the-Middle) |
| Open redirect | T1204 (User Execution) — social engineering via trusted domain |
| Subdomain takeover | T1584 (Compromise Infrastructure) |
| Exposed S3/GCS/Blob | T1530 (Data from Cloud Storage) |
| Excessive data in API response | T1213 (Data from Information Repositories) |
| Missing rate limiting | T1110 family + T1498 (Network Denial of Service) |
| Verbose errors | T1592 (Gather Victim Host Information) |
| Source maps exposed | T1592 + T1591 (Gather Victim Org Information) |
| Prompt injection (LLM) | T1190 + T1059 — new category, often mapped to existing techniques |

---

## 5. Cloud ATT&CK

Cloud-specific techniques organized by cloud environment.

### Key cloud techniques
| Technique ID | Name | Cloud context |
|--------------|------|--------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Compromised cloud credentials |
| T1199 | Trusted Relationship | Cross-account access abuse |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Adding attacker-controlled credentials |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Assigning excessive permissions |
| T1538 | Cloud Service Dashboard | Attacker access to cloud console |
| T1526 | Cloud Service Discovery | Enumeration of cloud services |
| T1580 | Cloud Infrastructure Discovery | Mapping cloud resources |
| T1578 | Modify Cloud Compute Infrastructure | Tampering with cloud resources |
| T1619 | Cloud Storage Object Discovery | S3/GCS/Blob enumeration |
| T1530 | Data from Cloud Storage | Data theft from cloud storage |
| T1537 | Transfer Data to Cloud Account | Exfil to attacker-controlled cloud |
| T1552.005 | Credentials from Cloud Instance Metadata API | SSRF to metadata endpoints |

### Cloud attack chain example
```
T1190 (Exploit web app with SSRF) 
  → T1552.005 (Access EC2/GCE metadata) 
    → T1078.004 (Use stolen IAM role) 
      → T1580 (Enumerate cloud resources) 
        → T1530 (Exfiltrate from cloud storage)
```

---

## 6. Container ATT&CK

Container and Kubernetes-specific techniques.

### Key container techniques
| Technique ID | Name | K8s/container context |
|--------------|------|---------------------|
| T1610 | Deploy Container | Malicious container deployment |
| T1611 | Escape to Host | Container breakout to node |
| T1613 | Container and Resource Discovery | K8s API enumeration |
| T1552.007 | Container API | Accessing K8s API with exposed credentials |
| T1525 | Implant Internal Image | Compromised container image in registry |
| T1609 | Container Administration Command | Using kubectl exec / docker exec |
| T1053.007 | Scheduled Task: Container Orchestration Job | Malicious CronJobs, Jobs |

### Container attack chain example
```
T1190 (Exploit web app in pod)
  → T1613 (Discover K8s environment via service account token)
    → T1552.007 (Access K8s API)
      → T1610 (Deploy privileged container)
        → T1611 (Escape to host node)
          → T1078.004 (Use node cloud identity)
```

---

## 7. Mobile ATT&CK

Mobile-specific techniques organized into two tactic categories.

### Mobile tactics (differ from Enterprise)
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact
- Network Effects (mobile-specific)
- Remote Service Effects (mobile-specific)

### Key mobile techniques
| Technique ID | Name | Context |
|--------------|------|---------|
| T1475 | Deliver Malicious App via Authorized App Store | Trojan apps in stores |
| T1476 | Deliver Malicious App via Other Means | Sideloading attacks |
| T1456 | Drive-by Compromise | Mobile browser exploits |
| T1474 | Supply Chain Compromise | Malicious SDKs |
| T1418 | Application Discovery | Enumerating installed apps |
| T1409 | Stored Application Data | Extracting app data |
| T1417 | Input Capture | Keyloggers, overlay attacks |
| T1411 | Input Prompt | Phishing via fake prompts |
| T1429 | Audio Capture | Microphone access |
| T1414 | Clipboard Data | Reading clipboard |
| T1422 | System Network Configuration Discovery | Network info |
| T1533 | Data from Local System | Mobile device data |
| T1646 | Exfiltration Over C2 Channel | Data exfil |

---

## 8. ATT&CK for ICS

Industrial Control Systems matrix for operational technology environments.

### ICS-specific tactics (beyond Enterprise)
- Impair Process Control
- Inhibit Response Function

### When ICS ATT&CK is relevant
- Manufacturing environments
- Utilities (power, water, gas)
- Transportation systems
- Building automation
- Medical devices in clinical settings

Most web audits don't touch ICS, but mentioned for completeness. If the target environment includes OT/ICS components, additional specialized assessment is needed beyond the web audit scope.

---

## 9. MITRE D3FEND

D3FEND is the defensive counterpart to ATT&CK — a knowledge graph of defensive countermeasures.

### D3FEND tactics (defensive)
| Tactic | Purpose |
|--------|---------|
| Harden | Pre-attack hardening (configuration, patching) |
| Detect | Observe attacker activity |
| Isolate | Contain attackers after detection |
| Deceive | Mislead attackers (honeypots, canaries) |
| Evict | Remove attackers from environment |
| Restore | Recover from incidents |
| Model | Understand the system being defended |

### D3FEND-ATT&CK mapping
Each ATT&CK technique can be mapped to D3FEND countermeasures that prevent, detect, or respond to it. This mapping is invaluable for:
- Writing remediation sections that reference specific defensive techniques
- Designing defense-in-depth strategies
- Identifying detection gaps

Example:
```
ATT&CK T1190 (Exploit Public-Facing Application)
  D3FEND defensive options:
    → D3-IOPR (Input-based Process Restriction)
    → D3-ANAA (Authentication Anomaly Analysis)
    → D3-URA (Unused Resource Attack)
    → D3-SMRA (System Mapping Attack Analysis)
```

---

## 10. Adversary Emulation

ATT&CK enables realistic adversary emulation — testing defenses against specific threat actors or TTPs.

### MITRE ATT&CK Evaluations
Public evaluations of security products against emulated adversaries (APT29, APT3, Carbanak+FIN7, Wizard Spider, Sandworm, Turla).

### Adversary emulation for audits
Instead of random testing, emulate specific threat actors relevant to the target's industry:

| Industry | Relevant threat actors |
|----------|----------------------|
| Financial services | FIN7, Carbanak, Lazarus, FIN11 |
| Healthcare | Ransomware groups (Conti, LockBit, BlackCat), APT41 |
| Government | APT28, APT29, APT41, Turla |
| Energy/utilities | Sandworm, Energetic Bear, Xenotime |
| Technology | APT10, APT41, Lazarus |
| Retail | FIN7, Magecart, FIN6 |
| Defense industrial base | APT28, APT29, APT41 |

### Emulation plan components
1. Select adversary based on target's threat landscape
2. Map their known TTPs from ATT&CK
3. Design test scenarios covering each TTP
4. Execute safely (controlled environment)
5. Measure detection and response
6. Identify gaps

---

## 11. Detection Engineering

ATT&CK-driven detection engineering uses the framework to build and prioritize detections.

### Detection coverage assessment
For each technique in scope:
1. Identify data sources needed to detect it
2. Check if the organization collects those data sources
3. Check if detection logic exists for that technique
4. Test detection effectiveness (can it be bypassed?)
5. Document coverage or gaps

### ATT&CK data sources
Common data sources for web/cloud audits:
| Data Source | Techniques it helps detect |
|-------------|---------------------------|
| Web logs (HTTP access) | T1190, T1595, T1594 |
| Authentication logs | T1078, T1110, T1556 |
| Network traffic | T1071, T1572, T1557 |
| API monitoring | T1190, T1526, T1557 |
| Container logs | T1609, T1610, T1611 |
| Cloud audit logs (CloudTrail, Cloud Audit Logs) | T1078.004, T1580, T1530 |
| DNS logs | T1568, T1071.004 |
| Process monitoring | T1059, T1055 |
| File monitoring | T1505.003, T1027, T1070 |

### ATT&CK Navigator
Use ATT&CK Navigator (attack.mitre.org/navigator) to:
- Visualize technique coverage
- Create layers for different scenarios (current defenses, specific threat actors, detection priorities)
- Compare coverage against adversary TTPs
- Track detection engineering progress

---

## 12. Mapping Findings to ATT&CK

### Finding annotation template
For each security finding, add ATT&CK context:

```
ATT&CK mapping:
  - Tactic(s): [e.g., TA0001 Initial Access, TA0006 Credential Access]
  - Technique(s): [e.g., T1190 Exploit Public-Facing Application]
  - Sub-technique(s): [e.g., T1110.004 Credential Stuffing]
  - Enables downstream techniques: [list of techniques this finding enables]
  - Defensive mitigations (D3FEND): [relevant defensive countermeasures]
```

### Attack chain annotation
For attack chains, map each step to ATT&CK:

```
Attack chain: [name]
Steps:
1. T1595 (Active Scanning) — attacker discovers exposed endpoints
2. T1190 (Exploit Public-Facing App) — SQLi on /api/search
3. T1003 (Credential Dumping) — extract user password hashes
4. T1078 (Valid Accounts) — crack and use admin credentials
5. T1213 (Data from Information Repositories) — access sensitive data
Final impact: TA0010 Exfiltration — T1567 (Exfiltration Over Web Service)
```

### Benefits of ATT&CK mapping
- Speaks the language of SOC teams and threat intel
- Enables finding-to-detection-to-response traceability
- Supports executive communication about adversary behavior
- Integrates with SIEM correlation rules and playbooks
- Links findings to specific defensive capabilities

---

## 13. ATT&CK Assessment Checklist

```
Threat-Informed Defense:
[ ] Target's threat landscape identified (relevant threat actors)
[ ] Priority TTPs mapped for target industry
[ ] Detection coverage assessed against priority TTPs
[ ] Defensive gaps identified and prioritized

Finding Mapping:
[ ] All findings mapped to ATT&CK tactics and techniques
[ ] Attack chains include full technique sequences
[ ] Downstream techniques identified (what this finding enables)
[ ] Mappings used for communication with blue team / SOC

Detection Engineering:
[ ] Data sources for priority techniques available
[ ] Detection rules written for priority techniques
[ ] Detection coverage gaps documented
[ ] Regular validation of detection effectiveness

Adversary Emulation:
[ ] Relevant threat actors identified
[ ] TTP mapping completed for emulation
[ ] Safe emulation plan documented
[ ] Purple team exercises scheduled

Documentation:
[ ] ATT&CK Navigator layer maintained for current coverage
[ ] Mitigations (D3FEND) mapped to defensive controls
[ ] Threat intelligence integrated with ATT&CK taxonomy
[ ] Incident reports reference ATT&CK consistently
```

---

## Using ATT&CK in Remediation Recommendations

When writing remediation advice, reference both ATT&CK (the threat) and D3FEND (the defense):

**Example finding:** SQL injection in search endpoint

**Remediation framed with ATT&CK/D3FEND:**
```
This finding maps to ATT&CK T1190 (Exploit Public-Facing Application). 

Exploitation enables downstream techniques:
- T1005 (Data from Local System)
- T1003 (OS Credential Dumping) if DB has stored credentials
- T1059 (Command and Scripting Interpreter) if RCE achievable via SQLi

Defensive countermeasures (D3FEND):
- D3-IOPR (Input-based Process Restriction) — parameterized queries
- D3-DENCR (Data Encryption) — encrypt sensitive data at rest
- D3-ANAA (Authentication Anomaly Analysis) — detect unusual DB query patterns
- D3-CA (Code Analysis) — SAST for injection patterns

This framing connects technical remediation to broader defense-in-depth
and detection improvements.
```
