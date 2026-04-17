# PCI-DSS (Payment Card Industry Data Security Standard)

This reference covers PCI-DSS v4.0.1 assessment. Apply when the target organization stores, processes, or transmits cardholder data, or affects the security of cardholder data environments (CDE).

## Table of Contents
1. [PCI-DSS Overview](#1-pci-dss-overview)
2. [Scoping the CDE](#2-scoping-the-cde)
3. [Validation Types](#3-validation-types)
4. [Self-Assessment Questionnaires (SAQs)](#4-self-assessment-questionnaires)
5. [The 12 Requirements — Detailed](#5-the-12-requirements)
6. [Testing Procedures](#6-testing-procedures)
7. [Compensating Controls](#7-compensating-controls)
8. [Customized Approach (v4.0 New)](#8-customized-approach)
9. [Merchant and Service Provider Levels](#9-merchant-and-service-provider-levels)
10. [Common Compliance Gaps](#10-common-compliance-gaps)
11. [Mapping Findings to PCI-DSS](#11-mapping-findings-to-pci-dss)
12. [PCI-DSS Checklist](#12-pci-dss-checklist)

---

## 1. PCI-DSS Overview

PCI-DSS is maintained by the PCI Security Standards Council (PCI SSC) and required by the major card brands (Visa, Mastercard, American Express, Discover, JCB) for any organization that handles payment cards.

### Current version
| Version | Status | Notes |
|---------|--------|-------|
| v4.0 | Active | Initial v4 release |
| v4.0.1 | Current | Minor update, current standard |
| v3.2.1 | Retired (March 2024) | Previous standard |

### Who must comply
| Entity type | Must comply if |
|-------------|---------------|
| Merchant | Accepts, processes, or transmits payment cards |
| Service provider | Stores, processes, transmits, or could affect security of cardholder data on behalf of another entity |
| Payment processor | Core processing of payment transactions |
| Acquirer/Issuer | Financial institutions handling card data |

### What data is in scope
| Data element | PCI-DSS treatment |
|-------------|-----------------|
| Primary Account Number (PAN) | Cardholder data — full PCI scope |
| Cardholder name | Cardholder data (when associated with PAN) |
| Expiration date | Cardholder data (when associated with PAN) |
| Service code | Cardholder data (when associated with PAN) |
| Full track data | Sensitive authentication data — cannot be stored post-authorization |
| CAV2/CVC2/CVV2/CID | Sensitive authentication data — cannot be stored post-authorization |
| PIN/PIN block | Sensitive authentication data — cannot be stored post-authorization |

### PAN handling rules
- Full PAN visible: only to those with business need
- PAN at rest: must be rendered unreadable (encryption, truncation, hashing, tokenization)
- PAN displayed: mask by default (first six and last four digits maximum visible)
- PAN transmitted: strong cryptography on open/public networks

---

## 2. Scoping the CDE

Proper scoping determines what's subject to PCI-DSS. Over-scoping wastes resources; under-scoping creates compliance gaps.

### Cardholder Data Environment (CDE)
The CDE includes:
- Systems that store, process, or transmit cardholder data
- Systems that provide security services to CDE systems
- Systems connected to the CDE (in-scope but may be out with segmentation)

### In-scope categories
| Category | Description | Treatment |
|----------|------------|-----------|
| CDE | Systems handling CHD directly | Full PCI-DSS requirements |
| Connected-to CDE | Systems that could impact CDE security | Full PCI-DSS requirements unless segmented |
| Supporting CDE | Systems providing security services to CDE | Full PCI-DSS requirements |
| Out-of-scope | Isolated from CDE | No PCI-DSS requirements |

### Network segmentation
Segmentation is not required by PCI-DSS but dramatically reduces scope. For segmentation to reduce scope, it must:
- Isolate CDE from other networks
- Prevent connectivity that could compromise CDE
- Be tested at least annually (service providers: every 6 months)

### Scoping assessment questions
1. Where is payment card data entered, processed, stored, or transmitted?
2. What systems handle this data?
3. What systems are connected to those systems?
4. What systems provide services (AD, DNS, logging, monitoring) to CDE systems?
5. Where could data leakage occur?

---

## 3. Validation Types

| Type | Who performs | Required for |
|------|-------------|--------------|
| Report on Compliance (ROC) | QSA (Qualified Security Assessor) | Level 1 merchants, Level 1 service providers |
| Self-Assessment Questionnaire (SAQ) | Internal assessment | Levels 2-4 merchants based on criteria |
| Attestation of Compliance (AOC) | Accompanies both ROC and SAQ | All |

### Qualified Security Assessor (QSA)
- Company authorized by PCI SSC to perform PCI-DSS assessments
- Individual QSAs must be employed by a QSA Company
- ISA (Internal Security Assessor) — company-employed assessors trained by PCI SSC

---

## 4. Self-Assessment Questionnaires

There are multiple SAQ types based on how the merchant accepts and handles card data:

| SAQ | Applies to |
|-----|-----------|
| SAQ A | Card-not-present merchants that fully outsource all card data handling |
| SAQ A-EP | E-commerce merchants with partial outsourcing where merchant website can impact card data security |
| SAQ B | Merchants using only imprint machines or standalone dial-out terminals, no electronic cardholder data storage |
| SAQ B-IP | Merchants using only standalone, PTS-approved payment terminals with IP connection, no electronic cardholder data storage |
| SAQ C-VT | Merchants using only web-based virtual payment terminals, no electronic cardholder data storage |
| SAQ C | Merchants with payment application systems connected to internet, no electronic cardholder data storage |
| SAQ P2PE | Merchants using only PCI-listed P2PE validated payment terminals, no electronic cardholder data storage |
| SAQ D (Merchant) | All other merchants not included in above descriptions |
| SAQ D (Service Provider) | Service providers eligible to complete SAQ |
| SAQ SPoC | Merchants using SPoC-validated solution |

### How to determine the right SAQ
1. How is cardholder data accepted? (website redirect, iframe, form post, direct processing)
2. Is any cardholder data stored electronically?
3. Are payment applications present?
4. What processing method is used?

---

## 5. The 12 Requirements

PCI-DSS organizes controls into 12 requirements across 6 control objectives.

### Build and Maintain a Secure Network and Systems

#### Requirement 1: Install and maintain network security controls
| Sub-requirement | Focus |
|----------------|-------|
| 1.1 | Processes and mechanisms for installing network security controls |
| 1.2 | Network security controls (NSCs) are configured and maintained |
| 1.3 | Network access to and from the CDE is restricted |
| 1.4 | Network connections between trusted and untrusted networks are controlled |
| 1.5 | Risks from computing devices connecting to both untrusted networks and CDE are mitigated |

**Key controls:**
- Firewall/NSC rules documented with business justification
- Default deny policy
- Annual review of rules
- DMZ between public networks and internal systems
- Restricted outbound connections from CDE

#### Requirement 2: Apply secure configurations
| Sub-requirement | Focus |
|----------------|-------|
| 2.1 | Processes and mechanisms for applying secure configurations |
| 2.2 | System components are configured and managed securely |
| 2.3 | Wireless environments are configured and managed securely |

**Key controls:**
- Remove default vendor credentials
- Remove unnecessary services, accounts, functionality
- Configuration standards based on industry-accepted hardening (CIS, NIST)
- Inventory of system components
- Secure wireless configurations

### Protect Account Data

#### Requirement 3: Protect stored account data
| Sub-requirement | Focus |
|----------------|-------|
| 3.1 | Processes and mechanisms for protecting stored account data |
| 3.2 | Storage of account data is kept to a minimum |
| 3.3 | Sensitive authentication data (SAD) is not stored after authorization |
| 3.4 | Access to displays of full PAN and ability to copy cardholder data are restricted |
| 3.5 | PAN is secured wherever stored |
| 3.6 | Cryptographic keys used to protect stored account data are secured |
| 3.7 | Where cryptography is used to protect stored account data, key management processes are defined and implemented |

**Key controls:**
- Data retention and disposal policies
- Never store SAD post-authorization (track data, CVV, PIN)
- PAN masking on displays (show only first 6 + last 4)
- PAN rendered unreadable (encryption, truncation, tokenization, hashing)
- Strong cryptography (AES-256, RSA 2048+, ECC 224+)
- Key management (generation, distribution, storage, rotation, destruction)

#### Requirement 4: Protect cardholder data with strong cryptography during transmission
| Sub-requirement | Focus |
|----------------|-------|
| 4.1 | Processes and mechanisms for protecting cardholder data during transmission |
| 4.2 | PAN is protected with strong cryptography during transmission |

**Key controls:**
- Strong cryptography (TLS 1.2+, with TLS 1.3 preferred)
- Never send unprotected PAN via email, IM, SMS, chat
- Certificate validation
- Certificate inventory

### Maintain a Vulnerability Management Program

#### Requirement 5: Protect all systems and networks from malicious software
| Sub-requirement | Focus |
|----------------|-------|
| 5.1 | Processes and mechanisms for protecting from malicious software |
| 5.2 | Malicious software (malware) is prevented or detected and addressed |
| 5.3 | Anti-malware mechanisms and processes are active, maintained, and monitored |
| 5.4 | Anti-phishing mechanisms protect users |

#### Requirement 6: Develop and maintain secure systems and software
| Sub-requirement | Focus |
|----------------|-------|
| 6.1 | Processes and mechanisms for developing and maintaining secure systems and software |
| 6.2 | Bespoke and custom software are developed securely |
| 6.3 | Security vulnerabilities are identified and addressed |
| 6.4 | Public-facing web applications are protected against attacks |
| 6.5 | Changes to all system components are managed securely |

**Key controls:**
- Patch management (critical within 1 month)
- Secure coding practices (OWASP, SANS CWE)
- Code review (for public-facing apps, either code review or WAF required)
- Public-facing web app protection: automated technical solution (WAF) OR manual/automated vuln assessments
- Change control with testing and approval
- Separate dev/test/prod environments

### Implement Strong Access Control Measures

#### Requirement 7: Restrict access to system components and cardholder data by business need to know
| Sub-requirement | Focus |
|----------------|-------|
| 7.1 | Processes and mechanisms for restricting access by business need to know |
| 7.2 | Access to system components and data is appropriately defined and assigned |
| 7.3 | Access to system components and data is managed via an access control system(s) |

**Key controls:**
- Documented access control policy
- Least privilege access
- Role-based access with documented roles
- Default deny
- Access rights reviewed periodically

#### Requirement 8: Identify users and authenticate access to system components
| Sub-requirement | Focus |
|----------------|-------|
| 8.1 | Processes and mechanisms for identifying users and authenticating access |
| 8.2 | User identification and related accounts for users and administrators are strictly managed throughout an account's lifecycle |
| 8.3 | Strong authentication for users and administrators is established and managed |
| 8.4 | Multi-factor authentication (MFA) is implemented to secure access into the CDE |
| 8.5 | MFA systems are configured to prevent misuse |
| 8.6 | Use of application and system accounts and associated authentication factors is strictly managed |

**Key controls:**
- Unique user IDs (no shared accounts)
- Strong passwords/passphrases (12+ chars as of v4)
- MFA for all non-console access to CDE
- MFA for all remote access (admin and users)
- Session timeout (15 min idle)
- Account lockout after 10 failed attempts

#### Requirement 9: Restrict physical access to cardholder data
| Sub-requirement | Focus |
|----------------|-------|
| 9.1 | Processes and mechanisms for restricting physical access |
| 9.2 | Physical access controls manage entry into facilities and systems containing cardholder data |
| 9.3 | Physical access for personnel and visitors is authorized and managed |
| 9.4 | Media with cardholder data is securely stored, accessed, distributed, and destroyed |
| 9.5 | Point-of-interaction (POI) devices are protected from tampering and unauthorized substitution |

### Regularly Monitor and Test Networks

#### Requirement 10: Log and monitor all access to system components and cardholder data
| Sub-requirement | Focus |
|----------------|-------|
| 10.1 | Processes and mechanisms for logging and monitoring all access |
| 10.2 | Audit logs are implemented to support the detection of anomalies and suspicious activity, and the forensic analysis of events |
| 10.3 | Audit logs are protected from destruction and unauthorized modifications |
| 10.4 | Audit logs are reviewed to identify anomalies or suspicious activity |
| 10.5 | Audit log history is retained and available for analysis |
| 10.6 | Time-synchronization mechanisms support consistent time settings across all systems |
| 10.7 | Failures of critical security control systems are detected, reported, and responded to promptly |

**Key controls:**
- Log all access to cardholder data
- Log all admin actions
- Log authentication attempts (success and failure)
- Log 12+ months, with 3 months immediately available
- Daily log review (can be automated)
- Log integrity protection
- NTP synchronization

#### Requirement 11: Test security of systems and networks regularly
| Sub-requirement | Focus |
|----------------|-------|
| 11.1 | Processes and mechanisms for regularly testing security |
| 11.2 | Wireless access points are identified and monitored, and unauthorized ones are addressed |
| 11.3 | External and internal vulnerabilities are regularly identified, prioritized, and addressed |
| 11.4 | External and internal penetration testing is regularly performed, and exploitable vulnerabilities and security weaknesses are corrected |
| 11.5 | Network intrusions and unexpected file changes are detected and responded to |
| 11.6 | Unauthorized changes on payment pages are detected and responded to |

**Key controls:**
- Quarterly internal vulnerability scans
- Quarterly external scans by ASV (Approved Scanning Vendor)
- Annual pen testing (external and internal)
- Pen test after significant changes
- IDS/IPS for CDE traffic
- File integrity monitoring
- Change detection on payment pages (new in v4)

### Maintain an Information Security Policy

#### Requirement 12: Support information security with organizational policies and programs
| Sub-requirement | Focus |
|----------------|-------|
| 12.1 | A comprehensive information security policy that governs and provides direction for protection of the entity's information assets is known and current |
| 12.2 | Acceptable use policies for end-user technologies are defined and implemented |
| 12.3 | Risks to the cardholder data environment are formally identified, evaluated, and managed |
| 12.4 | PCI-DSS compliance is managed |
| 12.5 | PCI-DSS scope is documented and validated |
| 12.6 | Security awareness education is an ongoing activity |
| 12.7 | Personnel are screened to reduce risks from insider threats |
| 12.8 | Risk to information assets associated with third-party service provider (TPSP) relationships is managed |
| 12.9 | Third-party service providers support their customers' PCI-DSS compliance |
| 12.10 | Suspected and confirmed security incidents that could impact the CDE are responded to immediately |

---

## 6. Testing Procedures

Each PCI-DSS requirement has specific testing procedures. The QSA/assessor must:

### Testing approaches
| Method | Description |
|--------|------------|
| Observation | Watch processes being performed |
| Interview | Discuss with personnel |
| Documentation review | Examine policies, procedures, evidence |
| Examination | Inspect configurations, logs, systems |
| Sampling | Test a representative sample of systems/records |

### Sampling for PCI-DSS
Unlike SOC 2, PCI-DSS sampling is more prescriptive:
- Business facility types
- System component types
- Application types
- Location types
- Sample size must be justified

---

## 7. Compensating Controls

When a PCI-DSS requirement cannot be met as specified, compensating controls may be acceptable.

### Compensating control requirements
A compensating control must:
1. Meet the intent and rigor of the original requirement
2. Provide a similar level of defense
3. Be above and beyond other PCI-DSS requirements (can't reuse existing requirements)
4. Be commensurate with the risk imposed by not meeting the requirement

### Compensating Control Worksheet (CCW)
For each compensating control, document:
- Constraints (why the requirement cannot be met)
- Objective (what the original requirement aims to achieve)
- Identified Risk (risk from not meeting the requirement)
- Definition of Compensating Controls (what they are)
- Validation of Compensating Controls (how they meet the original intent)
- Maintenance (how they'll be kept in place)

### Common compensating control scenarios
- Legacy systems that can't support MFA (compensate with network isolation + monitoring)
- Inability to encrypt specific data (compensate with strict access control + DLP)
- Delayed patching (compensate with compensating controls + monitoring)

---

## 8. Customized Approach

PCI-DSS v4.0 introduced the "Customized Approach" as an alternative to the "Defined Approach":

### Defined Approach
- Follow the specific requirements and testing procedures as written
- Most organizations use this

### Customized Approach
- Meet the Customized Approach Objective stated in the requirement
- Design controls that meet that objective
- Document in detail (Controls Matrix and Targeted Risk Analysis)
- Validated by QSA
- Suitable for organizations with mature security programs

### When to use Customized Approach
- Organization has innovative security controls that meet objectives differently
- Traditional implementation doesn't fit architecture
- Risk-based approach preferred
- Mature security program with documentation

---

## 9. Merchant and Service Provider Levels

### Merchant levels
| Level | Criteria | Validation |
|-------|---------|-----------|
| 1 | >6M transactions/year (Visa/MC), or any merchant identified as L1 by brand | Annual ROC by QSA/ISA, quarterly ASV scans |
| 2 | 1M-6M transactions/year | Annual SAQ D or ROC, quarterly ASV scans |
| 3 | 20K-1M e-commerce transactions/year | Annual SAQ, quarterly ASV scans |
| 4 | <20K e-commerce or <1M total | Annual SAQ, quarterly ASV scans |

### Service provider levels
| Level | Criteria | Validation |
|-------|---------|-----------|
| 1 | >300K transactions/year | Annual ROC by QSA, quarterly ASV scans |
| 2 | <300K transactions/year | Annual SAQ D (Service Provider) or ROC |

---

## 10. Common Compliance Gaps

These are the most frequently cited PCI-DSS gaps in real assessments:

### Top gap areas
| Gap | Requirement | Why it's common |
|-----|------------|----------------|
| Insufficient log monitoring | Req 10.4 | Daily log review requires effort and tooling |
| Missing FIM on critical files | Req 11.5 | FIM deployment often incomplete |
| Inadequate patch management | Req 6.3 | Especially for less critical systems |
| MFA not everywhere | Req 8.4/8.5 | Legacy systems often missing MFA |
| Incomplete network documentation | Req 1.2 | Architecture evolves faster than documentation |
| Missing segmentation testing | Req 11.4 | Testing is specific and technical |
| Default credentials still present | Req 2.2 | Legacy systems, IoT devices, embedded systems |
| Stored SAD (CVV, track data) | Req 3.3 | Discovered in unexpected places (logs, backups) |
| Inadequate vendor management | Req 12.8 | Complex to maintain across many vendors |
| Weak change management | Req 6.5 | Emergency changes often bypass controls |

---

## 11. Mapping Findings to PCI-DSS

When auditing organizations subject to PCI-DSS, map findings to specific requirements:

### Finding annotation template
```
PCI-DSS mappings:
  - Requirement(s): [e.g., Req 3.5, Req 4.2]
  - Sub-requirement(s): [specific sub-requirement]
  - Scope: [CDE / Connected-to-CDE / Out-of-scope]
  - Compliance impact: [Compliance violation / Risk to compliance / Best practice gap]
  - Recommendation: [Defined approach / Customized approach / Compensating control]
```

### Quick-reference mapping
| Finding type | PCI-DSS requirement(s) |
|-------------|----------------------|
| SQL injection | 6.2.3, 6.2.4 (secure coding), 6.4 (public-facing app protection) |
| XSS | 6.2.3, 6.2.4, 6.4 |
| Missing TLS | 4.2.1 |
| Weak TLS config | 4.2.1, 2.2.7 |
| Default credentials | 2.2.2 |
| Missing MFA | 8.4, 8.5 |
| Insufficient password policy | 8.3 |
| Missing rate limiting / account lockout | 8.3.4 |
| Stored CVV | 3.3.1 — CRITICAL VIOLATION |
| Unmasked PAN display | 3.4 |
| Unencrypted stored PAN | 3.5 |
| Missing logging | 10.2 |
| Missing log review | 10.4 |
| IDOR / authorization bypass | 7.2, 7.3 |
| Exposed admin panel | 1.3, 7.2 |
| Missing WAF on payment page | 6.4 |
| Unauthorized payment page changes undetected | 11.6 (new in v4) |
| Missing patching | 6.3.3 |
| Missing vulnerability scanning | 11.3 |
| Missing pen testing | 11.4 |
| Insufficient network segmentation | 1.3, 1.4 |
| Unauthorized third-party scripts on payment pages | 6.4.3 (new in v4) |

### v4.0 new requirements to highlight
Several requirements new in v4.0 are frequent findings:

| Requirement | What's new |
|------------|-----------|
| 6.4.3 | Script management on payment pages (effective March 2025) |
| 11.6.1 | Change and tamper detection for payment pages (effective March 2025) |
| 8.3.10.1 | Passphrase requirements for customer passwords |
| 12.3.1 | Targeted risk analysis for customized approach |
| 3.5.1.2 | Disk-level encryption requirements tightened |
| 5.4.1 | Anti-phishing mechanisms (effective March 2025) |

---

## 12. PCI-DSS Checklist

```
Scoping:
[ ] CDE boundaries documented
[ ] Cardholder data flow diagrams current
[ ] Network diagrams show all CDE connections
[ ] Segmentation validated (if claimed)
[ ] Annual scope validation

Requirement 1 (Network Security):
[ ] Firewall/NSC rules documented
[ ] Default deny policy
[ ] Rules reviewed every 6 months
[ ] DMZ architecture
[ ] Restricted outbound from CDE

Requirement 2 (Configuration):
[ ] No default credentials
[ ] Hardening standards documented and applied
[ ] Unnecessary services/functions removed
[ ] System inventory maintained

Requirement 3 (Stored Data):
[ ] No SAD stored post-authorization
[ ] PAN masking on displays
[ ] PAN encrypted at rest
[ ] Key management documented
[ ] Retention and disposal policy

Requirement 4 (Transmission):
[ ] TLS 1.2+ everywhere
[ ] No unprotected PAN in email/IM/SMS
[ ] Certificate management

Requirement 5 (Malware):
[ ] Anti-malware deployed and current
[ ] Anti-phishing mechanisms (v4)

Requirement 6 (Secure Development):
[ ] Patching SLA defined and met
[ ] Secure coding practices
[ ] Code review or WAF for public-facing apps
[ ] Change management process
[ ] Script management on payment pages (v4 6.4.3)

Requirement 7 (Access Control):
[ ] Least privilege enforced
[ ] Documented roles
[ ] Access reviews

Requirement 8 (Authentication):
[ ] Unique user IDs
[ ] Strong passwords/passphrases
[ ] MFA for CDE access
[ ] MFA for remote access
[ ] Session timeout 15 min

Requirement 9 (Physical):
[ ] Physical access controls
[ ] Media disposal
[ ] POI device protection

Requirement 10 (Logging):
[ ] Comprehensive audit logging
[ ] Log retention 12+ months
[ ] Daily log review
[ ] Log integrity
[ ] Time synchronization

Requirement 11 (Testing):
[ ] Quarterly internal vuln scans
[ ] Quarterly ASV external scans
[ ] Annual internal and external pen testing
[ ] Segmentation testing
[ ] IDS/IPS deployment
[ ] File integrity monitoring
[ ] Payment page tamper detection (v4 11.6)

Requirement 12 (Policy):
[ ] Information security policy
[ ] Risk assessment program
[ ] Scope documentation
[ ] Security awareness training
[ ] Vendor management program
[ ] Incident response plan
[ ] Incident response testing
```

---

## Industry Context

PCI-DSS often overlaps with other frameworks. Use cross-mapping to save effort:

| Area | PCI-DSS | ISO 27001 | SOC 2 | NIST 800-53 |
|------|---------|-----------|-------|-------------|
| Access control | Req 7, 8 | A.5.15-A.5.18, A.8.3 | CC6 | AC family |
| Encryption | Req 3, 4 | A.8.24 | CC6.1, CC6.7 | SC-8, SC-13 |
| Logging | Req 10 | A.8.15, A.8.16 | CC7.2 | AU family |
| Change management | Req 6.5 | A.8.32 | CC8.1 | CM family |
| Incident response | Req 12.10 | A.5.24-A.5.28 | CC7.3, CC7.4 | IR family |
| Vulnerability management | Req 6.3, 11.3 | A.8.8 | CC7.1, CC7.5 | RA-5, SI-2 |
| Vendor management | Req 12.8, 12.9 | A.5.19-A.5.22 | CC9.2 | SA family |

Organizations with multiple compliance obligations should build unified controls that satisfy all applicable frameworks.
