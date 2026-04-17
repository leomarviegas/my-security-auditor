# SOC Auditing (SOC 1, SOC 2, SOC 3)

This reference covers Service Organization Control (SOC) auditing frameworks defined by the AICPA. Use when the target organization is preparing for, maintaining, or evaluating SOC compliance, or when findings need to be framed in SOC control language for audit readiness.

## Table of Contents
1. [SOC Audit Types Overview](#1-soc-audit-types-overview)
2. [SOC 1 — ICFR](#2-soc-1--icfr)
3. [SOC 2 — Trust Services Criteria](#3-soc-2--trust-services-criteria)
4. [SOC 3 — General Use Report](#4-soc-3--general-use-report)
5. [Type 1 vs Type 2 Audits](#5-type-1-vs-type-2-audits)
6. [Trust Services Criteria Detailed](#6-trust-services-criteria-detailed)
7. [Common Criteria (CC) Mapping](#7-common-criteria-mapping)
8. [Control Testing Methodology](#8-control-testing-methodology)
9. [Evidence Collection](#9-evidence-collection)
10. [Audit Readiness Assessment](#10-audit-readiness-assessment)
11. [SOC vs Other Frameworks](#11-soc-vs-other-frameworks)
12. [SOC Audit Checklist](#12-soc-audit-checklist)

---

## 1. SOC Audit Types Overview

The AICPA defines three types of SOC reports, each serving different audiences and purposes.

| Report Type | Purpose | Audience | Based On |
|-------------|---------|----------|----------|
| SOC 1 | Financial controls at service organizations | User auditors, financial stakeholders | SSAE 18 / ISAE 3402 |
| SOC 2 | Security, availability, confidentiality, processing integrity, privacy | Business partners, customers, regulators | Trust Services Criteria (TSC) |
| SOC 3 | Public-facing trust report | General public, marketing | Same TSC as SOC 2 but summarized |

### When each report is needed
| Scenario | Required report |
|----------|----------------|
| Service processes financial data affecting client reporting | SOC 1 |
| SaaS vendor needs to prove security to enterprise clients | SOC 2 |
| Company wants public trust seal on website | SOC 3 |
| Healthcare service provider | SOC 2 + HIPAA alignment |
| Payment processor | SOC 1 + PCI DSS |
| Cloud infrastructure provider | SOC 2 (often all 5 TSC) |

---

## 2. SOC 1 — ICFR

SOC 1 focuses on Internal Controls over Financial Reporting (ICFR). Applicable when a service organization's processes could affect their customers' financial statements.

### SOC 1 scope areas
| Area | Example controls |
|------|-----------------|
| Transaction processing | Authorization, completeness, accuracy, validity, cutoff |
| Financial data integrity | Reconciliations, approvals, segregation of duties |
| Access to financial systems | User provisioning, privileged access, termination |
| Change management (financial systems) | Testing, approvals, deployment controls |
| Data backup and recovery | Backup schedules, restore testing, retention |
| Computer operations | Job scheduling, batch processing, error handling |

### SOC 1 audit relevance for security auditors
When auditing a service organization for security purposes, identify any systems that process, store, or transmit data that could affect client financial reporting. These become in-scope for SOC 1.

---

## 3. SOC 2 — Trust Services Criteria

SOC 2 is the most common SOC report for technology companies. It evaluates controls against the AICPA Trust Services Criteria (TSC).

### The five Trust Services Categories
| Category | Abbreviation | Required? | Focus |
|----------|-------------|-----------|-------|
| Security | CC (Common Criteria) | **Always required** | Protection against unauthorized access |
| Availability | A | Optional | System uptime and accessibility |
| Processing Integrity | PI | Optional | Complete, valid, accurate, timely, authorized processing |
| Confidentiality | C | Optional | Protection of confidential information |
| Privacy | P | Optional | Personal information handling per AICPA Privacy Management Framework |

Most SOC 2 reports cover **Security only** or **Security + Availability**. Full five-category audits are less common but more thorough.

### Scope selection guidance
| Service type | Recommended categories |
|-------------|----------------------|
| B2B SaaS (general) | Security |
| Infrastructure/hosting | Security + Availability |
| Processing user-uploaded data | Security + Availability + Confidentiality |
| Healthcare / finance SaaS | Security + Availability + Confidentiality + Processing Integrity |
| Consumer platforms handling PII | Security + Privacy |
| Full enterprise trust | All five categories |

---

## 4. SOC 3 — General Use Report

SOC 3 is a summary report of the SOC 2 audit, intended for public distribution. It uses the same criteria as SOC 2 but omits detailed control testing results.

### SOC 3 characteristics
- Does not include the detailed "Description of System" section
- Does not include the detailed "Tests of Controls" section
- Can be publicly posted (website, marketing materials)
- Often used as a trust seal / badge
- Requires same underlying audit work as SOC 2

### When to recommend SOC 3
- Company wants public-facing trust signal
- Marketing-oriented compliance positioning
- Alongside SOC 2 (can't have SOC 3 without SOC 2 audit)

---

## 5. Type 1 vs Type 2 Audits

Both SOC 1 and SOC 2 come in two types:

| Type | Scope | Duration | What it proves |
|------|-------|----------|---------------|
| Type 1 | Point-in-time assessment | Single date | Controls are designed appropriately |
| Type 2 | Period assessment | Typically 6-12 months | Controls operated effectively over time |

### Practical differences
| Aspect | Type 1 | Type 2 |
|--------|--------|--------|
| Evidence required | Current state of controls | Evidence across the entire observation period |
| Sampling | Current point in time | Population-based sampling throughout period |
| Value to clients | Lower — shows design only | Higher — shows sustained operation |
| First-time audits | Often start here | Typically follow a Type 1 |
| Timeline | Weeks to months | 6-12 month observation + audit period |

### Progression path
Most organizations follow: Type 1 → Type 2 (first year) → Type 2 annual recurring

---

## 6. Trust Services Criteria Detailed

The AICPA 2017 Trust Services Criteria (updated periodically) defines the controls each category requires.

### Common Criteria (CC) — Required for all SOC 2 reports
The Common Criteria are organized into nine categories, aligned with COSO Internal Control framework:

| CC Category | Name | Focus |
|-------------|------|-------|
| CC1 | Control Environment | Governance, ethics, board oversight, organizational structure |
| CC2 | Communication and Information | Internal/external communication of security objectives |
| CC3 | Risk Assessment | Risk identification, analysis, fraud risk, change management |
| CC4 | Monitoring Activities | Ongoing and separate evaluations, deficiency communication |
| CC5 | Control Activities | Policies and procedures for achieving objectives |
| CC6 | Logical and Physical Access Controls | Access management, authentication, physical security |
| CC7 | System Operations | Threat detection, incident response, backup/recovery |
| CC8 | Change Management | System change authorization, testing, approval |
| CC9 | Risk Mitigation | Vendor management, business disruption risk |

### Availability (A) category
| Criterion | Focus |
|-----------|-------|
| A1.1 | Performance capacity to meet availability commitments |
| A1.2 | Environmental protections, backup, recovery, infrastructure |
| A1.3 | Recovery plan testing |

### Processing Integrity (PI) category
| Criterion | Focus |
|-----------|-------|
| PI1.1 | Obtains quality information to support processing |
| PI1.2 | Inputs are complete, accurate, and timely |
| PI1.3 | Processing is complete, accurate, and timely |
| PI1.4 | Outputs are complete, accurate, timely, and distributed appropriately |
| PI1.5 | Stored data is complete, accurate, and protected |

### Confidentiality (C) category
| Criterion | Focus |
|-----------|-------|
| C1.1 | Confidential information is protected during collection, use, retention, disclosure, and disposal |
| C1.2 | Disposal of confidential information |

### Privacy (P) category
Based on AICPA Privacy Management Framework with 8 principles:
| Principle | Focus |
|-----------|-------|
| P1 | Notice and communication |
| P2 | Choice and consent |
| P3 | Collection |
| P4 | Use, retention, and disposal |
| P5 | Access |
| P6 | Disclosure and notification |
| P7 | Quality |
| P8 | Monitoring and enforcement |

---

## 7. Common Criteria Mapping

### CC6: Logical and Physical Access Controls (most relevant for technical audits)
| Sub-criterion | Focus | Maps to audit findings |
|---------------|-------|----------------------|
| CC6.1 | Logical access software, infrastructure, architectures to protect information | Access control findings |
| CC6.2 | New internal and external users registered and authorized prior to access | User provisioning, onboarding controls |
| CC6.3 | Access rights updated and removed based on role changes or termination | Access reviews, offboarding |
| CC6.4 | Restrict physical access to facilities and protected information assets | Data center security, office access |
| CC6.5 | Discontinue logical and physical protections over physical assets only after ability to read/recover data has been diminished | Media disposal, data sanitization |
| CC6.6 | Implement logical access security measures to protect against threats from sources outside system boundaries | External access controls, VPN, firewall |
| CC6.7 | Restrict the transmission, movement, and removal of information to authorized users | Data transmission, DLP |
| CC6.8 | Implement controls to prevent or detect and act upon introduction of unauthorized or malicious software | Anti-malware, endpoint protection |

### CC7: System Operations
| Sub-criterion | Focus | Maps to audit findings |
|---------------|-------|----------------------|
| CC7.1 | Detect and monitor configuration changes | Configuration management |
| CC7.2 | Monitor system components and operation for anomalies | Monitoring, alerting |
| CC7.3 | Evaluate security events to determine if they could result in a failure | Incident detection |
| CC7.4 | Respond to identified security incidents | Incident response |
| CC7.5 | Identify and manage known threats to availability | Vulnerability management |

### CC8: Change Management
| Sub-criterion | Focus | Maps to audit findings |
|---------------|-------|----------------------|
| CC8.1 | Authorize, design, develop, document, test, approve, and implement changes | Change management process |

---

## 8. Control Testing Methodology

### Testing approaches
| Method | What it involves | When to use |
|--------|-----------------|-------------|
| Inquiry | Interviews with control owners | Initial understanding, not sufficient alone |
| Observation | Watching control execution | Physical controls, real-time processes |
| Inspection | Reviewing documentation, evidence, configurations | Most common for technical controls |
| Reperformance | Auditor re-executes the control | Highest assurance, most rigorous |

### Sample sizes for Type 2 audits
Typical sampling guidance (auditor judgment applies):

| Population size | Typical sample size |
|----------------|-------------------|
| Population ≤ 25 | 100% (test all) |
| 26-250 | 25 items |
| 251-2500 | 40-60 items |
| 2500+ | 60-80 items |

### Control operating effectiveness testing
For each control, document:
1. Control description
2. Control frequency (continuous, daily, weekly, monthly, annual, on-event)
3. Control owner
4. Testing approach
5. Sample population
6. Sample size
7. Exceptions identified
8. Root cause analysis for exceptions
9. Management response

---

## 9. Evidence Collection

### Common evidence types by control category

**Access controls:**
- User access listings with role assignments
- User provisioning tickets/approvals
- User termination tickets with access revocation timestamps
- Privileged access reviews (quarterly/annual)
- MFA enrollment lists
- Password policy configuration screenshots

**Change management:**
- Change tickets with approvals
- Code review records (pull request approvals)
- Deployment logs
- Rollback records
- Emergency change documentation

**Incident response:**
- Incident tickets with timelines
- Post-incident reviews
- Communication logs
- Resolution documentation

**Monitoring:**
- Alert configuration evidence
- Sample alerts reviewed and actioned
- Monitoring tool screenshots
- Log retention configuration

**Vulnerability management:**
- Vulnerability scan reports
- Remediation tickets with timelines
- Patch management records
- Exception documentation

**Backup and recovery:**
- Backup schedule configuration
- Backup success/failure logs
- Restore test documentation
- Recovery time/point objective validation

### Evidence quality standards
| Attribute | Requirement |
|-----------|------------|
| Authenticity | Verifiable source (screenshots with URLs, direct system exports) |
| Completeness | Covers the entire audit period for Type 2 |
| Sufficient | Enough samples to support conclusion |
| Relevant | Directly supports the control being tested |
| Timely | Generated during or close to the audit period |

---

## 10. Audit Readiness Assessment

When auditing an organization for SOC readiness (pre-audit gap analysis):

### Phase 1: Scoping
- Which services are in scope?
- Which Trust Services Criteria will be included?
- What's the observation period for Type 2?
- Who are the control owners?

### Phase 2: Control inventory
Map the organization's existing controls to Trust Services Criteria. Identify:
- Controls that fully address criteria
- Controls that partially address criteria (design gaps)
- Missing controls (criteria not addressed)

### Phase 3: Gap analysis
For each Trust Services Criterion, assess:

| Gap type | Description | Remediation priority |
|----------|------------|---------------------|
| Missing control | No control exists to address the criterion | Critical — must be addressed before audit |
| Design gap | Control exists but doesn't fully address the criterion | High — redesign required |
| Operational gap | Control is designed appropriately but not operating consistently | High — process improvement required |
| Evidence gap | Control operates but evidence isn't retained | Medium — evidence collection process needed |
| Documentation gap | Control is informal/undocumented | Medium — formalization required |

### Phase 4: Remediation planning
Group gaps by:
- Priority (based on criterion importance and current gap severity)
- Complexity (how long to remediate)
- Owner (who implements the fix)
- Evidence requirements (what evidence needs to be generated)

### Phase 5: Pre-audit validation
Before the external auditor arrives:
- Run a mock audit testing a sample of controls
- Verify evidence is available for the entire observation period
- Ensure control owners can articulate their controls
- Validate that documentation is current

---

## 11. SOC vs Other Frameworks

### Framework comparison
| Framework | Scope | Audit style | Duration |
|-----------|-------|------------|----------|
| SOC 2 | Service organizations, TSC-based | Independent CPA audit | Point-in-time or period |
| ISO 27001 | Any organization, ISMS-based | Accredited certifier | 3-year cycle with surveillance |
| PCI DSS | Payment card data | QSA audit or self-assessment | Annual |
| HIPAA | Healthcare PHI | OCR enforcement, self-assessment | Ongoing |
| FedRAMP | Federal cloud services | 3PAO assessment | Authorization + continuous monitoring |
| NIST 800-53 | US federal systems | Self or third-party | Varies |

### Cross-framework mapping
Many controls satisfy multiple frameworks. Common mappings:

| Control area | SOC 2 | ISO 27001 | NIST 800-53 | PCI DSS |
|-------------|-------|-----------|-------------|---------|
| Access control | CC6.1-CC6.3 | A.5.15-A.5.18, A.8.3 | AC family | Req 7, 8 |
| Encryption | CC6.1, CC6.7 | A.8.24 | SC-8, SC-13, SC-28 | Req 3, 4 |
| Logging | CC7.2 | A.8.15, A.8.16 | AU family | Req 10 |
| Change management | CC8.1 | A.8.32 | CM family | Req 6 |
| Incident response | CC7.3-CC7.4 | A.5.24-A.5.28 | IR family | Req 12.10 |
| Vulnerability management | CC7.1, CC7.5 | A.8.8 | RA-5, SI-2 | Req 6.1, 11.2 |
| Vendor management | CC9.2 | A.5.19-A.5.22 | SA family | Req 12.8 |

### Recommendation to organizations
If pursuing multiple certifications, build controls once and map to all relevant frameworks. A unified control framework saves significant audit effort.

---

## 12. SOC Audit Checklist

```
Scoping:
[ ] SOC type determined (1 vs 2 vs 3)
[ ] Trust Services Categories selected
[ ] Type 1 vs Type 2 decided
[ ] Observation period defined
[ ] System description drafted

Governance (CC1):
[ ] Organizational structure documented
[ ] Security policies approved by leadership
[ ] Roles and responsibilities defined
[ ] Code of conduct exists and is acknowledged
[ ] Board oversight of security program

Risk Assessment (CC3):
[ ] Risk assessment methodology documented
[ ] Annual risk assessment conducted
[ ] Fraud risk considered
[ ] Changes in risk environment tracked
[ ] Risk register maintained

Monitoring (CC4):
[ ] Continuous monitoring controls in place
[ ] Separate evaluations (audits) performed
[ ] Deficiencies communicated to management
[ ] Corrective actions tracked

Access Controls (CC6):
[ ] User provisioning process documented and followed
[ ] Quarterly or more frequent access reviews
[ ] Termination process includes access revocation
[ ] Privileged access separately controlled and monitored
[ ] MFA enforced for all access
[ ] Password policy meets requirements
[ ] Physical access controls (data centers, offices)

System Operations (CC7):
[ ] Monitoring and alerting configured
[ ] Incident response plan documented and tested
[ ] Vulnerability management program with defined SLAs
[ ] Patch management process
[ ] Backup process with restore testing

Change Management (CC8):
[ ] Change management process documented
[ ] Changes require approval before production
[ ] Testing required before deployment
[ ] Emergency change process defined
[ ] Changes tracked in ticketing system

Vendor Management (CC9):
[ ] Vendor inventory maintained
[ ] Vendor risk assessments performed
[ ] Vendor SOC 2 reports collected and reviewed
[ ] Contracts include security requirements

Availability (if in scope):
[ ] Capacity monitoring and management
[ ] Environmental controls (power, cooling, fire)
[ ] Backup and recovery tested periodically
[ ] Business continuity plan documented

Confidentiality (if in scope):
[ ] Data classification scheme
[ ] Data protection controls per classification
[ ] Secure disposal procedures

Evidence Collection:
[ ] Evidence retention policy (typically 1+ year for Type 2)
[ ] Centralized evidence repository
[ ] Control owner identified for each control
[ ] Evidence collected throughout observation period
[ ] Pre-audit walkthrough completed
```

---

## Mapping SOC to Security Findings

When writing findings during a security audit, annotate them with SOC 2 Common Criteria mappings when relevant:

```
SOC 2 mappings:
  - Trust Services Category: [Security / Availability / Confidentiality / etc.]
  - Common Criteria: [CC6.1, CC6.2, etc.]
  - Type 1 vs Type 2 impact: [Design gap / Operational gap]
  - Auditor impact: [Likely to be identified as audit exception / Manageable with compensating controls]
```

This helps organizations preparing for SOC audits understand the audit implications of security findings alongside technical severity.
