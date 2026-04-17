# Risk Management Frameworks

This reference covers risk management frameworks used to quantify, prioritize, and communicate security findings. Use these to move beyond subjective severity ratings and provide defensible risk assessments.

## Table of Contents
1. [NIST Risk Management Framework (RMF)](#1-nist-rmf)
2. [NIST Cybersecurity Framework (CSF 2.0)](#2-nist-csf-20)
3. [FAIR (Factor Analysis of Information Risk)](#3-fair)
4. [ISO 31000 Risk Management](#4-iso-31000)
5. [CVSS (Common Vulnerability Scoring System)](#5-cvss)
6. [Risk Rating Methodology](#6-risk-rating-methodology)
7. [Mapping Findings to Risk Frameworks](#7-mapping-findings)

---

## 1. NIST RMF

The NIST Risk Management Framework (SP 800-37) provides a structured process for managing organizational risk. Use it to frame recommendations in the remediation plan.

### RMF steps
| Step | Activity | Audit relevance |
|------|---------|----------------|
| Prepare | Establish context, risk tolerance, roles | Use to understand the organization's risk appetite during scoping |
| Categorize | Classify system by impact (FIPS 199: low/moderate/high) | Determines required security controls and audit depth |
| Select | Choose security controls (SP 800-53) | Reference specific controls in remediation recommendations |
| Implement | Deploy selected controls | Assess whether controls are actually implemented |
| Assess | Evaluate control effectiveness | Core of the security audit — are controls working? |
| Authorize | Risk-based decision to operate | Help the user understand residual risk for authorization decisions |
| Monitor | Ongoing surveillance | Recommend continuous monitoring improvements |

### NIST SP 800-53 control families (select relevant ones)
| Family | ID | Relevance |
|--------|----|-----------|
| Access Control | AC | Authorization, least privilege, session management |
| Audit & Accountability | AU | Logging, monitoring, non-repudiation |
| Configuration Management | CM | Hardening, change control, baseline configs |
| Identification & Authentication | IA | Auth mechanisms, MFA, credential management |
| Incident Response | IR | Detection, response, recovery procedures |
| Risk Assessment | RA | Vulnerability scanning, threat assessment |
| System & Communications Protection | SC | Encryption, network segmentation, boundary protection |
| System & Information Integrity | SI | Patching, malware protection, input validation |

Reference specific SP 800-53 control IDs in remediation for organizations that follow NIST.

---

## 2. NIST CSF 2.0

The Cybersecurity Framework 2.0 organizes security activities into six functions. Use to structure remediation recommendations at the organizational level.

### CSF 2.0 functions
| Function | Purpose | Key categories |
|----------|---------|---------------|
| **Govern** (GV) | Establish and oversee cybersecurity strategy | Risk strategy, roles/responsibilities, policy, oversight, supply chain risk |
| **Identify** (ID) | Understand assets, risks, and business context | Asset management, risk assessment, improvement |
| **Protect** (PR) | Safeguard against threats | Identity management, access control, awareness/training, data security, platform security, technology resilience |
| **Detect** (DE) | Discover cybersecurity events | Continuous monitoring, adverse event analysis |
| **Respond** (RS) | Take action on detected events | Incident management, analysis, mitigation, reporting, communication |
| **Recover** (RC) | Restore capabilities | Recovery planning, communication |

### Using CSF in reporting
Map structural remediation recommendations to CSF functions. Example: "Missing rate limiting" maps to PR (Protect) → Platform Security. "No audit logging" maps to DE (Detect) → Continuous Monitoring.

---

## 3. FAIR

Factor Analysis of Information Risk provides quantitative risk analysis. Use when the user needs business-case justification for remediation investments.

### FAIR ontology (simplified)
```
Risk = Loss Event Frequency × Loss Magnitude

Loss Event Frequency = Threat Event Frequency × Vulnerability
  - Threat Event Frequency = Contact Frequency × Probability of Action
  - Vulnerability = Difficulty × Threat Capability (gap between them)

Loss Magnitude = Primary Loss + Secondary Loss
  - Primary: productivity, response, replacement, fines
  - Secondary: reputation, competitive advantage, legal liability
```

### Applying FAIR to audit findings
For Critical/High findings, provide a FAIR-informed risk narrative:

```
Finding: [Title]
Threat event frequency: [How often would an attacker attempt this?]
  - Contact frequency: [How exposed is the attack surface?]
  - Probability of action: [Would an attacker bother?]
Vulnerability: [How likely is exploitation to succeed?]
  - Difficulty: [What controls exist?]
  - Threat capability: [What skill/resources does the attacker need?]
Loss magnitude estimate:
  - Primary: [Direct costs — incident response, remediation, downtime]
  - Secondary: [Indirect — reputation, regulatory, legal]
Annualized loss estimate: [Rough order of magnitude — $K, $M, etc.]
```

This helps engineering leaders prioritize remediation by business impact rather than abstract severity labels.

---

## 4. ISO 31000

ISO 31000 provides principles and guidelines for risk management applicable to any organization. Use its structure to frame the audit's risk assessment approach.

### ISO 31000 risk management process
| Step | Activity | Audit application |
|------|---------|------------------|
| Scope, context, criteria | Define external/internal context, risk criteria, risk appetite | Understand during scoping — what level of risk is acceptable? |
| Risk identification | Find, recognize, describe risks | Phases 1-3 of the audit — discover vulnerabilities and threats |
| Risk analysis | Understand risk nature, likelihood, consequences | Phase 4 — chain analysis, severity rating, impact assessment |
| Risk evaluation | Compare against risk criteria, prioritize | Phase 5 — cross-review, severity calibration |
| Risk treatment | Select and implement treatments | Phase 6 — remediation plan with options: avoid, mitigate, transfer, accept |
| Monitoring and review | Track effectiveness of treatments | Recommend ongoing monitoring in structural remediation |
| Communication and consultation | Engage stakeholders throughout | The report itself, plus recommended communication approach |

### Risk treatment options
When writing remediation plans, classify each recommendation:
| Treatment | Meaning | Example |
|-----------|---------|---------|
| Avoid | Eliminate the risk source | Remove the feature, disable the endpoint |
| Mitigate | Reduce likelihood or impact | Add auth, input validation, rate limiting |
| Transfer | Shift risk to third party | Insurance, managed WAF, bug bounty program |
| Accept | Acknowledge and monitor | Low-severity issues with compensating controls |

---

## 5. CVSS

The Common Vulnerability Scoring System v4.0 provides standardized vulnerability scoring. Use to assign quantitative scores alongside severity labels.

### CVSS v4.0 base metrics
| Metric Group | Metrics |
|-------------|---------|
| Exploitability | Attack Vector (AV), Attack Complexity (AC), Attack Requirements (AT), Privileges Required (PR), User Interaction (UI) |
| Vulnerable System Impact | Confidentiality (VC), Integrity (VI), Availability (VA) |
| Subsequent System Impact | Confidentiality (SC), Integrity (SI), Availability (SA) |

### CVSS score to severity mapping
| Score range | Severity |
|------------|---------|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

### When to calculate CVSS
- Always for Critical and High findings
- Optionally for Medium findings
- Not necessary for Low/Informational

### CVSS vector string format
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

Include the CVSS vector string in findings when applicable — it provides a standardized, reproducible severity assessment that external teams can validate.

---

## 6. Risk Rating Methodology

Combine qualitative severity with quantitative risk factors for defensible prioritization.

### Risk matrix
```
                    Impact
                Low    Med    High   Critical
Likelihood
  High       | Med  | High | Crit | Crit  |
  Medium     | Low  | Med  | High | Crit  |
  Low        | Info | Low  | Med  | High  |
  Very Low   | Info | Info | Low  | Med   |
```

### Likelihood factors
| Factor | Questions |
|--------|----------|
| Attack surface exposure | Is this internet-facing? Requires auth? |
| Exploit complexity | Does this need special tools/knowledge? |
| Detection likelihood | Would exploitation be noticed? |
| Attacker motivation | Is the data/access valuable enough to target? |
| Existing controls | Are there compensating controls reducing likelihood? |

### Impact factors
| Factor | Questions |
|--------|----------|
| Data sensitivity | What data is exposed? PII? Financial? Health? |
| Scope of breach | Single user or all users? |
| Regulatory implications | GDPR/HIPAA/PCI penalties? |
| Business disruption | Revenue impact? Operational impact? |
| Reputation damage | Would this make the news? |

---

## 7. Mapping Findings

Every finding should include risk framework mappings where applicable.

### Finding risk annotation template
```
Risk framework mappings:
  - OWASP Top 10: [A01–A10]
  - OWASP API Top 10: [API1–API10] (if API finding)
  - CVSS v4.0: [vector string] → [score]
  - NIST SP 800-53: [control family/ID]
  - NIST CSF 2.0: [function.category]
  - Risk rating: [Likelihood × Impact matrix result]
  - FAIR estimate: [annualized loss order of magnitude]
```

Not every mapping is needed for every finding — use the relevant ones. Critical/High findings should have CVSS and at least two framework mappings. Medium findings need at least OWASP mapping. Low/Info need only the OWASP category.
