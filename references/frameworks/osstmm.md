# OSSTMM — Open Source Security Testing Methodology Manual

This reference covers OSSTMM, a peer-reviewed methodology for security testing and measurement maintained by ISECOM (Institute for Security and Open Methodologies). Use OSSTMM when you need quantifiable, reproducible security measurements that go beyond subjective severity ratings — particularly for operational security assessment, trust analysis, and scientific security metrics.

## Table of Contents
1. [OSSTMM Overview](#1-osstmm-overview)
2. [Core Concepts](#2-core-concepts)
3. [The Five Channels](#3-the-five-channels)
4. [OSSTMM Testing Types](#4-osstmm-testing-types)
5. [Operational Security Metrics](#5-operational-security-metrics)
6. [RAV — Risk Assessment Value](#6-rav--risk-assessment-value)
7. [The 17 Modules](#7-the-17-modules)
8. [Trust Analysis](#8-trust-analysis)
9. [Rules of Engagement](#9-rules-of-engagement)
10. [STAR — Security Test Audit Report](#10-star--security-test-audit-report)
11. [OSSTMM vs Other Frameworks](#11-osstmm-vs-other-frameworks)
12. [Applying OSSTMM to Web Audits](#12-applying-osstmm-to-web-audits)
13. [OSSTMM Checklist](#13-osstmm-checklist)

---

## 1. OSSTMM Overview

OSSTMM differs from OWASP, NIST, and ISO in a key way: it focuses on **operational security measurement** — what you can actually observe and quantify about how secure a system is, rather than checking whether it matches a list of controls.

### Current version
| Version | Year | Notes |
|---------|------|-------|
| OSSTMM 3 | 2010 | Current widely-used version |
| OSSTMM 4 | In development / limited release | Extended metrics, updated channels |

### What makes OSSTMM different
| Traditional approach | OSSTMM approach |
|---------------------|-----------------|
| "Does the control exist?" | "How effective is the operational security?" |
| Subjective severity (High/Med/Low) | Quantifiable RAV score (0-100%) |
| Checklist compliance | Scientific measurement |
| "What's broken?" | "What's the measurable security posture?" |
| Output: list of findings | Output: measured security balance |

### Core philosophy
OSSTMM emphasizes:
- **Scientific method** — measurements must be reproducible
- **Factual observation** — tests produce facts, not opinions
- **Measurable security** — security can and should be quantified
- **Trust is a security metric** — trust levels between entities are measurable
- **Operational focus** — what the system does, not what the documentation says

---

## 2. Core Concepts

### The OSSTMM security model

Security is defined as the separation between an asset and any threat. Three factors create this separation:

| Factor | Definition | Example |
|--------|-----------|---------|
| **Porosity** | The interactions that expose the asset | Open ports, public APIs, accessible UI, exposed data |
| **Controls** | Mechanisms that protect the asset despite porosity | Auth, encryption, input validation, monitoring |
| **Limitations** | Weaknesses that reduce control effectiveness | Vulnerabilities, misconfigurations, bypass paths |

### Operational security equation
```
Actual Security = Porosity + Controls - Limitations
```

When measured over a target, this produces the **Actual Security RAV** score.

### The three states of porosity
| State | Definition |
|-------|-----------|
| Visibility | The asset can be seen/identified |
| Access | The asset can be reached/interacted with |
| Trust | The asset is implicitly trusted by another asset |

All three contribute to porosity but have different security implications.

---

## 3. The Five Channels

OSSTMM defines five channels through which interactions occur. A complete security assessment considers all relevant channels.

| Channel | Scope | Example targets |
|---------|-------|----------------|
| **Human** | People-based interactions | Social engineering, phishing, impersonation, insider threats |
| **Physical** | Tangible, non-electronic | Facilities, hardware, documents, badges, locks |
| **Wireless** | Electromagnetic spectrum | WiFi, Bluetooth, RFID, cellular, NFC |
| **Telecommunications** | Voice and signaling networks | PBX, SIP/VoIP, cellular voice, fax |
| **Data Networks** | Wired digital communications | Internet, intranet, web apps, APIs, cloud services |

### Channel selection for web audits
Most web audits focus primarily on the Data Networks channel, but comprehensive assessments should consider:

| Web audit scenario | Channels to include |
|-------------------|-------------------|
| Standard web app audit | Data Networks |
| Web app + social engineering | Data Networks + Human |
| Web app + office network | Data Networks + Wireless + Physical |
| Full enterprise assessment | All five |
| IoT / smart device assessment | Data Networks + Wireless + Physical |

---

## 4. OSSTMM Testing Types

OSSTMM defines six testing types based on attacker knowledge and target awareness:

| Type | Attacker knowledge | Target awareness | Name |
|------|-------------------|-----------------|------|
| 1 | Zero knowledge | Unaware | **Blind** |
| 2 | Zero knowledge | Aware | **Double Blind** |
| 3 | Full knowledge | Unaware | **Gray Box** |
| 4 | Full knowledge | Aware | **Double Gray Box** |
| 5 | Limited knowledge | Aware | **Tandem** |
| 6 | Full knowledge | Fully informed & cooperating | **Reversal** |

### Practical implications
| Test type | Most useful for |
|-----------|----------------|
| Blind | Baseline security posture, external attacker simulation |
| Double Blind | Realistic red team, testing detection capabilities |
| Gray Box | Efficient vulnerability discovery with some knowledge |
| Double Gray Box | Standard collaborative security assessment |
| Tandem | Internal team validation |
| Reversal | Process improvement, training exercises |

Most web security audits in practice fall into Gray Box or Double Gray Box categories.

---

## 5. Operational Security Metrics

OSSTMM quantifies security through measurable operational values. Each channel is assessed using the same metric framework.

### Porosity metrics (OpSec)
Measurable aspects of what's exposed:

| Metric | Abbreviation | What it measures |
|--------|-------------|-----------------|
| Visibility | PV | Count of assets that can be identified |
| Access | PA | Count of assets that can be interacted with |
| Trust | PT | Count of trust relationships between assets |

**Porosity total (OpSec) = Visibility + Access + Trust**

### Controls metrics
Measurable protective mechanisms. OSSTMM defines 10 loss controls organized into two classes.

**Class A — Interactive Controls (direct interaction prevention):**
| Control | What it prevents |
|---------|-----------------|
| Authentication | Unauthorized identification |
| Indemnification | Liability from interactions |
| Resilience | Single point of failure |
| Subjugation | Forced interaction |
| Continuity | Service interruption |

**Class B — Process Controls (response to interactions):**
| Control | What it provides |
|---------|------------------|
| Non-Repudiation | Accountability for actions |
| Confidentiality | Protection of information content |
| Privacy | Protection of information source/subject |
| Integrity | Protection against tampering |
| Alarm | Notification of problems |

Each control is measured per interactive point (per port, per API endpoint, per feature).

### Limitations metrics
Measurable weaknesses:

| Limitation | What it represents |
|-----------|-------------------|
| Vulnerability | Flaw that permits unauthorized access or denies authorized access |
| Weakness | Flaw that reduces control effectiveness |
| Concern | Flaw that reduces process control effectiveness |
| Exposure | Unjustifiable action creating visibility |
| Anomaly | Unidentifiable element that cannot be accounted for |

---

## 6. RAV — Risk Assessment Value

The RAV is OSSTMM's unique contribution: a calculated score representing operational security balance.

### RAV properties
- Expressed as a percentage from 0 to 100%+ (yes, can exceed 100% with overlapping controls)
- 100% represents "perfect balance" — porosity fully compensated by controls with no limitations
- Below 100% means porosity exceeds controls (insecure balance)
- Above 100% means controls exceed porosity (over-engineered or defense-in-depth)

### RAV interpretation
| RAV score | Meaning |
|-----------|---------|
| 100% | Perfect operational balance |
| 90-99% | Strong security posture with minor gaps |
| 70-89% | Reasonable security with identified gaps |
| 50-69% | Significant gaps, prioritize remediation |
| < 50% | Major security deficit, systemic issues |

### Calculation approach (simplified)
```
RAV = 100 × (Controls Sum / (Porosity + Limitations))
```

The actual RAV calculation is more complex and involves:
1. Counting interactive points per channel
2. Measuring each OpSec dimension (V, A, T)
3. Counting each control type per interactive point
4. Counting each limitation by type
5. Normalizing and computing the balance

ISECOM provides spreadsheets and calculators to perform the actual calculation reliably.

### Why RAV matters for audits
- **Before/after measurement** — quantify improvement after remediation
- **Comparable across systems** — compare two systems with the same metric
- **Trend tracking** — monitor security posture over time
- **Executive communication** — single number easier to communicate than lists
- **Benchmarking** — compare against industry peers

---

## 7. The 17 Modules

OSSTMM organizes testing into 17 modules. Each module covers specific aspects of security testing. Not all modules apply to every audit — select based on scope.

### Channel-independent modules
| Module | Focus |
|--------|-------|
| Posture Review | Legal and regulatory landscape affecting the target |
| Logistics | Verification of scope, communication, documentation |
| Active Detection Verification | Testing whether detection mechanisms work |
| Visibility Audit | Determining what can be identified about the target |
| Access Verification | Determining what can be interacted with |
| Trust Verification | Identifying trust relationships and their boundaries |
| Controls Verification | Testing each of the 10 control types |
| Process Verification | Testing security processes under normal conditions |
| Configuration Verification | Testing configurations against documented policies |
| Property Validation | Verifying intellectual property protection |
| Segregation Review | Testing separation of duties, environments |
| Exposure Verification | Identifying unjustifiable visibility |
| Competitive Intelligence Scouting | Public information gathering |
| Quarantine Verification | Testing isolation of compromised systems |
| Privileges Audit | Testing privilege escalation paths |
| Survivability Validation | Testing recovery capabilities |
| Alert and Log Review | Testing monitoring and alerting |

### Module selection for common audits
| Audit type | Core modules |
|-----------|-------------|
| Web app security | Visibility, Access, Trust, Controls Verification, Configuration, Exposure, Privileges |
| Network pentest | All data network modules |
| Physical security | Physical channel modules |
| Red team exercise | Active Detection, Quarantine, Survivability, Alert/Log Review |
| Compliance audit | Posture Review, Process, Configuration, Segregation |

---

## 8. Trust Analysis

Trust is a distinctive focus of OSSTMM — explicitly measured as a security dimension.

### OSSTMM's 10 trust properties
Trust is evaluated across these measurable properties:

| Property | Question |
|----------|----------|
| Size | How many entities are trusted? |
| Symmetry | Is trust bidirectional? |
| Transparency | Is trust visible/documented? |
| Consistency | Is trust behavior predictable? |
| Integrity | Can trust be verified? |
| Offsets | Are there compensating controls? |
| Value | What does trust enable? |
| Component | Is trust broken into separable parts? |
| Porosity | How much porosity does trust create? |
| Limitations | What limits the trust? |

### Trust analysis for web audits
Apply trust analysis to:
| Target | Trust questions |
|--------|----------------|
| User sessions | What does a session token enable? Is it bounded? |
| API authentication | What does an API key enable? Is it scoped? |
| Third-party integrations | What does the integration trust? Is it verified? |
| Service-to-service | What do internal services assume about callers? |
| Cloud IAM | What does an IAM role trust? Is least privilege applied? |
| Browser same-origin | What does the origin model assume? |
| CORS trust | What origins are trusted, and why? |

### Trust-based findings
Trust analysis often reveals findings that pure vulnerability-based testing misses:
- Over-broad trust that creates risk without being a "vulnerability"
- Implicit trust relationships with no verification
- Trust symmetry assumptions that don't hold
- Trust degradation over time (permissions not revoked, tokens not rotated)

---

## 9. Rules of Engagement

OSSTMM defines strict rules for ethical, scientific testing.

### The OSSTMM rules of engagement
| Rule category | Requirement |
|--------------|-------------|
| Marketing and scoping | No scaremongering, clear scope, written authorization |
| Assessment delivery | Factual reporting, no fabrication, reproducible results |
| Contracts and negotiations | Written agreement, clearly defined scope, legal compliance |
| Scope | Respect boundaries, no unauthorized expansion |
| Test process | Scientific method, minimum impact, documented procedures |
| Reporting | Facts only, no conjecture, all findings disclosed to client |

### Ethical requirements
- Never test without written authorization
- Never cause harm to systems or users
- Disclose all findings to the client, even uncomfortable ones
- Never conceal findings to preserve business relationships
- Report only observed facts, not speculation
- Respect scope strictly — never expand without written approval

These align with the safety rules already defined in this skill's SKILL.md.

---

## 10. STAR — Security Test Audit Report

OSSTMM defines a specific report structure called STAR.

### STAR structure
| Section | Content |
|---------|---------|
| Test type | Which of the 6 test types was performed |
| Test timeline | Start/end dates, duration, tester identity |
| Scope | What was included, explicitly |
| Testing objectives | What was being measured |
| Rules of engagement | Any specific restrictions |
| Metrics | RAV calculation with all measured values |
| Porosity findings | Visibility, Access, Trust counts and details |
| Controls findings | Which controls tested, which passed/failed |
| Limitations findings | Vulnerabilities, weaknesses, concerns, exposures, anomalies |
| Conclusions | Factual summary — no opinion, no speculation |

### STAR vs traditional security reports
| Aspect | STAR | Traditional report |
|--------|------|------------------|
| Severity | Objective metrics | Subjective ratings |
| Findings | Facts only | Facts + analysis |
| Recommendations | Optional, clearly separated | Often mixed with findings |
| Reproducibility | Required (methodology documented) | Often not reproducible |
| Measurement | Quantified RAV | Qualitative summary |

STAR can be combined with traditional reporting — use OSSTMM metrics alongside OWASP/CVSS severity for richer reporting.

---

## 11. OSSTMM vs Other Frameworks

OSSTMM fits alongside other frameworks rather than replacing them:

| Framework | Strength | Weakness |
|-----------|----------|----------|
| **OSSTMM** | Scientific measurement, RAV metric, trust analysis, complete channel coverage | Learning curve, less prescriptive on specific vulnerabilities |
| **OWASP** | Specific vulnerabilities, web-focused depth, community-maintained | Subjective severity, checklist-heavy, narrow scope (primarily web/API/mobile/LLM) |
| **NIST** | Government recognition, comprehensive control catalogs | Documentation-heavy, less about measurement |
| **ISO 27001** | International certification, management system focus | Process-heavy, not testing-focused |
| **PTES** | Pentest-specific methodology | Less emphasis on measurement, narrower than OSSTMM |
| **NIST SP 800-115** | Technical testing guide | Less rigorous measurement than OSSTMM |

### Complementary use
Best practice: combine frameworks for comprehensive coverage.

| Phase | Primary framework | Supplement with |
|-------|------------------|----------------|
| What to test for | OWASP Top 10, WSTG | OSSTMM modules |
| How to measure | OSSTMM RAV | CVSS for individual findings |
| Compliance mapping | ISO, SOC, PCI | OSSTMM for operational measurement |
| Threat modeling | STRIDE, ATT&CK | OSSTMM trust analysis |
| Severity rating | CVSS | OSSTMM limitations classification |

---

## 12. Applying OSSTMM to Web Audits

Here's how to practically apply OSSTMM to a standard web security audit:

### Step 1: Define scope in OSSTMM terms
Instead of just listing URLs, define:
- **Channel(s)** in scope (typically Data Networks; add Human if social engineering is authorized)
- **Test type** (usually Double Gray Box for commercial audits)
- **Target surface** — what interactive points exist (ports, endpoints, UI elements)

### Step 2: Measure porosity
For each in-scope target:
- **Visibility** — count what can be identified (hostnames, services, endpoints, technologies)
- **Access** — count what can be interacted with (reachable endpoints, available methods, accessible features)
- **Trust** — identify trust relationships (SSO providers, API integrations, CDN trust, cookie domains)

### Step 3: Test controls
For each interactive point, verify each of the 10 controls:
| Control | Web audit test |
|---------|---------------|
| Authentication | Does authentication exist? Is it enforced? |
| Indemnification | Are ToS, privacy policy, logging in place for liability? |
| Resilience | Is there redundancy, rate limiting, DDoS protection? |
| Subjugation | Can the user be forced into actions (CSRF, clickjacking)? |
| Continuity | Is there monitoring of availability? |
| Non-Repudiation | Are actions attributable? (audit logs) |
| Confidentiality | Is data encrypted in transit/at rest? |
| Privacy | Is user data protected beyond just confidentiality? |
| Integrity | Is data tamper-protected? |
| Alarm | Are security events detected and alerted? |

### Step 4: Identify limitations
For each control that's incomplete or bypassable, classify:
- Vulnerability (allows unauthorized actions)
- Weakness (reduces control effectiveness)
- Concern (process-level issue)
- Exposure (unjustifiable visibility)
- Anomaly (unexplained behavior)

### Step 5: Calculate RAV
Using ISECOM's calculation method or tools, compute the RAV for the target.

### Step 6: Integrate with existing audit output
Add OSSTMM measurements to the standard audit report:
- Overall RAV score in the executive summary
- Per-channel RAV if multiple channels tested
- Trust analysis findings alongside traditional findings
- Porosity metrics as part of attack surface documentation

### Example RAV integration in report
```
## Executive Summary

### Security Posture Measurement (OSSTMM RAV)
- Overall RAV: 73%
- Data Networks channel: 73%
  - Porosity (exposed surface): 47 interactive points
  - Controls implemented: 68% of expected
  - Limitations identified: 23 (3 vulnerabilities, 12 weaknesses, 8 concerns)

Interpretation: Security posture is reasonable but has significant gaps,
particularly in Non-Repudiation (insufficient audit logging) and Alarm
(limited security event monitoring). Addressing the 3 vulnerabilities
and improving logging would raise RAV to ~88%.
```

---

## 13. OSSTMM Checklist

```
Scoping:
[ ] Channel(s) explicitly defined (Human, Physical, Wireless, Telecoms, Data Networks)
[ ] Test type documented (Blind through Reversal)
[ ] Rules of engagement written and agreed
[ ] Legal authorization in place

Porosity Measurement:
[ ] Visibility — all identifiable assets cataloged
[ ] Access — all reachable/interactive points cataloged
[ ] Trust — all trust relationships mapped

Controls Verification:
[ ] Authentication tested per interactive point
[ ] Indemnification verified (ToS, logging, contracts)
[ ] Resilience tested (redundancy, rate limits)
[ ] Subjugation tested (forced-action attacks)
[ ] Continuity verified (availability monitoring)
[ ] Non-Repudiation verified (audit trails)
[ ] Confidentiality tested (encryption, data protection)
[ ] Privacy verified (data subject protections)
[ ] Integrity tested (tamper protection)
[ ] Alarm verified (alerting, monitoring)

Limitations Classification:
[ ] Vulnerabilities categorized
[ ] Weaknesses categorized
[ ] Concerns categorized
[ ] Exposures categorized
[ ] Anomalies documented

Trust Analysis:
[ ] Trust relationships identified
[ ] Trust properties evaluated (size, symmetry, transparency, etc.)
[ ] Trust-based findings included

Reporting:
[ ] RAV calculated and documented
[ ] STAR report structure followed (or integrated into primary report)
[ ] Facts separated from recommendations
[ ] Methodology reproducible
[ ] All findings disclosed to client
```

---

## Mapping Findings to OSSTMM

Include OSSTMM context in findings when operational measurement adds value:

### Finding OSSTMM annotation template
```
OSSTMM mapping:
  - Channel: [Human / Physical / Wireless / Telecoms / Data Networks]
  - Porosity impact: [Visibility / Access / Trust — what this exposes]
  - Control class: [Which of the 10 controls is missing/inadequate]
  - Limitation type: [Vulnerability / Weakness / Concern / Exposure / Anomaly]
  - RAV impact: [How remediation would affect the overall score]
```

### When to use OSSTMM mapping
OSSTMM mapping is most valuable for:
- Audits where quantifiable improvement is important (before/after measurement)
- Mature security programs wanting rigorous metrics
- Multi-system comparisons
- Operational security assessment (vs pure vulnerability discovery)
- Situations where traditional severity ratings feel inadequate or disputed

Simpler audits may not need OSSTMM annotation — use judgment based on audit goals.
