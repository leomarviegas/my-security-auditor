# ISO Information & Cyber Security Standards

This reference covers ISO standards relevant to information security, cybersecurity, and privacy. Use these to frame findings and remediation in terms of internationally recognized controls and compliance requirements.

## Table of Contents
1. [ISO 27001 — Information Security Management System](#1-iso-27001)
2. [ISO 27002 — Security Controls](#2-iso-27002)
3. [ISO 27005 — Information Security Risk Management](#3-iso-27005)
4. [ISO 27017 — Cloud Security Controls](#4-iso-27017)
5. [ISO 27018 — PII Protection in Public Cloud](#5-iso-27018)
6. [ISO 27034 — Application Security](#6-iso-27034)
7. [ISO 27701 — Privacy Information Management](#7-iso-27701)
8. [ISO 27035 — Incident Management](#8-iso-27035)
9. [ISO 27032 — Cybersecurity Guidelines](#9-iso-27032)
10. [Mapping Findings to ISO Controls](#10-mapping-findings)

---

## 1. ISO 27001

The core ISMS (Information Security Management System) standard. Provides the management framework for establishing, implementing, maintaining, and improving information security.

### Annex A control themes (2022 edition)
ISO 27001:2022 reorganized controls into four themes:

| Theme | Controls | Coverage |
|-------|---------|----------|
| Organizational (5.x) | 37 controls | Policies, roles, threat intelligence, asset management, access control policy, supplier relations, compliance, BCM |
| People (6.x) | 8 controls | Screening, terms of employment, awareness, disciplinary, post-employment, remote work, reporting |
| Physical (7.x) | 14 controls | Security perimeters, physical entry, offices, monitoring, utilities, cabling, equipment, disposal, clear desk |
| Technological (8.x) | 34 controls | User endpoints, privileged access, information access restriction, source code, authentication, capacity, malware, vulnerability management, logging, network security, web filtering, cryptography, SDLC, testing, separation, change management, data masking, DLP, monitoring, redundancy |

### Key Annex A controls for web audit findings
| Control | ID | Maps to audit area |
|---------|----|--------------------|
| Access control policy | 5.15 | Authorization findings |
| Identity management | 5.16 | Authentication findings |
| Authentication information | 5.17 | Password/credential findings |
| Access rights | 5.18 | Privilege management findings |
| Information access restriction | 8.3 | IDOR, data exposure findings |
| Secure authentication | 8.5 | Auth mechanism findings |
| Protection against malware | 8.7 | Upload/injection findings |
| Management of technical vulnerabilities | 8.8 | All vulnerability findings |
| Configuration management | 8.9 | Security misconfiguration findings |
| Information deletion | 8.10 | Data retention findings |
| Data masking | 8.11 | PII exposure findings |
| Data leakage prevention | 8.12 | Data exposure findings |
| Monitoring activities | 8.16 | Logging/monitoring findings |
| Web filtering | 8.23 | SSRF, external request findings |
| Use of cryptography | 8.24 | Encryption/TLS findings |
| Secure development lifecycle | 8.25 | SDLC maturity findings |
| Application security requirements | 8.26 | Missing security requirements |
| Security testing in development | 8.29 | Testing gap findings |
| Separation of environments | 8.31 | Dev/prod separation findings |
| Change management | 8.32 | Deployment security findings |

---

## 2. ISO 27002

The detailed controls guide — provides implementation guidance for each control in Annex A. Reference specific 27002 sections when writing remediation.

### Control attributes (new in 2022)
Each control has five attributes useful for categorizing findings:

| Attribute | Values |
|-----------|--------|
| Control type | Preventive, Detective, Corrective |
| Information security properties | Confidentiality, Integrity, Availability |
| Cybersecurity concepts | Identify, Protect, Detect, Respond, Recover |
| Operational capabilities | Governance, Asset management, Information protection, HR security, Physical security, System/network security, Application security, Secure configuration, Identity/access management, Threat/vulnerability management, Continuity, Supplier relationships, Legal/compliance, Information security event management, Information security assurance |
| Security domains | Governance and ecosystem, Protection, Defence, Resilience |

Use these attributes to enrich findings with implementation context.

---

## 3. ISO 27005

Risk management specific to information security. Complements ISO 31000 with infosec-specific guidance.

### Risk assessment process
| Phase | Activities |
|-------|-----------|
| Context establishment | Define scope, risk criteria, impact scales, risk acceptance levels |
| Risk identification | Identify assets → threats → vulnerabilities → existing controls → consequences |
| Risk analysis | Assess likelihood × impact, consider qualitative and quantitative methods |
| Risk evaluation | Compare against risk criteria, rank and prioritize |
| Risk treatment | Apply controls from ISO 27002, document residual risk, get acceptance |

### Risk acceptance criteria
Help the user define or apply these:
- Maximum acceptable risk level per category (technical, business, compliance)
- Cost-benefit threshold for remediation
- Timeline expectations for different risk levels
- Escalation triggers for unacceptable risk

---

## 4. ISO 27017

Cloud-specific security controls — extends ISO 27002 for cloud environments.

### Additional cloud controls
| Area | Cloud-specific guidance |
|------|----------------------|
| Shared responsibility | Clearly define which security controls are customer vs provider responsibility |
| Virtual machine hardening | Secure cloud compute instances, image management, snapshot protection |
| Cloud admin operations | Privileged access management in cloud consoles, API key security |
| Multi-tenancy | Logical isolation, resource segregation, cross-tenant data protection |
| Cloud asset management | Inventory of cloud resources, tagging, lifecycle management |
| Cloud network security | Virtual network configuration, security groups, NACLs, WAF rules |
| Cloud data security | Encryption at rest and transit, key management, data residency, data deletion verification |
| Cloud monitoring | Cloud-native logging (CloudTrail, Cloud Audit Logs), cloud SIEM integration |
| Cloud incident response | Cloud-specific IR procedures, provider notification requirements |

---

## 5. ISO 27018

PII protection in public cloud. Apply when the target processes personal data in cloud environments.

### Key principles
| Principle | Requirement |
|-----------|------------|
| Consent and choice | PII processed only with data subject consent or legal basis |
| Purpose legitimacy | PII used only for stated purposes |
| Collection limitation | Minimal PII collected |
| Data minimization | Only process PII necessary for the purpose |
| Use, retention, disclosure | Limits on how PII is used, how long it's kept, who sees it |
| Transparency | Clear privacy notices, processing documentation |
| Individual participation | Data subject access, correction, deletion rights |
| Accountability | Documented policies, breach notification, privacy impact assessments |

### Audit relevance
Check whether the target:
- Exposes PII unnecessarily in API responses
- Stores PII without encryption
- Lacks data deletion mechanisms
- Has unclear or missing privacy documentation
- Processes PII without apparent legal basis

---

## 6. ISO 27034

Application security throughout the lifecycle. Use to frame SDLC-related recommendations.

### Application Security Controls (ASCs)
| Lifecycle phase | Security activities |
|----------------|-------------------|
| Requirements | Security requirements specification, risk analysis, compliance requirements |
| Design | Threat modeling, security architecture review, secure design patterns |
| Development | Secure coding standards, code review, SAST integration |
| Testing | DAST, penetration testing, fuzzing, security regression testing |
| Deployment | Hardened configuration, secrets management, environment validation |
| Operations | Monitoring, incident response, vulnerability management, patching |
| Disposal | Secure decommissioning, data destruction, access revocation |

### Organization Normative Framework (ONF)
ISO 27034 defines an ONF — a library of security controls applicable across applications. Recommend the user establish:
- A catalog of approved security controls per application risk level
- Minimum security baselines for different application types
- Verification procedures for each control
- Metrics for measuring application security maturity

---

## 7. ISO 27701

Privacy Information Management System — extends ISO 27001 for privacy. Apply when GDPR, LGPD, or other privacy regulations are relevant.

### Additional controls for PII controllers
| Control area | Requirements |
|-------------|------------|
| Conditions for collection | Legal basis, consent management, purpose specification |
| Obligations to PII principals | Right of access, correction, deletion, portability, objection |
| Privacy by design | Data minimization, pseudonymization, privacy defaults |
| PII sharing | Third-party agreements, cross-border transfer controls |
| Breach notification | Timely notification to authorities and data subjects |

### Additional controls for PII processors
| Control area | Requirements |
|-------------|------------|
| Processing conditions | Process only per controller instructions |
| Sub-processing | Transparency, equivalent security requirements |
| Data transfer | Location restrictions, adequacy requirements |
| Breach notification | Notify controller without undue delay |

---

## 8. ISO 27035

Information security incident management. Use to assess and recommend incident response capabilities.

### Incident management phases
| Phase | Activities | What to assess |
|-------|-----------|---------------|
| Plan and prepare | IR policies, team, playbooks, communication plans | Does the organization have IR procedures? |
| Detection and reporting | Monitoring, alerting, reporting channels | Are security events detectable? Are there logging gaps? |
| Assessment and decision | Triage, classification, escalation | Can the team assess and prioritize incidents? |
| Response | Containment, eradication, recovery | Are response procedures defined? |
| Lessons learned | Post-incident review, improvement | Is there a feedback loop? |

---

## 9. ISO 27032

Cybersecurity guidelines — bridges information security, network security, internet security, and critical infrastructure protection.

### Cybersecurity framework elements
| Element | Coverage |
|---------|----------|
| Stakeholder roles | Consumers, providers, carriers, regulators, response teams |
| Asset types | Personal, organizational, digital, and service assets |
| Threat landscape | Social engineering, malware, hacking, insider threats, supply chain |
| Controls | Application security, server protection, end-user education, network monitoring, SIEM, cyber insurance |
| Information sharing | ISACs, threat intelligence sharing, coordinated disclosure |

---

## 10. Mapping Findings to ISO Controls

Include ISO control mappings in findings that affect organizations seeking or maintaining ISO certification.

### Finding ISO annotation template
```
ISO mappings:
  - ISO 27001 Annex A: [control ID and name]
  - ISO 27002 section: [section number]
  - ISO 27002 attributes:
    - Control type: [Preventive/Detective/Corrective]
    - Security properties: [CIA triad]
    - Cybersecurity concept: [Identify/Protect/Detect/Respond/Recover]
  - Additional ISO standards: [27017/27018/27034/27701 if applicable]
```

### Quick-reference mapping
| Finding type | Primary ISO control |
|-------------|-------------------|
| Broken auth | 8.5 Secure authentication |
| Access control bypass | 8.3 Information access restriction |
| Injection/XSS | 8.26 Application security requirements |
| Missing encryption | 8.24 Use of cryptography |
| Data exposure | 8.12 Data leakage prevention |
| Missing logging | 8.16 Monitoring activities |
| Insecure config | 8.9 Configuration management |
| Unpatched components | 8.8 Management of technical vulnerabilities |
| Missing SDLC | 8.25 Secure development lifecycle |
| Upload vulnerabilities | 8.26 Application security requirements |
| Privacy violation | ISO 27701 applicable controls |
| Cloud misconfiguration | ISO 27017 applicable controls |
