# Security Architecture

This reference covers security architecture frameworks, secure design principles, and architectural assessment patterns. Use when evaluating the target's overall security design and providing structural remediation recommendations.

## Table of Contents
1. [SABSA Framework](#1-sabsa-framework)
2. [Defense in Depth](#2-defense-in-depth)
3. [Secure Design Principles](#3-secure-design-principles)
4. [Security Architecture Patterns](#4-security-architecture-patterns)
5. [Threat Modeling Methodologies](#5-threat-modeling-methodologies)
6. [Architecture Assessment](#6-architecture-assessment)
7. [Architecture Review Checklist](#7-architecture-review-checklist)

---

## 1. SABSA Framework

Sherwood Applied Business Security Architecture — a layered framework for enterprise security architecture.

### SABSA layers
| Layer | Perspective | Focus | Audit relevance |
|-------|-----------|-------|----------------|
| Contextual | Business | Business requirements, risk appetite, drivers | Understanding why security controls exist (or should) |
| Conceptual | Architect | Security concepts, principles, policies | Evaluating whether the right security model was chosen |
| Logical | Designer | Security services, mechanisms, processes | Assessing whether controls are logically complete |
| Physical | Builder | Technologies, products, implementations | Testing whether implementations actually work |
| Component | Tradesman | Standards, configurations, procedures | Checking configuration details and hardening |
| Operational | Facility manager | Operations, monitoring, incident response | Assessing ongoing security operations |

### Using SABSA in audit reports
Frame structural recommendations across SABSA layers. A finding at the Physical layer (e.g., missing input validation) may have a root cause at the Logical layer (no input validation policy) or Conceptual layer (no security requirements process).

---

## 2. Defense in Depth

Multiple layers of security controls so that failure of one layer doesn't mean total compromise.

### Defense layers for web applications
```
Layer 1: Network perimeter
  ├── WAF, DDoS protection, CDN security
  ├── Network segmentation, firewall rules
  └── TLS termination, certificate management

Layer 2: Application perimeter
  ├── API gateway authentication
  ├── Rate limiting, input validation
  └── CORS, CSP, security headers

Layer 3: Application logic
  ├── Business logic validation
  ├── Authorization checks per operation
  └── Input sanitization, output encoding

Layer 4: Data access
  ├── Object-level authorization (IDOR prevention)
  ├── Query parameterization
  └── Data access logging

Layer 5: Data storage
  ├── Encryption at rest
  ├── Access control on storage
  └── Backup encryption, retention policies

Layer 6: Monitoring and response
  ├── Security event logging
  ├── Anomaly detection, alerting
  └── Incident response procedures
```

### Assessing defense in depth
For each finding, ask: "If this one control fails, what's the next layer of defense?" If there is no next layer, that's a defense-in-depth gap worth calling out in the report.

| Scenario | Single-layer failure | Defense-in-depth mitigation |
|----------|---------------------|---------------------------|
| XSS payload accepted by input validation | Application accepts the payload | CSP blocks inline script execution |
| Auth token stolen | Attacker has a valid session | Short token lifetime + re-auth for sensitive ops |
| IDOR allows access to other user's data | Ownership check missing | Data access logging detects anomalous access patterns |
| SQL injection in one endpoint | Query not parameterized | WAF blocks common injection patterns + DB user has minimal permissions |

---

## 3. Secure Design Principles

Evaluate the target against these foundational principles.

| Principle | Description | How to assess |
|-----------|------------|--------------|
| Least privilege | Minimum access needed for each entity | Review roles, permissions, service account scopes |
| Defense in depth | Multiple overlapping controls | Check for single-layer-of-defense weaknesses |
| Fail securely | Default to deny when controls fail | Test error states — does a failure grant access? |
| Separation of duties | Critical operations require multiple parties | Review admin workflows — can one person approve their own changes? |
| Economy of mechanism | Keep security mechanisms simple | Complex auth flows often have bypass paths |
| Complete mediation | Every access checked, every time | Are there cached auth decisions that go stale? |
| Open design | Security doesn't depend on obscurity | Would the system be secure if the code were public? |
| Least common mechanism | Minimize shared resources between users | Shared caches, shared sessions, shared storage — each is a risk |
| Psychological acceptability | Security shouldn't be so burdensome that users bypass it | Are there friction points that drive users to workarounds? |
| Minimize attack surface | Reduce exposed interfaces and features | Unnecessary endpoints, debug features, admin panels |

---

## 4. Security Architecture Patterns

Common patterns for secure system design. Reference when writing remediation recommendations.

### Authentication patterns
| Pattern | When to use | Key considerations |
|---------|------------|-------------------|
| OAuth2 + OIDC | User authentication to web/mobile apps | Proper flow selection (PKCE for SPAs), token storage, scope management |
| mTLS | Service-to-service auth | Certificate management, rotation, revocation |
| API keys | Machine-to-machine, low-sensitivity | Rate limiting, key rotation, scope restriction |
| FIDO2/WebAuthn | Phishing-resistant human auth | Browser support, recovery flows, registration security |
| Token exchange | Cross-domain auth delegation | Audience restriction, impersonation prevention |

### Authorization patterns
| Pattern | When to use | Key considerations |
|---------|------------|-------------------|
| RBAC | Well-defined roles with stable permissions | Role explosion, privilege creep, regular reviews |
| ABAC | Dynamic, context-dependent access decisions | Policy complexity, attribute trust, performance |
| ReBAC | Relationship-based access (social, organizational) | Graph complexity, consistency, performance |
| Policy as code (OPA/Cedar) | Complex, auditable authorization logic | Policy testing, deployment, versioning |

### Data protection patterns
| Pattern | When to use | Key considerations |
|---------|------------|-------------------|
| Envelope encryption | Encrypting data with data keys encrypted by master keys | Key hierarchy management, rotation |
| Tokenization | Replacing sensitive data with non-sensitive tokens | Token vault security, de-tokenization access control |
| Field-level encryption | Encrypting specific sensitive fields | Key per field/tenant, query limitations |
| Client-side encryption | End-to-end encryption where server can't read data | Key management on client, recovery flows |

---

## 5. Threat Modeling Methodologies

Beyond STRIDE (covered in `owasp-complete.md`), these methodologies provide different perspectives.

### DREAD (risk rating)
| Factor | Question | Scale |
|--------|---------|-------|
| Damage | How much damage if exploited? | 1-10 |
| Reproducibility | How easy to reproduce? | 1-10 |
| Exploitability | How easy to exploit? | 1-10 |
| Affected users | How many users impacted? | 1-10 |
| Discoverability | How easy to discover? | 1-10 |

Risk score = average of all factors. Useful for quick comparison between findings.

### Attack Trees
Hierarchical decomposition of an attack goal into sub-goals and methods.
```
Goal: Steal user data
├── Exploit authentication weakness
│   ├── Brute force password
│   ├── Steal session token via XSS
│   └── Exploit password reset flow
├── Exploit authorization weakness
│   ├── IDOR on user data endpoint
│   └── Privilege escalation to admin
└── Exploit data exposure
    ├── Enumerate user IDs in API
    └── Access unprotected backup/export
```

Use attack trees to structure the attack chain section of the report.

### MITRE ATT&CK for Enterprise
Map findings to ATT&CK tactics when relevant:

| Tactic | Web audit relevance |
|--------|-------------------|
| Reconnaissance | Information gathered via recon phase |
| Initial Access | Entry points discovered (phishing, public exploits, valid accounts) |
| Execution | Code execution via injection, XSS |
| Persistence | Session manipulation, account creation |
| Privilege Escalation | Vertical/horizontal escalation findings |
| Defense Evasion | Bypassing controls, WAF evasion |
| Credential Access | Password theft, token extraction |
| Discovery | Internal enumeration from web surface |
| Lateral Movement | Cross-service access, pivot opportunities |
| Collection | Data gathering, bulk download |
| Exfiltration | Data extraction paths |
| Impact | Destructive potential (if any) |

---

## 6. Architecture Assessment

### Questions for architectural review
When the audit reveals structural issues (not just point vulnerabilities), assess the architecture.

**Boundary analysis:**
- Where are the trust boundaries? Are they correctly placed?
- Do all data flows cross boundaries through controlled checkpoints?
- Are there implicit trust relationships that shouldn't exist?

**Component analysis:**
- What is the single point of failure for security? (e.g., if the API gateway is compromised, what's left?)
- Are security-critical components redundant?
- Is the security architecture documented and maintained?

**Data flow analysis:**
- Where does sensitive data enter the system? Where does it exit?
- Is data protected at every point in its lifecycle (creation → transit → storage → processing → deletion)?
- Are there unnecessary data flows that could be eliminated?

**Failure mode analysis:**
- What happens when each security control fails?
- Does failure default to deny or allow?
- Are failures detected and alerted?

---

## 7. Architecture Review Checklist

```
Design Principles:
[ ] Least privilege applied to all entities
[ ] Defense in depth — no single-layer dependencies
[ ] Fail-secure — defaults to deny on error
[ ] Attack surface minimized — unnecessary features disabled
[ ] Security doesn't depend on obscurity

Boundaries:
[ ] Trust boundaries clearly defined
[ ] All boundary crossings authenticated and authorized
[ ] No implicit trust between components
[ ] Network segmentation reflects trust boundaries

Authentication:
[ ] Appropriate auth mechanism for each interaction type
[ ] Human auth: MFA, phishing-resistant where possible
[ ] Service auth: mTLS or workload identity
[ ] Token management: short-lived, properly scoped, securely stored

Authorization:
[ ] Authorization model appropriate for the domain (RBAC/ABAC/ReBAC)
[ ] Authorization enforced at the service level, not just perimeter
[ ] Object-level authorization on all data access
[ ] Regular access reviews

Data Protection:
[ ] Data classified by sensitivity
[ ] Encryption at rest and in transit
[ ] Key management following best practices
[ ] Data minimization — services access only needed data

Monitoring:
[ ] Security events logged comprehensively
[ ] Anomaly detection on critical paths
[ ] Incident response procedures documented
[ ] Regular security architecture reviews
```
