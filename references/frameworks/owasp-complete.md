# OWASP Frameworks — Complete Reference

This reference covers all major OWASP projects relevant to web and application security audits. Use the appropriate framework based on the target's architecture and the audit scope.

## Table of Contents
1. [OWASP Top 10 (Web — 2021)](#1-owasp-top-10-web--2021)
2. [OWASP API Security Top 10 (2023)](#2-owasp-api-security-top-10-2023)
3. [OWASP Mobile Top 10 (2024)](#3-owasp-mobile-top-10-2024)
4. [OWASP LLM Top 10 (2025)](#4-owasp-llm-top-10-2025)
5. [OWASP Cloud-Native Top 10](#5-owasp-cloud-native-top-10)
6. [OWASP Kubernetes Top 10](#6-owasp-kubernetes-top-10)
7. [OWASP ASVS (Application Security Verification Standard)](#7-owasp-asvs)
8. [OWASP SAMM (Software Assurance Maturity Model)](#8-owasp-samm)
9. [OWASP Testing Guide (WSTG)](#9-owasp-testing-guide-wstg)
10. [OWASP Threat Modeling](#10-owasp-threat-modeling)
11. [OWASP Cheat Sheet Series — Key Sheets](#11-owasp-cheat-sheet-series)
12. [Framework Selection Matrix](#12-framework-selection-matrix)

---

## 1. OWASP Top 10 (Web — 2021)

The foundational web application risk list. Every web audit should map findings to these categories.

| ID | Category | What to check |
|----|----------|--------------|
| A01 | Broken Access Control | IDOR, BOLA, privilege escalation, force browsing, CORS misconfiguration, missing function-level access control, metadata manipulation (JWT, cookies, hidden fields) |
| A02 | Cryptographic Failures | Sensitive data transmitted in cleartext, weak/deprecated algorithms, missing TLS, improper certificate validation, weak key generation, hardcoded secrets, insufficient entropy |
| A03 | Injection | SQL/NoSQL injection, LDAP injection, OS command injection, ORM injection, expression language injection, header injection (CRLF), XPath injection |
| A04 | Insecure Design | Missing threat modeling, insecure business logic, missing rate limiting on high-value flows, unprotected credential recovery, no separation between tenants |
| A05 | Security Misconfiguration | Default credentials, unnecessary features enabled, verbose error handling, missing security headers, misconfigured cloud permissions, XML external entities (XXE) |
| A06 | Vulnerable & Outdated Components | Known CVEs in dependencies, unmaintained libraries, outdated frameworks, missing patch management, unsupported OS/runtime versions |
| A07 | Identification & Authentication Failures | Credential stuffing allowed, weak passwords permitted, missing MFA, session fixation, improper session invalidation, exposed session IDs in URLs |
| A08 | Software & Data Integrity Failures | CI/CD pipeline vulnerabilities, unsigned updates, insecure deserialization, dependency confusion, compromised build artifacts, missing integrity verification (SRI) |
| A09 | Security Logging & Monitoring Failures | Missing audit logs for auth events, no alerting on suspicious activity, logs stored insecurely, insufficient log detail, no intrusion detection |
| A10 | Server-Side Request Forgery (SSRF) | URL fetching without validation, internal service access via user-supplied URLs, cloud metadata endpoint access (169.254.169.254), DNS rebinding |

### Mapping findings to Top 10
Every finding in the final report should include an `OWASP Top 10` field mapping to the relevant A01–A10 category. Multiple categories can apply.

---

## 2. OWASP API Security Top 10 (2023)

Apply to every API endpoint discovered during the audit.

| ID | Category | What to check |
|----|----------|--------------|
| API1 | Broken Object Level Authorization | Can user A access user B's objects by manipulating IDs? Missing ownership validation per-request |
| API2 | Broken Authentication | Weak auth mechanisms, missing token validation, credential exposure in URLs/logs, insufficient brute-force protection |
| API3 | Broken Object Property Level Authorization | Mass assignment (extra fields accepted), excessive data exposure (API returns more fields than UI shows), sensitive fields modifiable |
| API4 | Unrestricted Resource Consumption | Missing rate limiting, no pagination limits, unbounded query complexity (GraphQL), large payload acceptance, missing timeouts |
| API5 | Broken Function Level Authorization | Admin endpoints accessible to regular users, missing role checks on methods, HTTP method tampering bypasses controls |
| API6 | Unrestricted Access to Sensitive Business Flows | Automated abuse of purchase/booking/comment flows, missing bot detection, no velocity checks on high-value operations |
| API7 | Server-Side Request Forgery | User-controlled URLs fetched server-side, internal network scanning, cloud metadata access, webhook URL abuse |
| API8 | Security Misconfiguration | CORS wildcard with credentials, missing TLS, verbose error responses, unnecessary HTTP methods enabled, default configurations |
| API9 | Improper Inventory Management | Shadow/zombie APIs still accessible, undocumented endpoints, old API versions not decommissioned, missing API gateway controls |
| API10 | Unsafe Consumption of APIs | Insufficient validation of third-party API responses, blind trust of upstream data, no circuit breakers, missing input sanitization from external sources |

### API audit checklist
For every endpoint: verify auth → check object-level authz → test property-level authz → probe rate limits → test method confusion → verify error handling → check CORS → assess data exposure.

---

## 3. OWASP Mobile Top 10 (2024)

Apply when the target has mobile apps or mobile-accessible APIs.

| ID | Category | What to check |
|----|----------|--------------|
| M1 | Improper Credential Usage | Hardcoded credentials, insecure credential storage, credentials in logs or shared preferences |
| M2 | Inadequate Supply Chain Security | Compromised third-party SDKs, malicious dependencies, unverified library sources |
| M3 | Insecure Authentication/Authorization | Weak biometric implementation, missing server-side auth validation, bypassable local auth |
| M4 | Insufficient Input/Output Validation | Injection via mobile inputs, WebView injection, unsafe deep link handling, clipboard data exposure |
| M5 | Insecure Communication | Missing certificate pinning, cleartext traffic, weak TLS configuration, MitM susceptibility |
| M6 | Inadequate Privacy Controls | Excessive data collection, missing consent flows, PII in logs/analytics, over-broad permissions |
| M7 | Insufficient Binary Protections | Missing obfuscation, no tamper detection, debuggable release builds, reverse-engineering exposure |
| M8 | Security Misconfiguration | Exported components, debug mode enabled, insecure default settings, backup exposure |
| M9 | Insecure Data Storage | Sensitive data in shared preferences/SQLite unencrypted, world-readable files, cache exposure |
| M10 | Insufficient Cryptography | Weak algorithms, hardcoded keys, improper key management, insufficient key length |

---

## 4. OWASP LLM Top 10 (2025)

Apply when the target uses AI/LLM features — increasingly common in modern apps.

| ID | Category | What to check |
|----|----------|--------------|
| LLM01 | Prompt Injection | Direct prompt injection in user inputs, indirect injection via data sources, system prompt extraction attempts |
| LLM02 | Sensitive Information Disclosure | Training data leakage, PII in model outputs, system prompt exposure, conversation data exfiltration |
| LLM03 | Supply Chain Vulnerabilities | Compromised model weights, poisoned training data, malicious plugins/tools, vulnerable model hosting |
| LLM04 | Data and Model Poisoning | Training data manipulation, fine-tuning attacks, adversarial examples that persist |
| LLM05 | Improper Output Handling | Unsanitized LLM output rendered as HTML/JS, LLM output used in SQL/system commands, blind trust of model responses |
| LLM06 | Excessive Agency | LLM with overly broad tool permissions, autonomous actions without human approval, missing guardrails on function calling |
| LLM07 | System Prompt Leakage | System prompt extractable via crafted queries, prompt visible in client-side code or API responses |
| LLM08 | Vector and Embedding Weaknesses | Embedding inversion attacks, poisoned vector stores, unauthorized access to embedding databases |
| LLM09 | Misinformation | Hallucinated outputs presented as fact, no grounding/citation mechanisms, confidence scores missing |
| LLM10 | Unbounded Consumption | Denial-of-wallet via expensive model calls, no token/cost limits, recursive agent loops |

### LLM testing approach
For each AI feature: attempt prompt injection → try system prompt extraction → check output sanitization → test tool permissions → verify cost controls → assess data leakage.

---

## 5. OWASP Cloud-Native Top 10

Apply when the target runs on cloud infrastructure (AWS, GCP, Azure).

| ID | Category | What to check |
|----|----------|--------------|
| CNS1 | Insecure Cloud/Container/Orchestration Configuration | Public storage buckets, overly permissive IAM, default security groups, unpatched container images |
| CNS2 | Injection Flaws (CI/CD) | Pipeline injection, dependency confusion, build process manipulation |
| CNS3 | Improper Authentication & Authorization | Missing IAM least privilege, over-scoped service accounts, missing MFA for cloud console |
| CNS4 | CI/CD Pipeline & Software Supply Chain | Unsigned artifacts, missing SBOM, unverified base images, insecure registry access |
| CNS5 | Insecure Secrets Management | Secrets in environment variables, hardcoded in code, unencrypted at rest, overly broad secret access |
| CNS6 | Over-Permissive/Insecure Network Policies | Missing network segmentation, overly broad ingress/egress, missing service mesh mTLS |
| CNS7 | Using Components with Known Vulnerabilities | Unpatched base images, vulnerable sidecars, outdated service mesh versions |
| CNS8 | Improper Assets Management | Shadow cloud resources, untagged resources, missing inventory, abandoned infrastructure |
| CNS9 | Inadequate Compute Resource Quota Management | Missing resource limits, no autoscaling caps, denial-of-wallet risk |
| CNS10 | Ineffective Logging & Monitoring | Missing CloudTrail/audit logs, no container runtime monitoring, insufficient alerting |

---

## 6. OWASP Kubernetes Top 10

Apply when the target infrastructure uses Kubernetes. Cross-reference with `references/frameworks/kubernetes-security.md` for deeper K8s testing.

| ID | Category | What to check |
|----|----------|--------------|
| K01 | Insecure Workload Configurations | Running as root, missing securityContext, hostPath mounts, privileged containers, missing resource limits |
| K02 | Supply Chain Vulnerabilities | Unscanned container images, unsigned images, vulnerable base images, compromised registries |
| K03 | Overly Permissive RBAC | Cluster-admin to non-admin users, wildcard permissions, unnecessary service account tokens |
| K04 | Lack of Centralized Policy Enforcement | Missing OPA/Gatekeeper/Kyverno, no admission controllers, inconsistent security policies |
| K05 | Inadequate Logging and Monitoring | Missing audit logging, no runtime threat detection (Falco), insufficient metrics |
| K06 | Broken Authentication Mechanisms | Default service account tokens mounted, weak API server auth, missing OIDC integration |
| K07 | Missing Network Segmentation Controls | Missing NetworkPolicies, flat pod network, unrestricted pod-to-pod communication |
| K08 | Secrets Management Failures | Secrets in ConfigMaps, base64-not-encrypted secrets, missing external secret operators, secrets in container env |
| K09 | Misconfigured Cluster Components | Exposed API server, insecure etcd, kubelet anonymous access, missing encryption at rest |
| K10 | Outdated and Vulnerable Kubernetes Components | Unpatched control plane, EOL Kubernetes versions, vulnerable CNI/CSI plugins |

---

## 7. OWASP ASVS

The Application Security Verification Standard defines three levels of assurance. Use to scope the depth of audit.

### Verification levels
| Level | Name | When to use |
|-------|------|------------|
| L1 | Opportunistic | All applications — basic security hygiene, automated checks |
| L2 | Standard | Most business applications — protection against targeted attacks |
| L3 | Advanced | Critical applications — defense against advanced persistent threats |

### ASVS sections to assess
| Section | Domain | Key checks |
|---------|--------|-----------|
| V1 | Architecture & Threat Modeling | Threat model exists, security requirements documented, data flow diagrams |
| V2 | Authentication | Password policy, MFA, credential storage, session binding |
| V3 | Session Management | Session timeout, secure cookie attributes, concurrent session control |
| V4 | Access Control | Least privilege, deny-by-default, attribute-based access, IDOR prevention |
| V5 | Validation & Encoding | Input validation whitelist, output encoding context-specific, parameterized queries |
| V6 | Stored Cryptography | Approved algorithms only, proper key management, no hardcoded secrets |
| V7 | Error Handling & Logging | Generic errors to users, detailed logs for ops, tamper-proof audit trail |
| V8 | Data Protection | Data classification, PII handling, retention policies, encryption at rest/transit |
| V9 | Communication | TLS everywhere, certificate validation, HSTS, certificate pinning for mobile |
| V10 | Malicious Code | No backdoors, no time bombs, integrity verification, safe dependency management |
| V11 | Business Logic | Rate limiting, anti-automation, workflow integrity, fraud controls |
| V12 | Files & Resources | Upload validation, path traversal prevention, file size limits, safe storage |
| V13 | API & Web Services | API auth, input validation, rate limiting, schema validation, versioning |
| V14 | Configuration | Hardened defaults, no debug in production, security headers, dependency scanning |

Recommend the appropriate ASVS level based on the target's criticality, then check against the relevant sections.

---

## 8. OWASP SAMM

The Software Assurance Maturity Model assesses organizational security practices. Use for strategic recommendations in the remediation plan.

### SAMM business functions and practices
| Function | Practice 1 | Practice 2 | Practice 3 |
|----------|-----------|-----------|-----------|
| Governance | Strategy & Metrics | Policy & Compliance | Education & Guidance |
| Design | Threat Assessment | Security Requirements | Security Architecture |
| Implementation | Secure Build | Secure Deployment | Defect Management |
| Verification | Architecture Assessment | Requirements Testing | Security Testing |
| Operations | Incident Management | Environment Management | Operational Management |

### Maturity levels (per practice)
| Level | Description |
|-------|------------|
| 0 | Practice not performed |
| 1 | Ad-hoc, reactive, initial |
| 2 | Documented, consistent, repeatable |
| 3 | Measured, optimized, continuous improvement |

When writing remediation plans, frame structural improvements using SAMM practices and maturity targets.

---

## 9. OWASP Testing Guide (WSTG)

The Web Security Testing Guide provides the detailed test procedures. Map each audit activity to WSTG test IDs.

### WSTG categories and key test IDs
| Category | Test IDs | Focus |
|----------|---------|-------|
| Information Gathering | WSTG-INFO-01 to 10 | Search engine discovery, fingerprinting, application mapping, content discovery |
| Configuration & Deployment | WSTG-CONF-01 to 12 | Network/platform config, file extensions, backup files, HTTP methods, admin interfaces |
| Identity Management | WSTG-IDNT-01 to 05 | Role definitions, registration, account provisioning, enumeration, weak username policy |
| Authentication | WSTG-ATHN-01 to 10 | Credentials transport, default credentials, lockout, auth bypass, password recovery |
| Authorization | WSTG-ATHZ-01 to 04 | Directory traversal, authorization bypass, privilege escalation, IDOR |
| Session Management | WSTG-SESS-01 to 09 | Session token analysis, cookie attributes, session fixation, CSRF, logout functionality |
| Input Validation | WSTG-INPV-01 to 19 | XSS, injection variants, HTTP parameter pollution, XXE, SSRF, template injection |
| Error Handling | WSTG-ERRH-01 to 02 | Improper error handling, stack trace exposure |
| Cryptography | WSTG-CRYP-01 to 04 | Weak TLS, padding oracle, unencrypted channels, weak algorithms |
| Business Logic | WSTG-BUSL-01 to 09 | Workflow bypass, request forgery, integrity, timing, upload abuse, payment manipulation |
| Client-Side | WSTG-CLNT-01 to 13 | DOM XSS, resource manipulation, clickjacking, WebSocket, cross-origin, storage |

Reference WSTG test IDs in findings when applicable for traceability.

---

## 10. OWASP Threat Modeling

Use threat modeling to identify risks systematically before diving into technical testing.

### STRIDE model
| Threat | Description | What to look for |
|--------|------------|-----------------|
| **S**poofing | Impersonating a user or system | Weak auth, missing identity verification, token theft |
| **T**ampering | Modifying data or code | Input manipulation, unsigned messages, missing integrity checks |
| **R**epudiation | Denying actions | Missing audit logs, unsigned transactions, no non-repudiation |
| **I**nformation Disclosure | Exposing data | Verbose errors, PII leakage, missing encryption, side channels |
| **D**enial of Service | Disrupting availability | Missing rate limits, resource exhaustion, no circuit breakers |
| **E**levation of Privilege | Gaining unauthorized access | Privilege escalation, IDOR, missing authz checks, role confusion |

### PASTA (Process for Attack Simulation and Threat Analysis)
A risk-centric methodology — 7 stages:
1. Define business objectives
2. Define technical scope
3. Application decomposition (data flows, trust boundaries, entry points)
4. Threat analysis (who would attack and why)
5. Vulnerability analysis (what weaknesses exist)
6. Attack modeling (how would an attacker proceed)
7. Risk and impact analysis (business impact, likelihood, residual risk)

### LINDDUN (Privacy threat modeling)
Use when the target handles significant PII:
- **L**inking — correlating data across sources
- **I**dentifying — revealing identity from data
- **N**on-repudiation — inability to deny actions (privacy concern when unwanted)
- **D**etecting — observing user actions
- **D**ata disclosure — unauthorized data access
- **U**nawareness — user doesn't know about data processing
- **N**on-compliance — violating privacy regulations

---

## 11. OWASP Cheat Sheet Series — Key Sheets

Reference these when writing remediation guidance:

| Cheat Sheet | Use when remediating |
|------------|---------------------|
| Authentication | Login, password, MFA issues |
| Authorization | Access control, RBAC, ABAC issues |
| Session Management | Cookie, token, timeout issues |
| Cross-Site Scripting Prevention | Any XSS finding |
| SQL Injection Prevention | Any injection finding |
| CSRF Prevention | Cross-site request forgery |
| Input Validation | Any input-handling finding |
| Cryptographic Storage | Encryption, hashing issues |
| Transport Layer Protection | TLS, HTTPS issues |
| REST Security | API design issues |
| Content Security Policy | CSP configuration |
| Docker Security | Container security |
| Kubernetes Security | K8s configuration |
| Logging | Audit/monitoring gaps |
| Secrets Management | Credential/key handling |

---

## 12. Framework Selection Matrix

Use this to decide which frameworks apply based on the target.

| Target characteristic | Apply these frameworks |
|----------------------|----------------------|
| Any web application | Top 10, ASVS, WSTG, STRIDE |
| Has REST/GraphQL APIs | API Top 10, ASVS V13 |
| Has mobile apps | Mobile Top 10, ASVS V9 |
| Uses AI/LLM features | LLM Top 10 |
| Runs on cloud | Cloud-Native Top 10 |
| Uses Kubernetes | Kubernetes Top 10 |
| Handles PII | LINDDUN, ASVS V8 |
| Needs maturity assessment | SAMM |
| Needs detailed test procedures | WSTG |
| Needs threat modeling | STRIDE, PASTA |
