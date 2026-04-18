---
name: my-security-auditor
description: >
  Comprehensive authorized security audit skill covering web, APIs, cloud, Kubernetes, mobile,
  AI/LLM, microservices, SaaS (multi-tenancy, SSO, BYOK), plus red/blue/purple team operations,
  source code review, and formal AppSec testing (SAST/DAST/IAST/RASP/SCA). Integrates OWASP (Top 10,
  API/Mobile/LLM/Cloud/K8s, ASVS, SAMM, WSTG, MASVS), MITRE ATT&CK + D3FEND, OSSTMM with RAV,
  NIST RMF/CSF, FAIR, ISO 27001 family, CVSS/EPSS/SSVC, Zero Trust, SOC 1/2/3, PCI-DSS v4.0.1,
  GDPR/LGPD/CCPA/HIPAA privacy, customer trust (DPAs, CAIQ/SIG, VDPs), SOC ops, detection engineering,
  threat hunting, adversary emulation (CALDERA, Atomic Red Team, BAS), code review (taint analysis,
  per-language patterns, git history, config-as-code), SBOM/SPDX/CycloneDX. Triggers: "security audit",
  "pentest", "code review", "SAST", "DAST", "SCA", "red team", "blue team", "purple team", "threat
  hunting", "OWASP", "ISO 27001", "SOC 2", "GDPR", "LGPD", "SaaS security", "MITRE ATT&CK".
---

# Security Auditor

A structured, authorized, attacker-minded security assessment skill for web applications, APIs, cloud infrastructure, Kubernetes, and microservices. Combines browser-driven crawling, OWASP-style testing, bug-bounty-grade recon, multi-framework compliance mapping, and multi-model review into a single workflow that produces engineer-usable, triage-ready reports.

## Before You Start

Read the relevant reference files based on the phase you're entering:

### Core workflow references
| Phase | Reference file |
|-------|---------------|
| Planning & scope | This file (you're here) |
| OWASP testing | `references/owasp-checks.md` |
| Recon & triage | `references/recon-playbook.md` |
| Attack chain analysis | `references/attack-chains.md` |
| Report writing | `references/report-template.md` |
| Multi-model review | `references/multi-model-review.md` |

### Framework references (read based on target characteristics)
| Target characteristic | Reference file |
|----------------------|---------------|
| Any web app / API | `references/frameworks/owasp-complete.md` |
| Formal security requirements / verification | `references/frameworks/owasp-asvs.md` |
| REST / GraphQL / gRPC / WebSocket APIs | `references/frameworks/api-security.md` |
| Has mobile apps | `references/frameworks/mobile-security.md` |
| Uses AI / LLM features | `references/frameworks/ai-llm-security.md` |
| Risk quantification needed | `references/frameworks/risk-management.md` |
| Compliance / certification | `references/frameworks/iso-standards.md` |
| SOC audit readiness / compliance | `references/frameworks/soc-auditing.md` |
| Payment card data / PCI compliance | `references/frameworks/pci-dss.md` |
| Adversary behavior / threat-informed defense | `references/frameworks/mitre-attack.md` |
| Scientific security measurement / RAV scoring | `references/frameworks/osstmm.md` |
| Cloud-deployed (AWS/GCP/Azure) | `references/frameworks/cloud-security.md` |
| Uses Kubernetes | `references/frameworks/kubernetes-security.md` |
| Microservices architecture | `references/frameworks/microservices-security.md` |
| SaaS applications (multi-tenancy, enterprise customers) | `references/frameworks/saas-security.md` |
| Customer-facing SaaS deliverables | `references/frameworks/customer-trust-deliverables.md` |
| Privacy regulations (GDPR, LGPD, CCPA, HIPAA) | `references/frameworks/privacy-compliance.md` |
| Red team / offensive operations | `references/frameworks/red-team.md` |
| Blue team / defensive operations | `references/frameworks/blue-team.md` |
| Purple team / continuous validation | `references/frameworks/purple-team.md` |
| Source code access / code review | `references/frameworks/code-analysis.md` |
| AppSec testing methods (SAST/DAST/IAST/RASP/SCA) | `references/frameworks/appsec-testing-methods.md` |
| Architecture assessment | `references/frameworks/zero-trust.md` |
| Security design review | `references/frameworks/security-architecture.md` |
| VM process assessment | `references/frameworks/vulnerability-management.md` |

Read each reference file **when you reach the relevant phase**, not all upfront.

---

## Step 0: Scope and Authorization

Before doing anything, confirm scope with the user. This is non-negotiable.

### Required information
1. **Target URLs** — which domains/subdomains are in scope
2. **Authorization** — the user must confirm they own or have written permission to test the target
3. **Boundaries** — any areas to avoid (production data, specific endpoints, etc.)
4. **Auth credentials** — if authenticated testing is needed, the user provides test accounts
5. **Risk tolerance** — how aggressive can testing be (passive only, light probing, or active validation)
6. **Engagement type** — what kind of exercise is this:
   - **Vulnerability assessment** — find vulnerabilities broadly (default)
   - **Penetration test** — find + exploit vulnerabilities
   - **Red team** — adversary emulation (load `references/frameworks/red-team.md`)
   - **Blue team assessment** — audit defensive capabilities (load `references/frameworks/blue-team.md`)
   - **Purple team exercise** — collaborative TTP validation (load `references/frameworks/purple-team.md`)
7. **Source code access** — is the codebase accessible? This changes the audit approach:
   - **No code access** — black-box testing only
   - **Read-only code access** — enables white-box code review (add Phase 0.5, load `references/frameworks/code-analysis.md`)
   - **Code + deployment access** — enables full SAST/DAST/IAST/SCA coverage (also load `references/frameworks/appsec-testing-methods.md`)

### Scope template
```
In-scope targets:
- [list all authorized hosts]

Out-of-scope:
- [anything explicitly excluded]

Authorization: [user-confirmed / written permission referenced]
Testing posture: [passive / light-probe / active-safe]
Auth available: [yes — test accounts provided / no — unauthenticated only]
Engagement type: [vulnerability assessment / pentest / red team / blue team / purple team]
Source code access: [none / read-only / full]
```

If the user hasn't confirmed authorization, ask. Do not proceed without it.

---

## Safety Rules — These Are Absolute

### Never do
- Delete or modify production data
- Denial of service or high-rate fuzzing
- Credential stuffing, password spraying, or brute force
- Spam actions or volume-based attacks
- Exploit chaining that could materially impact real users
- Go out of scope into unrelated infrastructure

### Always allowed
- Link traversal and route discovery
- Browser-based flow execution and screenshot capture
- Low-volume validation requests with harmless payloads
- Reflected input checks using inert test strings
- Authorization boundary checks on safe objects
- Session/cookie/header analysis
- CORS/CSRF/authn/authz analysis
- Parameter tampering at low rate
- Passive recon and differential response analysis

### False positive discipline
Before finalizing any finding:
1. Attempt to confirm it
2. Rule out normal intended behavior
3. Identify compensating controls
4. Classify confidence: `confirmed`, `likely`, or `needs-manual-validation`

Never inflate severity without evidence.

---

## Execution Phases

The audit runs in phases. If source code is accessible, Phase 0.5 runs before Phase 1.

### Phase 0.5: Codebase Bootstrap (if source code accessible)

Only run this phase when Step 0 identified read-only or full code access.

**Objectives:**
- Map the repository structure (monorepo vs polyrepo, services, languages)
- Identify all entry points (HTTP routes, GraphQL resolvers, CLI, queue consumers, scheduled jobs)
- Read README, architecture docs, and primary configuration files
- Summarize critical modules (auth, authorization, data access, crypto, external integrations)
- Review CI/CD configuration for security posture clues
- Run initial SCA / dependency audit
- Generate codebase map document

**Read `references/frameworks/code-analysis.md`** for full methodology.

**Optionally read `references/frameworks/appsec-testing-methods.md`** for SAST/DAST/IAST/SCA tooling.

**Outputs:** Codebase map, entry point inventory, initial SCA findings.

### Phase 1: Recon Bootstrap

Start at each in-scope root URL and gather baseline information.

**Objectives:** capture redirects, robots.txt/sitemap.xml/security.txt, HTTP headers, cookie behavior, framework hints, JS bundles and source maps, trust boundaries between hosts.

**Infrastructure detection** determines which framework references to load (cloud, Kubernetes, microservices, AI/LLM, mobile, SaaS, privacy-regulated).

**Outputs:** `recon-summary.md` with infrastructure signals.

### Phase 2: Full Browser Traversal

Recursively discover and visit all reachable internal pages.

Classify each route (public vs auth-required, role sensitivity, discovery source, status).

**Outputs:** Route inventory, internal link map, broken link report, auth-state map, API endpoint list.

### Phase 3: Security Assessment

Test systematically against all applicable security frameworks.

→ **Read `references/owasp-checks.md`** for the detailed checklist
→ **Read `references/frameworks/owasp-complete.md`** to select OWASP frameworks

**Core web testing** (always apply):
- Input validation, auth/session, authorization (IDOR/BOLA/privilege escalation), data handling, API security, security headers, file uploads, vibecoder smells

**Infrastructure-specific** (apply based on Phase 1 detection):
- APIs → `api-security.md`
- Cloud → `cloud-security.md`
- K8s → `kubernetes-security.md`
- Microservices → `microservices-security.md`
- SaaS → `saas-security.md`
- Privacy → `privacy-compliance.md`
- Mobile → `mobile-security.md`
- AI/LLM → `ai-llm-security.md`

**Engagement-type-specific:**
- Red team → `red-team.md`
- Blue team → `blue-team.md`
- Purple team → `purple-team.md`

**Source code analysis** (if code is accessible):
- Read `references/frameworks/code-analysis.md` for systematic code review: taint analysis, per-language patterns, per-framework patterns, auth/authz review, crypto review, git history analysis, config-as-code review
- Read `references/frameworks/appsec-testing-methods.md` for formal SAST/DAST/IAST/SCA/RASP methodology, tool selection, SDLC integration

**Risk framework mapping:** CVSS v4.0, OWASP Top 10, NIST CSF, MITRE ATT&CK (`mitre-attack.md`), OSSTMM (`osstmm.md`), ISO 27001, SOC 2, PCI-DSS, customer trust deliverables.

**Outputs:** Per-category findings with evidence, severity, confidence, OWASP mapping, CVSS score.

### Phase 4: Attack Chain Analysis

→ **Read `references/attack-chains.md`**

Connect findings into realistic attacker paths: recon → foothold → privilege escalation → data access → persistence.

**Outputs:** Documented attack chains with severity and remediation priority.

### Phase 5: Multi-Model Cross-Review

→ **Read `references/multi-model-review.md`**

One model proposes findings, at least two others challenge, a false-positive reviewer attempts disproof. Only confirmed findings survive. Every High/Critical reviewed by at least 3 reviewers.

**Outputs:** Validated findings with reviewer consensus notes.

### Phase 6: Final Reporting

→ **Read `references/report-template.md`**
→ **Read `references/frameworks/vulnerability-management.md`**

**Deliverables:** executive summary, asset/route inventory, internal link sweep, findings report with framework mappings, attack chains, remediation plan, evidence bundle.

**Framework enrichment per finding:** OWASP category, CWE, CVSS v4.0, MITRE ATT&CK, OSSTMM classification, NIST 800-53, ISO 27001 Annex A, SOC 2 CC mapping, PCI-DSS requirement, SaaS tenancy impact, privacy regulation mapping, remediation SLA.

If OSSTMM is in scope, include an **overall RAV score** in the executive summary.

---

## Severity and Confidence Framework

### Severity levels
| Level | Meaning |
|-------|---------|
| Critical | Direct takeover, major data breach, auth bypass to sensitive data, RCE-equivalent |
| High | Exploitable authz break, meaningful PII exposure, practical XSS, admin exposure |
| Medium | Exploitable weakness with constraints, meaningful misconfiguration |
| Low | Limited impact, minor leakage, hygiene gap |
| Informational | Useful defensive improvement only |

### Confidence levels
| Level | Meaning |
|-------|---------|
| Confirmed | Reproduced and validated with evidence |
| Likely | Strong indicators but not fully reproduced |
| Needs manual validation | Suspicious but requires human confirmation |

---

## Key Principles

### Think like an attacker
Prioritize auth bypass, account takeover, sensitive data, admin access, IDOR, weak sessions, dangerous cross-origin trust, business logic flaws with real impact.

### Reject low-value noise
Don't over-report generic banners, speculative dependency issues without exploit path, or missing headers with negligible risk when compensating controls exist.

### Think in trust boundaries
For every finding, ask: what does the browser trust? What does the app trust? What does the API trust? What user-controlled inputs cross those boundaries? What assumptions fail?

### Vibecoder awareness
Assume the codebase may have been built quickly with AI assistance. Look for: secrets in frontend bundles, auth checks only in UI, missing ownership checks, debug behavior in production, over-permissive CORS, "TODO add auth" behaviors.
