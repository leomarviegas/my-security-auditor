---
name: my-security-auditor
description: >
  Comprehensive authorized security audit skill covering web, APIs, cloud, Kubernetes, mobile,
  AI/LLM, microservices, SaaS (multi-tenancy, SSO, BYOK), plus red/blue/purple team operations.
  Integrates OWASP (Top 10, API/Mobile/LLM/Cloud/K8s, ASVS, SAMM, WSTG, MASVS), MITRE ATT&CK +
  D3FEND, OSSTMM with RAV, NIST RMF/CSF, FAIR, ISO 27001 family, CVSS/EPSS/SSVC, Zero Trust (800-207,
  CISA ZTMM), SABSA, CIS, CSA CCM, SOC 1/2/3, PCI-DSS v4.0.1, GDPR/LGPD/CCPA/HIPAA privacy, customer
  trust deliverables (DPAs, CAIQ/SIG, VDPs), SOC operations, detection engineering, threat hunting,
  adversary emulation (CALDERA, Atomic Red Team, BAS), and vulnerability management. Combines browser
  crawling, bug-bounty recon, red team TTPs, multi-model review. Triggers: "security audit",
  "pentest", "red team", "blue team", "purple team", "threat hunting", "detection engineering",
  "SOC assessment", "adversary emulation", "OWASP", "ISO 27001", "SOC 2", "GDPR", "LGPD",
  "SaaS security", "MITRE ATT&CK".
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
| Any web app / API | `references/frameworks/owasp-complete.md` — All OWASP frameworks (Top 10, API Top 10, Mobile Top 10, LLM Top 10, Cloud-Native Top 10, K8s Top 10, ASVS, SAMM, WSTG, threat modeling, cheat sheets) |
| Formal security requirements / verification | `references/frameworks/owasp-asvs.md` — OWASP ASVS deep dive, 3 verification levels (L1/L2/L3), all 14 categories (V1-V14) with per-requirement testing guidance, audit workflow, compliance reporting template, finding-to-requirement mapping |
| REST / GraphQL / gRPC / WebSocket APIs | `references/frameworks/api-security.md` — OWASP API Top 10 (2023) deep dive, API discovery techniques, JWT/OAuth/API key testing, authorization testing matrix, GraphQL-specific attacks, gRPC/WebSocket/SOAP testing, parameter pollution, content-type manipulation |
| Has mobile apps | `references/frameworks/mobile-security.md` — OWASP Mobile Top 10 (2024) deep-dive with MASVS, MASTG, platform-specific testing (Android/iOS), mobile API security, decompilation and runtime analysis |
| Uses AI / LLM features | `references/frameworks/ai-llm-security.md` — OWASP LLM Top 10 (2025) deep-dive, ML Security Top 10, prompt injection test suites, AI agent security, RAG pipeline security, AI supply chain, AI privacy/compliance |
| Risk quantification needed | `references/frameworks/risk-management.md` — NIST RMF/CSF 2.0, FAIR, ISO 31000, CVSS v4.0, EPSS, SSVC, risk matrices |
| Compliance / certification | `references/frameworks/iso-standards.md` — ISO 27001/27002/27005/27017/27018/27034/27701/27035/27032 |
| SOC audit readiness / compliance | `references/frameworks/soc-auditing.md` — SOC 1/2/3, Trust Services Criteria (CC1-CC9 + A, PI, C, P), Type 1 vs Type 2, control testing methodology, evidence collection, audit readiness gap analysis, cross-framework mapping |
| Payment card data / PCI compliance | `references/frameworks/pci-dss.md` — PCI-DSS v4.0.1, all 12 requirements, CDE scoping, SAQ types (A, A-EP, B, B-IP, C, C-VT, D, P2PE), merchant/SP levels, compensating controls, customized approach, v4 new requirements |
| Adversary behavior / threat-informed defense | `references/frameworks/mitre-attack.md` — MITRE ATT&CK (Enterprise, Cloud, Container, Mobile, ICS matrices), all 14 tactics, key techniques for web audits, MITRE D3FEND defensive countermeasures, adversary emulation, detection engineering, finding-to-ATT&CK mapping |
| Scientific security measurement / RAV scoring | `references/frameworks/osstmm.md` — OSSTMM 3 methodology, RAV (Risk Assessment Value) quantifiable scoring, 5 channels (Human/Physical/Wireless/Telecoms/Data Networks), 6 test types, 10 operational controls, 17 modules, trust analysis, STAR report format |
| Cloud-deployed (AWS/GCP/Azure) | `references/frameworks/cloud-security.md` — CIS benchmarks, CSA CCM, cloud-specific attack surfaces |
| Uses Kubernetes | `references/frameworks/kubernetes-security.md` — K8s attack surface, RBAC, pod security, NetworkPolicies, CIS K8s benchmark, NSA/CISA hardening |
| Microservices architecture | `references/frameworks/microservices-security.md` — Service mesh, inter-service auth, API gateway, event-driven, distributed threats |
| SaaS applications (multi-tenancy, enterprise customers) | `references/frameworks/saas-security.md` — Multi-tenancy security, tenant isolation testing, cross-tenant leakage patterns, enterprise SSO/SAML/OIDC/SCIM, BYOK/CMEK, entitlement/billing security, trial abuse, resource quotas, admin access controls, webhook/integration security, audit logging |
| Customer-facing SaaS deliverables | `references/frameworks/customer-trust-deliverables.md` — Trust centers, security questionnaires (CAIQ, SIG, VSA), DPAs, subprocessor management, status pages, VDPs, transparency reports, certification strategy, incident communication |
| Privacy regulations (GDPR, LGPD, CCPA, HIPAA) | `references/frameworks/privacy-compliance.md` — GDPR deep dive, LGPD (Brazil), CCPA/CPRA, HIPAA, other regional regulations, DSAR testing (access/deletion/portability), data residency, cross-border transfers, DPIA methodology, consent management, privacy by design |
| Red team / offensive operations | `references/frameworks/red-team.md` — Engagement types (pentest vs red team vs assumed breach), kill chain models (Cyber Kill Chain, Unified Kill Chain, Diamond, Pyramid of Pain), 7 attack phases with TTPs, C2 frameworks (Cobalt Strike, Sliver, Mythic), social engineering, physical security, OPSEC for testers, evasion techniques, adversary emulation plans, red team reporting |
| Blue team / defensive operations | `references/frameworks/blue-team.md` — SOC operations model, SOC-CMM maturity, detection engineering (Sigma/YARA, detection-as-code), SIEM architecture, EDR/XDR/NDR, SOAR automation, threat hunting (hypothesis-driven, TTP-based), threat intelligence integration, incident response, deception technology, log management, blue team metrics |
| Purple team / continuous validation | `references/frameworks/purple-team.md` — Collaborative exercises, Atomic Red Team, MITRE CALDERA, BAS platforms (AttackIQ, SafeBreach, Cymulate), adversary emulation plans (APT3, APT29, FIN7, Ryuk), detection coverage assessment, ATT&CK Navigator, DeTT&CT, detection feedback loop, continuous validation programs, purple team metrics |
| Architecture assessment | `references/frameworks/zero-trust.md` — NIST 800-207, CISA ZTMM, Zero Trust principles, anti-patterns |
| Security design review | `references/frameworks/security-architecture.md` — SABSA, defense in depth, secure design principles, STRIDE/PASTA/DREAD, MITRE ATT&CK |
| VM process assessment | `references/frameworks/vulnerability-management.md` — VM lifecycle, CWE/CVE/CPE, CVSS+EPSS prioritization, SLAs, patch management, metrics |

Read each reference file **when you reach the relevant phase**, not all upfront. For most audits, you'll need `owasp-complete.md` and `risk-management.md` at minimum. Add framework references based on what you discover about the target's architecture during recon.

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
   - **Vulnerability assessment** — find vulnerabilities broadly (default for most "security audit" requests)
   - **Penetration test** — find + exploit vulnerabilities with broader scope
   - **Red team** — adversary emulation with mission objectives (load `references/frameworks/red-team.md`)
   - **Blue team assessment** — audit defensive capabilities / SOC maturity / detection coverage (load `references/frameworks/blue-team.md`)
   - **Purple team exercise** — collaborative validation of specific TTPs or adversary emulation (load `references/frameworks/purple-team.md`)

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
- Reflected input checks using inert test strings (e.g., `<script>alert(1)</script>` only where non-persistent)
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

The audit runs in six phases. Each phase builds on the previous one's outputs.

### Phase 1: Recon Bootstrap

Start at each in-scope root URL and gather baseline information.

**Objectives:**
- Capture redirect behavior and canonical URLs for each host
- Collect `robots.txt`, `sitemap.xml`, `security.txt` if present
- Record HTTP response headers and cookie behavior
- Identify framework hints (server headers, meta tags, asset structure)
- Locate public JS bundles, source maps, and referenced endpoints
- Map trust boundaries between hosts (shared cookies, CORS relationships, auth domains)

**Infrastructure detection** — identify the target's architecture to determine which framework references to load:
- Cloud provider: look for AWS (`x-amz-*`), GCP (`x-goog-*`), Azure (`x-ms-*`) headers, bucket URLs, cloud CDN patterns
- Kubernetes: look for envoy/istio headers, pod-style hostnames in errors, `/healthz` endpoints, distributed tracing headers
- Microservices: look for inconsistent error formats across endpoints, multiple API base paths, different response latencies, service mesh headers
- AI/LLM features: look for chat interfaces, AI-generated content, prompt-related endpoints, streaming responses, `/completions` or `/chat` API paths, model version references in responses
- Mobile apps: look for mobile-specific API endpoints (`/api/mobile/`, `/api/v*/app/`), deep link configurations (`/.well-known/assetlinks.json`, `/.well-known/apple-app-site-association`), app store links, mobile SDK references, push notification endpoints
- SaaS architecture: look for multi-tenancy indicators (tenant subdomains like `acme.app.com`, path-based tenancy `/t/acme/`, `X-Tenant-ID` headers, workspace/organization concepts), enterprise SSO endpoints (`/saml/`, `/sso/`, `/oidc/`), SCIM endpoints (`/scim/v2/`), trial/signup flows, pricing/plans pages, subprocessor lists, trust/security pages, DPA references
- Privacy-regulated processing: look for privacy policies, cookie banners, consent management platforms (OneTrust, Cookiebot), DSAR/privacy request mechanisms, regional data handling (EU/UK/Brazil/California references)

Based on what you detect, read the relevant framework reference files before proceeding to Phase 2.

**Browser tool selection:**
- Check if Playwright MCP tools are available (`playwright:playwright_navigate`, etc.)
- Check if Claude in Chrome MCP is available (`Claude in Chrome:navigate`, etc.)
- Use whichever is connected; if both are available, prefer Playwright for scripted flows and Chrome for interactive exploration
- If neither is available, use `web_fetch` for passive analysis and inform the user that browser-driven testing is limited

**Outputs:** Save a `recon-summary.md` capturing all discovered infrastructure signals and which framework references are relevant.

### Phase 2: Full Browser Traversal

Recursively discover and visit all reachable internal pages, behaving like a persistent human attacker and QA analyst.

**What to discover:**
- All first-party links, buttons, menus, forms, tabs, drawers, modals
- Pagination, footer/header links, CTAs, empty states
- Auth pages (login, signup, reset, verify), dashboards, admin surfaces
- Legal pages, help pages, error pages, settings, billing
- Hidden routes exposed by JS or referenced in network calls

**For each page:**
- Extract and deduplicate all same-origin links
- Visit each unique route at least once
- Click actionable UI elements where safe
- Submit forms with harmless test inputs
- Observe XHR/fetch/WebSocket/API calls in network traces
- Capture screenshots for key pages and suspicious states
- Record console errors and security-relevant browser warnings

**Classify each route:**
- Public vs auth-required
- Role sensitivity (user / admin / internal)
- Discovery source (link / JS reference / API call / sitemap / guessed)
- HTTP status code

**Outputs:** Route inventory, internal link map, broken link report, auth-state map, API endpoint list.

### Phase 3: Security Assessment

Test the application systematically against all applicable security frameworks.

→ **Read `references/owasp-checks.md`** for the detailed web application checklist
→ **Read `references/frameworks/owasp-complete.md`** to select which OWASP frameworks apply (Top 10, API Top 10, LLM Top 10, Cloud-Native Top 10, K8s Top 10, ASVS level selection, WSTG test mapping)

**Core web testing** (always apply):
- Input validation and sanitization (XSS, injection, template injection)
- Authentication and session management
- Authorization and access control (IDOR, BOLA, privilege escalation)
- Secure data handling and privacy
- API security (CORS, rate limiting, method confusion)
- Security headers and hygiene (CSP, HSTS, X-Frame-Options)
- File upload surfaces
- Vibecoder smell patterns (AI-built speed-over-security shortcuts)

**Infrastructure-specific testing** (apply based on Phase 1 detection):
- If APIs are in scope → read `references/frameworks/api-security.md` for OWASP API Top 10 (2023) deep testing, BOLA/BOPLA/BFLA scenarios, JWT/OAuth testing, GraphQL/gRPC/WebSocket attacks (critical for most modern audits)
- If cloud-deployed → read `references/frameworks/cloud-security.md` and test for cloud-specific attack surfaces (exposed buckets, metadata SSRF, subdomain takeover, serverless auth)
- If Kubernetes → read `references/frameworks/kubernetes-security.md` and test for K8s exposure (API server, dashboard, metrics endpoints, service account tokens)
- If microservices → read `references/frameworks/microservices-security.md` and test for inter-service auth gaps, gateway bypass, flat network access, service impersonation
- If SaaS / multi-tenant → read `references/frameworks/saas-security.md` for tenant isolation testing, cross-tenant leakage patterns (shared cache, search indexes, background jobs), enterprise SSO testing (SAML XSW, OIDC cross-tenant confusion), SCIM abuse, BYOK boundary testing, entitlement bypass, trial abuse, noisy neighbor scenarios — **this is critical for B2B SaaS audits**
- If privacy-regulated (EU/UK/Brazil/CA residents) → read `references/frameworks/privacy-compliance.md` for GDPR/LGPD/CCPA compliance verification, DSAR mechanism testing, data residency verification, consent management, DPIA assessment
- If mobile apps → read `references/frameworks/mobile-security.md` and test for insecure storage, certificate pinning, binary protections, WebView injection, deep link abuse, mobile API security (OWASP Mobile Top 10 M1–M10, MASVS, MASTG)
- If AI/LLM features → read `references/frameworks/ai-llm-security.md` and test for prompt injection (direct + indirect), system prompt leakage, output sanitization, tool/agent permission boundaries, RAG pipeline poisoning, denial-of-wallet, AI privacy (OWASP LLM Top 10 LLM01–LLM10, ML Security Top 10)

**Engagement-type-specific workflows** (apply based on Step 0 engagement type selection):
- If red team / adversary emulation → read `references/frameworks/red-team.md` for full kill chain methodology, TTPs per phase (reconnaissance through actions-on-objectives), C2 framework selection, OPSEC for testers, social engineering, physical security testing, and red team reporting conventions. Red team reports are narrative/path-focused, not vulnerability-list focused.
- If blue team assessment → read `references/frameworks/blue-team.md` for SOC maturity assessment (SOC-CMM), detection engineering evaluation, SIEM/EDR/XDR/NDR coverage review, SOAR automation assessment, threat hunting program evaluation, incident response capability measurement, and deception technology deployment
- If purple team exercise → read `references/frameworks/purple-team.md` for exercise design methodology, Atomic Red Team / CALDERA execution, BAS platform selection, adversary emulation plans (APT3/APT29/FIN7/etc.), MITRE ATT&CK Navigator coverage mapping, DeTT&CT tooling, and the detection feedback loop. Purple team outputs focus on measurable detection coverage improvement, not just findings.

**Architecture assessment** (apply on complex targets):
- Read `references/frameworks/zero-trust.md` to evaluate Zero Trust maturity
- Read `references/frameworks/security-architecture.md` for defense-in-depth and trust boundary analysis

**Risk framework mapping:**
- Read `references/frameworks/risk-management.md` to apply CVSS v4.0 scoring on Critical/High findings
- Map all findings to OWASP Top 10 categories
- Map to NIST CSF 2.0 functions for structural recommendations
- Map attack behavior to MITRE ATT&CK — read `references/frameworks/mitre-attack.md` for tactic/technique annotations and D3FEND defensive counterparts (critical for SOC/blue team integration)
- For quantifiable operational security measurement (RAV scoring, trust analysis, before/after comparison) → read `references/frameworks/osstmm.md` — especially valuable when the user wants reproducible metrics rather than subjective severity
- If the user needs compliance context → read `references/frameworks/iso-standards.md` for ISO 27001 Annex A mappings
- If the user is preparing for or maintaining SOC compliance → read `references/frameworks/soc-auditing.md` for SOC 2 Trust Services Criteria (Common Criteria CC1-CC9) mappings
- If the target handles payment card data → read `references/frameworks/pci-dss.md` for PCI-DSS v4.0.1 requirement mappings (mandatory for merchants, service providers, and anyone in the CDE scope)
- If SaaS customer trust deliverables are in scope (audit readiness for enterprise sales, maturity assessment) → read `references/frameworks/customer-trust-deliverables.md` for trust center review, security questionnaire preparation, DPA assessment, subprocessor management, VDP setup

Use harmless probes only. For each suspected issue, determine what's validated client-side vs server-side and whether validation is bypassable.

**Outputs:** Per-category findings with evidence, severity, confidence, OWASP mapping, and CVSS score (for Critical/High).

### Phase 4: Attack Chain Analysis

Connect individual findings into realistic attacker paths.

→ **Read `references/attack-chains.md` now** for chain patterns and escalation logic.

Think in terms of: recon → foothold → privilege escalation → data access → persistence.

For each chain, explain:
- Why it works (which trust boundary failed)
- What the attacker does next
- Realistic business impact
- Lowest-effort attack path

**Outputs:** Documented attack chains with severity and remediation priority.

### Phase 5: Multi-Model Cross-Review

Run all material findings through multi-model challenge and false-positive reduction.

→ **Read `references/multi-model-review.md` now** for the full review protocol.

**Core process:**
1. One model/agent proposes findings
2. At least two other strong models challenge them
3. A false-positive reviewer attempts to disprove them
4. Only confirmed findings survive

Every High/Critical finding must be reviewed by at least 3 strong reviewers. Document consensus vs disagreement.

**Outputs:** Validated findings with reviewer consensus notes.

### Phase 6: Final Reporting

Produce the complete deliverable package.

→ **Read `references/report-template.md` now** for the full template.
→ **Read `references/frameworks/vulnerability-management.md`** to include VM lifecycle recommendations, CWE classifications, remediation SLAs, and scanning integration advice.

**Required deliverables:**
1. Executive summary
2. Asset and route inventory
3. Internal link sweep report
4. Findings report (with full evidence and framework mappings)
5. Attack chain section
6. Remediation plan (immediate / short-term / medium-term / structural)
7. Evidence bundle references

**Framework enrichment** — every finding should include applicable mappings:
- OWASP category (Top 10, API Top 10, etc.)
- CWE identifier
- CVSS v4.0 vector and score (Critical/High findings)
- MITRE ATT&CK tactic(s) and technique(s) — essential for SOC/blue team integration
- OSSTMM classification (channel, control class, limitation type) — when operational measurement is in scope
- NIST SP 800-53 control (when relevant)
- ISO 27001 Annex A control (when compliance context applies)
- SOC 2 Common Criteria mapping (when SOC context applies)
- PCI-DSS requirement mapping (when payment card data is in scope)
- SaaS tenancy impact (cross-tenant / single-tenant / provider-level) — when auditing SaaS
- Privacy regulation mapping (GDPR/LGPD/CCPA/HIPAA articles) — when personal data involved
- Remediation SLA recommendation

If OSSTMM is in scope, include an **overall RAV score** in the executive summary to provide quantifiable operational security measurement.

**Structural recommendations** should reference:
- NIST CSF 2.0 functions for organizational improvements
- OWASP SAMM maturity targets for SDLC improvements
- Zero Trust maturity progression for architecture improvements
- VM metrics and KPIs for ongoing measurement

Save the final report as a markdown file and offer to convert to docx if the user wants a polished document.

---

## Severity and Confidence Framework

### Severity levels
| Level | Meaning |
|-------|---------|
| Critical | Direct takeover, major data breach, auth bypass to sensitive data, RCE-equivalent |
| High | Exploitable authz break, meaningful PII exposure, practical XSS, admin exposure |
| Medium | Exploitable weakness with constraints, meaningful misconfiguration, partial exposure |
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
Prioritize what attackers actually want: auth bypass, account takeover, sensitive data, admin access, exploitable IDOR, weak session flows, dangerous cross-origin trust, business logic flaws with real impact.

### Reject low-value noise
Don't over-report generic banners, speculative dependency issues without exploit path, missing headers with negligible risk when compensating controls exist, or weak observations without evidence.

### Think in trust boundaries
For every finding, ask: what does the browser trust? What does the app trust? What does the API trust? What user-controlled inputs cross those boundaries? What assumptions fail?

### Vibecoder awareness
Assume the codebase may have been built quickly with AI assistance. Look for speed-over-security patterns: secrets in frontend bundles, auth checks only in UI, missing ownership checks, debug behavior in production, over-permissive CORS, "TODO add auth" behaviors.
