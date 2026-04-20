---
name: my-security-auditor
description: >
  Comprehensive authorized security audit skill covering web, APIs, cloud, Kubernetes, mobile,
  AI/LLM, microservices, SaaS (multi-tenancy, SSO, BYOK), red/blue/purple team ops, source code
  review, formal AppSec testing (SAST/DAST/IAST/RASP/SCA), and network-layer audit (namespace
  access, services inventory, traffic flows, NetworkPolicy, iptables/nftables, VPN). Integrates
  OWASP (Top 10, API/Mobile/LLM/Cloud/K8s, ASVS, SAMM, WSTG, MASVS), MITRE ATT&CK, OSSTMM, NIST
  RMF/CSF, FAIR, ISO 27001 family, CVSS/EPSS/SSVC, Zero Trust, SOC 1/2/3, PCI-DSS v4.0.1,
  GDPR/LGPD/CCPA/HIPAA, customer trust (DPAs, CAIQ/SIG, VDPs), detection engineering, threat
  hunting, adversary emulation, SBOM/SPDX/CycloneDX. Triggers: "security audit", "pentest",
  "code review", "SAST", "DAST", "network audit", "firewall audit", "iptables", "nftables",
  "NetworkPolicy", "VPN audit", "red team", "blue team", "purple team", "OWASP", "ISO 27001",
  "SOC 2", "GDPR", "LGPD", "SaaS security", "MITRE ATT&CK".
---

# Security Auditor

A structured, authorized, attacker-minded security assessment skill for web applications, APIs, cloud infrastructure, Kubernetes, microservices, and network layer. Combines browser-driven crawling, OWASP-style testing, bug-bounty-grade recon, multi-framework compliance mapping, and multi-model review into a single workflow that produces engineer-usable, triage-ready reports.

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
| Network / infrastructure access (node shell, kubectl, cloud API) | `references/frameworks/network-security-audit.md` — namespace access (Linux netns + K8s), network services inventory, traffic flow journeys (pod-to-pod, pod-to-external, node-to-node, site-to-site VPN, user-to-app), NetworkPolicy auditing (default-deny, DNS egress, CNI extensions, service mesh L7), host firewall auditing (iptables, nftables, firewalld, UFW, pf, Windows, cloud SGs/NACLs) |
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
8. **Network / infrastructure access** — is any host, cluster, or cloud API reachable for audit? This determines which network dimensions can be covered:
   - **None** — skip network-layer testing; report only on externally-observable surface
   - **Node / host shell** — enables host firewall review, per-host services inventory, Linux netns enumeration (load `references/frameworks/network-security-audit.md`)
   - **kubectl access** — enables K8s namespace access testing, NetworkPolicy review, service/endpoint inventory (load `references/frameworks/network-security-audit.md` and `references/frameworks/kubernetes-security.md`)
   - **Cloud API access** — enables SG/NACL review, VPC flow analysis, cloud firewall audit (load `references/frameworks/network-security-audit.md` and `references/frameworks/cloud-security.md`)

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
Network/infra access: [none / node-shell / kubectl / cloud-api / multiple]
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
- Packet capture on production without explicit capture consent and data-residency review

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
- Read-only network-layer inspection on authorized hosts (`ss`, `ip addr`, `ip route`, `iptables -L`, `nft list ruleset`, `kubectl get netpol`, `aws ec2 describe-security-groups`)

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
- **Inventory network-as-code** — Terraform security groups and firewall rules, CloudFormation network stacks, NetworkPolicy manifests, Cilium/Calico/Antrea CRDs, iptables-as-Ansible playbooks; the declared network surface should match what Phase 1 observes at runtime
- Generate codebase map document

**Read `references/frameworks/code-analysis.md`** for full methodology.

**Optionally read `references/frameworks/appsec-testing-methods.md`** for SAST/DAST/IAST/SCA tooling.

**Outputs:** Codebase map, entry point inventory, initial SCA findings, network-as-code inventory.

### Phase 1: Recon Bootstrap

Start at each in-scope root URL and gather baseline information.

**Objectives:** capture redirects, robots.txt/sitemap.xml/security.txt, HTTP headers, cookie behavior, framework hints, JS bundles and source maps, trust boundaries between hosts.

**Infrastructure detection** determines which framework references to load (cloud, Kubernetes, microservices, AI/LLM, mobile, SaaS, privacy-regulated).

**Network surface detection** (when Step 0 granted any network/infra access) — run the inventory from `references/frameworks/network-security-audit.md` section 3 as part of recon:
- Per-host listener inventory (`ss -tulnpe`) on authorized nodes
- K8s service / ingress / gateway-api / endpoint inventory if kubectl is available
- Cloud VPC, subnet, route table, security group summary if cloud API access is available
- Cross-reference internal listeners against externally-reachable surface

**Outputs:** `recon-summary.md` with infrastructure signals and (when applicable) network surface inventory.

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

**Network-layer testing** (apply when Step 0 granted any network/infra access):

→ **Read `references/frameworks/network-security-audit.md`** and cover the five audit dimensions:

1. **Namespace access** — enumerate Linux netns and K8s namespaces; test intra-namespace reachability (probe pod reaches peer pods/services); test extra-namespace reachability (cross-ns FQDN, kube-system reachability, cloud metadata service 169.254.169.254); flag `hostNetwork: true`, `automountServiceAccountToken` leaks, and unexpected capability grants.
2. **Services inventory** — per-host `ss -tulnpe`, per-netns listener loop, K8s `svc`/`ingress`/`gateway`/`endpoints`/`endpointslices` dump; flag `hostPort`/`hostNetwork` pods, LoadBalancer/NodePort/externalIP services; cross-reference with external scan.
3. **Traffic flow journeys** — apply the nine-step methodology to significant paths: pod-to-pod same-ns, pod-to-pod cross-ns, pod-to-external (metadata service!), node-to-node control plane (kubelet 10250, kube-apiserver 6443, etcd 2379/2380, overlay VXLAN 8472/Geneve 6081, BGP 179), site-to-site VPN (IPsec `ip xfrm`, WireGuard `wg show`, OpenVPN config), user-to-application (DNS → CDN → LB → ingress → pod; check TLS termination points and back-end mTLS).
4. **Network policy auditing** — verify default-deny NetworkPolicy in every namespace; DNS egress explicitly allowed when default-deny is in place; selector correctness (`kubernetes.io/metadata.name`); port/protocol specificity; egress blast radius with metadata service excluded; empirical testing from probe pod with hubble/calicoctl observability; CNI extensions (Cilium CNP/CCNP, Calico GlobalNetworkPolicy, Antrea ClusterNetworkPolicy); service mesh L7 (Istio AuthorizationPolicy + PeerAuthentication STRICT, Linkerd Server/ServerAuthorization, Consul intentions).
5. **Host firewall auditing** — iptables all tables (filter/nat/mangle/raw), ip6tables separately (dual-stack gotcha), nftables `list ruleset`, firewalld zones + rich rules, UFW before/user/after.rules, pf (BSD/macOS), Windows Firewall profiles; cloud adjunct: AWS security groups/NACLs, GCP firewall rules, Azure NSGs; flag 0.0.0.0/0 on management ports (22/3389/5985/5986) and database ports (3306/5432/1433/6379/27017/9200), stale rules referencing deleted resources, and missing IPv6 coverage.

**Architecture assessment** (apply on complex targets):
- Read `references/frameworks/zero-trust.md` to evaluate Zero Trust maturity
- Read `references/frameworks/security-architecture.md` for defense-in-depth and trust boundary analysis

**Risk framework mapping:** CVSS v4.0, OWASP Top 10, NIST CSF, MITRE ATT&CK (`mitre-attack.md`), OSSTMM (`osstmm.md`), ISO 27001, SOC 2, PCI-DSS, customer trust deliverables.

**Outputs:** Per-category findings with evidence, severity, confidence, OWASP mapping, CVSS score.

### Phase 4: Attack Chain Analysis

→ **Read `references/attack-chains.md`**

Connect findings into realistic attacker paths: recon → foothold → privilege escalation → data access → persistence.

**Network chain component** — when network findings are present, look for the canonical lateral-movement chain: SSRF or RCE in pod → unrestricted pod egress → cloud metadata service reachable → IAM role credentials retrieved → cloud API abuse → data exfil. Missing NetworkPolicies + permissive egress + reachable metadata service is the end-to-end credential-compromise chain — flag each link individually and the chain as a whole.

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

**Network finding reporting conventions** — each network finding must include: (a) exact rule/policy/manifest reference (file path + line number for IaC, or `namespace/name` for K8s resources, or `sg-xxxxxx` for cloud SGs), (b) proposed replacement rule as YAML or command-line form, (c) MITRE ATT&CK mapping (typically TA0008 Lateral Movement, T1046 Network Service Scanning, T1041 Exfiltration Over C2, T1133 External Remote Services), (d) CIS benchmark citation when applicable (e.g., CIS AWS 5.2 for SSH-from-0.0.0.0/0).

If OSSTMM is in scope, include an **overall RAV score** in the executive summary.

---

## Severity and Confidence Framework

### Severity levels
| Level | Meaning |
|-------|---------|
| Critical | Direct takeover, major data breach, auth bypass to sensitive data, RCE-equivalent, flat-network lateral movement to data tier |
| High | Exploitable authz break, meaningful PII exposure, practical XSS, admin exposure, missing network segmentation with reachable secrets |
| Medium | Exploitable weakness with constraints, meaningful misconfiguration, missing default-deny with compensating controls |
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
Prioritize auth bypass, account takeover, sensitive data, admin access, IDOR, weak sessions, dangerous cross-origin trust, business logic flaws with real impact, and **lateral movement paths in flat networks**.

### Reject low-value noise
Don't over-report generic banners, speculative dependency issues without exploit path, or missing headers with negligible risk when compensating controls exist.

### Think in trust boundaries
For every finding, ask: what does the browser trust? What does the app trust? What does the API trust? What does each **pod and namespace** trust? What user-controlled inputs cross those boundaries? What assumptions fail?

### Vibecoder awareness
Assume the codebase may have been built quickly with AI assistance. Look for: secrets in frontend bundles, auth checks only in UI, missing ownership checks, debug behavior in production, over-permissive CORS, "TODO add auth" behaviors, **missing NetworkPolicies combined with unrestricted pod egress and reachable cloud metadata service** — the canonical AI-generated infra shortcut.
