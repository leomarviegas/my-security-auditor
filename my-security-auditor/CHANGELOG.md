# Changelog

All notable changes to `my-security-auditor` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] — 2026-04-19

### Added

- **`references/frameworks/network-security-audit.md`** — Network-layer audit reference covering the five dimensions of network security assessment:
  1. **Namespace access** (intra and extra) — Linux network namespace enumeration (`ip netns`, `/proc/*/ns/net`, `nsenter`), Kubernetes namespace enumeration, probe-pod testing of intra-namespace and cross-namespace reachability, ServiceAccount token mount review, `hostNetwork`/`hostPID` detection, cloud metadata service reachability testing.
  2. **Network services inventory** — per-host (`ss -tulnpe`, `lsof`, `ip addr`, `ip route`, `ip rule`), per-netns listener loop, Kubernetes `svc`/`ingress`/`gateway-api`/`endpoints`/`endpointslices`, `hostPort`/`hostNetwork` pod detection, external scan cross-reference.
  3. **Traffic flow journeys** — nine-step methodology (source, DNS, routing, egress filter, transit, ingress filter, destination, encryption, logging); six path types covered: pod-to-pod same-namespace, pod-to-pod cross-namespace, pod-to-external (with cloud metadata warning), node-to-node (kubelet 10250, kube-apiserver 6443, etcd 2379/2380, overlay VXLAN 8472/Geneve 6081, BGP 179), site-to-site VPN (IPsec `ip xfrm`, WireGuard `wg show`, strongSwan, OpenVPN; red flags for IKEv1, weak PSK, 0.0.0.0/0 selectors), user-to-application (dig, mtr, traceroute, sslyze, testssl.sh).
  4. **Network policy auditing** — default-deny NetworkPolicy YAML patterns and per-namespace coverage check script; DNS egress allow pattern; selector correctness (`kubernetes.io/metadata.name` post-1.21); port/protocol specificity; egress blast radius with RFC1918 + 169.254 + 127.0.0.0/8 exclusions; empirical testing with netshoot + hubble; CNI extensions matrix (Cilium CNP/CCNP, Calico GlobalNetworkPolicy, Antrea ClusterNetworkPolicy); service mesh L7 (Istio AuthorizationPolicy + PeerAuthentication, Linkerd Server/ServerAuthorization, Consul ServiceIntentions).
  5. **Host firewall auditing** — iptables all tables (filter/nat/mangle/raw, chain ordering, Kubernetes-specific chains KUBE-*, DOCKER, CILIUM-*, cali-*), ip6tables separately, nftables (inet family, sets, maps, dual-stack), firewalld (zones, rich rules, direct rules), UFW (before/user/after), pf (BSD/macOS), Windows Firewall; cloud adjunct: AWS describe-security-groups/describe-network-acls, GCP gcloud compute firewall-rules, Azure az network nsg; IPv6 dual-stack gotcha; findings tables.

### Changed

- **SKILL.md description** expanded with network audit triggers (`network audit`, `firewall audit`, `iptables`, `nftables`, `NetworkPolicy`, `VPN audit`). Stays under the 1024-character limit.

- **SKILL.md framework table** adds row for `network-security-audit.md` describing all five audit dimensions.

- **SKILL.md Step 0 question 8** (new): "Network / infrastructure access" with four levels (none / node-shell / kubectl / cloud-api) routing to appropriate references.

- **SKILL.md scope template** now includes network/infra access line.

- **SKILL.md Safety Rules** — Always-allowed adds read-only network-layer inspection on authorized hosts (`ss`, `iptables -L`, `nft list ruleset`, `kubectl get netpol`, `aws ec2 describe-security-groups`).

- **SKILL.md Phase 0.5 (Codebase Bootstrap)** — adds instruction to inventory network-as-code (Terraform SGs, CloudFormation stacks, NetworkPolicy manifests, Cilium/Calico/Antrea CRDs, iptables-as-Ansible).

- **SKILL.md Phase 1 (Recon Bootstrap)** — adds network-surface detection when Step 0 granted any network/infra access.

- **SKILL.md Phase 3 (Security Assessment)** — new "Network-layer testing" subsection enumerating the five audit dimensions.

- **SKILL.md Phase 4 (Attack Chain Analysis)** — adds network chain component note (SSRF + unrestricted pod egress + reachable metadata service = credential-compromise chain).

- **SKILL.md Phase 6 (Final Reporting)** — adds network-finding reporting conventions (exact rule/policy/manifest reference, proposed replacement rule, MITRE ATT&CK TA0008/T1046/T1041/T1133, CIS benchmark citation).

- **SKILL.md Key Principles** — "Think like an attacker" adds lateral movement in flat networks; "Think in trust boundaries" adds pod and namespace trust dimensions; "Vibecoder awareness" adds missing NetworkPolicies + unrestricted pod egress + reachable metadata service as the canonical AI-generated infra shortcut.

### File count

- 32 files total
- 1 `SKILL.md` + 5 core workflow references + 26 framework references

---

## [1.1.0] — 2026-04-18

### Added

- **`references/frameworks/code-analysis.md`** — Source code review methodology. Codebase reconnaissance, summarization workflow (repo → module → file → function levels), security-focused code review, per-language patterns (JavaScript/TypeScript, Python, Go, Java, Ruby, Rust, PHP), per-framework patterns (Express, FastAPI, Spring Boot, Django, Rails), taint analysis, authentication/authorization code review, cryptography review, input validation & output encoding, error handling review, git history analysis (secret scanning with gitleaks/trufflehog/git-secrets), configuration-as-code review (Dockerfile, Kubernetes, Terraform, CI/CD), and dependency review (SBOM, supply chain attack detection, license compliance).

- **`references/frameworks/appsec-testing-methods.md`** — Formal AppSec testing methodology. Method selection decision tree by code access level, SAST deep-dive (Semgrep, CodeQL, Checkmarx, Fortify, Veracode, SonarQube, Bandit, Brakeman, gosec), DAST (Burp Suite Pro, OWASP ZAP, Nuclei, StackHawk, Schemathesis), IAST (Contrast Security, Seeker, Hdiv), RASP (Imperva, Contrast Protect, Signal Sciences) with WAF comparison, SCA (Snyk, Trivy, Grype, OSV-Scanner) with SBOM generation (SPDX/CycloneDX/SWID), secret scanning, container & IaC scanning, fuzzing (AFL, libFuzzer, go-fuzz, cargo-fuzz, Jazzer, RESTler), SDLC integration with shift-left strategy, and tool stack recommendations by maturity level (startup $0 / mid $10-50k / enterprise $200k-$1M+).

- **`README.md`** — Installation instructions, file inventory, and usage trigger examples.

- **`CHANGELOG.md`** — This file.

### Changed

- **SKILL.md Step 0** now includes a source code access question (none / read-only / full). Routes the engagement into black-box, white-box, or combined testing flows.

- **SKILL.md Phase 0.5: Codebase Bootstrap** (new phase) runs before Phase 1 when source code is accessible. Maps repository structure, enumerates entry points, summarizes critical modules, reviews CI/CD configuration, runs initial SCA, and produces a codebase map that guides all subsequent phases.

- **SKILL.md Phase 3 (Security Assessment)** now routes to `code-analysis.md` and `appsec-testing-methods.md` when source code is in scope.

- **SKILL.md description** adds triggers for `code review`, `SAST`, `DAST`, and `SCA`. Stays under the 1024-character limit.

- **Framework table** in SKILL.md adds rows for the two new references.

### File count

- 31 files total, approximately 20,800 lines
- 1 `SKILL.md` + 5 core workflow references + 25 framework references

---

## [1.0.0] — 2026-04-17

### Added

Initial release with 29 files covering:

**Core workflow (6 files):**
- `SKILL.md` — Orchestrator with 6-phase workflow
- `references/owasp-checks.md` — Web app checklist
- `references/recon-playbook.md` — Bug bounty recon methodology
- `references/attack-chains.md` — 10 chain patterns
- `references/report-template.md` — Multi-audience reporting
- `references/multi-model-review.md` — Multi-model orchestration (Gemini, Codex, Qwen, Ollama)

**OWASP family (5 files):**
- `owasp-complete.md` — Top 10, API/Mobile/LLM/Cloud-Native/K8s Top 10, ASVS, SAMM, WSTG, STRIDE/PASTA/LINDDUN
- `owasp-asvs.md` — ASVS deep dive V1-V14
- `api-security.md` — API Top 10 2023, JWT/OAuth/REST/GraphQL/gRPC/WebSocket/SOAP
- `mobile-security.md` — Mobile Top 10 2024, MASVS, MASTG
- `ai-llm-security.md` — LLM Top 10 2025, prompt injection, RAG

**Infrastructure (3 files):**
- `cloud-security.md` — AWS/GCP/Azure, CIS, CSA CCM
- `kubernetes-security.md` — K8s attack surface, RBAC, PSS
- `microservices-security.md` — Service mesh, inter-service auth

**SaaS-specific (3 files):**
- `saas-security.md` — Multi-tenancy, SSO/SAML/SCIM, BYOK, entitlements, trial abuse
- `customer-trust-deliverables.md` — CAIQ/SIG, DPAs, subprocessors, VDPs
- `privacy-compliance.md` — GDPR/LGPD/CCPA/HIPAA, DSAR testing

**Compliance (4 files):**
- `iso-standards.md` — ISO 27001/27002/27005/27017/27018/27034/27701
- `risk-management.md` — NIST RMF/CSF 2.0, FAIR, CVSS v4.0, EPSS, SSVC
- `soc-auditing.md` — SOC 1/2/3, TSC CC1-CC9
- `pci-dss.md` — PCI-DSS v4.0.1 all 12 requirements, SAQs

**Methodology & tooling (5 files):**
- `mitre-attack.md` — ATT&CK matrices, D3FEND
- `osstmm.md` — RAV scoring, 5 channels, 17 modules
- `zero-trust.md` — NIST 800-207, CISA ZTMM
- `security-architecture.md` — SABSA, defense in depth
- `vulnerability-management.md` — VM lifecycle, CWE/CVE/CPE

**Engagement types (3 files):**
- `red-team.md` — Kill chain, TTPs, C2 frameworks, OPSEC, social engineering
- `blue-team.md` — SOC operations, SOC-CMM, detection engineering, SIEM/EDR/XDR
- `purple-team.md` — Atomic Red Team, CALDERA, BAS, adversary emulation

[1.2.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.2.0
[1.1.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.0.0
