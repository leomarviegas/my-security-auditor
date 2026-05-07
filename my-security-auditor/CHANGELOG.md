# Changelog

All notable changes to `my-security-auditor` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] — 2026-05-07

### Added

- **`references/frameworks/mitre-atlas.md`** — Dedicated MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) reference covering the adversary-tactic lens for AI/ML targets, complementing `ai-llm-security.md` (vulnerability lens). Coverage:

  - **ATLAS vs ATT&CK vs OWASP comparison** — when to use which framework, and how to cite findings across all three.

  - **The ATLAS matrix — 14 tactics** including the two ATLAS-unique ones: AML.TA0005 ML Model Access (between Initial Access and Execution; captures black-box / white-box / on-device / physical-sensor access levels) and AML.TA0001 ML Attack Staging (crafting adversarial examples, training proxy models, verifying attack feasibility before deployment). Plus mappings to ATT&CK Enterprise tactics.

  - **Techniques by tactic** with `AML.T0xxx` IDs grouped under each tactic:
    - Reconnaissance: T0000 Search Public Research, T0001 Public Adversarial Analysis, T0006 Active Scanning, T0007 Search Application Repos
    - Resource Development: T0002 Acquire Public ML Artifacts, T0008 Acquire Infrastructure, T0016 Obtain Capabilities (Foolbox/ART/CleverHans/TextAttack), T0017 Develop Capabilities, T0019 Publish Poisoned Datasets, T0021 Establish Accounts
    - Initial Access: T0010 ML Supply Chain Compromise, T0012 Valid Accounts, T0049 Exploit Public-Facing App, T0052 Phishing, T0053 LLM Plugin Compromise
    - **ML Model Access** (ATLAS-unique): T0040 Inference API Access, T0044 Full Model Access, T0047 ML-Enabled Product, T0041 Physical Environment Access
    - Execution: T0050 Command/Scripting Interpreter (pickle/torch.load risk), T0011 User Execution, T0051 LLM Prompt Injection (with sub-techniques T0051.000 Direct, T0051.001 Indirect)
    - Persistence: T0018 Backdoor ML Model, T0020 Poison Training Data
    - Defense Evasion: T0015 Evade ML Model, T0054 LLM Jailbreak
    - Discovery: T0003 Discover Model Family, T0004 Discover Model Ontology
    - Collection: T0035 ML Artifact Collection, T0036 Data from Information Repos, T0037 Data from Local System
    - **ML Attack Staging** (ATLAS-unique): T0005 Create Proxy Model, T0042 Verify Attack, T0043 Craft Adversarial Data with sub-techniques (T0043.000 White-Box Optimisation, T0043.001 Black-Box Optimisation, T0043.002 Black-Box Transfer, T0043.003 Manual Modification, T0043.004 Insert Backdoor Trigger)
    - Exfiltration: T0024 Exfiltration via ML Inference API with sub-techniques (T0024.000 Membership Inference, T0024.001 Model Inversion, T0024.002 Model Extraction), T0025 Cyber Means, T0055 Unsecured Credentials, T0056 Extract LLM System Prompt, T0057 LLM Data Leakage
    - Impact: T0029 Denial of ML Service, T0031 Erode ML Model Integrity, T0034 Cost Harvesting (denial-of-wallet), T0046 Spamming with Chaff Data, T0048 External Harms with sub-techniques (T0048.000 Financial, T0048.001 Reputational, T0048.002 Societal, T0048.003 User Harm), T0058 Publish Hallucinated Entities (slopsquatting)

  - **Case studies (real-world adversary actions)** — ~25+ documented cases including AML.CS0000 Malware C&C Detector Evasion, CS0002 VirusTotal Poisoning, CS0003 Cylance Bypass, CS0004 Camera Hijack on Facial Recognition, CS0007 Microsoft Tay Poisoning, CS0009 ProofPoint Evasion, CS0010 Microsoft Edge AI Evasion, CS0011 Azure Service Disruption, CS0012 Compromised PyTorch Dependency Chain (torchtriton typosquat), CS0014 Confusing Antimalware NN, CS0015 MathGPT Code Execution via Prompt Injection, CS0017 ClearviewAI Misconfiguration, CS0021 ChatGPT Plugin Privacy Leak, CS0022 ChatGPT Package Hallucination.

  - **Mitigations (M0000–M0015)** — Limit Public Release of Information, Limit Model Artifact Release, Passive Output Obfuscation, Model Hardening (adversarial training/distillation/randomised smoothing/ensembling), Restrict Query Numbers, Control Access at Rest, Use Ensemble Methods, Sanitize Training Data, Validate ML Model, Use Multi-Modal Sensors, Input Restoration, Restrict Library Loading (safetensors over pickle), Encrypt Sensitive Information, Code Signing, Verify ML Artifacts (SLSA/sigstore), Adversarial Input Detection.

  - **ATLAS-anchored audit checklist** organised by audit area: Reconnaissance/Discovery surface, ML Model Access boundary, Supply chain integrity, Training-data integrity, LLM application security (prompt injection / jailbreak / system prompt extraction / PII regurgitation / output sanitisation), Agent / tool-use security, RAG security, Inference-API abuse (DoS / cost harvesting), Defensive evasion testing, Impact controls, Logging & monitoring & incident response. Each checklist item anchored to specific ATLAS technique IDs.

  - **Cross-mapping table** — ATLAS technique ↔ OWASP LLM Top 10 (2025) ↔ OWASP ML Top 10 — for triple-citation in findings (developers want OWASP, defenders want ATLAS, threat-intel wants ATT&CK).

  - **Phase integration guidance** for Phases 0/0.5/1/3/4/5/6 covering AI/ML targets, including adversary-emulation patterns using ATLAS technique chains as emulation atoms (paired with garak, PromptFoo, NeMo Guardrails, PyRIT as test harnesses).

  - **Reporting conventions** — every AI/ML finding should carry OWASP LLM ID + ATLAS technique ID + ATT&CK technique ID + case study reference where applicable; report structure suggestion with ATLAS technique coverage matrix and mitigation roadmap mapped to M-series.

### Changed

- **SKILL.md description** expanded with `MITRE ATLAS` and `adversarial ML` triggers; `MITRE ATT&CK` line now reads `MITRE ATT&CK + ATLAS`. Stays under the 1024-character limit (1016 chars).

- **SKILL.md framework table** adds row for `mitre-atlas.md` alongside `ai-llm-security.md`. The two rows are now labelled "vulnerability lens" and "adversary lens" respectively, signalling that AI-heavy targets should load both.

- **SKILL.md Phase 3 (Security Assessment)** — AI/LLM routing now points to BOTH `ai-llm-security.md` AND `mitre-atlas.md`, with explicit ATLAS technique ID hints (T0051 prompt injection, T0054 jailbreak, T0024 model/data extraction, T0010 supply chain, T0019/T0020 poisoning, T0029 DoS / cost harvesting).

- **SKILL.md Phase 4 (Attack Chain Analysis)** — adds AI/ML chain component with four canonical ATLAS technique chains: indirect prompt injection → tool compromise → exfiltration; supply-chain → backdoor → integrity erosion; model extraction → proxy → transfer attack → evasion; hallucinated package → developer install → code execution.

- **SKILL.md Phase 6 (Final Reporting)** — framework enrichment per finding now explicitly includes ATLAS technique ID(s) `AML.T0xxx` and case study references `AML.CS00xx` for AI/ML findings, in addition to the existing OWASP/CVSS/ATT&CK/OSSTMM stack.

### File count

- 34 files total (was 33)
- 1 `SKILL.md` + 5 core workflow references + 27 framework references (gained `mitre-atlas.md`)

---

## [1.2.0] — 2026-04-19

### Added

- **`references/frameworks/network-security-audit.md`** — Network-layer audit reference covering the five dimensions of network security assessment:
  1. **Namespace access** (intra and extra) — Linux network namespace enumeration (`ip netns`, `/proc/*/ns/net`, `nsenter`), Kubernetes namespace enumeration, probe-pod testing of intra-namespace and cross-namespace reachability, ServiceAccount token mount review, `hostNetwork`/`hostPID` detection, cloud metadata service reachability testing.
  2. **Network services inventory** — per-host (`ss -tulnpe`, `lsof`, `ip addr`, `ip route`, `ip rule`), per-netns listener loop, Kubernetes `svc`/`ingress`/`gateway-api`/`endpoints`/`endpointslices`, `hostPort`/`hostNetwork` pod detection, external scan cross-reference.
  3. **Traffic flow journeys** — nine-step methodology (source, DNS, routing, egress filter, transit, ingress filter, destination, encryption, logging); six path types covered: pod-to-pod same-namespace, pod-to-pod cross-namespace, pod-to-external (with cloud metadata warning), node-to-node (kubelet 10250, kube-apiserver 6443, etcd 2379/2380, overlay VXLAN 8472/Geneve 6081, BGP 179), site-to-site VPN (IPsec `ip xfrm`, WireGuard `wg show`, strongSwan, OpenVPN; red flags for IKEv1, weak PSK, 0.0.0.0/0 selectors), client-to-site VPN (OpenVPN server config, WireGuard `AllowedIPs` per-peer, strongSwan IKEv2 RA with EAP-TLS/RADIUS, Cisco AnyConnect / GlobalProtect / FortiClient / Pulse concentrators with known mass-exploited CVEs, Tailscale / Netbird / Firezone / ZeroTier overlays, Cloudflare Access / Zscaler ZPA / Twingate ZTNA platforms; authentication/authorization/device-posture/split-tunnel/DNS-leak/kill-switch/offboarding-SLA dimensions; Zero Trust migration guidance), user-to-application (dig, mtr, traceroute, sslyze, testssl.sh).
  4. **Network policy auditing** — default-deny NetworkPolicy YAML patterns and per-namespace coverage check script; DNS egress allow pattern; selector correctness (`kubernetes.io/metadata.name` post-1.21); port/protocol specificity; egress blast radius with RFC1918 + 169.254 + 127.0.0.0/8 exclusions; empirical testing with netshoot + hubble; CNI extensions matrix (Cilium CNP/CCNP, Calico GlobalNetworkPolicy, Antrea ClusterNetworkPolicy); service mesh L7 (Istio AuthorizationPolicy + PeerAuthentication, Linkerd Server/ServerAuthorization, Consul ServiceIntentions).
  5. **Host firewall auditing** — iptables all tables (filter/nat/mangle/raw, chain ordering, Kubernetes-specific chains KUBE-*, DOCKER, CILIUM-*, cali-*), ip6tables separately, nftables (inet family, sets, maps, dual-stack), firewalld (zones, rich rules, direct rules), UFW (before/user/after), pf (BSD/macOS), Windows Firewall; cloud adjunct: AWS describe-security-groups/describe-network-acls, GCP gcloud compute firewall-rules, Azure az network nsg; IPv6 dual-stack gotcha; findings tables.
  6. **WAF, load balancer, API gateway, and reverse proxy auditing** (section 7) — edge architecture inventory with empirical fingerprinting; WAF product recognition across cloud, CDN-integrated, appliance, OSS, and API-specific categories; direct-to-origin bypass testing with mitigation requirements; ModSecurity/CRS deep-dive; AWS WAFv2; Cloudflare; load balancer coverage across cloud L4/L7, hardware (F5 BIG-IP, Citrix ADC), software (HAProxy, NGINX, Envoy, Traefik), K8s ingress controllers, service mesh gateways; TLS audit; backend health check hygiene; sticky session cookie flags; X-Forwarded-For chain audit; F5 BIG-IP audit; Citrix NetScaler audit; NGINX/HAProxy config review; ingress-nginx audit; API gateway audit; reverse proxy bug classes (HTTP Request Smuggling, host header confusion, path traversal, CRLF header injection, cache poisoning, WebSocket upgrade smuggling); TLS termination topology mapping; WAF bypass testing methodology; mass-exploited edge CVE catalogue cross-referenced against CISA KEV (F5, Citrix, ingress-nginx IngressNightmare, HAProxy, NGINX, Apache, Envoy/Istio, Kong, Traefik, Fortinet FortiWeb).

### Changed

- **SKILL.md description** expanded with network audit triggers (`network audit`, `firewall audit`, `iptables`, `nftables`, `NetworkPolicy`, `VPN audit`). Stays under the 1024-character limit.

- **SKILL.md framework table** adds row for `network-security-audit.md` describing all five audit dimensions.

- **SKILL.md Step 0 question 8** (new): "Network / infrastructure access" with four levels (none / node-shell / kubectl / cloud-api) routing to appropriate references.

- **SKILL.md scope template** now includes network/infra access line.

- **SKILL.md Safety Rules** — Always-allowed adds read-only network-layer inspection on authorized hosts (`ss`, `iptables -L`, `nft list ruleset`, `kubectl get netpol`, `aws ec2 describe-security-groups`).

- **SKILL.md Phase 0.5 (Codebase Bootstrap)** — adds instruction to inventory network-as-code (Terraform SGs, CloudFormation stacks, NetworkPolicy manifests, Cilium/Calico/Antrea CRDs, iptables-as-Ansible).

- **SKILL.md Phase 1 (Recon Bootstrap)** — adds network-surface detection when Step 0 granted any network/infra access.

- **SKILL.md Phase 3 (Security Assessment)** — new "Network-layer testing" subsection enumerating the five audit dimensions plus edge auditing.

- **SKILL.md Phase 4 (Attack Chain Analysis)** — adds network chain component note (SSRF + unrestricted pod egress + reachable metadata service = credential-compromise chain).

- **SKILL.md Phase 6 (Final Reporting)** — adds network-finding reporting conventions.

### File count

- 33 files total
- 1 `SKILL.md` + 5 core workflow references + 27 framework references

---

## [1.1.0] — 2026-04-18

### Added

- **`references/frameworks/code-analysis.md`** — Source code review methodology.
- **`references/frameworks/appsec-testing-methods.md`** — Formal AppSec testing methodology (SAST, DAST, IAST, RASP, SCA, fuzzing).
- **`README.md`** — Installation instructions, file inventory, usage trigger examples.
- **`CHANGELOG.md`** — This file.

### Changed

- **SKILL.md Step 0** now includes a source code access question.
- **SKILL.md Phase 0.5: Codebase Bootstrap** (new phase) for white-box engagements.
- **SKILL.md Phase 3** now routes to `code-analysis.md` and `appsec-testing-methods.md` when source code is in scope.
- **SKILL.md description** adds triggers for `code review`, `SAST`, `DAST`, `SCA`.

### File count

- 31 files total

---

## [1.0.0] — 2026-04-17

### Added

Initial release with 29 files covering 13 security domains.

[1.3.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.3.0
[1.2.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.2.0
[1.1.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.0.0
