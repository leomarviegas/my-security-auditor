# Changelog

All notable changes to `my-security-auditor` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-04-17

First public release. The skill covers 13 security domains across 26 files
with ~17,000 lines of testing guidance and framework references.

### Added

**Core orchestration:**
- `SKILL.md` — 6-phase audit workflow with Step 0 authorization gate
- Progressive disclosure architecture (orchestrator stays under 500 lines)
- Engagement-type detection (vulnerability assessment / pentest / red team / blue team / purple team)
- Infrastructure auto-detection (cloud, Kubernetes, microservices, SaaS, mobile, AI/LLM, privacy-regulated)

**Reference files — core workflow:**
- `recon-playbook.md` — bug-bounty style reconnaissance methodology
- `attack-chains.md` — 10 chain patterns, trust boundaries
- `owasp-checks.md` — web application checklist
- `report-template.md` — comprehensive reporting with multi-audience outputs, finding templates, metrics dashboards, evidence organization, export formats (Markdown, JSON, SARIF, CSV)
- `multi-model-review.md` — cross-validation via Gemini, Codex, Qwen, and other models

**Framework references — OWASP:**
- `owasp-complete.md` — Top 10, API/Mobile/LLM/Cloud-Native/K8s Top 10, ASVS, SAMM, WSTG, threat modeling
- `owasp-asvs.md` — ASVS deep dive, all 14 categories V1-V14, three verification levels
- `api-security.md` — OWASP API Top 10 (2023) deep dive, JWT/OAuth/REST/GraphQL/gRPC/WebSocket/SOAP testing
- `mobile-security.md` — Mobile Top 10 2024, MASVS, MASTG, Android/iOS specifics
- `ai-llm-security.md` — LLM Top 10 2025, ML Security Top 10, prompt injection test suite

**Framework references — Infrastructure:**
- `cloud-security.md` — AWS/GCP/Azure, CIS, CSA CCM, shared responsibility
- `kubernetes-security.md` — K8s attack surface, RBAC, PSS, NetworkPolicies, NSA/CISA
- `microservices-security.md` — service mesh, inter-service auth, API gateway, event-driven

**Framework references — SaaS & compliance:**
- `saas-security.md` — multi-tenancy, tenant isolation, enterprise SSO/SCIM, BYOK, entitlements, trial abuse
- `customer-trust-deliverables.md` — trust centers, CAIQ/SIG, DPAs, subprocessors, VDPs
- `privacy-compliance.md` — GDPR/LGPD/CCPA/CPRA/HIPAA deep dives, DSAR testing, DPIA
- `iso-standards.md` — ISO 27001/27002/27005/27017/27018/27701 families
- `soc-auditing.md` — SOC 1/2/3, Trust Services Criteria CC1-CC9
- `pci-dss.md` — PCI-DSS v4.0.1 all 12 requirements, SAQs, merchant levels

**Framework references — Risk & threat modeling:**
- `risk-management.md` — NIST RMF/CSF 2.0, FAIR, ISO 31000, CVSS v4.0, EPSS, SSVC
- `zero-trust.md` — NIST 800-207, CISA ZTMM
- `security-architecture.md` — SABSA, defense in depth, STRIDE/PASTA/DREAD
- `vulnerability-management.md` — VM lifecycle, CWE/CVE/CPE, SLAs
- `osstmm.md` — OSSTMM 3, RAV scoring, 5 channels, 17 modules
- `mitre-attack.md` — Enterprise/Cloud/Container/Mobile/ICS matrices, D3FEND

**Framework references — Team operations:**
- `red-team.md` — Engagement types, kill chain models (Cyber Kill Chain, Unified Kill Chain, Diamond, Pyramid of Pain), 7-phase TTPs, C2 frameworks, OPSEC, social engineering, physical security, adversary emulation
- `blue-team.md` — SOC operations, SOC-CMM maturity, detection engineering (Sigma/YARA, detection-as-code), SIEM/EDR/XDR/NDR, SOAR, threat hunting, threat intel, incident response, deception technology
- `purple-team.md` — Collaborative exercises, Atomic Red Team, MITRE CALDERA, BAS platforms, adversary emulation plans, ATT&CK coverage assessment, detection feedback loop, continuous validation

### Notes
- All 26 framework references include mapping templates so findings are
  automatically annotated with OWASP / CWE / CVSS / MITRE ATT&CK / NIST 800-53 /
  ISO 27001 / SOC 2 / PCI-DSS / SaaS tenancy impact / privacy regulations
- Report template supports Markdown, JSON, SARIF, and CSV export formats
- Multi-audience reporting: executive summary, technical report, developer guide, metrics dashboard

[Unreleased]: https://github.com/leomarviegas/my-security-auditor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.0.0
