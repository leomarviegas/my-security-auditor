# Changelog

All notable changes to `my-security-auditor` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/leomarviegas/my-security-auditor/releases/tag/v1.0.0
