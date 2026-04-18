# my-security-auditor

A Claude Code skill for comprehensive authorized security audits.

## What this skill does

Structured, attacker-minded security assessment covering web applications, APIs, cloud, Kubernetes, microservices, mobile, AI/LLM, and SaaS. Integrates all major security frameworks (OWASP, MITRE ATT&CK, NIST, ISO 27001, SOC 2, PCI-DSS, GDPR/LGPD) plus red/blue/purple team operations, source code review, and formal AppSec testing methods (SAST/DAST/IAST/RASP/SCA).

## Installation

### Option 1: From release (recommended)

Download `my-security-auditor.skill` from the [latest release](https://github.com/leomarviegas/my-security-auditor/releases/latest), then:

```bash
unzip my-security-auditor.skill -d ~/.claude/skills/
```

### Option 2: Clone and symlink

```bash
git clone https://github.com/leomarviegas/my-security-auditor.git
ln -s $(pwd)/my-security-auditor/my-security-auditor ~/.claude/skills/my-security-auditor
```

## What's included (v1.1)

31 files across SKILL.md and 5 core workflow references + 25 framework references:

### Core workflow
- `SKILL.md` — Orchestrator with 7-phase workflow (Step 0, Phase 0.5 codebase bootstrap, Phases 1–6)
- `references/owasp-checks.md` — Web app checklist
- `references/recon-playbook.md` — Bug bounty recon methodology
- `references/attack-chains.md` — 10 chain patterns
- `references/report-template.md` — Multi-audience reporting
- `references/multi-model-review.md` — Gemini/Codex/Qwen/Ollama orchestration

### Framework references (25 files)

**OWASP family:**
- `owasp-complete.md` — Top 10, API/Mobile/LLM/Cloud-Native/K8s Top 10, ASVS, SAMM, WSTG, STRIDE/PASTA/LINDDUN
- `owasp-asvs.md` — ASVS deep dive V1-V14
- `api-security.md` — API Top 10 2023, JWT/OAuth/REST/GraphQL/gRPC/WebSocket/SOAP
- `mobile-security.md` — Mobile Top 10 2024, MASVS, MASTG
- `ai-llm-security.md` — LLM Top 10 2025, prompt injection, RAG

**Infrastructure:**
- `cloud-security.md` — AWS/GCP/Azure, CIS, CSA CCM
- `kubernetes-security.md` — K8s attack surface, RBAC, PSS
- `microservices-security.md` — Service mesh, inter-service auth

**SaaS-specific:**
- `saas-security.md` — Multi-tenancy, SSO/SAML/SCIM, BYOK, entitlements, trial abuse
- `customer-trust-deliverables.md` — CAIQ/SIG, DPAs, subprocessors, VDPs
- `privacy-compliance.md` — GDPR/LGPD/CCPA/HIPAA, DSAR testing

**Compliance:**
- `iso-standards.md` — ISO 27001/27002/27005/27017/27018/27034/27701
- `risk-management.md` — NIST RMF/CSF 2.0, FAIR, CVSS v4.0, EPSS, SSVC
- `soc-auditing.md` — SOC 1/2/3, TSC CC1-CC9
- `pci-dss.md` — PCI-DSS v4.0.1 all 12 requirements, SAQs

**Methodology & tooling:**
- `mitre-attack.md` — ATT&CK matrices (Enterprise/Cloud/Container/Mobile/ICS), D3FEND
- `osstmm.md` — RAV scoring, 5 channels, 17 modules
- `zero-trust.md` — NIST 800-207, CISA ZTMM
- `security-architecture.md` — SABSA, defense in depth, threat modeling
- `vulnerability-management.md` — VM lifecycle, CWE/CVE/CPE

**Engagement types:**
- `red-team.md` — Kill chain, TTPs, C2 frameworks, OPSEC, social engineering
- `blue-team.md` — SOC operations, SOC-CMM, detection engineering, SIEM/EDR/XDR, threat hunting, IR
- `purple-team.md` — Atomic Red Team, CALDERA, BAS, adversary emulation, detection feedback loop

**Code analysis (new in v1.1):**
- `code-analysis.md` — Codebase recon, summarization, per-language patterns (JS/TS, Python, Go, Java, Ruby, Rust, PHP), per-framework (Express, FastAPI, Spring, Django, Rails), taint analysis, auth/authz review, crypto review, git history, config-as-code
- `appsec-testing-methods.md` — SAST/DAST/IAST/RASP/SCA methodology, tool selection, SDLC integration

## Usage

Trigger in Claude Code with phrases like:
- "Audit this web app for security issues"
- "Run a SaaS security audit covering multi-tenancy and tenant isolation"
- "Review my codebase for security issues"
- "Assess my SOC 2 readiness"
- "Red team engagement against [target]"
- "Blue team maturity assessment"
- "Purple team exercise validating detections for [adversary]"

The skill will request authorization, scope, and engagement type before proceeding.

## Note on this repository

The authoritative distribution is the packaged `.skill` file attached to each release. The individual markdown files in this repository are provided for browsing and review. Always install via the release artifact for the complete, validated skill.

## License

Apache License 2.0

## Versions

- **v1.1** — Added `code-analysis.md` and `appsec-testing-methods.md` (source code review + formal AppSec testing methodology)
- **v1.0** — Initial release with 29 files covering web, APIs, cloud, K8s, mobile, AI/LLM, SaaS, red/blue/purple teams, all major compliance frameworks
