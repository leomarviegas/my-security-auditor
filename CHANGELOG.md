# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-17

### Added
- Initial public release of `my-security-auditor` Claude skill
- Six-phase execution workflow (scope/auth → recon → traversal → assessment → chain analysis → multi-model review → reporting)
- **25+ framework references** covering:
  - **Core workflow:** OWASP web checks, recon playbook, attack chains, multi-model review, reporting template
  - **OWASP:** Top 10, API Top 10 (2023), Mobile Top 10, LLM Top 10 (2025), Cloud-Native Top 10, K8s Top 10, ASVS (all 14 categories V1-V14), SAMM, WSTG, MASVS
  - **Risk & compliance:** NIST CSF 2.0, NIST SP 800-53, NIST RMF, FAIR, ISO 27001/27002/27005/27017/27018/27034/27701/27035/27032, CVSS v4.0, EPSS, SSVC
  - **Cloud & infrastructure:** Cloud security (AWS/GCP/Azure), Kubernetes security, Microservices security, Zero Trust (NIST 800-207, CISA ZTMM)
  - **Specialized:** Mobile security, AI/LLM security, SaaS security (multi-tenancy, enterprise SSO, BYOK), Privacy compliance (GDPR/LGPD/CCPA/HIPAA), Customer trust deliverables, API security deep-dive
  - **Standards:** SOC 1/2/3, PCI-DSS v4.0.1, CIS Controls, CSA CCM, SABSA
  - **Threat modeling:** MITRE ATT&CK + D3FEND, OSSTMM with RAV scoring, vulnerability management
  - **Team operations:** Red team methodology, Blue team defensive operations, Purple team continuous validation
- **Multi-audience reporting** — executive summary, technical report, per-developer guide, metrics dashboard
- **Export formats** — Markdown, JSON, SARIF, CSV
- **Framework enrichment** — every finding automatically annotated with OWASP/CWE/CVSS/MITRE/NIST/ISO/SOC 2/PCI-DSS/SaaS/privacy mappings
- **Progressive disclosure architecture** — orchestrator (SKILL.md) under 500 lines, deep references loaded only when needed
- **Engagement type awareness** — vulnerability assessment / pentest / red team / blue team / purple team
- **Multi-model review integration** — Gemini, Codex, Qwen, Ollama Cloud for cross-validation
- **Repository documentation:**
  - README with badges and quick start
  - LICENSE (Apache 2.0)
  - CONTRIBUTING.md with style guide
  - SECURITY.md with vulnerability disclosure policy
  - CODE_OF_CONDUCT.md (Contributor Covenant)
  - Issue templates (bug report, feature request, framework request)
  - Pull request template
  - Comprehensive docs/ directory (INSTALLATION, USAGE, FRAMEWORKS, ARCHITECTURE, EXAMPLES)

### Safety
- Mandatory authorization gate at Step 0
- Absolute safety rules (no DoS, no data modification, no credential stuffing, no out-of-scope activity)
- False positive discipline built into workflow
- Red team content scoped to authorized engagements

## Upcoming

### Planned for [1.1.0]
- FedRAMP framework reference
- HITRUST CSF framework reference
- Expanded OAuth 2.1 / OIDC security testing
- WebAuthn/FIDO2 testing scenarios
- Additional adversary emulation plans (APT40, Lazarus, Scattered Spider)

### Ideas under consideration
- Video tutorials linked from docs
- Auto-generated framework coverage matrix
- Integration with common audit tools (Burp Suite projects, Nuclei templates)
- Dedicated container security reference (beyond K8s)
- Hardware security reference (firmware, embedded, IoT)

---

For older changes before public release, see commit history.

## Versioning

- **Major** — backward-incompatible changes to skill structure or orchestrator behavior
- **Minor** — new framework references, significant expansions to existing references
- **Patch** — corrections, typo fixes, minor improvements
