# my-security-auditor

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Claude Code Skill](https://img.shields.io/badge/Claude_Code-Skill-purple)](https://docs.claude.com/en/docs/claude-code/skills)
[![OWASP](https://img.shields.io/badge/OWASP-Top_10_%2B_ASVS-red)](https://owasp.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)](https://attack.mitre.org/)

> Comprehensive Claude Code skill for authorized security audits. Covers web, APIs, cloud, Kubernetes, mobile, AI/LLM, microservices, SaaS (multi-tenancy, enterprise SSO, BYOK), plus red/blue/purple team operations.

## What this is

`my-security-auditor` is a Claude Code skill that transforms Claude into a structured security auditor. Instead of ad-hoc security advice, the skill provides a systematic, phase-based workflow backed by 25+ framework references covering every major security discipline.

**Frameworks integrated:**

- **OWASP** — Top 10, API Top 10, Mobile Top 10, LLM Top 10, Cloud-Native Top 10, K8s Top 10, ASVS, SAMM, WSTG, MASVS
- **MITRE** — ATT&CK + D3FEND, adversary emulation
- **OSSTMM** with RAV scoring
- **NIST** — RMF, CSF 2.0, FAIR, 800-53, 800-207 (Zero Trust)
- **ISO** — 27001, 27002, 27005, 27017, 27018, 27034, 27701
- **Risk scoring** — CVSS v4.0, EPSS, SSVC
- **Compliance** — SOC 1/2/3, PCI-DSS v4.0.1, GDPR/LGPD/CCPA/HIPAA
- **Architecture** — SABSA, Zero Trust (CISA ZTMM), CIS benchmarks, CSA CCM
- **SaaS-specific** — multi-tenancy, enterprise SSO/SCIM, BYOK/CMEK
- **Team ops** — Red team (full kill chain, C2, OPSEC), Blue team (SOC, SIEM, detection engineering, threat hunting), Purple team (CALDERA, Atomic Red Team, BAS platforms)

## Quick start

### Installation

1. Download the latest release: `my-security-auditor.skill`
2. Install to Claude Code:
   ```bash
   unzip my-security-auditor.skill -d ~/.claude/skills/
   ```
3. Verify installation:
   ```bash
   ls ~/.claude/skills/my-security-auditor/
   ```

### Usage

The skill triggers automatically when you ask Claude Code for security-related work. Example prompts:

```
Perform a security audit of https://app.example.com
I need a pentest of our API. Authorized target is api.example.com
Run an OWASP Top 10 review against the codebase
Audit our SaaS tenant isolation — we have customers A and B
Assess our SOC maturity and detection coverage
Design a purple team exercise for credential access TTPs
Check our GDPR/LGPD compliance posture
```

## What makes it different

| Generic "do a security audit" | With this skill |
|-------------------------------|-----------------|
| Ad-hoc checklist from training data | Structured 6-phase workflow (Scope → Recon → Traversal → Assessment → Chains → Report) |
| Generic OWASP mentions | Progressive disclosure — loads only relevant frameworks per target |
| Surface-level findings | Multi-model cross-review for false-positive discipline |
| Subjective severity | CVSS v4.0 + EPSS + SSVC + OSSTMM RAV |
| "Looks secure to me" | Attack chain analysis mapping individual findings into real exploit paths |
| Mixed-audience reports | Separate executive / technical / developer / metrics artifacts |

## Architecture

The skill uses progressive disclosure — `SKILL.md` stays under 500 lines as an orchestrator. Framework references load only when relevant. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for details.

```
my-security-auditor/
├── SKILL.md                              # Orchestrator (~350 lines)
└── references/
    ├── recon-playbook.md                 # Recon methodology
    ├── owasp-checks.md                   # Web app checklist
    ├── attack-chains.md                  # Chain patterns
    ├── report-template.md                # Reporting (multi-audience)
    ├── multi-model-review.md             # Cross-validation
    └── frameworks/                       # 25 deep-dive references
        ├── owasp-complete.md
        ├── owasp-asvs.md
        ├── api-security.md
        ├── mobile-security.md
        ├── ai-llm-security.md
        ├── cloud-security.md
        ├── kubernetes-security.md
        ├── microservices-security.md
        ├── saas-security.md
        ├── customer-trust-deliverables.md
        ├── privacy-compliance.md
        ├── iso-standards.md
        ├── risk-management.md
        ├── soc-auditing.md
        ├── pci-dss.md
        ├── mitre-attack.md
        ├── osstmm.md
        ├── zero-trust.md
        ├── security-architecture.md
        ├── vulnerability-management.md
        ├── red-team.md
        ├── blue-team.md
        └── purple-team.md
```

## Documentation

| Document | Purpose |
|----------|---------|
| [Installation Guide](docs/INSTALLATION.md) | Detailed install instructions |
| [Usage Guide](docs/USAGE.md) | How to invoke the skill, prompt examples |
| [Frameworks Reference](docs/FRAMEWORKS.md) | Complete list of all 25 frameworks with summaries |
| [Architecture](docs/ARCHITECTURE.md) | How the skill is structured |
| [Examples](docs/EXAMPLES.md) | Real-world use cases (SaaS audit, red team, purple team) |
| [Contributing](CONTRIBUTING.md) | How to add frameworks, improve content |
| [Security Policy](SECURITY.md) | Vulnerability disclosure |
| [Changelog](CHANGELOG.md) | Version history |

## Safety and authorization

**This skill is for authorized security testing only.** Before any active testing, the skill's Step 0 mandates:

- Written authorization from the target owner
- Clearly defined scope (in-scope / out-of-scope)
- Testing posture (passive / light-probe / active-safe)
- Engagement type (vulnerability assessment / pentest / red team / blue team / purple team)

The skill refuses to proceed without authorization confirmation. Never use this for unauthorized testing.

## Stats

- **29 files**, ~17,000 lines of security methodology
- **25 framework references** across all major security disciplines
- **6 phases** of audit workflow (Scope → Recon → Traversal → Assessment → Chains → Report)
- **5 engagement types** supported (VA / Pentest / Red / Blue / Purple)

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose new frameworks, improve existing content, or report issues.

## Acknowledgments

Built on decades of security community knowledge. Framework references synthesize guidance from:
OWASP Foundation, MITRE Corporation, ISECOM (OSSTMM), NIST, ISO, Cloud Security Alliance, Center for Internet Security, PCI Security Standards Council, and the broader security community.

---

**Disclaimer:** This skill provides methodology and guidance. It is not a substitute for qualified security professionals on high-stakes engagements. Use appropriate judgment and human oversight for critical security work.
