# my-security-auditor

> Comprehensive Claude skill for authorized security auditing across web, APIs, cloud, Kubernetes, mobile, AI/LLM, microservices, and SaaS — plus red/blue/purple team operations.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Claude Skill](https://img.shields.io/badge/Claude-Skill-orange)](https://docs.claude.com)
[![Frameworks](https://img.shields.io/badge/Frameworks-25%2B-green)](docs/FRAMEWORKS.md)
[![Lines](https://img.shields.io/badge/Lines-17K-lightgrey)](docs/ARCHITECTURE.md)

---

## What it is

A Claude skill that transforms Claude into an experienced security auditor capable of:

- Performing authorized security audits across diverse attack surfaces
- Applying 25+ security frameworks including OWASP, MITRE ATT&CK, NIST, ISO 27001, SOC 2, PCI-DSS, GDPR/LGPD/CCPA/HIPAA
- Running red team adversary emulation, blue team defensive assessment, and purple team collaborative exercises
- Producing audit reports with multi-audience output (executive, technical, developer) and multiple export formats
- Cross-validating findings through multi-model review

The skill uses **progressive disclosure** — the orchestrator (`SKILL.md`) stays under 500 lines and loads deeper framework references only when the audit requires them.

## Key capabilities

| Domain | Coverage |
|--------|----------|
| **Web Application Security** | OWASP Top 10, ASVS L1/L2/L3, WSTG, SAMM |
| **API Security** | OWASP API Top 10 (2023), REST/GraphQL/gRPC/WebSocket/SOAP testing |
| **Cloud Security** | AWS/GCP/Azure, CIS benchmarks, CSA CCM, shared responsibility |
| **Kubernetes Security** | K8s Top 10, RBAC, PSS, NetworkPolicies, NSA/CISA guidance |
| **Mobile Security** | OWASP Mobile Top 10, MASVS, MASTG, Android/iOS specifics |
| **AI/LLM Security** | OWASP LLM Top 10 (2025), ML Security Top 10, prompt injection |
| **Microservices** | Service mesh, inter-service auth, API gateway, event-driven |
| **SaaS Security** | Multi-tenancy, tenant isolation, enterprise SSO, BYOK, entitlements |
| **Customer Trust** | Trust centers, CAIQ/SIG, DPAs, subprocessor management, VDPs |
| **Privacy Compliance** | GDPR, LGPD, CCPA/CPRA, HIPAA, DSAR testing, DPIA |
| **Red Team** | Kill chain models, TTPs per phase, C2 frameworks, OPSEC, adversary emulation |
| **Blue Team** | SOC operations, detection engineering, SIEM/EDR/XDR, threat hunting |
| **Purple Team** | Atomic Red Team, CALDERA, BAS platforms, continuous validation |

See [`docs/FRAMEWORKS.md`](docs/FRAMEWORKS.md) for the complete framework catalog.

## Quick start

### Installation

1. **Download the latest packaged skill** from [Releases](https://github.com/leomarviegas/my-security-auditor/releases) (or build it yourself — see below)

2. **Install to Claude Code:**
   ```bash
   unzip my-security-auditor.skill -d ~/.claude/skills/
   ```

3. **Verify installation:**
   ```bash
   ls ~/.claude/skills/my-security-auditor/
   ```

For detailed installation options (including Claude projects, team deployments, and validation), see [`docs/INSTALLATION.md`](docs/INSTALLATION.md).

### Building from source

```bash
# Clone the repository
git clone https://github.com/leomarviegas/my-security-auditor.git
cd my-security-auditor

# Package the skill (requires skill-creator from Anthropic)
python3 -m scripts.package_skill ./my-security-auditor ./dist/

# Install locally
unzip dist/my-security-auditor.skill -d ~/.claude/skills/
```

### Triggering the skill

The skill activates when Claude receives requests mentioning security auditing concerns:

```
"Perform a security audit of my SaaS application"
"Run an OWASP Top 10 assessment"
"Do a pentest of this API"
"Test my multi-tenant isolation"
"Evaluate my SOC detection coverage"
"Plan a purple team exercise for credential access TTPs"
"Review GDPR compliance for my data handling"
```

See [`docs/USAGE.md`](docs/USAGE.md) for complete usage patterns and example prompts.

## How it works

The skill is organized in six execution phases with progressive loading of framework references:

```
Step 0: Scope & Authorization (mandatory gate)
  ↓
Phase 1: Recon Bootstrap (auto-detects target architecture)
  ↓
Phase 2: Full Browser Traversal
  ↓
Phase 3: Security Assessment (routes to relevant frameworks)
  ↓
Phase 4: Attack Chain Analysis
  ↓
Phase 5: Multi-Model Cross-Review (reduces false positives/negatives)
  ↓
Phase 6: Final Reporting (with framework enrichment per finding)
```

Each finding is automatically annotated with:
- OWASP category (Top 10, API Top 10, etc.)
- CWE identifier
- CVSS v4.0 vector and score
- MITRE ATT&CK tactic(s) and technique(s)
- NIST SP 800-53 / ISO 27001 Annex A / SOC 2 CC / PCI-DSS mappings
- SaaS tenancy impact (when applicable)
- Privacy regulation mappings (when personal data involved)
- Remediation SLA recommendation

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full architecture.

## Documentation

- [**Installation Guide**](docs/INSTALLATION.md) — Setting up the skill in Claude Code
- [**Usage Guide**](docs/USAGE.md) — How to trigger and use the skill effectively
- [**Architecture**](docs/ARCHITECTURE.md) — Progressive disclosure design and phase orchestration
- [**Framework Catalog**](docs/FRAMEWORKS.md) — All 25+ frameworks with summaries
- [**Examples**](docs/EXAMPLES.md) — Real-world audit scenarios (SaaS, red team, purple team, privacy)

## Safety & responsible use

This skill is for **authorized security testing only**. The skill enforces authorization requirements at multiple checkpoints:

- Step 0 requires explicit user authorization before any testing
- Hard safety rules are absolute (no DoS, no data modification, no credential stuffing, no out-of-scope activity)
- False positive discipline is built into the workflow
- Red team content is scoped to authorized engagements

**Unauthorized security testing is illegal in most jurisdictions.** Only use this skill against systems you own or have written permission to test.

See [SECURITY.md](SECURITY.md) for the security policy, vulnerability disclosure process, and ethical use guidelines.

## Contributing

Contributions are very welcome — new frameworks, test scenarios, bug fixes, corrections to existing content, and improvements to the orchestrator are all valuable.

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to propose a new framework reference
- How to test changes locally
- How to submit pull requests
- Style guide for references

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

Licensed under the Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Acknowledgments

This skill builds on the work of many security communities:

- [OWASP Foundation](https://owasp.org/) — Top 10, ASVS, SAMM, WSTG, MASVS, API/Mobile/LLM/Cloud/K8s Top 10
- [MITRE](https://www.mitre.org/) — ATT&CK, D3FEND, CALDERA, Atomic Red Team Evaluations
- [NIST](https://www.nist.gov/) — CSF 2.0, SP 800-53, SP 800-61, RMF
- [ISO/IEC](https://www.iso.org/) — 27001, 27002, 27701, 27017, 27018 families
- [CIS](https://www.cisecurity.org/) — CIS Controls, CIS Benchmarks
- [Cloud Security Alliance](https://cloudsecurityalliance.org/) — CCM, CAIQ, STAR
- [Red Canary](https://redcanary.com/) — Atomic Red Team
- [ISECOM](https://www.isecom.org/) — OSSTMM with RAV

And the broader security research community whose published work informs this skill.

## Disclaimer

This skill is provided "as is" without warranty. The authors are not responsible for misuse or damage caused by unauthorized use. Always obtain proper authorization before conducting security testing. Consult legal counsel if you are unsure about the legality of testing in your jurisdiction.
