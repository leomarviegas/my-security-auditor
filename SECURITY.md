# Security Policy

## Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

This repository contains a security auditing skill, so it has a particular responsibility to handle vulnerabilities well. If you find a security issue with the skill content itself, or with content that could cause harm if used incorrectly, please report privately.

### How to report

**Preferred:** GitHub Security Advisories
- Go to the [Security tab](../../security/advisories)
- Click "Report a vulnerability"
- Provide details confidentially

**Alternative:** Email
- Send to: leomarviegas@users.noreply.github.com
- Subject: `[SECURITY] my-security-auditor - <brief description>`
- Include details of the issue and reproduction steps

### What to report

**In-scope security concerns:**
- Instructions in the skill that could enable harm to systems the user doesn't own
- Content that could help bypass authentication, authorization, or security controls in ways not clearly labeled as red team / authorized testing
- Inaccurate security advice that could lead to vulnerable implementations
- Embedded secrets, credentials, or other sensitive data in the repository
- Malicious code or suggestions that would compromise users running the skill
- Skill behaviors that could lead to prompt injection against Claude

**Out of scope:**
- General bugs or errors — use [regular issues](../../issues/new?template=bug_report.md)
- Debate over framework best practices — use [feature requests](../../issues/new?template=feature_request.md)
- Questions about the legality of security testing — consult legal counsel
- Issues in third-party references linked from this skill (report to the owners)

### Response timeline

- **Initial acknowledgment:** within 48 hours
- **Triage decision:** within 7 days
- **Resolution timeline:** depends on severity
  - Critical: within 7 days
  - High: within 30 days
  - Medium: within 90 days
  - Low: next regular release

### Disclosure

I follow responsible disclosure:
- Private coordination during the fix
- Public disclosure after fix is released
- Credit to the reporter (unless they prefer anonymity)
- CVE assignment if applicable

## Responsible use

This skill is for **authorized security testing only**.

### Legal considerations

Security testing without authorization is illegal in most jurisdictions. Laws include:
- United States: Computer Fraud and Abuse Act (CFAA)
- United Kingdom: Computer Misuse Act 1990
- European Union: Directive 2013/40/EU
- Brazil: Lei Carolina Dieckmann (12.737/2012), Lei Geral de Proteção de Dados (LGPD)
- Many other jurisdictions have similar laws

### Ethical use guidelines

- **Always obtain written authorization** before testing any system
- **Stay within defined scope** — testing adjacent systems can constitute unauthorized access
- **Document your authorization** — keep written permission accessible
- **Report findings responsibly** — through agreed-upon channels
- **Protect data discovered** — don't exfiltrate, don't retain, don't share
- **No destructive testing** — unless explicitly authorized
- **Respect bug bounty program terms** — they define what is authorized

### If you discover a vulnerability during authorized testing

1. Stop active exploitation immediately
2. Document what you found and how
3. Report through the agreed-upon channel
4. Preserve evidence per engagement rules
5. Do not share details publicly until remediated

### Using this skill for malicious purposes

This skill is licensed under Apache 2.0, which does not prevent malicious use. However:
- Using this skill to perform unauthorized testing is illegal
- The author accepts no responsibility for misuse
- Malicious users are solely responsible for their actions

## Supply chain security

This repository:
- Contains documentation and markdown only — no executable code
- Has no build dependencies
- Has no runtime dependencies beyond the Claude platform
- Requires no external services during skill execution
- Is versioned and signed through GitHub

If you fork or modify this skill:
- Review all changes carefully
- Pin to specific versions rather than tracking main
- Verify integrity before distribution

## Dependencies

The skill itself has no external code dependencies. When used with Claude Code, the skill may invoke:
- Claude's web_search, web_fetch tools (standard platform tools)
- Claude's computer use tools (sandboxed environment)
- Optional MCP integrations (user-installed)

All dependencies are part of the user's Claude environment, not this repository.

## Secrets and credentials

This repository:
- Must not contain any real credentials, tokens, or API keys
- Examples that appear credential-like must be clearly labeled as placeholders
- CI/CD (if added) must not expose secrets

If you spot what appears to be a real credential, report it via security advisory immediately.
