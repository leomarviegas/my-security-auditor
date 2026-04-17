# Security Policy

## Scope

This security policy covers the `my-security-auditor` skill itself — the orchestration files, reference content, and any tooling in this repository. It does not cover vulnerabilities in applications that use this skill for testing (those should be reported to the application's security team).

## Ethical use

This skill is designed for **authorized security testing only**. Inappropriate use includes:

- Testing systems without written authorization from the owner
- Using the skill to attack production systems you don't own
- Modifying the skill to bypass its authorization requirements
- Using red team content for non-sanctioned activity
- Sharing techniques to enable unauthorized access

Unauthorized security testing is illegal in most jurisdictions under laws like:
- Computer Fraud and Abuse Act (CFAA) — United States
- Computer Misuse Act — United Kingdom
- Lei Carolina Dieckmann (Lei nº 12.737) — Brazil
- Equivalent laws in most other jurisdictions

**The authors and contributors disclaim all responsibility for misuse.** Users are solely responsible for ensuring their activities are authorized.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x.x   | ✅ Active support |
| < 1.0   | ❌ Not supported (pre-release) |

Security updates are applied to the latest minor version. Older versions should be upgraded.

## Reporting a vulnerability

### What to report

Security issues in this skill specifically:

1. **Authorization bypass** — ways to make the skill operate without proper authorization
2. **Safety rule bypass** — ways to make the skill perform prohibited actions (DoS, destruction, etc.)
3. **Injection issues** — ways to manipulate the skill via crafted inputs that cause it to perform unintended actions
4. **Information disclosure** — if the skill could be made to reveal sensitive content inappropriately
5. **Dependency vulnerabilities** — if any tooling has security issues
6. **Supply chain risks** — if the distribution method could be compromised

### What not to report here

- Vulnerabilities in applications audited by this skill (report to the app owner)
- Vulnerabilities in Anthropic's Claude platform (report to Anthropic)
- Vulnerabilities in frameworks referenced by this skill (report to OWASP, MITRE, NIST, etc.)
- General product suggestions (use GitHub issues)

### How to report

**Preferred:** GitHub Security Advisories

Open a private advisory at:
https://github.com/leomarviegas/my-security-auditor/security/advisories/new

This creates a private conversation with the maintainers.

**Alternative:** Email

If GitHub Security Advisories is unavailable, email:
- `leomar.viegas@gmail.com`

Use subject line: `[SECURITY] my-security-auditor — <brief description>`

### What to include

Please include:

1. **Description** — What the vulnerability is
2. **Impact** — What an attacker could achieve
3. **Steps to reproduce** — Exact steps to trigger the issue
4. **Environment** — Claude version, skill version, any relevant context
5. **Proposed fix** — If you have one in mind
6. **Your contact information** — For follow-up questions
7. **Preferred attribution** — How you'd like to be credited (or "anonymous")

### What to expect

**Response timeline:**
- **Initial acknowledgment:** Within 72 hours
- **Preliminary assessment:** Within 7 days
- **Fix development:** 14-90 days depending on severity
- **Public disclosure:** Coordinated with reporter after fix release

**Severity levels:**
- **Critical:** Authorization bypass, safety rule bypass, active exploitation risk
- **High:** Significant impact that affects normal use
- **Medium:** Limited impact or requires specific conditions
- **Low:** Minor issues with minimal impact

### Safe harbor for researchers

If you report a security issue in good faith:

1. We will not pursue legal action for your research activities
2. We will work with you on responsible disclosure timing
3. We will credit you in release notes (unless you prefer anonymity)
4. We consider your report confidential until coordinated disclosure

**Good faith means:**
- You reported the issue rather than exploiting it
- You did not access data beyond what was necessary to demonstrate the issue
- You did not cause harm to users or the project
- You gave reasonable time for a fix before public disclosure (typically 90 days)

We do not currently offer a paid bug bounty program. We deeply appreciate responsible disclosures and will publicly acknowledge contributors in release notes.

## Disclosure process

Once a vulnerability is confirmed:

1. **Private fix development** — We develop and test a fix
2. **CVE assignment** — We request a CVE if appropriate
3. **Fix release** — New version released with fix
4. **Security advisory** — Published on GitHub explaining the issue
5. **Public notification** — Announcement via repository release notes
6. **Credit** — Reporter acknowledged unless anonymity requested

## Known security considerations

### By design

- **Red team content** is included to support authorized adversary emulation. This content describes how attackers operate. It is not a vulnerability; it is an educational resource used under explicit authorization.
- **TTPs documented** in references describe real attacker techniques. This is necessary for defensive testing and detection engineering. Users must have authorization to execute any described technique.
- **Example payloads** in references use inert test strings (e.g., `<script>alert(1)</script>`) deliberately. They demonstrate issues without enabling harm.

### Authorization enforcement

The skill implements multiple authorization checkpoints:

- **Step 0** requires explicit scope confirmation before any activity
- **Safety rules** are absolute and documented in `SKILL.md`
- **Testing posture** (passive/light-probe/active-safe) is set by the user
- **False positive discipline** reduces unintended consequences
- **Out-of-scope rejection** is built into the workflow

These are behavioral controls, not technical enforcement. Users could instruct Claude to ignore them, but doing so is explicitly out of scope of this skill's intended use.

## Security hygiene for users

If you install and use this skill:

1. **Verify integrity** — Check the package hash against GitHub releases
2. **Install from trusted source** — Use the official repository, not mirrors
3. **Keep current** — Update to the latest version for security fixes
4. **Review scope** — Ensure your testing is authorized before triggering the skill
5. **Respect laws** — Understand testing laws in your jurisdiction
6. **Report issues** — If you find a problem, disclose responsibly

## Contact

- Security reports: GitHub Security Advisories or `leomar.viegas@gmail.com`
- General questions: GitHub Issues
- Discussions: GitHub Discussions
