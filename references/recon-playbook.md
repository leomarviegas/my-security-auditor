# Bug Bounty Recon Playbook

This reference covers the recon methodology and triage discipline for Phase 1 and the bug-bounty-grade reporting standards used throughout the audit.

## Table of Contents
1. [Recon Objectives](#recon-objectives)
2. [Subdomain and Host Analysis](#subdomain-and-host-analysis)
3. [Asset Discovery](#asset-discovery)
4. [Flow Enumeration](#flow-enumeration)
5. [Finding Discipline](#finding-discipline)
6. [False Positive Policy](#false-positive-policy)

---

## Recon Objectives

The goal of recon is to map the full attack surface before testing begins. Think of it as building a blueprint of everything the attacker can see and touch.

### What to map
- Subdomain behavior across all in-scope hosts
- Differences between marketing site, application, and API exposure
- Trust boundaries between subdomains (shared cookies? shared auth? CORS trust?)
- Redirect patterns between hosts
- Public assets, JS bundles, and the endpoints they reference
- Configuration files at well-known paths
- Authentication and session domains

---

## Subdomain and Host Analysis

For each in-scope host, document:

### DNS and infrastructure signals
- Does the host resolve? To what IP/CDN?
- Are there CNAME chains that reveal hosting providers?
- Do different subdomains share infrastructure or are they separate?

### Behavioral comparison
- Which hosts serve the marketing site vs the application vs the API?
- Do they share the same session cookies?
- What CORS headers does each host return?
- Do they trust each other's origins?
- Are there redirect chains between them?

### Configuration files to check
```
/robots.txt
/sitemap.xml
/.well-known/security.txt
/humans.txt
/crossdomain.xml
/.well-known/openid-configuration
/.well-known/assetlinks.json
/.well-known/apple-app-site-association
```

---

## Asset Discovery

### JavaScript analysis
For every JS bundle loaded by the application:

1. **Route discovery** — search for path patterns (`/api/`, `/admin/`, `/internal/`, route definitions)
2. **Endpoint references** — find API URLs, fetch/axios calls, WebSocket connections
3. **Feature flags** — look for conditional features, A/B test configs, environment checks
4. **Environment values** — API keys, base URLs, debug flags, version strings
5. **Secrets** — any hardcoded tokens, credentials, or connection strings

### Source maps
- Check if `.map` files are accessible for any JS bundle (append `.map` to the URL)
- Source maps expose the complete original source code — this is a significant finding

### Versioned assets
- Note version numbers in asset paths or filenames
- Check if old versions of assets are still accessible
- Look for cache-busting patterns that reveal deployment timestamps

---

## Flow Enumeration

Map every user-facing flow you can discover. For each flow, document the steps, the endpoints called, and any security-relevant behavior.

### Critical flows to find and trace
| Flow | What to look for |
|------|-----------------|
| Login | Auth mechanism, lockout behavior, error messages |
| Signup | Enumeration risk, verification requirements, duplicate handling |
| Logout | Session invalidation, cookie clearing, redirect behavior |
| Password reset | Token delivery, expiry, replay, verification |
| Email verification | Token handling, bypass possibilities |
| Invite / onboarding | Token reuse, role assignment, enumeration |
| Billing / payment | PCI exposure, token handling, authorization |
| Settings / profile | Self-service changes, auth re-verification |
| Admin panel | Access controls, available operations, audit logging |
| Search | Input handling, result exposure, injection surface |
| File upload | Type validation, storage, retrieval security |
| Export / download | Authorization, data scope, path traversal |
| Notifications | Delivery mechanisms, content injection |
| API documentation | Schema exposure, example credentials, playground access |

---

## Finding Discipline

Every finding must meet bug-bounty triage standards. Weak, theoretical, or unsupported findings waste everyone's time and damage credibility.

### Required fields for every finding
```
ID: [unique identifier]
Title: [clear, specific, actionable title]
Severity: [Critical / High / Medium / Low / Informational]
Confidence: [Confirmed / Likely / Needs manual validation]
Affected asset(s): [host, service, component]
Affected route(s)/endpoint(s): [exact URLs or patterns]
Category: [OWASP category or custom]
Description: [what the issue is, in plain language]
Why it works: [which trust boundary or assumption failed]
Attack scenario: [what a real attacker would do with this]
Reproduction steps: [numbered steps anyone can follow]
Evidence: [screenshots, request/response snippets, console output]
Impact: [realistic business/user impact]
False-positive checks performed: [what you did to rule out false positive]
Remediation: [specific, actionable fix]
Reviewer consensus: [which models agreed/disagreed, final verdict]
```

### What makes a finding triage-ready
- The reproduction steps actually work — someone else can follow them
- The evidence supports the claim — not just "I think this might be vulnerable"
- The severity matches the realistic impact — no inflation
- The remediation is specific — not "add better security"
- False-positive checks are documented — shows rigor

### What gets rejected
- "This header is missing" without explaining real-world impact
- "This could theoretically lead to..." without demonstrating it
- Generic scanner output pasted without validation
- Speculative dependency vulnerabilities without a path to exploit
- Missing best practices that have compensating controls in place

---

## False Positive Policy

False positives are the biggest credibility killer in security reporting. Apply this checklist to every finding before finalizing it.

### Before reporting a finding, answer these questions:
1. **Can I reproduce it consistently?** If not, it might be a transient state or measurement error.
2. **Is this intentional behavior?** Some things that look like vulnerabilities are design decisions (e.g., sequential IDs that aren't sensitive).
3. **Are there compensating controls?** A missing header matters less if CSP covers the same risk.
4. **Would an attacker actually exploit this?** If it requires unlikely conditions or yields trivial impact, downgrade or drop it.
5. **Am I the one who's confused?** Sometimes what looks wrong is actually correct behavior you don't fully understand yet.

### Confidence calibration
- **Confirmed**: You reproduced it, you have evidence, you've ruled out false positive
- **Likely**: Strong indicators exist but you couldn't fully reproduce (e.g., timing-based, requires specific account state)
- **Needs manual validation**: Suspicious behavior that could be a vulnerability or could be benign — flag it but be honest about uncertainty
