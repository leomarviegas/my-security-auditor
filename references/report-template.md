# Security Audit Reporting

This reference provides comprehensive guidance on producing high-quality security audit deliverables. Good reporting is where most audits fail — technical findings are useless if they don't reach the right audience in the right format with clear action items.

## Table of Contents
1. [Reporting Philosophy](#1-reporting-philosophy)
2. [Multi-Audience Reporting](#2-multi-audience-reporting)
3. [Executive Summary](#3-executive-summary)
4. [Technical Report Structure](#4-technical-report-structure)
5. [Finding Template & Examples](#5-finding-template--examples)
6. [Evidence Organization](#6-evidence-organization)
7. [Metrics and Dashboards](#7-metrics-and-dashboards)
8. [Remediation Tracking](#8-remediation-tracking)
9. [Retest and Verification Reporting](#9-retest-and-verification-reporting)
10. [Export Formats](#10-export-formats)
11. [Common Reporting Mistakes](#11-common-reporting-mistakes)
12. [Report Quality Checklist](#12-report-quality-checklist)

---

## 1. Reporting Philosophy

### The report is the product
Everything else in the audit — discovery, testing, validation — is in service of producing a report that drives remediation. A brilliant audit with a poor report is a failed audit. Report with the same rigor you test with.

### Core principles
| Principle | Implementation |
|-----------|---------------|
| **Right audience, right detail** | Different readers need different depth — don't make executives read CVE numbers |
| **Facts, then analysis** | Distinguish what you found from what you think it means |
| **Actionable over comprehensive** | A shorter report with clear actions beats an exhaustive report |
| **Reproducible** | Anyone should be able to verify findings by following your steps |
| **Respectful** | The target's engineering team is your partner, not your enemy |
| **Quantifiable improvement** | The client should be able to measure "are we more secure after remediation?" |

### What a good report enables
1. **Executives** — understand risk and approve remediation budget
2. **Engineering managers** — prioritize work across teams and sprints
3. **Developers** — fix individual findings with clear steps
4. **Security teams** — track remediation and perform retesting
5. **Compliance teams** — map findings to controls and frameworks
6. **Auditors (external)** — verify the work was done properly

If the report doesn't serve all six readers, it's incomplete.

---

## 2. Multi-Audience Reporting

Produce multiple report artifacts from a single audit, tailored to each audience.

### The four core artifacts
| Artifact | Length | Audience | Purpose |
|----------|--------|----------|---------|
| Executive Summary | 1-2 pages | C-level, board | Risk overview, budget approval |
| Technical Report | 20-100+ pages | Security, engineering leadership | Complete findings with evidence |
| Developer Remediation Guide | Per-finding | Individual developers | Fix the specific issues |
| Metrics Dashboard | 1 page | Anyone tracking over time | Current state, trends |

### Artifact structure per audience

**Executive (2 pages max):**
- One-paragraph business risk summary
- Finding counts by severity (visual)
- Top 5 business risks with impact
- Remediation cost/effort estimate
- Recommended priorities
- Regulatory/compliance implications

**Technical Leadership (20-40 pages):**
- Executive summary (2 pages)
- Scope and methodology
- Findings summary dashboard
- All findings grouped by severity, each 1-2 pages
- Attack chains
- Architectural observations
- Remediation roadmap
- Compliance mappings
- Appendix: methodology, tools, evidence index

**Developer (1-3 pages per finding):**
- Finding title and severity
- Specific affected code/endpoints
- Reproduction steps
- Evidence (screenshots, request/response)
- Specific fix with code example
- Testing guidance (how to verify the fix)
- References to secure coding guidance

**Metrics Dashboard (1 page):**
- Current severity distribution
- Trend vs last audit
- Remediation SLA compliance
- Risk score (or RAV) with comparison
- Compliance posture (by framework)
- Category heatmap (where most findings cluster)

---

## 3. Executive Summary

The executive summary is the most-read and least-forgiven part of the report. Write it last, after everything else is done.

### Executive summary template
```markdown
# Security Audit — Executive Summary

**Target:** [Organization / Application name]
**Audit period:** [Date range]
**Audit type:** [Web / API / Mobile / Cloud / Full-stack]
**Auditor:** [Name / Organization]

## Bottom Line
[One paragraph — 3-4 sentences — capturing the overall security posture,
most critical risk, and essential next step.]

## Key Findings

### By the numbers
| Severity | Count | SLA Remediation |
|----------|-------|-----------------|
| Critical | N     | 24-72 hours     |
| High     | N     | 1-2 weeks       |
| Medium   | N     | 1-3 months      |
| Low      | N     | 3-6 months      |
| Info     | N     | Next cycle      |

### Top 3 Business Risks
**Risk 1:** [title]
- Impact: [business description]
- Likelihood: [High/Medium/Low]
- Affected: [users/systems/data]

**Risk 2:** [same structure]
**Risk 3:** [same structure]

## Required Actions
### Within 72 hours
- [Immediate actions]

### Within 2 weeks
- [Short-term actions]

### Within 90 days (structural)
- [Medium-term improvements]

## Compliance Impact
| Framework | Impact |
|-----------|--------|
| PCI-DSS | [e.g., 3 requirements not met] |
| SOC 2 | [e.g., CC6.1 operational gap] |

## Estimated Remediation Effort
Total: ~[X] engineering days over [timeline]
```

### Executive summary principles
- **Business impact before technical detail** — "Attackers can read any user's private messages" not "Missing authorization check at /api/messages/:id"
- **Quantify when possible** — "~50,000 users affected" not "many users"
- **Be honest about severity** — don't soften to avoid bad news
- **End with clear next steps** — the executive should close the document knowing what to do

---

## 4. Technical Report Structure

### Complete technical report outline

```
# Security Audit Technical Report
**Version:** 1.0
**Date:** [date]
**Confidentiality:** [Restricted / Confidential]

## Table of Contents

## 1. Executive Summary
[See Executive Summary section]

## 2. Scope and Methodology
### 2.1 Scope
### 2.2 Authorization
### 2.3 Testing Posture
### 2.4 Methodology [frameworks applied]
### 2.5 Tools Used
### 2.6 Limitations

## 3. Audit Statistics
### 3.1 Coverage metrics
### 3.2 Finding distribution
### 3.3 Finding categories
### 3.4 Operational security score (RAV if OSSTMM applied)

## 4. Key Findings Summary
[Table of all findings]

## 5. Detailed Findings
### 5.1 Critical Severity Findings
### 5.2 High Severity Findings
### 5.3 Medium Severity Findings
### 5.4 Low Severity Findings
### 5.5 Informational Findings

## 6. Attack Chains

## 7. Architectural Observations

## 8. Remediation Plan
### 8.1 Immediate (24-72 hours)
### 8.2 Short-term (1-2 weeks)
### 8.3 Medium-term (1-3 months)
### 8.4 Structural (ongoing)
### 8.5 Process Improvements

## 9. Compliance Mapping
### 9.1 OWASP Top 10 Coverage
### 9.2 OWASP ASVS Compliance
### 9.3 Other applicable frameworks

## 10. Appendices
### A. Asset Inventory
### B. Endpoint Inventory
### C. Link Sweep Results
### D. Tools and Commands
### E. Evidence Index
### F. Methodology Notes
### G. Glossary
### H. References
```

---

## 5. Finding Template & Examples

### Complete finding template

```markdown
## [FINDING-ID]: [Clear, Specific Title]

**Severity:** Critical / High / Medium / Low / Informational
**Confidence:** Confirmed / Likely / Needs manual validation
**Status:** Open / Fixed / Accepted / False positive

### Affected Assets
- **Host(s):** [specific hosts]
- **Endpoint(s)/Route(s):** [exact URLs]
- **Component(s):** [specific components]

### Summary
[2-3 sentences in plain language — what is the issue, who's affected,
what's the impact. Readable by non-technical staff.]

### Technical Description
[Detailed explanation for engineers.]

### Why It Works
[Which trust boundary or security assumption fails. Root cause.]

### Attack Scenario
[Narrative of real attacker exploitation:]
1. How the attacker discovers this
2. What prerequisites they need
3. Step-by-step exploitation
4. What they accomplish
5. What additional attacks this enables

### Reproduction Steps
1. [Numbered step 1]
2. [Numbered step 2]
3. [Numbered step 3]

### Evidence
[Screenshots, request/response pairs, console output]

**Request:**
```http
GET /api/users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer <token>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json
{"sensitive": "data"}
```

Screenshots: `evidence/FINDING-001/`

### Business Impact
- **Data at risk:** [specifics]
- **Users affected:** [count/category]
- **Regulatory impact:** [GDPR/HIPAA/PCI]
- **Reputational impact:** [if made public]
- **Financial impact:** [direct costs]

### Remediation

**Immediate mitigation:**
[Workarounds if fix takes time]

**Proper fix:**
[Specific technical fix with code example]

```python
# Before (vulnerable)
@app.route('/api/users/<id>')
def get(id): return User.query.get(id).dict()

# After (secure)
@app.route('/api/users/<id>')
@require_auth
def get(id):
    if not current_user.can_access(id):
        abort(403)
    return User.query.get(id).dict()
```

**Verification:**
[How to verify the fix — specific tests]

**References:**
- [OWASP guide link]
- [CWE link]

### False Positive Checks
- [Check 1 and result]
- [Check 2 and result]

### Framework Mappings
| Framework | Mapping |
|-----------|---------|
| OWASP Top 10 | A01:2021 Broken Access Control |
| OWASP API Top 10 | API1:2023 Broken Object Level Authorization |
| OWASP ASVS | V4.1.3 (L1) |
| CWE | CWE-639 |
| CVSS v4.0 | [vector] [score] |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application |
| NIST SP 800-53 | AC-3 Access Enforcement |
| ISO 27001 | A.8.3 Information access restriction |
| SOC 2 | CC6.1 |
| PCI-DSS | 7.2, 7.3 |

### Reviewer Consensus
- **Primary analyst:** [verdict + reasoning]
- **False-positive challenger:** [verdict]
- **Exploit plausibility:** [verdict]
- **Independent reviewer:** [verdict]
- **Final verdict:** [confirmed severity]
```

### Finding severity calibration examples

**When to mark Critical:**
- Unauthenticated RCE on production
- Full database dump without auth
- Authentication bypass to admin
- Cryptographic keys exposed publicly
- Vulnerability affecting >10K users with trivial exploit

**When to mark High:**
- Authenticated RCE
- Bulk PII access via authenticated IDOR
- Privilege escalation to admin
- Stored XSS in admin interface
- Authenticated SQLi

**When to mark Medium:**
- Reflected XSS requiring user interaction
- Limited IDOR (single record, non-sensitive)
- Information disclosure without exploitation path
- Weak encryption for non-sensitive data
- CSRF without high-impact actions

**When to mark Low:**
- Missing security headers with compensating controls
- Limited information leakage
- Weak password policy (without abuse)
- Minor hardening opportunities
- DoS requiring significant resources

**When to mark Informational:**
- Defense-in-depth improvements
- Best practice recommendations
- Security maturity observations
- Documentation improvements

### Full finding example (condensed)

```markdown
## F-001: BOLA Allows Access to Any User's Private Messages

**Severity:** High **Confidence:** Confirmed **Status:** Open

### Affected Assets
- api.example.com, GET /api/v1/messages/:message_id

### Summary
Any authenticated user can read any other user's private messages by
changing the message ID in the request. ~45,000 users affected.

### Why It Works
Endpoint authenticates the request but doesn't verify ownership.
Backend trusts that the UI only shows IDs the user owns.

### Attack Scenario
1. Attacker registers account, logs in, captures token
2. Message IDs are sequential — trivial to enumerate
3. Script iterates IDs 1-50000 with ~3hr rate limiting
4. Complete archive of all historical messages obtained

### Reproduction Steps
1. Register account A, send message (note ID 47823)
2. Register account B, capture its token
3. curl -H "Authorization: Bearer <B_TOKEN>" api.example.com/api/v1/messages/47823
4. Observe account A's message returned

### Evidence
[Request/response pairs, screenshots]

### Remediation
```python
# Add ownership check
if (message.sender_id != current_user.id and 
    current_user.id not in message.recipient_ids):
    abort(403)
```

### Framework Mappings
| Framework | Mapping |
|-----------|---------|
| OWASP API Top 10 | API1:2023 BOLA |
| CWE | CWE-639 |
| CVSS v4.0 | 7.1 High |
| ISO 27001 | A.8.3 |
| SOC 2 | CC6.1 |
| PCI-DSS | 7.2 |
```

---

## 6. Evidence Organization

Evidence must be organized to be useful. Poor evidence organization is a common weakness.

### Evidence directory structure
```
audit-{target}-{date}/
├── README.md
├── scope.md
├── methodology.md
├── report/
│   ├── executive-summary.md
│   ├── executive-summary.pdf
│   ├── technical-report.md
│   ├── technical-report.pdf
│   └── developer-guide.md
├── findings/
│   ├── F-001-bola-messages/
│   │   ├── finding.md
│   │   ├── screenshots/
│   │   │   ├── 01-request.png
│   │   │   ├── 02-response.png
│   │   │   └── 03-impact.png
│   │   ├── evidence/
│   │   │   ├── burp-requests.xml
│   │   │   └── curl-reproduction.sh
│   │   └── references/
│   ├── F-002-.../
│   └── ...
├── recon/
│   ├── endpoints-discovered.json
│   ├── routes-inventory.csv
│   ├── link-sweep-results.csv
│   ├── subdomain-enumeration.txt
│   └── screenshots/
├── network-captures/
│   ├── full-session.har
│   └── specific-flows/
├── tools/
│   ├── nuclei-results.json
│   ├── burp-project.burp
│   └── custom-scripts/
└── chain-of-custody.md
```

### Evidence quality standards

Each piece of evidence should have:
| Attribute | Why |
|-----------|-----|
| Timestamp | When was this collected |
| Source | What tool, what target |
| Context | What was happening |
| Integrity | Hash of the evidence file |
| Chain of custody | Who handled it |

### Chain of custody template
```markdown
# Chain of Custody
## Audit: [Target-Date]

| Timestamp | Evidence ID | Action | By | Hash |
|-----------|-------------|--------|----|----|
| 2024-03-15 14:23 UTC | F-001/burp-requests.xml | Captured | Claude | sha256:abc... |
| 2024-03-15 15:00 UTC | F-001/ | Reviewed | Sec Lead | — |
```

### Redaction for external sharing
- Replace real usernames with "User A", "User B"
- Redact real email addresses
- Redact real tokens (show format, not value)
- Redact PII in screenshots
- Keep evidence clarity, remove identifying details

---

## 7. Metrics and Dashboards

### Core audit metrics dashboard

```markdown
## Security Posture Metrics

### Finding metrics
- Total findings: X
- Critical: X (X%)
- High: X (X%)
- Medium: X (X%)
- Low: X (X%)
- Informational: X (X%)

### Coverage metrics
- Endpoints tested: X of Y discovered (X%)
- OWASP Top 10 categories verified: 10 of 10
- ASVS L[N] requirements verified: X of Y (X%)
- Authentication flows tested: X of Y

### Severity metrics
- Average CVSS: X.X
- Maximum CVSS: X.X
- Findings with CVSS > 7.0: X

### Operational metrics (if OSSTMM applied)
- OSSTMM RAV score: X%
- Trust boundary violations: X
- Missing controls: X

### Compliance metrics
- ASVS L2 compliance: X% (X of Y requirements)
- PCI-DSS requirements at risk: X
- ISO 27001 control gaps: X
- SOC 2 CC gaps: X
```

### Trend tracking (recurring audits)

```markdown
## Finding count over time
| Audit | Date | Critical | High | Medium | Low | Info | Total |
|-------|------|----------|------|--------|-----|------|-------|
| 1 | 2024-Q1 | 5 | 12 | 23 | 34 | 12 | 86 |
| 2 | 2024-Q2 | 2 | 8 | 19 | 28 | 15 | 72 |
| 3 | 2024-Q3 | 0 | 4 | 15 | 22 | 18 | 59 |
| 4 | 2024-Q4 | 0 | 2 | 11 | 18 | 20 | 51 |

## RAV trend
Q1: 47% → Q2: 58% → Q3: 71% → Q4: 81%

## Remediation SLA compliance
Q1: 42% → Q2: 61% → Q3: 78% → Q4: 89%
```

### Category heatmap
Identify where findings cluster:

```
OWASP Top 10 finding distribution:

A01 Access Control        ████████████████ 12
A02 Cryptographic         ██ 2
A03 Injection             ██████ 5
A04 Insecure Design       ████████ 7
A05 Misconfiguration      ██████████ 9
A06 Vulnerable Components ████ 3
A07 Auth Failures         ██████████████ 11
A08 Integrity Failures    █ 1
A09 Logging & Monitoring  ██████████████████ 15
A10 SSRF                  ██ 2
```

This instantly shows where architectural improvements are most needed.

---

## 8. Remediation Tracking

### Remediation state machine
```
Open → In Progress → Fixed (awaiting retest) → Verified Closed
                                             → Remains Open (retest failed)
     → Accepted (risk accepted)
     → False Positive
     → Duplicate
```

### Remediation tracking table
```markdown
| Finding | Severity | Status | Assigned | Due | Updated | Verified |
|---------|----------|--------|----------|-----|---------|----------|
| F-001 | High | In Progress | @alice | 2024-03-29 | 2024-03-20 | — |
| F-002 | Critical | Fixed | @bob | 2024-03-16 | 2024-03-16 | Pending retest |
| F-003 | Medium | Accepted | @security | — | 2024-03-18 | CISO approval |
| F-004 | Low | False Positive | — | — | 2024-03-17 | Security team |
```

### Risk acceptance documentation
```markdown
## Risk Acceptance: F-XXX

**Finding:** [title]
**Severity:** [level]
**Accepted by:** [name, title, date]
**Accepted until:** [review date]

### Rationale
[Why risk is accepted rather than remediated]

### Compensating controls
[What protects against exploitation despite not fixing]

### Monitoring
[How the risk will be monitored]

### Review triggers
[What would cause re-evaluation]
```

---

## 9. Retest and Verification Reporting

After findings are reported "Fixed", verify the fixes.

### Retest report template
```markdown
# Retest Report
**Original audit:** [reference]
**Retest date:** [date]
**Scope:** [which findings]

## Retest Results Summary
| Finding | Original | Retest Result | Notes |
|---------|----------|---------------|-------|
| F-001 | High | ✅ Fixed | Verified via reproduction steps |
| F-002 | Critical | ✅ Fixed | Verified + regression test added |
| F-003 | Medium | ❌ Not Fixed | Fix was partial, still reproducible |
| F-004 | High | ⚠️ New Issue | Fix introduced F-015 |

## Verified Fixes (X findings)
[Details of each]

## Incomplete Fixes (Y findings)
[Details of each]

## New Issues from Fixes (Z findings)
[Details of each]

## Overall Improvement
- Findings closed: X
- New findings: Y
- Net change: X - Y = Z findings improvement
- Severity-weighted improvement: [calculation]
```

### Verification methodology per finding
1. Re-execute original reproduction steps
2. Verify vulnerability is no longer reproducible
3. Test for bypass (attackers try variations)
4. Test adjacent functionality for similar patterns
5. Verify no new issues introduced
6. Document verification

---

## 10. Export Formats

Different stakeholders need reports in different formats.

### Format decision matrix
| Audience | Format | Why |
|----------|--------|-----|
| Executives | PDF, PowerPoint | Professional, shareable |
| Engineering leadership | PDF, Markdown | Readable, printable |
| Individual developers | Markdown, GitHub Issues | In their workflow |
| Compliance teams | PDF with appendices | Archival |
| Security tools | JSON, SARIF | Integration |
| Tracking systems | CSV | Jira/Linear import |

### JSON export format
```json
{
  "audit": {
    "id": "AUDIT-2024-Q1",
    "target": "example.com",
    "date_range": {"start": "2024-03-01", "end": "2024-03-15"},
    "methodology": ["OWASP Top 10", "ASVS L2", "OSSTMM"],
    "auditor": "Claude AI Security Auditor"
  },
  "summary": {
    "total_findings": 51,
    "severity_counts": {
      "critical": 0, "high": 2, "medium": 11, "low": 18, "informational": 20
    },
    "rav_score": 81
  },
  "findings": [
    {
      "id": "F-001",
      "title": "BOLA Vulnerability in Messages Endpoint",
      "severity": "high",
      "confidence": "confirmed",
      "status": "open",
      "cvss": {
        "version": "4.0",
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N",
        "score": 7.1
      },
      "affected": {
        "hosts": ["api.example.com"],
        "endpoints": ["/api/v1/messages/:id"],
        "methods": ["GET"]
      },
      "mappings": {
        "owasp_top_10": ["A01:2021"],
        "owasp_api_top_10": ["API1:2023"],
        "owasp_asvs": ["V4.1.3"],
        "cwe": ["CWE-639"],
        "mitre_attack": ["T1190"],
        "iso_27001": ["A.8.3"],
        "soc_2": ["CC6.1"],
        "pci_dss": ["7.2"]
      },
      "evidence": "findings/F-001/",
      "remediation": {
        "priority": "high",
        "sla_days": 14,
        "estimated_effort_days": 2
      }
    }
  ]
}
```

### SARIF format
SARIF (Static Analysis Results Interchange Format) is the standard for security findings interchange. It integrates with GitHub Advanced Security, Azure DevOps, and most security platforms.

Key SARIF fields:
- `tool.driver.name` — auditor identifier
- `results[].ruleId` — finding type
- `results[].level` — severity (error/warning/note)
- `results[].locations[].physicalLocation` — finding location
- `results[].message` — description
- `results[].properties` — framework mappings

### CSV export for tracking systems
```csv
ID,Title,Severity,Status,CVSS,Endpoint,Method,Assigned,DueDate,OWASP,CWE
F-001,BOLA in Messages,High,Open,7.1,/api/v1/messages/:id,GET,,2024-03-29,A01:2021,CWE-639
F-002,JWT none algorithm,Critical,Fixed,9.8,/api/auth/verify,POST,@bob,2024-03-16,A02:2021,CWE-347
```

### Markdown with HTML enhancements
For technical reports, markdown with embedded HTML enables:
- Callout boxes for severity
- Collapsible sections for evidence
- Syntax highlighting for code
- Mermaid diagrams for attack chains
- Properly styled tables

---

## 11. Common Reporting Mistakes

### Content mistakes
| Mistake | Fix |
|---------|-----|
| Severity inflation | Calibrate against realistic impact, not theoretical worst case |
| Generic recommendations | Be specific with code and patterns, not "add proper auth" |
| Missing reproduction steps | Always include numbered steps anyone can follow |
| No business context | Always explain why engineers should care |
| Technical jargon for execs | Translate to business language |
| Untested fix suggestions | Don't suggest fixes you haven't thought through |

### Structural mistakes
| Mistake | Fix |
|---------|-----|
| Single giant report | Create multiple artifacts for different audiences |
| Evidence mixed with findings | Separate evidence files, reference them |
| No traceability | Always include framework mappings |
| Missing metadata | Include dates, versions, scope, authorization |
| No retest plan | Every finding needs verification steps |

### Communication mistakes
| Mistake | Fix |
|---------|-----|
| Adversarial tone | Engineering is your partner — respect their work |
| Security theater | Don't report things that don't matter |
| No context for non-findings | Explain why you tested even if nothing found |
| Missing appreciation | Acknowledge what the target does well |

---

## 12. Report Quality Checklist

```
Structure:
[ ] Multiple artifacts produced for different audiences
[ ] Executive summary is 1-2 pages and business-focused
[ ] Technical report has all required sections
[ ] Developer guide is per-finding and actionable
[ ] Metrics dashboard is concise and visual

Findings:
[ ] Every finding has complete template filled out
[ ] Severity calibrated against realistic impact
[ ] Reproduction steps tested and work
[ ] Evidence organized and linked
[ ] Framework mappings complete
[ ] Remediation advice specific and tested
[ ] False positive checks documented

Evidence:
[ ] Evidence organized in per-finding directories
[ ] Screenshots clear and annotated
[ ] Request/response pairs captured
[ ] Evidence integrity (hashes) documented
[ ] Chain of custody maintained
[ ] Sensitive data redacted as appropriate

Compliance:
[ ] Applicable frameworks identified
[ ] Framework mappings on every finding
[ ] Compliance summary section included
[ ] Regulatory implications highlighted

Metrics:
[ ] Finding counts and distributions
[ ] Coverage metrics
[ ] Severity metrics (avg CVSS, max CVSS)
[ ] Trend comparison (if recurring)
[ ] Visual dashboards

Remediation:
[ ] Prioritized remediation plan
[ ] SLAs defined per severity
[ ] Effort estimates provided
[ ] Process improvements recommended
[ ] Retest plan documented

Communication:
[ ] Report proofread
[ ] Technical terms explained for executives
[ ] Tone is professional and collaborative
[ ] Acknowledgments of good practices included
[ ] Clear next steps at end of every section

Format:
[ ] Multiple export formats available
[ ] PDFs properly formatted
[ ] JSON structured for tool integration
[ ] CSV ready for tracking system import
[ ] Version numbers and timestamps everywhere
```

---

## Using This Reporting Guidance

When producing the final audit report in Phase 6:

1. **Start with the finding template** — use it for every finding
2. **Build artifacts in dependency order** — findings first, then technical report, then executive summary (you need findings to summarize them)
3. **Create evidence directory as you test** — don't wait until reporting phase
4. **Use the metrics dashboard** — produces quick impact visualization
5. **Generate exports** — provide JSON, Markdown, and CSV alongside prose reports
6. **Quality checklist before delivery** — use the checklist in section 12

The goal: produce reports that drive actual remediation, not reports that just check a compliance box.
