# Application Security Testing Methods

This reference covers the formal application security testing methodologies — SAST, DAST, IAST, RASP, and SCA. Each method has specific use cases, tools, and integration patterns. Use this reference to understand which testing method applies to your audit engagement, tool selection, and integration with the SDLC.

## Table of Contents
1. [Testing Methods Overview](#1-testing-methods-overview)
2. [Selecting the Right Method(s)](#2-selecting-the-right-methods)
3. [SAST (Static Application Security Testing)](#3-sast-static-application-security-testing)
4. [DAST (Dynamic Application Security Testing)](#4-dast-dynamic-application-security-testing)
5. [IAST (Interactive Application Security Testing)](#5-iast-interactive-application-security-testing)
6. [RASP (Runtime Application Self-Protection)](#6-rasp-runtime-application-self-protection)
7. [SCA (Software Composition Analysis)](#7-sca-software-composition-analysis)
8. [Secret Scanning](#8-secret-scanning)
9. [Container & IaC Scanning](#9-container--iac-scanning)
10. [Fuzzing](#10-fuzzing)
11. [SDLC Integration](#11-sdlc-integration)
12. [Shift-Left Testing](#12-shift-left-testing)
13. [Tool Stack Recommendations](#13-tool-stack-recommendations)
14. [Testing Method Checklist](#14-testing-method-checklist)

---

## 1. Testing Methods Overview

Application security testing methods complement each other — no single method catches everything.

### Methods compared

| Method | Target | When | Finds | Misses |
|--------|--------|------|-------|--------|
| **SAST** | Source code | Pre-deploy | Code-level bugs (SQLi patterns, crypto misuse) | Runtime behavior, config issues |
| **DAST** | Running app | Post-deploy / staging | Runtime vulns (exposed services, auth flaws) | Code logic, unreachable code |
| **IAST** | Running app + instrumentation | During testing | Both code + runtime, low false positives | Coverage depends on test coverage |
| **RASP** | Production runtime | Continuous | Active exploitation attempts | Not a testing tool — a protection tool |
| **SCA** | Dependencies | Any time | Known CVEs in deps, license issues | Zero-days, custom code issues |
| **Secret scanning** | Source + git history | Continuous | Leaked credentials | Secrets not in the codebase |
| **Container scanning** | Images | Build / registry | Image CVEs, misconfigurations | Runtime behavior of container |
| **IaC scanning** | Infrastructure code | Pre-deploy | Cloud misconfigurations | Runtime state drift |

### Testing pyramid for AppSec

```
   [Pen Test / Red Team]        ← Expensive, periodic
   [DAST (scanning)]             ← Post-deploy
   [IAST (during integration)]   ← If mature
   [SAST (every commit)]         ← Shift-left
   [SCA + Secret + IaC Scanning] ← Continuous
   [Secure SDLC (training, TM)]  ← Foundational
```

Start from the bottom and work up. Foundational practices enable tool effectiveness.

---

## 2. Selecting the Right Method(s)

Choose based on what you have access to and what you're trying to achieve.

### Decision tree

```
Do you have source code access?
├── No → DAST only (black-box) + SCA on binaries + container scanning if images accessible
├── Yes, read-only → SAST + DAST + SCA + Secret scanning + code analysis (see code-analysis.md)
└── Yes, with deployment access → SAST + DAST + IAST + SCA + Secret + IaC scanning + RASP evaluation

Is this a single audit or ongoing program?
├── Single audit → apply methods manually, report gaps for SDLC integration
└── Ongoing program → integrate into CI/CD, automate where possible, monitor continuously
```

### Method selection by SDLC phase

| SDLC Phase | Methods |
|------------|---------|
| Requirements | Threat modeling (not AST, but AppSec) |
| Design | Architecture review (not AST) |
| Coding | SAST (real-time IDE), SCA (pre-commit) |
| Build | SAST (full), SCA, Secret scanning, IaC scanning |
| Test | DAST, IAST, Integration tests |
| Deploy | Container scanning, Configuration validation |
| Operate | RASP, WAF, Monitoring, Continuous DAST |

### Method selection by engagement type

- **Vulnerability assessment:** SAST (if code available), DAST, SCA, Secret scanning (light)
- **Penetration test:** DAST (primary), SAST (supplementary if code), SCA (identify known-vuln paths), Manual testing
- **Red team engagement:** Minimal automated scanning (don't burn tools), manual exploitation focus, SCA for initial recon
- **Blue team assessment:** RASP evaluation, detection coverage, SDLC integration review, tool stack assessment
- **Continuous program:** All methods integrated in CI/CD, automated baseline scanning, purple team validation of detections

---

## 3. SAST (Static Application Security Testing)

Analysis of source code without executing it.

### How SAST works

**Analysis techniques:**
1. **Pattern matching** — regex or AST-based patterns for known-bad code
2. **Data flow analysis** — trace data from source to sink
3. **Control flow analysis** — understand execution paths
4. **Symbolic execution** — analyze behavior across input space
5. **Semantic analysis** — language-level understanding

### SAST strengths

- Early in SDLC (shift-left)
- Full code coverage (every path)
- Specific file:line findings
- Works without running the app
- Finds hard-to-reach code paths
- Can be automated in CI/CD
- Developer-friendly when integrated in IDE

### SAST weaknesses

- High false positive rates (especially with pattern matching)
- Misses runtime behavior and configuration issues
- Can't test environment-dependent logic
- May time out on large codebases
- Limited cross-language analysis

### Vulnerability classes

**Well-detected:** SQL injection patterns, command injection patterns, XSS in templates, path traversal, hardcoded secrets, unsafe deserialization, weak cryptography usage, missing input validation.

**Poorly detected:** Authorization logic bugs (business logic), race conditions, complex multi-step vulnerabilities, issues requiring runtime context, third-party library interactions.

### SAST tool landscape

**Commercial:**
| Tool | Strengths |
|------|-----------|
| Checkmarx | Broad language support, mature |
| Fortify (OpenText) | Deep analysis, many languages |
| Veracode | SaaS model, policy support, binary analysis option |
| Coverity (Synopsys) | Deep technical analysis |
| SonarQube (commercial tiers) | Integrated code quality + security |

**Open source / free tier:**
| Tool | Strengths |
|------|-----------|
| Semgrep | Pattern-based, fast, customizable rules |
| CodeQL | GitHub-backed, deep analysis, free for OSS |
| Bandit | Python-specific, easy to use |
| ESLint + security plugins | JavaScript/TypeScript, dev workflow friendly |
| Brakeman | Rails-specific, de facto for Rails |
| gosec | Go-specific, fast |
| spotbugs | Java/JVM, good for legacy Java |
| SonarQube Community | Multi-language, free community edition |

**Built into platforms:** GitHub Advanced Security (CodeQL-powered), GitLab Ultimate, Azure DevOps, AWS CodeGuru.

### SAST deployment patterns

- **IDE integration (real-time):** developer writes code → plugin scans on save → inline findings → fixed before commit
- **Pre-commit hooks:** git commit → hook runs quick SAST → blocked if findings → developer fixes
- **CI/CD pipeline:** PR opened → CI runs full SAST → results posted on PR → required for merge
- **Nightly/scheduled:** nightly build → deep SAST (longer analysis) → AppSec team reviews → prioritized

### SAST rule customization

**Why custom rules matter:** catch org-specific patterns, enforce internal security standards, find framework-specific issues, reduce noise.

**Semgrep rule example:**
```yaml
rules:
  - id: hardcoded-aws-key
    pattern: $KEY = "AKIA..."
    message: Hardcoded AWS access key detected
    languages: [python, javascript, go]
    severity: ERROR
    metadata:
      cwe: CWE-798
```

**CodeQL query example:**
```ql
import javascript
from StringLiteral s
where s.getValue().regexpMatch("AKIA[0-9A-Z]{16}")
select s, "Potential AWS access key"
```

### SAST finding triage

Per finding: does the flagged code actually exist (can be stale)? Is the code path reachable? Is the data actually user-controlled? Is there compensating control? Is it a genuine bug?

**Triage categories:** True positive (fix), False positive (suppress with justification), Won't fix (accept risk with justification), Needs manual review.

**Suppression best practice:** inline with justification: `# nosemgrep: hardcoded-secret -- this is a test fixture, not real secret`

### SAST integration pitfalls

**Common failures:** Too many FPs → devs ignore all findings; too slow in CI → devs skip/disable; no triage process → findings pile up; no onboarding → devs don't know how to respond; wrong severity calibration → important findings missed.

**Success factors:** Start with focused rules (high-confidence only), gradually expand, fast feedback (under 10min in CI), clear fix guidance, regular rule review and tuning.

---

## 4. DAST (Dynamic Application Security Testing)

Testing running applications from the outside.

### How DAST works

1. Crawl the application (like a browser)
2. Identify input points (forms, parameters, API endpoints)
3. Send test payloads (SQL injection, XSS, etc.)
4. Observe responses for vulnerability indicators
5. Report findings with proof

### DAST strengths

- Tests the actual running system
- Finds config issues
- No source code needed
- Finds runtime-specific issues
- Language-agnostic
- Tests full stack (including infrastructure)
- Replicates attacker view

### DAST weaknesses

- Requires deployed application
- Crawler may miss paths (JS-heavy apps, authenticated areas)
- Slow (especially for large apps)
- Limited business logic understanding
- Can cause side effects (if not careful)
- Authentication often difficult
- Coverage depends on crawl quality

### DAST tool landscape

**Commercial:**
| Tool | Strengths |
|------|-----------|
| Burp Suite Pro | Industry standard for manual + automated |
| Invicti (Netsparker) | Strong crawler, lower FP |
| Acunetix | Fast scanning |
| HCL AppScan | Mature, enterprise-focused |
| StackHawk | Modern, DevOps-friendly |
| Detectify | SaaS, continuous, attack surface focused |

**Open source:**
| Tool | Strengths |
|------|-----------|
| OWASP ZAP | Free, full-featured, scriptable |
| Nuclei | Template-based, fast |
| w3af | Framework-oriented |
| nikto | Web server scanning, quick baseline |
| sqlmap | SQL injection specific, best-in-class |

**API-specific:**
| Tool | Strengths |
|------|-----------|
| Schemathesis | Property-based testing from OpenAPI |
| Postman (Newman) | Test runner |
| 42Crunch | API security platform |
| APIsecurity.io | API-focused scanner |
| Dredd | OpenAPI/Swagger spec compliance |

### DAST deployment patterns

- **Manual (pentesting):** Start Burp → browse through proxy → manually fuzz → manually exploit → report
- **Scheduled (continuous):** Nightly scan of staging → results to security team → track new vulns → trending
- **CI/CD (shift-right):** Deploy to staging → DAST against staging → block prod promotion if critical findings
- **Production scanning (carefully):** Limited safe checks, rate-limited, authenticated from allowed source, impact monitoring

### DAST configuration essentials

**Authentication options:** basic auth credentials, form-based login recording, OAuth token injection, session cookie injection, custom authentication script. Each test should verify auth still works during scan.

**Crawling strategy:** Configure starting URLs, set scope, depth limits, exclude logout/destructive operations, configure JavaScript rendering for SPAs, include API endpoints.

**Payload tuning:** Skip FP-prone payloads, include framework-specific custom payloads, adjust aggression per environment, skip destructive checks in production.

### DAST for SPAs / JS-heavy apps

Traditional crawlers miss JS-rendered content. Solutions:
- Headless browser crawler (ZAP with Firefox/Chrome driver)
- API-first scanning (scan API rather than UI)
- Manual seeding (record navigation manually)
- Burp Pro (built-in browser-based crawler)
- Custom scripts (selenium/playwright feeding URLs)

### DAST for APIs

Requires API definition:
1. Provide OpenAPI/Swagger spec
2. Configure authentication
3. Tool generates requests from spec
4. Tests each endpoint with variations
5. Reports findings

**Advantages:** complete endpoint coverage (not just crawled), type-aware fuzzing, parameter variation testing.

---

## 5. IAST (Interactive Application Security Testing)

Instrumentation-based analysis during runtime.

### How IAST works

IAST agents are installed in the application runtime. As the app runs, the agent observes function calls, data flow, external calls, database queries. When tests run or users interact, IAST detects vulnerable patterns: user input reaching dangerous sinks, unsafe library usage, configuration issues. Reports include specific code location + runtime context.

### IAST strengths

- Low false positive rate (sees actual data flow)
- Finds issues missed by both SAST and DAST
- Works during normal testing (no extra scan time)
- Specific code-level findings
- Understands runtime context
- Works with CI/CD without extra scan step

### IAST weaknesses

- Coverage depends on test coverage (no tests → no findings)
- Requires installing agent (performance overhead)
- Limited language support (mostly Java, .NET, Node.js, Python)
- Commercial tools only (limited OSS)
- More complex to deploy
- May miss paths not exercised by tests

### IAST tool landscape

| Tool | Strengths | Languages |
|------|-----------|-----------|
| Contrast Security | Mature, comprehensive | Java, .NET, Node.js, Python, Ruby |
| Seeker (Synopsys) | Deep analysis | Java, .NET, Node.js, Python |
| Hdiv Security | Active protection + IAST | Java, .NET, Node.js |
| Checkmarx IAST | Integrated with Checkmarx SAST | Multiple |
| Veracode Dynamic Analysis | Integrated platform | Multiple |

### IAST deployment

1. Install IAST agent (Java: JVM agent; .NET: IIS module; Node.js: npm package; Python: pip package)
2. Configure agent (identity, reporting backend, sensitivity tuning)
3. Deploy to test environment (5-10% performance impact typical)
4. Run tests normally (unit, integration, manual, DAST)
5. Review IAST findings (specific to exercised code paths, runtime context, high confidence)

### IAST vs SAST vs DAST finding comparison

```
SAST finding:
  Type: SQL injection
  Location: UserController.java:42
  Confidence: 60% (pattern match, can't verify data flow)

DAST finding:
  Type: SQL injection
  Location: /api/users (endpoint)
  Evidence: Error-based injection confirmed
  Confidence: 95%

IAST finding:
  Type: SQL injection
  Location: UserController.java:42 → UserService.java:78 → db.query()
  Evidence: User input from HTTP request reached db.query() without parameterization
  Context: Observed during integration test "testUserSearch"
  Confidence: 99% (actual data flow observed)
```

IAST combines specificity of SAST with confidence of DAST.

---

## 6. RASP (Runtime Application Self-Protection)

Runtime protection rather than testing — but important for AppSec understanding.

### How RASP works

RASP agents sit in the application runtime. When a request arrives, the agent intercepts at key points (incoming HTTP, SQL queries, file operations, command execution, authentication). It evaluates for attack patterns (SQL injection indicators, file access outside allowed paths, dangerous commands) and either blocks (blocking mode) or alerts (monitoring mode).

### RASP strengths

- Zero false positives (sees real attack attempts)
- Language/framework-aware (understands context)
- Protects against both known and unknown attacks (for detected classes)
- No signature updates needed
- Protects against zero-days in some cases
- Low operational overhead

### RASP weaknesses

- Performance impact (some percent)
- Language/runtime specific
- Not all attack classes covered
- Can cause legitimate request failures if too aggressive
- Commercial tools (limited OSS)
- Not a replacement for WAF or other controls
- Deployment complexity

### RASP tool landscape

| Tool | Strengths |
|------|-----------|
| Imperva RASP | Mature, broad protection |
| Contrast Protect | Same agent as Contrast IAST |
| Signal Sciences (Fastly) | Focuses on web apps |
| Jscrambler | JavaScript-specific |
| Waratek | Java-specific, deep |

### RASP vs WAF

| Aspect | WAF | RASP |
|--------|-----|------|
| Location | Network (proxy) | Application runtime |
| Visibility | HTTP only | Full app behavior |
| False positives | Higher (no context) | Lower (with context) |
| Language awareness | None | High |
| Zero-day protection | Limited | Some classes |
| Performance impact | Minimal | Some overhead |
| Complexity | Low-medium | Medium-high |
| Use case | Broad protection | Deep app protection |

WAF and RASP are complementary, not replacements.

### RASP evaluation for audit

When auditing a security program: Is RASP deployed? What attack classes covered? Blocking or monitor-only mode? Performance impact measured? Alerts integrated with SOC? FPs tuned? Bypass attempts monitored?

---

## 7. SCA (Software Composition Analysis)

Analysis of open-source and third-party dependencies.

### What SCA covers

**Primary:** known vulnerabilities in dependencies (CVE-based), license compliance, outdated packages, supply chain risk indicators, dependency confusion risks, abandoned packages.

**Secondary:** transitive dependency analysis, dependency graph complexity, maintainer reputation, security policy of projects used.

### SCA tool landscape

**Commercial:**
| Tool | Strengths |
|------|-----------|
| Snyk | Comprehensive, developer-friendly, free tier |
| Black Duck (Synopsys) | Enterprise, license compliance |
| WhiteSource (Mend) | Full SCA + IaC |
| GitHub Advanced Security | Integrated with GitHub |
| GitLab Ultimate | Integrated with GitLab |
| JFrog Xray | Artifact-focused |
| Sonatype Nexus IQ | Deep component analysis |
| FOSSA | License compliance focus |

**Open source:**
| Tool | Strengths |
|------|-----------|
| Dependabot (GitHub) | Free on GitHub, automated PRs |
| Trivy | Fast, multi-ecosystem |
| Grype | Fast, multi-ecosystem (Anchore) |
| OSV-Scanner | Google-backed, OSV database |
| Retire.js | JavaScript-specific |
| dependency-check (OWASP) | Multi-language, mature |
| npm audit | Node.js built-in |
| pip-audit | Python, by PyPA |
| cargo-audit | Rust, by RustSec |
| govulncheck | Go, by Go team |

### SCA workflow

**CI/CD integration:** PR opened → SCA runs → compare against baseline → new vulns block merge → update lockfile, re-scan → merge if clean.

**Continuous monitoring:** packages monitored → new CVE published → alert raised → assess exploitability in context → patch, mitigate, or accept risk.

### SCA finding prioritization

Severity alone isn't enough. Consider:
1. Is the vulnerable code path reachable in your code?
2. Is the vulnerability exploitable in your context? (needs user input? network access?)
3. What's the fix complexity? (minor version bump vs major refactor)
4. What's the risk of not fixing? (active exploitation — check KEV catalog; public exploits)

**Reachability analysis:** Tools like Snyk's reachability analysis determine if your code actually calls the vulnerable function, reducing noise.

### SBOM (Software Bill of Materials)

SBOMs list all components in your software.

**Formats:** SPDX (Linux Foundation), CycloneDX (OWASP), SWID (ISO/IEC).

**Use cases:** compliance (executive orders, regulations), supply chain visibility, incident response (quickly identify affected systems), license compliance auditing, customer transparency.

**Generation:**
```bash
# Multi-language
syft packages dir:/path/to/project -o cyclonedx-json
trivy fs --format cyclonedx --output sbom.json .

# Language-specific
npm sbom               # Node.js
cyclonedx-bom          # Python
cyclonedx-gomod        # Go
```

### Supply chain attack detection

Beyond CVEs, watch for:
- Sudden new maintainer of trusted package
- Unusual version bumps (0.1.0 → 5.0.0 overnight)
- Package description changes
- Typosquatting (similar names to popular packages)
- Dependency confusion (internal name available publicly)
- Install scripts added in new versions
- Obfuscated code in updates
- Network activity from build tools

**Defensive measures:** lockfiles, private registries for internal packages, integrity hashes, pinned versions (vs ranges), automated scanning before merging updates.

---

## 8. Secret Scanning

Finding leaked credentials in source code and history.

### Tools

| Tool | Strengths |
|------|-----------|
| git-secrets (AWS) | Lightweight, focused on AWS |
| gitleaks | Fast, modern |
| trufflehog | Multi-platform, verifies some secrets |
| detect-secrets (Yelp) | Pre-commit friendly |
| GitHub Secret Scanning | Built into GitHub, vendor partnerships |
| GitGuardian | Commercial, comprehensive |
| Nightfall | Commercial, AI-based |

### Placement

**Pre-commit hooks:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/zricethezav/gitleaks
    rev: v8.x.x
    hooks:
      - id: gitleaks
```

**CI/CD:**
```yaml
- name: Gitleaks scan
  run: gitleaks detect --source . --verbose

# Scheduled historical scan
- name: Full history scan
  run: gitleaks detect --source . --log-opts="--all"
```

**GitHub:** Enable Secret Scanning in repo settings, vendor partnerships catch leaks before commit, push protection blocks commits with detected secrets.

### Response

When a secret is found:
1. Rotate IMMEDIATELY (even before cleanup)
2. Check access logs for unauthorized use
3. Determine scope (how long leaked, who could see)
4. Clean from git history (BFG or git-filter-repo)
5. Force-push cleaned history (coordinate with team)
6. Update .gitignore and pre-commit hooks
7. Document incident
8. Consider if incident notification required

**Never:** Delete the file and commit (old versions still in history); ignore because "it's a test secret"; wait to rotate ("I'll do it tomorrow").

---

## 9. Container & IaC Scanning

### Container image scanning

**What to scan:** base image vulnerabilities, application dependencies in image, OS package vulnerabilities, image configuration issues, embedded secrets, known malicious components.

**Tools:**
| Tool | Strengths |
|------|-----------|
| Trivy | Fast, comprehensive, open source |
| Grype | Open source, Anchore ecosystem |
| Snyk Container | Commercial, developer-friendly |
| Anchore Enterprise | Policy-based scanning |
| Aqua Security | Runtime + scanning |
| Prisma Cloud (Palo Alto) | Cloud-native security |
| Docker Scout | Integrated with Docker Hub |
| JFrog Xray | Artifact scanner |

**Workflow:** build image → scan in CI → compare against policy → fail build if violation → push to registry on pass → re-scan periodically (new CVEs for existing images).

### IaC scanning

**What to scan:** Terraform, CloudFormation, Kubernetes manifests, Helm charts, Dockerfile, Ansible playbooks, Pulumi programs.

**Tools:**
| Tool | Strengths |
|------|-----------|
| Checkov | Multi-framework, easy to use |
| tfsec | Terraform-specific |
| Terrascan | Multi-framework |
| Snyk IaC | Integrated with Snyk |
| Bridgecrew (Prisma) | Commercial |
| kube-score | Kubernetes focus |
| Polaris | Kubernetes policy |
| OPA Conftest | Policy-based |

**Placement:** IDE plugin (real-time) → pre-commit hook → CI/CD pipeline → registry scanning (for Helm charts etc.).

### Common IaC issues

**Terraform:** S3 bucket `acl = "public-read"`; security group `cidr_blocks = ["0.0.0.0/0"]` with `protocol = "-1"`; `encrypted = false` on storage; IAM policy with `Action = "*"` and `Resource = "*"`.

**Kubernetes:** No resource limits; `runAsUser: 0`; `privileged: true`; `image: app:latest` (unpinned).

---

## 10. Fuzzing

Automated input generation to find bugs.

### Fuzzing types

- **Black-box:** no code knowledge, random or mutation-based input, good for protocol fuzzing
- **White-box:** uses code coverage to guide input generation, much more effective, requires code access
- **Coverage-guided:** AFL/LibFuzzer style, instrument code to track coverage, evolve inputs to reach new paths

### Fuzzing use cases

**Excels at:** parser code (file formats, protocols), APIs with structured input, libraries handling untrusted input, serialization/deserialization code.

**Less valuable for:** business logic code, UI code, well-tested standard operations.

### Fuzzing tools

| Tool | Type | Use case |
|------|------|----------|
| AFL / AFL++ | Coverage-guided | Native code |
| libFuzzer | Coverage-guided | C/C++ in-process |
| go-fuzz / fuzzing (Go 1.18+) | Coverage-guided | Go code |
| cargo-fuzz | Coverage-guided | Rust code |
| Atheris | Coverage-guided | Python |
| Jazzer | Coverage-guided | Java/JVM |
| RESTler | API fuzzing | REST APIs |
| Schemathesis | Property-based | OpenAPI |
| Radamsa | Mutation | Generic |

### Fuzzing integration

**OSS-Fuzz style:** continuous fuzzing for open-source projects, Google provides free compute, regressions caught automatically.

**Internal infrastructure:** fuzzing nodes run continuously → test cases generated → crashes collected → deduplicated and triaged → reports filed as bugs.

---

## 11. SDLC Integration

Integrating AppSec testing throughout the SDLC.

### Shift-left AppSec

Principle: **find issues as early as possible** (cheapest to fix).

**Cost of fixing bugs by phase:** Requirements/Design 1x, Coding 6x, Testing 15x, Production 100x+.

### Integration points per SDLC phase

- **Requirements:** threat modeling, security requirements definition, abuse case analysis
- **Design:** architecture review, design review, threat model updates
- **Coding:** secure coding training, IDE plugins (SAST), pre-commit hooks, pair programming for security-sensitive code
- **Build:** SAST in CI, SCA in CI, secret scanning, IaC scanning, container scanning, quality gates
- **Test:** security unit tests, DAST in staging, IAST during integration, penetration testing pre-release
- **Deploy:** container image scanning, configuration validation, infrastructure scanning, deployment security checks
- **Operate:** RASP (if deployed), WAF, monitoring and alerting, continuous DAST, bug bounty, incident response

### DevSecOps toolchain example

```
Developer Workflow:
  IDE (Semgrep plugin) → git pre-commit (gitleaks) → git push

CI Pipeline (on PR):
  SAST (Semgrep) → SCA (Trivy) → IaC scan (Checkov) → Unit tests

CI Pipeline (on merge):
  Container scan (Trivy) → Sign image → Push to registry

CD Pipeline:
  Deploy to staging → DAST (ZAP) → E2E tests with IAST (Contrast)

Production:
  Deploy → WAF → RASP (Contrast Protect) → Monitoring

Continuous:
  Scheduled DAST → SCA (monitoring) → Bug bounty
```

### Quality gates

- **Commit-time:** no secrets in diff, no critical SAST findings in new code, no license violations introduced
- **PR merge:** all SAST findings triaged, no new critical SCA vulnerabilities, security-sensitive changes reviewed
- **Pre-deploy:** DAST passes (no critical findings), container scan passes, config validation passes
- **Production:** continuous monitoring, SLA compliance for vulnerability response

### AppSec metrics

- **Activity:** scans per period, findings per scan, issues created/closed, training completion
- **Quality:** MTTD, MTTR, escape rate (prod vs pre-prod), FP rate per tool
- **Strategic:** coverage of SDLC with security tools, automation percentage, developer satisfaction, cost per vuln remediated

---

## 12. Shift-Left Testing

### Why shift-left

**Benefits:** cheaper to fix, faster feedback, culture of security ownership, reduced production incidents, better developer velocity.

**Requirements:** developer-friendly tools, fast feedback loops, clear fix guidance, training and support, measurable outcomes.

### Anti-patterns

- **"Security wall":** security blocks releases at the last minute → frustration, bypass attempts. **Fix:** earlier integration with developer-friendly tools.
- **Tool overload:** too many tools, too many alerts → ignored. **Fix:** curated tool selection, noise reduction, prioritization.
- **Blame culture:** developers blamed for findings → resistance. **Fix:** collaborative approach, security as enabler.
- **Compliance-only focus:** tools for compliance not effectiveness → security theater. **Fix:** outcome-focused metrics, actual vuln reduction.

### Implementation stages

1. **Developer awareness** — security training, secure coding guides, security champions
2. **IDE integration** — SAST plugins, linter rules, real-time feedback
3. **Pre-commit / pre-push** — secret scanning, quick SAST checks, lint rules
4. **PR-level checks** — full SAST, SCA, IaC scanning, security review for sensitive changes
5. **Full CI/CD integration** — all checks automated, quality gates enforced, metrics tracked
6. **Continuous improvement** — regular tool tuning, rule customization, purple team validation, feedback from production

---

## 13. Tool Stack Recommendations

### Minimal (startup / small team)

```
Free / open source only:
- GitHub Advanced Security (free for OSS) OR:
  - Dependabot (SCA + updates)
  - Semgrep CI (SAST)
  - gitleaks (secret scanning)
- Trivy (container + IaC scanning)
- OWASP ZAP (DAST)
- Bandit / ESLint-security / gosec (language-specific SAST)

Cost: $0
Effort: Low-Medium
Coverage: Basic but meaningful
```

### Mid-size team

```
Mix of free and commercial:
- Snyk (SCA + container + IaC + SAST)
- Semgrep (custom SAST rules)
- GitHub Secret Scanning
- Burp Suite Pro (1-2 licenses)
- OWASP ZAP (CI integration)
- gitleaks / trufflehog

Cost: $10-50k/year
Effort: Medium
Coverage: Solid across SDLC
```

### Enterprise

```
Commercial with deep integration:
- Checkmarx / Fortify / Veracode (SAST)
- Invicti / Burp Enterprise / StackHawk (DAST)
- Contrast Security / Seeker (IAST)
- Snyk / Black Duck (SCA)
- GitGuardian (secret scanning)
- Prisma Cloud / Aqua (container + runtime)
- OPA Gatekeeper (policy)
- Contrast Protect / Imperva (RASP)

Cost: $200k-$1M+/year
Effort: High (team required)
Coverage: Comprehensive
```

### Decision criteria

- **Technical:** language/framework coverage, accuracy (TP rate), speed, integration options
- **Operational:** deployment complexity, maintenance burden, documentation quality, support responsiveness
- **Strategic:** vendor stability, roadmap alignment, total cost, community/ecosystem
- **Developer experience:** IDE integration, FP rate, fix guidance quality, CI/CD speed

---

## 14. Testing Method Checklist

```
SAST Deployment:
[ ] Tool selected for primary languages
[ ] Custom rules for organization patterns
[ ] IDE integration configured
[ ] CI/CD integration with quality gates
[ ] Triage process documented
[ ] FP management established
[ ] Developer training provided

DAST Deployment:
[ ] Scanning infrastructure set up
[ ] Authentication configuration working
[ ] Scope correctly defined
[ ] Scheduled scans running
[ ] CI/CD integration for pre-prod
[ ] Results triage process
[ ] API scanning if applicable

IAST (if applicable):
[ ] Tool selected for runtime
[ ] Agents deployed to test environments
[ ] Performance impact measured and acceptable
[ ] Integration with CI/CD
[ ] Test coverage sufficient for IAST effectiveness

RASP (if deployed):
[ ] Deployment plan understood
[ ] Coverage of attack classes verified
[ ] Monitoring mode first, blocking after tuning
[ ] Performance impact measured
[ ] Integration with SOC

SCA Deployment:
[ ] Dependency scanning on every build
[ ] SBOM generation automated
[ ] Vulnerability database current
[ ] Reachability analysis considered
[ ] License compliance checked
[ ] Update process defined
[ ] Supply chain risk assessment

Secret Scanning:
[ ] Pre-commit hooks
[ ] CI/CD scanning
[ ] Git history fully scanned
[ ] GitHub Secret Scanning enabled
[ ] Response process for findings
[ ] Developer training on secret management

Container Scanning:
[ ] Images scanned in CI
[ ] Registry scanning enabled
[ ] Base image selection policy
[ ] Minimal image practices enforced
[ ] Dockerfile linting

IaC Scanning:
[ ] All IaC types scanned
[ ] CI/CD integration
[ ] Policy framework (OPA, etc.)
[ ] Custom policies for org-specific patterns

SDLC Integration:
[ ] Shift-left strategy implemented
[ ] Tools integrated across SDLC phases
[ ] Quality gates defined
[ ] Metrics tracked
[ ] Developer experience positive
[ ] Continuous improvement process
```

---

## Mapping Testing Method Findings

Each testing method produces findings with characteristic attributes.

### Finding annotation template (by method)

```
SAST finding:
  - Tool: [Semgrep / Checkmarx / etc.]
  - Rule: [specific rule ID]
  - File:line: [specific location]
  - Confidence: [low / medium / high]
  - Requires runtime context: [yes / no]

DAST finding:
  - Tool: [Burp / ZAP / etc.]
  - URL/endpoint: [specific]
  - Payload: [the exact payload used]
  - Evidence: [response indicating vuln]
  - Confidence: [high — usually observed]

IAST finding:
  - Tool: [Contrast / Seeker / etc.]
  - Code path: [source → sink with intermediate functions]
  - Runtime context: [what triggered the observation]
  - Confidence: [very high — actual data flow]

SCA finding:
  - Tool: [Snyk / Trivy / etc.]
  - Package: [name and version]
  - CVE: [identifier]
  - Severity: [from NVD]
  - Reachability: [if known]
  - Fix: [version that fixes]
```

### Cross-method validation

Strongest findings are detected by multiple methods:

```
Example: SQL Injection Finding

SAST detected it:
  - Location: UserController.java:42
  - Rule: sql-injection-concat
  - Confidence: medium (pattern match)

DAST confirmed it:
  - Endpoint: /api/users/search
  - Payload: ' OR 1=1--
  - Evidence: database error message returned
  - Confidence: high

IAST observed it:
  - Data flow: HTTP query → UserController.search() → UserRepository.raw()
  - Runtime: confirmed data reached sink
  - Confidence: very high

Combined confidence: Near 100%
Report with SAST location for fix + DAST evidence for demonstration
```

### Cross-reference with other frameworks

Testing method findings should map to:
- `references/frameworks/owasp-complete.md` for OWASP categorization
- `references/frameworks/code-analysis.md` for code-level methodology
- `references/frameworks/vulnerability-management.md` for VM lifecycle
- `references/frameworks/purple-team.md` for validating detections
