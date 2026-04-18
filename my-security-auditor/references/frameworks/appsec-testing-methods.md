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

See full content in the skill package at `/mnt/user-data/outputs/my-security-auditor.skill`.

This file is a placeholder for the GitHub repository. The complete reference content (1,589 lines) is packaged in the distributable `.skill` file and installed locally at `~/.claude/skills/my-security-auditor/references/frameworks/appsec-testing-methods.md`.

The full reference covers:

## 1. Testing Methods Overview
- Comparative matrix (SAST/DAST/IAST/RASP/SCA/Secret/Container/IaC)
- AppSec testing pyramid

## 2. Method Selection
- Decision tree based on code access
- Selection by SDLC phase
- Selection by engagement type

## 3. SAST Deep-Dive
- Pattern matching, data flow, control flow, symbolic execution
- Strengths/weaknesses
- Well-detected vs poorly-detected vulnerability classes
- Tool landscape: Checkmarx, Fortify, Veracode, Coverity, SonarQube, Semgrep, CodeQL, Bandit, Brakeman, gosec, spotbugs
- Deployment patterns (IDE, pre-commit, CI/CD, scheduled)
- Custom rule examples (Semgrep, CodeQL)
- Finding triage and suppression

## 4. DAST Deep-Dive
- Commercial: Burp Suite Pro, Invicti, Acunetix, HCL AppScan, StackHawk, Detectify
- Open source: OWASP ZAP, Nuclei, sqlmap
- API-specific: Schemathesis, 42Crunch, Postman, APIsecurity.io, Dredd
- Configuration essentials (auth, crawling, payload tuning)
- DAST for SPAs and APIs

## 5. IAST Deep-Dive
- How agent-based instrumentation works
- Commercial tools: Contrast Security, Seeker, Hdiv, Checkmarx IAST, Veracode
- Typical deployment per language (Java, .NET, Node.js, Python)
- IAST vs SAST vs DAST finding comparison

## 6. RASP Deep-Dive
- Runtime protection architecture
- Tools: Imperva, Contrast Protect, Signal Sciences, Jscrambler, Waratek, Sqreen
- RASP vs WAF comparison
- Audit evaluation checklist

## 7. SCA Deep-Dive
- Commercial: Snyk, Black Duck, WhiteSource/Mend, GitHub Advanced Security, GitLab Ultimate, JFrog Xray, Sonatype Nexus IQ, FOSSA
- Open source: Dependabot, Trivy, Grype, OSV-Scanner, Retire.js, dependency-check, npm audit, pip-audit, cargo-audit, govulncheck
- Reachability analysis
- SBOM (SPDX, CycloneDX, SWID)
- Supply chain attack detection
- Recent incidents: event-stream, Colors.js/Faker.js, ua-parser-js, xz-utils, polyfill.io

## 8. Secret Scanning
- Tools: git-secrets, gitleaks, trufflehog, detect-secrets, GitHub Secret Scanning, GitGuardian, Nightfall
- Placement (pre-commit, CI/CD, GitHub push protection)
- Response workflow

## 9. Container & IaC Scanning
- Container tools: Trivy, Grype, Snyk Container, Anchore, Aqua, Prisma Cloud, Docker Scout, JFrog Xray
- IaC tools: Checkov, tfsec, Terrascan, Snyk IaC, Bridgecrew, kube-score, Polaris, OPA Conftest
- Common issues in Terraform and Kubernetes

## 10. Fuzzing
- Black-box, white-box, coverage-guided
- Tools: AFL/AFL++, libFuzzer, go-fuzz, cargo-fuzz, Atheris, Jazzer, RESTler, Schemathesis, Radamsa
- OSS-Fuzz integration

## 11-12. SDLC Integration & Shift-Left
- Cost of fixing bugs by phase
- Integration points per SDLC phase
- DevSecOps toolchain example
- Quality gates
- AppSec metrics
- Shift-left anti-patterns and success factors
- 6-stage implementation

## 13. Tool Stack Recommendations
- Minimal (startup, $0)
- Mid-size team ($10-50k/year)
- Enterprise ($200k-$1M+/year)
- Evaluation criteria

## 14. Testing Method Checklist
- SAST, DAST, IAST, RASP, SCA, Secret Scanning, Container, IaC deployment checklists

## Mapping Testing Method Findings
- Per-method finding annotation templates
- Cross-method validation example
- Cross-references to related skill files

---

**To get the complete reference:** Install the skill via the `.skill` package.

```bash
# Download from releases
unzip my-security-auditor.skill -d ~/.claude/skills/
```

The packaged skill contains the full 1,589-line reference.
