# Attack Chain Analysis

This reference covers how to connect individual findings into realistic attacker paths and prioritize them by exploitability and business impact.

## Table of Contents
1. [Attack Chain Thinking](#attack-chain-thinking)
2. [Common Chain Patterns](#common-chain-patterns)
3. [Trust Boundary Framework](#trust-boundary-framework)
4. [Chain Severity Escalation](#chain-severity-escalation)
5. [Documenting Chains](#documenting-chains)

---

## Attack Chain Thinking

Individual vulnerabilities rarely tell the full story. A Low-severity information disclosure becomes Critical when it enables account takeover through a chain of small weaknesses. Your job is to think like an attacker who connects dots.

### The attacker's mental model
```
Recon → Foothold → Privilege Escalation → Data Access → Persistence / Lateral Movement
```

At each step, ask:
- What did I just learn?
- What can I now access that I couldn't before?
- What's the lowest-effort next step?
- Where does the application trust me more than it should?

### What makes a chain credible
- Each step is individually achievable (not theoretical)
- The chain flows naturally — an attacker would realistically discover and follow it
- The final impact is meaningfully worse than any individual finding
- The effort required is realistic for the attacker model (opportunistic vs targeted)

---

## Common Chain Patterns

These are the most frequently seen attack chains in web applications. Look for these patterns specifically.

### 1. Route Exposure → Missing AuthZ → Data Access
```
Discovery: Attacker finds /admin or /internal routes via JS bundle analysis
Exploitation: Routes return 200 instead of 401/403 — no server-side auth check
Escalation: Admin functionality accessible, sensitive data exposed
Impact: Full admin access without authentication
```
**Why it happens:** UI-only access control — routes hidden from navigation but not protected server-side.

### 2. User Enumeration → Weak Auth → Account Takeover
```
Discovery: Login error messages distinguish "user not found" vs "wrong password"
Exploitation: Attacker confirms valid email addresses
Escalation: Combined with weak password policy or missing lockout → credential guessing
Impact: Account compromise
```
**Why it happens:** Verbose error messages + insufficient brute-force protection.

### 3. IDOR + Missing Ownership → Horizontal Breach
```
Discovery: API uses sequential numeric IDs for user resources
Exploitation: Changing the ID in requests returns other users' data
Escalation: Enumerate all IDs to extract full dataset
Impact: Mass data breach across all users
```
**Why it happens:** Missing server-side ownership validation — the API trusts the client to only request its own resources.

### 4. Reflected Input + Missing CSP → Practical XSS
```
Discovery: User input reflected in page without encoding
Exploitation: Craft URL with script payload
Escalation: No CSP to block inline scripts → full JS execution
Impact: Session theft, account takeover, phishing from trusted domain
```
**Why it happens:** Missing output encoding + no CSP safety net.

### 5. Verbose Errors + Predictable IDs + Missing Ownership → Targeted Breach
```
Discovery: Error messages reveal database structure or internal IDs
Exploitation: IDs are sequential/predictable → enumerate resources
Escalation: No ownership check on resources → access any user's data
Impact: Targeted data theft with forensic knowledge of the system
```
**Why it happens:** Multiple small leaks compound into a full attack path.

### 6. Weak Session + Missing Re-Auth → Privilege Persistence
```
Discovery: Session tokens don't rotate after privilege changes
Exploitation: User gets elevated privileges (or compromises an admin session)
Escalation: Session remains valid indefinitely → persistent elevated access
Impact: Long-term unauthorized admin access
```
**Why it happens:** Sessions not invalidated on role change + no re-authentication for sensitive actions.

### 7. CORS Misconfiguration + Cookie Auth → Cross-Origin Data Theft
```
Discovery: API reflects Origin header in Access-Control-Allow-Origin with credentials
Exploitation: Attacker hosts a page on evil.com that reads API responses
Escalation: Victim visits evil.com while logged in → attacker reads their data
Impact: Cross-origin data theft for any authenticated user
```
**Why it happens:** Permissive CORS + cookie-based auth without CSRF protection.

### 8. File Upload + Missing Validation → Stored XSS / RCE-Adjacent
```
Discovery: Upload accepts arbitrary file types
Exploitation: Upload .html or .svg with embedded scripts
Escalation: Files served from same origin → script executes in app context
Impact: Stored XSS affecting any user who views the file
```
**Why it happens:** Missing file type validation + unsafe content serving.

### 9. Open Redirect + OAuth → Token Theft
```
Discovery: Application has an open redirect endpoint
Exploitation: Inject redirect URL into OAuth callback parameter
Escalation: Auth token sent to attacker-controlled destination
Impact: Account takeover via stolen OAuth token
```
**Why it happens:** Insufficient redirect_uri validation in OAuth flow.

### 10. API Over-Exposure + GraphQL Introspection → Schema-Guided Attack
```
Discovery: GraphQL introspection enabled, revealing full schema
Exploitation: Discover undocumented mutations and sensitive fields
Escalation: Access restricted operations via direct GraphQL queries
Impact: Data access and operations beyond intended authorization
```
**Why it happens:** Development features left enabled in production.

---

## Trust Boundary Framework

Every web application has implicit trust boundaries. Vulnerabilities happen when these boundaries are crossed without verification.

### The four trust layers
```
┌──────────────────────────────────┐
│          Browser / Client        │  ← Fully attacker-controlled
├──────────────────────────────────┤
│       Application Layer          │  ← Business logic, routing, rendering
├──────────────────────────────────┤
│           API Layer              │  ← Data access, validation, auth enforcement
├──────────────────────────────────┤
│        Data / Infrastructure     │  ← Database, file storage, secrets
└──────────────────────────────────┘
```

### Questions for each boundary
**Browser → Application:**
- What does the app trust from the browser? (inputs, headers, cookies, local storage)
- Can the browser manipulate application state?
- Are client-side validations the only validations?

**Application → API:**
- Does the API independently verify auth/authz, or does it trust the application layer?
- Can API endpoints be called directly, bypassing the application?
- Are there internal APIs accessible from the public network?

**API → Data:**
- Does the API enforce ownership on data access?
- Can the API be tricked into accessing data it shouldn't?
- Are queries parameterized or do they trust input?

---

## Chain Severity Escalation

When individual findings combine into a chain, the chain's severity follows escalation rules.

### Severity escalation table
| Individual findings | Chain result | Chain severity |
|--------------------|-------------|----------------|
| Info + Low | Useful recon context | Low |
| Low + Low | Minor combined impact | Low-Medium |
| Low + Medium | Meaningful attack path | Medium-High |
| Medium + Medium | Significant attack path | High |
| Any + Auth Bypass | Account/data compromise | High-Critical |
| Any + Admin Access | Full system compromise | Critical |

### The key question
"If I told the CTO about this chain, would they cancel their weekend?" If yes, it's High or Critical.

---

## Documenting Chains

### Chain documentation template
```
Chain ID: [CHAIN-001]
Title: [Descriptive title of the full attack path]
Severity: [Based on escalation table]
Individual findings involved: [F-001, F-003, F-007]

Attack narrative:
Step 1: [What the attacker discovers/does first] → [reference finding]
Step 2: [How they leverage step 1] → [reference finding]  
Step 3: [Final exploitation] → [reference finding]
Final impact: [What the attacker achieves]

Trust boundary failures:
- [Which boundary was crossed without verification]
- [What assumption was violated]

Why this chain is realistic:
- [Why an attacker would discover this path]
- [Effort level required]
- [Attacker model: opportunistic / targeted / insider]

Remediation priority:
- Break the chain at: [which step is cheapest to fix]
- Recommended fix: [specific action]
```
