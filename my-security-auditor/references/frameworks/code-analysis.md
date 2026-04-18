# Code Analysis and Review

This reference covers source-code-level security analysis — the discipline of reading, understanding, and auditing code for security issues. Use this reference when the engagement has source code access (which is most modern audits). This closes the gap between black-box testing methodology and the reality that most SaaS audits happen with full codebase visibility.

## Table of Contents
1. [When to Use Code Analysis](#1-when-to-use-code-analysis)
2. [Codebase Reconnaissance](#2-codebase-reconnaissance)
3. [Code Summarization Workflow](#3-code-summarization-workflow)
4. [Security-Focused Code Review](#4-security-focused-code-review)
5. [Per-Language Review Patterns](#5-per-language-review-patterns)
6. [Per-Framework Security Patterns](#6-per-framework-security-patterns)
7. [Taint Analysis](#7-taint-analysis)
8. [Authentication & Authorization Code Review](#8-authentication--authorization-code-review)
9. [Input Validation & Output Encoding Review](#9-input-validation--output-encoding-review)
10. [Cryptography Code Review](#10-cryptography-code-review)
11. [Error Handling & Information Disclosure](#11-error-handling--information-disclosure)
12. [Git History Analysis](#12-git-history-analysis)
13. [Configuration-as-Code Review](#13-configuration-as-code-review)
14. [Dependency Review](#14-dependency-review)
15. [Integration with Audit Phases](#15-integration-with-audit-phases)
16. [Code Analysis Checklist](#16-code-analysis-checklist)

---

## 1. When to Use Code Analysis

### Code analysis vs black-box testing

Code analysis and black-box testing are complementary:

| Aspect | Black-Box Testing | Code Analysis |
|--------|------------------|---------------|
| Visibility | Only runtime behavior | Full logic visibility |
| Coverage | What you can reach | Everything including dead paths |
| Confidence | High (observed) | Variable (reasoned) |
| Speed | Slower per endpoint | Faster per file |
| Finds | Integration issues | Logic bugs, missing checks |
| Misses | Dead code, conditional paths | Runtime behavior differences |

**Use both when possible.** Code analysis finds the "why," black-box testing confirms the "what."

### When code access changes the audit

**Code changes priorities:**
- Authorization logic review becomes systematic (read every endpoint)
- Crypto usage review becomes possible
- Secrets in code discoverable
- Dependency analysis enables SCA
- Dead code can be identified (attack surface reduction)
- Business logic flaws easier to find

**Code access doesn't replace:**
- Runtime behavior (race conditions may only manifest in prod)
- Configuration issues (env vars not in code)
- Infrastructure issues (AWS/K8s/network)
- Third-party integration issues

### Engagement scoping with code access

When scoping, clarify:
- **What code is accessible?** Monorepo? All services? Just the API?
- **Is git history accessible?** (important for secret scanning)
- **Are internal dependencies accessible?** (shared libraries)
- **Are build artifacts in scope?** (Docker images, binaries)
- **Is CI/CD config accessible?** (GitHub Actions, GitLab CI, etc.)

---

## 2. Codebase Reconnaissance

Before diving into security review, understand what you're looking at.

### Repository structure mapping

**First-pass questions:**
```
1. What kind of codebase is this?
   - Monorepo / polyrepo / single service
   - Multi-language / single-language
   - Framework-based / custom

2. What's the top-level structure?
   - ls the root, read README, read package.json/go.mod/Cargo.toml/pom.xml
   - Identify apps vs libraries vs infrastructure

3. What's the runtime architecture?
   - Monolith / microservices / serverless
   - Frontend / backend / both
   - Databases / queues / caches / external APIs
```

**Standard recon commands:**
```bash
# Overall structure
tree -L 2 -I 'node_modules|vendor|target|dist'

# Language breakdown
cloc . --exclude-dir=node_modules,vendor,dist

# Identify entry points
find . -name "main.*" -o -name "app.*" -o -name "server.*" -o -name "index.*" | head -20

# Identify config files
find . -name "*.yaml" -o -name "*.yml" -o -name "*.json" -o -name "*.toml" -o -name "*.env*" | grep -v node_modules | head -30

# Identify CI/CD
ls .github/workflows/ .gitlab-ci.yml .circleci/ Jenkinsfile .drone.yml 2>/dev/null
```

### Entry point discovery

Every security review should enumerate entry points — places where external input enters the system.

**Common entry points:**
| Entry point type | Where to look |
|-----------------|---------------|
| HTTP API routes | Route definitions (Express routers, FastAPI routers, Rails routes.rb) |
| GraphQL resolvers | schema.graphql + resolver files |
| WebSocket handlers | Usually in API directory |
| CLI commands | Cobra (Go), Click (Python), yargs (Node) |
| Queue consumers | Message handlers (Kafka, RabbitMQ, SQS) |
| Scheduled jobs | Cron definitions, scheduled task files |
| Event handlers | Webhooks, pub/sub subscriptions |
| Database triggers | Migration files, stored procedures |
| File watchers | Filesystem event handlers |

**Framework-specific entry point commands:**
```bash
# Express/Node.js
grep -rn "app\.\(get\|post\|put\|delete\|patch\)\|router\.\(get\|post\|put\|delete\|patch\)" --include="*.js" --include="*.ts"

# FastAPI
grep -rn "@app\.\|@router\." --include="*.py"

# Flask
grep -rn "@app\.route\|@blueprint\.route" --include="*.py"

# Go net/http or common frameworks
grep -rn "HandleFunc\|\.Get(\|\.Post(\|\.Put(\|\.Delete(" --include="*.go"

# Rails
cat config/routes.rb

# Spring
grep -rn "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@RequestMapping" --include="*.java"

# Django
find . -name "urls.py" | head -5
```

### Configuration file audit

```bash
# Search for common config patterns
find . -type f \( -name "*.env*" -o -name "config.*" -o -name "settings.*" -o -name "*.conf" -o -name "*.ini" \) -not -path "*/node_modules/*" | head -20

# Check for common secret patterns (only on authorized code)
grep -rEn "(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]+['\"]" --include="*.{js,ts,py,go,rb,java,yaml,yml,json}" | head -20
```

### Output: Codebase map

After recon, produce a structured summary with: Structure (type, languages, services, LOC), Entry Points (type, location, count), Architecture (pattern, modules, DB, external services), Build & Deploy (CI/CD, deployment, registry, secrets), Security-Relevant Configuration (auth, session, CORS, rate limiting), and Observations.

This map feeds every subsequent audit phase.

---

## 3. Code Summarization Workflow

Before auditing, understand what the code does.

### Summarization levels

- **Repo level** (1 paragraph): what the project does, role in larger system
- **Module level** (3-5 sentences): what it does, depends on, depended on by
- **File level** (1-3 sentences): contents and responsibility
- **Function level** (1 sentence): what it does, inputs, outputs

### Summarization-first audit workflow

1. Read README, docs/, architecture docs
2. Read main entry points and trace basic request flow
3. Summarize repo structure and primary flows
4. Identify critical modules (auth, authorization, data access)
5. Summarize critical modules in depth
6. Start systematic audit with summary-identified critical modules
7. Trace input from entry to storage/output
8. Check for security controls at each layer
9. Document findings with code-level evidence
10. Review modules not in critical path
11. Look for forgotten endpoints, admin functions
12. Check less-obvious input entry points

### Critical module identification

Prioritize: **Authentication**, **Authorization**, **Data access layer**, **Input validation**, **Cryptography**, **Session management**, **External integrations**, **File upload/download**, **Admin functionality**, **Audit logging**.

---

## 4. Security-Focused Code Review

### Review methodology

**1. Trust boundary identification:** User HTTP requests, third-party API responses, queue messages, database query results (shared schemas), file uploads, WebSocket messages.

**2. Asset identification:** User credentials, session tokens, PII, business data, cryptographic keys, admin functionality.

**3. Flow tracing:** User input → validation → business logic → storage; Database read → response shaping → output; External API → processing → storage.

**4. Control verification:** Input validated? Authentication required? Authorization checked? Output encoded? Sensitive data protected?

### Code review patterns per vulnerability class

**Injection (SQL, Command, etc.):**
Look for string concatenation with user input in queries, exec/eval with user input, subprocess.call with user input, dynamic code generation, ORM raw() calls with concat.

Flag: `query = "SELECT * FROM users WHERE id = " + userId`, `exec(f"process {user_input}")`, `db.Query("WHERE name = '" + name + "'")`

**Broken access control:**
Look for endpoints without authorization check, object access without ownership verification, role checks that can be bypassed, client-trusted authorization decisions.

Flag: `GET /api/users/:id` without checking `req.user.id == id`, `if (req.body.role == 'admin')` trusting client, missing middleware on admin routes.

**Authentication failures:**
Look for password handling without hashing, token validation missing steps, session without proper invalidation, MFA bypasses.

Flag: `if (user.password === input)` (plaintext compare), `jwt.verify(token, secret)` without alg check, `logout()` that doesn't invalidate.

**Sensitive data exposure:**
Logging sensitive data, sensitive data in responses, sensitive data in URLs/query params, sensitive data in error messages.

**Security misconfiguration:**
Defaults in production, debug mode enabled, verbose errors, unnecessary features enabled, missing security headers.

### Code smell catalog

**Inconsistency smells:** Same operation implemented differently (one secure, one not); mix of ORM and raw queries; some endpoints authenticated, similar ones not; different validation patterns across handlers.

**Complexity smells:** Overly complex authorization logic (likely has holes); nested ternaries; large functions; copy-paste code (same bug in multiple places).

**Commentary smells:** "TODO: add auth", "FIXME: this is insecure", "Don't touch this", outdated comments, comments explaining "why" workarounds exist.

**Historic smells:** Recent "quick fix" commits to security-sensitive code; reverted security commits; code copied from older systems; "temporarily disabled" checks.

### Vibecoder patterns (AI-built code smells)

- Generic placeholder values — `secret="your-secret-here"`, `api_key="xxx"`
- Hardcoded CORS to `*` — LLMs default to permissive
- Missing error handling — happy path only
- Insecure defaults — `verify=False`, `strict: false`
- Console.log debugging left in
- Example code from docs not adapted — insecure defaults from tutorials
- Over-generic error messages — masking real issues
- Missing rate limiting — LLMs rarely add it proactively

---

## 5. Per-Language Review Patterns

### JavaScript / TypeScript

**High-risk patterns:**
- XSS: `element.innerHTML = userInput`, `document.write(userInput)`, `eval(userInput)`, `new Function(userInput)`, `setTimeout(userInput, 100)`
- Prototype pollution: `Object.assign({}, userInput)`, `_.merge(target, userInput)`
- Path traversal: `fs.readFile(userPath)`, `require(userPath)`
- Command injection: `child_process.exec(userCmd)`, `child_process.execSync(userCmd)`

**Review focus:** Template injection (React `dangerouslySetInnerHTML`, Vue `v-html`), ReDoS, deserialization, prototype pollution, event loop abuse, timing attacks.

### Python

**High-risk patterns:**
- Injection: `exec(user_input)`, `eval(user_input)`, `os.system(user_input)`, `subprocess.call(user_input, shell=True)`, `pickle.loads(user_input)`
- SQL injection: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`, `cursor.execute("..." % user_id)`
- Path traversal: `open(user_path)`, `send_file(user_path)`
- Unsafe deserialization: `yaml.load(user_input)` (use safe_load), `pickle.loads(user_input)`
- XXE: `xml.etree.ElementTree.parse(user_input)`, `lxml.etree.fromstring(user_input)`

**Review focus:** Django SQL injection in raw queries, Flask template injection (`render_template_string` with user input), FastAPI missing dependency validation, Celery task injection, pickle usage anywhere.

### Go

**High-risk patterns:**
- SQL injection: `db.Query("SELECT * FROM users WHERE id = " + userId)`
- Command injection: `exec.Command("sh", "-c", userCmd)`, `exec.Command(userCmd)`
- Path traversal: `os.Open(userPath)`, `http.ServeFile(w, r, userPath)`
- Template injection: `text/template` with user input, `html/template.HTML(userInput)` (XSS bypass)
- Deserialization: `gob.Decode(userInput)`

**Review focus:** SQL injection despite prepared statement support, race conditions (easier to spot in Go due to explicit goroutines), missing context cancellation, TOCTOU bugs, umask on file creation.

### Java

**High-risk patterns:**
- SQL injection: `stmt.execute("SELECT * FROM users WHERE id = " + userId)`
- Deserialization (extremely dangerous): `ObjectInputStream.readObject()` with user input
- XXE: `DocumentBuilder` without `setFeature(...disallow-doctype-decl...)`
- Command injection: `Runtime.getRuntime().exec(userCmd)`
- Reflection abuse: `Class.forName(userClassName).newInstance()`

**Review focus:** Deserialization (Jackson, XStream, native), XXE in XML parsers (default unsafe in old Java), Spring-specific issues (SpEL injection, data binding), Log4j-style lookups (JNDI injection).

### Ruby

**High-risk patterns:**
- Injection: `eval(user_input)`, `send(user_input)`, `constantize(user_input)`, `Kernel.exec(user_input)`
- Rails SQL injection: `User.where("id = #{params[:id]}")`, `User.where(params[:conditions])`
- YAML deserialization: `YAML.load(user_input)`
- Mass assignment: `User.new(params[:user])` without strong_parameters

**Review focus:** Rails-specific (strong_parameters, SQL injection in where), Regex DoS, dynamic method calls via `send()`, ERB template injection.

### Rust

**High-risk patterns (safer but not immune):**
- Unsafe blocks: `unsafe { ... }`
- SQL with raw queries: `sqlx::query(&format!("... {}", id))`
- Command execution: `Command::new("sh").arg("-c").arg(user_input)`
- Path traversal: `File::open(user_path)`

**Review focus:** `unsafe` blocks (rare but critical), integer overflow in release mode, panic-in-production, cargo-audit.

### PHP

**High-risk patterns:**
- Injection: `eval($user_input)`, `system($user_input)`, `exec($user_input)`
- SQL injection: `mysql_query("... $id")`, `$pdo->query("... $id")` if not parameterized
- File inclusion: `include $user_path`, `require $user_path` (LFI/RFI)
- Deserialization: `unserialize($user_input)`
- Type juggling: `if ($password == $input)` (loose comparison bugs)

**Review focus:** Type juggling (`==` vs `===`), magic methods in deserialization, file inclusion, legacy `mysql_*`, register_globals.

---

## 6. Per-Framework Security Patterns

### Express / Node.js

Common issues: CSRF without protection (no csurf), CORS misconfigured, Helmet missing, body parser limits missing, async error handlers missing (unhandled rejections), session cookie misconfigured.

Review middleware order, `cors({ origin: '*' })`, `express.json({ limit: '50mb' })`, `helmet()`, auth middleware on admin routes, cookie session config (secret, httpOnly, secure, sameSite).

### FastAPI

Common issues: Missing `response_model` (leaks extra fields), Pydantic too permissive, CORS too broad, missing OAuth2PasswordBearer scope validation, dependency injection not applied uniformly.

Verify `Depends(get_current_user)` actually validates token, `Depends(require_admin)` actually checks role, `response_model` filters output.

### Spring Boot

Common issues: Actuator endpoints exposed (env, heapdump, jolokia), CSRF disabled without justification, deserialization in `@RequestBody`, SpEL injection, unrestricted file uploads.

Verify `@PreAuthorize("hasRole('ADMIN')")` applied, `http.csrf().disable()` justified, `@CrossOrigin(origins = "*")` not on sensitive endpoints, actuator exposure limited.

### Django

Common issues: `DEBUG=True` in production, `ALLOWED_HOSTS` too permissive, `SECRET_KEY` in code, disabled security middleware, `@csrf_exempt` without justification, raw SQL with string formatting.

Verify `@login_required` applied, `@user_passes_test(is_admin)` applied, `User.objects.raw` parameterized, no `User.objects.extra(where=["... %s" % x])`.

### Rails

Common issues: Missing strong_parameters, skip_forgery_protection misused, `send_file` with user input (path traversal), deserialization via Marshal.load, unsafe link_to with user data.

Verify `before_action :require_admin`, `params.require(:user).permit(...)`, no `User.find_by_sql("... #{params[:id]}")`.

---

## 7. Taint Analysis

Tracking untrusted data from sources to sinks.

### Methodology

1. Identify sources (where untrusted data enters)
2. Identify sinks (where untrusted data is dangerous)
3. Trace flows from each source
4. At each step, check if data is sanitized
5. If data reaches sink without sanitization → finding

### Common sources

**User-controlled:** HTTP request parameters (query, body, headers, cookies), file uploads, WebSocket messages, form inputs.

**Semi-trusted:** Third-party API responses, database values (shared schemas), environment variables (if user-settable), configuration files (if user-modifiable).

**Less obvious:** Filenames, URLs passed to fetchers, Referer header, User-Agent, DNS responses.

### Common sinks

**Code execution:** `eval()`, `exec()`, `Function()`, `Runtime.exec()`, `subprocess.run()`, `require()` with dynamic input, dynamic imports.

**SQL:** `db.query()`, `db.exec()`, ORM raw query methods, cursor execution.

**Template rendering:** Template engines with HTML flag, string interpolation in responses, `innerHTML`, `outerHTML`.

**File system:** `fs.readFile()`, `fs.writeFile()`, `open()`, path operations.

**Network:** HTTP request methods (SSRF), DNS resolution, File:// URLs.

**Serialization:** `pickle.loads()`, `ObjectInputStream`, `YAML.load()` (unsafe variant).

### Taint analysis example

```
SOURCE: GET /search?q=<user-input>
  Handler: const q = req.query.q;

TRACE:
  searchUsers(q)        — No validation, passed to buildQuery(q)
  buildQuery(q)         — Returns `SELECT ... WHERE name LIKE '${q}%'` — CONCAT!
  executeQuery(query)   — db.query(query) — SINK

FINDING: SQL injection from GET /search?q

Evidence path:
  src/routes/search.js:15 (source)
  src/services/search.js:42 (searchUsers)
  src/services/query-builder.js:18 (buildQuery — dangerous concat)
  src/db/index.js:33 (executeQuery — sink)
```

### Sanitization patterns

Data becomes cleaned when it passes through: validation (that actually rejects), escaping (context-appropriate), parameterized queries (SQL), template engines (HTML, correctly configured), encoding libraries.

**Common mistakes:** Blacklist-based validation (always incomplete), encoding in wrong context (URL encoding for HTML), escape once use twice, custom regex that misses edge cases.

### Automated taint analysis tools

| Tool | Notes |
|------|-------|
| Semgrep | Pattern-based, taint-aware rules |
| CodeQL | Proper taint tracking, GitHub-backed |
| Psalm (PHP) | Taint analysis built-in |
| Phan (PHP) | Supports taint analysis |
| Pyre (Python) | Facebook's Python checker |

---

## 8. Authentication & Authorization Code Review

The most common source of critical vulnerabilities.

### Authentication review checklist

**Password handling:**
- Passwords hashed (not encrypted, not plaintext)
- Hash algorithm appropriate (bcrypt cost 12+, argon2id, scrypt — not MD5/SHA1)
- Salt per password
- Timing-safe comparison (constant-time)
- Password change requires current password
- Password reset tokens single-use and expiring

**Token handling:**
- JWT algorithm explicit (not 'none', not RS256/HS256 switchable)
- Token expiration enforced
- Refresh token rotation on use
- Tokens stored securely (httpOnly cookies over localStorage)
- Token revocation mechanism for critical operations
- Tokens include necessary claims (iss, aud, exp)

**Session handling:**
- Session ID regenerated on login (fixation prevention)
- Session invalidated on logout
- Session invalidated on password change
- Concurrent session handling defined
- Session timeout appropriate

**MFA:**
- MFA enrollment secure
- TOTP codes validated in correct time window
- Rate limiting on code attempts
- MFA bypass mechanisms documented and secure
- Backup codes (single-use, properly hashed)
- MFA required for high-privilege operations

### Authorization review

Per endpoint: authentication check present; authorization check present (role/permission); object-level authorization (ownership check); no client-trusted authorization.

**Flag patterns:**
- `if (req.user.isAdmin)` — trusted from session ✓
- `if (req.body.isAdmin)` — trusted from client ✗
- Missing auth check on similar endpoint
- Same resource accessed differently (one checks, one doesn't)

**Anti-patterns:**
1. UI-based authorization — UI hides admin button, endpoint accessible to all
2. Implicit authorization through path — `/api/users` vs `/api/admin/users`
3. Authorization-by-filtering — `WHERE user = me` skippable
4. Trusting client user ID — `PUT /api/user/{id}` where id from client

### Common authorization bugs

**Missing checks:** `app.get('/api/orders/:id', ...)` returning anyone's order — need `if (order.userId !== req.user.id && !req.user.isAdmin) return 403`.

**Trust-boundary confusion:** `@app.post("/api/posts")` trusting `post.user_id` from client — use authenticated identity: `user: User = Depends(get_current_user)`.

**Mass assignment:** `@user.update(params[:user])` allows changing any attribute including role — use strong parameters: `params.require(:user).permit(:name, :email)`.

---

## 9. Input Validation & Output Encoding Review

### Input validation

**Location priority:** validation at entry (best) > before dangerous operations > after processing (bad) > no validation (worst).

**Characteristics:** allowlist-based, type checking, length limits, format checking (regex), range checking, business logic validation, rejection (not just sanitization) for invalid data.

**Common failures:** only length check not content, regex missing edge cases (negative? scientific notation?), client-side only (bypassable), blocklist approach (trivial to bypass).

### Output encoding

Context-appropriate encoding is critical.

**Contexts:**
- HTML body: `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#x27;`
- HTML attribute: same + quote-delimited
- JavaScript: `\x3c`, `\x3e`, `\u003C`, `\u003E`
- URL: percent encoding
- CSS: `\6C`
- JSON: `\uXXXX`
- SQL: parameterized queries (not encoding!)
- LDAP: escape special chars
- XML: `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`

**Common bugs:** HTML-encoded in JS context, double encoding, encoding won't help (`<iframe src="{{userInput}}">` — src is URL context).

### Template engine review

**Safe by default:** React JSX (auto-escapes unless `dangerouslySetInnerHTML`), Vue `{{ }}` (unsafe via `v-html`), Angular (unsafe via `bypassSecurityTrust*`), Django templates, Rails ERB `<%= %>` (raw via `<%== %>`).

**Review focus per engine:**
- **React:** search `dangerouslySetInnerHTML`, check `__html` contents, verify sanitization
- **Vue:** search `v-html`, check directive value
- **Angular:** search `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, etc.
- **Django:** search `|safe` filter, `mark_safe()` calls, autoescape blocks

---

## 10. Cryptography Code Review

Crypto code is high-risk territory.

### Algorithm selection

**Symmetric encryption:** AES-256-GCM (authenticated, preferred) or ChaCha20-Poly1305. AES-256-CBC with HMAC acceptable. Avoid DES, 3DES, AES-ECB, unauthenticated modes alone.

**Asymmetric:** RSA 2048+ (4096 for long-lived), ECDSA P-256+, Ed25519 (preferred for new code). Avoid RSA-1024.

**Password hashing:** Argon2id (preferred), bcrypt cost 12+, scrypt. Never MD5, SHA1, or SHA-256 alone (too fast).

**Integrity hashing:** SHA-256, SHA-512, SHA-3. Never MD5 or SHA1 (collision vulnerable).

**MAC:** HMAC-SHA256+. Never homemade MAC constructs.

### Key management

- Keys from secure random source
- Keys stored separately from code
- Keys rotated periodically
- Keys of appropriate length
- Derivation via KDF (PBKDF2, Argon2, scrypt, HKDF)
- No hardcoded keys

### IV/Nonce handling

- Unique per encryption
- Appropriate length (GCM: 96 bits, CBC: 128 bits)
- Generated cryptographically
- Stored with ciphertext
- Never reused with same key

### Random number generation

- Use `crypto.randomBytes`, `secrets` module (Python), `crypto/rand` (Go)
- Never `Math.random()`, `rand()`, weak PRNGs
- Never time-based seeds alone or predictable patterns

### Common crypto issues

**Custom crypto** — red flag: rolling your own ciphers, MAC constructions, key derivation. Use well-audited libraries only.

**ECB mode:** `AES.new(key, AES.MODE_ECB)` — replace with `AES.MODE_GCM` (encrypt_and_digest returns nonce + ciphertext + tag).

**Hardcoded IV:** `iv = b'0123456789abcdef'` static — use `iv = secrets.token_bytes(16)`.

**Weak password hashing:** `hashlib.md5(password)` — use `bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))` or `argon2.PasswordHasher().hash(password)`.

**Timing attack:** `provided == expected` leaks — use `secrets.compare_digest(provided, expected)`.

---

## 11. Error Handling & Information Disclosure

### Error handling review

**Disclosure in responses:** stack traces, database error messages, file paths, internal IPs, framework versions, debug info.

**Flag:** `res.status(500).json({error: err.stack})`, `return {error: err.toString()}`, debug output in production logs, verbose database errors surfaced.

**Secure pattern:** log details server-side, return generic error + request ID: `logger.error('...', {err, userId}); res.status(500).json({error: 'Internal server error', requestId: req.id})`.

### Logging review

- Sensitive data not logged (passwords, tokens, PII)
- Stack traces go to server logs, not responses
- Logs have access controls
- Log levels appropriate (DEBUG not in prod)
- Structured logging for security events
- Audit logs for security-relevant actions
- Log tampering prevention

### Information disclosure vectors

**Direct:** error messages, stack traces, debug pages, database errors, file system errors.

**Indirect:** timing differences (valid vs invalid username), response size differences, status code differences, header differences.

**Source maps:** JS source maps on production reveal internal paths, function names, can expose commented-out code.

**Metadata:** server headers (nginx version, PHP version), X-Powered-By headers, response header leaks.

---

## 12. Git History Analysis

Git history often contains security-relevant information.

### Secret scanning

```bash
# git-secrets
git secrets --scan-history

# gitleaks
gitleaks detect --source . --verbose

# trufflehog
trufflehog git file://. --no-verification

# Manual search
git log -p -S "password" | grep -E "password.*=.*['\"]"
git log -p -S "api_key" | grep -E "api_key.*=.*['\"]"
```

### Historical vulnerabilities

```bash
# Commits that fix security issues
git log --all --grep="security\|vuln\|CVE\|xss\|sqli\|injection\|auth"

# Reverts of security fixes (bad sign)
git log --all --grep="revert.*security\|revert.*auth"

# Suspicious commit messages
git log --all --grep="temporary\|hack\|fixme\|todo.*security"
```

### Deleted files

```bash
git log --diff-filter=D --summary | grep delete
git log --all -- path/to/deleted/file
git show <commit>:path/to/deleted/file
```

### Secret patterns to search

- **AWS:** `AKIA[0-9A-Z]{16}` (Access Key), 40-char Secret Access Key
- **GCP:** `AIza[0-9A-Za-z_-]{35}` (API Key), `-----BEGIN PRIVATE KEY-----`
- **Stripe:** `sk_live_[0-9a-zA-Z]{24}`, `rk_live_[0-9a-zA-Z]{24}`
- **GitHub:** `ghp_[A-Za-z0-9_]{36}` (PAT), `gho_[A-Za-z0-9_]{36}` (OAuth)
- **Slack:** `xox[baprs]-[A-Za-z0-9-]{10,}`
- **Database URLs:** `postgresql://[^/]+:[^@]+@`, `mongodb://[^/]+:[^@]+@`, `mysql://[^/]+:[^@]+@`
- **Generic:** `api[_-]?key['"].*['"][A-Za-z0-9_-]{20,}['"]`, similar for secret/password/token

### Secret remediation

1. Rotate the secret IMMEDIATELY (don't clean up first)
2. Verify no unauthorized use during exposure window
3. Clean git history (BFG Repo-Cleaner, git filter-repo)
4. Force-push cleaned history
5. Notify users to re-clone
6. Update .gitignore to prevent recurrence
7. Consider git-secrets or pre-commit hooks

**Secrets in public git history should be assumed compromised. Rotation is mandatory, not optional.**

---

## 13. Configuration-as-Code Review

Modern infrastructure is defined in code — this code has security implications.

### Dockerfile security

**Anti-patterns:** No USER directive (runs as root), `:latest` tag, no multi-stage builds, secrets in layers, sensitive files copied (.git, .env).

**Good practices:** `USER app` (non-root), minimal base image (alpine, distroless, scratch), multi-stage builds, specific version tags, HEALTHCHECK defined, EXPOSE only needed ports.

**Scanners:** Hadolint (linter), Trivy, Docker Scout, Grype, Anchore.

### Docker Compose

Flag: `image: postgres:latest` (unpinned), hardcoded passwords in env, ports exposed to host when should be internal, no restart policy, no resource limits.

Better: use `POSTGRES_PASSWORD_FILE` with secrets, internal networks, `restart: unless-stopped`, resource limits.

### Kubernetes manifests

**Critical security settings:** `securityContext` with `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities: drop: [ALL]`. Resource limits and requests defined. Probes (liveness, readiness). Specific image tags (not `:latest`). NetworkPolicy restricts traffic. RBAC minimal. Secrets via projected volumes or CSI. PodSecurityStandards/Admission enforced.

**Scanners:** kube-score, kubesec, Polaris, Falco (runtime), OPA Gatekeeper (policy).

### Terraform / IaC

Common issues: S3 bucket `acl = "public-read"`, security group `cidr_blocks = ["0.0.0.0/0"]` with `protocol = "-1"`, IAM policy `Action = "*"`, `encrypted = false` on storage.

**Review checklist:** no public resources unless intentional, IAM least privilege, encryption at rest enabled, encryption in transit enforced, logging enabled (CloudTrail, Activity Log), tags for governance, state file secured, secrets from secret management, versioning/lifecycle/backup configured, network segmentation.

**Scanners:** tfsec, Checkov, Terrascan.

### CI/CD pipeline review

**GitHub Actions dangerous patterns:**
- `pull_request_target` with checkout of PR head + test run = attacker code with secrets
- Unpinned actions: `uses: actions/checkout@main` (use SHA)
- Script injection: `run: echo "Hello ${{ github.event.issue.title }}"`

**Safe:** Pin actions to SHA, use `pull_request` (not `pull_request_target`) for fork PRs, sanitize user input in workflow, minimal permissions (not `write-all`), audit log enabled, branch protection, required status checks, required reviews for sensitive paths, deployment approval for production.

---

## 14. Dependency Review

Supply chain security.

### Direct vs transitive

Typical ratio: Direct 50-100, Transitive 500-5000+. Most vulnerabilities are transitive.

### Review process

1. Generate SBOM
2. Check for known vulnerabilities (CVE database)
3. Check for abandoned/unmaintained packages
4. Check for suspicious packages (typosquatting, supply chain)
5. Check license compliance
6. Check dependency confusion risks
7. Review update frequency

### SBOM generation

```bash
# Multi-language
syft packages dir:/path/to/project
trivy fs --format cyclonedx --output sbom.json .

# Node.js
npm audit
npm sbom

# Python
pip-audit
cyclonedx-bom -o sbom.xml

# Go
cyclonedx-gomod mod -o sbom.json

# Rust
cargo audit
cargo-cyclonedx

# Java
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

### Vulnerability scanning tools

| Tool | Ecosystem | Notes |
|------|-----------|-------|
| Snyk | Multi | Commercial + free tier |
| Dependabot | GitHub | Free on GitHub |
| Trivy | Multi | Open source, fast |
| Grype | Multi | Open source |
| OSV-Scanner | Multi | Google's, open source |
| npm audit | Node.js | Built-in |
| pip-audit | Python | By PyPA |
| cargo-audit | Rust | By RustSec |
| govulncheck | Go | By Go team |

### Severity prioritization

Check exploitability: Is vulnerable code path reachable? Is vulnerable function actually called? Is input controllable by attacker?

### Supply chain attack indicators

- Sudden new maintainer of trusted package
- Rapid version bumps without clear reason
- Package description/homepage changes
- Publisher account compromised (check advisories)
- Typosquatting
- Dependency confusion
- Preinstall/postinstall scripts in new versions
- Obfuscated code
- Network connections from build tools
- Unexpected binaries bundled

**Notable incidents:** event-stream/flatmap-stream (2018), Colors.js/Faker.js (2022), ua-parser-js (2021), xz-utils (2024), polyfill.io (2024).

### License compliance

- **Permissive:** MIT, BSD, Apache 2.0, ISC (safe for most uses)
- **Weak copyleft:** LGPL, MPL (may require license notice)
- **Strong copyleft:** GPL, AGPL (may require releasing source)
- **Proprietary/restricted:** Commercial, BSL, Commons Clause

Review: all compatible licenses, GPL/AGPL impact understood, license files included, no conflicts, commercial licenses valid and paid.

---

## 15. Integration with Audit Phases

### Phase 0.5: Codebase Bootstrap (new phase)

When code is accessible:
- Read README, docs, architecture docs
- Map repository structure
- Identify entry points
- Summarize critical modules
- Check CI/CD for security posture clues
- Run initial SCA / dependency audit
- Generate codebase map document

**Output:** Codebase map guiding all subsequent phases.

### Cross-phase integration

**Phase 1 (Recon Bootstrap):** Use code to confirm framework/language, find API routes from source (better than JS bundle reverse engineering), identify admin/hidden endpoints.

**Phase 2 (Browser Traversal):** Compare browser findings with code — discrepancies reveal undocumented endpoints, code shows routes UI doesn't link to, code shows authorization that might be bypassed.

**Phase 3 (Security Assessment):** Code analysis finds what black-box misses — authorization logic gaps, input validation weaknesses, insecure defaults, dead code with old vulnerabilities, feature flags revealing hidden functionality.

**Phase 4 (Attack Chains):** Understand full data flow, find subtle privilege escalation paths, trace trust boundary violations.

**Phase 6 (Reporting):** Code-level findings provide exact file/line numbers, code snippets as evidence, specific fix recommendations, root cause analysis.

### Finding enrichment with code context

Without code access: "SQL injection in user search, use parameterized queries".

With code access:
- Location: `src/api/search.ts:42`
- Code: `db.query("SELECT * FROM users WHERE name LIKE '" + query + "'")`
- Root cause: string concatenation instead of parameter binding
- Remediation: `db.query("SELECT * FROM users WHERE name LIKE $1", [query + '%'])`
- Similar issues: 7 other locations using same anti-pattern

---

## 16. Code Analysis Checklist

```
Codebase Reconnaissance:
[ ] Repository structure mapped
[ ] Primary languages identified
[ ] Frameworks identified
[ ] Entry points enumerated
[ ] Configuration files located
[ ] CI/CD configuration reviewed
[ ] Codebase map document created

Code Summarization:
[ ] README and docs reviewed
[ ] Critical modules summarized
[ ] Data flows traced
[ ] Trust boundaries identified
[ ] Architecture patterns identified

Code Review:
[ ] Authentication code reviewed
[ ] Authorization code reviewed (all endpoints)
[ ] Input validation reviewed
[ ] Output encoding reviewed
[ ] Cryptography usage reviewed
[ ] Error handling reviewed
[ ] Session management reviewed
[ ] File handling reviewed
[ ] SQL/database interaction reviewed
[ ] External API calls reviewed
[ ] Third-party integration reviewed

Taint Analysis:
[ ] Sources identified (all user input)
[ ] Sinks identified (dangerous operations)
[ ] Flows traced source to sink
[ ] Sanitization verified at each step

Git History:
[ ] Secret scanning performed (gitleaks, trufflehog, git-secrets)
[ ] Suspicious commit patterns checked
[ ] Deleted files reviewed
[ ] Reverts of security fixes checked

Configuration as Code:
[ ] Dockerfile security reviewed
[ ] Docker-compose reviewed
[ ] Kubernetes manifests reviewed
[ ] Terraform/CloudFormation reviewed
[ ] CI/CD pipeline security reviewed
[ ] Secret management configuration reviewed

Dependencies:
[ ] SBOM generated
[ ] Vulnerability scan performed
[ ] Critical/high CVEs addressed
[ ] License compliance verified
[ ] Supply chain risk assessed

Integration:
[ ] Code findings cross-referenced with black-box findings
[ ] Root causes identified
[ ] Similar patterns checked across codebase
[ ] Findings include specific file:line references
[ ] Remediation includes code examples
```

---

## Cross-reference with other frameworks

Code analysis findings should map to:
- `references/frameworks/owasp-complete.md` for OWASP categorization
- `references/frameworks/owasp-asvs.md` for specific ASVS requirements verified
- `references/frameworks/appsec-testing-methods.md` for SAST/DAST/IAST tooling
- `references/attack-chains.md` for chaining code findings with runtime findings
