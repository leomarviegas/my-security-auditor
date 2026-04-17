# OWASP-Style Web Assessment Checks

This reference contains the full checklist for Phase 3 of the web security audit. Work through each category systematically against the target application.

## Table of Contents
1. [Input Validation and Sanitization](#1-input-validation-and-sanitization)
2. [Authentication and Session Management](#2-authentication-and-session-management)
3. [Authorization and Access Control](#3-authorization-and-access-control)
4. [Secure Data Handling and Privacy](#4-secure-data-handling-and-privacy)
5. [API Security](#5-api-security)
6. [Security Headers and Hygiene](#6-security-headers-and-hygiene)
7. [File Upload Surfaces](#7-file-upload-surfaces)
8. [Vibecoder Smell Patterns](#8-vibecoder-smell-patterns)

---

## 1. Input Validation and Sanitization

Check all forms and input surfaces for unsafe handling.

### What to test
- HTML/script tag handling in text fields
- Reflected XSS: inject `<script>alert(1)</script>` or encoded variants in URL params, search fields, form inputs — only where non-persistent and safe
- Stored XSS: if a safe test surface exists (e.g., profile bio on a test account), try harmless payloads
- Dangerous HTML rendering (does the app render user-supplied HTML unsanitized?)
- Markdown or rich-text rendering abuse
- Template injection indicators (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`)
- SQL/NoSQL injection via safe probes: single quotes, `' OR 1=1--`, JSON structure manipulation
- Command injection indicators: backticks, `$(whoami)`, pipe characters
- Header injection / CRLF: `%0d%0a` in header-reflected inputs
- Path traversal: `../` sequences in file-related parameters
- Mass assignment / overposting: send extra JSON keys and check if they're accepted
- Missing length restrictions on text inputs
- Weak type validation (string where number expected, array where string expected)
- Unsafe filename handling in any upload or export feature

### Harmless probe payloads
Use these as your standard test inputs:
```
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
{{7*7}}
' OR '1'='1
'; DROP TABLE test; --
../../../etc/passwd
%0d%0aInjected-Header: true
```

### For each input surface, determine
- What is validated client-side vs server-side
- Whether client-side validation is bypassable (disable JS, modify request)
- Whether error messages leak internals (stack traces, SQL errors, file paths)
- Whether the app provides specific but non-sensitive validation errors

---

## 2. Authentication and Session Management

### Login flow
- Are credentials sent over HTTPS?
- Is there lockout or throttling after repeated failures?
- Do error messages distinguish between "user not found" and "wrong password"? (they shouldn't)
- Is there protection against credential stuffing (CAPTCHA, rate limiting)?

### Signup flow
- Can duplicate accounts be created?
- Are there email verification requirements?
- What password policy is enforced (length, complexity)?
- Can the signup flow be abused for user enumeration?

### Password reset
- Is the reset token time-limited?
- Is it single-use?
- Does it properly verify identity before allowing reset?
- Can the reset link be replayed?
- Is the token in the URL (potentially logged/leaked via referrer)?

### Session management
- Cookie flags: check for `HttpOnly`, `Secure`, `SameSite`
- Session fixation: does the session ID change after login?
- Idle timeout: does the session expire after inactivity?
- Logout: does it actually invalidate the server-side session?
- Concurrent sessions: are they limited or detectable?

### Token handling
- Where are JWTs stored? (`localStorage` = XSS-vulnerable, `httpOnly cookie` = safer)
- Is JWT signature actually validated server-side?
- Are refresh tokens properly scoped and rotated?
- Does role/permission change invalidate existing sessions?

### Additional auth patterns
- MFA: is it available? Required for sensitive actions?
- Magic links: do they expire? Are they single-use?
- OAuth flows: are state parameters validated? Is redirect_uri locked down?
- Remember-me: how is it implemented? Does it create a long-lived session?

---

## 3. Authorization and Access Control

### Vertical privilege escalation
- Can a regular user access admin routes directly?
- Are admin API endpoints protected server-side, or just hidden in the UI?
- Can a user escalate their role by modifying request parameters?

### Horizontal privilege escalation
- Can user A access user B's resources by changing IDs in URLs or API calls?
- Are resources ownership-filtered on the server side?
- Can predictable/sequential IDs be enumerated?

### IDOR / BOLA testing
- Identify all endpoints that take resource IDs (user profiles, documents, settings)
- Try accessing resources with IDs belonging to other users
- Check both GET (read) and PUT/DELETE (modify/delete) operations
- Test with both authenticated and unauthenticated requests

### Force browsing
- Try accessing `/admin`, `/dashboard`, `/internal`, `/debug`, `/api/admin/*`
- Check if routes return 403 (exists but forbidden) vs 404 (not found) — 403 confirms existence
- Look for routes referenced in JS bundles that aren't linked in the UI

### Role enforcement
- Is role checking done at the API layer or only in the UI rendering?
- If the UI hides a button for non-admins, does the underlying API still accept the request?
- Test by intercepting and replaying requests with different auth tokens

---

## 4. Secure Data Handling and Privacy

### Data exposure
- Do API responses include more data than the UI displays? (over-fetching)
- Are internal IDs, email addresses, or tokens visible in frontend code?
- Do error responses include stack traces, SQL queries, or file paths?
- Is PII visible in URL parameters (where it gets logged)?

### Client-side storage
- What's stored in `localStorage` and `sessionStorage`?
- Are tokens, PII, or sensitive config values stored client-side?
- Is sensitive data cleared on logout?

### Caching
- Are `Cache-Control` and `Pragma` headers set correctly on sensitive pages?
- Can authenticated pages be accessed from browser cache after logout?

### Secrets in code
- Search JS bundles for API keys, secrets, tokens, or credentials
- Look for environment variables leaked into client-side code
- Check for `.env` files accessible at common paths

---

## 5. API Security

### For every observed API endpoint, check:

**Authentication**
- Does it require auth? Should it?
- Can auth be bypassed by omitting the token?

**CORS**
- What origins are allowed? Is it `*` (wildcard)?
- Does it reflect the `Origin` header back (dangerously permissive)?
- Are credentials allowed with permissive origins?

**Rate limiting**
- Is there rate limiting on sensitive endpoints (login, reset, search)?
- What are the limits? Are they per-user or per-IP?

**Method confusion**
- Does a GET endpoint also accept POST/PUT/DELETE?
- Does changing the HTTP method bypass auth or validation?

**Content type**
- Does the API enforce expected Content-Type?
- Can JSON endpoints be exploited via form submission (CSRF via content-type confusion)?

**Error handling**
- Are errors generic ("something went wrong") or leaky (stack traces, SQL errors)?
- Do 404s and 403s behave consistently?

**CSRF**
- For cookie-authenticated endpoints, are CSRF tokens required?
- Can state-changing operations be triggered from a cross-origin page?

**GraphQL specifics (if present)**
- Is introspection enabled? Can the full schema be queried?
- Are there field-level access controls or can any authenticated user query anything?
- Is query depth/complexity limited?

---

## 6. Security Headers and Hygiene

Check these headers on every response from in-scope hosts:

| Header | What to look for |
|--------|-----------------|
| `Content-Security-Policy` | Present? Restrictive? Does it allow `unsafe-inline` or `unsafe-eval`? |
| `X-Frame-Options` | Present? Set to `DENY` or `SAMEORIGIN`? |
| `Strict-Transport-Security` | Present? Long `max-age`? `includeSubDomains`? |
| `X-Content-Type-Options` | Should be `nosniff` |
| `Referrer-Policy` | Should be `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | Present? Restricting sensitive APIs (camera, mic, geolocation)? |

### Additional hygiene checks
- HTTPS enforcement: does HTTP redirect to HTTPS? Are there mixed-content loads?
- `robots.txt`: does it reveal sensitive paths?
- `sitemap.xml`: does it expose internal or admin routes?
- Source maps: are `.map` files accessible? They leak full source code
- Stack traces or debug banners in production
- Server version headers (`Server`, `X-Powered-By`) leaking specific versions
- Insecure redirect behavior (open redirects via URL parameters)
- Common exposed paths: `/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `/debug`, `/graphql`, `/swagger`, `/api-docs`

---

## 7. File Upload Surfaces

If the application has file upload features, check:

### Validation
- What file extensions are allowed? Can the filter be bypassed?
- Is MIME type validated server-side (not just client-side)?
- Are magic bytes checked (file content matches claimed type)?
- Are file size limits enforced?

### Filename handling
- Can path traversal be performed via filename (`../../etc/passwd`)?
- Are filenames sanitized (special characters, null bytes)?
- Are uploaded files renamed or stored with original names?

### Storage and retrieval
- Are uploaded files publicly accessible without auth?
- What `Content-Type` and `Content-Disposition` headers are set when retrieving uploads?
- Could an uploaded HTML/SVG file execute scripts when viewed?
- Is there image/document processing that could be exploited (ImageMagick, PDF parsing)?

---

## 8. Vibecoder Smell Patterns

These are common shortcuts in AI-assisted or rapidly-built codebases. Look for:

### Code-level smells observable from the web surface
- Secrets, API keys, or connection strings visible in JS bundles
- Example or test credentials that still work (`admin/admin`, `test@test.com/password`)
- Auth checks implemented only in UI components (API accepts any request)
- Role or user identity trusted from client-side request parameters
- Missing ownership filters (any authenticated user can access any resource)
- Over-permissive CORS (`Access-Control-Allow-Origin: *` with credentials)
- Debug/development behavior active in production (verbose errors, dev tools, hot reload)
- Source maps deployed to production
- `dangerouslySetInnerHTML` or equivalent raw HTML rendering without sanitization
- `TODO`, `FIXME`, `HACK`, or `temporary` comments visible in client-side code
- Default framework configurations not hardened for production

### LLM/AI-specific patterns
- If the app uses AI features, check for prompt injection surfaces
- Are user inputs passed directly into LLM prompts without sanitization?
- Can system prompts be leaked via crafted inputs?
- Is AI-generated output rendered without sanitization?
