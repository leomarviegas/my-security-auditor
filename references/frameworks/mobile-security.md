# OWASP Mobile Application Security

This reference provides comprehensive mobile application security assessment guidance based on the OWASP Mobile Top 10 (2024), OWASP MASTG (Mobile Application Security Testing Guide), and OWASP MASVS (Mobile Application Security Verification Standard).

## Table of Contents
1. [Mobile Top 10 (2024) — Detailed](#1-mobile-top-10-2024)
2. [MASVS Verification Levels](#2-masvs-verification-levels)
3. [MASTG Testing Categories](#3-mastg-testing-categories)
4. [Platform-Specific Testing](#4-platform-specific-testing)
5. [Mobile API Security](#5-mobile-api-security)
6. [Mobile Threat Landscape](#6-mobile-threat-landscape)
7. [Mobile Security Checklist](#7-mobile-security-checklist)

---

## 1. Mobile Top 10 (2024)

### M1: Improper Credential Usage

**What it covers:** Hardcoded credentials, insecure credential storage, credentials in logs or shared preferences, API keys embedded in app bundles.

**Testing approach:**
- Decompile the app binary (APK/IPA) and search for hardcoded strings: API keys, tokens, passwords, connection strings, secret keys
- Check `SharedPreferences` (Android) and `NSUserDefaults`/Keychain (iOS) for stored credentials
- Review network traffic for credentials transmitted in plaintext or URL parameters
- Check if credentials persist after logout
- Search for credentials in application logs (`adb logcat` on Android)
- Look for debug/test credentials left in production builds
- Check if backup files contain credentials (Android `allowBackup=true`)

**Common patterns to catch:**
- Firebase API keys with overly broad permissions (Firebase keys are public by design but should be restricted via app check / security rules)
- AWS/GCP/Azure credentials in app bundles
- OAuth client secrets embedded in mobile apps (they shouldn't be — use PKCE instead)
- Backend API keys that should be server-side only
- Third-party SDK credentials (analytics, crash reporting, push notifications)

**Remediation guidance:**
- Use platform secure storage (Android Keystore, iOS Keychain) for all credentials
- Never embed server-side secrets in mobile apps
- Use OAuth2 with PKCE for mobile auth flows
- Implement credential rotation mechanisms
- Use Firebase App Check or equivalent for API key protection

---

### M2: Inadequate Supply Chain Security

**What it covers:** Compromised third-party SDKs, malicious dependencies, unverified library sources, vulnerable open-source components.

**Testing approach:**
- Extract and inventory all third-party libraries from the app binary
- Check library versions against known vulnerability databases (NVD, GitHub Advisory, Snyk)
- Verify SDK sources — are they from official repositories?
- Check for known malicious SDKs (data harvesting, ad fraud)
- Review SDK permissions — do they request more than their functionality needs?
- Check if SDKs have their own network communication (potential data exfiltration)
- Verify code signing and integrity of dependencies

**Key concerns:**
- Ad SDKs collecting excessive user data
- Analytics SDKs with known privacy violations
- Abandoned libraries with unpatched vulnerabilities
- Dependencies pulled from unofficial mirrors
- SDKs that include native code with additional attack surface

---

### M3: Insecure Authentication/Authorization

**What it covers:** Weak biometric implementation, missing server-side auth validation, bypassable local authentication, session management weaknesses.

**Testing approach:**
- Test if authentication can be bypassed by modifying local app state
- Verify that auth decisions are made server-side, not just client-side
- Check biometric implementation — can it be bypassed by rooting/jailbreaking?
- Test session token handling: storage, transmission, expiration, invalidation
- Check for user enumeration via auth endpoints
- Test password/PIN brute force protections
- Verify MFA implementation if present
- Test "remember me" functionality for security
- Check if app properly handles auth state after backgrounding/foregrounding
- Test deep link authentication bypass (`myapp://auth?token=...`)

**Authorization-specific tests:**
- Can one user access another user's data by modifying API requests from the app?
- Are role checks enforced server-side?
- Can premium/paid features be unlocked by modifying local app data?
- Does the app properly handle downgraded permissions?

---

### M4: Insufficient Input/Output Validation

**What it covers:** Injection via mobile inputs, WebView injection, unsafe deep link handling, clipboard data exposure, intent injection (Android).

**Testing approach:**
- Test all input fields for injection payloads (XSS, SQL, command injection)
- Check WebView configuration:
  - Is JavaScript enabled? (`setJavaScriptEnabled(true)`)
  - Are `addJavascriptInterface` bridges safe from injection?
  - Can external URLs be loaded in the WebView?
  - Is `file://` access restricted?
- Test deep link / universal link handlers for injection and redirect abuse
- Check clipboard handling — is sensitive data copied to clipboard? Is clipboard cleared?
- Test inter-app communication:
  - Android: Intent injection, exported components, broadcast receivers
  - iOS: URL scheme hijacking, Universal Links validation
- Check if app validates server responses before processing
- Test for format string vulnerabilities in native code

**WebView-specific risks:**
- JavaScript bridge allowing native function calls from web content
- Loading untrusted URLs without validation
- `file://` access enabling local file reading
- Missing SSL certificate validation in WebView
- Cookie sharing between WebView and native HTTP client

---

### M5: Insecure Communication

**What it covers:** Missing certificate pinning, cleartext traffic, weak TLS configuration, MitM susceptibility.

**Testing approach:**
- Intercept traffic with a proxy (Burp Suite, mitmproxy) to verify TLS enforcement
- Check for cleartext HTTP traffic (Android `networkSecurityConfig`, iOS ATS settings)
- Test certificate pinning:
  - Is pinning implemented?
  - Can it be bypassed with a custom CA?
  - Does it pin to leaf, intermediate, or root?
  - How does the app handle pin failure?
- Check TLS configuration (protocol versions, cipher suites)
- Test for TLS fallback to older versions
- Verify certificate validation — does the app accept self-signed certs?
- Check WebSocket and other non-HTTP communication for encryption
- Test third-party SDK communication — are they also using TLS?

**Platform-specific checks:**
- Android: Check `network_security_config.xml`, check for `TrustManager` overrides that disable validation
- iOS: Check ATS (App Transport Security) configuration, check for `NSAllowsArbitraryLoads`

---

### M6: Inadequate Privacy Controls

**What it covers:** Excessive data collection, missing consent flows, PII in logs/analytics, over-broad permissions.

**Testing approach:**
- Review app permissions — are they minimal and justified?
- Check what data is collected and sent to servers/analytics
- Verify consent mechanisms before data collection
- Check for PII in application logs
- Review analytics SDK configuration — what data is being tracked?
- Check if location/contacts/photos are accessed without clear need
- Verify data deletion mechanisms (account deletion, data export)
- Check compliance with platform privacy requirements (Google Play data safety, Apple privacy labels)
- Test if the app respects OS-level privacy settings (tracking transparency, location permissions)

---

### M7: Insufficient Binary Protections

**What it covers:** Missing obfuscation, no tamper detection, debuggable release builds, reverse-engineering exposure.

**Testing approach:**
- Check if the app is debuggable (`android:debuggable="true"`, iOS entitlements)
- Attempt to decompile and read source code (jadx for Android, Hopper/Ghidra for iOS)
- Check for code obfuscation (ProGuard/R8 for Android, Swift compilation for iOS)
- Test for root/jailbreak detection and its bypassability
- Check for tamper detection (signature verification, integrity checks)
- Test if the app can run on emulators (relevant for some security contexts)
- Check for anti-debugging mechanisms
- Look for sensitive business logic that could be reverse-engineered

---

### M8: Security Misconfiguration

**What it covers:** Exported components, debug mode enabled, insecure default settings, backup exposure.

**Testing approach:**
- Android-specific:
  - Check `AndroidManifest.xml` for exported components (activities, services, content providers, broadcast receivers)
  - Verify `allowBackup` is false or backup rules exclude sensitive data
  - Check for debug-only features accessible in release builds
  - Review content provider permissions
  - Check for world-readable/writable files
- iOS-specific:
  - Check `Info.plist` for insecure configurations
  - Review URL schemes for hijacking potential
  - Check Keychain access groups
  - Verify data protection classes on files
- Cross-platform:
  - Check for development/staging server URLs in production builds
  - Verify feature flags don't expose debug functionality
  - Check for insecure default configurations in third-party SDKs

---

### M9: Insecure Data Storage

**What it covers:** Sensitive data in shared preferences/SQLite unencrypted, world-readable files, cache exposure, screenshot/background snapshot exposure.

**Testing approach:**
- Check local databases (SQLite, Realm) for unencrypted sensitive data
- Review SharedPreferences/NSUserDefaults for sensitive values
- Check file system for sensitive files with improper permissions
- Verify that sensitive data is encrypted at rest using platform mechanisms
- Check cache directories for sensitive data
- Test background snapshot protection (does the app obscure content when backgrounded?)
- Check if keyboard cache contains sensitive input
- Review cookie storage for sensitive tokens
- Test data persistence after logout — is everything cleaned up?
- Check external storage (SD card on Android) for sensitive files

---

### M10: Insufficient Cryptography

**What it covers:** Weak algorithms, hardcoded keys, improper key management, insufficient key length.

**Testing approach:**
- Identify cryptographic operations in the decompiled code
- Check for deprecated algorithms (MD5, SHA1 for security purposes, DES, 3DES, RC4)
- Verify key lengths meet current standards (AES-256, RSA-2048+, ECC P-256+)
- Check for hardcoded encryption keys or IVs
- Verify proper use of cryptographic APIs:
  - Is CBC mode used with proper IV handling?
  - Is GCM/authenticated encryption used where needed?
  - Are keys derived properly (PBKDF2, Argon2) from passwords?
- Check for custom/homegrown cryptographic implementations (major red flag)
- Verify random number generation uses secure sources (`SecureRandom`, not `Math.random`)
- Check certificate validation implementation

---

## 2. MASVS Verification Levels

The Mobile Application Security Verification Standard defines two levels:

| Level | Name | When to apply |
|-------|------|--------------|
| MASVS-L1 | Standard Security | All mobile apps — baseline security |
| MASVS-L2 | Defense in Depth | Apps handling sensitive data, financial apps, healthcare |

### MASVS categories
| Category | ID | Coverage |
|----------|----|----------|
| Storage | MASVS-STORAGE | Secure data storage, data leakage prevention |
| Crypto | MASVS-CRYPTO | Cryptographic best practices |
| Auth | MASVS-AUTH | Authentication and session management |
| Network | MASVS-NETWORK | Network communication security |
| Platform | MASVS-PLATFORM | Platform interaction security (IPC, WebViews, deep links) |
| Code | MASVS-CODE | Code quality, binary protections |
| Resilience | MASVS-RESILIENCE | Anti-tampering, anti-reversing (L2 only) |
| Privacy | MASVS-PRIVACY | User privacy protection |

---

## 3. MASTG Testing Categories

The Mobile Application Security Testing Guide provides detailed test cases. Key tests per category:

### Storage testing
| Test ID | Description |
|---------|------------|
| MASTG-TEST-0001 | Testing local storage for sensitive data |
| MASTG-TEST-0002 | Testing logs for sensitive data |
| MASTG-TEST-0003 | Testing backups for sensitive data |
| MASTG-TEST-0004 | Testing memory for sensitive data |
| MASTG-TEST-0005 | Testing clipboard for sensitive data |

### Network testing
| Test ID | Description |
|---------|------------|
| MASTG-TEST-0019 | Testing endpoint identity verification |
| MASTG-TEST-0020 | Testing custom certificate stores and pinning |
| MASTG-TEST-0021 | Testing unencrypted requests |

### Platform testing
| Test ID | Description |
|---------|------------|
| MASTG-TEST-0027 | Testing deep links |
| MASTG-TEST-0028 | Testing WebViews |
| MASTG-TEST-0029 | Testing for injection flaws |

---

## 4. Platform-Specific Testing

### Android-specific
| Area | Tools / Approach |
|------|-----------------|
| APK analysis | apktool, jadx, dex2jar for decompilation |
| Dynamic analysis | Frida for runtime hooking, objection for quick checks |
| Traffic interception | Burp Suite + user-installed CA or Frida script to bypass pinning |
| Storage inspection | adb shell to browse app sandbox, check databases and shared prefs |
| Component testing | drozer for exported component analysis |
| Root detection bypass | Magisk Hide, Frida scripts |

### iOS-specific
| Area | Tools / Approach |
|------|-----------------|
| IPA analysis | Hopper, Ghidra, class-dump for binary analysis |
| Dynamic analysis | Frida, Cycript for runtime manipulation |
| Traffic interception | Burp Suite + profile-based CA, SSL Kill Switch for pinning bypass |
| Storage inspection | iExplorer, ssh to device for file system access |
| Keychain inspection | Keychain-dumper on jailbroken devices |
| Jailbreak detection bypass | Liberty Lite, Frida scripts |

---

## 5. Mobile API Security

Mobile apps almost always communicate with backend APIs. Apply these additional checks beyond standard API testing:

| Check | Why it matters for mobile |
|-------|-------------------------|
| Certificate pinning on API connections | Prevents MitM even on compromised networks |
| Token storage security | Mobile-specific storage risks (backup, screenshot, clipboard) |
| Offline token handling | Mobile apps may cache tokens for offline use — check expiration and refresh |
| Push notification token security | FCM/APNs tokens should be scoped and rotatable |
| API versioning | Old mobile app versions may use deprecated/vulnerable API versions |
| Rate limiting per device | Device ID or installation ID based rate limiting |
| Attestation | App integrity verification (Play Integrity API, App Attest) before granting API access |

---

## 6. Mobile Threat Landscape

### Common mobile attack scenarios
| Scenario | Attack path |
|----------|-----------|
| Stolen/lost device | Physical access → data extraction from local storage |
| Malicious WiFi | MitM on public WiFi → credential theft (if pinning missing) |
| Malicious app on same device | IPC abuse, clipboard sniffing, screen recording |
| Reverse engineering | Decompile app → extract secrets, bypass protections, create modded versions |
| Supply chain attack | Compromised SDK → data exfiltration, credential theft |
| Deep link abuse | Crafted deep link → auth bypass, redirect to phishing |

---

## 7. Mobile Security Checklist

```
Credentials & Storage:
[ ] No hardcoded secrets in app binary
[ ] Sensitive data stored in platform secure storage (Keystore/Keychain)
[ ] No sensitive data in logs, clipboard, or backups
[ ] Data cleared on logout
[ ] Background screenshot protection for sensitive screens

Authentication:
[ ] Auth decisions made server-side
[ ] Biometric implementation follows platform best practices
[ ] Session tokens properly managed (short-lived, secure storage, invalidation)
[ ] MFA available for sensitive operations

Communication:
[ ] All traffic over TLS (no cleartext exceptions)
[ ] Certificate pinning implemented
[ ] TLS configuration current (TLS 1.2+ only)
[ ] Certificate validation not overridden

Input/Output:
[ ] All inputs validated (client + server side)
[ ] WebViews restricted (no file access, limited JS bridge)
[ ] Deep links validated and sanitized
[ ] Server responses validated before processing

Privacy:
[ ] Minimal permissions requested
[ ] User consent before data collection
[ ] No PII in analytics/logs
[ ] Data deletion mechanism available

Binary Protection:
[ ] Release build not debuggable
[ ] Code obfuscation applied
[ ] Root/jailbreak detection (where appropriate)
[ ] Tamper detection (where appropriate)

Supply Chain:
[ ] All dependencies from trusted sources
[ ] Dependencies scanned for vulnerabilities
[ ] SDK permissions reviewed
[ ] No abandoned/unmaintained libraries
```
