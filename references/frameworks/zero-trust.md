# Zero Trust Architecture

This reference covers Zero Trust security principles and assessment. Apply when evaluating the target's authentication, authorization, and network architecture against modern security standards.

## Table of Contents
1. [Zero Trust Principles](#1-zero-trust-principles)
2. [NIST SP 800-207 Zero Trust Architecture](#2-nist-sp-800-207)
3. [Zero Trust Maturity Model (CISA)](#3-cisa-ztmm)
4. [Zero Trust Assessment Areas](#4-assessment-areas)
5. [Zero Trust Anti-Patterns](#5-anti-patterns)
6. [Implementation Patterns](#6-implementation-patterns)
7. [Zero Trust Checklist](#7-zero-trust-checklist)

---

## 1. Zero Trust Principles

Zero Trust is not a product — it's an architectural approach based on core principles.

### Core tenets
| Principle | Meaning | What to check |
|-----------|---------|--------------|
| Never trust, always verify | Every request is authenticated and authorized regardless of network location | Are internal services authenticated? Can internal users bypass auth? |
| Least privilege access | Users and services get minimum necessary permissions | Are RBAC roles overly broad? Do service accounts have excessive permissions? |
| Assume breach | Design as if the network is already compromised | Is there lateral movement prevention? Are blast radii limited? |
| Verify explicitly | Authenticate based on all available data points (identity, location, device, behavior) | Is auth only based on password, or does it consider context (IP, device, behavior)? |
| Micro-segmentation | Fine-grained network and access boundaries | Is the network flat? Can any authenticated user reach any service? |
| Continuous validation | Don't trust sessions — revalidate continuously | Are long-lived tokens used? Is session state re-evaluated? |

---

## 2. NIST SP 800-207

The foundational Zero Trust Architecture document from NIST defines the logical components and deployment models.

### ZTA logical components
| Component | Function | Assessment questions |
|-----------|---------|---------------------|
| Policy Engine (PE) | Makes access decisions based on policy | Is there a centralized access decision point? Are policies documented? |
| Policy Administrator (PA) | Enforces PE decisions by configuring the data plane | Are access decisions enforced consistently across all services? |
| Policy Enforcement Point (PEP) | Gateway that enables/denies access | Is there a PEP for every resource? Can resources be accessed without going through a PEP? |
| Continuous Diagnostics & Mitigation (CDM) | Monitors asset state and compliance | Is device/workload health monitored? Is compliance checked at access time? |
| Threat Intelligence | Feeds risk signals into access decisions | Are threat intelligence feeds integrated into access decisions? |
| Activity Logs | Record all access for analysis | Are access events logged comprehensively? |
| Data Access Policy | Defines who can access what | Are data access policies defined and enforced? |

### ZTA deployment approaches
| Approach | Description | Audit focus |
|----------|------------|------------|
| Enhanced Identity Governance | Identity-centric, strong auth for all resources | Auth mechanism strength, token management, identity federation |
| Micro-segmentation | Network-centric, segments around each resource | Network policies, service mesh configuration, firewall rules |
| Software-Defined Perimeters | Overlay network hiding resources from unauthorized users | SDP gateway configuration, controller security, enrollment process |

---

## 3. CISA Zero Trust Maturity Model

CISA's maturity model grades Zero Trust implementation across five pillars at four levels.

### Maturity levels
| Level | Description |
|-------|------------|
| Traditional | Perimeter-based security, static policies, manual processes |
| Initial | Some automation, beginning identity-centric approach, basic visibility |
| Advanced | Centralized identity, automated policy enforcement, cross-pillar integration |
| Optimal | Continuous verification, dynamic policies, full automation, real-time risk assessment |

### Five pillars
| Pillar | Traditional | Initial | Advanced | Optimal |
|--------|-----------|---------|----------|---------|
| **Identity** | Passwords, basic MFA | Risk-based MFA, some SSO | Continuous validation, behavior analytics | Passwordless, real-time risk scoring, just-in-time access |
| **Devices** | No device posture checks | Basic compliance checks | Continuous compliance, EDR integration | Real-time device health in every access decision |
| **Networks** | Perimeter firewall, flat internal | Basic segmentation, VPN | Micro-segmentation, encrypted internal traffic | Software-defined, fully encrypted, dynamic segmentation |
| **Applications & Workloads** | Perimeter protection only | Basic auth per app, some WAF | Per-request authorization, workload identity | Continuous workload verification, adaptive access |
| **Data** | Perimeter protection | Basic classification, some encryption | Automated classification, DLP, encryption everywhere | Real-time data access governance, automated response |

### Cross-cutting capabilities
| Capability | What to assess |
|-----------|---------------|
| Visibility & Analytics | Can the organization see all access events? Are anomalies detected? |
| Automation & Orchestration | Are access policies automatically enforced? Are responses automated? |
| Governance | Are Zero Trust policies documented, reviewed, and updated? |

---

## 4. Assessment Areas

When auditing a target, assess these Zero Trust dimensions.

### Identity and authentication
| Check | Zero Trust expectation | Common failures |
|-------|----------------------|----------------|
| All resources require auth | No resource accessible without identity verification | Internal APIs without auth, public health endpoints exposing data |
| Strong authentication | MFA, phishing-resistant auth (FIDO2/WebAuthn) | Password-only auth, SMS-based MFA, weak recovery flows |
| Session management | Short-lived tokens, continuous validation | Long-lived JWTs, sessions that never expire, no re-auth for sensitive ops |
| Service identity | Every service has a verifiable identity | Services using shared secrets, no inter-service auth |
| Identity federation | Centralized identity across all services | Fragmented auth (different identity stores per service) |

### Network architecture
| Check | Zero Trust expectation | Common failures |
|-------|----------------------|----------------|
| Micro-segmentation | Fine-grained network boundaries per workload | Flat networks, broad security groups, no NetworkPolicies |
| Encrypted transit | All traffic encrypted, even internal | Plaintext HTTP between services, mTLS in permissive mode |
| No implicit trust | Network location doesn't grant access | VPN = full internal access, trusted IP ranges bypass auth |
| East-west traffic control | Lateral movement restricted | Any service can reach any other service |
| Egress control | Outbound traffic restricted and monitored | Unrestricted internet access from internal services |

### Access control
| Check | Zero Trust expectation | Common failures |
|-------|----------------------|----------------|
| Per-request authorization | Every request evaluated against policy | Auth checked at login only, subsequent requests trusted |
| Context-aware access | Decisions consider identity + device + location + behavior + risk | Simple role check only, no contextual signals |
| Just-in-time access | Elevated permissions granted temporarily | Standing admin access, permanent elevated roles |
| Least privilege | Minimum necessary permissions per entity | Over-broad roles, wildcard permissions, default-allow |

### Data protection
| Check | Zero Trust expectation | Common failures |
|-------|----------------------|----------------|
| Data classification | All data classified by sensitivity | No classification scheme, everything treated the same |
| Encryption everywhere | At rest and in transit, always | Unencrypted databases, plaintext internal communication |
| Access governance | Data access logged, monitored, controlled | No data access logging, no DLP |
| Data minimization | Services access only needed data | Over-fetching, shared databases, broad query access |

---

## 5. Anti-Patterns

These are common patterns that violate Zero Trust principles. Flag them when observed.

| Anti-pattern | Why it's bad | Zero Trust alternative |
|-------------|-------------|----------------------|
| VPN as security boundary | VPN = trusted, outside = untrusted. Breach inside VPN = game over | Per-resource auth regardless of network |
| Network-based trust | "Internal network" traffic bypasses auth | mTLS + identity verification on all traffic |
| Long-lived tokens | Stolen token = extended unauthorized access | Short-lived tokens with continuous validation |
| Shared service accounts | Multiple services share one identity | Unique identity per service (SPIFFE/workload identity) |
| Role explosion without governance | Too many roles, nobody knows who has what | Attribute-based access control (ABAC), regular access reviews |
| Auth at the perimeter only | Gateway checks auth, internal services trust each other | Auth at every service, defense in depth |
| Static security policies | Policies defined once, never updated | Continuous policy evaluation based on real-time signals |
| Implicit trust for admins | Admin users bypass security controls | Admin access subject to same or stricter controls |

---

## 6. Implementation Patterns

Recommend these patterns when writing Zero Trust remediation guidance.

### Identity-centric patterns
| Pattern | Implementation |
|---------|---------------|
| Centralized IdP | OIDC/SAML federation through single identity provider |
| Phishing-resistant MFA | FIDO2/WebAuthn for human users |
| Workload identity | SPIFFE/SPIRE or cloud provider workload identity (GKE WI, EKS IRSA) |
| Just-in-time access | Temporary role elevation with automatic expiry |
| Continuous authentication | Re-evaluate session risk based on behavior, location, device changes |

### Network-centric patterns
| Pattern | Implementation |
|---------|---------------|
| Micro-segmentation | Kubernetes NetworkPolicies, cloud security groups per workload |
| Service mesh mTLS | Istio STRICT mode, Linkerd auto-mTLS, Consul Connect |
| Software-defined perimeter | Zscaler, Cloudflare Access, Google BeyondCorp |
| Encrypted DNS | DNS-over-HTTPS/TLS for internal resolution |

### Data-centric patterns
| Pattern | Implementation |
|---------|---------------|
| Attribute-based access | ABAC policies evaluating user attributes, resource sensitivity, context |
| Data tokenization | Replace sensitive data with tokens for non-privileged services |
| Field-level encryption | Encrypt specific sensitive fields, decrypt only for authorized services |
| Automated classification | ML-based data classification with policy enforcement |

---

## 7. Zero Trust Checklist

```
Identity:
[ ] All resources require authentication (no exceptions for "internal" resources)
[ ] MFA enforced for all human users
[ ] Phishing-resistant auth available for high-privilege users
[ ] Service-to-service authentication in place
[ ] Short-lived tokens (< 1 hour for access tokens)
[ ] Session re-evaluation for sensitive operations

Network:
[ ] No implicit network trust (VPN doesn't bypass per-resource auth)
[ ] Micro-segmentation between services
[ ] All internal traffic encrypted (mTLS)
[ ] Egress traffic restricted and monitored
[ ] Lateral movement limited by network controls

Access Control:
[ ] Per-request authorization (not just per-session)
[ ] Least privilege enforced (regular access reviews)
[ ] Context-aware access decisions (not just role check)
[ ] Just-in-time access for elevated permissions
[ ] Admin access subject to same or stricter controls

Data:
[ ] Data classified by sensitivity
[ ] Encryption at rest and in transit everywhere
[ ] Data access logged and monitored
[ ] Data minimization per service (each gets only what it needs)
[ ] DLP controls for sensitive data

Monitoring:
[ ] All access events logged with correlation IDs
[ ] Anomaly detection on access patterns
[ ] Continuous compliance monitoring
[ ] Automated response to policy violations
[ ] Regular access reviews and certification
```
