# Cloud Security Frameworks

This reference covers cloud-specific security assessment frameworks for AWS, GCP, and Azure. Apply when the target application is deployed on cloud infrastructure.

## Table of Contents
1. [Shared Responsibility Model](#1-shared-responsibility-model)
2. [CIS Cloud Benchmarks](#2-cis-cloud-benchmarks)
3. [AWS Security Assessment](#3-aws-security)
4. [GCP Security Assessment](#4-gcp-security)
5. [Azure Security Assessment](#5-azure-security)
6. [Cloud Security Alliance (CSA) CCM](#6-csa-ccm)
7. [Cloud Attack Surface](#7-cloud-attack-surface)
8. [Cloud Security Checklist](#8-cloud-security-checklist)

---

## 1. Shared Responsibility Model

Understanding who is responsible for what is the foundation of cloud security.

### Responsibility split by service model
| Security domain | IaaS | PaaS | SaaS |
|----------------|------|------|------|
| Physical infrastructure | Provider | Provider | Provider |
| Network infrastructure | Provider | Provider | Provider |
| Hypervisor/host OS | Provider | Provider | Provider |
| Guest OS / runtime | **Customer** | Provider | Provider |
| Application code | **Customer** | **Customer** | Provider |
| Data | **Customer** | **Customer** | **Customer** |
| Identity & access management | **Shared** | **Shared** | **Shared** |
| Network controls | **Shared** | **Shared** | Provider (mostly) |
| Encryption configuration | **Customer** | **Shared** | **Shared** |

### Audit implication
When assessing cloud-deployed applications, focus on the customer-responsibility areas. Findings in provider-managed areas should be noted but attributed correctly.

---

## 2. CIS Cloud Benchmarks

The Center for Internet Security publishes hardening benchmarks for each cloud provider. Key areas to assess:

### CIS benchmark categories (common across providers)
| Category | What to check |
|----------|--------------|
| Identity and Access Management | MFA enforcement, root/admin account protection, password policies, API key management, service account hygiene |
| Logging and Monitoring | CloudTrail/Cloud Audit/Activity Log enabled, log storage protection, alerting configured, log retention |
| Networking | Default security group restrictions, VPC flow logs, no public access to management ports, network ACLs |
| Storage | No public S3/GCS/Blob buckets, encryption at rest enabled, access logging, versioning |
| Compute | No public IPs on internal instances, security groups minimal, OS hardening, instance metadata protection |
| Database | No public database endpoints, encryption at rest and transit, backup encryption, audit logging |
| Key Management | Customer-managed keys where required, key rotation, key access policies |

---

## 3. AWS Security

### AWS-specific attack surfaces observable from web audit
| Surface | What to look for |
|---------|-----------------|
| S3 buckets | Publicly accessible buckets (bucket URL patterns: `s3.amazonaws.com`, `s3-region.amazonaws.com`), directory listing enabled, sensitive data in public buckets |
| CloudFront | Missing custom error pages (leaking S3 origins), insecure origin access, missing WAF |
| API Gateway | Missing API keys or auth, verbose error responses, CORS misconfiguration, missing throttling |
| Cognito | User pool configuration exposure, identity pool misconfiguration, token handling weaknesses |
| Lambda | Function URL exposure, overly permissive execution roles, env variable secrets |
| EC2 metadata | SSRF to `169.254.169.254` → IAM role credential theft (IMDSv2 enforcement check) |
| ELB/ALB | Health check endpoint exposure, HTTP to HTTPS redirect, security group configuration |
| SES/SNS | Email spoofing configuration, notification endpoint exposure |

### AWS security headers to check
- `x-amz-*` headers revealing AWS infrastructure details
- S3 bucket names in URLs or responses
- AWS account IDs in error messages or responses
- IAM role ARNs in error messages

---

## 4. GCP Security

### GCP-specific attack surfaces
| Surface | What to look for |
|---------|-----------------|
| Cloud Storage | Public buckets, uniform vs fine-grained access, signed URL abuse |
| Cloud Run / Functions | Unauthenticated invocation, overly permissive service accounts, env variable secrets |
| Firebase | Insecure Realtime Database rules, Firestore rules, publicly readable/writable data, exposed API keys (Firebase API keys are public by design but should be restricted) |
| GCE metadata | SSRF to `metadata.google.internal` → service account token theft |
| Cloud Endpoints / API Gateway | Missing API key validation, unrestricted methods, CORS |
| IAP (Identity-Aware Proxy) | Bypass via direct IP access, header injection (`x-goog-iap-jwt-assertion`) |
| Cloud CDN | Cache poisoning, origin exposure through error pages |

### GCP security headers
- `x-goog-*` headers revealing GCP details
- Project IDs in responses or error messages
- Service account emails in responses

---

## 5. Azure Security

### Azure-specific attack surfaces
| Surface | What to look for |
|---------|-----------------|
| Blob Storage | Public containers, shared access signatures (SAS) with overly broad permissions or long expiry |
| App Service | Exposed Kudu/SCM console (`*.scm.azurewebsites.net`), debug settings, exposed environment variables |
| Azure Functions | Anonymous function access, overly permissive function keys, env variable secrets |
| Azure AD / Entra ID | Misconfigured app registrations, overly broad API permissions, consent phishing |
| IMDS | SSRF to `169.254.169.254` → managed identity token theft |
| API Management | Missing subscription keys, open developer portal, policy bypass |
| Key Vault | Overly permissive access policies, secrets in application settings instead of Key Vault |
| Front Door / CDN | WAF bypass, origin exposure, cache poisoning |

### Azure security headers
- `x-ms-*` headers revealing Azure details
- Subscription IDs or tenant IDs in responses
- Resource group names in error messages

---

## 6. CSA CCM

The Cloud Security Alliance Cloud Controls Matrix maps security controls across cloud environments and compliance frameworks.

### CCM domains
| Domain | ID | Focus areas |
|--------|----|------------|
| Audit & Assurance | A&A | Independent auditing, information system regulatory mapping |
| Application & Interface Security | AIS | Application security, API security, data integrity |
| Business Continuity & Operational Resilience | BCR | Planning, testing, disaster recovery |
| Change Control & Configuration Management | CCC | Change management, unauthorized change detection, baseline configs |
| Cryptography, Encryption & Key Management | CEK | Encryption, key management, certificate management |
| Datacenter Security | DCS | Physical security (provider responsibility) |
| Data Security & Privacy Lifecycle Management | DSP | Classification, inventory, flow mapping, retention, privacy |
| Governance, Risk & Compliance | GRC | Policies, risk management, compliance |
| Human Resources | HRS | Background checks, training, termination procedures |
| Identity & Access Management | IAM | Entitlements, credential lifecycle, MFA, privileged access |
| Interoperability & Portability | IPY | APIs, data portability, vendor lock-in |
| Infrastructure & Virtualization Security | IVS | Network security, OS hardening, segmentation |
| Logging & Monitoring | LOG | Encryption of logs, monitoring, alerting, forensics |
| Security Incident Management | SEF | Management, response, notification, remediation |
| Supply Chain Management | STA | Supply chain risk, data quality, third-party assessment |
| Threat & Vulnerability Management | TVM | Threat intelligence, vulnerability detection, patching |
| Universal Endpoint Management | UEM | Endpoint security policies |

---

## 7. Cloud Attack Surface

### Common cloud attack patterns observable from web audit
| Pattern | Detection method |
|---------|-----------------|
| Exposed cloud storage | Check for S3/GCS/Blob URLs in page source, API responses, JS bundles |
| Metadata endpoint SSRF | Test any URL-fetching features for `169.254.169.254` or `metadata.google.internal` access |
| Subdomain takeover | Check DNS for dangling CNAME records pointing to decommissioned cloud services |
| Insecure serverless | Test function/Lambda URLs for authentication requirements |
| Cloud credential leakage | Search JS bundles and responses for cloud API keys, access keys, connection strings |
| Misconfigured CDN | Check error pages for origin server exposure, test cache poisoning |
| Overly permissive APIs | Test cloud service APIs (Firebase, API Gateway) for authentication requirements |
| Cloud console exposure | Check for exposed admin panels (Kudu, Firebase console, etc.) |

---

## 8. Cloud Security Checklist

### Quick assessment checklist for cloud-deployed targets
```
[ ] No cloud credentials/keys in client-side code
[ ] Cloud metadata endpoint not accessible via SSRF
[ ] No public storage buckets with sensitive data
[ ] Serverless functions require authentication
[ ] Cloud CDN/proxy doesn't expose origin servers
[ ] No subdomain takeover vulnerabilities
[ ] Cloud-specific security headers don't leak infrastructure details
[ ] API gateway enforces authentication and rate limiting
[ ] No exposed admin consoles (Kudu, Firebase, etc.)
[ ] Cloud provider security features enabled (WAF, DDoS protection)
[ ] Encryption at rest and in transit configured
[ ] IAM follows least privilege
[ ] Logging and monitoring enabled across services
```
