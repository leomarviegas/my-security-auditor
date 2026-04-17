# Kubernetes Security

This reference covers Kubernetes-specific security assessment. Apply when the target application runs on Kubernetes (EKS, GKE, AKS, RKE2, k3s, or self-managed).

## Table of Contents
1. [K8s Attack Surface from Web Audit](#1-k8s-attack-surface)
2. [API Server Security](#2-api-server-security)
3. [RBAC Assessment](#3-rbac-assessment)
4. [Pod Security](#4-pod-security)
5. [Network Policies](#5-network-policies)
6. [Secrets Management](#6-secrets-management)
7. [Supply Chain Security](#7-supply-chain-security)
8. [Runtime Security](#8-runtime-security)
9. [CIS Kubernetes Benchmark](#9-cis-kubernetes-benchmark)
10. [NSA/CISA Kubernetes Hardening Guide](#10-nsacisa-hardening)
11. [K8s Security Checklist](#11-k8s-security-checklist)

---

## 1. K8s Attack Surface from Web Audit

Even from a web-only audit perspective, you can detect Kubernetes deployment patterns and assess related risks.

### Observable K8s indicators
| Indicator | Where to find it | Risk |
|-----------|-----------------|------|
| Kubernetes-style headers | `Server: istio-envoy`, `x-envoy-*`, `x-b3-*` trace headers | Infrastructure exposure, service mesh detection |
| Pod hostname patterns | Error messages containing hostnames like `app-deployment-5d4b9-xyz` | Pod naming scheme reveals deployment structure |
| Health/readiness endpoints | `/healthz`, `/readyz`, `/livez`, `/ready`, `/health` | May expose internal state, dependency status |
| Exposed metrics | `/metrics` (Prometheus), `/debug/pprof` (Go profiling) | Internal metrics, performance data, potential DoS |
| Service mesh traces | Distributed tracing headers (Jaeger, Zipkin, OpenTelemetry) | Service topology mapping |
| Ingress controller headers | `server: nginx/x.x`, Traefik, Kong, HAProxy signatures | Ingress controller identification and version |
| Kubernetes API exposure | Accessible at port 6443 or 443 with K8s API responses | Full cluster compromise if unauthenticated |
| Dashboard exposure | Kubernetes Dashboard accessible without auth | Full cluster visibility and potential control |
| etcd exposure | Port 2379/2380 accessible | Complete cluster data (secrets, configs, state) |

### K8s-specific web testing
| Test | How |
|------|-----|
| Exposed API server | Try `https://target:6443/api`, `https://target:6443/version` |
| Exposed dashboard | Check common paths: `/dashboard`, `/api/v1/namespaces/kubernetes-dashboard` |
| Exposed metrics | Check `/metrics`, `/debug/vars`, `/debug/pprof/` |
| SSRF to internal services | If URL-fetching features exist, try `http://kubernetes.default.svc`, `http://10.96.0.1` |
| Service account token leakage | Check for JWT tokens with Kubernetes-specific claims in responses or client code |

---

## 2. API Server Security

The Kubernetes API server is the control plane's front door. If it's accessible, the cluster is at risk.

### Assessment areas
| Area | What to check |
|------|--------------|
| Authentication | Anonymous access disabled, strong auth methods (OIDC, client certs), no default tokens |
| Authorization | RBAC enabled (not ABAC or AlwaysAllow), admission controllers active |
| Network access | API server not publicly accessible, firewall rules restricting access |
| Audit logging | API audit logs enabled, logging policy covers sensitive operations |
| TLS | Valid certificates, strong TLS configuration, no self-signed certs in production |
| Admission controllers | PodSecurity, OPA/Gatekeeper/Kyverno active, webhook configs secure |

---

## 3. RBAC Assessment

Role-Based Access Control is Kubernetes' authorization mechanism. Misconfigurations are a leading cause of cluster compromise.

### Common RBAC misconfigurations
| Misconfiguration | Risk | How to detect |
|-----------------|------|--------------|
| Wildcard permissions (`*` on resources/verbs) | Full access to all resources | Review ClusterRoleBindings for `*` verbs or resources |
| cluster-admin bound to service accounts | Service account compromise = cluster compromise | Check bindings to `cluster-admin` ClusterRole |
| Default service account with elevated permissions | Every pod in namespace gets those permissions | Check default SA bindings per namespace |
| Excessive namespace-admin grants | Lateral movement between namespaces | Review RoleBindings with broad permissions |
| `escalate` or `bind` verbs granted | Privilege escalation via creating new bindings | Check for roles granting these verbs |
| `create pods` permission | Container escape → node compromise → cluster compromise | Treat pod creation as a high-privilege operation |
| Secrets access without need | Read all secrets including tokens and credentials | Check for `get/list/watch` on secrets |

### Least privilege assessment questions
- Does each service account have only the permissions it needs?
- Are there any ClusterRoleBindings that should be namespace-scoped RoleBindings?
- Are there unused service accounts with elevated permissions?
- Is RBAC the only authorization mode enabled?

---

## 4. Pod Security

Pod security controls prevent container breakout and privilege escalation.

### Pod Security Standards (PSS)
| Profile | Level | Requirements |
|---------|-------|-------------|
| Privileged | Unrestricted | No restrictions — only for system-level workloads |
| Baseline | Minimally restrictive | No privileged containers, no hostPath, no host networking, limited capabilities |
| Restricted | Heavily restricted | Must run as non-root, read-only root filesystem, drop ALL capabilities, seccomp enforced |

### Critical pod security checks
| Check | Risk if missing |
|-------|----------------|
| `runAsNonRoot: true` | Container escape via root privileges |
| `readOnlyRootFilesystem: true` | Malware persistence, config tampering |
| `allowPrivilegeEscalation: false` | suid binary exploitation |
| `capabilities.drop: [ALL]` | Kernel capability abuse |
| No `hostPath` volumes | Host filesystem access → node compromise |
| No `hostNetwork: true` | Network namespace escape, service sniffing |
| No `hostPID: true` | Process namespace escape, signal injection |
| `seccompProfile: RuntimeDefault` | Reduced syscall attack surface |
| Resource limits set | DoS prevention, noisy neighbor protection |
| No `privileged: true` | Complete container escape |

---

## 5. Network Policies

Kubernetes NetworkPolicies control pod-to-pod and pod-to-external communication. Missing policies mean flat network — any pod can reach any other pod.

### Assessment areas
| Area | What to check |
|------|--------------|
| Default deny | Is there a default-deny ingress/egress policy per namespace? |
| Ingress rules | Do pods only accept traffic from expected sources? |
| Egress rules | Are pods restricted in what they can reach (especially internet, metadata endpoint)? |
| Namespace isolation | Can pods in different namespaces communicate freely? |
| DNS egress | Is CoreDNS/kube-dns egress allowed but other egress restricted? |
| Metadata endpoint | Is egress to `169.254.169.254` blocked? |
| Service mesh policies | If using Istio/Linkerd, are AuthorizationPolicies or similar enforced? |

### Flat network risk
Without NetworkPolicies, a compromised pod can:
- Scan all pods in the cluster
- Access internal services (databases, caches, admin tools)
- Reach the Kubernetes API server
- Access cloud metadata endpoints
- Exfiltrate data to external hosts

---

## 6. Secrets Management

Kubernetes native secrets are base64-encoded, not encrypted. This is a major misconception and common vulnerability.

### Secret storage assessment
| Method | Security level | Issues |
|--------|---------------|--------|
| Kubernetes Secrets (default) | Low | Base64 only, stored in etcd, accessible via API |
| Kubernetes Secrets + etcd encryption at rest | Medium | Encrypted in storage but still accessible via API |
| External Secrets Operator + Vault/AWS SM/GCP SM | High | Secrets in dedicated secret manager, synced to K8s |
| CSI Secrets Store Driver | High | Secrets mounted directly from external manager, not stored in etcd |
| Sealed Secrets | Medium | Encrypted in Git, decrypted in cluster |

### Common K8s secrets issues
| Issue | Risk |
|-------|------|
| Secrets in ConfigMaps | Not even base64-encoded, visible in plain text |
| Secrets in environment variables | Visible in pod spec, may leak in logs/crash dumps |
| Secrets in container images | Baked into layers, extractable from registry |
| Default service account tokens auto-mounted | Every pod gets a token even if it doesn't need K8s API access |
| Secrets with overly broad RBAC access | Any pod with `get secrets` permission reads all secrets in namespace |

---

## 7. Supply Chain Security

Container supply chain attacks target the path from source code to running containers.

### Supply chain assessment areas
| Area | What to check |
|------|--------------|
| Image provenance | Are images from trusted registries? Are they signed (cosign/Notary)? |
| Base image security | Are base images minimal (distroless/alpine)? Are they regularly updated? |
| Vulnerability scanning | Are images scanned for CVEs before deployment (Trivy, Grype, Snyk)? |
| Admission control | Do admission controllers block unsigned or vulnerable images? |
| SBOM | Are Software Bills of Materials generated and tracked? |
| Build pipeline security | Is the CI/CD pipeline hardened? Are build environments ephemeral? |
| Registry security | Is the container registry access-controlled? Are images immutable (no mutable tags like `latest`)? |
| Runtime verification | Are running containers monitored for drift from their image? |

---

## 8. Runtime Security

Runtime security monitors and protects containers during execution.

### Runtime security tools and checks
| Area | Tools/Approaches | What to check |
|------|-----------------|--------------|
| Syscall monitoring | Falco, Sysdig, Tetragon | Are unexpected syscalls detected and alerted? |
| File integrity | Runtime file monitoring | Are modifications to container filesystems detected? |
| Network monitoring | Cilium, Calico with flow logs | Is anomalous network traffic detected? |
| Process monitoring | Falco rules, eBPF-based tools | Are unexpected processes (shells, miners) detected? |
| Drift detection | Various runtime scanners | Do running containers match their image? |

---

## 9. CIS Kubernetes Benchmark

The CIS benchmark covers hardening for all K8s components.

### Key benchmark sections
| Section | Component | Critical checks |
|---------|----------|----------------|
| 1 | Control Plane | API server flags (--anonymous-auth=false, --authorization-mode=RBAC), etcd encryption, audit logging |
| 2 | etcd | Client cert auth, peer encryption, data encryption at rest |
| 3 | Control Plane Configuration | Authentication, authorization, admission control |
| 4 | Worker Nodes | Kubelet config (--anonymous-auth=false, --authorization-mode=Webhook), protect kubelet cert/key |
| 5 | Policies | Pod Security Standards, NetworkPolicies, RBAC, secrets encryption, resource quotas |

---

## 10. NSA/CISA Hardening

The NSA/CISA Kubernetes Hardening Guide provides government-grade recommendations.

### Core recommendations
| Area | Recommendation |
|------|---------------|
| Pod security | Use non-root containers, read-only filesystems, drop capabilities, use seccomp/AppArmor |
| Network | Deny-by-default NetworkPolicies, encrypt traffic (mTLS via service mesh), separate sensitive workloads |
| Authentication | Disable anonymous auth, use short-lived tokens, enforce MFA for human access |
| Authorization | Least-privilege RBAC, no wildcard permissions, audit bindings regularly |
| Logging | Enable API audit logging, container logging, network flow logging |
| Threat detection | Runtime security monitoring (Falco), intrusion detection, anomaly alerting |
| Supply chain | Scan images, sign images, use minimal base images, pin image digests |
| Upgrading | Keep K8s and components current, automate patching, test upgrades |

---

## 11. K8s Security Checklist

### Quick assessment checklist
```
API Server & Control Plane:
[ ] API server not publicly exposed
[ ] Anonymous authentication disabled
[ ] RBAC enabled as sole authorization mode
[ ] Audit logging enabled
[ ] etcd encrypted at rest
[ ] Admission controllers active (PodSecurity/OPA/Kyverno)

Workload Security:
[ ] Pods run as non-root
[ ] Privileged containers not used (except system workloads)
[ ] Read-only root filesystems
[ ] Capabilities dropped
[ ] Resource limits set on all containers
[ ] Seccomp profiles applied

Networking:
[ ] Default-deny NetworkPolicies per namespace
[ ] No unnecessary pod-to-pod communication
[ ] Metadata endpoint blocked via egress policies
[ ] mTLS between services (service mesh)

Secrets:
[ ] External secrets manager used (Vault/AWS SM/GCP SM)
[ ] No secrets in ConfigMaps or env variables
[ ] Default service account token auto-mount disabled
[ ] Secrets RBAC restricted per namespace

Supply Chain:
[ ] Images scanned for vulnerabilities
[ ] Images signed and verified at admission
[ ] Minimal base images used
[ ] Mutable tags (latest) not used in production
[ ] SBOM generated

Monitoring & Response:
[ ] Runtime security monitoring active (Falco/Tetragon)
[ ] Container log aggregation
[ ] Network flow monitoring
[ ] Alerting for security events
```
