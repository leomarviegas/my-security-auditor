# Network Security Audit

This reference covers network-layer auditing across five dimensions: namespace access (Linux netns and Kubernetes namespaces), network services inventory, traffic flow journeys between trust zones, network policy auditing, and host firewall auditing. Use this when the engagement scope includes any network or infrastructure access — node shell, kubectl, or cloud API.

## Table of Contents
1. [When to Use This Reference](#1-when-to-use-this-reference)
2. [Namespace Access Auditing](#2-namespace-access-auditing)
3. [Network Services Inventory](#3-network-services-inventory)
4. [Traffic Flow Journeys](#4-traffic-flow-journeys)
5. [Network Policy Auditing](#5-network-policy-auditing)
6. [Host Firewall Auditing](#6-host-firewall-auditing)
7. [WAF, Load Balancer, and API Gateway Auditing](#7-waf-load-balancer-and-api-gateway-auditing)
8. [Integration with Audit Phases](#8-integration-with-audit-phases)
9. [Network Security Checklist](#9-network-security-checklist)

---

## 1. When to Use This Reference

### Trigger conditions

Load this reference when:
- The engagement includes node or host shell access (Linux, Windows servers)
- kubectl access is granted (pods, services, netpol, endpoints)
- Cloud API access is granted (AWS/GCP/Azure VPC, security groups, NACLs, firewall rules)
- The user asks for a "network audit", "firewall audit", "NetworkPolicy review", "VPN audit", "segmentation review", "lateral movement assessment", or "traffic flow analysis"
- Phase 1 recon identifies Kubernetes, service mesh, or complex network topology
- Blue team / detection engineering engagement includes network visibility assessment

### Scope boundaries

This reference covers the **authorized** audit of network surfaces. It does NOT cover:
- Active network exploitation (use `red-team.md` for engagements that include exploitation)
- Wireless network attacks (out of scope for most infrastructure audits)
- Physical network access (separate engagement type)

### Authorization prerequisites

Before running any of the commands in this reference, confirm:

| Capability needed | Authorization to confirm |
|-------------------|--------------------------|
| Node shell access | User owns or operates the node; shell access is authorized |
| kubectl access | User has RBAC permissions; namespace scope documented |
| Cloud API access | IAM role scoped to read-only is available |
| Packet capture | Explicit capture consent; check data residency rules |
| Cross-namespace probes | Authorized for all namespaces being probed |

Network-layer audits can trigger SIEM alerts. Notify the defensive team before running port scans, cross-namespace probes, or packet captures against production.

---

## 2. Namespace Access Auditing

Two distinct concepts share the word "namespace": Linux network namespaces (kernel-level network isolation) and Kubernetes namespaces (API-level logical partitioning). Audit both when applicable.

### 2.1 Linux network namespace enumeration

**List all network namespaces on a host:**

```bash
# Named namespaces
ip netns list

# All namespaces (including anonymous ones used by containers)
sudo ls -la /proc/*/ns/net | awk '{print $NF}' | sort -u

# Match namespaces to processes
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  ns=$(readlink /proc/$pid/ns/net 2>/dev/null)
  if [ -n "$ns" ]; then
    echo "$ns $pid $(cat /proc/$pid/comm 2>/dev/null)"
  fi
done | sort -u
```

**Per-namespace inspection:**

```bash
# Enter a named namespace and inspect
sudo ip netns exec <ns-name> ip addr
sudo ip netns exec <ns-name> ip route
sudo ip netns exec <ns-name> ss -tulnpe

# For container/anonymous namespaces, use nsenter with a PID
sudo nsenter -t <pid> -n ip addr
sudo nsenter -t <pid> -n ss -tulnpe
```

**Red flags:**
- Processes running with `hostNetwork: true` or in the host netns when they shouldn't be
- Namespaces with `CAP_NET_ADMIN` leaking into unprivileged containers
- Bind mounts of `/proc/*/ns/net` into containers (namespace escape vector)
- Multiple containers sharing an unexpected network namespace

### 2.2 Kubernetes namespace enumeration

**List all namespaces and their workloads:**

```bash
kubectl get namespaces
kubectl get namespace -o json | jq -r '.items[] | "\(.metadata.name)\t\(.metadata.labels)"'

# Per-namespace resource dump
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  echo "===== $ns ====="
  kubectl get -n $ns pods,svc,endpoints,networkpolicy,ingress,hpa 2>/dev/null
done
```

**Identify high-value namespaces:**
- `kube-system` — control plane components, CoreDNS, CNI agents
- `kube-public` — cluster-info, world-readable
- `kube-node-lease` — node heartbeat leases
- Ingress controller namespaces (nginx-ingress, contour, traefik)
- Service mesh namespaces (istio-system, linkerd, consul)
- Monitoring namespaces (prometheus, grafana, datadog)
- Secrets-operator / external-secrets namespaces
- Any namespace labeled `tier=prod` or similar

### 2.3 Intra-namespace access testing

Deploy a probe pod in each namespace and test reachability:

```bash
# Temporary debug pod in namespace
kubectl run netshoot-$RANDOM -n <namespace> --rm -it --image=nicolaka/netshoot --restart=Never -- /bin/bash

# Inside the pod, probe other workloads in the SAME namespace
nmap -sT -p- <same-ns-pod-ip>
curl -v http://<same-ns-service>:<port>/

# Check if the ServiceAccount token is mounted
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -c1-50

# Test if the pod can reach the API server
curl -sk https://kubernetes.default.svc/api/v1/namespaces/<namespace>/pods \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

**What you're checking:**
- Can pods within a namespace reach each other unrestricted? (usually yes by default)
- Do workloads mount SA tokens they don't need? (`automountServiceAccountToken: false` missing)
- Are port ranges restricted, or is everything open?

### 2.4 Extra-namespace access testing

From a pod in namespace A, test reachability to namespace B:

```bash
# Cross-namespace service FQDN
curl -v http://<service>.<other-ns>.svc.cluster.local:<port>/

# Cross-namespace pod IP (if pod IPs are flat across namespaces — common)
curl -v http://<pod-ip-in-other-ns>:<port>/

# Test reachability to kube-system
curl -sk https://kube-dns.kube-system.svc.cluster.local:53/
nmap -sT -p 6443,10250,10259,10257 <control-plane-ip>

# Test cloud metadata service (SSRF-via-pod)
curl --max-time 2 http://169.254.169.254/latest/meta-data/
curl --max-time 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/
```

**Red flags:**
- Pods in `tenant-a` can reach `tenant-b` services without NetworkPolicy
- Any pod can reach kube-apiserver on 6443 or kubelet on 10250
- Any pod can reach the cloud metadata service (credential exposure)
- Any pod can reach the overlay network control plane (etcd, BGP peers)

---

## 3. Network Services Inventory

What's listening, where, and on behalf of what process. Collect this per host and per namespace.

### 3.1 Per-host listener inventory

**Linux host:**

```bash
# All listening TCP/UDP sockets with PID and owner
sudo ss -tulnpe

# Alternative with lsof (slower, more detail)
sudo lsof -i -P -n | grep LISTEN

# Interface and routing state
ip addr
ip route
ip rule        # policy routing rules
ip -6 addr     # IPv6 — don't forget dual-stack
ip -6 route
```

**Consolidated output per host:**

```bash
cat <<'EOF' > /tmp/listener-inventory.sh
#!/bin/bash
echo "=== Hostname ==="
hostname
echo "=== Interfaces ==="
ip -br addr
echo "=== Routes (v4) ==="
ip -4 route
echo "=== Routes (v6) ==="
ip -6 route
echo "=== Listening sockets ==="
sudo ss -tulnpe
echo "=== Established connections (sample) ==="
sudo ss -tnp | head -20
EOF
chmod +x /tmp/listener-inventory.sh
sudo /tmp/listener-inventory.sh
```

### 3.2 Per-netns listener inventory

```bash
# Loop through all named netns
for ns in $(ip netns list | awk '{print $1}'); do
  echo "===== netns: $ns ====="
  sudo ip netns exec $ns ss -tulnpe 2>/dev/null
done

# For containers, loop via /proc/*/ns/net
declare -A seen_ns
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  ns=$(readlink /proc/$pid/ns/net 2>/dev/null)
  [ -z "$ns" ] && continue
  [ "${seen_ns[$ns]}" = "1" ] && continue
  seen_ns[$ns]=1
  echo "===== PID $pid ($ns) ====="
  sudo nsenter -t $pid -n ss -tulnpe 2>/dev/null
done
```

### 3.3 Kubernetes service and endpoint inventory

```bash
# All services across all namespaces with cluster IP, ports, type
kubectl get svc -A -o wide

# All ingresses
kubectl get ingress -A -o wide

# Gateway API resources (newer ingress model)
kubectl get gateway,httproute,tcproute,tlsroute,grpcroute -A 2>/dev/null

# Endpoints — which pod IPs back each service
kubectl get endpoints -A

# EndpointSlices (K8s 1.21+, replaces endpoints at scale)
kubectl get endpointslices -A

# Services exposed to the outside world
kubectl get svc -A -o json | jq -r '
  .items[]
  | select(.spec.type=="LoadBalancer" or .spec.type=="NodePort" or (.spec.externalIPs // [] | length > 0))
  | "\(.metadata.namespace)/\(.metadata.name)\t\(.spec.type)\t\(.spec.ports)"
'

# Pods using hostNetwork or hostPort (bypass cluster network)
kubectl get pods -A -o json | jq -r '
  .items[]
  | select(.spec.hostNetwork==true or ([.spec.containers[].ports[]?.hostPort // empty] | length > 0))
  | "\(.metadata.namespace)/\(.metadata.name)\thostNetwork=\(.spec.hostNetwork)\thostPorts=\([.spec.containers[].ports[]?.hostPort // empty])"
'
```

### 3.4 External scan cross-reference

If authorized for external scanning, cross-reference internal inventory against what's reachable from outside:

```bash
# From an authorized external vantage point, scan the advertised endpoints
nmap -sT -Pn -p- --top-ports 1000 <public-ip-or-lb>

# Delta: what's exposed externally that isn't in your inventory? Or vice versa?
```

**Red flags:**
- Services bound to `0.0.0.0` when they should be on `127.0.0.1` or the private interface
- Database ports (3306, 5432, 6379, 27017, 9200) reachable from outside the namespace/VPC
- Admin/management ports (kubelet 10250, etcd 2379, Prometheus 9090) reachable widely
- `hostNetwork: true` pods exposing ports directly on node IPs
- Deprecated kubelet read-only port 10255 exposed (discloses pod info without auth)
- LoadBalancer services exposing internal APIs with no ACL

### 3.5 Service inventory output template

```
| Host/Namespace | Bind Address | Port | Proto | Process/Pod | Purpose | External Exposure |
|----------------|--------------|------|-------|-------------|---------|-------------------|
| prod-ns        | 10.42.1.5    | 8080 | TCP   | api-gw      | HTTP    | LB → Internet     |
| prod-ns        | 10.42.1.6    | 5432 | TCP   | postgres    | DB      | ClusterIP only    |
| kube-system    | 0.0.0.0      | 10250| TCP   | kubelet     | kubelet | Node-local SG     |
```

---

## 4. Traffic Flow Journeys

For any source→destination pair, trace the traffic through every hop and check what can inspect, filter, or modify it. This is the core of a network audit.

### 4.1 Nine-step journey methodology

For each significant traffic path, answer:

1. **Source** — who initiates (pod, VM, user, external client)?
2. **DNS** — how is the destination resolved? Which resolver? Can it be poisoned?
3. **Routing** — which route table is consulted? Default route or specific?
4. **Egress filter** — what firewall/policy applies leaving the source?
5. **Transit** — what carries the traffic (overlay, underlay, VPN, internet)?
6. **Ingress filter** — what firewall/policy applies arriving at destination?
7. **Destination** — who accepts (service, pod, endpoint)?
8. **Encryption** — is traffic encrypted in transit? Mutual auth?
9. **Logging** — what logs record this flow (flow logs, mesh telemetry, NetworkPolicy audit)?

Each of these is a potential finding dimension. A missing egress filter, an unencrypted transit link, or an unlogged flow are all audit outputs.

### 4.2 Path type: pod-to-pod same namespace

```
[pod-a] → CNI veth → node bridge → (overlay?) → node bridge → CNI veth → [pod-b]
```

**Checks:**
- NetworkPolicy selecting pod-b restricts ingress from pod-a? (Usually no by default.)
- Service mesh sidecar (Envoy, Linkerd proxy) intercepts and enforces mTLS?
- iptables/nftables rules added by kube-proxy or CNI log or filter this flow?

### 4.3 Path type: pod-to-pod cross-namespace

```
[pod-a in ns-a] → same as above → [pod-b in ns-b]
```

**Checks:**
- Both pods in flat pod network by default — reachable unless NetworkPolicy in place
- NetworkPolicy in ns-b selecting pod-b with `from.namespaceSelector` matching ns-a?
- Is `kubernetes.io/metadata.name` label used correctly to select the source namespace?
- Service mesh AuthorizationPolicy enforcing per-service allow-list?

### 4.4 Path type: pod-to-external

```
[pod] → CNI → node → SNAT (kube-proxy/MASQUERADE) → VPC/NAT gateway → internet
```

**Checks:**
- NetworkPolicy with `egress` rules restricting external destinations?
- Cluster egress gateway (Cilium, Istio) centralizes and controls egress?
- Can pods reach `169.254.169.254` (cloud metadata)? Huge red flag if yes.
- Are FQDN-based egress allowlists enforced, or only CIDR?
- VPC NACL / security group on node allows the egress?
- VPC flow logs recording the flow?

**Canonical attack chain to test:**
```
SSRF in webapp pod → pod egress allows metadata service → retrieve IAM role credentials → cloud API access
```

If a pod has no legitimate reason to reach the cloud metadata service, block `169.254.169.254` at the CNI / NetworkPolicy level and at IMDSv2 (AWS) with hop-limit 1.

### 4.5 Path type: node-to-node (control plane)

```
[kubelet on node-a] → underlay → [kube-apiserver on control-plane]
[node-a etcd peer] → underlay → [node-b etcd peer]
[CNI BGP speaker] → underlay → [CNI BGP speaker peer]
```

**Ports to verify are restricted to control plane/node CIDR only:**

| Port | Purpose | Who should reach |
|------|---------|------------------|
| 6443 | kube-apiserver | nodes, admins |
| 10250 | kubelet | kube-apiserver, metrics-server |
| 10255 | kubelet read-only (deprecated) | nobody — should be disabled |
| 10259 | kube-scheduler | localhost |
| 10257 | kube-controller-manager | localhost |
| 2379 | etcd client | kube-apiserver only |
| 2380 | etcd peer | etcd nodes only |
| 8472 | VXLAN overlay (Flannel/Cilium) | nodes only |
| 6081 | Geneve overlay (Antrea/OVN) | nodes only |
| 179 | BGP (Calico/Cilium) | BGP peers only |

### 4.6 Path type: site-to-site VPN

```
[on-prem host] → on-prem firewall → VPN tunnel → cloud VPN gateway → VPC route → [cloud workload]
```

**IPsec audit:**
```bash
# Active SAs and selectors
sudo ip xfrm state
sudo ip xfrm policy

# strongSwan
sudo swanctl --list-sas
sudo swanctl --list-conns

# Libreswan
sudo ipsec status
sudo ipsec auto --status
```

**WireGuard audit:**
```bash
sudo wg show
sudo wg show all dump
```

**OpenVPN audit:**
```bash
cat /etc/openvpn/server.conf   # check cipher, auth, tls-version-min
```

**Red flags:**
- IKEv1 in use (deprecated, use IKEv2)
- Weak PSK (short, dictionary, shared across tunnels)
- Traffic selectors `0.0.0.0/0 <-> 0.0.0.0/0` (should be specific CIDRs)
- PFS (Perfect Forward Secrecy) disabled
- DH group 1, 2, or 5 (use group 14+ or ECP)
- Aggressive mode enabled
- Split-tunnel when full-tunnel was intended (or vice versa, depending on policy)

### 4.7 Path type: client-to-site VPN (remote access)

```
[remote user device] → internet → VPN concentrator / ZTNA gateway → corporate network / specific apps
```

Client-to-site VPN is the traditional remote access model. Modern deployments increasingly replace it with ZTNA (Zero Trust Network Access), which publishes applications individually rather than granting network-level access. Audit both when they coexist.

**Deployment types to recognize:**

| Category | Examples |
|----------|----------|
| Classic IPsec IKEv2 RA | strongSwan, Libreswan, Windows built-in, Cisco ASA/Firepower IKEv2 |
| SSL VPN concentrators | Cisco AnyConnect (Secure Client), Palo Alto GlobalProtect, Fortinet FortiClient / FortiGate SSL VPN, SonicWall NetExtender, Pulse / Ivanti Connect Secure, Citrix Gateway |
| OpenVPN-based | OpenVPN Community, OpenVPN Access Server, OpenVPN Cloud / CloudConnexa |
| WireGuard-based | Raw WireGuard, Tailscale, Netbird, Firezone, WG-Easy, WG Portal |
| Overlay mesh | ZeroTier, OpenZiti, Nebula (Slack), Innernet |
| ZTNA platforms | Cloudflare Access + WARP, Zscaler ZPA, Netskope Private Access, Palo Alto Prisma Access, Twingate, Banyan / SonicWall CSE, Perimeter 81, Check Point Harmony Connect |

Identify which category the target uses; the audit commands and red flags differ significantly.

**Authentication audit:**

```
[ ] What factors are required? (password, cert, TOTP, push, FIDO2, SAML assertion)
[ ] Is MFA mandatory for ALL users, or can some bypass it? ("legacy devices", service accounts)
[ ] Is SSO wired to the organisation's IdP (Okta, Entra ID, Google Workspace, Ping)?
[ ] Client certificates: who signs them? Rotation policy? CRL/OCSP checked at connect?
[ ] For FIDO2/WebAuthn: is phishing-resistant auth the default or an option?
[ ] Local fallback users (break-glass) — who has them, how are they monitored?
[ ] Is there a RADIUS or TACACS+ middleman? If so, review its config too.
```

**Authorization audit:**

```
[ ] Is access flat ("once in, everyone can reach everything")? This is the most common problem.
[ ] Are groups from the IdP (Azure AD groups, Okta groups) mapped to VPN policies?
[ ] Per-user or per-group ACLs restricting reachable subnets/apps?
[ ] Application-level publishing (ZTNA) vs full network access (classic VPN)?
[ ] Time-based conditions (business hours, maintenance windows)?
[ ] Contextual conditions (device posture, geolocation, risk score)?
```

**Device posture / HIP check:**

```
[ ] Is device posture evaluated before granting access?
[ ] What checks run: OS version, patch level, disk encryption (BitLocker/FileVault/LUKS),
    EDR/AV presence (CrowdStrike, SentinelOne, Defender), screen lock policy, MDM enrolment?
[ ] What happens on non-compliance: block, quarantine (limited access), warn-and-allow?
[ ] Is BYOD handled differently from managed devices?
[ ] Are posture checks re-evaluated periodically, or only at connect time?
```

**Split-tunnel vs full-tunnel policy:**

| Mode | Pro | Con | Audit focus |
|------|-----|-----|-------------|
| Full-tunnel | Unified logging, DNS/web filtering applies, easier egress control | Latency, bandwidth cost at concentrator | Is actual user traffic traversing? DNS resolving via corporate? |
| Split-tunnel | Performance, concentrator bandwidth preserved | Local malware has unfiltered egress; no corporate DNS/web filter on personal traffic | Are internal CIDRs the ONLY routes pushed? Is metadata service (169.254.169.254) excluded? |
| Inverse split | Only specified risky traffic through VPN (e.g., to sanctioned SaaS) | Uncommon, complex | Clarity of policy |

**OpenVPN server audit:**

```bash
# Key settings to grep for
cat /etc/openvpn/server/server.conf | grep -iE   'cipher|auth |tls-version-min|tls-cipher|tls-crypt|tls-auth|duplicate-cn|client-cert-not-required|compress|comp-lzo|push|verify-client-cert|remote-cert-tls|ncp-ciphers|data-ciphers'

# Critical red flags
# - duplicate-cn                    → multiple users sharing a cert (no per-user accountability)
# - client-cert-not-required        → password-only auth
# - comp-lzo / compress              → VORACLE CVE-2018-0739 compression oracle
# - cipher BF-CBC or DES-*          → deprecated
# - tls-version-min < 1.2           → deprecated
# - auth SHA1                        → weak HMAC
# - no tls-crypt / tls-auth          → missing HMAC firewall on control channel

# Running state
sudo openvpn --status /run/openvpn-server/status-server.log
sudo journalctl -u openvpn-server@server --since "1 day ago" | grep -iE 'auth|tls|handshake|error'
```

**WireGuard client-to-site audit:**

```bash
sudo cat /etc/wireguard/wg0.conf
sudo wg show
sudo wg show all dump   # PublicKey  PSK  Endpoint  AllowedIPs  latest-handshake  rx  tx  keepalive

# Per [Peer] block, check:
#   AllowedIPs = X  → this is BOTH the egress filter (source auth) AND the ingress filter.
#   Overly broad AllowedIPs (e.g., 10.0.0.0/8 when only 10.42.1.0/24 is needed) = lateral movement risk.
#   PresharedKey present (defence-in-depth against quantum + second factor)
#   Endpoint not pinned = client can roam, which is fine, but audit the connection log separately.

# WireGuard itself has NO built-in authentication beyond the public key. Identity must be
# enforced by:
#   (a) a control plane (Tailscale coordination, Netbird management, Firezone portal)
#   (b) a wrapper that issues short-lived peer configs (e.g., Firezone + SAML)
# Bare WireGuard without a control plane = static keys = no deprovisioning story = finding.
```

**strongSwan IKEv2 RA VPN audit:**

```bash
sudo swanctl --list-conns
sudo swanctl --list-sas
sudo swanctl --list-pols

# Key settings in /etc/swanctl/conf.d/*.conf:
#   proposals        → ike + esp cipher suites (reject aes128-sha1-modp1024)
#   rekey_time       → session lifetime
#   local { auths }  → server auth method (certificate / psk / eap-mschapv2 / eap-tls / eap-radius)
#   remote { auths } → client auth method (prefer eap-tls or eap-radius over eap-mschapv2)
#   pools            → assigned IP ranges for clients
#   rightdns         → pushed DNS
#   rightsourceip    → client tunnel IP

# EAP-MSCHAPv2 alone is password-only — flag if not combined with cert or MFA-via-RADIUS.
```

**Cisco AnyConnect / GlobalProtect / FortiClient audit:**

Access the management console / firewall manager (ASDM, Panorama, FortiManager) and export:

```
[ ] RA VPN profile / tunnel group / portal config
[ ] Connection profiles: AAA method, group policy binding
[ ] Group policies: split-tunnel ACL, DNS servers, session timeouts, banner
[ ] Host scan / HIP objects / HIP profiles: what posture is checked, what action on failure
[ ] Certificate maps / authorization overrides
[ ] SAML IdP metadata (entity ID, ACS URL, signing cert rotation)
[ ] WebVPN / clientless portal: any bookmarks to internal apps = audit those too
```

Known mass-exploited CVEs to check patch level against:
- Pulse/Ivanti Connect Secure — CVE-2019-11510, CVE-2023-46805, CVE-2024-21887
- Citrix ADC/Gateway — CVE-2019-19781, CVE-2023-3519, CitrixBleed CVE-2023-4966
- Fortinet SSL VPN — CVE-2022-42475, CVE-2022-40684, CVE-2024-21762
- Cisco ASA / Firepower — CVE-2020-3452, CVE-2024-20481 (ArcaneDoor)
- SonicWall — CVE-2021-20016, CVE-2024-40766
- Palo Alto GlobalProtect — CVE-2024-3400

An unpatched RA VPN concentrator is one of the highest-probability initial access vectors. Always check firmware/patch version against vendor advisories.

**Tailscale audit:**

```bash
tailscale status
tailscale netcheck
tailscale whois <peer-ip>
sudo tailscale debug daemon-goroutines
```

Admin console (https://login.tailscale.com/admin):
```
[ ] ACL policy (HuJSON) — least privilege, no * → *, tags scoped
[ ] Tagged devices mapped to human accountability
[ ] Device posture integrations (CrowdStrike, Intune, Jamf, Kolide)
[ ] 2FA enforced on admin console
[ ] SSH via Tailscale SSH (CA-based) vs host-managed keys
[ ] Exit nodes: who can use them, what traffic is exposed
[ ] Auth keys: are any reusable / non-expiring ones present? (risk)
[ ] Share list: tailnet-to-tailnet sharing, scope
[ ] Logs streaming to SIEM
```

**Netbird / Firezone / ZeroTier audit:**

```bash
# Netbird client
sudo netbird status
sudo netbird debug bundle

# Firezone (self-hosted)
# Check admin portal: actors, resources, policies, identity providers

# ZeroTier
sudo zerotier-cli info
sudo zerotier-cli listnetworks -j

# ZeroTier Central (https://my.zerotier.com): network rules (flow table), capabilities, tags,
# members, private vs public network, auto-assign pool
```

**ZTNA platform audit (Cloudflare Access, Zscaler ZPA, Twingate, etc.):**

ZTNA replaces "connect to network, then reach apps" with "authenticate, then reach only this app." Audit focuses shift from tunnel crypto to application publishing and identity policy.

```
[ ] Application inventory: which apps are published behind ZTNA? Are there apps not yet published?
[ ] Per-app policy: who can access, from what device posture, requiring which MFA factor
[ ] Identity provider integration: IdP, group claim mapping, JIT provisioning, SCIM deprovisioning
[ ] Device posture integration (Cloudflare WARP client, Zscaler Client Connector, Netskope Client)
[ ] Short-lived session tokens? Reauth interval?
[ ] Connector (app-side) health and HA: tunnels into the gateway from each deployed app
[ ] Split DNS for internal FQDNs
[ ] Legacy VPN bypass: is there still a traditional VPN for apps not yet migrated? Audit it too.
[ ] "Trusted network" bypass: if you're on the corporate LAN, do ZTNA policies still apply, or is there a perimeter exception that undermines the model?
[ ] Logs ingested to SIEM; alerting on impossible travel, new device, anomalous app usage
[ ] Admin console access itself protected with MFA + IP allowlist
```

**DNS leak testing (client-side, while connected):**

A correctly configured client-to-site VPN should not leak DNS queries to the ISP resolver.

```bash
# From the client, with the VPN connected:
dig +short whoami.akamai.net @8.8.8.8
# Expected: returns the VPN gateway's public IP or the corporate egress, NOT the ISP's IP
# If it returns your ISP's IP, DNS is leaking.

# Browser-based leak test: https://dnsleaktest.com (extended test)

# On Linux, verify resolver actually points to pushed DNS:
resolvectl status
cat /etc/resolv.conf
```

**Kill switch / failure-mode audit:**

```
[ ] What happens if the tunnel drops mid-session?
    - Ideal: kill switch — all non-VPN traffic blocked until reconnect (OpenVPN `route` with no
      `redirect-gateway def1` fallback; WireGuard with `PostDown` rules; GlobalProtect "Always On")
    - Risky: silent fall-through to local network
[ ] What happens if concentrator is unreachable? HA across regions? Client retry policy?
[ ] Is there a "captive portal" exception that opens a backdoor during Wi-Fi login?
```

**Offboarding lifecycle:**

```
[ ] When an employee is terminated, how quickly does VPN access revoke?
    - Target: < 15 minutes (IdP-triggered session termination)
    - Acceptable: end of session + IdP block on reconnect
    - Unacceptable: next certificate renewal cycle (could be months)
[ ] Are long-lived tokens / reusable auth keys / static WireGuard peer configs revoked?
[ ] Is the SIEM alerting on access attempts from terminated user identities?
```

**Logging and monitoring:**

```
[ ] Connection events logged: login, logout, disconnect reason, bytes transferred
[ ] Authentication failures logged with source IP and username
[ ] Device posture failures logged
[ ] Policy violations (ACL hits, blocked apps) logged
[ ] Anomalous behaviour: impossible travel, new device, unusual hours, geo-rare locations
[ ] Logs integrated into SIEM; retention matches compliance regime
[ ] Logs protected from tampering by authenticated users
```

**Red flags for client-to-site VPN:**
- No MFA on VPN login, or MFA bypass for "legacy devices"
- Shared credentials / team accounts
- Password-only auth (no client cert, no SAML, no MFA)
- Local user database instead of IdP (slow deprovisioning)
- Full-tunnel without DNS/web filtering, or split-tunnel without client egress control
- WireGuard `AllowedIPs = 0.0.0.0/0` on peers that need only specific subnets
- Bare WireGuard (no control plane) with static peer keys — no deprovisioning story
- OpenVPN `duplicate-cn` or `client-cert-not-required`
- Certificate lifetimes > 1 year without automated rotation
- No device posture check; BYOD connects at any patch level
- Unpatched concentrator firmware (see CVE list above)
- VPN admin console reachable from the public internet without allowlist
- No idle session timeout
- DNS leak on client-side (leaks to ISP resolver)
- No kill switch (traffic falls through to local network on tunnel drop)
- Offboarding takes > 24 hours to revoke VPN access
- SIEM not ingesting VPN logs
- Legacy VPN coexisting with ZTNA but not separately audited

**Zero Trust migration context:**

Traditional RA VPN grants "inside the network" trust after authentication; this violates Zero Trust principles. Recommended migration path:

1. **Short-term (harden existing VPN)** — MFA mandatory, IdP integration, device posture check, strict group-based ACLs, patch concentrator, ingest logs to SIEM.
2. **Medium-term (deploy ZTNA alongside)** — stand up a ZTNA platform, publish apps one tier at a time (start with web apps, then TCP-based internal tools), migrate user populations department by department.
3. **Long-term (retire classic VPN)** — remove network-level access; all access is per-application and identity-aware. Exception process for legacy protocols that ZTNA can't yet publish.

Map current state against `references/frameworks/zero-trust.md` CISA ZTMM maturity stages.

### 4.8 Path type: user-to-application

```
[user browser] → DNS → CDN/WAF → LB → ingress controller → service → pod
```

**Checks at each hop:**

```bash
# DNS resolution path
dig +trace <fqdn>
dig <fqdn> @8.8.8.8
dig <fqdn> @1.1.1.1
# Compare answers — any discrepancy suggests split-horizon or poisoning

# Full path trace
mtr -rwzbc 10 <fqdn>
traceroute -T -p 443 <fqdn>

# TLS termination points and certificates
curl -vI https://<fqdn>/
sslyze --regular <fqdn>
testssl.sh <fqdn>
```

**What to find:**
- Where does TLS terminate? (CDN, LB, ingress, app?) — each is a decryption point
- Mutual TLS on back-end hops, or plaintext past the LB?
- HSTS enforced? Certificate chain valid? OCSP stapling?
- CDN-origin split allowing origin bypass?

### 4.9 Per-path output template

For each significant traffic journey, document:

```
Path: <source> → <destination>
Purpose: <business function>
Steps:
  1. Source: <identity/IP>
  2. DNS: <resolver, answer, TTL>
  3. Routing: <route chosen>
  4. Egress filter: <rule applied>
  5. Transit: <medium, encryption>
  6. Ingress filter: <rule applied>
  7. Destination: <service/pod>
  8. Encryption: <TLS/IPsec/plaintext>
  9. Logging: <where recorded>
Findings:
  - <any issue at any step>
```

---

## 5. Network Policy Auditing

NetworkPolicy is Kubernetes' built-in pod-level firewall. Its effectiveness depends on the CNI supporting it (Calico, Cilium, Antrea, Weave do; some older CNIs don't).

### 5.1 Default-deny baseline

The single most important NetworkPolicy audit question: **is there a default-deny policy in each namespace?**

```bash
# Find namespaces WITHOUT a default-deny policy
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  count=$(kubectl get networkpolicy -n $ns -o json 2>/dev/null | jq '[.items[] | select(.spec.podSelector=={} and (.spec.policyTypes | contains(["Ingress","Egress"])))] | length')
  if [ "$count" = "0" ]; then
    echo "MISSING default-deny: $ns"
  fi
done
```

**Reference default-deny:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: <ns>
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
```

**DNS egress must be explicitly allowed** when default-deny is in place, or pods can't resolve anything:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: <ns>
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### 5.2 Selector correctness

Selector bugs silently disable policies. Audit each policy:

- `podSelector: {}` matches all pods in the namespace
- `namespaceSelector: {}` matches all namespaces
- `kubernetes.io/metadata.name` (auto-set on namespaces since 1.21) is the correct label for selecting a namespace by name
- Custom labels must actually exist on the target pods/namespaces

**Policy-to-pod effectiveness check:**
```bash
# For each NetworkPolicy, show what pods it applies to
kubectl get netpol -A -o json | jq -r '
  .items[]
  | "\(.metadata.namespace)/\(.metadata.name) selector: \(.spec.podSelector)"
'
```

### 5.3 Port and protocol specificity

Policies that allow all ports (no `ports:` field) are usually too broad. Each `to` rule should specify the exact ports/protocols the application needs.

### 5.4 Egress blast radius

Egress rules often allow broad CIDR ranges. Audit each egress policy:

- Does it allow `0.0.0.0/0`? If yes, justify.
- Does it exclude `169.254.169.254/32` (cloud metadata)?
- Does it exclude RFC1918 ranges the pod shouldn't touch?

**Reference restricted egress:**

```yaml
spec:
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32   # cloud metadata
              - 10.0.0.0/8            # private
              - 172.16.0.0/12         # private
              - 192.168.0.0/16        # private
              - 127.0.0.0/8           # loopback
```

### 5.5 Empirical testing

Don't trust the YAML — test with live traffic:

```bash
# From a pod in namespace A, probe a pod/service in namespace B
kubectl run -n <ns-a> netshoot-$RANDOM --rm -it --image=nicolaka/netshoot --restart=Never -- \
  bash -c 'curl -v --max-time 5 http://<svc>.<ns-b>.svc.cluster.local:<port>/'

# With Cilium, use hubble to observe drops
hubble observe --verdict DROPPED --since 1m

# With Calico, check policy logs
calicoctl get globalnetworkpolicy -o yaml
```

### 5.6 CNI extensions

Standard NetworkPolicy is L3/L4 and namespace-scoped. CNIs extend beyond this:

| CNI | Extension | Scope | Features |
|-----|-----------|-------|----------|
| Cilium | `CiliumNetworkPolicy` (CNP) | namespace | L7 HTTP/DNS/Kafka rules, FQDN egress |
| Cilium | `CiliumClusterwideNetworkPolicy` (CCNP) | cluster | Same, cluster-wide |
| Calico | `NetworkPolicy` (projectcalico.org/v3) | namespace | Tiers, deny rules, richer selectors |
| Calico | `GlobalNetworkPolicy` | cluster | Node-level, pre/post-rule tiers |
| Antrea | `ClusterNetworkPolicy` | cluster | Tiers, priority, logging |
| Antrea | `NetworkPolicy` | namespace | K8s-style with extensions |

Audit commands:
```bash
kubectl get ciliumnetworkpolicies,ciliumclusterwidenetworkpolicies -A 2>/dev/null
kubectl get networkpolicies.projectcalico.org,globalnetworkpolicies.projectcalico.org -A 2>/dev/null
kubectl get clusternetworkpolicies.crd.antrea.io -A 2>/dev/null
```

### 5.7 Service mesh L7 policies

When a service mesh is present, L7 authorization often matters more than NetworkPolicy:

**Istio:**
```bash
kubectl get authorizationpolicy -A -o yaml
kubectl get peerauthentication -A -o yaml     # mTLS mode: STRICT/PERMISSIVE/DISABLE
kubectl get destinationrule -A -o yaml         # trafficPolicy.tls.mode
```

**Linkerd:**
```bash
kubectl get server,serverauthorization -A -o yaml
```

**Consul:**
```bash
consul intention list
```

Red flags: `PeerAuthentication mode: PERMISSIVE` cluster-wide (should be STRICT), AuthorizationPolicies with `action: ALLOW` and `rules: []` (allows everything), missing AuthorizationPolicy selecting a sensitive service.

### 5.8 Findings table format

```
| Finding | Namespace | Policy | Severity | Evidence | Fix |
|---------|-----------|--------|----------|----------|-----|
| No default-deny | prod-api | — | High | No NetworkPolicy with podSelector: {} | Apply default-deny-all manifest |
| Egress allows metadata | webapp | allow-all-egress | Critical | ipBlock 0.0.0.0/0 no except | Add 169.254.169.254/32 to except |
| PERMISSIVE mTLS | default | default peerauth | Medium | mode: PERMISSIVE | Set mode: STRICT |
```

---

## 6. Host Firewall Auditing

Multiple firewall implementations often coexist on the same host. Audit all of them — a rule in the "wrong" table can be silently ineffective.

### 6.1 iptables

Legacy but still widespread. Kubernetes kube-proxy, Docker, and many distros use it (or iptables-nft compatibility).

**Inspect all tables:**

```bash
# List every rule in every table with counters and line numbers
for table in filter nat mangle raw security; do
  echo "========== TABLE: $table =========="
  sudo iptables -t $table -L -n -v --line-numbers
done

# IPv6
for table in filter nat mangle raw security; do
  echo "========== TABLE: $table (v6) =========="
  sudo ip6tables -t $table -L -n -v --line-numbers
done

# Save full dump for diff/archival
sudo iptables-save > /tmp/iptables.dump
sudo ip6tables-save > /tmp/ip6tables.dump
```

**What to audit:**
- Default policy on INPUT, FORWARD, OUTPUT (DROP is secure, ACCEPT is not)
- Chain ordering — first match wins; an early `ACCEPT` overrides later `DROP`
- Custom chains (DOCKER, DOCKER-USER, KUBE-*, CILIUM-*, cali-*) — where are they inserted?
- NAT rules in `nat` table (DNAT, SNAT, MASQUERADE) — unexpected entries
- LOG targets — are denies logged for incident response?
- `-m state --state RELATED,ESTABLISHED ACCEPT` early in the chain? Good.
- Rules matching `0.0.0.0/0` in unexpected contexts
- Rules that reference interfaces or subnets that no longer exist (stale rules)

**Kubernetes-specific chains to expect:**
```
KUBE-SERVICES     — service dispatch
KUBE-NODEPORTS    — NodePort handling
KUBE-POSTROUTING  — SNAT for masquerading
KUBE-FORWARD      — pod forwarding
KUBE-EXTERNAL-SERVICES
KUBE-FIREWALL     — kube-proxy drop rules
```

### 6.2 nftables

The modern replacement for iptables. Single unified framework across families (inet, ip, ip6, arp, bridge, netdev).

```bash
# Full ruleset
sudo nft list ruleset

# Per-table inspection
sudo nft list tables
sudo nft list table inet filter
sudo nft list table ip nat
sudo nft list table ip6 filter

# Save
sudo nft list ruleset > /tmp/nftables.dump
```

**nftables-specific audit points:**
- `inet` family rules apply to both IPv4 and IPv6 — good for dual-stack
- Sets and maps (`type ipv4_addr`, `type inet_service`) — audit set contents for stale entries
- Chain priorities (lower = earlier)
- `jump` vs `goto` — semantic difference in return behavior
- Verdict chains (`type filter hook input priority 0; policy drop`)
- Use of `counter` and `log` statements for visibility

### 6.3 firewalld

Common on RHEL/Fedora/CentOS/Rocky. Zone-based abstraction over nftables/iptables.

```bash
sudo firewall-cmd --state
sudo firewall-cmd --get-default-zone
sudo firewall-cmd --get-active-zones

# Per-zone permanent config
for zone in $(sudo firewall-cmd --get-zones); do
  echo "===== zone: $zone ====="
  sudo firewall-cmd --zone=$zone --list-all
done

# Rich rules (often where policy exceptions hide)
sudo firewall-cmd --list-rich-rules
```

**Audit points:**
- Default zone (public vs trusted vs internal)
- Interface-to-zone assignments match the actual interface purpose
- Port/service allowlists per zone
- Rich rules with `accept` actions on unexpected source/destination combos
- Direct rules bypassing zone logic (`firewall-cmd --direct --get-all-rules`)

### 6.4 UFW (Uncomplicated Firewall)

Debian/Ubuntu convenience wrapper over iptables/nftables.

```bash
sudo ufw status verbose
sudo ufw status numbered
sudo cat /etc/ufw/user.rules
sudo cat /etc/ufw/before.rules
sudo cat /etc/ufw/after.rules
```

**Audit points:**
- Default incoming/outgoing policies
- Rule ordering (numbered) — first match wins
- `before.rules` / `after.rules` customizations (often where misconfig hides)
- ALLOW IN from 0.0.0.0/0 entries

### 6.5 pf (BSD, macOS)

```bash
sudo pfctl -sr     # rules
sudo pfctl -sn     # NAT
sudo pfctl -ss     # states (active connections)
sudo pfctl -sa     # all
```

### 6.6 Windows Firewall

```powershell
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Get-NetFirewallRule -Enabled True | Select-Object DisplayName, Direction, Action, Profile | Sort-Object Direction, Action
Get-NetFirewallRule -Action Allow -Direction Inbound -Enabled True | Get-NetFirewallPortFilter
```

### 6.7 Cloud firewall adjunct

Host firewalls are layered with cloud network firewalls:

**AWS:**
```bash
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName,Description]' --output table
aws ec2 describe-network-acls --query 'NetworkAcls[*].[NetworkAclId,VpcId,Entries]'
aws ec2 describe-vpcs
aws ec2 describe-route-tables
```

**GCP:**
```bash
gcloud compute firewall-rules list --format='table(name,network,direction,sourceRanges.list():label=SRC_RANGES,allowed[].map().firewall_rule().list():label=ALLOW,denied[].map().firewall_rule().list():label=DENY,targetTags.list():label=TARGET_TAGS)'
gcloud compute networks list
gcloud compute routes list
```

**Azure:**
```bash
az network nsg list --query '[].{name:name, rg:resourceGroup, location:location}' -o table
az network nsg rule list --nsg-name <nsg> --resource-group <rg> -o table
az network vnet list -o table
```

**Red flags across cloud firewalls:**
- `0.0.0.0/0` on management ports (22 SSH, 3389 RDP, 5985/5986 WinRM)
- `0.0.0.0/0` on database ports (3306, 5432, 1433, 6379, 27017, 9200)
- Allow-all rules (`any any any`) that override more specific denies
- Default-allow NACLs without explicit deny rules
- Security groups attached but with no rules (effective allow-none — but may be a misconfig if allow was intended)
- Rules referencing deleted security groups (stale)
- Rules allowing entire VPC CIDR on high-risk ports when subnet-level would suffice

### 6.8 IPv6 dual-stack gotcha

A firewall policy that looks airtight in IPv4 may have no equivalent in IPv6. Every host firewall (iptables ↔ ip6tables, nftables inet vs ip/ip6, UFW v6, Windows, pf) needs the IPv6 table audited separately unless using a unified family like nftables `inet`.

If IPv6 is enabled on an interface but no v6 rules exist, the host is effectively open on v6. Fix is either disable IPv6 or mirror the v4 policy.

### 6.9 Host firewall findings table

```
| Host | Firewall | Rule | Issue | Severity | Recommendation |
|------|----------|------|-------|----------|----------------|
| db-01 | iptables | -A INPUT -p tcp --dport 5432 -j ACCEPT | No source restriction | High | Restrict to app-subnet CIDR |
| bastion | firewalld | public zone, service=ssh | 0.0.0.0/0 on SSH | Medium | Restrict to admin VPN CIDR |
| node-03 | ip6tables | (empty) | IPv6 policy absent while v6 enabled | High | Disable IPv6 or apply mirror policy |
```

---

## 7. WAF, Load Balancer, and API Gateway Auditing

The edge — where traffic enters the application — is usually the most exposed surface and the most frequently attacked. Audit every component that sits between the internet and the application: CDN, WAF, load balancer, reverse proxy, API gateway, ingress controller. A misconfigured edge device or an unpatched WAF appliance is one of the top-3 initial access vectors industry-wide.

### 7.1 Edge architecture inventory

First map what is actually in the request path. Ask the team, but also verify empirically — the documented architecture and the running architecture are often different.

```bash
# HTTP response header fingerprinting
curl -sI https://app.example.com/ | grep -iE 'server|via|x-cache|x-served-by|x-cdn|cf-ray|x-amz-cf-id|x-azure|x-goog|x-varnish|x-envoy|x-kong|x-trace'

# Common fingerprints:
#   cloudflare / CF-Ray            → Cloudflare
#   AkamaiGHost                    → Akamai
#   Fastly / x-served-by: cache-*  → Fastly
#   x-amz-cf-id / x-amz-cf-pop     → AWS CloudFront
#   Google Frontend / GFE          → GCP Load Balancer
#   Microsoft-IIS / ARR            → Azure / IIS
#   envoy                          → Envoy (Istio, Ambassador, Gateway API, etc.)
#   nginx                          → NGINX or ingress-nginx
#   haproxy                        → HAProxy
#   BigIP / F5-TrafficShield       → F5 BIG-IP
#   kong                           → Kong API Gateway

# DNS + CNAME chain reveals CDN/LB topology
dig app.example.com +trace
dig +short CNAME app.example.com

# TLS certificate + SNI often discloses infrastructure
openssl s_client -connect app.example.com:443 -servername app.example.com < /dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# TRACE / TRACK (if enabled) expose intermediate hops
curl -X TRACE https://app.example.com/
```

**Common edge architectures to expect:**

| Architecture | Layers (outermost → innermost) |
|--------------|-------------------------------|
| Simple cloud | Client → Cloud LB → Origin |
| CDN-fronted | Client → CDN → Cloud LB → Origin |
| CDN + WAF | Client → CDN + WAF → Cloud LB → Origin |
| K8s + CDN | Client → CDN + WAF → Cloud LB → Ingress Controller → Service → Pod |
| Service mesh | Client → CDN + WAF → Cloud LB → Istio/Envoy Gateway → sidecar → Pod |
| API-only | Client → API Gateway (Kong/Apigee/AWS APIGW) → Backend |
| Hybrid (common) | Client → CDN + WAF → Cloud LB → API Gateway → K8s Service → Pod |

Diagram the actual topology. Each layer is a trust boundary and a decryption/inspection point.

### 7.2 WAF auditing

**WAF product recognition:**

| Category | Products |
|----------|----------|
| Cloud-native WAF | AWS WAF (WebACLv2 + managed rule groups), Azure WAF (Front Door + App Gateway), Google Cloud Armor, Oracle WAF |
| CDN-integrated WAF | Cloudflare WAF + Firewall Rules, Akamai Kona / App & API Protector, Fastly Next-Gen WAF (Signal Sciences), Imperva (Incapsula), Sucuri |
| Appliance / software WAF | F5 Advanced WAF / ASM / Distributed Cloud WAAP, Fortinet FortiWeb, Barracuda WAF, Radware AppWall, Citrix Web App Firewall |
| OSS / self-hosted | ModSecurity v2/v3 + OWASP CRS 4.x, Coraza (Go port of ModSec), NAXSI, OpenAppSec, BunkerWeb |
| API-specific WAF / WAAP | Salt Security, Noname, Wallarm, 42Crunch, Traceable AI, Corsha |
| In-cluster / runtime | ingress-nginx + ModSecurity, Envoy WASM filters, Kuma, OPA at L7 |

**What to audit:**

```
[ ] Is the WAF actually in the path for ALL ingress? (No direct-to-origin bypass — tested in 7.2.1)
[ ] Mode: detection-only (logging) vs prevention (blocking)? Most misconfigs sit in detect mode for months.
[ ] Managed rule group coverage: OWASP Top 10, known bad bots, virtual patches for unpatched CVEs
[ ] Custom rules: regex quality, ReDoS risk, maintenance cadence
[ ] Rule evaluation order: does a broad ALLOW precede narrower BLOCK rules?
[ ] Body inspection size limit (typically 8-64 KB) — bodies above the limit often pass unchecked
[ ] Parameter parsing coverage: JSON, XML, multipart, GraphQL, nested bodies, form-urlencoded
[ ] Encoding normalization: URL encoding, double encoding, Unicode, case variation
[ ] HTTP method coverage: GET/POST usually; PUT/DELETE/PATCH/OPTIONS often ignored
[ ] HTTP/2 and HTTP/3 request handling (some WAFs only inspect HTTP/1.1 properly)
[ ] WebSocket upgrade path — frequently exempt from WAF inspection
[ ] gRPC / protobuf content inspection (almost never done)
[ ] Rate limiting: per-IP, per-session, per-API-key, per-endpoint
[ ] Bot management: JS challenges, CAPTCHA, fingerprinting, managed bot rule groups
[ ] Geo-blocking if required by compliance (sanctions lists, data residency)
[ ] IP allowlist / denylist with current context
[ ] TLS termination: pass-through (WAF cannot inspect) vs re-terminate
[ ] Upstream X-Forwarded-For: correctly appended; origin trusts only WAF/LB source IP
[ ] Logging: full request capture or just matched rules?
[ ] SIEM integration and alerting on rule matches + anomalies
[ ] Virtual patches applied for known upstream CVEs (Log4Shell, Spring4Shell, Struts, etc.)
[ ] False-positive tuning process — who tunes, how often, what's the approval chain
[ ] Continuous bypass testing on each deploy (CI integration with gotestwaf, nowafpls)
```

#### 7.2.1 Direct-to-origin bypass test (critical)

If the origin is reachable directly — bypassing the CDN/WAF — the WAF is effectively optional. This is one of the highest-impact WAF findings and should always be tested.

```bash
# Methods to discover the origin IP:
#   1. Historical DNS records (SecurityTrails, Shodan "ssl.cert.subject.cn", Censys)
#   2. TLS certificate transparency logs (crt.sh for the apex + subdomains)
#   3. Mail servers — MX records often point directly at origin
#   4. GitHub / GitLab commits leaking IPs in config files or docker-compose.yml
#   5. Application SSRF (ask a deployed function to fetch a canary)
#   6. Misconfigured dev/staging/preview subdomains that bypass the CDN
#   7. Favicon hash matching on Shodan / Censys

# Once a candidate origin IP is identified, test bypass:
curl -sk --resolve app.example.com:443:<origin-ip> https://app.example.com/ -o /dev/null -w '%{http_code}\n'
# If it returns the real application (200, 302 to login, etc.), the WAF is bypassed.

# Mitigation that MUST be present at origin:
#   (a) Refuse connections not from CDN IP ranges — Cloudflare IP list, CloudFront prefix
#       list, Fastly IP list, Akamai IP list. Enforce at cloud SG, not just at nginx allow/deny.
#   (b) OR require mTLS with a cert that only the CDN possesses (Cloudflare Authenticated
#       Origin Pulls, Fastly TLS Mutual Auth).
#   (c) OR require a shared secret header the CDN adds and origin validates.
# "Security through origin IP obscurity" alone is not a defence.
```

#### 7.2.2 ModSecurity / OWASP CRS audit

```bash
# Config locations (varies by distro / integration)
cat /etc/modsecurity/modsecurity.conf
cat /etc/modsecurity.d/*.conf
ls /usr/share/modsecurity-crs/rules/

# Key settings
grep -rE 'SecRuleEngine|SecRequestBodyLimit|SecResponseBodyAccess|SecAuditEngine|SecDefaultAction' \
    /etc/modsecurity/

# Rule exclusions — where false-positive reduction often crosses into false-negative risk
grep -rE 'SecRuleRemoveById|SecRuleRemoveByTag|SecRuleUpdateTargetById' /etc/modsecurity/

# Paranoia level (1-4, higher = more strict, higher FP rate)
grep -rE 'tx.paranoia_level' /etc/modsecurity/
# PL1 default light; PL2 sensible for most; PL3/PL4 very strict, expect tuning

# CRS version
head -5 /usr/share/modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf
```

**Red flags:**
- `SecRuleEngine DetectionOnly` (observation only, not blocking)
- `SecRequestBodyLimitAction ProcessPartial` without alerting (large body → silent pass-through)
- Wildcard exclusions like `SecRuleRemoveById 9*` (removes entire rule ranges)
- Missing CRS rule groups: REQUEST-942 (SQLi), REQUEST-941 (XSS), REQUEST-930 (LFI), REQUEST-932 (RCE)
- Paranoia level forced to 0 or 1 without justification

#### 7.2.3 AWS WAF audit

```bash
# Regional WebACLs (ALB, API Gateway, Cognito, App Runner, AppSync)
aws wafv2 list-web-acls --scope REGIONAL

# CloudFront WebACLs (always us-east-1)
aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1

# Dump ACL detail
aws wafv2 get-web-acl --scope REGIONAL --id <id> --name <n>

# Resources protected by each ACL
aws wafv2 list-resources-for-web-acl --web-acl-arn <arn> --scope REGIONAL

# Logging configuration
aws wafv2 get-logging-configuration --resource-arn <acl-arn>
```

**Red flags:**
- No WebACL attached to ALB / CloudFront / API Gateway
- All managed rule groups in `COUNT` mode (observation only, no blocking)
- `DefaultAction: Allow` combined with overly permissive custom rules
- No logging to CloudWatch Logs or Kinesis Firehose → no audit trail
- Missing AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesSQLiRuleSet

#### 7.2.4 Cloudflare WAF audit

Dashboard path: **Security → WAF → Custom rules / Managed rules / Rate limiting rules**.

```
[ ] Managed rulesets enabled: Cloudflare Managed Ruleset, Cloudflare OWASP Core Ruleset
[ ] Managed ruleset version is current (lag > 90 days is a finding)
[ ] Sensitivity: Low / Medium / High — document the choice per app tier
[ ] Custom rules covering business-specific exposures
[ ] Rate limiting per endpoint (not just global)
[ ] Bot Fight Mode or Super Bot Fight Mode enabled appropriately
[ ] "Skip" / "Allow" rules audited — they are the #1 cause of silent bypass
[ ] "Under Attack Mode" — if permanently on, it masks real protection gaps
[ ] Page Rules / Configuration Rules order: bypass rules must not precede security rules
[ ] Authenticated Origin Pulls (mTLS CDN → origin) enabled to prevent direct-to-origin bypass
[ ] API Shield deployed for API endpoints (schema validation, sequence analysis)
```

API-based audit:
```bash
# Requires API token with Zone.Firewall Services Read
curl -s -H "Authorization: Bearer $CF_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/firewall/waf/packages" | jq
```

### 7.3 Load balancer auditing

**Load balancer product recognition:**

| Category | Products |
|----------|----------|
| Cloud L4/L7 | AWS ALB / NLB / GLB / CLB; GCP GCLB, ILB, NLB, HTTP(S) LB; Azure Front Door, Application Gateway, Load Balancer, Traffic Manager |
| Hardware appliance | F5 BIG-IP (LTM / DNS / AFM / ASM), Citrix ADC / NetScaler, A10 Thunder, Radware Alteon |
| Software | HAProxy, NGINX (OSS + Plus), Envoy, Traefik, Caddy, Varnish |
| K8s ingress controllers | ingress-nginx, Traefik, HAProxy Ingress, Contour, Kong Ingress, Ambassador/Emissary, NGINX Ingress (F5), GKE Gateway, AWS LoadBalancer Controller |
| Service mesh gateways | Istio Ingress/Egress Gateway, Linkerd, Consul API Gateway, Envoy Gateway |
| Bare-metal K8s | kube-vip, MetalLB, PureLB |

#### 7.3.1 TLS configuration audit

```bash
# Gold-standard TLS audit tools
testssl.sh https://app.example.com
sslyze --regular app.example.com:443
nmap --script ssl-enum-ciphers -p 443 app.example.com
```

**Required verifications:**

```
[ ] TLS 1.0 and 1.1 disabled (PCI-DSS 4.0 requires this)
[ ] TLS 1.2+ only; TLS 1.3 preferred; 1.3 negotiated when client supports
[ ] Cipher suite list contains no RC4, 3DES, NULL, EXPORT, ANON, MD5, SHA1
[ ] Forward secrecy (ECDHE) for all modern clients
[ ] OCSP stapling enabled; Must-Staple where feasible
[ ] HSTS header present, max-age >= 6 months (31536000) for preload eligibility
[ ] includeSubDomains and preload directives where appropriate
[ ] Certificate validity: not expiring in <30 days, max lifetime <=398 days (CA/B Forum)
[ ] Certificate key: RSA >=2048 or ECDSA P-256/P-384
[ ] SAN list matches only intended hostnames (no accidental wildcards covering test envs)
[ ] Intermediate chain complete (no missing intermediates)
[ ] Session resumption: tickets use automated key rotation; no manual static keys
[ ] Secure renegotiation only (RFC 5746)
[ ] No BEAST/CRIME/BREACH/POODLE/Heartbleed/Ticketbleed/ROBOT indicators
[ ] ALPN offers h2, http/1.1; h3 if QUIC deployed
```

#### 7.3.2 Backend health check audit

```
[ ] Health check path is dedicated (e.g., /healthz, /readyz), not the homepage
[ ] Health check endpoint does not leak version, build info, or internal detail
[ ] Health check auth: matches what the LB is configured to send
[ ] Health check interval and threshold are aggressive enough to detect failures
[ ] Unhealthy backend ejection actually stops routing (confirmed via logs)
[ ] TLS / mTLS on health checks if backends expect it
[ ] Passive health checks in addition to active where supported
```

#### 7.3.3 Sticky session audit

```
[ ] Session affinity enabled only where needed — prefer stateless backends
[ ] Sticky cookie flags: HttpOnly, Secure, SameSite=Strict or Lax (NOT None without justification)
[ ] Cookie name not predictable — defaults (AWSALB, AWSALBCORS, JSESSIONID) leak the LB vendor
[ ] Stickiness lifetime bounded; no indefinite pinning
[ ] Failover behaviour tested when pinned backend fails
```

#### 7.3.4 X-Forwarded-For chain audit (high-impact, often-missed finding)

A misconfigured XFF chain lets an attacker spoof their IP, bypassing rate limits, IP allowlists, and geo-blocks.

```
[ ] Does the outermost LB overwrite (not append) client XFF so upstream cannot see client-supplied XFF?
[ ] Does the origin trust the RIGHTMOST XFF entry from a trusted proxy (never the leftmost)?
[ ] Trusted-proxy configuration at origin is explicit (nginx set_real_ip_from, Apache
    RemoteIPInternalProxy, Rails config.action_dispatch.trusted_proxies)
[ ] X-Real-IP and X-Forwarded-For are consistent
[ ] X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-Port equally sanitized
[ ] Attacker-supplied X-Client-IP, True-Client-IP, X-Original-Forwarded-For stripped or ignored
```

#### 7.3.5 F5 BIG-IP audit

```bash
# Via tmsh on the appliance
tmsh show sys version
tmsh list ltm virtual all-properties
tmsh list ltm pool all-properties
tmsh list ltm profile ssl-client
tmsh list ltm profile ssl-server
tmsh list security firewall policy
tmsh list security dos device-config

# iRules (LB-side code — review for injection bugs)
tmsh list ltm rule
# Audit iRules for: eval of user input, session handling bugs, HTTP header injection,
# regex backtracking vulnerabilities (TCL regex is notorious)

# Hygiene: TMUI admin interface MUST NOT be reachable from the internet.
# Network policy should restrict TMUI (typically 8443, 443 on mgmt IF) to admin VPN CIDR.
```

Critical CVEs to cross-check patch level:
- CVE-2020-5902 — TMUI unauthenticated RCE
- CVE-2022-1388 — iControl REST authentication bypass
- CVE-2023-46747 — TMUI auth bypass → RCE
- CVE-2023-46748 — AJP smuggling via TMUI

#### 7.3.6 Citrix ADC / NetScaler / Gateway audit

```
[ ] NetScaler IP (NSIP) and Management IP (MIP) NOT reachable from internet
[ ] Admin accounts use MFA; default nsroot/nsroot must be changed
[ ] Management firewall restricts to admin subnets
[ ] Firmware version cross-checked against CISA KEV
```

Critical CVEs:
- CVE-2019-19781 ("Shitrix") — directory traversal → RCE
- CVE-2023-3519 — unauthenticated RCE
- CVE-2023-4966 ("CitrixBleed") — session token memory leak

#### 7.3.7 NGINX / HAProxy (software LB) audit

```bash
# NGINX effective config dump
nginx -T 2>&1 | less

# Key settings to grep
grep -iE 'ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers|add_header|proxy_pass|proxy_set_header|real_ip_from|set_real_ip_from|merge_slashes|client_max_body_size|large_client_header_buffers|server_tokens' \
  /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null
```

**Common NGINX bugs:**
- Off-by-one in location matching: `/admin` vs `/admin/` behave differently
- `proxy_pass` without trailing slash when location has one → path traversal
- `merge_slashes off` enables `//../..` normalization attacks
- `Host` header forwarded without validation → SSRF via Host
- Large client body buffered to `/tmp` with world-readable permissions
- Missing security headers (X-Frame-Options, CSP, Referrer-Policy)
- `server_tokens on` leaks exact version
- Regex-based location blocks matched before prefix blocks — order traps

```bash
# HAProxy
haproxy -vv                       # version + features
cat /etc/haproxy/haproxy.cfg

# Audit:
#   global section: chroot, user, no-splice-auto
#   defaults: timeouts reasonable (connect 5s, client/server 30s typical)
#   frontend: ACLs, http-request policies
#   backend: server lines (verify ca-file for HTTPS backends, not "verify none")
#   stats interface NOT exposed to internet (bind only to admin subnet)
```

#### 7.3.8 Ingress controller audit (Kubernetes)

```bash
# Identify deployed controller
kubectl get ingressclass
kubectl get pods -A -l app.kubernetes.io/name=ingress-nginx 2>/dev/null
kubectl get pods -A -l app.kubernetes.io/name=traefik 2>/dev/null

# Per-controller config map
kubectl -n ingress-nginx get configmap ingress-nginx-controller -o yaml

# Critical settings to verify:
#   allow-snippet-annotations=false                (default false since 1.9)
#   annotations-risk-level=Critical                (block risky annotations)
#   ssl-protocols, ssl-ciphers                     (match TLS policy above)
#   enable-modsecurity=true                        (if ModSec integration expected)
#   use-forwarded-headers=true                     (with proper trusted proxy list)
#   proxy-read-timeout, proxy-send-timeout         (DoS risk if too long)
#   hsts-max-age, hsts-include-subdomains, hsts-preload

# Per-ingress audit for snippet injection risk
kubectl get ingress -A -o yaml | grep -A 3 'nginx.ingress.kubernetes.io/configuration-snippet\|nginx.ingress.kubernetes.io/server-snippet\|nginx.ingress.kubernetes.io/modsecurity-snippet\|nginx.ingress.kubernetes.io/auth-url\|nginx.ingress.kubernetes.io/auth-snippet'
# Snippet annotations = RCE vectors if allowed from untrusted namespaces. Must be disabled
# unless there's a strong reason and strict admission control restricts which namespaces
# can use them.
```

Critical ingress-nginx CVEs to cross-check patch level:
- CVE-2021-25742 — configuration snippet RCE
- CVE-2022-4886 — path sanitization bypass
- CVE-2023-5043, CVE-2023-5044 — nginx annotation RCE
- CVE-2025-24513 / CVE-2025-1097 / CVE-2025-1098 / CVE-2025-24514 / CVE-2025-1974 — **IngressNightmare** (March 2025): unauthenticated cluster-wide RCE chain

### 7.4 API gateway auditing

API gateways serve as auth, rate limit, transform, and route layers. Audit them as both load balancers and access-control layers.

**Products:**

| Category | Products |
|----------|----------|
| Cloud-native | AWS API Gateway (REST / HTTP / WebSocket), GCP API Gateway + Apigee, Azure API Management, Oracle API Gateway |
| Self-hosted | Kong (OSS + Enterprise), Tyk, KrakenD, WSO2, Gravitee, Ambassador/Emissary, Traefik |
| K8s-native | Kong Ingress Controller, Ambassador, Gloo Edge, Envoy Gateway, Istio Gateway |
| Service mesh as APIGW | Istio (AuthorizationPolicy + RequestAuthentication), Linkerd (HTTPRoute), Consul ingress |

**Audit checklist:**

```
[ ] Authentication mechanisms in use: API key, JWT, OAuth 2.0 client credentials, mTLS, SAML,
    basic auth (flag if present). Which is enforced on which route?
[ ] Key / token rotation: automated; lifecycle events logged; max lifetime capped
[ ] JWT validation: signing algorithm pinned (never `alg: none`, never symmetric-vs-asymmetric
    confusion), issuer and audience validated, expiration enforced, clock skew tolerance bounded
[ ] OAuth scopes: per-endpoint scope requirement, not global "api:access"
[ ] Rate limiting per API-key AND per-endpoint (not just per-IP — trivially distributed)
[ ] Quota and throttling: hard caps vs soft (429) responses; 429 includes Retry-After
[ ] Request/response transformation: sensitive headers stripped before upstream; no PII in logs
[ ] Path rewriting and normalization: no path confusion attacks (../, //, \, %2e%2e)
[ ] Upstream TLS: mTLS where backends require; cert validation always on (never "verify none")
[ ] Caching: sensitive data NOT cached; Vary and Cache-Control respected
[ ] Analytics / logging: per-call logs to SIEM; PII redaction rules
[ ] Versioning: /v1 vs /v2; deprecation calendar; old versions actually retired
[ ] Developer portal: does NOT leak internal endpoints, staging URLs, or example real tokens
[ ] Admin API exposure: Kong admin API (8001/8444) MUST NOT be reachable from internet
[ ] Plugin/filter chain ORDER is correct: auth before rate-limit-by-consumer;
    IP allowlist before auth; CORS after auth
[ ] Schema validation (OpenAPI enforcement) on request + response
[ ] API Shield / positive-security-model deployed for high-value APIs
```

**Kong-specific:**

```bash
# Admin API (must be internal-only) — inventory
http :8001/services
http :8001/routes
http :8001/plugins
http :8001/consumers

# Declarative config if dbless
cat /etc/kong/kong.yaml

# Critical plugins to audit: key-auth, jwt, oauth2, rate-limiting, cors,
# ip-restriction, bot-detection, request-transformer, response-transformer,
# hmac-auth, basic-auth, acl, ldap-auth, opa
```

**AWS API Gateway-specific:**

```bash
# HTTP API (v2)
aws apigatewayv2 get-apis
aws apigatewayv2 get-routes      --api-id <api-id>
aws apigatewayv2 get-authorizers --api-id <api-id>
aws apigatewayv2 get-stages      --api-id <api-id>

# REST API (v1)
aws apigateway get-rest-apis
aws apigateway get-resources --rest-api-id <id>

# Verify:
#   - Stage throttling limits set
#   - WAF WebACL attached
#   - Resource policy restricts to expected principals or VPC endpoints
#   - CloudWatch logging at INFO or ERROR level (not OFF)
#   - CloudTrail data events enabled for Execute-API
#   - X-Ray tracing on for debuggability
#   - Usage plans + API keys for partner access
```

### 7.5 Reverse proxy auditing

Separate from API gateways, reverse proxies (NGINX, HAProxy, Apache, Envoy) are often deployed ad-hoc as glue layers. Each is a potential source of subtle bugs.

**Common reverse proxy attack classes to test:**

```
[ ] HTTP Request Smuggling (CL.TE, TE.CL, TE.TE) between LB and backend
    - Tools: smuggler.py (James Kettle / PortSwigger), h2cSmuggler
    - Test HTTP/2 → HTTP/1.1 downgrade desync
[ ] Host header confusion: does the proxy forward client-supplied Host, or a synthesized one?
    - Can an attacker reach different virtual hosts by manipulating Host?
[ ] Path traversal through proxy: /static/..%2F..%2Fadmin/
    - NGINX merge_slashes behaviour
    - Apache AllowEncodedSlashes default = Off
    - Envoy path normalization
[ ] CRLF header injection via query string or upstream response
[ ] Proxy trust: preserves X-Forwarded-* from untrusted clients?
[ ] Open redirect via upstream Location header
[ ] SSRF: attacker-controlled upstream URL (proxy_pass with variable)
[ ] WebSocket upgrade smuggling (WS → internal HTTP)
[ ] h2 → h1 desync where CL/TE semantics differ
[ ] Cache poisoning via unkeyed headers (X-Host, X-Forwarded-Host, X-Original-URL, X-Rewrite-URL)
[ ] Second-order cache poisoning via stored response
[ ] Range header DoS against upstream
```

Review NGINX `location` blocks for off-by-one slash issues, `rewrite` without `break`/`last`, `proxy_pass` trailing-slash mismatches, and `$uri` vs `$request_uri` in access logs (one normalizes, the other doesn't — matters for audit trails).

### 7.6 TLS termination topology

Map where TLS terminates and re-initiates. Each termination point is a decryption boundary; document which parties hold keys and who can observe plaintext.

```
[ ] Client → CDN (CDN holds cert and sees plaintext)
[ ] CDN → Cloud LB (may be HTTPS with or without verification, or plaintext over private link)
[ ] Cloud LB → Backend (HTTPS? mTLS? plaintext within VPC?)
[ ] Pass-through TLS (LB forwards encrypted bytes; backend terminates — loses L7 features)
[ ] End-to-end mTLS (zero-trust — every hop verifies peer cert)
```

**PCI-DSS 4.0 req 4.2.1** requires encrypted transmission of cardholder data across public networks; map explicitly for PCI scopes. FIPS 140-2/140-3 requirements apply in federal deployments.

### 7.7 WAF / LB bypass testing

Standardize bypass testing as part of Phase 3:

```bash
# Comprehensive WAF bypass scanner
gotestwaf --url https://app.example.com/ --verbose

# Payload mutation helper
nowafpls --url https://app.example.com/search --param q

# Manual test catalogue:
#   1. HTTP method tunneling      X-HTTP-Method-Override: POST on GET request
#   2. URL encoding               /admin → /%61dmin → /%2561dmin (double-encode)
#   3. Unicode overlong           /admin → /ad%c0%adin
#   4. Case variation             /admin → /ADMIN → /Admin
#   5. Line ending injection      \r\n in headers
#   6. Transfer-Encoding smuggling mixed with Content-Length
#   7. HTTP/2 vs HTTP/1.1 header field name discrepancies
#   8. Body size exceeding WAF inspection limit (often 8-32 KB)
#   9. Null byte injection        /admin\x00.php
#  10. SNI / Host header mismatch causing routing to an unprotected origin
#  11. Cache poisoning            X-Forwarded-Host, X-Original-URL, X-Rewrite-URL
#  12. Parameter pollution        q=safe&q=attack (WAF sees first, app sees last, or vice versa)
#  13. JSON / XML nested deeply   some WAFs stop parsing beyond depth N
#  14. GraphQL introspection + complex query DoS

# Always test with a benign canary payload first (1=1 → 1' OR 1=1--)
```

### 7.8 Mass-exploited edge CVEs (check patch level)

Every audit must enumerate edge device versions and cross-check CISA KEV. These are the top initial-access CVEs from the past few years:

```
F5 BIG-IP:
  CVE-2020-5902    TMUI unauthenticated RCE
  CVE-2022-1388    iControl REST authentication bypass
  CVE-2023-46747   TMUI auth bypass → RCE
  CVE-2023-46748   AJP smuggling via TMUI

Citrix ADC / NetScaler / Gateway:
  CVE-2019-19781   "Shitrix" directory traversal → RCE
  CVE-2023-3519    unauthenticated RCE
  CVE-2023-4966    "CitrixBleed" session token leak

Ingress-NGINX:
  CVE-2021-25742   configuration snippet RCE
  CVE-2022-4886    path sanitization bypass
  CVE-2023-5043    annotation-based RCE
  CVE-2023-5044    path regex validation bypass
  CVE-2025-24513, CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-1974
                   IngressNightmare (unauthenticated cluster-wide RCE chain)

HAProxy:
  CVE-2021-40346   integer overflow request smuggling
  CVE-2023-44487   HTTP/2 Rapid Reset (industry-wide)

NGINX / nginx-plus:
  CVE-2021-23017   DNS resolver off-by-one
  CVE-2022-41741, CVE-2022-41742   mp4 module memory corruption
  CVE-2024-7347    njs cache poisoning

Apache HTTPD:
  CVE-2021-41773, CVE-2021-42013   path traversal → RCE
  CVE-2023-25690                   reverse-proxy HTTP smuggling

Envoy / Istio Gateway:
  CVE-2023-44487   HTTP/2 Rapid Reset
  Various Istio ambient-mode authz bypasses

Kong:
  CVE-2024-32876   unauthenticated admin API access in dbless clusters

Traefik:
  CVE-2024-28869, CVE-2024-45410   header handling + rewrite bugs

Fortinet FortiWeb:
  CVE-2023-34992, CVE-2024-23108   management interface auth bypass

AWS WAF / Cloudflare / managed:
  Not patchable by customer — but managed rule group version LAG is a finding.
  Lag > 90 days should trigger remediation.
```

Cross-reference every version finding against **CISA Known Exploited Vulnerabilities (KEV)** catalog before writing severity.

## 8. Integration with Audit Phases

**Phase 0.5 (Codebase Bootstrap)** — inventory network-as-code: Terraform security groups and firewall rules, NetworkPolicy manifests, Cilium/Calico CRDs, iptables-as-Ansible playbooks, CloudFormation network stacks. What the code declares should match what the runtime has.

**Phase 1 (Recon Bootstrap)** — when node/kubectl/cloud-API access is granted in Step 0, run the network surface detection (section 3) as part of initial recon. The inventory drives which network dimensions need deeper audit.

**Phase 3 (Security Assessment)** — network-layer testing is its own subsection covering the audit dimensions (sections 2–7 of this reference: namespace access, services inventory, traffic flow journeys, network policy, host firewalls, and edge devices / WAF / LB / API gateway). Findings feed into Phase 4 attack chains.

**Phase 4 (Attack Chain Analysis)** — network findings chain powerfully with application findings. The canonical chain: *SSRF in webapp → pod egress allows metadata service → retrieve IAM credentials → cloud API → data exfil*. Missing NetworkPolicies + unrestricted pod egress + reachable metadata service is the end-to-end credential-compromise chain.

**Phase 6 (Final Reporting)** — network findings should include:
- Exact rule / policy / manifest reference (file path, line number, or `namespace/name`)
- Proposed replacement rule as YAML or command-line form
- MITRE ATT&CK mapping: TA0008 (Lateral Movement), T1046 (Network Service Scanning), T1041 (Exfiltration Over C2)
- Cloud / CIS benchmark reference when applicable (e.g., CIS AWS 5.2 — "No security group allows 0.0.0.0/0 to 22")

---

## 9. Network Security Checklist

```
Namespace Access:
[ ] Linux netns inventoried on each audited host
[ ] Processes matched to their netns
[ ] K8s namespaces inventoried with workload counts
[ ] High-value namespaces identified (kube-system, istio-system, prod-*)
[ ] Intra-namespace reachability tested from probe pod
[ ] Cross-namespace reachability tested from probe pod
[ ] Pod-to-metadata-service reachability tested
[ ] ServiceAccount token auto-mount reviewed
[ ] hostNetwork and hostPID usage identified

Services Inventory:
[ ] Per-host listener inventory (ss -tulnpe) captured
[ ] Per-netns listener inventory captured
[ ] K8s services, ingresses, gateway-api resources listed
[ ] Endpoints / EndpointSlices reconciled with services
[ ] LoadBalancer / NodePort / externalIP services flagged
[ ] hostNetwork / hostPort pods flagged
[ ] External scan delta against internal inventory
[ ] Deprecated endpoints identified (kubelet 10255, etc.)

Traffic Flow:
[ ] Nine-step methodology applied to each significant path
[ ] Pod-to-pod same-ns paths traced
[ ] Pod-to-pod cross-ns paths traced
[ ] Pod-to-external paths traced (metadata service checked!)
[ ] Node-to-node control plane paths checked for restriction
[ ] Site-to-site VPN tunnels audited (IPsec, WireGuard, OpenVPN)
[ ] Client-to-site (remote access) VPN audited: concentrator, auth, posture, split/full tunnel
[ ] VPN MFA enforcement verified for all users (no "legacy device" exemption)
[ ] VPN concentrator firmware patched against current mass-exploited CVEs
[ ] DNS leak test from client with VPN connected
[ ] Kill switch / tunnel-drop behaviour verified
[ ] Offboarding revokes VPN access within acceptable SLA
[ ] ZTNA platform policies reviewed (if deployed alongside or replacing VPN)
[ ] User-to-app paths traced (DNS, CDN, LB, ingress, pod)
[ ] TLS termination points identified; back-end mTLS verified

Network Policy:
[ ] Default-deny present in every namespace
[ ] DNS egress explicitly allowed where default-deny applied
[ ] Selectors verified correct (kubernetes.io/metadata.name)
[ ] Port/protocol specificity reviewed
[ ] Egress blast radius audited; metadata service excluded
[ ] Policies empirically tested from probe pod
[ ] CNI extensions inventoried (Cilium CNP, Calico GNP, Antrea CNP)
[ ] Service mesh L7 policies reviewed (Istio, Linkerd, Consul)
[ ] PeerAuthentication mode STRICT (Istio) verified

Host Firewall:
[ ] iptables all tables (filter, nat, mangle, raw, security) dumped
[ ] ip6tables reviewed separately (dual-stack gotcha)
[ ] nftables ruleset dumped and reviewed
[ ] firewalld zones, services, rich rules, direct rules reviewed
[ ] UFW before.rules / user.rules / after.rules reviewed
[ ] pf rules/NAT reviewed (BSD/macOS hosts)
[ ] Windows Firewall profiles and rules reviewed
[ ] AWS Security Groups and NACLs reviewed
[ ] GCP firewall rules reviewed
[ ] Azure NSGs reviewed
[ ] 0.0.0.0/0 on management ports checked
[ ] 0.0.0.0/0 on database ports checked
[ ] Stale rules referencing deleted resources identified

Edge / WAF / Load Balancer / API Gateway:
[ ] Edge architecture inventoried and diagrammed (client → CDN → WAF → LB → ingress → pod)
[ ] WAF product and version identified; firmware vs CISA KEV cross-checked
[ ] WAF in prevention mode (not detection-only) for production
[ ] Direct-to-origin bypass tested — origin rejects non-CDN source IPs (or mTLS / shared secret)
[ ] Managed rule groups enabled (OWASP CRS, AWS common, Cloudflare managed); version current
[ ] Body inspection size limit understood; oversized-body handling audited
[ ] HTTP/2 and HTTP/3 request inspection verified
[ ] WebSocket and gRPC paths covered or explicitly exempted with justification
[ ] Rate limiting per-API-key and per-endpoint (not only per-IP)
[ ] Bot management configured (challenge/CAPTCHA/fingerprint)
[ ] WAF logs ingested to SIEM with anomaly alerting
[ ] WAF bypass testing run (gotestwaf / nowafpls) on each release
[ ] TLS config passes testssl.sh / sslyze (no TLS 1.0/1.1, no weak ciphers, HSTS present)
[ ] Certificate inventory: expiration, key strength, SAN correctness, intermediate chain
[ ] Backend health checks on dedicated endpoints that don't leak version info
[ ] Sticky session cookies have HttpOnly + Secure + SameSite flags
[ ] X-Forwarded-For chain: outer LB overwrites client XFF; origin trusts only rightmost from trusted proxy
[ ] X-Forwarded-Host / X-Forwarded-Proto / X-Real-IP handling consistent with XFF
[ ] Attacker-supplied X-Client-IP / True-Client-IP / X-Original-Forwarded-For stripped
[ ] F5 TMUI / Citrix NSIP / HAProxy stats / Kong admin API NOT reachable from internet
[ ] F5 / Citrix / NetScaler firmware patched against mass-exploited CVEs (listed in section 7.8)
[ ] Ingress-nginx snippet annotations disabled (allow-snippet-annotations=false)
[ ] Ingress-nginx patched against IngressNightmare (CVE-2025-24513 etc.)
[ ] API gateway: JWT algorithm pinned (no alg:none), issuer/audience validated, expiration enforced
[ ] API gateway: authentication required on ALL routes; no accidental public endpoints
[ ] API gateway developer portal does not leak internal endpoints or staging URLs
[ ] API gateway admin API (Kong 8001/8444, Apigee, etc.) internal-only
[ ] Request smuggling tests run (CL.TE, TE.CL, TE.TE, h2→h1 desync)
[ ] Path traversal via proxy tested (NGINX merge_slashes, Apache AllowEncodedSlashes)
[ ] Cache poisoning via unkeyed headers tested (X-Host, X-Forwarded-Host, X-Original-URL)
[ ] TLS termination topology mapped; each decryption boundary documented
[ ] For PCI scope: PCI-DSS 4.0 req 4.2.1 encrypted transmission requirements met
```

---

## Cross-reference with other frameworks

Network findings should map to:
- `references/frameworks/kubernetes-security.md` — K8s-specific context (RBAC, PSS, CIS K8s benchmark)
- `references/frameworks/cloud-security.md` — cloud firewall context (CIS AWS/GCP/Azure)
- `references/frameworks/zero-trust.md` — segmentation maturity mapping
- `references/frameworks/microservices-security.md` — service mesh context
- `references/frameworks/mitre-attack.md` — lateral movement (TA0008), network service scanning (T1046), exfiltration (TA0010)
- `references/attack-chains.md` — chaining network findings with application findings
- `references/frameworks/red-team.md` — when authorized for exploitation beyond audit
- `references/frameworks/api-security.md` — API gateway and API-layer security in depth
- `references/frameworks/owasp-complete.md` — OWASP Top 10 + WAF rule coverage reference
