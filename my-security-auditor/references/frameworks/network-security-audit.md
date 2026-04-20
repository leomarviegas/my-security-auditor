# Network Security Audit

This reference covers network-layer auditing across five dimensions: namespace access (Linux netns and Kubernetes namespaces), network services inventory, traffic flow journeys between trust zones, network policy auditing, and host firewall auditing. Use this when the engagement scope includes any network or infrastructure access — node shell, kubectl, or cloud API.

## Table of Contents
1. [When to Use This Reference](#1-when-to-use-this-reference)
2. [Namespace Access Auditing](#2-namespace-access-auditing)
3. [Network Services Inventory](#3-network-services-inventory)
4. [Traffic Flow Journeys](#4-traffic-flow-journeys)
5. [Network Policy Auditing](#5-network-policy-auditing)
6. [Host Firewall Auditing](#6-host-firewall-auditing)
7. [Integration with Audit Phases](#7-integration-with-audit-phases)
8. [Network Security Checklist](#8-network-security-checklist)

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

## 7. Integration with Audit Phases

**Phase 0.5 (Codebase Bootstrap)** — inventory network-as-code: Terraform security groups and firewall rules, NetworkPolicy manifests, Cilium/Calico CRDs, iptables-as-Ansible playbooks, CloudFormation network stacks. What the code declares should match what the runtime has.

**Phase 1 (Recon Bootstrap)** — when node/kubectl/cloud-API access is granted in Step 0, run the network surface detection (section 3) as part of initial recon. The inventory drives which network dimensions need deeper audit.

**Phase 3 (Security Assessment)** — network-layer testing is its own subsection covering all five dimensions (sections 2–6 of this reference). Findings feed into Phase 4 attack chains.

**Phase 4 (Attack Chain Analysis)** — network findings chain powerfully with application findings. The canonical chain: *SSRF in webapp → pod egress allows metadata service → retrieve IAM credentials → cloud API → data exfil*. Missing NetworkPolicies + unrestricted pod egress + reachable metadata service is the end-to-end credential-compromise chain.

**Phase 6 (Final Reporting)** — network findings should include:
- Exact rule / policy / manifest reference (file path, line number, or `namespace/name`)
- Proposed replacement rule as YAML or command-line form
- MITRE ATT&CK mapping: TA0008 (Lateral Movement), T1046 (Network Service Scanning), T1041 (Exfiltration Over C2)
- Cloud / CIS benchmark reference when applicable (e.g., CIS AWS 5.2 — "No security group allows 0.0.0.0/0 to 22")

---

## 8. Network Security Checklist

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
