# Network Security Audit

This reference covers network-layer security auditing across Linux network namespaces, Kubernetes namespaces, host firewalls, and cross-boundary traffic flows. Use this when auditing the network plane of a target — which systems can reach which, through which paths, with which controls enforcing the boundaries. This is complementary to application-layer testing (see `api-security.md`) and Kubernetes-layer testing (see `kubernetes-security.md`) — it sits underneath both.

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

Load this reference when the engagement scope includes:
- Linux host network posture (any host with network services)
- Kubernetes cluster network auditing (beyond the K8s API surface)
- Cross-namespace access control validation (Linux `netns` or K8s `namespaces`)
- VPN configuration review
- Firewall rule auditing (iptables, nftables, pf, Windows Firewall, cloud security groups)
- Zero Trust microsegmentation validation
- Incident response network forensics
- Lateral movement attack path analysis

### What this reference covers vs doesn't cover

**Covers:**
- Namespace enumeration and isolation testing (Linux + K8s)
- Service inventory per namespace (ports, protocols, processes)
- Traffic flow tracing (pod-to-pod, node-to-node, cluster-to-VPN, cluster-to-internet)
- Network policy effectiveness (K8s NetworkPolicy, Cilium, Calico)
- Host firewall rule analysis (iptables, nftables, UFW, firewalld, pf)

**Doesn't cover:**
- Application-layer issues (see `api-security.md`, `owasp-complete.md`)
- Kubernetes RBAC and API server hardening (see `kubernetes-security.md`)
- Cloud security group policies in isolation (see `cloud-security.md` — though we touch on it)
- Network device firmware exploitation (out of scope for most engagements)

### Authorization prerequisites

Network auditing typically requires elevated access. Before starting, confirm with the user:
- **Read access to nodes** (`ssh` or equivalent for `iptables -L`, `ss`, `nft list`)
- **Kubernetes cluster access** (`kubectl auth can-i`) — specifically `list` on `pods`, `services`, `networkpolicies`, `namespaces`, `endpoints` across all namespaces
- **Network capture consent** if `tcpdump` / `tshark` will be used
- **VPN/gateway access** for device-side auditing
- **Cloud API access** for security group / NACL / VPC flow log review

Document what was authorized. Network telemetry often reveals PII or credentials in transit — treat capture files as sensitive.

---

## 2. Namespace Access Auditing

Two distinct concepts share the "namespace" name. Audit both when they coexist.

### Linux network namespaces (`netns`)

Linux network namespaces isolate network stacks: interfaces, routing tables, iptables rules, sockets. Containers, VPN clients, and multi-tenant workloads use them.

**Enumeration:**
```bash
# List all network namespaces (named)
ip netns list

# Find all namespaces including anonymous (used by containers)
ls -la /proc/*/ns/net | sort -k11 -u

# Match namespaces to processes
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  ns=$(readlink /proc/$pid/ns/net 2>/dev/null)
  cmd=$(cat /proc/$pid/comm 2>/dev/null)
  echo "$pid $ns $cmd"
done | sort -k2 | uniq -f1

# Inspect a specific namespace
ip netns exec <ns-name> ip addr
ip netns exec <ns-name> ip route
ip netns exec <ns-name> ss -tlnp
ip netns exec <ns-name> iptables -L -n -v
```

**What to check:**
- Are namespaces properly isolated, or do they share interfaces via bridges/veth pairs that break isolation?
- Do container namespaces have unexpected host-network access (`--net=host` / `hostNetwork: true`)?
- Are there forgotten namespaces (ghost containers, stopped-but-not-cleaned workloads) still holding sockets?
- Which namespaces have `/proc/sys/net/ipv4/ip_forward=1` enabled? (implies routing, often intentional for VPN/container gateways but sometimes accidental)
- Do veth pairs cross trust boundaries without firewalling?

**Red flags:**
- Container with `hostNetwork: true` or `--net=host` AND `hostPID: true`/`--pid=host` — full access to host networking + processes
- `CAP_NET_ADMIN` in container capabilities — can modify host iptables from container if namespace not truly isolated
- Shared network namespace across pods that shouldn't share (pod sandboxes misconfigured)
- `/var/run/netns/` entries with no corresponding process (leaked namespaces)

### Kubernetes namespaces

K8s namespaces are logical isolation for RBAC, quotas, and default NetworkPolicy scopes — but **not network isolation by default**. Without NetworkPolicies, all pods in all namespaces can reach all other pods.

**Enumeration:**
```bash
# All namespaces
kubectl get namespaces -o wide

# What's in each (pods, services, network policies)
for ns in $(kubectl get ns -o name | cut -d/ -f2); do
  echo "=== $ns ==="
  kubectl -n $ns get pods,svc,netpol,endpoints
done

# Cross-namespace RBAC (who can list pods in which namespaces?)
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>

# ServiceAccount tokens with cluster-wide scope
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]? | .kind=="ServiceAccount") |
      {crb:.metadata.name, role:.roleRef.name, subjects:.subjects}'

# Which namespaces have no NetworkPolicy at all
for ns in $(kubectl get ns -o name | cut -d/ -f2); do
  count=$(kubectl -n $ns get netpol -o name 2>/dev/null | wc -l)
  echo "$ns: $count netpols"
done
```

**Intra-namespace access testing:**

Deploy an ephemeral test pod in the target namespace and attempt to reach everything:
```bash
kubectl -n <target-ns> run netshoot --rm -it --image=nicolaka/netshoot --restart=Never -- sh

# Inside the pod:
# 1. Enumerate services in this namespace
nslookup kubernetes.default
for svc in $(getent hosts | awk '{print $2}'); do
  echo "=== $svc ==="
  nmap -Pn -p- --min-rate=1000 $svc
done

# 2. Probe pods directly (bypass services)
for pod_ip in $(getent ahostsv4 | awk '{print $1}' | sort -u); do
  nmap -Pn -sT --top-ports=100 $pod_ip
done

# 3. Check service account token access
cat /var/run/secrets/kubernetes.io/serviceaccount/token
curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default/api/v1/namespaces/<target-ns>/pods
```

**Cross-namespace (extra-namespace) access testing:**

```bash
# From a pod in namespace A, try to reach services in namespace B
kubectl -n namespace-a run tester --rm -it --image=nicolaka/netshoot --restart=Never -- sh

# Inside:
# FQDN resolves cross-namespace via CoreDNS
nslookup api.namespace-b.svc.cluster.local
curl -v http://api.namespace-b.svc.cluster.local/health

# Direct pod IP across namespaces
curl -v http://<pod-ip-in-namespace-b>:<port>

# kube-system reachability (often overlooked)
curl -v http://kube-dns.kube-system.svc.cluster.local:53
curl -v https://kubernetes.default.svc.cluster.local
```

**What a secure baseline looks like:**
- Every namespace has at least a default-deny NetworkPolicy
- Cross-namespace traffic is explicitly allow-listed
- `kube-system` and `kube-public` are unreachable from tenant namespaces except for DNS (port 53 to kube-dns/CoreDNS)
- `hostNetwork: true` is restricted to ingress controllers and infrastructure components only
- Pod-to-pod traffic within a namespace follows the least-privilege principle (e.g., frontend cannot directly reach database; only backend can)

**Common misconfigurations:**
- No NetworkPolicies anywhere — flat network, every pod can reach every other pod
- NetworkPolicies only in production namespace, dev/staging wide open (and sharing the cluster)
- `namespaceSelector: {}` in ingress rule — accidentally allows from all namespaces
- Missing egress policies — pods can exfiltrate to internet freely
- Default namespace used for workloads (mixing system and user pods)

---

## 3. Network Services Inventory

Before you can audit what's exposed, inventory it.

### Host-level inventory

**Per host, enumerate:**
```bash
# Listening sockets with process/user/namespace context
ss -tulnpe
ss -tulnpe -A 'all'  # including established

# Full netstat alternative
ss -tulwnpe | awk '/LISTEN/ {print $5, $7}'

# Same data via lsof (comprehensive)
sudo lsof -i -P -n | grep LISTEN

# Per-interface address bindings
ip -4 -o addr show
ip -6 -o addr show

# Default gateway and routing context
ip route
ip -6 route
ip rule show  # policy routing — often reveals VPN/multi-homing
```

**Per-namespace (host):**
```bash
for ns in $(ip netns list | awk '{print $1}'); do
  echo "=== netns: $ns ==="
  ip netns exec "$ns" ss -tulnpe
done
```

**Capture for audit record:**
```bash
# Produce a single consolidated services inventory
(
  echo "# Host: $(hostname) | Date: $(date -Iseconds)"
  echo "## Listening sockets (root namespace)"
  ss -tulnpe
  echo "## Routing table"
  ip route
  ip -6 route
  echo "## Interfaces"
  ip -o addr
  echo "## Per-netns listeners"
  for ns in $(ip netns list | awk '{print $1}'); do
    echo "### netns: $ns"
    ip netns exec "$ns" ss -tulnpe
  done
) > services-$(hostname)-$(date +%Y%m%d).txt
```

### Kubernetes service inventory

```bash
# All services cluster-wide, with external exposure
kubectl get svc -A -o wide

# Services exposed externally (LoadBalancer, NodePort, ExternalIP)
kubectl get svc -A -o json | jq -r '
  .items[] |
  select(.spec.type == "LoadBalancer" or .spec.type == "NodePort" or (.spec.externalIPs // [] | length > 0)) |
  "\(.metadata.namespace)/\(.metadata.name) \(.spec.type) ports=\([.spec.ports[] | "\(.port)/\(.protocol)"] | join(",")) externalIPs=\(.spec.externalIPs // [])"
'

# Ingress resources — what's HTTP-exposed
kubectl get ingress -A -o wide

# Gateway API resources (newer)
kubectl get gateway,httproute,tcproute,udproute -A 2>/dev/null

# Endpoints — what's actually backing services (reveals pod IPs)
kubectl get endpoints -A -o wide

# EndpointSlices (newer, preferred)
kubectl get endpointslices -A

# NetworkPolicy coverage
kubectl get netpol -A -o wide

# Pods using hostNetwork (bypass CNI/NetworkPolicy)
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostNetwork == true) |
  "\(.metadata.namespace)/\(.metadata.name) node=\(.spec.nodeName)"
'

# Pods using hostPort (bind port on node)
kubectl get pods -A -o json | jq -r '
  .items[] |
  .spec.containers[]? |
  select(.ports[]? | .hostPort != null) |
  .name
'

# Services exposed via NodePort — all node IPs become listeners
kubectl get svc -A -o json | jq -r '
  .items[] |
  select(.spec.type == "NodePort") |
  "\(.metadata.namespace)/\(.metadata.name) nodePorts=\([.spec.ports[] | .nodePort] | join(","))"
'
```

### Cross-referencing inventory with reality

Inventories lie. Processes die, configurations drift, test services get forgotten. Always cross-reference:

**Scan from outside the boundary:**
```bash
# From an untrusted network, scan what's actually reachable
nmap -Pn -sS -p- --min-rate=1000 -oA external-scan <external-ip>
nmap -Pn -sU --top-ports=100 -oA external-udp <external-ip>

# TLS services — enumerate certs and supported ciphers
nmap -p 443,8443 --script ssl-enum-ciphers,ssl-cert <target>

# From inside the cluster, scan the cluster network
kubectl run scanner --rm -it --image=instrumentisto/nmap --restart=Never -- \
  nmap -Pn -sT -p- --min-rate=5000 10.0.0.0/16
```

**Compare:**
- What the inventory says is listening vs what nmap finds
- What NetworkPolicies say is allowed vs what actually connects
- Document gaps as findings

### Service inventory output template

For each service found, record:
```
Service: <n>
Namespace/Host: <location>
Port/Protocol: <tcp/udp port>
Process/Pod: <what's serving it>
Bound interface(s): <0.0.0.0 / specific IP>
Intended audience: <internal / cluster / external>
Authentication: <yes / no / mTLS / token / none>
Encryption: <TLS / plaintext / mTLS>
Accessible from (tested): <list of source contexts>
Exposed externally: <yes / no>
Findings: <misconfigurations observed>
```

---

## 4. Traffic Flow Journeys

For each network path of interest, trace what actually happens — end to end.

### Flow journey methodology

For every sensitive path (user → app, app → db, pod → external API, branch office → HQ), produce a flow journey document with these steps:

1. **Source identification** — where does traffic originate (user IP, pod, namespace, region)?
2. **DNS resolution path** — which resolver, split-horizon, caching, DNSSEC?
3. **Routing decision** — which routing table, policy rules, VPN selectors?
4. **Egress filter** — firewall, security group, egress NetworkPolicy?
5. **Transit path** — which VPN, peering, transit gateway, internet path?
6. **Ingress filter** — DDoS protection, WAF, security group, ingress NetworkPolicy?
7. **Destination decoding** — service mesh, load balancer, ingress controller, pod?
8. **Encryption state** — TLS? mTLS? where terminated?
9. **Logging points** — where is this path observable (flow logs, access logs, mTLS logs)?

Document gaps at each step.

### Pod-to-pod (intra-cluster, same namespace)

**Expected path:**
```
Pod A (eth0) → veth-pair → CNI bridge/overlay
  → NetworkPolicy evaluation (if present)
  → kube-proxy iptables/ipvs (if targeting ClusterIP)
  → Pod B (eth0)
```

**Audit steps:**
```bash
# From Pod A, reach Pod B
kubectl -n <ns> exec -it <pod-a> -- sh
# Inside:
nc -zv <pod-b-ip> <port>
curl -v http://<service-name>:<port>

# Observe from the CNI side (on node)
sudo nsenter -t $(pgrep -f "coredns\|calico-node\|cilium-agent" | head -1) -n ss -tn
sudo iptables -t nat -L KUBE-SERVICES -n -v | head -50
sudo iptables -L CILIUM-INPUT -n -v  # if Cilium

# For overlay networks (VXLAN, Geneve), check the encap path
sudo tcpdump -i <overlay-interface> -nn -c 100 'udp port 8472 or udp port 6081'
```

**Common issues:**
- MTU mismatch when overlay encapsulation adds headers (1500 - 50 = 1450 typical for VXLAN) — manifests as large packets silently dropped
- kube-proxy mode mismatch (iptables vs IPVS) causing inconsistent behavior
- Dual-stack partial implementation (IPv4 works, IPv6 silently doesn't)
- Service topology ignored (all traffic routes cross-zone, cost + latency issues + blast radius)

### Pod-to-pod (cross-namespace)

**Expected path:** same as intra-namespace, but traverses two NetworkPolicy evaluations (egress from source namespace, ingress into destination namespace).

**Audit:**
```bash
# From Pod in namespace A, reach service in namespace B
kubectl -n namespace-a exec -it <pod> -- curl -v \
  http://<service>.namespace-b.svc.cluster.local:<port>

# Check both policies
kubectl -n namespace-a get netpol -o yaml  # egress rules
kubectl -n namespace-b get netpol -o yaml  # ingress rules

# Tools like Cilium's Hubble or Calico's calicoctl can trace live
hubble observe --from-namespace namespace-a --to-namespace namespace-b --last 100
calicoctl get globalnetworkpolicy -o yaml
```

### Pod-to-external (cluster → internet)

**Expected path:**
```
Pod → CNI egress → NetworkPolicy egress eval
  → Node's default route
  → NAT gateway / cloud egress (SNAT to node/NAT IP)
  → Security group / firewall egress eval
  → Internet → destination
```

**Audit:**
```bash
# From pod, determine what's reachable externally
kubectl exec -it <pod> -- sh
# Inside:
curl -v https://icanhazip.com  # SNAT IP visible?
curl -v https://1.1.1.1
dig @8.8.8.8 example.com
nc -zv ssh.github.com 22

# Check egress NetworkPolicy
kubectl -n <ns> get netpol -o yaml | grep -A20 egress

# Check cloud-level egress
# AWS:
aws ec2 describe-security-groups --filters "Name=group-id,Values=<sg-id>"
aws ec2 describe-route-tables --route-table-ids <rtb-id>
aws ec2 describe-flow-logs  # VPC Flow Logs

# GCP:
gcloud compute firewall-rules list --filter="direction=EGRESS"
gcloud logging read 'resource.type="gce_subnetwork"' --limit 100

# Azure:
az network nsg rule list --nsg-name <nsg> -g <rg> --query "[?direction=='Outbound']"
```

**Common gaps:**
- No egress filtering at all — compromised pod can exfiltrate anywhere, reach metadata service, attack internal IPs
- Metadata service (`169.254.169.254`) not explicitly blocked — IMDSv1 tokens harvestable (SSRF → credential theft path)
- Link-local addresses accessible (`169.254.0.0/16`, `fe80::/10`)
- Egress to RFC1918 not restricted (pod can reach corporate intranet unintentionally)

### Node-to-node (control plane and data plane)

**Expected paths:**
- **Control plane:** kubelet → kube-apiserver (6443), etcd peer (2380), etcd client (2379), scheduler/controller-manager internal
- **Data plane:** overlay protocol (VXLAN 8472, Geneve 6081, WireGuard), IPIP, BGP for direct routing (Calico)

**Audit:**
```bash
# On each node, confirm expected inter-node listeners
sudo ss -tlnp | grep -E ':(6443|2379|2380|10250|10255|10256|8472|6081|179)'

# Verify TLS on control-plane paths
openssl s_client -connect <node>:6443 -showcerts < /dev/null
openssl s_client -connect <node>:2379 -showcerts < /dev/null

# Check etcd auth — unauthenticated etcd = cluster takeover
etcdctl --endpoints=https://<node>:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/peer.crt \
  --key=/etc/kubernetes/pki/etcd/peer.key \
  endpoint health
# If the above works WITHOUT certs, you found a critical issue

# Kubelet read-only port (10255) — should be disabled (--read-only-port=0)
curl -s http://<node>:10255/pods
```

### Site-to-site VPN (IPsec, WireGuard, OpenVPN)

**Expected path:**
```
Client LAN → VPN client → encrypted tunnel over internet
  → VPN gateway → decryption → internal routing → destination
```

**Audit:**
```bash
# Identify VPN type per host
sudo ip -d link show | grep -iE 'wireguard|gre|ipip|tun|ipsec'
sudo ip xfrm state  # IPsec SAs
sudo ip xfrm policy  # IPsec policies
sudo wg show all  # WireGuard config (requires root)
sudo swanctl --list-conns  # strongSwan
sudo swanctl --list-sas

# Routing to confirm VPN is actually used
ip route get <destination-behind-vpn>
ip rule show

# VPN cipher/strength
# IPsec:
sudo ip xfrm state | grep -E 'enc|auth|aead'
# WireGuard uses ChaCha20Poly1305 / Curve25519 / BLAKE2s — fixed, strong

# Check which networks the VPN exposes
# On the gateway:
sudo iptables -t filter -L FORWARD -n -v
sudo iptables -t nat -L POSTROUTING -n -v
```

**Red flags:**
- IKEv1 in use (deprecated, weak) — should be IKEv2
- PSK authentication with weak shared secret (brute-forceable)
- Too-permissive traffic selectors (VPN allows `0.0.0.0/0 ↔ 0.0.0.0/0` — full-mesh access)
- No dead-peer detection, no replay protection
- Split tunneling misconfigured — sensitive destinations going over cleartext internet
- VPN endpoint accessible from internet for management (SSH/web UI) without IP allowlist
- Pre-shared keys in CI/CD logs, backup files, or git

### User-to-application (external → service)

**Expected path:**
```
User browser → DNS → CDN/WAF/DDoS → cloud LB → Ingress controller
  → service mesh (maybe) → pod → app
```

Trace each hop with real tooling:
```bash
# DNS trace
dig +trace example.com

# Full TCP/TLS handshake timing
curl -w "@curl-format.txt" -o /dev/null -s https://example.com
# where curl-format.txt contains:
#     time_namelookup:  %{time_namelookup}s\n
#     time_connect:     %{time_connect}s\n
#     time_appconnect:  %{time_appconnect}s\n
#     time_starttransfer: %{time_starttransfer}s\n
#     time_total:       %{time_total}s\n

# Hop-by-hop
mtr -rwzbc 30 example.com
traceroute -T -p 443 example.com

# TLS inspection
sslyze --regular example.com
testssl.sh example.com
```

**Audit questions:**
- Is there a WAF? What rules? Is it in detect-only or blocking mode?
- Does the LB do TLS termination, or passthrough to the ingress controller?
- Does the ingress controller enforce auth, rate limiting, WAF rules?
- Is there mTLS between ingress controller and pods (service mesh)?
- Where are the logs for each hop? Who has access?

---

## 5. Network Policy Auditing

Kubernetes NetworkPolicies (and their CNI-specific extensions) are the primary cluster-layer microsegmentation control.

### NetworkPolicy fundamentals

Standard `networking.k8s.io/v1` NetworkPolicy:
- **Scope:** namespaced (applies only to pods in its namespace)
- **Selection:** `podSelector` chooses which pods it applies to
- **Direction:** `ingress` (to pods), `egress` (from pods), or both
- **Semantics:** additive — if no policy selects a pod, all traffic is allowed; if any policy selects a pod, only explicitly allowed traffic is permitted (for the specified direction)

**Critical implication:** a namespace with zero NetworkPolicies has zero isolation. Adding one NetworkPolicy for one pod leaves all other pods fully open.

### The default-deny baseline

Every namespace should have a default-deny NetworkPolicy, then explicit allow rules layered on top:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: <ns>
spec:
  podSelector: {}  # applies to every pod
  policyTypes:
    - Ingress
    - Egress
```

Without explicit allow rules after this, pods can't even do DNS. Add back what's needed:

```yaml
# Always needed: DNS egress to CoreDNS
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

### Audit procedure

**1. Coverage check:**
```bash
# Every namespace should have at least a default-deny
for ns in $(kubectl get ns -o name | cut -d/ -f2); do
  has_default_deny=$(kubectl -n $ns get netpol -o json | \
    jq '[.items[] | select(.spec.podSelector == {} and (.spec.policyTypes | contains(["Ingress"])))] | length')
  echo "$ns: default-deny-ingress=$has_default_deny"
done
```

**2. Selector correctness:**

Read each NetworkPolicy and verify:
- Does the `podSelector` match the intended pods? (`kubectl get pods -l <selector>`)
- Do `namespaceSelector` + `podSelector` combinations behave as expected? (these are AND within a single peer, OR across peers)
- Empty `{}` means "all" in that dimension — check this isn't accidental

Pitfall: pre-1.21 clusters, `namespaceSelector` matched labels on namespaces, but labels were opt-in. Post-1.21, every namespace has `kubernetes.io/metadata.name=<namespace-name>` automatically — use this for stable cross-namespace rules.

**3. Port/protocol specificity:**
- No `ports:` key means "all ports" — often wider than intended
- `protocol:` defaults to TCP — explicitly set UDP where needed (DNS, most notably)
- Named ports (`port: http`) only work if the target pod declares them

**4. Egress blast radius:**

Unrestricted egress is how data exfiltrates. Every namespace should have egress rules that:
- Allow DNS to CoreDNS
- Allow communication to required internal services
- Allow internet egress only where actually needed, ideally only to specific CIDRs or FQDNs (requires CNI with FQDN support — Cilium, Calico Enterprise)
- Deny metadata service (`169.254.169.254/32`) unless the pod specifically needs it

**5. CIDR-based rules:**

```yaml
egress:
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
          except:
            - 10.0.0.0/8        # cluster internal
            - 172.16.0.0/12     # RFC1918
            - 192.168.0.0/16    # RFC1918
            - 169.254.0.0/16    # link-local + cloud metadata
            - 127.0.0.0/8       # loopback
```

This pattern allows internet egress while blocking lateral movement into internal ranges.

**6. Policy effectiveness testing:**

The only way to know a policy works is to test it.
```bash
# Deploy netshoot in the namespace
kubectl -n <ns> run netshoot --rm -it --image=nicolaka/netshoot --restart=Never -- sh

# Attempt connections the policy SHOULD block
nc -zv -w3 <intentionally-forbidden-target> <port>
# Expect: timeout or connection refused

# Attempt connections the policy SHOULD allow
nc -zv -w3 <allowed-target> <port>
# Expect: success

# Cilium-specific: use hubble to watch in real time
hubble observe --from-pod <ns>/<pod> --last 100 --verdict DENIED
```

### Advanced NetworkPolicy (CNI-specific)

Standard NetworkPolicy has limitations — no FQDN rules, no L7 rules, no global policies. CNI-specific CRDs fill the gap:

| CNI | Extended policy kind | Key features |
|-----|---------------------|--------------|
| Cilium | `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy` | L7 (HTTP paths, DNS names), FQDN rules, node selectors, Kafka topic filtering |
| Calico | `GlobalNetworkPolicy`, `NetworkPolicy` (Calico flavor) | Cluster-wide scope, ordering, action=deny/log/pass, service account selectors |
| Weave | NetworkPolicy (standard only) | No extensions |
| Antrea | `ClusterNetworkPolicy`, `NetworkPolicy` (Antrea) | Priorities, FQDN, Tier-based |

**Audit these CRDs too:**
```bash
# Cilium
kubectl get ciliumnetworkpolicy -A
kubectl get ciliumclusterwidenetworkpolicy

# Calico
kubectl get globalnetworkpolicy
kubectl get networkpolicy.projectcalico.org -A

# Antrea
kubectl get clusternetworkpolicy
kubectl get networkpolicy.crd.antrea.io -A
```

### L7 policy review (service mesh)

If Istio, Linkerd, or Consul is deployed, policy extends to HTTP methods, paths, and JWT claims.

```bash
# Istio
kubectl get authorizationpolicy -A
kubectl get peerauthentication -A
kubectl get destinationrule -A
kubectl get virtualservice -A

# Linkerd
kubectl get server -A
kubectl get serverauthorization -A
kubectl get authorizationpolicy -A
kubectl get httproute -A

# Consul
kubectl get servicedefaults -A
kubectl get serviceintentions -A
```

Review each for:
- Default action (deny everything, or permit everything?)
- mTLS mode (`STRICT` / `PERMISSIVE` / `DISABLE`)
- JWT validation issuer, audience, required claims
- Path-based rules correctness

### Common NetworkPolicy findings

| Finding | Severity | Description |
|---------|----------|-------------|
| No NetworkPolicies exist | High | Flat cluster network, full lateral movement possible |
| Default-deny missing in sensitive namespaces | High | Pods added later are unprotected by default |
| Egress unrestricted | High | Exfiltration and metadata service attacks possible |
| Metadata service (169.254.169.254) reachable from pods | High | Cloud credential theft via SSRF |
| `namespaceSelector: {}` in ingress | Medium | Accidentally allows from all namespaces |
| No DNS egress policy | Medium | Either DNS is broken or policy is incomplete |
| L7 policies missing where service mesh deployed | Medium | Network segmentation without application segmentation |
| hostNetwork pods unaccounted for | Medium | NetworkPolicy doesn't apply to hostNetwork pods |
| Named ports referenced that don't exist | Low | Policy silently doesn't match |

---

## 6. Host Firewall Auditing

Every Linux host has a firewall — even when "no firewall" is claimed, the default policies and bridge/conntrack interactions matter.

### iptables auditing

iptables has tables (`filter`, `nat`, `mangle`, `raw`, `security`) and chains within each. Review all.

**Full dump for audit record:**
```bash
# Binary-format save (most complete)
sudo iptables-save > iptables-$(hostname)-$(date +%Y%m%d).rules
sudo ip6tables-save > ip6tables-$(hostname)-$(date +%Y%m%d).rules

# Human-readable with counters
sudo iptables -L -n -v --line-numbers
sudo iptables -t nat -L -n -v --line-numbers
sudo iptables -t mangle -L -n -v --line-numbers
sudo iptables -t raw -L -n -v --line-numbers

# Per-chain statistics (identifies unused rules — zero hits over time)
sudo iptables -L -n -v -Z  # show and zero counters (caution: resets)
```

**What to audit:**

**1. Default policies:**
```bash
sudo iptables -S | head -4
# Expect:
# -P INPUT DROP            (good — deny by default)
# -P FORWARD DROP          (good — host isn't a router unless intentional)
# -P OUTPUT ACCEPT         (common, but restrictive OUTPUT is stronger)
```

If default policy is `ACCEPT`, every unmatched packet is allowed — audit every rule for negative effect instead of allow-listing.

**2. Rule specificity:**

For each rule, check:
- Source: is `0.0.0.0/0` intentional?
- Destination: does it match a specific interface?
- Port: is the port range as narrow as possible?
- State: is `-m conntrack --ctstate` used correctly? (`NEW,ESTABLISHED,RELATED` is typical; `INVALID` should be dropped)
- Target: `ACCEPT`, `DROP`, `REJECT`, custom chain?

**3. Rule ordering:**

iptables is first-match-wins within a chain. A permissive rule before a restrictive one defeats the restrictive one.
```bash
# Find suspicious early-chain ACCEPT rules
sudo iptables -L INPUT -n -v --line-numbers | head -20
```

**4. Custom chains:**

Chains like `DOCKER`, `DOCKER-USER`, `KUBE-SERVICES`, `CILIUM-INPUT` are auto-managed. Still audit them:
- Does `DOCKER-USER` (the one you're supposed to edit for Docker hosts) have your firewall rules, or is it empty?
- Do KUBE chains look sane, or has something injected unexpected rules?

**5. NAT table review:**

```bash
sudo iptables -t nat -S
```

Look for:
- `DNAT` to internal services — is it exposing something unintentionally?
- `SNAT` / `MASQUERADE` — identifies NAT boundaries, important for traffic flow journeys
- `KUBE-NODEPORTS` chain — NodePort services expose on all node IPs

**6. Logging visibility:**

Rules that drop/reject silently are invisible to SOC. Consider:
```bash
# Check for LOG targets
sudo iptables -S | grep LOG

# Proper logging pattern:
# -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW-DROP: " --log-level 4
# -A INPUT -j DROP
```

### nftables auditing

nftables replaces iptables on modern distros (RHEL 8+, Debian 11+, Ubuntu 20.04+). Same concepts, different syntax.

**Full dump:**
```bash
sudo nft list ruleset > nftables-$(hostname)-$(date +%Y%m%d).nft

# Per-family
sudo nft list table inet filter
sudo nft list table ip nat
sudo nft list table ip6 filter

# With counters
sudo nft -a list ruleset
```

**Audit points:**
- `inet filter` (dual-stack) is preferred over separate `ip filter` and `ip6 filter`
- Each chain has a `type`, `hook`, `priority`, and `policy`. `policy drop` = deny by default
- Named sets (`@blacklist`, `@allowed_ports`) make rules reusable; audit sets too: `nft list set inet filter allowed_ports`
- Maps (like `dnat to tcp dport map { 80 : 10.0.0.1, 443 : 10.0.0.2 }`) redirect based on key

**Dual-stack gotcha:**

It's common to audit IPv4 rules thoroughly and ignore IPv6. Modern systems often have IPv6 enabled by default:
```bash
# Is IPv6 active?
ip -6 addr show
sysctl net.ipv6.conf.all.disable_ipv6

# Is IPv6 firewalled?
sudo ip6tables -L -n -v
sudo nft list table ip6 filter
```

Missing IPv6 firewall = complete bypass of IPv4 firewall for dual-stack services.

### Firewalld (RHEL/CentOS/Fedora)

firewalld is a zone-based front-end to nftables/iptables.

```bash
# Active zones and bindings
sudo firewall-cmd --get-active-zones

# Per-zone services, ports, rich rules, sources
sudo firewall-cmd --zone=public --list-all
sudo firewall-cmd --zone=trusted --list-all

# Default zone — critical to know
sudo firewall-cmd --get-default-zone

# Permanent vs runtime differences
sudo firewall-cmd --list-all --permanent
```

Audit:
- What zone is the default? `public` or `external` are safer; `trusted` = no filtering
- Which interfaces are in which zones?
- Rich rules (`firewall-cmd --list-rich-rules`) — often contain the actual security-relevant logic
- Services by name (`--list-services`) resolve to port definitions in `/usr/lib/firewalld/services/`

### UFW (Ubuntu Uncomplicated Firewall)

UFW is an iptables front-end.
```bash
sudo ufw status verbose
sudo ufw show raw      # underlying rules
sudo cat /etc/ufw/user.rules
sudo cat /etc/ufw/before.rules
sudo cat /etc/ufw/after.rules
```

Audit:
- Default incoming/outgoing policy
- Per-rule source/destination — `ALLOW IN` from `Anywhere` is common and often too permissive
- Rule application order (before → user → after)
- `/etc/default/ufw` — `IPT_SYSCTL` controls sysctl settings, check `net.ipv4.conf.all.rp_filter`, forward policy

### pf (BSD, macOS)

If in scope:
```bash
# OpenBSD/FreeBSD/pfSense
sudo pfctl -sr           # rules
sudo pfctl -sn           # NAT rules
sudo pfctl -ss           # state table
sudo pfctl -sa           # everything
sudo pfctl -v -sr        # verbose with counters
```

### Windows Firewall

If a Windows host is in scope:
```powershell
# Full rule export
Get-NetFirewallRule | Format-Table DisplayName,Enabled,Direction,Action,Profile
Get-NetFirewallProfile  # per-profile settings (Domain, Private, Public)

# Active rules by profile
Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {$_.Enabled -eq 'True'}

# Port-to-rule mapping
Get-NetFirewallPortFilter | ForEach-Object {
  $rule = $_ | Get-NetFirewallRule
  [PSCustomObject]@{
    Rule = $rule.DisplayName
    Direction = $rule.Direction
    Action = $rule.Action
    Protocol = $_.Protocol
    LocalPort = $_.LocalPort
  }
}
```

### Cloud-layer firewalls (adjunct)

Always check host firewall in context of cloud-level filters — the defense-in-depth layering matters.

**AWS Security Groups + NACLs:**
```bash
aws ec2 describe-security-groups --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName,Ingress:IpPermissions,Egress:IpPermissionsEgress}'
aws ec2 describe-network-acls --query 'NetworkAcls[*].{ID:NetworkAclId,Entries:Entries}'
```

**GCP firewall rules:**
```bash
gcloud compute firewall-rules list --format=yaml
```

**Azure NSGs:**
```bash
az network nsg list --query '[].{name:name,rules:securityRules}'
```

### Common firewall findings

| Finding | Severity | Description |
|---------|----------|-------------|
| Default policy `ACCEPT` on input/forward | High | Every unmatched packet allowed |
| IPv6 firewall absent, IPv6 active | High | Full bypass for dual-stack services |
| Management port (SSH/RDP/Kubernetes API) open to `0.0.0.0/0` | High | Direct brute-force / exploit surface |
| Internal services (DB, Redis, etcd) bound to `0.0.0.0` with no firewall | Critical | Database accessible from internet |
| Conflicting cloud SG and host firewall rules | Medium | Either redundancy or coverage gaps |
| Rules with stale source CIDRs (old office IPs, former vendors) | Medium | Attack surface sprawl |
| No logging on drop | Medium | Invisible attacks |
| Drift between declared config (Ansible/Terraform) and runtime rules | Medium | Config-as-code bypassed |
| Forwarded traffic unfiltered (ip_forward=1, FORWARD ACCEPT) | Medium | Host acts as unintentional router |

---

## 7. Integration with Audit Phases

### Phase 0.5 (Codebase Bootstrap)

If the engagement has code access, inspect network config as code:
- Terraform: `aws_security_group`, `google_compute_firewall`, `azurerm_network_security_group`
- Kubernetes manifests: NetworkPolicy, service type, `hostNetwork`, `hostPort`
- Helm charts: templated NetworkPolicies — render with `helm template` to see actual output
- Ansible: iptables/nftables modules, firewalld tasks
- Cilium / Calico CRDs in `manifests/`, `charts/`, `config/`

### Phase 1 (Recon Bootstrap)

External perspective of the network:
```bash
# Passive — what DNS reveals
dig +short example.com any
dig +short -x <ip>  # reverse
whois <ip>

# Which AS, which cloud provider
whois -h whois.cymru.com " -v <ip>"

# Subdomain / service enumeration
subfinder -d example.com
amass enum -d example.com

# Active scanning (with authorization)
nmap -Pn -sS -p- --min-rate=1000 <scope>
masscan -p1-65535 <scope> --rate=10000
```

### Phase 2 (Full Traversal)

Traffic flow journeys for every authentication state and role. Capture where traffic physically traverses.

### Phase 3 (Security Assessment)

Namespace access, service inventory, NetworkPolicy validation, firewall review all happen here.

### Phase 4 (Attack Chain Analysis)

Network findings become critical chain components:
- Internet → LB → pod (explicit path) combined with pod → metadata service (missing egress policy) = cloud credential compromise
- Compromised pod → cross-namespace pod (missing NetworkPolicy) = tenant breakout
- Internal network scan possible (flat L2) → lateral movement to DB (no host firewall) = data breach

### Phase 6 (Reporting)

Each network finding should include:
- Exact rule / policy / manifest reference (file, line number, resource name)
- Affected source and destination
- Reproduction steps (pcap sample if relevant)
- Proposed rule (YAML / iptables / nftables syntax ready to apply)
- Cross-reference to MITRE ATT&CK — Lateral Movement (TA0008), Exfiltration Over C2 Channel (T1041), Exploitation of Remote Services (T1210), etc.

---

## 8. Network Security Checklist

### Namespace access
- [ ] All Linux network namespaces enumerated (named + anonymous)
- [ ] All Kubernetes namespaces enumerated; each classified (system / tenant / infrastructure)
- [ ] Intra-namespace access tested from a neutral pod/container
- [ ] Cross-namespace access tested (A → B, A → kube-system, A → external)
- [ ] `hostNetwork: true` pods enumerated and justified
- [ ] `hostPort` bindings enumerated
- [ ] Container capabilities reviewed for `CAP_NET_ADMIN`, `CAP_NET_RAW`

### Service inventory
- [ ] Host listening sockets inventoried per host (`ss -tulnpe`)
- [ ] K8s Services inventoried (all types: ClusterIP, NodePort, LoadBalancer, ExternalName)
- [ ] Ingress / Gateway API resources inventoried
- [ ] External scan cross-checked against declared inventory
- [ ] Orphaned / forgotten services identified
- [ ] Every service has authentication and encryption documented

### Traffic flow journeys
- [ ] Pod-to-pod (intra-namespace) documented
- [ ] Pod-to-pod (cross-namespace) documented
- [ ] Pod-to-external documented (via NAT gateway, security group, egress policy)
- [ ] Node-to-node documented (control plane, data plane, overlay)
- [ ] VPN journeys documented (site-to-site, remote access)
- [ ] User-to-app journey documented (DNS → CDN → LB → Ingress → Pod)
- [ ] DNS resolution path documented (CoreDNS, upstream, split-horizon)
- [ ] Encryption state identified at each hop
- [ ] Logging points identified at each hop

### Network policy auditing
- [ ] Every namespace has a default-deny NetworkPolicy
- [ ] DNS egress explicitly allowed where needed
- [ ] Metadata service (169.254.169.254) explicitly denied where not needed
- [ ] Egress to RFC1918 ranges restricted
- [ ] CNI-specific extended policies reviewed (CiliumNetworkPolicy, Calico GlobalNetworkPolicy, etc.)
- [ ] Service mesh L7 policies reviewed (Istio AuthorizationPolicy, Linkerd Server / ServerAuthorization)
- [ ] Policy effectiveness empirically tested (positive and negative cases)
- [ ] Policies match intended pods via `kubectl get pods -l <selector>`

### Firewall auditing
- [ ] iptables / nftables full rule dump captured for each host
- [ ] Default policies identified per chain
- [ ] IPv6 firewall state matches IPv4
- [ ] NAT table reviewed
- [ ] Custom chains (Docker, kube-proxy, CNI) reviewed
- [ ] Management ports (SSH, RDP, K8s API, etcd) restricted to known IPs
- [ ] Rule ordering correctness verified (no ACCEPT shadowing restrictive rules)
- [ ] Firewall logging enabled for drop/reject events
- [ ] Cloud-level firewalls (security groups, NSGs, NACLs) reviewed
- [ ] Host and cloud firewalls not conflicting; redundancy intentional
- [ ] Drift between IaC declaration and runtime rules checked
- [ ] VPN gateway firewall rules reviewed

---

## Cross-reference with other skill references

- `kubernetes-security.md` — for Kubernetes RBAC, pod security standards, admission control, kubelet hardening (complements NetworkPolicy review with identity and admission layers)
- `cloud-security.md` — for cloud provider network constructs (VPCs, subnets, security groups, NACLs, transit gateways)
- `zero-trust.md` — for the broader architectural framing (microsegmentation, identity-aware proxies, continuous verification)
- `microservices-security.md` — for service mesh deep dive (mTLS, L7 policies, service identity)
- `mitre-attack.md` — for mapping lateral movement, exfiltration, and network service discovery techniques
- `red-team.md` — for attacker tradecraft in network environments (how lateral movement actually unfolds)
- `blue-team.md` — for detection engineering around network events (flow logs, Zeek, Suricata, eBPF-based observability)
