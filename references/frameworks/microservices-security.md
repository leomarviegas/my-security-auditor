# Microservices Security

This reference covers security assessment specific to microservices architectures. Apply when the target uses distributed services, API gateways, service meshes, or event-driven patterns.

## Table of Contents
1. [Microservices Attack Surface](#1-microservices-attack-surface)
2. [Inter-Service Authentication](#2-inter-service-authentication)
3. [API Gateway Security](#3-api-gateway-security)
4. [Service Mesh Security](#4-service-mesh-security)
5. [Data Flow Security](#5-data-flow-security)
6. [Event-Driven Security](#6-event-driven-security)
7. [Distributed System Threats](#7-distributed-system-threats)
8. [Service Discovery Security](#8-service-discovery-security)
9. [Microservices Security Checklist](#9-microservices-security-checklist)

---

## 1. Microservices Attack Surface

Microservices dramatically expand the attack surface compared to monoliths. Each service is a potential entry point.

### Attack surface expansion
| Monolith | Microservices |
|----------|--------------|
| Single entry point | Multiple entry points per service |
| In-process calls | Network calls (vulnerable to interception) |
| Single auth check | Auth check needed at every service |
| Shared memory | Shared nothing (data must be explicitly protected in transit) |
| Single deployment | Many deployments (inconsistent security posture) |
| One set of dependencies | Many independent dependency trees |

### Observable indicators of microservices architecture
| Indicator | Where to find it |
|-----------|-----------------|
| Multiple API base paths | `/api/users/`, `/api/orders/`, `/api/payments/` served by different backends |
| Inconsistent error formats | Different services return different error structures |
| Inconsistent auth behavior | Some endpoints check auth differently than others |
| Distributed tracing headers | `x-request-id`, `x-correlation-id`, `x-b3-traceid`, `traceparent` |
| Service mesh headers | `x-envoy-*`, `x-istio-*`, `x-linkerd-*` |
| Different response times | Services behind the same domain have very different latency profiles |
| Version mismatches | Different API versions or framework versions across endpoints |

---

## 2. Inter-Service Authentication

How services authenticate with each other is a critical trust boundary.

### Authentication patterns and risks
| Pattern | Security level | Risks |
|---------|---------------|-------|
| No auth (trust the network) | Very low | Any compromised service can call any other service |
| Shared secret / API key | Low | Key rotation difficult, lateral movement if key leaked |
| Mutual TLS (mTLS) | High | Strong identity, but certificate management is complex |
| JWT with service identity | Medium-High | Stateless verification, but JWT validation must be correct everywhere |
| SPIFFE/SPIRE | High | Automatic identity provisioning, short-lived certificates |
| OAuth2 client credentials | Medium-High | Standard flow, but requires proper scope enforcement |

### What to check
- Are internal services accessible without authentication from the public network?
- Do services validate the identity of calling services?
- Are service-to-service tokens properly scoped (principle of least privilege)?
- Can an external request bypass the API gateway and hit internal services directly?
- Are internal communication channels encrypted (mTLS)?
- Are service credentials rotated regularly?
- Can a compromised service impersonate another service?

---

## 3. API Gateway Security

The API gateway is the perimeter of a microservices system. It must enforce security before requests reach internal services.

### Gateway security responsibilities
| Function | What to check |
|----------|--------------|
| Authentication | All external requests authenticated before routing |
| Authorization | Gateway enforces coarse-grained access control |
| Rate limiting | Per-user and per-endpoint rate limits |
| Input validation | Request size limits, content-type validation, header sanitization |
| TLS termination | Strong TLS configuration, no plaintext fallback |
| CORS | Restrictive CORS policy at gateway level |
| Request routing | No path traversal to internal services, no route injection |
| Response filtering | Sensitive headers stripped, internal errors masked |
| Logging | All requests logged with correlation IDs |

### Gateway bypass attacks
| Attack | How |
|--------|-----|
| Direct service access | Hit internal service IPs/ports directly, bypassing gateway |
| Path traversal | Use `../` or encoded variants to route to unintended services |
| HTTP method override | Use `X-HTTP-Method-Override` to bypass method-based routing |
| Header injection | Inject routing headers (`Host`, `X-Forwarded-For`) to manipulate routing |
| WebSocket bypass | Upgrade to WebSocket to bypass HTTP-level gateway controls |
| Large payload bypass | Send oversized payloads to bypass gateway validation (gateway may truncate, service processes full payload) |

---

## 4. Service Mesh Security

Service meshes (Istio, Linkerd, Consul Connect) add a security layer between services.

### Service mesh security features to verify
| Feature | What to check |
|---------|--------------|
| mTLS | Is mTLS enforced (STRICT mode) or permissive (allows plaintext)? |
| Authorization policies | Are AuthorizationPolicies defined per service? |
| Traffic policies | Is external traffic properly classified and restricted? |
| Certificate management | Are certificates auto-rotated? What's the TTL? |
| Observability | Are security-relevant metrics and traces collected? |
| Egress control | Is outbound traffic restricted and monitored? |
| Rate limiting | Are per-service rate limits configured? |

### Service mesh misconfigurations
| Misconfiguration | Risk |
|-----------------|------|
| mTLS in PERMISSIVE mode | Services accept both encrypted and plaintext traffic |
| Missing AuthorizationPolicies | All authenticated services can reach all other services |
| Overly broad egress rules | Compromised services can exfiltrate data to external hosts |
| Disabled certificate validation | Man-in-the-middle between services |
| Missing sidecar injection | Some pods bypass the mesh entirely |

---

## 5. Data Flow Security

In microservices, data flows across many services and networks. Each hop is a potential exposure point.

### Data flow assessment
| Question | What to look for |
|----------|-----------------|
| Is data encrypted in transit between all services? | Plaintext HTTP between services, missing mTLS |
| Is PII minimized per service? | Services receiving more data than they need |
| Are there data transformation boundaries? | Services stripping sensitive fields before forwarding |
| Is data at rest encrypted per service? | Each service's database independently encrypted |
| Are there data loss prevention controls? | Bulk data export, large response filtering |
| Is data classification applied? | Different handling for public, internal, confidential, restricted data |

### Data leakage patterns in microservices
| Pattern | Risk |
|---------|------|
| Over-fetching between services | Service A requests full user record when it only needs user ID |
| Logging PII in service logs | Distributed logging systems aggregate PII from all services |
| Shared databases between services | Ownership boundary violations, unauthorized data access |
| Cache poisoning across services | Shared cache stores one service's response, served to another |
| Event bus data exposure | Sensitive data in message queues readable by subscribing services |

---

## 6. Event-Driven Security

Many microservices use event-driven patterns (Kafka, RabbitMQ, NATS, SQS/SNS, Redis Pub/Sub).

### Event-driven security checks
| Area | What to check |
|------|--------------|
| Message authentication | Are messages signed or authenticated? Can a rogue service publish? |
| Message encryption | Is sensitive data in messages encrypted? |
| Topic/queue access control | Are subscriptions restricted to authorized services? |
| Message validation | Do consumers validate message schema before processing? |
| Replay protection | Can old messages be replayed to cause duplicate actions? |
| Dead letter handling | Do dead letter queues expose sensitive data? |
| Event sourcing | Is the event log access-controlled? Does it contain PII? |

---

## 7. Distributed System Threats

Microservices introduce distributed system-specific threats that don't exist in monoliths.

### Threat catalog
| Threat | Description | Mitigation |
|--------|------------|------------|
| Service impersonation | Compromised or rogue service pretends to be a legitimate service | mTLS, SPIFFE identities, service mesh AuthorizationPolicies |
| Confused deputy | Service A tricks Service B into performing actions A isn't authorized for | Request-level authorization, not just service-level, propagate user context |
| Fan-out amplification | Single request triggers exponential internal calls (DDoS amplification) | Circuit breakers, rate limiting, bulkheading |
| Data inconsistency exploitation | Exploit eventual consistency windows for double-spending or race conditions | Idempotency, saga patterns, distributed locks |
| Cascading failure abuse | Trigger one service failure that cascades through the system | Circuit breakers, bulkheading, graceful degradation, timeouts |
| Sidecar bypass | Bypass service mesh proxy to access service directly | Enforce mTLS STRICT, drop non-mesh traffic at pod level |
| Config poisoning | Modify shared configuration (Consul, etcd, ConfigMaps) affecting all services | Config access control, config integrity verification, audit logging |
| Secret sprawl | Secrets duplicated across many services, increasing exposure surface | Centralized secret management, dynamic secrets, short-lived credentials |

---

## 8. Service Discovery Security

Service discovery mechanisms (DNS, Consul, Eureka, K8s Services) are trust-critical infrastructure.

### Service discovery risks
| Risk | Description |
|------|------------|
| DNS poisoning | Redirect service traffic to malicious endpoints |
| Registry manipulation | Register rogue service instances in discovery registry |
| Stale entries | Decommissioned services still resolvable, potentially hijackable |
| Information disclosure | Service registry reveals full internal architecture |
| Lack of health validation | Unhealthy or compromised instances receive traffic |

---

## 9. Microservices Security Checklist

```
Perimeter:
[ ] API gateway enforces authentication on all external routes
[ ] Rate limiting per user and per endpoint
[ ] Input validation at gateway level
[ ] No direct access to internal services from public network
[ ] CORS restricted at gateway level

Inter-Service:
[ ] mTLS enforced between all services
[ ] Service-to-service authorization policies defined
[ ] Services authenticate calling service identity
[ ] Service tokens follow least privilege (scoped to needed operations)
[ ] No shared secrets for inter-service auth

Data:
[ ] Data encrypted in transit between all services
[ ] PII minimized per service (each service gets only what it needs)
[ ] No PII in distributed logs (or logs are access-controlled)
[ ] Each service's data store independently access-controlled
[ ] Shared caches don't cross security boundaries

Event Systems:
[ ] Message bus access control per topic/queue
[ ] Sensitive data in messages encrypted
[ ] Consumer validation on message schema
[ ] Replay protection for idempotent operations

Resilience:
[ ] Circuit breakers on all inter-service calls
[ ] Timeouts configured for all external calls
[ ] Bulkheading prevents cascading failures
[ ] Graceful degradation defined per service
[ ] Health checks don't expose sensitive information

Observability:
[ ] Distributed tracing across services
[ ] Security event logging with correlation IDs
[ ] Anomaly detection on inter-service traffic patterns
[ ] Centralized log aggregation with access control
```
