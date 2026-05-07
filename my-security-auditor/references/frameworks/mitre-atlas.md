# MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems

ATLAS is MITRE's knowledge base of adversary tactics and techniques against AI/ML systems, modelled after ATT&CK but specific to ML, generative AI, and AI-enabled applications. Where OWASP LLM Top 10 catalogues vulnerability *classes*, ATLAS catalogues attacker *behaviour* — the tactical lens that lets findings map to detection rules, threat-intel feeds, and adversary emulation playbooks.

Use this reference when the audit target has any of: ML inference endpoints, LLM-powered features, AI agents with tool use, RAG pipelines, fine-tuned models, vector databases, model registries, or AI/ML CI/CD pipelines. Pair it with `ai-llm-security.md` (vulnerability lens), `mitre-attack.md` (enterprise context), and `red-team.md` / `purple-team.md` when the engagement includes adversary emulation.

> **Note on currency:** ATLAS evolves rapidly — new tactics, techniques, case studies, and mitigations are added regularly at https://atlas.mitre.org. The IDs and entries below reflect the publicly documented matrix; verify against the live site before locking technique IDs into report citations. ATLAS releases include a navigator UI, STIX bundles, and the framework can be browsed alongside ATT&CK in MITRE's ATLAS Navigator.

## Table of Contents

1. [How ATLAS relates to ATT&CK, OWASP LLM Top 10, and ML Top 10](#1-how-atlas-relates-to-attck-owasp-llm-top-10-and-ml-top-10)
2. [The ATLAS matrix — tactics](#2-the-atlas-matrix--tactics)
3. [Techniques by tactic](#3-techniques-by-tactic)
4. [Case studies — real-world adversary actions](#4-case-studies--real-world-adversary-actions)
5. [Mitigations](#5-mitigations)
6. [ATLAS-anchored audit checklist](#6-atlas-anchored-audit-checklist)
7. [Cross-mapping: ATLAS ↔ OWASP LLM Top 10 ↔ ML Top 10](#7-cross-mapping-atlas--owasp-llm-top-10--ml-top-10)
8. [Integration with audit phases](#8-integration-with-audit-phases)
9. [Reporting conventions for ATLAS findings](#9-reporting-conventions-for-atlas-findings)
10. [Cross-references](#10-cross-references)

---

## 1. How ATLAS relates to ATT&CK, OWASP LLM Top 10, and ML Top 10

These frameworks overlap but are not redundant. Use all three when the target is AI-heavy.

| Framework | Lens | Strength | Use it for |
|-----------|------|----------|------------|
| **MITRE ATT&CK** | Adversary tactics/techniques against enterprise IT | Mature, broad detection-engineering ecosystem (Sigma rules, Atomic Red Team) | Mapping the *non-AI* parts of an AI compromise (initial access via phishing, lateral movement, exfil) |
| **MITRE ATLAS** | Adversary tactics/techniques specific to AI/ML systems | Captures attacks that ATT&CK doesn't (model evasion, training-data poisoning, prompt injection, model extraction) | Mapping AI-specific behaviour: what the attacker did *to the model or agent* |
| **OWASP LLM Top 10 (2025)** | Vulnerability classes in LLM applications | Developer-friendly, action-oriented, OWASP-style with prevention guidance | Engineer-facing remediation guidance; the *defect* lens |
| **OWASP ML Security Top 10** | Vulnerability classes in ML systems generally (not just LLM) | Covers classical ML attacks (membership inference, model inversion, transfer learning attacks) | Non-LLM ML systems (recommendation, fraud, vision, speech, NLP classifiers) |

**Practical translation:**

A finding that "the application is vulnerable to indirect prompt injection through retrieved web content" is:
- An **OWASP LLM01** vulnerability (defect lens),
- Implemented through **AML.T0051.001 LLM Prompt Injection: Indirect** (behaviour lens),
- Often staged via **AML.T0019 Publish Poisoned Datasets** when the attacker plants the payload upstream.

Reports should carry all three IDs when applicable — defenders use OWASP for fix prioritisation, ATLAS for detection coverage, and ATT&CK for the surrounding kill chain.

---

## 2. The ATLAS matrix — tactics

ATLAS organises adversary behaviour into tactics that mirror ATT&CK Enterprise plus AI-specific ones. The IDs use the `AML.TA00xx` namespace.

| Tactic | ID | What it captures | Closest ATT&CK analogue |
|--------|----|----|---|
| Reconnaissance | AML.TA0002 | Gathering info about the target ML system, model family, training data, research papers | TA0043 (same name) |
| Resource Development | AML.TA0003 | Acquiring or developing capabilities: proxy models, adversarial examples, infra | TA0042 |
| Initial Access | AML.TA0004 | Gaining first foothold (against the *system* hosting the model) | TA0001 |
| ML Model Access | AML.TA0005 | Gaining access to the ML model itself — full weights, inference API, side channels | *(ATLAS-unique)* |
| Execution | AML.TA0006 | Running adversary-controlled code on the system | TA0002 |
| Persistence | AML.TA0007 | Maintaining access (poisoned weights persisting after retraining, backdoored datasets) | TA0003 |
| Privilege Escalation | *(varies by ATLAS version)* | Elevating privileges within the ML system | TA0004 |
| Defense Evasion | AML.TA0011 | Evading ML-based detectors (the ATLAS sense) or evading the security stack around the model | TA0005 |
| Credential Access | *(in newer ATLAS versions)* | Getting credentials to ML registries, training infra, model APIs | TA0006 |
| Discovery | AML.TA0012 | Mapping the ML system: model family, ontology, training data sources | TA0007 |
| Collection | AML.TA0013 | Gathering ML artifacts, training data, telemetry to support the attack | TA0009 |
| ML Attack Staging | AML.TA0001 | Preparing ML-specific attacks: crafting adversarial examples, training proxy models, verifying attack feasibility | *(ATLAS-unique)* |
| Command and Control | *(in newer ATLAS versions)* | Communicating with compromised AI systems / agents | TA0011 |
| Exfiltration | AML.TA0009 | Stealing model weights, training data, system prompts, embedding stores | TA0010 |
| Impact | AML.TA0010 | Final harm: degraded model integrity, denial of ML service, financial harm, reputational harm | TA0040 |

The two **ATLAS-unique tactics** are:

- **AML.TA0005 ML Model Access** — between Initial Access and Execution. Captures cases where attackers don't compromise the host but gain enough model access (inference API, leaked weights) to mount their attack. This is fundamental for ATLAS because many ML attacks require *only* model access, not host compromise.

- **AML.TA0001 ML Attack Staging** — analogous to ATT&CK's Resource Development but specific to building the attack against a given target model. Includes crafting adversarial examples, training a substitute/proxy model, and verifying the attack works before deploying it.

---

## 3. Techniques by tactic

The table below lists representative techniques with their `AML.T00xx` IDs. New techniques are added regularly — confirm the latest list at https://atlas.mitre.org/matrices/ATLAS.

### 3.1 Reconnaissance (AML.TA0002)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0000 | Search for Victim's Publicly Available Research Materials | Has the team published papers, blog posts, talks, or job ads disclosing model architecture, training data, or defences? |
| AML.T0001 | Search for Publicly Available Adversarial Vulnerability Analysis | Has anyone publicly demonstrated attacks on the same model family / dataset? |
| AML.T0006 | Active Scanning | Probing the inference API: rate limits, model fingerprinting, version disclosure |
| AML.T0007 | Search Application Repositories | GitHub, HuggingFace, Docker Hub disclosure — are model artifacts, training scripts, or system prompts public? |

### 3.2 Resource Development (AML.TA0003)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0002 | Acquire Public ML Artifacts | Public model weights / datasets reused without provenance check |
| AML.T0008 | Acquire Infrastructure | Compute for training proxy models or generating large-scale adversarial input |
| AML.T0016 | Obtain Capabilities | Off-the-shelf adversarial-ML tools (Foolbox, ART, CleverHans, TextAttack) |
| AML.T0017 | Develop Capabilities | Building custom attack tooling specific to the target |
| AML.T0019 | Publish Poisoned Datasets | Pre-positioning poisoned data on HuggingFace, Kaggle, GitHub for downstream consumption |
| AML.T0021 | Establish Accounts | Sock-puppet accounts to upload poisoned data, submit poisoned PRs |

### 3.3 Initial Access (AML.TA0004)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0010 | ML Supply Chain Compromise | Compromised pip/PyPI packages, HuggingFace models, data, container images, trained weights |
| AML.T0012 | Valid Accounts | Stolen credentials to model registry, training infra, MLOps platform |
| AML.T0049 | Exploit Public-Facing Application | The host serving the model is exploited via standard web vulnerabilities |
| AML.T0052 | Phishing | ML-team-targeted phishing for registry creds, GitHub access |
| AML.T0053 | LLM Plugin Compromise | Plugins/tools the agent calls become attack vector |

### 3.4 ML Model Access (AML.TA0005) — *ATLAS-unique*

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0040 | ML Model Inference API Access | Black-box query access (the most common access level — all public APIs) |
| AML.T0044 | Full ML Model Access | White-box (weights leaked, on-device deployment, open-weights) |
| AML.T0047 | ML-Enabled Product or Service | Product that wraps the model — testing the wrapper without direct model access |
| AML.T0041 | Physical Environment Access | Sensors, cameras, microphones the ML system reads — physical adversarial patches |

### 3.5 Execution (AML.TA0006)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0050 | Command and Scripting Interpreter | Code execution on the system serving the model (often via insecure deserialisation in pickled models) |
| AML.T0011 | User Execution | Tricked user runs malicious notebook / script |
| AML.T0051 | LLM Prompt Injection | Adversary input causes LLM to execute attacker instructions |
| AML.T0051.000 | LLM Prompt Injection: Direct | User typing the injection (jailbreak-style) |
| AML.T0051.001 | LLM Prompt Injection: Indirect | Payload reaches LLM via retrieved content (web pages, emails, RAG documents) |

### 3.6 Persistence (AML.TA0007)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0018 | Backdoor ML Model | Backdoor trigger embedded during training; model behaves normally except on trigger input |
| AML.T0020 | Poison Training Data | Poisoning that survives across retraining rounds |

### 3.7 Defense Evasion (AML.TA0011)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0015 | Evade ML Model | Crafting input that bypasses an ML-based detector (malware classifier, spam filter, fraud detector, content moderation) |
| AML.T0054 | LLM Jailbreak | Bypassing safety alignment of an LLM (DAN-style, role-play, multi-turn escalation, encoded payloads) |

### 3.8 Discovery (AML.TA0012)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0003 | Discover ML Model Family | Fingerprinting which base model / family is in use (response patterns, tokenisation tells, refusal phrasing) |
| AML.T0004 | Discover ML Model Ontology | Mapping the label space (classification classes, allowed tools, system-prompt-defined personas) |

### 3.9 Collection (AML.TA0013)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0035 | ML Artifact Collection | Gathering models, weights, datasets, configs from the compromised env |
| AML.T0036 | Data from Information Repositories | Internal wikis / notebooks containing training data, prompts, eval sets |
| AML.T0037 | Data from Local System | Caches, logs, on-disk model files |

### 3.10 ML Attack Staging (AML.TA0001) — *ATLAS-unique*

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0005 | Create Proxy ML Model | Train substitute model that approximates the target; use it for white-box attack craft, then transfer |
| AML.T0042 | Verify Attack | Test the adversarial input against the proxy / via API before final deployment |
| AML.T0043 | Craft Adversarial Data | The actual generation of inputs designed to manipulate the model |
| AML.T0043.000 | Craft Adversarial Data: White-Box Optimisation | FGSM, PGD, C&W on known-weights model |
| AML.T0043.001 | Craft Adversarial Data: Black-Box Optimisation | Query-based attacks (HopSkipJump, Square Attack, NES) |
| AML.T0043.002 | Craft Adversarial Data: Black-Box Transfer | Adversarial example crafted on proxy, transferred to target |
| AML.T0043.003 | Craft Adversarial Data: Manual Modification | Hand-crafted text/image perturbations |
| AML.T0043.004 | Craft Adversarial Data: Insert Backdoor Trigger | Adding the agreed trigger pattern to test data |

### 3.11 Exfiltration (AML.TA0009)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0024 | Exfiltration via ML Inference API | Stealing data through the model: model extraction, training-data extraction, embedding inversion |
| AML.T0024.000 | Exfiltration via ML Inference API: Infer Training Data Membership | Membership inference (was this record used to train?) |
| AML.T0024.001 | Exfiltration via ML Inference API: Invert ML Model | Model inversion (reconstruct training inputs from outputs) |
| AML.T0024.002 | Exfiltration via ML Inference API: Extract ML Model | Model extraction (functional clone via queries) |
| AML.T0025 | Exfiltration via Cyber Means | Standard exfil channels (after model/data is collected) |
| AML.T0055 | Unsecured Credentials | API keys, model registry tokens leaked in repos / logs |
| AML.T0056 | Extract LLM System Prompt | Prompt-extraction attacks revealing the deployed system prompt |
| AML.T0057 | LLM Data Leakage | Sensitive content leaks through normal LLM outputs (PII regurgitation, RAG-document leakage) |

### 3.12 Impact (AML.TA0010)

| ID | Technique | Audit relevance |
|----|-----------|-----------------|
| AML.T0029 | Denial of ML Service | Token-flood, slow-prompt, denial-of-wallet (cost-amplification) |
| AML.T0031 | Erode ML Model Integrity | Long-running poisoning to gradually degrade model quality |
| AML.T0034 | Cost Harvesting | Inducing the victim to pay for compute (denial-of-wallet specifically against cloud-billed inference) |
| AML.T0046 | Spamming ML System with Chaff Data | Polluting feedback / monitoring channels |
| AML.T0048 | External Harms | Real-world harm produced by manipulated model output |
| AML.T0048.000 | External Harms: Financial Harm | Fraud enabled by manipulating fraud-detection models |
| AML.T0048.001 | External Harms: Reputational Harm | Brand damage from agent saying harmful things |
| AML.T0048.002 | External Harms: Societal Harm | Mis/disinformation, large-scale manipulation |
| AML.T0048.003 | External Harms: User Harm | Direct harm to individual users (advice causing self-harm, exposure of private info) |
| AML.T0058 | Publish Hallucinated Entities | Slopsquatting — publishing real packages/services matching names that LLMs hallucinate |

---

## 4. Case studies — real-world adversary actions

ATLAS includes ~25+ documented case studies under the `AML.CS00xx` namespace. Use these as audit anchors: ask "could this happen to the target?" for each relevant case.

| ID | Case study | Lessons for the audit |
|----|-----------|------------------------|
| AML.CS0000 | Evasion of Deep Learning Detector for Malware C&C Traffic | Black-box evasion of ML detectors is feasible with limited query budget |
| AML.CS0002 | VirusTotal Poisoning | Adversary uploads samples to influence collective ML detectors — supply-chain poisoning |
| AML.CS0003 | Bypassing Cylance's AI Malware Detection | Researchers demonstrated reliable evasion against a deployed commercial AV using model extraction + crafted byte sequences |
| AML.CS0004 | Camera Hijack Attack on Facial Recognition | Physical adversarial techniques against biometric systems |
| AML.CS0007 | Microsoft Tay Poisoning | Online learning + adversarial users = catastrophic model behaviour drift within hours |
| AML.CS0009 | ProofPoint Evasion | Anti-phishing ML evaded via crafted email patterns |
| AML.CS0010 | Microsoft Edge AI Evasion | Browser AI model evasion through crafted page content |
| AML.CS0011 | Microsoft Azure Service Disruption | DoS against ML service through crafted high-cost queries |
| AML.CS0012 | Compromised PyTorch Dependency Chain | `torchtriton` typosquat distributed via PyTorch nightly — supply-chain compromise of a widely-used ML lib |
| AML.CS0014 | Confusing Antimalware Neural Networks | Universal adversarial perturbation against malware classifiers |
| AML.CS0015 | Achieving Code Execution in MathGPT via Prompt Injection | Indirect prompt injection chained to code execution in an LLM-backed tool |
| AML.CS0017 | ClearviewAI Misconfiguration | Public-bucket exposure of facial recognition source/data — *not* adversarial ML, but an ML-system data breach |
| AML.CS0021 | ChatGPT Plugin Privacy Leak | Plugin design issue exposing user data — relevant to any tool-using agent |
| AML.CS0022 | ChatGPT Package Hallucination | LLM hallucinated a package name, attacker registered it (slopsquatting) |
| AML.CS0027 | Microsoft Tay (revisited) | Tay incident revisited with updated framing |

For each case study, the ATLAS page lists the tactics+techniques used (the "kill chain" view), affected products, mitigations, and primary references. When auditing, walk through the techniques used in each case study against the target — if the same technique is feasible, that's an audit finding even before exploitation is demonstrated.

---

## 5. Mitigations

ATLAS mitigations live under `AML.M00xx`. Map them to findings as remediation guidance and to controls assessment as compensating-control evidence.

| ID | Mitigation | Implementation hints |
|----|-----------|----------------------|
| AML.M0000 | Limit Public Release of Information | Don't publish detailed model cards with architecture/hyperparameters/training-data provenance for sensitive models; review job ads and conference talks |
| AML.M0001 | Limit Model Artifact Release | Don't publish weights for models that are commercially / safety-sensitive; if published, license with restrictions |
| AML.M0002 | Passive ML Output Obfuscation | Return labels not probabilities; round probabilities; hide top-k; truncate logits — defeats query-efficient extraction and inversion |
| AML.M0003 | Model Hardening | Adversarial training, defensive distillation, randomised smoothing, ensembling — provides empirical robustness |
| AML.M0004 | Restrict Number of ML Model Queries | Per-IP / per-account / per-session rate limits; throttle on suspicious query patterns; require billing for high-volume access |
| AML.M0005 | Control Access to ML Models and Data at Rest | Encrypted storage for model weights; IAM scoping on registry; SBOM of ML artifacts |
| AML.M0006 | Use Ensemble Methods | Multiple models voting reduces feasibility of transfer attacks |
| AML.M0007 | Sanitize Training Data | Provenance tracking, anomaly detection, dataset signing, near-duplicate filtering, label-error detection |
| AML.M0008 | Validate ML Model | Pre-deployment evaluation against known adversarial benchmarks (HELM, AdvGLUE, RobustBench); regression on red-team prompts |
| AML.M0009 | Use Multi-Modal Sensors | Defence-in-depth — single sensor evasion doesn't compromise the whole pipeline |
| AML.M0010 | Input Restoration | Pre-processing defences (denoising, quantisation, feature squeezing) |
| AML.M0011 | Restrict Library Loading | Prevent arbitrary code execution via untrusted models / pickled artifacts; use safetensors instead of pickle |
| AML.M0012 | Encrypt Sensitive Information | TLS for inference traffic; encrypted memory / TEEs for high-sensitivity inference |
| AML.M0013 | Code Signing | Sign model artifacts; verify signatures in CI/CD before deployment |
| AML.M0014 | Verify ML Artifacts | Hash-pinning model versions; provenance attestation (SLSA, sigstore) |
| AML.M0015 | Adversarial Input Detection | Runtime detectors that flag adversarial-looking inputs (input statistics, denoising distance, stateful detection) |

Mitigations layer — none alone is sufficient. A robust deployment combines hardened model (M0003), restricted access (M0004, M0005), validated artifacts (M0008, M0013, M0014), runtime detection (M0015), and information hygiene (M0000, M0001).

---

## 6. ATLAS-anchored audit checklist

Use this checklist when the target has any AI/ML surface. Each entry is anchored to one or more ATLAS techniques.

### 6.1 Reconnaissance & Discovery surface

```
[ ] Public model artifacts released only as policy permits (M0001 vs T0002, T0007)
[ ] Job ads / conference talks / blog posts don't disclose training data, eval sets, or defences (M0000 vs T0000)
[ ] No public adversarial vulnerability analysis the team hasn't responded to (T0001)
[ ] Inference API doesn't fingerprint the model family in error messages, headers, or response patterns (T0003)
[ ] Tokenisation / formatting quirks that disclose base model are minimised
[ ] Model registry / HuggingFace org locked down to authenticated read for non-public models (M0005)
```

### 6.2 ML Model Access boundary

```
[ ] Inference API requires authentication (T0040 — black-box query baseline)
[ ] Per-account query budget enforced (M0004)
[ ] Probability outputs not returned to untrusted clients; labels only (M0002 vs T0024.001/.002)
[ ] No top-k logits, perplexities, or attention weights leaked through the API
[ ] Public model weights audit: is open-weights deployment intentional? (T0044)
[ ] On-device / mobile model deployment uses obfuscation + integrity checks
[ ] Physical sensor inputs (camera, mic, IoT) include sanity/sanity-loss filtering (T0041)
```

### 6.3 Supply chain integrity (T0010, T0019, T0058)

```
[ ] All third-party model artifacts (HuggingFace, model zoos) hash-pinned and provenance-checked (M0014)
[ ] safetensors used in place of pickle for all loaded weights (M0011 vs T0050)
[ ] Training datasets pinned by hash; differential check at each retrain
[ ] CI/CD verifies model artifact signatures before deployment (M0013)
[ ] Python dependency pinning + lock files; SBOM generated; CISA KEV checked
[ ] Hallucinated package names monitored — registries notified, namespace-squatting reviewed (T0058)
[ ] Container images from trusted registries; image signing (cosign / Notary v2) verified
```

### 6.4 Training-data integrity (T0019, T0020, T0031)

```
[ ] Training data sources documented with provenance per data card
[ ] Crowdsourced data / user-feedback channels include moderation, throttling, and label-noise detection (M0007)
[ ] Anomaly detection on training data distribution shifts before retrain (M0007 vs T0031)
[ ] Validation set held out from any user-influenced source
[ ] Pre-deployment evaluation against poisoned-data probes (M0008)
[ ] Online-learning pipelines have rollback capability and adversarial-input rate limits (lessons from CS0007 Tay)
```

### 6.5 LLM application security (T0051, T0054, T0056, T0057)

```
[ ] System prompt cannot be exfiltrated via prompt-extraction techniques (T0056) — test with the suite in ai-llm-security.md §4
[ ] Direct prompt injection: adversarial user input cannot escape framing (T0051.000)
[ ] Indirect prompt injection: retrieved content (web, RAG, file uploads) is treated as untrusted; prompt-context separation enforced (T0051.001)
[ ] Jailbreak resistance: tested against current public DAN/role-play/encoded-payload variants (T0054)
[ ] Output sanitisation: model outputs that go to other systems (browsers, code execution, downstream APIs) are validated as untrusted (T0050 chain — see CS0015 MathGPT)
[ ] PII / training-data regurgitation tested with canary tokens (T0057, T0024.000)
[ ] System prompt does not contain secrets, API keys, or sensitive operational details
```

### 6.6 Agent / tool-use security (T0053)

```
[ ] Agent tool/plugin permissions follow least-privilege; per-tool scoping
[ ] Tool definitions do not allow arbitrary URL fetch / file write / shell exec without further authorisation
[ ] Tool outputs treated as untrusted input on next turn (return-to-prompt-injection vector)
[ ] Plugin marketplace / third-party plugins reviewed before enablement (T0053; CS0021)
[ ] Multi-step agent plans subject to user confirmation for high-impact actions
[ ] Agent memory / scratchpad sanitised between sessions and tenants
```

### 6.7 RAG security (T0019, T0051.001)

```
[ ] Document ingestion sanitises hidden prompts (HTML comments, white-on-white text, unicode tricks)
[ ] Vector store access-controlled per tenant; no cross-tenant similarity search
[ ] Document provenance retained and surfaced in answers
[ ] Embedding inversion risk evaluated (CS0008-style) — sensitive content not embedded with weak models
[ ] Retrieval ranking not manipulable by attacker-controlled documents (poisoning)
```

### 6.8 Inference-API abuse (T0029, T0034)

```
[ ] Per-account / per-IP rate limits with tight-budget cap on long-context queries (M0004)
[ ] Cost-aware throttling: token-based limits not just request-count
[ ] Slow-prompt / "denial-of-wallet" patterns detected and blocked
[ ] Streaming endpoints don't allow indefinite hold-open (slowloris-style)
[ ] Concurrent-request caps enforced
[ ] Resource isolation: a single tenant cannot starve others (T0029)
```

### 6.9 Defensive evasion testing (T0015, T0046)

```
[ ] If the system uses ML for security purposes (malware, fraud, spam, content moderation, abuse detection): test for evasion against current public attack tools (Foolbox, ART, TextAttack)
[ ] Per CS0003 (Cylance), CS0014 (anti-malware NN), CS0009 (ProofPoint): black-box evasion budget assumed available to motivated adversary
[ ] Multi-modal sensors / ensembles in place for high-stakes decisions (M0006, M0009)
[ ] Adversarial input detection runtime layer monitored (M0015)
[ ] Model retraining cadence considers concept drift + adversarial drift
```

### 6.10 Impact controls (T0048)

```
[ ] Output guardrails enforce content policies
[ ] Financial-impact actions (transfer, trade, refund, charge) require additional verification beyond LLM judgement (T0048.000)
[ ] Brand-sensitive outputs (anything published) gated by review or strict allowlist (T0048.001)
[ ] User-harm scenarios (mental health, medical, legal advice) trigger appropriate escalation
[ ] PII / private-info exposure paths instrumented and tested (T0048.003)
```

### 6.11 Logging, monitoring, incident response

```
[ ] Inference logs include enough context to retrospectively detect prompt injection / jailbreak attempts
[ ] Anomalous query patterns alerted (high-volume model-extraction-like queries, repeated jailbreak attempts)
[ ] Model output auditing: high-risk outputs sampled and reviewed
[ ] Feedback channels (thumbs-down, flagged outputs) reviewed for adversary-correlated patterns
[ ] Incident-response runbook covers: model compromise, training-data poisoning, prompt-injection-leading-to-RCE, supply-chain artifact compromise
[ ] Adversary-emulation exercises periodically run with ATLAS-anchored TTPs (AML.T0051, T0054, T0024, T0029)
```

---

## 7. Cross-mapping: ATLAS ↔ OWASP LLM Top 10 ↔ ML Top 10

Use this table to add multi-framework citations to findings.

| ATLAS technique | OWASP LLM Top 10 (2025) | OWASP ML Top 10 |
|-----------------|--------------------------|-----------------|
| AML.T0051 LLM Prompt Injection (Direct + Indirect) | LLM01:2025 Prompt Injection | — |
| AML.T0054 LLM Jailbreak | LLM01:2025 Prompt Injection (jailbreak sub-class) | — |
| AML.T0056 Extract LLM System Prompt | LLM07:2025 System Prompt Leakage | — |
| AML.T0057 LLM Data Leakage | LLM02:2025 Sensitive Information Disclosure | ML06 Output Integrity Attack (partial) |
| AML.T0010 ML Supply Chain Compromise | LLM03:2025 Supply Chain | ML07 Transfer Learning Attack |
| AML.T0019 Publish Poisoned Datasets | LLM04:2025 Data and Model Poisoning | ML02 Data Poisoning |
| AML.T0020 Poison Training Data | LLM04:2025 Data and Model Poisoning | ML02 Data Poisoning |
| AML.T0050 Command and Scripting Interpreter (via LLM output) | LLM05:2025 Improper Output Handling | — |
| AML.T0053 LLM Plugin Compromise | LLM06:2025 Excessive Agency (overlapping) | — |
| AML.T0040 ML Model Inference API Access (uncontrolled) | LLM06:2025 Excessive Agency | ML08 Model Skewing (partial) |
| AML.T0024.000 Membership Inference | LLM02:2025 Sensitive Information Disclosure | ML04 Membership Inference Attack |
| AML.T0024.001 Model Inversion | — | ML03 Model Inversion Attack |
| AML.T0024.002 Model Extraction | — | ML05 Model Stealing |
| AML.T0008 Vector / Embedding Weaknesses | LLM08:2025 Vector and Embedding Weaknesses | — |
| AML.T0058 Publish Hallucinated Entities | LLM09:2025 Misinformation (hallucinated package — CS0022) | — |
| AML.T0029 Denial of ML Service | LLM10:2025 Unbounded Consumption | ML09 Output Integrity Attack (DoS variant) |
| AML.T0034 Cost Harvesting | LLM10:2025 Unbounded Consumption | — |
| AML.T0015 Evade ML Model | — | ML01 Input Manipulation Attack |
| AML.T0018 Backdoor ML Model | LLM04:2025 Data and Model Poisoning | ML10 Neural Net Reprogramming |

When writing a finding, cite all three columns where applicable. Example:

> **F-12: Indirect prompt injection via uploaded documents.**
> The agent processes user-uploaded PDFs and treats their contents as instructions.
> An attacker can place hidden instructions in a PDF that, when summarised, cause the agent to invoke its email-send tool and exfiltrate prior conversation context.
>
> - **OWASP LLM:** LLM01:2025 Prompt Injection; LLM06:2025 Excessive Agency
> - **MITRE ATLAS:** AML.T0051.001 LLM Prompt Injection: Indirect → AML.T0053 LLM Plugin Compromise → AML.T0024 Exfiltration via ML Inference API
> - **MITRE ATT&CK:** TA0010 Exfiltration; T1041 Exfiltration Over C2 Channel
> - **OWASP ML:** *(not applicable — LLM-specific)*

---

## 8. Integration with audit phases

**Phase 0 (Scope and Authorization)** — when AI/LLM features are in scope, confirm whether adversary emulation against the model is authorised. Some attacks (model extraction, large-scale evasion) generate distinctive query patterns that may trigger abuse defences; coordinate with the defensive team.

**Phase 0.5 (Codebase Bootstrap)** — when source is accessible, inventory:
- Model artifacts and their loading code (look for `pickle.load` and bare `torch.load` — T0050 risk)
- System prompts and tool/plugin definitions
- RAG / retrieval pipelines and document ingestion
- Training / fine-tuning pipelines and data sources
- Evaluation suites (do they include ATLAS-anchored adversarial probes?)

**Phase 1 (Recon Bootstrap)** — AI surface detection:
- Endpoints matching `/chat`, `/completions`, `/embeddings`, `/agent`, `/v1/messages` etc.
- Streaming response patterns (SSE, chunked) suggest LLM
- Model-version disclosure in headers / response metadata
- Tool/plugin manifests at well-known paths
- WebSocket-backed agent endpoints

**Phase 3 (Security Assessment)** — when AI/LLM is detected:
- Read this file alongside `ai-llm-security.md` (vuln lens) and `mitre-attack.md` (enterprise context).
- Walk the ATLAS-anchored checklist (§6 above) appropriate to the target's AI surface.
- For each finding, prepare ATLAS technique IDs for the Phase 6 report.

**Phase 4 (Attack Chain Analysis)** — chain ATLAS techniques:
- Indirect prompt injection (T0051.001) → tool abuse (T0053) → exfiltration (T0024)
- Supply-chain compromise (T0010) → backdoor model (T0018) → persistent integrity erosion (T0031)
- Inference API access (T0040) → model extraction (T0024.002) → proxy model (T0005) → black-box transfer attack (T0043.002) → evasion (T0015)
- Hallucinated package (T0058) → developer install → execution (T0050) → initial access (T0049 chain)

**Phase 5 (Multi-Model Cross-Review)** — AI findings benefit especially from multi-model review since prompt-injection / jailbreak severity depends on output handling, which is easy to misjudge. Use Gemini/Codex/Qwen as challengers.

**Phase 6 (Final Reporting)** — every AI finding should carry the OWASP LLM + ATLAS technique + ATT&CK technique triple where applicable (see §7 mapping). Include relevant ATLAS case study references when the finding mirrors a documented case.

**Adversary emulation engagements** (when scope includes red team / purple team for AI):
- ATLAS technique IDs are the natural emulation atoms — pick a chain (e.g., T0051.001 → T0053 → T0024) and execute.
- Pair with `purple-team.md` for collaborative validation.
- ATLAS does not currently have an "Atomic Red Team"-equivalent open library, but tools like garak, PromptFoo, NeMo Guardrails, and PyRIT provide programmable test harnesses for many techniques.

---

## 9. Reporting conventions for ATLAS findings

Each AI/ML finding in the report should include:

- **OWASP LLM Top 10 ID** (e.g., LLM01:2025) — the developer-facing vulnerability class
- **ATLAS technique ID(s)** (e.g., AML.T0051.001) — the adversary-behaviour anchor
- **ATT&CK technique ID(s)** when the finding chains into the broader kill chain (e.g., T1041 Exfiltration)
- **Case study reference** when the finding mirrors a documented ATLAS case (e.g., "similar to AML.CS0015 MathGPT")
- **Affected model / pipeline / agent** — be specific: which model version, which RAG pipeline, which tool
- **Required attacker access level** — public-API black-box, authenticated user, supply-chain, insider
- **Mitigation recommendations citing ATLAS mitigations** — `AML.M0004 Restrict Number of ML Model Queries`, etc.

Report structure suggestion for the AI/ML section:

```
## AI / ML Findings

### Findings ranked by severity

[per-finding table with OWASP / ATLAS / ATT&CK columns]

### Attack chains observed or feasible

[diagram or narrative showing technique chains, e.g., T0051.001 → T0053 → T0024]

### ATLAS technique coverage matrix

| Tactic | Techniques tested | Findings | Out-of-scope |
|--------|-------------------|----------|--------------|
| Reconnaissance      | T0000, T0001, T0006, T0007 | F-01 | — |
| ML Model Access     | T0040 | F-04, F-05 | T0044 (no white-box access) |
| Execution           | T0051, T0051.000, T0051.001 | F-08, F-09 | T0050 (out of scope) |
| ...                 | ...   | ...   | ... |

### Mitigation roadmap mapped to ATLAS M-series

[per-mitigation rollout plan]
```

For executive summary, present the AI risk landscape using the ATLAS tactic categories — leaders find the tactical view (what an attacker would *do*) more actionable than a vulnerability list.

---

## 10. Cross-references

- `references/frameworks/ai-llm-security.md` — OWASP LLM Top 10 (2025) + ML Top 10 vulnerability lens; pair with this file for complete AI coverage
- `references/frameworks/mitre-attack.md` — enterprise ATT&CK; chain ATLAS findings into the broader kill chain
- `references/frameworks/red-team.md` — adversary emulation methodology; ATLAS techniques are natural emulation atoms
- `references/frameworks/purple-team.md` — collaborative ATLAS-anchored exercises
- `references/frameworks/blue-team.md` — detection engineering for AI-targeted attacks
- `references/frameworks/code-analysis.md` — review of model loading code (`pickle.load`, `torch.load`), system prompts, tool definitions, RAG pipelines
- `references/frameworks/appsec-testing-methods.md` — formal testing methods; adversarial-ML tools fit under DAST-style runtime testing
- `references/frameworks/saas-security.md` — multi-tenant AI service considerations (cross-tenant prompt leakage, embedding-store isolation)
- `references/frameworks/privacy-compliance.md` — training-data PII / GDPR Art. 22 / DPIA implications
- `references/attack-chains.md` — chain patterns including AI-specific chains
- `references/report-template.md` — finding template that supports OWASP+ATLAS+ATT&CK triple citation

External references:
- ATLAS Matrix: https://atlas.mitre.org/matrices/ATLAS
- ATLAS Navigator: https://mitre-atlas.github.io/atlas-navigator/
- ATLAS GitHub (STIX bundles, data files): https://github.com/mitre-atlas/atlas-data
- ATT&CK Matrix: https://attack.mitre.org
- OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/
- OWASP ML Security Top 10: https://owasp.org/www-project-machine-learning-security-top-10/
