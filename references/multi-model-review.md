# Multi-Model Review Protocol

This reference defines how to orchestrate cross-validation of security findings using multiple AI models as specialist reviewers. The goal is to minimize false positives, catch blind spots, and produce findings that survive hostile triage.

## Table of Contents
1. [Why Multi-Model Review](#why-multi-model-review)
2. [Available Tools](#available-tools)
3. [Role Assignments](#role-assignments)
4. [Review Process](#review-process)
5. [Escalation and Tie-Breaking](#escalation-and-tie-breaking)
6. [Documenting Consensus](#documenting-consensus)

---

## Why Multi-Model Review

Single-perspective security analysis has blind spots. Different models have different strengths — some excel at reasoning about exploit plausibility, others at code analysis, others at adversarial thinking. By routing findings through multiple reviewers with different specializations, we:

- Catch false positives before they reach the report
- Identify findings that one model missed but another caught
- Build confidence through independent agreement
- Produce findings with documented consensus — much harder to dismiss

---

## Available Tools

Use whichever of these tools are connected in the current session. Not all will be available every time — adapt based on what's accessible.

### Primary external tools
Check for availability and use when connected:

| Tool | How to check | Best for |
|------|-------------|----------|
| **Gemini MCP** (Ollama) | Check Ollama MCP tools | Broad reasoning, flow analysis, triage language |
| **Codex MCP** | Check available MCP tools | Route/API reasoning, automation logic, reproducibility |
| **Qwen Code MCP** | Check available MCP tools | Practical validation, implementation-level review |
| **Ollama models** | Check `Ollama_Cloud:ollama_list` | Specialist reviewers (see role assignments below) |

### Using Ollama models as reviewers
If Ollama MCP is connected, use `Ollama_Cloud:ollama_chat` or `Ollama_Cloud:ollama_generate` to send findings to specialist models for review. Structure the prompt clearly:

```
You are a [specialist role] reviewing a security finding.

Finding:
[paste the finding details]

Questions:
1. Is this finding valid? Could this be a false positive?
2. Is the severity rating appropriate?
3. Are there compensating controls that would mitigate this?
4. Would a real attacker exploit this? What's the realistic effort?
5. Is the remediation advice correct and sufficient?

Respond with: AGREE, DISAGREE, or PARTIALLY AGREE, followed by your reasoning.
```

### Recommended Ollama models by specialty

**Architecture and trust boundaries:**
- `thesheorans1/glm5-architect` — architectural analysis, trust boundary mapping
- `glm-5:cloud` or `glm-4.7:cloud` — structural security reasoning

**Exploit plausibility and adversarial thinking:**
- `deepseek-v3.1:671b-cloud` or `deepseek-v3.2:cloud` — exploit chain reasoning
- `kimi-k2:1t-cloud` or `kimi-k2.5:cloud` — adversary-style escalation analysis
- `kimi-k2-thinking:cloud` — deep adversarial reasoning

**Precision remediation and false-positive analysis:**
- `thesheorans1/minimax-surgeon` — surgical false-positive reduction
- `minimax-m2.7:cloud` or `minimax-m2.5:cloud` — precision analysis

**Practical validation and reproduction:**
- `thesheorans1/qwen3-implementer` — step-by-step reproduction validation
- `qwen3-coder:480b-cloud` or `qwen3-coder-next:cloud` — code-level verification

**Independent cross-checkers:**
- `mistral-large-3:675b-cloud` — independent broad review
- `nemotron-3-super:cloud` — cross-validation
- `cogito-2.1:671b-cloud` — reasoning-heavy review

**Lightweight secondary reviewers:**
- `gemma3:27b-cloud` — quick sanity check
- `ministral-3:14b-cloud` — fast secondary opinion
- `devstral-2:123b-cloud` — developer-perspective review

**Visual / UI analysis:**
- `qwen3-vl:235b-instruct-cloud` — screenshot and UI state interpretation

**Semantic clustering (optional):**
- `qwen3-embedding:0.6b` — for clustering related findings or evidence

### When tools aren't available
If Ollama or external model tools aren't connected, simulate the multi-perspective review by:
1. Analyzing the finding from multiple explicit perspectives (attacker, defender, false-positive hunter)
2. Documenting each perspective's conclusion
3. Being extra rigorous about false-positive checks
4. Noting in the report that full multi-model review wasn't available

---

## Role Assignments

Each finding should be reviewed from these perspectives. Assign to specific models when available, or simulate when not.

### Required review roles

**1. Primary Analyst** (you, Claude)
- Discovers and documents the initial finding
- Provides evidence and reproduction steps
- Proposes severity and confidence

**2. False-Positive Challenger**
- Best models: `thesheorans1/minimax-surgeon`, `kimi-k2-thinking:cloud`
- Job: Try to prove the finding is NOT a real vulnerability
- Questions to ask:
  - Could this behavior be intentional?
  - Are there compensating controls I'm missing?
  - Am I misunderstanding the application's design?
  - Would this work in the real deployment environment?

**3. Exploit Plausibility Reviewer**
- Best models: `deepseek-v3.1:671b-cloud`, `kimi-k2.5:cloud`
- Job: Evaluate whether the exploit is realistic
- Questions to ask:
  - What's the realistic effort to exploit this?
  - What preconditions does the attacker need?
  - Is there a simpler attack path I'm missing?
  - Would the chain actually work end-to-end?

**4. Remediation Architect**
- Best models: `thesheorans1/glm5-architect`, `qwen3-coder:480b-cloud`
- Job: Validate the proposed fix and suggest improvements
- Questions to ask:
  - Does the fix actually address the root cause?
  - Could the fix introduce new issues?
  - Is there a simpler or more robust approach?
  - Does this align with security best practices for the tech stack?

**5. Independent Cross-Checker**
- Best models: `mistral-large-3:675b-cloud`, `nemotron-3-super:cloud`, `cogito-2.1:671b-cloud`
- Job: Review the full finding without bias from the primary analysis
- Questions to ask:
  - Does the evidence support the conclusion?
  - Is the severity rating justified?
  - Would this finding survive triage in a real bug bounty program?

---

## Review Process

### For every finding:

**Step 1: Primary analysis** (Claude)
- Document the finding with all required fields
- Assign initial severity and confidence

**Step 2: Route to reviewers**
- For Informational/Low: Route to 1 reviewer (false-positive challenger)
- For Medium: Route to 2 reviewers (false-positive challenger + exploit plausibility)
- For High/Critical: Route to at least 3 reviewers (false-positive challenger + exploit plausibility + independent cross-checker)

**Step 3: Collect and synthesize reviews**
- If all reviewers agree → finding stands as-is
- If reviewers suggest severity adjustment → adjust with justification
- If any reviewer identifies a likely false positive → investigate further before including
- If reviewers disagree → escalate (see below)

**Step 4: Final classification**
- Update the finding with reviewer consensus
- Document any disagreements and how they were resolved
- Finalize severity and confidence

---

## Escalation and Tie-Breaking

When reviewers disagree on a finding (especially High/Critical findings), escalate to the strongest available reasoning models.

### Escalation order
1. `kimi-k2.5:cloud` — strong adversarial reasoning
2. `deepseek-v3.2:cloud` — deep exploit analysis
3. `glm-5:cloud` — architectural perspective

### Escalation prompt
```
Two security reviewers disagree on this finding:

Finding: [details]

Reviewer A says: [AGREE/DISAGREE + reasoning]
Reviewer B says: [AGREE/DISAGREE + reasoning]

Please resolve this disagreement. Consider:
1. Is the finding valid?
2. What is the correct severity?
3. Which reviewer's reasoning is stronger and why?

Provide your verdict with detailed justification.
```

### If escalation models also disagree
- Downgrade confidence to "Needs manual validation"
- Include all perspectives in the report
- Flag for human review
- Do NOT drop the finding entirely — let the human decide

---

## Documenting Consensus

Every finding in the final report must include a reviewer consensus section.

### Consensus documentation format
```
Reviewer consensus:
- Primary analyst (Claude): [verdict + key reasoning]
- False-positive challenger ([model name]): [AGREE/DISAGREE + key reasoning]
- Exploit plausibility ([model name]): [AGREE/DISAGREE + key reasoning]
- Independent reviewer ([model name]): [AGREE/DISAGREE + key reasoning]
- Escalation ([model name], if needed): [verdict + reasoning]
- Final verdict: [Confirmed / Downgraded to X / Flagged for manual review]
```

### Model review ledger
At the end of the report, include a summary ledger:

| Finding | Proposer | Challengers | Tie-break | Final Verdict |
|---------|----------|-------------|-----------|---------------|
| F-001 | Claude | minimax-surgeon ✓, kimi-k2.5 ✓ | — | Confirmed High |
| F-002 | Claude | minimax-surgeon ✗, deepseek ✓ | glm-5 ✓ | Confirmed Medium |
| F-003 | Claude | minimax-surgeon ✗, kimi-k2.5 ✗ | — | Dropped (false positive) |

Legend: ✓ = agrees with finding, ✗ = disagrees with finding
