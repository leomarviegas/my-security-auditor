# Contributing to my-security-auditor

Thank you for your interest in contributing! This skill benefits from community expertise — new frameworks, TTPs, detection patterns, and corrections are all valuable contributions.

## Ways to contribute

### 1. Report bugs or inaccuracies
- Open a [bug report issue](../../issues/new?template=bug_report.md)
- Include the framework reference, specific section, and what's wrong
- For factual corrections, cite the authoritative source

### 2. Request new frameworks or coverage
- Open a [framework request issue](../../issues/new?template=framework_request.md)
- Explain why the framework matters and for which audit scenarios
- Provide links to authoritative documentation

### 3. Improve existing references
- Add missing TTPs or test scenarios
- Update deprecated information
- Improve examples and code samples
- Fix typos and formatting

### 4. Add new framework references
- Follow the style guide below
- Match the structure of existing framework files
- Include authoritative references

## Contribution workflow

1. **Open an issue first** — discuss significant changes before implementing
2. **Fork the repository**
3. **Create a feature branch:**
   ```bash
   git checkout -b add-framework-xyz
   ```
4. **Make your changes** following the style guide
5. **Test locally:**
   ```bash
   # Validate SKILL.md description length (must be under 1024 chars)
   # Validate references load correctly
   # Test skill installation
   ```
6. **Commit with clear messages:**
   ```bash
   git commit -m "Add framework: XYZ Security Guidelines"
   ```
7. **Open a Pull Request** using the PR template
8. **Respond to review feedback**

## Style guide for framework references

### File naming
- Lowercase with hyphens: `api-security.md`, `cloud-security.md`
- Descriptive but concise
- Match the content focus

### Structure
Every framework reference should have:

```markdown
# Framework Name

Brief introduction — what this covers, when to use it.

## Table of Contents
1. [Overview](#1-overview)
2. [Core concepts](#2-core-concepts)
...

---

## 1. Overview
[Background and context]

## 2. Core concepts
[Key terminology and ideas]

## N. [Topic-specific sections]
[Testing methodology, checklists, examples]

## N+1. [Framework] Checklist
```
[ ] Item 1
[ ] Item 2
```

---

## Mapping [Framework] Findings

### Finding annotation template
```
Framework-specific mappings:
  - [field]: [example]
```

### Common finding patterns
| Finding | Maps to |
|---------|---------|
| Example | Framework category |
```

### Writing style
- **Concrete over abstract** — specific commands, payloads, examples
- **Testable over theoretical** — if it can't be tested, question if it belongs
- **Current** — reference current versions of standards (not old ones)
- **Neutral** — describe what defenders and attackers do, not what they "should"
- **Authoritative links** — link to the original standard, not secondary sources

### Length guidelines
- SKILL.md should stay under 500 lines (orchestrator, not content)
- Framework references can be long (500-1500 lines is typical)
- Single reference should cover one framework or closely related family
- Split if coverage diverges significantly

### Code examples
- Use realistic code, not pseudocode
- Include both vulnerable and fixed versions when relevant
- Language syntax highlighting with triple backticks
- Real command syntax that actually works

### Tables
- Use tables for comparative data
- Keep rows under ~100 characters for readability
- Use consistent formatting across references

## Testing your changes

### Validate the packaged skill
```bash
cd /path/to/repo

# Package using skill-creator tooling
python3 -m scripts.package_skill ./my-security-auditor ./dist/

# Verify it builds without errors
# Validation will flag description > 1024 chars, malformed YAML, etc.
```

### Test in Claude Code
```bash
# Install your modified version
unzip dist/my-security-auditor.skill -d ~/.claude/skills/

# Trigger the skill with test prompts related to your changes
# Verify that your new content loads and is referenced correctly
```

### Review checklist
Before opening a PR, verify:
- [ ] SKILL.md description is under 1024 characters
- [ ] New references are mentioned in SKILL.md framework table
- [ ] New references follow the style guide structure
- [ ] Cross-references to other framework files are valid
- [ ] Authoritative sources are linked
- [ ] Examples work as written
- [ ] No typos or formatting issues
- [ ] CHANGELOG.md updated with your change

## Pull request guidelines

### PR title
Use conventional prefixes:
- `feat:` new feature or framework
- `fix:` bug fix or correction
- `docs:` documentation improvement
- `refactor:` restructuring without behavior change
- `style:` formatting, typos
- `test:` test additions

Examples:
- `feat: Add FedRAMP compliance framework`
- `fix: Correct CVSS v4.0 vector example in api-security.md`
- `docs: Improve installation instructions for team deployments`

### PR description
Include:
- **What** you changed
- **Why** you changed it
- **How** to test the change
- **References** to sources/issues

### Review process
- Maintainer review within 1-2 weeks
- Changes may be requested
- Squash merge is typical for clean history

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Please review and follow it.

## Questions?

- Open a [discussion issue](../../issues/new?template=feature_request.md)
- Security-sensitive issues: see [SECURITY.md](SECURITY.md)

Thank you for contributing!
