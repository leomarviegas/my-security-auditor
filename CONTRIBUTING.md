# Contributing to my-security-auditor

Thank you for considering a contribution! This skill is most valuable when it reflects diverse security expertise from the community.

## What we welcome

- **New framework references** — regulations, standards, methodologies we don't yet cover
- **Updates to existing references** — keeping content current with new versions (OWASP updates, NIST revisions, new CVSS versions)
- **Bug fixes** — corrections to technical content, broken cross-references, typos
- **Better examples** — concrete, realistic scenarios that improve findings
- **New test techniques** — additions to existing frameworks (e.g., new JWT attacks, new GraphQL abuses)
- **Translations** — particularly for privacy regulation deep-dives
- **Tooling improvements** — scripts for packaging, validation, or testing

## What we generally decline

- Vendor-specific marketing content (we prefer tool-agnostic guidance)
- Content that conflicts with the skill's safety posture (e.g., "how to exploit without authorization")
- Duplicative frameworks that don't add unique value
- Changes that break progressive disclosure (e.g., making SKILL.md 2000 lines)

## How to contribute

### Small changes (typos, corrections, minor additions)

1. Fork the repository
2. Make your change on a feature branch
3. Open a pull request with a clear description
4. Reference any issue your change addresses

### Adding a new framework reference

New framework references are substantial contributions. Before writing, **open an issue** first to discuss:

1. What framework or standard you want to add
2. Why it's valuable (what gap it fills, who benefits)
3. How it relates to existing references
4. Rough outline of sections

Once approved:

1. Follow the structure of existing references in `my-security-auditor/references/frameworks/`
2. Include a Table of Contents
3. Organize with clear numbered sections
4. End with a findings mapping template showing how to annotate findings using this framework
5. Keep each reference under ~1,500 lines (split if needed)
6. Add cross-references to related files
7. Update `SKILL.md` to add your reference to the framework table
8. Update `docs/FRAMEWORKS.md` with a summary entry
9. Add an entry to `CHANGELOG.md` under `[Unreleased]`

### Style guide

**Tone:**
- Direct, professional, technical
- Assume the reader is a competent security practitioner
- Don't hedge with "it might be considered" when you mean "it is"
- Be willing to have opinions (e.g., "use AES-only Kerberos to prevent T1558.003")

**Structure:**
- Short paragraphs over dense blocks
- Use tables for comparative information
- Code blocks for commands, requests, responses
- Checklists for actionable items
- End sections with "findings mapping" examples where relevant

**Framework mappings:**
Every framework reference should support tagging findings with that framework. Include:
- What to tag (OWASP category? CWE? control ID?)
- Template for including in finding reports
- Example findings with mappings

**What to avoid:**
- Marketing-style "this framework is the industry-leading solution for..."
- Vague statements without actionable content ("ensure proper security controls")
- Duplicating content from other references (cross-reference instead)
- Tool-specific tutorials (keep it methodology-focused)

### Testing changes locally

The skill loads when Claude detects relevant triggers. To test changes:

1. **Package the skill:**
   ```bash
   # Requires Anthropic's skill-creator package
   python3 -m scripts.package_skill ./my-security-auditor ./dist/
   ```

2. **Install locally:**
   ```bash
   unzip -o dist/my-security-auditor.skill -d ~/.claude/skills/
   ```

3. **Test activation** by asking Claude to perform a security audit on a test target, or by explicitly mentioning the framework your change relates to

4. **Verify the change** loads correctly and produces the expected guidance

### Pull request checklist

Before submitting:

- [ ] Content technically accurate and up-to-date
- [ ] No claims without support (link to authoritative source where possible)
- [ ] Follows existing file structure and style
- [ ] `SKILL.md` framework table updated (if adding new reference)
- [ ] `docs/FRAMEWORKS.md` updated (if adding new reference)
- [ ] `CHANGELOG.md` updated
- [ ] File stays under ~1,500 lines (split large contributions)
- [ ] Cross-references to related files included
- [ ] No vendor marketing or adversarial content
- [ ] Tested locally with `package_skill.py`

## Issue reporting

### Bug reports

Please include:
- Exact location (file path, line number, or section)
- What is incorrect or outdated
- What it should say instead (if known)
- Source/reference for the correction (where applicable)

Use the bug report template in `.github/ISSUE_TEMPLATE/`.

### Feature requests

For new frameworks or significant additions:
- Use the framework request template
- Describe the gap the addition fills
- Explain who benefits

## Review process

- Pull requests typically receive initial feedback within 1-2 weeks
- Larger additions (new frameworks) may take longer
- All contributions are reviewed for accuracy, style, and fit
- You may be asked to make revisions before merging
- Your contributions will be attributed in the CHANGELOG

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Licensing

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE), the same license as the rest of the project.

## Recognition

Contributors are acknowledged in:
- The `CHANGELOG.md` for each release
- Git commit history (permanent record)
- The `CONTRIBUTORS.md` file (for significant contributions)

## Questions?

Open a [discussion](https://github.com/leomarviegas/my-security-auditor/discussions) or an issue labeled `question`. We're happy to help.

## Attribution for framework content

When contributing content derived from OWASP, MITRE, NIST, or other published standards:
- Link to the original source
- Paraphrase rather than copying verbatim
- Respect the original license (most are permissive but verify)
- Update `NOTICE` if adding a new framework source
