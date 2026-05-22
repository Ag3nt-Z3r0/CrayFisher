# Skill 05-C: Responsible Disclosure

## Purpose
Draft a notification email and a GitHub Security Advisory draft for responsibly
reporting a vulnerability to the project maintainers.

## Pre-disclosure checklist
- [ ] Only disclose vulnerabilities with CVSS ≥ 4.0 (MEDIUM or above)
- [ ] Confidence ≥ 0.35
- [ ] Located the repo's SECURITY.md or security contact
- [ ] Report drafted (05-A)

## Locate SECURITY.md
```bash
find <local_path> -name "SECURITY.md" -o -name "SECURITY.txt" | head -5
cat <local_path>/SECURITY.md
```

## Email draft template

File: `reports/<repo-name>/DISCLOSURE_EMAIL.md`

```markdown
Subject: [Security] <vuln type> Vulnerability in <project name> (<file path>)

Hello <project name> Security Team,

I am a security researcher and have discovered a <severity> severity
<vuln type> vulnerability in <project name>.

**Summary**
<one-line summary>

**Severity**: CVSS 3.1 <score> (<severity>)
**Affected File**: `<file path>` (line <line>)

**Description**
<3–5 sentence description>

**Impact**
<concrete attack scenario and damage>

**Remediation**
<recommended fix>

I am happy to provide a full technical report and work with you
on a coordinated disclosure timeline.

Please acknowledge receipt of this report within 7 days.
I will keep this information confidential for 90 days from this date
to allow time for a fix to be released.

Regards,
<name>
```

## GitHub Security Advisory draft template

File: `reports/<repo-name>/GITHUB_ADVISORY.md`

```markdown
# GitHub Security Advisory Draft

## Ecosystem
<npm | PyPI | Go | Maven>

## Package Name
<package name>

## Affected Versions
< <version (latest at analysis time)>

## Patched Version
N/A (unpatched)

## Severity
<CRITICAL | HIGH | MEDIUM | LOW>

## CVSS Vector
`CVSS:3.1/<vector>`

## Description
<vulnerability description>

## Patch
<recommended fix>

## References
- <report URL or PoC>
```

## Post-disclosure timeline log

After disclosing, record the following dates.
- **Disclosure date**: <date>
- **Acknowledgement deadline**: disclosure date + 7 days
- **Public deadline**: disclosure date + 90 days (industry standard)
- **Patch confirmed**: (fill in later)
