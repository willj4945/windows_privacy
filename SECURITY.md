# Security Policy

Windows 11 Privacy Toolkit modifies registry values, services, and optional Windows features while running with Administrator privileges. Because of that, security issues in this project can have real impact on a user's machine, and we take reports seriously.

---

## Supported Versions

Only the latest code on the `main` branch is supported with security fixes. There are no long-term maintenance branches.

| Version | Supported |
| --- | --- |
| `main` (latest) | :white_check_mark: |
| Older commits / forks | :x: |

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately using one of these methods:

1. **Preferred:** [GitHub Security Advisories](https://github.com/willj4945/windows_privacy/security/advisories/new) — lets you submit a private report directly from the repository.
2. **Email:** [willj4945@gmail.com](mailto:willj4945@gmail.com) — include "SECURITY" in the subject line.

When reporting, please include as much of the following as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce, including the affected function(s), registry key(s), or feature(s)
- Your Windows build/version and PowerShell version
- Any relevant log output from `Win11PrivacyToolkit_Log.txt`

### What to expect

- **Acknowledgment** within a few days of your report.
- An assessment of the issue and, if confirmed, a plan for a fix.
- Credit in the release notes once a fix ships, unless you'd prefer to remain anonymous.

Please give us a reasonable amount of time to investigate and patch before disclosing the issue publicly.

---

## Scope

This project is a client-side PowerShell/WinForms tool with no network service, backend, or authentication layer. Reports in scope include (but aren't limited to):

- Code that could cause unintended, undisclosed, or irreversible changes to a system (e.g. removing a protected app, disabling something the UI doesn't say it will)
- Privilege escalation beyond the Administrator context the tool already requires
- Command/argument injection in any `reg add`, service, or process invocation
- Unsafe handling of paths or input that could be leveraged by a malicious local actor
- Logic errors in the "All Microsoft Store apps" removal scoping (e.g. the protected-package list, publisher check) that could cause a critical system component to be removed

Generally **out of scope**:

- Issues that require the attacker to already have Administrator access and are simply "the tool does what an admin script does" (e.g. the fact that it disables telemetry — that's the intended feature)
- Social engineering or physical access scenarios
- Findings from automated scanners without a demonstrated, practical impact

If you're unsure whether something is in scope, report it anyway — we'd rather triage a false positive than miss a real issue.
