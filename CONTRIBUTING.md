# Contributing to Windows 11 Privacy Toolkit

Thanks for your interest in contributing! This project is a small, focused tool, so keeping changes simple, safe, and well-tested matters more than volume of code.

---

## Ways to Contribute

- **Bug reports** — something behaves unexpectedly, a registry key doesn't stick, a scan result seems wrong
- **Feature ideas** — a new privacy/security setting worth hardening, or a UX improvement to the GUI
- **Pull requests** — bug fixes, new settings, test coverage, documentation

For security vulnerabilities, please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

---

## Before You Start

- Check open [issues](https://github.com/willj4945/windows_privacy/issues) and [pull requests](https://github.com/willj4945/windows_privacy/pulls) to avoid duplicate work.
- For anything larger than a small fix (a new tab, a new settings category, a behavior change), please open an issue first to discuss the approach before writing code.

---

## Development Setup

### Requirements

- Windows 11 (build 22000 or later) — most functions call Windows-specific cmdlets and can't be validated on other platforms
- Administrator privileges (the script self-checks and exits if not elevated)
- Windows PowerShell 5.1 or PowerShell 7+
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) and [Pester 5](https://pester.dev) for local linting/testing

```powershell
git clone https://github.com/willj4945/windows_privacy.git
cd windows_privacy

Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force
```

### Project Layout

| File | Purpose |
| --- | --- |
| `Win11PrivacyToolkit.ps1` | WinForms GUI — tabs, controls, event handlers. Dot-sources the functions file at startup. |
| `Win11PrivacyFunctions.ps1` | All backend logic — registry/service/feature changes, scanning, bloatware removal. No GUI code lives here. |
| `tests\Win11Privacy.Tests.ps1` | Pester unit tests for the functions file |
| `.github\workflows\psscriptanalyzer.yml` | CI: lint (PSScriptAnalyzer) + test (Pester) on every push/PR to `main` |

Keep this separation: GUI code (`Win11PrivacyToolkit.ps1`) should only wire up controls and call functions; the actual system changes belong in `Win11PrivacyFunctions.ps1` so they stay testable in isolation.

---

## Coding Conventions

- **Naming:** PowerShell `Verb-Noun` for functions (e.g. `Disable-Telemetry`, `Enable-NetworkProtection`), matching the existing approved-verb style throughout `Win11PrivacyFunctions.ps1`.
- **Logging:** Any function that changes system state should call `Log "..."` at the end describing what happened, so it shows up in `Win11PrivacyToolkit_Log.txt`.
- **Reversibility:** Prefer changes that can be undone (policy registry keys over destructive edits) and wire new toggles into the Restore Defaults path where applicable.
- **Safety over cleverness:** This tool runs as Administrator against real user machines. Favor explicit, readable code (`Test-Path` checks, `-ErrorAction SilentlyContinue` where failure is expected and non-fatal) over terse one-liners.
- **No unrelated formatting changes** in a PR that's meant to fix one thing — keep diffs focused and reviewable.
- **Comments:** only where the *why* isn't obvious (e.g. a specific registry key chosen to close a known attack vector) — not restating what the code does.

### Adding a new setting

1. Add the backend function to `Win11PrivacyFunctions.ps1` (`Disable-X` / `Enable-X`), with a `Log` call at the end.
2. Add a checkbox/radio control to the relevant tab in `Win11PrivacyToolkit.ps1`, and wire it into `$taskList` in the `Apply` button handler.
3. If the setting is detectable, add it to the Scan tab's scoring logic so the Privacy Score reflects it.
4. Add a Pester test covering the registry/service/feature change.
5. Update the feature table in `README.MD`.

### Adding to the bloatware removal list

The "All Microsoft Store apps" option is deliberately conservative — it only touches Microsoft-published packages and skips a protected list of shell/security/runtime components. If you're proposing changes to that scoping, explain in your PR why a package is safe (or unsafe) to remove; this is one of the more safety-sensitive parts of the codebase.

---

## Testing & Linting

Run both before opening a PR — CI will run them again automatically, but catching issues locally is faster:

```powershell
# Lint
Invoke-ScriptAnalyzer -Path .\Win11PrivacyFunctions.ps1 -Severity Error,Warning
Invoke-ScriptAnalyzer -Path .\Win11PrivacyToolkit.ps1   -Severity Error,Warning

# Tests
Invoke-Pester -Path .\tests -Output Detailed
```

New backend functions should ship with a corresponding Pester test in `tests\Win11Privacy.Tests.ps1` (mocking registry/service calls as the existing tests do).

---

## Submitting a Pull Request

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes, following the conventions above
4. Run lint + tests locally
5. Commit with a clear message describing the *why*, not just the *what*
6. Push to your fork and open a pull request against `main`
7. Fill in what the change does and how you tested it — PSScriptAnalyzer and Pester will also run automatically on the PR

A maintainer will review and may ask for changes before merging. Please be patient — this is maintained on a best-effort basis.

---

## Code of Conduct

Be respectful and constructive. Assume good faith, keep discussion focused on the code, and avoid personal attacks. Reports of abusive behavior can be sent to [willj4945@gmail.com](mailto:willj4945@gmail.com).

---

Thanks again for helping make this tool better!
