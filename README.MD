# 🛡️ Windows 11 Privacy Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-%230078D7.svg?style=for-the-badge&logo=powershell&logoColor=white)
![Windows 11](https://img.shields.io/badge/Windows%2011-0078D6?style=for-the-badge&logo=windows11&logoColor=white)
![CI](https://img.shields.io/github/actions/workflow/status/willj4945/windows_privacy/psscriptanalyzer.yml?label=CI&style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> **Windows 11 Privacy Toolkit** is a GUI-based PowerShell utility that helps users harden their privacy and security on Windows 11 — with no coding required. Changes are applied selectively via checkboxes, logged to disk, and reversible via a built-in restore point.

---

## ✨ Features

| Feature | Description |
| --- | --- |
| 🖥️ **WinForms GUI** | Tabbed interface — no command-line knowledge required |
| 📊 **Privacy Scan & Score** | Live scan of your current system against all 18 settings below, with a percentage score and rating — rescans automatically after you apply changes |
| 🔒 **Privacy hardening** | Disable telemetry, ads, tracking, Recall, Cortana, and Bing |
| 📢 **Ad & content controls** | Block suggested apps, lock screen ads, and tailored experiences |
| 🛡️ **Security hardening** | Disable SMBv1, enable Network Protection and Controlled Folder Access, enforce UAC, block AutoRun |
| 🗑️ **Debloating** | Remove common bloatware or all non-essential Microsoft Store apps |
| ♻️ **Safe & reversible** | Creates a system restore point before applying changes; includes a Restore Defaults action |
| 📋 **Full audit log** | Every change is timestamped and written to `Documents\Win11PrivacyToolkit_Log.txt` |
| ✅ **CI linting** | PSScriptAnalyzer runs on every push and pull request |

---

## 🧩 What It Does

### Scan Tab

Opens automatically when the app launches and shows your current Privacy Score — the percentage of the 18 settings below that are already hardened, with a color-coded rating (Excellent / Good / Fair / Needs Attention). Click **Run Scan** any time, or apply changes on the other tabs and the score refreshes automatically so you can see it improve.

### Privacy Tab

| Setting | Action |
| --- | --- |
| Telemetry & Data Collection | Disables `DiagTrack`, `dmwappushservice`, related scheduled tasks, and `AllowTelemetry` registry keys |
| Advertising ID | Turns off the per-user advertising identifier |
| Location Services | Disables the Windows location service |
| Activity History | Stops local collection and cloud upload of activity data |
| Windows Recall | Disables the AI screenshot indexing feature via policy registry keys |
| Cortana & Bing Search | Removes Bing web results and Cortana from the Start Menu search box |
| Suggested Apps & Promotions | Stops silent installation of promoted apps and Start Menu ads |
| Lock Screen Spotlight & Ads | Disables rotating lock screen images and overlay promotions |
| Tailored Experiences | Disables diagnostic-data-based personalization and Feedback Hub prompts |

### Services Tab

| Setting | Action |
| --- | --- |
| OneDrive Integration | Disables OneDrive file sync policy and stops the process |
| Background Apps | Globally disables background access for all applications |
| Edge Sync & Telemetry | Disables Edge profile sync and metrics reporting via policy |

### Security Tab

| Setting | Action |
| --- | --- |
| Disable SMBv1 | Removes the SMB1Protocol Windows feature and disables it via registry — closes the WannaCry attack vector |
| Enable Network Protection | Activates Defender Network Protection to block connections to malicious domains and IPs |
| Enable Controlled Folder Access | Activates ransomware protection for common user folders |
| Enforce UAC Maximum | Sets UAC to require credential entry on a secure desktop for all admin operations |
| Disable AutoRun | Blocks AutoRun for all drive types, preventing USB-based malware execution |

### Bloatware Tab

| Option | Action |
| --- | --- |
| Skip | No app removal |
| Common bloatware | Removes Xbox, Teams (consumer), News, Clipchamp, YourPhone, Feedback Hub, BingWeather, Game Bar, and more |
| All Microsoft Store apps | Removes every Microsoft Store app except Windows Store, Desktop App Installer, and Calculator |

---

## 🚀 Getting Started

### Requirements

- Windows 11 (build 22000 or later)
- Administrator privileges
- Windows PowerShell 5.1 or PowerShell 7+

### Installation

#### 1. Clone the repository

```powershell
git clone https://github.com/willj4945/windows_privacy.git
cd windows_privacy
```

> **Note:** Both `Win11PrivacyToolkit.ps1` and `Win11PrivacyFunctions.ps1` must remain in the same directory. The main script dot-sources the functions file at startup.

#### 2. Allow script execution (current session only)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

#### 3. Run the toolkit

```powershell
.\Win11PrivacyToolkit.ps1
```

The GUI will open automatically. You must run as Administrator — the script will prompt you if it detects insufficient privileges.

---

## 🧭 Usage

1. On launch, the **Scan** tab shows your current Privacy Score
2. Click **Create Restore Point** before making any changes (strongly recommended)
3. Select the **Privacy**, **Services**, **Security**, or **Bloatware** tab
4. Check or uncheck the settings you want to apply
5. Click **Apply Selected** — a progress bar tracks each operation, then the Scan tab reopens with your updated score
6. Restart when prompted for all changes to take effect

All applied changes are appended to:

```text
C:\Users\<YourUser>\Documents\Win11PrivacyToolkit_Log.txt
```

To undo registry and service changes, click **Restore Defaults** or roll back via the system restore point created in step 1.

---

## 🔧 CI / Code Quality

Every push and pull request runs two jobs via GitHub Actions:

| Job | Tool | What it checks |
| --- | --- | --- |
| lint | [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) | `Error` and `Warning` findings across both `.ps1` files |
| test | [Pester 5](https://pester.dev) | Unit tests for all backend functions (registry paths, values, service calls) |

To run the checks locally:

```powershell
# Lint
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path .\Win11PrivacyFunctions.ps1 -Severity Error,Warning
Invoke-ScriptAnalyzer -Path .\Win11PrivacyToolkit.ps1   -Severity Error,Warning

# Tests
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force
Invoke-Pester -Path .\tests -Output Detailed
```

---

## ⚠️ Disclaimer

> **Use at your own risk.**
> This script modifies Windows registry values, services, and optional features. While every option has been tested for safety, results may vary depending on your Windows build and configuration.
> Always create a restore point before applying changes — the toolkit makes this easy with the button at the top of the window.

---

## 🤝 Contributing

Pull requests and feature ideas are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m "Add my feature"`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a pull request — PSScriptAnalyzer will run automatically on the PR

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
You are free to use, modify, and distribute this script with attribution.

---

## ⭐ Support the Project

- Give the repo a **⭐ Star** on GitHub
- Share it with others who value privacy
- Open an issue or PR with ideas for new settings

---

**Author:** Will Johnson · [github.com/willj4945](https://github.com/willj4945)

---

> *"Privacy is not about hiding something wrong — it's about protecting something right."*
> — Edward Snowden
