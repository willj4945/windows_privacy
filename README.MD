# 🛡️ Windows 11 Privacy Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-%230078D7.svg?style=for-the-badge&logo=powershell&logoColor=white)
![Windows 11](https://img.shields.io/badge/Windows%2011-0078D6?style=for-the-badge&logo=windows11&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> **Windows 11 Privacy Toolkit** is an interactive PowerShell utility designed to help users take control of their privacy and reduce data collection, tracking, and system bloat in Windows 11 — safely and transparently.

---

## ⚙️ Features

✅ **Menu-based interactive interface** – No coding required. Navigate through an intuitive text-based menu.  
✅ **Safe privacy hardening** – Disable telemetry, ads, tracking, location, and sync services.  
✅ **App debloating** – Remove unwanted default apps easily (with categories and safety filters).  
✅ **System Restore Point** – Automatically creates a restore point before making changes.  
✅ **Edge and OneDrive control** – Disable telemetry and integration.  
✅ **Logging & transparency** – Every change is logged for audit and rollback.  
✅ **Reversible** – Includes an option to restore default Windows settings.  

---

## 🧩 What It Does

The toolkit targets key privacy and data collection areas in Windows 11:

| Category | Actions Performed |
|-----------|------------------|
| **Telemetry & Diagnostics** | Disables Microsoft telemetry and diagnostics tracking services |
| **Advertising ID** | Turns off ad tracking and targeted experiences |
| **Location Services** | Disables location-based tracking |
| **Activity History** | Stops activity collection and cloud upload |
| **OneDrive Integration** | Disables OneDrive sync and startup integration |
| **Background Apps** | Disables non-essential background apps |
| **Edge Sync & Metrics** | Disables Edge browser sync and telemetry |
| **Default Apps / Bloatware** | Removes unnecessary Microsoft Store and system apps |
| **Restore Defaults** | Reverts most changes to Windows defaults |

---

## 🚀 Getting Started

### 🔧 Requirements
- Windows 11 (build 22000 or later)
- Administrator privileges
- PowerShell 5.1 or PowerShell 7+

---

### 📥 Installation

#### 1. Clone the repository
```bash
git clone https://github.com/<yourusername>/Win11PrivacyToolkit.git
cd Win11PrivacyToolkit
````

#### 2. Allow script execution

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

#### 3. Run the toolkit

```powershell
.\Win11PrivacyToolkit.ps1
```

---

## 🧭 Usage

The script will launch an **interactive menu** like this:

```
===============================
   WINDOWS 11 PRIVACY TOOLKIT
===============================
1) Create System Restore Point
2) Disable Telemetry & Data Collection
3) Disable Advertising ID
4) Disable Location Services
5) Disable Activity History
6) Disable OneDrive Integration
7) Disable Background Apps
8) Disable Edge Sync & Telemetry
9) Remove Bloatware Apps
10) Restore Defaults
11) Exit
```

Use the numbers to select what you’d like to perform.
All changes are logged at:

```
C:\Users\<YourUser>\Documents\Win11PrivacyToolkit_Log.txt
```

---

## 🛠️ Advanced Options

### 🪟 App Removal (Debloat)

* **Option 1:** Removes common bloatware (Tips, Xbox, News, etc.)
* **Option 2:** Removes *all* Microsoft Store apps except core essentials

### 🧩 Logging

Every change is appended to:

```
Documents\Win11PrivacyToolkit_Log.txt
```

### ♻️ Restoring Defaults

Select **Option 10** to revert most registry and service modifications.
You can also use your system restore point if needed.

---

## ⚠️ Disclaimer

> **Use at your own risk.**
> This script modifies Windows settings and registry values. While every step has been tested for safety, results may vary depending on your Windows configuration.
> Always create a restore point (the toolkit offers this option by default) before making changes.

---

## 🤝 Contributing

Pull requests and feature ideas are welcome!
If you have suggestions or improvements:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m "Add my feature"`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 💡 Planned Features

* [ ] Arrow-key or checkbox-based TUI (with `Terminal.Gui` or `Out-GridView`)
* [ ] Dark/Light theme modes
* [ ] Advanced telemetry rollback system
* [ ] Optional integration with **O&O ShutUp10++ CLI**
* [ ] “Safe mode” and “Expert mode” presets

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
You are free to use, modify, and distribute this script with attribution.

---

## ⭐ Support the Project

If you find this toolkit useful:

* Give this repo a **⭐ Star** on GitHub
* Share it with others who value privacy
* Contribute ideas or improvements

---

## 📬 Contact

**Author:** Will Johnson
**GitHub:** https://github.com/willj4945
---

> “Privacy is not about hiding something wrong — it’s about protecting something right.”
>
> — Edward Snowden
