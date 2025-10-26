<#
.SYNOPSIS
Windows 11 Privacy Toolkit
Author: You
Description: Interactive menu-based script to help users disable telemetry, ads, tracking, and bloatware safely.
Version: 1.0
#>

# --- Requires Administrator Privileges ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "`n[!] Please run this script as Administrator.`n" -ForegroundColor Red
    Pause
    exit
}

# --- Global Config ---
$LogFile = "$env:USERPROFILE\Documents\Win11PrivacyToolkit_Log.txt"
$Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"=== Win11PrivacyToolkit Run @ $Time ===" | Out-File $LogFile -Append

function Log($msg) {
    "$((Get-Date).ToString('HH:mm:ss')) - $msg" | Out-File $LogFile -Append
}

function Pause-Key {
    Write-Host "`nPress any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

# --- Utility: Create Restore Point ---
function Create-RestorePoint {
    Write-Host "`nCreating a system restore point..." -ForegroundColor Yellow
    try {
        Checkpoint-Computer -Description "Pre-PrivacyToolkit" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "Restore point created successfully." -ForegroundColor Green
        Log "Restore point created."
    } catch {
        Write-Host "Failed to create restore point." -ForegroundColor Red
        Log "Failed to create restore point: $_"
    }
}

# --- Privacy Tweaks Functions ---
function Disable-Telemetry {
    Write-Host "`nDisabling Telemetry..." -ForegroundColor Cyan
    $keys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    )
    foreach ($key in $keys) {
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -Path $key -Name "AllowTelemetry" -Value 0 -Type DWord
    }
    Stop-Service "DiagTrack" -ErrorAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
    Log "Telemetry disabled."
}

function Disable-Advertising {
    Write-Host "`nDisabling Advertising ID..." -ForegroundColor Cyan
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
    Log "Advertising ID disabled."
}

function Disable-Location {
    Write-Host "`nDisabling Location Services..." -ForegroundColor Cyan
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 0 /f | Out-Null
    Log "Location Services disabled."
}

function Disable-ActivityHistory {
    Write-Host "`nDisabling Activity History..." -ForegroundColor Cyan
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f | Out-Null
    Log "Activity History disabled."
}

function Disable-OneDrive {
    Write-Host "`nDisabling OneDrive Integration..." -ForegroundColor Cyan
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSync /t REG_DWORD /d 1 /f | Out-Null
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    Log "OneDrive disabled."
}

function Disable-BackgroundApps {
    Write-Host "`nDisabling background apps..." -ForegroundColor Cyan
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f | Out-Null
    Log "Background apps disabled."
}

function Debloat-Apps {
    Write-Host "`nSelect categories of apps to remove:`n"
    Write-Host "1) Remove common bloatware (tips, news, xbox, music, etc.)"
    Write-Host "2) Remove *all* Microsoft Store apps (except essential ones)"
    Write-Host "3) Cancel"
    $choice = Read-Host "Enter choice (1-3)"
    switch ($choice) {
        1 {
            $apps = @(
                "Microsoft.XboxApp","Microsoft.GetHelp","Microsoft.Getstarted",
                "Microsoft.Microsoft3DViewer","Microsoft.MicrosoftSolitaireCollection",
                "Microsoft.ZuneMusic","Microsoft.ZuneVideo","Microsoft.BingNews",
                "Microsoft.MicrosoftStickyNotes","Microsoft.People"
            )
        }
        2 {
            $apps = (Get-AppxPackage -AllUsers | Where-Object { $_.Name -notmatch "Microsoft.WindowsStore|Microsoft.DesktopAppInstaller|Microsoft.WindowsCalculator" }).Name
        }
        default { return }
    }

    foreach ($app in $apps) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Log "Removed app: $app"
    }

    Write-Host "`nSelected apps removed." -ForegroundColor Green
}

function Disable-EdgeSync {
    Write-Host "`nDisabling Edge sync & telemetry..." -ForegroundColor Cyan
    $edgeKeys = "HKLM\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgeKeys)) { New-Item $edgeKeys -Force | Out-Null }
    Set-ItemProperty -Path $edgeKeys -Name "SyncDisabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $edgeKeys -Name "MetricsReportingEnabled" -Value 0 -Type DWord
    Log "Edge telemetry disabled."
}

function Restore-Defaults {
    Write-Host "`nRestoring Windows default settings (partial)..." -ForegroundColor Yellow
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Basic defaults restored. A reboot is recommended." -ForegroundColor Green
    Log "Restored defaults."
}

# --- Main Menu ---
function Show-Menu {
    Clear-Host
    Write-Host "==============================="
    Write-Host "   WINDOWS 11 PRIVACY TOOLKIT  "
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "1) Create System Restore Point"
    Write-Host "2) Disable Telemetry & Data Collection"
    Write-Host "3) Disable Advertising ID"
    Write-Host "4) Disable Location Services"
    Write-Host "5) Disable Activity History"
    Write-Host "6) Disable OneDrive Integration"
    Write-Host "7) Disable Background Apps"
    Write-Host "8) Disable Edge Sync & Telemetry"
    Write-Host "9) Remove Bloatware Apps"
    Write-Host "10) Restore Defaults"
    Write-Host "11) Exit"
}

do {
    Show-Menu
    $opt = Read-Host "`nSelect an option (1-11)"
    switch ($opt) {
        1 { Create-RestorePoint }
        2 { Disable-Telemetry }
        3 { Disable-Advertising }
        4 { Disable-Location }
        5 { Disable-ActivityHistory }
        6 { Disable-OneDrive }
        7 { Disable-BackgroundApps }
        8 { Disable-EdgeSync }
        9 { Debloat-Apps }
        10 { Restore-Defaults }
        11 { Write-Host "Goodbye!" -ForegroundColor Yellow; break }
        default { Write-Host "Invalid choice." -ForegroundColor Red }
    }
    Pause-Key
} while ($opt -ne 11)

Write-Host "`nAll operations completed. Log saved at:`n$LogFile" -ForegroundColor Cyan
