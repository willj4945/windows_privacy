<#
.SYNOPSIS
Windows 11 Privacy Toolkit
Original Author: Will Johnson https://github.com/willj4945
Description: GUI-based tool to help users disable telemetry, ads, tracking, bloatware, and harden security.
Version: 3.0
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Requires Administrator Privileges ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    [System.Windows.Forms.MessageBox]::Show(
        "Please run this script as Administrator.",
        "Administrator Required",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    exit
}

# --- Global Config ---
$LogFile = "$env:USERPROFILE\Documents\Win11PrivacyToolkit_Log.txt"
"=== Win11PrivacyToolkit Run @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $LogFile -Append

function Log($msg) {
    "$((Get-Date).ToString('HH:mm:ss')) - $msg" | Out-File $LogFile -Append
}

# --- Utility ---
function New-RestorePoint {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    try {
        Checkpoint-Computer -Description "Pre-PrivacyToolkit" -RestorePointType "MODIFY_SETTINGS"
        Log "Restore point created."
        return $true
    } catch {
        Log "Failed to create restore point: $_"
        return $false
    }
}

# --- Privacy: Tracking & Data Collection ---
function Disable-Telemetry {
    $keys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
    )
    foreach ($key in $keys) {
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -Path $key -Name "AllowTelemetry" -Value 0 -Type DWord
    }

    foreach ($svc in @("DiagTrack", "dmwappushservice")) {
        Stop-Service $svc -ErrorAction SilentlyContinue
        Set-Service  $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }

    $tasks = @(
        @{ Path = "\Microsoft\Windows\Application Experience\";                    Name = "Microsoft Compatibility Appraiser" },
        @{ Path = "\Microsoft\Windows\Application Experience\";                    Name = "ProgramDataUpdater" },
        @{ Path = "\Microsoft\Windows\Autochk\";                                   Name = "Proxy" },
        @{ Path = "\Microsoft\Windows\Customer Experience Improvement Program\";   Name = "Consolidator" },
        @{ Path = "\Microsoft\Windows\Customer Experience Improvement Program\";   Name = "UsbCeip" },
        @{ Path = "\Microsoft\Windows\DiskDiagnostic\";                            Name = "Microsoft-Windows-DiskDiagnosticDataCollector" }
    )
    foreach ($t in $tasks) {
        Disable-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction SilentlyContinue | Out-Null
    }

    Log "Telemetry disabled (registry, services, scheduled tasks)."
}

function Disable-Advertising {
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
    Log "Advertising ID disabled."
}

function Disable-Location {
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 0 /f | Out-Null
    Log "Location Services disabled."
}

function Disable-ActivityHistory {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities  /t REG_DWORD /d 0 /f | Out-Null
    Log "Activity History disabled."
}

function Disable-Recall {
    foreach ($hive in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
                         'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI')) {
        if (-not (Test-Path $hive)) { New-Item -Path $hive -Force | Out-Null }
        Set-ItemProperty -Path $hive -Name 'DisableAIDataAnalysis' -Value 1 -Type DWord
    }
    Log "Windows Recall disabled."
}

function Disable-CortanaAndBingSearch {
    $searchPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
    if (-not (Test-Path $searchPolicy)) { New-Item -Path $searchPolicy -Force | Out-Null }
    Set-ItemProperty -Path $searchPolicy -Name 'AllowCortana'          -Value 0 -Type DWord
    Set-ItemProperty -Path $searchPolicy -Name 'AllowCortanaAboveLock' -Value 0 -Type DWord
    Set-ItemProperty -Path $searchPolicy -Name 'DisableWebSearch'       -Value 1 -Type DWord

    $userSearch = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
    if (-not (Test-Path $userSearch)) { New-Item -Path $userSearch -Force | Out-Null }
    Set-ItemProperty -Path $userSearch -Name 'BingSearchEnabled' -Value 0 -Type DWord
    Set-ItemProperty -Path $userSearch -Name 'CortanaConsent'    -Value 0 -Type DWord
    Log "Cortana and Bing Search disabled."
}

# --- Privacy: Suggested Content & Ads ---
function Disable-SuggestedContent {
    $cdm = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    if (-not (Test-Path $cdm)) { New-Item -Path $cdm -Force | Out-Null }
    Set-ItemProperty -Path $cdm -Name 'SilentInstalledAppsEnabled'      -Value 0 -Type DWord
    Set-ItemProperty -Path $cdm -Name 'SubscribedContent-338388Enabled' -Value 0 -Type DWord
    Set-ItemProperty -Path $cdm -Name 'SystemPaneSuggestionsEnabled'    -Value 0 -Type DWord
    Log "Suggested apps and Start Menu promotions disabled."
}

function Disable-LockScreenAd {
    $cdm = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    if (-not (Test-Path $cdm)) { New-Item -Path $cdm -Force | Out-Null }
    Set-ItemProperty -Path $cdm -Name 'RotatingLockScreenEnabled'        -Value 0 -Type DWord
    Set-ItemProperty -Path $cdm -Name 'RotatingLockScreenOverlayEnabled' -Value 0 -Type DWord
    Set-ItemProperty -Path $cdm -Name 'SubscribedContent-338387Enabled'  -Value 0 -Type DWord
    Log "Lock screen Spotlight and ads disabled."
}

function Disable-TailoredExperience {
    $privKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy'
    if (-not (Test-Path $privKey)) { New-Item -Path $privKey -Force | Out-Null }
    Set-ItemProperty -Path $privKey -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Value 0 -Type DWord

    $siuf = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules'
    if (-not (Test-Path $siuf)) { New-Item -Path $siuf -Force | Out-Null }
    Set-ItemProperty -Path $siuf -Name 'NumberOfSIUFInPeriod' -Value 0 -Type DWord

    $cdm = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    if (Test-Path $cdm) {
        Set-ItemProperty -Path $cdm -Name 'SubscribedContent-338389Enabled' -Value 0 -Type DWord -ErrorAction SilentlyContinue
    }
    Log "Tailored experiences and feedback prompts disabled."
}

# --- Microsoft Services ---
function Disable-OneDrive {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSync /t REG_DWORD /d 1 /f | Out-Null
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    Log "OneDrive disabled."
}

function Disable-BackgroundApp {
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f | Out-Null
    Log "Background apps disabled."
}

function Disable-EdgeSync {
    $edgePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    if (-not (Test-Path $edgePath)) { New-Item $edgePath -Force | Out-Null }
    Set-ItemProperty -Path $edgePath -Name "SyncDisabled"            -Value 1 -Type DWord
    Set-ItemProperty -Path $edgePath -Name "MetricsReportingEnabled" -Value 0 -Type DWord
    Log "Edge sync and telemetry disabled."
}

# --- Security Hardening ---
function Disable-Smb1Protocol {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'SMB1' -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Log "SMBv1 disabled."
}

function Enable-NetworkProtection {
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
    Log "Network Protection enabled."
}

function Enable-ControlledFolderAccess {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Log "Controlled Folder Access (ransomware protection) enabled."
}

function Set-UacMax {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-ItemProperty -Path $uacKey -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord
    Set-ItemProperty -Path $uacKey -Name 'PromptOnSecureDesktop'      -Value 1 -Type DWord
    Log "UAC set to maximum (credential prompt on secure desktop)."
}

function Disable-AutoRun {
    $explorerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if (-not (Test-Path $explorerKey)) { New-Item -Path $explorerKey -Force | Out-Null }
    Set-ItemProperty -Path $explorerKey -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord
    Set-ItemProperty -Path $explorerKey -Name 'NoAutorun'           -Value 1   -Type DWord
    Log "AutoRun disabled for all drive types."
}

# --- Bloatware ---
function Remove-BloatApp {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Mode)
    if ($Mode -eq 1) {
        $apps = @(
            "Microsoft.XboxApp", "Microsoft.GetHelp", "Microsoft.Getstarted",
            "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.BingNews",
            "Microsoft.MicrosoftStickyNotes", "Microsoft.People",
            "Microsoft.Clipchamp", "MicrosoftTeams", "Microsoft.YourPhone",
            "Microsoft.WindowsFeedbackHub", "Microsoft.BingWeather",
            "Microsoft.Xbox.TCUI", "Microsoft.XboxGameOverlay",
            "Microsoft.XboxGamingOverlay", "Microsoft.GamingApp"
        )
    } elseif ($Mode -eq 2) {
        $apps = (Get-AppxPackage -AllUsers | Where-Object {
            $_.Name -notmatch "Microsoft.WindowsStore|Microsoft.DesktopAppInstaller|Microsoft.WindowsCalculator"
        }).Name
    } else { return }

    foreach ($app in $apps) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Log "Removed app: $app"
    }
}

function Restore-Default {
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"       -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"         -Recurse -ErrorAction SilentlyContinue
    Log "Restored defaults."
}

# =============================================================================
# GUI
# =============================================================================

$form                  = New-Object System.Windows.Forms.Form
$form.Text             = "Windows 11 Privacy Toolkit"
$form.Size             = New-Object System.Drawing.Size(520, 660)
$form.StartPosition    = "CenterScreen"
$form.FormBorderStyle  = "FixedDialog"
$form.MaximizeBox      = $false
$form.Font             = New-Object System.Drawing.Font("Segoe UI", 9)

# --- Header ---
$lblTitle           = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "Windows 11 Privacy Toolkit"
$lblTitle.Font      = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$lblTitle.Location  = New-Object System.Drawing.Point(15, 12)
$lblTitle.Size      = New-Object System.Drawing.Size(480, 28)
$form.Controls.Add($lblTitle)

# --- Restore Point Warning ---
$pnlWarn             = New-Object System.Windows.Forms.Panel
$pnlWarn.Location    = New-Object System.Drawing.Point(8, 48)
$pnlWarn.Size        = New-Object System.Drawing.Size(498, 38)
$pnlWarn.BackColor   = [System.Drawing.Color]::FromArgb(255, 243, 205)
$pnlWarn.BorderStyle = "FixedSingle"
$form.Controls.Add($pnlWarn)

$lblWarn           = New-Object System.Windows.Forms.Label
$lblWarn.Text      = "[!]  Create a restore point before applying changes."
$lblWarn.Location  = New-Object System.Drawing.Point(8, 11)
$lblWarn.Size      = New-Object System.Drawing.Size(310, 18)
$lblWarn.BackColor = [System.Drawing.Color]::Transparent
$pnlWarn.Controls.Add($lblWarn)

$btnRestorePoint          = New-Object System.Windows.Forms.Button
$btnRestorePoint.Text     = "Create Restore Point"
$btnRestorePoint.Location = New-Object System.Drawing.Point(336, 6)
$btnRestorePoint.Size     = New-Object System.Drawing.Size(152, 26)
$btnRestorePoint.Add_Click({
    $btnRestorePoint.Enabled = $false
    $lblStatus.Text = "Status: Creating restore point..."
    [System.Windows.Forms.Application]::DoEvents()
    if (New-RestorePoint) {
        $btnRestorePoint.Text = "[Done]"
        $lblStatus.Text = "Status: Restore point created."
    } else {
        $btnRestorePoint.Enabled = $true
        $lblStatus.Text = "Status: Failed to create restore point."
    }
})
$pnlWarn.Controls.Add($btnRestorePoint)

# --- Tab Control ---
$tabCtrl          = New-Object System.Windows.Forms.TabControl
$tabCtrl.Location = New-Object System.Drawing.Point(8, 94)
$tabCtrl.Size     = New-Object System.Drawing.Size(498, 490)
$form.Controls.Add($tabCtrl)

# =============================================================================
# TAB: Privacy
# =============================================================================
$tabPrivacy      = New-Object System.Windows.Forms.TabPage
$tabPrivacy.Text = "Privacy"
$tabCtrl.Controls.Add($tabPrivacy)

$grpTracking          = New-Object System.Windows.Forms.GroupBox
$grpTracking.Text     = "Tracking & Data Collection"
$grpTracking.Location = New-Object System.Drawing.Point(8, 8)
$grpTracking.Size     = New-Object System.Drawing.Size(472, 195)
$tabPrivacy.Controls.Add($grpTracking)

$chkTelemetry          = New-Object System.Windows.Forms.CheckBox
$chkTelemetry.Text     = "Disable Telemetry & Data Collection"
$chkTelemetry.Checked  = $true
$chkTelemetry.Location = New-Object System.Drawing.Point(10, 22)
$chkTelemetry.Size     = New-Object System.Drawing.Size(450, 22)
$grpTracking.Controls.Add($chkTelemetry)

$chkAdvertising          = New-Object System.Windows.Forms.CheckBox
$chkAdvertising.Text     = "Disable Advertising ID"
$chkAdvertising.Checked  = $true
$chkAdvertising.Location = New-Object System.Drawing.Point(10, 50)
$chkAdvertising.Size     = New-Object System.Drawing.Size(450, 22)
$grpTracking.Controls.Add($chkAdvertising)

$chkLocation          = New-Object System.Windows.Forms.CheckBox
$chkLocation.Text     = "Disable Location Services"
$chkLocation.Checked  = $true
$chkLocation.Location = New-Object System.Drawing.Point(10, 78)
$chkLocation.Size     = New-Object System.Drawing.Size(450, 22)
$grpTracking.Controls.Add($chkLocation)

$chkActivity          = New-Object System.Windows.Forms.CheckBox
$chkActivity.Text     = "Disable Activity History"
$chkActivity.Checked  = $true
$chkActivity.Location = New-Object System.Drawing.Point(10, 106)
$chkActivity.Size     = New-Object System.Drawing.Size(450, 22)
$grpTracking.Controls.Add($chkActivity)

$chkRecall          = New-Object System.Windows.Forms.CheckBox
$chkRecall.Text     = "Disable Windows Recall (AI Screenshot Feature)"
$chkRecall.Checked  = $true
$chkRecall.Location = New-Object System.Drawing.Point(10, 134)
$chkRecall.Size     = New-Object System.Drawing.Size(450, 22)
$grpTracking.Controls.Add($chkRecall)

$chkBingSearch          = New-Object System.Windows.Forms.CheckBox
$chkBingSearch.Text     = "Disable Cortana & Bing Search in Start Menu"
$chkBingSearch.Checked  = $true
$chkBingSearch.Location = New-Object System.Drawing.Point(10, 162)
$chkBingSearch.Size     = New-Object System.Drawing.Size(450, 22)
$grpTracking.Controls.Add($chkBingSearch)

$grpAds          = New-Object System.Windows.Forms.GroupBox
$grpAds.Text     = "Suggested Content & Ads"
$grpAds.Location = New-Object System.Drawing.Point(8, 211)
$grpAds.Size     = New-Object System.Drawing.Size(472, 117)
$tabPrivacy.Controls.Add($grpAds)

$chkSuggestedContent          = New-Object System.Windows.Forms.CheckBox
$chkSuggestedContent.Text     = "Disable Suggested Apps & Start Menu Promotions"
$chkSuggestedContent.Checked  = $true
$chkSuggestedContent.Location = New-Object System.Drawing.Point(10, 22)
$chkSuggestedContent.Size     = New-Object System.Drawing.Size(450, 22)
$grpAds.Controls.Add($chkSuggestedContent)

$chkLockScreenAds          = New-Object System.Windows.Forms.CheckBox
$chkLockScreenAds.Text     = "Disable Lock Screen Spotlight & Ads"
$chkLockScreenAds.Checked  = $true
$chkLockScreenAds.Location = New-Object System.Drawing.Point(10, 50)
$chkLockScreenAds.Size     = New-Object System.Drawing.Size(450, 22)
$grpAds.Controls.Add($chkLockScreenAds)

$chkTailoredExp          = New-Object System.Windows.Forms.CheckBox
$chkTailoredExp.Text     = "Disable Tailored Experiences & Feedback Prompts"
$chkTailoredExp.Checked  = $true
$chkTailoredExp.Location = New-Object System.Drawing.Point(10, 78)
$chkTailoredExp.Size     = New-Object System.Drawing.Size(450, 22)
$grpAds.Controls.Add($chkTailoredExp)

# =============================================================================
# TAB: Services
# =============================================================================
$tabServices      = New-Object System.Windows.Forms.TabPage
$tabServices.Text = "Services"
$tabCtrl.Controls.Add($tabServices)

$grpServices          = New-Object System.Windows.Forms.GroupBox
$grpServices.Text     = "Microsoft Services"
$grpServices.Location = New-Object System.Drawing.Point(8, 8)
$grpServices.Size     = New-Object System.Drawing.Size(472, 118)
$tabServices.Controls.Add($grpServices)

$chkOneDrive          = New-Object System.Windows.Forms.CheckBox
$chkOneDrive.Text     = "Disable OneDrive Integration"
$chkOneDrive.Checked  = $true
$chkOneDrive.Location = New-Object System.Drawing.Point(10, 22)
$chkOneDrive.Size     = New-Object System.Drawing.Size(450, 22)
$grpServices.Controls.Add($chkOneDrive)

$chkBackground          = New-Object System.Windows.Forms.CheckBox
$chkBackground.Text     = "Disable Background Apps"
$chkBackground.Checked  = $true
$chkBackground.Location = New-Object System.Drawing.Point(10, 50)
$chkBackground.Size     = New-Object System.Drawing.Size(450, 22)
$grpServices.Controls.Add($chkBackground)

$chkEdge          = New-Object System.Windows.Forms.CheckBox
$chkEdge.Text     = "Disable Edge Sync & Telemetry"
$chkEdge.Checked  = $true
$chkEdge.Location = New-Object System.Drawing.Point(10, 78)
$chkEdge.Size     = New-Object System.Drawing.Size(450, 22)
$grpServices.Controls.Add($chkEdge)

# =============================================================================
# TAB: Security
# =============================================================================
$tabSecurity      = New-Object System.Windows.Forms.TabPage
$tabSecurity.Text = "Security"
$tabCtrl.Controls.Add($tabSecurity)

$grpSecurity          = New-Object System.Windows.Forms.GroupBox
$grpSecurity.Text     = "Security Hardening"
$grpSecurity.Location = New-Object System.Drawing.Point(8, 8)
$grpSecurity.Size     = New-Object System.Drawing.Size(472, 173)
$tabSecurity.Controls.Add($grpSecurity)

$chkSmb1          = New-Object System.Windows.Forms.CheckBox
$chkSmb1.Text     = "Disable SMBv1  (Legacy Protocol — Ransomware Risk)"
$chkSmb1.Checked  = $true
$chkSmb1.Location = New-Object System.Drawing.Point(10, 22)
$chkSmb1.Size     = New-Object System.Drawing.Size(450, 22)
$grpSecurity.Controls.Add($chkSmb1)

$chkNetProtect          = New-Object System.Windows.Forms.CheckBox
$chkNetProtect.Text     = "Enable Network Protection  (Block Malicious Domains)"
$chkNetProtect.Checked  = $true
$chkNetProtect.Location = New-Object System.Drawing.Point(10, 50)
$chkNetProtect.Size     = New-Object System.Drawing.Size(450, 22)
$grpSecurity.Controls.Add($chkNetProtect)

$chkCfa          = New-Object System.Windows.Forms.CheckBox
$chkCfa.Text     = "Enable Controlled Folder Access  (Ransomware Protection)"
$chkCfa.Checked  = $true
$chkCfa.Location = New-Object System.Drawing.Point(10, 78)
$chkCfa.Size     = New-Object System.Drawing.Size(450, 22)
$grpSecurity.Controls.Add($chkCfa)

$chkUac          = New-Object System.Windows.Forms.CheckBox
$chkUac.Text     = "Enforce UAC Maximum Level  (Credential Prompt)"
$chkUac.Checked  = $true
$chkUac.Location = New-Object System.Drawing.Point(10, 106)
$chkUac.Size     = New-Object System.Drawing.Size(450, 22)
$grpSecurity.Controls.Add($chkUac)

$chkAutoRun          = New-Object System.Windows.Forms.CheckBox
$chkAutoRun.Text     = "Disable AutoRun for All Drives  (USB Protection)"
$chkAutoRun.Checked  = $true
$chkAutoRun.Location = New-Object System.Drawing.Point(10, 134)
$chkAutoRun.Size     = New-Object System.Drawing.Size(450, 22)
$grpSecurity.Controls.Add($chkAutoRun)

# =============================================================================
# TAB: Bloatware
# =============================================================================
$tabBloat      = New-Object System.Windows.Forms.TabPage
$tabBloat.Text = "Bloatware"
$tabCtrl.Controls.Add($tabBloat)

$grpBloat          = New-Object System.Windows.Forms.GroupBox
$grpBloat.Text     = "Bloatware Removal"
$grpBloat.Location = New-Object System.Drawing.Point(8, 8)
$grpBloat.Size     = New-Object System.Drawing.Size(472, 104)
$tabBloat.Controls.Add($grpBloat)

$rdBloatNone          = New-Object System.Windows.Forms.RadioButton
$rdBloatNone.Text     = "Skip bloatware removal"
$rdBloatNone.Checked  = $true
$rdBloatNone.Location = New-Object System.Drawing.Point(10, 22)
$rdBloatNone.Size     = New-Object System.Drawing.Size(450, 22)
$grpBloat.Controls.Add($rdBloatNone)

$rdBloatCommon          = New-Object System.Windows.Forms.RadioButton
$rdBloatCommon.Text     = "Remove common bloatware  (Xbox, Teams, News, Clipchamp...)"
$rdBloatCommon.Location = New-Object System.Drawing.Point(10, 50)
$rdBloatCommon.Size     = New-Object System.Drawing.Size(450, 22)
$grpBloat.Controls.Add($rdBloatCommon)

$rdBloatAll          = New-Object System.Windows.Forms.RadioButton
$rdBloatAll.Text     = "Remove ALL Microsoft Store apps  (except essentials)"
$rdBloatAll.Location = New-Object System.Drawing.Point(10, 78)
$rdBloatAll.Size     = New-Object System.Drawing.Size(450, 22)
$grpBloat.Controls.Add($rdBloatAll)

# =============================================================================
# Action Buttons
# =============================================================================
$btnApply           = New-Object System.Windows.Forms.Button
$btnApply.Text      = "Apply Selected"
$btnApply.Location  = New-Object System.Drawing.Point(8, 593)
$btnApply.Size      = New-Object System.Drawing.Size(145, 34)
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnApply.ForeColor = [System.Drawing.Color]::White
$btnApply.FlatStyle = "Flat"
$btnApply.Add_Click({
    $taskList = [System.Collections.Generic.List[scriptblock]]::new()
    if ($chkTelemetry.Checked)       { $taskList.Add({ Disable-Telemetry }) }
    if ($chkAdvertising.Checked)     { $taskList.Add({ Disable-Advertising }) }
    if ($chkLocation.Checked)        { $taskList.Add({ Disable-Location }) }
    if ($chkActivity.Checked)        { $taskList.Add({ Disable-ActivityHistory }) }
    if ($chkRecall.Checked)          { $taskList.Add({ Disable-Recall }) }
    if ($chkBingSearch.Checked)      { $taskList.Add({ Disable-CortanaAndBingSearch }) }
    if ($chkSuggestedContent.Checked){ $taskList.Add({ Disable-SuggestedContent }) }
    if ($chkLockScreenAds.Checked)   { $taskList.Add({ Disable-LockScreenAd }) }
    if ($chkTailoredExp.Checked)     { $taskList.Add({ Disable-TailoredExperience }) }
    if ($chkOneDrive.Checked)        { $taskList.Add({ Disable-OneDrive }) }
    if ($chkBackground.Checked)      { $taskList.Add({ Disable-BackgroundApp }) }
    if ($chkEdge.Checked)            { $taskList.Add({ Disable-EdgeSync }) }
    if ($chkSmb1.Checked)            { $taskList.Add({ Disable-Smb1Protocol }) }
    if ($chkNetProtect.Checked)      { $taskList.Add({ Enable-NetworkProtection }) }
    if ($chkCfa.Checked)             { $taskList.Add({ Enable-ControlledFolderAccess }) }
    if ($chkUac.Checked)             { $taskList.Add({ Set-UacMax }) }
    if ($chkAutoRun.Checked)         { $taskList.Add({ Disable-AutoRun }) }
    if ($rdBloatCommon.Checked)      { $taskList.Add({ Remove-BloatApp -Mode 1 }) }
    elseif ($rdBloatAll.Checked)     { $taskList.Add({ Remove-BloatApp -Mode 2 }) }

    if ($taskList.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select at least one option.",
            "Nothing Selected",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }

    $btnApply.Enabled           = $false
    $btnRestoreDefaults.Enabled = $false
    $progressBar.Maximum        = $taskList.Count
    $progressBar.Value          = 0

    foreach ($task in $taskList) {
        $lblStatus.Text = "Status: Working..."
        [System.Windows.Forms.Application]::DoEvents()
        & $task
        $progressBar.Value++
        [System.Windows.Forms.Application]::DoEvents()
    }

    $lblStatus.Text             = "Status: Done. Log saved to: $LogFile"
    $btnApply.Enabled           = $true
    $btnRestoreDefaults.Enabled = $true

    [System.Windows.Forms.MessageBox]::Show(
        "All selected changes have been applied.`n`nA restart is recommended to complete the changes.",
        "Complete",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information)
})
$form.Controls.Add($btnApply)

$btnRestoreDefaults          = New-Object System.Windows.Forms.Button
$btnRestoreDefaults.Text     = "Restore Defaults"
$btnRestoreDefaults.Location = New-Object System.Drawing.Point(161, 593)
$btnRestoreDefaults.Size     = New-Object System.Drawing.Size(130, 34)
$btnRestoreDefaults.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "This will revert most registry and service changes.`n`nContinue?",
        "Confirm Restore",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        $lblStatus.Text = "Status: Restoring defaults..."
        [System.Windows.Forms.Application]::DoEvents()
        Restore-Default
        $lblStatus.Text = "Status: Defaults restored. Reboot recommended."
    }
})
$form.Controls.Add($btnRestoreDefaults)

$btnExit          = New-Object System.Windows.Forms.Button
$btnExit.Text     = "Exit"
$btnExit.Location = New-Object System.Drawing.Point(396, 593)
$btnExit.Size     = New-Object System.Drawing.Size(114, 34)
$btnExit.Add_Click({ $form.Close() })
$form.Controls.Add($btnExit)

# --- Status Area ---
$sep           = New-Object System.Windows.Forms.Panel
$sep.Location  = New-Object System.Drawing.Point(0, 635)
$sep.Size      = New-Object System.Drawing.Size(520, 1)
$sep.BackColor = [System.Drawing.Color]::Silver
$form.Controls.Add($sep)

$progressBar          = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(8, 641)
$progressBar.Size     = New-Object System.Drawing.Size(498, 8)
$progressBar.Style    = "Continuous"
$form.Controls.Add($progressBar)

$lblStatus           = New-Object System.Windows.Forms.Label
$lblStatus.Text      = "Status: Ready"
$lblStatus.ForeColor = [System.Drawing.Color]::Gray
$lblStatus.Location  = New-Object System.Drawing.Point(8, 652)
$lblStatus.Size      = New-Object System.Drawing.Size(498, 18)
$form.Controls.Add($lblStatus)

$form.ShowDialog() | Out-Null
