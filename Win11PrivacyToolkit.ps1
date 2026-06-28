<#
.SYNOPSIS
Windows 11 Privacy Toolkit
Original Author: Will Johnson https://github.com/willj4945
Description: GUI-based tool to help users disable telemetry, ads, tracking, and bloatware safely.
Version: 2.0
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
    try {
        Checkpoint-Computer -Description "Pre-PrivacyToolkit" -RestorePointType "MODIFY_SETTINGS"
        Log "Restore point created."
        return $true
    } catch {
        Log "Failed to create restore point: $_"
        return $false
    }
}

# --- Privacy Functions ---
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

function Disable-OneDrive {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSync /t REG_DWORD /d 1 /f | Out-Null
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    Log "OneDrive disabled."
}

function Disable-BackgroundApps {
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

function Debloat-Apps {
    param([int]$Mode)
    if ($Mode -eq 1) {
        $apps = @(
            "Microsoft.XboxApp", "Microsoft.GetHelp", "Microsoft.Getstarted",
            "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.BingNews",
            "Microsoft.MicrosoftStickyNotes", "Microsoft.People"
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

function Restore-Defaults {
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
$form.Size             = New-Object System.Drawing.Size(500, 690)
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
$lblTitle.Size      = New-Object System.Drawing.Size(460, 28)
$form.Controls.Add($lblTitle)

# --- Restore Point Warning ---
$pnlWarn             = New-Object System.Windows.Forms.Panel
$pnlWarn.Location    = New-Object System.Drawing.Point(12, 48)
$pnlWarn.Size        = New-Object System.Drawing.Size(460, 38)
$pnlWarn.BackColor   = [System.Drawing.Color]::FromArgb(255, 243, 205)
$pnlWarn.BorderStyle = "FixedSingle"
$form.Controls.Add($pnlWarn)

$lblWarn           = New-Object System.Windows.Forms.Label
$lblWarn.Text      = "[!]  Create a restore point before applying changes."
$lblWarn.Location  = New-Object System.Drawing.Point(8, 11)
$lblWarn.Size      = New-Object System.Drawing.Size(292, 18)
$lblWarn.BackColor = [System.Drawing.Color]::Transparent
$pnlWarn.Controls.Add($lblWarn)

$btnRestorePoint          = New-Object System.Windows.Forms.Button
$btnRestorePoint.Text     = "Create Restore Point"
$btnRestorePoint.Location = New-Object System.Drawing.Point(308, 6)
$btnRestorePoint.Size     = New-Object System.Drawing.Size(144, 26)
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

# --- Privacy GroupBox ---
$grpPrivacy          = New-Object System.Windows.Forms.GroupBox
$grpPrivacy.Text     = "Privacy"
$grpPrivacy.Location = New-Object System.Drawing.Point(12, 96)
$grpPrivacy.Size     = New-Object System.Drawing.Size(460, 195)
$form.Controls.Add($grpPrivacy)

$chkTelemetry          = New-Object System.Windows.Forms.CheckBox
$chkTelemetry.Text     = "Disable Telemetry & Data Collection"
$chkTelemetry.Checked  = $true
$chkTelemetry.Location = New-Object System.Drawing.Point(10, 22)
$chkTelemetry.Size     = New-Object System.Drawing.Size(430, 22)
$grpPrivacy.Controls.Add($chkTelemetry)

$chkAdvertising          = New-Object System.Windows.Forms.CheckBox
$chkAdvertising.Text     = "Disable Advertising ID"
$chkAdvertising.Checked  = $true
$chkAdvertising.Location = New-Object System.Drawing.Point(10, 50)
$chkAdvertising.Size     = New-Object System.Drawing.Size(430, 22)
$grpPrivacy.Controls.Add($chkAdvertising)

$chkLocation          = New-Object System.Windows.Forms.CheckBox
$chkLocation.Text     = "Disable Location Services"
$chkLocation.Checked  = $true
$chkLocation.Location = New-Object System.Drawing.Point(10, 78)
$chkLocation.Size     = New-Object System.Drawing.Size(430, 22)
$grpPrivacy.Controls.Add($chkLocation)

$chkActivity          = New-Object System.Windows.Forms.CheckBox
$chkActivity.Text     = "Disable Activity History"
$chkActivity.Checked  = $true
$chkActivity.Location = New-Object System.Drawing.Point(10, 106)
$chkActivity.Size     = New-Object System.Drawing.Size(430, 22)
$grpPrivacy.Controls.Add($chkActivity)

$chkRecall          = New-Object System.Windows.Forms.CheckBox
$chkRecall.Text     = "Disable Windows Recall (AI Screenshot Feature)"
$chkRecall.Checked  = $true
$chkRecall.Location = New-Object System.Drawing.Point(10, 134)
$chkRecall.Size     = New-Object System.Drawing.Size(430, 22)
$grpPrivacy.Controls.Add($chkRecall)

$chkBingSearch          = New-Object System.Windows.Forms.CheckBox
$chkBingSearch.Text     = "Disable Cortana & Bing Search in Start Menu"
$chkBingSearch.Checked  = $true
$chkBingSearch.Location = New-Object System.Drawing.Point(10, 162)
$chkBingSearch.Size     = New-Object System.Drawing.Size(430, 22)
$grpPrivacy.Controls.Add($chkBingSearch)

# --- Microsoft Services GroupBox ---
$grpServices          = New-Object System.Windows.Forms.GroupBox
$grpServices.Text     = "Microsoft Services"
$grpServices.Location = New-Object System.Drawing.Point(12, 299)
$grpServices.Size     = New-Object System.Drawing.Size(460, 118)
$form.Controls.Add($grpServices)

$chkOneDrive          = New-Object System.Windows.Forms.CheckBox
$chkOneDrive.Text     = "Disable OneDrive Integration"
$chkOneDrive.Checked  = $true
$chkOneDrive.Location = New-Object System.Drawing.Point(10, 22)
$chkOneDrive.Size     = New-Object System.Drawing.Size(430, 22)
$grpServices.Controls.Add($chkOneDrive)

$chkBackground          = New-Object System.Windows.Forms.CheckBox
$chkBackground.Text     = "Disable Background Apps"
$chkBackground.Checked  = $true
$chkBackground.Location = New-Object System.Drawing.Point(10, 50)
$chkBackground.Size     = New-Object System.Drawing.Size(430, 22)
$grpServices.Controls.Add($chkBackground)

$chkEdge          = New-Object System.Windows.Forms.CheckBox
$chkEdge.Text     = "Disable Edge Sync & Telemetry"
$chkEdge.Checked  = $true
$chkEdge.Location = New-Object System.Drawing.Point(10, 78)
$chkEdge.Size     = New-Object System.Drawing.Size(430, 22)
$grpServices.Controls.Add($chkEdge)

# --- Bloatware GroupBox ---
$grpBloat          = New-Object System.Windows.Forms.GroupBox
$grpBloat.Text     = "Bloatware"
$grpBloat.Location = New-Object System.Drawing.Point(12, 425)
$grpBloat.Size     = New-Object System.Drawing.Size(460, 104)
$form.Controls.Add($grpBloat)

$rdBloatNone          = New-Object System.Windows.Forms.RadioButton
$rdBloatNone.Text     = "Skip bloatware removal"
$rdBloatNone.Checked  = $true
$rdBloatNone.Location = New-Object System.Drawing.Point(10, 22)
$rdBloatNone.Size     = New-Object System.Drawing.Size(430, 22)
$grpBloat.Controls.Add($rdBloatNone)

$rdBloatCommon          = New-Object System.Windows.Forms.RadioButton
$rdBloatCommon.Text     = "Remove common bloatware  (Xbox, News, Tips...)"
$rdBloatCommon.Location = New-Object System.Drawing.Point(10, 50)
$rdBloatCommon.Size     = New-Object System.Drawing.Size(430, 22)
$grpBloat.Controls.Add($rdBloatCommon)

$rdBloatAll          = New-Object System.Windows.Forms.RadioButton
$rdBloatAll.Text     = "Remove ALL Microsoft Store apps  (except essentials)"
$rdBloatAll.Location = New-Object System.Drawing.Point(10, 78)
$rdBloatAll.Size     = New-Object System.Drawing.Size(430, 22)
$grpBloat.Controls.Add($rdBloatAll)

# --- Action Buttons ---
$btnApply           = New-Object System.Windows.Forms.Button
$btnApply.Text      = "Apply Selected"
$btnApply.Location  = New-Object System.Drawing.Point(12, 540)
$btnApply.Size      = New-Object System.Drawing.Size(145, 34)
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnApply.ForeColor = [System.Drawing.Color]::White
$btnApply.FlatStyle = "Flat"
$btnApply.Add_Click({
    $taskList = [System.Collections.Generic.List[scriptblock]]::new()
    if ($chkTelemetry.Checked)   { $taskList.Add({ Disable-Telemetry }) }
    if ($chkAdvertising.Checked) { $taskList.Add({ Disable-Advertising }) }
    if ($chkLocation.Checked)    { $taskList.Add({ Disable-Location }) }
    if ($chkActivity.Checked)    { $taskList.Add({ Disable-ActivityHistory }) }
    if ($chkRecall.Checked)      { $taskList.Add({ Disable-Recall }) }
    if ($chkBingSearch.Checked)  { $taskList.Add({ Disable-CortanaAndBingSearch }) }
    if ($chkOneDrive.Checked)    { $taskList.Add({ Disable-OneDrive }) }
    if ($chkBackground.Checked)  { $taskList.Add({ Disable-BackgroundApps }) }
    if ($chkEdge.Checked)        { $taskList.Add({ Disable-EdgeSync }) }
    if ($rdBloatCommon.Checked)  { $taskList.Add({ Debloat-Apps -Mode 1 }) }
    elseif ($rdBloatAll.Checked) { $taskList.Add({ Debloat-Apps -Mode 2 }) }

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
$btnRestoreDefaults.Location = New-Object System.Drawing.Point(165, 540)
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
        Restore-Defaults
        $lblStatus.Text = "Status: Defaults restored. Reboot recommended."
    }
})
$form.Controls.Add($btnRestoreDefaults)

$btnExit          = New-Object System.Windows.Forms.Button
$btnExit.Text     = "Exit"
$btnExit.Location = New-Object System.Drawing.Point(356, 540)
$btnExit.Size     = New-Object System.Drawing.Size(116, 34)
$btnExit.Add_Click({ $form.Close() })
$form.Controls.Add($btnExit)

# --- Status Area ---
$sep           = New-Object System.Windows.Forms.Panel
$sep.Location  = New-Object System.Drawing.Point(0, 584)
$sep.Size      = New-Object System.Drawing.Size(500, 1)
$sep.BackColor = [System.Drawing.Color]::Silver
$form.Controls.Add($sep)

$lblStatus           = New-Object System.Windows.Forms.Label
$lblStatus.Text      = "Status: Ready"
$lblStatus.ForeColor = [System.Drawing.Color]::Gray
$lblStatus.Location  = New-Object System.Drawing.Point(12, 593)
$lblStatus.Size      = New-Object System.Drawing.Size(460, 18)
$form.Controls.Add($lblStatus)

$progressBar          = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(12, 617)
$progressBar.Size     = New-Object System.Drawing.Size(460, 16)
$progressBar.Style    = "Continuous"
$form.Controls.Add($progressBar)

$form.ShowDialog() | Out-Null
