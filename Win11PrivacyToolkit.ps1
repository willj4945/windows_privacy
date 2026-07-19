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
        [System.Windows.Forms.MessageBoxButtons]::OK,2
        [System.Windows.Forms.MessageBoxIcon]::Warning)
    exit
}

# --- Global Config ---
$LogFile = "$PSScriptRoot\Win11PrivacyToolkit_Log.txt"
"=== Win11PrivacyToolkit Run @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $LogFile -Append

. "$PSScriptRoot\Win11PrivacyFunctions.ps1"

# --- Scrollable confirmation dialog (used for long app-removal lists) ---
# Returns a PSCustomObject: @{ Result = <DialogResult>; SelectedApps = <string[]> }
# SelectedApps reflects only the items still checked when the user clicks "Remove Checked".
function Show-AppRemovalConfirmDialog {
    param(
        [Parameter(Mandatory)][string[]] $AppNames
    )

    $dlg                 = New-Object System.Windows.Forms.Form
    $dlg.Text             = "Confirm App Removal"
    $dlg.Size             = New-Object System.Drawing.Size(480, 560)
    $dlg.StartPosition    = "CenterScreen"
    $dlg.FormBorderStyle  = "FixedDialog"
    $dlg.MaximizeBox      = $false
    $dlg.MinimizeBox      = $false
    $dlg.Font             = New-Object System.Drawing.Font("Segoe UI", 9)

    $lbl           = New-Object System.Windows.Forms.Label
    $lbl.Text      = "Uncheck anything you want to keep. $($AppNames.Count) app(s) checked for removal:"
    $lbl.Location  = New-Object System.Drawing.Point(12, 12)
    $lbl.Size      = New-Object System.Drawing.Size(440, 34)
    $dlg.Controls.Add($lbl)

    $lst                     = New-Object System.Windows.Forms.CheckedListBox
    $lst.Location            = New-Object System.Drawing.Point(12, 50)
    $lst.Size                = New-Object System.Drawing.Size(440, 366)
    $lst.CheckOnClick        = $true
    $lst.HorizontalScrollbar = $true
    foreach ($app in $AppNames) { [void]$lst.Items.Add($app, $true) }
    $dlg.Controls.Add($lst)

    $btnSelectAll          = New-Object System.Windows.Forms.Button
    $btnSelectAll.Text     = "Select All"
    $btnSelectAll.Location = New-Object System.Drawing.Point(12, 424)
    $btnSelectAll.Size     = New-Object System.Drawing.Size(90, 26)
    $btnSelectAll.Add_Click({ for ($i = 0; $i -lt $lst.Items.Count; $i++) { $lst.SetItemChecked($i, $true) } })
    $dlg.Controls.Add($btnSelectAll)

    $btnSelectNone          = New-Object System.Windows.Forms.Button
    $btnSelectNone.Text     = "Select None"
    $btnSelectNone.Location = New-Object System.Drawing.Point(108, 424)
    $btnSelectNone.Size     = New-Object System.Drawing.Size(90, 26)
    $btnSelectNone.Add_Click({ for ($i = 0; $i -lt $lst.Items.Count; $i++) { $lst.SetItemChecked($i, $false) } })
    $dlg.Controls.Add($btnSelectNone)

    $btnYes           = New-Object System.Windows.Forms.Button
    $btnYes.Text      = "Remove Checked"
    $btnYes.Location  = New-Object System.Drawing.Point(250, 462)
    $btnYes.Size      = New-Object System.Drawing.Size(105, 30)
    $btnYes.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $dlg.Controls.Add($btnYes)

    $btnNo            = New-Object System.Windows.Forms.Button
    $btnNo.Text       = "Cancel"
    $btnNo.Location   = New-Object System.Drawing.Point(361, 462)
    $btnNo.Size       = New-Object System.Drawing.Size(91, 30)
    $btnNo.DialogResult = [System.Windows.Forms.DialogResult]::No
    $dlg.Controls.Add($btnNo)

    $dlg.AcceptButton = $btnYes
    $dlg.CancelButton = $btnNo

    $result = $dlg.ShowDialog()

    return [PSCustomObject]@{
        Result       = $result
        SelectedApps = @($lst.CheckedItems)
    }
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
# TAB: Scan
# =============================================================================
$tabScan      = New-Object System.Windows.Forms.TabPage
$tabScan.Text = "Scan"
$tabCtrl.Controls.Add($tabScan)

$pnlScoreHeader             = New-Object System.Windows.Forms.Panel
$pnlScoreHeader.Location    = New-Object System.Drawing.Point(8, 8)
$pnlScoreHeader.Size        = New-Object System.Drawing.Size(472, 70)
$pnlScoreHeader.BorderStyle = "FixedSingle"
$tabScan.Controls.Add($pnlScoreHeader)

$lblScoreBig          = New-Object System.Windows.Forms.Label
$lblScoreBig.Text     = "Privacy Score: --"
$lblScoreBig.Font     = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblScoreBig.Location = New-Object System.Drawing.Point(10, 8)
$lblScoreBig.Size     = New-Object System.Drawing.Size(450, 30)
$pnlScoreHeader.Controls.Add($lblScoreBig)

$lblRating          = New-Object System.Windows.Forms.Label
$lblRating.Text     = "Click Run Scan to check your current privacy status."
$lblRating.Location = New-Object System.Drawing.Point(10, 42)
$lblRating.Size     = New-Object System.Drawing.Size(450, 22)
$pnlScoreHeader.Controls.Add($lblRating)

$lvResults               = New-Object System.Windows.Forms.ListView
$lvResults.Location      = New-Object System.Drawing.Point(8, 86)
$lvResults.Size          = New-Object System.Drawing.Size(472, 340)
$lvResults.View          = "Details"
$lvResults.FullRowSelect = $true
$lvResults.GridLines     = $true
$lvResults.Columns.Add("Category", 140) | Out-Null
$lvResults.Columns.Add("Setting", 232)  | Out-Null
$lvResults.Columns.Add("Status", 90)    | Out-Null
$tabScan.Controls.Add($lvResults)

$btnRunScan          = New-Object System.Windows.Forms.Button
$btnRunScan.Text     = "Run Scan"
$btnRunScan.Location = New-Object System.Drawing.Point(8, 432)
$btnRunScan.Size     = New-Object System.Drawing.Size(150, 26)
$tabScan.Controls.Add($btnRunScan)

$lblLastScan          = New-Object System.Windows.Forms.Label
$lblLastScan.Text     = "Last scanned: never"
$lblLastScan.ForeColor = [System.Drawing.Color]::Gray
$lblLastScan.Location = New-Object System.Drawing.Point(166, 437)
$lblLastScan.Size     = New-Object System.Drawing.Size(314, 20)
$tabScan.Controls.Add($lblLastScan)

function Update-ScanUI {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not $PSCmdlet.ShouldProcess('Scan tab', 'Refresh privacy score')) { return }

    $scan = Invoke-PrivacyScan

    $lblScoreBig.Text = "Privacy Score: $($scan.ScorePercent)% ($($scan.Rating))"
    $lblRating.Text   = "$($scan.PassedChecks) of $($scan.TotalChecks) checks passed"

    switch ($scan.Rating) {
        'Excellent' { $bg = [System.Drawing.Color]::FromArgb(212, 237, 218); $fg = [System.Drawing.Color]::FromArgb(30, 90, 40) }
        'Good'      { $bg = [System.Drawing.Color]::FromArgb(204, 229, 255); $fg = [System.Drawing.Color]::FromArgb(0, 90, 160) }
        'Fair'      { $bg = [System.Drawing.Color]::FromArgb(255, 229, 204); $fg = [System.Drawing.Color]::FromArgb(170, 90, 0) }
        default     { $bg = [System.Drawing.Color]::FromArgb(248, 215, 218); $fg = [System.Drawing.Color]::FromArgb(150, 30, 30) }
    }
    $pnlScoreHeader.BackColor = $bg
    $lblScoreBig.ForeColor    = $fg
    $lblRating.ForeColor      = $fg

    $lvResults.Items.Clear()
    foreach ($r in $scan.Results) {
        $item = New-Object System.Windows.Forms.ListViewItem($r.Category)
        $item.SubItems.Add($r.Name) | Out-Null
        if ($r.Passed) {
            $item.SubItems.Add("Hardened") | Out-Null
            $item.ForeColor = [System.Drawing.Color]::FromArgb(30, 120, 40)
        } else {
            $item.SubItems.Add("Not Hardened") | Out-Null
            $item.ForeColor = [System.Drawing.Color]::FromArgb(180, 30, 30)
        }
        $lvResults.Items.Add($item) | Out-Null
    }

    $lblLastScan.Text = "Last scanned: $((Get-Date).ToString('HH:mm:ss'))"
}

$btnRunScan.Add_Click({ Update-ScanUI })
$form.Add_Shown({ Update-ScanUI })

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
$chkSmb1.Text     = "Disable SMBv1  (Legacy Protocol - Ransomware Risk)"
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
    if ($chkTelemetry.Checked)        { $taskList.Add({ Disable-Telemetry }) }
    if ($chkAdvertising.Checked)      { $taskList.Add({ Disable-Advertising }) }
    if ($chkLocation.Checked)         { $taskList.Add({ Disable-Location }) }
    if ($chkActivity.Checked)         { $taskList.Add({ Disable-ActivityHistory }) }
    if ($chkRecall.Checked)           { $taskList.Add({ Disable-Recall }) }
    if ($chkBingSearch.Checked)       { $taskList.Add({ Disable-CortanaAndBingSearch }) }
    if ($chkSuggestedContent.Checked) { $taskList.Add({ Disable-SuggestedContent }) }
    if ($chkLockScreenAds.Checked)    { $taskList.Add({ Disable-LockScreenAd }) }
    if ($chkTailoredExp.Checked)      { $taskList.Add({ Disable-TailoredExperience }) }
    if ($chkOneDrive.Checked)         { $taskList.Add({ Disable-OneDrive }) }
    if ($chkBackground.Checked)       { $taskList.Add({ Disable-BackgroundApp }) }
    if ($chkEdge.Checked)             { $taskList.Add({ Disable-EdgeSync }) }
    if ($chkSmb1.Checked)             { $taskList.Add({ Disable-Smb1Protocol }) }
    if ($chkNetProtect.Checked)       { $taskList.Add({ Enable-NetworkProtection }) }
    if ($chkCfa.Checked)              { $taskList.Add({ Enable-ControlledFolderAccess }) }
    if ($chkUac.Checked)              { $taskList.Add({ Set-UacMax }) }
    if ($chkAutoRun.Checked)          { $taskList.Add({ Disable-AutoRun }) }
    if ($rdBloatCommon.Checked) {
        $taskList.Add({ Remove-BloatApp -Mode 1 })
    } elseif ($rdBloatAll.Checked) {
        $appsToRemove = Get-AppsToRemove -Mode 2
        if ($appsToRemove.Count -gt 0) {
            $confirm = Show-AppRemovalConfirmDialog -AppNames $appsToRemove
            if ($confirm.Result -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            if ($confirm.SelectedApps.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "No apps were checked for removal.",
                    "Nothing Selected",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information)
                return
            }
            $selectedApps = $confirm.SelectedApps
            $taskList.Add({ Remove-BloatApp -AppNames $selectedApps }.GetNewClosure())
        }
    }

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

    Update-ScanUI
    $tabCtrl.SelectedTab = $tabScan

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
