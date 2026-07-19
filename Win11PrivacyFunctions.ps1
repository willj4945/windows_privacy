function Log($msg) {
    try {
        "$((Get-Date).ToString('HH:mm:ss')) - $msg" | Out-File $LogFile -Append
    } catch {
        Write-Warning "Log write failed: $_"
    }
}

function New-RestorePoint {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    try {
        if ($PSCmdlet.ShouldProcess("System", "Create restore point")) {
            Checkpoint-Computer -Description "Pre-PrivacyToolkit" -RestorePointType "MODIFY_SETTINGS"
        }
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
    if ($PSCmdlet.ShouldProcess($uacKey, "Set UAC to maximum level")) {
        Set-ItemProperty -Path $uacKey -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord
        Set-ItemProperty -Path $uacKey -Name 'PromptOnSecureDesktop'      -Value 1 -Type DWord
    }
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
function Get-CommonBloatwareList {
    @(
        "Microsoft.XboxApp", "Microsoft.GetHelp", "Microsoft.Getstarted",
        "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.BingNews",
        "Microsoft.MicrosoftStickyNotes", "Microsoft.People",
        "Microsoft.Clipchamp", "MicrosoftTeams", "Microsoft.YourPhone",
        "Microsoft.WindowsFeedbackHub", "Microsoft.BingWeather",
        "Microsoft.Xbox.TCUI", "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay", "Microsoft.GamingApp"
    )
}

function Get-ProtectedAppxPackage {
    @(
        # Shell / sign-in critical
        'Microsoft.Windows.StartMenuExperienceHost', 'Microsoft.Windows.ShellExperienceHost',
        'Microsoft.LockApp', 'Microsoft.CredDialogHost', 'Microsoft.AccountsControl',
        'Microsoft.AAD.BrokerPlugin', 'Microsoft.Windows.CloudExperienceHost',
        'Microsoft.Windows.PinningConfirmationDialog', 'Microsoft.Windows.SecureAssessmentBrowser',
        'Microsoft.Windows.CapturePicker', 'Microsoft.Windows.NarratorQuickStart',
        'Microsoft.Windows.ParentalControls', 'Microsoft.Windows.PeopleExperienceHost',
        'Microsoft.Win32WebViewHost', 'MicrosoftWindows.Client.CBS',
        'MicrosoftWindows.Client.WebExperience', 'Microsoft.Windows.CBSPreview', 'NcsiUwpApp',
        # Security
        'Microsoft.Windows.SecHealthUI', 'Microsoft.SecHealthUI',
        # Runtime frameworks (version is baked into the Name, so these need wildcards)
        'Microsoft.VCLibs*', 'Microsoft.NET.Native.Runtime*', 'Microsoft.NET.Native.Framework*',
        'Microsoft.UI.Xaml*', 'Microsoft.WindowsAppRuntime*', 'Microsoft.Services.Store.Engagement',
        'Microsoft.Advertising.Xaml',
        # Kept by default / dev tools worth protecting even though Microsoft-published
        'Microsoft.WindowsStore', 'Microsoft.DesktopAppInstaller', 'Microsoft.WindowsCalculator',
        'Microsoft.WindowsNotepad', 'Microsoft.WindowsTerminal*', 'Microsoft.PowerShell*',
        'Microsoft.Windows.DevHome*', 'MicrosoftCorporationII.WindowsSubsystemForLinux',
        'Microsoft.VisualStudioCode*'
    )
}

function Test-ProtectedAppxPackage {
    param([string]$Name)
    foreach ($pattern in Get-ProtectedAppxPackage) {
        if ($Name -like $pattern) { return $true }
    }
    return $false
}

function Get-AppsToRemove {
    param([int]$Mode)
    if ($Mode -eq 1) {
        return Get-CommonBloatwareList
    } elseif ($Mode -eq 2) {
        return (Get-AppxPackage -AllUsers | Where-Object {
            $_.Publisher -like '*Microsoft Corporation*' -and -not (Test-ProtectedAppxPackage $_.Name)
        }).Name
    }
    return @()
}

function Remove-BloatApp {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$Mode,
        [string[]]$AppNames
    )
    $apps = if ($PSBoundParameters.ContainsKey('AppNames')) { $AppNames } else { Get-AppsToRemove -Mode $Mode }
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
# Privacy Scan: Status Checks
# Each Test-*Hardened function is read-only and mirrors the registry paths /
# services used by its corresponding Disable-*/Enable-* setter above.
# =============================================================================

function Test-TelemetryHardened {
    $telemetryOff = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -ErrorAction SilentlyContinue).AllowTelemetry -eq 0
    $serviceOff   = (Get-Service -Name 'DiagTrack' -ErrorAction SilentlyContinue).StartType -eq 'Disabled'
    return [bool]($telemetryOff -and $serviceOff)
}

function Test-AdvertisingHardened {
    $val = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
    return [bool]($val -eq 0)
}

function Test-LocationHardened {
    $val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -ErrorAction SilentlyContinue).Status
    return [bool]($val -eq 0)
}

function Test-ActivityHistoryHardened {
    $props = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
    return [bool](($props.PublishUserActivities -eq 0) -and ($props.UploadUserActivities -eq 0))
}

function Test-RecallHardened {
    $val = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -Name 'DisableAIDataAnalysis' -ErrorAction SilentlyContinue).DisableAIDataAnalysis
    return [bool]($val -eq 1)
}

function Test-CortanaAndBingSearchHardened {
    $policy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -ErrorAction SilentlyContinue
    $user   = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -ErrorAction SilentlyContinue
    return [bool](($policy.AllowCortana -eq 0) -and ($policy.DisableWebSearch -eq 1) -and ($user.BingSearchEnabled -eq 0))
}

function Test-SuggestedContentHardened {
    $cdm = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ErrorAction SilentlyContinue
    return [bool](($cdm.SilentInstalledAppsEnabled -eq 0) -and ($cdm.'SubscribedContent-338388Enabled' -eq 0) -and ($cdm.SystemPaneSuggestionsEnabled -eq 0))
}

function Test-LockScreenAdHardened {
    $cdm = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ErrorAction SilentlyContinue
    return [bool](($cdm.RotatingLockScreenEnabled -eq 0) -and ($cdm.RotatingLockScreenOverlayEnabled -eq 0))
}

function Test-TailoredExperienceHardened {
    $val = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -ErrorAction SilentlyContinue).TailoredExperiencesWithDiagnosticDataEnabled
    return [bool]($val -eq 0)
}

function Test-OneDriveHardened {
    $val = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -ErrorAction SilentlyContinue).DisableFileSync
    return [bool]($val -eq 1)
}

function Test-BackgroundAppHardened {
    $val = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -Name 'GlobalUserDisabled' -ErrorAction SilentlyContinue).GlobalUserDisabled
    return [bool]($val -eq 1)
}

function Test-EdgeSyncHardened {
    $edge = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue
    return [bool](($edge.SyncDisabled -eq 1) -and ($edge.MetricsReportingEnabled -eq 0))
}

function Test-Smb1ProtocolHardened {
    $val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -ErrorAction SilentlyContinue).SMB1
    return [bool]($val -eq 0)
}

function Test-NetworkProtectionHardened {
    try {
        return [bool]((Get-MpPreference -ErrorAction Stop).EnableNetworkProtection -eq 1)
    } catch {
        return $false
    }
}

function Test-ControlledFolderAccessHardened {
    try {
        return [bool]((Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess -eq 1)
    } catch {
        return $false
    }
}

function Test-UacMaxHardened {
    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    return [bool](($uac.ConsentPromptBehaviorAdmin -eq 2) -and ($uac.PromptOnSecureDesktop -eq 1))
}

function Test-AutoRunHardened {
    $explorer = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction SilentlyContinue
    return [bool](($explorer.NoDriveTypeAutoRun -eq 255) -and ($explorer.NoAutorun -eq 1))
}

function Test-BloatwareHardened {
    $installed = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -in (Get-CommonBloatwareList) }
    return [bool](-not $installed)
}

function Get-PrivacyChecklist {
    @(
        @{ Category = 'Tracking & Data Collection'; Name = 'Telemetry & Data Collection';      Test = 'Test-TelemetryHardened' }
        @{ Category = 'Tracking & Data Collection'; Name = 'Advertising ID';                    Test = 'Test-AdvertisingHardened' }
        @{ Category = 'Tracking & Data Collection'; Name = 'Location Services';                 Test = 'Test-LocationHardened' }
        @{ Category = 'Tracking & Data Collection'; Name = 'Activity History';                  Test = 'Test-ActivityHistoryHardened' }
        @{ Category = 'Tracking & Data Collection'; Name = 'Windows Recall';                    Test = 'Test-RecallHardened' }
        @{ Category = 'Tracking & Data Collection'; Name = 'Cortana & Bing Search';              Test = 'Test-CortanaAndBingSearchHardened' }
        @{ Category = 'Suggested Content & Ads';    Name = 'Suggested Apps & Promotions';        Test = 'Test-SuggestedContentHardened' }
        @{ Category = 'Suggested Content & Ads';    Name = 'Lock Screen Spotlight & Ads';        Test = 'Test-LockScreenAdHardened' }
        @{ Category = 'Suggested Content & Ads';    Name = 'Tailored Experiences';               Test = 'Test-TailoredExperienceHardened' }
        @{ Category = 'Microsoft Services';         Name = 'OneDrive Integration';               Test = 'Test-OneDriveHardened' }
        @{ Category = 'Microsoft Services';         Name = 'Background Apps';                    Test = 'Test-BackgroundAppHardened' }
        @{ Category = 'Microsoft Services';         Name = 'Edge Sync & Telemetry';               Test = 'Test-EdgeSyncHardened' }
        @{ Category = 'Security Hardening';         Name = 'SMBv1 Disabled';                     Test = 'Test-Smb1ProtocolHardened' }
        @{ Category = 'Security Hardening';         Name = 'Network Protection';                  Test = 'Test-NetworkProtectionHardened' }
        @{ Category = 'Security Hardening';         Name = 'Controlled Folder Access';            Test = 'Test-ControlledFolderAccessHardened' }
        @{ Category = 'Security Hardening';         Name = 'UAC Maximum Level';                   Test = 'Test-UacMaxHardened' }
        @{ Category = 'Security Hardening';         Name = 'AutoRun Disabled';                    Test = 'Test-AutoRunHardened' }
        @{ Category = 'Bloatware Removal';          Name = 'Common Bloatware Removed';            Test = 'Test-BloatwareHardened' }
    )
}

function Invoke-PrivacyScan {
    $results = foreach ($c in Get-PrivacyChecklist) {
        [PSCustomObject]@{
            Category = $c.Category
            Name     = $c.Name
            Passed   = [bool](& $c.Test)
        }
    }

    $total   = $results.Count
    $passed  = ($results | Where-Object Passed).Count
    $percent = if ($total -gt 0) { [math]::Round(100 * $passed / $total) } else { 0 }
    $rating  = if ($percent -ge 90) { 'Excellent' }
               elseif ($percent -ge 70) { 'Good' }
               elseif ($percent -ge 50) { 'Fair' }
               else { 'Needs Attention' }

    Log "Privacy Scan: $passed/$total checks passed ($percent% - $rating)"

    [PSCustomObject]@{
        Results      = $results
        TotalChecks  = $total
        PassedChecks = $passed
        ScorePercent = $percent
        Rating       = $rating
    }
}
