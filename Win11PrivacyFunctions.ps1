function Log($msg) {
    "$((Get-Date).ToString('HH:mm:ss')) - $msg" | Out-File $LogFile -Append
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
