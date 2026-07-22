#Requires -Module Pester

BeforeAll {
    $script:LogFile = [System.IO.Path]::GetTempFileName()
    . (Join-Path $PSScriptRoot '..\Win11PrivacyFunctions.ps1')
}

AfterAll {
    if (Test-Path $script:LogFile) { Remove-Item $script:LogFile -Force }
}

# ---------------------------------------------------------------------------
# Shared mocks applied before every test to suppress real system calls.
# Wrapped in one Describe because BeforeEach/AfterEach must live inside a
# block container in Pester 5+ -- they cannot appear at file root.
# ---------------------------------------------------------------------------
Describe 'Win11PrivacyToolkit' {
BeforeEach {
    Mock Log                          {}
    Mock Out-File                     {}
    Mock Test-Path                    { $false }
    Mock New-Item                     {}
    Mock Set-ItemProperty             {}
    Mock Stop-Service                 {}
    Mock Set-Service                  {}
    Mock Disable-ScheduledTask        {}
    Mock Stop-Process                 {}
    Mock Remove-Item                  {}
    Mock Disable-WindowsOptionalFeature {}
    Mock Set-MpPreference             {}
    Mock Checkpoint-Computer          {}
    Mock Get-AppxPackage              { @() }
    Mock Remove-AppxPackage           {}
    Mock reg                          {}
    Mock Get-ItemProperty             {}
    Mock Get-Service                  {}
    Mock Get-MpPreference             {}
}

# ---------------------------------------------------------------------------
Describe 'New-RestorePoint' {
    Context 'when Checkpoint-Computer succeeds' {
        It 'returns $true' {
            New-RestorePoint | Should -Be $true
        }
        It 'calls Checkpoint-Computer once' {
            New-RestorePoint
            Should -Invoke Checkpoint-Computer -Times 1
        }
    }

    Context 'when Checkpoint-Computer throws' {
        BeforeEach { Mock Checkpoint-Computer { throw 'Access denied' } }

        It 'returns $false' {
            New-RestorePoint | Should -Be $false
        }
        It 'logs the failure' {
            New-RestorePoint
            Should -Invoke Log -ParameterFilter { $msg -like 'Failed to create restore point*' }
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-Telemetry' {
    It 'sets AllowTelemetry=0 on all three registry paths' {
        Disable-Telemetry
        Should -Invoke Set-ItemProperty -Times 3 -ParameterFilter {
            $Name -eq 'AllowTelemetry' -and $Value -eq 0
        }
    }
    It 'stops the DiagTrack service' {
        Disable-Telemetry
        Should -Invoke Stop-Service -ParameterFilter { $Name -eq 'DiagTrack' }
    }
    It 'stops the dmwappushservice' {
        Disable-Telemetry
        Should -Invoke Stop-Service -ParameterFilter { $Name -eq 'dmwappushservice' }
    }
    It 'disables all six scheduled tasks' {
        Disable-Telemetry
        Should -Invoke Disable-ScheduledTask -Times 6
    }
    It 'creates missing registry keys' {
        Disable-Telemetry
        Should -Invoke New-Item -Times 3
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-Recall' {
    It 'sets DisableAIDataAnalysis=1 on the HKLM hive' {
        Disable-Recall
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -and
            $Name -eq 'DisableAIDataAnalysis' -and $Value -eq 1
        }
    }
    It 'sets DisableAIDataAnalysis=1 on the HKCU hive' {
        Disable-Recall
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Path -eq 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -and
            $Name -eq 'DisableAIDataAnalysis' -and $Value -eq 1
        }
    }
    It 'creates both registry keys when they are missing' {
        Disable-Recall
        Should -Invoke New-Item -Times 2
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-CortanaAndBingSearch' {
    It 'disables Cortana via AllowCortana=0' {
        Disable-CortanaAndBingSearch
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'AllowCortana' -and $Value -eq 0
        }
    }
    It 'disables web search via DisableWebSearch=1' {
        Disable-CortanaAndBingSearch
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'DisableWebSearch' -and $Value -eq 1
        }
    }
    It 'disables Bing in user search via BingSearchEnabled=0' {
        Disable-CortanaAndBingSearch
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'BingSearchEnabled' -and $Value -eq 0
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-SuggestedContent' {
    It 'disables silent app installs' {
        Disable-SuggestedContent
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'SilentInstalledAppsEnabled' -and $Value -eq 0
        }
    }
    It 'disables Start Menu subscribed content (338388)' {
        Disable-SuggestedContent
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'SubscribedContent-338388Enabled' -and $Value -eq 0
        }
    }
    It 'disables system pane suggestions' {
        Disable-SuggestedContent
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'SystemPaneSuggestionsEnabled' -and $Value -eq 0
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-LockScreenAd' {
    It 'disables rotating lock screen' {
        Disable-LockScreenAd
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'RotatingLockScreenEnabled' -and $Value -eq 0
        }
    }
    It 'disables lock screen overlay' {
        Disable-LockScreenAd
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'RotatingLockScreenOverlayEnabled' -and $Value -eq 0
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-TailoredExperience' {
    It 'sets TailoredExperiencesWithDiagnosticDataEnabled=0' {
        Disable-TailoredExperience
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'TailoredExperiencesWithDiagnosticDataEnabled' -and $Value -eq 0
        }
    }
    It 'sets NumberOfSIUFInPeriod=0 to silence feedback prompts' {
        Disable-TailoredExperience
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'NumberOfSIUFInPeriod' -and $Value -eq 0
        }
    }

    Context 'when the ContentDeliveryManager key exists' {
        BeforeEach {
            Mock Test-Path { $true } -ParameterFilter {
                $Path -like '*ContentDeliveryManager'
            }
        }
        It 'also disables subscribed content 338389' {
            Disable-TailoredExperience
            Should -Invoke Set-ItemProperty -ParameterFilter {
                $Name -eq 'SubscribedContent-338389Enabled' -and $Value -eq 0
            }
        }
    }

    Context 'when the ContentDeliveryManager key is missing' {
        It 'does not attempt to write SubscribedContent-338389Enabled' {
            Disable-TailoredExperience
            Should -Invoke Set-ItemProperty -Times 0 -ParameterFilter {
                $Name -eq 'SubscribedContent-338389Enabled'
            }
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-EdgeSync' {
    It 'sets SyncDisabled=1' {
        Disable-EdgeSync
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'SyncDisabled' -and $Value -eq 1
        }
    }
    It 'sets MetricsReportingEnabled=0' {
        Disable-EdgeSync
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'MetricsReportingEnabled' -and $Value -eq 0
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-Smb1Protocol' {
    It 'calls Disable-WindowsOptionalFeature for SMB1Protocol' {
        Disable-Smb1Protocol
        Should -Invoke Disable-WindowsOptionalFeature -ParameterFilter {
            $FeatureName -eq 'SMB1Protocol'
        }
    }
    It 'sets SMB1=0 in the LanmanServer registry key' {
        Disable-Smb1Protocol
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'SMB1' -and $Value -eq 0
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Enable-NetworkProtection' {
    It 'calls Set-MpPreference with EnableNetworkProtection Enabled' {
        Enable-NetworkProtection
        Should -Invoke Set-MpPreference -ParameterFilter {
            $EnableNetworkProtection -eq 'Enabled'
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Enable-ControlledFolderAccess' {
    It 'calls Set-MpPreference with EnableControlledFolderAccess Enabled' {
        Enable-ControlledFolderAccess
        Should -Invoke Set-MpPreference -ParameterFilter {
            $EnableControlledFolderAccess -eq 'Enabled'
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Set-UacMax' {
    It 'sets ConsentPromptBehaviorAdmin=2' {
        Set-UacMax
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'ConsentPromptBehaviorAdmin' -and $Value -eq 2
        }
    }
    It 'sets PromptOnSecureDesktop=1' {
        Set-UacMax
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'PromptOnSecureDesktop' -and $Value -eq 1
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Disable-AutoRun' {
    It 'sets NoDriveTypeAutoRun=255' {
        Disable-AutoRun
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'NoDriveTypeAutoRun' -and $Value -eq 255
        }
    }
    It 'sets NoAutorun=1' {
        Disable-AutoRun
        Should -Invoke Set-ItemProperty -ParameterFilter {
            $Name -eq 'NoAutorun' -and $Value -eq 1
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Remove-BloatApp' {
    Context 'Mode 1 (common bloatware)' {
        It 'attempts removal of 19 known bloatware packages' {
            Remove-BloatApp -Mode 1
            Should -Invoke Get-AppxPackage -Times 19
        }
        It 'includes Microsoft.Clipchamp in the removal list' {
            Remove-BloatApp -Mode 1
            Should -Invoke Get-AppxPackage -ParameterFilter { $Name -eq 'Microsoft.Clipchamp' }
        }
        It 'includes MicrosoftTeams in the removal list' {
            Remove-BloatApp -Mode 1
            Should -Invoke Get-AppxPackage -ParameterFilter { $Name -eq 'MicrosoftTeams' }
        }
        It 'includes Microsoft.GamingApp in the removal list' {
            Remove-BloatApp -Mode 1
            Should -Invoke Get-AppxPackage -ParameterFilter { $Name -eq 'Microsoft.GamingApp' }
        }
    }

    Context 'Mode 2 (all non-essential apps)' {
        BeforeEach {
            $msPublisher = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
            $fakePackages = @(
                [PSCustomObject]@{ Name = 'Microsoft.WindowsStore'; Publisher = $msPublisher }
                [PSCustomObject]@{ Name = 'Microsoft.DesktopAppInstaller'; Publisher = $msPublisher }
                [PSCustomObject]@{ Name = 'Microsoft.WindowsCalculator'; Publisher = $msPublisher }
                [PSCustomObject]@{ Name = 'Microsoft.BingNews'; Publisher = $msPublisher }
                [PSCustomObject]@{ Name = 'Microsoft.XboxApp'; Publisher = $msPublisher }
                [PSCustomObject]@{ Name = 'Microsoft.Windows.StartMenuExperienceHost'; Publisher = $msPublisher }
                [PSCustomObject]@{ Name = 'Valve.Steam'; Publisher = 'CN=Valve Corporation, O=Valve Corporation, L=Bellevue, S=Washington, C=US' }
            )
            Mock Get-AppxPackage { $fakePackages } -ParameterFilter { $AllUsers -eq $true }
        }
        It 'excludes Windows Store from removal' {
            Remove-BloatApp -Mode 2
            Should -Invoke Get-AppxPackage -Times 0 -ParameterFilter {
                $Name -eq 'Microsoft.WindowsStore'
            }
        }
        It 'excludes Desktop App Installer from removal' {
            Remove-BloatApp -Mode 2
            Should -Invoke Get-AppxPackage -Times 0 -ParameterFilter {
                $Name -eq 'Microsoft.DesktopAppInstaller'
            }
        }
        It 'removes non-essential apps like BingNews' {
            Remove-BloatApp -Mode 2
            Should -Invoke Get-AppxPackage -ParameterFilter { $Name -eq 'Microsoft.BingNews' }
        }
        It 'excludes shell components like StartMenuExperienceHost even though Microsoft-published' {
            Remove-BloatApp -Mode 2
            Should -Invoke Get-AppxPackage -Times 0 -ParameterFilter {
                $Name -eq 'Microsoft.Windows.StartMenuExperienceHost'
            }
        }
        It 'excludes third-party packages such as a Steam-published game' {
            Remove-BloatApp -Mode 2
            Should -Invoke Get-AppxPackage -Times 0 -ParameterFilter {
                $Name -eq 'Valve.Steam'
            }
        }
    }

    Context 'Mode 0 (invalid / skip)' {
        It 'does not call Get-AppxPackage' {
            Remove-BloatApp -Mode 0
            Should -Invoke Get-AppxPackage -Times 0
        }
    }

    Context 'AppNames (explicit list, used by the confirmation dialog opt-out)' {
        It 'removes only the apps passed in, ignoring Mode-based scanning' {
            Remove-BloatApp -AppNames @('Microsoft.BingNews', 'MicrosoftTeams')
            Should -Invoke Get-AppxPackage -Times 2
            Should -Invoke Get-AppxPackage -ParameterFilter { $Name -eq 'Microsoft.BingNews' }
            Should -Invoke Get-AppxPackage -ParameterFilter { $Name -eq 'MicrosoftTeams' }
        }
        It 'removes nothing when given an empty list' {
            Remove-BloatApp -AppNames @()
            Should -Invoke Get-AppxPackage -Times 0
        }
    }

    Context 'Game Bar overlay cleanup' {
        It 'disables Game Bar/DVR hooks when Microsoft.XboxGamingOverlay is removed (Mode 1)' {
            Remove-BloatApp -Mode 1
            Should -Invoke Set-ItemProperty -ParameterFilter {
                $Name -eq 'AppCaptureEnabled' -and $Value -eq 0
            }
        }
        It 'disables Game Bar/DVR hooks when an Xbox overlay package is passed via AppNames' {
            Remove-BloatApp -AppNames @('Microsoft.Xbox.TCUI')
            Should -Invoke Set-ItemProperty -ParameterFilter {
                $Name -eq 'GameDVR_Enabled' -and $Value -eq 0
            }
        }
        It 'does not touch Game Bar/DVR hooks when no Xbox overlay package is removed' {
            Remove-BloatApp -AppNames @('Microsoft.BingNews')
            Should -Invoke Set-ItemProperty -Times 0 -ParameterFilter {
                $Name -eq 'AppCaptureEnabled'
            }
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-ProtectedAppxPackage' {
    It 'returns $true for an exact protected name' {
        Test-ProtectedAppxPackage -Name 'Microsoft.LockApp' | Should -Be $true
    }
    It 'returns $true for a versioned framework name matching a wildcard pattern' {
        Test-ProtectedAppxPackage -Name 'Microsoft.VCLibs.140.00.UWPDesktop' | Should -Be $true
    }
    It 'returns $true for VS Code (Store build)' {
        Test-ProtectedAppxPackage -Name 'Microsoft.VisualStudioCode' | Should -Be $true
    }
    It 'returns $true for VS Code Insiders' {
        Test-ProtectedAppxPackage -Name 'Microsoft.VisualStudioCode.Insiders' | Should -Be $true
    }
    It 'returns $false for an unrelated package name' {
        Test-ProtectedAppxPackage -Name 'Microsoft.BingNews' | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Get-AppsToRemove' {
    It 'Mode 1 returns the common bloatware list' {
        (Get-AppsToRemove -Mode 1) | Should -Be (Get-CommonBloatwareList)
    }
    It 'Mode 2 excludes protected and non-Microsoft-published packages' {
        $msPublisher = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
        Mock Get-AppxPackage {
            @(
                [PSCustomObject]@{ Name = 'Microsoft.BingNews'; Publisher = $msPublisher }
                [PSCustomObject]@{ Name = 'Microsoft.LockApp'; Publisher = $msPublisher }
                [PSCustomObject]@{ Name = 'Valve.Steam'; Publisher = 'CN=Valve Corporation' }
            )
        } -ParameterFilter { $AllUsers -eq $true }

        $result = Get-AppsToRemove -Mode 2
        $result | Should -Contain 'Microsoft.BingNews'
        $result | Should -Not -Contain 'Microsoft.LockApp'
        $result | Should -Not -Contain 'Valve.Steam'
    }
    It 'Mode 0 returns an empty list' {
        (Get-AppsToRemove -Mode 0).Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
Describe 'Restore-Default' {
    It 'removes the DataCollection policy key' {
        Restore-Default
        Should -Invoke Remove-Item -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        }
    }
    It 'removes the OneDrive policy key' {
        Restore-Default
        Should -Invoke Remove-Item -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
        }
    }
    It 'removes the System policy key' {
        Restore-Default
        Should -Invoke Remove-Item -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        }
    }
}

# ===========================================================================
# Privacy Scan: Status Checks
# ===========================================================================

# ---------------------------------------------------------------------------
Describe 'Test-TelemetryHardened' {
    It 'returns $true when telemetry and DiagTrack are disabled' {
        Mock Get-ItemProperty { [PSCustomObject]@{ AllowTelemetry = 0 } } -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        }
        Mock Get-Service { [PSCustomObject]@{ StartType = 'Disabled' } } -ParameterFilter {
            $Name -eq 'DiagTrack'
        }
        Test-TelemetryHardened | Should -Be $true
    }
    It 'returns $false when telemetry is still enabled' {
        Test-TelemetryHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-AdvertisingHardened' {
    It 'returns $true when Enabled=0' {
        Mock Get-ItemProperty { [PSCustomObject]@{ Enabled = 0 } } -ParameterFilter {
            $Path -eq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
        }
        Test-AdvertisingHardened | Should -Be $true
    }
    It 'returns $false when the key is missing' {
        Test-AdvertisingHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-LocationHardened' {
    It 'returns $true when Status=0' {
        Mock Get-ItemProperty { [PSCustomObject]@{ Status = 0 } } -ParameterFilter {
            $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
        }
        Test-LocationHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-LocationHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-ActivityHistoryHardened' {
    It 'returns $true when both values are 0' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PublishUserActivities = 0; UploadUserActivities = 0 }
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' }
        Test-ActivityHistoryHardened | Should -Be $true
    }
    It 'returns $false when only one value is hardened' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PublishUserActivities = 0; UploadUserActivities = 1 }
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' }
        Test-ActivityHistoryHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-RecallHardened' {
    It 'returns $true when DisableAIDataAnalysis=1' {
        Mock Get-ItemProperty { [PSCustomObject]@{ DisableAIDataAnalysis = 1 } } -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        }
        Test-RecallHardened | Should -Be $true
    }
    It 'returns $false when the policy key is missing' {
        Test-RecallHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-CortanaAndBingSearchHardened' {
    It 'returns $true when all three values are hardened' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ AllowCortana = 0; DisableWebSearch = 1 }
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ BingSearchEnabled = 0 }
        } -ParameterFilter { $Path -eq 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' }
        Test-CortanaAndBingSearchHardened | Should -Be $true
    }
    It 'returns $false when Bing search is still enabled' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ AllowCortana = 0; DisableWebSearch = 1 }
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ BingSearchEnabled = 1 }
        } -ParameterFilter { $Path -eq 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' }
        Test-CortanaAndBingSearchHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-SuggestedContentHardened' {
    It 'returns $true when all three CDM values are 0' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{
                SilentInstalledAppsEnabled        = 0
                'SubscribedContent-338388Enabled' = 0
                SystemPaneSuggestionsEnabled      = 0
            }
        } -ParameterFilter { $Path -eq 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' }
        Test-SuggestedContentHardened | Should -Be $true
    }
    It 'returns $false when the CDM key is missing' {
        Test-SuggestedContentHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-LockScreenAdHardened' {
    It 'returns $true when both lock screen values are 0' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ RotatingLockScreenEnabled = 0; RotatingLockScreenOverlayEnabled = 0 }
        } -ParameterFilter { $Path -eq 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' }
        Test-LockScreenAdHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-LockScreenAdHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-TailoredExperienceHardened' {
    It 'returns $true when TailoredExperiencesWithDiagnosticDataEnabled=0' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ TailoredExperiencesWithDiagnosticDataEnabled = 0 }
        } -ParameterFilter { $Path -eq 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' }
        Test-TailoredExperienceHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-TailoredExperienceHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-OneDriveHardened' {
    It 'returns $true when DisableFileSync=1' {
        Mock Get-ItemProperty { [PSCustomObject]@{ DisableFileSync = 1 } } -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
        }
        Test-OneDriveHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-OneDriveHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-BackgroundAppHardened' {
    It 'returns $true when GlobalUserDisabled=1' {
        Mock Get-ItemProperty { [PSCustomObject]@{ GlobalUserDisabled = 1 } } -ParameterFilter {
            $Path -eq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
        }
        Test-BackgroundAppHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-BackgroundAppHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-EdgeSyncHardened' {
    It 'returns $true when sync and metrics are disabled' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ SyncDisabled = 1; MetricsReportingEnabled = 0 }
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' }
        Test-EdgeSyncHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-EdgeSyncHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-Smb1ProtocolHardened' {
    It 'returns $true when SMB1=0' {
        Mock Get-ItemProperty { [PSCustomObject]@{ SMB1 = 0 } } -ParameterFilter {
            $Path -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        }
        Test-Smb1ProtocolHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-Smb1ProtocolHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-NetworkProtectionHardened' {
    It 'returns $true when EnableNetworkProtection=1' {
        Mock Get-MpPreference { [PSCustomObject]@{ EnableNetworkProtection = 1 } }
        Test-NetworkProtectionHardened | Should -Be $true
    }
    It 'returns $false when Get-MpPreference throws' {
        Mock Get-MpPreference { throw 'Defender unavailable' }
        Test-NetworkProtectionHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-ControlledFolderAccessHardened' {
    It 'returns $true when EnableControlledFolderAccess=1' {
        Mock Get-MpPreference { [PSCustomObject]@{ EnableControlledFolderAccess = 1 } }
        Test-ControlledFolderAccessHardened | Should -Be $true
    }
    It 'returns $false when Get-MpPreference throws' {
        Mock Get-MpPreference { throw 'Defender unavailable' }
        Test-ControlledFolderAccessHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-UacMaxHardened' {
    It 'returns $true when both UAC values are set' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ ConsentPromptBehaviorAdmin = 2; PromptOnSecureDesktop = 1 }
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' }
        Test-UacMaxHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-UacMaxHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-AutoRunHardened' {
    It 'returns $true when both AutoRun values are set' {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ NoDriveTypeAutoRun = 255; NoAutorun = 1 }
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' }
        Test-AutoRunHardened | Should -Be $true
    }
    It 'returns $false by default' {
        Test-AutoRunHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-BloatwareHardened' {
    It 'returns $true when none of the common bloatware list is installed' {
        Test-BloatwareHardened | Should -Be $true
    }
    It 'returns $false when a common bloatware app is still installed' {
        Mock Get-AppxPackage { @([PSCustomObject]@{ Name = 'Microsoft.BingNews' }) } -ParameterFilter {
            $AllUsers -eq $true
        }
        Test-BloatwareHardened | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Get-PrivacyChecklist' {
    It 'returns 18 checks' {
        (Get-PrivacyChecklist).Count | Should -Be 18
    }
    It 'every entry names a Test function that actually exists' {
        foreach ($c in Get-PrivacyChecklist) {
            Get-Command $c.Test -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Invoke-PrivacyScan' {
    BeforeEach {
        function Test-StubPass { $true }
        function Test-StubFail { $false }
        Mock Get-PrivacyChecklist {
            @(
                @{ Category = 'A'; Name = 'One';   Test = 'Test-StubPass' }
                @{ Category = 'A'; Name = 'Two';   Test = 'Test-StubPass' }
                @{ Category = 'B'; Name = 'Three'; Test = 'Test-StubFail' }
                @{ Category = 'B'; Name = 'Four';  Test = 'Test-StubFail' }
            )
        }
    }

    It 'computes the pass count and percentage correctly' {
        $scan = Invoke-PrivacyScan
        $scan.TotalChecks  | Should -Be 4
        $scan.PassedChecks | Should -Be 2
        $scan.ScorePercent | Should -Be 50
        $scan.Rating       | Should -Be 'Fair'
    }
    It 'logs a summary line' {
        Invoke-PrivacyScan
        Should -Invoke Log -ParameterFilter { $msg -like 'Privacy Scan: 2/4*' }
    }
}

} # Describe 'Win11PrivacyToolkit'
