#Requires -Module Pester

BeforeAll {
    # Provide a temp log file so Log {} has a valid path if ever called un-mocked
    $script:LogFile = [System.IO.Path]::GetTempFileName()
    . "$PSScriptRoot\..\Win11PrivacyFunctions.ps1"
}

AfterAll {
    if (Test-Path $script:LogFile) { Remove-Item $script:LogFile -Force }
}

# ---------------------------------------------------------------------------
# Shared mocks applied before every test to suppress real system calls
# ---------------------------------------------------------------------------
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
            $fakePackages = @(
                [PSCustomObject]@{ Name = 'Microsoft.WindowsStore' },
                [PSCustomObject]@{ Name = 'Microsoft.DesktopAppInstaller' },
                [PSCustomObject]@{ Name = 'Microsoft.WindowsCalculator' },
                [PSCustomObject]@{ Name = 'Microsoft.BingNews' },
                [PSCustomObject]@{ Name = 'Microsoft.XboxApp' }
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
    }

    Context 'Mode 0 (invalid / skip)' {
        It 'does not call Get-AppxPackage' {
            Remove-BloatApp -Mode 0
            Should -Invoke Get-AppxPackage -Times 0
        }
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
