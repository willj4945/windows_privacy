<#
.SYNOPSIS
Windows 11 Privacy Toolkit
Original Author: Will Johnson https://github.com/willj4945
Description: GUI-based tool to help users disable telemetry, ads, tracking, bloatware, and harden security.
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml

# --- Version ---
# The release workflow bakes the tag version into the compiled exe's Win32 version
# resource (ps2exe -version). Read it back from the running process so the GUI always
# reflects the exe that's actually on disk, with no separate value to keep in sync.
function Get-ToolkitVersion {
    try {
        $exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        if ([System.IO.Path]::GetFileNameWithoutExtension($exePath) -eq 'Win11PrivacyToolkit') {
            $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exePath).FileVersion
            if ($fileVersion -match '^(\d+\.\d+\.\d+)\.0$') { return "v$($Matches[1])" }
            if ($fileVersion) { return "v$fileVersion" }
        }
    } catch {
        Write-Verbose "Get-ToolkitVersion: failed to read version info: $_"
    }
    return 'dev build'
}
$script:ToolkitVersion = Get-ToolkitVersion

# --- Requires Administrator Privileges ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    [System.Windows.MessageBox]::Show(
        "Please run this script as Administrator.",
        "Administrator Required",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Warning)
    exit
}

# --- Global Config ---
$LogFile = "$PSScriptRoot\Win11PrivacyToolkit_Log.txt"
"=== Win11PrivacyToolkit Run @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $LogFile -Append

. "$PSScriptRoot\Win11PrivacyFunctions.ps1"

# =============================================================================
# Native Win11 chrome: dark title bar + Mica backdrop via DwmSetWindowAttribute
# =============================================================================
Add-Type -Namespace Win11PrivacyToolkit -Name NativeMethods -MemberDefinition @'
[DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@

$DWMWA_USE_IMMERSIVE_DARK_MODE = 20
$DWMWA_SYSTEMBACKDROP_TYPE     = 38
$DWMSBT_MAINWINDOW             = 2  # Mica

function Enable-Win11Chrome {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][System.Windows.Window] $TargetWindow)
    if (-not $PSCmdlet.ShouldProcess('window', 'Apply dark title bar and Mica backdrop')) { return }

    try {
        $hwnd = (New-Object System.Windows.Interop.WindowInteropHelper($TargetWindow)).Handle

        $darkMode = 1
        [Win11PrivacyToolkit.NativeMethods]::DwmSetWindowAttribute($hwnd, $DWMWA_USE_IMMERSIVE_DARK_MODE, [ref]$darkMode, 4) | Out-Null

        $backdrop = $DWMSBT_MAINWINDOW
        $hr = [Win11PrivacyToolkit.NativeMethods]::DwmSetWindowAttribute($hwnd, $DWMWA_SYSTEMBACKDROP_TYPE, [ref]$backdrop, 4)
        if ($hr -eq 0) {
            $TargetWindow.Background = [System.Windows.Media.Brushes]::Transparent
        }
    } catch {
        Write-Verbose "Enable-Win11Chrome: native dark title bar/Mica unavailable: $_"
    }
}

# --- Small helpers ---
function ConvertTo-Brush {
    param([Parameter(Mandatory)][string] $Hex)
    [System.Windows.Media.SolidColorBrush]([System.Windows.Media.ColorConverter]::ConvertFromString($Hex))
}

# WPF has no Application.DoEvents(). This pumps the dispatcher queue at Background
# priority so the UI repaints during the synchronous Apply loop, same role DoEvents
# played in the WinForms version.
function Invoke-UIRefresh {
    $frame = New-Object System.Windows.Threading.DispatcherFrame
    $callback = {
        param($f)
        $f.Continue = $false
        return $null
    }
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke(
        [System.Windows.Threading.DispatcherPriority]::Background,
        [System.Windows.Threading.DispatcherOperationCallback]$callback,
        $frame) | Out-Null
    [System.Windows.Threading.Dispatcher]::PushFrame($frame)
}

# =============================================================================
# Dark theme resource dictionary (shared by the main window and the app-removal
# confirmation dialog so both windows render identically).
# =============================================================================
$themeResources = @'
<ResourceDictionary>
    <SolidColorBrush x:Key="WindowBackgroundBrush" Color="#FF1F1F1F"/>
    <SolidColorBrush x:Key="CardBackgroundBrush"   Color="#FF2B2B2B"/>
    <SolidColorBrush x:Key="BorderBrush1"          Color="#FF3F3F3F"/>
    <SolidColorBrush x:Key="TextPrimaryBrush"      Color="#FFFFFFFF"/>
    <SolidColorBrush x:Key="TextSecondaryBrush"    Color="#FFB0B0B0"/>
    <SolidColorBrush x:Key="AccentBrush"           Color="#FF0078D4"/>
    <SolidColorBrush x:Key="ControlBackgroundBrush" Color="#FF333333"/>
    <SolidColorBrush x:Key="ControlHoverBrush"     Color="#FF3D3D3D"/>
    <SolidColorBrush x:Key="WarnBackgroundBrush"   Color="#FF3B321A"/>
    <SolidColorBrush x:Key="WarnBorderBrush"       Color="#FF6B5A26"/>
    <SolidColorBrush x:Key="WarnTextBrush"         Color="#FFE8C468"/>

    <Style x:Key="CardStyle" TargetType="Border">
        <Setter Property="Background" Value="{StaticResource CardBackgroundBrush}"/>
        <Setter Property="BorderBrush" Value="{StaticResource BorderBrush1}"/>
        <Setter Property="BorderThickness" Value="1"/>
        <Setter Property="CornerRadius" Value="6"/>
        <Setter Property="Padding" Value="12"/>
        <Setter Property="Margin" Value="0,0,0,12"/>
    </Style>
    <Style x:Key="CardHeaderStyle" TargetType="TextBlock">
        <Setter Property="FontWeight" Value="SemiBold"/>
        <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
        <Setter Property="Margin" Value="0,0,0,8"/>
    </Style>
    <Style x:Key="AccentButtonStyle" TargetType="Button">
        <Setter Property="Background" Value="{StaticResource AccentBrush}"/>
        <Setter Property="Foreground" Value="White"/>
        <Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
        <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <Style TargetType="TextBlock">
        <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
    </Style>

    <Style TargetType="Button">
        <Setter Property="Background" Value="{StaticResource ControlBackgroundBrush}"/>
        <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
        <Setter Property="BorderBrush" Value="{StaticResource BorderBrush1}"/>
        <Setter Property="BorderThickness" Value="1"/>
        <Setter Property="Padding" Value="10,4"/>
        <Setter Property="Cursor" Value="Hand"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="Button">
                    <Border x:Name="border" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="True">
                            <Setter TargetName="border" Property="Opacity" Value="0.85"/>
                        </Trigger>
                        <Trigger Property="IsPressed" Value="True">
                            <Setter TargetName="border" Property="Opacity" Value="0.7"/>
                        </Trigger>
                        <Trigger Property="IsEnabled" Value="False">
                            <Setter TargetName="border" Property="Opacity" Value="0.4"/>
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <Style TargetType="CheckBox">
        <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
        <Setter Property="Margin" Value="0,4"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="CheckBox">
                    <StackPanel Orientation="Horizontal">
                        <Border x:Name="box" Width="18" Height="18" CornerRadius="3" BorderThickness="1.5" BorderBrush="{StaticResource BorderBrush1}" Background="Transparent" VerticalAlignment="Center">
                            <Path x:Name="checkMark" Data="M2,7 L6,11 L14,2" Stroke="White" StrokeThickness="2" StrokeStartLineCap="Round" StrokeEndLineCap="Round" StrokeLineJoin="Round" Visibility="Collapsed"/>
                        </Border>
                        <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center"/>
                    </StackPanel>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsChecked" Value="True">
                            <Setter TargetName="box" Property="Background" Value="{StaticResource AccentBrush}"/>
                            <Setter TargetName="box" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                            <Setter TargetName="checkMark" Property="Visibility" Value="Visible"/>
                        </Trigger>
                        <Trigger Property="IsMouseOver" Value="True">
                            <Setter TargetName="box" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <Style TargetType="RadioButton">
        <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
        <Setter Property="Margin" Value="0,4"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="RadioButton">
                    <StackPanel Orientation="Horizontal">
                        <Grid Width="18" Height="18" VerticalAlignment="Center">
                            <Ellipse x:Name="outer" Width="18" Height="18" Stroke="{StaticResource BorderBrush1}" StrokeThickness="1.5" Fill="Transparent"/>
                            <Ellipse x:Name="dot" Width="8" Height="8" Fill="{StaticResource AccentBrush}" HorizontalAlignment="Center" VerticalAlignment="Center" Visibility="Collapsed"/>
                        </Grid>
                        <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center"/>
                    </StackPanel>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsChecked" Value="True">
                            <Setter TargetName="outer" Property="Stroke" Value="{StaticResource AccentBrush}"/>
                            <Setter TargetName="dot" Property="Visibility" Value="Visible"/>
                        </Trigger>
                        <Trigger Property="IsMouseOver" Value="True">
                            <Setter TargetName="outer" Property="Stroke" Value="{StaticResource AccentBrush}"/>
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <Style TargetType="TabControl">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="BorderThickness" Value="0"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="TabControl">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        <Border Grid.Row="0" BorderBrush="{StaticResource BorderBrush1}" BorderThickness="0,0,0,1">
                            <TabPanel IsItemsHost="True" Background="Transparent"/>
                        </Border>
                        <Border Grid.Row="1" Background="Transparent">
                            <ContentPresenter ContentSource="SelectedContent"/>
                        </Border>
                    </Grid>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>
    <Style TargetType="TabItem">
        <Setter Property="Foreground" Value="{StaticResource TextSecondaryBrush}"/>
        <Setter Property="Padding" Value="14,8"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="TabItem">
                    <Border x:Name="border" Background="Transparent" BorderThickness="0,0,0,2" BorderBrush="Transparent" Padding="{TemplateBinding Padding}">
                        <ContentPresenter x:Name="content" ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsSelected" Value="True">
                            <Setter TargetName="border" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
                        </Trigger>
                        <Trigger Property="IsMouseOver" Value="True">
                            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <Style TargetType="ListView">
        <Setter Property="Background" Value="{StaticResource CardBackgroundBrush}"/>
        <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
        <Setter Property="BorderBrush" Value="{StaticResource BorderBrush1}"/>
        <Setter Property="BorderThickness" Value="1"/>
    </Style>
    <Style TargetType="GridViewColumnHeader">
        <Setter Property="Background" Value="{StaticResource ControlBackgroundBrush}"/>
        <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
        <Setter Property="Padding" Value="6,4"/>
        <Setter Property="HorizontalContentAlignment" Value="Left"/>
        <Setter Property="BorderBrush" Value="{StaticResource BorderBrush1}"/>
        <Setter Property="BorderThickness" Value="0,0,1,1"/>
    </Style>

    <Style TargetType="ListBox">
        <Setter Property="Background" Value="{StaticResource CardBackgroundBrush}"/>
        <Setter Property="BorderBrush" Value="{StaticResource BorderBrush1}"/>
        <Setter Property="BorderThickness" Value="1"/>
    </Style>
    <Style TargetType="ListBoxItem">
        <Setter Property="Background" Value="Transparent"/>
        <Setter Property="Padding" Value="2"/>
        <Style.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Background" Value="{StaticResource ControlHoverBrush}"/>
            </Trigger>
        </Style.Triggers>
    </Style>

    <Style TargetType="ProgressBar">
        <Setter Property="Background" Value="{StaticResource ControlBackgroundBrush}"/>
        <Setter Property="Foreground" Value="{StaticResource AccentBrush}"/>
        <Setter Property="BorderThickness" Value="0"/>
        <Setter Property="Height" Value="6"/>
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="ProgressBar">
                    <Grid x:Name="TemplateRoot">
                        <Border Background="{TemplateBinding Background}" CornerRadius="3"/>
                        <Border x:Name="PART_Track" Background="Transparent" CornerRadius="3"/>
                        <Border x:Name="PART_Indicator" Background="{TemplateBinding Foreground}" CornerRadius="3" HorizontalAlignment="Left"/>
                    </Grid>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>
</ResourceDictionary>
'@

# =============================================================================
# Scrollable confirmation dialog (used for long app-removal lists)
# Returns a PSCustomObject: @{ Result = <bool>; SelectedApps = <string[]> }
# SelectedApps reflects only the items still checked when the user clicks "Remove Checked".
# =============================================================================
function Show-AppRemovalConfirmDialog {
    param(
        [Parameter(Mandatory)][string[]] $AppNames
    )

    $dlgXamlTemplate = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Confirm App Removal" Width="440" Height="560" MinWidth="360" MinHeight="400"
        WindowStartupLocation="CenterOwner" ResizeMode="CanResize"
        Background="#FF1F1F1F"
        FontFamily="Segoe UI" FontSize="13">
    <Window.Resources>
        {{THEME_RESOURCES}}
    </Window.Resources>
    <Grid Margin="14">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock x:Name="lblPrompt" Grid.Row="0" TextWrapping="Wrap" Margin="0,0,0,10"/>
        <Border Grid.Row="1" Style="{StaticResource CardStyle}" Margin="0" Padding="4">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
                <StackPanel x:Name="spApps" Margin="6"/>
            </ScrollViewer>
        </Border>
        <Grid Grid.Row="2" Margin="0,10,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Button x:Name="btnSelectAll" Grid.Column="0" Content="Select All" Margin="0,0,4,0" Padding="0,6"/>
            <Button x:Name="btnSelectNone" Grid.Column="1" Content="Select None" Margin="4,0,0,0" Padding="0,6"/>
        </Grid>
        <Grid Grid.Row="3" Margin="0,10,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Button x:Name="btnYes" Grid.Column="0" Content="Remove Checked" Style="{StaticResource AccentButtonStyle}" Margin="0,0,4,0" Padding="0,8"/>
            <Button x:Name="btnNo" Grid.Column="1" Content="Cancel" Margin="4,0,0,0" Padding="0,8"/>
        </Grid>
    </Grid>
</Window>
'@

    $dlgXaml = $dlgXamlTemplate.Replace('{{THEME_RESOURCES}}', $themeResources)
    $reader  = New-Object System.Xml.XmlNodeReader ([xml]$dlgXaml)
    $dlg     = [Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $window

    $lblPrompt     = $dlg.FindName('lblPrompt')
    $spApps        = $dlg.FindName('spApps')
    $btnSelectAll  = $dlg.FindName('btnSelectAll')
    $btnSelectNone = $dlg.FindName('btnSelectNone')
    $btnYes        = $dlg.FindName('btnYes')
    $btnNo         = $dlg.FindName('btnNo')

    $lblPrompt.Text = "Uncheck anything you want to keep. $($AppNames.Count) app(s) checked for removal:"

    $checkBoxes = foreach ($app in $AppNames) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content   = $app
        $cb.IsChecked = $true
        [void]$spApps.Children.Add($cb)
        $cb
    }

    $btnSelectAll.Add_Click({ foreach ($cb in $checkBoxes) { $cb.IsChecked = $true } })
    $btnSelectNone.Add_Click({ foreach ($cb in $checkBoxes) { $cb.IsChecked = $false } })
    $btnYes.Add_Click({ $dlg.DialogResult = $true })
    $btnNo.Add_Click({ $dlg.DialogResult = $false })

    Enable-Win11Chrome -TargetWindow $dlg
    $accepted = [bool]($dlg.ShowDialog())

    return [PSCustomObject]@{
        Result       = $accepted
        SelectedApps = @($checkBoxes | Where-Object { $_.IsChecked } | ForEach-Object { $_.Content })
    }
}

# =============================================================================
# GUI
# =============================================================================

$mainXamlTemplate = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows 11 Privacy Toolkit"
        Width="580" Height="720" MinWidth="520" MinHeight="600"
        WindowStartupLocation="CenterScreen" ResizeMode="CanResize"
        Background="#FF1F1F1F"
        Foreground="#FFFFFFFF"
        FontFamily="Segoe UI" FontSize="13"
        UseLayoutRounding="True">
    <Window.Resources>
        {{THEME_RESOURCES}}
    </Window.Resources>

    <Grid Margin="14">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Grid Grid.Row="0" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock Grid.Column="0" Text="Windows 11 Privacy Toolkit" FontSize="20" FontWeight="Bold" Foreground="{StaticResource AccentBrush}" VerticalAlignment="Center"/>
            <TextBlock x:Name="lblVersion" Grid.Column="1" Foreground="{StaticResource TextSecondaryBrush}" VerticalAlignment="Bottom"/>
        </Grid>

        <!-- Restore Point Warning -->
        <Border Grid.Row="1" Background="{StaticResource WarnBackgroundBrush}" BorderBrush="{StaticResource WarnBorderBrush}" BorderThickness="1" CornerRadius="4" Padding="10,6" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" Text="[!]  Create a restore point before applying changes." Foreground="{StaticResource WarnTextBrush}" VerticalAlignment="Center"/>
                <Button x:Name="btnRestorePoint" Grid.Column="1" Content="Create Restore Point" Padding="10,4"/>
            </Grid>
        </Border>

        <!-- Tabs -->
        <TabControl x:Name="tabCtrl" Grid.Row="2">

            <!-- TAB: Scan -->
            <TabItem Header="Scan">
                <Grid Margin="0,12,0,0">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <Border x:Name="pnlScoreHeader" Grid.Row="0" Style="{StaticResource CardStyle}">
                        <StackPanel>
                            <TextBlock x:Name="lblScoreBig" Text="Privacy Score: --" FontSize="16" FontWeight="Bold"/>
                            <TextBlock x:Name="lblRating" Text="Click Run Scan to check your current privacy status." Margin="0,4,0,0"/>
                        </StackPanel>
                    </Border>
                    <ListView x:Name="lvResults" Grid.Row="1">
                        <ListView.View>
                            <GridView>
                                <GridViewColumn Header="Category" Width="140" DisplayMemberBinding="{Binding Category}"/>
                                <GridViewColumn Header="Setting" Width="220" DisplayMemberBinding="{Binding Setting}"/>
                                <GridViewColumn Header="Status" Width="90" DisplayMemberBinding="{Binding Status}"/>
                            </GridView>
                        </ListView.View>
                        <ListView.ItemContainerStyle>
                            <Style TargetType="ListViewItem">
                                <Setter Property="Background" Value="Transparent"/>
                                <Setter Property="Padding" Value="4,3"/>
                                <Style.Triggers>
                                    <Trigger Property="IsMouseOver" Value="True">
                                        <Setter Property="Background" Value="{StaticResource ControlHoverBrush}"/>
                                    </Trigger>
                                    <DataTrigger Binding="{Binding Passed}" Value="True">
                                        <Setter Property="Foreground" Value="#FF7FD99A"/>
                                    </DataTrigger>
                                    <DataTrigger Binding="{Binding Passed}" Value="False">
                                        <Setter Property="Foreground" Value="#FFE58C8C"/>
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </ListView.ItemContainerStyle>
                    </ListView>
                    <Grid Grid.Row="2" Margin="0,10,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Button x:Name="btnRunScan" Grid.Column="0" Content="Run Scan" Padding="14,6"/>
                        <TextBlock x:Name="lblLastScan" Grid.Column="1" Text="Last scanned: never" Foreground="{StaticResource TextSecondaryBrush}" VerticalAlignment="Center" Margin="12,0,0,0"/>
                    </Grid>
                </Grid>
            </TabItem>

            <!-- TAB: Privacy -->
            <TabItem Header="Privacy">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="0,12,0,0">
                        <Border Style="{StaticResource CardStyle}">
                            <StackPanel>
                                <TextBlock Text="Tracking &amp; Data Collection" Style="{StaticResource CardHeaderStyle}"/>
                                <CheckBox x:Name="chkTelemetry" Content="Disable Telemetry &amp; Data Collection" IsChecked="True"/>
                                <CheckBox x:Name="chkAdvertising" Content="Disable Advertising ID" IsChecked="True"/>
                                <CheckBox x:Name="chkLocation" Content="Disable Location Services" IsChecked="True"/>
                                <CheckBox x:Name="chkActivity" Content="Disable Activity History" IsChecked="True"/>
                                <CheckBox x:Name="chkRecall" Content="Disable Windows Recall (AI Screenshot Feature)" IsChecked="True"/>
                                <CheckBox x:Name="chkCopilot" Content="Disable Windows Copilot" IsChecked="True"/>
                                <CheckBox x:Name="chkBingSearch" Content="Disable Cortana &amp; Bing Search in Start Menu" IsChecked="True"/>
                            </StackPanel>
                        </Border>
                        <Border Style="{StaticResource CardStyle}">
                            <StackPanel>
                                <TextBlock Text="Suggested Content &amp; Ads" Style="{StaticResource CardHeaderStyle}"/>
                                <CheckBox x:Name="chkSuggestedContent" Content="Disable Suggested Apps &amp; Start Menu Promotions" IsChecked="True"/>
                                <CheckBox x:Name="chkLockScreenAds" Content="Disable Lock Screen Spotlight &amp; Ads" IsChecked="True"/>
                                <CheckBox x:Name="chkTailoredExp" Content="Disable Tailored Experiences &amp; Feedback Prompts" IsChecked="True"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>

            <!-- TAB: Services -->
            <TabItem Header="Services">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="0,12,0,0">
                        <Border Style="{StaticResource CardStyle}">
                            <StackPanel>
                                <TextBlock Text="Microsoft Services" Style="{StaticResource CardHeaderStyle}"/>
                                <CheckBox x:Name="chkOneDrive" Content="Disable OneDrive Integration" IsChecked="True"/>
                                <CheckBox x:Name="chkBackground" Content="Disable Background Apps" IsChecked="True"/>
                                <CheckBox x:Name="chkEdge" Content="Disable Edge Sync &amp; Telemetry" IsChecked="True"/>
                                <CheckBox x:Name="chkDeliveryOpt" Content="Disable Delivery Optimization Peer-to-Peer Updates" IsChecked="True"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>

            <!-- TAB: Security -->
            <TabItem Header="Security">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="0,12,0,0">
                        <Border Style="{StaticResource CardStyle}">
                            <StackPanel>
                                <TextBlock Text="Security Hardening" Style="{StaticResource CardHeaderStyle}"/>
                                <CheckBox x:Name="chkSmb1" Content="Disable SMBv1  (Legacy Protocol - Ransomware Risk)" IsChecked="True"/>
                                <CheckBox x:Name="chkNetProtect" Content="Enable Network Protection  (Block Malicious Domains)" IsChecked="True"/>
                                <CheckBox x:Name="chkCfa" Content="Enable Controlled Folder Access  (Ransomware Protection)" IsChecked="True"/>
                                <CheckBox x:Name="chkUac" Content="Enforce UAC Maximum Level  (Credential Prompt)" IsChecked="True"/>
                                <CheckBox x:Name="chkAutoRun" Content="Disable AutoRun for All Drives  (USB Protection)" IsChecked="True"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>

            <!-- TAB: Bloatware -->
            <TabItem Header="Bloatware">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="0,12,0,0">
                        <Border Style="{StaticResource CardStyle}">
                            <StackPanel>
                                <TextBlock Text="Bloatware Removal" Style="{StaticResource CardHeaderStyle}"/>
                                <RadioButton x:Name="rdBloatNone" GroupName="BloatwareMode" Content="Skip bloatware removal" IsChecked="True"/>
                                <RadioButton x:Name="rdBloatCommon" GroupName="BloatwareMode" Content="Remove common bloatware  (Xbox, Teams, News, Clipchamp...)"/>
                                <RadioButton x:Name="rdBloatAll" GroupName="BloatwareMode" Content="Remove ALL Microsoft Store apps  (except essentials)"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>

        </TabControl>

        <!-- Action Buttons -->
        <Grid Grid.Row="3" Margin="0,12,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Button x:Name="btnApply" Grid.Column="0" Content="Apply Selected" Style="{StaticResource AccentButtonStyle}" Margin="0,0,6,0" Padding="0,8"/>
            <Button x:Name="btnRestoreDefaults" Grid.Column="1" Content="Restore Defaults" Margin="6,0,6,0" Padding="0,8"/>
            <Button x:Name="btnExit" Grid.Column="2" Content="Exit" Margin="6,0,0,0" Padding="0,8"/>
        </Grid>

        <!-- Separator -->
        <Border Grid.Row="4" Background="{StaticResource BorderBrush1}" Height="1" Margin="0,12,0,10"/>

        <!-- Status Area -->
        <ProgressBar x:Name="progressBar" Grid.Row="5" Minimum="0" Margin="0,0,0,6"/>
        <TextBlock x:Name="lblStatus" Grid.Row="6" Text="Status: Ready" Foreground="{StaticResource TextSecondaryBrush}"/>
    </Grid>
</Window>
'@

$mainXaml = $mainXamlTemplate.Replace('{{THEME_RESOURCES}}', $themeResources)
$reader   = New-Object System.Xml.XmlNodeReader ([xml]$mainXaml)
$window   = [Windows.Markup.XamlReader]::Load($reader)
$window.Title = "Windows 11 Privacy Toolkit - $script:ToolkitVersion"

$window.Add_SourceInitialized({ Enable-Win11Chrome -TargetWindow $window })

# --- Control references ---
$lblVersion         = $window.FindName('lblVersion')
$btnRestorePoint    = $window.FindName('btnRestorePoint')
$tabCtrl            = $window.FindName('tabCtrl')

$pnlScoreHeader     = $window.FindName('pnlScoreHeader')
$lblScoreBig        = $window.FindName('lblScoreBig')
$lblRating          = $window.FindName('lblRating')
$lvResults          = $window.FindName('lvResults')
$btnRunScan         = $window.FindName('btnRunScan')
$lblLastScan        = $window.FindName('lblLastScan')

$chkTelemetry          = $window.FindName('chkTelemetry')
$chkAdvertising        = $window.FindName('chkAdvertising')
$chkLocation           = $window.FindName('chkLocation')
$chkActivity           = $window.FindName('chkActivity')
$chkRecall             = $window.FindName('chkRecall')
$chkCopilot            = $window.FindName('chkCopilot')
$chkBingSearch         = $window.FindName('chkBingSearch')
$chkSuggestedContent   = $window.FindName('chkSuggestedContent')
$chkLockScreenAds      = $window.FindName('chkLockScreenAds')
$chkTailoredExp        = $window.FindName('chkTailoredExp')

$chkOneDrive        = $window.FindName('chkOneDrive')
$chkBackground      = $window.FindName('chkBackground')
$chkEdge            = $window.FindName('chkEdge')
$chkDeliveryOpt     = $window.FindName('chkDeliveryOpt')

$chkSmb1            = $window.FindName('chkSmb1')
$chkNetProtect      = $window.FindName('chkNetProtect')
$chkCfa             = $window.FindName('chkCfa')
$chkUac             = $window.FindName('chkUac')
$chkAutoRun         = $window.FindName('chkAutoRun')

$rdBloatCommon      = $window.FindName('rdBloatCommon')
$rdBloatAll         = $window.FindName('rdBloatAll')

$btnApply           = $window.FindName('btnApply')
$btnRestoreDefaults = $window.FindName('btnRestoreDefaults')
$btnExit            = $window.FindName('btnExit')

$progressBar        = $window.FindName('progressBar')
$lblStatus          = $window.FindName('lblStatus')

$lblVersion.Text = $script:ToolkitVersion

function Update-ScanUI {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not $PSCmdlet.ShouldProcess('Scan tab', 'Refresh privacy score')) { return }

    $scan = Invoke-PrivacyScan

    $lblScoreBig.Text = "Privacy Score: $($scan.ScorePercent)% ($($scan.Rating))"
    $lblRating.Text   = "$($scan.PassedChecks) of $($scan.TotalChecks) checks passed"

    switch ($scan.Rating) {
        'Excellent' { $bg = '#FF15321F'; $fg = '#FF7FD99A' }
        'Good'      { $bg = '#FF15263B'; $fg = '#FF7FB8F2' }
        'Fair'      { $bg = '#FF3B2E12'; $fg = '#FFE8A33D' }
        default     { $bg = '#FF3B1418'; $fg = '#FFE58C8C' }
    }
    $pnlScoreHeader.Background = ConvertTo-Brush $bg
    $lblScoreBig.Foreground    = ConvertTo-Brush $fg
    $lblRating.Foreground      = ConvertTo-Brush $fg

    $lvResults.Items.Clear()
    foreach ($r in $scan.Results) {
        $lvResults.Items.Add([PSCustomObject]@{
            Category = $r.Category
            Setting  = $r.Name
            Status   = if ($r.Passed) { 'Hardened' } else { 'Not Hardened' }
            Passed   = $r.Passed
        })
    }

    $lblLastScan.Text = "Last scanned: $((Get-Date).ToString('HH:mm:ss'))"
}

$btnRunScan.Add_Click({ Update-ScanUI })
$window.Add_ContentRendered({ Update-ScanUI })

$btnRestorePoint.Add_Click({
    $btnRestorePoint.IsEnabled = $false
    $lblStatus.Text = "Status: Creating restore point..."
    Invoke-UIRefresh
    if (New-RestorePoint) {
        $btnRestorePoint.Content = "[Done]"
        $lblStatus.Text = "Status: Restore point created."
    } else {
        $btnRestorePoint.IsEnabled = $true
        $lblStatus.Text = "Status: Failed to create restore point."
    }
})

$btnApply.Add_Click({
    $taskList = [System.Collections.Generic.List[scriptblock]]::new()
    if ($chkTelemetry.IsChecked)        { $taskList.Add({ Disable-Telemetry }) }
    if ($chkAdvertising.IsChecked)      { $taskList.Add({ Disable-Advertising }) }
    if ($chkLocation.IsChecked)         { $taskList.Add({ Disable-Location }) }
    if ($chkActivity.IsChecked)         { $taskList.Add({ Disable-ActivityHistory }) }
    if ($chkRecall.IsChecked)           { $taskList.Add({ Disable-Recall }) }
    if ($chkCopilot.IsChecked)          { $taskList.Add({ Disable-WindowsCopilot }) }
    if ($chkBingSearch.IsChecked)       { $taskList.Add({ Disable-CortanaAndBingSearch }) }
    if ($chkSuggestedContent.IsChecked) { $taskList.Add({ Disable-SuggestedContent }) }
    if ($chkLockScreenAds.IsChecked)    { $taskList.Add({ Disable-LockScreenAd }) }
    if ($chkTailoredExp.IsChecked)      { $taskList.Add({ Disable-TailoredExperience }) }
    if ($chkOneDrive.IsChecked)         { $taskList.Add({ Disable-OneDrive }) }
    if ($chkBackground.IsChecked)       { $taskList.Add({ Disable-BackgroundApp }) }
    if ($chkEdge.IsChecked)             { $taskList.Add({ Disable-EdgeSync }) }
    if ($chkDeliveryOpt.IsChecked)      { $taskList.Add({ Disable-DeliveryOptimizationP2P }) }
    if ($chkSmb1.IsChecked)             { $taskList.Add({ Disable-Smb1Protocol }) }
    if ($chkNetProtect.IsChecked)       { $taskList.Add({ Enable-NetworkProtection }) }
    if ($chkCfa.IsChecked)              { $taskList.Add({ Enable-ControlledFolderAccess }) }
    if ($chkUac.IsChecked)              { $taskList.Add({ Set-UacMax }) }
    if ($chkAutoRun.IsChecked)          { $taskList.Add({ Disable-AutoRun }) }
    if ($rdBloatCommon.IsChecked) {
        $taskList.Add({ Remove-BloatApp -Mode 1 })
    } elseif ($rdBloatAll.IsChecked) {
        $appsToRemove = Get-AppsToRemove -Mode 2
        if ($appsToRemove.Count -gt 0) {
            $confirm = Show-AppRemovalConfirmDialog -AppNames $appsToRemove
            if (-not $confirm.Result) { return }
            if ($confirm.SelectedApps.Count -eq 0) {
                [System.Windows.MessageBox]::Show(
                    "No apps were checked for removal.",
                    "Nothing Selected",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information)
                return
            }
            $selectedApps = $confirm.SelectedApps
            $taskList.Add({ Remove-BloatApp -AppNames $selectedApps })
        }
    }

    if ($taskList.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "Please select at least one option.",
            "Nothing Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    $btnApply.IsEnabled           = $false
    $btnRestoreDefaults.IsEnabled = $false
    $progressBar.Maximum          = $taskList.Count
    $progressBar.Value            = 0

    foreach ($task in $taskList) {
        $lblStatus.Text = "Status: Working..."
        Invoke-UIRefresh
        & $task
        $progressBar.Value++
        Invoke-UIRefresh
    }

    $lblStatus.Text               = "Status: Done. Log saved to: $LogFile"
    $btnApply.IsEnabled           = $true
    $btnRestoreDefaults.IsEnabled = $true

    Update-ScanUI
    $tabCtrl.SelectedIndex = 0

    [System.Windows.MessageBox]::Show(
        "All selected changes have been applied.`n`nA restart is recommended to complete the changes.",
        "Complete",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
})

$btnRestoreDefaults.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show(
        "This will revert most registry and service changes.`n`nContinue?",
        "Confirm Restore",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning)
    if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
        $lblStatus.Text = "Status: Restoring defaults..."
        Invoke-UIRefresh
        Restore-Default
        $lblStatus.Text = "Status: Defaults restored. Reboot recommended."
    }
})

$btnExit.Add_Click({ $window.Close() })

$window.ShowDialog() | Out-Null
