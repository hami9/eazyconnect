<#
.SYNOPSIS
    EazyConnect Modern Fluent WPF Prerequisite & Deployment Setup Wizard
    Supports Windows PowerShell 5.1+ and PowerShell 7+ (re-launches in STA if needed).
#>
[CmdletBinding()]
param(
    [ValidateSet('', 'client', 'server', 'full')]
    [string]$Role = ''
)

$ErrorActionPreference = 'Stop'

# Ensure STA apartment mode for WPF + WinForms FolderBrowserDialog
if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    $selfArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', $PSCommandPath)
    if ($Role) { $selfArgs += @('-Role', $Role) }
    $pwshExe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $pwshExe -ArgumentList $selfArgs
    exit 0
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ScriptDir = $PSScriptRoot
$RepoRoot = if (Test-Path (Join-Path $ScriptDir '..\Cargo.toml')) {
    (Resolve-Path (Join-Path $ScriptDir '..')).Path
} else {
    $ScriptDir
}

# --- XAML Definition (Fluent Dark Theme) ------------------------------------
[xml]$XAML = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="EazyConnect Setup &amp; Prerequisite Wizard"
        Height="720" Width="980" MinHeight="640" MinWidth="860"
        WindowStartupLocation="CenterScreen"
        Background="#0B1120" Foreground="#F1F5F9"
        FontFamily="Segoe UI">

    <Window.Resources>
        <Style TargetType="Button" x:Key="PrimaryBtn">
            <Setter Property="Background" Value="#0EA5E9"/>
            <Setter Property="Foreground" Value="#0B1120"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="16,9"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="7" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#38BDF8"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#334155"/>
                                <Setter Property="Foreground" Value="#94A3B8"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="Button" x:Key="SuccessBtn" BasedOn="{StaticResource PrimaryBtn}">
            <Setter Property="Background" Value="#10B981"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="7" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#34D399"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#334155"/>
                                <Setter Property="Foreground" Value="#94A3B8"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="Button" x:Key="GhostBtn">
            <Setter Property="Background" Value="#1E293B"/>
            <Setter Property="Foreground" Value="#E2E8F0"/>
            <Setter Property="FontWeight" Value="Medium"/>
            <Setter Property="FontSize" Value="12.5"/>
            <Setter Property="Padding" Value="13,8"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="7" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#334155"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Opacity" Value="0.5"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#0F172A"/>
            <Setter Property="Foreground" Value="#F1F5F9"/>
            <Setter Property="CaretBrush" Value="#38BDF8"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="FontSize" Value="12.5"/>
        </Style>

        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#E2E8F0"/>
            <Setter Property="FontSize" Value="12.5"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>

        <Style TargetType="RadioButton">
            <Setter Property="Foreground" Value="#F1F5F9"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#0F172A" BorderBrush="#1E293B" BorderThickness="0,0,0,1" Padding="24,18">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <Border Grid.Column="0" Width="44" Height="44" CornerRadius="10" Background="#0F172A" BorderBrush="#38BDF8" BorderThickness="2" Margin="0,0,14,0">
                    <Border Margin="8" Background="#38BDF8" CornerRadius="4"/>
                </Border>

                <StackPanel Grid.Column="1" VerticalAlignment="Center">
                    <TextBlock Text="EazyConnect Setup &amp; Prerequisite Wizard" FontSize="19" FontWeight="Bold" Foreground="#F8FAFC"/>
                    <TextBlock Text="Rust + CubeHash E2E Sync, Chat &amp; Hardware Bridge — Dual-Homed LAN &amp; VPN Edition" FontSize="12" Foreground="#94A3B8" Margin="0,2,0,0"/>
                </StackPanel>

                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <Border x:Name="VpnBadge" Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="10,5" Margin="0,0,8,0">
                        <TextBlock x:Name="VpnBadgeText" Text="Scanning VPN..." FontSize="11.5" Foreground="#94A3B8" FontWeight="SemiBold"/>
                    </Border>
                    <Border x:Name="AdminBadge" Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="10,5">
                        <TextBlock x:Name="AdminBadgeText" Text="User Mode" FontSize="11.5" Foreground="#94A3B8" FontWeight="SemiBold"/>
                    </Border>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Step Navigation Strip -->
        <Border Grid.Row="1" Background="#111827" BorderBrush="#1E293B" BorderThickness="0,0,0,1" Padding="24,10">
            <StackPanel Orientation="Horizontal">
                <Button x:Name="Step1Tab" Content="1. Prerequisites &amp; Dependencies" Style="{StaticResource PrimaryBtn}" Margin="0,0,10,0"/>
                <Button x:Name="Step2Tab" Content="2. Role, Build &amp; VPN Setup" Style="{StaticResource GhostBtn}" Margin="0,0,10,0"/>
                <Button x:Name="Step3Tab" Content="3. Install &amp; Launch" Style="{StaticResource GhostBtn}"/>
            </StackPanel>
        </Border>

        <!-- Main Content Area -->
        <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" Padding="24,18">
            <Grid>
                <!-- STEP 1: PREREQUISITES -->
                <StackPanel x:Name="Step1Panel" Visibility="Visible">
                    <Border Background="#162033" BorderBrush="#263554" BorderThickness="1" CornerRadius="10" Padding="18" Margin="0,0,0,14">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0">
                                <TextBlock Text="System Environment &amp; Prerequisite Scanner" FontSize="15.5" FontWeight="SemiBold" Foreground="#F8FAFC"/>
                                <TextBlock Text="Automatically inspects runtime libraries, Rust source-build tools, Git, and Windows Inno Setup via winget." FontSize="12" Foreground="#94A3B8" Margin="0,3,0,0"/>
                            </StackPanel>
                            <Button x:Name="BtnRescan" Grid.Column="1" Content="Re-Scan System" Style="{StaticResource GhostBtn}" VerticalAlignment="Center"/>
                        </Grid>
                    </Border>

                    <!-- Prereq Rows Container -->
                    <StackPanel x:Name="PrereqListPanel" Margin="0,0,0,14"/>

                    <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                        <Button x:Name="BtnInstallPrereqs" Content="Install Checked Missing Prerequisites (winget)" Style="{StaticResource SuccessBtn}" Margin="0,0,10,0"/>
                        <Button x:Name="BtnToStep2" Content="Next: Configure Role &amp; Network -&gt;" Style="{StaticResource PrimaryBtn}"/>
                    </StackPanel>
                </StackPanel>

                <!-- STEP 2: ROLE & NETWORK -->
                <StackPanel x:Name="Step2Panel" Visibility="Collapsed">
                    <Border Background="#162033" BorderBrush="#263554" BorderThickness="1" CornerRadius="10" Padding="18" Margin="0,0,0,14">
                        <StackPanel>
                            <TextBlock Text="Deployment Role &amp; Binaries Source" FontSize="15.5" FontWeight="SemiBold" Foreground="#F8FAFC" Margin="0,0,0,10"/>
                            <WrapPanel Margin="0,0,0,12">
                                <RadioButton x:Name="RbRoleClient" Content="Client Workstation (Native UI + CLI)" IsChecked="True" Margin="0,0,22,6"/>
                                <RadioButton x:Name="RbRoleServer" Content="Master Server (HTTPS + WSS Relay + Discovery)" Margin="0,0,22,6"/>
                                <RadioButton x:Name="RbRoleFull" Content="Full Node (Master Server + Native Client UI)" Margin="0,0,0,6"/>
                            </WrapPanel>

                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="150"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Install Directory:" VerticalAlignment="Center" Foreground="#CBD5E1"/>
                                <TextBox x:Name="TxtInstallDir" Grid.Column="1" Margin="0,0,8,0"/>
                                <Button x:Name="BtnBrowseInstallDir" Grid.Column="2" Content="Browse..." Style="{StaticResource GhostBtn}"/>
                            </Grid>

                            <StackPanel Orientation="Horizontal">
                                <RadioButton x:Name="RbSrcPrebuilt" Content="Use Prebuilt Release Binaries" IsChecked="True" Margin="0,0,20,0"/>
                                <RadioButton x:Name="RbSrcCargo" Content="Build Fresh Release Binaries (cargo build --release --bins)"/>
                            </StackPanel>
                            <TextBlock x:Name="TxtSourceStatus" Text="Checking release binaries..." FontSize="11.5" Foreground="#38BDF8" Margin="0,6,0,0"/>
                        </StackPanel>
                    </Border>

                    <!-- Client / Master Config -->
                    <Grid Margin="0,0,0,14">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="14"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Border Grid.Column="0" Background="#162033" BorderBrush="#263554" BorderThickness="1" CornerRadius="10" Padding="16">
                            <StackPanel>
                                <TextBlock Text="Connection &amp; Security Parameters" FontSize="14.5" FontWeight="SemiBold" Foreground="#F8FAFC" Margin="0,0,0,10"/>

                                <TextBlock Text="Master URL (for Client):" FontSize="12" Foreground="#94A3B8"/>
                                <Grid Margin="0,4,0,8">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="TxtMasterUrl" Grid.Column="0" Margin="0,0,6,0" Text="https://127.0.0.1:8000"/>
                                    <Button x:Name="BtnSetupDiscover" Grid.Column="1" Content="Discover" Style="{StaticResource GhostBtn}"/>
                                </Grid>

                                <TextBlock Text="TLS SHA-256 Pin (optional 64-hex):" FontSize="12" Foreground="#94A3B8"/>
                                <TextBox x:Name="TxtTlsPin" Margin="0,4,0,8"/>

                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="10"/>
                                        <ColumnDefinition Width="110"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Invite Code:" FontSize="12" Foreground="#94A3B8"/>
                                        <TextBox x:Name="TxtInviteCode" Margin="0,4,0,0" Text="EAZY-TEST-2026"/>
                                    </StackPanel>
                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="Master Port:" FontSize="12" Foreground="#94A3B8"/>
                                        <TextBox x:Name="TxtServerPort" Margin="0,4,0,0" Text="8000"/>
                                    </StackPanel>
                                </Grid>
                                <CheckBox x:Name="ChkLanOnly" Content="Restrict Master binding to primary LAN IP (--lan-only)" Margin="0,10,0,0"/>
                            </StackPanel>
                        </Border>

                        <Border Grid.Column="2" Background="#162033" BorderBrush="#263554" BorderThickness="1" CornerRadius="10" Padding="16">
                            <StackPanel>
                                <TextBlock Text="Windows &amp; VPN Integration" FontSize="14.5" FontWeight="SemiBold" Foreground="#F8FAFC" Margin="0,0,0,10"/>
                                <CheckBox x:Name="ChkDesktopShortcut" Content="Create Desktop &amp; Start Menu shortcuts (EazyConnect UI)" IsChecked="True" Margin="0,0,0,8"/>
                                <CheckBox x:Name="ChkFirewallRules" Content="Allow TCP 8000 &amp; UDP 37020 in Windows Firewall" IsChecked="True" Margin="0,0,0,8"/>
                                <CheckBox x:Name="ChkStartupTask" Content="Register Windows logon Startup Task (schtasks)" Margin="0,0,0,10"/>

                                <Border x:Name="VpnAdviceCard" Background="#0F172A" BorderBrush="#334155" BorderThickness="1" CornerRadius="8" Padding="12">
                                    <StackPanel>
                                        <TextBlock x:Name="TxtVpnAdviceTitle" Text="Network &amp; VPN Status" FontWeight="SemiBold" Foreground="#F59E0B" FontSize="12.5"/>
                                        <TextBlock x:Name="TxtVpnAdviceBody" TextWrapping="Wrap" FontSize="11.5" Foreground="#CBD5E1" Margin="0,4,0,8" Text="Checking active network adapters..."/>
                                        <Button x:Name="BtnElevateSetup" Content="Re-launch Setup as Administrator (for Firewall / Routes)" Style="{StaticResource GhostBtn}"/>
                                    </StackPanel>
                                </Border>
                            </StackPanel>
                        </Border>
                    </Grid>

                    <StackPanel Orientation="Horizontal">
                        <Button x:Name="BtnBackToStep1" Content="&lt;- Back" Style="{StaticResource GhostBtn}" Margin="0,0,10,0"/>
                        <Button x:Name="BtnStartInstall" Content="Install &amp; Configure EazyConnect" Style="{StaticResource SuccessBtn}"/>
                    </StackPanel>
                </StackPanel>

                <!-- STEP 3: PROGRESS & COMPLETION -->
                <StackPanel x:Name="Step3Panel" Visibility="Collapsed">
                    <Border Background="#162033" BorderBrush="#263554" BorderThickness="1" CornerRadius="10" Padding="18" Margin="0,0,0,14">
                        <StackPanel>
                            <Grid Margin="0,0,0,8">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock x:Name="TxtProgressTitle" Grid.Column="0" Text="Ready to install" FontSize="15.5" FontWeight="SemiBold" Foreground="#F8FAFC"/>
                                <TextBlock x:Name="TxtProgressPct" Grid.Column="1" Text="0%" FontSize="14" FontWeight="Bold" Foreground="#38BDF8"/>
                            </Grid>
                            <ProgressBar x:Name="InstallProgressBar" Height="10" Minimum="0" Maximum="100" Value="0" Background="#0F172A" Foreground="#10B981" BorderThickness="0"/>
                        </StackPanel>
                    </Border>

                    <StackPanel x:Name="CompletionActions" Orientation="Horizontal" Margin="0,0,0,12" Visibility="Collapsed">
                        <Button x:Name="BtnLaunchUi" Content="Launch EazyConnect Native UI" Style="{StaticResource PrimaryBtn}" Margin="0,0,10,0"/>
                        <Button x:Name="BtnLaunchServer" Content="Start Master Server Window" Style="{StaticResource SuccessBtn}" Margin="0,0,10,0"/>
                        <Button x:Name="BtnOpenInstallDir" Content="Open Install Folder" Style="{StaticResource GhostBtn}"/>
                    </StackPanel>
                </StackPanel>
            </Grid>
        </ScrollViewer>

        <!-- Bottom Live Installer Log -->
        <Border Grid.Row="3" Background="#0F172A" BorderBrush="#1E293B" BorderThickness="0,1,0,0" Padding="24,12">
            <StackPanel>
                <Grid Margin="0,0,0,6">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock Grid.Column="0" Text="Live Installer &amp; Prerequisite Script Output" FontSize="12" FontWeight="SemiBold" Foreground="#94A3B8"/>
                    <ProgressBar x:Name="MiniProgressBar" Grid.Column="1" Width="180" Height="6" Minimum="0" Maximum="100" Value="0" Background="#1E293B" Foreground="#38BDF8" BorderThickness="0" VerticalAlignment="Center"/>
                </Grid>
                <TextBox x:Name="TxtLog" Height="115" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="11.5" Background="#070B14" Foreground="#CBD5E1" BorderBrush="#1E293B"/>
            </StackPanel>
        </Border>
    </Grid>
</Window>
"@

$Reader = New-Object System.Xml.XmlNodeReader $XAML
$Window = [Windows.Markup.XamlReader]::Load($Reader)

# --- Bind Named Controls ----------------------------------------------------
$VpnBadgeText = $Window.FindName("VpnBadgeText")
$VpnBadge = $Window.FindName("VpnBadge")
$AdminBadgeText = $Window.FindName("AdminBadgeText")
$AdminBadge = $Window.FindName("AdminBadge")

$Step1Tab = $Window.FindName("Step1Tab")
$Step2Tab = $Window.FindName("Step2Tab")
$Step3Tab = $Window.FindName("Step3Tab")
$Step1Panel = $Window.FindName("Step1Panel")
$Step2Panel = $Window.FindName("Step2Panel")
$Step3Panel = $Window.FindName("Step3Panel")

$PrereqListPanel = $Window.FindName("PrereqListPanel")
$BtnRescan = $Window.FindName("BtnRescan")
$BtnInstallPrereqs = $Window.FindName("BtnInstallPrereqs")
$BtnToStep2 = $Window.FindName("BtnToStep2")

$RbRoleClient = $Window.FindName("RbRoleClient")
$RbRoleServer = $Window.FindName("RbRoleServer")
$RbRoleFull = $Window.FindName("RbRoleFull")
$TxtInstallDir = $Window.FindName("TxtInstallDir")
$BtnBrowseInstallDir = $Window.FindName("BtnBrowseInstallDir")
$RbSrcPrebuilt = $Window.FindName("RbSrcPrebuilt")
$RbSrcCargo = $Window.FindName("RbSrcCargo")
$TxtSourceStatus = $Window.FindName("TxtSourceStatus")

$TxtMasterUrl = $Window.FindName("TxtMasterUrl")
$BtnSetupDiscover = $Window.FindName("BtnSetupDiscover")
$TxtTlsPin = $Window.FindName("TxtTlsPin")
$TxtInviteCode = $Window.FindName("TxtInviteCode")
$TxtServerPort = $Window.FindName("TxtServerPort")
$ChkLanOnly = $Window.FindName("ChkLanOnly")
$ChkDesktopShortcut = $Window.FindName("ChkDesktopShortcut")
$ChkFirewallRules = $Window.FindName("ChkFirewallRules")
$ChkStartupTask = $Window.FindName("ChkStartupTask")
$TxtVpnAdviceTitle = $Window.FindName("TxtVpnAdviceTitle")
$TxtVpnAdviceBody = $Window.FindName("TxtVpnAdviceBody")
$BtnElevateSetup = $Window.FindName("BtnElevateSetup")
$BtnBackToStep1 = $Window.FindName("BtnBackToStep1")
$BtnStartInstall = $Window.FindName("BtnStartInstall")

$TxtProgressTitle = $Window.FindName("TxtProgressTitle")
$TxtProgressPct = $Window.FindName("TxtProgressPct")
$InstallProgressBar = $Window.FindName("InstallProgressBar")
$MiniProgressBar = $Window.FindName("MiniProgressBar")
$CompletionActions = $Window.FindName("CompletionActions")
$BtnLaunchUi = $Window.FindName("BtnLaunchUi")
$BtnLaunchServer = $Window.FindName("BtnLaunchServer")
$BtnOpenInstallDir = $Window.FindName("BtnOpenInstallDir")
$TxtLog = $Window.FindName("TxtLog")

# --- Shared UI Helpers ------------------------------------------------------
$State = [hashtable]::Synchronized(@{
    Window = $Window
    LogBox = $TxtLog
    PrereqChecks = @{}
    Busy = $false
})

function Append-Log([string]$Line) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $Window.Dispatcher.Invoke([Action]{
        $TxtLog.AppendText("[$ts] $Line`r`n")
        $TxtLog.ScrollToEnd()
    })
}

function Set-Progress([int]$Pct, [string]$Title) {
    $Window.Dispatcher.Invoke([Action]{
        $InstallProgressBar.Value = $Pct
        $MiniProgressBar.Value = $Pct
        $TxtProgressPct.Text = "$Pct%"
        if ($Title) { $TxtProgressTitle.Text = $Title }
    })
}

function Switch-Step([int]$Step) {
    $Step1Panel.Visibility = if ($Step -eq 1) { 'Visible' } else { 'Collapsed' }
    $Step2Panel.Visibility = if ($Step -eq 2) { 'Visible' } else { 'Collapsed' }
    $Step3Panel.Visibility = if ($Step -eq 3) { 'Visible' } else { 'Collapsed' }

    $Step1Tab.Style = if ($Step -eq 1) { $Window.FindResource("PrimaryBtn") } else { $Window.FindResource("GhostBtn") }
    $Step2Tab.Style = if ($Step -eq 2) { $Window.FindResource("PrimaryBtn") } else { $Window.FindResource("GhostBtn") }
    $Step3Tab.Style = if ($Step -eq 3) { $Window.FindResource("PrimaryBtn") } else { $Window.FindResource("GhostBtn") }
}

function Run-BackgroundTask([scriptblock]$Work) {
    if ($State.Busy) {
        Append-Log "Another operation is currently running; please wait."
        return
    }
    $State.Busy = $true
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript($Work).AddArgument($State)
    $null = $ps.BeginInvoke()
}

# --- Prerequisite & Environment Inspection ----------------------------------
$PrereqSpecs = @(
    @{
        Key = 'winget'
        Name = 'Windows Package Manager (winget)'
        Desc = 'Required for automated 1-click prerequisite installation.'
        WingetId = ''
        Optional = $false
        Check = {
            $cmd = Get-Command winget -ErrorAction SilentlyContinue
            if ($cmd) { return @{ Installed = $true; Status = 'Ready (winget available)' } }
            return @{ Installed = $false; Status = 'Missing (install App Installer from Microsoft Store)' }
        }
    },
    @{
        Key = 'vcredist'
        Name = 'Microsoft Visual C++ 2015-2022 Redistributable (x64)'
        Desc = 'Native C runtime prerequisite required by Windows desktop binaries.'
        WingetId = 'Microsoft.VCRedist.2015+.x64'
        Optional = $false
        Check = {
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue
            if ($reg -and $reg.Installed -eq 1) {
                return @{ Installed = $true; Status = "Installed (v$($reg.Major).$($reg.Minor).$($reg.Bld))" }
            }
            return @{ Installed = $false; Status = 'Missing (recommended)' }
        }
    },
    @{
        Key = 'rust'
        Name = 'Rust Toolchain (rustup / cargo / rustc)'
        Desc = 'Needed when building binaries from source (not needed for prebuilt .exe deployment).'
        WingetId = 'Rustlang.Rustup'
        Optional = $true
        Check = {
            $cargo = Get-Command cargo -ErrorAction SilentlyContinue
            if ($cargo) {
                $ver = (& cargo --version 2>$null | Select-Object -First 1)
                return @{ Installed = $true; Status = "Installed ($ver)" }
            }
            return @{ Installed = $false; Status = 'Not installed (optional for prebuilt .exe)' }
        }
    },
    @{
        Key = 'msvc'
        Name = 'Visual Studio C++ Build Tools (MSVC Linker)'
        Desc = 'Required alongside Rust only if compiling EazyConnect from source.'
        WingetId = 'Microsoft.VisualStudio.2022.BuildTools'
        WingetArgs = '--override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
        Optional = $true
        Check = {
            $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
            if (Test-Path $vswhere) {
                $vcPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
                if ($vcPath) { return @{ Installed = $true; Status = 'Installed (MSVC x64 detected)' } }
            }
            return @{ Installed = $false; Status = 'Not detected (needed only for Rust builds)' }
        }
    },
    @{
        Key = 'git'
        Name = 'Git for Windows'
        Desc = 'Optional source updates and repository syncing.'
        WingetId = 'Git.Git'
        Optional = $true
        Check = {
            $g = Get-Command git -ErrorAction SilentlyContinue
            if ($g) {
                $ver = (& git --version 2>$null | Select-Object -First 1)
                return @{ Installed = $true; Status = "Installed ($ver)" }
            }
            return @{ Installed = $false; Status = 'Missing (optional)' }
        }
    },
    @{
        Key = 'inno'
        Name = 'Inno Setup 6 Compiler (ISCC.exe)'
        Desc = 'Optional packaging tool to compile standalone EazyConnect-Setup.exe.'
        WingetId = 'JRSoftware.InnoSetup'
        Optional = $true
        Check = {
            $cands = @(
                (Get-Command iscc -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }),
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
                "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
            ) | Where-Object { $_ -and (Test-Path $_) }
            if ($cands) { return @{ Installed = $true; Status = 'Installed (ISCC.exe found)' } }
            return @{ Installed = $false; Status = 'Not installed (optional packager)' }
        }
    }
)

function Refresh-Prerequisites {
    $PrereqListPanel.Children.Clear()
    $State.PrereqChecks.Clear()

    foreach ($spec in $PrereqSpecs) {
        $res = & $spec.Check

        $card = New-Object System.Windows.Controls.Border
        $card.Background = [Windows.Media.BrushConverter]::new().ConvertFrom('#162033')
        $card.BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFrom('#263554')
        $card.BorderThickness = '1'
        $card.CornerRadius = '8'
        $card.Padding = '14,10'
        $card.Margin = '0,0,0,8'

        $grid = New-Object System.Windows.Controls.Grid
        $col0 = New-Object System.Windows.Controls.ColumnDefinition; $col0.Width = 'Auto'
        $col1 = New-Object System.Windows.Controls.ColumnDefinition; $col1.Width = '*'
        $col2 = New-Object System.Windows.Controls.ColumnDefinition; $col2.Width = 'Auto'
        $grid.ColumnDefinitions.Add($col0); $grid.ColumnDefinitions.Add($col1); $grid.ColumnDefinitions.Add($col2)

        $chk = New-Object System.Windows.Controls.CheckBox
        $chk.Margin = '0,0,12,0'
        $chk.VerticalAlignment = 'Center'
        $chk.IsEnabled = (-not $res.Installed) -and ([bool]$spec.WingetId)
        $chk.IsChecked = (-not $res.Installed) -and (-not $spec.Optional) -and ([bool]$spec.WingetId)
        [System.Windows.Controls.Grid]::SetColumn($chk, 0)

        $textStack = New-Object System.Windows.Controls.StackPanel
        $lblName = New-Object System.Windows.Controls.TextBlock
        $lblName.Text = $spec.Name
        $lblName.FontWeight = 'SemiBold'
        $lblName.FontSize = 13
        $lblName.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom('#F8FAFC')
        $lblDesc = New-Object System.Windows.Controls.TextBlock
        $lblDesc.Text = $spec.Desc
        $lblDesc.FontSize = 11.5
        $lblDesc.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom('#94A3B8')
        $null = $textStack.Children.Add($lblName)
        $null = $textStack.Children.Add($lblDesc)
        [System.Windows.Controls.Grid]::SetColumn($textStack, 1)

        $badge = New-Object System.Windows.Controls.Border
        $badge.CornerRadius = '6'
        $badge.Padding = '10,4'
        $badge.VerticalAlignment = 'Center'
        $badgeColor = if ($res.Installed) { '#10B981' } elseif ($spec.Optional) { '#F59E0B' } else { '#F43F5E' }
        $badge.Background = [Windows.Media.BrushConverter]::new().ConvertFrom('#0F172A')
        $badge.BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFrom($badgeColor)
        $badge.BorderThickness = '1'
        $badgeText = New-Object System.Windows.Controls.TextBlock
        $badgeText.Text = $res.Status
        $badgeText.FontSize = 11.5
        $badgeText.FontWeight = 'SemiBold'
        $badgeText.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom($badgeColor)
        $badge.Child = $badgeText
        [System.Windows.Controls.Grid]::SetColumn($badge, 2)

        $null = $grid.Children.Add($chk)
        $null = $grid.Children.Add($textStack)
        $null = $grid.Children.Add($badge)
        $card.Child = $grid
        $null = $PrereqListPanel.Children.Add($card)

        $State.PrereqChecks[$spec.Key] = @{ CheckBox = $chk; Spec = $spec; Installed = $res.Installed }
    }
}

function Refresh-HostStatus {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $AdminBadgeText.Text = "Admin Elevated"
        $AdminBadgeText.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom('#10B981')
        $AdminBadge.BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFrom('#10B981')
        $BtnElevateSetup.Visibility = 'Collapsed'
    } else {
        $AdminBadgeText.Text = "Standard User"
        $AdminBadgeText.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom('#F59E0B')
        $AdminBadge.BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFrom('#F59E0B')
        $BtnElevateSetup.Visibility = 'Visible'
    }

    $vpns = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and ($_.Name -match 'VPN|TAP|TUN|Wintun|WireGuard|OpenVPN|Windscribe|Cisco|Tailscale|ZeroTier|WARP|Proton|Mullvad|Forti|Outline|Nekoray|SoftEther' -or
        $_.InterfaceDescription -match 'VPN|TAP|TUN|Wintun|WireGuard|OpenVPN|Windscribe|Cisco|Tailscale|ZeroTier|WARP|Proton|Mullvad|Forti|Outline|Nekoray|SoftEther')
    }
    if ($vpns) {
        $vpnNames = ($vpns.Name | Select-Object -Unique) -join ', '
        $VpnBadgeText.Text = "VPN: $vpnNames"
        $VpnBadgeText.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom('#F59E0B')
        $VpnBadge.BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFrom('#F59E0B')
        $TxtVpnAdviceTitle.Text = "Active VPN Detected: $vpnNames"
        $TxtVpnAdviceBody.Text = "For Mesh VPNs (WireGuard/Tailscale/ZeroTier), use the VPN IP cleanly. For Exit VPNs (Windscribe/WARP/etc.) when using LAN peers, enable 'Allow LAN Traffic' in your VPN firewall settings."
    } else {
        $VpnBadgeText.Text = "LAN Direct"
        $VpnBadgeText.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom('#10B981')
        $VpnBadge.BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFrom('#10B981')
        $TxtVpnAdviceTitle.Text = "Direct LAN Network Active"
        $TxtVpnAdviceBody.Text = "No active Exit VPN interference detected. UDP 37020 discovery and HTTPS/WSS will operate directly over your active LAN interface."
    }

    $defaultDir = if ($isAdmin) {
        Join-Path $env:ProgramFiles 'EazyConnect'
    } else {
        Join-Path $env:LOCALAPPDATA 'Programs\EazyConnect'
    }
    if (-not $TxtInstallDir.Text) { $TxtInstallDir.Text = $defaultDir }

    $prebuiltDir = Find-PrebuiltBinaryDir
    $hasCargo = Test-Path (Join-Path $RepoRoot 'Cargo.toml')
    if ($prebuiltDir) {
        $TxtSourceStatus.Text = "Found prebuilt binaries in: $prebuiltDir"
        $RbSrcPrebuilt.IsEnabled = $true
        $RbSrcPrebuilt.IsChecked = $true
    } elseif ($hasCargo) {
        $TxtSourceStatus.Text = "No prebuilt binaries found yet — Cargo release build selected automatically."
        $RbSrcCargo.IsChecked = $true
        $RbSrcPrebuilt.IsEnabled = $false
    } else {
        $TxtSourceStatus.Text = "WARNING: Neither prebuilt binaries nor Cargo.toml found next to installer."
    }
    $RbSrcCargo.IsEnabled = $hasCargo
}

function Find-PrebuiltBinaryDir {
    $candidates = @(
        (Join-Path $RepoRoot 'target\release'),
        $RepoRoot,
        $ScriptDir
    )
    foreach ($dir in $candidates) {
        if ((Test-Path (Join-Path $dir 'eazyconnect-ui.exe')) -or (Test-Path (Join-Path $dir 'eazyconnect-client.exe')) -or (Test-Path (Join-Path $dir 'eazyconnect-server.exe'))) {
            return $dir
        }
    }
    return $null
}

# --- Button Handlers --------------------------------------------------------
$Step1Tab.Add_Click({ Switch-Step 1 })
$Step2Tab.Add_Click({ Switch-Step 2 })
$Step3Tab.Add_Click({ Switch-Step 3 })
$BtnToStep2.Add_Click({ Switch-Step 2 })
$BtnBackToStep1.Add_Click({ Switch-Step 1 })

$BtnRescan.Add_Click({
    Refresh-Prerequisites
    Refresh-HostStatus
    Append-Log "Re-scanned prerequisites, active VPN adapters, and release binaries."
})

$BtnBrowseInstallDir.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Choose EazyConnect installation directory"
    $dlg.SelectedPath = $TxtInstallDir.Text
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $TxtInstallDir.Text = $dlg.SelectedPath
    }
})

$BtnElevateSetup.Add_Click({
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    $selectedRole = if ($RbRoleServer.IsChecked) { 'server' } elseif ($RbRoleFull.IsChecked) { 'full' } else { 'client' }
    $args += @('-Role', $selectedRole)
    try {
        Start-Process -FilePath ((Get-Process -Id $PID).Path) -ArgumentList $args -Verb RunAs
        $Window.Close()
    } catch {
        Append-Log "Elevation cancelled or failed: $_"
    }
})

$BtnInstallPrereqs.Add_Click({
    $toInstall = @()
    foreach ($kv in $State.PrereqChecks.GetEnumerator()) {
        $item = $kv.Value
        if ($item.CheckBox.IsChecked -and $item.Spec.WingetId) {
            $toInstall += $item.Spec
        }
    }
    if ($toInstall.Count -eq 0) {
        Append-Log "No missing checked prerequisites selected."
        return
    }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Append-Log "ERROR: winget is missing on this machine. Install 'App Installer' from Microsoft Store first."
        return
    }

    Switch-Step 3
    $CompletionActions.Visibility = 'Collapsed'
    Set-Progress 5 "Installing prerequisites..."

    $itemsSnapshot = $toInstall
    Run-BackgroundTask {
        param($S)
        $win = $S.Window
        $log = {
            param($m)
            $ts = (Get-Date).ToString("HH:mm:ss")
            $win.Dispatcher.Invoke([Action]{
                $S.LogBox.AppendText("[$ts] $m`r`n")
                $S.LogBox.ScrollToEnd()
            })
        }
        $total = $using:itemsSnapshot.Count
        $idx = 0
        foreach ($spec in $using:itemsSnapshot) {
            $idx++
            $pct = [int](($idx - 1) * 100 / $total)
            $win.Dispatcher.Invoke([Action]{
                $win.FindName("InstallProgressBar").Value = $pct
                $win.FindName("MiniProgressBar").Value = $pct
                $win.FindName("TxtProgressPct").Text = "$pct%"
                $win.FindName("TxtProgressTitle").Text = "Installing $($spec.Name)..."
            })
            & $log "Running: winget install --id $($spec.WingetId) --silent ..."
            $wingetArgs = "install --id $($spec.WingetId) -e --accept-package-agreements --accept-source-agreements --silent"
            if ($spec.WingetArgs) { $wingetArgs += " $($spec.WingetArgs)" }
            $proc = Start-Process -FilePath "winget.exe" -ArgumentList $wingetArgs -Wait -PassThru -WindowStyle Hidden
            & $log "Finished $($spec.WingetId) with exit code $($proc.ExitCode)."
        }
        $win.Dispatcher.Invoke([Action]{
            $win.FindName("InstallProgressBar").Value = 100
            $win.FindName("MiniProgressBar").Value = 100
            $win.FindName("TxtProgressPct").Text = "100%"
            $win.FindName("TxtProgressTitle").Text = "Prerequisite installation finished. Re-scanning..."
        })
        $S.Busy = $false
        $win.Dispatcher.Invoke([Action]{
            Refresh-Prerequisites
            Switch-Step 1
        })
    }
})

$BtnSetupDiscover.Add_Click({
    $pre = Find-PrebuiltBinaryDir
    $cliExe = if ($pre -and (Test-Path (Join-Path $pre 'eazyconnect-client.exe'))) {
        Join-Path $pre 'eazyconnect-client.exe'
    } else {
        $null
    }
    if (-not $cliExe) {
        Append-Log "Build or place eazyconnect-client.exe first to run UDP discovery inside setup."
        return
    }
    Append-Log "Probing LAN / VPN Masters via UDP 37020..."
    $out = & $cliExe discover --timeout-ms 1500 2>&1
    foreach ($line in $out) {
        Append-Log "$line"
        if ($line -match '^(https?://[^\s|]+).*tls_pin=([0-9a-fA-F]{64}|<none>)') {
            $TxtMasterUrl.Text = $Matches[1]
            if ($Matches[2] -ne '<none>') { $TxtTlsPin.Text = $Matches[2] }
        }
    }
})

$BtnStartInstall.Add_Click({
    $roleMode = if ($RbRoleServer.IsChecked) { 'server' } elseif ($RbRoleFull.IsChecked) { 'full' } else { 'client' }
    $installDir = $TxtInstallDir.Text.Trim()
    if (-not $installDir) {
        Append-Log "ERROR: Install directory cannot be empty."
        return
    }
    $useCargo = [bool]$RbSrcCargo.IsChecked
    $masterUrl = $TxtMasterUrl.Text.Trim()
    $tlsPin = $TxtTlsPin.Text.Trim()
    $inviteCode = $TxtInviteCode.Text.Trim()
    $serverPort = $TxtServerPort.Text.Trim()
    $lanOnly = [bool]$ChkLanOnly.IsChecked
    $mkShortcuts = [bool]$ChkDesktopShortcut.IsChecked
    $addFw = [bool]$ChkFirewallRules.IsChecked
    $addStartup = [bool]$ChkStartupTask.IsChecked
    $repoDir = $RepoRoot
    $iconSrc = Join-Path $ScriptDir 'eazyconnect.ico'

    Switch-Step 3
    $CompletionActions.Visibility = 'Collapsed'
    Set-Progress 5 "Preparing installation..."

    Run-BackgroundTask {
        param($S)
        $win = $S.Window
        $log = {
            param($m)
            $ts = (Get-Date).ToString("HH:mm:ss")
            $win.Dispatcher.Invoke([Action]{
                $S.LogBox.AppendText("[$ts] $m`r`n")
                $S.LogBox.ScrollToEnd()
            })
        }
        $prog = {
            param($p, $t)
            $win.Dispatcher.Invoke([Action]{
                $win.FindName("InstallProgressBar").Value = $p
                $win.FindName("MiniProgressBar").Value = $p
                $win.FindName("TxtProgressPct").Text = "$p%"
                $win.FindName("TxtProgressTitle").Text = $t
            })
        }

        try {
            if ($using:useCargo) {
                & $prog 15 "Compiling Rust workspace release binaries..."
                & $log "Running cargo build --release --bins in $($using:repoDir)..."
                $cargoExe = (Get-Command cargo -ErrorAction Stop).Source
                $p = Start-Process -FilePath $cargoExe -ArgumentList @('build', '--manifest-path', (Join-Path $using:repoDir 'Cargo.toml'), '--release', '--bins') -Wait -PassThru -WindowStyle Hidden
                if ($p.ExitCode -ne 0) { throw "cargo build exited with code $($p.ExitCode)" }
            }

            & $prog 40 "Copying EazyConnect binaries to $($using:installDir)..."
            New-Item -ItemType Directory -Path $using:installDir -Force | Out-Null

            $srcDirs = @((Join-Path $using:repoDir 'target\release'), $using:repoDir, $using:ScriptDir)
            $neededBins = switch ($using:roleMode) {
                'server' { @('eazyconnect-server.exe') }
                'client' { @('eazyconnect-ui.exe', 'eazyconnect-client.exe') }
                default  { @('eazyconnect-server.exe', 'eazyconnect-ui.exe', 'eazyconnect-client.exe') }
            }
            foreach ($bin in $neededBins) {
                $found = $null
                foreach ($sd in $srcDirs) {
                    $cand = Join-Path $sd $bin
                    if (Test-Path $cand) { $found = $cand; break }
                }
                if ($found) {
                    Copy-Item $found (Join-Path $using:installDir $bin) -Force
                    & $log "Installed $bin"
                } else {
                    & $log "WARNING: $bin not found in source directories."
                }
            }
            if (Test-Path $using:iconSrc) {
                Copy-Item $using:iconSrc (Join-Path $using:installDir 'eazyconnect.ico') -Force
            }

            if ($using:roleMode -ne 'server' -and $using:masterUrl) {
                & $prog 60 "Writing client configuration..."
                $cfgDir = Join-Path $env:APPDATA 'eazyconnect'
                New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
                $cfgFile = Join-Path $cfgDir 'config.json'
                $cfgObj = if (Test-Path $cfgFile) {
                    Get-Content $cfgFile -Raw | ConvertFrom-Json
                } else {
                    [PSCustomObject]@{ verify = $true; profile = @{ name = ''; photo = ''; language = 'en' } }
                }
                $cfgObj | Add-Member -NotePropertyName 'master' -NotePropertyValue $using:masterUrl -Force
                $cfgObj | Add-Member -NotePropertyName 'verify' -NotePropertyValue $true -Force
                if ($using:tlsPin) {
                    $cfgObj | Add-Member -NotePropertyName 'tls_pin_hex' -NotePropertyValue $using:tlsPin -Force
                }
                $cfgObj | ConvertTo-Json -Depth 6 | Set-Content -Path $cfgFile -Encoding UTF8
                & $log "Saved client config -> $cfgFile"
            }

            if ($using:addFw) {
                & $prog 75 "Configuring Windows Firewall (TCP $($using:serverPort), UDP 37020)..."
                $isAdm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if ($isAdm) {
                    netsh advfirewall firewall delete rule name="EazyConnect HTTPS/WSS" | Out-Null
                    netsh advfirewall firewall add rule name="EazyConnect HTTPS/WSS" dir=in action=allow protocol=TCP localport=$($using:serverPort) | Out-Null
                    netsh advfirewall firewall delete rule name="EazyConnect UDP Discovery" | Out-Null
                    netsh advfirewall firewall add rule name="EazyConnect UDP Discovery" dir=in action=allow protocol=UDP localport=37020 | Out-Null
                    & $log "Windows Firewall rules added cleanly (TCP $($using:serverPort) & UDP 37020)."
                } else {
                    & $log "Skipping firewall rule (not running as Administrator — use 'Re-launch as Administrator' if needed)."
                }
            }

            if ($using:mkShortcuts) {
                & $prog 88 "Creating Desktop and Start Menu shortcuts..."
                $uiExe = Join-Path $using:installDir 'eazyconnect-ui.exe'
                $ico = Join-Path $using:installDir 'eazyconnect.ico'
                if (Test-Path $uiExe) {
                    $ws = New-Object -ComObject WScript.Shell
                    $deskLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'EazyConnect.lnk'
                    $s1 = $ws.CreateShortcut($deskLnk)
                    $s1.TargetPath = $uiExe
                    $s1.WorkingDirectory = $using:installDir
                    if (Test-Path $ico) { $s1.IconLocation = $ico }
                    $s1.Save()

                    $progMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'EazyConnect'
                    New-Item -ItemType Directory -Path $progMenu -Force | Out-Null
                    $startLnk = Join-Path $progMenu 'EazyConnect Control Center.lnk'
                    $s2 = $ws.CreateShortcut($startLnk)
                    $s2.TargetPath = $uiExe
                    $s2.WorkingDirectory = $using:installDir
                    if (Test-Path $ico) { $s2.IconLocation = $ico }
                    $s2.Save()
                    & $log "Created shortcuts on Desktop and Start Menu."
                }
            }

            if ($using:addStartup) {
                & $prog 95 "Registering Windows logon Startup task..."
                if ($using:roleMode -eq 'server' -or $using:roleMode -eq 'full') {
                    $srvExe = Join-Path $using:installDir 'eazyconnect-server.exe'
                    if (Test-Path $srvExe) {
                        $cmdLine = "`"$srvExe`" --listen 0.0.0.0:$($using:serverPort)"
                        if ($using:inviteCode) { $cmdLine += " --invite-code $($using:inviteCode)" }
                        if ($using:lanOnly) { $cmdLine += " --lan-only" }
                        schtasks /Create /F /SC ONLOGON /TN "EazyConnectMaster" /TR $cmdLine | Out-Null
                        & $log "Registered Startup Task 'EazyConnectMaster' (exit $LASTEXITCODE)."
                    }
                } else {
                    $uiExe = Join-Path $using:installDir 'eazyconnect-ui.exe'
                    if (Test-Path $uiExe) {
                        schtasks /Create /F /SC ONLOGON /TN "EazyConnectUI" /TR "`"$uiExe`"" | Out-Null
                        & $log "Registered Startup Task 'EazyConnectUI' (exit $LASTEXITCODE)."
                    }
                }
            }

            & $prog 100 "EazyConnect installation complete!"
            & $log "Setup finished cleanly!"
            $win.Dispatcher.Invoke([Action]{
                $win.FindName("CompletionActions").Visibility = 'Visible'
                $uiPresent = Test-Path (Join-Path $using:installDir 'eazyconnect-ui.exe')
                $srvPresent = Test-Path (Join-Path $using:installDir 'eazyconnect-server.exe')
                $win.FindName("BtnLaunchUi").Visibility = if ($uiPresent) { 'Visible' } else { 'Collapsed' }
                $win.FindName("BtnLaunchServer").Visibility = if ($srvPresent) { 'Visible' } else { 'Collapsed' }
            })
        } catch {
            & $log "INSTALL ERROR: $_"
            & $prog 0 "Installation failed — see log below."
        }
        $S.Busy = $false
    }
})

$BtnLaunchUi.Add_Click({
    $exe = Join-Path $TxtInstallDir.Text.Trim() 'eazyconnect-ui.exe'
    if (Test-Path $exe) { Start-Process -FilePath $exe -WorkingDirectory $TxtInstallDir.Text.Trim() }
})

$BtnLaunchServer.Add_Click({
    $dir = $TxtInstallDir.Text.Trim()
    $exe = Join-Path $dir 'eazyconnect-server.exe'
    if (Test-Path $exe) {
        $argStr = "--listen 0.0.0.0:$($TxtServerPort.Text.Trim())"
        if ($TxtInviteCode.Text.Trim()) { $argStr += " --invite-code `"$($TxtInviteCode.Text.Trim())`"" }
        if ($ChkLanOnly.IsChecked) { $argStr += " --lan-only" }
        Start-Process -FilePath $exe -ArgumentList $argStr -WorkingDirectory $dir
    }
})

$BtnOpenInstallDir.Add_Click({
    $dir = $TxtInstallDir.Text.Trim()
    if (Test-Path $dir) { Start-Process explorer.exe $dir }
})

# Apply role parameter override if relaunched elevated
if ($Role -eq 'server') { $RbRoleServer.IsChecked = $true; Switch-Step 2 }
elseif ($Role -eq 'full') { $RbRoleFull.IsChecked = $true; Switch-Step 2 }
elseif ($Role -eq 'client') { $RbRoleClient.IsChecked = $true; Switch-Step 2 }

Refresh-Prerequisites
Refresh-HostStatus
Append-Log "EazyConnect Prerequisite & Setup Wizard ready."

$null = $Window.ShowDialog()
