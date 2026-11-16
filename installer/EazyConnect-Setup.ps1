<#
.SYNOPSIS
    EazyConnect Modern Simplified Setup & Prerequisite Wizard
    Supports Windows PowerShell 5.1+ and PowerShell 7+ (auto re-launches in STA if needed).
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

$ScriptDir = $PSScriptRoot
$RepoRoot = if (Test-Path (Join-Path $ScriptDir '..\Cargo.toml')) {
    (Resolve-Path (Join-Path $ScriptDir '..')).Path
} else {
    $ScriptDir
}

# --- XAML Definition (Discord / Modern Dark Theme) --------------------------
[xml]$XAML = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="EazyConnect Setup"
        Height="660" Width="880" MinHeight="520" MinWidth="680"
        WindowStartupLocation="CenterScreen"
        Background="#1E1F22" Foreground="#F2F3F5"
        FontFamily="Segoe UI">

    <Window.Resources>
        <Style TargetType="Button" x:Key="PrimaryBtn">
            <Setter Property="Background" Value="#5865F2"/>
            <Setter Property="Foreground" Value="#FFFFFF"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="16,9"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="8" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#6D78F8"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#383A40"/>
                                <Setter Property="Foreground" Value="#80848E"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="Button" x:Key="SuccessBtn" BasedOn="{StaticResource PrimaryBtn}">
            <Setter Property="Background" Value="#23A55A"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="8" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#2BC069"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#383A40"/>
                                <Setter Property="Foreground" Value="#80848E"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="Button" x:Key="GhostBtn">
            <Setter Property="Background" Value="#2B2D31"/>
            <Setter Property="Foreground" Value="#DBDEE1"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="12.5"/>
            <Setter Property="Padding" Value="13,8"/>
            <Setter Property="BorderBrush" Value="#3F4147"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#383A40"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Opacity" Value="0.45"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="Button" x:Key="StepPillActive" BasedOn="{StaticResource PrimaryBtn}">
            <Setter Property="Padding" Value="14,6"/>
            <Setter Property="FontSize" Value="12.5"/>
        </Style>

        <Style TargetType="Button" x:Key="StepPillIdle" BasedOn="{StaticResource GhostBtn}">
            <Setter Property="Padding" Value="14,6"/>
            <Setter Property="FontSize" Value="12.5"/>
        </Style>

        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#1E1F22"/>
            <Setter Property="Foreground" Value="#F2F3F5"/>
            <Setter Property="CaretBrush" Value="#5865F2"/>
            <Setter Property="BorderBrush" Value="#3F4147"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10,7"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>

        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#DBDEE1"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>

        <Style TargetType="RadioButton">
            <Setter Property="Foreground" Value="#F2F3F5"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>

        <Style TargetType="Expander">
            <Setter Property="Foreground" Value="#DBDEE1"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
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
        <Border Grid.Row="0" Background="#2B2D31" BorderBrush="#111214" BorderThickness="0,0,0,1" Padding="24,16">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <Border Grid.Column="0" Width="42" Height="42" CornerRadius="12" Background="#5865F2" Margin="0,0,14,0">
                    <TextBlock Text="EC" FontSize="17" FontWeight="Bold" Foreground="#FFFFFF" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                </Border>

                <StackPanel Grid.Column="1" VerticalAlignment="Center">
                    <TextBlock Text="EazyConnect Easy Setup" FontSize="18" FontWeight="Bold" Foreground="#F2F3F5"/>
                    <TextBlock Text="Encrypted P2P Chat &amp; CubeHash File Transfer — Automatic LAN &amp; VPN Setup" FontSize="12" Foreground="#949BA4" TextWrapping="Wrap" Margin="0,2,0,0"/>
                </StackPanel>

                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <Border x:Name="VpnBadge" Background="#1E1F22" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="8" Padding="10,5" Margin="0,0,8,0">
                        <TextBlock x:Name="VpnBadgeText" Text="Checking network..." FontSize="11.5" Foreground="#949BA4" FontWeight="SemiBold"/>
                    </Border>
                    <Border x:Name="AdminBadge" Background="#1E1F22" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="8" Padding="10,5">
                        <TextBlock x:Name="AdminBadgeText" Text="Checking user..." FontSize="11.5" Foreground="#949BA4" FontWeight="SemiBold"/>
                    </Border>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Clean 3-Step Breadcrumb Strip -->
        <Border Grid.Row="1" Background="#232428" BorderBrush="#111214" BorderThickness="0,0,0,1" Padding="24,10">
            <WrapPanel Orientation="Horizontal" VerticalAlignment="Center">
                <Button x:Name="Step1Tab" Content="1. Choose Setup" Style="{StaticResource StepPillActive}" Margin="0,0,8,0"/>
                <TextBlock Text="&#8250;" Foreground="#6D717A" FontSize="16" VerticalAlignment="Center" Margin="0,0,8,0"/>
                <Button x:Name="Step2Tab" Content="2. Quick Options" Style="{StaticResource StepPillIdle}" Margin="0,0,8,0"/>
                <TextBlock Text="&#8250;" Foreground="#6D717A" FontSize="16" VerticalAlignment="Center" Margin="0,0,8,0"/>
                <Button x:Name="Step3Tab" Content="3. Ready" Style="{StaticResource StepPillIdle}"/>
            </WrapPanel>
        </Border>

        <!-- Main Scrollable Content Area -->
        <ScrollViewer Grid.Row="2" Background="#313338" VerticalScrollBarVisibility="Auto" Padding="24,20">
            <Grid MaxWidth="880">
                <!-- VIEW 1: SIMPLE WELCOME MENU -->
                <StackPanel x:Name="Step1Panel" Visibility="Visible">
                    <TextBlock Text="What would you like to set up?" FontSize="20" FontWeight="Bold" Foreground="#F2F3F5" Margin="0,0,0,4"/>
                    <TextBlock Text="Pick an option below — most users only need Quick Client Install." FontSize="13" Foreground="#B5BAC1" TextWrapping="Wrap" Margin="0,0,0,18"/>

                    <!-- Featured Recommended Client Card -->
                    <Border Background="#2B2D31" BorderBrush="#5865F2" BorderThickness="1.5" CornerRadius="12" Padding="20" Margin="0,0,0,14">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="16"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0">
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                                    <Border Background="#5865F2" CornerRadius="6" Padding="8,3" Margin="0,0,10,0">
                                        <TextBlock Text="RECOMMENDED" FontSize="10.5" FontWeight="Bold" Foreground="#FFFFFF"/>
                                    </Border>
                                    <TextBlock Text="Desktop App &amp; P2P Chat" FontSize="12" Foreground="#949BA4" VerticalAlignment="Center"/>
                                </StackPanel>
                                <TextBlock Text="Install EazyConnect Desktop App" FontSize="17" FontWeight="Bold" Foreground="#F2F3F5"/>
                                <TextBlock Text="Installs the Discord-style chat &amp; CubeHash file-sharing app with automatic LAN/VPN discovery and a Desktop shortcut." FontSize="12.5" Foreground="#B5BAC1" TextWrapping="Wrap" Margin="0,5,0,0"/>
                            </StackPanel>
                            <StackPanel Grid.Column="2" VerticalAlignment="Center">
                                <Button x:Name="BtnChooseClient" Content="Set Up Client &#8594;" Style="{StaticResource PrimaryBtn}" Margin="0,0,0,6" MinWidth="165"/>
                                <Button x:Name="BtnExpressClient" Content="1-Click Express Install" Style="{StaticResource SuccessBtn}" MinWidth="165"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <!-- Secondary Cards Row -->
                    <Grid Margin="0,0,0,12">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="14"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <!-- Card 2: Server / Full Node -->
                        <Border Grid.Column="0" Background="#2B2D31" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="12" Padding="18">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="*"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>
                                <StackPanel Grid.Row="0" Margin="0,0,0,14">
                                    <TextBlock Text="Host Master Server" FontSize="15.5" FontWeight="Bold" Foreground="#F2F3F5"/>
                                    <TextBlock Text="Run the encrypted blind relay &amp; automatic LAN/VPN discovery host so friends or team devices can pair." FontSize="12" Foreground="#B5BAC1" TextWrapping="Wrap" Margin="0,5,0,0"/>
                                </StackPanel>
                                <WrapPanel Grid.Row="1" Orientation="Horizontal">
                                    <Button x:Name="BtnChooseServer" Content="Server Only" Style="{StaticResource GhostBtn}" Margin="0,0,8,6"/>
                                    <Button x:Name="BtnChooseFull" Content="Server + Client App" Style="{StaticResource GhostBtn}" Margin="0,0,0,6"/>
                                </WrapPanel>
                            </Grid>
                        </Border>

                        <!-- Card 3: System Prerequisites -->
                        <Border Grid.Column="2" Background="#2B2D31" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="12" Padding="18">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="*"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>
                                <StackPanel Grid.Row="0" Margin="0,0,0,14">
                                    <DockPanel Margin="0,0,0,4">
                                        <Border x:Name="PrereqSummaryBadge" DockPanel.Dock="Right" Background="#1E1F22" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="6" Padding="8,3" VerticalAlignment="Center">
                                            <TextBlock x:Name="PrereqSummaryText" Text="Scanning..." FontSize="11" FontWeight="SemiBold" Foreground="#949BA4"/>
                                        </Border>
                                        <TextBlock Text="System Prerequisites" FontSize="15.5" FontWeight="Bold" Foreground="#F2F3F5"/>
                                    </DockPanel>
                                    <TextBlock Text="Check &amp; auto-install C++ Runtime, Rust toolchain, Git, or Inno Setup packager via winget." FontSize="12" Foreground="#B5BAC1" TextWrapping="Wrap" Margin="0,3,0,0"/>
                                </StackPanel>
                                <WrapPanel Grid.Row="1" Orientation="Horizontal">
                                    <Button x:Name="BtnOpenPrereqs" Content="Open Prerequisites &#8594;" Style="{StaticResource GhostBtn}" Margin="0,0,8,6"/>
                                    <Button x:Name="BtnQuickAutoPrereqs" Content="Auto-Install Missing" Style="{StaticResource SuccessBtn}" Visibility="Collapsed" Margin="0,0,0,6"/>
                                </WrapPanel>
                            </Grid>
                        </Border>
                    </Grid>
                </StackPanel>

                <!-- VIEW 1B: PREREQUISITES SUB-VIEW -->
                <StackPanel x:Name="PrereqPanel" Visibility="Collapsed">
                    <DockPanel Margin="0,0,0,14">
                        <Button x:Name="BtnPrereqBack" DockPanel.Dock="Left" Content="&#8592; Back to Menu" Style="{StaticResource GhostBtn}" Margin="0,0,12,0"/>
                        <Button x:Name="BtnRescan" DockPanel.Dock="Right" Content="Re-Scan" Style="{StaticResource GhostBtn}"/>
                        <StackPanel VerticalAlignment="Center">
                            <TextBlock Text="System Prerequisites &amp; Tools" FontSize="17" FontWeight="Bold" Foreground="#F2F3F5"/>
                            <TextBlock Text="Runtime libraries run prebuilt binaries; developer tools are only needed to compile from source." FontSize="12" Foreground="#949BA4" TextWrapping="Wrap"/>
                        </StackPanel>
                    </DockPanel>

                    <StackPanel x:Name="PrereqListPanel" Margin="0,0,0,14"/>

                    <WrapPanel Orientation="Horizontal">
                        <Button x:Name="BtnInstallPrereqs" Content="Install Checked Missing Items (winget)" Style="{StaticResource SuccessBtn}" Margin="0,0,10,8"/>
                        <Button x:Name="BtnToStep2FromPrereq" Content="Continue to Setup &#8594;" Style="{StaticResource PrimaryBtn}" Margin="0,0,0,8"/>
                    </WrapPanel>
                </StackPanel>

                <!-- VIEW 2: CLEAN STREAMLINED ROLE SETUP -->
                <StackPanel x:Name="Step2Panel" Visibility="Collapsed">
                    <!-- Selected Mode Switcher -->
                    <Border Background="#2B2D31" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="10" Padding="16" Margin="0,0,0,14">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0">
                                <TextBlock x:Name="TxtSelectedRoleHeading" Text="Desktop Client Setup" FontSize="16" FontWeight="Bold" Foreground="#F2F3F5"/>
                                <TextBlock x:Name="TxtSelectedRoleSub" Text="Installs the EazyConnect chat app with automatic LAN/VPN discovery." FontSize="12" Foreground="#949BA4" TextWrapping="Wrap" Margin="0,2,0,0"/>
                            </StackPanel>
                            <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                                <RadioButton x:Name="RbRoleClient" Content="Client" IsChecked="True" Margin="0,0,12,0"/>
                                <RadioButton x:Name="RbRoleServer" Content="Server" Margin="0,0,12,0"/>
                                <RadioButton x:Name="RbRoleFull" Content="Full Node"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <!-- Client Quick Config (hidden in server-only mode) -->
                    <Border x:Name="ClientConfigGroup" Background="#2B2D31" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="10" Padding="16" Margin="0,0,0,14">
                        <StackPanel>
                            <TextBlock Text="Connect to Master Server" FontSize="14.5" FontWeight="SemiBold" Foreground="#F2F3F5" Margin="0,0,0,8"/>
                            <Grid Margin="0,0,0,6">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox x:Name="TxtMasterUrl" Grid.Column="0" Text="https://127.0.0.1:8000"/>
                                <Button x:Name="BtnSetupDiscover" Grid.Column="2" Content="Discover Nearby" Style="{StaticResource PrimaryBtn}"/>
                            </Grid>
                            <TextBlock Text="Optional: click Discover Nearby to find a running Master Server on your LAN/VPN automatically. You can also connect anytime inside the app." FontSize="11.5" Foreground="#949BA4" TextWrapping="Wrap" Margin="0,0,0,10"/>
                            <CheckBox x:Name="ChkDesktopShortcut" Content="Create Desktop &amp; Start Menu shortcuts" IsChecked="True"/>
                        </StackPanel>
                    </Border>

                    <!-- Server Quick Config (hidden in client-only mode) -->
                    <Border x:Name="ServerConfigGroup" Background="#2B2D31" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="10" Padding="16" Margin="0,0,0,14" Visibility="Collapsed">
                        <StackPanel>
                            <TextBlock Text="Master Server Host Settings" FontSize="14.5" FontWeight="SemiBold" Foreground="#F2F3F5" Margin="0,0,0,10"/>
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="12"/>
                                    <ColumnDefinition Width="120"/>
                                </Grid.ColumnDefinitions>
                                <StackPanel Grid.Column="0">
                                    <TextBlock Text="Invite Code" FontSize="12" Foreground="#B5BAC1" Margin="0,0,0,4"/>
                                    <TextBox x:Name="TxtInviteCode" Text="EAZY-TEST-2026"/>
                                </StackPanel>
                                <StackPanel Grid.Column="2">
                                    <TextBlock Text="Port" FontSize="12" Foreground="#B5BAC1" Margin="0,0,0,4"/>
                                    <TextBox x:Name="TxtServerPort" Text="8000"/>
                                </StackPanel>
                            </Grid>
                            <WrapPanel Orientation="Horizontal">
                                <CheckBox x:Name="ChkFirewallRules" Content="Open Windows Firewall ports (TCP 8000 &amp; UDP 37020)" IsChecked="True" Margin="0,0,14,4"/>
                                <Button x:Name="BtnElevateSetup" Content="Run as Admin (for Firewall)" Style="{StaticResource GhostBtn}" Padding="10,5" FontSize="11.5"/>
                            </WrapPanel>
                        </StackPanel>
                    </Border>

                    <!-- Collapsed Advanced & Developer Settings -->
                    <Border Background="#2B2D31" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="10" Padding="14" Margin="0,0,0,16">
                        <Expander Header="Advanced &amp; Developer Options" IsExpanded="False">
                            <StackPanel Margin="0,12,0,0">
                                <TextBlock Text="Install Directory" FontSize="12" Foreground="#B5BAC1" Margin="0,0,0,4"/>
                                <Grid Margin="0,0,0,12">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="8"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="TxtInstallDir" Grid.Column="0"/>
                                    <Button x:Name="BtnBrowseInstallDir" Grid.Column="2" Content="Browse..." Style="{StaticResource GhostBtn}"/>
                                </Grid>

                                <TextBlock Text="Binary Source" FontSize="12" Foreground="#B5BAC1" Margin="0,0,0,4"/>
                                <WrapPanel Orientation="Horizontal" Margin="0,0,0,4">
                                    <RadioButton x:Name="RbSrcPrebuilt" Content="Use Prebuilt Binaries (Fast)" IsChecked="True" Margin="0,0,18,4"/>
                                    <RadioButton x:Name="RbSrcCargo" Content="Build from Source (cargo build --release)" Margin="0,0,0,4"/>
                                </WrapPanel>
                                <TextBlock x:Name="TxtSourceStatus" Text="Checking binaries..." FontSize="11.5" Foreground="#949BA4" Margin="0,0,0,12"/>

                                <TextBlock Text="Manual TLS SHA-256 Pin (optional 64-hex override)" FontSize="12" Foreground="#B5BAC1" Margin="0,0,0,4"/>
                                <TextBox x:Name="TxtTlsPin" Margin="0,0,0,10"/>

                                <CheckBox x:Name="ChkLanOnly" Content="Restrict Master Server binding to primary LAN IP (--lan-only)" Margin="0,0,0,8"/>
                                <CheckBox x:Name="ChkStartupTask" Content="Auto-start EazyConnect on Windows logon (schtasks)" Margin="0,0,0,12"/>

                                <Border Background="#1E1F22" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="8" Padding="12">
                                    <StackPanel>
                                        <TextBlock x:Name="TxtVpnAdviceTitle" Text="Network &amp; VPN Status" FontWeight="SemiBold" Foreground="#F0B232" FontSize="12.5"/>
                                        <TextBlock x:Name="TxtVpnAdviceBody" TextWrapping="Wrap" FontSize="11.5" Foreground="#B5BAC1" Margin="0,4,0,0" Text="Checking active network adapters..."/>
                                    </StackPanel>
                                </Border>
                            </StackPanel>
                        </Expander>
                    </Border>

                    <!-- Action Buttons -->
                    <DockPanel>
                        <Button x:Name="BtnBackToStep1" DockPanel.Dock="Left" Content="&#8592; Change Mode" Style="{StaticResource GhostBtn}"/>
                        <Button x:Name="BtnStartInstall" DockPanel.Dock="Right" Content="Install EazyConnect Now" Style="{StaticResource SuccessBtn}" MinWidth="210"/>
                        <Border/>
                    </DockPanel>
                </StackPanel>

                <!-- VIEW 3: PROGRESS & READY -->
                <StackPanel x:Name="Step3Panel" Visibility="Collapsed">
                    <Border Background="#2B2D31" BorderBrush="#3F4147" BorderThickness="1" CornerRadius="12" Padding="24" Margin="0,0,0,16">
                        <StackPanel>
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock x:Name="TxtProgressTitle" Grid.Column="0" Text="Ready to install" FontSize="16" FontWeight="Bold" Foreground="#F2F3F5"/>
                                <TextBlock x:Name="TxtProgressPct" Grid.Column="1" Text="0%" FontSize="15" FontWeight="Bold" Foreground="#5865F2"/>
                            </Grid>
                            <ProgressBar x:Name="InstallProgressBar" Height="10" Minimum="0" Maximum="100" Value="0" Background="#1E1F22" Foreground="#23A55A" BorderThickness="0"/>
                            <TextBlock x:Name="TxtInstallSummary" Text="Files are copied locally and shortcuts are configured automatically." FontSize="12.5" Foreground="#949BA4" TextWrapping="Wrap" Margin="0,12,0,0"/>
                        </StackPanel>
                    </Border>

                    <WrapPanel x:Name="CompletionActions" Orientation="Horizontal" Visibility="Collapsed">
                        <Button x:Name="BtnLaunchUi" Content="Launch EazyConnect" Style="{StaticResource PrimaryBtn}" Margin="0,0,10,8"/>
                        <Button x:Name="BtnLaunchServer" Content="Start Master Server" Style="{StaticResource SuccessBtn}" Margin="0,0,10,8"/>
                        <Button x:Name="BtnOpenInstallDir" Content="Open Folder" Style="{StaticResource GhostBtn}" Margin="0,0,10,8"/>
                        <Button x:Name="BtnDoneMenu" Content="Back to Menu" Style="{StaticResource GhostBtn}" Margin="0,0,0,8"/>
                    </WrapPanel>
                </StackPanel>
            </Grid>
        </ScrollViewer>

        <!-- Compact Footer Status + Collapsible Log -->
        <Border Grid.Row="3" Background="#232428" BorderBrush="#111214" BorderThickness="0,1,0,0" Padding="24,10">
            <StackPanel>
                <Expander x:Name="ExpLog" IsExpanded="False">
                    <Expander.Header>
                        <Grid Width="780">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="160"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock x:Name="TxtFooterStatus" Grid.Column="0" Text="EazyConnect Setup ready." FontSize="12" FontWeight="Normal" Foreground="#949BA4" VerticalAlignment="Center"/>
                            <TextBlock Grid.Column="1" Text="Technical Log" FontSize="11.5" Foreground="#B5BAC1" VerticalAlignment="Center" Margin="0,0,12,0"/>
                            <ProgressBar x:Name="MiniProgressBar" Grid.Column="2" Height="6" Minimum="0" Maximum="100" Value="0" Background="#1E1F22" Foreground="#5865F2" BorderThickness="0" VerticalAlignment="Center"/>
                        </Grid>
                    </Expander.Header>
                    <TextBox x:Name="TxtLog" Height="120" Margin="0,10,0,0" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="11.5" Background="#1E1F22" Foreground="#DBDEE1" BorderBrush="#3F4147"/>
                </Expander>
            </StackPanel>
        </Border>
    </Grid>
</Window>
"@

$Reader = New-Object System.Xml.XmlNodeReader $XAML
$Window = [Windows.Markup.XamlReader]::Load($Reader)

# --- Bind Controls ----------------------------------------------------------
$VpnBadgeText = $Window.FindName("VpnBadgeText")
$VpnBadge = $Window.FindName("VpnBadge")
$AdminBadgeText = $Window.FindName("AdminBadgeText")
$AdminBadge = $Window.FindName("AdminBadge")

$Step1Tab = $Window.FindName("Step1Tab")
$Step2Tab = $Window.FindName("Step2Tab")
$Step3Tab = $Window.FindName("Step3Tab")
$Step1Panel = $Window.FindName("Step1Panel")
$PrereqPanel = $Window.FindName("PrereqPanel")
$Step2Panel = $Window.FindName("Step2Panel")
$Step3Panel = $Window.FindName("Step3Panel")

$BtnChooseClient = $Window.FindName("BtnChooseClient")
$BtnExpressClient = $Window.FindName("BtnExpressClient")
$BtnChooseServer = $Window.FindName("BtnChooseServer")
$BtnChooseFull = $Window.FindName("BtnChooseFull")
$BtnOpenPrereqs = $Window.FindName("BtnOpenPrereqs")
$BtnQuickAutoPrereqs = $Window.FindName("BtnQuickAutoPrereqs")
$PrereqSummaryBadge = $Window.FindName("PrereqSummaryBadge")
$PrereqSummaryText = $Window.FindName("PrereqSummaryText")

$PrereqListPanel = $Window.FindName("PrereqListPanel")
$BtnPrereqBack = $Window.FindName("BtnPrereqBack")
$BtnRescan = $Window.FindName("BtnRescan")
$BtnInstallPrereqs = $Window.FindName("BtnInstallPrereqs")
$BtnToStep2FromPrereq = $Window.FindName("BtnToStep2FromPrereq")

$TxtSelectedRoleHeading = $Window.FindName("TxtSelectedRoleHeading")
$TxtSelectedRoleSub = $Window.FindName("TxtSelectedRoleSub")
$RbRoleClient = $Window.FindName("RbRoleClient")
$RbRoleServer = $Window.FindName("RbRoleServer")
$RbRoleFull = $Window.FindName("RbRoleFull")

$ClientConfigGroup = $Window.FindName("ClientConfigGroup")
$ServerConfigGroup = $Window.FindName("ServerConfigGroup")
$TxtMasterUrl = $Window.FindName("TxtMasterUrl")
$BtnSetupDiscover = $Window.FindName("BtnSetupDiscover")
$ChkDesktopShortcut = $Window.FindName("ChkDesktopShortcut")
$TxtInviteCode = $Window.FindName("TxtInviteCode")
$TxtServerPort = $Window.FindName("TxtServerPort")
$ChkFirewallRules = $Window.FindName("ChkFirewallRules")
$BtnElevateSetup = $Window.FindName("BtnElevateSetup")

$TxtInstallDir = $Window.FindName("TxtInstallDir")
$BtnBrowseInstallDir = $Window.FindName("BtnBrowseInstallDir")
$RbSrcPrebuilt = $Window.FindName("RbSrcPrebuilt")
$RbSrcCargo = $Window.FindName("RbSrcCargo")
$TxtSourceStatus = $Window.FindName("TxtSourceStatus")
$TxtTlsPin = $Window.FindName("TxtTlsPin")
$ChkLanOnly = $Window.FindName("ChkLanOnly")
$ChkStartupTask = $Window.FindName("ChkStartupTask")
$TxtVpnAdviceTitle = $Window.FindName("TxtVpnAdviceTitle")
$TxtVpnAdviceBody = $Window.FindName("TxtVpnAdviceBody")
$BtnBackToStep1 = $Window.FindName("BtnBackToStep1")
$BtnStartInstall = $Window.FindName("BtnStartInstall")

$TxtProgressTitle = $Window.FindName("TxtProgressTitle")
$TxtProgressPct = $Window.FindName("TxtProgressPct")
$TxtInstallSummary = $Window.FindName("TxtInstallSummary")
$InstallProgressBar = $Window.FindName("InstallProgressBar")
$MiniProgressBar = $Window.FindName("MiniProgressBar")
$CompletionActions = $Window.FindName("CompletionActions")
$BtnLaunchUi = $Window.FindName("BtnLaunchUi")
$BtnLaunchServer = $Window.FindName("BtnLaunchServer")
$BtnOpenInstallDir = $Window.FindName("BtnOpenInstallDir")
$BtnDoneMenu = $Window.FindName("BtnDoneMenu")
$ExpLog = $Window.FindName("ExpLog")
$TxtFooterStatus = $Window.FindName("TxtFooterStatus")
$TxtLog = $Window.FindName("TxtLog")

# --- Shared Synchronized State ----------------------------------------------
$State = [hashtable]::Synchronized(@{
    Window = $Window
    LogBox = $TxtLog
    FooterText = $TxtFooterStatus
    PrereqChecks = @{}
    Busy = $false
})

function Append-Log([string]$Line) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $Window.Dispatcher.Invoke([Action]{
        $TxtLog.AppendText("[$ts] $Line`r`n")
        $TxtLog.ScrollToEnd()
        $TxtFooterStatus.Text = $Line
    })
}

function Set-Progress([int]$Pct, [string]$Title) {
    $Window.Dispatcher.Invoke([Action]{
        $InstallProgressBar.Value = $Pct
        $MiniProgressBar.Value = $Pct
        $TxtProgressPct.Text = "$Pct%"
        if ($Title) {
            $TxtProgressTitle.Text = $Title
            $TxtFooterStatus.Text = $Title
        }
    })
}

function Switch-View([string]$ViewName, $W = $Window) {
    $W.FindName("Step1Panel").Visibility  = if ($ViewName -eq 'menu')   { 'Visible' } else { 'Collapsed' }
    $W.FindName("PrereqPanel").Visibility = if ($ViewName -eq 'prereq') { 'Visible' } else { 'Collapsed' }
    $W.FindName("Step2Panel").Visibility  = if ($ViewName -eq 'config') { 'Visible' } else { 'Collapsed' }
    $W.FindName("Step3Panel").Visibility  = if ($ViewName -eq 'done')   { 'Visible' } else { 'Collapsed' }

    $stepIdx = switch ($ViewName) {
        'config' { 2 }
        'done'   { 3 }
        default  { 1 }
    }
    $W.FindName("Step1Tab").Style = if ($stepIdx -eq 1) { $W.FindResource("StepPillActive") } else { $W.FindResource("StepPillIdle") }
    $W.FindName("Step2Tab").Style = if ($stepIdx -eq 2) { $W.FindResource("StepPillActive") } else { $W.FindResource("StepPillIdle") }
    $W.FindName("Step3Tab").Style = if ($stepIdx -eq 3) { $W.FindResource("StepPillActive") } else { $W.FindResource("StepPillIdle") }
}

function Update-RoleVisibility {
    $roleMode = if ($RbRoleServer.IsChecked) { 'server' } elseif ($RbRoleFull.IsChecked) { 'full' } else { 'client' }
    switch ($roleMode) {
        'client' {
            $TxtSelectedRoleHeading.Text = "Desktop Client Setup"
            $TxtSelectedRoleSub.Text = "Installs the Discord-style chat & file-sharing app on this PC."
            $ClientConfigGroup.Visibility = 'Visible'
            $ServerConfigGroup.Visibility = 'Collapsed'
        }
        'server' {
            $TxtSelectedRoleHeading.Text = "Master Server Host Setup"
            $TxtSelectedRoleSub.Text = "Configures the encrypted relay & automatic UDP discovery host."
            $ClientConfigGroup.Visibility = 'Collapsed'
            $ServerConfigGroup.Visibility = 'Visible'
        }
        'full' {
            $TxtSelectedRoleHeading.Text = "Full Node Setup (Server + Desktop App)"
            $TxtSelectedRoleSub.Text = "Hosts the Master Server relay and installs the Desktop App on this PC."
            $ClientConfigGroup.Visibility = 'Visible'
            $ServerConfigGroup.Visibility = 'Visible'
        }
    }
}

function Run-BackgroundTask([scriptblock]$Work, [hashtable]$TaskParams = @{}) {
    if ($State.Busy) {
        Append-Log "An operation is already running; please wait."
        return
    }
    $State.Busy = $true
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript($Work).AddArgument($State).AddArgument($TaskParams)
    $null = $ps.BeginInvoke()
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

# --- Prerequisite Inspection Definitions -----------------------------------
$PrereqSpecs = @(
    @{
        Key = 'winget'
        Name = 'Windows Package Manager (winget)'
        Desc = 'Required for 1-click prerequisite installation.'
        WingetId = ''
        Optional = $false
        Check = {
            $cmd = Get-Command winget -ErrorAction SilentlyContinue
            if ($cmd) { return @{ Installed = $true; Status = 'Ready' } }
            return @{ Installed = $false; Status = 'Missing (install App Installer)' }
        }
    },
    @{
        Key = 'vcredist'
        Name = 'Microsoft Visual C++ 2015-2022 Runtime (x64)'
        Desc = 'Recommended C runtime library for Windows desktop apps.'
        WingetId = 'Microsoft.VCRedist.2015+.x64'
        Optional = $false
        Check = {
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue
            if ($reg -and $reg.Installed -eq 1) {
                return @{ Installed = $true; Status = "Installed (v$($reg.Major).$($reg.Minor).$($reg.Bld))" }
            }
            return @{ Installed = $false; Status = 'Recommended Missing' }
        }
    },
    @{
        Key = 'rust'
        Name = 'Rust Toolchain (rustup / cargo)'
        Desc = 'Developer tool: only needed when building binaries from source.'
        WingetId = 'Rustlang.Rustup'
        Optional = $true
        Check = {
            $cargo = Get-Command cargo -ErrorAction SilentlyContinue
            if ($cargo) {
                $ver = (& cargo --version 2>$null | Select-Object -First 1)
                return @{ Installed = $true; Status = "Installed ($ver)" }
            }
            return @{ Installed = $false; Status = 'Optional (not needed for prebuilt .exe)' }
        }
    },
    @{
        Key = 'msvc'
        Name = 'Visual Studio C++ Build Tools (MSVC)'
        Desc = 'Developer tool: required only alongside Rust source builds.'
        WingetId = 'Microsoft.VisualStudio.2022.BuildTools'
        WingetArgs = '--override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
        Optional = $true
        Check = {
            $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
            if (Test-Path $vswhere) {
                $vcPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
                if ($vcPath) { return @{ Installed = $true; Status = 'Installed (MSVC x64)' } }
            }
            return @{ Installed = $false; Status = 'Optional' }
        }
    },
    @{
        Key = 'git'
        Name = 'Git for Windows'
        Desc = 'Optional source code sync tool.'
        WingetId = 'Git.Git'
        Optional = $true
        Check = {
            $g = Get-Command git -ErrorAction SilentlyContinue
            if ($g) {
                $ver = (& git --version 2>$null | Select-Object -First 1)
                return @{ Installed = $true; Status = "Installed ($ver)" }
            }
            return @{ Installed = $false; Status = 'Optional' }
        }
    },
    @{
        Key = 'inno'
        Name = 'Inno Setup 6 Compiler (ISCC.exe)'
        Desc = 'Optional packager to generate EazyConnect-Setup.exe.'
        WingetId = 'JRSoftware.InnoSetup'
        Optional = $true
        Check = {
            $cands = @(
                (Get-Command iscc -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }),
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
                "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
            ) | Where-Object { $_ -and (Test-Path $_) }
            if ($cands) { return @{ Installed = $true; Status = 'Installed' } }
            return @{ Installed = $false; Status = 'Optional' }
        }
    }
)

function Render-PrereqCards([array]$Results, $W = $Window, $S = $State) {
    $listPanel = $W.FindName("PrereqListPanel")
    $listPanel.Children.Clear()
    $S.PrereqChecks.Clear()
    $missingRequired = 0
    $bc = [Windows.Media.BrushConverter]::new()

    $addedDevHeader = $false
    foreach ($entry in $Results) {
        $spec = $entry.Spec
        $res = $entry.Result
        if ((-not $spec.Optional) -and (-not $res.Installed) -and $spec.WingetId) {
            $missingRequired++
        }

        if ($spec.Optional -and (-not $addedDevHeader)) {
            $addedDevHeader = $true
            $hdr = New-Object System.Windows.Controls.TextBlock
            $hdr.Text = "OPTIONAL DEVELOPER & PACKAGING TOOLS"
            $hdr.FontSize = 11
            $hdr.FontWeight = 'Bold'
            $hdr.Foreground = $bc.ConvertFrom('#949BA4')
            $hdr.Margin = '0,10,0,6'
            $null = $listPanel.Children.Add($hdr)
        }

        $card = New-Object System.Windows.Controls.Border
        $card.Background = $bc.ConvertFrom('#2B2D31')
        $card.BorderBrush = $bc.ConvertFrom('#3F4147')
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
        $lblName.Foreground = $bc.ConvertFrom('#F2F3F5')
        $lblDesc = New-Object System.Windows.Controls.TextBlock
        $lblDesc.Text = $spec.Desc
        $lblDesc.FontSize = 11.5
        $lblDesc.TextWrapping = 'Wrap'
        $lblDesc.Foreground = $bc.ConvertFrom('#949BA4')
        $null = $textStack.Children.Add($lblName)
        $null = $textStack.Children.Add($lblDesc)
        [System.Windows.Controls.Grid]::SetColumn($textStack, 1)

        $badge = New-Object System.Windows.Controls.Border
        $badge.CornerRadius = '6'
        $badge.Padding = '10,4'
        $badge.VerticalAlignment = 'Center'
        $badge.Margin = '10,0,0,0'
        $badgeColor = if ($res.Installed) { '#23A55A' } elseif ($spec.Optional) { '#949BA4' } else { '#F23F43' }
        $badge.Background = $bc.ConvertFrom('#1E1F22')
        $badge.BorderBrush = $bc.ConvertFrom($badgeColor)
        $badge.BorderThickness = '1'
        $badgeText = New-Object System.Windows.Controls.TextBlock
        $badgeText.Text = $res.Status
        $badgeText.FontSize = 11.5
        $badgeText.FontWeight = 'SemiBold'
        $badgeText.Foreground = $bc.ConvertFrom($badgeColor)
        $badge.Child = $badgeText
        [System.Windows.Controls.Grid]::SetColumn($badge, 2)

        $null = $grid.Children.Add($chk)
        $null = $grid.Children.Add($textStack)
        $null = $grid.Children.Add($badge)
        $card.Child = $grid
        $null = $listPanel.Children.Add($card)

        $S.PrereqChecks[$spec.Key] = @{ CheckBox = $chk; Spec = $spec; Installed = $res.Installed }
    }

    $sumTxt = $W.FindName("PrereqSummaryText")
    $sumBadge = $W.FindName("PrereqSummaryBadge")
    $btnQuick = $W.FindName("BtnQuickAutoPrereqs")
    if ($missingRequired -eq 0) {
        $sumTxt.Text = "Runtime Ready"
        $sumTxt.Foreground = $bc.ConvertFrom('#23A55A')
        $sumBadge.BorderBrush = $bc.ConvertFrom('#23A55A')
        $btnQuick.Visibility = 'Collapsed'
    } else {
        $sumTxt.Text = "$missingRequired Required Missing"
        $sumTxt.Foreground = $bc.ConvertFrom('#F0B232')
        $sumBadge.BorderBrush = $bc.ConvertFrom('#F0B232')
        $btnQuick.Visibility = 'Visible'
    }
}

function Invoke-AsyncSystemScan {
    # Instant admin + source checks on UI thread (fast)
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $bc = [Windows.Media.BrushConverter]::new()
    if ($isAdmin) {
        $AdminBadgeText.Text = "Administrator"
        $AdminBadgeText.Foreground = $bc.ConvertFrom('#23A55A')
        $AdminBadge.BorderBrush = $bc.ConvertFrom('#23A55A')
        $BtnElevateSetup.Visibility = 'Collapsed'
    } else {
        $AdminBadgeText.Text = "Standard User"
        $AdminBadgeText.Foreground = $bc.ConvertFrom('#949BA4')
        $AdminBadge.BorderBrush = $bc.ConvertFrom('#3F4147')
        $BtnElevateSetup.Visibility = 'Visible'
    }

    $defaultDir = if ($isAdmin) { Join-Path $env:ProgramFiles 'EazyConnect' } else { Join-Path $env:LOCALAPPDATA 'Programs\EazyConnect' }
    if (-not $TxtInstallDir.Text) { $TxtInstallDir.Text = $defaultDir }

    $prebuiltDir = Find-PrebuiltBinaryDir
    $hasCargo = Test-Path (Join-Path $RepoRoot 'Cargo.toml')
    if ($prebuiltDir) {
        $TxtSourceStatus.Text = "Found prebuilt release apps in: $prebuiltDir"
        $RbSrcPrebuilt.IsEnabled = $true
        $RbSrcPrebuilt.IsChecked = $true
    } elseif ($hasCargo) {
        $TxtSourceStatus.Text = "No prebuilt binaries found yet — Cargo release build selected automatically."
        $RbSrcCargo.IsChecked = $true
        $RbSrcPrebuilt.IsEnabled = $false
    } else {
        $TxtSourceStatus.Text = "WARNING: Neither prebuilt executables nor Cargo.toml found next to setup."
    }
    $RbSrcCargo.IsEnabled = $hasCargo

    # Run slower OS probes (Get-NetAdapter, vswhere, winget, cargo) asynchronously so UI stays instant!
    $specsSnapshot = $PrereqSpecs
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'MTA'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript({
        param($W, $S, $Specs, $RenderFn)
        $results = @()
        foreach ($spec in $Specs) {
            $res = & $spec.Check
            $results += @{ Spec = $spec; Result = $res }
        }
        $vpns = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -eq 'Up' -and ($_.Name -match 'VPN|TAP|TUN|Wintun|WireGuard|OpenVPN|Windscribe|Cisco|Tailscale|ZeroTier|WARP|Proton|Mullvad|Forti|Outline|Nekoray|SoftEther' -or
            $_.InterfaceDescription -match 'VPN|TAP|TUN|Wintun|WireGuard|OpenVPN|Windscribe|Cisco|Tailscale|ZeroTier|WARP|Proton|Mullvad|Forti|Outline|Nekoray|SoftEther')
        }
        $vpnList = if ($vpns) { ($vpns.Name | Select-Object -Unique) -join ', ' } else { '' }

        $W.Dispatcher.Invoke([Action]{
            & $RenderFn $results $W $S
            $bcInner = [Windows.Media.BrushConverter]::new()
            $vpnBadge = $W.FindName("VpnBadge")
            $vpnTxt = $W.FindName("VpnBadgeText")
            $advTitle = $W.FindName("TxtVpnAdviceTitle")
            $advBody = $W.FindName("TxtVpnAdviceBody")
            if ($vpnList) {
                $vpnTxt.Text = "VPN: $vpnList"
                $vpnTxt.Foreground = $bcInner.ConvertFrom('#F0B232')
                $vpnBadge.BorderBrush = $bcInner.ConvertFrom('#F0B232')
                $advTitle.Text = "Active VPN Detected: $vpnList"
                $advBody.Text = "For Mesh VPNs (WireGuard/Tailscale/ZeroTier), peers connect directly over VPN IPs. For Exit VPNs when reaching LAN peers, ensure 'Allow LAN Traffic' is enabled in your VPN settings."
            } else {
                $vpnTxt.Text = "LAN Direct"
                $vpnTxt.Foreground = $bcInner.ConvertFrom('#23A55A')
                $vpnBadge.BorderBrush = $bcInner.ConvertFrom('#23A55A')
                $advTitle.Text = "Direct LAN Network Active"
                $advBody.Text = "No interfering Exit VPN adapter detected. UDP 37020 auto-discovery and HTTPS/WSS work automatically on your LAN."
            }
        })
    }).AddArgument($Window).AddArgument($State).AddArgument($specsSnapshot).AddArgument(${function:Render-PrereqCards})
    $null = $ps.BeginInvoke()
}

# --- Shared Install Helpers -------------------------------------------------
function Start-WingetInstall([array]$ToInstall, [string]$ReturnView) {
    if ($ToInstall.Count -eq 0) {
        Append-Log "All checked prerequisites are already installed."
        return
    }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Append-Log "ERROR: winget is unavailable. Install 'App Installer' from Microsoft Store first."
        $ExpLog.IsExpanded = $true
        return
    }

    Switch-View 'done'
    $CompletionActions.Visibility = 'Collapsed'
    $TxtInstallSummary.Text = "Installing selected system packages silently via Windows Package Manager (winget)..."
    Set-Progress 5 "Installing prerequisites..."

    $taskParams = @{
        Items = $ToInstall
        SpecsRef = $PrereqSpecs
        RenderFn = ${function:Render-PrereqCards}
        SwitchFn = ${function:Switch-View}
        ReturnView = $ReturnView
    }
    Run-BackgroundTask {
        param($S, $P)
        $win = $S.Window
        $log = {
            param($m)
            $ts = (Get-Date).ToString("HH:mm:ss")
            $win.Dispatcher.Invoke([Action]{
                $S.LogBox.AppendText("[$ts] $m`r`n")
                $S.LogBox.ScrollToEnd()
                $S.FooterText.Text = $m
            })
        }
        $total = $P.Items.Count
        $idx = 0
        foreach ($spec in $P.Items) {
            $idx++
            $pct = [int](($idx - 1) * 100 / $total)
            $win.Dispatcher.Invoke([Action]{
                $win.FindName("InstallProgressBar").Value = $pct
                $win.FindName("MiniProgressBar").Value = $pct
                $win.FindName("TxtProgressPct").Text = "$pct%"
                $win.FindName("TxtProgressTitle").Text = "Installing $($spec.Name)..."
            })
            & $log "winget install --id $($spec.WingetId) ..."
            $wingetArgs = "install --id $($spec.WingetId) -e --accept-package-agreements --accept-source-agreements --silent"
            if ($spec.WingetArgs) { $wingetArgs += " $($spec.WingetArgs)" }
            $proc = Start-Process -FilePath "winget.exe" -ArgumentList $wingetArgs -Wait -PassThru -WindowStyle Hidden
            & $log "Finished $($spec.WingetId) (exit $($proc.ExitCode))."
        }
        # Refresh prerequisite state before returning
        $freshResults = @()
        foreach ($s in $P.SpecsRef) {
            $freshResults += @{ Spec = $s; Result = (& $s.Check) }
        }
        $S.Busy = $false
        $win.Dispatcher.Invoke([Action]{
            $win.FindName("InstallProgressBar").Value = 100
            $win.FindName("MiniProgressBar").Value = 100
            $win.FindName("TxtProgressPct").Text = "100%"
            & $P.RenderFn $freshResults $win $S
            & $P.SwitchFn $P.ReturnView $win
        })
    } $taskParams
}

function Start-EazyConnectInstall {
    $roleMode = if ($RbRoleServer.IsChecked) { 'server' } elseif ($RbRoleFull.IsChecked) { 'full' } else { 'client' }
    $installDir = $TxtInstallDir.Text.Trim()
    if (-not $installDir) {
        Append-Log "ERROR: Install directory cannot be empty."
        return
    }

    Switch-View 'done'
    $CompletionActions.Visibility = 'Collapsed'
    $TxtInstallSummary.Text = "Deploying EazyConnect into $installDir..."
    Set-Progress 5 "Preparing installation..."

    $taskParams = @{
        RoleMode    = $roleMode
        InstallDir  = $installDir
        UseCargo    = [bool]$RbSrcCargo.IsChecked
        MasterUrl   = $TxtMasterUrl.Text.Trim()
        TlsPin      = $TxtTlsPin.Text.Trim()
        InviteCode  = $TxtInviteCode.Text.Trim()
        ServerPort  = $TxtServerPort.Text.Trim()
        LanOnly     = [bool]$ChkLanOnly.IsChecked
        MkShortcuts = [bool]$ChkDesktopShortcut.IsChecked
        AddFw       = [bool]$ChkFirewallRules.IsChecked
        AddStartup  = [bool]$ChkStartupTask.IsChecked
        RepoDir     = $RepoRoot
        ScriptDir   = $ScriptDir
        IconSrc     = Join-Path $ScriptDir 'eazyconnect.ico'
    }

    Run-BackgroundTask {
        param($S, $P)
        $win = $S.Window
        $log = {
            param($m)
            $ts = (Get-Date).ToString("HH:mm:ss")
            $win.Dispatcher.Invoke([Action]{
                $S.LogBox.AppendText("[$ts] $m`r`n")
                $S.LogBox.ScrollToEnd()
                $S.FooterText.Text = $m
            })
        }
        $prog = {
            param($pct, $title)
            $win.Dispatcher.Invoke([Action]{
                $win.FindName("InstallProgressBar").Value = $pct
                $win.FindName("MiniProgressBar").Value = $pct
                $win.FindName("TxtProgressPct").Text = "$pct%"
                $win.FindName("TxtProgressTitle").Text = $title
                $S.FooterText.Text = $title
            })
        }

        try {
            if ($P.UseCargo) {
                & $prog 15 "Building release executables from source..."
                & $log "Running cargo build --release --bins in $($P.RepoDir)..."
                $cargoExe = (Get-Command cargo -ErrorAction Stop).Source
                $proc = Start-Process -FilePath $cargoExe -ArgumentList @('build', '--manifest-path', (Join-Path $P.RepoDir 'Cargo.toml'), '--release', '--bins') -Wait -PassThru -WindowStyle Hidden
                if ($proc.ExitCode -ne 0) { throw "cargo build exited with code $($proc.ExitCode)" }
            }

            & $prog 40 "Copying EazyConnect apps to $($P.InstallDir)..."
            New-Item -ItemType Directory -Path $P.InstallDir -Force | Out-Null

            $srcDirs = @((Join-Path $P.RepoDir 'target\release'), $P.RepoDir, $P.ScriptDir)
            $neededBins = switch ($P.RoleMode) {
                'server' { @('eazyconnect-server.exe') }
                'client' { @('eazyconnect-ui.exe', 'eazyconnect-client.exe') }
                default  { @('eazyconnect-server.exe', 'eazyconnect-ui.exe', 'eazyconnect-client.exe') }
            }
            $copiedAny = $false
            foreach ($bin in $neededBins) {
                $found = $null
                foreach ($sd in $srcDirs) {
                    $cand = Join-Path $sd $bin
                    if (Test-Path $cand) { $found = $cand; break }
                }
                if ($found) {
                    Copy-Item $found (Join-Path $P.InstallDir $bin) -Force
                    & $log "Installed $bin"
                    $copiedAny = $true
                } else {
                    & $log "WARNING: $bin not found in source directories."
                }
            }
            if (-not $copiedAny) {
                throw "No EazyConnect executables found to copy. Select 'Build from Source' or place prebuilt binaries beside setup."
            }
            if (Test-Path $P.IconSrc) {
                Copy-Item $P.IconSrc (Join-Path $P.InstallDir 'eazyconnect.ico') -Force
            }

            if ($P.RoleMode -ne 'server' -and $P.MasterUrl) {
                & $prog 60 "Saving Desktop App connection preferences..."
                $cfgDir = Join-Path $env:APPDATA 'eazyconnect'
                New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
                $cfgFile = Join-Path $cfgDir 'config.json'
                $cfgObj = if (Test-Path $cfgFile) {
                    Get-Content $cfgFile -Raw | ConvertFrom-Json
                } else {
                    [PSCustomObject]@{ verify = $true; profile = @{ name = ''; photo = ''; language = 'en' } }
                }
                $cfgObj | Add-Member -NotePropertyName 'master' -NotePropertyValue $P.MasterUrl -Force
                $cfgObj | Add-Member -NotePropertyName 'verify' -NotePropertyValue $true -Force
                if ($P.TlsPin) {
                    $cfgObj | Add-Member -NotePropertyName 'tls_pin_hex' -NotePropertyValue $P.TlsPin -Force
                }
                $cfgObj | ConvertTo-Json -Depth 6 | Set-Content -Path $cfgFile -Encoding UTF8
                & $log "Saved client config -> $cfgFile"
            }

            if ($P.AddFw -and ($P.RoleMode -ne 'client')) {
                & $prog 75 "Configuring Windows Firewall rules..."
                $isAdm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if ($isAdm) {
                    netsh advfirewall firewall delete rule name="EazyConnect HTTPS/WSS" | Out-Null
                    netsh advfirewall firewall add rule name="EazyConnect HTTPS/WSS" dir=in action=allow protocol=TCP localport=$($P.ServerPort) | Out-Null
                    netsh advfirewall firewall delete rule name="EazyConnect UDP Discovery" | Out-Null
                    netsh advfirewall firewall add rule name="EazyConnect UDP Discovery" dir=in action=allow protocol=UDP localport=37020 | Out-Null
                    & $log "Windows Firewall rules added (TCP $($P.ServerPort) & UDP 37020)."
                } else {
                    & $log "Skipped Firewall rule (not Administrator — click 'Run as Admin' if remote clients cannot connect)."
                }
            }

            if ($P.MkShortcuts -and ($P.RoleMode -ne 'server')) {
                & $prog 88 "Creating Desktop and Start Menu shortcuts..."
                $uiExe = Join-Path $P.InstallDir 'eazyconnect-ui.exe'
                $ico = Join-Path $P.InstallDir 'eazyconnect.ico'
                if (Test-Path $uiExe) {
                    $ws = New-Object -ComObject WScript.Shell
                    $deskLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'EazyConnect.lnk'
                    $s1 = $ws.CreateShortcut($deskLnk)
                    $s1.TargetPath = $uiExe
                    $s1.WorkingDirectory = $P.InstallDir
                    if (Test-Path $ico) { $s1.IconLocation = $ico }
                    $s1.Save()

                    $progMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'EazyConnect'
                    New-Item -ItemType Directory -Path $progMenu -Force | Out-Null
                    $startLnk = Join-Path $progMenu 'EazyConnect.lnk'
                    $s2 = $ws.CreateShortcut($startLnk)
                    $s2.TargetPath = $uiExe
                    $s2.WorkingDirectory = $P.InstallDir
                    if (Test-Path $ico) { $s2.IconLocation = $ico }
                    $s2.Save()
                    & $log "Desktop & Start Menu shortcuts created."
                }
            }

            if ($P.AddStartup) {
                & $prog 95 "Registering Windows logon startup task..."
                if ($P.RoleMode -eq 'server' -or $P.RoleMode -eq 'full') {
                    $srvExe = Join-Path $P.InstallDir 'eazyconnect-server.exe'
                    if (Test-Path $srvExe) {
                        $cmdLine = "`"$srvExe`" --listen 0.0.0.0:$($P.ServerPort)"
                        if ($P.InviteCode) { $cmdLine += " --invite-code $($P.InviteCode)" }
                        if ($P.LanOnly) { $cmdLine += " --lan-only" }
                        schtasks /Create /F /SC ONLOGON /TN "EazyConnectMaster" /TR $cmdLine | Out-Null
                        & $log "Registered Startup Task 'EazyConnectMaster' (exit $LASTEXITCODE)."
                    }
                } else {
                    $uiExe = Join-Path $P.InstallDir 'eazyconnect-ui.exe'
                    if (Test-Path $uiExe) {
                        schtasks /Create /F /SC ONLOGON /TN "EazyConnectUI" /TR "`"$uiExe`"" | Out-Null
                        & $log "Registered Startup Task 'EazyConnectUI' (exit $LASTEXITCODE)."
                    }
                }
            }

            & $prog 100 "EazyConnect is installed and ready!"
            & $log "Installation completed cleanly."
            $win.Dispatcher.Invoke([Action]{
                $win.FindName("TxtInstallSummary").Text = "Installed cleanly into $($P.InstallDir). You can launch EazyConnect right now."
                $win.FindName("CompletionActions").Visibility = 'Visible'
                $uiPresent = Test-Path (Join-Path $P.InstallDir 'eazyconnect-ui.exe')
                $srvPresent = Test-Path (Join-Path $P.InstallDir 'eazyconnect-server.exe')
                $win.FindName("BtnLaunchUi").Visibility = if ($uiPresent) { 'Visible' } else { 'Collapsed' }
                $win.FindName("BtnLaunchServer").Visibility = if ($srvPresent) { 'Visible' } else { 'Collapsed' }
            })
        } catch {
            & $log "INSTALL ERROR: $_"
            & $prog 0 "Installation encountered an error."
            $win.Dispatcher.Invoke([Action]{
                $win.FindName("TxtInstallSummary").Text = "$_"
                $win.FindName("ExpLog").IsExpanded = $true
                $win.FindName("CompletionActions").Visibility = 'Visible'
                $win.FindName("BtnLaunchUi").Visibility = 'Collapsed'
                $win.FindName("BtnLaunchServer").Visibility = 'Collapsed'
            })
        }
        $S.Busy = $false
    } $taskParams
}

# --- Event Wiring -----------------------------------------------------------
$Step1Tab.Add_Click({ Switch-View 'menu' })
$Step2Tab.Add_Click({ Switch-View 'config' })
$Step3Tab.Add_Click({ Switch-View 'done' })

$BtnChooseClient.Add_Click({
    $RbRoleClient.IsChecked = $true
    Update-RoleVisibility
    Switch-View 'config'
})
$BtnExpressClient.Add_Click({
    $RbRoleClient.IsChecked = $true
    Update-RoleVisibility
    Start-EazyConnectInstall
})
$BtnChooseServer.Add_Click({
    $RbRoleServer.IsChecked = $true
    Update-RoleVisibility
    Switch-View 'config'
})
$BtnChooseFull.Add_Click({
    $RbRoleFull.IsChecked = $true
    Update-RoleVisibility
    Switch-View 'config'
})

$BtnOpenPrereqs.Add_Click({ Switch-View 'prereq' })
$BtnPrereqBack.Add_Click({ Switch-View 'menu' })
$BtnToStep2FromPrereq.Add_Click({ Update-RoleVisibility; Switch-View 'config' })
$BtnBackToStep1.Add_Click({ Switch-View 'menu' })
$BtnDoneMenu.Add_Click({ Switch-View 'menu' })

$RbRoleClient.Add_Checked({ Update-RoleVisibility })
$RbRoleServer.Add_Checked({ Update-RoleVisibility })
$RbRoleFull.Add_Checked({ Update-RoleVisibility })

$BtnRescan.Add_Click({
    Invoke-AsyncSystemScan
    Append-Log "Re-scanned prerequisites, network adapters, and release binaries."
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

$BtnQuickAutoPrereqs.Add_Click({
    $toInstall = @()
    foreach ($kv in $State.PrereqChecks.GetEnumerator()) {
        $item = $kv.Value
        if ((-not $item.Installed) -and (-not $item.Spec.Optional) -and $item.Spec.WingetId) {
            $toInstall += $item.Spec
        }
    }
    Start-WingetInstall -ToInstall $toInstall -ReturnView 'menu'
})

$BtnInstallPrereqs.Add_Click({
    $toInstall = @()
    foreach ($kv in $State.PrereqChecks.GetEnumerator()) {
        $item = $kv.Value
        if ($item.CheckBox.IsChecked -and $item.Spec.WingetId) {
            $toInstall += $item.Spec
        }
    }
    Start-WingetInstall -ToInstall $toInstall -ReturnView 'prereq'
})

$BtnSetupDiscover.Add_Click({
    $pre = Find-PrebuiltBinaryDir
    $cliExe = if ($pre -and (Test-Path (Join-Path $pre 'eazyconnect-client.exe'))) {
        Join-Path $pre 'eazyconnect-client.exe'
    } else {
        $null
    }
    if (-not $cliExe) {
        Append-Log "Place or build eazyconnect-client.exe first to discover Masters."
        return
    }
    $BtnSetupDiscover.IsEnabled = $false
    $BtnSetupDiscover.Content = "Scanning..."
    Append-Log "Scanning LAN / VPN for EazyConnect Master Servers (UDP 37020)..."

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'MTA'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript({
        param($S, $Exe)
        $out = & $Exe discover --timeout-ms 1500 2>&1
        $foundUrl = $null
        $foundPin = $null
        foreach ($line in $out) {
            $ts = (Get-Date).ToString("HH:mm:ss")
            $msg = "$line"
            $S.Window.Dispatcher.Invoke([Action]{
                $S.LogBox.AppendText("[$ts] $msg`r`n")
                $S.LogBox.ScrollToEnd()
            })
            if ((-not $foundUrl) -and ($msg -match '^(https?://[^\s|]+).*tls_pin=([0-9a-fA-F]{64}|<none>)')) {
                $foundUrl = $Matches[1]
                if ($Matches[2] -ne '<none>') { $foundPin = $Matches[2] }
            }
        }
        $S.Window.Dispatcher.Invoke([Action]{
            $btn = $S.Window.FindName("BtnSetupDiscover")
            $btn.IsEnabled = $true
            $btn.Content = "Discover Nearby"
            if ($foundUrl) {
                $S.Window.FindName("TxtMasterUrl").Text = $foundUrl
                if ($foundPin) { $S.Window.FindName("TxtTlsPin").Text = $foundPin }
                $S.FooterText.Text = "Found Master Server: $foundUrl"
            } else {
                $S.FooterText.Text = "No LAN Master answered; you can still connect manually inside the app."
            }
        })
    }).AddArgument($State).AddArgument($cliExe)
    $null = $ps.BeginInvoke()
})

$BtnStartInstall.Add_Click({ Start-EazyConnectInstall })

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

# Apply initial CLI -Role override if re-launched elevated
if ($Role -eq 'server') { $RbRoleServer.IsChecked = $true; Update-RoleVisibility; Switch-View 'config' }
elseif ($Role -eq 'full') { $RbRoleFull.IsChecked = $true; Update-RoleVisibility; Switch-View 'config' }
elseif ($Role -eq 'client') { $RbRoleClient.IsChecked = $true; Update-RoleVisibility; Switch-View 'config' }
else { Update-RoleVisibility; Switch-View 'menu' }

# Scan asynchronously right after the window renders so opening feels instantaneous!
$Window.Add_ContentRendered({
    Invoke-AsyncSystemScan
    Append-Log "EazyConnect Setup ready."
})

$null = $Window.ShowDialog()
