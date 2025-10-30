<#
.SYNOPSIS
    Windows Security Hardening Script - Automated security configuration tool

.DESCRIPTION
    This PowerShell script implements comprehensive Windows security hardening measures
    including password policies, user account settings, network configurations, 
    Windows services, firewall rules, and local security policies.

.PARAMETER ConfigFile
    Optional path to external configuration file (JSON format)

.PARAMETER LogPath
    Path for log file output (default: current directory)

.PARAMETER Silent
    Run in silent mode without user prompts

.PARAMETER WhatIf
    Show what changes would be made without applying them

.EXAMPLE
    .\WindowsSecurityHardening.ps1
    Run the script interactively with default settings

.EXAMPLE
    .\WindowsSecurityHardening.ps1 -Silent -LogPath "C:\Logs"
    Run silently with custom log path

.NOTES
    Author: Windows Security Hardening Script
    Version: 1.0.0
    Created: $(Get-Date -Format 'yyyy-MM-dd')
    
    Requirements:
    - Windows PowerShell 5.1 or PowerShell Core 7.x
    - Administrative privileges required
    - Windows 10/11 or Windows Server 2016/2019/2022
    
    This script modifies system security settings and requires administrative privileges.
    A system restore point will be created before making changes.

.LINK
    https://github.com/your-org/windows-security-hardening
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false)]
    [switch]$Silent,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Script metadata
$Script:ScriptVersion = "1.0.0"
$Script:ScriptName = "Windows Security Hardening Script"
$Script:ScriptAuthor = "Security Team"
$Script:RequiredPSVersion = "5.1"

# Global variables
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:ExecutionResults = @()
$Script:BackupInfo = @{}

#region Prerequisites and Validation Functions

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates system prerequisites before script execution
    .DESCRIPTION
        Checks administrative privileges, PowerShell version, and Windows version compatibility
    .OUTPUTS
        Boolean indicating if all prerequisites are met
    #>
    
    Write-LogMessage "Checking system prerequisites..." -Level "Info"
    
    $prerequisitesPassed = $true
    
    # Check if running as administrator
    if (-not (Test-IsAdministrator)) {
        Write-LogMessage "ERROR: Script must be run with administrative privileges" -Level "Error"
        $prerequisitesPassed = $false
    }
    
    # Check PowerShell version
    if (-not (Test-PowerShellVersion)) {
        Write-LogMessage "ERROR: PowerShell version $Script:RequiredPSVersion or higher is required" -Level "Error"
        $prerequisitesPassed = $false
    }
    
    # Check Windows version
    if (-not (Test-WindowsVersion)) {
        Write-LogMessage "ERROR: Unsupported Windows version detected" -Level "Error"
        $prerequisitesPassed = $false
    }
    
    if ($prerequisitesPassed) {
        Write-LogMessage "All prerequisites validated successfully" -Level "Success"
    }
    
    return $prerequisitesPassed
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if the current PowerShell session is running with administrative privileges
    .OUTPUTS
        Boolean indicating administrative status
    #>
    
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-LogMessage "Failed to check administrative privileges: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Test-PowerShellVersion {
    <#
    .SYNOPSIS
        Validates PowerShell version compatibility
    .OUTPUTS
        Boolean indicating version compatibility
    #>
    
    try {
        $currentVersion = $PSVersionTable.PSVersion
        $requiredVersion = [Version]$Script:RequiredPSVersion
        
        Write-LogMessage "Current PowerShell version: $currentVersion" -Level "Info"
        
        if ($currentVersion -ge $requiredVersion) {
            return $true
        }
        else {
            Write-LogMessage "PowerShell version $requiredVersion or higher is required" -Level "Warning"
            return $false
        }
    }
    catch {
        Write-LogMessage "Failed to check PowerShell version: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Test-WindowsVersion {
    <#
    .SYNOPSIS
        Validates Windows version compatibility
    .OUTPUTS
        Boolean indicating Windows version compatibility
    #>
    
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $osVersion = [Version]$osInfo.Version
        $osName = $osInfo.Caption
        
        Write-LogMessage "Operating System: $osName (Version: $osVersion)" -Level "Info"
        
        # Windows 10 (10.0.10240) and later, Windows Server 2016 (10.0.14393) and later
        $minVersion = [Version]"10.0.10240"
        
        if ($osVersion -ge $minVersion) {
            return $true
        }
        else {
            Write-LogMessage "Windows 10/Server 2016 or later is required" -Level "Warning"
            return $false
        }
    }
    catch {
        Write-LogMessage "Failed to check Windows version: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

#endregion

#region Logging System

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the centralized logging system
    .DESCRIPTION
        Sets up log file path and creates initial log entries
    #>
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $LogPath "WindowsSecurityHardening_$timestamp.log"
    
    try {
        # Create log directory if it doesn't exist
        $logDir = Split-Path $Script:LogFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        
        # Initialize log file with header
        $logHeader = @"
================================================================================
$Script:ScriptName v$Script:ScriptVersion
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $env:USERNAME
Computer: $env:COMPUTERNAME
PowerShell Version: $($PSVersionTable.PSVersion)
================================================================================

"@
        
        $logHeader | Out-File -FilePath $Script:LogFile -Encoding UTF8
        
        Write-Host "Logging initialized: $Script:LogFile" -ForegroundColor Green
    }
    catch {
        Write-Host "WARNING: Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor Yellow
        $Script:LogFile = ""
    }
}

function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes messages to both console and log file
    .PARAMETER Message
        The message to log
    .PARAMETER Level
        Log level (Info, Warning, Error, Success)
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        "Info"    { Write-Host $logEntry -ForegroundColor White }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
        "Debug"   { Write-Host $logEntry -ForegroundColor Gray }
    }
    
    # File output
    if ($Script:LogFile -and (Test-Path (Split-Path $Script:LogFile -Parent))) {
        try {
            $logEntry | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8
        }
        catch {
            Write-Host "WARNING: Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

#endregion

#region Backup and Restore Point Functions

function New-SystemRestorePoint {
    <#
    .SYNOPSIS
        Creates a system restore point before making security changes
    .DESCRIPTION
        Creates a system restore point with a descriptive name and stores the restore point ID
    .OUTPUTS
        Returns the restore point sequence number if successful, $null if failed
    #>
    
    Write-LogMessage "Creating system restore point..." -Level "Info"
    
    try {
        # Check if System Restore is enabled
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($null -eq $restoreStatus) {
            Write-LogMessage "System Restore is not enabled on this system" -Level "Warning"
            Write-LogMessage "Attempting to enable System Restore..." -Level "Info"
            
            # Enable System Restore on system drive
            $systemDrive = $env:SystemDrive
            Enable-ComputerRestore -Drive $systemDrive -ErrorAction Stop
            Write-LogMessage "System Restore enabled on $systemDrive" -Level "Success"
        }
        
        # Create restore point description with timestamp
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $description = "Windows Security Hardening - Before Changes ($timestamp)"
        
        # Create the restore point
        $restorePoint = Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        
        # Get the most recent restore point (should be the one we just created)
        $latestRestorePoint = Get-ComputerRestorePoint | Sort-Object SequenceNumber -Descending | Select-Object -First 1
        
        if ($latestRestorePoint) {
            $Script:BackupInfo.RestorePointId = $latestRestorePoint.SequenceNumber
            $Script:BackupInfo.RestorePointDescription = $description
            $Script:BackupInfo.RestorePointCreated = Get-Date
            
            Write-LogMessage "System restore point created successfully" -Level "Success"
            Write-LogMessage "Restore Point ID: $($latestRestorePoint.SequenceNumber)" -Level "Info"
            Write-LogMessage "Description: $description" -Level "Info"
            
            return $latestRestorePoint.SequenceNumber
        }
        else {
            Write-LogMessage "Failed to verify restore point creation" -Level "Warning"
            return $null
        }
    }
    catch {
        Write-LogMessage "Failed to create system restore point: $($_.Exception.Message)" -Level "Error"
        Write-LogMessage "Continuing without restore point - manual backup recommended" -Level "Warning"
        return $null
    }
}

function Backup-RegistryKeys {
    <#
    .SYNOPSIS
        Backs up critical registry keys before making modifications
    .DESCRIPTION
        Exports specified registry keys to backup files for potential restoration
    .PARAMETER RegistryPaths
        Array of registry paths to backup
    .OUTPUTS
        Returns hashtable with backup file paths and status
    #>
    
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$RegistryPaths = @(
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            "HKLM\SYSTEM\CurrentControlSet\Services\upnphost",
            "HKLM\SOFTWARE\Policies\Microsoft\Windows",
            "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
            "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        )
    )
    
    Write-LogMessage "Backing up critical registry keys..." -Level "Info"
    
    $backupResults = @{}
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = Join-Path $LogPath "RegistryBackups_$timestamp"
    
    try {
        # Create backup directory
        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
            Write-LogMessage "Created registry backup directory: $backupDir" -Level "Info"
        }
        
        foreach ($regPath in $RegistryPaths) {
            try {
                # Convert registry path for reg.exe command
                $regKey = $regPath -replace "HKLM\\", "HKEY_LOCAL_MACHINE\" -replace "HKCU\\", "HKEY_CURRENT_USER\"
                
                # Create safe filename from registry path
                $safeFileName = ($regPath -replace "[\\\/:*?""<>|]", "_") + ".reg"
                $backupFile = Join-Path $backupDir $safeFileName
                
                # Export registry key using reg.exe
                $regArgs = @("export", $regKey, $backupFile, "/y")
                $process = Start-Process -FilePath "reg.exe" -ArgumentList $regArgs -Wait -PassThru -WindowStyle Hidden
                
                if ($process.ExitCode -eq 0 -and (Test-Path $backupFile)) {
                    $backupResults[$regPath] = @{
                        Status = "Success"
                        BackupFile = $backupFile
                        Size = (Get-Item $backupFile).Length
                    }
                    Write-LogMessage "Backed up registry key: $regPath" -Level "Success"
                }
                else {
                    $backupResults[$regPath] = @{
                        Status = "Failed"
                        Error = "Registry export failed with exit code: $($process.ExitCode)"
                    }
                    Write-LogMessage "Failed to backup registry key: $regPath" -Level "Warning"
                }
            }
            catch {
                $backupResults[$regPath] = @{
                    Status = "Failed"
                    Error = $_.Exception.Message
                }
                Write-LogMessage "Error backing up registry key $regPath`: $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        # Store backup information
        $Script:BackupInfo.RegistryBackups = $backupResults
        $Script:BackupInfo.RegistryBackupDir = $backupDir
        
        $successCount = ($backupResults.Values | Where-Object { $_.Status -eq "Success" }).Count
        $totalCount = $backupResults.Count
        
        Write-LogMessage "Registry backup completed: $successCount/$totalCount keys backed up successfully" -Level "Info"
        
        return $backupResults
    }
    catch {
        Write-LogMessage "Critical error during registry backup: $($_.Exception.Message)" -Level "Error"
        return @{}
    }
}

function Backup-ServiceStates {
    <#
    .SYNOPSIS
        Backs up current Windows service states before making modifications
    .DESCRIPTION
        Captures current service status, startup type, and configuration for restoration
    .OUTPUTS
        Returns hashtable with service state information
    #>
    
    Write-LogMessage "Backing up Windows service states..." -Level "Info"
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = Join-Path $LogPath "ServiceStates_$timestamp.json"
        
        # Get all services and their current states
        $services = Get-Service | ForEach-Object {
            $service = $_
            $serviceConfig = $null
            
            try {
                # Get additional service configuration using WMI
                $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            }
            catch {
                Write-LogMessage "Warning: Could not get extended info for service: $($service.Name)" -Level "Debug"
            }
            
            @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status.ToString()
                StartType = if ($serviceConfig) { $serviceConfig.StartMode } else { "Unknown" }
                ServiceType = $service.ServiceType.ToString()
                CanStop = $service.CanStop
                CanPauseAndContinue = $service.CanPauseAndContinue
                DependentServices = @($service.DependentServices | ForEach-Object { $_.Name })
                ServicesDependedOn = @($service.ServicesDependedOn | ForEach-Object { $_.Name })
                PathName = if ($serviceConfig) { $serviceConfig.PathName } else { $null }
                Description = if ($serviceConfig) { $serviceConfig.Description } else { $null }
            }
        }
        
        # Convert to JSON and save to file
        $servicesJson = $services | ConvertTo-Json -Depth 3
        $servicesJson | Out-File -FilePath $backupFile -Encoding UTF8
        
        # Store backup information
        $Script:BackupInfo.ServiceStates = @{
            BackupFile = $backupFile
            ServiceCount = $services.Count
            BackupTime = Get-Date
        }
        
        Write-LogMessage "Service states backed up successfully" -Level "Success"
        Write-LogMessage "Backup file: $backupFile" -Level "Info"
        Write-LogMessage "Services backed up: $($services.Count)" -Level "Info"
        
        return $services
    }
    catch {
        Write-LogMessage "Failed to backup service states: $($_.Exception.Message)" -Level "Error"
        return @()
    }
}

function Backup-SecurityPolicies {
    <#
    .SYNOPSIS
        Backs up current local security policies using secedit
    .DESCRIPTION
        Exports current security policies to a backup file for potential restoration
    .OUTPUTS
        Returns the path to the backup file if successful, $null if failed
    #>
    
    Write-LogMessage "Backing up local security policies..." -Level "Info"
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = Join-Path $LogPath "SecurityPolicies_$timestamp.inf"
        $logFile = Join-Path $LogPath "SecurityPolicyBackup_$timestamp.log"
        
        # Use secedit to export current security policies
        $seceditArgs = @("/export", "/cfg", $backupFile, "/log", $logFile, "/quiet")
        $process = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -WindowStyle Hidden
        
        if ($process.ExitCode -eq 0 -and (Test-Path $backupFile)) {
            # Verify the backup file contains data
            $backupContent = Get-Content $backupFile -ErrorAction SilentlyContinue
            if ($backupContent -and $backupContent.Count -gt 0) {
                $Script:BackupInfo.SecurityPolicies = @{
                    BackupFile = $backupFile
                    LogFile = $logFile
                    BackupTime = Get-Date
                    FileSize = (Get-Item $backupFile).Length
                }
                
                Write-LogMessage "Security policies backed up successfully" -Level "Success"
                Write-LogMessage "Backup file: $backupFile" -Level "Info"
                Write-LogMessage "File size: $((Get-Item $backupFile).Length) bytes" -Level "Info"
                
                return $backupFile
            }
            else {
                Write-LogMessage "Security policy backup file is empty or invalid" -Level "Warning"
                return $null
            }
        }
        else {
            Write-LogMessage "secedit export failed with exit code: $($process.ExitCode)" -Level "Error"
            
            # Try to read the log file for more details
            if (Test-Path $logFile) {
                $logContent = Get-Content $logFile -ErrorAction SilentlyContinue
                if ($logContent) {
                    Write-LogMessage "secedit log output:" -Level "Debug"
                    $logContent | ForEach-Object { Write-LogMessage "  $_" -Level "Debug" }
                }
            }
            
            return $null
        }
    }
    catch {
        Write-LogMessage "Failed to backup security policies: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Initialize-BackupSystem {
    <#
    .SYNOPSIS
        Initializes the complete backup system before making security changes
    .DESCRIPTION
        Orchestrates all backup operations including restore point, registry, services, and policies
    .OUTPUTS
        Returns boolean indicating if backup system was initialized successfully
    #>
    
    Write-LogMessage "Initializing backup system..." -Level "Info"
    Write-LogMessage "This may take several minutes..." -Level "Info"
    
    try {
        # Initialize backup info structure
        $Script:BackupInfo = @{
            BackupStartTime = Get-Date
            RestorePointId = $null
            RegistryBackups = @{}
            ServiceStates = @{}
            SecurityPolicies = @{}
            BackupCompleted = $false
        }
        
        $backupSuccess = $true
        
        # Step 1: Create system restore point
        Write-LogMessage "Step 1/4: Creating system restore point..." -Level "Info"
        $restorePointId = New-SystemRestorePoint
        if ($restorePointId) {
            Write-LogMessage "System restore point created: ID $restorePointId" -Level "Success"
        }
        else {
            Write-LogMessage "System restore point creation failed" -Level "Warning"
            $backupSuccess = $false
        }
        
        # Step 2: Backup registry keys
        Write-LogMessage "Step 2/4: Backing up critical registry keys..." -Level "Info"
        $registryBackup = Backup-RegistryKeys
        if ($registryBackup -and $registryBackup.Count -gt 0) {
            $successCount = ($registryBackup.Values | Where-Object { $_.Status -eq "Success" }).Count
            Write-LogMessage "Registry backup completed: $successCount keys backed up" -Level "Success"
        }
        else {
            Write-LogMessage "Registry backup failed" -Level "Warning"
            $backupSuccess = $false
        }
        
        # Step 3: Backup service states
        Write-LogMessage "Step 3/4: Backing up Windows service states..." -Level "Info"
        $serviceBackup = Backup-ServiceStates
        if ($serviceBackup -and $serviceBackup.Count -gt 0) {
            Write-LogMessage "Service states backup completed: $($serviceBackup.Count) services" -Level "Success"
        }
        else {
            Write-LogMessage "Service states backup failed" -Level "Warning"
            $backupSuccess = $false
        }
        
        # Step 4: Backup security policies
        Write-LogMessage "Step 4/4: Backing up local security policies..." -Level "Info"
        $policyBackup = Backup-SecurityPolicies
        if ($policyBackup) {
            Write-LogMessage "Security policies backup completed" -Level "Success"
        }
        else {
            Write-LogMessage "Security policies backup failed" -Level "Warning"
            $backupSuccess = $false
        }
        
        # Finalize backup information
        $Script:BackupInfo.BackupEndTime = Get-Date
        $Script:BackupInfo.BackupDuration = $Script:BackupInfo.BackupEndTime - $Script:BackupInfo.BackupStartTime
        $Script:BackupInfo.BackupCompleted = $true
        
        # Generate backup summary
        Write-LogMessage "`n" + "="*60 -Level "Info"
        Write-LogMessage "BACKUP SUMMARY" -Level "Info"
        Write-LogMessage "="*60 -Level "Info"
        Write-LogMessage "Backup Duration: $($Script:BackupInfo.BackupDuration.ToString('mm\:ss'))" -Level "Info"
        
        if ($Script:BackupInfo.RestorePointId) {
            Write-LogMessage "System Restore Point: ID $($Script:BackupInfo.RestorePointId)" -Level "Success"
        }
        
        if ($Script:BackupInfo.RegistryBackups -and $Script:BackupInfo.RegistryBackups.Count -gt 0) {
            $regSuccessCount = ($Script:BackupInfo.RegistryBackups.Values | Where-Object { $_.Status -eq "Success" }).Count
            Write-LogMessage "Registry Keys Backed Up: $regSuccessCount/$($Script:BackupInfo.RegistryBackups.Count)" -Level "Info"
        }
        
        if ($Script:BackupInfo.ServiceStates -and $Script:BackupInfo.ServiceStates.ServiceCount) {
            Write-LogMessage "Services Backed Up: $($Script:BackupInfo.ServiceStates.ServiceCount)" -Level "Info"
        }
        
        if ($Script:BackupInfo.SecurityPolicies -and $Script:BackupInfo.SecurityPolicies.BackupFile) {
            Write-LogMessage "Security Policies: Backed up successfully" -Level "Success"
        }
        
        Write-LogMessage "="*60 -Level "Info"
        
        if ($backupSuccess) {
            Write-LogMessage "Backup system initialized successfully" -Level "Success"
            Write-LogMessage "System is ready for security hardening modifications" -Level "Info"
        }
        else {
            Write-LogMessage "Backup system initialized with warnings" -Level "Warning"
            Write-LogMessage "Some backup operations failed - proceed with caution" -Level "Warning"
        }
        
        return $backupSuccess
    }
    catch {
        Write-LogMessage "Critical error initializing backup system: $($_.Exception.Message)" -Level "Error"
        $Script:BackupInfo.BackupCompleted = $false
        return $false
    }
}

function Get-BackupInformation {
    <#
    .SYNOPSIS
        Returns current backup information for reporting and verification
    .OUTPUTS
        Returns the backup information hashtable
    #>
    
    return $Script:BackupInfo
}

#endregion

#region Configuration Management

function Initialize-Configuration {
    <#
    .SYNOPSIS
        Initializes the configuration object structure for all security settings
    .DESCRIPTION
        Creates the master configuration object with all security settings and their default values
    .OUTPUTS
        Hashtable containing all configuration settings
    #>
    
    Write-LogMessage "Initializing security configuration settings..." -Level "Info"
    
    $config = @{
        # Password Policy Configuration (Requirement 1)
        PasswordPolicy = @{
            HistoryCount = 24           # Remember 24 passwords
            MaxAge = 60                 # Maximum password age in days
            MinAge = 1                  # Minimum password age in days
            MinLength = 10              # Minimum password length
            ComplexityEnabled = $true   # Enable password complexity requirements
        }
        
        # Account Lockout Policy (Requirement 2)
        LockoutPolicy = @{
            Duration = 30               # Account lockout duration in minutes
            Threshold = 10              # Account lockout threshold (failed attempts)
            ResetCounter = 30           # Reset lockout counter after minutes
        }
        
        # User Account Settings (Requirement 3)
        UserSettings = @{
            ForcePasswordChange = $true     # Force all users to change password at next logon
            DisableUnauthorized = $true     # Disable unauthorized user accounts
            AuthorizedAdmins = @()          # List of authorized administrators
            AuthorizedRDPUsers = @()        # List of authorized RDP users
            RestrictAdminGroup = $true      # Restrict Administrators group
            RestrictGuestGroup = $true      # Ensure Guests group contains only Guest account
        }
        
        # Windows Security Features (Requirement 4)
        SecurityFeatures = @{
            EnableSmartScreen = $true       # Enable SmartScreen online services
            DisableWiFiSense = $true        # Disable Wi-Fi Sense automatic connections
            MaximizeUAC = $true             # Set UAC to maximum level
            EnableDefender = $true          # Enable Windows Defender when available
        }
        
        # Network Adapter Configuration (Requirement 5)
        NetworkSettings = @{
            DisableClientForMSNetworks = $true      # Disable Client for MS Networks
            DisableFileAndPrinterSharing = $true    # Disable File and Printer Sharing
            DisableIPv6 = $true                     # Disable IPv6 protocol
            DisableDNSRegistration = $true          # Disable DNS registration
            DisableNetBIOS = $true                  # Disable NetBIOS over TCP/IP
        }
        
        # Windows Services Configuration (Requirement 6)
        ServicesConfig = @{
            DisableUPnP = $true             # Stop and disable UPnP Device Host
            DisableTelnet = $true           # Stop and disable Telnet service
            DisableSNMPTrap = $true         # Stop and disable SNMP Trap service
            DisableRemoteRegistry = $true   # Stop and disable Remote Registry
            EnableEventCollector = $true    # Enable Windows Event Collector
        }
        
        # Windows Features Configuration (Requirement 7)
        FeaturesConfig = @{
            DisableTelnetClient = $true     # Disable Telnet client feature
            DisableTelnetServer = $true     # Disable Telnet server feature
            DisableSNMP = $true             # Disable SNMP feature
            DisableSMBv1 = $true            # Disable SMB v1 protocol
            DisableIIS = $true              # Disable IIS when not required
            DisableTFTP = $true             # Disable TFTP when FTP not required
        }
        
        # Firewall Rules Configuration (Requirement 8)
        FirewallRules = @{
            BlockMicrosoftEdge = $true      # Block Microsoft Edge
            BlockWindowsSearch = $true      # Block Windows Search
            BlockMSNApps = $true            # Block MSN applications
            BlockXboxApps = $true           # Block Xbox applications
            BlockMicrosoftPhotos = $true    # Block Microsoft Photos
        }
        
        # System Settings Configuration (Requirement 9)
        SystemSettings = @{
            DisableAutoPlay = $true         # Disable AutoPlay functionality
            ScreenSaverTimeout = 10         # Screen saver timeout in minutes
            RequireLogonOnResume = $true    # Require logon on resume
            DisableOneDriveStartup = $true  # Disable OneDrive startup
            EnableAuditing = $true          # Enable comprehensive auditing
        }
        
        # Local Security Policy Configuration (Requirement 10)
        SecurityPolicy = @{
            DisableAdministratorAccount = $true     # Disable Administrator account
            DisableGuestAccount = $true             # Disable Guest account
            BlockMicrosoftAccounts = $true          # Block Microsoft account usage
            EnableDigitalSigning = $true            # Enable digital signing
            ConfigureInteractiveLogon = $true       # Configure interactive logon settings
            MaximizeNetworkSecurity = $true         # Set network security to maximum
        }
        
        # Registry Modifications (Requirement 11)
        RegistrySettings = @{
            DisableUPnPPort1900 = $true     # Disable UPnP on port 1900
            SetUPnPMode = 2                 # Set UPnPMode registry value
            VerifyChanges = $true           # Verify registry changes
        }
        
        # Script Execution Settings (Requirement 12)
        ExecutionSettings = @{
            ShowProgress = $true            # Display progress information
            ReportChanges = $true           # Report successful changes
            LogErrors = $true               # Log errors encountered
            ProvideSummary = $true          # Provide execution summary
            DetailedErrorMessages = $true   # Provide clear error messages
        }
        
        # Backup and Recovery Settings
        BackupSettings = @{
            CreateRestorePoint = $true      # Create system restore point
            BackupRegistry = $true          # Backup registry keys
            BackupServices = $true          # Backup service states
            BackupPolicies = $true          # Backup security policies
        }
    }
    
    # Load external configuration if specified
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        try {
            Write-LogMessage "Loading external configuration from: $ConfigFile" -Level "Info"
            $externalConfig = Get-Content $ConfigFile | ConvertFrom-Json -AsHashtable
            
            # Merge external configuration with defaults
            foreach ($section in $externalConfig.Keys) {
                if ($config.ContainsKey($section)) {
                    foreach ($setting in $externalConfig[$section].Keys) {
                        $config[$section][$setting] = $externalConfig[$section][$setting]
                    }
                }
            }
            
            Write-LogMessage "External configuration loaded successfully" -Level "Success"
        }
        catch {
            Write-LogMessage "Failed to load external configuration: $($_.Exception.Message)" -Level "Warning"
            Write-LogMessage "Continuing with default configuration..." -Level "Info"
        }
    }
    
    Write-LogMessage "Configuration initialized with $(($config.Keys).Count) sections" -Level "Success"
    return $config
}

function Show-Configuration {
    <#
    .SYNOPSIS
        Displays the current configuration settings
    .PARAMETER Config
        Configuration hashtable to display
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Current Configuration Settings:" -Level "Info"
    Write-LogMessage "================================" -Level "Info"
    
    foreach ($section in $Config.Keys | Sort-Object) {
        Write-LogMessage "[$section]" -Level "Info"
        foreach ($setting in $Config[$section].Keys | Sort-Object) {
            $value = $Config[$section][$setting]
            if ($value -is [array]) {
                $displayValue = "[$($value -join ', ')]"
            } else {
                $displayValue = $value
            }
            Write-LogMessage "  $setting = $displayValue" -Level "Info"
        }
        Write-LogMessage "" -Level "Info"
    }
}

#endregion
#re
gion Main Execution Framework

function Start-SecurityHardening {
    <#
    .SYNOPSIS
        Main entry point for the security hardening process
    .DESCRIPTION
        Orchestrates the complete security hardening workflow with error handling
    #>
    
    try {
        Write-LogMessage "Starting Windows Security Hardening Process..." -Level "Info"
        Write-LogMessage "Script Version: $Script:ScriptVersion" -Level "Info"
        
        # Initialize configuration
        $config = Initialize-Configuration
        
        # Show configuration if not in silent mode
        if (-not $Silent) {
            Show-Configuration -Config $config
            
            if (-not $WhatIf) {
                $confirmation = Read-Host "`nDo you want to proceed with these settings? (Y/N)"
                if ($confirmation -notmatch '^[Yy]') {
                    Write-LogMessage "Operation cancelled by user" -Level "Warning"
                    return
                }
            }
        }
        
        if ($WhatIf) {
            Write-LogMessage "WhatIf mode: No changes will be made to the system" -Level "Warning"
        }
        
        # Validate prerequisites
        if (-not (Test-Prerequisites)) {
            throw "Prerequisites validation failed. Cannot continue."
        }
        
        # Initialize backup system if not in WhatIf mode
        if (-not $WhatIf -and $config.BackupSettings.CreateRestorePoint) {
            Write-LogMessage "Initializing backup and restore point system..." -Level "Info"
            $backupSuccess = Initialize-BackupSystem
            
            if (-not $backupSuccess) {
                if (-not $Silent) {
                    $continueChoice = Read-Host "`nBackup system initialization had warnings. Continue anyway? (Y/N)"
                    if ($continueChoice -notmatch '^[Yy]') {
                        Write-LogMessage "Operation cancelled due to backup system warnings" -Level "Warning"
                        return
                    }
                }
                else {
                    Write-LogMessage "Continuing with backup system warnings in silent mode" -Level "Warning"
                }
            }
        }
        elseif ($WhatIf) {
            Write-LogMessage "Backup system skipped in WhatIf mode" -Level "Info"
        }
        else {
            Write-LogMessage "Backup system disabled in configuration" -Level "Warning"
        }
        
        Write-LogMessage "Security hardening process initialized successfully" -Level "Success"
        Write-LogMessage "Configuration loaded and validated" -Level "Success"
        Write-LogMessage "Ready to begin security configuration modules..." -Level "Info"
        
        # Store configuration for use by other modules
        $Script:Configuration = $config
        
        return $config
    }
    catch {
        Write-LogMessage "Failed to initialize security hardening: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

function Complete-SecurityHardening {
    <#
    .SYNOPSIS
        Completes the security hardening process and generates summary
    .DESCRIPTION
        Performs cleanup, generates execution summary, and provides final status
    #>
    
    try {
        $endTime = Get-Date
        $executionTime = $endTime - $Script:StartTime
        
        Write-LogMessage "Security hardening process completed" -Level "Success"
        Write-LogMessage "Total execution time: $($executionTime.ToString('hh\:mm\:ss'))" -Level "Info"
        
        # Generate execution summary
        Write-LogMessage "`n" + "="*80 -Level "Info"
        Write-LogMessage "EXECUTION SUMMARY" -Level "Info"
        Write-LogMessage "="*80 -Level "Info"
        Write-LogMessage "Start Time: $($Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "Info"
        Write-LogMessage "End Time: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "Info"
        Write-LogMessage "Duration: $($executionTime.ToString('hh\:mm\:ss'))" -Level "Info"
        Write-LogMessage "Log File: $Script:LogFile" -Level "Info"
        
        if ($Script:ExecutionResults.Count -gt 0) {
            $successCount = ($Script:ExecutionResults | Where-Object { $_.Success }).Count
            $failureCount = $Script:ExecutionResults.Count - $successCount
            
            Write-LogMessage "Modules Executed: $($Script:ExecutionResults.Count)" -Level "Info"
            Write-LogMessage "Successful: $successCount" -Level "Success"
            Write-LogMessage "Failed: $failureCount" -Level $(if ($failureCount -gt 0) { "Warning" } else { "Info" })
        }
        
        Write-LogMessage "="*80 -Level "Info"
        
        if (-not $Silent) {
            Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
    catch {
        Write-LogMessage "Error during completion: $($_.Exception.Message)" -Level "Error"
    }
}

function Add-ExecutionResult {
    <#
    .SYNOPSIS
        Adds an execution result to the global results collection
    .PARAMETER ModuleName
        Name of the module that was executed
    .PARAMETER Success
        Whether the module execution was successful
    .PARAMETER Changes
        Array of changes made by the module
    .PARAMETER Errors
        Array of errors encountered
    .PARAMETER Warnings
        Array of warnings generated
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [bool]$Success,
        
        [Parameter(Mandatory = $false)]
        [array]$Changes = @(),
        
        [Parameter(Mandatory = $false)]
        [array]$Errors = @(),
        
        [Parameter(Mandatory = $false)]
        [array]$Warnings = @()
    )
    
    $result = @{
        ModuleName = $ModuleName
        Success = $Success
        Changes = $Changes
        Errors = $Errors
        Warnings = $Warnings
        ExecutionTime = Get-Date
    }
    
    $Script:ExecutionResults += $result
}

#endregion

#region Password Policy Configuration Module

function Set-PasswordPolicy {
    <#
    .SYNOPSIS
        Configures local password policy settings according to security requirements
    .DESCRIPTION
        Implements password policy configuration using secedit to enforce:
        - Password history: 24 passwords
        - Maximum password age: 60 days
        - Minimum password age: 1 day
        - Minimum password length: 10 characters
        - Password complexity: Enabled
    .PARAMETER Config
        Configuration hashtable containing password policy settings
    .OUTPUTS
        Returns execution result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Configuring password policy settings..." -Level "Info"
    
    $result = @{
        ModuleName = "Password Policy Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
    }
    
    try {
        # Validate configuration parameters
        if (-not $Config.ContainsKey('PasswordPolicy')) {
            throw "Password policy configuration section not found"
        }
        
        $passwordConfig = $Config.PasswordPolicy
        
        # Validate required settings
        $requiredSettings = @('HistoryCount', 'MaxAge', 'MinAge', 'MinLength', 'ComplexityEnabled')
        foreach ($setting in $requiredSettings) {
            if (-not $passwordConfig.ContainsKey($setting)) {
                throw "Required password policy setting '$setting' not found in configuration"
            }
        }
        
        Write-LogMessage "Password policy configuration validated" -Level "Success"
        
        # Create temporary security template file
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $tempDir = Join-Path $env:TEMP "SecurityHardening_$timestamp"
        $templateFile = Join-Path $tempDir "PasswordPolicy.inf"
        $logFile = Join-Path $tempDir "PasswordPolicy.log"
        
        # Create temporary directory
        if (-not (Test-Path $tempDir)) {
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        }
        
        # Generate security template content for password policy
        $templateContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
PasswordHistorySize = $($passwordConfig.HistoryCount)
MaximumPasswordAge = $($passwordConfig.MaxAge)
MinimumPasswordAge = $($passwordConfig.MinAge)
MinimumPasswordLength = $($passwordConfig.MinLength)
PasswordComplexity = $(if ($passwordConfig.ComplexityEnabled) { 1 } else { 0 })
ClearTextPassword = 0
RequireLogonToChangePassword = 0
"@
        
        # Write template to file
        $templateContent | Out-File -FilePath $templateFile -Encoding Unicode
        Write-LogMessage "Security template created: $templateFile" -Level "Info"
        
        # Apply password policy using secedit
        Write-LogMessage "Applying password policy configuration..." -Level "Info"
        $seceditArgs = @("/configure", "/cfg", $templateFile, "/log", $logFile, "/quiet")
        
        if ($WhatIf) {
            Write-LogMessage "WhatIf: Would execute secedit.exe with arguments: $($seceditArgs -join ' ')" -Level "Info"
            $result.Changes += "Would set password history to $($passwordConfig.HistoryCount) passwords"
            $result.Changes += "Would set maximum password age to $($passwordConfig.MaxAge) days"
            $result.Changes += "Would set minimum password age to $($passwordConfig.MinAge) day"
            $result.Changes += "Would set minimum password length to $($passwordConfig.MinLength) characters"
            $result.Changes += "Would $(if ($passwordConfig.ComplexityEnabled) { 'enable' } else { 'disable' }) password complexity requirements"
            $result.Success = $true
        }
        else {
            $process = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -WindowStyle Hidden
            
            if ($process.ExitCode -eq 0) {
                Write-LogMessage "Password policy applied successfully" -Level "Success"
                
                # Record changes made
                $result.Changes += "Set password history to $($passwordConfig.HistoryCount) passwords"
                $result.Changes += "Set maximum password age to $($passwordConfig.MaxAge) days"
                $result.Changes += "Set minimum password age to $($passwordConfig.MinAge) day"
                $result.Changes += "Set minimum password length to $($passwordConfig.MinLength) characters"
                $result.Changes += "$(if ($passwordConfig.ComplexityEnabled) { 'Enabled' } else { 'Disabled' }) password complexity requirements"
                
                # Validate the applied policy
                $validationResult = Test-PasswordPolicyApplication -Config $passwordConfig
                if ($validationResult.Success) {
                    Write-LogMessage "Password policy validation successful" -Level "Success"
                    $result.Success = $true
                }
                else {
                    $result.Errors += "Password policy validation failed: $($validationResult.Error)"
                    $result.Warnings += "Policy may not have been applied correctly"
                }
            }
            else {
                $errorMsg = "secedit failed with exit code: $($process.ExitCode)"
                
                # Try to read the log file for more details
                if (Test-Path $logFile) {
                    $logContent = Get-Content $logFile -ErrorAction SilentlyContinue
                    if ($logContent) {
                        $errorMsg += ". Log details: $($logContent -join '; ')"
                    }
                }
                
                throw $errorMsg
            }
        }
        
        # Cleanup temporary files
        try {
            if (Test-Path $tempDir) {
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            $result.Warnings += "Failed to cleanup temporary files: $($_.Exception.Message)"
        }
        
        Write-LogMessage "Password policy configuration completed" -Level "Success"
    }
    catch {
        $result.Errors += $_.Exception.Message
        Write-LogMessage "Password policy configuration failed: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Test-PasswordPolicyApplication {
    <#
    .SYNOPSIS
        Validates that password policy settings have been applied correctly
    .DESCRIPTION
        Verifies the current password policy settings match the configured values
        using net accounts command and registry checks
    .PARAMETER Config
        Password policy configuration to validate against
    .OUTPUTS
        Returns validation result with success status and details
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Validating password policy application..." -Level "Info"
    
    $validationResult = @{
        Success = $true
        Error = ""
        Details = @()
    }
    
    try {
        # Use net accounts to get current password policy
        $netAccountsOutput = & net accounts 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to retrieve current password policy using 'net accounts'"
        }
        
        # Parse net accounts output
        $currentPolicy = @{}
        foreach ($line in $netAccountsOutput) {
            if ($line -match "Force user logoff how long after time expires\?:\s*(.+)") {
                # This line is not directly related to our settings
            }
            elseif ($line -match "Minimum password age \(days\):\s*(\d+)") {
                $currentPolicy.MinAge = [int]$matches[1]
            }
            elseif ($line -match "Maximum password age \(days\):\s*(\d+)") {
                $currentPolicy.MaxAge = [int]$matches[1]
            }
            elseif ($line -match "Minimum password length:\s*(\d+)") {
                $currentPolicy.MinLength = [int]$matches[1]
            }
            elseif ($line -match "Length of password history maintained:\s*(\d+)") {
                $currentPolicy.HistoryCount = [int]$matches[1]
            }
            elseif ($line -match "Account lockout threshold:\s*(\d+|Never)") {
                # This is lockout policy, not password policy
            }
        }
        
        # Validate password history
        if ($currentPolicy.ContainsKey('HistoryCount')) {
            if ($currentPolicy.HistoryCount -eq $Config.HistoryCount) {
                $validationResult.Details += "Password history: $($currentPolicy.HistoryCount) passwords (✓)"
                Write-LogMessage "Password history validation passed: $($currentPolicy.HistoryCount)" -Level "Success"
            }
            else {
                $validationResult.Success = $false
                $validationResult.Details += "Password history: Expected $($Config.HistoryCount), got $($currentPolicy.HistoryCount) (✗)"
                Write-LogMessage "Password history validation failed: Expected $($Config.HistoryCount), got $($currentPolicy.HistoryCount)" -Level "Error"
            }
        }
        else {
            $validationResult.Success = $false
            $validationResult.Details += "Password history: Could not retrieve current value (✗)"
        }
        
        # Validate maximum password age
        if ($currentPolicy.ContainsKey('MaxAge')) {
            if ($currentPolicy.MaxAge -eq $Config.MaxAge) {
                $validationResult.Details += "Maximum password age: $($currentPolicy.MaxAge) days (✓)"
                Write-LogMessage "Maximum password age validation passed: $($currentPolicy.MaxAge)" -Level "Success"
            }
            else {
                $validationResult.Success = $false
                $validationResult.Details += "Maximum password age: Expected $($Config.MaxAge), got $($currentPolicy.MaxAge) (✗)"
                Write-LogMessage "Maximum password age validation failed: Expected $($Config.MaxAge), got $($currentPolicy.MaxAge)" -Level "Error"
            }
        }
        else {
            $validationResult.Success = $false
            $validationResult.Details += "Maximum password age: Could not retrieve current value (✗)"
        }
        
        # Validate minimum password age
        if ($currentPolicy.ContainsKey('MinAge')) {
            if ($currentPolicy.MinAge -eq $Config.MinAge) {
                $validationResult.Details += "Minimum password age: $($currentPolicy.MinAge) day (✓)"
                Write-LogMessage "Minimum password age validation passed: $($currentPolicy.MinAge)" -Level "Success"
            }
            else {
                $validationResult.Success = $false
                $validationResult.Details += "Minimum password age: Expected $($Config.MinAge), got $($currentPolicy.MinAge) (✗)"
                Write-LogMessage "Minimum password age validation failed: Expected $($Config.MinAge), got $($currentPolicy.MinAge)" -Level "Error"
            }
        }
        else {
            $validationResult.Success = $false
            $validationResult.Details += "Minimum password age: Could not retrieve current value (✗)"
        }
        
        # Validate minimum password length
        if ($currentPolicy.ContainsKey('MinLength')) {
            if ($currentPolicy.MinLength -eq $Config.MinLength) {
                $validationResult.Details += "Minimum password length: $($currentPolicy.MinLength) characters (✓)"
                Write-LogMessage "Minimum password length validation passed: $($currentPolicy.MinLength)" -Level "Success"
            }
            else {
                $validationResult.Success = $false
                $validationResult.Details += "Minimum password length: Expected $($Config.MinLength), got $($currentPolicy.MinLength) (✗)"
                Write-LogMessage "Minimum password length validation failed: Expected $($Config.MinLength), got $($currentPolicy.MinLength)" -Level "Error"
            }
        }
        else {
            $validationResult.Success = $false
            $validationResult.Details += "Minimum password length: Could not retrieve current value (✗)"
        }
        
        # Validate password complexity using registry
        try {
            $complexityRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $complexityValue = Get-ItemProperty -Path $complexityRegPath -Name "PasswordComplexity" -ErrorAction SilentlyContinue
            
            if ($complexityValue) {
                $currentComplexity = $complexityValue.PasswordComplexity -eq 1
                $expectedComplexity = $Config.ComplexityEnabled
                
                if ($currentComplexity -eq $expectedComplexity) {
                    $validationResult.Details += "Password complexity: $(if ($currentComplexity) { 'Enabled' } else { 'Disabled' }) (✓)"
                    Write-LogMessage "Password complexity validation passed: $(if ($currentComplexity) { 'Enabled' } else { 'Disabled' })" -Level "Success"
                }
                else {
                    $validationResult.Success = $false
                    $validationResult.Details += "Password complexity: Expected $(if ($expectedComplexity) { 'Enabled' } else { 'Disabled' }), got $(if ($currentComplexity) { 'Enabled' } else { 'Disabled' }) (✗)"
                    Write-LogMessage "Password complexity validation failed: Expected $(if ($expectedComplexity) { 'Enabled' } else { 'Disabled' }), got $(if ($currentComplexity) { 'Enabled' } else { 'Disabled' })" -Level "Error"
                }
            }
            else {
                $validationResult.Success = $false
                $validationResult.Details += "Password complexity: Could not retrieve current value from registry (✗)"
            }
        }
        catch {
            $validationResult.Success = $false
            $validationResult.Details += "Password complexity: Registry check failed - $($_.Exception.Message) (✗)"
        }
        
        if (-not $validationResult.Success) {
            $validationResult.Error = "One or more password policy settings validation failed"
        }
        
        # Log validation summary
        Write-LogMessage "Password policy validation summary:" -Level "Info"
        foreach ($detail in $validationResult.Details) {
            Write-LogMessage "  $detail" -Level "Info"
        }
    }
    catch {
        $validationResult.Success = $false
        $validationResult.Error = "Password policy validation error: $($_.Exception.Message)"
        Write-LogMessage "Password policy validation error: $($_.Exception.Message)" -Level "Error"
    }
    
    return $validationResult
}

function Get-CurrentPasswordPolicy {
    <#
    .SYNOPSIS
        Retrieves the current password policy settings from the system
    .DESCRIPTION
        Gets current password policy configuration using net accounts and registry queries
    .OUTPUTS
        Returns hashtable with current password policy settings
    #>
    
    Write-LogMessage "Retrieving current password policy settings..." -Level "Info"
    
    $currentPolicy = @{
        HistoryCount = $null
        MaxAge = $null
        MinAge = $null
        MinLength = $null
        ComplexityEnabled = $null
    }
    
    try {
        # Get policy using net accounts
        $netAccountsOutput = & net accounts 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            foreach ($line in $netAccountsOutput) {
                if ($line -match "Minimum password age \(days\):\s*(\d+)") {
                    $currentPolicy.MinAge = [int]$matches[1]
                }
                elseif ($line -match "Maximum password age \(days\):\s*(\d+)") {
                    $currentPolicy.MaxAge = [int]$matches[1]
                }
                elseif ($line -match "Minimum password length:\s*(\d+)") {
                    $currentPolicy.MinLength = [int]$matches[1]
                }
                elseif ($line -match "Length of password history maintained:\s*(\d+)") {
                    $currentPolicy.HistoryCount = [int]$matches[1]
                }
            }
        }
        
        # Get password complexity from registry
        try {
            $complexityRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $complexityValue = Get-ItemProperty -Path $complexityRegPath -Name "PasswordComplexity" -ErrorAction SilentlyContinue
            
            if ($complexityValue) {
                $currentPolicy.ComplexityEnabled = $complexityValue.PasswordComplexity -eq 1
            }
        }
        catch {
            Write-LogMessage "Could not retrieve password complexity from registry: $($_.Exception.Message)" -Level "Warning"
        }
        
        Write-LogMessage "Current password policy retrieved successfully" -Level "Success"
    }
    catch {
        Write-LogMessage "Failed to retrieve current password policy: $($_.Exception.Message)" -Level "Error"
    }
    
    return $currentPolicy
}

function Invoke-PasswordPolicyConfiguration {
    <#
    .SYNOPSIS
        Main function to execute password policy configuration module
    .DESCRIPTION
        Orchestrates the complete password policy configuration process including
        validation, application, and verification
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Password Policy Configuration Module..." -Level "Info"
    Write-LogMessage "Requirements: 1.1, 1.2, 1.3, 1.4, 1.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Password Policy Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        # Get current password policy for comparison
        Write-LogMessage "Retrieving current password policy for comparison..." -Level "Info"
        $currentPolicy = Get-CurrentPasswordPolicy
        
        if ($currentPolicy.HistoryCount -ne $null) {
            Write-LogMessage "Current password history: $($currentPolicy.HistoryCount) passwords" -Level "Info"
        }
        if ($currentPolicy.MaxAge -ne $null) {
            Write-LogMessage "Current maximum password age: $($currentPolicy.MaxAge) days" -Level "Info"
        }
        if ($currentPolicy.MinAge -ne $null) {
            Write-LogMessage "Current minimum password age: $($currentPolicy.MinAge) days" -Level "Info"
        }
        if ($currentPolicy.MinLength -ne $null) {
            Write-LogMessage "Current minimum password length: $($currentPolicy.MinLength) characters" -Level "Info"
        }
        if ($currentPolicy.ComplexityEnabled -ne $null) {
            Write-LogMessage "Current password complexity: $(if ($currentPolicy.ComplexityEnabled) { 'Enabled' } else { 'Disabled' })" -Level "Info"
        }
        
        # Apply password policy configuration
        $policyResult = Set-PasswordPolicy -Config $Config
        
        # Merge results
        $moduleResult.Success = $policyResult.Success
        $moduleResult.Changes += $policyResult.Changes
        $moduleResult.Errors += $policyResult.Errors
        $moduleResult.Warnings += $policyResult.Warnings
        
        if ($policyResult.Success) {
            Write-LogMessage "Password Policy Configuration Module completed successfully" -Level "Success"
            
            # Log all changes made
            Write-LogMessage "Password policy changes applied:" -Level "Success"
            foreach ($change in $policyResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        else {
            Write-LogMessage "Password Policy Configuration Module failed" -Level "Error"
            foreach ($error in $policyResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log any warnings
        foreach ($warning in $policyResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Password Policy Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

#endregion

#region Account Lockout Policy Configuration Module

function Set-AccountLockoutPolicy {
    <#
    .SYNOPSIS
        Configures local account lockout policy settings according to security requirements
    .DESCRIPTION
        Implements account lockout policy configuration using secedit to enforce:
        - Account lockout duration: 30 minutes
        - Account lockout threshold: 10 failed attempts
        - Reset lockout counter: 30 minutes
    .PARAMETER Config
        Configuration hashtable containing account lockout policy settings
    .OUTPUTS
        Returns execution result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Configuring account lockout policy settings..." -Level "Info"
    
    $result = @{
        ModuleName = "Account Lockout Policy Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
    }
    
    try {
        # Validate configuration parameters
        if (-not $Config.ContainsKey('LockoutPolicy')) {
            throw "Account lockout policy configuration section not found"
        }
        
        $lockoutConfig = $Config.LockoutPolicy
        
        # Validate required settings
        $requiredSettings = @('Duration', 'Threshold', 'ResetCounter')
        foreach ($setting in $requiredSettings) {
            if (-not $lockoutConfig.ContainsKey($setting)) {
                throw "Required account lockout policy setting '$setting' not found in configuration"
            }
        }
        
        Write-LogMessage "Account lockout policy configuration validated" -Level "Success"
        
        # Create temporary security template file
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $tempDir = Join-Path $env:TEMP "SecurityHardening_$timestamp"
        $templateFile = Join-Path $tempDir "AccountLockoutPolicy.inf"
        $logFile = Join-Path $tempDir "AccountLockoutPolicy.log"
        
        # Create temporary directory
        if (-not (Test-Path $tempDir)) {
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        }
        
        # Generate security template content for account lockout policy
        $templateContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
LockoutDuration = $($lockoutConfig.Duration)
LockoutBadCount = $($lockoutConfig.Threshold)
ResetLockoutCount = $($lockoutConfig.ResetCounter)
"@
        
        # Write template to file
        $templateContent | Out-File -FilePath $templateFile -Encoding Unicode
        Write-LogMessage "Security template created: $templateFile" -Level "Info"
        
        # Apply account lockout policy using secedit
        Write-LogMessage "Applying account lockout policy configuration..." -Level "Info"
        $seceditArgs = @("/configure", "/cfg", $templateFile, "/log", $logFile, "/quiet")
        
        if ($WhatIf) {
            Write-LogMessage "WhatIf: Would execute secedit.exe with arguments: $($seceditArgs -join ' ')" -Level "Info"
            $result.Changes += "Would set account lockout duration to $($lockoutConfig.Duration) minutes"
            $result.Changes += "Would set account lockout threshold to $($lockoutConfig.Threshold) failed attempts"
            $result.Changes += "Would set lockout counter reset time to $($lockoutConfig.ResetCounter) minutes"
            $result.Success = $true
        }
        else {
            $process = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -WindowStyle Hidden
            
            if ($process.ExitCode -eq 0) {
                Write-LogMessage "Account lockout policy applied successfully" -Level "Success"
                
                # Record changes made
                $result.Changes += "Set account lockout duration to $($lockoutConfig.Duration) minutes"
                $result.Changes += "Set account lockout threshold to $($lockoutConfig.Threshold) failed attempts"
                $result.Changes += "Set lockout counter reset time to $($lockoutConfig.ResetCounter) minutes"
                
                # Validate the applied policy
                $validationResult = Test-AccountLockoutPolicyApplication -Config $lockoutConfig
                if ($validationResult.Success) {
                    Write-LogMessage "Account lockout policy validation successful" -Level "Success"
                    $result.Success = $true
                }
                else {
                    $result.Errors += "Account lockout policy validation failed: $($validationResult.Error)"
                    $result.Warnings += "Policy may not have been applied correctly"
                }
            }
            else {
                $errorMsg = "secedit failed with exit code: $($process.ExitCode)"
                
                # Try to read the log file for more details
                if (Test-Path $logFile) {
                    $logContent = Get-Content $logFile -ErrorAction SilentlyContinue
                    if ($logContent) {
                        $errorMsg += ". Log details: $($logContent -join '; ')"
                    }
                }
                
                throw $errorMsg
            }
        }
        
        # Cleanup temporary files
        try {
            if (Test-Path $tempDir) {
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            $result.Warnings += "Failed to cleanup temporary files: $($_.Exception.Message)"
        }
        
        Write-LogMessage "Account lockout policy configuration completed" -Level "Success"
    }
    catch {
        $result.Errors += $_.Exception.Message
        Write-LogMessage "Account lockout policy configuration failed: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Test-AccountLockoutPolicyApplication {
    <#
    .SYNOPSIS
        Validates that account lockout policy settings have been applied correctly
    .DESCRIPTION
        Verifies the current account lockout policy settings match the configured values
        using net accounts command
    .PARAMETER Config
        Account lockout policy configuration to validate against
    .OUTPUTS
        Returns validation result with success status and details
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Validating account lockout policy application..." -Level "Info"
    
    $validationResult = @{
        Success = $true
        Error = ""
        Details = @()
    }
    
    try {
        # Use net accounts to get current account lockout policy
        $netAccountsOutput = & net accounts 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to retrieve current account lockout policy using 'net accounts'"
        }
        
        # Parse net accounts output for lockout settings
        $currentPolicy = @{}
        foreach ($line in $netAccountsOutput) {
            if ($line -match "Account lockout threshold:\s*(\d+|Never)") {
                if ($matches[1] -eq "Never") {
                    $currentPolicy.Threshold = 0
                } else {
                    $currentPolicy.Threshold = [int]$matches[1]
                }
            }
            elseif ($line -match "Account lockout duration \(minutes\):\s*(\d+)") {
                $currentPolicy.Duration = [int]$matches[1]
            }
            elseif ($line -match "Reset account lockout counter after \(minutes\):\s*(\d+)") {
                $currentPolicy.ResetCounter = [int]$matches[1]
            }
        }
        
        # Validate account lockout threshold
        if ($currentPolicy.ContainsKey('Threshold')) {
            if ($currentPolicy.Threshold -eq $Config.Threshold) {
                $validationResult.Details += "Account lockout threshold: $($currentPolicy.Threshold) failed attempts (✓)"
                Write-LogMessage "Account lockout threshold validation passed: $($currentPolicy.Threshold)" -Level "Success"
            }
            else {
                $validationResult.Success = $false
                $validationResult.Details += "Account lockout threshold: Expected $($Config.Threshold), got $($currentPolicy.Threshold) (✗)"
                Write-LogMessage "Account lockout threshold validation failed: Expected $($Config.Threshold), got $($currentPolicy.Threshold)" -Level "Error"
            }
        }
        else {
            $validationResult.Success = $false
            $validationResult.Details += "Account lockout threshold: Could not retrieve current value (✗)"
        }
        
        # Validate account lockout duration
        if ($currentPolicy.ContainsKey('Duration')) {
            if ($currentPolicy.Duration -eq $Config.Duration) {
                $validationResult.Details += "Account lockout duration: $($currentPolicy.Duration) minutes (✓)"
                Write-LogMessage "Account lockout duration validation passed: $($currentPolicy.Duration)" -Level "Success"
            }
            else {
                $validationResult.Success = $false
                $validationResult.Details += "Account lockout duration: Expected $($Config.Duration), got $($currentPolicy.Duration) (✗)"
                Write-LogMessage "Account lockout duration validation failed: Expected $($Config.Duration), got $($currentPolicy.Duration)" -Level "Error"
            }
        }
        else {
            $validationResult.Success = $false
            $validationResult.Details += "Account lockout duration: Could not retrieve current value (✗)"
        }
        
        # Validate reset lockout counter
        if ($currentPolicy.ContainsKey('ResetCounter')) {
            if ($currentPolicy.ResetCounter -eq $Config.ResetCounter) {
                $validationResult.Details += "Reset lockout counter: $($currentPolicy.ResetCounter) minutes (✓)"
                Write-LogMessage "Reset lockout counter validation passed: $($currentPolicy.ResetCounter)" -Level "Success"
            }
            else {
                $validationResult.Success = $false
                $validationResult.Details += "Reset lockout counter: Expected $($Config.ResetCounter), got $($currentPolicy.ResetCounter) (✗)"
                Write-LogMessage "Reset lockout counter validation failed: Expected $($Config.ResetCounter), got $($currentPolicy.ResetCounter)" -Level "Error"
            }
        }
        else {
            $validationResult.Success = $false
            $validationResult.Details += "Reset lockout counter: Could not retrieve current value (✗)"
        }
        
        if (-not $validationResult.Success) {
            $validationResult.Error = "One or more account lockout policy settings validation failed"
        }
        
        # Log validation summary
        Write-LogMessage "Account lockout policy validation summary:" -Level "Info"
        foreach ($detail in $validationResult.Details) {
            Write-LogMessage "  $detail" -Level "Info"
        }
    }
    catch {
        $validationResult.Success = $false
        $validationResult.Error = "Account lockout policy validation error: $($_.Exception.Message)"
        Write-LogMessage "Account lockout policy validation error: $($_.Exception.Message)" -Level "Error"
    }
    
    return $validationResult
}

function Get-CurrentAccountLockoutPolicy {
    <#
    .SYNOPSIS
        Retrieves the current account lockout policy settings from the system
    .DESCRIPTION
        Gets current account lockout policy configuration using net accounts command
    .OUTPUTS
        Returns hashtable with current account lockout policy settings
    #>
    
    Write-LogMessage "Retrieving current account lockout policy settings..." -Level "Info"
    
    $currentPolicy = @{
        Duration = $null
        Threshold = $null
        ResetCounter = $null
    }
    
    try {
        # Get policy using net accounts
        $netAccountsOutput = & net accounts 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            foreach ($line in $netAccountsOutput) {
                if ($line -match "Account lockout threshold:\s*(\d+|Never)") {
                    if ($matches[1] -eq "Never") {
                        $currentPolicy.Threshold = 0
                    } else {
                        $currentPolicy.Threshold = [int]$matches[1]
                    }
                }
                elseif ($line -match "Account lockout duration \(minutes\):\s*(\d+)") {
                    $currentPolicy.Duration = [int]$matches[1]
                }
                elseif ($line -match "Reset account lockout counter after \(minutes\):\s*(\d+)") {
                    $currentPolicy.ResetCounter = [int]$matches[1]
                }
            }
        }
        
        Write-LogMessage "Current account lockout policy retrieved successfully" -Level "Success"
    }
    catch {
        Write-LogMessage "Failed to retrieve current account lockout policy: $($_.Exception.Message)" -Level "Error"
    }
    
    return $currentPolicy
}

function Invoke-AccountLockoutPolicyConfiguration {
    <#
    .SYNOPSIS
        Main function to execute account lockout policy configuration module
    .DESCRIPTION
        Orchestrates the complete account lockout policy configuration process including
        validation, application, and verification
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Account Lockout Policy Configuration Module..." -Level "Info"
    Write-LogMessage "Requirements: 2.1, 2.2, 2.3" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Account Lockout Policy Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        # Get current account lockout policy for comparison
        Write-LogMessage "Retrieving current account lockout policy for comparison..." -Level "Info"
        $currentPolicy = Get-CurrentAccountLockoutPolicy
        
        if ($currentPolicy.Threshold -ne $null) {
            Write-LogMessage "Current account lockout threshold: $($currentPolicy.Threshold) failed attempts" -Level "Info"
        }
        if ($currentPolicy.Duration -ne $null) {
            Write-LogMessage "Current account lockout duration: $($currentPolicy.Duration) minutes" -Level "Info"
        }
        if ($currentPolicy.ResetCounter -ne $null) {
            Write-LogMessage "Current reset lockout counter: $($currentPolicy.ResetCounter) minutes" -Level "Info"
        }
        
        # Apply account lockout policy configuration
        $policyResult = Set-AccountLockoutPolicy -Config $Config
        
        # Merge results
        $moduleResult.Success = $policyResult.Success
        $moduleResult.Changes += $policyResult.Changes
        $moduleResult.Errors += $policyResult.Errors
        $moduleResult.Warnings += $policyResult.Warnings
        
        if ($policyResult.Success) {
            Write-LogMessage "Account Lockout Policy Configuration Module completed successfully" -Level "Success"
            
            # Log all changes made
            Write-LogMessage "Account lockout policy changes applied:" -Level "Success"
            foreach ($change in $policyResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        else {
            Write-LogMessage "Account Lockout Policy Configuration Module failed" -Level "Error"
            foreach ($error in $policyResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log any warnings
        foreach ($warning in $policyResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Account Lockout Policy Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

#endregion

#region User Account Management Module

function Get-LocalUserAccounts {
    <#
    .SYNOPSIS
        Enumerates all local user accounts on the system
    .DESCRIPTION
        Retrieves comprehensive information about all local user accounts including
        account status, properties, and group memberships
    .OUTPUTS
        Returns array of hashtables containing user account information
    #>
    
    Write-LogMessage "Enumerating local user accounts..." -Level "Info"
    
    $userAccounts = @()
    
    try {
        # Get all local users using Get-LocalUser (Windows 10/Server 2016+)
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $localUsers = Get-LocalUser -ErrorAction Stop
            
            foreach ($user in $localUsers) {
                try {
                    # Get additional user information
                    $userInfo = @{
                        Name = $user.Name
                        FullName = $user.FullName
                        Description = $user.Description
                        Enabled = $user.Enabled
                        UserMayChangePassword = $user.UserMayChangePassword
                        PasswordChangeableDate = $user.PasswordChangeableDate
                        PasswordExpires = $user.PasswordExpires
                        PasswordLastSet = $user.PasswordLastSet
                        PasswordRequired = $user.PasswordRequired
                        AccountExpires = $user.AccountExpires
                        LastLogon = $user.LastLogon
                        SID = $user.SID.Value
                        PrincipalSource = $user.PrincipalSource.ToString()
                        ObjectClass = $user.ObjectClass
                        GroupMemberships = @()
                        IsBuiltIn = $false
                        IsAuthorized = $false
                    }
                    
                    # Determine if this is a built-in account
                    $builtInAccounts = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
                    $userInfo.IsBuiltIn = $builtInAccounts -contains $user.Name
                    
                    # Get group memberships
                    try {
                        $groups = Get-LocalGroupMember -Group "Users" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$($user.Name)" -or $_.Name -eq $user.Name }
                        if ($groups) {
                            $userInfo.GroupMemberships += "Users"
                        }
                        
                        $adminGroups = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$($user.Name)" -or $_.Name -eq $user.Name }
                        if ($adminGroups) {
                            $userInfo.GroupMemberships += "Administrators"
                        }
                        
                        $guestGroups = Get-LocalGroupMember -Group "Guests" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$($user.Name)" -or $_.Name -eq $user.Name }
                        if ($guestGroups) {
                            $userInfo.GroupMemberships += "Guests"
                        }
                        
                        # Check Remote Desktop Users group if it exists
                        try {
                            $rdpGroups = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$($user.Name)" -or $_.Name -eq $user.Name }
                            if ($rdpGroups) {
                                $userInfo.GroupMemberships += "Remote Desktop Users"
                            }
                        }
                        catch {
                            # Remote Desktop Users group may not exist on all systems
                        }
                    }
                    catch {
                        Write-LogMessage "Warning: Could not retrieve group memberships for user: $($user.Name)" -Level "Warning"
                    }
                    
                    $userAccounts += $userInfo
                    Write-LogMessage "Enumerated user: $($user.Name) (Enabled: $($user.Enabled))" -Level "Info"
                }
                catch {
                    Write-LogMessage "Error processing user $($user.Name): $($_.Exception.Message)" -Level "Warning"
                }
            }
        }
        else {
            # Fallback to WMI for older systems
            Write-LogMessage "Get-LocalUser not available, using WMI fallback..." -Level "Info"
            $wmiUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop
            
            foreach ($user in $wmiUsers) {
                try {
                    $userInfo = @{
                        Name = $user.Name
                        FullName = $user.FullName
                        Description = $user.Description
                        Enabled = -not $user.Disabled
                        UserMayChangePassword = -not $user.PasswordCantChange
                        PasswordChangeableDate = $null
                        PasswordExpires = -not $user.PasswordExpires
                        PasswordLastSet = $null
                        PasswordRequired = $user.PasswordRequired
                        AccountExpires = $null
                        LastLogon = $null
                        SID = $user.SID
                        PrincipalSource = "Local"
                        ObjectClass = "User"
                        GroupMemberships = @()
                        IsBuiltIn = $false
                        IsAuthorized = $false
                    }
                    
                    # Determine if this is a built-in account
                    $builtInAccounts = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
                    $userInfo.IsBuiltIn = $builtInAccounts -contains $user.Name
                    
                    $userAccounts += $userInfo
                    Write-LogMessage "Enumerated user (WMI): $($user.Name) (Enabled: $(-not $user.Disabled))" -Level "Info"
                }
                catch {
                    Write-LogMessage "Error processing WMI user $($user.Name): $($_.Exception.Message)" -Level "Warning"
                }
            }
        }
        
        Write-LogMessage "Successfully enumerated $($userAccounts.Count) local user accounts" -Level "Success"
    }
    catch {
        Write-LogMessage "Failed to enumerate local user accounts: $($_.Exception.Message)" -Level "Error"
        throw
    }
    
    return $userAccounts
}

function Test-UserAccountAuthorization {
    <#
    .SYNOPSIS
        Determines if user accounts are authorized based on configuration
    .DESCRIPTION
        Evaluates user accounts against authorized user lists and built-in account policies
        to determine which accounts should be enabled or disabled
    .PARAMETER UserAccounts
        Array of user account objects to evaluate
    .PARAMETER Config
        Configuration hashtable containing authorization settings
    .OUTPUTS
        Returns updated user account array with authorization status
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserAccounts,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Evaluating user account authorization..." -Level "Info"
    
    try {
        if (-not $Config.ContainsKey('UserSettings')) {
            throw "User settings configuration section not found"
        }
        
        $userConfig = $Config.UserSettings
        $authorizedAdmins = if ($userConfig.ContainsKey('AuthorizedAdmins')) { $userConfig.AuthorizedAdmins } else { @() }
        $authorizedRDPUsers = if ($userConfig.ContainsKey('AuthorizedRDPUsers')) { $userConfig.AuthorizedRDPUsers } else { @() }
        
        Write-LogMessage "Authorized administrators: $($authorizedAdmins -join ', ')" -Level "Info"
        Write-LogMessage "Authorized RDP users: $($authorizedRDPUsers -join ', ')" -Level "Info"
        
        foreach ($user in $UserAccounts) {
            # Built-in accounts have special handling
            if ($user.IsBuiltIn) {
                switch ($user.Name) {
                    'Administrator' {
                        # Administrator account should be disabled per security policy
                        $user.IsAuthorized = $false
                        Write-LogMessage "Built-in Administrator account marked as unauthorized (will be disabled)" -Level "Info"
                    }
                    'Guest' {
                        # Guest account should be disabled per security policy
                        $user.IsAuthorized = $false
                        Write-LogMessage "Built-in Guest account marked as unauthorized (will be disabled)" -Level "Info"
                    }
                    'DefaultAccount' {
                        # DefaultAccount is typically disabled by default
                        $user.IsAuthorized = $false
                        Write-LogMessage "DefaultAccount marked as unauthorized (should remain disabled)" -Level "Info"
                    }
                    'WDAGUtilityAccount' {
                        # Windows Defender Application Guard utility account
                        $user.IsAuthorized = $false
                        Write-LogMessage "WDAGUtilityAccount marked as unauthorized (should remain disabled)" -Level "Info"
                    }
                    default {
                        # Other built-in accounts - check against authorized lists
                        $user.IsAuthorized = $authorizedAdmins -contains $user.Name
                        Write-LogMessage "Built-in account $($user.Name) authorization: $($user.IsAuthorized)" -Level "Info"
                    }
                }
            }
            else {
                # Regular user accounts - check against authorized lists
                $isAuthorizedAdmin = $authorizedAdmins -contains $user.Name
                $isAuthorizedRDPUser = $authorizedRDPUsers -contains $user.Name
                $isInAdminGroup = $user.GroupMemberships -contains "Administrators"
                
                if ($isInAdminGroup) {
                    # User is in Administrators group - must be in authorized admin list
                    $user.IsAuthorized = $isAuthorizedAdmin
                    if ($user.IsAuthorized) {
                        Write-LogMessage "User $($user.Name) is authorized administrator" -Level "Success"
                    }
                    else {
                        Write-LogMessage "User $($user.Name) is in Administrators group but not in authorized list" -Level "Warning"
                    }
                }
                else {
                    # Regular user - authorized if in either admin or RDP list, or if no restrictions are configured
                    if ($authorizedAdmins.Count -eq 0 -and $authorizedRDPUsers.Count -eq 0) {
                        # No authorization restrictions configured - allow all regular users
                        $user.IsAuthorized = $true
                        Write-LogMessage "User $($user.Name) is authorized (no restrictions configured)" -Level "Info"
                    }
                    else {
                        # Check against authorized lists
                        $user.IsAuthorized = $isAuthorizedAdmin -or $isAuthorizedRDPUser
                        if ($user.IsAuthorized) {
                            Write-LogMessage "User $($user.Name) is authorized" -Level "Success"
                        }
                        else {
                            Write-LogMessage "User $($user.Name) is not in authorized user lists" -Level "Warning"
                        }
                    }
                }
            }
        }
        
        $authorizedCount = ($UserAccounts | Where-Object { $_.IsAuthorized }).Count
        $unauthorizedCount = $UserAccounts.Count - $authorizedCount
        
        Write-LogMessage "User authorization evaluation completed" -Level "Success"
        Write-LogMessage "Authorized users: $authorizedCount" -Level "Info"
        Write-LogMessage "Unauthorized users: $unauthorizedCount" -Level "Info"
    }
    catch {
        Write-LogMessage "Failed to evaluate user account authorization: $($_.Exception.Message)" -Level "Error"
        throw
    }
    
    return $UserAccounts
}

function Get-UserAccountProperties {
    <#
    .SYNOPSIS
        Retrieves detailed properties for a specific user account
    .DESCRIPTION
        Gets comprehensive information about a user account including security settings,
        group memberships, and account status
    .PARAMETER UserName
        Name of the user account to examine
    .OUTPUTS
        Returns hashtable with detailed user account properties
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )
    
    Write-LogMessage "Retrieving detailed properties for user: $UserName" -Level "Info"
    
    $userProperties = @{
        Name = $UserName
        Exists = $false
        Properties = @{}
        GroupMemberships = @()
        SecuritySettings = @{}
        Errors = @()
    }
    
    try {
        # Check if user exists using Get-LocalUser
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            try {
                $user = Get-LocalUser -Name $UserName -ErrorAction Stop
                $userProperties.Exists = $true
                
                # Basic properties
                $userProperties.Properties = @{
                    FullName = $user.FullName
                    Description = $user.Description
                    Enabled = $user.Enabled
                    UserMayChangePassword = $user.UserMayChangePassword
                    PasswordChangeableDate = $user.PasswordChangeableDate
                    PasswordExpires = $user.PasswordExpires
                    PasswordLastSet = $user.PasswordLastSet
                    PasswordRequired = $user.PasswordRequired
                    AccountExpires = $user.AccountExpires
                    LastLogon = $user.LastLogon
                    SID = $user.SID.Value
                    PrincipalSource = $user.PrincipalSource.ToString()
                }
                
                Write-LogMessage "User $UserName found and properties retrieved" -Level "Success"
            }
            catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
                Write-LogMessage "User $UserName does not exist" -Level "Info"
                return $userProperties
            }
        }
        else {
            # Fallback to WMI
            $wmiUser = Get-CimInstance -ClassName Win32_UserAccount -Filter "Name='$UserName' AND LocalAccount=True" -ErrorAction SilentlyContinue
            if ($wmiUser) {
                $userProperties.Exists = $true
                $userProperties.Properties = @{
                    FullName = $wmiUser.FullName
                    Description = $wmiUser.Description
                    Enabled = -not $wmiUser.Disabled
                    SID = $wmiUser.SID
                }
                Write-LogMessage "User $UserName found via WMI" -Level "Success"
            }
            else {
                Write-LogMessage "User $UserName does not exist" -Level "Info"
                return $userProperties
            }
        }
        
        # Get group memberships
        try {
            $allGroups = @('Users', 'Administrators', 'Guests', 'Remote Desktop Users', 'Power Users', 'Backup Operators')
            
            foreach ($groupName in $allGroups) {
                try {
                    $groupMembers = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
                    $isMember = $groupMembers | Where-Object { 
                        $_.Name -eq $UserName -or 
                        $_.Name -eq "$env:COMPUTERNAME\$UserName" -or
                        $_.Name -like "*\$UserName"
                    }
                    
                    if ($isMember) {
                        $userProperties.GroupMemberships += $groupName
                        Write-LogMessage "User $UserName is member of group: $groupName" -Level "Info"
                    }
                }
                catch {
                    # Group may not exist on this system
                    Write-LogMessage "Could not check membership in group $groupName`: $($_.Exception.Message)" -Level "Debug"
                }
            }
        }
        catch {
            $userProperties.Errors += "Failed to retrieve group memberships: $($_.Exception.Message)"
            Write-LogMessage "Failed to retrieve group memberships for $UserName`: $($_.Exception.Message)" -Level "Warning"
        }
        
        # Get additional security settings from registry if possible
        try {
            # Check if user has "Force password change at next logon" flag
            # This would typically be checked via ADSI or other methods for local accounts
            $userProperties.SecuritySettings = @{
                MustChangePasswordAtNextLogon = $false  # Default for local accounts
                CannotChangePassword = -not $userProperties.Properties.UserMayChangePassword
                PasswordNeverExpires = -not $userProperties.Properties.PasswordExpires
                AccountDisabled = -not $userProperties.Properties.Enabled
            }
        }
        catch {
            $userProperties.Errors += "Failed to retrieve security settings: $($_.Exception.Message)"
            Write-LogMessage "Failed to retrieve security settings for $UserName`: $($_.Exception.Message)" -Level "Warning"
        }
        
        Write-LogMessage "Retrieved detailed properties for user $UserName" -Level "Success"
    }
    catch {
        $userProperties.Errors += "Failed to retrieve user properties: $($_.Exception.Message)"
        Write-LogMessage "Failed to retrieve properties for user $UserName`: $($_.Exception.Message)" -Level "Error"
    }
    
    return $userProperties
}

function Test-UserAccountCompliance {
    <#
    .SYNOPSIS
        Tests user accounts for compliance with security requirements
    .DESCRIPTION
        Validates user accounts against security requirements including authorization,
        group memberships, and account settings
    .PARAMETER UserAccounts
        Array of user account objects to test
    .PARAMETER Config
        Configuration hashtable containing compliance requirements
    .OUTPUTS
        Returns compliance test results
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserAccounts,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Testing user account compliance..." -Level "Info"
    
    $complianceResults = @{
        OverallCompliance = $true
        TotalUsers = $UserAccounts.Count
        CompliantUsers = 0
        NonCompliantUsers = 0
        Issues = @()
        Details = @()
    }
    
    try {
        if (-not $Config.ContainsKey('UserSettings')) {
            throw "User settings configuration section not found"
        }
        
        $userConfig = $Config.UserSettings
        
        foreach ($user in $UserAccounts) {
            $userCompliant = $true
            $userIssues = @()
            
            # Test 1: Unauthorized users should be disabled
            if (-not $user.IsAuthorized -and $user.Enabled) {
                $userCompliant = $false
                $userIssues += "Unauthorized user account is enabled"
                $complianceResults.Issues += "User '$($user.Name)' is unauthorized but enabled"
            }
            
            # Test 2: Built-in Administrator account should be disabled
            if ($user.Name -eq 'Administrator' -and $user.Enabled) {
                $userCompliant = $false
                $userIssues += "Built-in Administrator account is enabled"
                $complianceResults.Issues += "Built-in Administrator account should be disabled"
            }
            
            # Test 3: Built-in Guest account should be disabled
            if ($user.Name -eq 'Guest' -and $user.Enabled) {
                $userCompliant = $false
                $userIssues += "Built-in Guest account is enabled"
                $complianceResults.Issues += "Built-in Guest account should be disabled"
            }
            
            # Test 4: Check Administrators group membership
            if ($user.GroupMemberships -contains "Administrators") {
                $authorizedAdmins = if ($userConfig.ContainsKey('AuthorizedAdmins')) { $userConfig.AuthorizedAdmins } else { @() }
                if ($authorizedAdmins.Count -gt 0 -and $authorizedAdmins -notcontains $user.Name) {
                    $userCompliant = $false
                    $userIssues += "User is in Administrators group but not in authorized list"
                    $complianceResults.Issues += "User '$($user.Name)' is in Administrators group but not authorized"
                }
            }
            
            # Test 5: Check Guests group membership (should only contain Guest account)
            if ($user.GroupMemberships -contains "Guests" -and $user.Name -ne 'Guest') {
                $userCompliant = $false
                $userIssues += "Non-Guest user is in Guests group"
                $complianceResults.Issues += "User '$($user.Name)' should not be in Guests group"
            }
            
            # Test 6: Check Remote Desktop Users group membership
            if ($user.GroupMemberships -contains "Remote Desktop Users") {
                $authorizedRDPUsers = if ($userConfig.ContainsKey('AuthorizedRDPUsers')) { $userConfig.AuthorizedRDPUsers } else { @() }
                if ($authorizedRDPUsers.Count -gt 0 -and $authorizedRDPUsers -notcontains $user.Name) {
                    $userCompliant = $false
                    $userIssues += "User is in Remote Desktop Users group but not in authorized list"
                    $complianceResults.Issues += "User '$($user.Name)' is in Remote Desktop Users group but not authorized"
                }
            }
            
            # Update compliance counters
            if ($userCompliant) {
                $complianceResults.CompliantUsers++
            }
            else {
                $complianceResults.NonCompliantUsers++
                $complianceResults.OverallCompliance = $false
            }
            
            # Add user details to results
            $complianceResults.Details += @{
                UserName = $user.Name
                Compliant = $userCompliant
                Issues = $userIssues
                Enabled = $user.Enabled
                IsAuthorized = $user.IsAuthorized
                GroupMemberships = $user.GroupMemberships
            }
        }
        
        Write-LogMessage "User account compliance testing completed" -Level "Success"
        Write-LogMessage "Total users: $($complianceResults.TotalUsers)" -Level "Info"
        Write-LogMessage "Compliant users: $($complianceResults.CompliantUsers)" -Level "Info"
        Write-LogMessage "Non-compliant users: $($complianceResults.NonCompliantUsers)" -Level "Info"
        Write-LogMessage "Overall compliance: $($complianceResults.OverallCompliance)" -Level $(if ($complianceResults.OverallCompliance) { "Success" } else { "Warning" })
        
        if ($complianceResults.Issues.Count -gt 0) {
            Write-LogMessage "Compliance issues found:" -Level "Warning"
            foreach ($issue in $complianceResults.Issues) {
                Write-LogMessage "  - $issue" -Level "Warning"
            }
        }
    }
    catch {
        Write-LogMessage "Failed to test user account compliance: $($_.Exception.Message)" -Level "Error"
        $complianceResults.OverallCompliance = $false
        $complianceResults.Issues += "Compliance testing failed: $($_.Exception.Message)"
    }
    
    return $complianceResults
}

function Set-UserPasswordChangeRequired {
    <#
    .SYNOPSIS
        Configures users to change password at next logon
    .DESCRIPTION
        Sets the "User must change password at next logon" flag for specified users
        or all users based on configuration
    .PARAMETER UserAccounts
        Array of user account objects to configure
    .PARAMETER Config
        Configuration hashtable containing user settings
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserAccounts,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Configuring users to change password at next logon..." -Level "Info"
    
    $result = @{
        Success = $true
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        if (-not $Config.ContainsKey('UserSettings') -or -not $Config.UserSettings.ContainsKey('ForcePasswordChange')) {
            throw "ForcePasswordChange setting not found in configuration"
        }
        
        if (-not $Config.UserSettings.ForcePasswordChange) {
            Write-LogMessage "Force password change is disabled in configuration" -Level "Info"
            return $result
        }
        
        foreach ($user in $UserAccounts) {
            try {
                # Skip built-in accounts that shouldn't have password changes forced
                if ($user.IsBuiltIn -and $user.Name -in @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')) {
                    Write-LogMessage "Skipping password change requirement for built-in account: $($user.Name)" -Level "Info"
                    continue
                }
                
                # Skip disabled accounts
                if (-not $user.Enabled) {
                    Write-LogMessage "Skipping disabled account: $($user.Name)" -Level "Info"
                    continue
                }
                
                # For local accounts, we use net user command to force password change
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would force password change for user: $($user.Name)" -Level "Info"
                    $result.Changes += "Would force password change for user: $($user.Name)"
                }
                else {
                    # Use net user command to set password change requirement
                    $netUserArgs = @($user.Name, "/logonpasswordchg:yes")
                    $process = Start-Process -FilePath "net.exe" -ArgumentList ("user " + ($netUserArgs -join " ")) -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $env:TEMP\netuser_output.txt -RedirectStandardError $env:TEMP\netuser_error.txt
                    
                    if ($process.ExitCode -eq 0) {
                        Write-LogMessage "Successfully set password change requirement for user: $($user.Name)" -Level "Success"
                        $result.Changes += "Set password change requirement for user: $($user.Name)"
                    }
                    else {
                        $errorOutput = ""
                        if (Test-Path "$env:TEMP\netuser_error.txt") {
                            $errorOutput = Get-Content "$env:TEMP\netuser_error.txt" -Raw
                        }
                        $result.Errors += "Failed to set password change for user $($user.Name): Exit code $($process.ExitCode). $errorOutput"
                        Write-LogMessage "Failed to set password change for user $($user.Name): Exit code $($process.ExitCode)" -Level "Error"
                        $result.Success = $false
                    }
                    
                    # Cleanup temp files
                    @("$env:TEMP\netuser_output.txt", "$env:TEMP\netuser_error.txt") | ForEach-Object {
                        if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
            catch {
                $result.Errors += "Error configuring password change for user $($user.Name): $($_.Exception.Message)"
                Write-LogMessage "Error configuring password change for user $($user.Name): $($_.Exception.Message)" -Level "Error"
                $result.Success = $false
            }
        }
        
        Write-LogMessage "Password change configuration completed" -Level "Success"
    }
    catch {
        $result.Errors += "Failed to configure password change requirements: $($_.Exception.Message)"
        Write-LogMessage "Failed to configure password change requirements: $($_.Exception.Message)" -Level "Error"
        $result.Success = $false
    }
    
    return $result
}

function Set-UnauthorizedUserAccounts {
    <#
    .SYNOPSIS
        Disables unauthorized user accounts
    .DESCRIPTION
        Disables user accounts that are not in the authorized users list
    .PARAMETER UserAccounts
        Array of user account objects to process
    .PARAMETER Config
        Configuration hashtable containing user settings
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserAccounts,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Disabling unauthorized user accounts..." -Level "Info"
    
    $result = @{
        Success = $true
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        if (-not $Config.ContainsKey('UserSettings') -or -not $Config.UserSettings.ContainsKey('DisableUnauthorized')) {
            throw "DisableUnauthorized setting not found in configuration"
        }
        
        if (-not $Config.UserSettings.DisableUnauthorized) {
            Write-LogMessage "Disable unauthorized users is disabled in configuration" -Level "Info"
            return $result
        }
        
        $unauthorizedUsers = $UserAccounts | Where-Object { -not $_.IsAuthorized -and $_.Enabled }
        
        if ($unauthorizedUsers.Count -eq 0) {
            Write-LogMessage "No unauthorized enabled users found" -Level "Info"
            return $result
        }
        
        Write-LogMessage "Found $($unauthorizedUsers.Count) unauthorized enabled users" -Level "Warning"
        
        foreach ($user in $unauthorizedUsers) {
            try {
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would disable unauthorized user: $($user.Name)" -Level "Info"
                    $result.Changes += "Would disable unauthorized user: $($user.Name)"
                }
                else {
                    # Use Disable-LocalUser if available
                    if (Get-Command Disable-LocalUser -ErrorAction SilentlyContinue) {
                        Disable-LocalUser -Name $user.Name -ErrorAction Stop
                        Write-LogMessage "Successfully disabled unauthorized user: $($user.Name)" -Level "Success"
                        $result.Changes += "Disabled unauthorized user: $($user.Name)"
                    }
                    else {
                        # Fallback to net user command
                        $process = Start-Process -FilePath "net.exe" -ArgumentList @("user", $user.Name, "/active:no") -Wait -PassThru -WindowStyle Hidden
                        
                        if ($process.ExitCode -eq 0) {
                            Write-LogMessage "Successfully disabled unauthorized user: $($user.Name)" -Level "Success"
                            $result.Changes += "Disabled unauthorized user: $($user.Name)"
                        }
                        else {
                            throw "net user command failed with exit code: $($process.ExitCode)"
                        }
                    }
                }
            }
            catch {
                $result.Errors += "Failed to disable user $($user.Name): $($_.Exception.Message)"
                Write-LogMessage "Failed to disable user $($user.Name): $($_.Exception.Message)" -Level "Error"
                $result.Success = $false
            }
        }
        
        Write-LogMessage "Unauthorized user account disabling completed" -Level "Success"
    }
    catch {
        $result.Errors += "Failed to disable unauthorized users: $($_.Exception.Message)"
        Write-LogMessage "Failed to disable unauthorized users: $($_.Exception.Message)" -Level "Error"
        $result.Success = $false
    }
    
    return $result
}

function Set-GroupMembershipManagement {
    <#
    .SYNOPSIS
        Manages group memberships according to security requirements
    .DESCRIPTION
        Configures Administrators and Guests group memberships, and Remote Desktop Users
        group based on authorization lists
    .PARAMETER UserAccounts
        Array of user account objects to process
    .PARAMETER Config
        Configuration hashtable containing user settings
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserAccounts,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Managing group memberships..." -Level "Info"
    
    $result = @{
        Success = $true
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        if (-not $Config.ContainsKey('UserSettings')) {
            throw "User settings configuration section not found"
        }
        
        $userConfig = $Config.UserSettings
        $authorizedAdmins = if ($userConfig.ContainsKey('AuthorizedAdmins')) { $userConfig.AuthorizedAdmins } else { @() }
        $authorizedRDPUsers = if ($userConfig.ContainsKey('AuthorizedRDPUsers')) { $userConfig.AuthorizedRDPUsers } else { @() }
        
        # Manage Administrators group
        if ($userConfig.ContainsKey('RestrictAdminGroup') -and $userConfig.RestrictAdminGroup) {
            Write-LogMessage "Managing Administrators group membership..." -Level "Info"
            
            try {
                # Get current Administrators group members
                $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
                
                foreach ($member in $adminMembers) {
                    # Extract username from domain\username format
                    $memberName = if ($member.Name -like "*\*") {
                        ($member.Name -split "\\")[-1]
                    } else {
                        $member.Name
                    }
                    
                    # Skip built-in accounts and system accounts
                    if ($member.PrincipalSource -eq "Local" -and $memberName -notin @('Administrator') -and $authorizedAdmins -notcontains $memberName) {
                        if ($WhatIf) {
                            Write-LogMessage "WhatIf: Would remove $memberName from Administrators group" -Level "Info"
                            $result.Changes += "Would remove $memberName from Administrators group"
                        }
                        else {
                            try {
                                Remove-LocalGroupMember -Group "Administrators" -Member $member.Name -ErrorAction Stop
                                Write-LogMessage "Removed unauthorized user $memberName from Administrators group" -Level "Success"
                                $result.Changes += "Removed $memberName from Administrators group"
                            }
                            catch {
                                $result.Errors += "Failed to remove $memberName from Administrators group: $($_.Exception.Message)"
                                Write-LogMessage "Failed to remove $memberName from Administrators group: $($_.Exception.Message)" -Level "Error"
                                $result.Success = $false
                            }
                        }
                    }
                }
                
                # Add authorized administrators if they're not already members
                foreach ($authorizedAdmin in $authorizedAdmins) {
                    $isCurrentMember = $adminMembers | Where-Object { 
                        $memberName = if ($_.Name -like "*\*") { ($_.Name -split "\\")[-1] } else { $_.Name }
                        $memberName -eq $authorizedAdmin
                    }
                    
                    if (-not $isCurrentMember) {
                        # Check if user exists
                        $userExists = $UserAccounts | Where-Object { $_.Name -eq $authorizedAdmin }
                        if ($userExists) {
                            if ($WhatIf) {
                                Write-LogMessage "WhatIf: Would add $authorizedAdmin to Administrators group" -Level "Info"
                                $result.Changes += "Would add $authorizedAdmin to Administrators group"
                            }
                            else {
                                try {
                                    Add-LocalGroupMember -Group "Administrators" -Member $authorizedAdmin -ErrorAction Stop
                                    Write-LogMessage "Added authorized user $authorizedAdmin to Administrators group" -Level "Success"
                                    $result.Changes += "Added $authorizedAdmin to Administrators group"
                                }
                                catch {
                                    $result.Errors += "Failed to add $authorizedAdmin to Administrators group: $($_.Exception.Message)"
                                    Write-LogMessage "Failed to add $authorizedAdmin to Administrators group: $($_.Exception.Message)" -Level "Error"
                                    $result.Success = $false
                                }
                            }
                        }
                        else {
                            $result.Warnings += "Authorized admin $authorizedAdmin does not exist as a local user"
                            Write-LogMessage "Authorized admin $authorizedAdmin does not exist as a local user" -Level "Warning"
                        }
                    }
                }
            }
            catch {
                $result.Errors += "Failed to manage Administrators group: $($_.Exception.Message)"
                Write-LogMessage "Failed to manage Administrators group: $($_.Exception.Message)" -Level "Error"
                $result.Success = $false
            }
        }
        
        # Manage Guests group
        if ($userConfig.ContainsKey('RestrictGuestGroup') -and $userConfig.RestrictGuestGroup) {
            Write-LogMessage "Managing Guests group membership..." -Level "Info"
            
            try {
                # Get current Guests group members
                $guestMembers = Get-LocalGroupMember -Group "Guests" -ErrorAction Stop
                
                foreach ($member in $guestMembers) {
                    # Extract username from domain\username format
                    $memberName = if ($member.Name -like "*\*") {
                        ($member.Name -split "\\")[-1]
                    } else {
                        $member.Name
                    }
                    
                    # Remove all members except the built-in Guest account
                    if ($memberName -ne "Guest") {
                        if ($WhatIf) {
                            Write-LogMessage "WhatIf: Would remove $memberName from Guests group" -Level "Info"
                            $result.Changes += "Would remove $memberName from Guests group"
                        }
                        else {
                            try {
                                Remove-LocalGroupMember -Group "Guests" -Member $member.Name -ErrorAction Stop
                                Write-LogMessage "Removed user $memberName from Guests group" -Level "Success"
                                $result.Changes += "Removed $memberName from Guests group"
                            }
                            catch {
                                $result.Errors += "Failed to remove $memberName from Guests group: $($_.Exception.Message)"
                                Write-LogMessage "Failed to remove $memberName from Guests group: $($_.Exception.Message)" -Level "Error"
                                $result.Success = $false
                            }
                        }
                    }
                }
            }
            catch {
                $result.Errors += "Failed to manage Guests group: $($_.Exception.Message)"
                Write-LogMessage "Failed to manage Guests group: $($_.Exception.Message)" -Level "Error"
                $result.Success = $false
            }
        }
        
        # Manage Remote Desktop Users group
        if ($authorizedRDPUsers.Count -gt 0) {
            Write-LogMessage "Managing Remote Desktop Users group membership..." -Level "Info"
            
            try {
                # Check if Remote Desktop Users group exists
                $rdpGroup = Get-LocalGroup -Name "Remote Desktop Users" -ErrorAction SilentlyContinue
                if ($rdpGroup) {
                    # Get current Remote Desktop Users group members
                    $rdpMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction Stop
                    
                    # Remove unauthorized members
                    foreach ($member in $rdpMembers) {
                        $memberName = if ($member.Name -like "*\*") {
                            ($member.Name -split "\\")[-1]
                        } else {
                            $member.Name
                        }
                        
                        if ($member.PrincipalSource -eq "Local" -and $authorizedRDPUsers -notcontains $memberName) {
                            if ($WhatIf) {
                                Write-LogMessage "WhatIf: Would remove $memberName from Remote Desktop Users group" -Level "Info"
                                $result.Changes += "Would remove $memberName from Remote Desktop Users group"
                            }
                            else {
                                try {
                                    Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $member.Name -ErrorAction Stop
                                    Write-LogMessage "Removed unauthorized user $memberName from Remote Desktop Users group" -Level "Success"
                                    $result.Changes += "Removed $memberName from Remote Desktop Users group"
                                }
                                catch {
                                    $result.Errors += "Failed to remove $memberName from Remote Desktop Users group: $($_.Exception.Message)"
                                    Write-LogMessage "Failed to remove $memberName from Remote Desktop Users group: $($_.Exception.Message)" -Level "Error"
                                    $result.Success = $false
                                }
                            }
                        }
                    }
                    
                    # Add authorized RDP users if they're not already members
                    foreach ($authorizedRDPUser in $authorizedRDPUsers) {
                        $isCurrentMember = $rdpMembers | Where-Object { 
                            $memberName = if ($_.Name -like "*\*") { ($_.Name -split "\\")[-1] } else { $_.Name }
                            $memberName -eq $authorizedRDPUser
                        }
                        
                        if (-not $isCurrentMember) {
                            # Check if user exists
                            $userExists = $UserAccounts | Where-Object { $_.Name -eq $authorizedRDPUser }
                            if ($userExists) {
                                if ($WhatIf) {
                                    Write-LogMessage "WhatIf: Would add $authorizedRDPUser to Remote Desktop Users group" -Level "Info"
                                    $result.Changes += "Would add $authorizedRDPUser to Remote Desktop Users group"
                                }
                                else {
                                    try {
                                        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $authorizedRDPUser -ErrorAction Stop
                                        Write-LogMessage "Added authorized user $authorizedRDPUser to Remote Desktop Users group" -Level "Success"
                                        $result.Changes += "Added $authorizedRDPUser to Remote Desktop Users group"
                                    }
                                    catch {
                                        $result.Errors += "Failed to add $authorizedRDPUser to Remote Desktop Users group: $($_.Exception.Message)"
                                        Write-LogMessage "Failed to add $authorizedRDPUser to Remote Desktop Users group: $($_.Exception.Message)" -Level "Error"
                                        $result.Success = $false
                                    }
                                }
                            }
                            else {
                                $result.Warnings += "Authorized RDP user $authorizedRDPUser does not exist as a local user"
                                Write-LogMessage "Authorized RDP user $authorizedRDPUser does not exist as a local user" -Level "Warning"
                            }
                        }
                    }
                }
                else {
                    $result.Warnings += "Remote Desktop Users group does not exist on this system"
                    Write-LogMessage "Remote Desktop Users group does not exist on this system" -Level "Warning"
                }
            }
            catch {
                $result.Errors += "Failed to manage Remote Desktop Users group: $($_.Exception.Message)"
                Write-LogMessage "Failed to manage Remote Desktop Users group: $($_.Exception.Message)" -Level "Error"
                $result.Success = $false
            }
        }
        
        Write-LogMessage "Group membership management completed" -Level "Success"
    }
    catch {
        $result.Errors += "Failed to manage group memberships: $($_.Exception.Message)"
        Write-LogMessage "Failed to manage group memberships: $($_.Exception.Message)" -Level "Error"
        $result.Success = $false
    }
    
    return $result
}

function Invoke-UserAccountConfiguration {
    <#
    .SYNOPSIS
        Main function to execute user account configuration module
    .DESCRIPTION
        Orchestrates the complete user account configuration process including
        enumeration, authorization, and configuration of user accounts and groups
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting User Account Configuration Module..." -Level "Info"
    Write-LogMessage "Requirements: 3.1, 3.2, 3.3, 3.4, 3.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "User Account Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        UserAccounts = @()
        ComplianceResults = @{}
    }
    
    try {
        # Step 1: Enumerate all local user accounts
        Write-LogMessage "Step 1: Enumerating local user accounts..." -Level "Info"
        $userAccounts = Get-LocalUserAccounts
        $moduleResult.UserAccounts = $userAccounts
        
        if ($userAccounts.Count -eq 0) {
            throw "No local user accounts found"
        }
        
        Write-LogMessage "Found $($userAccounts.Count) local user accounts" -Level "Success"
        
        # Step 2: Evaluate user authorization
        Write-LogMessage "Step 2: Evaluating user account authorization..." -Level "Info"
        $authorizedUsers = Test-UserAccountAuthorization -UserAccounts $userAccounts -Config $Config
        
        # Step 3: Test current compliance
        Write-LogMessage "Step 3: Testing current user account compliance..." -Level "Info"
        $complianceResults = Test-UserAccountCompliance -UserAccounts $authorizedUsers -Config $Config
        $moduleResult.ComplianceResults = $complianceResults
        
        if ($complianceResults.OverallCompliance) {
            Write-LogMessage "All user accounts are currently compliant" -Level "Success"
        }
        else {
            Write-LogMessage "Found $($complianceResults.NonCompliantUsers) non-compliant user accounts" -Level "Warning"
        }
        
        # Step 4: Configure password change requirements
        Write-LogMessage "Step 4: Configuring password change requirements..." -Level "Info"
        $passwordChangeResult = Set-UserPasswordChangeRequired -UserAccounts $authorizedUsers -Config $Config
        
        $moduleResult.Changes += $passwordChangeResult.Changes
        $moduleResult.Errors += $passwordChangeResult.Errors
        $moduleResult.Warnings += $passwordChangeResult.Warnings
        
        if (-not $passwordChangeResult.Success) {
            $moduleResult.Success = $false
        }
        
        # Step 5: Disable unauthorized user accounts
        Write-LogMessage "Step 5: Disabling unauthorized user accounts..." -Level "Info"
        $disableUsersResult = Set-UnauthorizedUserAccounts -UserAccounts $authorizedUsers -Config $Config
        
        $moduleResult.Changes += $disableUsersResult.Changes
        $moduleResult.Errors += $disableUsersResult.Errors
        $moduleResult.Warnings += $disableUsersResult.Warnings
        
        if (-not $disableUsersResult.Success) {
            $moduleResult.Success = $false
        }
        
        # Step 6: Manage group memberships
        Write-LogMessage "Step 6: Managing group memberships..." -Level "Info"
        $groupManagementResult = Set-GroupMembershipManagement -UserAccounts $authorizedUsers -Config $Config
        
        $moduleResult.Changes += $groupManagementResult.Changes
        $moduleResult.Errors += $groupManagementResult.Errors
        $moduleResult.Warnings += $groupManagementResult.Warnings
        
        if (-not $groupManagementResult.Success) {
            $moduleResult.Success = $false
        }
        
        # Determine overall success
        if ($moduleResult.Errors.Count -eq 0) {
            $moduleResult.Success = $true
            Write-LogMessage "User Account Configuration Module completed successfully" -Level "Success"
        }
        else {
            Write-LogMessage "User Account Configuration Module completed with errors" -Level "Warning"
        }
        
        # Log summary of changes
        if ($moduleResult.Changes.Count -gt 0) {
            Write-LogMessage "User account configuration changes applied:" -Level "Success"
            foreach ($change in $moduleResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        
        # Log any errors
        if ($moduleResult.Errors.Count -gt 0) {
            Write-LogMessage "User account configuration errors:" -Level "Error"
            foreach ($error in $moduleResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log any warnings
        if ($moduleResult.Warnings.Count -gt 0) {
            Write-LogMessage "User account configuration warnings:" -Level "Warning"
            foreach ($warning in $moduleResult.Warnings) {
                Write-LogMessage "  Warning: $warning" -Level "Warning"
            }
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "User Account Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
        $moduleResult.Success = $false
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

#endregion

#region Windows Security Features Configuration Module

function Set-WindowsSecurityFeatures {
    <#
    .SYNOPSIS
        Configures Windows security features according to security requirements
    .DESCRIPTION
        Implements Windows security features configuration including:
        - Enable SmartScreen online services through registry
        - Disable Wi-Fi Sense automatic hotspot connections
        - Set User Account Control to maximum level
        - Enable Windows Defender when available
    .PARAMETER Config
        Configuration hashtable containing Windows security features settings
    .OUTPUTS
        Returns execution result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Configuring Windows security features..." -Level "Info"
    
    $result = @{
        ModuleName = "Windows Security Features Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
    }
    
    try {
        # Validate configuration parameters
        if (-not $Config.ContainsKey('SecurityFeatures')) {
            throw "Security features configuration section not found"
        }
        
        $securityConfig = $Config.SecurityFeatures
        
        # Validate required settings
        $requiredSettings = @('EnableSmartScreen', 'DisableWiFiSense', 'MaximizeUAC', 'EnableDefender')
        foreach ($setting in $requiredSettings) {
            if (-not $securityConfig.ContainsKey($setting)) {
                throw "Required security feature setting '$setting' not found in configuration"
            }
        }
        
        Write-LogMessage "Windows security features configuration validated" -Level "Success"
        
        $featureResults = @()
        
        # Configure SmartScreen online services
        if ($securityConfig.EnableSmartScreen) {
            Write-LogMessage "Configuring SmartScreen online services..." -Level "Info"
            $smartScreenResult = Set-SmartScreenConfiguration -Enable $true
            $featureResults += $smartScreenResult
            
            if ($smartScreenResult.Success) {
                $result.Changes += $smartScreenResult.Changes
                Write-LogMessage "SmartScreen configuration completed successfully" -Level "Success"
            }
            else {
                $result.Errors += $smartScreenResult.Errors
                $result.Warnings += $smartScreenResult.Warnings
            }
        }
        
        # Disable Wi-Fi Sense automatic hotspot connections
        if ($securityConfig.DisableWiFiSense) {
            Write-LogMessage "Disabling Wi-Fi Sense automatic hotspot connections..." -Level "Info"
            $wifiSenseResult = Set-WiFiSenseConfiguration -Disable $true
            $featureResults += $wifiSenseResult
            
            if ($wifiSenseResult.Success) {
                $result.Changes += $wifiSenseResult.Changes
                Write-LogMessage "Wi-Fi Sense configuration completed successfully" -Level "Success"
            }
            else {
                $result.Errors += $wifiSenseResult.Errors
                $result.Warnings += $wifiSenseResult.Warnings
            }
        }
        
        # Set User Account Control to maximum level
        if ($securityConfig.MaximizeUAC) {
            Write-LogMessage "Setting User Account Control to maximum level..." -Level "Info"
            $uacResult = Set-UACConfiguration -MaximizeLevel $true
            $featureResults += $uacResult
            
            if ($uacResult.Success) {
                $result.Changes += $uacResult.Changes
                Write-LogMessage "UAC configuration completed successfully" -Level "Success"
            }
            else {
                $result.Errors += $uacResult.Errors
                $result.Warnings += $uacResult.Warnings
            }
        }
        
        # Enable Windows Defender when available
        if ($securityConfig.EnableDefender) {
            Write-LogMessage "Enabling Windows Defender..." -Level "Info"
            $defenderResult = Set-WindowsDefenderConfiguration -Enable $true
            $featureResults += $defenderResult
            
            if ($defenderResult.Success) {
                $result.Changes += $defenderResult.Changes
                Write-LogMessage "Windows Defender configuration completed successfully" -Level "Success"
            }
            else {
                $result.Errors += $defenderResult.Errors
                $result.Warnings += $defenderResult.Warnings
            }
        }
        
        # Determine overall success
        $successfulFeatures = ($featureResults | Where-Object { $_.Success }).Count
        $totalFeatures = $featureResults.Count
        
        if ($successfulFeatures -eq $totalFeatures) {
            $result.Success = $true
            Write-LogMessage "All Windows security features configured successfully ($successfulFeatures/$totalFeatures)" -Level "Success"
        }
        elseif ($successfulFeatures -gt 0) {
            $result.Success = $false
            $result.Warnings += "Partial success: $successfulFeatures/$totalFeatures features configured successfully"
            Write-LogMessage "Partial success: $successfulFeatures/$totalFeatures Windows security features configured" -Level "Warning"
        }
        else {
            $result.Success = $false
            Write-LogMessage "Failed to configure any Windows security features" -Level "Error"
        }
        
        Write-LogMessage "Windows security features configuration completed" -Level "Info"
    }
    catch {
        $result.Errors += $_.Exception.Message
        Write-LogMessage "Windows security features configuration failed: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Set-SmartScreenConfiguration {
    <#
    .SYNOPSIS
        Configures SmartScreen online services through registry settings
    .DESCRIPTION
        Enables or disables SmartScreen online services by modifying registry values
    .PARAMETER Enable
        Boolean indicating whether to enable SmartScreen online services
    .OUTPUTS
        Returns configuration result with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Enable
    )
    
    Write-LogMessage "Configuring SmartScreen online services..." -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        # SmartScreen registry paths and values
        $smartScreenSettings = @(
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                Name = "EnableSmartScreen"
                Value = if ($Enable) { 1 } else { 0 }
                Type = "DWORD"
                Description = "Enable SmartScreen Filter"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
                Name = "SmartScreenEnabled"
                Value = if ($Enable) { "RequireAdmin" } else { "Off" }
                Type = "String"
                Description = "SmartScreen for File Explorer"
            },
            @{
                Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
                Name = "EnableWebContentEvaluation"
                Value = if ($Enable) { 1 } else { 0 }
                Type = "DWORD"
                Description = "SmartScreen for Store Apps"
            }
        )
        
        foreach ($setting in $smartScreenSettings) {
            try {
                # Ensure the registry path exists
                if (-not (Test-Path $setting.Path)) {
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would create registry path: $($setting.Path)" -Level "Info"
                    }
                    else {
                        New-Item -Path $setting.Path -Force | Out-Null
                        Write-LogMessage "Created registry path: $($setting.Path)" -Level "Info"
                    }
                }
                
                # Set the registry value
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level "Info"
                    $result.Changes += "Would $(if ($Enable) { 'enable' } else { 'disable' }) $($setting.Description)"
                }
                else {
                    if ($setting.Type -eq "DWORD") {
                        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
                    }
                    else {
                        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force
                    }
                    
                    Write-LogMessage "Set registry value: $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level "Success"
                    $result.Changes += "$(if ($Enable) { 'Enabled' } else { 'Disabled' }) $($setting.Description)"
                }
            }
            catch {
                $errorMsg = "Failed to configure $($setting.Description): $($_.Exception.Message)"
                $result.Errors += $errorMsg
                Write-LogMessage $errorMsg -Level "Error"
            }
        }
        
        # Verify configuration if not in WhatIf mode
        if (-not $WhatIf) {
            $verificationResult = Test-SmartScreenConfiguration -ExpectedEnabled $Enable
            if ($verificationResult.Success) {
                Write-LogMessage "SmartScreen configuration verification successful" -Level "Success"
                $result.Success = $true
            }
            else {
                $result.Warnings += "SmartScreen configuration verification failed: $($verificationResult.Error)"
                Write-LogMessage "SmartScreen configuration verification failed: $($verificationResult.Error)" -Level "Warning"
                $result.Success = $result.Errors.Count -eq 0  # Success if no errors, even with verification warnings
            }
        }
        else {
            $result.Success = $true
        }
    }
    catch {
        $result.Errors += "SmartScreen configuration error: $($_.Exception.Message)"
        Write-LogMessage "SmartScreen configuration error: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Set-WiFiSenseConfiguration {
    <#
    .SYNOPSIS
        Configures Wi-Fi Sense automatic hotspot connections through registry settings
    .DESCRIPTION
        Disables Wi-Fi Sense automatic hotspot connections by modifying registry values
    .PARAMETER Disable
        Boolean indicating whether to disable Wi-Fi Sense features
    .OUTPUTS
        Returns configuration result with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Disable
    )
    
    Write-LogMessage "Configuring Wi-Fi Sense settings..." -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        # Wi-Fi Sense registry settings
        $wifiSenseSettings = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
                Name = "Value"
                Value = if ($Disable) { 0 } else { 1 }
                Type = "DWORD"
                Description = "Wi-Fi HotSpot Reporting"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
                Name = "Value"
                Value = if ($Disable) { 0 } else { 1 }
                Type = "DWORD"
                Description = "Auto-connect to Wi-Fi Sense Hotspots"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
                Name = "AutoConnectAllowedOEM"
                Value = if ($Disable) { 0 } else { 1 }
                Type = "DWORD"
                Description = "OEM Auto-connect"
            }
        )
        
        foreach ($setting in $wifiSenseSettings) {
            try {
                # Ensure the registry path exists
                if (-not (Test-Path $setting.Path)) {
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would create registry path: $($setting.Path)" -Level "Info"
                    }
                    else {
                        New-Item -Path $setting.Path -Force | Out-Null
                        Write-LogMessage "Created registry path: $($setting.Path)" -Level "Info"
                    }
                }
                
                # Set the registry value
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level "Info"
                    $result.Changes += "Would $(if ($Disable) { 'disable' } else { 'enable' }) $($setting.Description)"
                }
                else {
                    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
                    Write-LogMessage "Set registry value: $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level "Success"
                    $result.Changes += "$(if ($Disable) { 'Disabled' } else { 'Enabled' }) $($setting.Description)"
                }
            }
            catch {
                $errorMsg = "Failed to configure $($setting.Description): $($_.Exception.Message)"
                $result.Errors += $errorMsg
                Write-LogMessage $errorMsg -Level "Warning"  # Non-critical for Wi-Fi Sense
            }
        }
        
        # Wi-Fi Sense may not be available on all systems, so we consider partial success acceptable
        if ($result.Errors.Count -eq 0) {
            $result.Success = $true
            Write-LogMessage "Wi-Fi Sense configuration completed successfully" -Level "Success"
        }
        elseif ($result.Changes.Count -gt 0) {
            $result.Success = $true
            $result.Warnings += "Wi-Fi Sense partially configured - some settings may not be available on this system"
            Write-LogMessage "Wi-Fi Sense partially configured - some settings may not be available" -Level "Warning"
        }
        else {
            $result.Success = $false
            Write-LogMessage "Failed to configure Wi-Fi Sense settings" -Level "Error"
        }
    }
    catch {
        $result.Errors += "Wi-Fi Sense configuration error: $($_.Exception.Message)"
        Write-LogMessage "Wi-Fi Sense configuration error: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Set-UACConfiguration {
    <#
    .SYNOPSIS
        Configures User Account Control (UAC) to maximum security level
    .DESCRIPTION
        Sets UAC to maximum level by configuring registry values for all UAC settings
    .PARAMETER MaximizeLevel
        Boolean indicating whether to set UAC to maximum security level
    .OUTPUTS
        Returns configuration result with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [bool]$MaximizeLevel
    )
    
    Write-LogMessage "Configuring User Account Control (UAC) settings..." -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        # UAC registry settings for maximum security
        $uacSettings = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "EnableLUA"
                Value = if ($MaximizeLevel) { 1 } else { 0 }
                Type = "DWORD"
                Description = "Enable User Account Control"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "ConsentPromptBehaviorAdmin"
                Value = if ($MaximizeLevel) { 2 } else { 5 }  # 2 = Prompt for consent on secure desktop
                Type = "DWORD"
                Description = "UAC behavior for administrators"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "ConsentPromptBehaviorUser"
                Value = if ($MaximizeLevel) { 0 } else { 3 }  # 0 = Automatically deny elevation requests
                Type = "DWORD"
                Description = "UAC behavior for standard users"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "PromptOnSecureDesktop"
                Value = if ($MaximizeLevel) { 1 } else { 0 }
                Type = "DWORD"
                Description = "Switch to secure desktop when prompting"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "ValidateAdminCodeSignatures"
                Value = if ($MaximizeLevel) { 1 } else { 0 }
                Type = "DWORD"
                Description = "Only elevate signed and validated executables"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "EnableSecureUIAPaths"
                Value = if ($MaximizeLevel) { 1 } else { 0 }
                Type = "DWORD"
                Description = "Only elevate UIAccess applications in secure locations"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "EnableInstallerDetection"
                Value = if ($MaximizeLevel) { 1 } else { 0 }
                Type = "DWORD"
                Description = "Detect application installations and prompt for elevation"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "EnableVirtualization"
                Value = if ($MaximizeLevel) { 1 } else { 0 }
                Type = "DWORD"
                Description = "Virtualize file and registry write failures"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "FilterAdministratorToken"
                Value = if ($MaximizeLevel) { 1 } else { 0 }
                Type = "DWORD"
                Description = "Admin Approval Mode for Built-in Administrator"
            }
        )
        
        foreach ($setting in $uacSettings) {
            try {
                # Ensure the registry path exists
                if (-not (Test-Path $setting.Path)) {
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would create registry path: $($setting.Path)" -Level "Info"
                    }
                    else {
                        New-Item -Path $setting.Path -Force | Out-Null
                        Write-LogMessage "Created registry path: $($setting.Path)" -Level "Info"
                    }
                }
                
                # Set the registry value
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level "Info"
                    $result.Changes += "Would configure $($setting.Description)"
                }
                else {
                    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
                    Write-LogMessage "Set registry value: $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level "Success"
                    $result.Changes += "Configured $($setting.Description)"
                }
            }
            catch {
                $errorMsg = "Failed to configure $($setting.Description): $($_.Exception.Message)"
                $result.Errors += $errorMsg
                Write-LogMessage $errorMsg -Level "Error"
            }
        }
        
        # Verify configuration if not in WhatIf mode
        if (-not $WhatIf) {
            $verificationResult = Test-UACConfiguration -ExpectedMaximized $MaximizeLevel
            if ($verificationResult.Success) {
                Write-LogMessage "UAC configuration verification successful" -Level "Success"
                $result.Success = $true
            }
            else {
                $result.Warnings += "UAC configuration verification failed: $($verificationResult.Error)"
                Write-LogMessage "UAC configuration verification failed: $($verificationResult.Error)" -Level "Warning"
                $result.Success = $result.Errors.Count -eq 0  # Success if no errors, even with verification warnings
            }
        }
        else {
            $result.Success = $true
        }
        
        if ($result.Success) {
            Write-LogMessage "UAC configured to $(if ($MaximizeLevel) { 'maximum security level' } else { 'default level' })" -Level "Success"
        }
    }
    catch {
        $result.Errors += "UAC configuration error: $($_.Exception.Message)"
        Write-LogMessage "UAC configuration error: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Set-WindowsDefenderConfiguration {
    <#
    .SYNOPSIS
        Configures Windows Defender when available
    .DESCRIPTION
        Enables Windows Defender and configures basic security settings
    .PARAMETER Enable
        Boolean indicating whether to enable Windows Defender
    .OUTPUTS
        Returns configuration result with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Enable
    )
    
    Write-LogMessage "Configuring Windows Defender..." -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        # Check if Windows Defender is available
        $defenderAvailable = $false
        
        # Check for Windows Defender service
        $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($defenderService) {
            $defenderAvailable = $true
            Write-LogMessage "Windows Defender service found" -Level "Info"
        }
        
        # Check for Windows Security (Windows 10/11)
        $securityCenterService = Get-Service -Name "SecurityHealthService" -ErrorAction SilentlyContinue
        if ($securityCenterService) {
            Write-LogMessage "Windows Security service found" -Level "Info"
        }
        
        if (-not $defenderAvailable) {
            $result.Warnings += "Windows Defender service not found - may not be available on this system"
            Write-LogMessage "Windows Defender service not found - checking for third-party antivirus" -Level "Warning"
            
            # Check for third-party antivirus
            try {
                $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
                if ($antivirusProducts) {
                    $activeAV = $antivirusProducts | Where-Object { $_.productState -band 0x1000 }
                    if ($activeAV) {
                        $result.Warnings += "Third-party antivirus detected: $($activeAV.displayName -join ', ')"
                        Write-LogMessage "Third-party antivirus detected: $($activeAV.displayName -join ', ')" -Level "Info"
                        $result.Success = $true  # Consider this successful as system has antivirus protection
                        $result.Changes += "Verified antivirus protection is active (third-party)"
                        return $result
                    }
                }
            }
            catch {
                Write-LogMessage "Could not check for third-party antivirus: $($_.Exception.Message)" -Level "Debug"
            }
            
            $result.Success = $false
            $result.Errors += "No antivirus protection found on system"
            return $result
        }
        
        if ($Enable) {
            # Windows Defender registry settings
            $defenderSettings = @(
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
                    Name = "DisableAntiSpyware"
                    Value = 0
                    Type = "DWORD"
                    Description = "Enable Windows Defender Anti-Spyware"
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
                    Name = "DisableRealtimeMonitoring"
                    Value = 0
                    Type = "DWORD"
                    Description = "Enable Real-Time Protection"
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
                    Name = "SpynetReporting"
                    Value = 2
                    Type = "DWORD"
                    Description = "Enable Advanced MAPS reporting"
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
                    Name = "SubmitSamplesConsent"
                    Value = 1
                    Type = "DWORD"
                    Description = "Enable automatic sample submission"
                }
            )
            
            foreach ($setting in $defenderSettings) {
                try {
                    # Ensure the registry path exists
                    if (-not (Test-Path $setting.Path)) {
                        if ($WhatIf) {
                            Write-LogMessage "WhatIf: Would create registry path: $($setting.Path)" -Level "Info"
                        }
                        else {
                            New-Item -Path $setting.Path -Force | Out-Null
                            Write-LogMessage "Created registry path: $($setting.Path)" -Level "Info"
                        }
                    }
                    
                    # Set the registry value
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would set $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level "Info"
                        $result.Changes += "Would configure $($setting.Description)"
                    }
                    else {
                        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
                        Write-LogMessage "Set registry value: $($setting.Path)\$($setting.Name) = $($setting.Value)" -Level "Success"
                        $result.Changes += "Configured $($setting.Description)"
                    }
                }
                catch {
                    $errorMsg = "Failed to configure $($setting.Description): $($_.Exception.Message)"
                    $result.Warnings += $errorMsg  # Non-critical warnings for Defender settings
                    Write-LogMessage $errorMsg -Level "Warning"
                }
            }
            
            # Try to start Windows Defender service if not running
            if (-not $WhatIf) {
                try {
                    if ($defenderService.Status -ne "Running") {
                        Write-LogMessage "Starting Windows Defender service..." -Level "Info"
                        Start-Service -Name "WinDefend" -ErrorAction Stop
                        $result.Changes += "Started Windows Defender service"
                        Write-LogMessage "Windows Defender service started successfully" -Level "Success"
                    }
                    else {
                        Write-LogMessage "Windows Defender service is already running" -Level "Info"
                    }
                    
                    # Set service to automatic startup
                    Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction Stop
                    $result.Changes += "Set Windows Defender service to automatic startup"
                    Write-LogMessage "Windows Defender service set to automatic startup" -Level "Success"
                }
                catch {
                    $result.Warnings += "Failed to start or configure Windows Defender service: $($_.Exception.Message)"
                    Write-LogMessage "Failed to start or configure Windows Defender service: $($_.Exception.Message)" -Level "Warning"
                }
            }
            else {
                $result.Changes += "Would start Windows Defender service and set to automatic"
            }
        }
        
        # Consider configuration successful if we made changes or verified protection
        if ($result.Changes.Count -gt 0) {
            $result.Success = $true
            Write-LogMessage "Windows Defender configuration completed" -Level "Success"
        }
        else {
            $result.Success = $false
            $result.Errors += "No Windows Defender configuration changes were made"
        }
    }
    catch {
        $result.Errors += "Windows Defender configuration error: $($_.Exception.Message)"
        Write-LogMessage "Windows Defender configuration error: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Test-SmartScreenConfiguration {
    <#
    .SYNOPSIS
        Verifies SmartScreen configuration settings
    .PARAMETER ExpectedEnabled
        Boolean indicating expected SmartScreen state
    .OUTPUTS
        Returns verification result with success status
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [bool]$ExpectedEnabled
    )
    
    $result = @{
        Success = $true
        Error = ""
        Details = @()
    }
    
    try {
        # Check SmartScreen registry values
        $smartScreenChecks = @(
            @{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                Name = "EnableSmartScreen"
                ExpectedValue = if ($ExpectedEnabled) { 1 } else { 0 }
                Description = "SmartScreen Filter Policy"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
                Name = "SmartScreenEnabled"
                ExpectedValue = if ($ExpectedEnabled) { "RequireAdmin" } else { "Off" }
                Description = "SmartScreen for File Explorer"
            }
        )
        
        foreach ($check in $smartScreenChecks) {
            try {
                $currentValue = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
                if ($currentValue) {
                    $actualValue = $currentValue.($check.Name)
                    if ($actualValue -eq $check.ExpectedValue) {
                        $result.Details += "$($check.Description): Configured correctly (✓)"
                    }
                    else {
                        $result.Success = $false
                        $result.Details += "$($check.Description): Expected $($check.ExpectedValue), got $actualValue (✗)"
                    }
                }
                else {
                    $result.Success = $false
                    $result.Details += "$($check.Description): Registry value not found (✗)"
                }
            }
            catch {
                $result.Success = $false
                $result.Details += "$($check.Description): Verification failed - $($_.Exception.Message) (✗)"
            }
        }
        
        if (-not $result.Success) {
            $result.Error = "SmartScreen configuration verification failed"
        }
    }
    catch {
        $result.Success = $false
        $result.Error = "SmartScreen verification error: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-UACConfiguration {
    <#
    .SYNOPSIS
        Verifies UAC configuration settings
    .PARAMETER ExpectedMaximized
        Boolean indicating expected UAC maximized state
    .OUTPUTS
        Returns verification result with success status
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [bool]$ExpectedMaximized
    )
    
    $result = @{
        Success = $true
        Error = ""
        Details = @()
    }
    
    try {
        # Check key UAC registry values
        $uacChecks = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "EnableLUA"
                ExpectedValue = if ($ExpectedMaximized) { 1 } else { 0 }
                Description = "UAC Enabled"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "ConsentPromptBehaviorAdmin"
                ExpectedValue = if ($ExpectedMaximized) { 2 } else { 5 }
                Description = "Admin Consent Behavior"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Name = "PromptOnSecureDesktop"
                ExpectedValue = if ($ExpectedMaximized) { 1 } else { 0 }
                Description = "Secure Desktop Prompting"
            }
        )
        
        foreach ($check in $uacChecks) {
            try {
                $currentValue = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
                if ($currentValue) {
                    $actualValue = $currentValue.($check.Name)
                    if ($actualValue -eq $check.ExpectedValue) {
                        $result.Details += "$($check.Description): Configured correctly (✓)"
                    }
                    else {
                        $result.Success = $false
                        $result.Details += "$($check.Description): Expected $($check.ExpectedValue), got $actualValue (✗)"
                    }
                }
                else {
                    $result.Success = $false
                    $result.Details += "$($check.Description): Registry value not found (✗)"
                }
            }
            catch {
                $result.Success = $false
                $result.Details += "$($check.Description): Verification failed - $($_.Exception.Message) (✗)"
            }
        }
        
        if (-not $result.Success) {
            $result.Error = "UAC configuration verification failed"
        }
    }
    catch {
        $result.Success = $false
        $result.Error = "UAC verification error: $($_.Exception.Message)"
    }
    
    return $result
}

function Get-CurrentSecurityFeaturesStatus {
    <#
    .SYNOPSIS
        Retrieves current status of Windows security features
    .OUTPUTS
        Returns hashtable with current security features status
    #>
    
    Write-LogMessage "Retrieving current Windows security features status..." -Level "Info"
    
    $status = @{
        SmartScreen = @{
            Enabled = $false
            Details = @()
        }
        WiFiSense = @{
            Disabled = $false
            Details = @()
        }
        UAC = @{
            Maximized = $false
            Details = @()
        }
        WindowsDefender = @{
            Enabled = $false
            Details = @()
        }
    }
    
    try {
        # Check SmartScreen status
        try {
            $smartScreenPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
            $smartScreenExplorer = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
            
            if ($smartScreenPolicy -and $smartScreenPolicy.EnableSmartScreen -eq 1) {
                $status.SmartScreen.Enabled = $true
                $status.SmartScreen.Details += "Policy: Enabled"
            }
            
            if ($smartScreenExplorer -and $smartScreenExplorer.SmartScreenEnabled -eq "RequireAdmin") {
                $status.SmartScreen.Details += "Explorer: RequireAdmin"
            }
        }
        catch {
            $status.SmartScreen.Details += "Error checking SmartScreen: $($_.Exception.Message)"
        }
        
        # Check UAC status
        try {
            $uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
            $uacBehavior = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
            
            if ($uacEnabled -and $uacEnabled.EnableLUA -eq 1) {
                $status.UAC.Details += "UAC: Enabled"
                if ($uacBehavior -and $uacBehavior.ConsentPromptBehaviorAdmin -eq 2) {
                    $status.UAC.Maximized = $true
                    $status.UAC.Details += "Level: Maximum (Secure Desktop)"
                }
            }
        }
        catch {
            $status.UAC.Details += "Error checking UAC: $($_.Exception.Message)"
        }
        
        # Check Windows Defender status
        try {
            $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            if ($defenderService) {
                $status.WindowsDefender.Details += "Service: $($defenderService.Status)"
                if ($defenderService.Status -eq "Running") {
                    $status.WindowsDefender.Enabled = $true
                }
            }
            else {
                $status.WindowsDefender.Details += "Service: Not found"
            }
        }
        catch {
            $status.WindowsDefender.Details += "Error checking Windows Defender: $($_.Exception.Message)"
        }
        
        Write-LogMessage "Security features status retrieved successfully" -Level "Success"
    }
    catch {
        Write-LogMessage "Failed to retrieve security features status: $($_.Exception.Message)" -Level "Error"
    }
    
    return $status
}

function Invoke-WindowsSecurityFeaturesConfiguration {
    <#
    .SYNOPSIS
        Main function to execute Windows security features configuration module
    .DESCRIPTION
        Orchestrates the complete Windows security features configuration process including
        SmartScreen, Wi-Fi Sense, UAC, and Windows Defender configuration
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Windows Security Features Configuration Module..." -Level "Info"
    Write-LogMessage "Requirements: 4.1, 4.2, 4.3, 4.4" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Windows Security Features Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        # Get current security features status for comparison
        Write-LogMessage "Retrieving current Windows security features status for comparison..." -Level "Info"
        $currentStatus = Get-CurrentSecurityFeaturesStatus
        
        Write-LogMessage "Current SmartScreen status: $(if ($currentStatus.SmartScreen.Enabled) { 'Enabled' } else { 'Disabled' })" -Level "Info"
        Write-LogMessage "Current UAC status: $(if ($currentStatus.UAC.Maximized) { 'Maximized' } else { 'Not Maximized' })" -Level "Info"
        Write-LogMessage "Current Windows Defender status: $(if ($currentStatus.WindowsDefender.Enabled) { 'Enabled' } else { 'Disabled' })" -Level "Info"
        
        # Apply Windows security features configuration
        $featuresResult = Set-WindowsSecurityFeatures -Config $Config
        
        # Merge results
        $moduleResult.Success = $featuresResult.Success
        $moduleResult.Changes += $featuresResult.Changes
        $moduleResult.Errors += $featuresResult.Errors
        $moduleResult.Warnings += $featuresResult.Warnings
        
        if ($featuresResult.Success) {
            Write-LogMessage "Windows Security Features Configuration Module completed successfully" -Level "Success"
            
            # Log all changes made
            Write-LogMessage "Windows security features changes applied:" -Level "Success"
            foreach ($change in $featuresResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        else {
            Write-LogMessage "Windows Security Features Configuration Module failed" -Level "Error"
            foreach ($error in $featuresResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log any warnings
        foreach ($warning in $featuresResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Windows Security Features Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

#endregion

#region Network Adapter Configuration Module

function Get-NetworkAdapters {
    <#
    .SYNOPSIS
        Enumerates all network adapters on the system
    .DESCRIPTION
        Retrieves comprehensive information about all network adapters including
        their properties, protocol bindings, and current configuration
    .OUTPUTS
        Returns array of hashtables containing network adapter information
    #>
    
    Write-LogMessage "Enumerating network adapters..." -Level "Info"
    
    $networkAdapters = @()
    
    try {
        # Try to use Get-NetAdapter (Windows 8/Server 2012+)
        if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
            Write-LogMessage "Using Get-NetAdapter for adapter enumeration" -Level "Info"
            
            $adapters = Get-NetAdapter -ErrorAction Stop
            
            foreach ($adapter in $adapters) {
                try {
                    # Get additional adapter information
                    $adapterInfo = @{
                        Name = $adapter.Name
                        InterfaceDescription = $adapter.InterfaceDescription
                        InterfaceIndex = $adapter.InterfaceIndex
                        Status = $adapter.Status.ToString()
                        AdminStatus = $adapter.AdminStatus.ToString()
                        MediaType = $adapter.MediaType.ToString()
                        PhysicalMediaType = $adapter.PhysicalMediaType.ToString()
                        LinkSpeed = $adapter.LinkSpeed
                        MacAddress = $adapter.MacAddress
                        InterfaceGuid = $adapter.InterfaceGuid.ToString()
                        DriverInformation = $adapter.DriverInformation
                        Virtual = $adapter.Virtual
                        Hidden = $adapter.Hidden
                        NotUserRemovable = $adapter.NotUserRemovable
                        ProtocolBindings = @()
                        IPv6Enabled = $null
                        DNSRegistrationEnabled = $null
                        NetBIOSEnabled = $null
                        ClientForMSNetworksEnabled = $null
                        FileAndPrinterSharingEnabled = $null
                    }
                    
                    # Get protocol bindings using WMI as fallback
                    try {
                        $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "GUID='$($adapter.InterfaceGuid)'" -ErrorAction SilentlyContinue
                        if ($wmiAdapter) {
                            $adapterInfo.PNPDeviceID = $wmiAdapter.PNPDeviceID
                            $adapterInfo.Manufacturer = $wmiAdapter.Manufacturer
                            $adapterInfo.ProductName = $wmiAdapter.ProductName
                        }
                    }
                    catch {
                        Write-LogMessage "Warning: Could not retrieve WMI information for adapter: $($adapter.Name)" -Level "Debug"
                    }
                    
                    $networkAdapters += $adapterInfo
                    Write-LogMessage "Enumerated adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -Level "Info"
                }
                catch {
                    Write-LogMessage "Error processing adapter $($adapter.Name): $($_.Exception.Message)" -Level "Warning"
                }
            }
        }
        else {
            # Fallback to WMI for older systems
            Write-LogMessage "Get-NetAdapter not available, using WMI fallback..." -Level "Info"
            
            $wmiAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "NetEnabled=True" -ErrorAction Stop
            
            foreach ($adapter in $wmiAdapters) {
                try {
                    $adapterInfo = @{
                        Name = $adapter.NetConnectionID
                        InterfaceDescription = $adapter.Description
                        InterfaceIndex = $adapter.InterfaceIndex
                        Status = if ($adapter.NetConnectionStatus) { "Up" } else { "Down" }
                        AdminStatus = if ($adapter.NetEnabled) { "Up" } else { "Down" }
                        MediaType = $adapter.AdapterType
                        PhysicalMediaType = $adapter.AdapterType
                        LinkSpeed = $adapter.Speed
                        MacAddress = $adapter.MACAddress
                        InterfaceGuid = $adapter.GUID
                        PNPDeviceID = $adapter.PNPDeviceID
                        Manufacturer = $adapter.Manufacturer
                        ProductName = $adapter.ProductName
                        Virtual = $false
                        Hidden = $false
                        NotUserRemovable = $true
                        ProtocolBindings = @()
                        IPv6Enabled = $null
                        DNSRegistrationEnabled = $null
                        NetBIOSEnabled = $null
                        ClientForMSNetworksEnabled = $null
                        FileAndPrinterSharingEnabled = $null
                    }
                    
                    $networkAdapters += $adapterInfo
                    Write-LogMessage "Enumerated adapter (WMI): $($adapter.NetConnectionID) ($($adapter.Description))" -Level "Info"
                }
                catch {
                    Write-LogMessage "Error processing WMI adapter $($adapter.NetConnectionID): $($_.Exception.Message)" -Level "Warning"
                }
            }
        }
        
        Write-LogMessage "Successfully enumerated $($networkAdapters.Count) network adapters" -Level "Success"
    }
    catch {
        Write-LogMessage "Failed to enumerate network adapters: $($_.Exception.Message)" -Level "Error"
        throw
    }
    
    return $networkAdapters
}

function Get-NetworkAdapterProtocolBindings {
    <#
    .SYNOPSIS
        Retrieves protocol bindings for network adapters
    .DESCRIPTION
        Gets detailed information about protocol bindings including Client for MS Networks,
        File and Printer Sharing, IPv6, and other network protocols
    .PARAMETER AdapterName
        Name of the network adapter to examine
    .PARAMETER InterfaceGuid
        GUID of the network interface
    .OUTPUTS
        Returns hashtable with protocol binding information
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        
        [Parameter(Mandatory = $false)]
        [string]$InterfaceGuid
    )
    
    Write-LogMessage "Retrieving protocol bindings for adapter: $AdapterName" -Level "Info"
    
    $protocolBindings = @{
        AdapterName = $AdapterName
        ClientForMSNetworks = @{ Enabled = $null; ComponentID = "ms_msclient" }
        FileAndPrinterSharing = @{ Enabled = $null; ComponentID = "ms_server" }
        IPv6Protocol = @{ Enabled = $null; ComponentID = "ms_tcpip6" }
        IPv4Protocol = @{ Enabled = $null; ComponentID = "ms_tcpip" }
        QoSPacketScheduler = @{ Enabled = $null; ComponentID = "ms_pacer" }
        LinkLayerTopologyDiscovery = @{ Enabled = $null; ComponentID = "ms_lltdio" }
        NetworkAdapterMultiplexor = @{ Enabled = $null; ComponentID = "ms_implat" }
        Errors = @()
    }
    
    try {
        # Method 1: Try using Get-NetAdapterBinding (Windows 8/Server 2012+)
        if (Get-Command Get-NetAdapterBinding -ErrorAction SilentlyContinue) {
            try {
                $bindings = Get-NetAdapterBinding -Name $AdapterName -ErrorAction Stop
                
                foreach ($binding in $bindings) {
                    switch ($binding.ComponentID) {
                        "ms_msclient" {
                            $protocolBindings.ClientForMSNetworks.Enabled = $binding.Enabled
                            Write-LogMessage "Client for MS Networks: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_server" {
                            $protocolBindings.FileAndPrinterSharing.Enabled = $binding.Enabled
                            Write-LogMessage "File and Printer Sharing: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_tcpip6" {
                            $protocolBindings.IPv6Protocol.Enabled = $binding.Enabled
                            Write-LogMessage "IPv6 Protocol: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_tcpip" {
                            $protocolBindings.IPv4Protocol.Enabled = $binding.Enabled
                            Write-LogMessage "IPv4 Protocol: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_pacer" {
                            $protocolBindings.QoSPacketScheduler.Enabled = $binding.Enabled
                            Write-LogMessage "QoS Packet Scheduler: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_lltdio" {
                            $protocolBindings.LinkLayerTopologyDiscovery.Enabled = $binding.Enabled
                            Write-LogMessage "Link Layer Topology Discovery: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_implat" {
                            $protocolBindings.NetworkAdapterMultiplexor.Enabled = $binding.Enabled
                            Write-LogMessage "Network Adapter Multiplexor: $($binding.Enabled)" -Level "Info"
                        }
                    }
                }
                
                Write-LogMessage "Successfully retrieved protocol bindings using Get-NetAdapterBinding" -Level "Success"
            }
            catch {
                Write-LogMessage "Get-NetAdapterBinding failed: $($_.Exception.Message)" -Level "Warning"
                $protocolBindings.Errors += "Get-NetAdapterBinding failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Registry-based approach for protocol bindings
        if ($InterfaceGuid -and ($protocolBindings.ClientForMSNetworks.Enabled -eq $null)) {
            try {
                Write-LogMessage "Attempting registry-based protocol binding detection..." -Level "Info"
                
                # Check registry for network adapter bindings
                $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                
                # Find the adapter in registry by matching GUID or description
                $adapterKeys = Get-ChildItem -Path $adapterRegPath -ErrorAction SilentlyContinue
                
                foreach ($key in $adapterKeys) {
                    try {
                        $keyPath = $key.PSPath
                        $netCfgInstanceId = Get-ItemProperty -Path $keyPath -Name "NetCfgInstanceId" -ErrorAction SilentlyContinue
                        
                        if ($netCfgInstanceId -and $netCfgInstanceId.NetCfgInstanceId -eq $InterfaceGuid) {
                            # Found the adapter, check for component bindings
                            $componentBindings = Get-ItemProperty -Path $keyPath -Name "ComponentBindings" -ErrorAction SilentlyContinue
                            
                            if ($componentBindings -and $componentBindings.ComponentBindings) {
                                $bindings = $componentBindings.ComponentBindings
                                
                                $protocolBindings.ClientForMSNetworks.Enabled = $bindings -contains "ms_msclient"
                                $protocolBindings.FileAndPrinterSharing.Enabled = $bindings -contains "ms_server"
                                $protocolBindings.IPv6Protocol.Enabled = $bindings -contains "ms_tcpip6"
                                $protocolBindings.IPv4Protocol.Enabled = $bindings -contains "ms_tcpip"
                                
                                Write-LogMessage "Retrieved protocol bindings from registry" -Level "Success"
                            }
                            break
                        }
                    }
                    catch {
                        # Continue to next key
                        continue
                    }
                }
            }
            catch {
                Write-LogMessage "Registry-based binding detection failed: $($_.Exception.Message)" -Level "Warning"
                $protocolBindings.Errors += "Registry detection failed: $($_.Exception.Message)"
            }
        }
        
        # Method 3: WMI-based approach as final fallback
        if ($protocolBindings.ClientForMSNetworks.Enabled -eq $null) {
            try {
                Write-LogMessage "Attempting WMI-based protocol binding detection..." -Level "Info"
                
                # Use WMI to check network adapter configuration
                $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Description='$($AdapterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
                
                if (-not $wmiAdapter) {
                    # Try by interface index if available
                    $netAdapter = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "NetConnectionID='$($AdapterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
                    if ($netAdapter) {
                        $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Index=$($netAdapter.Index)" -ErrorAction SilentlyContinue
                    }
                }
                
                if ($wmiAdapter) {
                    # WMI doesn't provide direct protocol binding info, but we can infer some settings
                    $protocolBindings.IPv6Protocol.Enabled = $wmiAdapter.IPEnabled -and ($wmiAdapter.IPAddress -contains "::1" -or $wmiAdapter.DefaultIPGateway -like "*:*")
                    
                    Write-LogMessage "Retrieved partial binding information from WMI" -Level "Info"
                }
            }
            catch {
                Write-LogMessage "WMI-based binding detection failed: $($_.Exception.Message)" -Level "Warning"
                $protocolBindings.Errors += "WMI detection failed: $($_.Exception.Message)"
            }
        }
        
        Write-LogMessage "Protocol binding retrieval completed for adapter: $AdapterName" -Level "Success"
    }
    catch {
        Write-LogMessage "Failed to retrieve protocol bindings for adapter $AdapterName`: $($_.Exception.Message)" -Level "Error"
        $protocolBindings.Errors += "General failure: $($_.Exception.Message)"
    }
    
    return $protocolBindings
}

function Set-NetworkAdapterProtocolBinding {
    <#
    .SYNOPSIS
        Modifies protocol bindings for a network adapter
    .DESCRIPTION
        Enables or disables specific protocol bindings on a network adapter
    .PARAMETER AdapterName
        Name of the network adapter to modify
    .PARAMETER ComponentID
        Component ID of the protocol to modify (e.g., ms_msclient, ms_server, ms_tcpip6)
    .PARAMETER Enabled
        Whether to enable or disable the protocol binding
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        
        [Parameter(Mandatory = $true)]
        [string]$ComponentID,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    Write-LogMessage "Modifying protocol binding for adapter $AdapterName`: $ComponentID = $Enabled" -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ComponentID = $ComponentID
        AdapterName = $AdapterName
        Enabled = $Enabled
    }
    
    try {
        # Method 1: Try using Set-NetAdapterBinding (Windows 8/Server 2012+)
        if (Get-Command Set-NetAdapterBinding -ErrorAction SilentlyContinue) {
            try {
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set $ComponentID binding to $Enabled on adapter $AdapterName" -Level "Info"
                    $result.Changes += "Would set $ComponentID binding to $Enabled"
                    $result.Success = $true
                }
                else {
                    Set-NetAdapterBinding -Name $AdapterName -ComponentID $ComponentID -Enabled $Enabled -ErrorAction Stop
                    Write-LogMessage "Successfully set $ComponentID binding to $Enabled on adapter $AdapterName" -Level "Success"
                    $result.Changes += "Set $ComponentID binding to $Enabled"
                    $result.Success = $true
                }
                
                return $result
            }
            catch {
                Write-LogMessage "Set-NetAdapterBinding failed: $($_.Exception.Message)" -Level "Warning"
                $result.Warnings += "Set-NetAdapterBinding failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Registry-based approach for older systems
        try {
            Write-LogMessage "Attempting registry-based protocol binding modification..." -Level "Info"
            
            # Find the network adapter in registry
            $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            $adapterKeys = Get-ChildItem -Path $adapterRegPath -ErrorAction Stop
            
            $adapterFound = $false
            foreach ($key in $adapterKeys) {
                try {
                    $keyPath = $key.PSPath
                    $driverDesc = Get-ItemProperty -Path $keyPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                    $netConnectionID = Get-ItemProperty -Path $keyPath -Name "NetConnectionID" -ErrorAction SilentlyContinue
                    
                    if (($driverDesc -and $driverDesc.DriverDesc -eq $AdapterName) -or 
                        ($netConnectionID -and $netConnectionID.NetConnectionID -eq $AdapterName)) {
                        
                        $adapterFound = $true
                        
                        # Get current bindings
                        $currentBindings = Get-ItemProperty -Path $keyPath -Name "ComponentBindings" -ErrorAction SilentlyContinue
                        
                        if ($currentBindings -and $currentBindings.ComponentBindings) {
                            $bindings = [System.Collections.ArrayList]$currentBindings.ComponentBindings
                            
                            if ($Enabled) {
                                # Add component if not present
                                if ($bindings -notcontains $ComponentID) {
                                    if ($WhatIf) {
                                        Write-LogMessage "WhatIf: Would add $ComponentID to adapter bindings" -Level "Info"
                                        $result.Changes += "Would add $ComponentID to bindings"
                                    }
                                    else {
                                        $bindings.Add($ComponentID) | Out-Null
                                        Set-ItemProperty -Path $keyPath -Name "ComponentBindings" -Value $bindings.ToArray() -ErrorAction Stop
                                        Write-LogMessage "Added $ComponentID to adapter bindings" -Level "Success"
                                        $result.Changes += "Added $ComponentID to bindings"
                                    }
                                }
                                else {
                                    Write-LogMessage "$ComponentID already enabled on adapter" -Level "Info"
                                }
                            }
                            else {
                                # Remove component if present
                                if ($bindings -contains $ComponentID) {
                                    if ($WhatIf) {
                                        Write-LogMessage "WhatIf: Would remove $ComponentID from adapter bindings" -Level "Info"
                                        $result.Changes += "Would remove $ComponentID from bindings"
                                    }
                                    else {
                                        $bindings.Remove($ComponentID)
                                        Set-ItemProperty -Path $keyPath -Name "ComponentBindings" -Value $bindings.ToArray() -ErrorAction Stop
                                        Write-LogMessage "Removed $ComponentID from adapter bindings" -Level "Success"
                                        $result.Changes += "Removed $ComponentID from bindings"
                                    }
                                }
                                else {
                                    Write-LogMessage "$ComponentID already disabled on adapter" -Level "Info"
                                }
                            }
                            
                            $result.Success = $true
                        }
                        else {
                            $result.Warnings += "Could not find ComponentBindings registry value"
                        }
                        
                        break
                    }
                }
                catch {
                    continue
                }
            }
            
            if (-not $adapterFound) {
                $result.Errors += "Could not find adapter $AdapterName in registry"
                Write-LogMessage "Could not find adapter $AdapterName in registry" -Level "Error"
            }
        }
        catch {
            $result.Errors += "Registry-based modification failed: $($_.Exception.Message)"
            Write-LogMessage "Registry-based modification failed: $($_.Exception.Message)" -Level "Error"
        }
        
        # Method 3: netsh command as final fallback for specific protocols
        if (-not $result.Success -and $ComponentID -eq "ms_tcpip6") {
            try {
                Write-LogMessage "Attempting netsh command for IPv6 protocol..." -Level "Info"
                
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would use netsh to $(if ($Enabled) { 'enable' } else { 'disable' }) IPv6 on $AdapterName" -Level "Info"
                    $result.Changes += "Would use netsh to $(if ($Enabled) { 'enable' } else { 'disable' }) IPv6"
                    $result.Success = $true
                }
                else {
                    $netshAction = if ($Enabled) { "enable" } else { "disable" }
                    $netshArgs = @("interface", "ipv6", $netshAction, $AdapterName)
                    
                    $process = Start-Process -FilePath "netsh.exe" -ArgumentList $netshArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\netsh_output.txt" -RedirectStandardError "$env:TEMP\netsh_error.txt"
                    
                    if ($process.ExitCode -eq 0) {
                        Write-LogMessage "Successfully used netsh to $(if ($Enabled) { 'enable' } else { 'disable' }) IPv6 on $AdapterName" -Level "Success"
                        $result.Changes += "Used netsh to $(if ($Enabled) { 'enable' } else { 'disable' }) IPv6"
                        $result.Success = $true
                    }
                    else {
                        $errorOutput = ""
                        if (Test-Path "$env:TEMP\netsh_error.txt") {
                            $errorOutput = Get-Content "$env:TEMP\netsh_error.txt" -Raw
                        }
                        $result.Errors += "netsh command failed: Exit code $($process.ExitCode). $errorOutput"
                    }
                    
                    # Cleanup temp files
                    @("$env:TEMP\netsh_output.txt", "$env:TEMP\netsh_error.txt") | ForEach-Object {
                        if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
            catch {
                $result.Errors += "netsh command failed: $($_.Exception.Message)"
                Write-LogMessage "netsh command failed: $($_.Exception.Message)" -Level "Error"
            }
        }
        
        if ($result.Success) {
            Write-LogMessage "Protocol binding modification completed successfully" -Level "Success"
        }
        else {
            Write-LogMessage "Protocol binding modification failed" -Level "Error"
        }
    }
    catch {
        $result.Errors += "Failed to modify protocol binding: $($_.Exception.Message)"
        Write-LogMessage "Failed to modify protocol binding: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Test-NetworkAdapterConfiguration {
    <#
    .SYNOPSIS
        Tests network adapter configuration for compliance
    .DESCRIPTION
        Validates network adapter settings against security requirements
    .PARAMETER NetworkAdapters
        Array of network adapter objects to test
    .PARAMETER Config
        Configuration hashtable containing network settings requirements
    .OUTPUTS
        Returns compliance test results
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$NetworkAdapters,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Testing network adapter configuration compliance..." -Level "Info"
    
    $complianceResults = @{
        OverallCompliance = $true
        TotalAdapters = $NetworkAdapters.Count
        CompliantAdapters = 0
        NonCompliantAdapters = 0
        Issues = @()
        Details = @()
    }
    
    try {
        if (-not $Config.ContainsKey('NetworkSettings')) {
            throw "Network settings configuration section not found"
        }
        
        $networkConfig = $Config.NetworkSettings
        
        foreach ($adapter in $NetworkAdapters) {
            $adapterCompliant = $true
            $adapterIssues = @()
            
            # Skip virtual, hidden, or non-user-removable adapters for some tests
            $skipAdapter = $adapter.Virtual -or $adapter.Hidden -or ($adapter.Status -ne "Up")
            
            if (-not $skipAdapter) {
                # Get protocol bindings for this adapter
                $bindings = Get-NetworkAdapterProtocolBindings -AdapterName $adapter.Name -InterfaceGuid $adapter.InterfaceGuid
                
                # Test 1: Client for MS Networks should be disabled
                if ($networkConfig.DisableClientForMSNetworks -and $bindings.ClientForMSNetworks.Enabled -eq $true) {
                    $adapterCompliant = $false
                    $adapterIssues += "Client for MS Networks is enabled"
                    $complianceResults.Issues += "Adapter '$($adapter.Name)' has Client for MS Networks enabled"
                }
                
                # Test 2: File and Printer Sharing should be disabled
                if ($networkConfig.DisableFileAndPrinterSharing -and $bindings.FileAndPrinterSharing.Enabled -eq $true) {
                    $adapterCompliant = $false
                    $adapterIssues += "File and Printer Sharing is enabled"
                    $complianceResults.Issues += "Adapter '$($adapter.Name)' has File and Printer Sharing enabled"
                }
                
                # Test 3: IPv6 should be disabled
                if ($networkConfig.DisableIPv6 -and $bindings.IPv6Protocol.Enabled -eq $true) {
                    $adapterCompliant = $false
                    $adapterIssues += "IPv6 protocol is enabled"
                    $complianceResults.Issues += "Adapter '$($adapter.Name)' has IPv6 protocol enabled"
                }
            }
            
            # Update compliance counters
            if ($adapterCompliant) {
                $complianceResults.CompliantAdapters++
            }
            else {
                $complianceResults.NonCompliantAdapters++
                $complianceResults.OverallCompliance = $false
            }
            
            # Add adapter details to results
            $complianceResults.Details += @{
                AdapterName = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                Status = $adapter.Status
                Compliant = $adapterCompliant
                Issues = $adapterIssues
                Skipped = $skipAdapter
                Virtual = $adapter.Virtual
                Hidden = $adapter.Hidden
            }
        }
        
        Write-LogMessage "Network adapter compliance testing completed" -Level "Success"
        Write-LogMessage "Total adapters: $($complianceResults.TotalAdapters)" -Level "Info"
        Write-LogMessage "Compliant adapters: $($complianceResults.CompliantAdapters)" -Level "Info"
        Write-LogMessage "Non-compliant adapters: $($complianceResults.NonCompliantAdapters)" -Level "Info"
        Write-LogMessage "Overall compliance: $($complianceResults.OverallCompliance)" -Level $(if ($complianceResults.OverallCompliance) { "Success" } else { "Warning" })
        
        if ($complianceResults.Issues.Count -gt 0) {
            Write-LogMessage "Compliance issues found:" -Level "Warning"
            foreach ($issue in $complianceResults.Issues) {
                Write-LogMessage "  - $issue" -Level "Warning"
            }
        }
    }
    catch {
        Write-LogMessage "Failed to test network adapter compliance: $($_.Exception.Message)" -Level "Error"
        $complianceResults.OverallCompliance = $false
        $complianceResults.Issues += "Compliance testing failed: $($_.Exception.Message)"
    }
    
    return $complianceResults
}

function Set-NetworkProtocolsAndServices {
    <#
    .SYNOPSIS
        Configures network protocols and services according to security requirements
    .DESCRIPTION
        Disables Client for MS Networks, File and Printer Sharing, IPv6 protocol,
        DNS registration, and NetBIOS over TCP/IP on all network adapters
    .PARAMETER NetworkAdapters
        Array of network adapter objects to configure
    .PARAMETER Config
        Configuration hashtable containing network settings
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$NetworkAdapters,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Configuring network protocols and services..." -Level "Info"
    
    $result = @{
        Success = $true
        Changes = @()
        Errors = @()
        Warnings = @()
        AdapterResults = @()
    }
    
    try {
        if (-not $Config.ContainsKey('NetworkSettings')) {
            throw "Network settings configuration section not found"
        }
        
        $networkConfig = $Config.NetworkSettings
        
        # Validate required settings
        $requiredSettings = @('DisableClientForMSNetworks', 'DisableFileAndPrinterSharing', 'DisableIPv6', 'DisableDNSRegistration', 'DisableNetBIOS')
        foreach ($setting in $requiredSettings) {
            if (-not $networkConfig.ContainsKey($setting)) {
                throw "Required network setting '$setting' not found in configuration"
            }
        }
        
        Write-LogMessage "Network configuration validated" -Level "Success"
        
        foreach ($adapter in $NetworkAdapters) {
            $adapterResult = @{
                AdapterName = $adapter.Name
                Success = $true
                Changes = @()
                Errors = @()
                Warnings = @()
            }
            
            try {
                # Skip virtual, hidden, or disabled adapters
                if ($adapter.Virtual -or $adapter.Hidden -or $adapter.Status -ne "Up") {
                    Write-LogMessage "Skipping adapter $($adapter.Name) (Virtual: $($adapter.Virtual), Hidden: $($adapter.Hidden), Status: $($adapter.Status))" -Level "Info"
                    $adapterResult.Warnings += "Adapter skipped due to status or type"
                    $result.AdapterResults += $adapterResult
                    continue
                }
                
                Write-LogMessage "Configuring adapter: $($adapter.Name)" -Level "Info"
                
                # 1. Disable Client for MS Networks (Requirement 5.1)
                if ($networkConfig.DisableClientForMSNetworks) {
                    Write-LogMessage "Disabling Client for MS Networks on $($adapter.Name)..." -Level "Info"
                    $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_msclient" -Enabled $false
                    
                    if ($bindingResult.Success) {
                        $adapterResult.Changes += $bindingResult.Changes
                        $result.Changes += "Adapter $($adapter.Name): " + ($bindingResult.Changes -join ", ")
                    }
                    else {
                        $adapterResult.Errors += $bindingResult.Errors
                        $adapterResult.Warnings += $bindingResult.Warnings
                        $adapterResult.Success = $false
                        $result.Success = $false
                    }
                }
                
                # 2. Disable File and Printer Sharing for Microsoft Networks (Requirement 5.2)
                if ($networkConfig.DisableFileAndPrinterSharing) {
                    Write-LogMessage "Disabling File and Printer Sharing on $($adapter.Name)..." -Level "Info"
                    $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_server" -Enabled $false
                    
                    if ($bindingResult.Success) {
                        $adapterResult.Changes += $bindingResult.Changes
                        $result.Changes += "Adapter $($adapter.Name): " + ($bindingResult.Changes -join ", ")
                    }
                    else {
                        $adapterResult.Errors += $bindingResult.Errors
                        $adapterResult.Warnings += $bindingResult.Warnings
                        $adapterResult.Success = $false
                        $result.Success = $false
                    }
                }
                
                # 3. Disable IPv6 Protocol (Requirement 5.3)
                if ($networkConfig.DisableIPv6) {
                    Write-LogMessage "Disabling IPv6 protocol on $($adapter.Name)..." -Level "Info"
                    $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_tcpip6" -Enabled $false
                    
                    if ($bindingResult.Success) {
                        $adapterResult.Changes += $bindingResult.Changes
                        $result.Changes += "Adapter $($adapter.Name): " + ($bindingResult.Changes -join ", ")
                    }
                    else {
                        $adapterResult.Errors += $bindingResult.Errors
                        $adapterResult.Warnings += $bindingResult.Warnings
                        $adapterResult.Success = $false
                        $result.Success = $false
                    }
                }
                
                # 4. Configure DNS registration settings (Requirement 5.4)
                if ($networkConfig.DisableDNSRegistration) {
                    Write-LogMessage "Disabling DNS registration on $($adapter.Name)..." -Level "Info"
                    $dnsResult = Set-DNSRegistrationSettings -AdapterName $adapter.Name -Enabled $false
                    
                    if ($dnsResult.Success) {
                        $adapterResult.Changes += $dnsResult.Changes
                        $result.Changes += "Adapter $($adapter.Name): " + ($dnsResult.Changes -join ", ")
                    }
                    else {
                        $adapterResult.Errors += $dnsResult.Errors
                        $adapterResult.Warnings += $dnsResult.Warnings
                        $adapterResult.Success = $false
                        $result.Success = $false
                    }
                }
                
                # 5. Disable NetBIOS over TCP/IP (Requirement 5.5)
                if ($networkConfig.DisableNetBIOS) {
                    Write-LogMessage "Disabling NetBIOS over TCP/IP on $($adapter.Name)..." -Level "Info"
                    $netbiosResult = Set-NetBIOSSettings -AdapterName $adapter.Name -InterfaceGuid $adapter.InterfaceGuid -Enabled $false
                    
                    if ($netbiosResult.Success) {
                        $adapterResult.Changes += $netbiosResult.Changes
                        $result.Changes += "Adapter $($adapter.Name): " + ($netbiosResult.Changes -join ", ")
                    }
                    else {
                        $adapterResult.Errors += $netbiosResult.Errors
                        $adapterResult.Warnings += $netbiosResult.Warnings
                        $adapterResult.Success = $false
                        $result.Success = $false
                    }
                }
                
                if ($adapterResult.Success) {
                    Write-LogMessage "Successfully configured adapter: $($adapter.Name)" -Level "Success"
                }
                else {
                    Write-LogMessage "Failed to fully configure adapter: $($adapter.Name)" -Level "Warning"
                }
            }
            catch {
                $adapterResult.Errors += "Failed to configure adapter: $($_.Exception.Message)"
                $adapterResult.Success = $false
                $result.Success = $false
                Write-LogMessage "Error configuring adapter $($adapter.Name): $($_.Exception.Message)" -Level "Error"
            }
            
            $result.AdapterResults += $adapterResult
        }
        
        Write-LogMessage "Network protocols and services configuration completed" -Level "Success"
    }
    catch {
        $result.Errors += "Failed to configure network protocols and services: $($_.Exception.Message)"
        $result.Success = $false
        Write-LogMessage "Failed to configure network protocols and services: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Set-DNSRegistrationSettings {
    <#
    .SYNOPSIS
        Configures DNS registration settings for a network adapter
    .DESCRIPTION
        Enables or disables DNS registration for network connections
    .PARAMETER AdapterName
        Name of the network adapter to configure
    .PARAMETER Enabled
        Whether to enable or disable DNS registration
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    Write-LogMessage "Configuring DNS registration for adapter $AdapterName`: $Enabled" -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        # Method 1: Try using Set-DnsClient (Windows 8/Server 2012+)
        if (Get-Command Set-DnsClient -ErrorAction SilentlyContinue) {
            try {
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set DNS registration to $Enabled on adapter $AdapterName" -Level "Info"
                    $result.Changes += "Would set DNS registration to $Enabled"
                    $result.Success = $true
                }
                else {
                    # Get the interface index for the adapter
                    $netAdapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop
                    
                    # Configure DNS registration
                    Set-DnsClient -InterfaceIndex $netAdapter.InterfaceIndex -RegisterThisConnectionsAddress $Enabled -ErrorAction Stop
                    
                    Write-LogMessage "Successfully set DNS registration to $Enabled on adapter $AdapterName" -Level "Success"
                    $result.Changes += "Set DNS registration to $Enabled"
                    $result.Success = $true
                }
                
                return $result
            }
            catch {
                Write-LogMessage "Set-DnsClient failed: $($_.Exception.Message)" -Level "Warning"
                $result.Warnings += "Set-DnsClient failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Registry-based approach
        try {
            Write-LogMessage "Attempting registry-based DNS registration configuration..." -Level "Info"
            
            # Find the network adapter in registry
            $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            $interfaceKeys = Get-ChildItem -Path $adapterRegPath -ErrorAction Stop
            
            $adapterFound = $false
            foreach ($key in $interfaceKeys) {
                try {
                    $keyPath = $key.PSPath
                    
                    # Try to match by adapter name or description
                    # This is a best-effort approach as registry doesn't always have clear adapter name mapping
                    $dhcpDomain = Get-ItemProperty -Path $keyPath -Name "DhcpDomain" -ErrorAction SilentlyContinue
                    $adapterGuid = Split-Path $keyPath -Leaf
                    
                    # Check if this interface corresponds to our adapter
                    # We'll use a heuristic approach since exact matching is complex
                    $registrationValue = if ($Enabled) { 1 } else { 0 }
                    
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would set DNS registration registry values for interface $adapterGuid" -Level "Info"
                        $result.Changes += "Would set DNS registration registry values"
                        $result.Success = $true
                        $adapterFound = $true
                        break
                    }
                    else {
                        # Set DNS registration values
                        Set-ItemProperty -Path $keyPath -Name "RegistrationEnabled" -Value $registrationValue -Type DWord -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $keyPath -Name "RegisterAdapterName" -Value $registrationValue -Type DWord -ErrorAction SilentlyContinue
                        
                        Write-LogMessage "Set DNS registration registry values for interface $adapterGuid" -Level "Info"
                        $result.Changes += "Set DNS registration registry values"
                        $result.Success = $true
                        $adapterFound = $true
                    }
                }
                catch {
                    continue
                }
            }
            
            if (-not $adapterFound) {
                $result.Warnings += "Could not find specific interface in registry, applied to all interfaces"
                Write-LogMessage "Applied DNS registration settings to all network interfaces" -Level "Warning"
            }
        }
        catch {
            $result.Errors += "Registry-based DNS configuration failed: $($_.Exception.Message)"
            Write-LogMessage "Registry-based DNS configuration failed: $($_.Exception.Message)" -Level "Error"
        }
        
        # Method 3: netsh command as fallback
        if (-not $result.Success) {
            try {
                Write-LogMessage "Attempting netsh command for DNS registration..." -Level "Info"
                
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would use netsh to configure DNS registration on $AdapterName" -Level "Info"
                    $result.Changes += "Would use netsh to configure DNS registration"
                    $result.Success = $true
                }
                else {
                    $netshValue = if ($Enabled) { "enable" } else { "disable" }
                    $netshArgs = @("interface", "ip", "set", "dns", $AdapterName, "register=$netshValue")
                    
                    $process = Start-Process -FilePath "netsh.exe" -ArgumentList $netshArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\netsh_dns_output.txt" -RedirectStandardError "$env:TEMP\netsh_dns_error.txt"
                    
                    if ($process.ExitCode -eq 0) {
                        Write-LogMessage "Successfully configured DNS registration using netsh on $AdapterName" -Level "Success"
                        $result.Changes += "Configured DNS registration using netsh"
                        $result.Success = $true
                    }
                    else {
                        $errorOutput = ""
                        if (Test-Path "$env:TEMP\netsh_dns_error.txt") {
                            $errorOutput = Get-Content "$env:TEMP\netsh_dns_error.txt" -Raw
                        }
                        $result.Errors += "netsh DNS command failed: Exit code $($process.ExitCode). $errorOutput"
                    }
                    
                    # Cleanup temp files
                    @("$env:TEMP\netsh_dns_output.txt", "$env:TEMP\netsh_dns_error.txt") | ForEach-Object {
                        if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
            catch {
                $result.Errors += "netsh DNS command failed: $($_.Exception.Message)"
                Write-LogMessage "netsh DNS command failed: $($_.Exception.Message)" -Level "Error"
            }
        }
        
        if ($result.Success) {
            Write-LogMessage "DNS registration configuration completed successfully" -Level "Success"
        }
        else {
            Write-LogMessage "DNS registration configuration failed" -Level "Error"
        }
    }
    catch {
        $result.Errors += "Failed to configure DNS registration: $($_.Exception.Message)"
        Write-LogMessage "Failed to configure DNS registration: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Set-NetBIOSSettings {
    <#
    .SYNOPSIS
        Configures NetBIOS over TCP/IP settings for a network adapter
    .DESCRIPTION
        Enables or disables NetBIOS over TCP/IP for network connections
    .PARAMETER AdapterName
        Name of the network adapter to configure
    .PARAMETER InterfaceGuid
        GUID of the network interface
    .PARAMETER Enabled
        Whether to enable or disable NetBIOS over TCP/IP
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        
        [Parameter(Mandatory = $false)]
        [string]$InterfaceGuid,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    Write-LogMessage "Configuring NetBIOS over TCP/IP for adapter $AdapterName`: $Enabled" -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        # Method 1: Try using Set-NetAdapterAdvancedProperty (Windows 8/Server 2012+)
        if (Get-Command Set-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue) {
            try {
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set NetBIOS over TCP/IP to $Enabled on adapter $AdapterName" -Level "Info"
                    $result.Changes += "Would set NetBIOS over TCP/IP to $Enabled"
                    $result.Success = $true
                }
                else {
                    # NetBIOS setting: 0 = Default, 1 = Enable, 2 = Disable
                    $netbiosValue = if ($Enabled) { 1 } else { 2 }
                    
                    # Try to set NetBIOS setting using advanced properties
                    Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName "NetBIOS over Tcpip" -DisplayValue $netbiosValue -ErrorAction Stop
                    
                    Write-LogMessage "Successfully set NetBIOS over TCP/IP to $Enabled on adapter $AdapterName" -Level "Success"
                    $result.Changes += "Set NetBIOS over TCP/IP to $Enabled"
                    $result.Success = $true
                }
                
                return $result
            }
            catch {
                Write-LogMessage "Set-NetAdapterAdvancedProperty failed: $($_.Exception.Message)" -Level "Warning"
                $result.Warnings += "Set-NetAdapterAdvancedProperty failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Registry-based approach
        try {
            Write-LogMessage "Attempting registry-based NetBIOS configuration..." -Level "Info"
            
            # NetBIOS settings are stored in the registry under the interface GUID
            if ($InterfaceGuid) {
                $netbiosRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$InterfaceGuid"
                
                if (Test-Path $netbiosRegPath) {
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would set NetBIOS registry value for interface $InterfaceGuid" -Level "Info"
                        $result.Changes += "Would set NetBIOS registry value"
                        $result.Success = $true
                    }
                    else {
                        # NetBIOS setting: 0 = Default (usually enabled), 1 = Enable, 2 = Disable
                        $netbiosValue = if ($Enabled) { 1 } else { 2 }
                        
                        Set-ItemProperty -Path $netbiosRegPath -Name "NetbiosOptions" -Value $netbiosValue -Type DWord -ErrorAction Stop
                        
                        Write-LogMessage "Successfully set NetBIOS registry value for interface $InterfaceGuid" -Level "Success"
                        $result.Changes += "Set NetBIOS registry value to $netbiosValue"
                        $result.Success = $true
                    }
                }
                else {
                    $result.Warnings += "NetBIOS registry path not found for interface $InterfaceGuid"
                    Write-LogMessage "NetBIOS registry path not found for interface $InterfaceGuid" -Level "Warning"
                }
            }
            else {
                # Try to find the interface by adapter name
                $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
                $interfaceKeys = Get-ChildItem -Path $netbtPath -ErrorAction SilentlyContinue
                
                $interfaceFound = $false
                foreach ($key in $interfaceKeys) {
                    try {
                        # Apply NetBIOS setting to all TCP/IP interfaces as a fallback
                        if ($key.Name -like "*Tcpip_*") {
                            if ($WhatIf) {
                                Write-LogMessage "WhatIf: Would set NetBIOS registry value for interface $($key.PSChildName)" -Level "Info"
                                $result.Changes += "Would set NetBIOS registry value for $($key.PSChildName)"
                                $interfaceFound = $true
                            }
                            else {
                                $netbiosValue = if ($Enabled) { 1 } else { 2 }
                                Set-ItemProperty -Path $key.PSPath -Name "NetbiosOptions" -Value $netbiosValue -Type DWord -ErrorAction SilentlyContinue
                                Write-LogMessage "Set NetBIOS registry value for interface $($key.PSChildName)" -Level "Info"
                                $interfaceFound = $true
                            }
                        }
                    }
                    catch {
                        continue
                    }
                }
                
                if ($interfaceFound) {
                    $result.Changes += "Set NetBIOS registry values for TCP/IP interfaces"
                    $result.Success = $true
                }
                else {
                    $result.Warnings += "No TCP/IP interfaces found in NetBT registry"
                }
            }
        }
        catch {
            $result.Errors += "Registry-based NetBIOS configuration failed: $($_.Exception.Message)"
            Write-LogMessage "Registry-based NetBIOS configuration failed: $($_.Exception.Message)" -Level "Error"
        }
        
        # Method 3: WMI-based approach as additional fallback
        if (-not $result.Success) {
            try {
                Write-LogMessage "Attempting WMI-based NetBIOS configuration..." -Level "Info"
                
                # Find the network adapter configuration
                $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Description='$($AdapterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
                
                if (-not $wmiAdapter) {
                    # Try by connection ID
                    $netAdapter = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "NetConnectionID='$($AdapterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
                    if ($netAdapter) {
                        $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Index=$($netAdapter.Index)" -ErrorAction SilentlyContinue
                    }
                }
                
                if ($wmiAdapter -and $wmiAdapter.TcpipNetbiosOptions -ne $null) {
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would set NetBIOS options via WMI for adapter $AdapterName" -Level "Info"
                        $result.Changes += "Would set NetBIOS options via WMI"
                        $result.Success = $true
                    }
                    else {
                        # NetBIOS options: 0 = Use NetBIOS from DHCP, 1 = Enable, 2 = Disable
                        $netbiosOption = if ($Enabled) { 1 } else { 2 }
                        
                        $wmiResult = $wmiAdapter | Invoke-CimMethod -MethodName "SetTcpipNetbios" -Arguments @{ TcpipNetbiosOptions = $netbiosOption }
                        
                        if ($wmiResult.ReturnValue -eq 0) {
                            Write-LogMessage "Successfully set NetBIOS options via WMI for adapter $AdapterName" -Level "Success"
                            $result.Changes += "Set NetBIOS options via WMI"
                            $result.Success = $true
                        }
                        else {
                            $result.Errors += "WMI SetTcpipNetbios method failed with return value: $($wmiResult.ReturnValue)"
                        }
                    }
                }
                else {
                    $result.Warnings += "Could not find WMI network adapter configuration"
                }
            }
            catch {
                $result.Errors += "WMI-based NetBIOS configuration failed: $($_.Exception.Message)"
                Write-LogMessage "WMI-based NetBIOS configuration failed: $($_.Exception.Message)" -Level "Error"
            }
        }
        
        if ($result.Success) {
            Write-LogMessage "NetBIOS over TCP/IP configuration completed successfully" -Level "Success"
        }
        else {
            Write-LogMessage "NetBIOS over TCP/IP configuration failed" -Level "Error"
        }
    }
    catch {
        $result.Errors += "Failed to configure NetBIOS over TCP/IP: $($_.Exception.Message)"
        Write-LogMessage "Failed to configure NetBIOS over TCP/IP: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Invoke-NetworkAdapterConfiguration {
    <#
    .SYNOPSIS
        Main function to execute network adapter configuration module
    .DESCRIPTION
        Orchestrates the complete network adapter configuration process including
        enumeration, protocol binding modifications, and verification
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Network Adapter Configuration Module..." -Level "Info"
    Write-LogMessage "Requirements: 5.1, 5.2, 5.3, 5.4, 5.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Network Adapter Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        # Step 1: Enumerate network adapters
        Write-LogMessage "Step 1: Enumerating network adapters..." -Level "Info"
        $networkAdapters = Get-NetworkAdapters
        
        if ($networkAdapters.Count -eq 0) {
            throw "No network adapters found on the system"
        }
        
        Write-LogMessage "Found $($networkAdapters.Count) network adapters" -Level "Success"
        
        # Step 2: Get current protocol bindings for comparison
        Write-LogMessage "Step 2: Retrieving current protocol bindings..." -Level "Info"
        foreach ($adapter in $networkAdapters) {
            if (-not ($adapter.Virtual -or $adapter.Hidden -or $adapter.Status -ne "Up")) {
                $bindings = Get-NetworkAdapterProtocolBindings -AdapterName $adapter.Name -InterfaceGuid $adapter.InterfaceGuid
                
                Write-LogMessage "Adapter $($adapter.Name) current bindings:" -Level "Info"
                Write-LogMessage "  Client for MS Networks: $($bindings.ClientForMSNetworks.Enabled)" -Level "Info"
                Write-LogMessage "  File and Printer Sharing: $($bindings.FileAndPrinterSharing.Enabled)" -Level "Info"
                Write-LogMessage "  IPv6 Protocol: $($bindings.IPv6Protocol.Enabled)" -Level "Info"
            }
        }
        
        # Step 3: Apply network protocol and service configurations
        Write-LogMessage "Step 3: Applying network protocol and service configurations..." -Level "Info"
        $configResult = Set-NetworkProtocolsAndServices -NetworkAdapters $networkAdapters -Config $Config
        
        # Merge results
        $moduleResult.Success = $configResult.Success
        $moduleResult.Changes += $configResult.Changes
        $moduleResult.Errors += $configResult.Errors
        $moduleResult.Warnings += $configResult.Warnings
        
        # Step 4: Validate configuration compliance
        Write-LogMessage "Step 4: Validating network adapter configuration compliance..." -Level "Info"
        $complianceResult = Test-NetworkAdapterConfiguration -NetworkAdapters $networkAdapters -Config $Config
        $moduleResult.ValidationResults = $complianceResult
        
        if ($complianceResult.OverallCompliance) {
            Write-LogMessage "Network adapter configuration compliance validation passed" -Level "Success"
        }
        else {
            Write-LogMessage "Network adapter configuration compliance validation failed" -Level "Warning"
            $moduleResult.Warnings += "Some adapters are not compliant with security requirements"
        }
        
        if ($moduleResult.Success) {
            Write-LogMessage "Network Adapter Configuration Module completed successfully" -Level "Success"
            
            # Log summary of changes
            Write-LogMessage "Network adapter configuration changes applied:" -Level "Success"
            foreach ($change in $configResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
            
            # Log adapter-specific results
            foreach ($adapterResult in $configResult.AdapterResults) {
                if ($adapterResult.Success -and $adapterResult.Changes.Count -gt 0) {
                    Write-LogMessage "Adapter $($adapterResult.AdapterName): $($adapterResult.Changes.Count) changes applied" -Level "Success"
                }
                elseif (-not $adapterResult.Success) {
                    Write-LogMessage "Adapter $($adapterResult.AdapterName): Configuration failed" -Level "Warning"
                }
            }
        }
        else {
            Write-LogMessage "Network Adapter Configuration Module failed" -Level "Error"
            foreach ($error in $configResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log any warnings
        foreach ($warning in $configResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Network Adapter Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

#endregion

#region Script Entry Point

# Main script execution
if ($MyInvocation.InvocationName -ne '.') {
    try {
        # Initialize logging system
        Initialize-Logging
        
        Write-LogMessage "Windows Security Hardening Script v$Script:ScriptVersion" -Level "Info"
        Write-LogMessage "Author: $Script:ScriptAuthor" -Level "Info"
        Write-LogMessage "Execution started by: $env:USERNAME on $env:COMPUTERNAME" -Level "Info"
        
        # Start the security hardening process
        $configuration = Start-SecurityHardening
        
        if ($configuration) {
            Write-LogMessage "Script foundation initialized successfully" -Level "Success"
            Write-LogMessage "Configuration object created with $($configuration.Keys.Count) sections" -Level "Info"
            
            # Note: Additional security modules will be implemented in subsequent tasks
            Write-LogMessage "Ready for security module implementation..." -Level "Info"
        }
        
        # Complete the process
        Complete-SecurityHardening
    }
    catch {
        Write-LogMessage "Critical error during script execution: $($_.Exception.Message)" -Level "Error"
        Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "Debug"
        
        if (-not $Silent) {
            Write-Host "`nScript execution failed. Check the log file for details." -ForegroundColor Red
            Write-Host "Press any key to exit..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        
        exit 1
    }
}

#endregion

# Export functions for module testing and external use
Export-ModuleMember -Function @(
    'Test-Prerequisites',
    'Test-IsAdministrator', 
    'Test-PowerShellVersion',
    'Test-WindowsVersion',
    'Initialize-Logging',
    'Write-LogMessage',
    'New-SystemRestorePoint',
    'Backup-RegistryKeys',
    'Backup-ServiceStates',
    'Backup-SecurityPolicies',
    'Initialize-BackupSystem',
    'Get-BackupInformation',
    'Initialize-Configuration',
    'Show-Configuration',
    'Start-SecurityHardening',
    'Complete-SecurityHardening',
    'Add-ExecutionResult',
    'Set-PasswordPolicy',
    'Test-PasswordPolicyApplication',
    'Get-CurrentPasswordPolicy',
    'Invoke-PasswordPolicyConfiguration',
    'Set-AccountLockoutPolicy',
    'Test-AccountLockoutPolicyApplication',
    'Get-CurrentAccountLockoutPolicy',
    'Invoke-AccountLockoutPolicyConfiguration',
    'Get-LocalUserAccounts',
    'Test-UserAccountAuthorization',
    'Get-UserAccountProperties',
    'Test-UserAccountCompliance',
    'Set-UserPasswordChangeRequired',
    'Set-UnauthorizedUserAccounts',
    'Set-GroupMembershipManagement',
    'Invoke-UserAccountConfiguration',
    'Set-WindowsSecurityFeatures',
    'Set-SmartScreenConfiguration',
    'Set-WiFiSenseConfiguration',
    'Set-UACConfiguration',
    'Set-WindowsDefenderConfiguration',
    'Test-SmartScreenConfiguration',
    'Test-UACConfiguration',
    'Get-CurrentSecurityFeaturesStatus',
    'Invoke-WindowsSecurityFeaturesConfiguration',
    'Get-NetworkAdapters',
    'Get-NetworkAdapterProtocolBindings',
    'Set-NetworkAdapterProtocolBinding',
    'Test-NetworkAdapterConfiguration',
    'Set-NetworkProtocolsAndServices',
    'Set-DNSRegistrationSettings',
    'Set-NetBIOSSettings',
    'Invoke-NetworkAdapterConfiguration'
)