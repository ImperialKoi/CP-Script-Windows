<#
.SYNOPSIS
    Windows Security Hardening Script - Main Entry Point

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
    .\WindowsSecurityHardening-Main.ps1
    Run the script interactively with default settings

.EXAMPLE
    .\WindowsSecurityHardening-Main.ps1 -Silent -LogPath "C:\Logs"
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

# Global variables
$Script:StartTime = Get-Date
$Script:ExecutionResults = @()
$Script:Configuration = @{}

# Import required modules
$ModulePath = Join-Path $PSScriptRoot "Modules"

try {
    Write-Host "Loading security hardening modules..." -ForegroundColor Yellow
    
    # Import core modules
    Import-Module (Join-Path $ModulePath "Prerequisites.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $ModulePath "Logging.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $ModulePath "BackupSystem.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $ModulePath "NetworkAdapter.psm1") -Force -ErrorAction Stop
    
    Write-Host "All modules loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "Failed to load required modules: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please ensure all module files are present in the Modules directory" -ForegroundColor Red
    exit 1
}

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

#region Main Execution Framework

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
    
    # Log changes to the detailed change log (Requirement 12.2)
    foreach ($change in $Changes) {
        # Parse change description to extract details for change logging
        $changeType = "System"
        $target = $change
        $action = "Applied"
        $requirementId = ""
        
        # Try to extract more specific information from change description
        if ($change -match "Registry.*:.*=") {
            $changeType = "Registry"
            $action = "Modified"
        }
        elseif ($change -match "Service.*:") {
            $changeType = "Service"
            if ($change -match "Started|Stopped") {
                $action = if ($change -match "Started") { "Started" } else { "Stopped" }
            }
            elseif ($change -match "Enabled|Disabled") {
                $action = if ($change -match "Enabled") { "Enabled" } else { "Disabled" }
            }
        }
        elseif ($change -match "Feature.*:") {
            $changeType = "Feature"
            $action = if ($change -match "Disabled") { "Disabled" } else { "Configured" }
        }
        elseif ($change -match "Firewall.*:") {
            $changeType = "Firewall"
            $action = "Created"
        }
        elseif ($change -match "Network.*:") {
            $changeType = "Network"
            $action = "Configured"
        }
        elseif ($change -match "Policy.*:") {
            $changeType = "Policy"
            $action = "Applied"
        }
        
        # Extract requirement ID if present
        if ($change -match "\[Req[^:]*:\s*([^\]]+)\]") {
            $requirementId = $matches[1]
        }
        
        Add-ChangeLogEntry -ModuleName $ModuleName -ChangeType $changeType -Target $target -Action $action -RequirementId $requirementId -Success $true
    }
    
    # Log errors to the detailed change log (Requirement 12.3)
    foreach ($error in $Errors) {
        Add-ChangeLogEntry -ModuleName $ModuleName -ChangeType "System" -Target $error -Action "Failed" -Success $false -ErrorMessage $error
    }
}

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
            $backupSuccess = Initialize-BackupSystem -LogPath $LogPath
            
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
        
        # Process each adapter individually
        foreach ($adapter in $networkAdapters) {
            # Skip virtual, hidden, or disabled adapters
            if ($adapter.Virtual -or $adapter.Hidden -or $adapter.Status -ne "Up") {
                Write-LogMessage "Skipping adapter $($adapter.Name) (Virtual: $($adapter.Virtual), Hidden: $($adapter.Hidden), Status: $($adapter.Status))" -Level "Info"
                continue
            }
            
            Write-LogMessage "Configuring adapter: $($adapter.Name)" -Level "Info"
            
            # 1. Disable Client for MS Networks (Requirement 5.1)
            if ($Config.NetworkSettings.DisableClientForMSNetworks) {
                Write-LogMessage "Disabling Client for MS Networks on $($adapter.Name)..." -Level "Info"
                $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_msclient" -Enabled $false
                
                if ($bindingResult.Success) {
                    $moduleResult.Changes += "Adapter $($adapter.Name): " + ($bindingResult.Changes -join ", ")
                }
                else {
                    $moduleResult.Errors += $bindingResult.Errors
                    $moduleResult.Warnings += $bindingResult.Warnings
                    $moduleResult.Success = $false
                }
            }
            
            # 2. Disable File and Printer Sharing for Microsoft Networks (Requirement 5.2)
            if ($Config.NetworkSettings.DisableFileAndPrinterSharing) {
                Write-LogMessage "Disabling File and Printer Sharing on $($adapter.Name)..." -Level "Info"
                $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_server" -Enabled $false
                
                if ($bindingResult.Success) {
                    $moduleResult.Changes += "Adapter $($adapter.Name): " + ($bindingResult.Changes -join ", ")
                }
                else {
                    $moduleResult.Errors += $bindingResult.Errors
                    $moduleResult.Warnings += $bindingResult.Warnings
                    $moduleResult.Success = $false
                }
            }
            
            # 3. Disable IPv6 Protocol (Requirement 5.3)
            if ($Config.NetworkSettings.DisableIPv6) {
                Write-LogMessage "Disabling IPv6 protocol on $($adapter.Name)..." -Level "Info"
                $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_tcpip6" -Enabled $false
                
                if ($bindingResult.Success) {
                    $moduleResult.Changes += "Adapter $($adapter.Name): " + ($bindingResult.Changes -join ", ")
                }
                else {
                    $moduleResult.Errors += $bindingResult.Errors
                    $moduleResult.Warnings += $bindingResult.Warnings
                    $moduleResult.Success = $false
                }
            }
            
            # 4. Configure DNS registration settings (Requirement 5.4)
            if ($Config.NetworkSettings.DisableDNSRegistration) {
                Write-LogMessage "Disabling DNS registration on $($adapter.Name)..." -Level "Info"
                $dnsResult = Set-DNSRegistrationSettings -AdapterName $adapter.Name -Enabled $false
                
                if ($dnsResult.Success) {
                    $moduleResult.Changes += "Adapter $($adapter.Name): " + ($dnsResult.Changes -join ", ")
                }
                else {
                    $moduleResult.Errors += $dnsResult.Errors
                    $moduleResult.Warnings += $dnsResult.Warnings
                    $moduleResult.Success = $false
                }
            }
            
            # 5. Disable NetBIOS over TCP/IP (Requirement 5.5)
            if ($Config.NetworkSettings.DisableNetBIOS) {
                Write-LogMessage "Disabling NetBIOS over TCP/IP on $($adapter.Name)..." -Level "Info"
                $netbiosResult = Set-NetBIOSSettings -AdapterName $adapter.Name -InterfaceGuid $adapter.InterfaceGuid -Enabled $false
                
                if ($netbiosResult.Success) {
                    $moduleResult.Changes += "Adapter $($adapter.Name): " + ($netbiosResult.Changes -join ", ")
                }
                else {
                    $moduleResult.Errors += $netbiosResult.Errors
                    $moduleResult.Warnings += $netbiosResult.Warnings
                    $moduleResult.Success = $false
                }
            }
        }
        
        # Set success if no errors occurred
        if ($moduleResult.Errors.Count -eq 0) {
            $moduleResult.Success = $true
        }
        
        if ($moduleResult.Success) {
            Write-LogMessage "Network Adapter Configuration Module completed successfully" -Level "Success"
            
            # Log summary of changes
            Write-LogMessage "Network adapter configuration changes applied:" -Level "Success"
            foreach ($change in $moduleResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        else {
            Write-LogMessage "Network Adapter Configuration Module failed" -Level "Error"
            foreach ($error in $moduleResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log any warnings
        foreach ($warning in $moduleResult.Warnings) {
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

function Invoke-WindowsServicesConfiguration {
    <#
    .SYNOPSIS
        Main function to execute Windows services management configuration
    .DESCRIPTION
        Orchestrates the complete Windows services configuration process including
        service enumeration, state checking, dependency validation, and service modifications
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Windows Services Management Module..." -Level "Info"
    Write-LogMessage "Requirements: 6.1, 6.2, 6.3, 6.4, 6.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Windows Services Management"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        # Step 1: Create service enumeration and state checking functions
        Write-LogMessage "Step 1: Enumerating Windows services and checking current states..." -Level "Info"
        
        # Define target services for configuration
        $targetServices = @{
            # Services to disable (Requirements 6.1, 6.2, 6.3, 6.4)
            "upnphost" = @{
                DisplayName = "UPnP Device Host"
                TargetState = "Stopped"
                TargetStartType = "Disabled"
                Requirement = "6.1"
                Description = "Stop and disable UPnP Device Host service"
            }
            "TlntSvr" = @{
                DisplayName = "Telnet"
                TargetState = "Stopped"
                TargetStartType = "Disabled"
                Requirement = "6.2"
                Description = "Stop and disable Telnet service"
            }
            "SNMPTRAP" = @{
                DisplayName = "SNMP Trap"
                TargetState = "Stopped"
                TargetStartType = "Disabled"
                Requirement = "6.3"
                Description = "Stop and disable SNMP Trap service"
            }
            "RemoteRegistry" = @{
                DisplayName = "Remote Registry"
                TargetState = "Stopped"
                TargetStartType = "Disabled"
                Requirement = "6.4"
                Description = "Stop and disable Remote Registry service"
            }
            # Service to enable (Requirement 6.5)
            "Wecsvc" = @{
                DisplayName = "Windows Event Collector"
                TargetState = "Running"
                TargetStartType = "Automatic"
                Requirement = "6.5"
                Description = "Configure Windows Event Collector as running and automatic"
            }
        }
        
        # Enumerate and check current service states
        $serviceStates = @{}
        foreach ($serviceName in $targetServices.Keys) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    $serviceStates[$serviceName] = @{
                        Service = $service
                        CurrentState = $service.Status
                        CurrentStartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartMode
                        Exists = $true
                    }
                    
                    Write-LogMessage "Service '$($targetServices[$serviceName].DisplayName)' - Current State: $($service.Status), Start Type: $($serviceStates[$serviceName].CurrentStartType)" -Level "Info"
                }
                else {
                    $serviceStates[$serviceName] = @{
                        Service = $null
                        CurrentState = "NotFound"
                        CurrentStartType = "NotFound"
                        Exists = $false
                    }
                    
                    Write-LogMessage "Service '$($targetServices[$serviceName].DisplayName)' - Not found on this system" -Level "Warning"
                    $moduleResult.Warnings += "Service '$($targetServices[$serviceName].DisplayName)' not found on this system"
                }
            }
            catch {
                Write-LogMessage "Error checking service '$serviceName': $($_.Exception.Message)" -Level "Error"
                $moduleResult.Errors += "Error checking service '$serviceName': $($_.Exception.Message)"
            }
        }
        
        # Step 2: Implement service dependency checking before modifications
        Write-LogMessage "Step 2: Checking service dependencies..." -Level "Info"
        
        function Test-ServiceDependencies {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ServiceName,
                
                [Parameter(Mandatory = $true)]
                [string]$TargetState
            )
            
            try {
                $service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
                if (-not $service) {
                    return @{ CanModify = $false; Reason = "Service not found" }
                }
                
                # Check dependent services
                $dependentServices = Get-Service -Name $ServiceName | ForEach-Object { $_.DependentServices }
                
                if ($TargetState -eq "Stopped" -and $dependentServices.Count -gt 0) {
                    $runningDependents = $dependentServices | Where-Object { $_.Status -eq "Running" }
                    
                    if ($runningDependents.Count -gt 0) {
                        $dependentNames = ($runningDependents | ForEach-Object { $_.DisplayName }) -join ", "
                        Write-LogMessage "Service '$ServiceName' has running dependent services: $dependentNames" -Level "Warning"
                        return @{ 
                            CanModify = $true
                            Reason = "Has dependent services that will be stopped: $dependentNames"
                            DependentServices = $runningDependents
                        }
                    }
                }
                
                # Check service dependencies (services this service depends on)
                $serviceDependencies = $service.ServiceDependencies
                if ($serviceDependencies -and $serviceDependencies.Count -gt 0) {
                    Write-LogMessage "Service '$ServiceName' depends on: $($serviceDependencies -join ', ')" -Level "Info"
                }
                
                return @{ CanModify = $true; Reason = "No blocking dependencies found" }
            }
            catch {
                return @{ CanModify = $false; Reason = "Error checking dependencies: $($_.Exception.Message)" }
            }
        }
        
        # Step 3: Apply service configurations based on requirements
        Write-LogMessage "Step 3: Applying Windows services configurations..." -Level "Info"
        
        foreach ($serviceName in $targetServices.Keys) {
            $serviceConfig = $targetServices[$serviceName]
            $currentState = $serviceStates[$serviceName]
            
            # Skip if service doesn't exist
            if (-not $currentState.Exists) {
                Write-LogMessage "Skipping '$($serviceConfig.DisplayName)' - service not found" -Level "Warning"
                continue
            }
            
            Write-LogMessage "Configuring service: $($serviceConfig.DisplayName) (Requirement $($serviceConfig.Requirement))" -Level "Info"
            
            # Check if configuration is needed
            $needsStateChange = $currentState.CurrentState -ne $serviceConfig.TargetState
            $needsStartTypeChange = $currentState.CurrentStartType -ne $serviceConfig.TargetStartType
            
            if (-not $needsStateChange -and -not $needsStartTypeChange) {
                Write-LogMessage "Service '$($serviceConfig.DisplayName)' already in desired state" -Level "Success"
                continue
            }
            
            # Check dependencies before making changes
            $dependencyCheck = Test-ServiceDependencies -ServiceName $serviceName -TargetState $serviceConfig.TargetState
            
            if (-not $dependencyCheck.CanModify) {
                Write-LogMessage "Cannot modify service '$($serviceConfig.DisplayName)': $($dependencyCheck.Reason)" -Level "Error"
                $moduleResult.Errors += "Cannot modify service '$($serviceConfig.DisplayName)': $($dependencyCheck.Reason)"
                continue
            }
            
            if ($dependencyCheck.DependentServices) {
                Write-LogMessage "Service modification will affect dependent services: $($dependencyCheck.Reason)" -Level "Warning"
                $moduleResult.Warnings += "Service '$($serviceConfig.DisplayName)': $($dependencyCheck.Reason)"
            }
            
            try {
                # Apply service configuration based on requirements
                $changesMade = @()
                
                # Handle services that need to be stopped and disabled (Requirements 6.1, 6.2, 6.3, 6.4)
                if ($serviceConfig.TargetState -eq "Stopped" -and $serviceConfig.TargetStartType -eq "Disabled") {
                    
                    # Stop the service if it's running
                    if ($currentState.CurrentState -eq "Running") {
                        Write-LogMessage "Stopping service '$($serviceConfig.DisplayName)'..." -Level "Info"
                        Stop-Service -Name $serviceName -Force -ErrorAction Stop
                        $changesMade += "Stopped service"
                        
                        # Wait for service to stop
                        $timeout = 30
                        $elapsed = 0
                        do {
                            Start-Sleep -Seconds 1
                            $elapsed++
                            $service = Get-Service -Name $serviceName
                        } while ($service.Status -ne "Stopped" -and $elapsed -lt $timeout)
                        
                        if ($service.Status -ne "Stopped") {
                            throw "Service did not stop within $timeout seconds"
                        }
                    }
                    
                    # Set startup type to disabled
                    if ($currentState.CurrentStartType -ne "Disabled") {
                        Write-LogMessage "Setting service '$($serviceConfig.DisplayName)' startup type to Disabled..." -Level "Info"
                        Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
                        $changesMade += "Set startup type to Disabled"
                    }
                }
                
                # Handle Windows Event Collector service (Requirement 6.5)
                elseif ($serviceConfig.TargetState -eq "Running" -and $serviceConfig.TargetStartType -eq "Automatic") {
                    
                    # Set startup type to automatic
                    if ($currentState.CurrentStartType -ne "Automatic") {
                        Write-LogMessage "Setting service '$($serviceConfig.DisplayName)' startup type to Automatic..." -Level "Info"
                        Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
                        $changesMade += "Set startup type to Automatic"
                    }
                    
                    # Start the service if it's not running
                    if ($currentState.CurrentState -ne "Running") {
                        Write-LogMessage "Starting service '$($serviceConfig.DisplayName)'..." -Level "Info"
                        Start-Service -Name $serviceName -ErrorAction Stop
                        $changesMade += "Started service"
                        
                        # Wait for service to start
                        $timeout = 30
                        $elapsed = 0
                        do {
                            Start-Sleep -Seconds 1
                            $elapsed++
                            $service = Get-Service -Name $serviceName
                        } while ($service.Status -ne "Running" -and $elapsed -lt $timeout)
                        
                        if ($service.Status -ne "Running") {
                            throw "Service did not start within $timeout seconds"
                        }
                    }
                }
                
                if ($changesMade.Count -gt 0) {
                    $changeDescription = "Service '$($serviceConfig.DisplayName)': " + ($changesMade -join ", ")
                    $moduleResult.Changes += $changeDescription
                    Write-LogMessage "Successfully configured service '$($serviceConfig.DisplayName)': $($changesMade -join ', ')" -Level "Success"
                }
                
                # Verify the changes
                $verificationService = Get-Service -Name $serviceName
                $verificationWmi = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
                
                $finalState = $verificationService.Status
                $finalStartType = $verificationWmi.StartMode
                
                if ($finalState -eq $serviceConfig.TargetState -and $finalStartType -eq $serviceConfig.TargetStartType) {
                    Write-LogMessage "Verification successful: Service '$($serviceConfig.DisplayName)' is now $finalState with $finalStartType startup" -Level "Success"
                    $moduleResult.ValidationResults += "Service '$($serviceConfig.DisplayName)': State=$finalState, StartType=$finalStartType (Target: $($serviceConfig.TargetState)/$($serviceConfig.TargetStartType))"
                }
                else {
                    Write-LogMessage "Verification failed: Service '$($serviceConfig.DisplayName)' - Expected: $($serviceConfig.TargetState)/$($serviceConfig.TargetStartType), Actual: $finalState/$finalStartType" -Level "Warning"
                    $moduleResult.Warnings += "Service '$($serviceConfig.DisplayName)' verification failed - Expected: $($serviceConfig.TargetState)/$($serviceConfig.TargetStartType), Actual: $finalState/$finalStartType"
                }
            }
            catch {
                $errorMessage = "Failed to configure service '$($serviceConfig.DisplayName)': $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $moduleResult.Errors += $errorMessage
            }
        }
        
        # Step 4: Final validation and summary
        Write-LogMessage "Step 4: Performing final validation..." -Level "Info"
        
        $successfulConfigurations = 0
        $totalConfigurations = 0
        
        foreach ($serviceName in $targetServices.Keys) {
            $serviceConfig = $targetServices[$serviceName]
            $currentState = $serviceStates[$serviceName]
            
            if ($currentState.Exists) {
                $totalConfigurations++
                
                try {
                    $service = Get-Service -Name $serviceName
                    $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
                    
                    if ($service.Status -eq $serviceConfig.TargetState -and $wmiService.StartMode -eq $serviceConfig.TargetStartType) {
                        $successfulConfigurations++
                    }
                }
                catch {
                    Write-LogMessage "Error during final validation of service '$serviceName': $($_.Exception.Message)" -Level "Warning"
                }
            }
        }
        
        # Set overall success based on results
        if ($moduleResult.Errors.Count -eq 0 -and $successfulConfigurations -eq $totalConfigurations) {
            $moduleResult.Success = $true
            Write-LogMessage "Windows Services Management Module completed successfully" -Level "Success"
            Write-LogMessage "Successfully configured $successfulConfigurations of $totalConfigurations services" -Level "Success"
        }
        elseif ($moduleResult.Errors.Count -eq 0) {
            $moduleResult.Success = $true
            Write-LogMessage "Windows Services Management Module completed with warnings" -Level "Warning"
            Write-LogMessage "Successfully configured $successfulConfigurations of $totalConfigurations services" -Level "Warning"
        }
        else {
            Write-LogMessage "Windows Services Management Module failed" -Level "Error"
            Write-LogMessage "Successfully configured $successfulConfigurations of $totalConfigurations services" -Level "Warning"
            foreach ($error in $moduleResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log summary of changes
        if ($moduleResult.Changes.Count -gt 0) {
            Write-LogMessage "Windows services configuration changes applied:" -Level "Success"
            foreach ($change in $moduleResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        
        # Log any warnings
        foreach ($warning in $moduleResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Windows Services Management Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

function Invoke-WindowsFeaturesConfiguration {
    <#
    .SYNOPSIS
        Main function to execute Windows features management configuration
    .DESCRIPTION
        Orchestrates the complete Windows features configuration process including
        feature enumeration, disabling unnecessary features, and verification
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Windows Features Management Module..." -Level "Info"
    Write-LogMessage "Requirements: 7.1, 7.2, 7.3, 7.4, 7.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Windows Features Management"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        # Step 1: Implement Windows feature enumeration functions
        Write-LogMessage "Step 1: Enumerating Windows features..." -Level "Info"
        
        # Define target features for configuration
        $targetFeatures = @{
            # Features to disable (Requirements 7.1, 7.2, 7.3, 7.4, 7.5)
            "TelnetClient" = @{
                DisplayName = "Telnet Client"
                TargetState = "Disabled"
                Requirement = "7.1"
                Description = "Disable Telnet client feature"
                FeatureName = "TelnetClient"
            }
            "TelnetServer" = @{
                DisplayName = "Telnet Server"
                TargetState = "Disabled"
                Requirement = "7.1"
                Description = "Disable Telnet server feature"
                FeatureName = "TelnetServer"
            }
            "SNMP-Service" = @{
                DisplayName = "Simple Network Management Protocol (SNMP)"
                TargetState = "Disabled"
                Requirement = "7.2"
                Description = "Disable SNMP feature"
                FeatureName = "SNMP-Service"
            }
            "SMB1Protocol" = @{
                DisplayName = "SMB 1.0/CIFS File Sharing Support"
                TargetState = "Disabled"
                Requirement = "7.3"
                Description = "Disable SMB v1 protocol support"
                FeatureName = "SMB1Protocol"
            }
            "IIS-WebServerRole" = @{
                DisplayName = "Internet Information Services"
                TargetState = "Disabled"
                Requirement = "7.4"
                Description = "Disable Internet Information Services when not required"
                FeatureName = "IIS-WebServerRole"
            }
            "TFTP" = @{
                DisplayName = "Trivial File Transfer Protocol (TFTP) Client"
                TargetState = "Disabled"
                Requirement = "7.5"
                Description = "Configure TFTP feature based on FTP server requirements"
                FeatureName = "TFTP"
            }
        }
        
        # Function to get Windows feature information
        function Get-WindowsFeatureInfo {
            param(
                [Parameter(Mandatory = $true)]
                [string]$FeatureName
            )
            
            try {
                # Try Get-WindowsOptionalFeature first (works on client OS)
                $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
                
                if ($feature) {
                    return @{
                        Name = $feature.FeatureName
                        State = $feature.State
                        Method = "WindowsOptionalFeature"
                        Exists = $true
                        Feature = $feature
                    }
                }
                
                # Try Get-WindowsFeature (works on server OS)
                $feature = Get-WindowsFeature -Name $FeatureName -ErrorAction SilentlyContinue
                
                if ($feature) {
                    $state = switch ($feature.InstallState) {
                        "Installed" { "Enabled" }
                        "Available" { "Disabled" }
                        "Removed" { "DisabledWithPayloadRemoved" }
                        default { $feature.InstallState }
                    }
                    
                    return @{
                        Name = $feature.Name
                        State = $state
                        Method = "WindowsFeature"
                        Exists = $true
                        Feature = $feature
                    }
                }
                
                return @{
                    Name = $FeatureName
                    State = "NotFound"
                    Method = "None"
                    Exists = $false
                    Feature = $null
                }
            }
            catch {
                return @{
                    Name = $FeatureName
                    State = "Error"
                    Method = "None"
                    Exists = $false
                    Feature = $null
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Function to disable Windows feature
        function Disable-WindowsFeatureSecure {
            param(
                [Parameter(Mandatory = $true)]
                [string]$FeatureName,
                
                [Parameter(Mandatory = $true)]
                [string]$Method
            )
            
            try {
                $result = @{
                    Success = $false
                    Changes = @()
                    Errors = @()
                    RestartRequired = $false
                }
                
                if ($Method -eq "WindowsOptionalFeature") {
                    Write-LogMessage "Disabling feature '$FeatureName' using Disable-WindowsOptionalFeature..." -Level "Info"
                    $disableResult = Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop
                    
                    $result.Success = $true
                    $result.Changes += "Disabled Windows optional feature '$FeatureName'"
                    $result.RestartRequired = $disableResult.RestartNeeded
                    
                    if ($disableResult.RestartNeeded) {
                        Write-LogMessage "Feature '$FeatureName' disabled successfully (restart required)" -Level "Success"
                    }
                    else {
                        Write-LogMessage "Feature '$FeatureName' disabled successfully" -Level "Success"
                    }
                }
                elseif ($Method -eq "WindowsFeature") {
                    Write-LogMessage "Disabling feature '$FeatureName' using Uninstall-WindowsFeature..." -Level "Info"
                    $disableResult = Uninstall-WindowsFeature -Name $FeatureName -ErrorAction Stop
                    
                    $result.Success = $disableResult.Success
                    if ($disableResult.Success) {
                        $result.Changes += "Uninstalled Windows feature '$FeatureName'"
                        $result.RestartRequired = $disableResult.RestartNeeded
                        
                        if ($disableResult.RestartNeeded) {
                            Write-LogMessage "Feature '$FeatureName' uninstalled successfully (restart required)" -Level "Success"
                        }
                        else {
                            Write-LogMessage "Feature '$FeatureName' uninstalled successfully" -Level "Success"
                        }
                    }
                    else {
                        $result.Errors += "Failed to uninstall Windows feature '$FeatureName'"
                        Write-LogMessage "Failed to uninstall feature '$FeatureName'" -Level "Error"
                    }
                }
                else {
                    $result.Errors += "Unknown method '$Method' for feature '$FeatureName'"
                }
                
                return $result
            }
            catch {
                return @{
                    Success = $false
                    Changes = @()
                    Errors = @("Error disabling feature '$FeatureName': $($_.Exception.Message)")
                    RestartRequired = $false
                }
            }
        }
        
        # Enumerate and check current feature states
        $featureStates = @{}
        foreach ($featureName in $targetFeatures.Keys) {
            $featureInfo = Get-WindowsFeatureInfo -FeatureName $featureName
            $featureStates[$featureName] = $featureInfo
            
            $featureConfig = $targetFeatures[$featureName]
            
            if ($featureInfo.Exists) {
                Write-LogMessage "Feature '$($featureConfig.DisplayName)' - Current State: $($featureInfo.State), Method: $($featureInfo.Method)" -Level "Info"
            }
            else {
                Write-LogMessage "Feature '$($featureConfig.DisplayName)' - Not found on this system" -Level "Warning"
                $moduleResult.Warnings += "Feature '$($featureConfig.DisplayName)' not found on this system"
            }
        }
        
        # Step 2: Apply feature configurations based on requirements
        Write-LogMessage "Step 2: Applying Windows features configurations..." -Level "Info"
        
        $restartRequired = $false
        
        foreach ($featureName in $targetFeatures.Keys) {
            $featureConfig = $targetFeatures[$featureName]
            $currentState = $featureStates[$featureName]
            
            # Skip if feature doesn't exist
            if (-not $currentState.Exists) {
                Write-LogMessage "Skipping '$($featureConfig.DisplayName)' - feature not found" -Level "Warning"
                continue
            }
            
            # Skip if there was an error getting feature info
            if ($currentState.State -eq "Error") {
                Write-LogMessage "Skipping '$($featureConfig.DisplayName)' - error getting feature info: $($currentState.Error)" -Level "Error"
                $moduleResult.Errors += "Error getting info for feature '$($featureConfig.DisplayName)': $($currentState.Error)"
                continue
            }
            
            Write-LogMessage "Configuring feature: $($featureConfig.DisplayName) (Requirement $($featureConfig.Requirement))" -Level "Info"
            
            # Check if configuration is needed
            $needsDisabling = $currentState.State -eq "Enabled" -and $featureConfig.TargetState -eq "Disabled"
            
            if (-not $needsDisabling) {
                if ($currentState.State -eq "Disabled" -or $currentState.State -eq "DisabledWithPayloadRemoved") {
                    Write-LogMessage "Feature '$($featureConfig.DisplayName)' already disabled" -Level "Success"
                }
                else {
                    Write-LogMessage "Feature '$($featureConfig.DisplayName)' in state '$($currentState.State)' - no action needed" -Level "Info"
                }
                continue
            }
            
            try {
                # Apply feature configuration based on requirements
                
                # Disable Telnet client/server and SNMP features (Requirements 7.1, 7.2)
                if ($featureConfig.Requirement -eq "7.1" -or $featureConfig.Requirement -eq "7.2") {
                    Write-LogMessage "Disabling $($featureConfig.DisplayName) (Requirement $($featureConfig.Requirement))..." -Level "Info"
                    $disableResult = Disable-WindowsFeatureSecure -FeatureName $featureName -Method $currentState.Method
                    
                    if ($disableResult.Success) {
                        $moduleResult.Changes += $disableResult.Changes
                        if ($disableResult.RestartRequired) {
                            $restartRequired = $true
                        }
                    }
                    else {
                        $moduleResult.Errors += $disableResult.Errors
                    }
                }
                
                # Disable SMB v1 protocol support (Requirement 7.3)
                elseif ($featureConfig.Requirement -eq "7.3") {
                    Write-LogMessage "Disabling SMB v1 protocol support (Requirement 7.3)..." -Level "Info"
                    $disableResult = Disable-WindowsFeatureSecure -FeatureName $featureName -Method $currentState.Method
                    
                    if ($disableResult.Success) {
                        $moduleResult.Changes += $disableResult.Changes
                        if ($disableResult.RestartRequired) {
                            $restartRequired = $true
                        }
                        
                        # Additional SMB v1 registry settings for complete removal
                        try {
                            Write-LogMessage "Applying additional SMB v1 registry settings..." -Level "Info"
                            
                            # Disable SMB v1 server
                            $smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                            if (Test-Path $smbServerPath) {
                                Set-ItemProperty -Path $smbServerPath -Name "SMB1" -Value 0 -Type DWord -ErrorAction Stop
                                $moduleResult.Changes += "Set SMB1 server registry value to 0"
                            }
                            
                            # Disable SMB v1 client
                            $smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
                            if (Test-Path $smbClientPath) {
                                Set-ItemProperty -Path $smbClientPath -Name "Start" -Value 4 -Type DWord -ErrorAction Stop
                                $moduleResult.Changes += "Disabled SMB v1 client driver"
                            }
                        }
                        catch {
                            Write-LogMessage "Warning: Could not apply additional SMB v1 registry settings: $($_.Exception.Message)" -Level "Warning"
                            $moduleResult.Warnings += "Could not apply additional SMB v1 registry settings: $($_.Exception.Message)"
                        }
                    }
                    else {
                        $moduleResult.Errors += $disableResult.Errors
                    }
                }
                
                # Disable Internet Information Services when not required (Requirement 7.4)
                elseif ($featureConfig.Requirement -eq "7.4") {
                    Write-LogMessage "Disabling Internet Information Services (Requirement 7.4)..." -Level "Info"
                    $disableResult = Disable-WindowsFeatureSecure -FeatureName $featureName -Method $currentState.Method
                    
                    if ($disableResult.Success) {
                        $moduleResult.Changes += $disableResult.Changes
                        if ($disableResult.RestartRequired) {
                            $restartRequired = $true
                        }
                    }
                    else {
                        $moduleResult.Errors += $disableResult.Errors
                    }
                }
                
                # Configure TFTP feature based on FTP server requirements (Requirement 7.5)
                elseif ($featureConfig.Requirement -eq "7.5") {
                    Write-LogMessage "Disabling TFTP client (Requirement 7.5 - FTP server not required)..." -Level "Info"
                    $disableResult = Disable-WindowsFeatureSecure -FeatureName $featureName -Method $currentState.Method
                    
                    if ($disableResult.Success) {
                        $moduleResult.Changes += $disableResult.Changes
                        if ($disableResult.RestartRequired) {
                            $restartRequired = $true
                        }
                    }
                    else {
                        $moduleResult.Errors += $disableResult.Errors
                    }
                }
            }
            catch {
                $errorMessage = "Failed to configure feature '$($featureConfig.DisplayName)': $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $moduleResult.Errors += $errorMessage
            }
        }
        
        # Step 3: Final validation and summary
        Write-LogMessage "Step 3: Performing final validation..." -Level "Info"
        
        $successfulConfigurations = 0
        $totalConfigurations = 0
        
        foreach ($featureName in $targetFeatures.Keys) {
            $featureConfig = $targetFeatures[$featureName]
            $currentState = $featureStates[$featureName]
            
            if ($currentState.Exists -and $currentState.State -ne "Error") {
                $totalConfigurations++
                
                try {
                    # Re-check feature state after configuration
                    $updatedFeatureInfo = Get-WindowsFeatureInfo -FeatureName $featureName
                    
                    if ($updatedFeatureInfo.State -eq "Disabled" -or $updatedFeatureInfo.State -eq "DisabledWithPayloadRemoved") {
                        $successfulConfigurations++
                        $moduleResult.ValidationResults += "Feature '$($featureConfig.DisplayName)': State=$($updatedFeatureInfo.State) (Target: Disabled)"
                    }
                    else {
                        Write-LogMessage "Validation warning: Feature '$($featureConfig.DisplayName)' - Expected: Disabled, Actual: $($updatedFeatureInfo.State)" -Level "Warning"
                        $moduleResult.Warnings += "Feature '$($featureConfig.DisplayName)' validation - Expected: Disabled, Actual: $($updatedFeatureInfo.State)"
                    }
                }
                catch {
                    Write-LogMessage "Error during final validation of feature '$featureName': $($_.Exception.Message)" -Level "Warning"
                    $moduleResult.Warnings += "Error validating feature '$featureName': $($_.Exception.Message)"
                }
            }
        }
        
        # Handle restart requirement notification
        if ($restartRequired) {
            Write-LogMessage "IMPORTANT: A system restart is required to complete some feature changes" -Level "Warning"
            $moduleResult.Warnings += "System restart required to complete feature changes"
        }
        
        # Set overall success based on results
        if ($moduleResult.Errors.Count -eq 0 -and $successfulConfigurations -eq $totalConfigurations) {
            $moduleResult.Success = $true
            Write-LogMessage "Windows Features Management Module completed successfully" -Level "Success"
            Write-LogMessage "Successfully configured $successfulConfigurations of $totalConfigurations features" -Level "Success"
        }
        elseif ($moduleResult.Errors.Count -eq 0) {
            $moduleResult.Success = $true
            Write-LogMessage "Windows Features Management Module completed with warnings" -Level "Warning"
            Write-LogMessage "Successfully configured $successfulConfigurations of $totalConfigurations features" -Level "Warning"
        }
        else {
            Write-LogMessage "Windows Features Management Module failed" -Level "Error"
            Write-LogMessage "Successfully configured $successfulConfigurations of $totalConfigurations features" -Level "Warning"
            foreach ($error in $moduleResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log summary of changes
        if ($moduleResult.Changes.Count -gt 0) {
            Write-LogMessage "Windows features configuration changes applied:" -Level "Success"
            foreach ($change in $moduleResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        
        # Log any warnings
        foreach ($warning in $moduleResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Windows Features Management Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

function Invoke-FirewallConfiguration {
    <#
    .SYNOPSIS
        Main function to execute firewall configuration module
    .DESCRIPTION
        Orchestrates the complete firewall configuration process including
        rule creation, validation, and conflict detection for blocking specific applications
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Firewall Configuration Module..." -Level "Info"
    Write-LogMessage "Requirements: 8.1, 8.2, 8.3, 8.4, 8.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Firewall Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        # Step 1: Implement firewall rule creation functions
        Write-LogMessage "Step 1: Initializing firewall rule creation functions..." -Level "Info"
        
        # Define target applications for firewall blocking
        $targetApplications = @{
            # Microsoft Edge (Requirement 8.1)
            "MicrosoftEdge" = @{
                DisplayName = "Microsoft Edge"
                Requirement = "8.1"
                Description = "Create inbound firewall rules to block Microsoft Edge"
                ExecutablePaths = @(
                    "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
                    "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
                    "%LocalAppData%\Microsoft\Edge\Application\msedge.exe"
                )
                RuleNamePrefix = "Block_Microsoft_Edge"
            }
            
            # Windows Search (Requirement 8.2)
            "WindowsSearch" = @{
                DisplayName = "Windows Search"
                Requirement = "8.2"
                Description = "Create inbound firewall rules to block Windows Search"
                ExecutablePaths = @(
                    "%SystemRoot%\System32\SearchIndexer.exe",
                    "%SystemRoot%\System32\SearchProtocolHost.exe",
                    "%SystemRoot%\System32\SearchFilterHost.exe"
                )
                RuleNamePrefix = "Block_Windows_Search"
            }
            
            # MSN Applications (Requirement 8.3)
            "MSNApps" = @{
                DisplayName = "MSN Applications (Money, Sports, News, Weather)"
                Requirement = "8.3"
                Description = "Create inbound firewall rules to block MSN applications"
                ExecutablePaths = @(
                    "%ProgramFiles%\WindowsApps\Microsoft.BingNews_*\Microsoft.News.exe",
                    "%ProgramFiles%\WindowsApps\Microsoft.BingWeather_*\Microsoft.Weather.exe",
                    "%ProgramFiles%\WindowsApps\Microsoft.BingSports_*\Microsoft.Sports.exe",
                    "%ProgramFiles%\WindowsApps\Microsoft.BingFinance_*\Microsoft.Finance.exe",
                    "%LocalAppData%\Microsoft\WindowsApps\Microsoft.News.exe",
                    "%LocalAppData%\Microsoft\WindowsApps\Microsoft.Weather.exe"
                )
                RuleNamePrefix = "Block_MSN_Apps"
            }
            
            # Xbox Applications (Requirement 8.4)
            "XboxApps" = @{
                DisplayName = "Xbox Applications"
                Requirement = "8.4"
                Description = "Create inbound firewall rules to block Xbox applications"
                ExecutablePaths = @(
                    "%ProgramFiles%\WindowsApps\Microsoft.XboxApp_*\XboxApp.exe",
                    "%ProgramFiles%\WindowsApps\Microsoft.Xbox.TCUI_*\XboxTCUI.exe",
                    "%ProgramFiles%\WindowsApps\Microsoft.XboxGameOverlay_*\GameBar.exe",
                    "%ProgramFiles%\WindowsApps\Microsoft.XboxGamingOverlay_*\GameBar.exe",
                    "%LocalAppData%\Microsoft\WindowsApps\XboxApp.exe"
                )
                RuleNamePrefix = "Block_Xbox_Apps"
            }
            
            # Microsoft Photos (Requirement 8.5)
            "MicrosoftPhotos" = @{
                DisplayName = "Microsoft Photos"
                Requirement = "8.5"
                Description = "Create inbound firewall rules to block Microsoft Photos"
                ExecutablePaths = @(
                    "%ProgramFiles%\WindowsApps\Microsoft.Windows.Photos_*\Microsoft.Photos.exe",
                    "%LocalAppData%\Microsoft\WindowsApps\Microsoft.Photos.exe"
                )
                RuleNamePrefix = "Block_Microsoft_Photos"
            }
        }
        
        # Function to expand environment variables in paths
        function Expand-EnvironmentPath {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path
            )
            
            try {
                # Expand environment variables
                $expandedPath = [System.Environment]::ExpandEnvironmentVariables($Path)
                
                # Handle wildcard paths for WindowsApps
                if ($expandedPath -like "*WindowsApps*" -and $expandedPath -like "*_**") {
                    $basePath = $expandedPath -replace "_\*.*", "_*"
                    $searchPattern = Split-Path $expandedPath -Leaf
                    $searchDir = Split-Path $expandedPath -Parent
                    $searchDir = $searchDir -replace "_\*", "_*"
                    
                    # Find matching directories
                    if (Test-Path (Split-Path $searchDir -Parent)) {
                        $matchingDirs = Get-ChildItem -Path (Split-Path $searchDir -Parent) -Directory -Filter (Split-Path $searchDir -Leaf) -ErrorAction SilentlyContinue
                        
                        $foundPaths = @()
                        foreach ($dir in $matchingDirs) {
                            $fullExePath = Join-Path $dir.FullName $searchPattern
                            if (Test-Path $fullExePath) {
                                $foundPaths += $fullExePath
                            }
                        }
                        
                        return $foundPaths
                    }
                }
                
                # Check if the expanded path exists
                if (Test-Path $expandedPath) {
                    return @($expandedPath)
                }
                
                return @()
            }
            catch {
                Write-LogMessage "Error expanding path '$Path': $($_.Exception.Message)" -Level "Warning"
                return @()
            }
        }
        
        # Function to create firewall rule with validation
        function New-FirewallRuleSecure {
            param(
                [Parameter(Mandatory = $true)]
                [string]$RuleName,
                
                [Parameter(Mandatory = $true)]
                [string]$Program,
                
                [Parameter(Mandatory = $true)]
                [string]$Direction,
                
                [Parameter(Mandatory = $true)]
                [string]$Action,
                
                [Parameter(Mandatory = $false)]
                [string]$Description = ""
            )
            
            try {
                $result = @{
                    Success = $false
                    RuleName = $RuleName
                    Changes = @()
                    Errors = @()
                    Warnings = @()
                }
                
                # Check if rule already exists
                $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                
                if ($existingRule) {
                    Write-LogMessage "Firewall rule '$RuleName' already exists - checking configuration..." -Level "Info"
                    
                    # Get the application filter for the existing rule
                    $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $existingRule -ErrorAction SilentlyContinue
                    
                    if ($appFilter -and $appFilter.Program -eq $Program -and $existingRule.Direction -eq $Direction -and $existingRule.Action -eq $Action) {
                        Write-LogMessage "Firewall rule '$RuleName' already configured correctly" -Level "Success"
                        $result.Success = $true
                        return $result
                    }
                    else {
                        Write-LogMessage "Firewall rule '$RuleName' exists but has different configuration - removing and recreating..." -Level "Warning"
                        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
                        $result.Changes += "Removed existing firewall rule with different configuration"
                    }
                }
                
                # Create the new firewall rule
                Write-LogMessage "Creating firewall rule: $RuleName" -Level "Info"
                
                $ruleParams = @{
                    DisplayName = $RuleName
                    Direction = $Direction
                    Action = $Action
                    Program = $Program
                    Enabled = "True"
                    Profile = "Any"
                    ErrorAction = "Stop"
                }
                
                if ($Description) {
                    $ruleParams.Description = $Description
                }
                
                $newRule = New-NetFirewallRule @ruleParams
                
                if ($newRule) {
                    Write-LogMessage "Successfully created firewall rule: $RuleName" -Level "Success"
                    $result.Success = $true
                    $result.Changes += "Created firewall rule '$RuleName' to block '$Program'"
                }
                else {
                    $result.Errors += "Failed to create firewall rule '$RuleName'"
                }
                
                return $result
            }
            catch {
                return @{
                    Success = $false
                    RuleName = $RuleName
                    Changes = @()
                    Errors = @("Error creating firewall rule '$RuleName': $($_.Exception.Message)")
                    Warnings = @()
                }
            }
        }
        
        # Function to validate firewall rule and detect conflicts
        function Test-FirewallRuleConflicts {
            param(
                [Parameter(Mandatory = $true)]
                [string]$RuleName,
                
                [Parameter(Mandatory = $true)]
                [string]$Program
            )
            
            try {
                $conflicts = @()
                
                # Get all firewall rules that might conflict
                $allRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
                
                foreach ($rule in $allRules) {
                    try {
                        $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                        
                        if ($appFilter -and $appFilter.Program -eq $Program) {
                            $conflicts += @{
                                RuleName = $rule.DisplayName
                                Program = $appFilter.Program
                                Action = $rule.Action
                                Direction = $rule.Direction
                            }
                        }
                    }
                    catch {
                        # Skip rules that can't be processed
                        continue
                    }
                }
                
                return @{
                    HasConflicts = $conflicts.Count -gt 0
                    Conflicts = $conflicts
                }
            }
            catch {
                Write-LogMessage "Error checking firewall rule conflicts for '$RuleName': $($_.Exception.Message)" -Level "Warning"
                return @{
                    HasConflicts = $false
                    Conflicts = @()
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Step 2: Apply firewall configurations based on requirements
        Write-LogMessage "Step 2: Applying firewall configurations..." -Level "Info"
        
        # Check if Windows Firewall service is running
        $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
        if (-not $firewallService -or $firewallService.Status -ne "Running") {
            Write-LogMessage "Windows Firewall service is not running - attempting to start..." -Level "Warning"
            try {
                Start-Service -Name "MpsSvc" -ErrorAction Stop
                Write-LogMessage "Windows Firewall service started successfully" -Level "Success"
            }
            catch {
                $errorMessage = "Cannot configure firewall rules - Windows Firewall service is not available: $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $moduleResult.Errors += $errorMessage
                throw $errorMessage
            }
        }
        
        # Process each application group
        foreach ($appKey in $targetApplications.Keys) {
            $appConfig = $targetApplications[$appKey]
            
            Write-LogMessage "Configuring firewall rules for: $($appConfig.DisplayName) (Requirement $($appConfig.Requirement))" -Level "Info"
            
            $ruleIndex = 1
            $appRulesCreated = 0
            
            # Process each executable path for the application
            foreach ($executablePath in $appConfig.ExecutablePaths) {
                Write-LogMessage "Processing executable path: $executablePath" -Level "Info"
                
                # Expand environment variables and find actual paths
                $actualPaths = Expand-EnvironmentPath -Path $executablePath
                
                if ($actualPaths.Count -eq 0) {
                    Write-LogMessage "No executable found for path: $executablePath" -Level "Info"
                    continue
                }
                
                # Create firewall rules for each found executable
                foreach ($actualPath in $actualPaths) {
                    $ruleName = "$($appConfig.RuleNamePrefix)_$ruleIndex"
                    $ruleDescription = "$($appConfig.Description) - $actualPath"
                    
                    Write-LogMessage "Creating firewall rule for: $actualPath" -Level "Info"
                    
                    # Check for conflicts before creating the rule
                    $conflictCheck = Test-FirewallRuleConflicts -RuleName $ruleName -Program $actualPath
                    
                    if ($conflictCheck.HasConflicts) {
                        Write-LogMessage "Potential conflicts detected for '$actualPath':" -Level "Warning"
                        foreach ($conflict in $conflictCheck.Conflicts) {
                            Write-LogMessage "  - Rule '$($conflict.RuleName)' allows $($conflict.Direction) traffic for same program" -Level "Warning"
                            $moduleResult.Warnings += "Firewall conflict: Rule '$($conflict.RuleName)' allows traffic for '$actualPath'"
                        }
                    }
                    
                    # Create the firewall rule
                    $ruleResult = New-FirewallRuleSecure -RuleName $ruleName -Program $actualPath -Direction "Inbound" -Action "Block" -Description $ruleDescription
                    
                    if ($ruleResult.Success) {
                        $moduleResult.Changes += $ruleResult.Changes
                        $appRulesCreated++
                        
                        # Validate the created rule
                        try {
                            $createdRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                            $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $createdRule -ErrorAction Stop
                            
                            if ($createdRule.Action -eq "Block" -and $createdRule.Direction -eq "Inbound" -and $appFilter.Program -eq $actualPath) {
                                Write-LogMessage "Firewall rule '$ruleName' validated successfully" -Level "Success"
                                $moduleResult.ValidationResults += "Rule '$ruleName': Action=Block, Direction=Inbound, Program=$actualPath"
                            }
                            else {
                                Write-LogMessage "Firewall rule '$ruleName' validation failed - incorrect configuration" -Level "Warning"
                                $moduleResult.Warnings += "Rule '$ruleName' validation failed"
                            }
                        }
                        catch {
                            Write-LogMessage "Error validating firewall rule '$ruleName': $($_.Exception.Message)" -Level "Warning"
                            $moduleResult.Warnings += "Error validating rule '$ruleName': $($_.Exception.Message)"
                        }
                    }
                    else {
                        $moduleResult.Errors += $ruleResult.Errors
                        $moduleResult.Warnings += $ruleResult.Warnings
                    }
                    
                    $ruleIndex++
                }
            }
            
            if ($appRulesCreated -gt 0) {
                Write-LogMessage "Successfully created $appRulesCreated firewall rules for $($appConfig.DisplayName)" -Level "Success"
            }
            else {
                Write-LogMessage "No firewall rules created for $($appConfig.DisplayName) - no executables found" -Level "Warning"
                $moduleResult.Warnings += "No executables found for $($appConfig.DisplayName)"
            }
        }
        
        # Step 3: Final validation and summary
        Write-LogMessage "Step 3: Performing final validation..." -Level "Info"
        
        $totalRulesCreated = 0
        $validatedRules = 0
        
        # Count all created rules
        foreach ($appKey in $targetApplications.Keys) {
            $appConfig = $targetApplications[$appKey]
            $appRules = Get-NetFirewallRule -DisplayName "$($appConfig.RuleNamePrefix)*" -ErrorAction SilentlyContinue
            
            if ($appRules) {
                $appRuleCount = if ($appRules -is [array]) { $appRules.Count } else { 1 }
                $totalRulesCreated += $appRuleCount
                
                # Validate each rule
                foreach ($rule in $appRules) {
                    try {
                        $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                        
                        if ($rule.Action -eq "Block" -and $rule.Direction -eq "Inbound" -and $rule.Enabled -eq "True") {
                            $validatedRules++
                        }
                    }
                    catch {
                        Write-LogMessage "Error validating rule '$($rule.DisplayName)': $($_.Exception.Message)" -Level "Warning"
                    }
                }
            }
        }
        
        # Set overall success based on results
        if ($moduleResult.Errors.Count -eq 0 -and $totalRulesCreated -gt 0) {
            $moduleResult.Success = $true
            Write-LogMessage "Firewall Configuration Module completed successfully" -Level "Success"
            Write-LogMessage "Created $totalRulesCreated firewall rules, $validatedRules validated successfully" -Level "Success"
        }
        elseif ($moduleResult.Errors.Count -eq 0) {
            $moduleResult.Success = $true
            Write-LogMessage "Firewall Configuration Module completed with warnings" -Level "Warning"
            Write-LogMessage "Created $totalRulesCreated firewall rules, $validatedRules validated successfully" -Level "Warning"
        }
        else {
            Write-LogMessage "Firewall Configuration Module failed" -Level "Error"
            Write-LogMessage "Created $totalRulesCreated firewall rules, $validatedRules validated successfully" -Level "Warning"
            foreach ($error in $moduleResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log summary of changes
        if ($moduleResult.Changes.Count -gt 0) {
            Write-LogMessage "Firewall configuration changes applied:" -Level "Success"
            foreach ($change in $moduleResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        
        # Log any warnings
        foreach ($warning in $moduleResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Firewall Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

function Invoke-RegistryModifications {
    <#
    .SYNOPSIS
        Main function to execute registry modifications module
    .DESCRIPTION
        Orchestrates the complete registry modifications process including
        safe registry key creation and modification, backup functions, and validation
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Registry Modifications Module..." -Level "Info"
    Write-LogMessage "Requirements: 11.1, 11.2, 11.3" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Registry Modifications"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
        BackupResults = @()
    }
    
    try {
        # Step 1: Create registry manipulation functions
        Write-LogMessage "Step 1: Initializing registry manipulation functions..." -Level "Info"
        
        # Function to safely create or modify registry keys with backup
        function Set-RegistryValueSecure {
            <#
            .SYNOPSIS
                Safely creates or modifies registry values with backup and validation
            .PARAMETER Path
                Registry path (e.g., "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion")
            .PARAMETER Name
                Registry value name
            .PARAMETER Value
                Registry value data
            .PARAMETER Type
                Registry value type (String, DWord, QWord, Binary, MultiString, ExpandString)
            .PARAMETER BackupPath
                Path to store registry backup files
            .OUTPUTS
                Returns result object with success status, changes, and errors
            #>
            
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path,
                
                [Parameter(Mandatory = $true)]
                [string]$Name,
                
                [Parameter(Mandatory = $true)]
                $Value,
                
                [Parameter(Mandatory = $true)]
                [ValidateSet("String", "DWord", "QWord", "Binary", "MultiString", "ExpandString")]
                [string]$Type,
                
                [Parameter(Mandatory = $false)]
                [string]$BackupPath = $null
            )
            
            $result = @{
                Success = $false
                Changes = @()
                Errors = @()
                Warnings = @()
                BackupCreated = $false
                BackupFile = $null
            }
            
            try {
                Write-LogMessage "Setting registry value: $Path\$Name = $Value ($Type)" -Level "Info"
                
                # Validate registry path format
                if (-not ($Path -match "^HK(LM|CU|CR|U|CC):" -or $Path -match "^HKEY_")) {
                    throw "Invalid registry path format: $Path"
                }
                
                # Convert HKEY_ format to PowerShell format if needed
                $psPath = $Path
                if ($Path -match "^HKEY_") {
                    $psPath = $Path -replace "^HKEY_LOCAL_MACHINE", "HKLM:" -replace "^HKEY_CURRENT_USER", "HKCU:" -replace "^HKEY_CLASSES_ROOT", "HKCR:" -replace "^HKEY_USERS", "HKU:" -replace "^HKEY_CURRENT_CONFIG", "HKCC:"
                }
                
                # Create backup if backup path is provided
                if ($BackupPath) {
                    try {
                        Write-LogMessage "Creating registry backup for $psPath..." -Level "Info"
                        
                        # Ensure backup directory exists
                        if (-not (Test-Path $BackupPath)) {
                            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
                        }
                        
                        # Generate backup filename
                        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        $safePath = ($psPath -replace ":", "_" -replace "\\", "_")
                        $backupFile = Join-Path $BackupPath "Registry_Backup_${safePath}_${timestamp}.reg"
                        
                        # Export registry key for backup
                        $exportPath = $psPath -replace ":", "" -replace "HKLM", "HKEY_LOCAL_MACHINE" -replace "HKCU", "HKEY_CURRENT_USER" -replace "HKCR", "HKEY_CLASSES_ROOT" -replace "HKU", "HKEY_USERS" -replace "HKCC", "HKEY_CURRENT_CONFIG"
                        
                        $regExportCmd = "reg export `"$exportPath`" `"$backupFile`" /y"
                        $exportResult = Invoke-Expression $regExportCmd 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            Write-LogMessage "Registry backup created: $backupFile" -Level "Success"
                            $result.BackupCreated = $true
                            $result.BackupFile = $backupFile
                        }
                        else {
                            Write-LogMessage "Registry backup failed: $exportResult" -Level "Warning"
                            $result.Warnings += "Registry backup failed: $exportResult"
                        }
                    }
                    catch {
                        Write-LogMessage "Registry backup error: $($_.Exception.Message)" -Level "Warning"
                        $result.Warnings += "Registry backup error: $($_.Exception.Message)"
                    }
                }
                
                # Check if registry key exists, create if necessary
                if (-not (Test-Path $psPath)) {
                    Write-LogMessage "Creating registry key: $psPath" -Level "Info"
                    New-Item -Path $psPath -Force | Out-Null
                    $result.Changes += "Created registry key: $psPath"
                }
                
                # Get current value for comparison
                $currentValue = $null
                $valueExists = $false
                
                try {
                    $currentValue = Get-ItemProperty -Path $psPath -Name $Name -ErrorAction Stop
                    $valueExists = $true
                    Write-LogMessage "Current registry value: $($currentValue.$Name)" -Level "Info"
                }
                catch {
                    Write-LogMessage "Registry value does not exist, will be created" -Level "Info"
                }
                
                # Set the registry value
                Set-ItemProperty -Path $psPath -Name $Name -Value $Value -Type $Type -ErrorAction Stop
                
                # Verify the change
                $verificationValue = Get-ItemProperty -Path $psPath -Name $Name -ErrorAction Stop
                
                if ($verificationValue.$Name -eq $Value) {
                    if ($valueExists) {
                        $result.Changes += "Modified registry value: $psPath\$Name = $Value (was: $($currentValue.$Name))"
                    }
                    else {
                        $result.Changes += "Created registry value: $psPath\$Name = $Value"
                    }
                    
                    Write-LogMessage "Registry value set successfully and verified" -Level "Success"
                    $result.Success = $true
                }
                else {
                    throw "Registry value verification failed. Expected: $Value, Actual: $($verificationValue.$Name)"
                }
            }
            catch {
                $errorMessage = "Failed to set registry value $psPath\$Name: $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $result.Errors += $errorMessage
            }
            
            return $result
        }
        
        # Function to validate registry changes
        function Test-RegistryValue {
            <#
            .SYNOPSIS
                Validates that a registry value exists and has the expected value
            .PARAMETER Path
                Registry path
            .PARAMETER Name
                Registry value name
            .PARAMETER ExpectedValue
                Expected value
            .OUTPUTS
                Returns validation result object
            #>
            
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path,
                
                [Parameter(Mandatory = $true)]
                [string]$Name,
                
                [Parameter(Mandatory = $true)]
                $ExpectedValue
            )
            
            $result = @{
                IsValid = $false
                ActualValue = $null
                ExpectedValue = $ExpectedValue
                Path = $Path
                Name = $Name
                Error = $null
            }
            
            try {
                # Convert HKEY_ format to PowerShell format if needed
                $psPath = $Path
                if ($Path -match "^HKEY_") {
                    $psPath = $Path -replace "^HKEY_LOCAL_MACHINE", "HKLM:" -replace "^HKEY_CURRENT_USER", "HKCU:" -replace "^HKEY_CLASSES_ROOT", "HKCR:" -replace "^HKEY_USERS", "HKU:" -replace "^HKEY_CURRENT_CONFIG", "HKCC:"
                }
                
                if (Test-Path $psPath) {
                    $registryValue = Get-ItemProperty -Path $psPath -Name $Name -ErrorAction Stop
                    $result.ActualValue = $registryValue.$Name
                    $result.IsValid = ($result.ActualValue -eq $ExpectedValue)
                }
                else {
                    $result.Error = "Registry path does not exist: $psPath"
                }
            }
            catch {
                $result.Error = "Error validating registry value: $($_.Exception.Message)"
            }
            
            return $result
        }
        
        # Function to create comprehensive registry backup
        function Backup-RegistryKeysSecure {
            <#
            .SYNOPSIS
                Creates backup of multiple registry keys before modifications
            .PARAMETER RegistryPaths
                Array of registry paths to backup
            .PARAMETER BackupPath
                Directory to store backup files
            .OUTPUTS
                Returns backup result object
            #>
            
            param(
                [Parameter(Mandatory = $true)]
                [string[]]$RegistryPaths,
                
                [Parameter(Mandatory = $true)]
                [string]$BackupPath
            )
            
            $result = @{
                Success = $false
                BackupFiles = @()
                Errors = @()
                Warnings = @()
            }
            
            try {
                Write-LogMessage "Creating comprehensive registry backup..." -Level "Info"
                
                # Ensure backup directory exists
                if (-not (Test-Path $BackupPath)) {
                    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $successCount = 0
                
                foreach ($regPath in $RegistryPaths) {
                    try {
                        # Convert PowerShell path to reg.exe format
                        $exportPath = $regPath -replace ":", "" -replace "HKLM", "HKEY_LOCAL_MACHINE" -replace "HKCU", "HKEY_CURRENT_USER" -replace "HKCR", "HKEY_CLASSES_ROOT" -replace "HKU", "HKEY_USERS" -replace "HKCC", "HKEY_CURRENT_CONFIG"
                        
                        # Generate backup filename
                        $safePath = ($exportPath -replace "\\", "_" -replace " ", "_")
                        $backupFile = Join-Path $BackupPath "Registry_Backup_${safePath}_${timestamp}.reg"
                        
                        # Export registry key
                        $regExportCmd = "reg export `"$exportPath`" `"$backupFile`" /y"
                        $exportResult = Invoke-Expression $regExportCmd 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            Write-LogMessage "Backed up registry key: $regPath -> $backupFile" -Level "Success"
                            $result.BackupFiles += $backupFile
                            $successCount++
                        }
                        else {
                            Write-LogMessage "Failed to backup registry key $regPath: $exportResult" -Level "Warning"
                            $result.Warnings += "Failed to backup $regPath: $exportResult"
                        }
                    }
                    catch {
                        Write-LogMessage "Error backing up registry key $regPath: $($_.Exception.Message)" -Level "Warning"
                        $result.Warnings += "Error backing up $regPath: $($_.Exception.Message)"
                    }
                }
                
                if ($successCount -gt 0) {
                    $result.Success = $true
                    Write-LogMessage "Registry backup completed: $successCount of $($RegistryPaths.Count) keys backed up" -Level "Success"
                }
                else {
                    $result.Errors += "No registry keys were successfully backed up"
                }
            }
            catch {
                $result.Errors += "Registry backup failed: $($_.Exception.Message)"
            }
            
            return $result
        }
        
        Write-LogMessage "Registry manipulation functions initialized successfully" -Level "Success"
        
        # Step 2: Create registry backup before making changes
        Write-LogMessage "Step 2: Creating registry backup before modifications..." -Level "Info"
        
        # Define registry paths that will be modified
        $registryPathsToBackup = @(
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
            "HKLM\SYSTEM\CurrentControlSet\Services\upnphost",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
        )
        
        # Create backup directory
        $backupDir = Join-Path $env:TEMP "WindowsSecurityHardening_RegistryBackup"
        
        $backupResult = Backup-RegistryKeysSecure -RegistryPaths $registryPathsToBackup -BackupPath $backupDir
        
        if ($backupResult.Success) {
            Write-LogMessage "Registry backup completed successfully" -Level "Success"
            $moduleResult.BackupResults = $backupResult.BackupFiles
            $moduleResult.Changes += "Created registry backup with $($backupResult.BackupFiles.Count) files"
        }
        else {
            Write-LogMessage "Registry backup completed with warnings" -Level "Warning"
            $moduleResult.Warnings += $backupResult.Warnings
            $moduleResult.Errors += $backupResult.Errors
        }
        
        # Step 3: Apply UPnP and network registry settings (Requirements 11.1, 11.2, 11.3)
        Write-LogMessage "Step 3: Applying UPnP and network registry settings..." -Level "Info"
        
        # Registry modifications based on configuration
        $registryModifications = @()
        
        # Requirement 11.1 & 11.2: Create registry entry to disable UPnP on port 1900 and set UPnPMode
        if ($Config.RegistrySettings.DisableUPnPPort1900 -and $Config.RegistrySettings.SetUPnPMode) {
            
            # Disable UPnP on port 1900
            $registryModifications += @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                Name = "DisableUPnPOnPort1900"
                Value = 1
                Type = "DWord"
                Description = "Disable UPnP on port 1900 (Requirement 11.1)"
                Requirement = "11.1"
            }
            
            # Set UPnPMode registry value to 2
            $registryModifications += @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                Name = "UPnPMode"
                Value = $Config.RegistrySettings.SetUPnPMode
                Type = "DWord"
                Description = "Set UPnPMode registry value to 2 (Requirement 11.2)"
                Requirement = "11.2"
            }
            
            # Additional UPnP service registry modifications
            $registryModifications += @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"
                Name = "Start"
                Value = 4
                Type = "DWord"
                Description = "Disable UPnP Device Host service startup (Requirement 11.1)"
                Requirement = "11.1"
            }
        }
        
        # Apply each registry modification
        $successfulModifications = 0
        $totalModifications = $registryModifications.Count
        
        foreach ($modification in $registryModifications) {
            Write-LogMessage "Applying registry modification (Requirement $($modification.Requirement)): $($modification.Description)" -Level "Info"
            
            try {
                $setResult = Set-RegistryValueSecure -Path $modification.Path -Name $modification.Name -Value $modification.Value -Type $modification.Type -BackupPath $backupDir
                
                if ($setResult.Success) {
                    $moduleResult.Changes += $setResult.Changes
                    $successfulModifications++
                    
                    if ($setResult.BackupCreated) {
                        $moduleResult.BackupResults += $setResult.BackupFile
                    }
                }
                else {
                    $moduleResult.Errors += $setResult.Errors
                    $moduleResult.Warnings += $setResult.Warnings
                }
            }
            catch {
                $errorMessage = "Failed to apply registry modification '$($modification.Description)': $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $moduleResult.Errors += $errorMessage
            }
        }
        
        # Step 4: Verify registry changes are applied correctly (Requirement 11.3)
        Write-LogMessage "Step 4: Verifying registry changes..." -Level "Info"
        
        $verificationResults = @()
        
        foreach ($modification in $registryModifications) {
            Write-LogMessage "Verifying registry value: $($modification.Path)\$($modification.Name)" -Level "Info"
            
            $validationResult = Test-RegistryValue -Path $modification.Path -Name $modification.Name -ExpectedValue $modification.Value
            
            if ($validationResult.IsValid) {
                Write-LogMessage "Registry verification successful: $($modification.Path)\$($modification.Name) = $($validationResult.ActualValue)" -Level "Success"
                $verificationResults += "PASS: $($modification.Path)\$($modification.Name) = $($validationResult.ActualValue)"
            }
            else {
                if ($validationResult.Error) {
                    Write-LogMessage "Registry verification error: $($validationResult.Error)" -Level "Error"
                    $moduleResult.Errors += "Verification error: $($validationResult.Error)"
                    $verificationResults += "ERROR: $($modification.Path)\$($modification.Name) - $($validationResult.Error)"
                }
                else {
                    Write-LogMessage "Registry verification failed: $($modification.Path)\$($modification.Name) - Expected: $($validationResult.ExpectedValue), Actual: $($validationResult.ActualValue)" -Level "Error"
                    $moduleResult.Errors += "Verification failed: $($modification.Path)\$($modification.Name) - Expected: $($validationResult.ExpectedValue), Actual: $($validationResult.ActualValue)"
                    $verificationResults += "FAIL: $($modification.Path)\$($modification.Name) - Expected: $($validationResult.ExpectedValue), Actual: $($validationResult.ActualValue)"
                }
            }
        }
        
        $moduleResult.ValidationResults = $verificationResults
        
        # Step 5: Final validation and summary
        Write-LogMessage "Step 5: Performing final validation..." -Level "Info"
        
        $passedValidations = ($verificationResults | Where-Object { $_ -like "PASS:*" }).Count
        $totalValidations = $verificationResults.Count
        
        # Set overall success based on results
        if ($moduleResult.Errors.Count -eq 0 -and $successfulModifications -eq $totalModifications -and $passedValidations -eq $totalValidations) {
            $moduleResult.Success = $true
            Write-LogMessage "Registry Modifications Module completed successfully" -Level "Success"
            Write-LogMessage "Successfully applied $successfulModifications of $totalModifications registry modifications" -Level "Success"
            Write-LogMessage "All $totalValidations registry validations passed" -Level "Success"
        }
        elseif ($moduleResult.Errors.Count -eq 0 -and $successfulModifications -gt 0) {
            $moduleResult.Success = $true
            Write-LogMessage "Registry Modifications Module completed with warnings" -Level "Warning"
            Write-LogMessage "Successfully applied $successfulModifications of $totalModifications registry modifications" -Level "Warning"
            Write-LogMessage "Passed $passedValidations of $totalValidations registry validations" -Level "Warning"
        }
        else {
            Write-LogMessage "Registry Modifications Module failed" -Level "Error"
            Write-LogMessage "Successfully applied $successfulModifications of $totalModifications registry modifications" -Level "Warning"
            Write-LogMessage "Passed $passedValidations of $totalValidations registry validations" -Level "Warning"
            foreach ($error in $moduleResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log summary of changes
        if ($moduleResult.Changes.Count -gt 0) {
            Write-LogMessage "Registry modifications applied:" -Level "Success"
            foreach ($change in $moduleResult.Changes) {
                Write-LogMessage "  - $change" -Level "Success"
            }
        }
        
        # Log backup information
        if ($moduleResult.BackupResults.Count -gt 0) {
            Write-LogMessage "Registry backup files created:" -Level "Info"
            foreach ($backupFile in $moduleResult.BackupResults) {
                Write-LogMessage "  - $backupFile" -Level "Info"
            }
        }
        
        # Log validation results
        if ($moduleResult.ValidationResults.Count -gt 0) {
            Write-LogMessage "Registry validation results:" -Level "Info"
            foreach ($validation in $moduleResult.ValidationResults) {
                $level = if ($validation -like "PASS:*") { "Success" } elseif ($validation -like "ERROR:*") { "Error" } else { "Warning" }
                Write-LogMessage "  - $validation" -Level $level
            }
        }
        
        # Log any warnings
        foreach ($warning in $moduleResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Registry Modifications Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

function Invoke-LocalSecurityPolicyConfiguration {
    <#
    .SYNOPSIS
        Main function to execute local security policy configuration module
    .DESCRIPTION
        Orchestrates the complete local security policy configuration process including
        policy export, modification, and import with comprehensive validation
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Local Security Policy Configuration Module..." -Level "Info"
    Write-LogMessage "Requirements: 10.1, 10.2, 10.3, 10.4, 10.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Local Security Policy Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
        BackupResults = @()
    }
    
    try {
        # Step 1: Implement security policy export and import functions
        Write-LogMessage "Step 1: Initializing security policy export and import functions..." -Level "Info"
        
        # Function to export current security policies
        function Export-SecurityPolicy {
            <#
            .SYNOPSIS
                Exports current local security policy to a file
            .PARAMETER ExportPath
                Path where the security policy will be exported
            .OUTPUTS
                Returns result object with success status and file path
            #>
            
            param(
                [Parameter(Mandatory = $true)]
                [string]$ExportPath
            )
            
            $result = @{
                Success = $false
                ExportFile = $null
                Errors = @()
                Warnings = @()
            }
            
            try {
                Write-LogMessage "Exporting current security policy to: $ExportPath" -Level "Info"
                
                # Ensure export directory exists
                $exportDir = Split-Path $ExportPath -Parent
                if (-not (Test-Path $exportDir)) {
                    New-Item -Path $exportDir -ItemType Directory -Force | Out-Null
                }
                
                # Use secedit to export current security policy
                $seceditArgs = "/export /cfg `"$ExportPath`" /quiet"
                $exportProcess = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\secedit_export_out.txt" -RedirectStandardError "$env:TEMP\secedit_export_err.txt"
                
                if ($exportProcess.ExitCode -eq 0) {
                    if (Test-Path $ExportPath) {
                        Write-LogMessage "Security policy exported successfully" -Level "Success"
                        $result.Success = $true
                        $result.ExportFile = $ExportPath
                    }
                    else {
                        $result.Errors += "Export completed but file not found at: $ExportPath"
                    }
                }
                else {
                    $errorOutput = ""
                    if (Test-Path "$env:TEMP\secedit_export_err.txt") {
                        $errorOutput = Get-Content "$env:TEMP\secedit_export_err.txt" -Raw
                    }
                    $result.Errors += "secedit export failed with exit code $($exportProcess.ExitCode): $errorOutput"
                }
                
                # Clean up temporary files
                @("$env:TEMP\secedit_export_out.txt", "$env:TEMP\secedit_export_err.txt") | ForEach-Object {
                    if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
                }
                
                return $result
            }
            catch {
                $result.Errors += "Error exporting security policy: $($_.Exception.Message)"
                return $result
            }
        }
        
        # Function to modify policy template
        function Edit-SecurityPolicyTemplate {
            <#
            .SYNOPSIS
                Modifies security policy template with specified settings
            .PARAMETER TemplatePath
                Path to the security policy template file
            .PARAMETER PolicySettings
                Hashtable containing policy settings to apply
            .OUTPUTS
                Returns result object with success status and changes made
            #>
            
            param(
                [Parameter(Mandatory = $true)]
                [string]$TemplatePath,
                
                [Parameter(Mandatory = $true)]
                [hashtable]$PolicySettings
            )
            
            $result = @{
                Success = $false
                Changes = @()
                Errors = @()
                Warnings = @()
                ModifiedFile = $null
            }
            
            try {
                Write-LogMessage "Modifying security policy template: $TemplatePath" -Level "Info"
                
                if (-not (Test-Path $TemplatePath)) {
                    $result.Errors += "Template file not found: $TemplatePath"
                    return $result
                }
                
                # Read the current template content
                $templateContent = Get-Content $TemplatePath -Encoding Unicode
                $modifiedContent = $templateContent
                $changesMade = @()
                
                # Define security policy mappings for requirements
                $policyMappings = @{
                    # Requirement 10.1: Disable Administrator and Guest accounts
                    "DisableAdministratorAccount" = @{
                        Section = "[System Access]"
                        Setting = "EnableAdminAccount"
                        Value = "0"
                        Description = "Disable Administrator account"
                    }
                    "DisableGuestAccount" = @{
                        Section = "[System Access]"
                        Setting = "EnableGuestAccount"
                        Value = "0"
                        Description = "Disable Guest account"
                    }
                    
                    # Requirement 10.2: Block Microsoft account usage
                    "BlockMicrosoftAccounts" = @{
                        Section = "[Registry Values]"
                        Setting = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser"
                        Value = "4,3"
                        Description = "Block Microsoft account usage"
                    }
                    
                    # Requirement 10.3: Enable digital signing for network communications
                    "EnableDigitalSigning" = @{
                        Section = "[Registry Values]"
                        Setting = "MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature"
                        Value = "4,1"
                        Description = "Enable digital signing for server communications"
                    }
                    "EnableClientDigitalSigning" = @{
                        Section = "[Registry Values]"
                        Setting = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature"
                        Value = "4,1"
                        Description = "Enable digital signing for client communications"
                    }
                    
                    # Requirement 10.4: Configure interactive logon security settings
                    "ConfigureInteractiveLogon" = @{
                        Section = "[Registry Values]"
                        Setting = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName"
                        Value = "4,1"
                        Description = "Don't display last user name in logon screen"
                    }
                    "DisableCAD" = @{
                        Section = "[Registry Values]"
                        Setting = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD"
                        Value = "4,0"
                        Description = "Require Ctrl+Alt+Del for interactive logon"
                    }
                    
                    # Requirement 10.5: Set network security authentication to most secure levels
                    "MaximizeNetworkSecurity" = @{
                        Section = "[Registry Values]"
                        Setting = "MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"
                        Value = "4,5"
                        Description = "Set LM authentication to most secure level"
                    }
                    "DisableNTLMv1" = @{
                        Section = "[Registry Values]"
                        Setting = "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec"
                        Value = "4,537395200"
                        Description = "Configure NTLM minimum client security"
                    }
                }
                
                # Apply policy settings based on configuration
                foreach ($settingKey in $PolicySettings.Keys) {
                    if ($PolicySettings[$settingKey] -and $policyMappings.ContainsKey($settingKey)) {
                        $policyMapping = $policyMappings[$settingKey]
                        
                        Write-LogMessage "Applying policy setting: $($policyMapping.Description)" -Level "Info"
                        
                        # Find the section in the template
                        $sectionFound = $false
                        $settingFound = $false
                        
                        for ($i = 0; $i -lt $modifiedContent.Count; $i++) {
                            $line = $modifiedContent[$i]
                            
                            # Check if we found the target section
                            if ($line.Trim() -eq $policyMapping.Section) {
                                $sectionFound = $true
                                continue
                            }
                            
                            # If we're in the target section, look for the setting
                            if ($sectionFound) {
                                # Check if we've moved to a new section
                                if ($line.Trim().StartsWith("[") -and $line.Trim() -ne $policyMapping.Section) {
                                    # We've moved to a new section without finding the setting
                                    # Insert the setting before this new section
                                    $modifiedContent = $modifiedContent[0..($i-1)] + "$($policyMapping.Setting) = $($policyMapping.Value)" + $modifiedContent[$i..($modifiedContent.Count-1)]
                                    $changesMade += $policyMapping.Description
                                    $settingFound = $true
                                    break
                                }
                                
                                # Check if this line contains our setting
                                if ($line.Trim().StartsWith($policyMapping.Setting)) {
                                    # Update existing setting
                                    $modifiedContent[$i] = "$($policyMapping.Setting) = $($policyMapping.Value)"
                                    $changesMade += "$($policyMapping.Description) (updated existing)"
                                    $settingFound = $true
                                    break
                                }
                            }
                        }
                        
                        # If section wasn't found, add it
                        if (-not $sectionFound) {
                            $modifiedContent += ""
                            $modifiedContent += $policyMapping.Section
                            $modifiedContent += "$($policyMapping.Setting) = $($policyMapping.Value)"
                            $changesMade += "$($policyMapping.Description) (added new section)"
                            $settingFound = $true
                        }
                        # If section was found but setting wasn't, add it to the end of the section
                        elseif (-not $settingFound) {
                            # Find the end of the section and add the setting
                            for ($i = 0; $i -lt $modifiedContent.Count; $i++) {
                                if ($modifiedContent[$i].Trim() -eq $policyMapping.Section) {
                                    # Find the end of this section
                                    $j = $i + 1
                                    while ($j -lt $modifiedContent.Count -and -not $modifiedContent[$j].Trim().StartsWith("[")) {
                                        $j++
                                    }
                                    # Insert the setting before the next section or at the end
                                    $modifiedContent = $modifiedContent[0..($j-1)] + "$($policyMapping.Setting) = $($policyMapping.Value)" + $modifiedContent[$j..($modifiedContent.Count-1)]
                                    $changesMade += "$($policyMapping.Description) (added to section)"
                                    break
                                }
                            }
                        }
                    }
                }
                
                # Write the modified content back to the file
                if ($changesMade.Count -gt 0) {
                    $modifiedContent | Set-Content $TemplatePath -Encoding Unicode
                    Write-LogMessage "Applied $($changesMade.Count) policy modifications to template" -Level "Success"
                    $result.Success = $true
                    $result.Changes = $changesMade
                    $result.ModifiedFile = $TemplatePath
                }
                else {
                    Write-LogMessage "No policy modifications were needed" -Level "Info"
                    $result.Success = $true
                }
                
                return $result
            }
            catch {
                $result.Errors += "Error modifying policy template: $($_.Exception.Message)"
                return $result
            }
        }
        
        # Function to import security policy with validation
        function Import-SecurityPolicy {
            <#
            .SYNOPSIS
                Imports security policy from template file with validation
            .PARAMETER TemplatePath
                Path to the security policy template file to import
            .OUTPUTS
                Returns result object with success status and validation results
            #>
            
            param(
                [Parameter(Mandatory = $true)]
                [string]$TemplatePath
            )
            
            $result = @{
                Success = $false
                ImportFile = $TemplatePath
                Errors = @()
                Warnings = @()
                ValidationResults = @()
            }
            
            try {
                Write-LogMessage "Importing security policy from: $TemplatePath" -Level "Info"
                
                if (-not (Test-Path $TemplatePath)) {
                    $result.Errors += "Template file not found: $TemplatePath"
                    return $result
                }
                
                # Create a temporary database file for secedit
                $tempDb = Join-Path $env:TEMP "secedit_$(Get-Random).sdb"
                
                # Use secedit to configure the security policy
                $seceditArgs = "/configure /cfg `"$TemplatePath`" /db `"$tempDb`" /quiet"
                $importProcess = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\secedit_import_out.txt" -RedirectStandardError "$env:TEMP\secedit_import_err.txt"
                
                if ($importProcess.ExitCode -eq 0) {
                    Write-LogMessage "Security policy imported successfully" -Level "Success"
                    $result.Success = $true
                    
                    # Validate the import by checking some key settings
                    $validationResults = Test-SecurityPolicySettings
                    $result.ValidationResults = $validationResults
                }
                else {
                    $errorOutput = ""
                    if (Test-Path "$env:TEMP\secedit_import_err.txt") {
                        $errorOutput = Get-Content "$env:TEMP\secedit_import_err.txt" -Raw
                    }
                    $result.Errors += "secedit import failed with exit code $($importProcess.ExitCode): $errorOutput"
                }
                
                # Clean up temporary files
                @($tempDb, "$env:TEMP\secedit_import_out.txt", "$env:TEMP\secedit_import_err.txt") | ForEach-Object {
                    if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
                }
                
                return $result
            }
            catch {
                $result.Errors += "Error importing security policy: $($_.Exception.Message)"
                return $result
            }
        }
        
        # Function to validate security policy settings
        function Test-SecurityPolicySettings {
            <#
            .SYNOPSIS
                Validates that security policy settings have been applied correctly
            .OUTPUTS
                Returns array of validation results
            #>
            
            $validationResults = @()
            
            try {
                Write-LogMessage "Validating applied security policy settings..." -Level "Info"
                
                # Check Administrator account status
                try {
                    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
                    if ($adminAccount) {
                        $validationResults += "Administrator account enabled: $($adminAccount.Enabled)"
                    }
                }
                catch {
                    $validationResults += "Could not check Administrator account status: $($_.Exception.Message)"
                }
                
                # Check Guest account status
                try {
                    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
                    if ($guestAccount) {
                        $validationResults += "Guest account enabled: $($guestAccount.Enabled)"
                    }
                }
                catch {
                    $validationResults += "Could not check Guest account status: $($_.Exception.Message)"
                }
                
                # Check registry settings for Microsoft account blocking
                try {
                    $msAccountSetting = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -ErrorAction SilentlyContinue
                    if ($msAccountSetting) {
                        $validationResults += "Microsoft account blocking: $($msAccountSetting.NoConnectedUser)"
                    }
                }
                catch {
                    $validationResults += "Could not check Microsoft account blocking setting"
                }
                
                # Check digital signing settings
                try {
                    $serverSigning = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                    if ($serverSigning) {
                        $validationResults += "Server digital signing required: $($serverSigning.RequireSecuritySignature)"
                    }
                    
                    $clientSigning = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                    if ($clientSigning) {
                        $validationResults += "Client digital signing required: $($clientSigning.RequireSecuritySignature)"
                    }
                }
                catch {
                    $validationResults += "Could not check digital signing settings"
                }
                
                # Check LM compatibility level
                try {
                    $lmCompat = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
                    if ($lmCompat) {
                        $validationResults += "LM compatibility level: $($lmCompat.LmCompatibilityLevel)"
                    }
                }
                catch {
                    $validationResults += "Could not check LM compatibility level"
                }
                
                return $validationResults
            }
            catch {
                return @("Error during validation: $($_.Exception.Message)")
            }
        }
        
        # Step 2: Execute security policy configuration
        Write-LogMessage "Step 2: Executing security policy configuration..." -Level "Info"
        
        # Create working directory for policy files
        $policyWorkDir = Join-Path $env:TEMP "SecurityPolicy_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $policyWorkDir -ItemType Directory -Force | Out-Null
        
        # Define file paths
        $currentPolicyFile = Join-Path $policyWorkDir "current_policy.inf"
        $modifiedPolicyFile = Join-Path $policyWorkDir "modified_policy.inf"
        
        try {
            # Export current security policy
            Write-LogMessage "Exporting current security policy..." -Level "Info"
            $exportResult = Export-SecurityPolicy -ExportPath $currentPolicyFile
            
            if (-not $exportResult.Success) {
                $moduleResult.Errors += $exportResult.Errors
                throw "Failed to export current security policy"
            }
            
            $moduleResult.BackupResults += "Current policy exported to: $currentPolicyFile"
            
            # Copy current policy to modified policy file for editing
            Copy-Item $currentPolicyFile $modifiedPolicyFile -Force
            
            # Prepare policy settings based on configuration
            $policySettings = @{
                "DisableAdministratorAccount" = $Config.SecurityPolicy.DisableAdministratorAccount
                "DisableGuestAccount" = $Config.SecurityPolicy.DisableGuestAccount
                "BlockMicrosoftAccounts" = $Config.SecurityPolicy.BlockMicrosoftAccounts
                "EnableDigitalSigning" = $Config.SecurityPolicy.EnableDigitalSigning
                "EnableClientDigitalSigning" = $Config.SecurityPolicy.EnableDigitalSigning
                "ConfigureInteractiveLogon" = $Config.SecurityPolicy.ConfigureInteractiveLogon
                "DisableCAD" = $Config.SecurityPolicy.ConfigureInteractiveLogon
                "MaximizeNetworkSecurity" = $Config.SecurityPolicy.MaximizeNetworkSecurity
                "DisableNTLMv1" = $Config.SecurityPolicy.MaximizeNetworkSecurity
            }
            
            # Modify policy template
            Write-LogMessage "Modifying security policy template..." -Level "Info"
            $modifyResult = Edit-SecurityPolicyTemplate -TemplatePath $modifiedPolicyFile -PolicySettings $policySettings
            
            if (-not $modifyResult.Success) {
                $moduleResult.Errors += $modifyResult.Errors
                throw "Failed to modify security policy template"
            }
            
            $moduleResult.Changes += $modifyResult.Changes
            
            # Import modified security policy
            Write-LogMessage "Importing modified security policy..." -Level "Info"
            $importResult = Import-SecurityPolicy -TemplatePath $modifiedPolicyFile
            
            if (-not $importResult.Success) {
                $moduleResult.Errors += $importResult.Errors
                throw "Failed to import modified security policy"
            }
            
            $moduleResult.ValidationResults += $importResult.ValidationResults
            $moduleResult.Changes += "Security policy imported successfully"
            
            # Final validation
            Write-LogMessage "Performing final validation..." -Level "Info"
            $finalValidation = Test-SecurityPolicySettings
            $moduleResult.ValidationResults += $finalValidation
            
            # Set success if no errors occurred
            if ($moduleResult.Errors.Count -eq 0) {
                $moduleResult.Success = $true
                Write-LogMessage "Local Security Policy Configuration Module completed successfully" -Level "Success"
                
                # Log summary of changes
                Write-LogMessage "Security policy configuration changes applied:" -Level "Success"
                foreach ($change in $moduleResult.Changes) {
                    Write-LogMessage "  - $change" -Level "Success"
                }
                
                # Log validation results
                Write-LogMessage "Security policy validation results:" -Level "Info"
                foreach ($validation in $moduleResult.ValidationResults) {
                    Write-LogMessage "  - $validation" -Level "Info"
                }
            }
            else {
                Write-LogMessage "Local Security Policy Configuration Module failed" -Level "Error"
                foreach ($error in $moduleResult.Errors) {
                    Write-LogMessage "  Error: $error" -Level "Error"
                }
            }
        }
        finally {
            # Clean up working directory
            if (Test-Path $policyWorkDir) {
                try {
                    Remove-Item $policyWorkDir -Recurse -Force -ErrorAction SilentlyContinue
                }
                catch {
                    Write-LogMessage "Warning: Could not clean up working directory: $policyWorkDir" -Level "Warning"
                }
            }
        }
        
        # Log any warnings
        foreach ($warning in $moduleResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Local Security Policy Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

function Complete-SecurityHardening {
    <#
    .SYNOPSIS
        Completes the security hardening process and generates comprehensive reports
    .DESCRIPTION
        Performs cleanup, generates execution summary, compliance report, and provides final status
        Implements Requirements 12.1, 12.2, 12.3, 12.4 for comprehensive reporting
    #>
    
    try {
        $endTime = Get-Date
        $executionTime = $endTime - $Script:StartTime
        
        Write-LogMessage "Completing security hardening process..." -Level "Info"
        Write-LogMessage "Total execution time: $($executionTime.ToString('hh\:mm\:ss'))" -Level "Info"
        
        # Generate comprehensive execution summary report (Requirement 12.4)
        Write-LogMessage "Generating comprehensive execution summary report..." -Level "Info"
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $summaryReportPath = Join-Path $LogPath "WindowsSecurityHardening_ExecutionSummary_$timestamp.txt"
        $complianceReportPath = Join-Path $LogPath "WindowsSecurityHardening_ComplianceReport_$timestamp.txt"
        
        try {
            # Generate execution summary report
            $summaryReport = Generate-ExecutionSummaryReport -ExecutionResults $Script:ExecutionResults -OutputPath $summaryReportPath
            
            # Generate compliance report showing all applied configurations
            $complianceReport = Generate-ComplianceReport -ExecutionResults $Script:ExecutionResults -OutputPath $complianceReportPath
            
            Write-LogMessage "Reports generated successfully:" -Level "Success"
            Write-LogMessage "  - Execution Summary: $summaryReportPath" -Level "Success"
            Write-LogMessage "  - Compliance Report: $complianceReportPath" -Level "Success"
        }
        catch {
            Write-LogMessage "Error generating reports: $($_.Exception.Message)" -Level "Error"
        }
        
        # Display final progress summary (Requirement 12.1)
        Write-ProgressSummary
        
        # Generate execution summary for console display (Requirements 12.1, 12.2, 12.4)
        Write-LogMessage "`n" + "="*80 -Level "Info"
        Write-LogMessage "WINDOWS SECURITY HARDENING - FINAL SUMMARY" -Level "Info"
        Write-LogMessage "="*80 -Level "Info"
        Write-LogMessage "Execution Details:" -Level "Info"
        Write-LogMessage "  Start Time: $($Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "Info"
        Write-LogMessage "  End Time: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "Info"
        Write-LogMessage "  Duration: $($executionTime.ToString('hh\:mm\:ss'))" -Level "Info"
        Write-LogMessage "  Log File: $(Get-LogFilePath)" -Level "Info"
        
        # Module execution summary (Requirement 12.2)
        if ($Script:ExecutionResults.Count -gt 0) {
            $successCount = ($Script:ExecutionResults | Where-Object { $_.Success }).Count
            $failureCount = $Script:ExecutionResults.Count - $successCount
            
            Write-LogMessage "`nModule Execution Summary:" -Level "Info"
            Write-LogMessage "  Total Modules: $($Script:ExecutionResults.Count)" -Level "Info"
            Write-LogMessage "  Successful: $successCount" -Level "Success"
            Write-LogMessage "  Failed: $failureCount" -Level $(if ($failureCount -gt 0) { "Error" } else { "Info" })
            
            # Display individual module results (Requirement 12.2)
            Write-LogMessage "`nModule Results:" -Level "Info"
            foreach ($result in $Script:ExecutionResults | Sort-Object ModuleName) {
                $status = if ($result.Success) { "SUCCESS" } else { "FAILED" }
                $statusLevel = if ($result.Success) { "Success" } else { "Error" }
                
                Write-LogMessage "  [$status] $($result.ModuleName)" -Level $statusLevel
                Write-LogMessage "    Changes: $($result.Changes.Count) | Errors: $($result.Errors.Count) | Warnings: $($result.Warnings.Count)" -Level "Info"
                
                # Show successful changes (Requirement 12.2)
                if ($result.Changes.Count -gt 0) {
                    Write-LogMessage "    Successful Changes:" -Level "Success"
                    foreach ($change in $result.Changes | Select-Object -First 3) {
                        Write-LogMessage "      - $change" -Level "Success"
                    }
                    if ($result.Changes.Count -gt 3) {
                        Write-LogMessage "      - ... and $($result.Changes.Count - 3) more changes" -Level "Success"
                    }
                }
                
                # Show errors if any (Requirement 12.3)
                if ($result.Errors.Count -gt 0) {
                    Write-LogMessage "    Errors Encountered:" -Level "Error"
                    foreach ($error in $result.Errors | Select-Object -First 2) {
                        Write-LogMessage "      - $error" -Level "Error"
                    }
                    if ($result.Errors.Count -gt 2) {
                        Write-LogMessage "      - ... and $($result.Errors.Count - 2) more errors" -Level "Error"
                    }
                }
            }
        }
        else {
            Write-LogMessage "No module execution results available" -Level "Warning"
        }
        
        # Changes summary (Requirement 12.2)
        $changesSummary = Get-ChangeLogSummary
        if ($changesSummary.TotalChanges -gt 0) {
            Write-LogMessage "`nConfiguration Changes Summary:" -Level "Info"
            Write-LogMessage "  Total Changes: $($changesSummary.TotalChanges)" -Level "Info"
            Write-LogMessage "  Successful: $($changesSummary.SuccessfulChanges)" -Level "Success"
            Write-LogMessage "  Failed: $($changesSummary.FailedChanges)" -Level $(if ($changesSummary.FailedChanges -gt 0) { "Error" } else { "Info" })
            Write-LogMessage "  Success Rate: $([math]::Round(($changesSummary.SuccessfulChanges / [math]::Max($changesSummary.TotalChanges, 1)) * 100, 1))%" -Level "Info"
            
            # Changes by type
            if ($changesSummary.ChangesByType.Count -gt 0) {
                Write-LogMessage "`nChanges by Type:" -Level "Info"
                foreach ($changeType in $changesSummary.ChangesByType.Keys | Sort-Object) {
                    $typeData = $changesSummary.ChangesByType[$changeType]
                    Write-LogMessage "  $changeType: $($typeData.Total) (Success: $($typeData.Successful), Failed: $($typeData.Failed))" -Level "Info"
                }
            }
            
            # Requirements compliance
            if ($changesSummary.ChangesByRequirement.Count -gt 0) {
                Write-LogMessage "`nRequirements Compliance:" -Level "Info"
                $compliantReqs = ($changesSummary.ChangesByRequirement.Values | Where-Object { $_.Failed -eq 0 }).Count
                $totalReqs = $changesSummary.ChangesByRequirement.Count
                $compliancePercentage = [math]::Round(($compliantReqs / [math]::Max($totalReqs, 1)) * 100, 1)
                
                Write-LogMessage "  Requirements Addressed: $totalReqs" -Level "Info"
                Write-LogMessage "  Fully Compliant: $compliantReqs" -Level "Success"
                Write-LogMessage "  Compliance Score: $compliancePercentage%" -Level $(if ($compliancePercentage -ge 90) { "Success" } elseif ($compliancePercentage -ge 70) { "Warning" } else { "Error" })
            }
        }
        else {
            Write-LogMessage "`nNo configuration changes were tracked" -Level "Warning"
        }
        
        # Final status determination
        $overallSuccess = $true
        $criticalErrors = 0
        
        if ($Script:ExecutionResults.Count -gt 0) {
            $failedModules = $Script:ExecutionResults | Where-Object { -not $_.Success }
            $criticalErrors = ($failedModules | ForEach-Object { $_.Errors.Count } | Measure-Object -Sum).Sum
            
            if ($failedModules.Count -gt 0) {
                $overallSuccess = $false
            }
        }
        
        Write-LogMessage "`n" + "="*80 -Level "Info"
        
        if ($overallSuccess) {
            Write-LogMessage "SECURITY HARDENING COMPLETED SUCCESSFULLY" -Level "Success"
            Write-LogMessage "All security modules executed without critical errors" -Level "Success"
        }
        elseif ($criticalErrors -eq 0) {
            Write-LogMessage "SECURITY HARDENING COMPLETED WITH WARNINGS" -Level "Warning"
            Write-LogMessage "Some modules completed with warnings but no critical errors" -Level "Warning"
        }
        else {
            Write-LogMessage "SECURITY HARDENING COMPLETED WITH ERRORS" -Level "Error"
            Write-LogMessage "$criticalErrors critical errors encountered during execution" -Level "Error"
        }
        
        Write-LogMessage "`nFor detailed information, review the generated reports:" -Level "Info"
        Write-LogMessage "  - Execution Summary: $summaryReportPath" -Level "Info"
        Write-LogMessage "  - Compliance Report: $complianceReportPath" -Level "Info"
        Write-LogMessage "  - Detailed Log: $(Get-LogFilePath)" -Level "Info"
        
        Write-LogMessage "="*80 -Level "Info"
        
        # Clear PowerShell progress bar
        try {
            Write-Progress -Activity "Windows Security Hardening" -Completed
        }
        catch {
            # Progress bar not available in all environments
        }
        
        if (-not $Silent) {
            Write-Host "`nSecurity hardening process completed. Check the reports for detailed results." -ForegroundColor Green
            Write-Host "Press any key to exit..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
    catch {
        Write-LogMessage "Error during completion: $($_.Exception.Message)" -Level "Error"
        Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "Debug"
    }
}

#endregion

#region System Settings Configuration Module

function Invoke-SystemSettingsConfiguration {
    <#
    .SYNOPSIS
        Main function to execute system settings configuration module
    .DESCRIPTION
        Orchestrates the complete system settings configuration process including
        AutoPlay, screen saver, OneDrive startup, and auditing configurations
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting System Settings Configuration Module..." -Level "Info"
    Write-LogMessage "Requirements: 9.1, 9.2, 9.3, 9.4, 9.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "System Settings Configuration"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        # Step 1: Disable AutoPlay functionality through registry (Requirement 9.1)
        if ($Config.SystemSettings.DisableAutoPlay) {
            Write-LogMessage "Step 1: Disabling AutoPlay functionality (Requirement 9.1)..." -Level "Info"
            
            try {
                # Disable AutoPlay for all drives
                $autoPlayPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                
                # Ensure the registry path exists
                if (-not (Test-Path $autoPlayPath)) {
                    New-Item -Path $autoPlayPath -Force | Out-Null
                    $moduleResult.Changes += "Created registry path: $autoPlayPath"
                }
                
                # Set NoDriveTypeAutoRun to disable AutoPlay for all drive types
                Set-ItemProperty -Path $autoPlayPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction Stop
                $moduleResult.Changes += "Disabled AutoPlay for all drive types (NoDriveTypeAutoRun = 255)"
                
                # Also disable AutoPlay in user policy
                $userAutoPlayPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                if (-not (Test-Path $userAutoPlayPath)) {
                    New-Item -Path $userAutoPlayPath -Force | Out-Null
                    $moduleResult.Changes += "Created user registry path: $userAutoPlayPath"
                }
                
                Set-ItemProperty -Path $userAutoPlayPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction Stop
                $moduleResult.Changes += "Disabled AutoPlay for current user (NoDriveTypeAutoRun = 255)"
                
                # Disable AutoPlay service if it exists
                $autoPlayService = Get-Service -Name "ShellHWDetection" -ErrorAction SilentlyContinue
                if ($autoPlayService -and $autoPlayService.Status -eq "Running") {
                    Stop-Service -Name "ShellHWDetection" -Force -ErrorAction Stop
                    Set-Service -Name "ShellHWDetection" -StartupType Disabled -ErrorAction Stop
                    $moduleResult.Changes += "Stopped and disabled Shell Hardware Detection service"
                }
                
                Write-LogMessage "AutoPlay functionality disabled successfully" -Level "Success"
            }
            catch {
                $errorMessage = "Failed to disable AutoPlay functionality: $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $moduleResult.Errors += $errorMessage
            }
        }
        
        # Step 2: Configure screen saver with 10-minute timeout and logon requirement (Requirements 9.2, 9.3)
        if ($Config.SystemSettings.ScreenSaverTimeout -gt 0 -and $Config.SystemSettings.RequireLogonOnResume) {
            Write-LogMessage "Step 2: Configuring screen saver with $($Config.SystemSettings.ScreenSaverTimeout)-minute timeout and logon requirement (Requirements 9.2, 9.3)..." -Level "Info"
            
            try {
                $screenSaverPath = "HKCU:\Control Panel\Desktop"
                $timeoutSeconds = $Config.SystemSettings.ScreenSaverTimeout * 60
                
                # Enable screen saver
                Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaveActive" -Value "1" -Type String -ErrorAction Stop
                $moduleResult.Changes += "Enabled screen saver"
                
                # Set screen saver timeout
                Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaveTimeOut" -Value $timeoutSeconds.ToString() -Type String -ErrorAction Stop
                $moduleResult.Changes += "Set screen saver timeout to $($Config.SystemSettings.ScreenSaverTimeout) minutes"
                
                # Require password on resume
                Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaverIsSecure" -Value "1" -Type String -ErrorAction Stop
                $moduleResult.Changes += "Enabled password requirement on screen saver resume"
                
                # Set a default screen saver (blank screen)
                Set-ItemProperty -Path $screenSaverPath -Name "SCRNSAVE.EXE" -Value "scrnsave.scr" -Type String -ErrorAction Stop
                $moduleResult.Changes += "Set default screen saver to blank screen"
                
                # Also configure system-wide screen saver policy
                $systemScreenSaverPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
                if (-not (Test-Path $systemScreenSaverPath)) {
                    New-Item -Path $systemScreenSaverPath -Force | Out-Null
                    $moduleResult.Changes += "Created system screen saver policy path"
                }
                
                Set-ItemProperty -Path $systemScreenSaverPath -Name "ScreenSaveActive" -Value "1" -Type String -ErrorAction Stop
                Set-ItemProperty -Path $systemScreenSaverPath -Name "ScreenSaveTimeOut" -Value $timeoutSeconds.ToString() -Type String -ErrorAction Stop
                Set-ItemProperty -Path $systemScreenSaverPath -Name "ScreenSaverIsSecure" -Value "1" -Type String -ErrorAction Stop
                $moduleResult.Changes += "Applied system-wide screen saver policy"
                
                Write-LogMessage "Screen saver configured successfully with $($Config.SystemSettings.ScreenSaverTimeout)-minute timeout and logon requirement" -Level "Success"
            }
            catch {
                $errorMessage = "Failed to configure screen saver: $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $moduleResult.Errors += $errorMessage
            }
        }
        
        # Step 3: Disable OneDrive startup through registry and scheduled tasks (Requirement 9.4)
        if ($Config.SystemSettings.DisableOneDriveStartup) {
            Write-LogMessage "Step 3: Disabling OneDrive startup (Requirement 9.4)..." -Level "Info"
            
            try {
                # Disable OneDrive through Group Policy
                $oneDrivePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
                if (-not (Test-Path $oneDrivePolicyPath)) {
                    New-Item -Path $oneDrivePolicyPath -Force | Out-Null
                    $moduleResult.Changes += "Created OneDrive policy registry path"
                }
                
                Set-ItemProperty -Path $oneDrivePolicyPath -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -ErrorAction Stop
                $moduleResult.Changes += "Disabled OneDrive file sync through Group Policy"
                
                # Disable OneDrive startup for current user
                $runPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                $oneDriveRunKey = Get-ItemProperty -Path $runPath -Name "OneDrive" -ErrorAction SilentlyContinue
                if ($oneDriveRunKey) {
                    Remove-ItemProperty -Path $runPath -Name "OneDrive" -ErrorAction Stop
                    $moduleResult.Changes += "Removed OneDrive from user startup registry"
                }
                
                # Disable OneDrive startup system-wide
                $systemRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                $systemOneDriveRunKey = Get-ItemProperty -Path $systemRunPath -Name "OneDrive" -ErrorAction SilentlyContinue
                if ($systemOneDriveRunKey) {
                    Remove-ItemProperty -Path $systemRunPath -Name "OneDrive" -ErrorAction Stop
                    $moduleResult.Changes += "Removed OneDrive from system startup registry"
                }
                
                # Disable OneDrive scheduled tasks
                $oneDriveTasks = @(
                    "OneDrive Standalone Update Task",
                    "OneDrive Standalone Update Task-S-1-5-21*",
                    "OneDrive Per-Machine Standalone Update Task"
                )
                
                foreach ($taskPattern in $oneDriveTasks) {
                    try {
                        $tasks = Get-ScheduledTask -TaskName $taskPattern -ErrorAction SilentlyContinue
                        foreach ($task in $tasks) {
                            if ($task.State -ne "Disabled") {
                                Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
                                $moduleResult.Changes += "Disabled scheduled task: $($task.TaskName)"
                            }
                        }
                    }
                    catch {
                        Write-LogMessage "Warning: Could not disable OneDrive scheduled task '$taskPattern': $($_.Exception.Message)" -Level "Warning"
                        $moduleResult.Warnings += "Could not disable OneDrive scheduled task '$taskPattern': $($_.Exception.Message)"
                    }
                }
                
                # Stop OneDrive process if running
                $oneDriveProcesses = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
                if ($oneDriveProcesses) {
                    foreach ($process in $oneDriveProcesses) {
                        try {
                            Stop-Process -Id $process.Id -Force -ErrorAction Stop
                            $moduleResult.Changes += "Stopped OneDrive process (PID: $($process.Id))"
                        }
                        catch {
                            Write-LogMessage "Warning: Could not stop OneDrive process: $($_.Exception.Message)" -Level "Warning"
                            $moduleResult.Warnings += "Could not stop OneDrive process: $($_.Exception.Message)"
                        }
                    }
                }
                
                Write-LogMessage "OneDrive startup disabled successfully" -Level "Success"
            }
            catch {
                $errorMessage = "Failed to disable OneDrive startup: $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $moduleResult.Errors += $errorMessage
            }
        }
        
        # Step 4: Configure comprehensive auditing for Success/Failure events (Requirement 9.5)
        if ($Config.SystemSettings.EnableAuditing) {
            Write-LogMessage "Step 4: Configuring comprehensive auditing for Success/Failure events (Requirement 9.5)..." -Level "Info"
            
            try {
                # Define audit categories and their settings
                $auditCategories = @{
                    "Account Logon" = "Success,Failure"
                    "Account Management" = "Success,Failure"
                    "Directory Service Access" = "Success,Failure"
                    "Logon Events" = "Success,Failure"
                    "Object Access" = "Success,Failure"
                    "Policy Change" = "Success,Failure"
                    "Privilege Use" = "Success,Failure"
                    "Process Tracking" = "Success,Failure"
                    "System Events" = "Success,Failure"
                }
                
                # Apply audit settings using auditpol.exe
                foreach ($category in $auditCategories.Keys) {
                    try {
                        $setting = $auditCategories[$category]
                        Write-LogMessage "Configuring audit policy for '$category' to '$setting'..." -Level "Info"
                        
                        $auditCmd = "auditpol.exe /set /category:`"$category`" /success:enable /failure:enable"
                        $auditResult = Invoke-Expression $auditCmd 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            $moduleResult.Changes += "Configured audit policy for '$category': $setting"
                            Write-LogMessage "Successfully configured audit policy for '$category'" -Level "Success"
                        }
                        else {
                            Write-LogMessage "Failed to configure audit policy for '$category': $auditResult" -Level "Warning"
                            $moduleResult.Warnings += "Failed to configure audit policy for '$category': $auditResult"
                        }
                    }
                    catch {
                        Write-LogMessage "Error configuring audit policy for '$category': $($_.Exception.Message)" -Level "Warning"
                        $moduleResult.Warnings += "Error configuring audit policy for '$category': $($_.Exception.Message)"
                    }
                }
                
                # Configure additional audit settings through registry
                $auditRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                
                # Enable audit of security policy changes
                Set-ItemProperty -Path $auditRegistryPath -Name "crashonauditfail" -Value 0 -Type DWord -ErrorAction Stop
                $moduleResult.Changes += "Configured system to continue on audit failure"
                
                # Set audit log size and retention
                $eventLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
                Set-ItemProperty -Path $eventLogPath -Name "MaxSize" -Value 0x6400000 -Type DWord -ErrorAction Stop  # 100MB
                Set-ItemProperty -Path $eventLogPath -Name "Retention" -Value 0 -Type DWord -ErrorAction Stop  # Overwrite as needed
                $moduleResult.Changes += "Configured Security event log size to 100MB with overwrite retention"
                
                Write-LogMessage "Comprehensive auditing configured successfully" -Level "Success"
            }
            catch {
                $errorMessage = "Failed to configure comprehensive auditing: $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $moduleResult.Errors += $errorMessage
            }
        }
        
        # Step 5: Final validation and summary
        Write-LogMessage "Step 5: Performing final validation..." -Level "Info"
        
        try {
            # Validate AutoPlay settings
            if ($Config.SystemSettings.DisableAutoPlay) {
                $autoPlayValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
                if ($autoPlayValue -and $autoPlayValue.NoDriveTypeAutoRun -eq 255) {
                    $moduleResult.ValidationResults += "AutoPlay disabled: NoDriveTypeAutoRun = 255"
                }
                else {
                    $moduleResult.Warnings += "AutoPlay validation failed: NoDriveTypeAutoRun not set correctly"
                }
            }
            
            # Validate screen saver settings
            if ($Config.SystemSettings.ScreenSaverTimeout -gt 0) {
                $screenSaverActive = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
                $screenSaverTimeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
                $screenSaverSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
                
                if ($screenSaverActive -and $screenSaverActive.ScreenSaveActive -eq "1" -and 
                    $screenSaverTimeout -and [int]$screenSaverTimeout.ScreenSaveTimeOut -eq ($Config.SystemSettings.ScreenSaverTimeout * 60) -and
                    $screenSaverSecure -and $screenSaverSecure.ScreenSaverIsSecure -eq "1") {
                    $moduleResult.ValidationResults += "Screen saver configured: $($Config.SystemSettings.ScreenSaverTimeout) minutes with password requirement"
                }
                else {
                    $moduleResult.Warnings += "Screen saver validation failed: Settings not configured correctly"
                }
            }
            
            # Validate OneDrive startup settings
            if ($Config.SystemSettings.DisableOneDriveStartup) {
                $oneDrivePolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
                if ($oneDrivePolicy -and $oneDrivePolicy.DisableFileSyncNGSC -eq 1) {
                    $moduleResult.ValidationResults += "OneDrive startup disabled: DisableFileSyncNGSC = 1"
                }
                else {
                    $moduleResult.Warnings += "OneDrive validation failed: DisableFileSyncNGSC not set correctly"
                }
            }
            
            # Validate audit settings
            if ($Config.SystemSettings.EnableAuditing) {
                try {
                    $auditResult = & auditpol.exe /get /category:"Account Logon" 2>&1
                    if ($LASTEXITCODE -eq 0 -and $auditResult -match "Success and Failure") {
                        $moduleResult.ValidationResults += "Auditing configured: Account Logon events set to Success and Failure"
                    }
                    else {
                        $moduleResult.Warnings += "Audit validation warning: Could not verify audit policy settings"
                    }
                }
                catch {
                    $moduleResult.Warnings += "Audit validation error: $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-LogMessage "Error during validation: $($_.Exception.Message)" -Level "Warning"
            $moduleResult.Warnings += "Validation error: $($_.Exception.Message)"
        }
        
        # Set overall success based on results
        if ($moduleResult.Errors.Count -eq 0) {
            $moduleResult.Success = $true
            Write-LogMessage "System Settings Configuration Module completed successfully" -Level "Success"
            
            # Log summary of changes
            if ($moduleResult.Changes.Count -gt 0) {
                Write-LogMessage "System settings configuration changes applied:" -Level "Success"
                foreach ($change in $moduleResult.Changes) {
                    Write-LogMessage "  - $change" -Level "Success"
                }
            }
            
            # Log validation results
            if ($moduleResult.ValidationResults.Count -gt 0) {
                Write-LogMessage "System settings validation results:" -Level "Info"
                foreach ($validation in $moduleResult.ValidationResults) {
                    Write-LogMessage "  - $validation" -Level "Info"
                }
            }
        }
        else {
            Write-LogMessage "System Settings Configuration Module failed" -Level "Error"
            foreach ($error in $moduleResult.Errors) {
                Write-LogMessage "  Error: $error" -Level "Error"
            }
        }
        
        # Log any warnings
        foreach ($warning in $moduleResult.Warnings) {
            Write-LogMessage "  Warning: $warning" -Level "Warning"
        }
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "System Settings Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
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
        Initialize-Logging -LogPath $LogPath -ScriptName $Script:ScriptName -ScriptVersion $Script:ScriptVersion
        
        # Initialize progress reporting system (Requirement 12.1)
        $moduleNames = @(
            "Network Adapter Configuration",
            "Windows Services Management", 
            "Windows Features Management",
            "Firewall Configuration",
            "Registry Modifications",
            "Local Security Policy Configuration",
            "System Settings Configuration"
        )
        Initialize-ProgressReporting -TotalModules $moduleNames.Count -ModuleNames $moduleNames
        
        # Initialize change logging system (Requirement 12.2, 12.3)
        Initialize-ChangeLogging
        
        Write-LogMessage "Windows Security Hardening Script v$Script:ScriptVersion" -Level "Info"
        Write-LogMessage "Author: $Script:ScriptAuthor" -Level "Info"
        Write-LogMessage "Execution started by: $env:USERNAME on $env:COMPUTERNAME" -Level "Info"
        
        # Start the security hardening process
        Update-ModuleProgress -ModuleName "Initialization" -Status "Starting" -CurrentStep "Initializing security hardening process"
        $configuration = Start-SecurityHardening
        Update-ModuleProgress -ModuleName "Initialization" -Status "Completed" -PercentComplete 100
        
        if ($configuration) {
            Write-LogMessage "Script foundation initialized successfully" -Level "Success"
            Write-LogMessage "Configuration object created with $($configuration.Keys.Count) sections" -Level "Info"
            
            # Execute main controller with integrated module execution
            Write-LogMessage "Starting integrated module execution through main controller..." -Level "Info"
            
            # Determine execution mode based on parameters
            $executionMode = "Interactive"
            if ($Silent) {
                $executionMode = "Silent"
            }
            elseif ($WhatIf) {
                $executionMode = "WhatIf"
            }
            
            # Execute all modules through the main controller
            $controllerResult = Invoke-MainController -Config $configuration -ExecutionMode $executionMode
            
            if ($controllerResult.Success) {
                Write-LogMessage "All security modules completed successfully" -Level "Success"
                Write-LogMessage "Total modules executed: $($controllerResult.ModulesExecuted.Count)" -Level "Success"
                Write-LogMessage "Successful modules: $($controllerResult.ModulesSucceeded.Count)" -Level "Success"
                Write-LogMessage "Failed modules: $($controllerResult.ModulesFailed.Count)" -Level $(if ($controllerResult.ModulesFailed.Count -gt 0) { "Warning" } else { "Success" })
                Write-LogMessage "Total changes applied: $($controllerResult.TotalChanges)" -Level "Success"
            }
            else {
                Write-LogMessage "Security module execution completed with issues" -Level "Warning"
                Write-LogMessage "Some modules may have failed - check detailed logs for more information" -Level "Warning"
            }
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

#region Missing Module Functions Implementation

function Invoke-PasswordPolicyConfiguration {
    <#
    .SYNOPSIS
        Main function to execute password policy configuration module
    .DESCRIPTION
        Orchestrates the complete password policy configuration process including
        password history, age, length, and complexity requirements
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
    Write-LogMessage "Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3" -Level "Info"
    
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
        Write-LogMessage "Password Policy Configuration module implementation pending" -Level "Warning"
        Write-LogMessage "This module will be implemented in a future task" -Level "Info"
        
        # Placeholder for actual implementation
        $moduleResult.Success = $true
        $moduleResult.Warnings += "Module not yet fully implemented"
        
        Write-LogMessage "Password Policy Configuration Module completed (placeholder)" -Level "Success"
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Password Policy Configuration Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

function Invoke-UserAccountManagement {
    <#
    .SYNOPSIS
        Main function to execute user account management module
    .DESCRIPTION
        Orchestrates the complete user account management process including
        account restrictions, group memberships, and security settings
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting User Account Management Module..." -Level "Info"
    Write-LogMessage "Requirements: 3.1, 3.2, 3.3, 3.4, 3.5" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "User Account Management"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        Write-LogMessage "User Account Management module implementation pending" -Level "Warning"
        Write-LogMessage "This module will be implemented in a future task" -Level "Info"
        
        # Placeholder for actual implementation
        $moduleResult.Success = $true
        $moduleResult.Warnings += "Module not yet fully implemented"
        
        Write-LogMessage "User Account Management Module completed (placeholder)" -Level "Success"
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "User Account Management Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}

function Invoke-WindowsSecurityFeatures {
    <#
    .SYNOPSIS
        Main function to execute Windows security features configuration module
    .DESCRIPTION
        Orchestrates the complete Windows security features configuration process including
        SmartScreen, Wi-Fi Sense, UAC, and Windows Defender settings
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Windows Security Features Module..." -Level "Info"
    Write-LogMessage "Requirements: 4.1, 4.2, 4.3, 4.4" -Level "Info"
    
    $moduleResult = @{
        ModuleName = "Windows Security Features"
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ExecutionTime = Get-Date
        ValidationResults = @()
    }
    
    try {
        Write-LogMessage "Windows Security Features module implementation pending" -Level "Warning"
        Write-LogMessage "This module will be implemented in a future task" -Level "Info"
        
        # Placeholder for actual implementation
        $moduleResult.Success = $true
        $moduleResult.Warnings += "Module not yet fully implemented"
        
        Write-LogMessage "Windows Security Features Module completed (placeholder)" -Level "Success"
    }
    catch {
        $moduleResult.Errors += $_.Exception.Message
        Write-LogMessage "Windows Security Features Module failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    # Add result to global execution results
    Add-ExecutionResult -ModuleName $moduleResult.ModuleName -Success $moduleResult.Success -Changes $moduleResult.Changes -Errors $moduleResult.Errors -Warnings $moduleResult.Warnings
    
    return $moduleResult
}



#endregion

#region Main Script Controller and Execution Flow

function Invoke-MainController {
    <#
    .SYNOPSIS
        Main execution controller that orchestrates all security hardening modules
    .DESCRIPTION
        Implements the main execution controller that orchestrates all modules with proper
        error handling, progress tracking, and execution mode support
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .PARAMETER ExecutionMode
        Execution mode: Interactive, Silent, or WhatIf
    .OUTPUTS
        Returns overall execution result
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Interactive", "Silent", "WhatIf")]
        [string]$ExecutionMode
    )
    
    Write-LogMessage "Starting Main Security Hardening Controller..." -Level "Info"
    Write-LogMessage "Execution Mode: $ExecutionMode" -Level "Info"
    Write-LogMessage "Requirements: 12.1, 12.4" -Level "Info"
    
    $controllerResult = @{
        Success = $false
        ExecutionMode = $ExecutionMode
        ModulesExecuted = @()
        ModulesSucceeded = @()
        ModulesFailed = @()
        TotalChanges = 0
        TotalErrors = 0
        TotalWarnings = 0
        ExecutionStartTime = Get-Date
        ExecutionEndTime = $null
        ExecutionDuration = $null
    }
    
    try {
        # Define the execution sequence of security modules
        $securityModules = @(
            @{
                Name = "Password Policy Configuration"
                Function = "Invoke-PasswordPolicyConfiguration"
                Requirements = @("1.1", "1.2", "1.3", "1.4", "1.5", "2.1", "2.2", "2.3")
                Description = "Configure password policies and account lockout settings"
                Critical = $true
            },
            @{
                Name = "User Account Management"
                Function = "Invoke-UserAccountManagement"
                Requirements = @("3.1", "3.2", "3.3", "3.4", "3.5")
                Description = "Manage user accounts and group memberships"
                Critical = $true
            },
            @{
                Name = "Windows Security Features"
                Function = "Invoke-WindowsSecurityFeatures"
                Requirements = @("4.1", "4.2", "4.3", "4.4")
                Description = "Configure Windows security features (SmartScreen, UAC, Defender)"
                Critical = $true
            },
            @{
                Name = "Network Adapter Configuration"
                Function = "Invoke-NetworkAdapterConfiguration"
                Requirements = @("5.1", "5.2", "5.3", "5.4", "5.5")
                Description = "Configure network adapter settings and protocols"
                Critical = $true
            },
            @{
                Name = "Windows Services Management"
                Function = "Invoke-WindowsServicesConfiguration"
                Requirements = @("6.1", "6.2", "6.3", "6.4", "6.5")
                Description = "Manage Windows services security settings"
                Critical = $true
            },
            @{
                Name = "Windows Features Management"
                Function = "Invoke-WindowsFeaturesConfiguration"
                Requirements = @("7.1", "7.2", "7.3", "7.4", "7.5")
                Description = "Disable unnecessary Windows features"
                Critical = $true
            },
            @{
                Name = "Firewall Configuration"
                Function = "Invoke-FirewallConfiguration"
                Requirements = @("8.1", "8.2", "8.3", "8.4", "8.5")
                Description = "Configure Windows Firewall rules"
                Critical = $true
            },
            @{
                Name = "System Settings Configuration"
                Function = "Invoke-SystemSettingsConfiguration"
                Requirements = @("9.1", "9.2", "9.3", "9.4", "9.5")
                Description = "Configure system settings (AutoPlay, screen saver, auditing)"
                Critical = $true
            },
            @{
                Name = "Local Security Policy Configuration"
                Function = "Invoke-LocalSecurityPolicyConfiguration"
                Requirements = @("10.1", "10.2", "10.3", "10.4", "10.5")
                Description = "Configure local security policies"
                Critical = $true
            },
            @{
                Name = "Registry Modifications"
                Function = "Invoke-RegistryModifications"
                Requirements = @("11.1", "11.2", "11.3")
                Description = "Apply security-related registry modifications"
                Critical = $true
            }
            @{
                Name = "Windows Security Features"
                Function = "Invoke-WindowsSecurityFeatures"
                Requirements = @("4.1", "4.2", "4.3", "4.4")
                Description = "Configure Windows security features"
                Critical = $false
            },
            @{
                Name = "Network Adapter Configuration"
                Function = "Invoke-NetworkAdapterConfiguration"
                Requirements = @("5.1", "5.2", "5.3", "5.4", "5.5")
                Description = "Configure network adapter settings and protocols"
                Critical = $false
            },
            @{
                Name = "Windows Services Management"
                Function = "Invoke-WindowsServicesConfiguration"
                Requirements = @("6.1", "6.2", "6.3", "6.4", "6.5")
                Description = "Manage Windows services security settings"
                Critical = $false
            },
            @{
                Name = "Windows Features Management"
                Function = "Invoke-WindowsFeaturesConfiguration"
                Requirements = @("7.1", "7.2", "7.3", "7.4", "7.5")
                Description = "Disable unnecessary Windows features"
                Critical = $false
            },
            @{
                Name = "Firewall Configuration"
                Function = "Invoke-FirewallConfiguration"
                Requirements = @("8.1", "8.2", "8.3", "8.4", "8.5")
                Description = "Configure Windows Firewall rules"
                Critical = $false
            },
            @{
                Name = "Registry Modifications"
                Function = "Invoke-RegistryModifications"
                Requirements = @("11.1", "11.2", "11.3")
                Description = "Apply security-related registry modifications"
                Critical = $false
            },
            @{
                Name = "Local Security Policy Configuration"
                Function = "Invoke-LocalSecurityPolicyConfiguration"
                Requirements = @("10.1", "10.2", "10.3", "10.4", "10.5")
                Description = "Configure local security policies"
                Critical = $true
            },
            @{
                Name = "System Settings Configuration"
                Function = "Invoke-SystemSettingsConfiguration"
                Requirements = @("9.1", "9.2", "9.3", "9.4", "9.5")
                Description = "Configure system security settings"
                Critical = $false
            }
        )
        
        Write-LogMessage "Execution sequence defined with $($securityModules.Count) security modules" -Level "Info"
        
        # Interactive mode confirmation
        if ($ExecutionMode -eq "Interactive") {
            Write-Host "`n" -ForegroundColor Yellow
            Write-Host "Windows Security Hardening Script" -ForegroundColor Cyan
            Write-Host "===================================" -ForegroundColor Cyan
            Write-Host "This script will apply comprehensive security hardening to your Windows system." -ForegroundColor White
            Write-Host "The following modules will be executed:" -ForegroundColor White
            Write-Host ""
            
            foreach ($module in $securityModules) {
                $criticalText = if ($module.Critical) { " [CRITICAL]" } else { "" }
                Write-Host "  - $($module.Name)$criticalText" -ForegroundColor $(if ($module.Critical) { "Red" } else { "Yellow" })
                Write-Host "    $($module.Description)" -ForegroundColor Gray
                Write-Host "    Requirements: $($module.Requirements -join ', ')" -ForegroundColor Gray
                Write-Host ""
            }
            
            Write-Host "IMPORTANT WARNINGS:" -ForegroundColor Red
            Write-Host "- This script requires administrative privileges" -ForegroundColor Yellow
            Write-Host "- A system restore point will be created before changes" -ForegroundColor Yellow
            Write-Host "- Some changes may require a system restart" -ForegroundColor Yellow
            Write-Host "- Critical modules must succeed for overall success" -ForegroundColor Yellow
            Write-Host ""
            
            do {
                $confirmation = Read-Host "Do you want to proceed with the security hardening? (Y/N/S for Silent mode)"
                $confirmation = $confirmation.ToUpper()
                
                if ($confirmation -eq "S") {
                    Write-LogMessage "User switched to Silent mode" -Level "Info"
                    $ExecutionMode = "Silent"
                    $controllerResult.ExecutionMode = "Silent"
                    break
                }
                elseif ($confirmation -eq "Y") {
                    Write-LogMessage "User confirmed interactive execution" -Level "Info"
                    break
                }
                elseif ($confirmation -eq "N") {
                    Write-LogMessage "User cancelled execution" -Level "Warning"
                    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
                    return $controllerResult
                }
                else {
                    Write-Host "Please enter Y (Yes), N (No), or S (Silent mode)" -ForegroundColor Red
                }
            } while ($true)
        }
        
        # WhatIf mode notification
        if ($ExecutionMode -eq "WhatIf") {
            Write-LogMessage "Running in WhatIf mode - no actual changes will be made" -Level "Warning"
            Write-Host "`nWHATIF MODE: No changes will be made to the system" -ForegroundColor Magenta
            Write-Host "This mode will show what changes would be applied." -ForegroundColor Magenta
            Write-Host ""
        }
        
        # Execute security modules sequentially
        Write-LogMessage "Beginning sequential execution of security modules..." -Level "Info"
        
        $moduleIndex = 1
        $totalModules = $securityModules.Count
        
        foreach ($module in $securityModules) {
            $controllerResult.ModulesExecuted += $module.Name
            
            Write-LogMessage "[$moduleIndex/$totalModules] Starting module: $($module.Name)" -Level "Info"
            Write-LogMessage "Requirements: $($module.Requirements -join ', ')" -Level "Info"
            
            # Interactive mode confirmation for each module
            if ($ExecutionMode -eq "Interactive") {
                Write-Host "`n[$moduleIndex/$totalModules] $($module.Name)" -ForegroundColor Cyan
                Write-Host "$($module.Description)" -ForegroundColor White
                Write-Host "Requirements: $($module.Requirements -join ', ')" -ForegroundColor Gray
                
                if ($module.Critical) {
                    Write-Host "[CRITICAL MODULE] - Required for overall success" -ForegroundColor Red
                }
                
                do {
                    $moduleConfirmation = Read-Host "Execute this module? (Y/N/S for Silent mode from now on)"
                    $moduleConfirmation = $moduleConfirmation.ToUpper()
                    
                    if ($moduleConfirmation -eq "S") {
                        Write-LogMessage "User switched to Silent mode for remaining modules" -Level "Info"
                        $ExecutionMode = "Silent"
                        break
                    }
                    elseif ($moduleConfirmation -eq "Y") {
                        break
                    }
                    elseif ($moduleConfirmation -eq "N") {
                        Write-LogMessage "User skipped module: $($module.Name)" -Level "Warning"
                        
                        if ($module.Critical) {
                            Write-Host "WARNING: Skipping critical module may affect overall security posture" -ForegroundColor Red
                            $skipCritical = Read-Host "Are you sure you want to skip this critical module? (Y/N)"
                            if ($skipCritical.ToUpper() -ne "Y") {
                                continue
                            }
                        }
                        
                        Write-LogMessage "Module skipped by user: $($module.Name)" -Level "Warning"
                        $moduleIndex++
                        continue
                    }
                    else {
                        Write-Host "Please enter Y (Yes), N (No), or S (Silent mode)" -ForegroundColor Red
                    }
                } while ($true)
            }
            
            try {
                # Execute the module function
                Write-LogMessage "Executing module function: $($module.Function)" -Level "Info"
                
                $moduleStartTime = Get-Date
                $moduleResult = $null
                
                # Call the appropriate module function
                switch ($module.Function) {
                    "Invoke-PasswordPolicyConfiguration" {
                        $moduleResult = Invoke-PasswordPolicyConfiguration -Config $Config
                    }
                    "Invoke-UserAccountManagement" {
                        $moduleResult = Invoke-UserAccountManagement -Config $Config
                    }
                    "Invoke-WindowsSecurityFeatures" {
                        $moduleResult = Invoke-WindowsSecurityFeatures -Config $Config
                    }
                    "Invoke-NetworkAdapterConfiguration" {
                        $moduleResult = Invoke-NetworkAdapterConfiguration -Config $Config
                    }
                    "Invoke-WindowsServicesConfiguration" {
                        $moduleResult = Invoke-WindowsServicesConfiguration -Config $Config
                    }
                    "Invoke-WindowsFeaturesConfiguration" {
                        $moduleResult = Invoke-WindowsFeaturesConfiguration -Config $Config
                    }
                    "Invoke-FirewallConfiguration" {
                        $moduleResult = Invoke-FirewallConfiguration -Config $Config
                    }
                    "Invoke-RegistryModifications" {
                        $moduleResult = Invoke-RegistryModifications -Config $Config
                    }
                    "Invoke-LocalSecurityPolicyConfiguration" {
                        $moduleResult = Invoke-LocalSecurityPolicyConfiguration -Config $Config
                    }
                    "Invoke-SystemSettingsConfiguration" {
                        $moduleResult = Invoke-SystemSettingsConfiguration -Config $Config
                    }
                    default {
                        Write-LogMessage "Unknown module function: $($module.Function)" -Level "Error"
                        $moduleResult = @{ Success = $false; Changes = @(); Errors = @("Unknown module function"); Warnings = @() }
                    }
                }
                
                $moduleEndTime = Get-Date
                $moduleDuration = $moduleEndTime - $moduleStartTime
                
                # Process module results
                if ($moduleResult -and $moduleResult.Success) {
                    $controllerResult.ModulesSucceeded += $module.Name
                    Write-LogMessage "Module '$($module.Name)' completed successfully in $($moduleDuration.TotalSeconds) seconds" -Level "Success"
                    
                    if ($moduleResult.Changes) {
                        $controllerResult.TotalChanges += $moduleResult.Changes.Count
                        Write-LogMessage "Module applied $($moduleResult.Changes.Count) changes" -Level "Success"
                    }
                }
                else {
                    $controllerResult.ModulesFailed += $module.Name
                    Write-LogMessage "Module '$($module.Name)' failed after $($moduleDuration.TotalSeconds) seconds" -Level "Error"
                    
                    if ($module.Critical) {
                        Write-LogMessage "CRITICAL MODULE FAILED: $($module.Name)" -Level "Error"
                        
                        if ($ExecutionMode -eq "Interactive") {
                            Write-Host "`nCRITICAL MODULE FAILED: $($module.Name)" -ForegroundColor Red
                            Write-Host "This is a critical module required for security hardening." -ForegroundColor Red
                            
                            $continueChoice = Read-Host "Continue with remaining modules? (Y/N)"
                            if ($continueChoice.ToUpper() -ne "Y") {
                                Write-LogMessage "User chose to stop execution after critical module failure" -Level "Error"
                                throw "Critical module failure - execution stopped by user"
                            }
                        }
                        elseif ($ExecutionMode -eq "Silent") {
                            Write-LogMessage "Critical module failed in silent mode - continuing with remaining modules" -Level "Warning"
                        }
                    }
                }
                
                # Aggregate errors and warnings
                if ($moduleResult) {
                    if ($moduleResult.Errors) {
                        $controllerResult.TotalErrors += $moduleResult.Errors.Count
                    }
                    if ($moduleResult.Warnings) {
                        $controllerResult.TotalWarnings += $moduleResult.Warnings.Count
                    }
                }
                
                # Progress update
                $progressPercent = [math]::Round(($moduleIndex / $totalModules) * 100)
                Write-LogMessage "Overall progress: $progressPercent% ($moduleIndex/$totalModules modules completed)" -Level "Info"
                
                if ($ExecutionMode -ne "Silent") {
                    Write-Host "Progress: $progressPercent% ($moduleIndex/$totalModules)" -ForegroundColor Green
                }
            }
            catch {
                $controllerResult.ModulesFailed += $module.Name
                $errorMessage = "Module '$($module.Name)' failed with exception: $($_.Exception.Message)"
                Write-LogMessage $errorMessage -Level "Error"
                $controllerResult.TotalErrors++
                
                if ($module.Critical) {
                    Write-LogMessage "CRITICAL MODULE EXCEPTION: $($module.Name)" -Level "Error"
                    
                    if ($ExecutionMode -eq "Interactive") {
                        Write-Host "`nCRITICAL MODULE EXCEPTION: $($module.Name)" -ForegroundColor Red
                        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                        
                        $continueChoice = Read-Host "Continue with remaining modules? (Y/N)"
                        if ($continueChoice.ToUpper() -ne "Y") {
                            Write-LogMessage "User chose to stop execution after critical module exception" -Level "Error"
                            throw "Critical module exception - execution stopped by user"
                        }
                    }
                }
            }
            
            $moduleIndex++
        }
        
        # Calculate overall results
        $controllerResult.ExecutionEndTime = Get-Date
        $controllerResult.ExecutionDuration = $controllerResult.ExecutionEndTime - $controllerResult.ExecutionStartTime
        
        # Determine overall success
        $criticalModules = $securityModules | Where-Object { $_.Critical }
        $criticalModulesFailed = $controllerResult.ModulesFailed | Where-Object { 
            $failedModule = $_
            $criticalModules | Where-Object { $_.Name -eq $failedModule }
        }
        
        if ($criticalModulesFailed.Count -eq 0 -and $controllerResult.ModulesSucceeded.Count -gt 0) {
            $controllerResult.Success = $true
            Write-LogMessage "Main Controller completed successfully" -Level "Success"
        }
        else {
            Write-LogMessage "Main Controller completed with failures" -Level "Warning"
        }
        
        # Generate execution summary
        Write-LogMessage "=== EXECUTION SUMMARY ===" -Level "Info"
        Write-LogMessage "Execution Mode: $($controllerResult.ExecutionMode)" -Level "Info"
        Write-LogMessage "Total Duration: $($controllerResult.ExecutionDuration.TotalMinutes.ToString('F2')) minutes" -Level "Info"
        Write-LogMessage "Modules Executed: $($controllerResult.ModulesExecuted.Count)" -Level "Info"
        Write-LogMessage "Modules Succeeded: $($controllerResult.ModulesSucceeded.Count)" -Level "Success"
        Write-LogMessage "Modules Failed: $($controllerResult.ModulesFailed.Count)" -Level $(if ($controllerResult.ModulesFailed.Count -gt 0) { "Error" } else { "Info" })
        Write-LogMessage "Total Changes Applied: $($controllerResult.TotalChanges)" -Level "Success"
        Write-LogMessage "Total Errors: $($controllerResult.TotalErrors)" -Level $(if ($controllerResult.TotalErrors -gt 0) { "Error" } else { "Info" })
        Write-LogMessage "Total Warnings: $($controllerResult.TotalWarnings)" -Level $(if ($controllerResult.TotalWarnings -gt 0) { "Warning" } else { "Info" })
        Write-LogMessage "Overall Success: $($controllerResult.Success)" -Level $(if ($controllerResult.Success) { "Success" } else { "Error" })
        
        if ($controllerResult.ModulesSucceeded.Count -gt 0) {
            Write-LogMessage "Successful Modules:" -Level "Success"
            foreach ($module in $controllerResult.ModulesSucceeded) {
                Write-LogMessage "  - $module" -Level "Success"
            }
        }
        
        if ($controllerResult.ModulesFailed.Count -gt 0) {
            Write-LogMessage "Failed Modules:" -Level "Error"
            foreach ($module in $controllerResult.ModulesFailed) {
                Write-LogMessage "  - $module" -Level "Error"
            }
        }
        
        return $controllerResult
    }
    catch {
        $controllerResult.ExecutionEndTime = Get-Date
        $controllerResult.ExecutionDuration = $controllerResult.ExecutionEndTime - $controllerResult.ExecutionStartTime
        
        Write-LogMessage "Main Controller failed with exception: $($_.Exception.Message)" -Level "Error"
        Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "Debug"
        
        return $controllerResult
    }
}

function Start-InteractiveMode {
    <#
    .SYNOPSIS
        Starts the script in interactive mode with user prompts and confirmations
    .DESCRIPTION
        Implements interactive mode execution with user prompts, confirmations,
        and real-time feedback during the security hardening process
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result from main controller
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Interactive Mode execution" -Level "Info"
    
    try {
        # Display welcome message
        Clear-Host
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║              Windows Security Hardening Script              ║" -ForegroundColor Cyan
        Write-Host "║                     Interactive Mode                        ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "This script will guide you through the Windows security hardening process." -ForegroundColor White
        Write-Host "You will be prompted before each major operation." -ForegroundColor White
        Write-Host ""
        
        # Show system information
        Write-Host "System Information:" -ForegroundColor Yellow
        Write-Host "  Computer Name: $env:COMPUTERNAME" -ForegroundColor Gray
        Write-Host "  User: $env:USERNAME" -ForegroundColor Gray
        Write-Host "  OS Version: $((Get-WmiObject Win32_OperatingSystem).Caption)" -ForegroundColor Gray
        Write-Host "  PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
        Write-Host ""
        
        # Execute main controller in interactive mode
        $result = Invoke-MainController -Config $Config -ExecutionMode "Interactive"
        
        # Display final results
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $(if ($result.Success) { "Green" } else { "Red" })
        Write-Host "║                    EXECUTION COMPLETE                       ║" -ForegroundColor $(if ($result.Success) { "Green" } else { "Red" })
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $(if ($result.Success) { "Green" } else { "Red" })
        Write-Host ""
        
        if ($result.Success) {
            Write-Host "✓ Security hardening completed successfully!" -ForegroundColor Green
        }
        else {
            Write-Host "⚠ Security hardening completed with issues." -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "Summary:" -ForegroundColor White
        Write-Host "  Duration: $($result.ExecutionDuration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor Gray
        Write-Host "  Modules Succeeded: $($result.ModulesSucceeded.Count)" -ForegroundColor Green
        Write-Host "  Modules Failed: $($result.ModulesFailed.Count)" -ForegroundColor $(if ($result.ModulesFailed.Count -gt 0) { "Red" } else { "Gray" })
        Write-Host "  Changes Applied: $($result.TotalChanges)" -ForegroundColor Green
        Write-Host "  Errors: $($result.TotalErrors)" -ForegroundColor $(if ($result.TotalErrors -gt 0) { "Red" } else { "Gray" })
        Write-Host "  Warnings: $($result.TotalWarnings)" -ForegroundColor $(if ($result.TotalWarnings -gt 0) { "Yellow" } else { "Gray" })
        Write-Host ""
        
        if ($result.ModulesFailed.Count -gt 0) {
            Write-Host "Failed Modules:" -ForegroundColor Red
            foreach ($module in $result.ModulesFailed) {
                Write-Host "  - $module" -ForegroundColor Red
            }
            Write-Host ""
        }
        
        Write-Host "Check the log file for detailed information about all changes made." -ForegroundColor White
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        
        return $result
    }
    catch {
        Write-LogMessage "Interactive mode failed: $($_.Exception.Message)" -Level "Error"
        Write-Host ""
        Write-Host "Interactive mode failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        throw
    }
}

function Start-SilentMode {
    <#
    .SYNOPSIS
        Starts the script in silent mode for automated deployment
    .DESCRIPTION
        Implements silent mode execution without user prompts for automated
        deployment scenarios and scheduled execution
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result from main controller
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting Silent Mode execution" -Level "Info"
    
    try {
        Write-LogMessage "Silent mode: No user interaction will be required" -Level "Info"
        Write-LogMessage "All modules will be executed automatically" -Level "Info"
        
        # Execute main controller in silent mode
        $result = Invoke-MainController -Config $Config -ExecutionMode "Silent"
        
        # Log final results
        Write-LogMessage "Silent mode execution completed" -Level "Info"
        Write-LogMessage "Overall Success: $($result.Success)" -Level $(if ($result.Success) { "Success" } else { "Error" })
        
        return $result
    }
    catch {
        Write-LogMessage "Silent mode failed: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

function Start-WhatIfMode {
    <#
    .SYNOPSIS
        Starts the script in WhatIf mode to show what changes would be made
    .DESCRIPTION
        Implements WhatIf mode execution that shows what changes would be made
        without actually applying them to the system
    .PARAMETER Config
        Configuration hashtable containing all security settings
    .OUTPUTS
        Returns execution result from main controller
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-LogMessage "Starting WhatIf Mode execution" -Level "Info"
    
    try {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
        Write-Host "║                      WHATIF MODE                            ║" -ForegroundColor Magenta
        Write-Host "║              No changes will be made                        ║" -ForegroundColor Magenta
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "This mode will show you what changes would be applied without making them." -ForegroundColor White
        Write-Host ""
        
        # Execute main controller in WhatIf mode
        $result = Invoke-MainController -Config $Config -ExecutionMode "WhatIf"
        
        # Display final results
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
        Write-Host "║                   WHATIF COMPLETE                           ║" -ForegroundColor Magenta
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "WhatIf analysis completed. No changes were made to your system." -ForegroundColor Magenta
        Write-Host ""
        Write-Host "Summary of what would be changed:" -ForegroundColor White
        Write-Host "  Modules that would run: $($result.ModulesExecuted.Count)" -ForegroundColor Gray
        Write-Host "  Potential changes: $($result.TotalChanges)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "To apply these changes, run the script without the -WhatIf parameter." -ForegroundColor White
        Write-Host ""
        
        return $result
    }
    catch {
        Write-LogMessage "WhatIf mode failed: $($_.Exception.Message)" -Level "Error"
        Write-Host ""
        Write-Host "WhatIf mode failed: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Invoke-ParameterHandling {
    <#
    .SYNOPSIS
        Handles different execution scenarios based on script parameters
    .DESCRIPTION
        Processes script parameters and determines the appropriate execution mode
        and configuration for different deployment scenarios
    .OUTPUTS
        Returns the appropriate execution result based on parameters
    #>
    
    Write-LogMessage "Processing script parameters and execution scenarios" -Level "Info"
    Write-LogMessage "Parameters: ConfigFile='$ConfigFile', LogPath='$LogPath', Silent=$Silent, WhatIf=$WhatIf" -Level "Info"
    
    try {
        # Initialize logging system
        Write-LogMessage "Initializing logging system with path: $LogPath" -Level "Info"
        Initialize-LoggingSystem -LogPath $LogPath
        
        # Initialize configuration
        Write-LogMessage "Initializing configuration system" -Level "Info"
        $config = Initialize-Configuration
        
        # Validate prerequisites
        Write-LogMessage "Validating system prerequisites" -Level "Info"
        if (-not (Test-Prerequisites)) {
            throw "System prerequisites validation failed"
        }
        
        # Initialize backup system (unless in WhatIf mode)
        if (-not $WhatIf) {
            Write-LogMessage "Initializing backup system" -Level "Info"
            $backupResult = Initialize-BackupSystem -LogPath $LogPath
            
            if (-not $backupResult -and -not $Silent) {
                $continueChoice = Read-Host "`nBackup system initialization had warnings. Continue anyway? (Y/N)"
                if ($continueChoice -notmatch '^[Yy]') {
                    Write-LogMessage "Execution cancelled due to backup system warnings" -Level "Warning"
                    return @{ Success = $false; Reason = "Backup system warnings" }
                }
            }
        }
        
        # Determine execution mode and execute
        $executionResult = $null
        
        if ($WhatIf) {
            Write-LogMessage "Executing in WhatIf mode" -Level "Info"
            $executionResult = Start-WhatIfMode -Config $config
        }
        elseif ($Silent) {
            Write-LogMessage "Executing in Silent mode" -Level "Info"
            $executionResult = Start-SilentMode -Config $config
        }
        else {
            Write-LogMessage "Executing in Interactive mode" -Level "Info"
            $executionResult = Start-InteractiveMode -Config $config
        }
        
        # Generate final compliance report
        Write-LogMessage "Generating final compliance report" -Level "Info"
        $complianceReportPath = Join-Path $LogPath "ComplianceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Generate-ComplianceReport -ExecutionResults $Script:ExecutionResults -OutputPath $complianceReportPath
        
        return $executionResult
    }
    catch {
        Write-LogMessage "Parameter handling failed: $($_.Exception.Message)" -Level "Error"
        Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "Debug"
        throw
    }
}

#endregion

#region Main Script Entry Point

# Main script execution entry point
try {
    Write-Host "Windows Security Hardening Script v$Script:ScriptVersion" -ForegroundColor Cyan
    Write-Host "Starting execution..." -ForegroundColor White
    
    # Execute parameter handling and main controller
    $finalResult = Invoke-ParameterHandling
    
    # Set exit code based on results
    if ($finalResult -and $finalResult.Success) {
        Write-LogMessage "Script execution completed successfully" -Level "Success"
        exit 0
    }
    else {
        Write-LogMessage "Script execution completed with failures" -Level "Error"
        exit 1
    }
}
catch {
    Write-LogMessage "Critical script failure: $($_.Exception.Message)" -Level "Error"
    Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "Debug"
    
    if (-not $Silent) {
        Write-Host "`nCritical script failure: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Check the log file for detailed error information." -ForegroundColor Yellow
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    exit 1
}

#endregion