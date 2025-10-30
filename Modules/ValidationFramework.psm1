<#
.SYNOPSIS
    Validation and Verification Framework Module

.DESCRIPTION
    This module provides comprehensive validation and verification functionality
    including pre-execution system compatibility checks, post-change verification,
    compliance validation, and system health monitoring.
    
    Requirements: 12.1, 12.2, 12.4
#>

# Import required modules for validation
if (Get-Module -Name "ErrorHandling" -ListAvailable) {
    Import-Module "ErrorHandling" -Force
}

# Global variables for validation
$Script:ValidationResults = @()
$Script:ComplianceResults = @()
$Script:SystemHealthBaseline = @{}

#region Pre-Execution System Compatibility Checks

function Test-SystemCompatibility {
    <#
    .SYNOPSIS
        Performs comprehensive pre-execution system compatibility checks
    .DESCRIPTION
        Validates system requirements, dependencies, and readiness for security hardening
    .OUTPUTS
        Hashtable containing compatibility check results
    #>
    
    Write-LogMessage "Starting comprehensive system compatibility checks..." -Level "Info"
    
    $compatibilityResult = @{
        OverallCompatible = $true
        Checks = @{}
        Errors = @()
        Warnings = @()
        Recommendations = @()
    }
    
    # Check 1: Operating System Compatibility
    $osCheck = Test-OperatingSystemCompatibility
    $compatibilityResult.Checks["OperatingSystem"] = $osCheck
    if (-not $osCheck.Compatible) {
        $compatibilityResult.OverallCompatible = $false
        $compatibilityResult.Errors += $osCheck.Issues
    }
    
    # Check 2: PowerShell Version and Features
    $psCheck = Test-PowerShellCompatibility
    $compatibilityResult.Checks["PowerShell"] = $psCheck
    if (-not $psCheck.Compatible) {
        $compatibilityResult.OverallCompatible = $false
        $compatibilityResult.Errors += $psCheck.Issues
    }
    
    # Check 3: Required Windows Features and Services
    $featuresCheck = Test-RequiredFeaturesAvailability
    $compatibilityResult.Checks["WindowsFeatures"] = $featuresCheck
    if (-not $featuresCheck.Compatible) {
        $compatibilityResult.Warnings += $featuresCheck.Issues
    }
    
    # Check 4: System Resources and Performance
    $resourcesCheck = Test-SystemResources
    $compatibilityResult.Checks["SystemResources"] = $resourcesCheck
    if (-not $resourcesCheck.Compatible) {
        $compatibilityResult.Warnings += $resourcesCheck.Issues
    }
    
    # Check 5: Network Configuration Prerequisites
    $networkCheck = Test-NetworkPrerequisites
    $compatibilityResult.Checks["Network"] = $networkCheck
    if (-not $networkCheck.Compatible) {
        $compatibilityResult.Warnings += $networkCheck.Issues
    }
    
    # Check 6: Security Software Compatibility
    $securityCheck = Test-SecuritySoftwareCompatibility
    $compatibilityResult.Checks["SecuritySoftware"] = $securityCheck
    if (-not $securityCheck.Compatible) {
        $compatibilityResult.Warnings += $securityCheck.Issues
        $compatibilityResult.Recommendations += $securityCheck.Recommendations
    }
    
    # Generate overall compatibility report
    if ($compatibilityResult.OverallCompatible) {
        Write-LogMessage "System compatibility check passed - system is ready for security hardening" -Level "Success"
    }
    else {
        Write-LogMessage "System compatibility check failed - critical issues must be resolved" -Level "Error"
    }
    
    return $compatibilityResult
}f
unction Test-OperatingSystemCompatibility {
    <#
    .SYNOPSIS
        Tests operating system compatibility for security hardening
    .OUTPUTS
        Hashtable containing OS compatibility results
    #>
    
    $result = @{
        Compatible = $true
        Issues = @()
        Details = @{}
    }
    
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $result.Details["OSName"] = $osInfo.Caption
        $result.Details["OSVersion"] = $osInfo.Version
        $result.Details["OSArchitecture"] = $osInfo.OSArchitecture
        $result.Details["BuildNumber"] = $osInfo.BuildNumber
        
        # Check minimum Windows version (Windows 10 1809 / Server 2019)
        $minVersion = [Version]"10.0.17763"
        $currentVersion = [Version]$osInfo.Version
        
        if ($currentVersion -lt $minVersion) {
            $result.Compatible = $false
            $result.Issues += "Windows version $($osInfo.Version) is not supported. Minimum required: Windows 10 1809 (10.0.17763) or Windows Server 2019"
        }
        
        # Check architecture (64-bit required for some features)
        if ($osInfo.OSArchitecture -ne "64-bit") {
            $result.Issues += "64-bit architecture recommended for optimal security features"
        }
        
        # Check if it's a domain controller (special considerations)
        $isDomainController = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -in @(4, 5)
        $result.Details["IsDomainController"] = $isDomainController
        
        if ($isDomainController) {
            $result.Issues += "Domain Controller detected - some security settings may require special consideration"
        }
        
        Write-LogMessage "OS Compatibility: $($osInfo.Caption) $($osInfo.Version) - Compatible: $($result.Compatible)" -Level "Info"
    }
    catch {
        $result.Compatible = $false
        $result.Issues += "Failed to retrieve operating system information: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-PowerShellCompatibility {
    <#
    .SYNOPSIS
        Tests PowerShell version and feature compatibility
    .OUTPUTS
        Hashtable containing PowerShell compatibility results
    #>
    
    $result = @{
        Compatible = $true
        Issues = @()
        Details = @{}
    }
    
    try {
        $result.Details["PSVersion"] = $PSVersionTable.PSVersion.ToString()
        $result.Details["PSEdition"] = $PSVersionTable.PSEdition
        $result.Details["CLRVersion"] = $PSVersionTable.CLRVersion.ToString()
        
        # Check minimum PowerShell version (5.1 or 7.0+)
        $minVersion51 = [Version]"5.1.0"
        $minVersion7 = [Version]"7.0.0"
        $currentVersion = $PSVersionTable.PSVersion
        
        if ($currentVersion -lt $minVersion51 -and $currentVersion -lt $minVersion7) {
            $result.Compatible = $false
            $result.Issues += "PowerShell version $currentVersion is not supported. Minimum required: PowerShell 5.1 or PowerShell 7.0+"
        }
        
        # Check execution policy
        $executionPolicy = Get-ExecutionPolicy
        $result.Details["ExecutionPolicy"] = $executionPolicy
        
        if ($executionPolicy -eq "Restricted") {
            $result.Issues += "PowerShell execution policy is set to Restricted - may prevent script execution"
        }
        
        # Check required modules availability
        $requiredModules = @("Microsoft.PowerShell.Management", "Microsoft.PowerShell.Security", "NetSecurity")
        $missingModules = @()
        
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -Name $module -ListAvailable)) {
                $missingModules += $module
            }
        }
        
        if ($missingModules.Count -gt 0) {
            $result.Issues += "Missing required PowerShell modules: $($missingModules -join ', ')"
        }
        
        Write-LogMessage "PowerShell Compatibility: Version $($PSVersionTable.PSVersion) - Compatible: $($result.Compatible)" -Level "Info"
    }
    catch {
        $result.Compatible = $false
        $result.Issues += "Failed to check PowerShell compatibility: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-RequiredFeaturesAvailability {
    <#
    .SYNOPSIS
        Tests availability of required Windows features and services
    .OUTPUTS
        Hashtable containing features availability results
    #>
    
    $result = @{
        Compatible = $true
        Issues = @()
        Details = @{}
    }
    
    try {
        # Check Windows Firewall service
        $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
        $result.Details["WindowsFirewall"] = if ($firewallService) { $firewallService.Status } else { "NotFound" }
        
        if (-not $firewallService) {
            $result.Compatible = $false
            $result.Issues += "Windows Firewall service not found - required for firewall configuration"
        }
        
        # Check Group Policy service
        $gpService = Get-Service -Name "gpsvc" -ErrorAction SilentlyContinue
        $result.Details["GroupPolicy"] = if ($gpService) { $gpService.Status } else { "NotFound" }
        
        # Check Windows Update service
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        $result.Details["WindowsUpdate"] = if ($wuService) { $wuService.Status } else { "NotFound" }
        
        # Check Registry service
        $regService = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        $result.Details["RemoteRegistry"] = if ($regService) { $regService.Status } else { "NotFound" }
        
        # Check if secedit.exe is available (for security policy configuration)
        $seceditPath = Get-Command "secedit.exe" -ErrorAction SilentlyContinue
        $result.Details["SecEdit"] = if ($seceditPath) { "Available" } else { "NotFound" }
        
        if (-not $seceditPath) {
            $result.Issues += "secedit.exe not found - required for security policy configuration"
        }
        
        Write-LogMessage "Required Features Check - Compatible: $($result.Compatible)" -Level "Info"
    }
    catch {
        $result.Compatible = $false
        $result.Issues += "Failed to check required features: $($_.Exception.Message)"
    }
    
    return $result
}func
tion Test-SystemResources {
    <#
    .SYNOPSIS
        Tests system resources and performance for security hardening operations
    .OUTPUTS
        Hashtable containing system resources results
    #>
    
    $result = @{
        Compatible = $true
        Issues = @()
        Details = @{}
    }
    
    try {
        # Check available memory
        $memory = Get-CimInstance -ClassName Win32_ComputerSystem
        $totalMemoryGB = [Math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
        $result.Details["TotalMemoryGB"] = $totalMemoryGB
        
        if ($totalMemoryGB -lt 2) {
            $result.Issues += "Low system memory ($totalMemoryGB GB) - may affect performance during security hardening"
        }
        
        # Check available disk space
        $systemDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
        $freeSpaceGB = [Math]::Round($systemDrive.FreeSpace / 1GB, 2)
        $result.Details["FreeSpaceGB"] = $freeSpaceGB
        
        if ($freeSpaceGB -lt 1) {
            $result.Compatible = $false
            $result.Issues += "Insufficient disk space ($freeSpaceGB GB free) - minimum 1GB required for backups and logs"
        }
        
        # Check CPU usage
        $cpu = Get-CimInstance -ClassName Win32_Processor
        $result.Details["ProcessorName"] = $cpu.Name
        $result.Details["NumberOfCores"] = $cpu.NumberOfCores
        
        # Check current system load
        $perfCounter = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3
        $avgCpuUsage = ($perfCounter.CounterSamples | Measure-Object -Property CookedValue -Average).Average
        $result.Details["CurrentCPUUsage"] = [Math]::Round($avgCpuUsage, 2)
        
        if ($avgCpuUsage -gt 80) {
            $result.Issues += "High CPU usage ($([Math]::Round($avgCpuUsage, 2))%) - may affect security hardening performance"
        }
        
        Write-LogMessage "System Resources Check - Memory: $totalMemoryGB GB, Free Space: $freeSpaceGB GB, CPU: $([Math]::Round($avgCpuUsage, 2))%" -Level "Info"
    }
    catch {
        $result.Issues += "Failed to check system resources: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-NetworkPrerequisites {
    <#
    .SYNOPSIS
        Tests network configuration prerequisites
    .OUTPUTS
        Hashtable containing network prerequisites results
    #>
    
    $result = @{
        Compatible = $true
        Issues = @()
        Details = @{}
    }
    
    try {
        # Check network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $result.Details["ActiveAdapters"] = $adapters.Count
        
        if ($adapters.Count -eq 0) {
            $result.Compatible = $false
            $result.Issues += "No active network adapters found - network configuration cannot be applied"
        }
        
        # Check if network location is set
        $networkProfiles = Get-NetConnectionProfile
        $result.Details["NetworkProfiles"] = $networkProfiles.Count
        
        foreach ($profile in $networkProfiles) {
            if ($profile.NetworkCategory -eq "Public") {
                $result.Issues += "Public network profile detected - some security settings may be more restrictive"
            }
        }
        
        # Check DNS resolution
        try {
            $dnsTest = Resolve-DnsName "microsoft.com" -ErrorAction Stop
            $result.Details["DNSResolution"] = "Working"
        }
        catch {
            $result.Issues += "DNS resolution test failed - may affect some network configurations"
            $result.Details["DNSResolution"] = "Failed"
        }
        
        Write-LogMessage "Network Prerequisites Check - Active Adapters: $($adapters.Count)" -Level "Info"
    }
    catch {
        $result.Issues += "Failed to check network prerequisites: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-SecuritySoftwareCompatibility {
    <#
    .SYNOPSIS
        Tests compatibility with existing security software
    .OUTPUTS
        Hashtable containing security software compatibility results
    #>
    
    $result = @{
        Compatible = $true
        Issues = @()
        Recommendations = @()
        Details = @{}
    }
    
    try {
        # Check Windows Defender status
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                $result.Details["WindowsDefender"] = @{
                    AntivirusEnabled = $defenderStatus.AntivirusEnabled
                    RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                    AntivirusSignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                }
                
                if (-not $defenderStatus.AntivirusEnabled) {
                    $result.Issues += "Windows Defender antivirus is disabled"
                }
            }
            else {
                $result.Details["WindowsDefender"] = "NotAvailable"
            }
        }
        catch {
            $result.Details["WindowsDefender"] = "CheckFailed"
        }
        
        # Check for third-party antivirus
        $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
        
        if ($antivirusProducts) {
            $result.Details["ThirdPartyAntivirus"] = @()
            
            foreach ($av in $antivirusProducts) {
                $avInfo = @{
                    DisplayName = $av.displayName
                    ProductState = $av.productState
                }
                $result.Details["ThirdPartyAntivirus"] += $avInfo
                
                # Check if third-party AV might interfere
                if ($av.displayName -notmatch "Windows Defender|Microsoft") {
                    $result.Recommendations += "Third-party antivirus '$($av.displayName)' detected - may require exclusions for security hardening operations"
                }
            }
        }
        
        # Check Windows Firewall profiles
        $firewallProfiles = Get-NetFirewallProfile
        $result.Details["FirewallProfiles"] = @{}
        
        foreach ($profile in $firewallProfiles) {
            $result.Details["FirewallProfiles"][$profile.Name] = @{
                Enabled = $profile.Enabled
                DefaultInboundAction = $profile.DefaultInboundAction
                DefaultOutboundAction = $profile.DefaultOutboundAction
            }
            
            if (-not $profile.Enabled) {
                $result.Issues += "Windows Firewall profile '$($profile.Name)' is disabled"
            }
        }
        
        Write-LogMessage "Security Software Compatibility Check completed" -Level "Info"
    }
    catch {
        $result.Issues += "Failed to check security software compatibility: $($_.Exception.Message)"
    }
    
    return $result
}#endreg
ion

#region Post-Change Verification Functions

function Initialize-SystemHealthBaseline {
    <#
    .SYNOPSIS
        Captures baseline system health metrics before security hardening
    .DESCRIPTION
        Records current system state for comparison after changes are applied
    #>
    
    Write-LogMessage "Capturing system health baseline..." -Level "Info"
    
    try {
        $Script:SystemHealthBaseline = @{
            Timestamp = Get-Date
            Services = @{}
            NetworkAdapters = @{}
            FirewallRules = @{}
            RegistryKeys = @{}
            WindowsFeatures = @{}
            SecurityPolicies = @{}
            SystemPerformance = @{}
        }
        
        # Capture services baseline
        $services = Get-Service
        foreach ($service in $services) {
            $Script:SystemHealthBaseline.Services[$service.Name] = @{
                Status = $service.Status
                StartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'").StartMode
            }
        }
        
        # Capture network adapters baseline
        $adapters = Get-NetAdapter
        foreach ($adapter in $adapters) {
            $Script:SystemHealthBaseline.NetworkAdapters[$adapter.Name] = @{
                Status = $adapter.Status
                LinkSpeed = $adapter.LinkSpeed
                InterfaceDescription = $adapter.InterfaceDescription
            }
        }
        
        # Capture firewall rules count
        $firewallRules = Get-NetFirewallRule
        $Script:SystemHealthBaseline.FirewallRules = @{
            TotalRules = $firewallRules.Count
            InboundRules = ($firewallRules | Where-Object { $_.Direction -eq "Inbound" }).Count
            OutboundRules = ($firewallRules | Where-Object { $_.Direction -eq "Outbound" }).Count
            BlockRules = ($firewallRules | Where-Object { $_.Action -eq "Block" }).Count
        }
        
        # Capture system performance baseline
        $cpu = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1
        $memory = Get-CimInstance -ClassName Win32_OperatingSystem
        
        $Script:SystemHealthBaseline.SystemPerformance = @{
            CPUUsage = $cpu.CounterSamples[0].CookedValue
            MemoryUsagePercent = [Math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
            AvailableMemoryMB = [Math]::Round($memory.FreePhysicalMemory / 1KB, 2)
        }
        
        Write-LogMessage "System health baseline captured successfully" -Level "Success"
        Write-LogMessage "Baseline includes $($Script:SystemHealthBaseline.Services.Count) services, $($Script:SystemHealthBaseline.NetworkAdapters.Count) network adapters, $($Script:SystemHealthBaseline.FirewallRules.TotalRules) firewall rules" -Level "Info"
    }
    catch {
        Write-LogMessage "Failed to capture system health baseline: $($_.Exception.Message)" -Level "Error"
        throw [ValidationException]::new("Failed to capture system health baseline: $($_.Exception.Message)", "ValidationFramework")
    }
}

function Test-PostChangeVerification {
    <#
    .SYNOPSIS
        Verifies system health and configuration after security hardening changes
    .PARAMETER ModuleName
        Name of the module that made changes
    .PARAMETER ExpectedChanges
        Array of expected changes to verify
    .OUTPUTS
        Hashtable containing verification results
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $false)]
        [array]$ExpectedChanges = @()
    )
    
    Write-LogMessage "Performing post-change verification for module: $ModuleName" -Level "Info"
    
    $verificationResult = @{
        ModuleName = $ModuleName
        Success = $true
        VerifiedChanges = @()
        FailedVerifications = @()
        SystemHealthImpact = @{}
        Warnings = @()
        Timestamp = Get-Date
    }
    
    try {
        # Verify expected changes
        foreach ($expectedChange in $ExpectedChanges) {
            $changeVerification = Confirm-SpecificChange -Change $expectedChange
            
            if ($changeVerification.Verified) {
                $verificationResult.VerifiedChanges += $changeVerification
                Write-LogMessage "Verified change: $($expectedChange.Description)" -Level "Success"
            }
            else {
                $verificationResult.FailedVerifications += $changeVerification
                $verificationResult.Success = $false
                Write-LogMessage "Failed to verify change: $($expectedChange.Description)" -Level "Error"
            }
        }
        
        # Check system health impact
        $healthImpact = Test-SystemHealthImpact
        $verificationResult.SystemHealthImpact = $healthImpact
        
        if ($healthImpact.CriticalIssues.Count -gt 0) {
            $verificationResult.Success = $false
            $verificationResult.Warnings += "Critical system health issues detected after changes"
        }
        
        # Add to global validation results
        $Script:ValidationResults += $verificationResult
        
        if ($verificationResult.Success) {
            Write-LogMessage "Post-change verification completed successfully for $ModuleName" -Level "Success"
        }
        else {
            Write-LogMessage "Post-change verification failed for $ModuleName" -Level "Error"
        }
    }
    catch {
        $verificationResult.Success = $false
        $verificationResult.FailedVerifications += @{
            Description = "Verification process failed"
            Error = $_.Exception.Message
            Verified = $false
        }
        
        Write-LogMessage "Post-change verification failed with exception: $($_.Exception.Message)" -Level "Error"
    }
    
    return $verificationResult
}

function Confirm-SpecificChange {
    <#
    .SYNOPSIS
        Confirms a specific configuration change was applied correctly
    .PARAMETER Change
        Hashtable describing the change to verify
    .OUTPUTS
        Hashtable containing verification result
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Change
    )
    
    $result = @{
        Description = $Change.Description
        Type = $Change.Type
        Verified = $false
        ActualValue = $null
        ExpectedValue = $Change.ExpectedValue
        Error = $null
    }
    
    try {
        switch ($Change.Type) {
            "Service" {
                $servic