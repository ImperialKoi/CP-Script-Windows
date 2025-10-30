<#
.SYNOPSIS
    Centralized Logging System Module

.DESCRIPTION
    This module provides centralized logging functionality for the
    Windows Security Hardening script with support for both console
    and file output with different log levels.
#>

# Global variables for logging
$Script:LogFile = ""

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the centralized logging system
    .DESCRIPTION
        Sets up log file path and creates initial log entries
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,
        
        [Parameter(Mandatory = $true)]
        [string]$ScriptVersion
    )
    
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
$ScriptName v$ScriptVersion
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

function Get-LogFilePath {
    <#
    .SYNOPSIS
        Returns the current log file path
    .OUTPUTS
        String containing the log file path
    #>
    
    return $Script:LogFile
}

#region Progress Reporting Functions

function Initialize-ProgressReporting {
    <#
    .SYNOPSIS
        Initializes progress reporting system for script execution
    .DESCRIPTION
        Sets up progress tracking variables and creates initial progress report structure
    .PARAMETER TotalModules
        Total number of modules to be executed
    .PARAMETER ModuleNames
        Array of module names for progress tracking
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [int]$TotalModules,
        
        [Parameter(Mandatory = $true)]
        [array]$ModuleNames
    )
    
    $Script:ProgressData = @{
        TotalModules = $TotalModules
        CompletedModules = 0
        CurrentModule = ""
        ModuleNames = $ModuleNames
        StartTime = Get-Date
        ModuleProgress = @{}
    }
    
    Write-LogMessage "Progress reporting initialized for $TotalModules modules" -Level "Info"
    Write-LogMessage "Modules to execute: $($ModuleNames -join ', ')" -Level "Info"
}

function Update-ModuleProgress {
    <#
    .SYNOPSIS
        Updates progress for the current module being executed
    .PARAMETER ModuleName
        Name of the module being executed
    .PARAMETER Status
        Current status (Starting, InProgress, Completed, Failed)
    .PARAMETER PercentComplete
        Percentage completion for the current module (0-100)
    .PARAMETER CurrentStep
        Description of current step being executed
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Starting", "InProgress", "Completed", "Failed")]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [int]$PercentComplete = 0,
        
        [Parameter(Mandatory = $false)]
        [string]$CurrentStep = ""
    )
    
    if (-not $Script:ProgressData) {
        Write-LogMessage "Progress reporting not initialized" -Level "Warning"
        return
    }
    
    $Script:ProgressData.CurrentModule = $ModuleName
    
    # Update module-specific progress
    if (-not $Script:ProgressData.ModuleProgress.ContainsKey($ModuleName)) {
        $Script:ProgressData.ModuleProgress[$ModuleName] = @{
            Status = "Starting"
            PercentComplete = 0
            StartTime = Get-Date
            EndTime = $null
            CurrentStep = ""
        }
    }
    
    $moduleProgress = $Script:ProgressData.ModuleProgress[$ModuleName]
    $moduleProgress.Status = $Status
    $moduleProgress.PercentComplete = $PercentComplete
    $moduleProgress.CurrentStep = $CurrentStep
    
    if ($Status -eq "Completed" -or $Status -eq "Failed") {
        $moduleProgress.EndTime = Get-Date
        if ($Status -eq "Completed") {
            $Script:ProgressData.CompletedModules++
        }
    }
    
    # Calculate overall progress
    $overallProgress = [math]::Round(($Script:ProgressData.CompletedModules / $Script:ProgressData.TotalModules) * 100, 1)
    
    # Display progress information
    $progressMessage = "[$overallProgress%] Module: $ModuleName - $Status"
    if ($CurrentStep) {
        $progressMessage += " - $CurrentStep"
    }
    if ($PercentComplete -gt 0) {
        $progressMessage += " ($PercentComplete%)"
    }
    
    Write-LogMessage $progressMessage -Level "Info"
    
    # Update PowerShell progress bar if available
    try {
        Write-Progress -Activity "Windows Security Hardening" -Status $progressMessage -PercentComplete $overallProgress
    }
    catch {
        # Progress bar not available in all environments
    }
}

function Write-ProgressSummary {
    <#
    .SYNOPSIS
        Writes a summary of overall progress to the log
    .DESCRIPTION
        Displays current execution progress including completed modules and time elapsed
    #>
    
    if (-not $Script:ProgressData) {
        Write-LogMessage "Progress reporting not initialized" -Level "Warning"
        return
    }
    
    $elapsed = (Get-Date) - $Script:ProgressData.StartTime
    $overallProgress = [math]::Round(($Script:ProgressData.CompletedModules / $Script:ProgressData.TotalModules) * 100, 1)
    
    Write-LogMessage "=== PROGRESS SUMMARY ===" -Level "Info"
    Write-LogMessage "Overall Progress: $overallProgress% ($($Script:ProgressData.CompletedModules)/$($Script:ProgressData.TotalModules) modules)" -Level "Info"
    Write-LogMessage "Time Elapsed: $($elapsed.ToString('hh\:mm\:ss'))" -Level "Info"
    Write-LogMessage "Current Module: $($Script:ProgressData.CurrentModule)" -Level "Info"
    
    # Show status of each module
    foreach ($moduleName in $Script:ProgressData.ModuleNames) {
        if ($Script:ProgressData.ModuleProgress.ContainsKey($moduleName)) {
            $moduleData = $Script:ProgressData.ModuleProgress[$moduleName]
            $duration = if ($moduleData.EndTime) { 
                ($moduleData.EndTime - $moduleData.StartTime).ToString('mm\:ss')
            } else { 
                "In Progress" 
            }
            Write-LogMessage "  $moduleName: $($moduleData.Status) - $duration" -Level "Info"
        } else {
            Write-LogMessage "  $moduleName: Not Started" -Level "Info"
        }
    }
    Write-LogMessage "=========================" -Level "Info"
}

#endregion

#region Change Logging Functions

function Initialize-ChangeLogging {
    <#
    .SYNOPSIS
        Initializes detailed change logging system
    .DESCRIPTION
        Sets up change tracking for all system modifications made by the script
    #>
    
    $Script:ChangeLog = @{
        Changes = @()
        StartTime = Get-Date
        SystemInfo = @{
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
            OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        }
    }
    
    Write-LogMessage "Change logging initialized" -Level "Info"
    Write-LogMessage "System: $($Script:ChangeLog.SystemInfo.ComputerName) - $($Script:ChangeLog.SystemInfo.OSVersion)" -Level "Info"
}

function Add-ChangeLogEntry {
    <#
    .SYNOPSIS
        Adds a detailed change entry to the change log
    .PARAMETER ModuleName
        Name of the module making the change
    .PARAMETER ChangeType
        Type of change (Registry, Service, Feature, Policy, Network, Firewall, User, System)
    .PARAMETER Target
        Target of the change (registry key, service name, etc.)
    .PARAMETER Action
        Action performed (Created, Modified, Deleted, Enabled, Disabled, Started, Stopped)
    .PARAMETER OldValue
        Previous value (if applicable)
    .PARAMETER NewValue
        New value set
    .PARAMETER RequirementId
        Requirement ID this change satisfies
    .PARAMETER Success
        Whether the change was successful
    .PARAMETER ErrorMessage
        Error message if change failed
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Registry", "Service", "Feature", "Policy", "Network", "Firewall", "User", "System", "File")]
        [string]$ChangeType,
        
        [Parameter(Mandatory = $true)]
        [string]$Target,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Created", "Modified", "Deleted", "Enabled", "Disabled", "Started", "Stopped", "Configured", "Applied")]
        [string]$Action,
        
        [Parameter(Mandatory = $false)]
        [string]$OldValue = "",
        
        [Parameter(Mandatory = $false)]
        [string]$NewValue = "",
        
        [Parameter(Mandatory = $false)]
        [string]$RequirementId = "",
        
        [Parameter(Mandatory = $true)]
        [bool]$Success,
        
        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = ""
    )
    
    if (-not $Script:ChangeLog) {
        Initialize-ChangeLogging
    }
    
    $changeEntry = @{
        Timestamp = Get-Date
        ModuleName = $ModuleName
        ChangeType = $ChangeType
        Target = $Target
        Action = $Action
        OldValue = $OldValue
        NewValue = $NewValue
        RequirementId = $RequirementId
        Success = $Success
        ErrorMessage = $ErrorMessage
    }
    
    $Script:ChangeLog.Changes += $changeEntry
    
    # Log the change
    $changeDescription = "$ChangeType change: $Action $Target"
    if ($NewValue) {
        $changeDescription += " = $NewValue"
    }
    if ($OldValue) {
        $changeDescription += " (was: $OldValue)"
    }
    if ($RequirementId) {
        $changeDescription += " [Req: $RequirementId]"
    }
    
    if ($Success) {
        Write-LogMessage "CHANGE: $changeDescription" -Level "Success"
    } else {
        Write-LogMessage "CHANGE FAILED: $changeDescription - $ErrorMessage" -Level "Error"
    }
}

function Get-ChangeLogSummary {
    <#
    .SYNOPSIS
        Returns a summary of all changes made during script execution
    .OUTPUTS
        Hashtable containing change statistics and summaries
    #>
    
    if (-not $Script:ChangeLog -or $Script:ChangeLog.Changes.Count -eq 0) {
        return @{
            TotalChanges = 0
            SuccessfulChanges = 0
            FailedChanges = 0
            ChangesByType = @{}
            ChangesByModule = @{}
            ChangesByRequirement = @{}
        }
    }
    
    $summary = @{
        TotalChanges = $Script:ChangeLog.Changes.Count
        SuccessfulChanges = ($Script:ChangeLog.Changes | Where-Object { $_.Success }).Count
        FailedChanges = ($Script:ChangeLog.Changes | Where-Object { -not $_.Success }).Count
        ChangesByType = @{}
        ChangesByModule = @{}
        ChangesByRequirement = @{}
        ExecutionTime = (Get-Date) - $Script:ChangeLog.StartTime
    }
    
    # Group changes by type
    $Script:ChangeLog.Changes | Group-Object ChangeType | ForEach-Object {
        $summary.ChangesByType[$_.Name] = @{
            Total = $_.Count
            Successful = ($_.Group | Where-Object { $_.Success }).Count
            Failed = ($_.Group | Where-Object { -not $_.Success }).Count
        }
    }
    
    # Group changes by module
    $Script:ChangeLog.Changes | Group-Object ModuleName | ForEach-Object {
        $summary.ChangesByModule[$_.Name] = @{
            Total = $_.Count
            Successful = ($_.Group | Where-Object { $_.Success }).Count
            Failed = ($_.Group | Where-Object { -not $_.Success }).Count
        }
    }
    
    # Group changes by requirement
    $Script:ChangeLog.Changes | Where-Object { $_.RequirementId } | Group-Object RequirementId | ForEach-Object {
        $summary.ChangesByRequirement[$_.Name] = @{
            Total = $_.Count
            Successful = ($_.Group | Where-Object { $_.Success }).Count
            Failed = ($_.Group | Where-Object { -not $_.Success }).Count
        }
    }
    
    return $summary
}

#endregion

#region Execution Summary Report

function Generate-ExecutionSummaryReport {
    <#
    .SYNOPSIS
        Generates a comprehensive execution summary report
    .DESCRIPTION
        Creates a detailed report of the entire script execution including
        progress, changes, errors, and compliance status
    .PARAMETER ExecutionResults
        Array of execution results from all modules
    .PARAMETER OutputPath
        Path where to save the summary report file
    .OUTPUTS
        Returns the report content as a string and optionally saves to file
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$ExecutionResults,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ""
    )
    
    $reportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $changesSummary = Get-ChangeLogSummary
    
    # Build the report
    $report = @"
================================================================================
WINDOWS SECURITY HARDENING - EXECUTION SUMMARY REPORT
================================================================================
Generated: $reportTimestamp
Computer: $env:COMPUTERNAME
User: $env:USERNAME
PowerShell Version: $($PSVersionTable.PSVersion)

OVERALL EXECUTION SUMMARY
================================================================================
Total Modules Executed: $($ExecutionResults.Count)
Successful Modules: $(($ExecutionResults | Where-Object { $_.Success }).Count)
Failed Modules: $(($ExecutionResults | Where-Object { -not $_.Success }).Count)
Total Execution Time: $($changesSummary.ExecutionTime.ToString('hh\:mm\:ss'))

CHANGES SUMMARY
================================================================================
Total Changes Made: $($changesSummary.TotalChanges)
Successful Changes: $($changesSummary.SuccessfulChanges)
Failed Changes: $($changesSummary.FailedChanges)
Success Rate: $([math]::Round(($changesSummary.SuccessfulChanges / [math]::Max($changesSummary.TotalChanges, 1)) * 100, 1))%

CHANGES BY TYPE
================================================================================
"@

    # Add changes by type
    foreach ($changeType in $changesSummary.ChangesByType.Keys | Sort-Object) {
        $typeData = $changesSummary.ChangesByType[$changeType]
        $report += "`n$changeType Changes: $($typeData.Total) (Success: $($typeData.Successful), Failed: $($typeData.Failed))"
    }

    $report += @"

MODULE EXECUTION DETAILS
================================================================================
"@

    # Add module details
    foreach ($result in $ExecutionResults | Sort-Object ModuleName) {
        $status = if ($result.Success) { "SUCCESS" } else { "FAILED" }
        $report += "`n[$status] $($result.ModuleName)"
        $report += "`n  Execution Time: $($result.ExecutionTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        $report += "`n  Changes Made: $($result.Changes.Count)"
        $report += "`n  Errors: $($result.Errors.Count)"
        $report += "`n  Warnings: $($result.Warnings.Count)"
        
        if ($result.Changes.Count -gt 0) {
            $report += "`n  Changes:"
            foreach ($change in $result.Changes) {
                $report += "`n    - $change"
            }
        }
        
        if ($result.Errors.Count -gt 0) {
            $report += "`n  Errors:"
            foreach ($error in $result.Errors) {
                $report += "`n    - $error"
            }
        }
        
        if ($result.Warnings.Count -gt 0) {
            $report += "`n  Warnings:"
            foreach ($warning in $result.Warnings) {
                $report += "`n    - $warning"
            }
        }
        
        $report += "`n"
    }

    $report += @"

REQUIREMENTS COMPLIANCE
================================================================================
"@

    # Add requirements compliance
    foreach ($reqId in $changesSummary.ChangesByRequirement.Keys | Sort-Object) {
        $reqData = $changesSummary.ChangesByRequirement[$reqId]
        $complianceStatus = if ($reqData.Failed -eq 0) { "COMPLIANT" } else { "PARTIAL" }
        $report += "`nRequirement $reqId: $complianceStatus ($($reqData.Successful)/$($reqData.Total) changes successful)"
    }

    $report += @"


DETAILED CHANGE LOG
================================================================================
"@

    # Add detailed change log
    if ($Script:ChangeLog -and $Script:ChangeLog.Changes.Count -gt 0) {
        foreach ($change in $Script:ChangeLog.Changes | Sort-Object Timestamp) {
            $status = if ($change.Success) { "SUCCESS" } else { "FAILED" }
            $report += "`n[$($change.Timestamp.ToString('HH:mm:ss'))] [$status] $($change.ModuleName)"
            $report += "`n  Type: $($change.ChangeType) | Action: $($change.Action) | Target: $($change.Target)"
            
            if ($change.NewValue) {
                $report += "`n  New Value: $($change.NewValue)"
            }
            if ($change.OldValue) {
                $report += "`n  Old Value: $($change.OldValue)"
            }
            if ($change.RequirementId) {
                $report += "`n  Requirement: $($change.RequirementId)"
            }
            if (-not $change.Success -and $change.ErrorMessage) {
                $report += "`n  Error: $($change.ErrorMessage)"
            }
            $report += "`n"
        }
    } else {
        $report += "`nNo detailed change log available."
    }

    $report += @"

================================================================================
END OF REPORT
================================================================================
"@

    # Save to file if path provided
    if ($OutputPath) {
        try {
            $reportDir = Split-Path $OutputPath -Parent
            if ($reportDir -and -not (Test-Path $reportDir)) {
                New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
            }
            
            $report | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-LogMessage "Execution summary report saved to: $OutputPath" -Level "Success"
        }
        catch {
            Write-LogMessage "Failed to save execution summary report: $($_.Exception.Message)" -Level "Error"
        }
    }
    
    return $report
}

#endregion

#region Compliance Report

function Generate-ComplianceReport {
    <#
    .SYNOPSIS
        Generates a compliance report showing all applied configurations
    .DESCRIPTION
        Creates a detailed compliance report mapping all changes to specific
        requirements and showing the current security posture
    .PARAMETER ExecutionResults
        Array of execution results from all modules
    .PARAMETER OutputPath
        Path where to save the compliance report file
    .OUTPUTS
        Returns the compliance report content as a string and optionally saves to file
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [array]$ExecutionResults,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ""
    )
    
    $reportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $changesSummary = Get-ChangeLogSummary
    
    # Define requirement mappings
    $requirementMappings = @{
        "1.1" = "Password history enforcement (24 passwords)"
        "1.2" = "Maximum password age (60 days)"
        "1.3" = "Minimum password age (1 day)"
        "1.4" = "Minimum password length (10 characters)"
        "1.5" = "Password complexity requirements"
        "2.1" = "Account lockout duration (30 minutes)"
        "2.2" = "Account lockout threshold (10 failed attempts)"
        "2.3" = "Lockout counter reset time (30 minutes)"
        "3.1" = "Force password change at next logon"
        "3.2" = "Disable unauthorized user accounts"
        "3.3" = "Restrict Administrators group"
        "3.4" = "Restrict Guests group"
        "3.5" = "Configure Remote Desktop Users group"
        "4.1" = "Enable SmartScreen online services"
        "4.2" = "Disable Wi-Fi Sense automatic connections"
        "4.3" = "Set User Account Control to maximum level"
        "4.4" = "Enable Windows Defender"
        "5.1" = "Disable Client for MS Networks"
        "5.2" = "Disable File and Printer Sharing"
        "5.3" = "Disable IPv6 protocol"
        "5.4" = "Disable DNS registration"
        "5.5" = "Disable NetBIOS over TCP/IP"
        "6.1" = "Stop and disable UPnP Device Host service"
        "6.2" = "Stop and disable Telnet service"
        "6.3" = "Stop and disable SNMP Trap service"
        "6.4" = "Stop and disable Remote Registry service"
        "6.5" = "Configure Windows Event Collector service"
        "7.1" = "Disable Telnet client and server features"
        "7.2" = "Disable SNMP feature"
        "7.3" = "Disable SMB v1 protocol"
        "7.4" = "Disable Internet Information Services"
        "7.5" = "Configure TFTP feature"
        "8.1" = "Block Microsoft Edge firewall rules"
        "8.2" = "Block Windows Search firewall rules"
        "8.3" = "Block MSN applications firewall rules"
        "8.4" = "Block Xbox applications firewall rules"
        "8.5" = "Block Microsoft Photos firewall rules"
        "9.1" = "Disable AutoPlay functionality"
        "9.2" = "Configure screen saver timeout"
        "9.3" = "Enable logon requirement on resume"
        "9.4" = "Disable OneDrive startup"
        "9.5" = "Configure comprehensive auditing"
        "10.1" = "Disable Administrator and Guest accounts"
        "10.2" = "Block Microsoft account usage"
        "10.3" = "Enable digital signing for network communications"
        "10.4" = "Configure interactive logon security settings"
        "10.5" = "Set network security authentication to maximum"
        "11.1" = "Disable UPnP on port 1900"
        "11.2" = "Set UPnPMode registry value"
        "11.3" = "Verify registry changes"
        "12.1" = "Display progress information"
        "12.2" = "Report successful changes"
        "12.3" = "Log errors encountered"
        "12.4" = "Provide execution summary"
        "12.5" = "Provide clear error messages"
    }
    
    # Build the compliance report
    $report = @"
================================================================================
WINDOWS SECURITY HARDENING - COMPLIANCE REPORT
================================================================================
Generated: $reportTimestamp
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Assessment Date: $(Get-Date -Format "yyyy-MM-dd")

EXECUTIVE SUMMARY
================================================================================
Total Security Requirements: $($requirementMappings.Keys.Count)
Requirements Addressed: $(($changesSummary.ChangesByRequirement.Keys).Count)
Successful Implementations: $(($changesSummary.ChangesByRequirement.Values | Where-Object { $_.Failed -eq 0 }).Count)
Partial Implementations: $(($changesSummary.ChangesByRequirement.Values | Where-Object { $_.Failed -gt 0 -and $_.Successful -gt 0 }).Count)
Failed Implementations: $(($changesSummary.ChangesByRequirement.Values | Where-Object { $_.Successful -eq 0 -and $_.Failed -gt 0 }).Count)

Overall Compliance Score: $([math]::Round((($changesSummary.ChangesByRequirement.Values | Where-Object { $_.Failed -eq 0 }).Count / [math]::Max($requirementMappings.Keys.Count, 1)) * 100, 1))%

DETAILED COMPLIANCE STATUS
================================================================================
"@

    # Add detailed compliance for each requirement
    foreach ($reqId in $requirementMappings.Keys | Sort-Object) {
        $reqDescription = $requirementMappings[$reqId]
        
        if ($changesSummary.ChangesByRequirement.ContainsKey($reqId)) {
            $reqData = $changesSummary.ChangesByRequirement[$reqId]
            
            if ($reqData.Failed -eq 0) {
                $status = "✓ COMPLIANT"
                $statusColor = "SUCCESS"
            } elseif ($reqData.Successful -gt 0) {
                $status = "⚠ PARTIAL"
                $statusColor = "WARNING"
            } else {
                $status = "✗ NON-COMPLIANT"
                $statusColor = "FAILED"
            }
            
            $report += "`n[$status] Requirement $reqId: $reqDescription"
            $report += "`n  Changes: $($reqData.Successful) successful, $($reqData.Failed) failed"
        } else {
            $report += "`n[✗ NOT ADDRESSED] Requirement $reqId: $reqDescription"
            $report += "`n  Status: No changes made for this requirement"
        }
    }

    $report += @"


SECURITY CONFIGURATION SUMMARY
================================================================================
"@

    # Add configuration summary by category
    $categories = @{
        "Password Policies" = @("1.1", "1.2", "1.3", "1.4", "1.5")
        "Account Lockout Policies" = @("2.1", "2.2", "2.3")
        "User Account Management" = @("3.1", "3.2", "3.3", "3.4", "3.5")
        "Windows Security Features" = @("4.1", "4.2", "4.3", "4.4")
        "Network Configuration" = @("5.1", "5.2", "5.3", "5.4", "5.5")
        "Windows Services" = @("6.1", "6.2", "6.3", "6.4", "6.5")
        "Windows Features" = @("7.1", "7.2", "7.3", "7.4", "7.5")
        "Firewall Rules" = @("8.1", "8.2", "8.3", "8.4", "8.5")
        "System Settings" = @("9.1", "9.2", "9.3", "9.4", "9.5")
        "Local Security Policies" = @("10.1", "10.2", "10.3", "10.4", "10.5")
        "Registry Modifications" = @("11.1", "11.2", "11.3")
        "Script Execution" = @("12.1", "12.2", "12.3", "12.4", "12.5")
    }
    
    foreach ($category in $categories.Keys) {
        $categoryReqs = $categories[$category]
        $compliantReqs = 0
        $partialReqs = 0
        $nonCompliantReqs = 0
        $notAddressedReqs = 0
        
        foreach ($reqId in $categoryReqs) {
            if ($changesSummary.ChangesByRequirement.ContainsKey($reqId)) {
                $reqData = $changesSummary.ChangesByRequirement[$reqId]
                if ($reqData.Failed -eq 0) {
                    $compliantReqs++
                } elseif ($reqData.Successful -gt 0) {
                    $partialReqs++
                } else {
                    $nonCompliantReqs++
                }
            } else {
                $notAddressedReqs++
            }
        }
        
        $categoryScore = [math]::Round(($compliantReqs / $categoryReqs.Count) * 100, 1)
        
        $report += "`n$category (Score: $categoryScore%)"
        $report += "`n  Compliant: $compliantReqs | Partial: $partialReqs | Non-Compliant: $nonCompliantReqs | Not Addressed: $notAddressedReqs"
    }

    $report += @"


APPLIED CONFIGURATIONS
================================================================================
"@

    # Add detailed applied configurations
    if ($Script:ChangeLog -and $Script:ChangeLog.Changes.Count -gt 0) {
        $successfulChanges = $Script:ChangeLog.Changes | Where-Object { $_.Success } | Sort-Object RequirementId, ChangeType, Target
        
        foreach ($change in $successfulChanges) {
            $reqInfo = if ($change.RequirementId) { " [Req: $($change.RequirementId)]" } else { "" }
            $report += "`n✓ $($change.ChangeType): $($change.Action) $($change.Target)$reqInfo"
            
            if ($change.NewValue) {
                $report += "`n  Value: $($change.NewValue)"
            }
            if ($change.OldValue) {
                $report += "`n  Previous: $($change.OldValue)"
            }
        }
    } else {
        $report += "`nNo configuration changes were successfully applied."
    }

    $report += @"


FAILED CONFIGURATIONS
================================================================================
"@

    # Add failed configurations
    if ($Script:ChangeLog -and $Script:ChangeLog.Changes.Count -gt 0) {
        $failedChanges = $Script:ChangeLog.Changes | Where-Object { -not $_.Success } | Sort-Object RequirementId, ChangeType, Target
        
        if ($failedChanges.Count -gt 0) {
            foreach ($change in $failedChanges) {
                $reqInfo = if ($change.RequirementId) { " [Req: $($change.RequirementId)]" } else { "" }
                $report += "`n✗ $($change.ChangeType): $($change.Action) $($change.Target)$reqInfo"
                $report += "`n  Error: $($change.ErrorMessage)"
            }
        } else {
            $report += "`nNo configuration failures occurred."
        }
    } else {
        $report += "`nNo configuration change information available."
    }

    $report += @"


RECOMMENDATIONS
================================================================================
"@

    # Add recommendations based on compliance status
    $recommendations = @()
    
    # Check for not addressed requirements
    $notAddressedReqs = $requirementMappings.Keys | Where-Object { -not $changesSummary.ChangesByRequirement.ContainsKey($_) }
    if ($notAddressedReqs.Count -gt 0) {
        $recommendations += "• Review and implement the $($notAddressedReqs.Count) requirements that were not addressed during this execution"
    }
    
    # Check for failed changes
    if ($changesSummary.FailedChanges -gt 0) {
        $recommendations += "• Investigate and resolve the $($changesSummary.FailedChanges) failed configuration changes"
    }
    
    # Check for partial implementations
    $partialReqs = $changesSummary.ChangesByRequirement.Values | Where-Object { $_.Failed -gt 0 -and $_.Successful -gt 0 }
    if ($partialReqs.Count -gt 0) {
        $recommendations += "• Complete the $($partialReqs.Count) partially implemented requirements"
    }
    
    # General recommendations
    $recommendations += "• Schedule regular compliance assessments to maintain security posture"
    $recommendations += "• Monitor system changes and validate continued compliance"
    $recommendations += "• Review and update security configurations based on organizational requirements"
    
    if ($recommendations.Count -gt 0) {
        foreach ($recommendation in $recommendations) {
            $report += "`n$recommendation"
        }
    } else {
        $report += "`nAll security requirements have been successfully implemented. Continue monitoring for compliance."
    }

    $report += @"


================================================================================
END OF COMPLIANCE REPORT
================================================================================
"@

    # Save to file if path provided
    if ($OutputPath) {
        try {
            $reportDir = Split-Path $OutputPath -Parent
            if ($reportDir -and -not (Test-Path $reportDir)) {
                New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
            }
            
            $report | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-LogMessage "Compliance report saved to: $OutputPath" -Level "Success"
        }
        catch {
            Write-LogMessage "Failed to save compliance report: $($_.Exception.Message)" -Level "Error"
        }
    }
    
    return $report
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Initialize-Logging',
    'Write-LogMessage',
    'Get-LogFilePath',
    'Initialize-ProgressReporting',
    'Update-ModuleProgress',
    'Write-ProgressSummary',
    'Initialize-ChangeLogging',
    'Add-ChangeLogEntry',
    'Get-ChangeLogSummary',
    'Generate-ExecutionSummaryReport',
    'Generate-ComplianceReport'
)