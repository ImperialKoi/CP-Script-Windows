<#
.SYNOPSIS
    Comprehensive Error Handling System Module

.DESCRIPTION
    This module provides comprehensive error handling functionality including
    custom exception types, error aggregation and categorization, and
    try-catch block management for all critical operations.
    
    Requirements: 12.3, 12.5
#>

# Global variables for error handling
$Script:ErrorCollection = @()
$Script:ErrorCategories = @{
    "System" = @()
    "Configuration" = @()
    "Network" = @()
    "Registry" = @()
    "Service" = @()
    "Feature" = @()
    "Firewall" = @()
    "Validation" = @()
    "Permission" = @()
    "Unknown" = @()
}

#region Custom Exception Types

class SecurityHardeningException : System.Exception {
    [string]$Category
    [string]$ModuleName
    [string]$Operation
    [hashtable]$Context
    
    SecurityHardeningException([string]$message) : base($message) {
        $this.Category = "Unknown"
        $this.ModuleName = "Unknown"
        $this.Operation = "Unknown"
        $this.Context = @{}
    }
    
    SecurityHardeningException([string]$message, [string]$category) : base($message) {
        $this.Category = $category
        $this.ModuleName = "Unknown"
        $this.Operation = "Unknown"
        $this.Context = @{}
    }
    
    SecurityHardeningException([string]$message, [string]$category, [string]$moduleName) : base($message) {
        $this.Category = $category
        $this.ModuleName = $moduleName
        $this.Operation = "Unknown"
        $this.Context = @{}
    }
    
    SecurityHardeningException([string]$message, [string]$category, [string]$moduleName, [string]$operation) : base($message) {
        $this.Category = $category
        $this.ModuleName = $moduleName
        $this.Operation = $operation
        $this.Context = @{}
    }
    
    SecurityHardeningException([string]$message, [string]$category, [string]$moduleName, [string]$operation, [hashtable]$context) : base($message) {
        $this.Category = $category
        $this.ModuleName = $moduleName
        $this.Operation = $operation
        $this.Context = $context
    }
}

class SystemValidationException : SecurityHardeningException {
    SystemValidationException([string]$message) : base($message, "System", "Prerequisites", "Validation") {}
    SystemValidationException([string]$message, [hashtable]$context) : base($message, "System", "Prerequisites", "Validation", $context) {}
}

class ConfigurationException : SecurityHardeningException {
    ConfigurationException([string]$message, [string]$moduleName) : base($message, "Configuration", $moduleName, "Configuration") {}
    ConfigurationException([string]$message, [string]$moduleName, [hashtable]$context) : base($message, "Configuration", $moduleName, "Configuration", $context) {}
}

class NetworkConfigurationException : SecurityHardeningException {
    NetworkConfigurationException([string]$message, [string]$operation) : base($message, "Network", "NetworkAdapter", $operation) {}
    NetworkConfigurationException([string]$message, [string]$operation, [hashtable]$context) : base($message, "Network", "NetworkAdapter", $operation, $context) {}
}

class RegistryOperationException : SecurityHardeningException {
    RegistryOperationException([string]$message, [string]$operation) : base($message, "Registry", "RegistryModifications", $operation) {}
    RegistryOperationException([string]$message, [string]$operation, [hashtable]$context) : base($message, "Registry", "RegistryModifications", $operation, $context) {}
}

class ServiceManagementException : SecurityHardeningException {
    ServiceManagementException([string]$message, [string]$operation) : base($message, "Service", "WindowsServices", $operation) {}
    ServiceManagementException([string]$message, [string]$operation, [hashtable]$context) : base($message, "Service", "WindowsServices", $operation, $context) {}
}

class FeatureManagementException : SecurityHardeningException {
    FeatureManagementException([string]$message, [string]$operation) : base($message, "Feature", "WindowsFeatures", $operation) {}
    FeatureManagementException([string]$message, [string]$operation, [hashtable]$context) : base($message, "Feature", "WindowsFeatures", $operation, $context) {}
}

class FirewallConfigurationException : SecurityHardeningException {
    FirewallConfigurationException([string]$message, [string]$operation) : base($message, "Firewall", "FirewallConfiguration", $operation) {}
    FirewallConfigurationException([string]$message, [string]$operation, [hashtable]$context) : base($message, "Firewall", "FirewallConfiguration", $operation, $context) {}
}

class ValidationException : SecurityHardeningException {
    ValidationException([string]$message, [string]$moduleName) : base($message, "Validation", $moduleName, "Validation") {}
    ValidationException([string]$message, [string]$moduleName, [hashtable]$context) : base($message, "Validation", $moduleName, "Validation", $context) {}
}

class PermissionException : SecurityHardeningException {
    PermissionException([string]$message, [string]$moduleName) : base($message, "Permission", $moduleName, "Permission") {}
    PermissionException([string]$message, [string]$moduleName, [hashtable]$context) : base($message, "Permission", $moduleName, "Permission", $context) {}
}

#endregion

#region Error Collection and Aggregation

function Initialize-ErrorHandling {
    <#
    .SYNOPSIS
        Initializes the error handling system
    .DESCRIPTION
        Clears error collections and sets up error tracking
    #>
    
    Write-LogMessage "Initializing comprehensive error handling system..." -Level "Info"
    
    # Clear existing error collections
    $Script:ErrorCollection = @()
    
    # Reset error categories
    foreach ($category in $Script:ErrorCategories.Keys) {
        $Script:ErrorCategories[$category] = @()
    }
    
    Write-LogMessage "Error handling system initialized successfully" -Level "Success"
}

function Add-ErrorRecord {
    <#
    .SYNOPSIS
        Adds an error record to the error collection with categorization
    .PARAMETER Exception
        The exception object to record
    .PARAMETER ModuleName
        Name of the module where the error occurred
    .PARAMETER Operation
        The operation that was being performed when the error occurred
    .PARAMETER Context
        Additional context information about the error
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception,
        
        [Parameter(Mandatory = $false)]
        [string]$ModuleName = "Unknown",
        
        [Parameter(Mandatory = $false)]
        [string]$Operation = "Unknown",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{}
    )
    
    $errorRecord = @{
        Timestamp = Get-Date
        Exception = $Exception
        Message = $Exception.Message
        ModuleName = $ModuleName
        Operation = $Operation
        Context = $Context
        Category = "Unknown"
        Severity = "Error"
        StackTrace = $Exception.StackTrace
    }
    
    # Determine category based on exception type or module name
    if ($Exception -is [SecurityHardeningException]) {
        $errorRecord.Category = $Exception.Category
        $errorRecord.ModuleName = $Exception.ModuleName
        $errorRecord.Operation = $Exception.Operation
        if ($Exception.Context.Count -gt 0) {
            $errorRecord.Context = $Exception.Context
        }
    }
    else {
        $errorRecord.Category = Get-ErrorCategory -ModuleName $ModuleName -Operation $Operation
    }
    
    # Determine severity based on exception type and context
    $errorRecord.Severity = Get-ErrorSeverity -Exception $Exception -Context $Context
    
    # Add to main error collection
    $Script:ErrorCollection += $errorRecord
    
    # Add to category-specific collection
    if ($Script:ErrorCategories.ContainsKey($errorRecord.Category)) {
        $Script:ErrorCategories[$errorRecord.Category] += $errorRecord
    }
    else {
        $Script:ErrorCategories["Unknown"] += $errorRecord
    }
    
    # Log the error
    Write-LogMessage "Error recorded: [$($errorRecord.Category)] $($errorRecord.Message)" -Level "Error"
    
    if ($Context.Count -gt 0) {
        Write-LogMessage "Error context: $($Context | ConvertTo-Json -Compress)" -Level "Debug"
    }
}

function Get-ErrorCategory {
    <#
    .SYNOPSIS
        Determines the error category based on module name and operation
    .PARAMETER ModuleName
        Name of the module where the error occurred
    .PARAMETER Operation
        The operation that was being performed
    .OUTPUTS
        String representing the error category
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )
    
    switch -Regex ($ModuleName) {
        "Prerequisites|System" { return "System" }
        "NetworkAdapter|Network" { return "Network" }
        "Registry" { return "Registry" }
        "Service|WindowsServices" { return "Service" }
        "Feature|WindowsFeatures" { return "Feature" }
        "Firewall" { return "Firewall" }
        "Validation" { return "Validation" }
        "Permission" { return "Permission" }
        default { return "Configuration" }
    }
}

function Get-ErrorSeverity {
    <#
    .SYNOPSIS
        Determines the error severity based on exception type and context
    .PARAMETER Exception
        The exception object
    .PARAMETER Context
        Additional context information
    .OUTPUTS
        String representing the error severity (Critical, High, Medium, Low)
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{}
    )
    
    # Critical errors that prevent script execution
    if ($Exception -is [SystemValidationException] -or 
        $Exception -is [PermissionException] -or
        $Exception.Message -match "Prerequisites|Administrator|Permission") {
        return "Critical"
    }
    
    # High severity errors that affect core functionality
    if ($Exception -is [ConfigurationException] -or
        $Exception -is [RegistryOperationException] -or
        $Exception.Message -match "Registry|Configuration|Backup") {
        return "High"
    }
    
    # Medium severity errors that affect specific features
    if ($Exception -is [NetworkConfigurationException] -or
        $Exception -is [ServiceManagementException] -or
        $Exception -is [FeatureManagementException] -or
        $Exception -is [FirewallConfigurationException]) {
        return "Medium"
    }
    
    # Low severity errors (validation warnings, etc.)
    if ($Exception -is [ValidationException]) {
        return "Low"
    }
    
    # Default to Medium for unknown exceptions
    return "Medium"
}

function Get-ErrorSummary {
    <#
    .SYNOPSIS
        Generates a comprehensive error summary report
    .OUTPUTS
        Hashtable containing error summary information
    #>
    
    $summary = @{
        TotalErrors = $Script:ErrorCollection.Count
        Categories = @{}
        Severities = @{
            Critical = 0
            High = 0
            Medium = 0
            Low = 0
        }
        RecentErrors = @()
        CriticalErrors = @()
    }
    
    # Count errors by category
    foreach ($category in $Script:ErrorCategories.Keys) {
        $summary.Categories[$category] = $Script:ErrorCategories[$category].Count
    }
    
    # Count errors by severity and collect critical errors
    foreach ($error in $Script:ErrorCollection) {
        $summary.Severities[$error.Severity]++
        
        if ($error.Severity -eq "Critical") {
            $summary.CriticalErrors += $error
        }
    }
    
    # Get recent errors (last 10)
    $summary.RecentErrors = $Script:ErrorCollection | Sort-Object Timestamp -Descending | Select-Object -First 10
    
    return $summary
}

#endregion

#region Try-Catch Block Helpers

function Invoke-SafeOperation {
    <#
    .SYNOPSIS
        Executes an operation within a comprehensive try-catch block
    .PARAMETER ScriptBlock
        The script block to execute safely
    .PARAMETER ModuleName
        Name of the module performing the operation
    .PARAMETER Operation
        Description of the operation being performed
    .PARAMETER Context
        Additional context information
    .PARAMETER ContinueOnError
        Whether to continue execution if an error occurs
    .OUTPUTS
        Hashtable containing operation result and error information
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{},
        
        [Parameter(Mandatory = $false)]
        [bool]$ContinueOnError = $true
    )
    
    $result = @{
        Success = $false
        Result = $null
        Error = $null
        ErrorRecord = $null
        ExecutionTime = $null
        Context = $Context
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        Write-LogMessage "Executing operation: $Operation in module: $ModuleName" -Level "Debug"
        
        $result.Result = & $ScriptBlock
        $result.Success = $true
        
        Write-LogMessage "Operation completed successfully: $Operation" -Level "Debug"
    }
    catch [SecurityHardeningException] {
        $result.Error = $_.Exception
        $result.ErrorRecord = $_
        
        Add-ErrorRecord -Exception $_.Exception -ModuleName $ModuleName -Operation $Operation -Context $Context
        
        Write-LogMessage "Security hardening exception in $ModuleName.$Operation`: $($_.Exception.Message)" -Level "Error"
        
        if (-not $ContinueOnError) {
            throw
        }
    }
    catch [System.UnauthorizedAccessException] {
        $permissionException = [PermissionException]::new("Access denied: $($_.Exception.Message)", $ModuleName, $Context)
        $result.Error = $permissionException
        $result.ErrorRecord = $_
        
        Add-ErrorRecord -Exception $permissionException -ModuleName $ModuleName -Operation $Operation -Context $Context
        
        Write-LogMessage "Permission error in $ModuleName.$Operation`: $($_.Exception.Message)" -Level "Error"
        
        if (-not $ContinueOnError) {
            throw $permissionException
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        $configException = [ConfigurationException]::new("Resource not found: $($_.Exception.Message)", $ModuleName, $Context)
        $result.Error = $configException
        $result.ErrorRecord = $_
        
        Add-ErrorRecord -Exception $configException -ModuleName $ModuleName -Operation $Operation -Context $Context
        
        Write-LogMessage "Resource not found in $ModuleName.$Operation`: $($_.Exception.Message)" -Level "Error"
        
        if (-not $ContinueOnError) {
            throw $configException
        }
    }
    catch [System.InvalidOperationException] {
        $configException = [ConfigurationException]::new("Invalid operation: $($_.Exception.Message)", $ModuleName, $Context)
        $result.Error = $configException
        $result.ErrorRecord = $_
        
        Add-ErrorRecord -Exception $configException -ModuleName $ModuleName -Operation $Operation -Context $Context
        
        Write-LogMessage "Invalid operation in $ModuleName.$Operation`: $($_.Exception.Message)" -Level "Error"
        
        if (-not $ContinueOnError) {
            throw $configException
        }
    }
    catch {
        # Generic exception handling
        $genericException = [SecurityHardeningException]::new($_.Exception.Message, "Unknown", $ModuleName, $Operation, $Context)
        $result.Error = $genericException
        $result.ErrorRecord = $_
        
        Add-ErrorRecord -Exception $genericException -ModuleName $ModuleName -Operation $Operation -Context $Context
        
        Write-LogMessage "Unexpected error in $ModuleName.$Operation`: $($_.Exception.Message)" -Level "Error"
        Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" -Level "Debug"
        
        if (-not $ContinueOnError) {
            throw $genericException
        }
    }
    finally {
        $stopwatch.Stop()
        $result.ExecutionTime = $stopwatch.Elapsed
        
        Write-LogMessage "Operation $Operation completed in $($result.ExecutionTime.TotalMilliseconds)ms" -Level "Debug"
    }
    
    return $result
}

function Test-CriticalErrors {
    <#
    .SYNOPSIS
        Checks if any critical errors have occurred that should stop execution
    .OUTPUTS
        Boolean indicating if critical errors exist
    #>
    
    $criticalErrors = $Script:ErrorCollection | Where-Object { $_.Severity -eq "Critical" }
    
    if ($criticalErrors.Count -gt 0) {
        Write-LogMessage "Critical errors detected - execution should be halted" -Level "Error"
        
        foreach ($error in $criticalErrors) {
            Write-LogMessage "Critical: [$($error.Category)] $($error.Message)" -Level "Error"
        }
        
        return $true
    }
    
    return $false
}

function Clear-ErrorCollection {
    <#
    .SYNOPSIS
        Clears the error collection and resets error tracking
    #>
    
    Write-LogMessage "Clearing error collection..." -Level "Info"
    
    $Script:ErrorCollection = @()
    
    foreach ($category in $Script:ErrorCategories.Keys) {
        $Script:ErrorCategories[$category] = @()
    }
    
    Write-LogMessage "Error collection cleared" -Level "Success"
}

#endregion

#region Error Reporting

function Write-ErrorReport {
    <#
    .SYNOPSIS
        Generates and writes a comprehensive error report
    .PARAMETER OutputPath
        Path to write the error report file
    .PARAMETER IncludeStackTrace
        Whether to include stack traces in the report
    #>
    
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = $null,
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeStackTrace = $false
    )
    
    $summary = Get-ErrorSummary
    
    $report = @"
================================================================================
Windows Security Hardening - Error Report
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
================================================================================

SUMMARY
-------
Total Errors: $($summary.TotalErrors)

Errors by Severity:
  Critical: $($summary.Severities.Critical)
  High:     $($summary.Severities.High)
  Medium:   $($summary.Severities.Medium)
  Low:      $($summary.Severities.Low)

Errors by Category:
"@
    
    foreach ($category in $summary.Categories.Keys | Sort-Object) {
        $report += "`n  $category`: $($summary.Categories[$category])"
    }
    
    if ($summary.CriticalErrors.Count -gt 0) {
        $report += "`n`nCRITICAL ERRORS`n" + ("=" * 50) + "`n"
        
        foreach ($error in $summary.CriticalErrors) {
            $report += "`n[$($error.Timestamp.ToString('HH:mm:ss'))] [$($error.Category)] $($error.ModuleName).$($error.Operation)`n"
            $report += "Message: $($error.Message)`n"
            
            if ($error.Context.Count -gt 0) {
                $report += "Context: $($error.Context | ConvertTo-Json -Compress)`n"
            }
            
            if ($IncludeStackTrace -and $error.StackTrace) {
                $report += "Stack Trace:`n$($error.StackTrace)`n"
            }
            
            $report += ("-" * 50) + "`n"
        }
    }
    
    if ($summary.RecentErrors.Count -gt 0) {
        $report += "`nRECENT ERRORS`n" + ("=" * 50) + "`n"
        
        foreach ($error in $summary.RecentErrors) {
            $report += "`n[$($error.Timestamp.ToString('HH:mm:ss'))] [$($error.Severity)] [$($error.Category)] $($error.ModuleName).$($error.Operation)`n"
            $report += "Message: $($error.Message)`n"
            
            if ($IncludeStackTrace -and $error.StackTrace) {
                $report += "Stack Trace:`n$($error.StackTrace)`n"
            }
            
            $report += ("-" * 30) + "`n"
        }
    }
    
    $report += "`n================================================================================`n"
    
    # Write to console
    Write-LogMessage "Error Report:" -Level "Info"
    Write-Host $report -ForegroundColor Yellow
    
    # Write to file if path specified
    if ($OutputPath) {
        try {
            $reportFile = Join-Path $OutputPath "ErrorReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $report | Out-File -FilePath $reportFile -Encoding UTF8
            Write-LogMessage "Error report written to: $reportFile" -Level "Success"
        }
        catch {
            Write-LogMessage "Failed to write error report to file: $($_.Exception.Message)" -Level "Warning"
        }
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Initialize-ErrorHandling',
    'Add-ErrorRecord',
    'Get-ErrorSummary',
    'Invoke-SafeOperation',
    'Test-CriticalErrors',
    'Clear-ErrorCollection',
    'Write-ErrorReport'
)