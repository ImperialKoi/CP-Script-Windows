<#
.SYNOPSIS
    Windows Security Hardening Script - Object-Oriented Main Entry Point

.DESCRIPTION
    This PowerShell script implements comprehensive Windows security hardening measures
    using an object-oriented architecture with separate classes and services for
    better maintainability and extensibility.

.PARAMETER ConfigFile
    Optional path to external configuration file (JSON format)

.PARAMETER LogPath
    Path for log file output (default: current directory)

.PARAMETER Silent
    Run in silent mode without user prompts

.PARAMETER WhatIf
    Show what changes would be made without applying them

.EXAMPLE
    .\WindowsSecurityHardening-OOP.ps1
    Run the script interactively with default settings

.EXAMPLE
    .\WindowsSecurityHardening-OOP.ps1 -Silent -LogPath "C:\Logs"
    Run silently with custom log path

.NOTES
    Author: Windows Security Hardening Script
    Version: 2.0.0 (Object-Oriented)
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
$Script:ScriptVersion = "2.0.0"
$Script:ScriptName = "Windows Security Hardening Script (OOP)"
$Script:ScriptAuthor = "Security Team"

# Global variables
$Script:StartTime = Get-Date

#region Module and Class Loading

# Import required modules
$ModulePath = Join-Path $PSScriptRoot "Modules"

try {
    Write-Host "Loading security hardening modules..." -ForegroundColor Yellow
    
    # Import core modules
    Import-Module (Join-Path $ModulePath "Prerequisites.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $ModulePath "Logging.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $ModulePath "BackupSystem.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $ModulePath "NetworkAdapter.psm1") -Force -ErrorAction Stop
    
    Write-Host "Core modules loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "Failed to load required modules: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please ensure all module files are present in the Modules directory" -ForegroundColor Red
    exit 1
}

# Load classes and services
try {
    Write-Host "Loading classes and services..." -ForegroundColor Yellow
    
    # Load model classes first
    . (Join-Path $PSScriptRoot "Classes\Models.ps1")
    
    # Load base service class
    . (Join-Path $PSScriptRoot "Classes\BaseSecurityService.ps1")
    
    # Load service implementations
    . (Join-Path $PSScriptRoot "Services\PasswordPolicyService.ps1")
    . (Join-Path $PSScriptRoot "Services\UserAccountService.ps1")
    . (Join-Path $PSScriptRoot "Services\WindowsSecurityFeaturesService.ps1")
    . (Join-Path $PSScriptRoot "Services\NetworkAdapterService.ps1")
    . (Join-Path $PSScriptRoot "Services\WindowsServicesService.ps1")
    . (Join-Path $PSScriptRoot "Services\WindowsFeaturesService.ps1")
    . (Join-Path $PSScriptRoot "Services\FirewallService.ps1")
    . (Join-Path $PSScriptRoot "Services\SystemSettingsService.ps1")
    . (Join-Path $PSScriptRoot "Services\SecurityPolicyService.ps1")
    . (Join-Path $PSScriptRoot "Services\RegistryService.ps1")
    
    # Load factory and controller classes
    . (Join-Path $PSScriptRoot "Classes\SecurityServiceFactory.ps1")
    . (Join-Path $PSScriptRoot "Classes\SecurityHardeningController.ps1")
    
    Write-Host "Classes and services loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "Failed to load classes and services: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please ensure all class and service files are present" -ForegroundColor Red
    exit 1
}

# Load legacy functions for backward compatibility
try {
    Write-Host "Loading legacy functions for compatibility..." -ForegroundColor Yellow
    
    # Source the original script to get legacy functions
    . (Join-Path $PSScriptRoot "WindowsSecurityHardening.ps1") -Silent -WhatIf 2>$null
    
    Write-Host "Legacy functions loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "Warning: Some legacy functions may not be available: $($_.Exception.Message)" -ForegroundColor Yellow
}

#endregion

#region Configuration Management

function Initialize-SecurityConfiguration {
    <#
    .SYNOPSIS
        Initializes the security configuration using the new configuration model
    .DESCRIPTION
        Creates and configures the SecurityConfiguration object with default values
        and optional external configuration file loading
    .OUTPUTS
        Returns SecurityConfiguration object
    #>
    
    try {
        Write-LogMessage "Initializing security configuration..." -Level "Info"
        
        # Create new configuration object
        $config = [SecurityConfiguration]::new()
        
        # Load external configuration if specified
        if ($ConfigFile -and (Test-Path $ConfigFile)) {
            try {
                Write-LogMessage "Loading external configuration from: $ConfigFile" -Level "Info"
                $externalConfig = Get-Content $ConfigFile | ConvertFrom-Json -AsHashtable
                $config.LoadFromHashtable($externalConfig)
                Write-LogMessage "External configuration loaded successfully" -Level "Success"
            }
            catch {
                Write-LogMessage "Failed to load external configuration: $($_.Exception.Message)" -Level "Warning"
                Write-LogMessage "Continuing with default configuration..." -Level "Info"
            }
        }
        
        Write-LogMessage "Security configuration initialized successfully" -Level "Success"
        return $config
    }
    catch {
        Write-LogMessage "Failed to initialize security configuration: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

function Show-SecurityConfiguration {
    <#
    .SYNOPSIS
        Displays the current security configuration
    .PARAMETER Config
        SecurityConfiguration object to display
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [SecurityConfiguration]$Config
    )
    
    Write-LogMessage "Current Security Configuration:" -Level "Info"
    Write-LogMessage "================================" -Level "Info"
    
    $configHash = $Config.ToHashtable()
    
    foreach ($section in $configHash.Keys | Sort-Object) {
        Write-LogMessage "[$section]" -Level "Info"
        foreach ($setting in $configHash[$section].Keys | Sort-Object) {
            $value = $configHash[$section][$setting]
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

#region Main Execution Functions

function Start-SecurityHardeningOOP {
    <#
    .SYNOPSIS
        Main entry point for the object-oriented security hardening process
    .DESCRIPTION
        Initializes the system and creates the main controller for execution
    .OUTPUTS
        Returns the configured SecurityHardeningController
    #>
    
    try {
        Write-LogMessage "Starting Windows Security Hardening Process (OOP)..." -Level "Info"
        Write-LogMessage "Script Version: $Script:ScriptVersion" -Level "Info"
        
        # Validate prerequisites
        if (-not (Test-Prerequisites)) {
            throw "Prerequisites validation failed. Cannot continue."
        }
        
        # Initialize logging system
        Initialize-Logging -LogPath $LogPath
        
        # Initialize configuration
        $config = Initialize-SecurityConfiguration
        
        # Show configuration if not in silent mode
        if (-not $Silent) {
            Show-SecurityConfiguration -Config $config
            
            if (-not $WhatIf) {
                $confirmation = Read-Host "`nDo you want to proceed with these settings? (Y/N)"
                if ($confirmation -notmatch '^[Yy]') {
                    Write-LogMessage "Operation cancelled by user" -Level "Warning"
                    return $null
                }
            }
        }
        
        if ($WhatIf) {
            Write-LogMessage "WhatIf mode: No changes will be made to the system" -Level "Warning"
        }
        
        # Initialize backup system if not in WhatIf mode
        if (-not $WhatIf) {
            Write-LogMessage "Initializing backup and restore point system..." -Level "Info"
            $backupSuccess = Initialize-BackupSystem -LogPath $LogPath
            
            if (-not $backupSuccess) {
                if (-not $Silent) {
                    $continueChoice = Read-Host "`nBackup system initialization had warnings. Continue anyway? (Y/N)"
                    if ($continueChoice -notmatch '^[Yy]') {
                        Write-LogMessage "Operation cancelled due to backup system warnings" -Level "Warning"
                        return $null
                    }
                }
                else {
                    Write-LogMessage "Continuing with backup system warnings in silent mode" -Level "Warning"
                }
            }
        }
        
        # Create and configure the main controller
        $controller = [SecurityHardeningController]::new($config.ToHashtable(), $LogPath)
        
        # Set execution mode
        if ($WhatIf) {
            $controller.SetExecutionMode("WhatIf")
        }
        elseif ($Silent) {
            $controller.SetExecutionMode("Silent")
        }
        else {
            $controller.SetExecutionMode("Interactive")
        }
        
        Write-LogMessage "Security hardening controller initialized successfully" -Level "Success"
        Write-LogMessage "Execution mode: $($controller.ExecutionMode)" -Level "Info"
        
        return $controller
    }
    catch {
        Write-LogMessage "Failed to initialize security hardening controller: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

function Invoke-SecurityHardeningExecution {
    <#
    .SYNOPSIS
        Executes the security hardening process using the controller
    .PARAMETER Controller
        The SecurityHardeningController instance to use for execution
    .OUTPUTS
        Returns ExecutionResult object
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [SecurityHardeningController]$Controller
    )
    
    try {
        Write-LogMessage "Starting security hardening execution..." -Level "Info"
        
        # Display mode-specific information
        switch ($Controller.ExecutionMode) {
            "Interactive" {
                Write-Host ""
                Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║              Windows Security Hardening Script              ║" -ForegroundColor Cyan
                Write-Host "║                     Interactive Mode                        ║" -ForegroundColor Cyan
                Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                Write-Host ""
            }
            "WhatIf" {
                Write-Host ""
                Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
                Write-Host "║                      WHATIF MODE                            ║" -ForegroundColor Magenta
                Write-Host "║              No changes will be made                        ║" -ForegroundColor Magenta
                Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
                Write-Host ""
            }
            "Silent" {
                Write-LogMessage "Running in silent mode - no user interaction required" -Level "Info"
            }
        }
        
        # Execute the security hardening process
        $result = $Controller.ExecuteSecurityHardening()
        
        # Display results
        $summary = $result.GetSummary()
        
        Write-LogMessage "Security hardening execution completed" -Level "Info"
        Write-LogMessage "Overall Success: $($summary.OverallSuccess)" -Level $(if ($summary.OverallSuccess) { "Success" } else { "Warning" })
        Write-LogMessage "Services Executed: $($summary.TotalServices)" -Level "Info"
        Write-LogMessage "Services Successful: $($summary.Successful)" -Level "Success"
        Write-LogMessage "Services Failed: $($summary.Failed)" -Level $(if ($summary.Failed -gt 0) { "Error" } else { "Info" })
        Write-LogMessage "Total Changes: $($summary.TotalChanges)" -Level "Success"
        Write-LogMessage "Total Errors: $($summary.TotalErrors)" -Level $(if ($summary.TotalErrors -gt 0) { "Error" } else { "Info" })
        Write-LogMessage "Total Warnings: $($summary.TotalWarnings)" -Level $(if ($summary.TotalWarnings -gt 0) { "Warning" } else { "Info" })
        Write-LogMessage "Execution Duration: $($summary.Duration.ToString('hh\:mm\:ss'))" -Level "Info"
        
        return $result
    }
    catch {
        Write-LogMessage "Security hardening execution failed: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

function Complete-SecurityHardeningOOP {
    <#
    .SYNOPSIS
        Completes the security hardening process and displays final results
    .PARAMETER Result
        The ExecutionResult object from the security hardening process
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [ExecutionResult]$Result
    )
    
    try {
        $summary = $Result.GetSummary()
        
        Write-LogMessage "Completing security hardening process..." -Level "Info"
        
        # Display final results based on execution mode
        if ($Result.ExecutionMode -ne "Silent") {
            Write-Host ""
            Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $(if ($summary.OverallSuccess) { "Green" } else { "Yellow" })
            Write-Host "║                    EXECUTION COMPLETE                       ║" -ForegroundColor $(if ($summary.OverallSuccess) { "Green" } else { "Yellow" })
            Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $(if ($summary.OverallSuccess) { "Green" } else { "Yellow" })
            Write-Host ""
            
            if ($summary.OverallSuccess) {
                Write-Host "✓ Security hardening completed successfully!" -ForegroundColor Green
            }
            else {
                Write-Host "⚠ Security hardening completed with issues." -ForegroundColor Yellow
            }
            
            Write-Host ""
            Write-Host "Summary:" -ForegroundColor White
            Write-Host "  Duration: $($summary.Duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor Gray
            Write-Host "  Services Succeeded: $($summary.Successful)" -ForegroundColor Green
            Write-Host "  Services Failed: $($summary.Failed)" -ForegroundColor $(if ($summary.Failed -gt 0) { "Red" } else { "Gray" })
            Write-Host "  Changes Applied: $($summary.TotalChanges)" -ForegroundColor Green
            Write-Host "  Errors: $($summary.TotalErrors)" -ForegroundColor $(if ($summary.TotalErrors -gt 0) { "Red" } else { "Gray" })
            Write-Host "  Warnings: $($summary.TotalWarnings)" -ForegroundColor $(if ($summary.TotalWarnings -gt 0) { "Yellow" } else { "Gray" })
            Write-Host ""
            
            if ($summary.Failed -gt 0) {
                Write-Host "Failed Services:" -ForegroundColor Red
                foreach ($serviceResult in $Result.ServiceResults) {
                    if (-not $serviceResult.Success) {
                        Write-Host "  - $($serviceResult.ModuleName)" -ForegroundColor Red
                    }
                }
                Write-Host ""
            }
            
            Write-Host "Check the log file for detailed information about all changes made." -ForegroundColor White
            Write-Host ""
            
            if ($Result.ExecutionMode -ne "WhatIf") {
                Write-Host "Press any key to exit..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
        
        Write-LogMessage "Security hardening process completed successfully" -Level "Success"
    }
    catch {
        Write-LogMessage "Error during completion: $($_.Exception.Message)" -Level "Error"
    }
}

#endregion

#region Main Script Entry Point

# Main script execution entry point
try {
    Write-Host "Windows Security Hardening Script v$Script:ScriptVersion (Object-Oriented)" -ForegroundColor Cyan
    Write-Host "Starting execution..." -ForegroundColor White
    
    # Initialize the security hardening controller
    $controller = Start-SecurityHardeningOOP
    
    if ($controller) {
        # Execute the security hardening process
        $result = Invoke-SecurityHardeningExecution -Controller $controller
        
        # Complete the process and display results
        Complete-SecurityHardeningOOP -Result $result
        
        # Set exit code based on results
        $summary = $result.GetSummary()
        if ($summary.OverallSuccess) {
            Write-LogMessage "Script execution completed successfully" -Level "Success"
            exit 0
        }
        else {
            Write-LogMessage "Script execution completed with issues" -Level "Warning"
            exit 1
        }
    }
    else {
        Write-LogMessage "Script execution cancelled or failed to initialize" -Level "Warning"
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