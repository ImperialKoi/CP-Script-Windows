<#
.SYNOPSIS
    Prerequisites and Validation Functions Module

.DESCRIPTION
    This module contains functions for validating system prerequisites
    before script execution including administrative privileges, 
    PowerShell version, and Windows version compatibility.
#>

# Script metadata (shared across modules)
$Script:RequiredPSVersion = "5.1"

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

# Export functions
Export-ModuleMember -Function @(
    'Test-Prerequisites',
    'Test-IsAdministrator', 
    'Test-PowerShellVersion',
    'Test-WindowsVersion'
)