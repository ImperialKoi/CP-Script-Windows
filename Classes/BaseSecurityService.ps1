<#
.SYNOPSIS
    Base class for all security services
.DESCRIPTION
    Provides common functionality and interface for all security hardening services
#>
class BaseSecurityService {
    [hashtable] $Configuration
    [string] $ServiceName
    [string[]] $Requirements
    [bool] $IsCritical
    
    # Constructor
    BaseSecurityService([hashtable] $config, [string] $serviceName, [string[]] $requirements) {
        $this.Configuration = $config
        $this.ServiceName = $serviceName
        $this.Requirements = $requirements
        $this.IsCritical = $true
    }
    
    # Abstract methods that must be implemented by derived classes
    [ServiceResult] Execute() {
        throw "Execute method must be implemented by derived class"
    }
    
    [ServiceResult] ExecuteWhatIf() {
        throw "ExecuteWhatIf method must be implemented by derived class"
    }
    
    # Common validation method
    [bool] ValidatePrerequisites() {
        try {
            Write-LogMessage "Validating prerequisites for $($this.ServiceName)" -Level "Info"
            
            # Check if running as administrator
            if (-not (Test-IsAdministrator)) {
                Write-LogMessage "Administrator privileges required for $($this.ServiceName)" -Level "Error"
                return $false
            }
            
            # Additional service-specific validation can be added here
            return $this.ValidateServiceSpecificPrerequisites()
        }
        catch {
            Write-LogMessage "Prerequisites validation failed for $($this.ServiceName): $($_.Exception.Message)" -Level "Error"
            return $false
        }
    }
    
    # Virtual method for service-specific prerequisite validation
    [bool] ValidateServiceSpecificPrerequisites() {
        return $true
    }
    
    # Common backup creation method
    [hashtable] CreateBackup() {
        try {
            Write-LogMessage "Creating backup for $($this.ServiceName)" -Level "Info"
            
            $backupResult = @{
                Success = $false
                BackupFiles = @()
                Errors = @()
            }
            
            # Service-specific backup logic
            $serviceBackup = $this.CreateServiceSpecificBackup()
            
            if ($serviceBackup.Success) {
                $backupResult.Success = $true
                $backupResult.BackupFiles = $serviceBackup.BackupFiles
                Write-LogMessage "Backup created successfully for $($this.ServiceName)" -Level "Success"
            }
            else {
                $backupResult.Errors = $serviceBackup.Errors
                Write-LogMessage "Backup creation failed for $($this.ServiceName)" -Level "Warning"
            }
            
            return $backupResult
        }
        catch {
            Write-LogMessage "Backup creation error for $($this.ServiceName): $($_.Exception.Message)" -Level "Error"
            return @{
                Success = $false
                BackupFiles = @()
                Errors = @($_.Exception.Message)
            }
        }
    }
    
    # Virtual method for service-specific backup creation
    [hashtable] CreateServiceSpecificBackup() {
        return @{
            Success = $true
            BackupFiles = @()
            Errors = @()
        }
    }
    
    # Common validation method for applied changes
    [bool] ValidateChanges([ServiceResult] $result) {
        try {
            Write-LogMessage "Validating changes for $($this.ServiceName)" -Level "Info"
            
            # Service-specific validation
            return $this.ValidateServiceSpecificChanges($result)
        }
        catch {
            Write-LogMessage "Change validation failed for $($this.ServiceName): $($_.Exception.Message)" -Level "Error"
            return $false
        }
    }
    
    # Virtual method for service-specific change validation
    [bool] ValidateServiceSpecificChanges([ServiceResult] $result) {
        return $true
    }
    
    # Helper method to create a successful result
    [ServiceResult] CreateSuccessResult() {
        $result = [ServiceResult]::new($this.ServiceName)
        $result.SetSuccess($true)
        return $result
    }
    
    # Helper method to create a failed result
    [ServiceResult] CreateFailedResult([string] $error) {
        $result = [ServiceResult]::new($this.ServiceName)
        $result.AddError($error)
        return $result
    }
    
    # Helper method to log service start
    [void] LogServiceStart() {
        Write-LogMessage "Starting $($this.ServiceName) service" -Level "Info"
        Write-LogMessage "Requirements: $($this.Requirements -join ', ')" -Level "Info"
        Write-LogMessage "Critical service: $($this.IsCritical)" -Level "Info"
    }
    
    # Helper method to log service completion
    [void] LogServiceCompletion([ServiceResult] $result) {
        if ($result.Success) {
            Write-LogMessage "$($this.ServiceName) service completed successfully" -Level "Success"
            Write-LogMessage "Changes applied: $($result.Changes.Count)" -Level "Success"
        }
        else {
            Write-LogMessage "$($this.ServiceName) service failed" -Level "Error"
            Write-LogMessage "Errors encountered: $($result.Errors.Count)" -Level "Error"
        }
        
        if ($result.Warnings.Count -gt 0) {
            Write-LogMessage "Warnings generated: $($result.Warnings.Count)" -Level "Warning"
        }
    }
    
    # Get service information
    [hashtable] GetServiceInfo() {
        return @{
            Name = $this.ServiceName
            Requirements = $this.Requirements
            IsCritical = $this.IsCritical
            Type = $this.GetType().Name
        }
    }
}