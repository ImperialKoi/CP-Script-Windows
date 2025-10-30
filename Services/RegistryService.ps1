<#
.SYNOPSIS
    Registry Modifications Service
.DESCRIPTION
    Handles security-related registry modifications including UPnP and network settings
#>
class RegistryService : BaseSecurityService {
    
    # Constructor
    RegistryService([hashtable] $config) : base($config, "Registry Modifications", @("11.1", "11.2", "11.3")) {
    }
    
    # Execute registry modifications
    [ServiceResult] Execute() {
        $this.LogServiceStart()
        $result = [ServiceResult]::new($this.ServiceName)
        
        try {
            # Use existing implementation from the main script
            $legacyResult = Invoke-RegistryModifications -Config $this.Configuration
            
            # Convert legacy result to ServiceResult
            $result.SetSuccess($legacyResult.Success)
            
            foreach ($change in $legacyResult.Changes) {
                $result.AddChange($change)
            }
            
            foreach ($error in $legacyResult.Errors) {
                $result.AddError($error)
            }
            
            foreach ($warning in $legacyResult.Warnings) {
                $result.AddWarning($warning)
            }
            
            foreach ($validation in $legacyResult.ValidationResults) {
                $result.AddValidationResult($validation)
            }
            
            if ($legacyResult.BackupResults) {
                $result.SetBackupResults(@{ BackupFiles = $legacyResult.BackupResults })
            }
            
            $this.LogServiceCompletion($result)
            return $result
        }
        catch {
            $result.AddError("Registry modifications failed: $($_.Exception.Message)")
            $this.LogServiceCompletion($result)
            return $result
        }
    }
    
    # Execute in WhatIf mode
    [ServiceResult] ExecuteWhatIf() {
        $result = [ServiceResult]::new($this.ServiceName)
        $result.AddChange("WhatIf: Would create registry entry to disable UPnP on port 1900")
        $result.AddChange("WhatIf: Would set UPnPMode registry value to 2")
        $result.AddChange("WhatIf: Would verify registry changes are applied correctly")
        $result.SetSuccess($true)
        return $result
    }
}