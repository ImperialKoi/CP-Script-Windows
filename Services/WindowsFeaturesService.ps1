<#
.SYNOPSIS
    Windows Features Management Service
.DESCRIPTION
    Handles Windows features configuration including disabling unnecessary features
#>
class WindowsFeaturesService : BaseSecurityService {
    
    # Constructor
    WindowsFeaturesService([hashtable] $config) : base($config, "Windows Features Management", @("7.1", "7.2", "7.3", "7.4", "7.5")) {
    }
    
    # Execute Windows features configuration
    [ServiceResult] Execute() {
        $this.LogServiceStart()
        $result = [ServiceResult]::new($this.ServiceName)
        
        try {
            # Use existing implementation from the main script
            $legacyResult = Invoke-WindowsFeaturesConfiguration -Config $this.Configuration
            
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
            
            $this.LogServiceCompletion($result)
            return $result
        }
        catch {
            $result.AddError("Windows features configuration failed: $($_.Exception.Message)")
            $this.LogServiceCompletion($result)
            return $result
        }
    }
    
    # Execute in WhatIf mode
    [ServiceResult] ExecuteWhatIf() {
        $result = [ServiceResult]::new($this.ServiceName)
        $result.AddChange("WhatIf: Would disable Telnet client and server")
        $result.AddChange("WhatIf: Would disable SNMP features")
        $result.AddChange("WhatIf: Would disable SMB v1 protocol")
        $result.AddChange("WhatIf: Would disable IIS when not required")
        $result.AddChange("WhatIf: Would configure TFTP based on requirements")
        $result.SetSuccess($true)
        return $result
    }
}