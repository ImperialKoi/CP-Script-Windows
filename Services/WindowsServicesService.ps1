<#
.SYNOPSIS
    Windows Services Management Service
.DESCRIPTION
    Handles Windows services security configuration including disabling unnecessary
    services and enabling required security services
#>
class WindowsServicesService : BaseSecurityService {
    
    # Constructor
    WindowsServicesService([hashtable] $config) : base($config, "Windows Services Management", @("6.1", "6.2", "6.3", "6.4", "6.5")) {
    }
    
    # Execute Windows services configuration
    [ServiceResult] Execute() {
        $this.LogServiceStart()
        $result = [ServiceResult]::new($this.ServiceName)
        
        try {
            # Validate prerequisites
            if (-not $this.ValidatePrerequisites()) {
                return $this.CreateFailedResult("Prerequisites validation failed")
            }
            
            # Create backup
            $backupResult = $this.CreateBackup()
            $result.SetBackupResults($backupResult)
            
            # Execute services configuration
            $this.ConfigureWindowsServices($result)
            
            # Validate changes
            if ($this.ValidateChanges($result)) {
                $result.SetSuccess($true)
            }
            
            $this.LogServiceCompletion($result)
            return $result
        }
        catch {
            $result.AddError("Windows services configuration failed: $($_.Exception.Message)")
            $this.LogServiceCompletion($result)
            return $result
        }
    }
    
    # Execute in WhatIf mode
    [ServiceResult] ExecuteWhatIf() {
        $this.LogServiceStart()
        $result = [ServiceResult]::new($this.ServiceName)
        
        try {
            Write-LogMessage "WhatIf: Windows services configuration would be applied" -Level "Info"
            
            # Get target services
            $targetServices = $this.GetTargetServices()
            
            foreach ($serviceName in $targetServices.Keys) {
                $serviceConfig = $targetServices[$serviceName]
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                
                if ($service) {
                    if ($serviceConfig.TargetState -eq "Stopped" -and $service.Status -eq "Running") {
                        $result.AddChange("WhatIf: Would stop service '$($serviceConfig.DisplayName)'")
                    }
                    
                    if ($serviceConfig.TargetStartType -eq "Disabled") {
                        $result.AddChange("WhatIf: Would set service '$($serviceConfig.DisplayName)' startup type to Disabled")
                    }
                    
                    if ($serviceConfig.TargetState -eq "Running" -and $service.Status -ne "Running") {
                        $result.AddChange("WhatIf: Would start service '$($serviceConfig.DisplayName)'")
                    }
                    
                    if ($serviceConfig.TargetStartType -eq "Automatic") {
                        $result.AddChange("WhatIf: Would set service '$($serviceConfig.DisplayName)' startup type to Automatic")
                    }
                }
                else {
                    $result.AddWarning("WhatIf: Service '$($serviceConfig.DisplayName)' not found on this system")
                }
            }
            
            $result.SetSuccess($true)
            $this.LogServiceCompletion($result)
            return $result
        }
        catch {
            $result.AddError("WhatIf simulation failed: $($_.Exception.Message)")
            $this.LogServiceCompletion($result)
            return $result
        }
    }
    
    # Configure Windows services
    [void] ConfigureWindowsServices([ServiceResult] $result) {
        Write-LogMessage "Configuring Windows services..." -Level "Info"
        
        # Get target services configuration
        $targetServices = $this.GetTargetServices()
        
        # Process each service
        foreach ($serviceName in $targetServices.Keys) {
            $serviceConfig = $targetServices[$serviceName]
            
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                
                if (-not $service) {
                    Write-LogMessage "Service '$($serviceConfig.DisplayName)' not found on this system" -Level "Warning"
                    $result.AddWarning("Service '$($serviceConfig.DisplayName)' not found on this system")
                    continue
                }
                
                Write-LogMessage "Configuring service: $($serviceConfig.DisplayName) (Requirement $($serviceConfig.Requirement))" -Level "Info"
                
                # Check current state
                $currentStartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartMode
                $needsStateChange = $service.Status -ne $serviceConfig.TargetState
                $needsStartTypeChange = $currentStartType -ne $serviceConfig.TargetStartType
                
                if (-not $needsStateChange -and -not $needsStartTypeChange) {
                    Write-LogMessage "Service '$($serviceConfig.DisplayName)' already in desired state" -Level "Success"
                    continue
                }
                
                # Apply service configuration
                $this.ConfigureService($serviceName, $serviceConfig, $result)
                
            }
            catch {
                $result.AddError("Failed to configure service '$($serviceConfig.DisplayName)': $($_.Exception.Message)")
            }
        }
    }
    
    # Configure individual service
    [void] ConfigureService([string] $serviceName, [hashtable] $serviceConfig, [ServiceResult] $result) {
        $changesMade = @()
        
        try {
            # Handle services that need to be stopped and disabled
            if ($serviceConfig.TargetState -eq "Stopped" -and $serviceConfig.TargetStartType -eq "Disabled") {
                
                # Stop the service if it's running
                $service = Get-Service -Name $serviceName
                if ($service.Status -eq "Running") {
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
                $currentStartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartMode
                if ($currentStartType -ne "Disabled") {
                    Write-LogMessage "Setting service '$($serviceConfig.DisplayName)' startup type to Disabled..." -Level "Info"
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
                    $changesMade += "Set startup type to Disabled"
                }
            }
            
            # Handle services that need to be started and set to automatic
            elseif ($serviceConfig.TargetState -eq "Running" -and $serviceConfig.TargetStartType -eq "Automatic") {
                
                # Set startup type to automatic
                $currentStartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartMode
                if ($currentStartType -ne "Automatic") {
                    Write-LogMessage "Setting service '$($serviceConfig.DisplayName)' startup type to Automatic..." -Level "Info"
                    Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
                    $changesMade += "Set startup type to Automatic"
                }
                
                # Start the service if it's not running
                $service = Get-Service -Name $serviceName
                if ($service.Status -ne "Running") {
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
                $result.AddChange($changeDescription)
                Write-LogMessage "Successfully configured service '$($serviceConfig.DisplayName)': $($changesMade -join ', ')" -Level "Success"
            }
            
        }
        catch {
            $result.AddError("Failed to configure service '$($serviceConfig.DisplayName)': $($_.Exception.Message)")
        }
    }
    
    # Get target services configuration
    [hashtable] GetTargetServices() {
        return @{
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
    }
    
    # Create service-specific backup
    [hashtable] CreateServiceSpecificBackup() {
        try {
            $backupResult = @{
                Success = $false
                BackupFiles = @()
                Errors = @()
            }
            
            # Backup current service states
            $targetServices = $this.GetTargetServices()
            $serviceStates = @{}
            
            foreach ($serviceName in $targetServices.Keys) {
                try {
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    if ($service) {
                        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
                        $serviceStates[$serviceName] = @{
                            Status = $service.Status
                            StartType = $wmiService.StartMode
                            DisplayName = $service.DisplayName
                        }
                    }
                }
                catch {
                    $backupResult.Errors += "Failed to backup service state for $serviceName: $($_.Exception.Message)"
                }
            }
            
            # Save service states to backup file
            if ($serviceStates.Count -gt 0) {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $backupFile = Join-Path $env:TEMP "WindowsServices_Backup_$timestamp.json"
                
                $serviceStates | ConvertTo-Json -Depth 3 | Out-File -FilePath $backupFile -Encoding UTF8
                $backupResult.BackupFiles += $backupFile
                $backupResult.Success = $true
            }
            
            return $backupResult
        }
        catch {
            return @{
                Success = $false
                BackupFiles = @()
                Errors = @("Service backup failed: $($_.Exception.Message)")
            }
        }
    }
    
    # Validate service-specific changes
    [bool] ValidateServiceSpecificChanges([ServiceResult] $result) {
        try {
            Write-LogMessage "Validating Windows services configuration changes..." -Level "Info"
            
            $targetServices = $this.GetTargetServices()
            $validationPassed = $true
            
            foreach ($serviceName in $targetServices.Keys) {
                $serviceConfig = $targetServices[$serviceName]
                
                try {
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    if ($service) {
                        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
                        
                        $actualState = $service.Status
                        $actualStartType = $wmiService.StartMode
                        
                        if ($actualState -eq $serviceConfig.TargetState -and $actualStartType -eq $serviceConfig.TargetStartType) {
                            $result.AddValidationResult("PASS: Service '$($serviceConfig.DisplayName)' - State: $actualState, StartType: $actualStartType")
                        }
                        else {
                            $result.AddValidationResult("FAIL: Service '$($serviceConfig.DisplayName)' - Expected: $($serviceConfig.TargetState)/$($serviceConfig.TargetStartType), Actual: $actualState/$actualStartType")
                            $validationPassed = $false
                        }
                    }
                    else {
                        $result.AddValidationResult("SKIP: Service '$($serviceConfig.DisplayName)' not found on system")
                    }
                }
                catch {
                    $result.AddValidationResult("ERROR: Failed to validate service '$($serviceConfig.DisplayName)': $($_.Exception.Message)")
                    $validationPassed = $false
                }
            }
            
            return $validationPassed
        }
        catch {
            Write-LogMessage "Windows services validation error: $($_.Exception.Message)" -Level "Error"
            return $false
        }
    }
}