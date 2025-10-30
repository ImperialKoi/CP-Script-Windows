using namespace System.Collections.Generic

<#
.SYNOPSIS
    Main controller class for Windows Security Hardening operations
.DESCRIPTION
    This class orchestrates the entire security hardening process, managing
    configuration, execution modes, and module coordination
#>
class SecurityHardeningController {
    [hashtable] $Configuration
    [string] $ExecutionMode
    [List[object]] $ExecutionResults
    [datetime] $StartTime
    [datetime] $EndTime
    [string] $LogPath
    [bool] $WhatIfMode
    [bool] $SilentMode

    # Constructor
    SecurityHardeningController([hashtable] $config, [string] $logPath) {
        $this.Configuration = $config
        $this.LogPath = $logPath
        $this.ExecutionResults = [List[object]]::new()
        $this.StartTime = Get-Date
        $this.WhatIfMode = $false
        $this.SilentMode = $false
        $this.ExecutionMode = "Interactive"
    }

    # Set execution mode
    [void] SetExecutionMode([string] $mode) {
        $validModes = @("Interactive", "Silent", "WhatIf")
        if ($mode -in $validModes) {
            $this.ExecutionMode = $mode
            $this.SilentMode = ($mode -eq "Silent")
            $this.WhatIfMode = ($mode -eq "WhatIf")
        }
        else {
            throw "Invalid execution mode: $mode. Valid modes are: $($validModes -join ', ')"
        }
    }

    # Execute all security modules
    [object] ExecuteSecurityHardening() {
        try {
            Write-LogMessage "Starting security hardening execution in $($this.ExecutionMode) mode" -Level "Info"
            
            # Initialize services
            $serviceFactory = [SecurityServiceFactory]::new($this.Configuration)
            $services = $serviceFactory.CreateAllServices()
            
            $result = [ExecutionResult]::new()
            $result.ExecutionMode = $this.ExecutionMode
            $result.StartTime = $this.StartTime
            
            # Execute each service
            foreach ($service in $services) {
                $serviceResult = $this.ExecuteService($service)
                $result.AddServiceResult($serviceResult)
                $this.ExecutionResults.Add($serviceResult)
            }
            
            $this.EndTime = Get-Date
            $result.EndTime = $this.EndTime
            $result.Duration = $this.EndTime - $this.StartTime
            
            # Generate final reports
            $this.GenerateFinalReports($result)
            
            return $result
        }
        catch {
            Write-LogMessage "Critical error in security hardening execution: $($_.Exception.Message)" -Level "Error"
            throw
        }
    }

    # Execute individual service
    [object] ExecuteService([object] $service) {
        try {
            Write-LogMessage "Executing service: $($service.GetType().Name)" -Level "Info"
            
            # Check execution mode permissions
            if ($this.ExecutionMode -eq "Interactive" -and -not $this.SilentMode) {
                $confirmation = $this.GetUserConfirmation($service)
                if (-not $confirmation) {
                    Write-LogMessage "Service skipped by user: $($service.GetType().Name)" -Level "Warning"
                    return [ServiceResult]::CreateSkipped($service.GetType().Name)
                }
            }
            
            # Execute the service
            if ($this.WhatIfMode) {
                return $service.ExecuteWhatIf()
            }
            else {
                return $service.Execute()
            }
        }
        catch {
            Write-LogMessage "Service execution failed: $($service.GetType().Name) - $($_.Exception.Message)" -Level "Error"
            return [ServiceResult]::CreateFailed($service.GetType().Name, $_.Exception.Message)
        }
    }

    # Get user confirmation for interactive mode
    [bool] GetUserConfirmation([object] $service) {
        if ($this.SilentMode) {
            return $true
        }
        
        $serviceName = $service.GetType().Name -replace "Service$", ""
        Write-Host "`nExecute $serviceName module? (Y/N/S for Silent mode)" -ForegroundColor Yellow
        
        do {
            $response = Read-Host
            switch ($response.ToUpper()) {
                "Y" { return $true }
                "N" { return $false }
                "S" { 
                    $this.SilentMode = $true
                    return $true 
                }
                default { 
                    Write-Host "Please enter Y (Yes), N (No), or S (Silent mode)" -ForegroundColor Red 
                }
            }
        } while ($true)
    }

    # Generate final reports
    [void] GenerateFinalReports([object] $result) {
        try {
            Write-LogMessage "Generating final execution reports..." -Level "Info"
            
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $summaryPath = Join-Path $this.LogPath "ExecutionSummary_$timestamp.txt"
            $compliancePath = Join-Path $this.LogPath "ComplianceReport_$timestamp.txt"
            
            # Generate reports using existing functions
            Generate-ExecutionSummaryReport -ExecutionResults $this.ExecutionResults.ToArray() -OutputPath $summaryPath
            Generate-ComplianceReport -ExecutionResults $this.ExecutionResults.ToArray() -OutputPath $compliancePath
            
            Write-LogMessage "Reports generated: $summaryPath, $compliancePath" -Level "Success"
        }
        catch {
            Write-LogMessage "Error generating reports: $($_.Exception.Message)" -Level "Warning"
        }
    }

    # Get execution summary
    [hashtable] GetExecutionSummary() {
        $successful = ($this.ExecutionResults | Where-Object { $_.Success }).Count
        $failed = ($this.ExecutionResults | Where-Object { -not $_.Success }).Count
        $totalChanges = ($this.ExecutionResults | ForEach-Object { $_.Changes.Count } | Measure-Object -Sum).Sum
        
        return @{
            TotalServices = $this.ExecutionResults.Count
            Successful = $successful
            Failed = $failed
            TotalChanges = $totalChanges
            Duration = if ($this.EndTime) { $this.EndTime - $this.StartTime } else { $null }
            ExecutionMode = $this.ExecutionMode
        }
    }
}