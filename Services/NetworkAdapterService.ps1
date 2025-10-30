<#
.SYNOPSIS
    Network Adapter Configuration Service
.DESCRIPTION
    Handles all network adapter security configurations including protocol bindings,
    DNS settings, and NetBIOS configuration
#>
class NetworkAdapterService : BaseSecurityService {
    
    # Constructor
    NetworkAdapterService([hashtable] $config) : base($config, "Network Adapter Configuration", @("5.1", "5.2", "5.3", "5.4", "5.5")) {
    }
    
    # Execute network adapter configuration
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
            
            # Execute network adapter configurations
            $this.ConfigureNetworkAdapters($result)
            
            # Validate changes
            if ($this.ValidateChanges($result)) {
                $result.SetSuccess($true)
            }
            
            $this.LogServiceCompletion($result)
            return $result
        }
        catch {
            $result.AddError("Network adapter configuration failed: $($_.Exception.Message)")
            $this.LogServiceCompletion($result)
            return $result
        }
    }
    
    # Execute in WhatIf mode
    [ServiceResult] ExecuteWhatIf() {
        $this.LogServiceStart()
        $result = [ServiceResult]::new($this.ServiceName)
        
        try {
            Write-LogMessage "WhatIf: Network adapter configuration would be applied" -Level "Info"
            
            # Simulate network adapter changes
            $networkAdapters = Get-NetworkAdapters
            
            foreach ($adapter in $networkAdapters) {
                if (-not ($adapter.Virtual -or $adapter.Hidden -or $adapter.Status -ne "Up")) {
                    if ($this.Configuration.NetworkSettings.DisableClientForMSNetworks) {
                        $result.AddChange("WhatIf: Would disable Client for MS Networks on $($adapter.Name)")
                    }
                    
                    if ($this.Configuration.NetworkSettings.DisableFileAndPrinterSharing) {
                        $result.AddChange("WhatIf: Would disable File and Printer Sharing on $($adapter.Name)")
                    }
                    
                    if ($this.Configuration.NetworkSettings.DisableIPv6) {
                        $result.AddChange("WhatIf: Would disable IPv6 protocol on $($adapter.Name)")
                    }
                    
                    if ($this.Configuration.NetworkSettings.DisableDNSRegistration) {
                        $result.AddChange("WhatIf: Would disable DNS registration on $($adapter.Name)")
                    }
                    
                    if ($this.Configuration.NetworkSettings.DisableNetBIOS) {
                        $result.AddChange("WhatIf: Would disable NetBIOS over TCP/IP on $($adapter.Name)")
                    }
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
    
    # Configure network adapters
    [void] ConfigureNetworkAdapters([ServiceResult] $result) {
        Write-LogMessage "Configuring network adapters..." -Level "Info"
        
        # Get network adapters
        $networkAdapters = Get-NetworkAdapters
        
        if ($networkAdapters.Count -eq 0) {
            $result.AddError("No network adapters found on the system")
            return
        }
        
        Write-LogMessage "Found $($networkAdapters.Count) network adapters" -Level "Success"
        
        # Process each adapter
        foreach ($adapter in $networkAdapters) {
            # Skip virtual, hidden, or disabled adapters
            if ($adapter.Virtual -or $adapter.Hidden -or $adapter.Status -ne "Up") {
                Write-LogMessage "Skipping adapter $($adapter.Name) (Virtual: $($adapter.Virtual), Hidden: $($adapter.Hidden), Status: $($adapter.Status))" -Level "Info"
                continue
            }
            
            Write-LogMessage "Configuring adapter: $($adapter.Name)" -Level "Info"
            
            # Configure protocol bindings
            $this.ConfigureProtocolBindings($adapter, $result)
            
            # Configure DNS settings
            $this.ConfigureDNSSettings($adapter, $result)
            
            # Configure NetBIOS settings
            $this.ConfigureNetBIOSSettings($adapter, $result)
        }
    }
    
    # Configure protocol bindings
    [void] ConfigureProtocolBindings([object] $adapter, [ServiceResult] $result) {
        # Disable Client for MS Networks (Requirement 5.1)
        if ($this.Configuration.NetworkSettings.DisableClientForMSNetworks) {
            try {
                $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_msclient" -Enabled $false
                if ($bindingResult.Success) {
                    $result.AddChange("Disabled Client for MS Networks on $($adapter.Name)")
                }
                else {
                    $result.AddError("Failed to disable Client for MS Networks on $($adapter.Name)")
                }
            }
            catch {
                $result.AddError("Error disabling Client for MS Networks on $($adapter.Name): $($_.Exception.Message)")
            }
        }
        
        # Disable File and Printer Sharing (Requirement 5.2)
        if ($this.Configuration.NetworkSettings.DisableFileAndPrinterSharing) {
            try {
                $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_server" -Enabled $false
                if ($bindingResult.Success) {
                    $result.AddChange("Disabled File and Printer Sharing on $($adapter.Name)")
                }
                else {
                    $result.AddError("Failed to disable File and Printer Sharing on $($adapter.Name)")
                }
            }
            catch {
                $result.AddError("Error disabling File and Printer Sharing on $($adapter.Name): $($_.Exception.Message)")
            }
        }
        
        # Disable IPv6 Protocol (Requirement 5.3)
        if ($this.Configuration.NetworkSettings.DisableIPv6) {
            try {
                $bindingResult = Set-NetworkAdapterProtocolBinding -AdapterName $adapter.Name -ComponentID "ms_tcpip6" -Enabled $false
                if ($bindingResult.Success) {
                    $result.AddChange("Disabled IPv6 protocol on $($adapter.Name)")
                }
                else {
                    $result.AddError("Failed to disable IPv6 protocol on $($adapter.Name)")
                }
            }
            catch {
                $result.AddError("Error disabling IPv6 protocol on $($adapter.Name): $($_.Exception.Message)")
            }
        }
    }
    
    # Configure DNS settings
    [void] ConfigureDNSSettings([object] $adapter, [ServiceResult] $result) {
        # Configure DNS registration settings (Requirement 5.4)
        if ($this.Configuration.NetworkSettings.DisableDNSRegistration) {
            try {
                $dnsResult = Set-DNSRegistrationSettings -AdapterName $adapter.Name -Enabled $false
                if ($dnsResult.Success) {
                    $result.AddChange("Disabled DNS registration on $($adapter.Name)")
                }
                else {
                    $result.AddError("Failed to disable DNS registration on $($adapter.Name)")
                }
            }
            catch {
                $result.AddError("Error disabling DNS registration on $($adapter.Name): $($_.Exception.Message)")
            }
        }
    }
    
    # Configure NetBIOS settings
    [void] ConfigureNetBIOSSettings([object] $adapter, [ServiceResult] $result) {
        # Disable NetBIOS over TCP/IP (Requirement 5.5)
        if ($this.Configuration.NetworkSettings.DisableNetBIOS) {
            try {
                $netbiosResult = Set-NetBIOSSettings -AdapterName $adapter.Name -InterfaceGuid $adapter.InterfaceGuid -Enabled $false
                if ($netbiosResult.Success) {
                    $result.AddChange("Disabled NetBIOS over TCP/IP on $($adapter.Name)")
                }
                else {
                    $result.AddError("Failed to disable NetBIOS over TCP/IP on $($adapter.Name)")
                }
            }
            catch {
                $result.AddError("Error disabling NetBIOS over TCP/IP on $($adapter.Name): $($_.Exception.Message)")
            }
        }
    }
    
    # Validate service-specific changes
    [bool] ValidateServiceSpecificChanges([ServiceResult] $result) {
        try {
            Write-LogMessage "Validating network adapter configuration changes..." -Level "Info"
            
            $networkAdapters = Get-NetworkAdapters
            $validationPassed = $true
            
            foreach ($adapter in $networkAdapters) {
                if (-not ($adapter.Virtual -or $adapter.Hidden -or $adapter.Status -ne "Up")) {
                    # Validate protocol bindings
                    $bindings = Get-NetworkAdapterProtocolBindings -AdapterName $adapter.Name -InterfaceGuid $adapter.InterfaceGuid
                    
                    if ($this.Configuration.NetworkSettings.DisableClientForMSNetworks -and $bindings.ClientForMSNetworks.Enabled) {
                        $result.AddValidationResult("FAIL: Client for MS Networks still enabled on $($adapter.Name)")
                        $validationPassed = $false
                    }
                    else {
                        $result.AddValidationResult("PASS: Client for MS Networks disabled on $($adapter.Name)")
                    }
                    
                    if ($this.Configuration.NetworkSettings.DisableFileAndPrinterSharing -and $bindings.FileAndPrinterSharing.Enabled) {
                        $result.AddValidationResult("FAIL: File and Printer Sharing still enabled on $($adapter.Name)")
                        $validationPassed = $false
                    }
                    else {
                        $result.AddValidationResult("PASS: File and Printer Sharing disabled on $($adapter.Name)")
                    }
                    
                    if ($this.Configuration.NetworkSettings.DisableIPv6 -and $bindings.IPv6Protocol.Enabled) {
                        $result.AddValidationResult("FAIL: IPv6 protocol still enabled on $($adapter.Name)")
                        $validationPassed = $false
                    }
                    else {
                        $result.AddValidationResult("PASS: IPv6 protocol disabled on $($adapter.Name)")
                    }
                }
            }
            
            return $validationPassed
        }
        catch {
            Write-LogMessage "Network adapter validation error: $($_.Exception.Message)" -Level "Error"
            return $false
        }
    }
}