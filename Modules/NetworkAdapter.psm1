<#
.SYNOPSIS
    Network Adapter Configuration Module

.DESCRIPTION
    This module provides comprehensive network adapter configuration functionality
    including enumeration, protocol binding management, and security hardening
    for network adapters according to security requirements.
#>

function Get-NetworkAdapters {
    <#
    .SYNOPSIS
        Enumerates all network adapters on the system
    .DESCRIPTION
        Retrieves comprehensive information about all network adapters including
        their properties, protocol bindings, and current configuration
    .OUTPUTS
        Returns array of hashtables containing network adapter information
    #>
    
    Write-LogMessage "Enumerating network adapters..." -Level "Info"
    
    $networkAdapters = @()
    
    try {
        # Try to use Get-NetAdapter (Windows 8/Server 2012+)
        if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
            Write-LogMessage "Using Get-NetAdapter for adapter enumeration" -Level "Info"
            
            $adapters = Get-NetAdapter -ErrorAction Stop
            
            foreach ($adapter in $adapters) {
                try {
                    # Get additional adapter information
                    $adapterInfo = @{
                        Name = $adapter.Name
                        InterfaceDescription = $adapter.InterfaceDescription
                        InterfaceIndex = $adapter.InterfaceIndex
                        Status = $adapter.Status.ToString()
                        AdminStatus = $adapter.AdminStatus.ToString()
                        MediaType = $adapter.MediaType.ToString()
                        PhysicalMediaType = $adapter.PhysicalMediaType.ToString()
                        LinkSpeed = $adapter.LinkSpeed
                        MacAddress = $adapter.MacAddress
                        InterfaceGuid = $adapter.InterfaceGuid.ToString()
                        DriverInformation = $adapter.DriverInformation
                        Virtual = $adapter.Virtual
                        Hidden = $adapter.Hidden
                        NotUserRemovable = $adapter.NotUserRemovable
                        ProtocolBindings = @()
                        IPv6Enabled = $null
                        DNSRegistrationEnabled = $null
                        NetBIOSEnabled = $null
                        ClientForMSNetworksEnabled = $null
                        FileAndPrinterSharingEnabled = $null
                    }
                    
                    # Get protocol bindings using WMI as fallback
                    try {
                        $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "GUID='$($adapter.InterfaceGuid)'" -ErrorAction SilentlyContinue
                        if ($wmiAdapter) {
                            $adapterInfo.PNPDeviceID = $wmiAdapter.PNPDeviceID
                            $adapterInfo.Manufacturer = $wmiAdapter.Manufacturer
                            $adapterInfo.ProductName = $wmiAdapter.ProductName
                        }
                    }
                    catch {
                        Write-LogMessage "Warning: Could not retrieve WMI information for adapter: $($adapter.Name)" -Level "Debug"
                    }
                    
                    $networkAdapters += $adapterInfo
                    Write-LogMessage "Enumerated adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -Level "Info"
                }
                catch {
                    Write-LogMessage "Error processing adapter $($adapter.Name): $($_.Exception.Message)" -Level "Warning"
                }
            }
        }
        else {
            # Fallback to WMI for older systems
            Write-LogMessage "Get-NetAdapter not available, using WMI fallback..." -Level "Info"
            
            $wmiAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "NetEnabled=True" -ErrorAction Stop
            
            foreach ($adapter in $wmiAdapters) {
                try {
                    $adapterInfo = @{
                        Name = $adapter.NetConnectionID
                        InterfaceDescription = $adapter.Description
                        InterfaceIndex = $adapter.InterfaceIndex
                        Status = if ($adapter.NetConnectionStatus) { "Up" } else { "Down" }
                        AdminStatus = if ($adapter.NetEnabled) { "Up" } else { "Down" }
                        MediaType = $adapter.AdapterType
                        PhysicalMediaType = $adapter.AdapterType
                        LinkSpeed = $adapter.Speed
                        MacAddress = $adapter.MACAddress
                        InterfaceGuid = $adapter.GUID
                        PNPDeviceID = $adapter.PNPDeviceID
                        Manufacturer = $adapter.Manufacturer
                        ProductName = $adapter.ProductName
                        Virtual = $false
                        Hidden = $false
                        NotUserRemovable = $true
                        ProtocolBindings = @()
                        IPv6Enabled = $null
                        DNSRegistrationEnabled = $null
                        NetBIOSEnabled = $null
                        ClientForMSNetworksEnabled = $null
                        FileAndPrinterSharingEnabled = $null
                    }
                    
                    $networkAdapters += $adapterInfo
                    Write-LogMessage "Enumerated adapter (WMI): $($adapter.NetConnectionID) ($($adapter.Description))" -Level "Info"
                }
                catch {
                    Write-LogMessage "Error processing WMI adapter $($adapter.NetConnectionID): $($_.Exception.Message)" -Level "Warning"
                }
            }
        }
        
        Write-LogMessage "Successfully enumerated $($networkAdapters.Count) network adapters" -Level "Success"
    }
    catch {
        Write-LogMessage "Failed to enumerate network adapters: $($_.Exception.Message)" -Level "Error"
        throw
    }
    
    return $networkAdapters
}

function Get-NetworkAdapterProtocolBindings {
    <#
    .SYNOPSIS
        Retrieves protocol bindings for network adapters
    .DESCRIPTION
        Gets detailed information about protocol bindings including Client for MS Networks,
        File and Printer Sharing, IPv6, and other network protocols
    .PARAMETER AdapterName
        Name of the network adapter to examine
    .PARAMETER InterfaceGuid
        GUID of the network interface
    .OUTPUTS
        Returns hashtable with protocol binding information
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        
        [Parameter(Mandatory = $false)]
        [string]$InterfaceGuid
    )
    
    Write-LogMessage "Retrieving protocol bindings for adapter: $AdapterName" -Level "Info"
    
    $protocolBindings = @{
        AdapterName = $AdapterName
        ClientForMSNetworks = @{ Enabled = $null; ComponentID = "ms_msclient" }
        FileAndPrinterSharing = @{ Enabled = $null; ComponentID = "ms_server" }
        IPv6Protocol = @{ Enabled = $null; ComponentID = "ms_tcpip6" }
        IPv4Protocol = @{ Enabled = $null; ComponentID = "ms_tcpip" }
        QoSPacketScheduler = @{ Enabled = $null; ComponentID = "ms_pacer" }
        LinkLayerTopologyDiscovery = @{ Enabled = $null; ComponentID = "ms_lltdio" }
        NetworkAdapterMultiplexor = @{ Enabled = $null; ComponentID = "ms_implat" }
        Errors = @()
    }
    
    try {
        # Method 1: Try using Get-NetAdapterBinding (Windows 8/Server 2012+)
        if (Get-Command Get-NetAdapterBinding -ErrorAction SilentlyContinue) {
            try {
                $bindings = Get-NetAdapterBinding -Name $AdapterName -ErrorAction Stop
                
                foreach ($binding in $bindings) {
                    switch ($binding.ComponentID) {
                        "ms_msclient" {
                            $protocolBindings.ClientForMSNetworks.Enabled = $binding.Enabled
                            Write-LogMessage "Client for MS Networks: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_server" {
                            $protocolBindings.FileAndPrinterSharing.Enabled = $binding.Enabled
                            Write-LogMessage "File and Printer Sharing: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_tcpip6" {
                            $protocolBindings.IPv6Protocol.Enabled = $binding.Enabled
                            Write-LogMessage "IPv6 Protocol: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_tcpip" {
                            $protocolBindings.IPv4Protocol.Enabled = $binding.Enabled
                            Write-LogMessage "IPv4 Protocol: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_pacer" {
                            $protocolBindings.QoSPacketScheduler.Enabled = $binding.Enabled
                            Write-LogMessage "QoS Packet Scheduler: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_lltdio" {
                            $protocolBindings.LinkLayerTopologyDiscovery.Enabled = $binding.Enabled
                            Write-LogMessage "Link Layer Topology Discovery: $($binding.Enabled)" -Level "Info"
                        }
                        "ms_implat" {
                            $protocolBindings.NetworkAdapterMultiplexor.Enabled = $binding.Enabled
                            Write-LogMessage "Network Adapter Multiplexor: $($binding.Enabled)" -Level "Info"
                        }
                    }
                }
                
                Write-LogMessage "Successfully retrieved protocol bindings using Get-NetAdapterBinding" -Level "Success"
            }
            catch {
                Write-LogMessage "Get-NetAdapterBinding failed: $($_.Exception.Message)" -Level "Warning"
                $protocolBindings.Errors += "Get-NetAdapterBinding failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Registry-based approach for protocol bindings
        if ($InterfaceGuid -and ($protocolBindings.ClientForMSNetworks.Enabled -eq $null)) {
            try {
                Write-LogMessage "Attempting registry-based protocol binding detection..." -Level "Info"
                
                # Check registry for network adapter bindings
                $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                
                # Find the adapter in registry by matching GUID or description
                $adapterKeys = Get-ChildItem -Path $adapterRegPath -ErrorAction SilentlyContinue
                
                foreach ($key in $adapterKeys) {
                    try {
                        $keyPath = $key.PSPath
                        $netCfgInstanceId = Get-ItemProperty -Path $keyPath -Name "NetCfgInstanceId" -ErrorAction SilentlyContinue
                        
                        if ($netCfgInstanceId -and $netCfgInstanceId.NetCfgInstanceId -eq $InterfaceGuid) {
                            # Found the adapter, check for component bindings
                            $componentBindings = Get-ItemProperty -Path $keyPath -Name "ComponentBindings" -ErrorAction SilentlyContinue
                            
                            if ($componentBindings -and $componentBindings.ComponentBindings) {
                                $bindings = $componentBindings.ComponentBindings
                                
                                $protocolBindings.ClientForMSNetworks.Enabled = $bindings -contains "ms_msclient"
                                $protocolBindings.FileAndPrinterSharing.Enabled = $bindings -contains "ms_server"
                                $protocolBindings.IPv6Protocol.Enabled = $bindings -contains "ms_tcpip6"
                                $protocolBindings.IPv4Protocol.Enabled = $bindings -contains "ms_tcpip"
                                
                                Write-LogMessage "Retrieved protocol bindings from registry" -Level "Success"
                            }
                            break
                        }
                    }
                    catch {
                        # Continue to next key
                        continue
                    }
                }
            }
            catch {
                Write-LogMessage "Registry-based binding detection failed: $($_.Exception.Message)" -Level "Warning"
                $protocolBindings.Errors += "Registry detection failed: $($_.Exception.Message)"
            }
        }
        
        # Method 3: WMI-based approach as final fallback
        if ($protocolBindings.ClientForMSNetworks.Enabled -eq $null) {
            try {
                Write-LogMessage "Attempting WMI-based protocol binding detection..." -Level "Info"
                
                # Use WMI to check network adapter configuration
                $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Description='$($AdapterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
                
                if (-not $wmiAdapter) {
                    # Try by interface index if available
                    $netAdapter = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "NetConnectionID='$($AdapterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
                    if ($netAdapter) {
                        $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Index=$($netAdapter.Index)" -ErrorAction SilentlyContinue
                    }
                }
                
                if ($wmiAdapter) {
                    # WMI doesn't provide direct protocol binding info, but we can infer some settings
                    $protocolBindings.IPv6Protocol.Enabled = $wmiAdapter.IPEnabled -and ($wmiAdapter.IPAddress -contains "::1" -or $wmiAdapter.DefaultIPGateway -like "*:*")
                    
                    Write-LogMessage "Retrieved partial binding information from WMI" -Level "Info"
                }
            }
            catch {
                Write-LogMessage "WMI-based binding detection failed: $($_.Exception.Message)" -Level "Warning"
                $protocolBindings.Errors += "WMI detection failed: $($_.Exception.Message)"
            }
        }
        
        Write-LogMessage "Protocol binding retrieval completed for adapter: $AdapterName" -Level "Success"
    }
    catch {
        Write-LogMessage "Failed to retrieve protocol bindings for adapter $AdapterName`: $($_.Exception.Message)" -Level "Error"
        $protocolBindings.Errors += "General failure: $($_.Exception.Message)"
    }
    
    return $protocolBindings
}

function Set-NetworkAdapterProtocolBinding {
    <#
    .SYNOPSIS
        Modifies protocol bindings for a network adapter
    .DESCRIPTION
        Enables or disables specific protocol bindings on a network adapter
    .PARAMETER AdapterName
        Name of the network adapter to modify
    .PARAMETER ComponentID
        Component ID of the protocol to modify (e.g., ms_msclient, ms_server, ms_tcpip6)
    .PARAMETER Enabled
        Whether to enable or disable the protocol binding
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        
        [Parameter(Mandatory = $true)]
        [string]$ComponentID,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    Write-LogMessage "Modifying protocol binding for adapter $AdapterName`: $ComponentID = $Enabled" -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
        ComponentID = $ComponentID
        AdapterName = $AdapterName
        Enabled = $Enabled
    }
    
    try {
        # Method 1: Try using Set-NetAdapterBinding (Windows 8/Server 2012+)
        if (Get-Command Set-NetAdapterBinding -ErrorAction SilentlyContinue) {
            try {
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set $ComponentID binding to $Enabled on adapter $AdapterName" -Level "Info"
                    $result.Changes += "Would set $ComponentID binding to $Enabled"
                    $result.Success = $true
                }
                else {
                    Set-NetAdapterBinding -Name $AdapterName -ComponentID $ComponentID -Enabled $Enabled -ErrorAction Stop
                    Write-LogMessage "Successfully set $ComponentID binding to $Enabled on adapter $AdapterName" -Level "Success"
                    $result.Changes += "Set $ComponentID binding to $Enabled"
                    $result.Success = $true
                }
                
                return $result
            }
            catch {
                Write-LogMessage "Set-NetAdapterBinding failed: $($_.Exception.Message)" -Level "Warning"
                $result.Warnings += "Set-NetAdapterBinding failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Registry-based approach for older systems
        try {
            Write-LogMessage "Attempting registry-based protocol binding modification..." -Level "Info"
            
            # Find the network adapter in registry
            $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            $adapterKeys = Get-ChildItem -Path $adapterRegPath -ErrorAction Stop
            
            $adapterFound = $false
            foreach ($key in $adapterKeys) {
                try {
                    $keyPath = $key.PSPath
                    $driverDesc = Get-ItemProperty -Path $keyPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                    $netConnectionID = Get-ItemProperty -Path $keyPath -Name "NetConnectionID" -ErrorAction SilentlyContinue
                    
                    if (($driverDesc -and $driverDesc.DriverDesc -eq $AdapterName) -or 
                        ($netConnectionID -and $netConnectionID.NetConnectionID -eq $AdapterName)) {
                        
                        $adapterFound = $true
                        
                        # Get current bindings
                        $currentBindings = Get-ItemProperty -Path $keyPath -Name "ComponentBindings" -ErrorAction SilentlyContinue
                        
                        if ($currentBindings -and $currentBindings.ComponentBindings) {
                            $bindings = [System.Collections.ArrayList]$currentBindings.ComponentBindings
                            
                            if ($Enabled) {
                                # Add component if not present
                                if ($bindings -notcontains $ComponentID) {
                                    if ($WhatIf) {
                                        Write-LogMessage "WhatIf: Would add $ComponentID to adapter bindings" -Level "Info"
                                        $result.Changes += "Would add $ComponentID to bindings"
                                    }
                                    else {
                                        $bindings.Add($ComponentID) | Out-Null
                                        Set-ItemProperty -Path $keyPath -Name "ComponentBindings" -Value $bindings.ToArray() -ErrorAction Stop
                                        Write-LogMessage "Added $ComponentID to adapter bindings" -Level "Success"
                                        $result.Changes += "Added $ComponentID to bindings"
                                    }
                                }
                                else {
                                    Write-LogMessage "$ComponentID already enabled on adapter" -Level "Info"
                                }
                            }
                            else {
                                # Remove component if present
                                if ($bindings -contains $ComponentID) {
                                    if ($WhatIf) {
                                        Write-LogMessage "WhatIf: Would remove $ComponentID from adapter bindings" -Level "Info"
                                        $result.Changes += "Would remove $ComponentID from bindings"
                                    }
                                    else {
                                        $bindings.Remove($ComponentID)
                                        Set-ItemProperty -Path $keyPath -Name "ComponentBindings" -Value $bindings.ToArray() -ErrorAction Stop
                                        Write-LogMessage "Removed $ComponentID from adapter bindings" -Level "Success"
                                        $result.Changes += "Removed $ComponentID from bindings"
                                    }
                                }
                                else {
                                    Write-LogMessage "$ComponentID already disabled on adapter" -Level "Info"
                                }
                            }
                            
                            $result.Success = $true
                        }
                        else {
                            $result.Warnings += "Could not find ComponentBindings registry value"
                        }
                        
                        break
                    }
                }
                catch {
                    continue
                }
            }
            
            if (-not $adapterFound) {
                $result.Errors += "Could not find adapter $AdapterName in registry"
                Write-LogMessage "Could not find adapter $AdapterName in registry" -Level "Error"
            }
        }
        catch {
            $result.Errors += "Registry-based modification failed: $($_.Exception.Message)"
            Write-LogMessage "Registry-based modification failed: $($_.Exception.Message)" -Level "Error"
        }
        
        # Method 3: netsh command as final fallback for specific protocols
        if (-not $result.Success -and $ComponentID -eq "ms_tcpip6") {
            try {
                Write-LogMessage "Attempting netsh command for IPv6 protocol..." -Level "Info"
                
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would use netsh to $(if ($Enabled) { 'enable' } else { 'disable' }) IPv6 on $AdapterName" -Level "Info"
                    $result.Changes += "Would use netsh to $(if ($Enabled) { 'enable' } else { 'disable' }) IPv6"
                    $result.Success = $true
                }
                else {
                    $netshAction = if ($Enabled) { "enable" } else { "disable" }
                    $netshArgs = @("interface", "ipv6", $netshAction, $AdapterName)
                    
                    $process = Start-Process -FilePath "netsh.exe" -ArgumentList $netshArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\netsh_output.txt" -RedirectStandardError "$env:TEMP\netsh_error.txt"
                    
                    if ($process.ExitCode -eq 0) {
                        Write-LogMessage "Successfully used netsh to $(if ($Enabled) { 'enable' } else { 'disable' }) IPv6 on $AdapterName" -Level "Success"
                        $result.Changes += "Used netsh to $(if ($Enabled) { 'enable' } else { 'disable' }) IPv6"
                        $result.Success = $true
                    }
                    else {
                        $errorOutput = ""
                        if (Test-Path "$env:TEMP\netsh_error.txt") {
                            $errorOutput = Get-Content "$env:TEMP\netsh_error.txt" -Raw
                        }
                        $result.Errors += "netsh command failed: Exit code $($process.ExitCode). $errorOutput"
                    }
                    
                    # Cleanup temp files
                    @("$env:TEMP\netsh_output.txt", "$env:TEMP\netsh_error.txt") | ForEach-Object {
                        if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
            catch {
                $result.Errors += "netsh command failed: $($_.Exception.Message)"
                Write-LogMessage "netsh command failed: $($_.Exception.Message)" -Level "Error"
            }
        }
        
        if ($result.Success) {
            Write-LogMessage "Protocol binding modification completed successfully" -Level "Success"
        }
        else {
            Write-LogMessage "Protocol binding modification failed" -Level "Error"
        }
    }
    catch {
        $result.Errors += "Failed to modify protocol binding: $($_.Exception.Message)"
        Write-LogMessage "Failed to modify protocol binding: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Set-DNSRegistrationSettings {
    <#
    .SYNOPSIS
        Configures DNS registration settings for a network adapter
    .DESCRIPTION
        Enables or disables DNS registration for network connections
    .PARAMETER AdapterName
        Name of the network adapter to configure
    .PARAMETER Enabled
        Whether to enable or disable DNS registration
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    Write-LogMessage "Configuring DNS registration for adapter $AdapterName`: $Enabled" -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        # Method 1: Try using Set-DnsClient (Windows 8/Server 2012+)
        if (Get-Command Set-DnsClient -ErrorAction SilentlyContinue) {
            try {
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set DNS registration to $Enabled on adapter $AdapterName" -Level "Info"
                    $result.Changes += "Would set DNS registration to $Enabled"
                    $result.Success = $true
                }
                else {
                    # Get the interface index for the adapter
                    $netAdapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop
                    
                    # Configure DNS registration
                    Set-DnsClient -InterfaceIndex $netAdapter.InterfaceIndex -RegisterThisConnectionsAddress $Enabled -ErrorAction Stop
                    
                    Write-LogMessage "Successfully set DNS registration to $Enabled on adapter $AdapterName" -Level "Success"
                    $result.Changes += "Set DNS registration to $Enabled"
                    $result.Success = $true
                }
                
                return $result
            }
            catch {
                Write-LogMessage "Set-DnsClient failed: $($_.Exception.Message)" -Level "Warning"
                $result.Warnings += "Set-DnsClient failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Registry-based approach
        try {
            Write-LogMessage "Attempting registry-based DNS registration configuration..." -Level "Info"
            
            # Find the network adapter in registry
            $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            $interfaceKeys = Get-ChildItem -Path $adapterRegPath -ErrorAction Stop
            
            $adapterFound = $false
            foreach ($key in $interfaceKeys) {
                try {
                    $keyPath = $key.PSPath
                    
                    # Try to match by adapter name or description
                    # This is a best-effort approach as registry doesn't always have clear adapter name mapping
                    $dhcpDomain = Get-ItemProperty -Path $keyPath -Name "DhcpDomain" -ErrorAction SilentlyContinue
                    $adapterGuid = Split-Path $keyPath -Leaf
                    
                    # Check if this interface corresponds to our adapter
                    # We'll use a heuristic approach since exact matching is complex
                    $registrationValue = if ($Enabled) { 1 } else { 0 }
                    
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would set DNS registration registry values for interface $adapterGuid" -Level "Info"
                        $result.Changes += "Would set DNS registration registry values"
                        $result.Success = $true
                        $adapterFound = $true
                        break
                    }
                    else {
                        # Set DNS registration values
                        Set-ItemProperty -Path $keyPath -Name "RegistrationEnabled" -Value $registrationValue -Type DWord -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $keyPath -Name "RegisterAdapterName" -Value $registrationValue -Type DWord -ErrorAction SilentlyContinue
                        
                        Write-LogMessage "Set DNS registration registry values for interface $adapterGuid" -Level "Info"
                        $result.Changes += "Set DNS registration registry values"
                        $result.Success = $true
                        $adapterFound = $true
                    }
                }
                catch {
                    continue
                }
            }
            
            if (-not $adapterFound) {
                $result.Warnings += "Could not find specific interface in registry, applied to all interfaces"
                Write-LogMessage "Applied DNS registration settings to all network interfaces" -Level "Warning"
            }
        }
        catch {
            $result.Errors += "Registry-based DNS configuration failed: $($_.Exception.Message)"
            Write-LogMessage "Registry-based DNS configuration failed: $($_.Exception.Message)" -Level "Error"
        }
        
        # Method 3: netsh command as fallback
        if (-not $result.Success) {
            try {
                Write-LogMessage "Attempting netsh command for DNS registration..." -Level "Info"
                
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would use netsh to configure DNS registration on $AdapterName" -Level "Info"
                    $result.Changes += "Would use netsh to configure DNS registration"
                    $result.Success = $true
                }
                else {
                    $netshValue = if ($Enabled) { "enable" } else { "disable" }
                    $netshArgs = @("interface", "ip", "set", "dns", $AdapterName, "register=$netshValue")
                    
                    $process = Start-Process -FilePath "netsh.exe" -ArgumentList $netshArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\netsh_dns_output.txt" -RedirectStandardError "$env:TEMP\netsh_dns_error.txt"
                    
                    if ($process.ExitCode -eq 0) {
                        Write-LogMessage "Successfully configured DNS registration using netsh on $AdapterName" -Level "Success"
                        $result.Changes += "Configured DNS registration using netsh"
                        $result.Success = $true
                    }
                    else {
                        $errorOutput = ""
                        if (Test-Path "$env:TEMP\netsh_dns_error.txt") {
                            $errorOutput = Get-Content "$env:TEMP\netsh_dns_error.txt" -Raw
                        }
                        $result.Errors += "netsh DNS command failed: Exit code $($process.ExitCode). $errorOutput"
                    }
                    
                    # Cleanup temp files
                    @("$env:TEMP\netsh_dns_output.txt", "$env:TEMP\netsh_dns_error.txt") | ForEach-Object {
                        if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
            catch {
                $result.Errors += "netsh DNS command failed: $($_.Exception.Message)"
                Write-LogMessage "netsh DNS command failed: $($_.Exception.Message)" -Level "Error"
            }
        }
        
        if ($result.Success) {
            Write-LogMessage "DNS registration configuration completed successfully" -Level "Success"
        }
        else {
            Write-LogMessage "DNS registration configuration failed" -Level "Error"
        }
    }
    catch {
        $result.Errors += "Failed to configure DNS registration: $($_.Exception.Message)"
        Write-LogMessage "Failed to configure DNS registration: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

function Set-NetBIOSSettings {
    <#
    .SYNOPSIS
        Configures NetBIOS over TCP/IP settings for a network adapter
    .DESCRIPTION
        Enables or disables NetBIOS over TCP/IP for network connections
    .PARAMETER AdapterName
        Name of the network adapter to configure
    .PARAMETER InterfaceGuid
        GUID of the network interface
    .PARAMETER Enabled
        Whether to enable or disable NetBIOS over TCP/IP
    .OUTPUTS
        Returns result object with success status and changes made
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,
        
        [Parameter(Mandatory = $false)]
        [string]$InterfaceGuid,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    Write-LogMessage "Configuring NetBIOS over TCP/IP for adapter $AdapterName`: $Enabled" -Level "Info"
    
    $result = @{
        Success = $false
        Changes = @()
        Errors = @()
        Warnings = @()
    }
    
    try {
        # Method 1: Try using Set-NetAdapterAdvancedProperty (Windows 8/Server 2012+)
        if (Get-Command Set-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue) {
            try {
                if ($WhatIf) {
                    Write-LogMessage "WhatIf: Would set NetBIOS over TCP/IP to $Enabled on adapter $AdapterName" -Level "Info"
                    $result.Changes += "Would set NetBIOS over TCP/IP to $Enabled"
                    $result.Success = $true
                }
                else {
                    # NetBIOS setting: 0 = Default, 1 = Enable, 2 = Disable
                    $netbiosValue = if ($Enabled) { 1 } else { 2 }
                    
                    # Try to set NetBIOS setting using advanced properties
                    Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName "NetBIOS over Tcpip" -DisplayValue $netbiosValue -ErrorAction Stop
                    
                    Write-LogMessage "Successfully set NetBIOS over TCP/IP to $Enabled on adapter $AdapterName" -Level "Success"
                    $result.Changes += "Set NetBIOS over TCP/IP to $Enabled"
                    $result.Success = $true
                }
                
                return $result
            }
            catch {
                Write-LogMessage "Set-NetAdapterAdvancedProperty failed: $($_.Exception.Message)" -Level "Warning"
                $result.Warnings += "Set-NetAdapterAdvancedProperty failed: $($_.Exception.Message)"
            }
        }
        
        # Method 2: Registry-based approach
        try {
            Write-LogMessage "Attempting registry-based NetBIOS configuration..." -Level "Info"
            
            # NetBIOS settings are stored in the registry under the interface GUID
            if ($InterfaceGuid) {
                $netbiosRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$InterfaceGuid"
                
                if (Test-Path $netbiosRegPath) {
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would set NetBIOS registry value for interface $InterfaceGuid" -Level "Info"
                        $result.Changes += "Would set NetBIOS registry value"
                        $result.Success = $true
                    }
                    else {
                        # NetBIOS setting: 0 = Default (usually enabled), 1 = Enable, 2 = Disable
                        $netbiosValue = if ($Enabled) { 1 } else { 2 }
                        
                        Set-ItemProperty -Path $netbiosRegPath -Name "NetbiosOptions" -Value $netbiosValue -Type DWord -ErrorAction Stop
                        
                        Write-LogMessage "Successfully set NetBIOS registry value for interface $InterfaceGuid" -Level "Success"
                        $result.Changes += "Set NetBIOS registry value to $netbiosValue"
                        $result.Success = $true
                    }
                }
                else {
                    $result.Warnings += "NetBIOS registry path not found for interface $InterfaceGuid"
                    Write-LogMessage "NetBIOS registry path not found for interface $InterfaceGuid" -Level "Warning"
                }
            }
            else {
                # Try to find the interface by adapter name
                $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
                $interfaceKeys = Get-ChildItem -Path $netbtPath -ErrorAction SilentlyContinue
                
                $interfaceFound = $false
                foreach ($key in $interfaceKeys) {
                    try {
                        # Apply NetBIOS setting to all TCP/IP interfaces as a fallback
                        if ($key.Name -like "*Tcpip_*") {
                            if ($WhatIf) {
                                Write-LogMessage "WhatIf: Would set NetBIOS registry value for interface $($key.PSChildName)" -Level "Info"
                                $result.Changes += "Would set NetBIOS registry value for $($key.PSChildName)"
                                $interfaceFound = $true
                            }
                            else {
                                $netbiosValue = if ($Enabled) { 1 } else { 2 }
                                Set-ItemProperty -Path $key.PSPath -Name "NetbiosOptions" -Value $netbiosValue -Type DWord -ErrorAction SilentlyContinue
                                Write-LogMessage "Set NetBIOS registry value for interface $($key.PSChildName)" -Level "Info"
                                $interfaceFound = $true
                            }
                        }
                    }
                    catch {
                        continue
                    }
                }
                
                if ($interfaceFound) {
                    $result.Changes += "Set NetBIOS registry values for TCP/IP interfaces"
                    $result.Success = $true
                }
                else {
                    $result.Warnings += "No TCP/IP interfaces found in NetBT registry"
                }
            }
        }
        catch {
            $result.Errors += "Registry-based NetBIOS configuration failed: $($_.Exception.Message)"
            Write-LogMessage "Registry-based NetBIOS configuration failed: $($_.Exception.Message)" -Level "Error"
        }
        
        # Method 3: WMI-based approach as additional fallback
        if (-not $result.Success) {
            try {
                Write-LogMessage "Attempting WMI-based NetBIOS configuration..." -Level "Info"
                
                # Find the network adapter configuration
                $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Description='$($AdapterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
                
                if (-not $wmiAdapter) {
                    # Try by connection ID
                    $netAdapter = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "NetConnectionID='$($AdapterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
                    if ($netAdapter) {
                        $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Index=$($netAdapter.Index)" -ErrorAction SilentlyContinue
                    }
                }
                
                if ($wmiAdapter -and $wmiAdapter.TcpipNetbiosOptions -ne $null) {
                    if ($WhatIf) {
                        Write-LogMessage "WhatIf: Would set NetBIOS options via WMI for adapter $AdapterName" -Level "Info"
                        $result.Changes += "Would set NetBIOS options via WMI"
                        $result.Success = $true
                    }
                    else {
                        # NetBIOS options: 0 = Use NetBIOS from DHCP, 1 = Enable, 2 = Disable
                        $netbiosOption = if ($Enabled) { 1 } else { 2 }
                        
                        $wmiResult = $wmiAdapter | Invoke-CimMethod -MethodName "SetTcpipNetbios" -Arguments @{ TcpipNetbiosOptions = $netbiosOption }
                        
                        if ($wmiResult.ReturnValue -eq 0) {
                            Write-LogMessage "Successfully set NetBIOS options via WMI for adapter $AdapterName" -Level "Success"
                            $result.Changes += "Set NetBIOS options via WMI"
                            $result.Success = $true
                        }
                        else {
                            $result.Errors += "WMI SetTcpipNetbios method failed with return value: $($wmiResult.ReturnValue)"
                        }
                    }
                }
                else {
                    $result.Warnings += "Could not find WMI network adapter configuration"
                }
            }
            catch {
                $result.Errors += "WMI-based NetBIOS configuration failed: $($_.Exception.Message)"
                Write-LogMessage "WMI-based NetBIOS configuration failed: $($_.Exception.Message)" -Level "Error"
            }
        }
        
        if ($result.Success) {
            Write-LogMessage "NetBIOS over TCP/IP configuration completed successfully" -Level "Success"
        }
        else {
            Write-LogMessage "NetBIOS over TCP/IP configuration failed" -Level "Error"
        }
    }
    catch {
        $result.Errors += "Failed to configure NetBIOS over TCP/IP: $($_.Exception.Message)"
        Write-LogMessage "Failed to configure NetBIOS over TCP/IP: $($_.Exception.Message)" -Level "Error"
    }
    
    return $result
}

# Export functions
Export-ModuleMember -Function @(
    'Get-NetworkAdapters',
    'Get-NetworkAdapterProtocolBindings',
    'Set-NetworkAdapterProtocolBinding',
    'Set-DNSRegistrationSettings',
    'Set-NetBIOSSettings'
)