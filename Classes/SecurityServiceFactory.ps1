using namespace System.Collections.Generic

<#
.SYNOPSIS
    Factory class for creating security service instances
.DESCRIPTION
    This factory creates and configures all security service instances
    based on the provided configuration
#>
class SecurityServiceFactory {
    [hashtable] $Configuration

    # Constructor
    SecurityServiceFactory([hashtable] $config) {
        $this.Configuration = $config
    }

    # Create all security services in execution order
    [List[object]] CreateAllServices() {
        $services = [List[object]]::new()
        
        # Add services in the correct execution order
        $services.Add([PasswordPolicyService]::new($this.Configuration))
        $services.Add([UserAccountService]::new($this.Configuration))
        $services.Add([WindowsSecurityFeaturesService]::new($this.Configuration))
        $services.Add([NetworkAdapterService]::new($this.Configuration))
        $services.Add([WindowsServicesService]::new($this.Configuration))
        $services.Add([WindowsFeaturesService]::new($this.Configuration))
        $services.Add([FirewallService]::new($this.Configuration))
        $services.Add([SystemSettingsService]::new($this.Configuration))
        $services.Add([SecurityPolicyService]::new($this.Configuration))
        $services.Add([RegistryService]::new($this.Configuration))
        
        return $services
    }

    # Create specific service by name
    [object] CreateService([string] $serviceName) {
        switch ($serviceName) {
            "PasswordPolicy" { return [PasswordPolicyService]::new($this.Configuration) }
            "UserAccount" { return [UserAccountService]::new($this.Configuration) }
            "WindowsSecurityFeatures" { return [WindowsSecurityFeaturesService]::new($this.Configuration) }
            "NetworkAdapter" { return [NetworkAdapterService]::new($this.Configuration) }
            "WindowsServices" { return [WindowsServicesService]::new($this.Configuration) }
            "WindowsFeatures" { return [WindowsFeaturesService]::new($this.Configuration) }
            "Firewall" { return [FirewallService]::new($this.Configuration) }
            "SystemSettings" { return [SystemSettingsService]::new($this.Configuration) }
            "SecurityPolicy" { return [SecurityPolicyService]::new($this.Configuration) }
            "Registry" { return [RegistryService]::new($this.Configuration) }
            default { throw "Unknown service: $serviceName" }
        }
    }

    # Get service execution order
    [string[]] GetServiceExecutionOrder() {
        return @(
            "PasswordPolicy",
            "UserAccount", 
            "WindowsSecurityFeatures",
            "NetworkAdapter",
            "WindowsServices",
            "WindowsFeatures",
            "Firewall",
            "SystemSettings",
            "SecurityPolicy",
            "Registry"
        )
    }
}