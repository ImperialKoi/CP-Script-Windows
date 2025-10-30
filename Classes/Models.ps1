using namespace System.Collections.Generic

<#
.SYNOPSIS
    Data models for the Windows Security Hardening system
.DESCRIPTION
    Contains all the data model classes used throughout the system
#>

# Base result class
class BaseResult {
    [bool] $Success
    [string] $ModuleName
    [List[string]] $Changes
    [List[string]] $Errors
    [List[string]] $Warnings
    [datetime] $ExecutionTime
    
    BaseResult([string] $moduleName) {
        $this.ModuleName = $moduleName
        $this.Changes = [List[string]]::new()
        $this.Errors = [List[string]]::new()
        $this.Warnings = [List[string]]::new()
        $this.ExecutionTime = Get-Date
        $this.Success = $false
    }
    
    [void] AddChange([string] $change) {
        $this.Changes.Add($change)
    }
    
    [void] AddError([string] $error) {
        $this.Errors.Add($error)
        $this.Success = $false
    }
    
    [void] AddWarning([string] $warning) {
        $this.Warnings.Add($warning)
    }
    
    [void] SetSuccess([bool] $success) {
        $this.Success = $success
    }
}

# Service execution result
class ServiceResult : BaseResult {
    [List[string]] $ValidationResults
    [hashtable] $BackupResults
    [string] $ServiceType
    
    ServiceResult([string] $moduleName) : base($moduleName) {
        $this.ValidationResults = [List[string]]::new()
        $this.BackupResults = @{}
        $this.ServiceType = $moduleName
    }
    
    [void] AddValidationResult([string] $result) {
        $this.ValidationResults.Add($result)
    }
    
    [void] SetBackupResults([hashtable] $backupResults) {
        $this.BackupResults = $backupResults
    }
    
    # Static factory methods
    static [ServiceResult] CreateSkipped([string] $moduleName) {
        $result = [ServiceResult]::new($moduleName)
        $result.AddWarning("Module skipped by user")
        $result.SetSuccess($true)
        return $result
    }
    
    static [ServiceResult] CreateFailed([string] $moduleName, [string] $error) {
        $result = [ServiceResult]::new($moduleName)
        $result.AddError($error)
        return $result
    }
}

# Overall execution result
class ExecutionResult {
    [string] $ExecutionMode
    [datetime] $StartTime
    [datetime] $EndTime
    [timespan] $Duration
    [List[ServiceResult]] $ServiceResults
    [bool] $OverallSuccess
    [int] $TotalChanges
    [int] $TotalErrors
    [int] $TotalWarnings
    
    ExecutionResult() {
        $this.ServiceResults = [List[ServiceResult]]::new()
        $this.OverallSuccess = $false
        $this.TotalChanges = 0
        $this.TotalErrors = 0
        $this.TotalWarnings = 0
    }
    
    [void] AddServiceResult([ServiceResult] $result) {
        $this.ServiceResults.Add($result)
        $this.TotalChanges += $result.Changes.Count
        $this.TotalErrors += $result.Errors.Count
        $this.TotalWarnings += $result.Warnings.Count
        
        # Update overall success
        $this.UpdateOverallSuccess()
    }
    
    [void] UpdateOverallSuccess() {
        $criticalFailures = $this.ServiceResults | Where-Object { -not $_.Success -and $_.Errors.Count -gt 0 }
        $this.OverallSuccess = ($criticalFailures.Count -eq 0)
    }
    
    [hashtable] GetSummary() {
        $successful = ($this.ServiceResults | Where-Object { $_.Success }).Count
        $failed = ($this.ServiceResults | Where-Object { -not $_.Success }).Count
        
        return @{
            TotalServices = $this.ServiceResults.Count
            Successful = $successful
            Failed = $failed
            TotalChanges = $this.TotalChanges
            TotalErrors = $this.TotalErrors
            TotalWarnings = $this.TotalWarnings
            Duration = $this.Duration
            OverallSuccess = $this.OverallSuccess
            ExecutionMode = $this.ExecutionMode
        }
    }
}

# Configuration model
class SecurityConfiguration {
    [hashtable] $PasswordPolicy
    [hashtable] $LockoutPolicy
    [hashtable] $UserSettings
    [hashtable] $SecurityFeatures
    [hashtable] $NetworkSettings
    [hashtable] $ServicesConfig
    [hashtable] $FeaturesConfig
    [hashtable] $FirewallRules
    [hashtable] $SystemSettings
    [hashtable] $SecurityPolicy
    [hashtable] $RegistrySettings
    [hashtable] $ExecutionSettings
    [hashtable] $BackupSettings
    
    SecurityConfiguration() {
        $this.InitializeDefaults()
    }
    
    [void] InitializeDefaults() {
        # Initialize with default values
        $this.PasswordPolicy = @{
            HistoryCount = 24
            MaxAge = 60
            MinAge = 1
            MinLength = 10
            ComplexityEnabled = $true
        }
        
        $this.LockoutPolicy = @{
            Duration = 30
            Threshold = 10
            ResetCounter = 30
        }
        
        $this.UserSettings = @{
            ForcePasswordChange = $true
            DisableUnauthorized = $true
            AuthorizedAdmins = @()
            AuthorizedRDPUsers = @()
            RestrictAdminGroup = $true
            RestrictGuestGroup = $true
        }
        
        $this.SecurityFeatures = @{
            EnableSmartScreen = $true
            DisableWiFiSense = $true
            MaximizeUAC = $true
            EnableDefender = $true
        }
        
        $this.NetworkSettings = @{
            DisableClientForMSNetworks = $true
            DisableFileAndPrinterSharing = $true
            DisableIPv6 = $true
            DisableDNSRegistration = $true
            DisableNetBIOS = $true
        }
        
        $this.ServicesConfig = @{
            DisableUPnP = $true
            DisableTelnet = $true
            DisableSNMPTrap = $true
            DisableRemoteRegistry = $true
            EnableEventCollector = $true
        }
        
        $this.FeaturesConfig = @{
            DisableTelnetClient = $true
            DisableTelnetServer = $true
            DisableSNMP = $true
            DisableSMBv1 = $true
            DisableIIS = $true
            DisableTFTP = $true
        }
        
        $this.FirewallRules = @{
            BlockMicrosoftEdge = $true
            BlockWindowsSearch = $true
            BlockMSNApps = $true
            BlockXboxApps = $true
            BlockMicrosoftPhotos = $true
        }
        
        $this.SystemSettings = @{
            DisableAutoPlay = $true
            ScreenSaverTimeout = 10
            RequireLogonOnResume = $true
            DisableOneDriveStartup = $true
            EnableAuditing = $true
        }
        
        $this.SecurityPolicy = @{
            DisableAdministratorAccount = $true
            DisableGuestAccount = $true
            BlockMicrosoftAccounts = $true
            EnableDigitalSigning = $true
            ConfigureInteractiveLogon = $true
            MaximizeNetworkSecurity = $true
        }
        
        $this.RegistrySettings = @{
            DisableUPnPPort1900 = $true
            SetUPnPMode = 2
            VerifyChanges = $true
        }
        
        $this.ExecutionSettings = @{
            ShowProgress = $true
            ReportChanges = $true
            LogErrors = $true
            ProvideSummary = $true
            DetailedErrorMessages = $true
        }
        
        $this.BackupSettings = @{
            CreateRestorePoint = $true
            BackupRegistry = $true
            BackupServices = $true
            BackupPolicies = $true
        }
    }
    
    [hashtable] ToHashtable() {
        return @{
            PasswordPolicy = $this.PasswordPolicy
            LockoutPolicy = $this.LockoutPolicy
            UserSettings = $this.UserSettings
            SecurityFeatures = $this.SecurityFeatures
            NetworkSettings = $this.NetworkSettings
            ServicesConfig = $this.ServicesConfig
            FeaturesConfig = $this.FeaturesConfig
            FirewallRules = $this.FirewallRules
            SystemSettings = $this.SystemSettings
            SecurityPolicy = $this.SecurityPolicy
            RegistrySettings = $this.RegistrySettings
            ExecutionSettings = $this.ExecutionSettings
            BackupSettings = $this.BackupSettings
        }
    }
    
    [void] LoadFromHashtable([hashtable] $config) {
        if ($config.ContainsKey("PasswordPolicy")) { $this.PasswordPolicy = $config.PasswordPolicy }
        if ($config.ContainsKey("LockoutPolicy")) { $this.LockoutPolicy = $config.LockoutPolicy }
        if ($config.ContainsKey("UserSettings")) { $this.UserSettings = $config.UserSettings }
        if ($config.ContainsKey("SecurityFeatures")) { $this.SecurityFeatures = $config.SecurityFeatures }
        if ($config.ContainsKey("NetworkSettings")) { $this.NetworkSettings = $config.NetworkSettings }
        if ($config.ContainsKey("ServicesConfig")) { $this.ServicesConfig = $config.ServicesConfig }
        if ($config.ContainsKey("FeaturesConfig")) { $this.FeaturesConfig = $config.FeaturesConfig }
        if ($config.ContainsKey("FirewallRules")) { $this.FirewallRules = $config.FirewallRules }
        if ($config.ContainsKey("SystemSettings")) { $this.SystemSettings = $config.SystemSettings }
        if ($config.ContainsKey("SecurityPolicy")) { $this.SecurityPolicy = $config.SecurityPolicy }
        if ($config.ContainsKey("RegistrySettings")) { $this.RegistrySettings = $config.RegistrySettings }
        if ($config.ContainsKey("ExecutionSettings")) { $this.ExecutionSettings = $config.ExecutionSettings }
        if ($config.ContainsKey("BackupSettings")) { $this.BackupSettings = $config.BackupSettings }
    }
}