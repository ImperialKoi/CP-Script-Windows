<#
.SYNOPSIS
    Backup and Restore Point Functions Module

.DESCRIPTION
    This module provides comprehensive backup functionality including
    system restore points, registry backups, service state backups,
    and security policy backups before making system changes.
#>

# Global backup information
$Script:BackupInfo = @{}

function New-SystemRestorePoint {
    <#
    .SYNOPSIS
        Creates a system restore point before making security changes
    .DESCRIPTION
        Creates a system restore point with a descriptive name and stores the restore point ID
    .OUTPUTS
        Returns the restore point sequence number if successful, $null if failed
    #>
    
    Write-LogMessage "Creating system restore point..." -Level "Info"
    
    try {
        # Check if System Restore is enabled
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($null -eq $restoreStatus) {
            Write-LogMessage "System Restore is not enabled on this system" -Level "Warning"
            Write-LogMessage "Attempting to enable System Restore..." -Level "Info"
            
            # Enable System Restore on system drive
            $systemDrive = $env:SystemDrive
            Enable-ComputerRestore -Drive $systemDrive -ErrorAction Stop
            Write-LogMessage "System Restore enabled on $systemDrive" -Level "Success"
        }
        
        # Create restore point description with timestamp
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $description = "Windows Security Hardening - Before Changes ($timestamp)"
        
        # Create the restore point
        $restorePoint = Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        
        # Get the most recent restore point (should be the one we just created)
        $latestRestorePoint = Get-ComputerRestorePoint | Sort-Object SequenceNumber -Descending | Select-Object -First 1
        
        if ($latestRestorePoint) {
            $Script:BackupInfo.RestorePointId = $latestRestorePoint.SequenceNumber
            $Script:BackupInfo.RestorePointDescription = $description
            $Script:BackupInfo.RestorePointCreated = Get-Date
            
            Write-LogMessage "System restore point created successfully" -Level "Success"
            Write-LogMessage "Restore Point ID: $($latestRestorePoint.SequenceNumber)" -Level "Info"
            Write-LogMessage "Description: $description" -Level "Info"
            
            return $latestRestorePoint.SequenceNumber
        }
        else {
            Write-LogMessage "Failed to verify restore point creation" -Level "Warning"
            return $null
        }
    }
    catch {
        Write-LogMessage "Failed to create system restore point: $($_.Exception.Message)" -Level "Error"
        Write-LogMessage "Continuing without restore point - manual backup recommended" -Level "Warning"
        return $null
    }
}

function Backup-RegistryKeys {
    <#
    .SYNOPSIS
        Backs up critical registry keys before making modifications
    .DESCRIPTION
        Exports specified registry keys to backup files for potential restoration
    .PARAMETER RegistryPaths
        Array of registry paths to backup
    .PARAMETER LogPath
        Path where backup files should be stored
    .OUTPUTS
        Returns hashtable with backup file paths and status
    #>
    
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$RegistryPaths = @(
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            "HKLM\SYSTEM\CurrentControlSet\Services\upnphost",
            "HKLM\SOFTWARE\Policies\Microsoft\Windows",
            "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
            "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ),
        
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    Write-LogMessage "Backing up critical registry keys..." -Level "Info"
    
    $backupResults = @{}
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = Join-Path $LogPath "RegistryBackups_$timestamp"
    
    try {
        # Create backup directory
        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
            Write-LogMessage "Created registry backup directory: $backupDir" -Level "Info"
        }
        
        foreach ($regPath in $RegistryPaths) {
            try {
                # Convert registry path for reg.exe command
                $regKey = $regPath -replace "HKLM\\", "HKEY_LOCAL_MACHINE\" -replace "HKCU\\", "HKEY_CURRENT_USER\"
                
                # Create safe filename from registry path
                $safeFileName = ($regPath -replace "[\\\/:*?""<>|]", "_") + ".reg"
                $backupFile = Join-Path $backupDir $safeFileName
                
                # Export registry key using reg.exe
                $regArgs = @("export", $regKey, $backupFile, "/y")
                $process = Start-Process -FilePath "reg.exe" -ArgumentList $regArgs -Wait -PassThru -WindowStyle Hidden
                
                if ($process.ExitCode -eq 0 -and (Test-Path $backupFile)) {
                    $backupResults[$regPath] = @{
                        Status = "Success"
                        BackupFile = $backupFile
                        Size = (Get-Item $backupFile).Length
                    }
                    Write-LogMessage "Backed up registry key: $regPath" -Level "Success"
                }
                else {
                    $backupResults[$regPath] = @{
                        Status = "Failed"
                        Error = "Registry export failed with exit code: $($process.ExitCode)"
                    }
                    Write-LogMessage "Failed to backup registry key: $regPath" -Level "Warning"
                }
            }
            catch {
                $backupResults[$regPath] = @{
                    Status = "Failed"
                    Error = $_.Exception.Message
                }
                Write-LogMessage "Error backing up registry key $regPath`: $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        # Store backup information
        $Script:BackupInfo.RegistryBackups = $backupResults
        $Script:BackupInfo.RegistryBackupDir = $backupDir
        
        $successCount = ($backupResults.Values | Where-Object { $_.Status -eq "Success" }).Count
        $totalCount = $backupResults.Count
        
        Write-LogMessage "Registry backup completed: $successCount/$totalCount keys backed up successfully" -Level "Info"
        
        return $backupResults
    }
    catch {
        Write-LogMessage "Critical error during registry backup: $($_.Exception.Message)" -Level "Error"
        return @{}
    }
}

function Backup-ServiceStates {
    <#
    .SYNOPSIS
        Backs up current Windows service states before making modifications
    .DESCRIPTION
        Captures current service status, startup type, and configuration for restoration
    .PARAMETER LogPath
        Path where backup files should be stored
    .OUTPUTS
        Returns hashtable with service state information
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    Write-LogMessage "Backing up Windows service states..." -Level "Info"
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = Join-Path $LogPath "ServiceStates_$timestamp.json"
        
        # Get all services and their current states
        $services = Get-Service | ForEach-Object {
            $service = $_
            $serviceConfig = $null
            
            try {
                # Get additional service configuration using WMI
                $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            }
            catch {
                Write-LogMessage "Warning: Could not get extended info for service: $($service.Name)" -Level "Debug"
            }
            
            @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status.ToString()
                StartType = if ($serviceConfig) { $serviceConfig.StartMode } else { "Unknown" }
                ServiceType = $service.ServiceType.ToString()
                CanStop = $service.CanStop
                CanPauseAndContinue = $service.CanPauseAndContinue
                DependentServices = @($service.DependentServices | ForEach-Object { $_.Name })
                ServicesDependedOn = @($service.ServicesDependedOn | ForEach-Object { $_.Name })
                PathName = if ($serviceConfig) { $serviceConfig.PathName } else { $null }
                Description = if ($serviceConfig) { $serviceConfig.Description } else { $null }
            }
        }
        
        # Convert to JSON and save to file
        $servicesJson = $services | ConvertTo-Json -Depth 3
        $servicesJson | Out-File -FilePath $backupFile -Encoding UTF8
        
        # Store backup information
        $Script:BackupInfo.ServiceStates = @{
            BackupFile = $backupFile
            ServiceCount = $services.Count
            BackupTime = Get-Date
        }
        
        Write-LogMessage "Service states backed up successfully" -Level "Success"
        Write-LogMessage "Backup file: $backupFile" -Level "Info"
        Write-LogMessage "Services backed up: $($services.Count)" -Level "Info"
        
        return $services
    }
    catch {
        Write-LogMessage "Failed to backup service states: $($_.Exception.Message)" -Level "Error"
        return @()
    }
}

function Backup-SecurityPolicies {
    <#
    .SYNOPSIS
        Backs up current local security policies using secedit
    .DESCRIPTION
        Exports current security policies to a backup file for potential restoration
    .PARAMETER LogPath
        Path where backup files should be stored
    .OUTPUTS
        Returns the path to the backup file if successful, $null if failed
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    Write-LogMessage "Backing up local security policies..." -Level "Info"
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = Join-Path $LogPath "SecurityPolicies_$timestamp.inf"
        $logFile = Join-Path $LogPath "SecurityPolicyBackup_$timestamp.log"
        
        # Use secedit to export current security policies
        $seceditArgs = @("/export", "/cfg", $backupFile, "/log", $logFile, "/quiet")
        $process = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -WindowStyle Hidden
        
        if ($process.ExitCode -eq 0 -and (Test-Path $backupFile)) {
            # Verify the backup file contains data
            $backupContent = Get-Content $backupFile -ErrorAction SilentlyContinue
            if ($backupContent -and $backupContent.Count -gt 0) {
                $Script:BackupInfo.SecurityPolicies = @{
                    BackupFile = $backupFile
                    LogFile = $logFile
                    BackupTime = Get-Date
                    FileSize = (Get-Item $backupFile).Length
                }
                
                Write-LogMessage "Security policies backed up successfully" -Level "Success"
                Write-LogMessage "Backup file: $backupFile" -Level "Info"
                Write-LogMessage "File size: $((Get-Item $backupFile).Length) bytes" -Level "Info"
                
                return $backupFile
            }
            else {
                Write-LogMessage "Security policy backup file is empty or invalid" -Level "Warning"
                return $null
            }
        }
        else {
            Write-LogMessage "secedit export failed with exit code: $($process.ExitCode)" -Level "Error"
            
            # Try to read the log file for more details
            if (Test-Path $logFile) {
                $logContent = Get-Content $logFile -ErrorAction SilentlyContinue
                if ($logContent) {
                    Write-LogMessage "secedit log output:" -Level "Debug"
                    $logContent | ForEach-Object { Write-LogMessage "  $_" -Level "Debug" }
                }
            }
            
            return $null
        }
    }
    catch {
        Write-LogMessage "Failed to backup security policies: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Initialize-BackupSystem {
    <#
    .SYNOPSIS
        Initializes the complete backup system before making security changes
    .DESCRIPTION
        Orchestrates all backup operations including restore point, registry, services, and policies
    .PARAMETER LogPath
        Path where backup files should be stored
    .OUTPUTS
        Returns boolean indicating if backup system was initialized successfully
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    Write-LogMessage "Initializing backup system..." -Level "Info"
    Write-LogMessage "This may take several minutes..." -Level "Info"
    
    try {
        # Initialize backup info structure
        $Script:BackupInfo = @{
            BackupStartTime = Get-Date
            RestorePointId = $null
            RegistryBackups = @{}
            ServiceStates = @{}
            SecurityPolicies = @{}
            BackupCompleted = $false
        }
        
        $backupSuccess = $true
        
        # Step 1: Create system restore point
        Write-LogMessage "Step 1/4: Creating system restore point..." -Level "Info"
        $restorePointId = New-SystemRestorePoint
        if ($restorePointId) {
            Write-LogMessage "System restore point created: ID $restorePointId" -Level "Success"
        }
        else {
            Write-LogMessage "System restore point creation failed" -Level "Warning"
            $backupSuccess = $false
        }
        
        # Step 2: Backup registry keys
        Write-LogMessage "Step 2/4: Backing up critical registry keys..." -Level "Info"
        $registryBackup = Backup-RegistryKeys -LogPath $LogPath
        if ($registryBackup -and $registryBackup.Count -gt 0) {
            $successCount = ($registryBackup.Values | Where-Object { $_.Status -eq "Success" }).Count
            Write-LogMessage "Registry backup completed: $successCount keys backed up" -Level "Success"
        }
        else {
            Write-LogMessage "Registry backup failed" -Level "Warning"
            $backupSuccess = $false
        }
        
        # Step 3: Backup service states
        Write-LogMessage "Step 3/4: Backing up Windows service states..." -Level "Info"
        $serviceBackup = Backup-ServiceStates -LogPath $LogPath
        if ($serviceBackup -and $serviceBackup.Count -gt 0) {
            Write-LogMessage "Service states backup completed: $($serviceBackup.Count) services" -Level "Success"
        }
        else {
            Write-LogMessage "Service states backup failed" -Level "Warning"
            $backupSuccess = $false
        }
        
        # Step 4: Backup security policies
        Write-LogMessage "Step 4/4: Backing up local security policies..." -Level "Info"
        $policyBackup = Backup-SecurityPolicies -LogPath $LogPath
        if ($policyBackup) {
            Write-LogMessage "Security policies backup completed" -Level "Success"
        }
        else {
            Write-LogMessage "Security policies backup failed" -Level "Warning"
            $backupSuccess = $false
        }
        
        # Finalize backup information
        $Script:BackupInfo.BackupEndTime = Get-Date
        $Script:BackupInfo.BackupDuration = $Script:BackupInfo.BackupEndTime - $Script:BackupInfo.BackupStartTime
        $Script:BackupInfo.BackupCompleted = $true
        
        # Generate backup summary
        Write-LogMessage "`n" + "="*60 -Level "Info"
        Write-LogMessage "BACKUP SUMMARY" -Level "Info"
        Write-LogMessage "="*60 -Level "Info"
        Write-LogMessage "Backup Duration: $($Script:BackupInfo.BackupDuration.ToString('mm\:ss'))" -Level "Info"
        
        if ($Script:BackupInfo.RestorePointId) {
            Write-LogMessage "System Restore Point: ID $($Script:BackupInfo.RestorePointId)" -Level "Success"
        }
        
        if ($Script:BackupInfo.RegistryBackups -and $Script:BackupInfo.RegistryBackups.Count -gt 0) {
            $regSuccessCount = ($Script:BackupInfo.RegistryBackups.Values | Where-Object { $_.Status -eq "Success" }).Count
            Write-LogMessage "Registry Keys Backed Up: $regSuccessCount/$($Script:BackupInfo.RegistryBackups.Count)" -Level "Info"
        }
        
        if ($Script:BackupInfo.ServiceStates -and $Script:BackupInfo.ServiceStates.ServiceCount) {
            Write-LogMessage "Services Backed Up: $($Script:BackupInfo.ServiceStates.ServiceCount)" -Level "Info"
        }
        
        if ($Script:BackupInfo.SecurityPolicies -and $Script:BackupInfo.SecurityPolicies.BackupFile) {
            Write-LogMessage "Security Policies: Backed up successfully" -Level "Success"
        }
        
        Write-LogMessage "="*60 -Level "Info"
        
        if ($backupSuccess) {
            Write-LogMessage "Backup system initialized successfully" -Level "Success"
            Write-LogMessage "System is ready for security hardening modifications" -Level "Info"
        }
        else {
            Write-LogMessage "Backup system initialized with warnings" -Level "Warning"
            Write-LogMessage "Some backup operations failed - proceed with caution" -Level "Warning"
        }
        
        return $backupSuccess
    }
    catch {
        Write-LogMessage "Critical error initializing backup system: $($_.Exception.Message)" -Level "Error"
        $Script:BackupInfo.BackupCompleted = $false
        return $false
    }
}

function Get-BackupInformation {
    <#
    .SYNOPSIS
        Returns current backup information for reporting and verification
    .OUTPUTS
        Returns the backup information hashtable
    #>
    
    return $Script:BackupInfo
}

# Export functions
Export-ModuleMember -Function @(
    'New-SystemRestorePoint',
    'Backup-RegistryKeys',
    'Backup-ServiceStates',
    'Backup-SecurityPolicies',
    'Initialize-BackupSystem',
    'Get-BackupInformation'
)