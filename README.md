# Windows Security Hardening Script

A comprehensive PowerShell-based security hardening solution for Windows systems that implements automated security configurations according to cybersecurity best practices.

## Overview

This script implements comprehensive Windows security hardening measures including:
- Password policies and account lockout settings
- User account management and authorization
- Network adapter security configurations
- Windows services management
- Security features and UAC settings
- Firewall rules and system settings
- Local security policies
- Registry modifications

## Architecture

The script has been refactored into a modular architecture for better maintainability and extensibility:

### Main Script
- `WindowsSecurityHardening.ps1` - Main entry point and orchestration

### Modules Directory
- `Prerequisites.psm1` - System prerequisites validation
- `Logging.psm1` - Centralized logging system
- `BackupSystem.psm1` - Backup and restore point management
- `NetworkAdapter.psm1` - Network adapter configuration

### Legacy Files
- `WindowsSecurityHardening-Original.ps1` - Original monolithic script (backup)

## Requirements

- Windows PowerShell 5.1 or PowerShell Core 7.x
- Administrative privileges required
- Windows 10/11 or Windows Server 2016/2019/2022
- System restore functionality enabled (recommended)

## Usage

### Basic Usage
```powershell
.\WindowsSecurityHardening.ps1
```

### Silent Mode
```powershell
.\WindowsSecurityHardening.ps1 -Silent -LogPath "C:\Logs"
```

### What-If Mode (Preview Changes)
```powershell
.\WindowsSecurityHardening.ps1 -WhatIf
```

### With Custom Configuration
```powershell
.\WindowsSecurityHardening.ps1 -ConfigFile "config.json"
```

## Parameters

- **ConfigFile**: Optional path to external configuration file (JSON format)
- **LogPath**: Path for log file output (default: current directory)
- **Silent**: Run in silent mode without user prompts
- **WhatIf**: Show what changes would be made without applying them

## Security Requirements Implemented

### Network Adapter Configuration (Requirements 5.1-5.5)
- **5.1**: Disable Client for MS Networks on network adapters
- **5.2**: Disable File and Printer Sharing for Microsoft Networks
- **5.3**: Disable IPv6 protocol
- **5.4**: Disable DNS registration for network connections
- **5.5**: Disable NetBIOS over TCP/IP

## Features

### Multi-Method Approach
Each configuration function implements multiple methods for maximum compatibility:
1. Modern PowerShell cmdlets (Windows 8/Server 2012+)
2. Registry manipulation for older systems
3. Legacy command-line tools as fallback

### Comprehensive Error Handling
- Detailed error reporting and logging
- Graceful degradation when methods fail
- Comprehensive validation of applied changes

### Backup and Recovery
- Automatic system restore point creation
- Registry key backups
- Service state backups
- Security policy backups

### Logging and Reporting
- Detailed execution logging
- Color-coded console output
- Comprehensive execution summaries
- Change tracking and validation

## Configuration

The script uses a comprehensive configuration system with default security settings. You can customize behavior by providing a JSON configuration file:

```json
{
  "NetworkSettings": {
    "DisableClientForMSNetworks": true,
    "DisableFileAndPrinterSharing": true,
    "DisableIPv6": true,
    "DisableDNSRegistration": true,
    "DisableNetBIOS": true
  },
  "BackupSettings": {
    "CreateRestorePoint": true,
    "BackupRegistry": true,
    "BackupServices": true,
    "BackupPolicies": true
  }
}
```

## Module Development

### Adding New Modules

1. Create a new `.psm1` file in the `Modules` directory
2. Implement required functions with proper error handling
3. Export functions using `Export-ModuleMember`
4. Import the module in the main script
5. Add orchestration function to main script

### Module Structure Template

```powershell
<#
.SYNOPSIS
    Module Name - Brief Description

.DESCRIPTION
    Detailed description of module functionality
#>

function Your-Function {
    <#
    .SYNOPSIS
        Function description
    .PARAMETER Parameter1
        Parameter description
    .OUTPUTS
        Return value description
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parameter1
    )
    
    # Implementation with error handling
    try {
        # Function logic
        Write-LogMessage "Operation completed" -Level "Success"
    }
    catch {
        Write-LogMessage "Operation failed: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Your-Function'
)
```

## Troubleshooting

### Common Issues

1. **Access Denied Errors**: Ensure script is run with administrative privileges
2. **Module Loading Failures**: Verify all module files are present in the Modules directory
3. **Network Configuration Failures**: Some network settings may require system restart
4. **Backup System Warnings**: System Restore may need to be enabled manually

### Debug Mode

Enable detailed logging by modifying the logging level in the script or using verbose PowerShell execution:

```powershell
.\WindowsSecurityHardening.ps1 -Verbose
```

## Security Considerations

- Always test in a non-production environment first
- Review configuration settings before execution
- Ensure system backups are available
- Document any custom configuration changes
- Monitor system behavior after hardening

## Contributing

When contributing to this project:

1. Follow the modular architecture
2. Implement comprehensive error handling
3. Add appropriate logging statements
4. Include parameter validation
5. Update documentation
6. Test on multiple Windows versions

## License

This project is provided as-is for educational and security hardening purposes. Use at your own risk and ensure compliance with your organization's policies.

## Version History

- **v1.0.0**: Initial modular implementation with network adapter configuration
  - Refactored monolithic script into modular architecture
  - Implemented comprehensive network adapter security hardening
  - Added multi-method compatibility approach
  - Enhanced logging and error handling

## Support

For issues and questions:
1. Check the log files for detailed error information
2. Review the troubleshooting section
3. Verify system requirements and prerequisites
4. Test in WhatIf mode to preview changes