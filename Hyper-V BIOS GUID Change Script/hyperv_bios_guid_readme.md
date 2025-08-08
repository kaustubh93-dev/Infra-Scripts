# Hyper-V BIOS GUID Change Script

A PowerShell script to modify the BIOS GUID of Hyper-V virtual machines. This script is useful for resolving GUID conflicts when cloning VMs or preparing machines for deployment.

## Overview

The BIOS GUID is a unique identifier embedded in the virtual machine's BIOS. When you clone or copy a VM, it retains the same GUID, which can cause conflicts in domain environments or with software licensing. This script safely changes the BIOS GUID while preserving the VM's configuration and state.

## Features

- ✅ Safely changes BIOS GUID for Hyper-V VMs
- ✅ Automatic GUID generation or custom GUID assignment
- ✅ Handles VM power state management (shutdown/restart)
- ✅ Progress reporting during operations
- ✅ Comprehensive error handling with detailed messages
- ✅ Support for remote Hyper-V hosts
- ✅ Confirmation prompts with override option
- ✅ Input validation for VM names and GUIDs

## Prerequisites

- Windows Server 2012 R2 / Windows 8.1 or later
- Hyper-V role installed and configured
- PowerShell 3.0 or later
- Administrative privileges on the Hyper-V host
- WMI access to the target Hyper-V server

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `VM` | String/VirtualMachine | ✅ | - | VM name or VM object to modify |
| `NewID` | GUID | ❌ | Auto-generated | Specific GUID to assign to the VM |
| `ComputerName` | String | ❌ | Local computer | Target Hyper-V host name |
| `Timeout` | UInt32 | ❌ | 300 | Timeout in seconds for VM shutdown |
| `Force` | Switch | ❌ | False | Skip confirmation prompts |

## Checking Current BIOS GUID

Before modifying any VM's BIOS GUID, it's important to check the current values and identify any duplicate GUIDs that might exist.

### Check All VMs' BIOS GUIDs

Use this WMI-based command to display all VMs and their current BIOS GUIDs:

```powershell
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"} |
    Select-Object ElementName, BIOSGUID | 
    Sort-Object ElementName | 
    Format-Table -AutoSize
```

**Sample Output:**
```
ElementName          BIOSGUID
-----------          --------
DC01                 {12345678-ABCD-1234-5678-123456789ABC}
WebServer01          {87654321-4321-4321-4321-210987654321}
WebServer01-Clone    {87654321-4321-4321-4321-210987654321}  # ⚠️ Duplicate!
DatabaseServer       {11111111-2222-3333-4444-555555555555}
```

### Identify Duplicate BIOS GUIDs

To specifically find VMs with identical BIOS GUIDs (common after cloning):

```powershell
# Find and display duplicate BIOS GUIDs
$AllVMs = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"} |
    Select-Object ElementName, BIOSGUID

$DuplicateGUIDs = $AllVMs | Group-Object BIOSGUID | Where-Object Count -gt 1

if ($DuplicateGUIDs) {
    Write-Host "⚠️  DUPLICATE BIOS GUIDs FOUND:" -ForegroundColor Red
    $DuplicateGUIDs | ForEach-Object {
        Write-Host "`nGUID: $($_.Name)" -ForegroundColor Yellow
        $_.Group | ForEach-Object {
            Write-Host "  - $($_.ElementName)" -ForegroundColor White
        }
    }
} else {
    Write-Host "✅ No duplicate BIOS GUIDs found." -ForegroundColor Green
}
```

### Check Specific VM's BIOS GUID

To check a single VM's current BIOS GUID:

```powershell
# Replace "YourVMName" with actual VM name
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.ElementName -eq "YourVMName" -and $_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"} |
    Select-Object ElementName, BIOSGUID
```

### Alternative Methods

If the WMI method doesn't work, try these alternatives:

```powershell
# Method 1: Using Hyper-V PowerShell module (may not work in all versions)
Get-VM | Select-Object Name, @{N='BIOSGUID';E={(Get-VMBios $_).SerialNumber}} | Format-Table -AutoSize

# Method 2: Check VM properties with error handling
Get-VM | ForEach-Object {
    try {
        $bios = Get-VMBios $_.Name -ErrorAction Stop
        [PSCustomObject]@{
            VMName = $_.Name
            Generation = $_.Generation
            BIOSGUID = if ($bios.SerialNumber) { $bios.SerialNumber } else { "Not Available" }
        }
    }
    catch {
        [PSCustomObject]@{
            VMName = $_.Name
            Generation = $_.Generation
            BIOSGUID = "Error retrieving GUID"
        }
    }
} | Format-Table -AutoSize
```

### Pre-Script Validation Workflow

Before running the BIOS GUID change script, follow this workflow:

```powershell
# Step 1: Check all current GUIDs
Write-Host "=== Current BIOS GUIDs ===" -ForegroundColor Cyan
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"} |
    Select-Object ElementName, BIOSGUID | 
    Sort-Object ElementName | 
    Format-Table -AutoSize

# Step 2: Identify duplicates
Write-Host "`n=== Checking for Duplicates ===" -ForegroundColor Cyan
$AllVMs = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"}

$Duplicates = $AllVMs | Group-Object BIOSGUID | Where-Object Count -gt 1
if ($Duplicates) {
    Write-Host "Found $($Duplicates.Count) duplicate GUID(s):" -ForegroundColor Red
    $Duplicates | ForEach-Object {
        Write-Host "GUID $($_.Name) is used by:" -ForegroundColor Yellow
        $_.Group.ElementName | ForEach-Object { Write-Host "  - $_" }
    }
} else {
    Write-Host "No duplicate GUIDs found." -ForegroundColor Green
}

# Step 3: Save current state for comparison
$CurrentGUIDs = $AllVMs | Select-Object ElementName, BIOSGUID
Write-Host "`n✅ Current state saved. Ready to proceed with GUID changes." -ForegroundColor Green
```

## Usage Examples

### Basic Usage

Change BIOS GUID with auto-generated ID:
```powershell
.\Set-VMBiosGuid.ps1 -VM "MyVM"
```

### Specify Custom GUID

Assign a specific GUID:
```powershell
.\Set-VMBiosGuid.ps1 -VM "MyVM" -NewID "12345678-1234-1234-1234-123456789abc"
```

### Remote Hyper-V Host

Target a remote Hyper-V server:
```powershell
.\Set-VMBiosGuid.ps1 -VM "MyVM" -ComputerName "HV-SERVER-01"
```

### Force Operation (No Prompts)

Skip all confirmation prompts:
```powershell
.\Set-VMBiosGuid.ps1 -VM "MyVM" -Force
```

### Pipeline Usage

Process multiple VMs from pipeline:
```powershell
Get-VM | Where-Object {$_.Name -like "Clone*"} | .\Set-VMBiosGuid.ps1 -Force
```

### Advanced Example

Complete example with all parameters:
```powershell
.\Set-VMBiosGuid.ps1 -VM "ProductionVM" -NewID "87654321-4321-4321-4321-210987654321" -ComputerName "HV-CLUSTER-01" -Timeout 600 -Force -Verbose
```

## Script Behavior

### VM State Management

1. **Running VM**: Script will prompt to shut down the VM (or shut down automatically with `-Force`)
2. **Stopped VM**: Script proceeds immediately with GUID change
3. **Other States**: Script will throw an error for VMs in unsupported states

### Safety Features

- **Automatic Backup**: Original GUID is logged for reference
- **State Restoration**: VM is returned to its original power state after modification
- **Validation**: Input parameters are validated before processing
- **Confirmation**: User confirmation required for destructive operations (unless `-Force` is used)

## Output Examples

### Successful Execution
```
VERBOSE: Validating input...
VERBOSE: Establishing WMI connection to Virtual Machine Management Service on HV-SERVER...
VERBOSE: Acquiring an empty parameter object for the ModifySystemSettings function...
VERBOSE: Establishing WMI connection to virtual machine MyVM
VERBOSE: Verifying that MyVM is off...
VERBOSE: Retrieving all current settings for virtual machine MyVM
VERBOSE: Extracting the settings data object from the settings data collection object...
VERBOSE: Generating new GUID...
VERBOSE: Original BIOS GUID: {A1B2C3D4-E5F6-1234-5678-9ABCDEF01234}
VERBOSE: Changing BIOSGUID in data object...
VERBOSE: New BIOS GUID: {12345678-ABCD-EFGH-IJKL-MNOPQRSTUVWX}
VERBOSE: Assigning modified data object as parameter for ModifySystemSettings function...
VERBOSE: Instructing Virtual Machine Management Service to modify settings for virtual machine MyVM
```

### Error Examples
```
Error: Virtual machine TestVM not found on computer HV-SERVER-01
Error: Virtual machine must be turned off to replace the BIOS GUID
Error: Provided GUID cannot be parsed. Supply a valid GUID or leave empty for auto-generation
```

## Common Use Cases

### 1. VM Cloning Preparation
```powershell
# After cloning a VM, change its GUID to avoid conflicts
.\Set-VMBiosGuid.ps1 -VM "WebServer-Clone" -Force
```

### 2. Fix Duplicate BIOS GUIDs
```powershell
# First, identify VMs with duplicate GUIDs
$Duplicates = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"} |
    Group-Object BIOSGUID | Where-Object Count -gt 1

# Fix duplicates (keeping the first VM, changing others)
$Duplicates | ForEach-Object {
    $VMsToFix = $_.Group | Select-Object -Skip 1  # Skip first VM, fix the rest
    $VMsToFix | ForEach-Object {
        Write-Host "Fixing duplicate GUID for VM: $($_.ElementName)" -ForegroundColor Yellow
        .\Set-VMBiosGuid.ps1 -VM $_.ElementName -Force
    }
}
```

### 3. Bulk VM Processing
```powershell
# Process all VMs with "Template" in their name
Get-VM | Where-Object Name -like "*Template*" | ForEach-Object {
    .\Set-VMBiosGuid.ps1 -VM $_.Name -Force -Verbose
}
```

### 4. Migration Scenarios
```powershell
# Prepare VMs for migration to avoid GUID conflicts
$VMs = @("VM1", "VM2", "VM3")
foreach ($VM in $VMs) {
    .\Set-VMBiosGuid.ps1 -VM $VM -ComputerName "Source-Host" -Force
}
```

### 5. Complete Workflow with Validation
```powershell
# Complete workflow: Check -> Fix -> Verify
Write-Host "=== Step 1: Check Current State ===" -ForegroundColor Cyan
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"} |
    Select-Object ElementName, BIOSGUID | Sort-Object ElementName | Format-Table

Write-Host "=== Step 2: Fix VM GUID ===" -ForegroundColor Cyan
.\Set-VMBiosGuid.ps1 -VM "MyClonedVM" -Force

Write-Host "=== Step 3: Verify Changes ===" -ForegroundColor Cyan
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.ElementName -eq "MyClonedVM"} | 
    Select-Object ElementName, BIOSGUID
```

## Troubleshooting

### Common Issues

**Issue**: "Virtual machine not found"
**Solution**: Verify VM name spelling and ensure you have access to the Hyper-V host

**Issue**: "Access denied" errors  
**Solution**: Run PowerShell as Administrator and ensure you have Hyper-V management permissions

**Issue**: "Timeout waiting for virtual machine to shut down"
**Solution**: Increase timeout value or manually shut down the VM first

**Issue**: VM won't shut down gracefully
**Solution**: Ensure Integration Services are installed and running in the guest OS

### Diagnostic Commands

Check current BIOS GUIDs:
```powershell
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"} |
    Select-Object ElementName, BIOSGUID | Sort-Object ElementName
```

Check for duplicate GUIDs:
```powershell
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized"} |
    Group-Object BIOSGUID | Where-Object Count -gt 1 | 
    ForEach-Object { 
        Write-Host "Duplicate GUID: $($_.Name)"; 
        $_.Group.ElementName 
    }
```

Check VM status:
```powershell
Get-VM -Name "MyVM" | Select-Object Name, State, IntegrationServicesState
```

Verify GUID change:
```powershell
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemSettingData | 
    Where-Object {$_.ElementName -eq "MyVM"} | Select-Object ElementName, BIOSGUID
```

Test WMI connectivity:
```powershell
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService -ComputerName "HV-SERVER"
```

## Security Considerations

- Script requires administrative privileges
- WMI access needed to target Hyper-V hosts
- Consider network security when targeting remote hosts
- GUID changes are permanent and cannot be easily undone
- Always test in non-production environments first

## Best Practices

1. **Always backup** your VMs before running the script
2. **Test thoroughly** in a lab environment before production use
3. **Document GUID changes** for audit trails
4. **Use meaningful naming** for cloned VMs to avoid confusion
5. **Verify integration services** are working before running the script
6. **Monitor VM performance** after GUID changes in production

## Version History

- **v1.0**: Initial release with basic GUID change functionality
- **v1.1**: Added remote host support and improved error handling
- **v1.2**: Enhanced pipeline support and progress reporting

## License

This script is provided as-is under the MIT License. Use at your own risk.

## Contributing

Contributions, issues, and feature requests are welcome. Please test thoroughly before submitting changes.

---

**⚠️ Warning**: Changing BIOS GUIDs can affect software licensing and domain relationships. Always test in a non-production environment first.