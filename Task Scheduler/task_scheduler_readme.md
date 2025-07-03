# Task Scheduler Permission Manager

A comprehensive PowerShell script that safely modifies Windows Task Scheduler permissions to grant full control access to specified users for multiple scheduled tasks.

## 🚀 Features

- **Administrator Validation**: Ensures the script runs with proper administrative privileges
- **Execution Policy Management**: Automatically handles PowerShell execution policy requirements
- **Backup System**: Creates timestamped backups of current task permissions before making changes
- **Dynamic User SID Resolution**: Prompts for username and dynamically retrieves the Security Identifier (SID)
- **Task Verification**: Validates that all tasks exist before attempting modifications
- **Comprehensive Error Handling**: Gracefully handles missing tasks and permission errors
- **Interactive Confirmation**: Shows what will be modified and requires user confirmation
- **Detailed Logging**: Provides clear feedback on success/failure for each operation

## 📋 Prerequisites

- **Windows Operating System** with Task Scheduler
- **PowerShell 5.1 or later**
- **Administrator privileges** (script will verify and exit if not present)
- **Valid user account** that exists on the system

## 🛠️ Installation

1. Download the `TaskPermissionManager.ps1` script
2. Place it in a directory of your choice
3. No additional installation required

## 🎯 Usage

### Basic Usage

1. **Right-click on PowerShell** and select "Run as Administrator"
2. **Navigate to the script directory**:
   ```powershell
   cd "C:\path\to\script"
   ```
3. **Execute the script**:
   ```powershell
   .\TaskPermissionManager.ps1
   ```
4. **Follow the interactive prompts**:
   - The script will validate administrator privileges
   - Enter the username when prompted
   - Review the list of tasks to be modified
   - Confirm the operation

### Example Execution Flow

```
=== Task Scheduler Permission Management Script ===

1. Checking Administrator privileges...
   ✓ Running as Administrator

2. Checking PowerShell Execution Policy...
   Current Execution Policy: RemoteSigned
   ✓ Execution Policy is acceptable

3. Backing up current task permissions...
   ✓ Backup completed: TaskPermissions_Backup_20250703_143022.txt

4. Getting User SID...
Enter the username for which to grant permissions: op_bto
   ✓ User SID for 'op_bto': S-1-5-21-3062014063-3611129464-3914457905-1402

5. Listing all available scheduled tasks...
   Available tasks:
     - Acc_Opening_Auto_NRITracker (Ready)
     - DCMSHOTLISTCARD (Ready)
     ...

6. Preparing to modify task permissions...
About to modify permissions for 17 tasks:
  - Acc_Opening_Auto_NRITracker
  - DCMSHOTLISTCARD
  ...

User: op_bto (SID: S-1-5-21-3062014063-3611129464-3914457905-1402)
Permission: Full Access

Do you want to proceed? (y/N): y

7. Modifying task permissions...
Processing task: Acc_Opening_Auto_NRITracker
  Old Security SDDL: D:ARAI(A;;FA;;;S-1-5-32-544)
  New Security SDDL: D:ARAI(A;;FA;;;S-1-5-21-3062014063-3611129464-3914457905-1402)
...

=== Operation Summary ===
Successfully modified: 15 tasks
Failed to modify: 2 tasks
Backup location: TaskPermissions_Backup_20250703_143022.txt
```

## 📝 Target Tasks

The script is configured to modify permissions for the following scheduled tasks:

- `Acc_Opening_Auto_NRITracker`
- `DCMSHOTLISTCARD`
- `EMAILTRIGGER`
- `ICoreSmsEmail`
- `ICoreSummary`
- `Optimize Start Menu Cache Files-S-1-5-21-2401899096-1803463866-3717766691-1006`
- `Optimize Start Menu Cache Files-S-1-5-21-2401899096-1803463866-3717766691-1012`
- `Prime Destroy Summary`
- `Prime_CCBlock`
- `ServiceMonitor`
- `SMS alert`
- `SMS And Email Summary`
- `SpeedPost`
- `Stage_WiseEmail`
- `Test01`
- `Vendor Production Interface`
- `WEBAPI Summary`

## 🔧 How It Works

### Security Descriptor (SDDL) Modification

The script modifies the Security Descriptor Definition Language (SDDL) string for each task:

- **Before**: Various existing permissions
- **After**: `D:ARAI(A;;FA;;;[USER-SID])` where:
  - `D:` = Discretionary ACL
  - `ARAI` = ACL flags (Auto-inherit, etc.)
  - `A;;FA;;;[USER-SID]` = Allow Full Access for specified user SID

### Permission Levels

The script grants **Full Access (FA)** which includes:
- Execute the task
- Read task properties
- Write/modify task properties
- Delete the task
- Change task permissions

## 🔒 Security Considerations

- **Administrative Privileges**: Required to modify system task permissions
- **User Validation**: Verifies the target user exists before proceeding
- **Backup Creation**: Always creates a backup before making changes
- **Confirmation Required**: User must explicitly confirm the operation
- **Limited Scope**: Only modifies permissions for predefined tasks

## 📂 Output Files

### Backup File
- **Format**: `TaskPermissions_Backup_YYYYMMDD_HHMMSS.txt`
- **Location**: Same directory as the script
- **Content**: Original SDDL strings for all tasks

### Example Backup Content
```
# Task Permissions Backup - 07/03/2025 14:30:22
# Generated before modifying permissions

Task: Acc_Opening_Auto_NRITracker
SDDL: D:ARAI(A;;FA;;;S-1-5-32-544)
---
Task: DCMSHOTLISTCARD
SDDL: D:ARAI(A;;FA;;;S-1-5-32-544)
---
```

## ⚠️ Troubleshooting

### Common Issues

1. **"This script must be run as Administrator!"**
   - **Solution**: Right-click PowerShell and select "Run as Administrator"

2. **"Execution Policy is Restricted"**
   - **Solution**: The script automatically handles this by temporarily changing to RemoteSigned

3. **"User 'username' not found on this system"**
   - **Solution**: Verify the username is spelled correctly and exists on the system

4. **"Task 'taskname' does not exist"**
   - **Solution**: The script will skip missing tasks and continue with others

### Error Handling

The script includes comprehensive error handling:
- Missing tasks are skipped with warnings
- Permission errors are logged but don't stop execution
- Backup failures can be overridden with user confirmation
- Invalid users are caught before any modifications

## 🔄 Rollback Instructions

If you need to restore original permissions:

1. **Locate the backup file** created during execution
2. **Create a custom rollback script** using the SDDL strings from the backup
3. **Use the same COM object approach** to restore original permissions

### Example Rollback Code
```powershell
$service = New-Object -ComObject "Schedule.Service"
$service.Connect()
$root = $service.GetFolder("\")
$task = $root.GetTask("TaskName")
$task.SetSecurityDescriptor("ORIGINAL_SDDL_FROM_BACKUP", 0)
```

## 📊 Script Validation

The script performs multiple validation steps:

1. ✅ Administrator privilege check
2. ✅ PowerShell execution policy validation
3. ✅ User account existence verification
4. ✅ Task existence confirmation
5. ✅ Backup creation success
6. ✅ User confirmation requirement

## 🤝 Contributing

To modify the script for your environment:

1. **Update the task list** in the `$tasksToModify` array
2. **Modify permission levels** by changing the SDDL string format
3. **Add additional validation** as needed for your specific requirements

## 📄 License

This script is provided as-is for educational and administrative purposes. Use at your own risk and always test in a non-production environment first.

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the PowerShell error messages for specific details
3. Verify all prerequisites are met
4. Test with a single task first before running on all tasks

---

**⚠️ Important**: Always test this script in a non-production environment before using it on critical systems. The backup functionality helps protect against unintended changes, but proper testing is essential.