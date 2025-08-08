 # Enhanced Task Scheduler Permission Management Script
# This script modifies scheduled task permissions to grant full control to a specified user

#Requires -RunAsAdministrator

# Function to check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to get user SID
function Get-UserSID {
    param([string]$Username)
    
    try {
        $user = Get-WmiObject -Class Win32_UserAccount -Filter "Name='$Username'"
        if ($user) {
            return $user.SID
        } else {
            Write-Error "User '$Username' not found on this system."
            return $null
        }
    }
    catch {
        Write-Error "Error retrieving SID for user '$Username': $($_.Exception.Message)"
        return $null
    }
}

# Function to backup current task permissions
function Backup-TaskPermissions {
    param([string]$BackupPath = "TaskPermissions_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt")
    
    Write-Host "Creating backup of current task permissions..." -ForegroundColor Yellow
    
    try {
        $service = New-Object -ComObject "Schedule.Service"
        $service.Connect()
        $rootFolder = $service.GetFolder("\")
        $tasks = $rootFolder.GetTasks(0)
        
        $backupContent = @()
        $backupContent += "# Task Permissions Backup - $(Get-Date)"
        $backupContent += "# Generated before modifying permissions"
        $backupContent += ""
        
        foreach ($task in $tasks) {
            try {
                $taskName = $task.Name
                $sddl = $task.GetSecurityDescriptor(4)
                $backupContent += "Task: $taskName"
                $backupContent += "SDDL: $sddl"
                $backupContent += "---"
            }
            catch {
                $backupContent += "Task: $($task.Name) - Error retrieving permissions: $($_.Exception.Message)"
                $backupContent += "---"
            }
        }
        
        $backupContent | Out-File -FilePath $BackupPath -Encoding UTF8
        Write-Host "Backup saved to: $BackupPath" -ForegroundColor Green
        return $BackupPath
    }
    catch {
        Write-Error "Failed to create backup: $($_.Exception.Message)"
        return $null
    }
}

# Function to verify task exists
function Test-TaskExists {
    param([string]$TaskName)
    
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        return $task -ne $null
    }
    catch {
        return $false
    }
}

# Main function to modify task permissions
function Set-TaskPermissions {
    param(
        [string]$Folder,
        [string]$TaskName,
        [string]$UserSID
    )
    
    try {
        # Check if task exists
        if (-not (Test-TaskExists -TaskName $TaskName)) {
            Write-Warning "Task '$TaskName' does not exist. Skipping..."
            return $false
        }
        
        $service = New-Object -ComObject "Schedule.Service"
        $service.Connect()
        
        Write-Host "Processing task: $TaskName" -ForegroundColor Cyan
        
        # Get current security descriptor
        $root = $service.GetFolder($Folder)
        $task = $root.GetTask($TaskName)
        $oldSddl = $task.GetSecurityDescriptor(4)
        
        Write-Host "  Old Security SDDL: $oldSddl" -ForegroundColor Gray
        
        # Set new security descriptor with full access for the specified user
        $newSddl = "D:ARAI(A;;FA;;;$UserSID)"
        $task.SetSecurityDescriptor($newSddl, 0)
        
        # Verify the change
        $newSddlVerify = $task.GetSecurityDescriptor(4)
        Write-Host "  New Security SDDL: $newSddlVerify" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Error "Failed to modify permissions for task '$TaskName': $($_.Exception.Message)"
        return $false
    }
}

# Main execution starts here
Write-Host "=== Task Scheduler Permission Management Script ===" -ForegroundColor White -BackgroundColor Blue
Write-Host ""

# Step 1: Check if running as Administrator
Write-Host "1. Checking Administrator privileges..." -ForegroundColor Yellow
if (-not (Test-Administrator)) {
    Write-Error "This script must be run as Administrator!"
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "   ✓ Running as Administrator" -ForegroundColor Green

# Step 2: Check Execution Policy
Write-Host "2. Checking PowerShell Execution Policy..." -ForegroundColor Yellow
$executionPolicy = Get-ExecutionPolicy
Write-Host "   Current Execution Policy: $executionPolicy" -ForegroundColor Gray

if ($executionPolicy -eq "Restricted") {
    Write-Host "   Execution Policy is Restricted. Temporarily changing to RemoteSigned..." -ForegroundColor Yellow
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Host "   ✓ Execution Policy updated" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to update Execution Policy: $($_.Exception.Message)"
        Read-Host "Press Enter to exit"
        exit 1
    }
} else {
    Write-Host "   ✓ Execution Policy is acceptable" -ForegroundColor Green
}

# Step 3: Backup current task permissions
Write-Host "3. Backing up current task permissions..." -ForegroundColor Yellow
$backupPath = Backup-TaskPermissions
if (-not $backupPath) {
    $continue = Read-Host "Backup failed. Continue anyway? (y/N)"
    if ($continue -notmatch "^[Yy]$") {
        Write-Host "Operation cancelled." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "   ✓ Backup completed: $backupPath" -ForegroundColor Green
}

# Step 4: Get User SID
Write-Host "4. Getting User SID..." -ForegroundColor Yellow
$username = Read-Host "Enter the username for which to grant permissions"
$userSID = Get-UserSID -Username $username

if (-not $userSID) {
    Write-Error "Cannot proceed without valid user SID."
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "   ✓ User SID for '$username': $userSID" -ForegroundColor Green

# Step 5: List all available tasks for verification
Write-Host "5. Listing all available scheduled tasks..." -ForegroundColor Yellow
try {
    $allTasks = Get-ScheduledTask | Select-Object TaskName, State | Sort-Object TaskName
    Write-Host "   Available tasks:" -ForegroundColor Gray
    $allTasks | ForEach-Object { Write-Host "     - $($_.TaskName) ($($_.State))" -ForegroundColor Gray }
}
catch {
    Write-Warning "Could not retrieve task list: $($_.Exception.Message)"
}

# Step 6: Define tasks to modify
Write-Host "6. Preparing to modify task permissions..." -ForegroundColor Yellow
$tasksToModify = @(
    "Acc_Opening_Auto_NRITracker",
    "DCMSHOTLISTCARD",
    "EMAILTRIGGER",
    "ICoreSmsEmail",
    "ICoreSummary",
    "Optimize Start Menu Cache Files-S-1-5-21-2401899096-1803463866-3717766691-1006",
    "Optimize Start Menu Cache Files-S-1-5-21-2401899096-1803463866-3717766691-1012",
    "Prime Destroy Summary",
    "Prime_CCBlock",
    "ServiceMonitor",
    "SMS alert",
    "SMS And Email Summary",
    "SpeedPost",
    "Stage_WiseEmail",
    "Test01",
    "Vendor Production Interface",
    "WEBAPI Summary"
)

# Confirm before proceeding
Write-Host ""
Write-Host "About to modify permissions for $($tasksToModify.Count) tasks:" -ForegroundColor Yellow
$tasksToModify | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
Write-Host ""
Write-Host "User: $username (SID: $userSID)" -ForegroundColor Yellow
Write-Host "Permission: Full Access" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Do you want to proceed? (y/N)"
if ($confirm -notmatch "^[Yy]$") {
    Write-Host "Operation cancelled." -ForegroundColor Red
    exit 0
}

# Step 7: Execute the permission changes
Write-Host "7. Modifying task permissions..." -ForegroundColor Yellow
$successCount = 0
$failureCount = 0

foreach ($taskName in $tasksToModify) {
    if (Set-TaskPermissions -Folder "\" -TaskName $taskName -UserSID $userSID) {
        $successCount++
    } else {
        $failureCount++
    }
}

# Summary
Write-Host ""
Write-Host "=== Operation Summary ===" -ForegroundColor White -BackgroundColor Blue
Write-Host "Successfully modified: $successCount tasks" -ForegroundColor Green
Write-Host "Failed to modify: $failureCount tasks" -ForegroundColor Red
Write-Host "Backup location: $backupPath" -ForegroundColor Cyan
Write-Host ""

if ($failureCount -gt 0) {
    Write-Host "Some tasks failed to be modified. Please review the errors above." -ForegroundColor Yellow
}

Write-Host "Script completed. Press Enter to exit..."
Read-Host