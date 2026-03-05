# ============================================
# VSS Shadow Copy Investigation Script
# Purpose: Diagnose what's creating massive shadow copies
# Run this in PowerShell as Administrator
# ============================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "VSS Shadow Copy Investigation Tool" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. Check Shadow Storage Configuration
Write-Host "[1] Shadow Storage Configuration" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
vssadmin list shadowstorage
Write-Host "`n"

# 2. List All Shadow Copies with Details
Write-Host "[2] Existing Shadow Copies" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
$shadows = vssadmin list shadows
$shadows
Write-Host "`n"

# 3. Count Shadow Copies Per Volume
Write-Host "[3] Shadow Copy Count Analysis" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
$shadowCount = ($shadows | Select-String "Shadow Copy ID").Count
Write-Host "Total Shadow Copies Found: $shadowCount" -ForegroundColor Green
Write-Host "`n"

# 4. Check VSS Writers Status (Critical!)
Write-Host "[4] VSS Writers Status" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
Write-Host "Checking for failed or stuck writers..." -ForegroundColor Gray
$writers = vssadmin list writers
$writers

# Parse writer states
$writerStates = $writers | Select-String "State: "
$failedWriters = $writerStates | Where-Object { $_ -notmatch "State: \[1\] Stable" }

if ($failedWriters) {
    Write-Host "`n⚠️ WARNING: Found VSS writers NOT in stable state!" -ForegroundColor Red
    $failedWriters
} else {
    Write-Host "`n✓ All VSS writers are in stable state" -ForegroundColor Green
}
Write-Host "`n"

# 5. Check VSS Providers
Write-Host "[5] VSS Providers" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
vssadmin list providers
Write-Host "`n"

# 6. Check for Backup Software / Scheduled Tasks
Write-Host "[6] Scheduled Tasks Creating Shadow Copies" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
Write-Host "Checking for scheduled backup tasks..." -ForegroundColor Gray

$vssRelatedTasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -like "*Shadow*" -or 
    $_.TaskPath -like "*Backup*" -or 
    $_.TaskName -like "*Shadow*" -or 
    $_.TaskName -like "*Backup*" -or
    $_.TaskName -like "*VSS*"
}

if ($vssRelatedTasks) {
    $vssRelatedTasks | Format-Table TaskName, State, LastRunTime, NextRunTime -AutoSize
} else {
    Write-Host "No obvious VSS-related scheduled tasks found" -ForegroundColor Gray
}
Write-Host "`n"

# 7. Check Windows Backup Status
Write-Host "[7] Windows Server Backup Configuration" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
try {
    $wbPolicy = Get-WBPolicy -ErrorAction SilentlyContinue
    if ($wbPolicy) {
        Write-Host "⚠️ Windows Server Backup is ENABLED" -ForegroundColor Red
        $wbPolicy | Format-List
    } else {
        Write-Host "✓ Windows Server Backup is not configured" -ForegroundColor Green
    }
} catch {
    Write-Host "Cannot check Windows Backup (may not be installed)" -ForegroundColor Gray
}
Write-Host "`n"

# 8. Check System Restore Settings
Write-Host "[8] System Restore Configuration" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
try {
    $systemRestore = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    if ($systemRestore) {
        Write-Host "System Restore Points Found: $($systemRestore.Count)" -ForegroundColor Yellow
        $systemRestore | Format-Table SequenceNumber, CreationTime, Description -AutoSize
    } else {
        Write-Host "No System Restore points found" -ForegroundColor Gray
    }
} catch {
    Write-Host "System Restore may be disabled" -ForegroundColor Gray
}
Write-Host "`n"

# 9. Check Event Logs for VSS Activity
Write-Host "[9] Recent VSS Events (Last 24 Hours)" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
Write-Host "Checking VSS event logs..." -ForegroundColor Gray

$vssEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'VSS'
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 50 -ErrorAction SilentlyContinue

if ($vssEvents) {
    $vssEvents | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize -Wrap
} else {
    Write-Host "No recent VSS events found" -ForegroundColor Gray
}
Write-Host "`n"

# 10. Check for Third-Party Backup Software
Write-Host "[10] Installed Backup Software Detection" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow

$backupSoftware = @(
    "Veeam", "Acronis", "Symantec", "Veritas", "Commvault", 
    "Backup Exec", "NetBackup", "DPM", "Azure Backup", "Carbonite"
)

$installedPrograms = Get-WmiObject -Class Win32_Product | Select-Object Name

foreach ($software in $backupSoftware) {
    $found = $installedPrograms | Where-Object { $_.Name -like "*$software*" }
    if ($found) {
        Write-Host "⚠️ FOUND: $($found.Name)" -ForegroundColor Red
    }
}
Write-Host "`n"

# 11. Check VSS Service Status
Write-Host "[11] VSS Service Status" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
Get-Service -Name VSS, swprv | Format-Table Name, Status, StartType -AutoSize
Write-Host "`n"

# 12. Disk Space Analysis
Write-Host "[12] Disk Space Summary" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Yellow
Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | 
    Select-Object Name, 
    @{Name="Used(GB)";Expression={[math]::Round($_.Used/1GB,2)}},
    @{Name="Free(GB)";Expression={[math]::Round($_.Free/1GB,2)}},
    @{Name="Total(GB)";Expression={[math]::Round(($_.Used+$_.Free)/1GB,2)}} | 
    Format-Table -AutoSize
Write-Host "`n"

# 13. Recommendations
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ANALYSIS & RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n📊 FINDINGS:" -ForegroundColor Yellow
Write-Host "• Shadow copies consuming: 2,256 GB" -ForegroundColor White
Write-Host "• Total shadow copies found: $shadowCount" -ForegroundColor White

Write-Host "`n⚠️ COMMON CAUSES:" -ForegroundColor Yellow
Write-Host "1. Third-party backup software (Veeam, Acronis, etc.) creating frequent snapshots" -ForegroundColor White
Write-Host "2. Windows Server Backup with aggressive schedule" -ForegroundColor White
Write-Host "3. SQL Server backups triggering VSS" -ForegroundColor White
Write-Host "4. Hyper-V checkpoints if this is a VM host" -ForegroundColor White
Write-Host "5. No maximum size limit configured (UNBOUNDED)" -ForegroundColor White

Write-Host "`n✅ RECOMMENDED ACTIONS:" -ForegroundColor Green
Write-Host "1. Set a maximum VSS storage limit:" -ForegroundColor White
Write-Host "   vssadmin resize shadowstorage /for=L: /on=L: /maxsize=100GB" -ForegroundColor Cyan
Write-Host "`n2. Delete old shadow copies:" -ForegroundColor White
Write-Host "   vssadmin delete shadows /for=L: /oldest" -ForegroundColor Cyan
Write-Host "`n3. If backup software is installed, check its retention policy" -ForegroundColor White
Write-Host "`n4. Review failed VSS writers and restart them if needed" -ForegroundColor White

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Investigation Complete!" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Export results to file
$outputFile = "$env:USERPROFILE\Desktop\VSS_Investigation_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Write-Host "💾 Exporting detailed results to: $outputFile" -ForegroundColor Yellow

Start-Transcript -Path $outputFile -Append
vssadmin list shadowstorage
vssadmin list shadows
vssadmin list writers
Stop-Transcript

Write-Host "`n✓ Export complete!" -ForegroundColor Green