# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Task Scheduler Diagnostics
# Source lines: 7009 - 7343
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Task Scheduler Diagnostics
function Test-TaskSchedulerHealth {
    <#
    .SYNOPSIS
        Performs comprehensive Task Scheduler diagnostics
    .DESCRIPTION
        Checks failed tasks, long-running tasks, disabled tasks, high-privilege tasks,
        credential failures, SDDL permissions, orphaned executables, and trigger health
    .EXAMPLE
        Test-TaskSchedulerHealth
    #>
    [CmdletBinding()]
    param()

    Write-Header "Task Scheduler Diagnostics"

    $allTasks = $null
    try {
        $allTasks = Get-ScheduledTask -ErrorAction Stop
        Write-Info "  Total scheduled tasks: $(@($allTasks).Count)"
    }
    catch {
        Write-DiagError "  Could not enumerate scheduled tasks: $($_.Exception.Message)"
        return
    }

    $allTaskInfo = @()
    foreach ($t in $allTasks) {
        try {
            $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            $allTaskInfo += [PSCustomObject]@{
                Task     = $t
                Info     = $info
                FullName = if ($t.TaskPath) { "$($t.TaskPath)$($t.TaskName)" } else { $t.TaskName }
            }
        }
        catch {
            $allTaskInfo += [PSCustomObject]@{
                Task     = $t
                Info     = $null
                FullName = if ($t.TaskPath) { "$($t.TaskPath)$($t.TaskName)" } else { $t.TaskName }
            }
        }
    }

    # 1. Failed Tasks (Last Run Result != 0)
    Write-Section "Failed Tasks (Last Run Result != 0)"
    try {
        $failedTasks = $allTaskInfo | Where-Object {
            $_.Info -and $_.Info.LastTaskResult -ne 0 -and $_.Info.LastTaskResult -ne 0x00041325 -and
            $_.Task.State -ne 'Disabled' -and $_.Task.TaskPath -notlike '\Microsoft\*'
        }
        if ($failedTasks) {
            Write-DiagWarning "  $(@($failedTasks).Count) non-Microsoft task(s) with failed last run:"
            foreach ($ft in $failedTasks | Select-Object -First 15) {
                $resultHex = "0x{0:X8}" -f $ft.Info.LastTaskResult
                $lastRun = if ($ft.Info.LastRunTime -and $ft.Info.LastRunTime.Year -gt 1999) { $ft.Info.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { "Never" }
                Write-DiagWarning "    $($ft.FullName): Result=$resultHex LastRun=$lastRun"
                # Decode common error codes
                switch ($ft.Info.LastTaskResult) {
                    0x8007052E { Write-DiagError "      → Logon failure (expired password or invalid credentials)" }
                    0x80070005 { Write-DiagError "      → Access denied (insufficient permissions)" }
                    0x80041326 { Write-Info "        → Task not yet run (scheduled for future)" }
                    0x800710E0 { Write-DiagWarning "      → Operator or administrator refused the request" }
                    0x00041306 { Write-DiagWarning "      → Task terminated by user" }
                    0x00041301 { Write-Info "        → Task is currently running" }
                }
            }
        }
        else {
            Write-Success "  No failed non-Microsoft tasks detected"
        }

        # Also show Microsoft tasks with failures (separate)
        $msFailedTasks = $allTaskInfo | Where-Object {
            $_.Info -and $_.Info.LastTaskResult -ne 0 -and $_.Info.LastTaskResult -ne 0x00041325 -and
            $_.Task.State -ne 'Disabled' -and $_.Task.TaskPath -like '\Microsoft\*'
        }
        if ($msFailedTasks -and @($msFailedTasks).Count -gt 0) {
            Write-Info "  Microsoft tasks with failures: $(@($msFailedTasks).Count) (use Get-ScheduledTask for details)"
        }
    }
    catch {
        Write-DiagWarning "  Could not check failed tasks: $($_.Exception.Message)"
    }

    # 2. Tasks Running Longer Than Expected (currently running)
    Write-Section "Long-Running / Stuck Tasks"
    try {
        $runningTasks = $allTaskInfo | Where-Object { $_.Task.State -eq 'Running' }
        if ($runningTasks) {
            Write-DiagWarning "  $(@($runningTasks).Count) task(s) currently running:"
            foreach ($rt in $runningTasks) {
                $runTime = ""
                if ($rt.Info -and $rt.Info.LastRunTime -and $rt.Info.LastRunTime.Year -gt 1999) {
                    $duration = (Get-Date) - $rt.Info.LastRunTime
                    $runTime = "$([math]::Round($duration.TotalMinutes, 0)) min"
                    if ($duration.TotalHours -gt 4) {
                        Write-DiagError "    $($rt.FullName): Running for $runTime — POSSIBLY STUCK"
                    }
                    elseif ($duration.TotalHours -gt 1) {
                        Write-DiagWarning "    $($rt.FullName): Running for $runTime"
                    }
                    else {
                        Write-Info "    $($rt.FullName): Running for $runTime"
                    }
                }
                else {
                    Write-Info "    $($rt.FullName): Running (start time unknown)"
                }
            }
        }
        else {
            Write-Info "  No tasks currently running"
        }
    }
    catch {
        Write-DiagWarning "  Could not check running tasks"
    }

    # 3. Disabled Tasks (non-Microsoft)
    Write-Section "Disabled Tasks"
    try {
        $disabledTasks = $allTasks | Where-Object {
            $_.State -eq 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'
        }
        if ($disabledTasks) {
            Write-Info "  $(@($disabledTasks).Count) non-Microsoft task(s) are disabled:"
            foreach ($dt in $disabledTasks | Select-Object -First 15) {
                Write-Info "    $($dt.TaskPath)$($dt.TaskName)"
            }
            if (@($disabledTasks).Count -gt 15) {
                Write-Info "    ... and $(@($disabledTasks).Count - 15) more"
            }
        }
        else {
            Write-Success "  No disabled non-Microsoft tasks"
        }
    }
    catch {
        Write-DiagWarning "  Could not check disabled tasks"
    }

    # 4. Tasks Running As SYSTEM / High Privilege
    Write-Section "High-Privilege Task Audit"
    try {
        $highPrivTasks = $allTasks | Where-Object {
            $_.Principal.UserId -in @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18') -and
            $_.Principal.RunLevel -eq 'Highest' -and
            $_.TaskPath -notlike '\Microsoft\*' -and
            $_.State -ne 'Disabled'
        }
        if ($highPrivTasks) {
            Write-DiagWarning "  $(@($highPrivTasks).Count) non-Microsoft task(s) run as SYSTEM with Highest privilege:"
            foreach ($hp in $highPrivTasks | Select-Object -First 10) {
                $actionExe = ($hp.Actions | Select-Object -First 1).Execute
                Write-DiagWarning "    $($hp.TaskPath)$($hp.TaskName) → $actionExe"
            }
            Write-Info "  Review these tasks — SYSTEM + Highest is a security risk if the executable is writable"
        }
        else {
            Write-Success "  No non-Microsoft high-privilege tasks found"
        }
    }
    catch {
        Write-DiagWarning "  Could not audit task privileges"
    }

    # 5. Tasks With Expired/Invalid Credentials (logon failure)
    Write-Section "Credential Failures (Logon Error 0x8007052E)"
    try {
        $credFailed = $allTaskInfo | Where-Object {
            $_.Info -and ($_.Info.LastTaskResult -eq 0x8007052E -or $_.Info.LastTaskResult -eq 0x80070005) -and
            $_.Task.State -ne 'Disabled'
        }
        if ($credFailed) {
            Write-DiagError "  $(@($credFailed).Count) task(s) failing due to credential/access issues:"
            foreach ($cf in $credFailed) {
                $principal = $cf.Task.Principal.UserId
                $resultHex = "0x{0:X8}" -f $cf.Info.LastTaskResult
                Write-DiagError "    $($cf.FullName): RunAs='$principal' Error=$resultHex"
                if ($cf.Info.LastTaskResult -eq 0x8007052E) {
                    Write-Info "      Fix: Update password for '$principal' in Task Scheduler properties"
                }
                elseif ($cf.Info.LastTaskResult -eq 0x80070005) {
                    Write-Info "      Fix: Grant '$principal' the 'Log on as a batch job' right"
                }
            }
        }
        else {
            Write-Success "  No credential-related task failures"
        }
    }
    catch {
        Write-DiagWarning "  Could not check credential failures"
    }

    # 6. Task SDDL Permission Audit
    Write-Section "Task Permission Audit (SDDL)"
    try {
        $service = New-Object -ComObject "Schedule.Service"
        $service.Connect()
        $rootFolder = $service.GetFolder("\")
        $comTasks = $rootFolder.GetTasks(0)
        $permIssues = 0
        foreach ($ct in $comTasks) {
            try {
                $sddl = $ct.GetSecurityDescriptor(4)
                # Flag tasks where Everyone (S-1-1-0) or Authenticated Users (S-1-5-11) have Full Access
                if ($sddl -match '\(A;;FA;;;S-1-1-0\)' -or $sddl -match '\(A;;FA;;;S-1-5-11\)') {
                    $permIssues++
                    Write-DiagWarning "    $($ct.Name): Overly permissive — Everyone or Authenticated Users have Full Access"
                }
            }
            catch { }
        }
        if ($permIssues -eq 0) {
            Write-Success "  No overly permissive task SDDL entries found (root folder)"
        }
        else {
            Write-DiagWarning "  $permIssues task(s) with overly broad permissions"
        }
    }
    catch {
        Write-DiagWarning "  Could not audit task SDDL permissions (COM access may be restricted)"
    }

    # 7. Orphaned Tasks (missing executables)
    Write-Section "Orphaned Tasks (Missing Executables)"
    try {
        $orphaned = @()
        $tasksWithActions = $allTasks | Where-Object {
            $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' -and $_.Actions.Count -gt 0
        }
        foreach ($t in $tasksWithActions) {
            foreach ($action in $t.Actions) {
                $exe = $action.Execute
                if ($exe -and $exe -notlike 'COM handler*' -and $exe -notlike '%*') {
                    # Strip quotes
                    $cleanExe = $exe.Trim('"', "'", ' ')
                    # Skip built-in commands
                    if ($cleanExe -notin @('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe') -and
                        $cleanExe -notlike '*.com' -and -not (Test-Path $cleanExe -ErrorAction SilentlyContinue)) {
                        $orphaned += [PSCustomObject]@{
                            Task = "$($t.TaskPath)$($t.TaskName)"
                            Exe  = $cleanExe
                        }
                    }
                }
            }
        }
        if ($orphaned) {
            Write-DiagWarning "  $(@($orphaned).Count) task(s) reference missing executables:"
            foreach ($o in $orphaned | Select-Object -First 10) {
                Write-DiagWarning "    $($o.Task) → $($o.Exe) [NOT FOUND]"
            }
            if (@($orphaned).Count -gt 10) {
                Write-Info "    ... and $(@($orphaned).Count - 10) more"
            }
        }
        else {
            Write-Success "  All non-Microsoft task executables exist on disk"
        }
    }
    catch {
        Write-DiagWarning "  Could not check for orphaned tasks: $($_.Exception.Message)"
    }

    # 8. Task Trigger Health (expired/no triggers)
    Write-Section "Task Trigger Health"
    try {
        $triggerIssues = @()
        $activeTasks = $allTasks | Where-Object {
            $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'
        }
        foreach ($t in $activeTasks) {
            $triggers = $t.Triggers
            if (-not $triggers -or $triggers.Count -eq 0) {
                $triggerIssues += [PSCustomObject]@{
                    Task  = "$($t.TaskPath)$($t.TaskName)"
                    Issue = "No triggers defined"
                }
                continue
            }
            foreach ($trigger in $triggers) {
                # Check for expired end boundaries
                if ($trigger.EndBoundary) {
                    try {
                        $endDate = [datetime]$trigger.EndBoundary
                        if ($endDate -lt (Get-Date)) {
                            $triggerIssues += [PSCustomObject]@{
                                Task  = "$($t.TaskPath)$($t.TaskName)"
                                Issue = "Trigger expired on $($endDate.ToString('yyyy-MM-dd'))"
                            }
                        }
                    }
                    catch { }
                }
                # Check for disabled triggers
                if ($trigger.Enabled -eq $false) {
                    $triggerIssues += [PSCustomObject]@{
                        Task  = "$($t.TaskPath)$($t.TaskName)"
                        Issue = "Trigger is disabled"
                    }
                }
            }
        }
        if ($triggerIssues) {
            Write-DiagWarning "  $(@($triggerIssues).Count) trigger issue(s) found:"
            foreach ($ti in $triggerIssues | Select-Object -First 15) {
                Write-DiagWarning "    $($ti.Task): $($ti.Issue)"
            }
            if (@($triggerIssues).Count -gt 15) {
                Write-Info "    ... and $(@($triggerIssues).Count - 15) more"
            }
        }
        else {
            Write-Success "  All active task triggers are healthy"
        }
    }
    catch {
        Write-DiagWarning "  Could not check task triggers: $($_.Exception.Message)"
    }

    # Summary
    Write-Host ""
    $taskSummary = @{
        Total    = @($allTasks).Count
        Ready    = @($allTasks | Where-Object { $_.State -eq 'Ready' }).Count
        Running  = @($allTasks | Where-Object { $_.State -eq 'Running' }).Count
        Disabled = @($allTasks | Where-Object { $_.State -eq 'Disabled' }).Count
    }
    Write-Info "Task Summary: Total=$($taskSummary.Total) Ready=$($taskSummary.Ready) Running=$($taskSummary.Running) Disabled=$($taskSummary.Disabled)"
}
#endregion
