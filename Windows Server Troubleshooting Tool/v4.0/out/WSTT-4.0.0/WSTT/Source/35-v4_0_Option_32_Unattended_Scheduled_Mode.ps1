# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 32: Unattended / Scheduled Mode
# Source lines: 9003 - 9089
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 32: Unattended / Scheduled Mode
function Show-UnattendedModeHelp {
    [CmdletBinding()] param()
    Write-Header 'UNATTENDED / SCHEDULED MODE (Option 32)'
    Write-Host @'
Run WSTT without prompts:

  .\WSTT_v4.0.ps1 -Unattended `
                  -Categories ModernSecurity,Server2025,Patching `
                  -Format JSON `
                  -OutputPath C:\WSTTReports

Multi-server fan-out:

  .\WSTT_v4.0.ps1 -Unattended -ComputerName srv01,srv02 `
                  -CredentialPath C:\Secure\creds.xml `
                  -Categories All -Format All -OutputPath C:\WSTTReports

Schedule daily run:

  $a = New-ScheduledTaskAction -Execute pwsh.exe `
        -Argument '-NoProfile -ExecutionPolicy RemoteSigned -File "C:\WSTT\WSTT_v4.0.ps1" -Unattended -Categories All -Format JSON -OutputPath C:\WSTTReports'
  $t = New-ScheduledTaskTrigger -Daily -At 02:00
  Register-ScheduledTask -TaskName WSTT-Daily -Action $a -Trigger $t -RunLevel Highest

Exit codes: 0 OK | 1 WARN found | 2 ERROR found | 3 FATAL/uncaught
'@ -ForegroundColor Gray
}

function Invoke-WSTTUnattended {
    <#
    .SYNOPSIS
        Non-interactive entry point. Runs selected categories, exports, sets exit code.
    #>
    [CmdletBinding()] param(
        [string[]]$Categories = @('All'),
        [string]$Format = 'JSON',
        [string]$OutputPath,
        [string[]]$ComputerName,
        [string]$CredentialPath,
        [int]$ThrottleLimit = 8
    )
    if (-not $OutputPath) { $OutputPath = Join-Path $env:TEMP "WSTTReports" }
    if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }

    Write-Host "WSTT v4.0 unattended run starting." -ForegroundColor Cyan
    Write-Info "Categories: $($Categories -join ',') | Format: $Format | Out: $OutputPath"

    $checkMap = [ordered]@{
        AD             = 'Test-ActiveDirectoryHealth'
        HyperV         = 'Test-HyperVHostHealth'
        AdvStorage     = 'Test-AdvancedStorageHealth'
        ModernSecurity = 'Test-ModernSecurityPosture'
        Server2025     = 'Test-Server2025FeatureAudit'
        PKI            = 'Test-CertificateAndPKIHealth'
        Arc            = 'Test-AzureArcHybridHealth'
        Patching       = 'Test-PatchingDepthAndLifecycle'
    }
    $selected = if ($Categories -contains 'All') { $checkMap.Keys } else { $Categories | Where-Object { $checkMap.ContainsKey($_) } }
    if (-not $selected) { Write-DiagWarning 'No matching v4.0 categories — nothing to do.'; exit 0 }

    if ($ComputerName) {
        $cred = $null
        if ($CredentialPath -and (Test-Path $CredentialPath)) {
            try { $cred = Import-Clixml $CredentialPath } catch { Write-DiagError "Credential import failed: $($_.Exception.Message)"; exit 3 }
        }
        Invoke-WSTTRemote -ComputerName $ComputerName -Credential $cred -Categories $selected -ThrottleLimit $ThrottleLimit
    } else {
        foreach ($c in $selected) {
            try { & $checkMap[$c] } catch { Write-DiagError "[$c] failed: $($_.Exception.Message)" -Category $c -CheckId 'unattended' }
        }
    }

    Export-FindingsToFile -Format $Format -OutputPath $OutputPath

    $worst = 0
    foreach ($f in $script:Findings) {
        switch ($f.Severity) {
            'WARN'  { if ($worst -lt 1) { $worst = 1 } }
            'ERROR' { if ($worst -lt 2) { $worst = 2 } }
            'FATAL' { $worst = 3 }
        }
    }
    Write-Host "WSTT v4.0 unattended run complete. Worst severity: $worst" -ForegroundColor Cyan
    exit $worst
}
#endregion
