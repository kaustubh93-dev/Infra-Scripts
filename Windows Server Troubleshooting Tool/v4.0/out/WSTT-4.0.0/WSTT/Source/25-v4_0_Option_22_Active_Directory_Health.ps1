# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 22: Active Directory Health
# Source lines: 8107 - 8224
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 22: Active Directory Health
function Test-ActiveDirectoryHealth {
    <#
    .SYNOPSIS
        DC-only health audit (dcdiag, repadmin, FSMO, SYSVOL, time, krbtgt, LDAP signing).
    #>
    [CmdletBinding()] param()
    Write-Header 'ACTIVE DIRECTORY HEALTH (Option 22)'
    $cap = Get-OSCapability
    if (-not $cap.IsDomainController) {
        Write-Info 'Host is not a Domain Controller — skipping AD health checks.'
        Add-Finding -Severity 'NA' -Category 'AD' -CheckId '22.1' -Message 'Not a DC; AD health skipped.'
        return
    }
    Write-Success "DC role detected on $($env:COMPUTERNAME)" -Category 'AD' -CheckId '22.1'

    Write-Section 'dcdiag (summary)'
    if (Test-WSTTCommand 'dcdiag.exe') {
        try {
            $dc = & dcdiag.exe /q 2>&1
            if ($LASTEXITCODE -eq 0 -and -not $dc) {
                Write-Success 'dcdiag /q reported no errors.' -Category 'AD' -CheckId '22.2'
            } else {
                Write-DiagError "dcdiag reported issues:`n$($dc -join [Environment]::NewLine)" -Category 'AD' -CheckId '22.2'
            }
        } catch { Write-DiagWarning "dcdiag failed: $($_.Exception.Message)" -Category 'AD' -CheckId '22.2' }
    } else { Write-DiagWarning 'dcdiag.exe not available.' -Category 'AD' -CheckId '22.2' }

    Write-Section 'Replication (repadmin /replsummary)'
    if (Test-WSTTCommand 'repadmin.exe') {
        try {
            $rs = & repadmin.exe /replsummary 2>&1 | Out-String
            Write-Host $rs
            if ($rs -match '\b[1-9]\d*\s+/\s+\d+\s+\d+%') {
                Write-DiagWarning 'Replication failures present in repadmin /replsummary.' -Category 'AD' -CheckId '22.3'
            } else {
                Write-Success 'No replication failures detected.' -Category 'AD' -CheckId '22.3'
            }
        } catch { Write-DiagWarning "repadmin failed: $($_.Exception.Message)" -Category 'AD' -CheckId '22.3' }
    } else { Write-DiagWarning 'repadmin.exe not available.' -Category 'AD' -CheckId '22.3' }

    Write-Section 'FSMO Role Holders'
    if (Test-WSTTCommand 'netdom.exe') {
        try { $fsmo = & netdom.exe query fsmo 2>&1 | Out-String; Write-Host $fsmo
              Add-Finding -Severity 'INFO' -Category 'AD' -CheckId '22.4' -Message 'FSMO holders enumerated.' -Data $fsmo
        } catch { Write-DiagWarning "netdom failed: $($_.Exception.Message)" -Category 'AD' -CheckId '22.4' }
    }

    Write-Section 'SYSVOL / DFSR'
    $sysvol = "\\$env:LOGONSERVER\SYSVOL"
    if (Test-Path $sysvol) {
        Write-Success "SYSVOL share readable: $sysvol" -Category 'AD' -CheckId '22.5'
    } else {
        Write-DiagError "SYSVOL share not readable: $sysvol" -Category 'AD' -CheckId '22.5'
    }
    if (Test-WSTTCommand 'Get-DfsrState') {
        try {
            $back = Get-DfsrState -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
            if ($back -gt 100) { Write-DiagWarning "DFSR backlog count: $back" -Category 'AD' -CheckId '22.5' }
            else { Write-Success "DFSR backlog: $back" -Category 'AD' -CheckId '22.5' }
        } catch {}
    }

    Write-Section 'Time Hierarchy (w32tm)'
    try {
        $w = & w32tm.exe /query /status 2>&1 | Out-String
        Write-Host $w
        if ($w -match 'Stratum:\s+(\d+)') {
            $stratum = [int]$Matches[1]
            if ($stratum -ge 10) { Write-DiagWarning "High stratum ($stratum) — time source may be local CMOS." -Category 'AD' -CheckId '22.6' }
            else { Write-Success "Time stratum: $stratum" -Category 'AD' -CheckId '22.6' }
        }
    } catch { Write-DiagWarning "w32tm /query failed: $($_.Exception.Message)" -Category 'AD' -CheckId '22.6' }

    Write-Section 'krbtgt password age'
    if (Test-WSTTCommand 'Get-ADUser') {
        try {
            $krb = Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction Stop
            $age = (New-TimeSpan -Start $krb.PasswordLastSet -End (Get-Date)).Days
            if ($age -gt 180) { Write-DiagWarning "krbtgt password age: $age days (rotate >=2x annually)." -Category 'AD' -CheckId '22.7' }
            else { Write-Success "krbtgt password age: $age days." -Category 'AD' -CheckId '22.7' }
        } catch { Write-DiagWarning "Get-ADUser krbtgt failed: $($_.Exception.Message)" -Category 'AD' -CheckId '22.7' }
    } else { Write-Info 'ActiveDirectory module not present — skipping krbtgt check.' }

    Write-Section 'LDAP signing & channel binding (ADV190023)'
    try {
        $ldapInt = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -EA SilentlyContinue).LDAPServerIntegrity
        $cb      = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -EA SilentlyContinue).LdapEnforceChannelBinding
        if ($ldapInt -ge 2) { Write-Success "LDAP signing enforced ($ldapInt)" -Category 'AD' -CheckId '22.8' }
        else { Write-DiagWarning "LDAPServerIntegrity=$ldapInt (recommend 2 = require)." -Category 'AD' -CheckId '22.8' }
        if ($cb -ge 2) { Write-Success "LDAP channel binding enforced ($cb)" -Category 'AD' -CheckId '22.8' }
        else { Write-DiagWarning "LdapEnforceChannelBinding=$cb (recommend 2)." -Category 'AD' -CheckId '22.8' }
    } catch {}

    Write-Section 'NTLM auditing (last 7d, source 8004/8002)'
    try {
        $ntlm = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NTLM/Operational';Id=8004,8002;StartTime=(Get-Date).AddDays(-7)} -EA SilentlyContinue
        $count = @($ntlm).Count
        Add-Finding -Severity 'INFO' -Category 'AD' -CheckId '22.9' -Message "NTLM events in last 7 days: $count"
        if ($count -gt 0) { Write-DiagWarning "NTLM in active use: $count events." -Category 'AD' -CheckId '22.9' }
        else { Write-Success 'No NTLM operational events in last 7 days.' -Category 'AD' -CheckId '22.9' }
    } catch { Write-Info 'NTLM operational log not enabled or unavailable.' }

    Write-Section 'AD database volume'
    try {
        $dsa = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'DSA Database file' -EA SilentlyContinue).'DSA Database file'
        if ($dsa) {
            $drive = [IO.Path]::GetPathRoot($dsa).TrimEnd('\').TrimEnd(':')
            $vol = Get-Volume -DriveLetter $drive -EA SilentlyContinue
            if ($vol) {
                $pct = [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 1)
                if ($pct -lt 15) { Write-DiagWarning "NTDS volume free: $pct% (low)" -Category 'AD' -CheckId '22.10' }
                else { Write-Success "NTDS volume free: $pct%" -Category 'AD' -CheckId '22.10' }
            }
        }
    } catch {}
}
#endregion
