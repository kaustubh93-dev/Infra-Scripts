# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 26: Server 2025 Feature Audit
# Source lines: 8518 - 8612
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 26: Server 2025 Feature Audit
function Test-Server2025FeatureAudit {
    <#
    .SYNOPSIS
        Detection of Hotpatch, dMSA, NTLM deprecation, SMB-over-QUIC, NetATC, GPU-P, ARM64, OpenSSH, TLS 1.3.
    #>
    [CmdletBinding()] param()
    Write-Header 'SERVER 2025 FEATURE AUDIT (Option 26)'
    $cap = Get-OSCapability
    Write-Info "Detected build: $($cap.BuildNumber) | Caption: $($cap.Caption) | Arch: $($cap.Architecture)"

    Write-Section 'Hotpatch'
    if (Test-WSTTCommand 'Get-HotPatchState') {
        try { Get-HotPatchState -EA SilentlyContinue | Format-List | Out-Host
              Write-Success 'Get-HotPatchState executed.' -Category 'Server2025' -CheckId '26.1' }
        catch { Write-DiagWarning "Get-HotPatchState failed: $($_.Exception.Message)" -Category 'Server2025' -CheckId '26.1' }
    } elseif ($cap.Is2022 -and $cap.IsAzureEdition) { Write-Info 'Server 2022 Azure Edition: Hotpatch managed via Azure Update Manager.' }
    else { Write-Info 'Hotpatch N/A on this OS.' ; Add-Finding -Severity 'NA' -Category 'Server2025' -CheckId '26.1' -Message 'Hotpatch unsupported on this OS.' }

    Write-Section 'dMSA (Delegated Managed Service Accounts)'
    if ($cap.Is2025 -and (Test-WSTTCommand 'Get-ADServiceAccount')) {
        try {
            $d = Get-ADServiceAccount -Filter * -EA SilentlyContinue | Where-Object { $_.ObjectClass -eq 'msDS-DelegatedManagedServiceAccount' }
            Write-Success "dMSA accounts: $(@($d).Count)" -Category 'Server2025' -CheckId '26.2'
        } catch {}
    } else { Write-Info 'dMSA requires Server 2025 + AD module.' ; Add-Finding -Severity 'NA' -Category 'Server2025' -CheckId '26.2' -Message 'dMSA N/A on this OS.' }

    Write-Section 'NTLM deprecation telemetry (last 7d)'
    try {
        $n = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NTLM/Operational';StartTime=(Get-Date).AddDays(-7)} -EA SilentlyContinue
        $count = @($n).Count
        if ($count -gt 0) { Write-DiagWarning "NTLM events in 7d: $count." -Category 'Server2025' -CheckId '26.3' }
        else { Write-Success 'No NTLM operational events.' -Category 'Server2025' -CheckId '26.3' }
    } catch {}

    Write-Section 'SMB-over-QUIC server'
    if (Test-WSTTCommand 'Get-SmbServerCertificateMapping') {
        try {
            $m = Get-SmbServerCertificateMapping -EA SilentlyContinue
            if ($m) { Write-Success "SMB-over-QUIC certificate mappings: $(@($m).Count)" -Category 'Server2025' -CheckId '26.4' }
            else { Write-Info 'No SMB-over-QUIC mappings.' }
        } catch {}
    } else { Write-Info 'Get-SmbServerCertificateMapping not available.' }

    Write-Section 'Network ATC intents'
    if (Test-WSTTCommand 'Get-NetIntent') {
        try {
            $i = Get-NetIntent -EA SilentlyContinue
            if ($i) { Write-Success "Net intents: $(@($i).Count)" -Category 'Server2025' -CheckId '26.5' }
            else { Write-Info 'No Network ATC intents configured.' }
        } catch {}
    } else { Write-Info 'Network ATC not present.' }

    Write-Section 'GPU partitioning'
    if (Test-WSTTCommand 'Get-VMHostPartitionableGpu') {
        try {
            $g = Get-VMHostPartitionableGpu -EA SilentlyContinue
            if ($g) { Write-Success "Partitionable GPUs: $(@($g).Count)" -Category 'Server2025' -CheckId '26.6' }
            else { Write-Info 'No partitionable GPUs.' }
        } catch {}
    }

    Write-Section 'ARM64 architecture'
    if ($cap.Architecture -eq 'ARM64') {
        Write-DiagWarning 'Host is ARM64 — verify all 3rd-party tools support ARM64.' -Category 'Server2025' -CheckId '26.7'
    } else { Write-Success "Architecture: $($cap.Architecture)" -Category 'Server2025' -CheckId '26.7' }

    Write-Section 'OpenSSH server'
    $sshd = Get-Service sshd -EA SilentlyContinue
    if ($sshd) { Write-Success "sshd status: $($sshd.Status)" -Category 'Server2025' -CheckId '26.8' }
    else { Write-Info 'OpenSSH server not installed.' }

    Write-Section 'WinRM listeners'
    try {
        $wl = & winrm enumerate winrm/config/listener 2>$null | Out-String
        if ($wl -match 'Transport\s*=\s*HTTPS') { Write-Success 'WinRM HTTPS listener present.' -Category 'Server2025' -CheckId '26.9' }
        else { Write-DiagWarning 'No WinRM HTTPS listener (only HTTP).' -Category 'Server2025' -CheckId '26.9' }
    } catch {}

    Write-Section 'TLS 1.3 (Schannel)'
    try {
        $t13 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name Enabled -EA SilentlyContinue).Enabled
        if ($t13 -eq 1) { Write-Success 'TLS 1.3 server enabled.' -Category 'Server2025' -CheckId '26.10' }
        elseif ($cap.Is2019) { Write-Info 'TLS 1.3 not supported on Server 2019.' }
        else { Write-Info 'TLS 1.3 server not explicitly enabled (may be default).' }
    } catch {}

    Write-Section 'Wi-Fi adapter (anti-pattern on server)'
    try {
        $wifi = Get-NetAdapter -EA SilentlyContinue | Where-Object { $_.MediaType -eq 'Native 802.11' }
        if ($wifi) { Write-DiagWarning "Wi-Fi adapter present on server: $(($wifi.Name) -join ',')" -Category 'Server2025' -CheckId '26.12' }
        else { Write-Success 'No Wi-Fi adapters on host.' -Category 'Server2025' -CheckId '26.12' }
    } catch {}
}
#endregion
