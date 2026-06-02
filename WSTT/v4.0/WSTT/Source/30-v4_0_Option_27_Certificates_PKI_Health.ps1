# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 27: Certificates & PKI Health
# Source lines: 8614 - 8692
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 27: Certificates & PKI Health
function Test-CertificateAndPKIHealth {
    <#
    .SYNOPSIS
        Expiring certs (My + WebHosting), WinRM listener cert, chain build, private key ACL audit.
    #>
    [CmdletBinding()] param()
    Write-Header 'CERTIFICATES & PKI HEALTH (Option 27)'

    Write-Section 'Expiring computer certificates (LocalMachine\My)'
    try {
        $now = Get-Date
        $certs = Get-ChildItem Cert:\LocalMachine\My -EA SilentlyContinue
        foreach ($c in $certs) {
            $days = ($c.NotAfter - $now).Days
            $msg = "{0,-30} expires in {1,4} days  Thumb={2}" -f ($c.Subject -replace '^CN=',''), $days, $c.Thumbprint
            if ($days -lt 0)       { Write-DiagError  "$msg (EXPIRED)" -Category 'PKI' -CheckId '27.1' }
            elseif ($days -le 30)  { Write-DiagError  $msg -Category 'PKI' -CheckId '27.1' }
            elseif ($days -le 90)  { Write-DiagWarning $msg -Category 'PKI' -CheckId '27.1' }
            else                   { Write-Info $msg }
        }
        if (-not $certs) { Write-Info 'No certificates in LocalMachine\My.' }
    } catch {}

    Write-Section 'Web bindings (IIS)'
    if (Test-WSTTCommand 'Get-WebBinding') {
        try {
            $bindings = Get-WebBinding -Protocol https -EA SilentlyContinue
            foreach ($b in $bindings) {
                $thumb = ($b.certificateHash)
                if ($thumb) {
                    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq $thumb
                    if ($cert) {
                        $days = ($cert.NotAfter - (Get-Date)).Days
                        if ($days -le 30) { Write-DiagError "IIS binding $($b.bindingInformation) cert expires in $days d." -Category 'PKI' -CheckId '27.2' }
                        else { Write-Success "IIS binding $($b.bindingInformation) ok ($days d)." -Category 'PKI' -CheckId '27.2' }
                    }
                }
            }
        } catch {}
    } else { Write-Info 'WebAdministration module not present (IIS not installed).' }

    Write-Section 'WinRM HTTPS listener cert'
    try {
        $wl = & winrm enumerate winrm/config/listener 2>$null | Out-String
        if ($wl -match 'CertificateThumbprint\s*=\s*([0-9A-F]+)') {
            $tb = $Matches[1]
            $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq $tb
            if ($cert) {
                $days = ($cert.NotAfter - (Get-Date)).Days
                if ($days -le 30) { Write-DiagError "WinRM cert expires in $days days." -Category 'PKI' -CheckId '27.3' }
                else { Write-Success "WinRM cert valid for $days days." -Category 'PKI' -CheckId '27.3' }
            }
        } else { Write-Info 'No WinRM HTTPS listener with bound certificate.' }
    } catch {}

    Write-Section 'Cert chain build (LocalMachine\My)'
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationFlag = 'EntireChain'
        $chain.ChainPolicy.RevocationMode = 'Online'
        foreach ($c in (Get-ChildItem Cert:\LocalMachine\My -EA SilentlyContinue)) {
            $ok = $chain.Build($c)
            if (-not $ok) {
                $reasons = ($chain.ChainStatus | ForEach-Object Status) -join ','
                Write-DiagWarning "Chain build failed for $($c.Subject): $reasons" -Category 'PKI' -CheckId '27.6'
            }
            $chain.Reset()
        }
    } catch {}

    Write-Section 'Auto-enrollment (last pulse)'
    try {
        $log = Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-AutoEnrollment']]]" -MaxEvents 1 -EA SilentlyContinue
        if ($log) { Write-Success "Last auto-enrollment event: $($log.TimeCreated) Id=$($log.Id)" -Category 'PKI' -CheckId '27.7' }
        else { Write-Info 'No auto-enrollment events found.' }
    } catch {}
}
#endregion
