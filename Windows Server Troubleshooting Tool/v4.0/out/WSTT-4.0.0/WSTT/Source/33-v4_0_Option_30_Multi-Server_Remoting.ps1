# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 30: Multi-Server Remoting
# Source lines: 8821 - 8896
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 30: Multi-Server Remoting
function Invoke-MultiServerRemotingMenu {
    <#
    .SYNOPSIS
        Interactive helper to fan out v4.0 checks to multiple servers via PSRemoting.
    #>
    [CmdletBinding()] param()
    Write-Header 'MULTI-SERVER REMOTING MODE (Option 30)'
    $servers = Read-Host 'Enter target server names (comma-separated)'
    if ([string]::IsNullOrWhiteSpace($servers)) { Write-DiagWarning 'No servers supplied.'; return }
    $list = $servers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $credPath = Read-Host 'Path to DPAPI clixml credential (Enter to use current user)'
    $cred = $null
    if ($credPath -and (Test-Path $credPath)) {
        try { $cred = Import-Clixml $credPath } catch { Write-DiagError "Cred import failed: $($_.Exception.Message)"; return }
    }
    $cat  = Read-Host 'Categories (e.g. ModernSecurity,Server2025,All)'
    if (-not $cat) { $cat = 'All' }
    $catArr = $cat -split ',' | ForEach-Object { $_.Trim() }
    Invoke-WSTTRemote -ComputerName $list -Credential $cred -Categories $catArr -ThrottleLimit $ThrottleLimit
}

function Invoke-WSTTRemote {
    <#
    .SYNOPSIS
        Executes selected v4.0 check functions against remote servers in parallel.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string[]]$ComputerName,
        [pscredential]$Credential,
        [string[]]$Categories = @('All'),
        [int]$ThrottleLimit = 8
    )
    $checkMap = @{
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
    if (-not $selected) { Write-DiagWarning 'No applicable categories selected.'; return }

    $sessionParams = @{ ComputerName = $ComputerName; ErrorAction = 'Continue' }
    if ($Credential) { $sessionParams.Credential = $Credential }
    $sessionParams.SessionOption = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 120000

    Write-Info "Fanning out to $($ComputerName.Count) server(s) for: $($selected -join ',')"
    $sessions = @()
    try {
        $sessions = New-PSSession @sessionParams
        if (-not $sessions) { Write-DiagError 'No PSSessions established.'; return }

        $scriptBlock = {
            param($scriptText, $checks)
            # Execute the v4.0 module text on the remote, then call selected functions.
            Invoke-Expression $scriptText
            $results = @()
            foreach ($fn in $checks) {
                try { & $fn | Out-Null } catch { }
            }
            return ,(Get-Findings)
        }
        $scriptText = Get-Content -Path $PSCommandPath -Raw
        $remoteFns  = $selected | ForEach-Object { $checkMap[$_] }
        $r = Invoke-Command -Session $sessions -ScriptBlock $scriptBlock -ArgumentList $scriptText, $remoteFns -ThrottleLimit $ThrottleLimit
        Write-Success "Collected $(@($r).Count) finding-set(s) from remote hosts."
        foreach ($set in $r) { foreach ($f in $set) { [void]$script:Findings.Add($f) } }
    } finally {
        if ($sessions) { Remove-PSSession $sessions -ErrorAction SilentlyContinue }
    }
}
#endregion
