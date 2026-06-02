# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 OS Capability Cache (Phase 0)
# Source lines: 259 - 354
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 OS Capability Cache (Phase 0)
$script:_OSCapability = $null

function Get-OSCapability {
    <#
    .SYNOPSIS
        Returns a cached PSCustomObject describing the host's OS, edition,
        architecture, role inventory and Server-2025-feature flags.
    .DESCRIPTION
        Replaces scattered Get-CimInstance Win32_OperatingSystem / Get-WindowsFeature
        calls. Safe on workstation, Core, ARM64. Idempotent / cached.
    #>
    [CmdletBinding()] param([switch]$Refresh)
    if ($script:_OSCapability -and -not $Refresh) { return $script:_OSCapability }

    $os   = $null; $cs = $null; $cpu = $null
    try { $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {}
    try { $cs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction Stop } catch {}
    try { $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1 } catch {}

    $build = 0
    if ($os -and $os.BuildNumber) { [int]::TryParse($os.BuildNumber, [ref]$build) | Out-Null }

    $isServer  = $false
    if ($os) { $isServer = ($os.ProductType -ne 1) } # 1=Workstation, 2=DC, 3=Server
    $isDC      = ($os -and $os.ProductType -eq 2)
    $isCore    = $false
    try {
        $instType = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -EA SilentlyContinue).InstallationType
        $isCore   = ($instType -eq 'Server Core')
    } catch {}

    $arch = 'x64'
    if ($cpu) {
        switch ($cpu.Architecture) {
            0 { $arch = 'x86' }
            5 { $arch = 'ARM' }
            9 { $arch = 'x64' }
            12 { $arch = 'ARM64' }
            default { $arch = "Unknown($($cpu.Architecture))" }
        }
    }

    # Detect Azure Edition (used by Hotpatch / SMB-over-QUIC on 2022)
    $isAzureEdition = $false
    if ($os -and $os.Caption) { $isAzureEdition = ($os.Caption -match 'Azure Edition') }

    # Roles / features (best effort — Server only)
    $roles = @()
    if ($isServer -and (Get-Command Get-WindowsFeature -EA SilentlyContinue)) {
        try {
            $roles = @(Get-WindowsFeature -EA SilentlyContinue |
                       Where-Object { $_.Installed } | Select-Object -ExpandProperty Name)
        } catch {}
    }

    $script:_OSCapability = [pscustomobject]@{
        Caption        = if ($os) { $os.Caption } else { 'Unknown' }
        BuildNumber    = $build
        Version        = if ($os) { $os.Version } else { '' }
        IsServer       = $isServer
        IsDomainController = $isDC
        IsCore         = $isCore
        IsAzureEdition = $isAzureEdition
        Architecture   = $arch
        Manufacturer   = if ($cs) { $cs.Manufacturer } else { '' }
        Model          = if ($cs) { $cs.Model } else { '' }
        Domain         = if ($cs) { $cs.Domain } else { '' }
        Roles          = $roles
        Is2019         = ($build -ge 17763 -and $build -lt 20348)
        Is2022         = ($build -ge 20348 -and $build -lt 26100)
        Is2025         = ($build -ge 26100)
    }
    return $script:_OSCapability
}

function Test-WSTTHasRole {
    <#
    .SYNOPSIS
        Returns $true if the supplied Windows feature/role is installed.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    $cap = Get-OSCapability
    return ($cap.Roles -contains $Name)
}

function Test-WSTTCommand {
    <#
    .SYNOPSIS
        Wrapper for `Get-Command -EA SilentlyContinue` used by the new options
        to gracefully N/A when a cmdlet is missing on the running OS.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}
#endregion
