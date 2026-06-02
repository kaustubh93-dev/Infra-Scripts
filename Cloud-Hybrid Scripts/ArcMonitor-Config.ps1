<#
.SYNOPSIS
    Arc Monitor Configuration Module
.DESCRIPTION
    Centralized configuration for Azure Arc Bootstrap Monitor.
    Edit this file to match your environment before running any monitor scripts.
    Values can also be set via the Setup Wizard: .\Start-ArcMonitor.ps1 -Mode Setup
#>

# ─── Azure Identity ────────────────────────────────────────────────────────────
$ArcConfig = @{
    TenantId       = "<YOUR-TENANT-ID>"
    SubscriptionId = "<YOUR-SUBSCRIPTION-ID>"
    ResourceGroup  = "rg-arc-onboarding"
    Location       = "eastus"
    Cloud          = "AzureCloud"              # AzureCloud | AzureUSGovernment | AzureChinaCloud
    AuthType       = "principal"               # principal | token | interactive
    CorrelationId  = ""                        # Optional — for tracking in Azure Arc logs

    # Service Principal (for at-scale / automated onboarding)
    # SECURITY: Prefer loading secrets from DPAPI-encrypted file (ArcSPN-Credentials.xml)
    #           or Azure Key Vault. Plaintext secrets here are for dev/test ONLY.
    ServicePrincipal = @{
        AppId  = "<YOUR-SP-APP-ID>"
        Secret = "<YOUR-SP-SECRET>"            # ⚠ Use Key Vault or Export-Clixml in production!
    }

    # Proxy (optional)
    ProxyServer = $null                        # e.g. "http://proxy.corp.local:8080"
}

# ─── Set environment variables for onboarding scripts ───────────────────────────
# These env vars are used by the Azure Arc onboarding agent (azcmagent connect)
$env:SUBSCRIPTION_ID = $ArcConfig.SubscriptionId
$env:RESOURCE_GROUP  = $ArcConfig.ResourceGroup
$env:TENANT_ID       = $ArcConfig.TenantId
$env:LOCATION        = $ArcConfig.Location
$env:AUTH_TYPE       = $ArcConfig.AuthType
$env:CORRELATION_ID  = $ArcConfig.CorrelationId
$env:CLOUD           = $ArcConfig.Cloud

# Service Principal credentials (used by azcmagent connect --service-principal-id)
$ServicePrincipalId           = $ArcConfig.ServicePrincipal.AppId
$ServicePrincipalClientSecret = $ArcConfig.ServicePrincipal.Secret

# ─── Azure Local (Azure Stack HCI) Nodes ───────────────────────────────────────
$AzureLocalConfig = @{
    Nodes = @(
        @{ Name = "hci-node-01"; IP = "10.0.0.11" }
        @{ Name = "hci-node-02"; IP = "10.0.0.12" }
        # Add more nodes as needed
    )
    Credential     = $null                     # Set via Get-Credential at runtime
    SolutionVersion = $null                    # e.g. "10.2505.0.x" — leave null for latest
}

# ─── VMware vSphere Environment ─────────────────────────────────────────────────
$VMwareConfig = @{
    vCenterServer  = "vcenter.corp.local"
    vCenterCred    = $null                     # Set via Get-Credential at runtime
    GuestCred      = $null                     # Guest OS credential for VM operations
    TargetVMs      = @(
        # Populate from vCenter or list manually
        # @{ Name = "vm-web-01"; GuestOS = "Windows" }
        # @{ Name = "vm-db-01";  GuestOS = "Linux" }
    )
    # Filter for auto-discovery (alternative to manual list)
    VMFilter = @{
        Folder    = $null                      # e.g. "Production VMs"
        Tag       = $null                      # e.g. "arc-onboard"
        Cluster   = $null                      # e.g. "Prod-Cluster"
    }
}

# ─── General On-Prem Servers ────────────────────────────────────────────────────
$OnPremConfig = @{
    Servers = @(
        @{ Name = "srv-app-01"; IP = "10.1.0.21"; OS = "Windows"; Protocol = "WinRM" }
        @{ Name = "srv-app-02"; IP = "10.1.0.22"; OS = "Windows"; Protocol = "WinRM" }
        @{ Name = "srv-linux-01"; IP = "10.1.0.31"; OS = "Linux"; Protocol = "SSH" }
        # Add more servers as needed
    )
    WinRMCredential = $null                    # Set via Get-Credential at runtime
    SSHKeyPath      = "~/.ssh/id_rsa"          # For Linux servers
    SSHUser         = "arcadmin"
}

# ─── Monitor Dashboard Settings ─────────────────────────────────────────────────
$MonitorSettings = @{
    PollIntervalSeconds = 60                   # How often to refresh status
    MaxPolls            = 120                  # Maximum poll attempts before timeout
    LogPath             = ".\ArcMonitor\Logs"  # Log file directory
    EnableLogging       = $true
    ShowDownloadProgress = $true
    ShowEvents          = $true
    AnimateHeader       = $true
}

# ─── Agent Download URLs ─────────────────────────────────────────────────────────
$AgentURLs = @{
    WindowsAgent    = "https://gbl.his.arc.azure.com/azcmagent-windows"
    WindowsAgentAlt = "https://aka.ms/azcmagent-windows"
    LinuxAgent      = "https://aka.ms/azcmagent"
    ArcInstaller    = "https://aka.ms/AzsHCIARCInstallerModule"
}

# ─── Onboarding Command Template ────────────────────────────────────────────────
# This is the azcmagent connect command used by all monitor scripts.
# Changing it here changes the command everywhere.
$ArcConnectArgs = @{
    Windows = @(
        "--service-principal-id", $ServicePrincipalId,
        "--service-principal-secret", $ServicePrincipalClientSecret,
        "--resource-group", $env:RESOURCE_GROUP,
        "--tenant-id", $env:TENANT_ID,
        "--location", $env:LOCATION,
        "--subscription-id", $env:SUBSCRIPTION_ID,
        "--cloud", $env:CLOUD
    )
    Linux = @(
        "--service-principal-id", $ServicePrincipalId,
        "--service-principal-secret", $ServicePrincipalClientSecret,
        "--resource-group", $env:RESOURCE_GROUP,
        "--tenant-id", $env:TENANT_ID,
        "--location", $env:LOCATION,
        "--subscription-id", $env:SUBSCRIPTION_ID,
        "--cloud", $env:CLOUD
    )
}
if ($env:CORRELATION_ID) {
    $ArcConnectArgs.Windows += @("--correlation-id", $env:CORRELATION_ID)
    $ArcConnectArgs.Linux   += @("--correlation-id", $env:CORRELATION_ID)
}

# ─── Secure Credential Loader ────────────────────────────────────────────────
# Attempts to load SP credentials from DPAPI-encrypted XML file (created by Setup Wizard).
# Falls back to values in $ArcConfig if encrypted file is not available.
$credXmlPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "ArcSPN-Credentials.xml"
if (Test-Path $credXmlPath) {
    try {
        $savedCred = Import-Clixml -Path $credXmlPath -ErrorAction Stop
        if ($savedCred.AppId -and $savedCred.Secret) {
            $ArcConfig.ServicePrincipal.AppId = $savedCred.AppId
            # Decrypt SecureString to plain text only when needed
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($savedCred.Secret)
            $ArcConfig.ServicePrincipal.Secret = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $ServicePrincipalId           = $ArcConfig.ServicePrincipal.AppId
            $ServicePrincipalClientSecret = $ArcConfig.ServicePrincipal.Secret
            Write-Host "  ✓ Loaded SP credentials from encrypted store." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ⚠ Could not load encrypted credentials: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Using values from ArcMonitor-Config.ps1 instead." -ForegroundColor DarkGray
    }
}

# ─── Export ──────────────────────────────────────────────────────────────────────
$script:ArcMonitorConfig = @{
    Arc          = $ArcConfig
    AzureLocal   = $AzureLocalConfig
    VMware       = $VMwareConfig
    OnPrem       = $OnPremConfig
    Monitor      = $MonitorSettings
    AgentURLs    = $AgentURLs
    ConnectArgs  = $ArcConnectArgs
}

# Clean up environment variables after export (minimize credential leakage window)
# These will be re-read from $ArcConfig when needed
Remove-Item Env:\SUBSCRIPTION_ID -ErrorAction SilentlyContinue
Remove-Item Env:\RESOURCE_GROUP -ErrorAction SilentlyContinue
Remove-Item Env:\TENANT_ID -ErrorAction SilentlyContinue

Write-Host "  Arc Monitor configuration loaded." -ForegroundColor Green
