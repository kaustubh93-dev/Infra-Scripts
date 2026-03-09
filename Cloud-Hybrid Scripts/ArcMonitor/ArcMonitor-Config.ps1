<#
.SYNOPSIS
    Arc Monitor Configuration Module
.DESCRIPTION
    Centralized configuration for Azure Arc Bootstrap Monitor.
    Edit this file to match your environment before running any monitor scripts.
#>

# ─── Azure Identity ────────────────────────────────────────────────────────────
$ArcConfig = @{
    TenantId       = "<YOUR-TENANT-ID>"
    SubscriptionId = "<YOUR-SUBSCRIPTION-ID>"
    ResourceGroup  = "rg-arc-onboarding"
    Location       = "eastus"
    Cloud          = "AzureCloud"              # AzureCloud | AzureUSGovernment | AzureChinaCloud

    # Service Principal (for at-scale / automated onboarding)
    ServicePrincipal = @{
        AppId  = "<YOUR-SP-APP-ID>"
        Secret = "<YOUR-SP-SECRET>"            # Use Key Vault in production!
    }

    # Proxy (optional)
    ProxyServer = $null                        # e.g. "http://proxy.corp.local:8080"
}

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
    WindowsAgent = "https://aka.ms/azcmagent-windows"
    LinuxAgent   = "https://aka.ms/azcmagent"
    ArcInstaller = "https://aka.ms/AzsHCIARCInstallerModule"
}

# ─── Export ──────────────────────────────────────────────────────────────────────
$Global:ArcMonitorConfig = @{
    Arc          = $ArcConfig
    AzureLocal   = $AzureLocalConfig
    VMware       = $VMwareConfig
    OnPrem       = $OnPremConfig
    Monitor      = $MonitorSettings
    AgentURLs    = $AgentURLs
}

Write-Host "✓ Arc Monitor configuration loaded." -ForegroundColor Green
