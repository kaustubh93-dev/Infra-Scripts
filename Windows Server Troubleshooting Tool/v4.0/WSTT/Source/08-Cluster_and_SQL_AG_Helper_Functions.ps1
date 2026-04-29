# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Cluster and SQL AG Helper Functions
# Source lines: 691 - 885
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Cluster and SQL AG Helper Functions
function Get-ClusterEnvironmentInfo {
    <#
    .SYNOPSIS
        Detects cluster membership, role, and SQL AG state for the local node
    .DESCRIPTION
        Returns a hashtable with IsClusterNode, ClusterName, NodeName, 
        IsAGInstalled, AGReplicas, and ClusterNetworks information.
        All downstream checks should use this cached result.
    .OUTPUTS
        Hashtable with cluster and AG environment details
    #>
    $info = @{
        IsClusterNode      = $false
        ClusterName        = $null
        NodeName           = $env:COMPUTERNAME
        ClusterNodes       = @()
        ClusterNetworks    = @()
        HeartbeatOnlyNICs  = @()
        CSVPaths           = @()
        QuorumType         = $null
        QuorumResource     = $null
        IsCAUEnabled       = $false
        IsAGInstalled      = $false
        AGDetails          = @()
        LocalReplicaRole   = $null
    }

    # Check if Failover Clustering is running
    try {
        $clusSvc = Get-Service -Name "ClusSvc" -ErrorAction SilentlyContinue
        if ($null -eq $clusSvc -or $clusSvc.Status -ne "Running") {
            return $info
        }
        $info.IsClusterNode = $true
    }
    catch { return $info }

    # Cluster basics
    try {
        $cluster = Get-Cluster -ErrorAction Stop
        $info.ClusterName = $cluster.Name
        $info.ClusterNodes = @(Get-ClusterNode -ErrorAction SilentlyContinue | Select-Object Name, State, NodeWeight)
    }
    catch { }

    # Cluster networks — identify heartbeat-only NICs
    try {
        $networks = Get-ClusterNetwork -ErrorAction SilentlyContinue
        $info.ClusterNetworks = @($networks)
        # Role 1 = Cluster only (heartbeat), Role 3 = Cluster and Client
        $info.HeartbeatOnlyNICs = @($networks | Where-Object { $_.Role -eq 1 } |
            ForEach-Object {
                $netName = $_.Name
                try {
                    $adapters = Get-ClusterNetworkInterface -Network $netName -ErrorAction SilentlyContinue
                    $adapters | Where-Object { $_.Node -eq $env:COMPUTERNAME } | ForEach-Object { $_.Adapter }
                }
                catch { }
            })
    }
    catch { }

    # Cluster Shared Volumes
    try {
        $csvs = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
        $info.CSVPaths = @($csvs | ForEach-Object {
                $_.SharedVolumeInfo.FriendlyVolumeName
            })
    }
    catch { }

    # Quorum
    try {
        $quorum = Get-ClusterQuorum -ErrorAction SilentlyContinue
        if ($quorum) {
            $info.QuorumType = $quorum.QuorumType
            $info.QuorumResource = if ($quorum.QuorumResource) { $quorum.QuorumResource.Name } else { "(none)" }
        }
    }
    catch { }

    # Cluster-Aware Updating
    try {
        $cauRun = Get-CauRun -ErrorAction SilentlyContinue
        if ($null -ne $cauRun -and $cauRun.Status -ne 'Completed' -and $cauRun.Status -ne 'NotStarted') {
            $info.IsCAUEnabled = $true
        }
    }
    catch { }

    # SQL AG Detection
    try {
        $sqlSvc = Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue
        if ($null -ne $sqlSvc -and $sqlSvc.Status -eq "Running") {
            $info.IsAGInstalled = $true
            try {
                $agQuery = @"
SELECT ag.name AS ag_name,
       ars.role_desc AS local_role,
       ars.synchronization_health_desc AS sync_health,
       al.dns_name AS listener_name,
       al.port AS listener_port
FROM sys.dm_hadr_availability_replica_states ars
JOIN sys.availability_groups ag ON ars.group_id = ag.group_id
LEFT JOIN sys.availability_group_listeners al ON ag.group_id = al.group_id
WHERE ars.is_local = 1
"@
                $agResults = Invoke-Sqlcmd -Query $agQuery -ServerInstance "." -ConnectionTimeout 5 -QueryTimeout 10 -ErrorAction Stop
                $info.AGDetails = @($agResults)
                if ($agResults.Count -gt 0) {
                    $info.LocalReplicaRole = $agResults[0].local_role
                }
            }
            catch {
                # Invoke-Sqlcmd may not be available; try SqlClient directly
                try {
                    $conn = New-Object System.Data.SqlClient.SqlConnection "Server=.;Integrated Security=True;Connection Timeout=5"
                    $conn.Open()
                    $cmd = $conn.CreateCommand()
                    $cmd.CommandText = "SELECT ag.name AS ag_name, ars.role_desc AS local_role, ars.synchronization_health_desc AS sync_health FROM sys.dm_hadr_availability_replica_states ars JOIN sys.availability_groups ag ON ars.group_id = ag.group_id WHERE ars.is_local = 1"
                    $reader = $cmd.ExecuteReader()
                    while ($reader.Read()) {
                        $info.AGDetails += [PSCustomObject]@{
                            ag_name       = $reader["ag_name"]
                            local_role    = $reader["local_role"]
                            sync_health   = $reader["sync_health"]
                            listener_name = $null
                            listener_port = $null
                        }
                        $info.LocalReplicaRole = $reader["local_role"]
                    }
                    $reader.Close()
                    $conn.Close()
                }
                catch { }
            }
        }
    }
    catch { }

    return $info
}

function Test-PathOnCSV {
    <#
    .SYNOPSIS
        Checks if a given path resides on a Cluster Shared Volume
    .PARAMETER Path
        The file system path to validate
    .PARAMETER CSVPaths
        Array of CSV mount points from Get-ClusterEnvironmentInfo
    .OUTPUTS
        Boolean — $true if path is on a CSV
    #>
    param(
        [string]$Path,
        [string[]]$CSVPaths
    )
    if (-not $CSVPaths -or $CSVPaths.Count -eq 0) { return $false }
    foreach ($csv in $CSVPaths) {
        if ($Path -like "$csv*") { return $true }
    }
    return $false
}

function Get-NonHeartbeatGateways {
    <#
    .SYNOPSIS
        Returns default gateways excluding cluster heartbeat-only networks
    .PARAMETER HeartbeatAdapters
        Array of adapter names that are cluster heartbeat-only
    #>
    param(
        [string[]]$HeartbeatAdapters = @()
    )
    try {
        $gateways = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop
        if ($HeartbeatAdapters.Count -eq 0) { return $gateways }
        $filtered = @()
        foreach ($gw in $gateways) {
            $ifAlias = (Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object { $_.ifIndex -eq $gw.InterfaceIndex }).Name
            if ($ifAlias -notin $HeartbeatAdapters) {
                $filtered += $gw
            }
            else {
                Write-Info "  Skipping heartbeat-only adapter '$ifAlias' for gateway ping"
            }
        }
        return $filtered
    }
    catch { return @() }
}
#endregion
