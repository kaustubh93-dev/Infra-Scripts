# Get Cluster Name from Registry
$clusterName = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\ClusSvc\Parameters" -Name "ClusterName" -ErrorAction SilentlyContinue).ClusterName
if ($clusterName) {
    Write-Output "Cluster Name: $clusterName"
} else {
    Write-Output "Cluster Name not found in registry"
}


# Method 1: Using Failover Clustering PowerShell Module (Recommended)
# This is the cleanest approach if the module is available

# Get File Share Witness resource and its SharePath
$fswResource = Get-ClusterResource | Where-Object {$_.ResourceType -eq "File Share Witness"}
if ($fswResource) {
    $sharePath = ($fswResource | Get-ClusterParameter -Name "SharePath").Value
    Write-Output "File Share Witness Resource: $($fswResource.Name)"
    Write-Output "Resource GUID: $($fswResource.Id)"
    Write-Output "Share Path: $sharePath"
} else {
    Write-Output "No File Share Witness resource found"
}


# Method 2: One-liner to get just the SharePath
# If you just want the SharePath value quickly

(Get-ClusterResource | Where-Object {$_.ResourceType -eq "File Share Witness"} | Get-ClusterParameter -Name "SharePath").Value

