$server = $env:COMPUTERNAME
 
Invoke-Command -ComputerName $server -ScriptBlock {
 
# Get Cluster Name from Registry
$clusterName = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\ClusSvc\Parameters" -Name "ClusterName" -ErrorAction SilentlyContinue).ClusterName
# Get File Share Witness resource and its SharePath
$fswResource = Get-ClusterResource | Where-Object {$_.ResourceType -eq "File Share Witness"}
if ($fswResource) {
    $sharePath = ($fswResource | Get-ClusterParameter -Name "SharePath").Value
} else {
    $sharePath = "No File Share Witness found"
}
# Output in requested format
if ($clusterName -and $sharePath) {
    Write-Output "$clusterName | $sharePath"
} else {
    Write-Output "Data not available | Data not available"
}
}