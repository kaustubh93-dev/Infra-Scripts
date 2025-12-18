# Export Shares
Get-SmbShare | Export-Csv C:\temp\shares.csv -NoTypeInformation

# Export Share ACLs
Get-SmbShare | ForEach-Object {
    Get-SmbShareAccess -Name $_.Name |
        Select @{n='Share';e={$_.Name}}, AccountName, AccessRight, AccessControlType
} | Export-Csv C:\temp\share_acls.csv -NoTypeInformation

# Export NTFS Permissions for all shares
$results = @()

Get-SmbShare | Where-Object { $_.Path -and (Test-Path $_.Path) } | ForEach-Object {
    $shareName = $_.Name
    $sharePath = $_.Path
    
    Write-Host "Processing NTFS permissions for share: $shareName ($sharePath)"
    
    try {
        $acl = Get-Acl -Path $sharePath
        
        foreach ($access in $acl.Access) {
            $results += [PSCustomObject]@{
                Share = $shareName
                Path = $sharePath
                IdentityReference = $access.IdentityReference
                FileSystemRights = $access.FileSystemRights
                AccessControlType = $access.AccessControlType
                IsInherited = $access.IsInherited
                InheritanceFlags = $access.InheritanceFlags
                PropagationFlags = $access.PropagationFlags
            }
        }
    }
    catch {
        Write-Warning "Failed to get NTFS permissions for $shareName ($sharePath): $($_.Exception.Message)"
        
        # Add error entry to results
        $results += [PSCustomObject]@{
            Share = $shareName
            Path = $sharePath
            IdentityReference = "ERROR"
            FileSystemRights = $_.Exception.Message
            AccessControlType = "N/A"
            IsInherited = "N/A"
            InheritanceFlags = "N/A"
            PropagationFlags = "N/A"
        }
    }
}

# Export NTFS permissions to CSV
$results | Export-Csv C:\temp\share_ntfs.csv -NoTypeInformation

Write-Host "Export completed. Files created:"
Write-Host "- C:\temp\shares.csv"
Write-Host "- C:\temp\share_acls.csv" 
Write-Host "- C:\temp\share_ntfs.csv"