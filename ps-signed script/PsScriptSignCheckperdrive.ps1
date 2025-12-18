# Define paths to exclude (system directories that cause access issues)
$excludePaths = @(
$excludePaths = @(
    "C:\Windows",
    "C:\Windows\winsxs", 
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Program Files\WindowsApps",
    "C:\$Recycle.Bin"
    "C:\Packages\Plugins"
    "C:\Program Files\Microsoft Monitoring Agent"
    "C:\Program Files\WindowsPowerShell"
    "C:\Program Files (x86)\WindowsPowerShell\Modules"
                 )
                 )
# Script to find all PowerShell files across the server
$PowerShellExtensions = @("*.ps1")
$AllScripts = @()

foreach ($extension in $PowerShellExtensions) {
    Write-Host "Searching for $extension files..." -ForegroundColor Yellow
    $scripts = Get-ChildItem -Path D:\ -Recurse -Include $extension -ErrorAction SilentlyContinue | 
        Where-Object {
            $fullPath = $_.FullName
            # Exclude if path starts with any excluded folder (case-insensitive)
            -not ($excludePaths | Where-Object { $fullPath.StartsWith($_, [System.StringComparison]::InvariantCultureIgnoreCase) })
        }
    $AllScripts += $scripts
}

Write-Host "Found $($AllScripts.Count) PowerShell files total" -ForegroundColor Green
$AllScripts | Select-Object FullName, Length, LastWriteTime | Export-Csv -Path "C:\PowerShell_Inventory.csv" -NoTypeInformation

# Script to verify signatures of PowerShell files
$UnsignedScripts = @()
$SignedScripts = @()

# Import the inventory from previous step
$AllScripts = Import-Csv -Path "C:\PowerShell_Inventory.csv"

foreach ($script in $AllScripts) {
    try {
        $signature = Get-AuthenticodeSignature -FilePath $script.FullName
        $scriptInfo = [PSCustomObject]@{
            FilePath = $script.FullName
            SignatureStatus = $signature.Status
            SignerCertificate = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "None" }
            TimeStamperCertificate = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { "None" }
        }
        
        if ($signature.Status -eq 'Valid') {
            $SignedScripts += $scriptInfo
            Write-Host "$($script.FullName) : SIGNED" -ForegroundColor Green
        } else {
            $UnsignedScripts += $scriptInfo
            Write-Host "$($script.FullName) : UNSIGNED" -ForegroundColor Red
        }
    }
    catch {
        Write-Warning "Could not check signature for: $($script.FullName)"
    }
}

# Export results
$UnsignedScripts | Export-Csv -Path "C:\Unsigned_Scripts.csv" -NoTypeInformation
$SignedScripts | Export-Csv -Path "C:\Signed_Scripts.csv" -NoTypeInformation

Write-Host "`nSummary:" -ForegroundColor Yellow
Write-Host "Signed Scripts: $($SignedScripts.Count)" -ForegroundColor Green
Write-Host "Unsigned Scripts: $($UnsignedScripts.Count)" -ForegroundColor Red
