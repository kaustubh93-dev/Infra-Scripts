# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: IIS Diagnostics
# Source lines: 6712 - 7007
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region IIS Diagnostics
function Test-IISHealth {
    <#
    .SYNOPSIS
        Performs comprehensive IIS health checks
    .DESCRIPTION
        Checks IIS services, AppPools, Websites, and Worker Processes.
    #>
    [CmdletBinding()]
    param()
    Write-Header "IIS Health Diagnostics"
    
    # Declare at function scope for reuse across check sections
    $appPools = $null
    $sites = $null
    
    # Check if we can determine if IIS is installed (WindowsFeature module might not be available everywhere, so wrap it or ignore)
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $iisInstalled = Get-WindowsFeature -Name Web-Server -ErrorAction Stop
            if (-not $iisInstalled -or $iisInstalled.Installed -eq $false) {
                Write-DiagWarning "IIS Web-Server role is not installed."
                return
            }
        }
    }
    catch {}
    
    # Import WebAdministration
    try {
        Import-Module WebAdministration -ErrorAction Stop
    }
    catch {
        Write-DiagWarning "Could not import WebAdministration module. IIS feature may be missing or corrupt (Requires PowerShell 5.1/Windows). Execute from 64-bit PowerShell if possible."
        return
    }

    # 1. Check IIS Services
    Write-Section "IIS Core Services Status"
    $iisServices = @("W3SVC", "WAS", "IISADMIN")
    foreach ($svc in $iisServices) {
        try {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -eq 'Running') {
                    Write-Success "Service '$svc' is Running."
                }
                else {
                    Write-DiagWarning "Service '$svc' is $($service.Status)."
                }
            }
            else {
                Write-DiagWarning "Service '$svc' not found."
            }
        }
        catch {
            Write-DiagWarning "Failed to query service '$svc'."
        }
    }

    # 2. Check AppPools
    Write-Section "Application Pools"
    try {
        if (Test-Path "IIS:\AppPools") {
            $appPools = Get-ChildItem "IIS:\AppPools" -ErrorAction SilentlyContinue
            if ($appPools) {
                foreach ($pool in $appPools) {
                    $state = $pool.state
                    $identity = $pool.processModel.identityType
                    if ($state -eq 'Started') {
                        Write-Success "AppPool: $($pool.Name) | State: $state | Identity: $identity"
                    }
                    else {
                        Write-DiagWarning "AppPool: $($pool.Name) | State: $state | Identity: $identity"
                    }
                }
            }
            else {
                Write-Info "No Application Pools found."
            }
        }
        else {
            Write-DiagWarning "IIS:\AppPools path not found. Is IIS configured correctly?"
        }
    }
    catch {
        Write-DiagError "Error checking Application Pools: $($_.Exception.Message)"
    }

    # 3. Check Websites
    Write-Section "Websites"
    try {
        if (Test-Path "IIS:\Sites") {
            $sites = Get-ChildItem "IIS:\Sites" -ErrorAction SilentlyContinue
            if ($sites) {
                foreach ($site in $sites) {
                    $state = $site.state
                    $bindings = ($site.bindings.Collection | ForEach-Object { "$($_.protocol)://$($_.bindingInformation)" }) -join ", "
                    $path = $site.physicalPath
                    if ($state -eq 'Started') {
                        Write-Success "Site: $($site.Name) | State: $state | Bindings: $bindings | Path: $path"
                    }
                    else {
                        Write-DiagWarning "Site: $($site.Name) | State: $state | Bindings: $bindings | Path: $path"
                    }
                }
            }
            else {
                Write-Info "No Websites found."
            }
        }
    }
    catch {
        Write-DiagError "Error checking Websites: $($_.Exception.Message)"
    }

    # 4. Check Worker Processes
    Write-Section "IIS Worker Processes (w3wp.exe)"
    try {
        $w3wps = Get-Process -Name w3wp -ErrorAction SilentlyContinue
        if ($w3wps) {
            foreach ($wp in $w3wps) {
                # Attempt to get the AppPool Name from CommandLine
                $appPoolName = "Unknown"
                try {
                    $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($wp.Id)" -ErrorAction Stop
                    if ($wmiProc.CommandLine -match "-ap `"(?<AppPool>[^`"]+)`"") {
                        $appPoolName = $Matches['AppPool']
                    }
                    elseif ($wmiProc.CommandLine -match "-ap (?<AppPool>\S+)") {
                        $appPoolName = $Matches['AppPool']
                    }
                }
                catch {}
                
                $memMB = [math]::Round($wp.WorkingSet64 / 1MB, 2)
                $cpuStr = if ($wp.CPU) { [math]::Round($wp.CPU, 2) } else { "N/A" }
                Write-Info "PID: $($wp.Id) | AppPool: $appPoolName | Memory: $memMB MB | CPU Time: $cpuStr sec"
            }
        }
        else {
            Write-Info "No w3wp.exe worker processes currently running."
        }
    }
    catch {
        Write-DiagError "Error checking worker processes: $($_.Exception.Message)"
    }

    # 5. Check AppPool Identities & Permissions
    Write-Section "AppPool Identities & Permissions"
    try {
        if ($appPools) {
            foreach ($pool in $appPools) {
                if ($pool.processModel.identityType -eq 'SpecificUser') {
                    $userName = $pool.processModel.userName
                    Write-Info "AppPool '$($pool.Name)' uses custom identity: $userName"
                    # Check if it's a local user and warn
                    if ($userName -match "^[^\\]+$" -or $userName -match "^\.\\") {
                        $cleanName = $userName -replace "^\.\\", ""
                        $localUser = Get-LocalUser -Name $cleanName -ErrorAction SilentlyContinue
                        if ($localUser) {
                            Write-Success "Local user account '$cleanName' exists."
                        }
                        else {
                            Write-DiagWarning "Local user account '$cleanName' not found. AppPool may fail to start."
                        }
                    }
                    else {
                        Write-Info "Domain/External account detected. Ensure password is not expired and account has 'Log on as a batch job' rights."
                    }
                }
                else {
                    # Built-in identity
                    Write-Success "AppPool '$($pool.Name)' uses built-in identity ($($pool.processModel.identityType))."
                }
            }
        }
        else {
            Write-Info "No Application Pools to check identities for."
        }
    }
    catch {
        Write-DiagError "Error checking AppPool identities: $($_.Exception.Message)"
    }

    # 6. Check Site Authentication Methods
    Write-Section "Site Authentication Methods"
    try {
        if ($sites) {
            foreach ($site in $sites) {
                $siteName = $site.Name
                $authMethods = @()
                
                $anon = Get-WebConfigurationProperty -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name enabled -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                if ($anon -and $anon.Value -eq $true) { $authMethods += "Anonymous" }
                
                $basic = Get-WebConfigurationProperty -Filter 'system.webServer/security/authentication/basicAuthentication' -Name enabled -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                if ($basic -and $basic.Value -eq $true) { $authMethods += "Basic" }
                
                $win = Get-WebConfigurationProperty -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name enabled -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                if ($win -and $win.Value -eq $true) { $authMethods += "Windows" }
                
                if ($authMethods.Count -gt 0) {
                    Write-Info "Site '$siteName' enabled authentication: $($authMethods -join ', ')"
                }
                else {
                    Write-DiagWarning "Site '$siteName' has no primary authentication methods enabled (or could not read config)."
                }
            }
        }
    }
    catch {
        Write-DiagError "Error checking authentication: $($_.Exception.Message)"
    }

    # 7. Check SSL/TLS Certificate Validation
    Write-Section "SSL/TLS Certificates"
    try {
        if ($sites) {
            $checkedHashes = @()
            foreach ($site in $sites) {
                # Look for https bindings
                $httpsBindings = $site.bindings.Collection | Where-Object { $_.protocol -eq 'https' }
                foreach ($binding in $httpsBindings) {
                    $hashStr = ""
                    if ($null -ne $binding.certificateHash) {
                        if ($binding.certificateHash -is [byte[]]) {
                            $hashStr = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
                        }
                        else {
                            $hashStr = $binding.certificateHash.ToString() -replace " ", ""
                        }
                    }
                    
                    if ($hashStr) {
                        if ($checkedHashes -notcontains $hashStr) {
                            $checkedHashes += $hashStr
                             
                            # Search local machine stores
                            $cert = Get-ChildItem -Path Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $hashStr } | Select-Object -First 1
                             
                            if ($cert) {
                                $daysRemaining = ($cert.NotAfter - (Get-Date)).Days
                                if ($daysRemaining -lt 0) {
                                    Write-DiagError "Certificate for '$($site.Name)' is EXPIRED! (Thumbprint: $hashStr, Expired on: $($cert.NotAfter))"
                                }
                                elseif ($daysRemaining -lt 30) {
                                    Write-DiagWarning "Certificate for '$($site.Name)' expires in $daysRemaining days. (Expires: $($cert.NotAfter))"
                                }
                                else {
                                    Write-Success "Certificate for '$($site.Name)' is valid ($daysRemaining days remaining)."
                                }
                            }
                            else {
                                Write-DiagWarning "Bound certificate for '$($site.Name)' (Thumbprint: $hashStr) not found in Local Machine stores. (Check binding correctness)"
                            }
                        }
                    }
                }
            }
            if ($checkedHashes.Count -eq 0) {
                Write-Info "No HTTPS bindings found."
            }
        }
    }
    catch {
        Write-DiagError "Error checking certificates: $($_.Exception.Message)"
    }

    # 8. Check IP Restrictions
    Write-Section "IP Security Restrictions"
    try {
        if ($sites) {
            foreach ($site in $sites) {
                $siteName = $site.Name
                $ipSec = Get-WebConfigurationProperty -Filter 'system.webServer/security/ipSecurity' -Name allowUnlisted -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                if ($ipSec -and $ipSec.Value -eq $false) {
                    Write-DiagWarning "Site '$siteName' has 'allowUnlisted' IP security set to FALSE. Unlisted IPs are blocked."
                }
                else {
                    # Check for explicit deny rules
                    $denyRules = Get-WebConfiguration -Filter 'system.webServer/security/ipSecurity/add[@allowed="false"]' -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
                    if ($denyRules) {
                        $count = @($denyRules).Count
                        Write-DiagWarning "Site '$siteName' has $count explicit IP deny rules configured."
                    }
                    else {
                        Write-Success "Site '$siteName' has no primary IP restrictions blocking unlisted traffic."
                    }
                }
            }
        }
    }
    catch {
        Write-DiagError "Error checking IP restrictions: $($_.Exception.Message)"
    }
}
#endregion
