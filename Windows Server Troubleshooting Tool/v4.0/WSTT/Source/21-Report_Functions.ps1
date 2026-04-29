# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Report Functions
# Source lines: 5985 - 6710
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Report Functions
function Show-ValidatorInfo {
    <#
    .SYNOPSIS
        Displays validator script information
    .DESCRIPTION
        Provides information about the validator script and its output
    #>
    Write-Header "Validator Script Information"
    Write-Info "The validator script generates HTML output with:"
    Write-Info "  * Key server sizing and specifications"
    Write-Info "  * High-level health status"
    Write-Info "  * Configuration details"
    Write-Info "`nOutput location: C:\Windows\ServerScanner"
    Write-Info "`nRequired: Run on ALL servers (cluster nodes or standalone)"
    Write-Info "Zip the ServerScanner folder and share for analysis"
}

function Test-TLSConfiguration {
    <#
    .SYNOPSIS
        Validates TLS configuration on the server
    .DESCRIPTION
        Checks enabled TLS protocols, cipher suites, and security configurations
    .EXAMPLE
        Test-TLSConfiguration
    #>
    [CmdletBinding()]
    param()
    Write-Header "TLS Configuration Validation"
    
    # TLS Registry Paths
    $tlsProtocols = @{
        "TLS 1.0" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
        "TLS 1.1" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
        "TLS 1.2" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
        "TLS 1.3" = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3"
    }
    
    Write-Info "Checking TLS Protocol Status..."
    Write-Info ""
    
    foreach ($protocol in $tlsProtocols.GetEnumerator()) {
        $protocolName = $protocol.Key
        $regPath = $protocol.Value
        
        Write-Info "--- $protocolName ---"
        
        # Check if protocol key exists
        if (Test-Path $regPath) {
            # Check Client settings
            $clientPath = Join-Path $regPath "Client"
            if (Test-Path $clientPath) {
                try {
                    $clientEnabled = Get-ItemProperty -Path $clientPath -Name "Enabled" -ErrorAction SilentlyContinue
                    $clientDisabledByDefault = Get-ItemProperty -Path $clientPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue
                    
                    if ($clientEnabled.Enabled -eq 1 -and $clientDisabledByDefault.DisabledByDefault -eq 0) {
                        Write-Success "  Client: ENABLED"
                    }
                    elseif ($clientEnabled.Enabled -eq 0 -or $clientDisabledByDefault.DisabledByDefault -eq 1) {
                        Write-DiagWarning "  Client: DISABLED"
                    }
                    else {
                        Write-Info "  Client: Not explicitly configured (using system default)"
                    }
                }
                catch {
                    Write-Info "  Client: Not explicitly configured (using system default)"
                }
            }
            else {
                Write-Info "  Client: Not explicitly configured (using system default)"
            }
            
            # Check Server settings
            $serverPath = Join-Path $regPath "Server"
            if (Test-Path $serverPath) {
                try {
                    $serverEnabled = Get-ItemProperty -Path $serverPath -Name "Enabled" -ErrorAction SilentlyContinue
                    $serverDisabledByDefault = Get-ItemProperty -Path $serverPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue
                    
                    if ($serverEnabled.Enabled -eq 1 -and $serverDisabledByDefault.DisabledByDefault -eq 0) {
                        Write-Success "  Server: ENABLED"
                    }
                    elseif ($serverEnabled.Enabled -eq 0 -or $serverDisabledByDefault.DisabledByDefault -eq 1) {
                        Write-DiagWarning "  Server: DISABLED"
                    }
                    else {
                        Write-Info "  Server: Not explicitly configured (using system default)"
                    }
                }
                catch {
                    Write-Info "  Server: Not explicitly configured (using system default)"
                }
            }
            else {
                Write-Info "  Server: Not explicitly configured (using system default)"
            }
        }
        else {
            Write-Info "  Protocol registry key does not exist (using system default)"
        }
        
        Write-Info ""
    }
    
    # Security Recommendations
    Write-Info "--- Security Recommendations ---"
    Write-DiagWarning "TLS 1.0 and TLS 1.1 are deprecated and should be disabled"
    Write-Success "TLS 1.2 should be enabled (minimum requirement)"
    Write-Success "TLS 1.3 should be enabled for best security (Windows Server 2022+)"
    Write-Info ""
    
    # Check .NET Framework TLS support
    Write-Info "--- .NET Framework TLS Support ---"
    try {
        $netFx4Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path) {
            $schUseStrongCrypto = Get-ItemProperty -Path $netFx4Path -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $systemDefaultTls = Get-ItemProperty -Path $netFx4Path -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
            
            if ($schUseStrongCrypto.SchUseStrongCrypto -eq 1) {
                Write-Success ".NET 4.x (32-bit): Strong Crypto ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (32-bit): Strong Crypto NOT enabled"
            }
            
            if ($systemDefaultTls.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (32-bit): System Default TLS ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (32-bit): System Default TLS NOT enabled"
            }
        }
        
        $netFx4Path64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path64) {
            $schUseStrongCrypto64 = Get-ItemProperty -Path $netFx4Path64 -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            $systemDefaultTls64 = Get-ItemProperty -Path $netFx4Path64 -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
            
            if ($schUseStrongCrypto64.SchUseStrongCrypto -eq 1) {
                Write-Success ".NET 4.x (64-bit): Strong Crypto ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (64-bit): Strong Crypto NOT enabled"
            }
            
            if ($systemDefaultTls64.SystemDefaultTlsVersions -eq 1) {
                Write-Success ".NET 4.x (64-bit): System Default TLS ENABLED"
            }
            else {
                Write-DiagWarning ".NET 4.x (64-bit): System Default TLS NOT enabled"
            }
        }
    }
    catch {
        Write-DiagError "Failed to check .NET Framework TLS configuration: $($_.Exception.Message)"
    }
    
    Write-Info ""
    
    # Check PowerShell TLS support
    Write-Info "--- PowerShell TLS Support ---"
    try {
        $securityProtocol = [Net.ServicePointManager]::SecurityProtocol
        Write-Info "Current PowerShell Session Security Protocol: $securityProtocol"
        
        if ($securityProtocol -match "Tls12") {
            Write-Success "TLS 1.2 is available in PowerShell"
        }
        else {
            Write-DiagWarning "TLS 1.2 is NOT configured in PowerShell"
            Write-Info "To enable: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
        }
        
        if ($securityProtocol -match "Tls13") {
            Write-Success "TLS 1.3 is available in PowerShell"
        }
    }
    catch {
        Write-DiagError "Failed to check PowerShell TLS configuration: $($_.Exception.Message)"
    }
    
    Write-Info ""
    
    # Check cipher suites
    Write-Info "--- TLS Cipher Suites ---"
    try {
        $cipherSuites = Get-TlsCipherSuite -ErrorAction SilentlyContinue
        if ($cipherSuites) {
            Write-Info "Total Cipher Suites Enabled: $($cipherSuites.Count)"
            Write-Info ""
            Write-Info "Top 10 Enabled Cipher Suites (by priority):"
            $cipherSuites | Select-Object -First 10 | ForEach-Object {
                $suite = $_.Name
                if ($suite -match "TLS_AES|TLS_CHACHA20") {
                    Write-Success "  $suite (TLS 1.3)"
                }
                elseif ($suite -match "GCM|ECDHE") {
                    Write-Success "  $suite (Strong)"
                }
                elseif ($suite -match "CBC") {
                    Write-DiagWarning "  $suite (Consider disabling CBC mode ciphers)"
                }
                else {
                    Write-Info "  $suite"
                }
            }
            
            # Check for weak cipher suites
            Write-Info ""
            Write-Info "Checking for weak/deprecated cipher suites..."
            $weakCiphers = $cipherSuites | Where-Object { 
                $_.Name -match "RC4|DES|3DES|MD5|NULL|EXPORT|anon" 
            }
            
            if ($weakCiphers) {
                Write-DiagError "CRITICAL: Weak cipher suites detected!"
                $weakCiphers | ForEach-Object {
                    Write-DiagWarning "  - $($_.Name)"
                }
            }
            else {
                Write-Success "No weak cipher suites detected"
            }
        }
        else {
            Write-DiagWarning "Could not retrieve cipher suite information (may require Windows Server 2012 R2+)"
        }
    }
    catch {
        Write-DiagWarning "Could not check cipher suites: $($_.Exception.Message)"
    }
    
    Write-Info ""
    Write-Info "--- Quick Fix Commands ---"
    Write-DiagWarning "IMPORTANT: The commands below are for REFERENCE ONLY. They are NOT auto-executed."
    Write-DiagWarning "Review each command carefully before running manually. Registry changes require a system restart."
    Write-Host @"

To disable TLS 1.0 and 1.1 (RECOMMENDED):
# Disable TLS 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force

# Disable TLS 1.1
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force

To enable TLS 1.2:
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force

To enable .NET Framework to use TLS 1.2:
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord

NOTE: A system restart is required after making TLS changes!

"@ -ForegroundColor Cyan
}

function Export-TLSReport {
    <#
    .SYNOPSIS
        Exports TLS configuration to a report file
    .DESCRIPTION
        Creates a detailed report of TLS settings for documentation
    #>
    Write-Header "Exporting TLS Configuration Report"
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $script:DefaultLogPath "TLSReport_$($timestamp).txt"
    
    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-DiagError "Cannot create report directory"
        return
    }
    
    try {
        $report = @"
========================================
TLS CONFIGURATION REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)
========================================

"@
        
        # Get all protocol info
        $tlsProtocols = @("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
        
        foreach ($protocol in $tlsProtocols) {
            $report += "`n--- $protocol ---`n"
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol"
            
            if (Test-Path $regPath) {
                # Client
                $clientPath = Join-Path $regPath "Client"
                if (Test-Path $clientPath) {
                    $clientProps = Get-ItemProperty -Path $clientPath -ErrorAction SilentlyContinue
                    $report += "Client Enabled: $($clientProps.Enabled)`n"
                    $report += "Client DisabledByDefault: $($clientProps.DisabledByDefault)`n"
                }
                else {
                    $report += "Client: Not configured`n"
                }
                
                # Server
                $serverPath = Join-Path $regPath "Server"
                if (Test-Path $serverPath) {
                    $serverProps = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
                    $report += "Server Enabled: $($serverProps.Enabled)`n"
                    $report += "Server DisabledByDefault: $($serverProps.DisabledByDefault)`n"
                }
                else {
                    $report += "Server: Not configured`n"
                }
            }
            else {
                $report += "Not configured (using system defaults)`n"
            }
        }
        
        # .NET Framework
        $report += "`n--- .NET Framework Configuration ---`n"
        $netFx4Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path) {
            $netProps = Get-ItemProperty -Path $netFx4Path -ErrorAction SilentlyContinue
            $report += "SchUseStrongCrypto (32-bit): $($netProps.SchUseStrongCrypto)`n"
            $report += "SystemDefaultTlsVersions (32-bit): $($netProps.SystemDefaultTlsVersions)`n"
        }
        
        $netFx4Path64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        if (Test-Path $netFx4Path64) {
            $netProps64 = Get-ItemProperty -Path $netFx4Path64 -ErrorAction SilentlyContinue
            $report += "SchUseStrongCrypto (64-bit): $($netProps64.SchUseStrongCrypto)`n"
            $report += "SystemDefaultTlsVersions (64-bit): $($netProps64.SystemDefaultTlsVersions)`n"
        }
        
        # Cipher Suites
        $report += "`n--- Enabled Cipher Suites ---`n"
        try {
            $cipherSuites = Get-TlsCipherSuite -ErrorAction SilentlyContinue
            if ($cipherSuites) {
                foreach ($suite in $cipherSuites) {
                    $report += "$($suite.Name)`n"
                }
            }
        }
        catch {
            $report += "Could not retrieve cipher suites`n"
        }
        
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "TLS Report generated: $($reportPath)"
        
        $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            try {
                notepad $reportPath
            }
            catch {
                Write-DiagWarning "Could not open report automatically. Please navigate to: $($reportPath)"
            }
        }
    }
    catch {
        Write-DiagError "Failed to generate TLS report: $($_.Exception.Message)"
    }
}

function Export-DiagnosticSection {
    <#
    .SYNOPSIS
        Captures diagnostic output from a script block and offers to save and open it
    .PARAMETER Title
        Report title
    .PARAMETER ScriptBlock
        The diagnostic function to capture output from
    #>
    param(
        [string]$Title,
        [scriptblock]$ScriptBlock
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeTitle = $Title -replace '[^a-zA-Z0-9]', '_'
    $reportPath = Join-Path $script:DefaultLogPath "${safeTitle}_${timestamp}.txt"
    
    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-DiagError "Cannot create report directory"
        return
    }
    
    try {
        $report = @()
        $report += "=" * 65
        $report += "$Title Report"
        $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $report += "Computer:  $($env:COMPUTERNAME)"
        $report += "=" * 65
        $report += ""
        
        # Capture all output streams from the script block
        $output = & $ScriptBlock *>&1
        foreach ($line in $output) {
            $text = $line.ToString()
            # Strip ANSI/color codes if any, and format cleanly
            $report += $text
        }
        
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "Report saved to: $reportPath"
        
        $open = Get-ValidatedChoice -Prompt "Open report in Notepad? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            try {
                notepad $reportPath
            }
            catch {
                Write-DiagWarning "Could not open report. Navigate to: $reportPath"
            }
        }
    }
    catch {
        Write-DiagError "Failed to save report: $($_.Exception.Message)"
    }
}

function Export-SystemReport {
    <#
    .SYNOPSIS
        Generates a comprehensive system diagnostic report
    .DESCRIPTION
        Creates a detailed text report with system information, resource usage,
        and configuration details
    .EXAMPLE
        Export-SystemReport
    #>
    Write-Header "Generating System Report"
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPath = Join-Path $script:DefaultLogPath "SystemReport_$($timestamp).txt"
    
    if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
        Write-DiagError "Cannot create report directory"
        return
    }
    
    try {
        $report = @"
========================================
SYSTEM DIAGNOSTIC REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)
========================================

"@
        
        # System Information
        $report += "`n--- SYSTEM INFORMATION ---`n"
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $report += "OS: $($os.Caption) $($os.Version)`n"
            $report += "Manufacturer: $($cs.Manufacturer)`n"
            $report += "Model: $($cs.Model)`n"
            $report += "Domain: $($cs.Domain)`n"
            $report += "Last Boot: $($os.LastBootUpTime)`n"
        }
        catch {
            $report += "Error retrieving system information: $($_.Exception.Message)`n"
        }
        
        # Memory (guard against $os being $null if system info retrieval failed)
        if ($null -ne $os) {
            try {
                $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
                $report += "`n--- MEMORY ---`n"
                $report += "Total: $($totalMemGB) GB`n"
                $report += "Free: $($freeMemGB) GB`n"
                $report += "Usage: $([math]::Round((($totalMemGB - $freeMemGB) / $totalMemGB) * 100, 2))%`n"
            }
            catch {
                $report += "Error retrieving memory information`n"
            }
        }
        else {
            $report += "`n--- MEMORY ---`nSkipped (system information unavailable)`n"
        }
        
        # CPU
        try {
            $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop
            $report += "`n--- PROCESSOR ---`n"
            $report += "Name: $($cpu.Name)`n"
            $report += "Cores: $($cpu.NumberOfCores)`n"
            $report += "Logical Processors: $($cpu.NumberOfLogicalProcessors)`n"
        }
        catch {
            $report += "Error retrieving CPU information`n"
        }
        
        # Disk
        $report += "`n--- DISK SPACE ---`n"
        try {
            $volumes = Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter }
            foreach ($vol in $volumes) {
                if ($vol.Size -le 0) { continue }
                $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
                $totalGB = [math]::Round($vol.Size / 1GB, 2)
                $usedPercent = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 2)
                $report += "Drive $($vol.DriveLetter): $($usedPercent)% used - $($freeGB) GB free of $($totalGB) GB`n"
            }
        }
        catch {
            $report += "Error retrieving disk information`n"
        }
        
        # Network
        $report += "`n--- NETWORK ADAPTERS ---`n"
        try {
            $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
            foreach ($adapter in $adapters) {
                $report += "$($adapter.Name): $($adapter.Status) - $($adapter.LinkSpeed)`n"
            }
        }
        catch {
            $report += "Error retrieving network adapter information`n"
        }
        
        # Top Processes
        $processAnalysis = Get-ProcessAnalysis
        if ($processAnalysis) {
            $report += "`n--- TOP 10 PROCESSES BY CPU ---`n"
            foreach ($proc in $processAnalysis.ByCPU) {
                $report += "$($proc.Name): CPU=$([math]::Round($proc.CPU, 2))s, Mem=$([math]::Round($proc.WS / 1MB, 2))MB`n"
            }
            
            $report += "`n--- TOP 10 PROCESSES BY MEMORY ---`n"
            foreach ($proc in $processAnalysis.ByMemory) {
                $report += "$($proc.Name): Mem=$([math]::Round($proc.WS / 1MB, 2))MB, CPU=$([math]::Round($proc.CPU, 2))s`n"
            }
        }
        
        # Services
        $report += "`n--- STOPPED AUTOMATIC SERVICES ---`n"
        try {
            $stoppedServices = Get-Service -ErrorAction Stop | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" }
            if ($stoppedServices) {
                foreach ($svc in $stoppedServices) {
                    $report += "$($svc.Name): $($svc.Status)`n"
                }
            }
            else {
                $report += "All automatic services are running`n"
            }
        }
        catch {
            $report += "Error retrieving service information`n"
        }
        
        # Power Plan
        $report += "`n--- POWER PLAN ---`n"
        try {
            $powerPlan = powercfg /getactivescheme
            $report += "$($powerPlan)`n"
        }
        catch {
            $report += "Error retrieving power plan information`n"
        }
        
        # Save report
        $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        Write-Success "Report generated: $($reportPath)"
        
        # Open report
        $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
        if ($open -eq "Y") {
            try {
                notepad $reportPath
            }
            catch {
                Write-DiagWarning "Could not open report automatically. Please navigate to: $($reportPath)"
            }
        }
    }
    catch {
        Write-DiagError "Failed to generate system report: $($_.Exception.Message)"
    }
}

function Get-DotNetFrameworkVersion {
    <#
    .SYNOPSIS
        Gets installed .NET Framework and .NET Core versions
    .DESCRIPTION
        Scans registry and outputs all installed versions of .NET framework
    #>
    Write-Header "Checking .NET Framework Versions"
    
    $now = Get-Date

    try {
        $release = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
    }
    catch {
        $release = $null
    }

    $OSVersion = switch ($release) {
        { $_ -ge 533325 } { ".NET Framework 4.8.1"; break }
        { $_ -ge 528040 } { ".NET Framework 4.8"; break }
        { $_ -ge 461808 } { ".NET Framework 4.7.2"; break }
        { $_ -ge 461308 } { ".NET Framework 4.7.1"; break }
        { $_ -ge 460798 } { ".NET Framework 4.7"; break }
        { $_ -ge 394802 } { ".NET Framework 4.6.2"; break }
        { $_ -ge 394254 } { ".NET Framework 4.6.1"; break }
        { $_ -ge 393295 } { ".NET Framework 4.6"; break }
        { $_ -ge 379893 } { ".NET Framework 4.5.2"; break }
        { $_ -ge 378675 } { ".NET Framework 4.5.1"; break }
        { $_ -ge 378389 } { ".NET Framework 4.5"; break }
        default { "No .NET Framework 4.5+ detected" }
    }

    $list = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue |
    Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue |
    Select-Object @{Name = 'Framework'; Expression = { $_.PSChildName } }, Version, Release |
    Sort-Object Framework, Version, Release;

    $Result = foreach ($item in $list) {
        [pscustomobject]@{
            Product   = '.NET Framework'
            Framework = $item.Framework
            Version   = $item.Version
            Release   = $item.Release
        }
    }

    $Result += [pscustomobject]@{
        Product   = '.NET Framework OS Default'
        Framework = $OSVersion
        Version   = $release
        Release   = ''
    }

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $programs = @()

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $programs += Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }
    }

    $programs = $programs | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -like "*Core Runtime*" } | Sort-Object DisplayName

    if ($programs) {
        $Result += foreach ($item in $programs) {
            [pscustomobject]@{
                Product   = '.NET Core'
                Framework = $item.DisplayName
                Version   = $item.DisplayVersion
                Release   = ''
            }
        }
    }

    $Result | Format-Table -AutoSize
    
    Write-Info "`n"
    $export = Get-ValidatedChoice -Prompt "Export .NET versions report to CSV? (Y/N)" -ValidChoices @("Y", "N")
    if ($export -eq "Y") {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $reportPath = Join-Path $script:DefaultLogPath "DotNetVersions_$($timestamp).csv"
        
        if (-not (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist)) {
            Write-DiagError "Cannot create report directory"
            return
        }
        
        # Add metadata for CSV
        $CsvResult = foreach ($item in $Result) {
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                Timestamp    = $now.ToString('yyyy/MM/dd HH:mm:ss')
                Product      = $item.Product
                Framework    = $item.Framework
                Version      = $item.Version
                Release      = $item.Release
            }
        }
        
        try {
            $CsvResult | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
            Write-Success "Report generated: $($reportPath)"
            
            $open = Get-ValidatedChoice -Prompt "Open report? (Y/N)" -ValidChoices @("Y", "N")
            if ($open -eq "Y") {
                try {
                    notepad $reportPath
                }
                catch {
                    Write-DiagWarning "Could not open report automatically."
                }
            }
        }
        catch {
            Write-DiagError "Failed to generate .NET versions report: $($_.Exception.Message)"
        }
    }
}
#endregion
