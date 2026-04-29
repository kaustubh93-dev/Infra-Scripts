# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Security & Authentication
# Source lines: 4920 - 5275
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Security & Authentication
function Test-SecurityAuthentication {
    <#
    .SYNOPSIS
        Checks security and authentication configuration
    .DESCRIPTION
        Examines account lockout policies, recent failed logons, Kerberos status,
        secure channel, and firewall profiles
    .EXAMPLE
        Test-SecurityAuthentication
    #>
    [CmdletBinding()]
    param()
    
    Write-Header "Security & Authentication Check"
    
    # Account lockout policy
    Write-Info "Account Lockout Policy:"
    try {
        $lockoutPolicy = net accounts 2>&1
        $lockoutThresholdMatch = $lockoutPolicy | Select-String "Lockout threshold"
        $lockoutDurationMatch = $lockoutPolicy | Select-String "Lockout duration"
        $lockoutWindowMatch = $lockoutPolicy | Select-String "Lockout observation window"
        
        if ($null -ne $lockoutThresholdMatch) {
            $lockoutThreshold = $lockoutThresholdMatch.ToString().Trim()
            Write-Info "  $lockoutThreshold"
        }
        if ($null -ne $lockoutDurationMatch) {
            $lockoutDuration = $lockoutDurationMatch.ToString().Trim()
            Write-Info "  $lockoutDuration"
        }
        if ($null -ne $lockoutWindowMatch) {
            $lockoutWindow = $lockoutWindowMatch.ToString().Trim()
            Write-Info "  $lockoutWindow"
        }
        
        if ($null -eq $lockoutThresholdMatch) {
            Write-DiagWarning "  Could not parse lockout policy (non-English locale?)"
        }
        elseif ($lockoutThreshold -match "Never") {
            Write-DiagWarning "  WARNING: No account lockout threshold configured!"
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve lockout policy"
    }
    
    # Recent failed logon events (Event 4625)
    Write-Section "Recent Failed Logon Attempts (last 24 hours)"
    try {
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        if ($failedLogons) {
            Write-DiagWarning "  Found $($failedLogons.Count) failed logon attempt(s)"
            
            # Group by target account
            $grouped = $failedLogons | ForEach-Object {
                try {
                    $xml = [xml]$_.ToXml()
                    $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                    $sourceIP = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                    [PSCustomObject]@{ User = $targetUser; IP = $sourceIP }
                }
                catch {
                    [PSCustomObject]@{ User = "Unknown"; IP = "Unknown" }
                }
            } | Group-Object User | Sort-Object Count -Descending | Select-Object -First 5
            
            Write-Info "  Top targeted accounts:"
            foreach ($g in $grouped) {
                Write-Info "    $($g.Name): $($g.Count) attempt(s)"
            }
        }
        else {
            Write-Success "  No failed logon attempts in last 24 hours"
        }
    }
    catch {
        Write-Info "  Could not query security event log (may require audit policy)"
    }
    
    # Kerberos ticket status
    Write-Section "Kerberos Ticket Status"
    try {
        $klistOutput = klist 2>&1
        $ticketMatch = $klistOutput | Select-String "Cached Tickets"
        if ($ticketMatch) {
            Write-Info "  $($ticketMatch.ToString().Trim())"
        }
        else {
            Write-DiagWarning "  Could not determine cached ticket count (non-English locale or no tickets)"
        }
        
        # Show ticket details
        $klistOutput | Select-String "Server:" | Select-Object -First 5 | ForEach-Object {
            Write-Info "    $($_.ToString().Trim())"
        }
    }
    catch {
        Write-DiagWarning "  Could not retrieve Kerberos ticket information"
    }
    
    # Secure channel with domain
    Write-Section "Domain Secure Channel"
    try {
        $domain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain
        if ($domain -and $domain -ne "WORKGROUP") {
            $secureChannel = Test-ComputerSecureChannel -ErrorAction Stop
            if ($secureChannel) {
                Write-Success "  Secure channel with '$domain' is healthy"
            }
            else {
                Write-DiagError "  Secure channel with '$domain' is BROKEN"
                Write-Info "  Fix: Test-ComputerSecureChannel -Repair -Credential (Get-Credential)"
            }
        }
        else {
            Write-Info "  Server is not domain-joined (WORKGROUP)"
        }
    }
    catch {
        Write-DiagWarning "  Could not verify secure channel: $($_.Exception.Message)"
    }
    
    # Windows Firewall status
    Write-Section "Windows Firewall Status"
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($fwProfile in $fwProfiles) {
            $status = if ($fwProfile.Enabled) { "ENABLED" } else { "DISABLED" }
            
            if ($fwProfile.Enabled) {
                Write-Success "  $($fwProfile.Name): $status (Inbound: $($fwProfile.DefaultInboundAction), Outbound: $($fwProfile.DefaultOutboundAction))"
            }
            else {
                Write-DiagWarning "  $($fwProfile.Name): $status"
            }
        }
    }
    catch {
        Write-DiagWarning "  Could not check Firewall status: $($_.Exception.Message)"
    }

    # Account Lockout Events (4740)
    Write-Section "Account Lockout Events (4740, last 24h)"
    try {
        $lockoutEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4740
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        if ($lockoutEvents) {
            Write-DiagWarning "  Found $($lockoutEvents.Count) account lockout event(s):"
            $lockoutEvents | Group-Object { $_.Properties[0].Value } | ForEach-Object {
                Write-DiagWarning "    Account '$($_.Name)': $($_.Count) lockout(s)"
            }
        }
        else {
            Write-Success "  No account lockouts in last 24 hours"
        }
    }
    catch {
        Write-Info "  Could not query lockout events (Security log may require audit policy)"
    }

    # Logon as a Service Policy
    Write-Section "Logon as a Service Policy"
    try {
        $tmpFile = Join-Path $env:TEMP "secedit_export_$([System.Guid]::NewGuid().ToString('N')).cfg"
        try {
            $null = secedit /export /cfg $tmpFile /quiet 2>&1
            if (Test-Path $tmpFile) {
                # S2: Restrict temp file ACL — only current user + SYSTEM can read
                try {
                    $acl = Get-Acl $tmpFile
                    $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance, remove inherited rules
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $currentUser, 'FullControl', 'Allow')
                    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
                    $acl.AddAccessRule($userRule)
                    $acl.AddAccessRule($systemRule)
                    Set-Acl $tmpFile $acl -ErrorAction Stop
                }
                catch {
                    Write-DiagWarning "  Could not restrict temp file permissions: $($_.Exception.Message)"
                }
                
                $content = Get-Content $tmpFile -Raw
                $match = [regex]::Match($content, 'SeServiceLogonRight\s*=\s*(.*)')
                if ($match.Success) {
                    Write-Info "  Accounts with 'Log on as a service' right:"
                    $accounts = $match.Groups[1].Value -split ','
                    foreach ($acct in $accounts) {
                        Write-Info "    - $($acct.Trim())"
                    }
                }
                else {
                    Write-DiagWarning "  SeServiceLogonRight not found in security policy"
                }
            }
        }
        finally {
            if (Test-Path $tmpFile -ErrorAction SilentlyContinue) {
                Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Info "  Could not export security policy"
    }

    # Schannel Errors (36870)
    Write-Section "Schannel TLS Errors"
    try {
        $schannelEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 36870, 36871, 36874
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($schannelEvents) {
            Write-DiagError "  Found $($schannelEvents.Count) Schannel error(s) in last 7 days:"
            foreach ($evt in $schannelEvents) {
                Write-DiagWarning "    [$($evt.TimeCreated.ToString('MM-dd HH:mm'))] Event $($evt.Id): $(Get-EventSnippet -Event $evt -MaxLength 80)"
            }
            Write-Info "  Common cause: Certificate private key not readable, or TLS version mismatch"
        }
        else {
            Write-Success "  No Schannel errors"
        }
    }
    catch { }

    # NTLM vs Kerberos Detection
    Write-Section "Authentication Protocol Usage (last 100 logons)"
    try {
        $logonEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 100 -ErrorAction SilentlyContinue

        if ($logonEvents) {
            $ntlmCount = 0
            $kerbCount = 0
            foreach ($evt in $logonEvents) {
                try {
                    $authPkg = if ($evt.Properties.Count -gt 14) { $evt.Properties[14].Value } else { $null }
                    if ($authPkg -eq 'NTLM' -or $authPkg -like 'NtLm*') { $ntlmCount++ }
                    elseif ($authPkg -eq 'Kerberos') { $kerbCount++ }
                }
                catch { }
            }
            Write-Info "  Kerberos logons: $kerbCount"
            Write-Info "  NTLM logons: $ntlmCount"
            if ($ntlmCount -gt $kerbCount -and $ntlmCount -gt 10) {
                Write-DiagWarning "  WARNING: NTLM usage is high - consider investigating Kerberos fallback issues"
            }
        }
    }
    catch {
        Write-Info "  Could not analyze authentication protocols"
    }

    # MachineKeys Permissions
    Write-Section "MachineKeys Directory Permissions"
    try {
        $mkPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
        if (Test-Path $mkPath) {
            $acl = Get-Acl $mkPath -ErrorAction Stop
            $hasSystem = $acl.Access | Where-Object { $_.IdentityReference -like '*SYSTEM*' }
            $hasAdmins = $acl.Access | Where-Object { $_.IdentityReference -like '*Administrators*' }
            if ($hasSystem -and $hasAdmins) {
                Write-Success "  MachineKeys has SYSTEM and Administrators access"
            }
            else {
                Write-DiagError "  MachineKeys missing SYSTEM or Administrators permissions!"
                Write-Info "  This can cause RDP, TLS certificate, and encryption failures"
            }
        }
    }
    catch {
        Write-Info "  Could not check MachineKeys permissions"
    }
}

function Start-SecurityLogCollection {
    <#
    .SYNOPSIS
        Starts security-related log collection
    .DESCRIPTION
        Provides options for authentication traces and firewall exports
    #>
    Write-Header "Security Log Collection"
    
    Write-Info "Security Log Collection Options:"
    Write-Host "1. Export Firewall rules and configuration" -ForegroundColor Yellow
    Write-Host "2. TSS Authentication trace" -ForegroundColor Yellow
    Write-Host "3. Export Security event log" -ForegroundColor Yellow
    
    $choice = Get-ValidatedChoice -Prompt "`nEnter choice (1-3)" -ValidChoices @("1", "2", "3")
    
    switch ($choice) {
        "1" {
            $exportPath = Join-Path $script:DefaultLogPath "FirewallExport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            if (Test-PathValid -Path $exportPath -CreateIfNotExist) {
                try {
                    $fwRulesPath = Join-Path $exportPath "firewall_rules.txt"
                    $fwConfigPath = Join-Path $exportPath "firewall_config.txt"
                    
                    Write-Info "Exporting firewall rules..."
                    netsh advfirewall firewall show rule name=all > $fwRulesPath
                    
                    Write-Info "Exporting firewall configuration..."
                    netsh advfirewall show allprofiles > $fwConfigPath
                    
                    Write-Success "Firewall configuration exported to: $exportPath"
                }
                catch {
                    Write-DiagError "Failed to export firewall config: $($_.Exception.Message)"
                }
            }
        }
        "2" {
            Invoke-WithTSSCheck `
                -TSSCommand "-Scenario ADS_Auth -AcceptEula" `
                -ManualAlternativeAction {
                Write-Info "Manual: Run 'nltest /sc_query:<domain>' to check secure channel"
                Write-Info "        Run 'klist' to check Kerberos tickets"
            } `
                -Description "Starting TSS Authentication trace..."
        }
        "3" {
            $secEvtxPath = Join-Path $script:DefaultLogPath "security_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
            try {
                if (Test-PathValid -Path $script:DefaultLogPath -CreateIfNotExist) {
                    Write-Info "Exporting Security event log..."
                    wevtutil epl Security $secEvtxPath
                    Write-Success "Security log exported to: $secEvtxPath"
                }
            }
            catch {
                Write-DiagError "Failed to export security log: $($_.Exception.Message)"
            }
        }
    }
}
#endregion
