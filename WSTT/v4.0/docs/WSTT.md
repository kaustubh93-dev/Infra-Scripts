---
Module Name: WSTT
Module Guid: aa6c2260-257b-4bbc-a757-c69eb2605144
Download Help Link: {{ Update Download Link }}
Help Version: {{ Please enter version of help manually (X.X.X.X) format }}
Locale: en-US
---

# WSTT Module
## Description
{{ Fill in the Description }}

## WSTT Cmdlets
### [Add-Finding](Add-Finding.md)
Adds a structured finding to the in-memory collection.

### [Export-DiagnosticSection](Export-DiagnosticSection.md)
Captures diagnostic output from a script block and offers to save and open it

### [Export-FindingsToFile](Export-FindingsToFile.md)
Serialises $script:Findings to JSON, NDJSON, CSV, or SARIF-lite.

### [Export-SystemReport](Export-SystemReport.md)
Generates a comprehensive system diagnostic report

### [Export-TLSReport](Export-TLSReport.md)
Exports TLS configuration to a report file

### [Get-ClusterEnvironmentInfo](Get-ClusterEnvironmentInfo.md)
Detects cluster membership, role, and SQL AG state for the local node

### [Get-DotNetFrameworkVersion](Get-DotNetFrameworkVersion.md)
Gets installed .NET Framework and .NET Core versions

### [Get-EventSnippet](Get-EventSnippet.md)
Safely extracts a message snippet from an event log entry

### [Get-Findings](Get-Findings.md)
Returns a snapshot copy of current findings.

### [Get-NonHeartbeatGateways](Get-NonHeartbeatGateways.md)
Returns default gateways excluding cluster heartbeat-only networks

### [Get-OSCapability](Get-OSCapability.md)
Returns a cached PSCustomObject describing the host's OS, edition,
architecture, role inventory and Server-2025-feature flags.

### [Get-ProcessAnalysis](Get-ProcessAnalysis.md)
Analyzes process resource usage

### [Get-RecentEvents](Get-RecentEvents.md)
Shared helper to query recent Windows Event Log entries

### [Get-ValidatedChoice](Get-ValidatedChoice.md)
Prompts user for input and validates against allowed values

### [Initialize-DiagnosticPaths](Initialize-DiagnosticPaths.md)
Initializes diagnostic paths and ensures they exist

### [Invoke-ExportDiagnosticsMenu](Invoke-ExportDiagnosticsMenu.md)
{{ Fill in the Synopsis }}

### [Invoke-MultiServerRemotingMenu](Invoke-MultiServerRemotingMenu.md)
Interactive helper to fan out v4.0 checks to multiple servers via PSRemoting.

### [Invoke-PostCheckExport](Invoke-PostCheckExport.md)
After a check completes interactively, optionally export the captured findings.

### [Invoke-TSSCommand](Invoke-TSSCommand.md)
Invokes a TSS command with proper path handling

### [Invoke-WithTSSCheck](Invoke-WithTSSCheck.md)
Executes a command with TSS availability check

### [Invoke-WSTTRemote](Invoke-WSTTRemote.md)
Executes selected v4.0 check functions against remote servers in parallel.

### [Invoke-WSTTUnattended](Invoke-WSTTUnattended.md)
Non-interactive entry point.
Runs selected categories, exports, sets exit code.

### [Protect-DiagMessage](Protect-DiagMessage.md)
Redacts potentially sensitive information from diagnostic messages

### [Reset-Findings](Reset-Findings.md)
Clear the in-memory findings collection (e.g., between unattended runs).

### [Set-TSSPath](Set-TSSPath.md)
Allows user to update the hardcoded TSS path

### [Show-AdditionalScenarios](Show-AdditionalScenarios.md)
Displays additional troubleshooting scenarios menu

### [Show-DNSDebugCommands](Show-DNSDebugCommands.md)
Displays manual DNS debug commands

### [Show-MainMenu](Show-MainMenu.md)
Displays the main menu

### [Show-NetworkTraceCommand](Show-NetworkTraceCommand.md)
Displays manual network trace commands

### [Show-PerfmonCommand](Show-PerfmonCommand.md)
Displays performance monitor collection commands

### [Show-StorPortCommands](Show-StorPortCommands.md)
Displays manual StorPort trace commands

### [Show-UnattendedModeHelp](Show-UnattendedModeHelp.md)
{{ Fill in the Synopsis }}

### [Show-ValidatorInfo](Show-ValidatorInfo.md)
Displays validator script information

### [Start-CPULogCollection](Start-CPULogCollection.md)
Starts CPU issue log collection

### [Start-DiskLogCollection](Start-DiskLogCollection.md)
Starts disk/storage issue log collection

### [Start-DNSLogCollection](Start-DNSLogCollection.md)
Starts DNS-related log collection

### [Start-EventLogCollection](Start-EventLogCollection.md)
Starts event log collection for analysis

### [Start-MemoryLogCollection](Start-MemoryLogCollection.md)
Starts memory issue log collection

### [Start-NetworkLogCollection](Start-NetworkLogCollection.md)
Starts network log collection based on issue type

### [Start-SecurityLogCollection](Start-SecurityLogCollection.md)
Starts security-related log collection

### [Start-ServicesLogCollection](Start-ServicesLogCollection.md)
Starts services-related log collection

### [Start-TroubleshootingTool](Start-TroubleshootingTool.md)
Main entry point for the troubleshooting tool

### [Start-WindowsUpdateLogCollection](Start-WindowsUpdateLogCollection.md)
Starts Windows Update related log collection

### [Test-ActiveDirectoryHealth](Test-ActiveDirectoryHealth.md)
DC-only health audit (dcdiag, repadmin, FSMO, SYSVOL, time, krbtgt, LDAP signing).

### [Test-AdvancedStorageHealth](Test-AdvancedStorageHealth.md)
S2D / Storage Replica / Dedup / ReFS / Storage QoS / NVMe firmware checks.

### [Test-AzureArcHybridHealth](Test-AzureArcHybridHealth.md)
Arc agent health, AMA, outbound endpoints, extension state.

### [Test-CertificateAndPKIHealth](Test-CertificateAndPKIHealth.md)
Expiring certs (My + WebHosting), WinRM listener cert, chain build, private key ACL audit.

### [Test-CPUUsage](Test-CPUUsage.md)
Analyzes CPU usage

### [Test-CrossCategoryHealth](Test-CrossCategoryHealth.md)
Consolidated health scorecard surfacing highest-frequency cross-cutting issues

### [Test-DiskPerformance](Test-DiskPerformance.md)
Analyzes disk performance

### [Test-DNSHealth](Test-DNSHealth.md)
Checks DNS health and connectivity

### [Test-EventLogHealth](Test-EventLogHealth.md)
Analyzes Windows Event Logs for issues

### [Test-HyperVHostHealth](Test-HyperVHostHealth.md)
Hyper-V host audit (VMs, integration services, dynamic memory, checkpoints, replica, vSwitch, GPU-P).

### [Test-IISHealth](Test-IISHealth.md)
Performs comprehensive IIS health checks

### [Test-MemoryUsage](Test-MemoryUsage.md)
Analyzes system memory usage

### [Test-ModernSecurityPosture](Test-ModernSecurityPosture.md)
Audits VBS/HVCI/Credential Guard, LSA-PPL, ASR, BitLocker, LAPS, SMB1, SMB signing, Defender.

### [Test-NetworkConfiguration](Test-NetworkConfiguration.md)
Performs comprehensive network configuration diagnostics

### [Test-PatchingDepthAndLifecycle](Test-PatchingDepthAndLifecycle.md)
Hotpatch state, latest LCU age, pending-reboot root cause, failed updates, OS lifecycle.

### [Test-PathOnCSV](Test-PathOnCSV.md)
Checks if a given path resides on a Cluster Shared Volume

### [Test-PathValid](Test-PathValid.md)
Validates and optionally creates a path

### [Test-SecurityAuthentication](Test-SecurityAuthentication.md)
Checks security and authentication configuration

### [Test-Server2025FeatureAudit](Test-Server2025FeatureAudit.md)
Detection of Hotpatch, dMSA, NTLM deprecation, SMB-over-QUIC, NetATC, GPU-P, ARM64, OpenSSH, TLS 1.3.

### [Test-ServicesHealth](Test-ServicesHealth.md)
Analyzes Windows services health

### [Test-TaskSchedulerHealth](Test-TaskSchedulerHealth.md)
Performs comprehensive Task Scheduler diagnostics

### [Test-TLSConfiguration](Test-TLSConfiguration.md)
Validates TLS configuration on the server

### [Test-TSSAvailable](Test-TSSAvailable.md)
Checks if TSS is available at the configured path

### [Test-WindowsUpdateStatus](Test-WindowsUpdateStatus.md)
Checks Windows Update status and history

### [Test-WSTTCommand](Test-WSTTCommand.md)
Wrapper for \`Get-Command -EA SilentlyContinue\` used by the new options
to gracefully N/A when a cmdlet is missing on the running OS.

### [Test-WSTTHasRole](Test-WSTTHasRole.md)
Returns $true if the supplied Windows feature/role is installed.

### [Write-DiagError](Write-DiagError.md)
Displays an error message

### [Write-DiagWarning](Write-DiagWarning.md)
Displays a warning message

### [Write-Header](Write-Header.md)
Displays a formatted header

### [Write-Info](Write-Info.md)
Displays an informational message

### [Write-Section](Write-Section.md)
Displays a section divider with title for readable output grouping

### [Write-Success](Write-Success.md)
Displays a success message

