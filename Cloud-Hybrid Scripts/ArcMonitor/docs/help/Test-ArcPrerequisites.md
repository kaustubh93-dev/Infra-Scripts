---
external help file: ArcMonitor-help.xml
Module Name: ArcMonitor
online version:
schema: 2.0.0
---

# Test-ArcPrerequisites

## SYNOPSIS
Runs all Azure Arc prerequisites remotely on a target machine.

## SYNTAX

```
Test-ArcPrerequisites [-ComputerName] <String> [-Credential] <PSCredential> [-ProxyServer <String>]
```

## DESCRIPTION
Validates OS version, PS version, .NET Framework, TLS 1.2, WinRM, admin rights, disk space, clock skew, pending reboot, internet access to Azure endpoints, existing agent status (Connected/Disconnected/Expired), HIMDS service, and required Windows services — all executed remotely on the target via Invoke-Command.

Runs 16 checks total. Auto-detects platform type (VMware, Azure Local, Hyper-V, Physical, KVM, Nutanix, Azure Native VM). Azure native VMs are auto-excluded from onboarding.

## PARAMETERS

### -ComputerName
Target server hostname or IP address. Validated against RFC 1123 hostname or IPv4 format.

```yaml
Type: String
Required: True
```

### -Credential
PSCredential for the remote server. Must have local Administrator rights on the target.

```yaml
Type: PSCredential
Required: True
```

### -ProxyServer
HTTP proxy URL (e.g., `http://proxy.corp.local:8080`). Optional. Used for Azure endpoint connectivity tests.

```yaml
Type: String
Required: False
Default value: None
```

## OUTPUTS
Hashtable with keys: `ComputerName`, `Timestamp`, `Reachable`, `Checks`, `Platform`, `OverallPass`, `FailedChecks`, `Warnings`.

## EXAMPLES

### Example 1: Check a single server
```powershell
$cred = Get-Credential
$result = Test-ArcPrerequisites -ComputerName "srv-app-01" -Credential $cred
$result.OverallPass  # True or False
$result.Checks.Keys  # List of all check names
```

### Example 2: Check with proxy
```powershell
$result = Test-ArcPrerequisites -ComputerName "srv-db-02" -Credential $cred -ProxyServer "http://proxy:8080"
```

## RELATED LINKS
- [Azure Arc Prerequisites](https://learn.microsoft.com/en-us/azure/azure-arc/servers/prerequisites)
- [Troubleshoot Agent Onboarding](https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-agent-onboard)
