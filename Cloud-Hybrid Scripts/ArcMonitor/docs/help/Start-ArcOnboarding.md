---
external help file: ArcMonitor-help.xml
Module Name: ArcMonitor
online version:
schema: 2.0.0
---

# Start-ArcOnboarding

## SYNOPSIS
Unified onboarding pipeline — launches TUI monitor in a separate window.

## SYNTAX

```
Start-ArcOnboarding [-Servers] <String[]> [-Credential] <PSCredential> [-SkipPreReqCheck]
                     [-PollInterval <Int32>] [-MaxPolls <Int32>]
```

## DESCRIPTION
Orchestrates the full Azure Arc onboarding pipeline for one or more Windows servers:

1. Runs 16 remote prerequisite checks (with auto-fix option)
2. Downloads and installs the Azure Connected Machine Agent (with Authenticode verification)
3. Connects to Azure Arc via `azcmagent connect` (with retry for transient errors)
4. Verifies HIMDS service is running

Opens a separate PowerShell window with a live TUI dashboard showing real-time status.
Status is shared via an atomic JSON state file.

On failure, provides Microsoft-documented exit code guidance (codes 1-23) with remediation steps.

## PARAMETERS

### -Servers
Array of target server hostnames or IP addresses.

```yaml
Type: String[]
Required: True
```

### -Credential
PSCredential for remote server access. Must be local Administrator on all targets.

```yaml
Type: PSCredential
Required: True
```

### -SkipPreReqCheck
Skip prerequisite validation and proceed directly to agent installation.

```yaml
Type: SwitchParameter
Required: False
```

### -PollInterval
Seconds between monitor window dashboard refreshes. Default: 30.

```yaml
Type: Int32
Required: False
Default value: 30
```

### -MaxPolls
Maximum number of poll cycles before monitor timeout. Default: 60.

```yaml
Type: Int32
Required: False
Default value: 60
```

## OUTPUTS
Array of hashtables with keys: `Server`, `Platform`, `Installed`, `Connected`, `HIMDS`, `Phase`, `Error`.

## EXAMPLES

### Example 1: Onboard two servers
```powershell
$cred = Get-Credential -Message "Remote Admin"
$results = Start-ArcOnboarding -Servers "srv01","srv02" -Credential $cred
$results | Where-Object { $_.Phase -eq "Done" }
```

### Example 2: Skip prereqs, fast polling
```powershell
Start-ArcOnboarding -Servers "srv03" -Credential $cred -SkipPreReqCheck -PollInterval 5
```

## RELATED LINKS
- [Azure Arc Deployment Options](https://learn.microsoft.com/en-us/azure/azure-arc/servers/deployment-options)
- [Service Principal Onboarding](https://learn.microsoft.com/en-us/azure/azure-arc/servers/onboard-service-principal)
