---
external help file: WSTT-help.xml
Module Name: WSTT
online version:
schema: 2.0.0
---

# Get-OSCapability

## SYNOPSIS
Returns a cached PSCustomObject describing the host's OS, edition,
architecture, role inventory and Server-2025-feature flags.

## SYNTAX

```
Get-OSCapability [-Refresh] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Replaces scattered Get-CimInstance Win32_OperatingSystem / Get-WindowsFeature
calls.
Safe on workstation, Core, ARM64.
Idempotent / cached.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Refresh
{{ Fill Refresh Description }}

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
