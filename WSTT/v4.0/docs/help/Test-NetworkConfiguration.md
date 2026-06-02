---
external help file: WSTT-help.xml
Module Name: WSTT
online version:
schema: 2.0.0
---

# Test-NetworkConfiguration

## SYNOPSIS
Performs comprehensive network configuration diagnostics

## SYNTAX

```
Test-NetworkConfiguration [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Checks RSS status, ephemeral port usage, VMQ settings, adapter properties,
power plan, network statistics, default gateway, link speed/duplex, TCP offload,
MTU/jumbo frames, DNS suffix, WINS, proxy, NIC drivers, binding order, firewall
rules, RDMA/SMB Direct, TCP parameters, NIC error events, and routing table

## EXAMPLES

### EXAMPLE 1
```
Test-NetworkConfiguration
```

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
Requires administrator privileges

## RELATED LINKS
