---
external help file: WSTT-help.xml
Module Name: WSTT
online version:
schema: 2.0.0
---

# Get-ClusterEnvironmentInfo

## SYNOPSIS
Detects cluster membership, role, and SQL AG state for the local node

## SYNTAX

```
Get-ClusterEnvironmentInfo [<CommonParameters>]
```

## DESCRIPTION
Returns a hashtable with IsClusterNode, ClusterName, NodeName, 
IsAGInstalled, AGReplicas, and ClusterNetworks information.
All downstream checks should use this cached result.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### Hashtable with cluster and AG environment details
## NOTES

## RELATED LINKS
