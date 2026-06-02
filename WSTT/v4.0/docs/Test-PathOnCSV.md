---
external help file: WSTT-help.xml
Module Name: WSTT
online version:
schema: 2.0.0
---

# Test-PathOnCSV

## SYNOPSIS
Checks if a given path resides on a Cluster Shared Volume

## SYNTAX

```
Test-PathOnCSV [[-Path] <String>] [[-CSVPaths] <String[]>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -CSVPaths
Array of CSV mount points from Get-ClusterEnvironmentInfo

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
The file system path to validate

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### Boolean - $true if path is on a CSV
## NOTES

## RELATED LINKS
