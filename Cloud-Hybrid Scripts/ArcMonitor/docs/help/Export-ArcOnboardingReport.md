---
external help file: ArcMonitor-help.xml
Module Name: ArcMonitor
online version:
schema: 2.0.0
---

# Export-ArcOnboardingReport

## SYNOPSIS
Exports onboarding results to an Excel spreadsheet.

## SYNTAX

```
Export-ArcOnboardingReport [-Results] <Hashtable[]> [-Path <String>]
```

## DESCRIPTION
Takes the output from `Start-ArcOnboarding` and exports it to a formatted Excel workbook using ImportExcel. Includes conditional formatting (green for success, red for failure), auto-sized columns, and a summary sheet.

Requires the `ImportExcel` module (`Install-Module ImportExcel -Force`).

## PARAMETERS

### -Results
Array of onboarding result hashtables from `Start-ArcOnboarding`.

```yaml
Type: Hashtable[]
Required: True
```

### -Path
Output Excel file path. Defaults to `.\Logs\ArcOnboarding_YYYYMMDD_HHmmss.xlsx`.

```yaml
Type: String
Required: False
```

## EXAMPLES

### Example 1: Export after onboarding
```powershell
$results = Start-ArcOnboarding -Servers "srv01","srv02" -Credential $cred
Export-ArcOnboardingReport -Results $results
```

### Example 2: Custom path
```powershell
Export-ArcOnboardingReport -Results $results -Path "C:\Reports\ArcReport.xlsx"
```

## RELATED LINKS
- [ImportExcel Module](https://github.com/dfinke/ImportExcel)
