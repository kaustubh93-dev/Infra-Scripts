<#
.SYNOPSIS
    Audits a machine against the DSC security baseline and generates a report
    for non-compliant settings.
#>
param(
    [string]$ConfigurationPath = "C:\DSC\SecurityBaseline.ps1"
)

# --- Step 1: Compile the DSC Configuration ---
Write-Host "Compiling DSC configuration from $ConfigurationPath..."
. $ConfigurationPath # This dot-sources and runs the script to create the MOF file
if (-not (Test-Path "C:\DSC\localhost.mof")) {
    throw "Failed to compile the DSC configuration. MOF file not found."
}

# --- Step 2: Test the Configuration against the local machine ---
Write-Host "Auditing the server against the baseline... (This may take a few minutes)"
$complianceResult = Test-DscConfiguration -Path "C:\DSC"

# --- Step 3: Generate the Report ---
$report = @()
$resultTime = Get-Date

if ($complianceResult.InDesiredState -eq $true) {
    Write-Host "Server is fully compliant with the DSC baseline." -ForegroundColor Green
} else {
    Write-Host "Server is NOT compliant. Generating report for non-compliant items..." -ForegroundColor Yellow

    foreach ($resource in $complianceResult.ResourcesInDesiredState | Where-Object { $_.InDesiredState -eq $false }) {
        # Get the current (actual) value of the non-compliant setting
        $dscResource = Get-DscConfiguration -CimSession localhost | Where-Object { $_.ResourceId -eq $resource.ResourceId }

        # Determine the Element and Actual Value based on the resource type
        $element = ""
        $actualValue = ""

        if ($dscResource.PsDscRunAsCredential.PsTypeName -like "*Registry*") {
            $element = "$($dscResource.Key)\$($dscResource.ValueName)"
            $actualValue = $dscResource.ValueData
        }
        elseif ($dscResource.PsDscRunAsCredential.PsTypeName -like "*SecurityOption*") {
            $element = "Security Option: $($dscResource.Name)"
            $actualValue = $dscResource.Value
        }
        elseif ($dscResource.PsDscRunAsCredential.PsTypeName -like "*UserRightsAssignment*") {
            $element = "User Right: $($dscResource.Name)"
            $actualValue = ($dscResource.Identity | Out-String).Trim()
        }
         elseif ($dscResource.PsDscRunAsCredential.PsTypeName -like "*AuditPolicySubcategory*") {
            $element = "Audit Policy: $($dscResource.Name)"
            $actualValue = $dscResource.AuditFlag
        }


        # Add the finding to our report
        $report += [PSCustomObject]@{
            "Element"       = $element
            "Result Time"   = $resultTime.ToString("g")
            "Result State"  = "Non-compliant"
            "Actual Value"  = $actualValue
        }
    }

    # Display the final report in a table format
    if ($report) {
        Write-Host "`n--- Compliance Audit Report ---" -ForegroundColor Cyan
        $report | Format-Table -AutoSize
    }
}
