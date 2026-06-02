#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Server Validator v5.0 - Generates comprehensive HTML report of server SOE attributes.

.DESCRIPTION
    The Server Validator script performs a comprehensive audit of Windows Server configurations,
    generating a detailed HTML report covering:
    - General server information (hardware, OS, domain)
    - Network adapter configuration and optimization
    - Disk configuration and health
    - Windows features and updates
    - Software inventory
    - Power management settings
    - Firewall configuration
    - Page file and memory dump settings
    - Performance counter snapshots
    - Cluster configuration (if applicable)
    - Event log exports
    - Pending reboot status
    
    Compatible with Windows Server 2016, 2019, 2022, and 2025.

.PARAMETER SettingsFile
    Optional CSV file containing compliance definitions for validation thresholds.
    
.PARAMETER OutputPath
    Directory where the report folder will be created. Defaults to C:\Windows\ServerScanner.
    
.PARAMETER EnableLogging
    When specified, enables PowerShell transcript logging for troubleshooting.

.EXAMPLE
    .\Validator_v5.0S.ps1
    Runs the validator with default settings, outputting to C:\Windows\ServerScanner.

.EXAMPLE
    .\Validator_v5.0S.ps1 -SettingsFile "C:\Config\baseline.csv" -EnableLogging
    Runs with custom compliance settings and enables transcript logging.

.EXAMPLE
    .\Validator_v5.0S.ps1 -OutputPath "D:\Reports"
    Runs the validator with custom output path.

.NOTES
    Script Name : Validator_v5.0S.ps1
    Version     : 5.0
    Author      : Server Validation Team
    
    Fixes in v5.0:
    - S1: Replaced Invoke-Expression with call operator (&)
    - S2: Added #Requires, [CmdletBinding()], proper param block
    - Q1-Q3: Fixed undefined variables, replaced all Get-WmiObject with Get-CimInstance
    - Q4: Added proper comment-based help
    - Q5: Replaced all aliases with full cmdlet names
    - Q6: Renamed Parse-LGPO to ConvertFrom-LGPO
    - Q7: Added $ErrorActionPreference = "Stop"
    - Q9: Fixed smart quotes in NTFS string
    - Q11: Set version to 5.0
    - Q12: Populated firewall Profile column
    - E1-E8: Comprehensive Try/Catch error handling for all external calls
    - L1-L4: Implemented proper logging with Write-Log function and transcript support
    - P1-P3: Performance optimizations (cached OS queries, ArrayList, foreach vs ForEach-Object)
    - W3: Cluster safety checks before calling cluster cmdlets
    - W4: Fixed brace nesting issues
    
    ALL THE SCRIPTS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND/OR FITNESS FOR A PARTICULAR PURPOSE.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SettingsFile,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Windows\ServerScanner",
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableLogging
)

# Set strict error handling
$ErrorActionPreference = "Stop"

# Script version
$scriptversion = "5.0"

#region Script-Level Variables and Initialization

$Computer = $env:COMPUTERNAME
$Date = Get-Date

# Ensure output directory exists
if (!(Test-Path -Path $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    catch {
        Write-Error "Failed to create output directory: $OutputPath. Error: $_"
        exit 1
    }
}

# Create report folder
$folderName = "$Computer-Report-$(Get-Date -Format 'dd-MM-yyyy-HH-mm')"
$ReportFolder = Join-Path -Path $OutputPath -ChildPath $folderName

try {
    New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null
}
catch {
    Write-Error "Failed to create report folder: $ReportFolder. Error: $_"
    exit 1
}

# Setup logging
$script:LogFile = Join-Path -Path $ReportFolder -ChildPath "$Computer`_$(Get-Date -Format 'HHmmss_dd-MM-yyyy').log"

# HTML report path
$HTMLReport = Join-Path -Path $ReportFolder -ChildPath "$Computer`_ServerValidator_Report.html"

#endregion

#region Logging Functions

<#
.SYNOPSIS
    Writes a message to the log file with timestamp and severity level.
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

#endregion

#region OS Compatibility and Caching

# Cache OS and Computer System information once at startup
try {
    $script:CachedOS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $script:CachedCS = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $script:OSBuild = [int]$script:CachedOS.BuildNumber
    $script:OSCaption = $script:CachedOS.Caption
    
    Write-Log -Message "OS: $script:OSCaption, Build: $script:OSBuild" -Level INFO
}
catch {
    Write-Error "Failed to retrieve OS information: $_"
    exit 1
}

# OS Build number constants
$script:Server2016Build = 14393
$script:Server2019Build = 17763
$script:Server2022Build = 20348
$script:Server2025Build = 26100

#endregion

#region Settings File Processing

# Load settings file if provided
$script:Settings = @()

if ($SettingsFile -and (Test-Path -Path $SettingsFile)) {
    try {
        $script:Settings = Import-Csv -Path $SettingsFile -ErrorAction Stop
        Write-Log -Message "Loaded settings from: $SettingsFile" -Level INFO
    }
    catch {
        Write-Log -Message "Failed to load settings file: $SettingsFile. Error: $_" -Level WARN
        $script:Settings = @()
    }
}
else {
    if ($SettingsFile) {
        Write-Log -Message "Settings file not found: $SettingsFile. Proceeding without compliance definitions." -Level WARN
    }
    else {
        Write-Log -Message "No settings file specified. Running without compliance definitions." -Level INFO
    }
}

# Extract version and software definitions from settings
$script:version = ($script:Settings | Where-Object { $_.category -eq "version" } | Select-Object -First 1).Compliant_Value
$script:swdefinitions = $script:Settings | Where-Object { $_.category -eq "software" }

if ($script:version) {
    Write-Log -Message "Settings file version: $script:version" -Level INFO
}

#endregion

#region Start Transcript if Enabled

if ($EnableLogging) {
    $transcriptPath = Join-Path -Path $ReportFolder -ChildPath "$Computer`_Transcript.log"
    try {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        Write-Log -Message "Transcript logging enabled: $transcriptPath" -Level INFO
    }
    catch {
        Write-Log -Message "Failed to start transcript: $_" -Level WARN
    }
}

#endregion

#region HTML Helper Functions

<#
.SYNOPSIS
    Creates the HTML report header with CSS and JavaScript.
#>
function New-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $true)]
        [string]$Version
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title - $ComputerName</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
            font-weight: 300;
            letter-spacing: 1px;
        }
        
        .header .meta {
            font-size: 14px;
            opacity: 0.9;
            margin-top: 10px;
        }
        
        .content {
            padding: 30px 40px;
        }
        
        .section {
            margin-bottom: 25px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
            background: #fafafa;
        }
        
        .section-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            user-select: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s;
        }
        
        .section-header:hover {
            background: linear-gradient(135deg, #5568d3 0%, #653a8b 100%);
        }
        
        .section-header h2 {
            font-size: 18px;
            font-weight: 500;
        }
        
        .section-header .toggle {
            font-size: 20px;
            transition: transform 0.3s;
        }
        
        .section-header .toggle.collapsed {
            transform: rotate(-90deg);
        }
        
        .section-content {
            padding: 20px;
            background: white;
            display: block;
        }
        
        .section-content.collapsed {
            display: none;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 13px;
        }
        
        table th {
            background: #2a5298;
            color: white;
            padding: 12px 10px;
            text-align: left;
            font-weight: 500;
            border-bottom: 2px solid #1e3c72;
        }
        
        table td {
            padding: 10px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        table tr:nth-child(even) {
            background: #f9f9f9;
        }
        
        table tr:hover {
            background: #f0f0f0;
        }
        
        .detail-row {
            display: grid;
            grid-template-columns: 250px 1fr;
            padding: 10px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .detail-row:last-child {
            border-bottom: none;
        }
        
        .detail-label {
            font-weight: 600;
            color: #2a5298;
        }
        
        .detail-value {
            font-family: 'Consolas', 'Courier New', monospace;
            color: #333;
        }
        
        .detail-row-4col {
            display: grid;
            grid-template-columns: 200px 1fr 150px 150px;
            padding: 10px;
            border-bottom: 1px solid #e0e0e0;
            gap: 10px;
        }
        
        .detail-row-4col:last-child {
            border-bottom: none;
        }
        
        .detail-row-4col .heading {
            font-weight: 600;
            color: #2a5298;
        }
        
        .detail-row-4col .detail {
            font-family: 'Consolas', 'Courier New', monospace;
            color: #333;
        }
        
        .detail-row-4col .reference {
            font-size: 11px;
            color: #666;
        }
        
        .detail-row-4col .action {
            font-weight: 500;
        }
        
        .status-pass {
            color: #28a745;
            font-weight: 600;
        }
        
        .status-fail {
            color: #dc3545;
            font-weight: 600;
        }
        
        .status-warn {
            color: #fd7e14;
            font-weight: 600;
        }
        
        .status-info {
            color: #17a2b8;
            font-weight: 600;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            font-size: 12px;
            color: #666;
            border-top: 1px solid #e0e0e0;
            background: #fafafa;
        }
        
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 12px;
        }
    </style>
    <script>
        function toggleSection(id) {
            var content = document.getElementById(id);
            var toggle = document.getElementById(id + '-toggle');
            
            if (content.classList.contains('collapsed')) {
                content.classList.remove('collapsed');
                toggle.classList.remove('collapsed');
            } else {
                content.classList.add('collapsed');
                toggle.classList.add('collapsed');
            }
        }
        
        function expandAll() {
            var contents = document.querySelectorAll('.section-content');
            var toggles = document.querySelectorAll('.toggle');
            
            contents.forEach(function(content) {
                content.classList.remove('collapsed');
            });
            
            toggles.forEach(function(toggle) {
                toggle.classList.remove('collapsed');
            });
        }
        
        function collapseAll() {
            var contents = document.querySelectorAll('.section-content');
            var toggles = document.querySelectorAll('.toggle');
            
            contents.forEach(function(content) {
                content.classList.add('collapsed');
            });
            
            toggles.forEach(function(toggle) {
                toggle.classList.add('collapsed');
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Server Validator Report</h1>
            <div class="meta">
                <strong>Computer:</strong> $ComputerName | 
                <strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | 
                <strong>Version:</strong> $Version
            </div>
            <div style="margin-top: 15px;">
                <button onclick="expandAll()" style="padding: 8px 16px; margin: 0 5px; cursor: pointer; background: white; color: #2a5298; border: none; border-radius: 5px; font-weight: 500;">Expand All</button>
                <button onclick="collapseAll()" style="padding: 8px 16px; margin: 0 5px; cursor: pointer; background: white; color: #2a5298; border: none; border-radius: 5px; font-weight: 500;">Collapse All</button>
            </div>
        </div>
        <div class="content">
"@
    
    return $html
}

<#
.SYNOPSIS
    Adds a collapsible section to the HTML report.
#>
function Add-HTMLSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [string]$Content,
        
        [Parameter(Mandatory = $false)]
        [int]$SectionNumber
    )
    
    $sectionId = "section-$SectionNumber"
    
    $html = @"
        <div class="section">
            <div class="section-header" onclick="toggleSection('$sectionId')">
                <h2>$Title</h2>
                <span class="toggle" id="$sectionId-toggle">▼</span>
            </div>
            <div class="section-content" id="$sectionId">
                $Content
            </div>
        </div>
"@
    
    return $html
}

<#
.SYNOPSIS
    Converts an array to an HTML table without wrapper elements.
#>
function Add-HTMLTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Data
    )
    
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        return "<p><em>No data available</em></p>"
    }
    
    # Ensure $Data is always an array
    $Data = @($Data)
    
    $html = New-Object System.Collections.ArrayList
    [void]$html.Add("<table>")
    
    # Get headers from first object
    $firstItem = $Data[0]
    $properties = $firstItem.PSObject.Properties.Name
    
    # Add header row
    [void]$html.Add("<tr>")
    foreach ($prop in $properties) {
        [void]$html.Add("<th>$prop</th>")
    }
    [void]$html.Add("</tr>")
    
    # Add data rows
    foreach ($item in $Data) {
        [void]$html.Add("<tr>")
        foreach ($prop in $properties) {
            $value = $item.$prop
            if ($null -eq $value) { $value = "" }
            
            # Apply status coloring
            $cellClass = ""
            if ($value -match "^(Pass|OK|Enabled|Licensed|Running)$") {
                $cellClass = " class='status-pass'"
            }
            elseif ($value -match "^(Fail|Failed|Error|Disabled|Unlicensed|Stopped)$") {
                $cellClass = " class='status-fail'"
            }
            elseif ($value -match "^(Warning|Warn|Pending)$") {
                $cellClass = " class='status-warn'"
            }
            
            [void]$html.Add("<td$cellClass>$value</td>")
        }
        [void]$html.Add("</tr>")
    }
    
    [void]$html.Add("</table>")
    
    return ($html -join "`n")
}

<#
.SYNOPSIS
    Adds a detail row (label and value) to the HTML report.
#>
function Add-HTMLDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        
        [Parameter(Mandatory = $false)]
        [string]$Value = ""
    )
    
    if ($null -eq $Value) { $Value = "" }
    
    $html = @"
<div class="detail-row">
    <div class="detail-label">$Label</div>
    <div class="detail-value">$Value</div>
</div>
"@
    
    return $html
}

<#
.SYNOPSIS
    Adds a 4-column detail row (Heading, Detail, Reference, Action) to the HTML report.
#>
function Add-HTMLNewDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Heading,
        
        [Parameter(Mandatory = $false)]
        [string]$Detail = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Reference = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Action = ""
    )
    
    if ($null -eq $Detail) { $Detail = "" }
    if ($null -eq $Reference) { $Reference = "" }
    if ($null -eq $Action) { $Action = "" }
    
    # Apply status coloring to Action
    $actionClass = ""
    if ($Action -match "^(Pass|OK|Compliant)") {
        $actionClass = " class='status-pass'"
    }
    elseif ($Action -match "^(Fail|Failed|Non-Compliant)") {
        $actionClass = " class='status-fail'"
    }
    elseif ($Action -match "^(Warning|Review)") {
        $actionClass = " class='status-warn'"
    }
    
    $html = @"
<div class="detail-row-4col">
    <div class="heading">$Heading</div>
    <div class="detail">$Detail</div>
    <div class="reference">$Reference</div>
    <div$actionClass class="action">$Action</div>
</div>
"@
    
    return $html
}

<#
.SYNOPSIS
    Closes the HTML report.
#>
function Close-HTMLReport {
    [CmdletBinding()]
    param()
    
    $html = @"
        </div>
        <div class="footer">
            Generated by Server Validator v$scriptversion | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

#endregion

#region Core Information Functions

<#
.SYNOPSIS
    Retrieves PowerShell version and execution policy information.
#>
function Get-PSInfo {
    [CmdletBinding()]
    param()
    
    try {
        $version = $PSVersionTable.PSVersion
        $policy = Get-ExecutionPolicy
        
        if (!$version -or !$policy) {
            throw "Error getting PowerShell information"
        }
        
        $output = [PSCustomObject]@{
            Version          = "$($version.Major).$($version.Minor).$($version.Build).$($version.Revision)"
            ExecutionPolicy = $policy
        }
        
        return $output
    }
    catch {
        Write-Log -Message "Error getting PowerShell information: $_" -Level ERROR
        return $null
    }
}

<#
.SYNOPSIS
    Retrieves the organizational unit (OU) of the computer in Active Directory.
#>
function Get-OU {
    [CmdletBinding()]
    param()
    
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry
        $computerName = $env:COMPUTERNAME
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $root
        $searcher.SearchScope = "Subtree"
        $searcher.Filter = "(&(objectClass=computer)(name=$computerName))"
        $colPropList = "DistinguishedName"
        
        foreach ($i in $colPropList) {
            [void]$searcher.PropertiesToLoad.Add($i)
        }
        
        $colResult = $searcher.FindOne()
        
        if ($null -eq $colResult) {
            return [PSCustomObject]@{
                Name = $computerName
                OU   = "Not found in AD"
            }
        }
        
        $dn = $colResult.Properties["distinguishedName"]
        $ouResult = $dn.Substring($computerName.Length + 4)
        
        return [PSCustomObject]@{
            Name = $computerName
            OU   = $ouResult
        }
    }
    catch {
        Write-Log -Message "Error getting OU information: $_" -Level WARN
        return [PSCustomObject]@{
            Name = $env:COMPUTERNAME
            OU   = "Error retrieving OU"
        }
    }
}

<#
.SYNOPSIS
    Determines device type based on chassis type.
#>
function Get-DeviceType {
    [CmdletBinding()]
    param()
    
    try {
        $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop
        
        if (!$enclosure) {
            throw "Error getting asset information from CIM"
        }
        
        [string]$chassis = $enclosure.ChassisTypes[0]
        
        # Chassis types: 8=Portable, 9=Laptop, 10=Notebook, 11=Hand Held, 14=Sub Notebook
        if ($chassis -in @("8", "9", "10", "11", "14")) {
            $deviceType = "Mobile"
        }
        # Chassis types for servers: 17=Main Server, 23=Rack Mount
        elseif ($chassis -in @("17", "23")) {
            $deviceType = "Server"
        }
        else {
            $deviceType = "Workstation"
        }
        
        return $deviceType
    }
    catch {
        Write-Log -Message "Error getting device type: $_" -Level ERROR
        return "Unknown"
    }
}

<#
.SYNOPSIS
    Retrieves Windows activation status.
#>
function Get-ActivationStatus {
    [CmdletBinding()]
    param()
    
    try {
        $wpa = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" -ErrorAction Stop |
            Where-Object { $null -ne $_.LicenseStatus } |
            Select-Object -First 1
        
        $out = [PSCustomObject]@{
            LicenseStatus = [string]::Empty
        }
        
        if ($wpa) {
            switch ($wpa.LicenseStatus) {
                0 { $out.LicenseStatus = "Unlicensed" }
                1 { $out.LicenseStatus = "Licensed" }
                2 { $out.LicenseStatus = "Out-Of-Box Grace Period" }
                3 { $out.LicenseStatus = "Out-Of-Tolerance Grace Period" }
                4 { $out.LicenseStatus = "Non-Genuine Grace Period" }
                5 { $out.LicenseStatus = "Notification" }
                6 { $out.LicenseStatus = "Extended Grace" }
                default { $out.LicenseStatus = "Unknown" }
            }
        }
        else {
            $out.LicenseStatus = "Unable to determine"
        }
        
        return $out
    }
    catch {
        Write-Log -Message "Error getting activation status: $_" -Level WARN
        return [PSCustomObject]@{
            LicenseStatus = "Error retrieving status"
        }
    }
}

<#
.SYNOPSIS
    Checks for pending reboot conditions.
#>
function Get-PendingReboot {
    [CmdletBinding()]
    param()
    
    try {
        $rebootPending = $false
        $reasons = New-Object System.Collections.ArrayList
        
        # Check Component Based Servicing
        try {
            $cbs = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
            if ($cbs) {
                $rebootPending = $true
                [void]$reasons.Add("Component Based Servicing")
            }
        }
        catch { }
        
        # Check Windows Update
        try {
            $wu = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
            if ($wu) {
                $rebootPending = $true
                [void]$reasons.Add("Windows Update")
            }
        }
        catch { }
        
        # Check Pending File Rename Operations
        try {
            $pfro = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
            if ($pfro -and $pfro.PendingFileRenameOperations) {
                $rebootPending = $true
                [void]$reasons.Add("Pending File Rename Operations")
            }
        }
        catch { }
        
        # Check SCCM Client
        try {
            $sccm = Invoke-CimMethod -Namespace "ROOT\ccm\ClientSDK" -ClassName "CCM_ClientUtilities" -Name "DetermineIfRebootPending" -ErrorAction SilentlyContinue
            if ($sccm -and ($sccm.RebootPending -or $sccm.IsHardRebootPending)) {
                $rebootPending = $true
                [void]$reasons.Add("SCCM Client")
            }
        }
        catch { }
        
        return [PSCustomObject]@{
            RebootPending = $rebootPending
            Reasons       = ($reasons -join ", ")
        }
    }
    catch {
        Write-Log -Message "Error checking pending reboot: $_" -Level WARN
        return [PSCustomObject]@{
            RebootPending = "Unknown"
            Reasons       = "Error checking reboot status"
        }
    }
}

<#
.SYNOPSIS
    Retrieves stopped services that are configured for automatic startup.
#>
function Get-StoppedAutomaticService {
    [CmdletBinding()]
    param()
    
    try {
        $services = Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State!='Running'" -ErrorAction Stop
        
        $serviceList = New-Object System.Collections.ArrayList
        
        foreach ($service in $services) {
            [void]$serviceList.Add([PSCustomObject]@{
                Name        = $service.Name
                DisplayName = $service.DisplayName
                State       = $service.State
                StartMode   = $service.StartMode
            })
        }
        
        return $serviceList
    }
    catch {
        Write-Log -Message "Error getting stopped automatic services: $_" -Level ERROR
        return @()
    }
}

<#
.SYNOPSIS
    Retrieves memory dump configuration.
#>
function Get-MemoryDump {
    [CmdletBinding()]
    param()
    
    try {
        $crashControl = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ErrorAction Stop
        
        $dumpType = switch ($crashControl.CrashDumpEnabled) {
            0 { "None" }
            1 { "Complete memory dump" }
            2 { "Kernel memory dump" }
            3 { "Small memory dump (256 KB)" }
            7 { "Automatic memory dump" }
            default { "Unknown" }
        }
        
        return [PSCustomObject]@{
            DumpType     = $dumpType
            DumpFile     = $crashControl.DumpFile
            MinidumpDir  = $crashControl.MinidumpDir
            AutoReboot   = $crashControl.AutoReboot
        }
    }
    catch {
        Write-Log -Message "Error getting memory dump configuration: $_" -Level WARN
        return [PSCustomObject]@{
            DumpType     = "Error"
            DumpFile     = "N/A"
            MinidumpDir  = "N/A"
            AutoReboot   = "N/A"
        }
    }
}

#endregion

#region Network Configuration Functions

<#
.SYNOPSIS
    Retrieves detailed NIC configuration including advanced properties.
#>
function Get-NICConfiguration {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering NIC configuration..." -Level INFO
    
    $nicList = New-Object System.Collections.ArrayList
    
    try {
        # Only available on Server 2016+
        if ($script:OSBuild -ge $script:Server2016Build) {
            $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
            
            foreach ($adapter in $adapters) {
                $nicInfo = [PSCustomObject]@{
                    Name            = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    Status          = $adapter.Status
                    LinkSpeed       = $adapter.LinkSpeed
                    MacAddress      = $adapter.MacAddress
                    NICPriority     = "N/A"
                    RxBuffers       = "N/A"
                    RxRingSize      = "N/A"
                }
                
                # Get advanced properties
                try {
                    $advProps = Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue
                    
                    $rxBuffersProp = $advProps | Where-Object { $_.DisplayName -like "*Receive Buffer*" } | Select-Object -First 1
                    if ($rxBuffersProp) {
                        $nicInfo.RxBuffers = $rxBuffersProp.DisplayValue
                    }
                    
                    $rxRingProp = $advProps | Where-Object { $_.DisplayName -like "*Ring*" -or $_.RegistryKeyword -eq "NumRxQueues" } | Select-Object -First 1
                    if ($rxRingProp) {
                        $nicInfo.RxRingSize = $rxRingProp.DisplayValue
                    }
                }
                catch {
                    Write-Log -Message "Could not retrieve advanced properties for adapter $($adapter.Name): $_" -Level WARN
                }
                
                # Get binding order (priority)
                try {
                    $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_tcpip" -ErrorAction SilentlyContinue
                    if ($binding) {
                        $nicInfo.NICPriority = $binding.BindingOrder
                    }
                }
                catch { }
                
                [void]$nicList.Add($nicInfo)
            }
        }
        else {
            Write-Log -Message "Get-NetAdapter cmdlet not available on this OS version (Build: $script:OSBuild)" -Level WARN
        }
    }
    catch {
        Write-Log -Message "Error retrieving NIC configuration: $_" -Level ERROR
    }
    
    return $nicList
}

<#
.SYNOPSIS
    Retrieves NIC power management settings.
#>
function Get-NICPowerManagement {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering NIC power management settings..." -Level INFO
    
    $nicPowerList = New-Object System.Collections.ArrayList
    
    try {
        if ($script:OSBuild -ge $script:Server2016Build) {
            $adapters = Get-NetAdapter -ErrorAction Stop
            
            foreach ($adapter in $adapters) {
                try {
                    $powerMgmt = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
                    
                    if ($powerMgmt) {
                        [void]$nicPowerList.Add([PSCustomObject]@{
                            Name                        = $adapter.Name
                            AllowComputerToTurnOffDevice = $powerMgmt.AllowComputerToTurnOffDevice
                            AllowDeviceToWakeComputer   = $powerMgmt.AllowDeviceToWakeComputer
                        })
                    }
                }
                catch {
                    Write-Log -Message "Could not retrieve power management for adapter $($adapter.Name): $_" -Level WARN
                }
            }
        }
    }
    catch {
        Write-Log -Message "Error retrieving NIC power management: $_" -Level ERROR
    }
    
    return $nicPowerList
}

<#
.SYNOPSIS
    Retrieves TCP Chimney and RSS settings.
#>
function Get-TCPSettings {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering TCP Chimney and RSS settings..." -Level INFO
    
    try {
        if ($script:OSBuild -ge $script:Server2016Build) {
            $offloadSettings = Get-NetOffloadGlobalSetting -ErrorAction Stop
            
            return [PSCustomObject]@{
                ReceiveSideScaling = $offloadSettings.ReceiveSideScaling
                Chimney            = $offloadSettings.Chimney
                TaskOffload        = $offloadSettings.TaskOffload
                NetworkDirect      = $offloadSettings.NetworkDirect
            }
        }
        else {
            return [PSCustomObject]@{
                ReceiveSideScaling = "N/A"
                Chimney            = "N/A"
                TaskOffload        = "N/A"
                NetworkDirect      = "N/A"
            }
        }
    }
    catch {
        Write-Log -Message "Error retrieving TCP settings: $_" -Level WARN
        return [PSCustomObject]@{
            ReceiveSideScaling = "Error"
            Chimney            = "Error"
            TaskOffload        = "Error"
            NetworkDirect      = "Error"
        }
    }
}

#endregion

#region Disk Configuration Functions

<#
.SYNOPSIS
    Retrieves disk configuration including volume and partition information.
#>
function Get-DiskConfiguration {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering disk configuration..." -Level INFO
    
    $diskList = New-Object System.Collections.ArrayList
    
    try {
        $volumes = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3" -ErrorAction Stop
        
        foreach ($volume in $volumes) {
            $sizeGB = [math]::Round($volume.Capacity / 1GB, 2)
            $freeGB = [math]::Round($volume.FreeSpace / 1GB, 2)
            $usedGB = $sizeGB - $freeGB
            $percentFree = if ($sizeGB -gt 0) { [math]::Round(($freeGB / $sizeGB) * 100, 2) } else { 0 }
            
            [void]$diskList.Add([PSCustomObject]@{
                DriveLetter  = $volume.DriveLetter
                Label        = $volume.Label
                FileSystem   = $volume.FileSystem
                SizeGB       = $sizeGB
                UsedGB       = $usedGB
                FreeGB       = $freeGB
                PercentFree  = $percentFree
                BlockSize    = $volume.BlockSize
            })
        }
    }
    catch {
        Write-Log -Message "Error retrieving disk configuration: $_" -Level ERROR
    }
    
    return $diskList
}

<#
.SYNOPSIS
    Retrieves mount point and block size details.
#>
function Get-MountDiskBlockSize {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering mount disk and block size details..." -Level INFO
    
    $mountList = New-Object System.Collections.ArrayList
    
    try {
        $volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop
        
        foreach ($volume in $volumes) {
            if ($volume.Name -like "*:\*" -or $volume.Caption -like "*Volume*") {
                [void]$mountList.Add([PSCustomObject]@{
                    Name       = $volume.Name
                    Caption    = $volume.Caption
                    FileSystem = $volume.FileSystem
                    BlockSize  = $volume.BlockSize
                    Capacity   = [math]::Round($volume.Capacity / 1GB, 2)
                })
            }
        }
    }
    catch {
        Write-Log -Message "Error retrieving mount disk block size: $_" -Level ERROR
    }
    
    return $mountList
}

#endregion

#region Windows Features and Updates Functions

<#
.SYNOPSIS
    Retrieves installed Windows features (roles and features).
#>
function Get-WindowsFeatureList {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering Windows features..." -Level INFO
    
    $featureList = New-Object System.Collections.ArrayList
    
    try {
        $features = Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.InstallState -eq 'Installed' }
        
        foreach ($feature in $features) {
            [void]$featureList.Add([PSCustomObject]@{
                Name         = $feature.Name
                DisplayName  = $feature.DisplayName
                FeatureType  = $feature.FeatureType
                InstallState = $feature.InstallState
            })
        }
    }
    catch {
        Write-Log -Message "Error retrieving Windows features: $_" -Level ERROR
    }
    
    return $featureList
}

<#
.SYNOPSIS
    Retrieves installed hotfixes and updates.
#>
function Get-HotfixList {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering installed hotfixes..." -Level INFO
    
    $hotfixList = New-Object System.Collections.ArrayList
    
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object -Property InstalledOn -Descending
        
        foreach ($hotfix in $hotfixes) {
            [void]$hotfixList.Add([PSCustomObject]@{
                HotFixID    = $hotfix.HotFixID
                Description = $hotfix.Description
                InstalledBy = $hotfix.InstalledBy
                InstalledOn = $hotfix.InstalledOn
            })
        }
    }
    catch {
        Write-Log -Message "Error retrieving hotfixes: $_" -Level ERROR
    }
    
    return $hotfixList
}

#endregion

#region Software Inventory Functions

<#
.SYNOPSIS
    Retrieves installed software from registry.
#>
function Get-SoftwareInventory {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering software inventory..." -Level INFO
    
    $softwareList = New-Object System.Collections.ArrayList
    
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($path in $registryPaths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction Stop
            
            foreach ($item in $items) {
                if ($item.DisplayName) {
                    [void]$softwareList.Add([PSCustomObject]@{
                        DisplayName     = $item.DisplayName
                        DisplayVersion  = $item.DisplayVersion
                        Publisher       = $item.Publisher
                        InstallDate     = $item.InstallDate
                    })
                }
            }
        }
        catch {
            Write-Log -Message "Error reading registry path ${path}: $_" -Level WARN
        }
    }
    
    return ($softwareList | Sort-Object -Property DisplayName -Unique)
}

#endregion

#region Power Management Functions

<#
.SYNOPSIS
    Retrieves server power management configuration.
#>
function Get-PowerManagement {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering power management settings..." -Level INFO
    
    try {
        $powerPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -Filter "IsActive=True" -ErrorAction Stop
        
        return [PSCustomObject]@{
            ActivePowerPlan = $powerPlan.ElementName
            Description     = $powerPlan.Description
        }
    }
    catch {
        Write-Log -Message "Error retrieving power management settings: $_" -Level WARN
        return [PSCustomObject]@{
            ActivePowerPlan = "Error retrieving"
            Description     = "N/A"
        }
    }
}

#endregion

#region Firewall Functions

<#
.SYNOPSIS
    Retrieves Windows Firewall status for all profiles.
#>
function Get-FirewallStatus {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering firewall status..." -Level INFO
    
    $firewallList = New-Object System.Collections.ArrayList
    
    try {
        if ($script:OSBuild -ge $script:Server2016Build) {
            $profiles = Get-NetFirewallProfile -ErrorAction Stop
            
            foreach ($profile in $profiles) {
                [void]$firewallList.Add([PSCustomObject]@{
                    Profile                 = $profile.Name
                    Enabled                 = $profile.Enabled
                    DefaultInboundAction    = $profile.DefaultInboundAction
                    DefaultOutboundAction   = $profile.DefaultOutboundAction
                    AllowInboundRules       = $profile.AllowInboundRules
                    AllowLocalFirewallRules = $profile.AllowLocalFirewallRules
                })
            }
        }
        else {
            Write-Log -Message "Get-NetFirewallProfile cmdlet not available on this OS version" -Level WARN
        }
    }
    catch {
        Write-Log -Message "Error retrieving firewall status: $_" -Level ERROR
    }
    
    return $firewallList
}

#endregion

#region Page File Functions

<#
.SYNOPSIS
    Retrieves page file configuration.
#>
function Get-PageFileConfiguration {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering page file configuration..." -Level INFO
    
    $pageFileList = New-Object System.Collections.ArrayList
    
    try {
        $pageFiles = Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop
        
        foreach ($pageFile in $pageFiles) {
            [void]$pageFileList.Add([PSCustomObject]@{
                Name          = $pageFile.Name
                AllocatedSize = $pageFile.AllocatedBaseSize
                CurrentUsage  = $pageFile.CurrentUsage
                PeakUsage     = $pageFile.PeakUsage
            })
        }
        
        # Check if page file is system managed
        try {
            $autoManage = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if ($autoManage.AutomaticManagedPagefile) {
                [void]$pageFileList.Add([PSCustomObject]@{
                    Name          = "System Managed"
                    AllocatedSize = "Auto"
                    CurrentUsage  = "Auto"
                    PeakUsage     = "Auto"
                })
            }
        }
        catch { }
    }
    catch {
        Write-Log -Message "Error retrieving page file configuration: $_" -Level ERROR
    }
    
    return $pageFileList
}

<#
.SYNOPSIS
    Checks if "Clear Page File at Shutdown" is enabled in registry.
#>
function Get-ClearPageFileAtShutdown {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Checking Clear Page File at Shutdown setting..." -Level INFO
    
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -ErrorAction Stop
        
        return [PSCustomObject]@{
            Enabled = if ($regValue.ClearPageFileAtShutdown -eq 1) { "Yes" } else { "No" }
        }
    }
    catch {
        Write-Log -Message "Error checking Clear Page File at Shutdown: $_" -Level WARN
        return [PSCustomObject]@{
            Enabled = "Unknown"
        }
    }
}

#endregion

#region Registry Settings Functions

<#
.SYNOPSIS
    Checks if 8.3 naming creation is disabled.
#>
function Get-Disable83Naming {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Checking 8.3 naming creation setting..." -Level INFO
    
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation" -ErrorAction Stop
        
        return [PSCustomObject]@{
            Disabled = switch ($regValue.NtfsDisable8dot3NameCreation) {
                0 { "No (Enabled on all volumes)" }
                1 { "Yes (Disabled on all volumes)" }
                2 { "Per volume setting" }
                3 { "Disabled on all except system volume" }
                default { "Unknown" }
            }
        }
    }
    catch {
        Write-Log -Message "Error checking 8.3 naming setting: $_" -Level WARN
        return [PSCustomObject]@{
            Disabled = "Unknown"
        }
    }
}

<#
.SYNOPSIS
    Retrieves system file versions for critical files.
#>
function Get-SysFileVersions {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering system file versions..." -Level INFO
    
    $fileList = New-Object System.Collections.ArrayList
    
    $criticalFiles = @(
        "$env:SystemRoot\System32\ntoskrnl.exe",
        "$env:SystemRoot\System32\hal.dll",
        "$env:SystemRoot\System32\ntdll.dll",
        "$env:SystemRoot\System32\kernel32.dll",
        "$env:SystemRoot\System32\user32.dll"
    )
    
    foreach ($filePath in $criticalFiles) {
        try {
            if (Test-Path -Path $filePath) {
                $fileInfo = Get-Item -Path $filePath -ErrorAction Stop
                $versionInfo = $fileInfo.VersionInfo
                
                [void]$fileList.Add([PSCustomObject]@{
                    FileName       = $fileInfo.Name
                    FileVersion    = $versionInfo.FileVersion
                    ProductVersion = $versionInfo.ProductVersion
                    LastWriteTime  = $fileInfo.LastWriteTime
                })
            }
        }
        catch {
            Write-Log -Message "Error getting version for ${filePath}: $_" -Level WARN
        }
    }
    
    return $fileList
}

#endregion

#region Cluster Functions

<#
.SYNOPSIS
    Retrieves cluster information if the server is part of a cluster.
#>
function Get-ClusterInfo {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Checking cluster configuration..." -Level INFO
    
    $clusterData = @{
        IsClusterNode = $false
        ClusterName   = "N/A"
        NodeName      = "N/A"
        State         = "N/A"
        Groups        = @()
        Resources     = @()
        Networks      = @()
        SharedVolumes = @()
    }
    
    try {
        # Check if Cluster Service exists and is running
        $clusSvc = Get-Service -Name "ClusSvc" -ErrorAction SilentlyContinue
        
        if ($null -eq $clusSvc -or $clusSvc.Status -ne "Running") {
            Write-Log -Message "Cluster Service not found or not running. Server is not a cluster node." -Level INFO
            return $clusterData
        }
        
        # Service is running, safe to query cluster
        $clusterData.IsClusterNode = $true
        
        try {
            $cluster = Get-Cluster -ErrorAction Stop
            $clusterData.ClusterName = $cluster.Name
            
            $node = Get-ClusterNode -Name $env:COMPUTERNAME -ErrorAction Stop
            $clusterData.NodeName = $node.Name
            $clusterData.State = $node.State
            
            # Get cluster groups
            $groups = Get-ClusterGroup -ErrorAction SilentlyContinue
            $groupList = New-Object System.Collections.ArrayList
            foreach ($group in $groups) {
                [void]$groupList.Add([PSCustomObject]@{
                    Name       = $group.Name
                    OwnerNode  = $group.OwnerNode
                    State      = $group.State
                    GroupType  = $group.GroupType
                })
            }
            $clusterData.Groups = $groupList
            
            # Get cluster resources
            $resources = Get-ClusterResource -ErrorAction SilentlyContinue
            $resourceList = New-Object System.Collections.ArrayList
            foreach ($resource in $resources) {
                [void]$resourceList.Add([PSCustomObject]@{
                    Name          = $resource.Name
                    ResourceType  = $resource.ResourceType
                    State         = $resource.State
                    OwnerGroup    = $resource.OwnerGroup
                })
            }
            $clusterData.Resources = $resourceList
            
            # Get cluster networks
            $networks = Get-ClusterNetwork -ErrorAction SilentlyContinue
            $networkList = New-Object System.Collections.ArrayList
            foreach ($network in $networks) {
                [void]$networkList.Add([PSCustomObject]@{
                    Name  = $network.Name
                    Role  = $network.Role
                    State = $network.State
                })
            }
            $clusterData.Networks = $networkList
            
            # Get cluster shared volumes
            $csvs = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
            $csvList = New-Object System.Collections.ArrayList
            foreach ($csv in $csvs) {
                [void]$csvList.Add([PSCustomObject]@{
                    Name      = $csv.Name
                    OwnerNode = $csv.OwnerNode
                    State     = $csv.State
                })
            }
            $clusterData.SharedVolumes = $csvList
            
            # Generate cluster log
            try {
                Write-Log -Message "Generating cluster log..." -Level INFO
                $clusterLogPath = Join-Path -Path $ReportFolder -ChildPath "ClusterLog.log"
                Get-ClusterLog -Destination $ReportFolder -TimeSpan 15 -ErrorAction Stop | Out-Null
                Write-Log -Message "Cluster log saved to: $clusterLogPath" -Level INFO
            }
            catch {
                Write-Log -Message "Error generating cluster log: $_" -Level WARN
            }
        }
        catch {
            Write-Log -Message "Error retrieving cluster details: $_" -Level ERROR
        }
    }
    catch {
        Write-Log -Message "Error checking cluster service: $_" -Level WARN
    }
    
    return $clusterData
}

#endregion

#region Performance Counter Functions

<#
.SYNOPSIS
    Retrieves physical disk performance counters.
#>
function Get-PhysicalDiskPerfCounters {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering physical disk performance counters..." -Level INFO
    
    $perfList = New-Object System.Collections.ArrayList
    
    $counters = @(
        "\PhysicalDisk(*)\Avg. Disk sec/Read",
        "\PhysicalDisk(*)\Avg. Disk sec/Write",
        "\PhysicalDisk(*)\Avg. Disk Queue Length",
        "\PhysicalDisk(*)\Disk Reads/sec",
        "\PhysicalDisk(*)\Disk Writes/sec"
    )
    
    foreach ($counter in $counters) {
        try {
            $samples = Get-Counter -Counter $counter -ErrorAction Stop
            
            foreach ($sample in $samples.CounterSamples) {
                [void]$perfList.Add([PSCustomObject]@{
                    Counter      = $sample.Path
                    InstanceName = $sample.InstanceName
                    CookedValue  = [math]::Round($sample.CookedValue, 4)
                    TimeStamp    = $sample.Timestamp
                })
            }
        }
        catch {
            Write-Log -Message "Error retrieving counter ${counter}: $_" -Level WARN
        }
    }
    
    return $perfList
}

<#
.SYNOPSIS
    Retrieves processor performance counters.
#>
function Get-ProcessorPerfCounters {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering processor performance counters..." -Level INFO
    
    $perfList = New-Object System.Collections.ArrayList
    
    $counters = @(
        "\Processor(*)\% Processor Time",
        "\Processor(*)\% Privileged Time",
        "\Processor(*)\% User Time",
        "\Processor(*)\% Interrupt Time"
    )
    
    foreach ($counter in $counters) {
        try {
            $samples = Get-Counter -Counter $counter -ErrorAction Stop
            
            foreach ($sample in $samples.CounterSamples) {
                [void]$perfList.Add([PSCustomObject]@{
                    Counter      = $sample.Path
                    InstanceName = $sample.InstanceName
                    CookedValue  = [math]::Round($sample.CookedValue, 2)
                    TimeStamp    = $sample.Timestamp
                })
            }
        }
        catch {
            Write-Log -Message "Error retrieving counter ${counter}: $_" -Level WARN
        }
    }
    
    return $perfList
}

<#
.SYNOPSIS
    Retrieves memory performance counters.
#>
function Get-MemoryPerfCounters {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Gathering memory performance counters..." -Level INFO
    
    $perfList = New-Object System.Collections.ArrayList
    
    $counters = @(
        "\Memory\Available MBytes",
        "\Memory\Pages/sec",
        "\Memory\Pool Paged Bytes",
        "\Memory\Pool Nonpaged Bytes",
        "\Memory\Cache Bytes"
    )
    
    foreach ($counter in $counters) {
        try {
            $sample = Get-Counter -Counter $counter -ErrorAction Stop
            
            [void]$perfList.Add([PSCustomObject]@{
                Counter     = $sample.CounterSamples[0].Path
                CookedValue = [math]::Round($sample.CounterSamples[0].CookedValue, 2)
                TimeStamp   = $sample.CounterSamples[0].Timestamp
            })
        }
        catch {
            Write-Log -Message "Error retrieving counter ${counter}: $_" -Level WARN
        }
    }
    
    return $perfList
}

#endregion

#region Event Log Functions

<#
.SYNOPSIS
    Exports recent System and Application event logs to CSV and EVTX files.
#>
function Export-EventLogs {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Exporting event logs..." -Level INFO
    
    $logNames = @("System", "Application")
    
    foreach ($logName in $logNames) {
        try {
            # Export to CSV using Get-WinEvent (preferred method)
            $csvPath = Join-Path -Path $ReportFolder -ChildPath "$logName`_EventLog.csv"
            
            try {
                $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction Stop
                $events | Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName | 
                    Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
                
                Write-Log -Message "Exported $logName log to CSV: $csvPath" -Level INFO
            }
            catch {
                Write-Log -Message "Error exporting $logName log to CSV: $_" -Level WARN
            }
            
            # Export to EVTX
            $evtxPath = Join-Path -Path $ReportFolder -ChildPath "$logName`_EventLog.evtx"
            
            try {
                wevtutil epl $logName $evtxPath
                Write-Log -Message "Exported $logName log to EVTX: $evtxPath" -Level INFO
            }
            catch {
                Write-Log -Message "Error exporting $logName log to EVTX: $_" -Level WARN
            }
        }
        catch {
            Write-Log -Message "Error processing $logName event log: $_" -Level ERROR
        }
    }
}

#endregion

#region LGPO Parser Function

<#
.SYNOPSIS
    Converts LGPO data from text format (replaces Parse-LGPO).
#>
function ConvertFrom-LGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    try {
        # Check if LGPO.exe exists
        $lgpoPath = Join-Path -Path $PSScriptRoot -ChildPath "LGPO.exe"
        
        if (!(Test-Path -Path $lgpoPath)) {
            Write-Log -Message "LGPO.exe not found at: $lgpoPath" -Level WARN
            return @()
        }
        
        # Use call operator instead of Invoke-Expression
        $output = & $lgpoPath /parse /m $Path 2>&1
        
        return $output
    }
    catch {
        Write-Log -Message "Error parsing LGPO data: $_" -Level ERROR
        return @()
    }
}

#endregion

#region Main Execution

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "  Server Validator v$scriptversion" -ForegroundColor Cyan
Write-Host "  Server: $Computer" -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

Write-Log -Message "===== Server Validator v$scriptversion Started =====" -Level INFO
Write-Log -Message "Computer: $Computer" -Level INFO
Write-Log -Message "Output Path: $ReportFolder" -Level INFO

#region Collect General Information

Write-Host "[1/23] Collecting general information..." -ForegroundColor Yellow

$generalInfo = @{
    ComputerName       = $Computer
    Manufacturer       = $script:CachedCS.Manufacturer
    Model              = $script:CachedCS.Model
    DeviceType         = (Get-DeviceType)
    TotalProcessors    = $script:CachedCS.NumberOfProcessors
    TotalLogicalProcs  = $script:CachedCS.NumberOfLogicalProcessors
    TotalMemoryGB      = [math]::Round($script:CachedCS.TotalPhysicalMemory / 1GB, 2)
    OSName             = $script:OSCaption
    OSBuildNumber      = $script:OSBuild
    LicenseStatus      = (Get-ActivationStatus).LicenseStatus
    OSArchitecture     = $script:CachedOS.OSArchitecture
    InstallDate        = $script:CachedOS.InstallDate
    Domain             = $script:CachedCS.Domain
    DomainRole         = switch ($script:CachedCS.DomainRole) {
        0 { "Standalone Workstation" }
        1 { "Member Workstation" }
        2 { "Standalone Server" }
        3 { "Member Server" }
        4 { "Backup Domain Controller" }
        5 { "Primary Domain Controller" }
        default { "Unknown" }
    }
    Organization       = $script:CachedOS.Organization
    PSVersion          = (Get-PSInfo).Version
    PSExecutionPolicy  = (Get-PSInfo).ExecutionPolicy
    OU                 = (Get-OU).OU
}

Write-Log -Message "General information collected" -Level INFO

#endregion

#region Collect NIC Configuration

Write-Host "[2/23] Collecting NIC configuration..." -ForegroundColor Yellow
$nicConfiguration = @(Get-NICConfiguration)
Write-Log -Message "NIC configuration collected ($($nicConfiguration.Count) adapters)" -Level INFO

#endregion

#region Collect Disk Configuration

Write-Host "[3/23] Collecting disk configuration..." -ForegroundColor Yellow
$diskConfiguration = @(Get-DiskConfiguration)
Write-Log -Message "Disk configuration collected ($($diskConfiguration.Count) volumes)" -Level INFO

#endregion

#region Collect Windows Features

Write-Host "[4/23] Collecting Windows features..." -ForegroundColor Yellow
$windowsFeatures = @(Get-WindowsFeatureList)
Write-Log -Message "Windows features collected ($($windowsFeatures.Count) features)" -Level INFO

#endregion

#region Collect Updates and Hotfixes

Write-Host "[5/23] Collecting updates and hotfixes..." -ForegroundColor Yellow
$hotfixes = @(Get-HotfixList)
Write-Log -Message "Hotfixes collected ($($hotfixes.Count) hotfixes)" -Level INFO

#endregion

#region Collect Software Inventory

Write-Host "[6/23] Collecting software inventory..." -ForegroundColor Yellow
$softwareInventory = @(Get-SoftwareInventory)
Write-Log -Message "Software inventory collected ($($softwareInventory.Count) applications)" -Level INFO

#endregion

#region Collect Power Management

Write-Host "[7/23] Collecting power management settings..." -ForegroundColor Yellow
$powerManagement = Get-PowerManagement
Write-Log -Message "Power management settings collected" -Level INFO

#endregion

#region Collect Firewall Status

Write-Host "[8/23] Collecting firewall status..." -ForegroundColor Yellow
$firewallStatus = @(Get-FirewallStatus)
Write-Log -Message "Firewall status collected" -Level INFO

#endregion

#region Collect NIC Power Management

Write-Host "[9/23] Collecting NIC power management..." -ForegroundColor Yellow
$nicPowerManagement = @(Get-NICPowerManagement)
Write-Log -Message "NIC power management collected" -Level INFO

#endregion

#region Collect Page File Configuration

Write-Host "[10/23] Collecting page file configuration..." -ForegroundColor Yellow
$pageFileConfiguration = @(Get-PageFileConfiguration)
Write-Log -Message "Page file configuration collected" -Level INFO

#endregion

#region Collect Memory Dump Information

Write-Host "[11/23] Collecting memory dump information..." -ForegroundColor Yellow
$memoryDump = Get-MemoryDump
Write-Log -Message "Memory dump information collected" -Level INFO

#endregion

#region Collect System File Versions

Write-Host "[12/23] Collecting system file versions..." -ForegroundColor Yellow
$sysFileVersions = @(Get-SysFileVersions)
Write-Log -Message "System file versions collected" -Level INFO

#endregion

#region Collect TCP Settings

Write-Host "[13/23] Collecting TCP Chimney and RSS settings..." -ForegroundColor Yellow
$tcpSettings = Get-TCPSettings
Write-Log -Message "TCP settings collected" -Level INFO

#endregion

#region Collect Clear Page File at Shutdown

Write-Host "[14/23] Checking Clear Page File at Shutdown..." -ForegroundColor Yellow
$clearPageFile = Get-ClearPageFileAtShutdown
Write-Log -Message "Clear Page File at Shutdown checked" -Level INFO

#endregion

#region Collect Disable 8.3 Naming

Write-Host "[15/23] Checking 8.3 naming creation..." -ForegroundColor Yellow
$disable83Naming = Get-Disable83Naming
Write-Log -Message "8.3 naming setting checked" -Level INFO

#endregion

#region Collect Pending Reboot Status

Write-Host "[16/23] Checking pending reboot status..." -ForegroundColor Yellow
$pendingReboot = Get-PendingReboot
Write-Log -Message "Pending reboot status checked" -Level INFO

#endregion

#region Collect Mount Disk Block Size

Write-Host "[17/23] Collecting mount disk block size details..." -ForegroundColor Yellow
$mountDiskBlockSize = @(Get-MountDiskBlockSize)
Write-Log -Message "Mount disk block size collected" -Level INFO

#endregion

#region Collect Stopped Automatic Services

Write-Host "[18/23] Collecting stopped automatic services..." -ForegroundColor Yellow
$stoppedServices = @(Get-StoppedAutomaticService)
Write-Log -Message "Stopped automatic services collected ($($stoppedServices.Count) services)" -Level INFO

#endregion

#region Collect Cluster Information

Write-Host "[19/23] Collecting cluster information..." -ForegroundColor Yellow
$clusterInfo = Get-ClusterInfo
Write-Log -Message "Cluster information collected" -Level INFO

#endregion

#region Collect Physical Disk Performance Counters

Write-Host "[20/23] Collecting physical disk performance counters..." -ForegroundColor Yellow
$physicalDiskPerf = @(Get-PhysicalDiskPerfCounters)
Write-Log -Message "Physical disk performance counters collected" -Level INFO

#endregion

#region Collect Processor Performance Counters

Write-Host "[21/23] Collecting processor performance counters..." -ForegroundColor Yellow
$processorPerf = @(Get-ProcessorPerfCounters)
Write-Log -Message "Processor performance counters collected" -Level INFO

#endregion

#region Collect Memory Performance Counters

Write-Host "[22/23] Collecting memory performance counters..." -ForegroundColor Yellow
$memoryPerf = @(Get-MemoryPerfCounters)
Write-Log -Message "Memory performance counters collected" -Level INFO

#endregion

#region Export Event Logs

Write-Host "[23/23] Exporting event logs..." -ForegroundColor Yellow
Export-EventLogs
Write-Log -Message "Event logs exported" -Level INFO

#endregion

Write-Host ""
Write-Host "Data collection complete. Generating HTML report..." -ForegroundColor Green
Write-Log -Message "Data collection complete. Generating HTML report..." -Level INFO

#region Generate HTML Report

# Initialize HTML
$htmlContent = New-Object System.Collections.ArrayList
[void]$htmlContent.Add((New-HTMLReport -Title "Server Validator Report" -ComputerName $Computer -Version $scriptversion))

# Section 1: General Information
$section1Content = ""
foreach ($key in $generalInfo.Keys | Sort-Object) {
    $section1Content += Add-HTMLDetail -Label $key -Value $generalInfo[$key]
}
[void]$htmlContent.Add((Add-HTMLSection -Title "General Information" -Content $section1Content -SectionNumber 1))

# Section 2: NIC Configuration
$section2Content = Add-HTMLTable -Data $nicConfiguration
if ($nicConfiguration.Count -gt 0) {
    $threshold = if ($nicConfiguration.Count -gt 1) { "Multiple NICs detected" } else { "Single NIC" }
    $section2Content += Add-HTMLNewDetail -Heading "NIC Count" -Detail $nicConfiguration.Count -Reference "Baseline: 2+ recommended for servers" -Action $threshold
}
[void]$htmlContent.Add((Add-HTMLSection -Title "NIC Configuration" -Content $section2Content -SectionNumber 2))

# Section 3: Disk Configuration
$section3Content = Add-HTMLTable -Data $diskConfiguration
if ($diskConfiguration -and $diskConfiguration.Count -gt 0) {
    foreach ($disk in $diskConfiguration) {
        if ($disk.PercentFree -lt 10) {
            $action = "Warning: Low disk space"
        }
        elseif ($disk.PercentFree -lt 20) {
            $action = "Review: Monitor disk space"
        }
        else {
            $action = "OK"
        }
        
        $section3Content += Add-HTMLNewDetail -Heading "Disk $($disk.DriveLetter)" -Detail "$($disk.FreeGB) GB free ($($disk.PercentFree)%)" -Reference "Min: 10% free" -Action $action
    }
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Disk Configuration" -Content $section3Content -SectionNumber 3))

# Section 4: Windows Features
$section4Content = Add-HTMLTable -Data $windowsFeatures
[void]$htmlContent.Add((Add-HTMLSection -Title "Windows Features" -Content $section4Content -SectionNumber 4))

# Section 5: Updates and Hotfixes
$section5Content = Add-HTMLTable -Data $hotfixes
if ($hotfixes -and $hotfixes.Count -gt 0) {
    $latestHotfix = $hotfixes | Select-Object -First 1
    if ($latestHotfix -and $latestHotfix.InstalledOn) {
        $daysSinceUpdate = ((Get-Date) - $latestHotfix.InstalledOn).Days
        if ($daysSinceUpdate -gt 60) {
            $action = "Warning: No updates in $daysSinceUpdate days"
        }
        elseif ($daysSinceUpdate -gt 30) {
            $action = "Review: Last update $daysSinceUpdate days ago"
        }
        else {
            $action = "OK"
        }
        $section5Content += Add-HTMLNewDetail -Heading "Latest Update" -Detail "$($latestHotfix.HotFixID) - $($latestHotfix.InstalledOn)" -Reference "Update monthly" -Action $action
    }
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Updates and Hotfixes" -Content $section5Content -SectionNumber 5))

# Section 6: Software Inventory
$section6Content = Add-HTMLTable -Data $softwareInventory
[void]$htmlContent.Add((Add-HTMLSection -Title "Software Inventory" -Content $section6Content -SectionNumber 6))

# Section 7: Server Power Management
$section7Content = ""
if ($powerManagement) {
    $section7Content = Add-HTMLDetail -Label "Active Power Plan" -Value $powerManagement.ActivePowerPlan
    $section7Content += Add-HTMLDetail -Label "Description" -Value $powerManagement.Description

    if ($powerManagement.ActivePowerPlan -like "*High*") {
        $action = "OK"
    }
    else {
        $action = "Review: Consider High Performance plan"
    }
    $section7Content += Add-HTMLNewDetail -Heading "Power Plan" -Detail $powerManagement.ActivePowerPlan -Reference "Recommended: High Performance" -Action $action
}
else {
    $section7Content = "<p><em>Power management information could not be retrieved</em></p>"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Server Power Management" -Content $section7Content -SectionNumber 7))

# Section 8: Windows Firewall Status
$section8Content = Add-HTMLTable -Data $firewallStatus
if ($firewallStatus -and $firewallStatus.Count -gt 0) {
    foreach ($fw in $firewallStatus) {
        $action = if ($fw.Enabled) { "Enabled" } else { "Warning: Disabled" }
        $section8Content += Add-HTMLNewDetail -Heading "$($fw.Profile) Profile" -Detail "Enabled: $($fw.Enabled)" -Reference "Should be enabled" -Action $action
    }
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Windows Firewall Status" -Content $section8Content -SectionNumber 8))

# Section 9: NIC Power Management
$section9Content = Add-HTMLTable -Data $nicPowerManagement
if ($nicPowerManagement -and $nicPowerManagement.Count -gt 0) {
    foreach ($nic in $nicPowerManagement) {
        if ($nic.AllowComputerToTurnOffDevice -eq $true) {
            $action = "Warning: Power saving enabled"
        }
        else {
            $action = "OK"
        }
        $section9Content += Add-HTMLNewDetail -Heading $nic.Name -Detail "Allow PC to turn off: $($nic.AllowComputerToTurnOffDevice)" -Reference "Should be False for servers" -Action $action
    }
}
[void]$htmlContent.Add((Add-HTMLSection -Title "NIC Power Management" -Content $section9Content -SectionNumber 9))

# Section 10: Server Page File Configuration
$section10Content = Add-HTMLTable -Data $pageFileConfiguration
$totalMemoryGB = $generalInfo.TotalMemoryGB
$recommendedPageFileGB = [math]::Ceiling($totalMemoryGB * 1.5)

if ($pageFileConfiguration.Count -gt 0) {
    # Filter out non-numeric "Auto" entries before measuring
    $numericPageFiles = @($pageFileConfiguration | Where-Object { $_.AllocatedSize -is [int] -or $_.AllocatedSize -is [long] -or $_.AllocatedSize -is [double] -or $_.AllocatedSize -is [uint32] })
    $isAutoManaged = @($pageFileConfiguration | Where-Object { $_.AllocatedSize -eq "Auto" }).Count -gt 0
    
    if ($numericPageFiles.Count -gt 0) {
        $totalPageFileMB = ($numericPageFiles | Measure-Object -Property AllocatedSize -Sum).Sum
        $pageFileGB = [math]::Round($totalPageFileMB / 1024, 2)
        
        if ($pageFileGB -ge $recommendedPageFileGB) {
            $action = "OK"
        }
        else {
            $action = "Review: Consider 1.5x RAM"
        }
        $section10Content += Add-HTMLNewDetail -Heading "Total Page File" -Detail "$pageFileGB GB" -Reference "Recommended: $recommendedPageFileGB GB (1.5x RAM)" -Action $action
    }
    elseif ($isAutoManaged) {
        $section10Content += Add-HTMLNewDetail -Heading "Page File" -Detail "System Managed (Auto)" -Reference "Recommended: Manual 1.5x RAM for servers" -Action "Review: Consider fixed size"
    }
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Server Page File Configuration" -Content $section10Content -SectionNumber 10))

# Section 11: Server Memory Dump Information
$section11Content = ""
if ($memoryDump) {
    $section11Content = Add-HTMLDetail -Label "Dump Type" -Value $memoryDump.DumpType
    $section11Content += Add-HTMLDetail -Label "Dump File" -Value $memoryDump.DumpFile
    $section11Content += Add-HTMLDetail -Label "Minidump Directory" -Value $memoryDump.MinidumpDir
    $section11Content += Add-HTMLDetail -Label "Auto Reboot" -Value $memoryDump.AutoReboot

    if ($memoryDump.DumpType -in @("Complete memory dump", "Kernel memory dump", "Automatic memory dump")) {
        $action = "OK"
    }
    else {
        $action = "Review: Configure appropriate dump type"
    }
    $section11Content += Add-HTMLNewDetail -Heading "Memory Dump" -Detail $memoryDump.DumpType -Reference "Kernel or Complete recommended" -Action $action
}
else {
    $section11Content = "<p><em>Memory dump information could not be retrieved</em></p>"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Server Memory Dump Information" -Content $section11Content -SectionNumber 11))

# Section 12: Server System File Versions
$section12Content = ""
if ($sysFileVersions -and $sysFileVersions.Count -gt 0) {
    foreach ($file in $sysFileVersions) {
        $section12Content += Add-HTMLNewDetail -Heading $file.FileName -Detail "Version: $($file.FileVersion)" -Reference "Last Modified: $($file.LastWriteTime)" -Action "Info"
    }
}
else {
    $section12Content = "<p><em>No system file version data available</em></p>"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Server System File Versions" -Content $section12Content -SectionNumber 12))

# Section 13: TCP Chimney and RSS Settings
$section13Content = ""
if ($tcpSettings) {
    $section13Content = Add-HTMLDetail -Label "Receive Side Scaling" -Value $tcpSettings.ReceiveSideScaling
    $section13Content += Add-HTMLDetail -Label "TCP Chimney" -Value $tcpSettings.Chimney
    $section13Content += Add-HTMLDetail -Label "Task Offload" -Value $tcpSettings.TaskOffload
    $section13Content += Add-HTMLDetail -Label "Network Direct" -Value $tcpSettings.NetworkDirect
}
else {
    $section13Content = "<p><em>TCP settings could not be retrieved</em></p>"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "TCP Chimney and RSS Settings" -Content $section13Content -SectionNumber 13))

# Section 14: Clear Page File at Shutdown
$section14Content = ""
if ($clearPageFile) {
    $section14Content = Add-HTMLDetail -Label "Clear Page File at Shutdown" -Value $clearPageFile.Enabled
}
else {
    $section14Content = "<p><em>Clear Page File setting could not be retrieved</em></p>"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Clear Page File at Shutdown Registry" -Content $section14Content -SectionNumber 14))

# Section 15: Disable 8.3 Naming Creation
$section15Content = ""
if ($disable83Naming) {
    $section15Content = Add-HTMLDetail -Label "8.3 Naming Creation" -Value $disable83Naming.Disabled
}
else {
    $section15Content = "<p><em>8.3 naming setting could not be retrieved</em></p>"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Disable 8.3 Naming Creation" -Content $section15Content -SectionNumber 15))

# Section 16: Pending Reboot Status
$section16Content = ""
if ($pendingReboot) {
    $section16Content = Add-HTMLDetail -Label "Reboot Pending" -Value $pendingReboot.RebootPending
    $section16Content += Add-HTMLDetail -Label "Reasons" -Value $pendingReboot.Reasons

    if ($pendingReboot.RebootPending -eq $true) {
        $action = "Warning: Reboot required"
    }
    else {
        $action = "OK"
    }
    $section16Content += Add-HTMLNewDetail -Heading "Pending Reboot" -Detail $pendingReboot.RebootPending -Reference "Check reasons" -Action $action
}
else {
    $section16Content = "<p><em>Pending reboot status could not be determined</em></p>"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Pending Reboot Status" -Content $section16Content -SectionNumber 16))

# Section 17: Mount Disk Block Size Details
$section17Content = Add-HTMLTable -Data $mountDiskBlockSize
[void]$htmlContent.Add((Add-HTMLSection -Title "Mount Disk / Block Size Details" -Content $section17Content -SectionNumber 17))

# Section 18: Stopped Autostart Services
$section18Content = Add-HTMLTable -Data $stoppedServices
if ($stoppedServices.Count -gt 0) {
    $section18Content += Add-HTMLNewDetail -Heading "Stopped Services" -Detail "$($stoppedServices.Count) automatic services are stopped" -Reference "Review each service" -Action "Warning"
}
else {
    $section18Content += Add-HTMLNewDetail -Heading "Stopped Services" -Detail "All automatic services are running" -Reference "" -Action "OK"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Stopped Autostart Services" -Content $section18Content -SectionNumber 18))

# Section 19: Cluster Report
$section19Content = Add-HTMLDetail -Label "Is Cluster Node" -Value $clusterInfo.IsClusterNode
if ($clusterInfo.IsClusterNode) {
    $section19Content += Add-HTMLDetail -Label "Cluster Name" -Value $clusterInfo.ClusterName
    $section19Content += Add-HTMLDetail -Label "Node Name" -Value $clusterInfo.NodeName
    $section19Content += Add-HTMLDetail -Label "Node State" -Value $clusterInfo.State
    
    if ($clusterInfo.Groups.Count -gt 0) {
        $section19Content += "<h3>Cluster Groups</h3>"
        $section19Content += Add-HTMLTable -Data $clusterInfo.Groups
    }
    
    if ($clusterInfo.Resources.Count -gt 0) {
        $section19Content += "<h3>Cluster Resources</h3>"
        $section19Content += Add-HTMLTable -Data $clusterInfo.Resources
    }
    
    if ($clusterInfo.Networks.Count -gt 0) {
        $section19Content += "<h3>Cluster Networks</h3>"
        $section19Content += Add-HTMLTable -Data $clusterInfo.Networks
    }
    
    if ($clusterInfo.SharedVolumes.Count -gt 0) {
        $section19Content += "<h3>Cluster Shared Volumes</h3>"
        $section19Content += Add-HTMLTable -Data $clusterInfo.SharedVolumes
    }
}
else {
    $section19Content += "<p><em>Server is not part of a failover cluster</em></p>"
}
[void]$htmlContent.Add((Add-HTMLSection -Title "Cluster Report" -Content $section19Content -SectionNumber 19))

# Section 20: Physical Disk Performance Counters
$section20Content = Add-HTMLTable -Data $physicalDiskPerf
[void]$htmlContent.Add((Add-HTMLSection -Title "Physical Disk Performance Counter Snapshot" -Content $section20Content -SectionNumber 20))

# Section 21: Processor Performance Counters
$section21Content = Add-HTMLTable -Data $processorPerf
[void]$htmlContent.Add((Add-HTMLSection -Title "Processor Performance Counter Snapshot" -Content $section21Content -SectionNumber 21))

# Section 22: Memory Performance Counters
$section22Content = Add-HTMLTable -Data $memoryPerf
[void]$htmlContent.Add((Add-HTMLSection -Title "Memory Performance Counter Snapshot" -Content $section22Content -SectionNumber 22))

# Section 23: Event Log Export
$section23Content = "<p>Event logs have been exported to the following locations:</p>"
$section23Content += Add-HTMLDetail -Label "System Event Log (CSV)" -Value (Join-Path -Path $ReportFolder -ChildPath "System_EventLog.csv")
$section23Content += Add-HTMLDetail -Label "System Event Log (EVTX)" -Value (Join-Path -Path $ReportFolder -ChildPath "System_EventLog.evtx")
$section23Content += Add-HTMLDetail -Label "Application Event Log (CSV)" -Value (Join-Path -Path $ReportFolder -ChildPath "Application_EventLog.csv")
$section23Content += Add-HTMLDetail -Label "Application Event Log (EVTX)" -Value (Join-Path -Path $ReportFolder -ChildPath "Application_EventLog.evtx")
[void]$htmlContent.Add((Add-HTMLSection -Title "Event Log Export" -Content $section23Content -SectionNumber 23))

# Close HTML
[void]$htmlContent.Add((Close-HTMLReport))

# Write HTML to file
try {
    $htmlContent -join "`n" | Out-File -FilePath $HTMLReport -Encoding UTF8 -ErrorAction Stop
    Write-Log -Message "HTML report generated: $HTMLReport" -Level INFO
    Write-Host ""
    Write-Host "HTML report generated successfully!" -ForegroundColor Green
    Write-Host "Report location: $HTMLReport" -ForegroundColor Cyan
}
catch {
    Write-Log -Message "Error writing HTML report: $_" -Level ERROR
    Write-Host "Error generating HTML report: $_" -ForegroundColor Red
    exit 1
}

#endregion

#region Compress Report Folder

Write-Host ""
Write-Host "Compressing report folder..." -ForegroundColor Yellow

$zipPath = "$ReportFolder.zip"

try {
    Compress-Archive -Path "$ReportFolder\*" -DestinationPath $zipPath -Force -ErrorAction Stop
    Write-Log -Message "Report compressed: $zipPath" -Level INFO
    Write-Host "Report compressed successfully!" -ForegroundColor Green
    Write-Host "Compressed report: $zipPath" -ForegroundColor Cyan
}
catch {
    Write-Log -Message "Error compressing report: $_" -Level WARN
    Write-Host "Warning: Could not compress report folder: $_" -ForegroundColor Yellow
}

#endregion

#region Stop Transcript

if ($EnableLogging) {
    try {
        Stop-Transcript | Out-Null
        Write-Log -Message "Transcript stopped" -Level INFO
    }
    catch {
        Write-Log -Message "Error stopping transcript: $_" -Level WARN
    }
}

#endregion

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "  Server Validator v$scriptversion Completed" -ForegroundColor Cyan
Write-Host "  Total Sections: 23" -ForegroundColor Cyan
Write-Host "  Report Folder: $ReportFolder" -ForegroundColor Cyan
Write-Host "  HTML Report: $HTMLReport" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

Write-Log -Message "===== Server Validator v$scriptversion Completed Successfully =====" -Level INFO

# Exit with success code
exit 0

#endregion
