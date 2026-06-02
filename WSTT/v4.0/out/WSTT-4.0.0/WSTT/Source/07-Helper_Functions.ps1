# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Helper Functions
# Source lines: 520 - 689
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Helper Functions
function Initialize-DiagnosticPaths {
    <#
    .SYNOPSIS
        Initializes diagnostic paths and ensures they exist
    .DESCRIPTION
        Creates necessary directories for logs and reports
    #>
    try {
        if (-not (Test-Path $script:TempBasePath)) {
            New-Item -Path $script:TempBasePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Info "Created diagnostic base path: $($script:TempBasePath)"
        }
        
        if (-not (Test-Path $script:DefaultLogPath)) {
            New-Item -Path $script:DefaultLogPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        
        return $true
    }
    catch {
        Write-DiagError "Failed to initialize diagnostic paths: $($_.Exception.Message)"
        return $false
    }
}

function Test-PathValid {
    <#
    .SYNOPSIS
        Validates and optionally creates a path
    .PARAMETER Path
        The path to validate
    .PARAMETER CreateIfNotExist
        If specified, creates the path if it doesn't exist
    #>
    param(
        [string]$Path,
        [switch]$CreateIfNotExist
    )
    
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    
    # Security: Reject path traversal, injection, and non-rooted paths
    if ($Path -match '\.\.' -or $Path -match '[\$\(\)&\|;`]' -or $Path -match '^\s*\\\\[^\\]+\\[^\\]+') {
        Write-DiagError "Path rejected for security: contains traversal, special characters, or UNC path"
        return $false
    }
    
    # Validate path format
    if (-not (Test-Path $Path -IsValid)) {
        Write-DiagError "Invalid path format: $($Path)"
        return $false
    }
    
    # Check if path exists
    if (-not (Test-Path $Path)) {
        if ($CreateIfNotExist) {
            try {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Success "Created directory: $($Path)"
                return $true
            }
            catch {
                Write-DiagError "Cannot create directory: $($_.Exception.Message)"
                return $false
            }
        }
        else {
            Write-DiagWarning "Path does not exist: $($Path)"
            return $false
        }
    }
    
    return $true
}

function Get-ValidatedChoice {
    <#
    .SYNOPSIS
        Prompts user for input and validates against allowed values
    .PARAMETER Prompt
        The prompt message
    .PARAMETER ValidChoices
        Array of valid choices
    .PARAMETER AllowEmpty
        If specified, allows empty input
    #>
    param(
        [string]$Prompt,
        [string[]]$ValidChoices,
        [switch]$AllowEmpty
    )
    
    do {
        $choice = Read-Host $Prompt
        
        if ([string]::IsNullOrWhiteSpace($choice) -and $AllowEmpty) {
            return ""
        }
        
        if ($choice -in $ValidChoices) {
            return $choice
        }
        
        Write-DiagWarning "Invalid choice. Please enter one of: $($ValidChoices -join ', ')"
    } while ($true)
}

function Invoke-WithTSSCheck {
    <#
    .SYNOPSIS
        Executes a command with TSS availability check
    .PARAMETER TSSCommand
        The TSS command to execute (without .\TSS.ps1 prefix)
    .PARAMETER ManualAlternativeAction
        Script block to execute if TSS is not available
    .PARAMETER Description
        Description of the operation
    #>
    param(
        [string]$TSSCommand,
        [scriptblock]$ManualAlternativeAction,
        [string]$Description
    )
    
    if (Test-TSSAvailable) {
        Write-Info $Description
        $confirm = Get-ValidatedChoice -Prompt "Start trace? (Y/N)" -ValidChoices @("Y", "N")
        
        if ($confirm -eq "Y") {
            Invoke-TSSCommand -Command $TSSCommand
        }
    }
    else {
        if ($ManualAlternativeAction) {
            & $ManualAlternativeAction
        }
    }
}

function Get-ProcessAnalysis {
    <#
    .SYNOPSIS
        Analyzes process resource usage
    .DESCRIPTION
        Gets top processes by CPU and Memory usage in a single call
    .PARAMETER TopCount
        Number of top processes to return (default: 10)
    #>
    param(
        [int]$TopCount = 10
    )
    
    try {
        $processes = Get-Process -ErrorAction Stop
        
        return @{
            ByCPU    = $processes | Sort-Object CPU -Descending | Select-Object -First $TopCount
            ByMemory = $processes | Sort-Object WS -Descending | Select-Object -First $TopCount
            Total    = $processes.Count
        }
    }
    catch {
        Write-DiagError "Failed to retrieve process information: $($_.Exception.Message)"
        return $null
    }
}
#endregion
