# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: Output and Display Functions
# Source lines: 356 - 451
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region Output and Display Functions

function Write-Header {
    <#
    .SYNOPSIS
        Displays a formatted header
    .PARAMETER Text
        The header text to display
    #>
    param([string]$Text)
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Section {
    <#
    .SYNOPSIS
        Displays a section divider with title for readable output grouping
    .PARAMETER Text
        The section title
    #>
    param([string]$Text)
    Write-Host ""
    Write-Host "--- $Text ---" -ForegroundColor DarkCyan
}

function Write-Success {
    <#
    .SYNOPSIS
        Displays a success message
    .PARAMETER Text
        The success message to display
    #>
    param([string]$Text, [string]$Category = 'General', [string]$CheckId = '')
    Write-Host "[SUCCESS] $($Text)" -ForegroundColor Green
    Add-Finding -Severity 'INFO' -Category $Category -CheckId $CheckId -Message $Text
}

function Write-DiagWarning {
    <#
    .SYNOPSIS
        Displays a warning message
    .PARAMETER Text
        The warning message to display
    #>
    param([string]$Text, [string]$Category = 'General', [string]$CheckId = '')
    # Forward to the built-in warning cmdlet to preserve expected behavior
    $safeText = Protect-DiagMessage -Message $Text
    Microsoft.PowerShell.Utility\Write-Warning -Message $safeText
    if ($safeText -ne $Text) { Write-Verbose "[WARNING FULL] $Text" }
    Add-Finding -Severity 'WARN' -Category $Category -CheckId $CheckId -Message $safeText
}

function Protect-DiagMessage {
    <#
    .SYNOPSIS
        Redacts potentially sensitive information from diagnostic messages
    .PARAMETER Message
        The message to sanitize
    #>
    param([string]$Message)
    # Redact UNC paths (\\server\share)
    $Message = $Message -replace '\\\\[^\s\\]+\\[^\s\\]+', '\\\\***\***'
    # Redact email addresses
    $Message = $Message -replace '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '***@***'
    # Redact domain\user patterns
    $Message = $Message -replace '(?<=[^\w])([A-Z][A-Z0-9]+)\\([A-Za-z0-9._-]+)(?=[^\w]|$)', '$1\***'
    return $Message
}

function Write-DiagError {
    <#
    .SYNOPSIS
        Displays an error message
    .PARAMETER Text
        The error message to display
    #>
    param([string]$Text, [string]$Category = 'General', [string]$CheckId = '')
    $safeText = Protect-DiagMessage -Message $Text
    Write-Host "[ERROR] $safeText" -ForegroundColor Red
    if ($safeText -ne $Text) { Write-Verbose "[ERROR FULL] $Text" }
    Add-Finding -Severity 'ERROR' -Category $Category -CheckId $CheckId -Message $safeText
}

function Write-Info {
    <#
    .SYNOPSIS
        Displays an informational message
    .PARAMETER Text
        The informational message to display
    #>
    param([string]$Text)
    Write-Host "[INFO] $($Text)" -ForegroundColor White
}
#endregion
