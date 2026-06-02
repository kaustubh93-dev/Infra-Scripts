# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: TSS Functions
# Source lines: 887 - 1082
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region TSS Functions
function Set-TSSPath {
    <#
    .SYNOPSIS
        Allows user to update the hardcoded TSS path
    .DESCRIPTION
        Prompts user for TSS installation path and validates it
    .OUTPUTS
        Boolean indicating if valid TSS path was set
    #>
    Write-Header "TSS Path Configuration"
    Write-Info "Current TSS Path: $($script:TSSPath)"
    Write-Info ""
    Write-Info "TSS (TroubleShootingScript) is the Microsoft-signed toolset used for"
    Write-Info "automated log collection (ETW, network traces, SDP reports, etc.)."
    Write-Info ""
    Write-Info "Download (official):"
    Write-Info "  - https://aka.ms/getTSS                    (TSS.zip - recommended)"
    Write-Info ""
    Write-Info "Documentation:"
    Write-Info "  - https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/introduction-to-troubleshootingscript-toolset-tss"
    Write-Info ""
    Write-Info "Tips:"
    Write-Info "  - Default extraction path is C:\TSS"
    Write-Info "  - After install, run:  .\TSS.ps1 -Update           (self-update to latest)"
    Write-Info "  - For unattended runs, append:  -AcceptEula"
    Write-Info "  - If blocked: Get-ChildItem -Recurse -Path C:\TSS\*.ps* | Unblock-File -Confirm:\$false"
    Write-Info ""

    $userPath = Read-Host "Enter the full path to TSS folder (or press Enter to keep current path)"
    
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        Write-Info "Keeping current TSS path: $($script:TSSPath)"
        return (Test-TSSAvailable)
    }
    
    # Validate the path
    if (-not (Test-Path $userPath -PathType Container)) {
        Write-DiagError "Invalid path: Directory does not exist"
        return $false
    }
    
    # Check if TSS.ps1 exists in the provided path
    $tssScript = Join-Path $userPath "TSS.ps1"
    if (-not (Test-Path $tssScript -PathType Leaf)) {
        Write-DiagError "TSS.ps1 not found in the specified directory: $($userPath)"
        Write-Info "Please ensure TSS.ps1 exists in the folder you specified."
        return $false
    }
    
    $script:TSSPath = $userPath
    Write-Success "TSS path updated to: $($script:TSSPath)"
    return $true
}

function Test-TSSAvailable {
    <#
    .SYNOPSIS
        Checks if TSS is available at the configured path
    .DESCRIPTION
        Verifies TSS.ps1 exists at the configured path
    .OUTPUTS
        Boolean indicating TSS availability
    #>
    if ([string]::IsNullOrWhiteSpace($script:TSSPath)) {
        Write-DiagWarning "TSS path not configured"
        Write-Info "Please configure TSS path from the main menu (option 15)"
        Write-Info "Download TSS from: https://aka.ms/getTSS  (default path: C:\TSS)"
        Write-Info "Docs: https://learn.microsoft.com/troubleshoot/windows-client/windows-tss/introduction-to-troubleshootingscript-toolset-tss"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-DiagWarning "TSS directory not found at: $($script:TSSPath)"
        Write-Info "Please update TSS path from the main menu (option 15)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (Test-Path $tssScript) {
        Write-Success "TSS found at: $($tssScript)"
        return $true
    }
    else {
        Write-DiagWarning "TSS.ps1 not found at: $($script:TSSPath)"
        Write-Info "Please verify TSS installation or update path from the main menu (option 15)"
        return $false
    }
}

function Invoke-TSSCommand {
    <#
    .SYNOPSIS
        Invokes a TSS command with proper path handling
    .PARAMETER Command
        The TSS command to execute (without the .\TSS.ps1 prefix)
    .EXAMPLE
        Invoke-TSSCommand "-SDP Net -AcceptEula"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -match '[&|;`\$\(\)\{\}]') {
                throw "TSS command contains forbidden shell metacharacters: $($_ -replace '[\w\s\-\\/:.,=]', '*')"
            }
            $true
        })]
        [string]$Command
    )
    
    if ([string]::IsNullOrWhiteSpace($script:TSSPath)) {
        Write-DiagError "TSS path not configured. Please configure from main menu (option 15)"
        return $false
    }
    
    if (-not (Test-Path $script:TSSPath -PathType Container)) {
        Write-DiagError "TSS directory not found at: $($script:TSSPath)"
        return $false
    }
    
    $tssScript = Join-Path $script:TSSPath "TSS.ps1"
    if (-not (Test-Path $tssScript)) {
        Write-DiagError "TSS.ps1 not found at: $($tssScript)"
        return $false
    }
    
    # S1: Verify the TSS script has a valid digital signature
    try {
        $sig = Get-AuthenticodeSignature -FilePath $tssScript -ErrorAction Stop
        switch ($sig.Status) {
            'Valid' {
                Write-Success "TSS.ps1 signature verified (signed by: $($sig.SignerCertificate.Subject))"
            }
            'NotSigned' {
                Write-DiagWarning "TSS.ps1 is NOT digitally signed. Verify you downloaded it from an official Microsoft source."
                $proceed = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                if ($proceed -ne "Y") {
                    Write-Info "TSS command cancelled by user."
                    return $false
                }
            }
            default {
                Write-DiagError "TSS.ps1 signature status: $($sig.Status) - $($sig.StatusMessage)"
                $proceed = Get-ValidatedChoice -Prompt "Continue anyway? (Y/N)" -ValidChoices @("Y", "N")
                if ($proceed -ne "Y") {
                    Write-Info "TSS command cancelled by user."
                    return $false
                }
            }
        }
    }
    catch {
        Write-DiagWarning "Could not verify TSS.ps1 signature: $($_.Exception.Message)"
    }
    
    try {
        # Change to TSS directory safely
        Push-Location $script:TSSPath

        # Execute TSS via -Command "& '<script>' <args>" instead of -File.
        # TSS.ps1 resolves its helper modules using $PSScriptRoot / $MyInvocation.InvocationName,
        # which behaves differently under -File and causes "There are no traces to start" errors
        # for -Xperf scenarios. Using & '<script>' matches how the user runs TSS manually.
        # See GitHub issues #2 and #3.
        Write-Info "Executing: powershell -Command `"& '$tssScript' $Command`""
        # Pass ArgumentList as an array so .NET quotes each element correctly.
        # A single-string ArgumentList that embeds quotes gets re-tokenized by
        # the native command-line splitter, producing parser errors like
        # "Unexpected token '-NewSession'" inside the child powershell.exe.
        $innerCommand = "& '$tssScript' $Command; exit `$LASTEXITCODE"
        $tssArgList = @(
            '-NoProfile',
            '-ExecutionPolicy', 'RemoteSigned',
            '-Command', $innerCommand
        )
        $proc = Start-Process -FilePath "powershell.exe" `
            -ArgumentList $tssArgList `
            -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -ne 0) {
            Write-DiagWarning "TSS process exited with code: $($proc.ExitCode)"
            Write-Info "If TSS reported 'There are no traces to start', verify your TSS version supports the requested -Xperf scenario and that xperf.exe is present under '$($script:TSSPath)\BinArch64\'."
        }
        
        Write-Success "TSS command completed"
        return $true
    }
    catch {
        Write-DiagError "Failed to execute TSS command: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Return to original location
        Pop-Location
    }
}
#endregion
