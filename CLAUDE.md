# CLAUDE.md — Infra-Scripts Repository Standards

This file defines coding standards for all PowerShell scripts in this repository.
These rules are automatically applied when working in this codebase.

## Language & Runtime

- PowerShell 5.1+ minimum. PS 7+ preferred for new scripts.
- All scripts must start with `#Requires -Version 5.1`
- All entry points must set `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`

## Coding Standards

### Functions
- Use `[CmdletBinding()]` on ALL functions
- Use approved verbs only (`Get-Verb` to check)
- Singular nouns: `Get-Server` not `Get-Servers`
- Add `[ValidateNotNullOrEmpty()]` on all mandatory string parameters
- Add `[SupportsShouldProcess]` on functions that modify system state
- Functions should be < 50 lines. Extract helpers for complex logic.

### Variables & Scope
- No `$Global:` scope — use `$script:` or module-scoped variables
- Never shadow automatic variables (`$input`, `$args`, `$this`, `$_`)
- Type pipeline results for StrictMode safety: `[string[]]$servers = @($pipeline)`
- Use `@($var).Count` instead of `$var.Count` for values that may be scalar

### Collections
- NEVER use `$array += $item` in loops — it's O(n²)
- Use `[System.Collections.Generic.List[object]]::new()` with `.Add()`
- Use `[System.Collections.Concurrent.ConcurrentBag[object]]` for parallel scenarios

### Error Handling
- `try/catch/finally` around: remote sessions, file I/O, web requests, external process calls
- Map external tool exit codes to human-readable messages with remediation guidance
- Retry transient failures with exponential backoff (network errors, HTTP 429/5xx)
- Clean up resources in `finally` blocks (PSSessions, TcpClients, env vars)

## Security Requirements

### Credentials
- NEVER store plaintext secrets in `.ps1` files
- Use `Export-Clixml` (DPAPI encryption) for local credential storage
- Use Azure Key Vault for production/shared environments
- Pass secrets via environment variables, NOT command-line arguments
- Clean sensitive env vars in `finally` blocks: `Remove-Item Env:\SECRET -ErrorAction SilentlyContinue`
- Mask secrets in console output — show last 4 chars max

### Execution Policy
- NEVER use `-ExecutionPolicy Bypass` — use `RemoteSigned`
- Sign scripts for production environments

### Transport
- Prefer WinRM over HTTPS (port 5986) for credential passing
- Always set PSSession timeouts: `New-PSSessionOption -OpenTimeout 30000`
- Verify Authenticode signatures on downloaded scripts before execution

### Input Validation
- Validate server names against RFC 1123 hostname or IPv4 regex
- Validate GUIDs (TenantId, SubscriptionId) before passing to external tools
- Never trust user input in `Invoke-Expression` or string-interpolated commands

## Testing Requirements

### Minimum Test Coverage
Every script/module must have a companion Pester 5 test file in `Tests/`:
1. **PSScriptAnalyzer lint gate** — 0 Error-level violations
2. **Security baseline** — no ExecutionPolicy Bypass, no $Global:, no plaintext secrets
3. **Input validation** — test edge cases for all user-facing parameters
4. **Core logic** — at least 1 test per public function

### Running Tests
```powershell
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester .\Tests\ -Output Detailed
```

## Module Structure

Projects with 3+ related functions should be organized as a module:
```
ModuleName/
├── ModuleName.psd1       # Module manifest
├── ModuleName.psm1       # Root module
├── Public/               # Exported functions
├── Private/              # Internal helpers
├── Config/               # defaults.json, schemas
├── Tests/                # Pester tests
├── docs/help/            # platyPS markdown help
├── .build.ps1            # Invoke-Build pipeline
└── README.md
```

## Build Pipeline

Module projects should include `.build.ps1` with Invoke-Build tasks:
- `Clean` — remove output directory
- `Analyze` — PSScriptAnalyzer (fail on errors)
- `Test` — Pester 5 (NUnit XML output)
- `Package` — copy to output for distribution

## Logging Standards

- `Start-Transcript` in entry point scripts for audit trails
- Structured log format: `"YYYY-MM-DD HH:MM:SS [LEVEL] Message"`
- Daily log rotation: `ScriptName_YYYYMMDD.log`
- NEVER log secrets, passwords, tokens, or connection strings
- Log all remote operations: registry changes, service control, reboots, file deletions

## Recommended Modules (awesome-powershell)

| Module | Purpose | Required |
|--------|---------|----------|
| PSScriptAnalyzer | Static code analysis | Yes — all projects |
| Pester 5 | BDD testing framework | Yes — all projects |
| InvokeBuild | Build automation | Yes — module projects |
| platyPS | Help generation | Recommended — modules |
| ImportExcel | Excel report export | Recommended — reporting scripts |
| PSThreadJob | Parallel processing | Recommended — multi-server ops |

## File Limits
- Scripts: < 800 lines per file
- Functions: < 50 lines per function
- Config values: externalize to JSON, not hardcoded in scripts
