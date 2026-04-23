@{
    # Module manifest for ArcMonitor
    # Generated for Azure Arc Onboarding Monitor framework

    RootModule        = 'ArcMonitor.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a3f7c8d1-4e2b-4f9a-b6c5-d8e9f0a1b2c3'
    Author            = 'ArcMonitor Team'
    CompanyName       = 'Internal'
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Azure Arc Onboarding Monitor — Unified framework for onboarding and monitoring Azure Arc-enabled servers across all platforms (VMware, Azure Local, Hyper-V, Physical, KVM, Nutanix).'

    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Start-ArcMonitor'
        'Test-ArcPrerequisites'
        'Test-ValidServerName'
        'Test-ServerReachability'
        'Test-ArcNetworkRequirements'
        'Install-ArcAgentRemote'
        'Connect-ArcAgentRemote'
        'Start-ArcOnboarding'
        'Get-TargetPlatform'
        'Get-ArcAgentStatusRemote'
        'Test-HIMDSServiceRemote'
        'Repair-ArcPrerequisites'
        'Show-ArcDashboard'
        'Write-ArcLog'
        'Export-ArcOnboardingReport'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    # Private data for module metadata
    PrivateData = @{
        PSData = @{
            Tags         = @('Azure', 'Arc', 'Onboarding', 'Monitor', 'HybridCloud', 'Infrastructure')
            ProjectUri   = ''
            ReleaseNotes = @'
v1.0.0 — Initial module release
- 16 remote prerequisite checks with auto-remediation
- azcmagent exit code mapping (Microsoft error codes 1-23)
- DPAPI-encrypted credential storage
- Two-window TUI dashboard (Unicode box-drawing)
- PSScriptAnalyzer lint gate + Pester 5 test suite
- Retry logic with exponential backoff for transient errors
- Excel report export via ImportExcel
- Parallel server processing via PSThreadJob
'@
        }
    }
}
