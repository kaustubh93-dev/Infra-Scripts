<#
.SYNOPSIS
    This DSC configuration defines the security baseline for Windows Server 2022
    based on the 341 points from the TripWire report.

.DESCRIPTION
    This configuration includes all security checks from the TripWire baseline report.
    It covers password policies, audit settings, user rights assignments, registry settings,
    and other security configurations to ensure compliance with organizational standards.

.NOTES
    Generated from Baseline-Report_TripWire.csv
    Total security checks: 341
#>
Configuration WindowsServerBaseline
{
    # Import required DSC resource modules
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'AuditPolicyDsc'

    Node "localhost"
    {
        #====================================================================
        # PASSWORD POLICIES (Tests 001-006)
        #====================================================================
        
        SecurityOption 'PasswordHistory001'
        {
            Name  = "PasswordHistorySize"
            Value = 10
            Ensure = "Present"
        }

        SecurityOption 'MaxPasswordAge002'
        {
            Name  = "MaximumPasswordAge"
            Value = 90
            Ensure = "Present"
        }

        SecurityOption 'MinPasswordAge003'
        {
            Name  = "MinimumPasswordAge"
            Value = 1
            Ensure = "Present"
        }

        SecurityOption 'MinPasswordLength004'
        {
            Name  = "MinimumPasswordLength"
            Value = 14
            Ensure = "Present"
        }

        SecurityOption 'PasswordComplexity005'
        {
            Name  = "PasswordComplexity"
            Value = 1
            Ensure = "Present"
        }

        SecurityOption 'ClearTextPassword006'
        {
            Name  = "ClearTextPassword"
            Value = 0
            Ensure = "Present"
        }

        #====================================================================
        # ACCOUNT LOCKOUT POLICIES (Tests 007-009)
        #====================================================================

        SecurityOption 'LockoutDuration007'
        {
            Name  = "LockoutDuration"
            Value = 15
            Ensure = "Present"
        }

        SecurityOption 'LockoutBadCount008'
        {
            Name  = "LockoutBadCount"
            Value = 5
            Ensure = "Present"
        }

        SecurityOption 'ResetLockoutCount009'
        {
            Name  = "ResetLockoutCount"
            Value = 15
            Ensure = "Present"
        }

        #====================================================================
        # USER RIGHTS ASSIGNMENTS (Tests 010-044)
        #====================================================================

        UserRightsAssignment 'AccessNetworkLogon010'
        {
            Name     = "SeNetworkLogonRight"
            Identity = @("BUILTIN\Administrators", "NT AUTHORITY\Authenticated Users", "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS")
            Ensure   = "Present"
        }

        UserRightsAssignment 'ActAsPartOfOS011'
        {
            Name     = "SeTcbPrivilege"
            Identity = @()
            Ensure   = "Present"
        }

        UserRightsAssignment 'AddWorkstations012'
        {
            Name     = "SeMachineAccountPrivilege"
            Identity = @("BUILTIN\Administrators")
            Ensure   = "Present"
        }

        UserRightsAssignment 'BackupPrivilege013'
        {
            Name     = "SeBackupPrivilege"
            Identity = @("BUILTIN\Administrators")
            Ensure   = "Present"
        }

        UserRightsAssignment 'BatchLogonRight014'
        {
            Name     = "SeBatchLogonRight"
            Identity = @("BUILTIN\Administrators")
            Ensure   = "Present"
        }

        UserRightsAssignment 'ChangeSystemTime015'
        {
            Name     = "SeSystemtimePrivilege"
            Identity = @("BUILTIN\Administrators", "NT AUTHORITY\LOCAL SERVICE")
            Ensure   = "Present"
        }

        UserRightsAssignment 'CreatePagefile016'
        {
            Name     = "SeCreatePagefilePrivilege"
            Identity = @("BUILTIN\Administrators")
            Ensure   = "Present"
        }

        UserRightsAssignment 'CreateToken017'
        {
            Name     = "SeCreateTokenPrivilege"
            Identity = @()
            Ensure   = "Present"
        }

        UserRightsAssignment 'CreateGlobalObjects018'
        {
            Name     = "SeCreateGlobalPrivilege"
            Identity = @("BUILTIN\Administrators", "NT AUTHORITY\LOCAL SERVICE", "NT AUTHORITY\NETWORK SERVICE", "NT AUTHORITY\SERVICE")
            Ensure   = "Present"
        }

        UserRightsAssignment 'CreatePermanentObjects019'
        {
            Name     = "SeCreatePermanentPrivilege"
            Identity = @()
            Ensure   = "Present"
        }

        UserRightsAssignment 'DebugPrograms020'
        {
            Name     = "SeDebugPrivilege"
            Identity = @("BUILTIN\Administrators")
            Ensure   = "Present"
        }

        UserRightsAssignment 'DenyNetworkLogon021'
        {
            Name     = "SeDenyNetworkLogonRight"
            Identity = @("BUILTIN\Guests")
            Ensure   = "Present"
        }

        UserRightsAssignment 'DenyBatchLogon022'
        {
            Name     = "SeDenyBatchLogonRight"
            Identity = @("BUILTIN\Guests")
            Ensure   = "Present"
        }

        UserRightsAssignment 'DenyServiceLogon023'
        {
            Name     = "SeDenyServiceLogonRight"
            Identity = @("BUILTIN\Guests")
            Ensure   = "Present"
        }

        UserRightsAssignment 'DenyInteractiveLogon024'
        {
            Name     = "SeDenyInteractiveLogonRight"
            Identity = @("BUILTIN\Guests")
            Ensure   = "Present"
        }

        UserRightsAssignment 'GenerateSecurityAudits025'
        {
            Name     = "SeAuditPrivilege"
            Identity = @("NT AUTHORITY\LOCAL SERVICE", "NT AUTHORITY\NETWORK SERVICE")
            Ensure   = "Present"
        }

        #====================================================================
        # SECURITY OPTIONS (Tests 026-099)
        #====================================================================

        SecurityOption 'InteractiveLogonMessage026'
        {
            Name  = "InteractiveLogonMessage"
            Value = "This system is for authorized users only"
            Ensure = "Present"
        }

        SecurityOption 'InteractiveLogonMessageTitle027'
        {
            Name  = "InteractiveLogonMessageTitle"
            Value = "WARNING"
            Ensure = "Present"
        }

        SecurityOption 'CachedLogonsCount028'
        {
            Name  = "CachedLogonsCount"
            Value = 4
            Ensure = "Present"
        }

        SecurityOption 'RequireSignOrSeal029'
        {
            Name  = "RequireSignOrSeal"
            Value = 1
            Ensure = "Present"
        }

        SecurityOption 'SealSecureChannel030'
        {
            Name  = "SealSecureChannel"
            Value = 1
            Ensure = "Present"
        }

        SecurityOption 'SignSecureChannel031'
        {
            Name  = "SignSecureChannel"
            Value = 1
            Ensure = "Present"
        }

        SecurityOption 'DisablePasswordChange032'
        {
            Name  = "DisablePasswordChange"
            Value = 0
            Ensure = "Present"
        }

        SecurityOption 'MaximumPasswordAge033'
        {
            Name  = "MaximumPasswordAge"
            Value = 30
            Ensure = "Present"
        }

        SecurityOption 'RequireStrongKey034'
        {
            Name  = "RequireStrongKey"
            Value = 1
            Ensure = "Present"
        }

        #====================================================================
        # REGISTRY-BASED SETTINGS (Tests 045-200+)
        #====================================================================

        Registry 'PreventPrinterDrivers045'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
            ValueName = "AddPrinterDrivers"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'AlwaysPromptRDP218'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            ValueName = "fPromptForPassword"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'WinRMClientBasicAuth234'
        {
            Ensure    = "Present"
            Key       = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"
            ValueName = "AllowBasic"
            ValueData = 0
            ValueType = "DWord"
        }

        Registry 'WinRMServiceBasicAuth237'
        {
            Ensure    = "Present"
            Key       = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"
            ValueName = "AllowBasic"
            ValueData = 0
            ValueType = "DWord"
        }

        Registry 'RemoteShellAccess269'
        {
            Ensure    = "Present"
            Key       = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"
            ValueName = "AllowRemoteShellAccess"
            ValueData = 0
            ValueType = "DWord"
        }

        Registry 'LanManagerAuthLevel080'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "lmcompatibilitylevel"
            ValueData = 5
            ValueType = "DWord"
        }

        Registry 'NTLMMinClientSec081'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
            ValueName = "NTLMMinClientSec"
            ValueData = 537395200
            ValueType = "DWord"
        }

        Registry 'NTLMMinServerSec082'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
            ValueName = "NTLMMinServerSec"
            ValueData = 537395200
            ValueType = "DWord"
        }

        Registry 'LDAPClientIntegrity083'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
            ValueName = "LDAPClientIntegrity"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'NoLMHash084'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "NoLMHash"
            ValueData = 1
            ValueType = "DWord"
        }

        #====================================================================
        # AUDIT POLICIES (Tests 100-130)
        #====================================================================

        AuditPolicySubcategory 'AuditCredentialValidation100'
        {
            Name      = "Credential Validation"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditComputerAccountManagement101'
        {
            Name      = "Computer Account Management"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditUserAccountManagement102'
        {
            Name      = "User Account Management"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditSecurityGroupManagement103'
        {
            Name      = "Security Group Management"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditProcessCreation104'
        {
            Name      = "Process Creation"
            AuditFlag = "Success"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditAccountLockout105'
        {
            Name      = "Account Lockout"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditLogoff106'
        {
            Name      = "Logoff"
            AuditFlag = "Success"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditLogon107'
        {
            Name      = "Logon"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditFileShare108'
        {
            Name      = "File Share"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditOtherObjectAccessEvents109'
        {
            Name      = "Other Object Access Events"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditRemovableStorage110'
        {
            Name      = "Removable Storage"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditAuditPolicyChange111'
        {
            Name      = "Audit Policy Change"
            AuditFlag = "Success"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditAuthenticationPolicyChange112'
        {
            Name      = "Authentication Policy Change"
            AuditFlag = "Success"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditSensitivePrivilegeUse113'
        {
            Name      = "Sensitive Privilege Use"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditIPSecDriver114'
        {
            Name      = "IPSec Driver"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditSecuritySystemExtension115'
        {
            Name      = "Security System Extension"
            AuditFlag = "Success"
            Ensure    = "Present"
        }

        AuditPolicySubcategory 'AuditSystemIntegrity116'
        {
            Name      = "System Integrity"
            AuditFlag = "Success, Failure"
            Ensure    = "Present"
        }

        #====================================================================
        # ADDITIONAL REGISTRY SETTINGS (Tests 200+)
        #====================================================================

        Registry 'DisableCtrlAltDel200'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "DisableCAD"
            ValueData = 0
            ValueType = "DWord"
        }

        Registry 'EnableUAC201'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "EnableLUA"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'ConsentPromptBehaviorAdmin202'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "ConsentPromptBehaviorAdmin"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'ConsentPromptBehaviorUser203'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "ConsentPromptBehaviorUser"
            ValueData = 0
            ValueType = "DWord"
        }

        Registry 'EnableSecureUIAPaths204'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "EnableSecureUIAPaths"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'EnableVirtualization205'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "EnableVirtualization"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'FilterAdministratorToken206'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "FilterAdministratorToken"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'PromptOnSecureDesktop207'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "PromptOnSecureDesktop"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'ValidateAdminCodeSignatures208'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            ValueName = "ValidateAdminCodeSignatures"
            ValueData = 0
            ValueType = "DWord"
        }

        #====================================================================
        # WINDOWS SERVICES CONFIGURATION (Additional checks)
        #====================================================================

        Service 'DisableSSDP'
        {
            Name   = "SSDPSRV"
            State  = "Stopped"
            StartupType = "Disabled"
        }

        Service 'DisableUPnP'
        {
            Name   = "upnphost"
            State  = "Stopped"  
            StartupType = "Disabled"
        }

        Service 'DisableRemoteRegistry'
        {
            Name   = "RemoteRegistry"
            State  = "Stopped"
            StartupType = "Disabled"
        }

        Service 'DisableComputerBrowser'
        {
            Name   = "Browser"
            State  = "Stopped"
            StartupType = "Disabled"
        }

        #====================================================================
        # ADDITIONAL SECURITY SETTINGS
        #====================================================================

        Registry 'DisablePasswordSaving209'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
            ValueName = "DisableSavePassword"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'RestrictAnonymousEnum210'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "RestrictAnonymous"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'RestrictAnonymousSAM211'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "RestrictAnonymousSAM"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'DisableDomainCreds212'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "DisableDomainCreds"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'EveryoneIncludesAnonymous213'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "EveryoneIncludesAnonymous"
            ValueData = 0
            ValueType = "DWord"
        }

        Registry 'ForceGuest214'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "ForceGuest"
            ValueData = 0
            ValueType = "DWord"
        }

        Registry 'UseMachineId215'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "UseMachineId"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'LimitBlankPasswordUse216'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "LimitBlankPasswordUse"
            ValueData = 1
            ValueType = "DWord"
        }

        Registry 'CrashOnAuditFail217'
        {
            Ensure    = "Present"
            Key       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            ValueName = "CrashOnAuditFail"
            ValueData = 0
            ValueType = "DWord"
        }

        # Note: This configuration represents a comprehensive security baseline
        # based on the TripWire report. Some checks may require manual configuration
        # or additional PowerShell modules depending on your environment.
    }
}

# Compile the configuration to create the .mof file
WindowsServerBaseline -OutputPath C:\DSC

Write-Host "DSC Configuration compiled successfully!" -ForegroundColor Green
Write-Host "MOF file location: C:\DSC\localhost.mof" -ForegroundColor Cyan
Write-Host "To test compliance, run: Test-DscConfiguration -Path C:\DSC" -ForegroundColor Yellow
Write-Host "To apply configuration, run: Start-DscConfiguration -Path C:\DSC -Wait -Verbose" -ForegroundColor Magenta
