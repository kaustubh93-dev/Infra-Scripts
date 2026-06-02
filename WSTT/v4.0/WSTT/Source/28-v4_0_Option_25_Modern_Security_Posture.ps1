# ============================================================================
# WSTT module source — auto-generated from WSTT_v4.0.ps1
# Region: v4.0 — Option 25: Modern Security Posture
# Source lines: 8396 - 8516
# DO NOT EDIT BY HAND — run tools\Split-Module.ps1 to regenerate.
# ============================================================================
#region v4.0 — Option 25: Modern Security Posture
function Test-ModernSecurityPosture {
    <#
    .SYNOPSIS
        Audits VBS/HVCI/Credential Guard, LSA-PPL, ASR, BitLocker, LAPS, SMB1, SMB signing, Defender.
    #>
    [CmdletBinding()] param()
    Write-Header 'MODERN SECURITY POSTURE (Option 25)'

    Write-Section 'Secure Boot'
    if (Test-WSTTCommand 'Confirm-SecureBootUEFI') {
        try {
            $sb = Confirm-SecureBootUEFI -EA SilentlyContinue
            if ($sb) { Write-Success 'Secure Boot enabled.' -Category 'Security' -CheckId '25.1' }
            else { Write-DiagWarning 'Secure Boot DISABLED.' -Category 'Security' -CheckId '25.1' }
        } catch { Write-Info 'Secure Boot status unavailable (likely BIOS/legacy).' }
    }

    Write-Section 'TPM'
    if (Test-WSTTCommand 'Get-Tpm') {
        try {
            $t = Get-Tpm -EA SilentlyContinue
            if ($t.TpmPresent -and $t.TpmReady) { Write-Success "TPM present & ready (Spec=$($t.ManufacturerVersion))." -Category 'Security' -CheckId '25.2' }
            else { Write-DiagWarning "TPM not ready (Present=$($t.TpmPresent) Ready=$($t.TpmReady))" -Category 'Security' -CheckId '25.2' }
        } catch {}
    }

    Write-Section 'VBS / HVCI / Credential Guard'
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -EA SilentlyContinue
        if ($dg) {
            $running = @($dg.SecurityServicesRunning)
            $svcMap  = @{1='Credential Guard';2='HVCI';3='SystemGuard';4='SMM Firmware Measurement'}
            $names   = $running | ForEach-Object { $svcMap[$_] } | Where-Object { $_ }
            if ($names) { Write-Success "Running: $($names -join ', ')" -Category 'Security' -CheckId '25.3' }
            else { Write-DiagWarning 'No VBS-based security services are running.' -Category 'Security' -CheckId '25.3' }
        }
    } catch {}

    Write-Section 'LSA Protection (RunAsPPL)'
    try {
        $ppl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
        if ($ppl -ge 1) { Write-Success "LSA protection enabled (RunAsPPL=$ppl)." -Category 'Security' -CheckId '25.4' }
        else { Write-DiagWarning 'LSA protection (RunAsPPL) NOT enabled.' -Category 'Security' -CheckId '25.4' }
    } catch {}

    Write-Section 'ASR rules (Defender)'
    if (Test-WSTTCommand 'Get-MpPreference') {
        try {
            $mp = Get-MpPreference -EA SilentlyContinue
            $ids = @($mp.AttackSurfaceReductionRules_Ids)
            $act = @($mp.AttackSurfaceReductionRules_Actions)
            $enabled = 0
            for ($i=0; $i -lt $ids.Count; $i++) { if ($act[$i] -eq 1 -or $act[$i] -eq 2) { $enabled++ } }
            if ($enabled -gt 0) { Write-Success "$enabled ASR rules enabled (of $($ids.Count))." -Category 'Security' -CheckId '25.5' }
            else { Write-DiagWarning 'No ASR rules in Block/Audit mode.' -Category 'Security' -CheckId '25.5' }
        } catch {}
    }

    Write-Section 'BitLocker'
    if (Test-WSTTCommand 'Get-BitLockerVolume') {
        try {
            $bl = Get-BitLockerVolume -EA SilentlyContinue
            $unenc = $bl | Where-Object { $_.ProtectionStatus -ne 'On' -and $_.VolumeType -eq 'OperatingSystem' }
            if ($unenc) { Write-DiagWarning "OS volume(s) NOT BitLocker protected: $(($unenc.MountPoint) -join ',')" -Category 'Security' -CheckId '25.8' }
            else { Write-Success 'OS volume BitLocker-protected (or no OS volume reported).' -Category 'Security' -CheckId '25.8' }
        } catch {}
    }

    Write-Section 'Defender status'
    if (Test-WSTTCommand 'Get-MpComputerStatus') {
        try {
            $st = Get-MpComputerStatus -EA SilentlyContinue
            if ($st.AMRunningMode -ne 'Normal') { Write-DiagError "Defender mode: $($st.AMRunningMode)" -Category 'Security' -CheckId '25.9' }
            else { Write-Success "Defender Normal; signature age $($st.AntivirusSignatureAge)d." -Category 'Security' -CheckId '25.9' }
        } catch {}
    }

    Write-Section 'LAPS (Windows LAPS)'
    if (Get-Service LapsSvc -EA SilentlyContinue) { Write-Success 'Windows LAPS service installed.' -Category 'Security' -CheckId '25.11' }
    else { Write-Info 'Windows LAPS service not present.' }

    Write-Section 'SMB1'
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -EA SilentlyContinue
        if ($smb1 -and $smb1.State -eq 'Enabled') { Write-DiagError 'SMB1 is INSTALLED — remove it.' -Category 'Security' -CheckId '25.12' }
        else { Write-Success 'SMB1 not installed.' -Category 'Security' -CheckId '25.12' }
    } catch {}

    Write-Section 'SMB signing & encryption'
    try {
        $sc = Get-SmbServerConfiguration -EA SilentlyContinue
        if ($sc) {
            if (-not $sc.RequireSecuritySignature) { Write-DiagWarning 'SMB server signing not REQUIRED.' -Category 'Security' -CheckId '25.13' }
            else { Write-Success 'SMB server signing required.' -Category 'Security' -CheckId '25.13' }
            if (-not $sc.EncryptData) { Write-Info 'SMB data encryption not globally enabled.' }
            else { Write-Success 'SMB data encryption globally enabled.' -Category 'Security' -CheckId '25.13' }
        }
    } catch {}

    Write-Section 'NTLM compatibility level'
    try {
        $lm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel
        if ($lm -ge 5) { Write-Success "LmCompatibilityLevel=$lm (NTLMv2 only)." -Category 'Security' -CheckId '25.14' }
        else { Write-DiagWarning "LmCompatibilityLevel=$lm (recommend 5)." -Category 'Security' -CheckId '25.14' }
    } catch {}

    Write-Section 'Print Spooler (PrintNightmare)'
    try {
        $sp = Get-Service Spooler -EA SilentlyContinue
        $cap = Get-OSCapability
        if ($cap.IsDomainController -and $sp.Status -eq 'Running') {
            Write-DiagError 'Spooler RUNNING on a Domain Controller — high risk.' -Category 'Security' -CheckId '25.15'
        } elseif ($sp.Status -eq 'Running') {
            $rd = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name RestrictDriverInstallationToAdministrators -EA SilentlyContinue).RestrictDriverInstallationToAdministrators
            if ($rd -ne 1) { Write-DiagWarning 'Spooler running and RestrictDriverInstallationToAdministrators != 1.' -Category 'Security' -CheckId '25.15' }
            else { Write-Success 'Spooler running with PrintNightmare mitigation.' -Category 'Security' -CheckId '25.15' }
        } else { Write-Success 'Spooler not running.' -Category 'Security' -CheckId '25.15' }
    } catch {}
}
#endregion
