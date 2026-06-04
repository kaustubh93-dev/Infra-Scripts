# 🛠️ Infra-Scripts

A comprehensive collection of PowerShell infrastructure automation scripts for Windows Server administration, Azure hybrid cloud management, and security compliance.

---

## 📋 Table of Contents

- [Repository Structure](#-repository-structure)
- [Tools & Scripts](#-tools--scripts)
- [Technologies](#️-technologies)
- [Use Cases](#-use-cases)
- [Getting Started](#-getting-started)
- [License](#-license)

## 📁 Repository Structure

```
Infra-Scripts/
├── 100+ upgrade/                          # Windows Server 2022 in-place upgrade automation
├── Cloud-Hybrid Scripts/ArcMonitor/       # Azure Arc monitoring & onboarding suite
├── Cluster script/                        # Windows Failover Cluster health & FSW management
├── Security-DSC/                          # PowerShell DSC security baselines (compliance)
├── Hyper-V BIOS GUID Change Script/       # Hyper-V VM BIOS GUID manipulation
├── Secure Boot Status Checker/            # Multi-server Secure Boot compliance auditing
├── SecureBoot_2026_UpdateScripts_v1.0/    # UEFI Secure Boot 2026 cert expiry preparation
├── Task Scheduler/                        # Task Scheduler ACL & permission management
├── VSS Shadow Copy Investigation Script/  # Volume Shadow Copy Service diagnostics
├── Windows Server Troubleshooting Tool/   # Comprehensive server diagnostics (WSTT v2.5–v3.0)
├── azure-vm-terraform/                    # Terraform IaC for Azure VM provisioning
├── azure/                                 # KQL queries for Azure Log Analytics
└── ps-signed script/                      # PowerShell script signature validation
```

## 🔧 Tools & Scripts

| Folder | Purpose | Key Files | Description |
|--------|---------|-----------|-------------|
| **100+ upgrade** | OS Upgrade | `Upgrade-Server2022.ps1`, `v3.ps1` | Automated Windows Server 2022 in-place upgrade (v1→v3) |
| **Cloud-Hybrid Scripts/ArcMonitor** | Hybrid Cloud | `Start-ArcMonitor.ps1`, `ArcMonitor.psm1` | Azure Arc monitoring, onboarding, pre-req checks & TUI dashboard |
| **Cluster script** | HA/Clustering | `GetClusterServicestatus-remotely.ps1` | Failover Cluster health checks, FSW share & witness ACL management |
| **Security-DSC** | Compliance | `SecurityBaseline.ps1`, `Run-BaselineAudit.ps1` | PowerShell DSC configurations for security baselines |
| **Hyper-V BIOS GUID Change Script** | Virtualization | `Set-VMBiosGuid.ps1` | Programmatically change Hyper-V VM BIOS GUIDs for licensing |
| **Secure Boot Status Checker** | Security | `README.md` | Remote multi-server Secure Boot compliance auditing |
| **SecureBoot_2026_UpdateScripts** | Security | `Detect-SecureBootCertReadiness.ps1` | Prepare for June 2026 UEFI cert expiry (CVE-2023-24932) |
| **Task Scheduler** | Administration | `TaskPermissionManager.ps1` | Task Scheduler ACL and permission management tool |
| **VSS Shadow Copy Investigation** | Diagnostics | `1.ps1` | Volume Shadow Copy Service investigation & diagnostics |
| **Windows Server Troubleshooting Tool** | Diagnostics | `WSTT_v3.0.ps1`, `Validator_v5.0S.ps1` | Full-stack server diagnostics (v3.0 = 320KB) with Validator sub-tools |
| **azure-vm-terraform** | IaC | `main.tf`, `variables.tf` | Terraform templates for Azure VM provisioning |
| **azure** | Monitoring | `1.kusto`, `2.kusto` | KQL queries for Azure Log Analytics workspaces |
| **ps-signed script** | Security | `PSScriptSignCheckmultipledrive.ps1` | Validate PowerShell script signatures across multiple drives |

## 🛠️ Technologies

| Technology | Usage |
|------------|-------|
| **PowerShell 5.1+** | Core scripting language for all automation tools |
| **PowerShell DSC** | Desired State Configuration for security baselines |
| **Terraform** | Infrastructure as Code for Azure VM provisioning |
| **KQL (Kusto)** | Azure Log Analytics queries for monitoring |
| **Azure Arc** | Hybrid cloud server management and onboarding |

## 🎯 Use Cases

| Audience | Relevant Tools |
|----------|---------------|
| **Windows Server Admins** | WSTT, Cluster scripts, VSS diagnostics, OS upgrade automation |
| **Cloud & Hybrid Infra Teams** | ArcMonitor, azure-vm-terraform, KQL queries |
| **Security & Compliance Teams** | Secure Boot scripts, DSC baselines, script signature validation |
| **Virtualization Engineers** | Hyper-V BIOS GUID tool, Task Scheduler permissions |

## ⚡ Getting Started

```powershell
# 1. Clone the repository
git clone https://github.com/kaustubh93-dev/Infra-Scripts.git
cd Infra-Scripts

# 2. Navigate to the tool you need
cd "Windows Server Troubleshooting Tool"

# 3. Check for a sub-README (many tools include one)
Get-ChildItem -Filter *.md

# 4. Run the script (most require Administrator privileges)
.\WSTT_v3.0.ps1
```

> **Note:** Most scripts require **Run as Administrator**. Review each script's parameters and embedded documentation before execution in production environments.

## 📄 License

This repository is maintained for internal infrastructure automation. See individual folders for any specific licensing or usage notes.
