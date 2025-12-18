# Windows Server Security Baseline with DSC and Azure Policy

This project provides a comprehensive framework for auditing and enforcing a security baseline on Windows Servers. It uses PowerShell Desired State Configuration (DSC) to codify security rules derived from a TripWire security report and includes instructions for deploying these configurations at scale using Azure Policy Guest Configuration for Azure Arc-enabled servers.

## Overview

The primary goal of this project is to automate the process of security compliance checking. Instead of manual audits or relying solely on third-party tools, this solution leverages native Microsoft technologies to:
1.  **Define a Baseline as Code**: Translate security requirements from a CSV report into a reusable PowerShell DSC script.
2.  **Audit Locally**: Run an on-demand audit against a local server to check for compliance and get a detailed report of non-compliant settings.
3.  **Enforce at Scale with Azure**: Wrap the DSC configuration in an Azure Policy to continuously audit and (optionally) auto-remediate your entire fleet of Azure Arc-enabled servers.

## Project Components

This repository contains the following key files:

*   `Baseline-Report_TripWire.csv`: The source security report containing 328 configuration checks for Windows Server. This file is the "source of truth" for the desired security posture.
*   `SecurityBaseline.ps1`: The PowerShell DSC configuration script. This file defines the entire security baseline by translating the rules from the CSV into DSC resource blocks (e.g., `Registry`, `SecurityOption`, `UserRightsAssignment`).
*   `Run-BaselineAudit.ps1`: A PowerShell script designed to run a local audit. It compiles the `SecurityBaseline.ps1` configuration and uses `Test-DscConfiguration` to compare the server's current state against the desired state, outputting a report of any deviations.
*   `RemediateTripwireFailures.ps1`: A PowerShell DSC script focused on remediating the specific failures identified in the initial report. It includes the logic to package the DSC into a `.zip` file for use with Azure Guest Configuration.
*   `azure-policy-guest-config.json`: The Azure Policy definition file. This JSON template defines a `DeployIfNotExists` policy that assigns the DSC configuration to Azure Arc-enabled servers, enabling at-scale auditing and enforcement.

## Prerequisites

Before using these scripts, ensure your environment meets the following requirements:

1.  **PowerShell**: PowerShell 5.1 or later.
2.  **PowerShell Modules**: The following modules must be installed on the machine where you will run the scripts. Run these commands in an elevated PowerShell prompt:
    ```
    # For authoring the DSC configuration
    Install-Module -Name SecurityPolicyDsc -Force
    Install-Module -Name AuditPolicyDsc -Force

    # For creating the Azure Guest Configuration package
    Install-Module -Name GuestConfiguration -Force
    ```
3.  **Azure Permissions**: To deploy the Azure Policy, you need permissions to create and assign policy definitions (e.g., `Resource Policy Contributor`) and create storage accounts (e.g., `Contributor`).

## Usage Instructions

### Method 1: Local Audit and Reporting

Use this method to run an on-demand audit on a single server.

1.  **Populate the Baseline**: Open `SecurityBaseline.ps1` and add DSC resource blocks for all 328 security checks from the `Baseline-Report_TripWire.csv` file. Examples for different types of checks (Registry, Security Policy, etc.) are provided in the script.
2.  **Run the Audit Script**: Open an elevated PowerShell prompt, navigate to the project directory, and execute the `Run-BaselineAudit.ps1` script.
    ```
    .\Run-BaselineAudit.ps1
    ```
3.  **Review the Output**: The script will output the compliance status. If the server is non-compliant, it will display a formatted table showing the setting, its current (actual) value, and the expected state.

### Method 2: At-Scale Auditing with Azure Policy

Use this method to apply the baseline to all your Azure Arc-enabled servers.

1.  **Create the DSC Package**:
    *   Open `RemediateTripwireFailures.ps1` (or your comprehensive `SecurityBaseline.ps1`).
    *   Run the script. This will compile the DSC and create a `RemediateTripwireFailures.zip` file in the output directory.

2.  **Upload to Azure Blob Storage**:
    *   Upload the generated `.zip` file to a container in an Azure Storage Account.
    *   Generate a **SAS URL** for the blob with read permissions.

3.  **Create and Assign the Azure Policy**:
    *   In the Azure portal, navigate to **Policy** > **Definitions**.
    *   Click **+ Policy definition** and paste the content of `azure-policy-guest-config.json`. **Important**: Update the `contentUri` property in the JSON with the SAS URL you generated.
    *   Save the definition.
    *   Assign the newly created policy to the management group, subscription, or resource group containing your Azure Arc-enabled servers.
    *   On the **Remediation** tab, check the box to **Create a remediation task**. This allows the policy to not only audit but also enforce the configuration.

4.  **Monitor Compliance**: View the compliance state of all your servers from the Azure Policy compliance dashboard. You can drill down into individual servers to see which specific settings are non-compliant.

