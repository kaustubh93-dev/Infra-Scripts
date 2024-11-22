# Secure Boot Status Checker

This PowerShell script checks the Secure Boot status of a list of servers and exports the results to a CSV file.

## Prerequisites

- PowerShell 5.1 or later
- A list of server names in a text file located at `C:\temp\ServerList.txt`
- Necessary permissions to run remote commands on the servers

## Usage

1. **Prepare the Server List:**
   - Create a text file named `ServerList.txt` in the `C:\temp\` directory.
   - Add the names of the servers you want to check, one per line.

2. **Run the Script:**
   - Open PowerShell with administrative privileges.
   - Execute the script.

```powershell
$date = Get-Date -Format "MM-dd-yyyy_HH-mm-ss"
#write-host $date  

# Read the list of servers from a file
$servers = Get-Content -Path "C:\temp\ServerList.txt"

# Create an empty array to store the results
$results = @()

foreach ($server in $servers) {
    # Check if the server is responding to ping or Test-NetConnection
    $ping = Test-Connection -ComputerName $server -Count 1 -Quiet
    $port445 = Test-NetConnection -ComputerName $server -Port 445 -InformationLevel Quiet
    $port5985 = Test-NetConnection -ComputerName $server -Port 5985 -InformationLevel Quiet

    if ($ping -or $port445 -or $port5985) {
        # Get Secure boot status
        $OS = (Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property Caption).caption
        $secureboot = Invoke-command -ComputerName $server -ScriptBlock {Confirm-SecureBootUEFI}
    } else {
        # If the server is not responding, set status to "Not Responding"
        $secureboot = "As the Server is not responding/communicating Secure Boot Status cannot be fetched" 
        $OS = "Server Not Responding/Communicating"
    }

    # Add the result to the array
    $results += [PSCustomObject]@{
        ServerName = $server
        OperatingSystem = $OS
        Secureboot =  $secureboot
    }
}

# Export the results to a CSV file
$results | Export-Csv -Path "C:\temp\Secureboot_status_$date.csv" -NoTypeInformation

Write-Output "Data for Secureboot status for all the servers has been exported to C:\temp\ location"

