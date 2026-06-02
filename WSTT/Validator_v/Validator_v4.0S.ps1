######################################################################################################
# ALL THE SCRIPTS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED                    #
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR          # 
# FITNESS FOR A PARTICULAR PURPOSE.                                                                  #
#                                                                                                    #
# This sample is not supported under any Microsoft standard support program or service.              #
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all         #
# implied warranties including, without limitation, any implied warranties of merchantability        #
# or of fitness for a particular purpose. The entire risk arising out of the use or performance      #
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,        #
# or anyone else involved in the creation, production, or delivery of the script be liable for       #
# any damages whatsoever (including, without limitation, damages for loss of business profits,       #
# business interruption, loss of business information, or other pecuniary loss) arising out of       #
# the use of or inability to use the sample or documentation, even if Microsoft has been advised     #
# of the possibility of such damages.                                                                #
#                                                                                                    #
# Script Name : Server_Validator.PS1                                                                 #
# Date        : 21 November,2018                                                                     #
# Purpose	  : The script is used to generate a report of specific SOE attributes and validate  #
#                across a baseline definition.                                                       #
# Project Name: Server Scaner                                                                        #
# Create by   : Rana@microsoft.com  
# Contributed : Sasaleem@microsoft.com
# Contributed : baghule@microsoft.com     (v4)                                                           #
######################################################################################################
$scriptversion = "3.0"
$Computer = $env:COMPUTERNAME
$Date = Get-Date

If(!(Test-Path -Path "C:\Windows\ServerScanner"))
    {
    New-Item c:\Windows\ServerScanner -type directory
    }

$folderName = $Computer + "-Report-" + (Get-Date).tostring("dd-MM-yyyy-hh-mm")            
New-Item -itemType Directory -Path C:\Windows\ServerScanner\ -Name $FolderName


#Log file information
$LogFile = "c:\Windows\ServerScanner\$folderName\" + $Computer + "_" + $date.Hour + $date.Minute + "_" + $Date.Day + "-" + $Date.Month + "-" + $Date.Year + ".log"


$version = $Settings | ? {$_.category -eq "version"} | ? {$_.Compliant_Value}
Add-Content $logfile "`r` $(get-date) : Settings File Version - $($Version.compliant_value)"


#Common Functions

Function Get-Psinfo{ 
    Try
        { 
            $1 = $PSVersionTable.PSVersion
            [string]$2 = Get-ExecutionPolicy
                                    
            If(!$1 -or !$2)
                { 
                Throw "Error getting PS Information" 
                }
                $output = New-Object PSObject -Property @{
						    Version="$($1.Major).$($1.Minor).$($1.Build).$($1.Revision)"
                            Expolicy = $2
                            }
            return $output
        }
    Catch
        {
        Return $_
        }
 }

Add-Content $logfile "`r` $(get-date) : PowerShell Version - $((Get-psinfo).version)"

Function Get-OU{ 
 
Try
    {
    $root = New-Object System.DirectoryServices.DirectoryEntry 
    $computerName = $env:COMPUTERNAME 
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $root
    $searcher.SearchScope = "Subtree"
    $searcher.Filter = "(&(objectClass=computer)(name=$ComputerName))"
    $colproplist = "DistinguishedName"
    Foreach($i in $colproplist){$searcher.PropertiesToLoad.add($i)}
    $colresult = $searcher.FindOne() 
    $dn = $colresult.Properties["distinguishedName"] 
    $ouResult = $dn.Substring($ComputerName.Length + 4) 
    New-Object PSObject -Property @{"Name" = $ComputerName; "OU" = $ouResult}
    }
Catch
    {
    Add-Content $logfile "`r` $(get-date) : Error getting OU Information"
    Add-Content $logfile "`r` $(get-date) : $($_.Exception.Message)"
    Return $_
    } 
}

Function Get-DeviceType{
 
    Try
        { 
        $1 = Get-WmiObject win32_systemenclosure
        If(!$1)
            { 
            Throw "Error getting Asset information from WMI." 
            }
            [string]$chassis = $1.ChassisTypes
            If(($chassis -eq "8") -or ($chassis -eq "9") -or ($chassis -eq "10") -or ($chassis -eq "11") -or ($chassis -eq "14"))
               {
               $DeviceType = "Mobile"
               }
            Else
               {
               $DeviceType = "Workstation"
               }
        return $DeviceType
        }
    Catch
        {
        Add-Content $logfile "`r` $(get-date) : Error getting device Type"
        Add-Content $logfile "`r` $(get-date) : $($_.Exception.Message)"
        Return $_
        }
 }

Function Get-ActivationStatus {
Try{
   $wpa = Get-WmiObject SoftwareLicensingProduct -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" `
            -Property LicenseStatus -ErrorAction Stop
   }
catch {
       $status = New-Object ComponentModel.Win32Exception ($_.Exception.ErrorCode)
       $wpa = $null    
       }
$out = New-Object psobject -Property @{LicenseStatus = [string]::Empty;}
if ($wpa){
            :outer foreach($item in $wpa)
                    {
                     switch ($item.LicenseStatus)
                        {
                        0 {$out.LicenseStatus = "Unlicensed"}
                        1 {$out.LicenseStatus = "Licensed"; break outer}
                        2 {$out.LicenseStatus = "Out-Of-Box Grace Period"; break outer}
                        3 {$out.LicenseStatus = "Out-Of-Tolerance Grace Period"; break outer}
                        4 {$out.LicenseStatus = "Non-Genuine Grace Period"; break outer}
                        5 {$out.LicenseStatus = "Notification"; break outer}
                        6 {$out.LicenseStatus = "Extended Grace"; break outer}
                        default {$out.Status = "Unknown value"}
                        }
                    }
                  }
     else
        {
        $out.Status = $status.Message
        }
     return $out

}

Function Parse-LGPO{
[cmdletbinding()]
 
Param(
[Parameter(Mandatory=$True,Position=0)]
[ValidateNotNullorEmpty()]
[string]$GP
)
$TempResult = ""
If($GP -eq "Machine"){$path = "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"}
Elseif($GP -eq "user"){$path = "C:\Windows\System32\GroupPolicy\User\Registry.pol"}
Elseif($GP -eq "Administrators"){$path = "C:\Windows\System32\grouppolicyusers\s-1-5-32-544\user\Registry.pol"}
Elseif($GP -eq "NonAdministrators"){$path = "C:\Windows\System32\grouppolicyusers\s-1-5-32-545\user\Registry.pol"}
Else{return}
If(Test-Path $path)
    {
    $TempResult = Invoke-Expression -Command ".\LGPO.exe /parse /m $path" | ? {$_ -AND $_ -ne "Computer"}| select -Skip 3 | select -SkipLast 2 -ErrorAction SilentlyContinue
    }
If(!$TempResult){Return}

$x = 0
$y = 1
$z = 2
$Parsed = @()

DO
{
$TP = "" | Select "Registry Path & Value"
$TP.'Registry Path & Value' += $TempResult[$x]+";"+$TempResult[$y]+";"+$TempResult[$z]
$x = $x+3
$y = $y+3
$z = $z+3
$Parsed += $TP
}
While ($z -le $($TempResult.Length))
return $Parsed
}

Function Get-LGMember {

[cmdletbinding()]
 
Param(
[Parameter(Position=0)]
[ValidateNotNullorEmpty()]
[string]$Group = "Administrators"
)
 
#define the scriptblock
$sb = {$members = net localgroup $Group | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4
New-Object PSObject -Property @{
 Group = $Group
 Members=$members
 }
} #end scriptblock
 
$paramhash = @{
 Scriptblock = $sb
 ArgumentList=$Group
 }
Try
    { 
    Invoke-Command @paramhash | Select * -ExcludeProperty RunspaceID
    }
catch
    {
    Add-Content $logfile "`r` $(get-date) : Error getting local group members for $group"
    Add-Content $logfile "`r` $(get-date) : $($_.Exception.Message)"
    Return $_
    }
     
}

Function Test-RegistryValue{
param ( [string]$key_path, [string]$key_value )
    #$ex = $false
    if ( test-path $key_path )
    {
        $k = Get-Item $key_path
        foreach ( $i in $k.Property )
        {
            if( $i -eq $key_value )
            {
                return $true
            }
        }
    }
    else
    {
        return $false
    }
}

Function Test-Value{
    param([string]$Path = $(throw "A path must be specified"), 
          [string]$ValueName = $(throw "A value name must be specified") )

    if(Test-Path $path)
    {
        [bool]$ValueFound = $false
        $myKey = Get-item -path $path -Force
        $values = $myKey.GetValueNames()
        foreach($name in $values)
        {
            if($name.ToLower() -eq $ValueName.ToLower())
            {
                $ValueFound = $true
                break
            }
        }
        return $ValueFound
    }
    else
    {
        return $false
    }
}

Function Get-RegProperty{
Param(
    [string] $Path = $(throw "No registry path is specified"),
    [string] $Name = $(throw "No value name is specified"))

    If(Test-Value -Path $Path -ValueName $Name)
    {
        return (Get-Item $Path).GetValue($Name)
    }
}

Function Get-FWProfile{ 
$output = New-Object PSObject
    
    Try
        { 
        $Domain = Get-RegProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "EnableFirewall"
        $Public = Get-RegProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "EnableFirewall"
        $Private = Get-RegProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "EnableFirewall"
        Add-Member -InputObject $output -MemberType NoteProperty -Name Domain -Value "$(switch($Domain){'1'{"ON"};'0'{"OFF"};Default{"--"}})"
        Add-Member -InputObject $output -MemberType NoteProperty -Name Public -Value "$(switch($Public){'1'{"ON"};'0'{"OFF"};Default{"--"}})"
        Add-Member -InputObject $output -MemberType NoteProperty -Name Private -Value "$(switch($Private){'1'{"ON"};'0'{"OFF"};Default{"--"}})"
        Return $output
        }

    Catch
        {
        Add-Content $logfile "`r` $(get-date) : Error getting FireWall keys"
        Add-Content $logfile "`r` $(get-date) : $($_.Exception.Message)"
        Return $_
        }
 }


 function Get-FileVersion ()
{
Param
    (
         [Parameter(Mandatory=$true, Position=0)] [string] $fName
    )

    $fPath = $DriverPath+$fName
    If (Test-Path $fPath)
    {
        $fVersion =  [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fPath).FileVersion 
    }
    Else
    {
      $fVersion="Not available"
    }
    return $fVersion  
    
}

Function Get-PendingReboot
{
[CmdletBinding()]
param(
	[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[Alias("CN","Computer")]
	[String[]]$ComputerName="$env:COMPUTERNAME",
	[String]$ErrorLog
	)

Begin {  }## End Begin Script Block
Process {
  Foreach ($Computer in $ComputerName) {
	Try {
	    ## Setting pending values to false to cut down on the number of else statements
	    $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
                        
	    ## Setting CBSRebootPend to null since not all versions of Windows has this value
	    $CBSRebootPend = $null
						
	    ## Querying WMI for build version
	    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

	    ## Making registry connection to the local/remote computer
	    $HKLM = [UInt32] "0x80000002"
	    $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
						
	    ## If Vista/2008 & Above query the CBS Reg Key
	    If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
		    $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
		    $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
	    }
							
	    ## Query WUAU from the registry
	    $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
	    $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
						
	    ## Query PendingFileRenameOperations from the registry
	    $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
	    $RegValuePFRO = $RegSubKeySM.sValue

	    ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
	    $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
	    $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

	    ## Query ComputerName and ActiveComputerName from the registry
	    $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
	    $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")

	    If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
	        $CompPendRen = $true
	    }
						
	    ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
	    If ($RegValuePFRO) {
		    $PendFileRename = $true
	    }

	    ## Determine SCCM 2012 Client Reboot Pending Status
	    ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
	    $CCMClientSDK = $null
	    $CCMSplat = @{
	        NameSpace='ROOT\ccm\ClientSDK'
	        Class='CCM_ClientUtilities'
	        Name='DetermineIfRebootPending'
	        ComputerName=$Computer
	        ErrorAction='Stop'
	    }
	    ## Try CCMClientSDK
	    Try {
	        $CCMClientSDK = Invoke-WmiMethod @CCMSplat
	    } Catch [System.UnauthorizedAccessException] {
	        $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
	        If ($CcmStatus.Status -ne 'Running') {
	            Write-Warning "$Computer`: Error - CcmExec service is not running."
	            $CCMClientSDK = $null
	        }
	    } Catch {
	        $CCMClientSDK = $null
	    }

	    If ($CCMClientSDK) {
	        If ($CCMClientSDK.ReturnValue -ne 0) {
		        Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
		    }
		    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
		        $SCCM = $true
		    }
	    }
            
	    Else {
	        $SCCM = $null
	    }

	    ## Creating Custom PSObject and Select-Object Splat
	    $SelectSplat = @{
	        Property=(
	            'Computer',
	            'CBServicing',
	            'WindowsUpdate',
	            'CCMClientSDK',
	            'PendComputerRename',
	            'PendFileRename',
	            'PendFileRenVal',
	            'RebootPending'
	        )}
	    New-Object -TypeName PSObject -Property @{
	        Computer=$WMI_OS.CSName
	        CBServicing=$CBSRebootPend
	        WindowsUpdate=$WUAURebootReq
	        CCMClientSDK=$SCCM
	        PendComputerRename=$CompPendRen
	        PendFileRename=$PendFileRename
	        PendFileRenVal=$RegValuePFRO
	        RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
	    } | Select-Object @SelectSplat

	} Catch {
	    Write-Warning "$Computer`: $_"
	    ## If $ErrorLog, log the file to a user specified location/path
	    If ($ErrorLog) {
	        Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
	    }				
	}			
  }## End Foreach ($Computer in $ComputerName)			
}## End Process

End {  }## End End

}## End Function Get-PendingReboot


Function Get-StoppedAutomaticService

 {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false,
            ValueFromPipeLine=$true,
            ValueFromPipeLineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        
        # Filter services with exit code 0
        [Parameter(Mandatory=$false,
            ValueFromPipeLine=$false,
            ValueFromPipeLineByPropertyName=$true)]
        [switch]$FilterCleanExit,
        
        # Exclusion List
        $ExclusionList = @('clr_optimization_v4.0.30319_32','clr_optimization_v4.0.30319_64','SysmonLog','ShellHWDetection','sppsvc','gupdate','MMCSS','RemoteRegistry','ccmsetup')
    )
    begin{}
    process {
        foreach ($Computer in $ComputerName) {
            try {
                $hostdns = [System.Net.DNS]::GetHostEntry($Computer)
                } 
            catch [Exception] {
                Write-Error "$($_.Exception.Message) $Computer."
                return
                }
            Write-Verbose "Checking services on $computer"
            write-Verbose "Exclusion List:"
            $ExclusionList | ForEach-Object {Write-Verbose " * $_"}
            if ($FilterCleanExit) {
                $StoppedAutomaticService = Get-WmiObject -Class win32_service -ComputerName $computer -Filter "state = 'stopped' and startmode = 'auto' and exitcode != 0" | 
                Where-Object { $ExclusionList -notcontains $_.name }
                }
            else {
                $StoppedAutomaticService = Get-WmiObject -Class win32_service -ComputerName $computer -Filter "state = 'stopped' and startmode = 'auto'" | 
                Where-Object { $ExclusionList -notcontains $_.name }
                }
            if ( $StoppedAutomaticService ) {
                Write-Verbose "Services needing attention:"
                $StoppedAutomaticService | ForEach-Object {Write-Verbose " * $($_.DisplayName)"}
                $StoppedAutomaticServiceObject = @()
                $StoppedAutomaticServiceObject += Get-Service $StoppedAutomaticService.name -ComputerName $StoppedAutomaticService.PSComputerName
                $StoppedAutomaticServiceObject
                # 
                }
            else {
                Write-Verbose "$Computer`: All services ok."
                }
            }
        }
    end {}
}

## End of Function Get-StoppedAutomaticService

Function Get-myHTML ($Header){
$Report = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>$($Header)</title>
<META http-equiv=Content-Type content='text/html; charset=windows-1252'>

<meta name="save" content="history">

<style type="text/css">
DIV .expando {DISPLAY: block; FONT-WEIGHT: normal; FONT-SIZE: 8pt; RIGHT: 8px; COLOR: #ffffff; FONT-FAMILY: Arial; POSITION: absolute; TEXT-DECORATION: underline}
TABLE {TABLE-LAYOUT: fixed; FONT-SIZE: 100%; WIDTH: 100%}
*{margin:0}
.dspcont { display:none; BORDER-RIGHT: #ffbb00 1px solid; BORDER-TOP: #ffbb00 1px solid; PADDING-LEFT: 16px; FONT-SIZE: 8pt;MARGIN-BOTTOM: -1px; PADDING-BOTTOM: 5px; MARGIN-LEFT: 0px; BORDER-LEFT: #ffbb00 1px solid; WIDTH: 95%; COLOR: #000000; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #ffbb00 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; BACKGROUND-COLOR: #f9f9f9}
.filler {BORDER-RIGHT: medium none; BORDER-TOP: medium none; DISPLAY: block; BACKGROUND: none transparent scroll repeat 0% 0%; MARGIN-BOTTOM: -1px; FONT: 100%/8px Tahoma; MARGIN-LEFT: 43px; BORDER-LEFT: medium none; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: medium none; POSITION: relative}
.save{behavior:url(#default#savehistory);}
.dspcont1{ display:none}
a.dsphead0 {BORDER-RIGHT: #000000 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #000000 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 12pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #000000 1px solid; CURSOR: hand; COLOR: #FFFFFF; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #000000 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #000000}
a.dsphead1 {BORDER-RIGHT: #ffbb00 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #ffbb00 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #ffbb00 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #ffbb00 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #00a1f1}
a.dsphead2 {BORDER-RIGHT: #ffbb00 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #ffbb00 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #ffbb00 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #ffbb00 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #00a1f1}
a.dsphead3 {BORDER-RIGHT: #ffbb00 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #ffbb00 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #ffbb00 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #ffbb00 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #FF8000}
a.dsphead4 {BORDER-RIGHT: #ffbb00 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #ffbb00 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #ffbb00 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #ffbb00 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #8A0829}
a.dsphead1 span.dspchar{font-family:monospace;font-weight:normal;}
td {VERTICAL-ALIGN: TOP; FONT-FAMILY: Tahoma}
th {VERTICAL-ALIGN: TOP; COLOR: #CC0000; TEXT-ALIGN: left}
BODY {margin-left: 4pt} 
BODY {margin-right: 4pt} 
BODY {margin-top: 6pt} 
</style>


<script type="text/javascript">
function dsp(loc){
   if(document.getElementById){
      var foc=loc.firstChild;
      foc=loc.firstChild.innerHTML?
         loc.firstChild:
         loc.firstChild.nextSibling;
      foc.innerHTML=foc.innerHTML=='hide'?'show':'hide';
      foc=loc.parentNode.nextSibling.style?
         loc.parentNode.nextSibling:
         loc.parentNode.nextSibling.nextSibling;
      foc.style.display=foc.style.display=='block'?'none':'block';}}  

if(!document.getElementById)
   document.write('<style type="text/css">\n'+'.dspcont{display:block;}\n'+ '</style>');
</script>

</head>
<body>
<b><font face="Arial" size="5">$($Header)</font></b><hr size="8" color="#CC0000">
<font face="Arial" size="1"><b>Version $scriptversion</b></font><br>
<font face="Arial" size="1">Report created on $(Get-Date) $Mode using Definitions Version $($version.compliant_value)</font>
<div class="filler"></div>
<div class="filler"></div>
<div class="filler"></div>
<div class="save">
"@
Return $Report
}

Function Get-myHeader0 ($Title){
$Report = @"
		<h1><a class="dsphead0">$($Title)</a></h1>
	<div class="filler"></div>
"@
Return $Report
}

Function Get-MyHeader ($Num, $Title){
$Report = @"
	<h2><a href="javascript:void(0)" class="dsphead$($Num)" onclick="dsp(this)">
	<span class="expando">show</span>$($Title)</a></h2>
	<div class="dspcont">
"@
Return $Report
}

Function Get-MyHeaderClose{

	$Report = @"
		</DIV>
		<div class="filler"></div>
"@
Return $Report
}

Function Get-myHeader0Close{

	$Report = @"
</DIV>
"@
Return $Report
}

Function Get-MyHTMLClose{

	$Report = @"
</div>

</body>
</html>
"@
Return $Report
}

Function Get-HTMLTable{
	param([array]$Content)
	$HTMLTable = $Content | ConvertTo-Html
	$HTMLTable = $HTMLTable -replace '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">', ""
	$HTMLTable = $HTMLTable -replace '<html xmlns="http://www.w3.org/1999/xhtml">', ""
	$HTMLTable = $HTMLTable -replace '<head>', ""
	$HTMLTable = $HTMLTable -replace '<title>HTML TABLE</title>', ""
	$HTMLTable = $HTMLTable -replace '</head><body>', ""
	$HTMLTable = $HTMLTable -replace '</body></html>', ""
	Return $HTMLTable
}

Function Get-HTMLDetail ($Heading, $Detail){
$Report = @"
<TABLE>
	<tr>
	<th width='25%'><b>$Heading</b></font></th>
	<td width='75%'>$($Detail)</td>
	</tr>
</TABLE>
"@
Return $Report
}

Function Get-HTMLNewDetail ($Heading, $Detail,$Ref,$Action){
$Report = @"
<TABLE>
	<tr>
	<th width='25%'><b>$Heading</b></font></th>
	<td width='25%'>$($Detail)</td>
    <td width='25%'>$($Ref)</td>
    <td width='25%'>$($Action)</td>
	</tr>
</TABLE>
"@
Return $Report
}

function Get-MemoryDump {
[CmdletBinding(
    SupportsShouldProcess=$True,
    ConfirmImpact='High')]

param (

[Parameter(
    Mandatory=$False,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    
    $ComputerName = $env:computername,
    
[Parameter(
    Mandatory=$False,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    [Alias('A')]
    [Switch] $Analyze

)

BEGIN {
    
    #clear variable
    $DriveLetter = ""
    $MiniDumpDirLength = 0
}

PROCESS {

    #create an object to store data
    $Object = New-Object PSObject

    #extract registry value
    try {
        $RemoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
        $RemoteRegistryKey= $RemoteRegistry.OpenSubKey("System\\CurrentControlSet\\Control\\CrashControl" )
  
    }catch{
        Write-Error "Remote Registry Error >> $_"
    }



    #wmi query for logical disks, physical memory, page file settings and operating system
    try {

        $Win32_LogicalDisk = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -ErrorVariable Win32_LogicalDisk_Error
        $Win32_PhysicalMemory = Get-WmiObject -ComputerName $ComputerName -Class Win32_PhysicalMemory -ErrorVariable Win32_PhysicalMemory_Error
        $Win32_PageFileSetting = Get-WmiObject -ComputerName $ComputerName -Class Win32_PageFileSetting -ErrorVariable Win32_PageFileSetting_Error
        $Win32_OperatingSystem = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorVariable Win32_OperatingSystem_Error | Select-Object Caption, OSArchitecture
        $Win32_PerfRawData_PerfOS_Memory = Get-WmiObject -ComputerName $ComputerName -Class Win32_PerfRawData_PerfOS_Memory -ErrorVariable Win32_PerfRawData_PerfOS_Memory_Error | Select-Object PoolPagedBytes, PoolNonpagedBytes
    
    }catch{
        Write-Error $ComputerName ">>" $_.ToString()
    }
    
    ####
    $Object | Add-Member -MemberType noteproperty -Name "HostName" -value $ComputerName
    $Object | Add-Member -MemberType noteproperty -Name "OperatingSystem" -value $Win32_OperatingSystem.Caption

    foreach($KeyName in $RemoteRegistryKey.GetValueNames()) {
        $Object | Add-Member -MemberType noteproperty -Name $KeyName -value $RemoteRegistryKey.GetValue($KeyName)
    }

    #verify if there is an existing dump file
    try {
    
        #verify CrashDumpEnabled is not small memory dump
        if($Object.CrashDumpEnabled -ne 3) {
        
            $DumpFile = Get-ChildItem $Object.DumpFile -ErrorAction Stop -ErrorVariable -ErrorVariable DumpFile_Error
        
            $Object | Add-Member -MemberType noteproperty -Name "DumpFileExists" -value $True
        
        }else{
        
            $DumpFile = Get-ChildItem $Object.MinidumpDir -Filter *.DMP -ErrorAction Stop -ErrorVariable MinidumpDir_Error
            
            #enumerate total mini dump files length
            foreach($MiniDumpFile in $DumpFile) { $MiniDumpDirLength += $MiniDumpFile.Length }
            
            $Object | Add-Member -MemberType noteproperty -Name "MinidumpDirExists" -value $True
        
        } #end of #verify CrashDumpEnabled is not small memory dump
        
    }catch{
        
        if($DumpFile_Error) {
            $DumpFile = 0
            $Object | Add-Member -MemberType noteproperty -Name "DumpFileExists" -value $False
        }
        
        elseif($MinidumpDir_Error) {
            $MiniDumpDirLength = 0
            $Object | Add-Member -MemberType noteproperty -Name "MinidumpDirExists" -value $False
        }
    
    } #end of #verify if there is an existing dump file
    
    switch($Object.CrashDumpEnabled) {
        0 { $DriveLetter = ""; $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "0 - None" -Force } #none
        1 { $DriveLetter = $Object.DumpFile.Substring(0,2); $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "1 - Complete Memory Dump" -Force} #complete memory dump
        2 { $DriveLetter = $Object.DumpFile.Substring(0,2); $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "2 - Kernel Memory Dump" -Force } #kernel memory dump
        3 { $DriveLetter = $Object.MinidumpDir.Substring(0,2); $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "3 - Small Memory Dump" -Force } #small memory dump
        7 { $DriveLetter = $Object.MinidumpDir.Substring(0,2); $Object | Add-Member -MemberType NoteProperty -Name "CrashDumpEnabled" -Value "7 - Automatic Memory Dump" -Force } #automatic memory dump
    }
    if($Object.LastCrashTime -ne $null) {
        $Value = [DateTime]::FromFileTime([int64]::Parse($Object.LastCrashTime)); $Object | Add-Member -MemberType NoteProperty -Name "LastCrashTime" -Value "$Value" -Force
    }


#### Physical Memory
    if($Analyze) {

        foreach($itemWin32_PhysicalMemory in $Win32_PhysicalMemory) {
            $PhysicalMemory = $PhysicalMemory + $itemWin32_PhysicalMemory.Capacity
        }

        $Object | Add-Member -MemberType noteproperty -Name "PhysicalMemory" -value $PhysicalMemory
        $Object | Add-Member -MemberType noteproperty -Name "KernelMemory" -value $($Win32_PerfRawData_PerfOS_Memory.PoolPagedBytes + $Win32_PerfRawData_PerfOS_Memory.PoolNonpagedBytes)
    }

#### Page File
    if($Analyze) {

        foreach($itemWin32_PageFileSetting in $Win32_PageFileSetting) {
            $Object | Add-Member -MemberType noteproperty -Name "PageFile" -value $itemWin32_PageFileSetting.Name
            $Object | Add-Member -MemberType noteproperty -Name "PageFileInitialSize" -value $($itemWin32_PageFileSetting.InitialSize*1MB)
            $Object | Add-Member -MemberType noteproperty -Name "PageFileMaximumSize" -value $($itemWin32_PageFileSetting.MaximumSize*1MB)
        }

        if($Object.PageFile -ne $null) {
            #set "Automatically manage paging file size for all drives" as False
            $Object | Add-Member -MemberType noteproperty -Name "AutomaticManagePageFileSize" -value "False"
        }else{
            #set "Automatically manage paging file size for all drives" as True
            $Object | Add-Member -MemberType noteproperty -Name "AutomaticManagePageFileSize" -value "True"
        }
    }
        
#### Logical Disk
    if($Analyze) {

        foreach($itemWin32_LogicalDisk in $Win32_LogicalDisk) {
        
            #verify DriveLetter matches itemWin32_LogicalDisk.DeviceID
            if($DriveLetter -eq $itemWin32_LogicalDisk.DeviceID) {            
                
                $Object | Add-Member -MemberType noteproperty -Name "LogicalDiskDriveLetter" -value $itemWin32_LogicalDisk.Name
                $Object | Add-Member -MemberType noteproperty -Name "LogicalDiskSize" -value $itemWin32_LogicalDisk.Size
                $Object | Add-Member -MemberType noteproperty -Name "LogicalDiskFreeSpace" -value $itemWin32_LogicalDisk.FreeSpace

            } #end of #verify DriveLetter matches itemWin32_LogicalDisk.DeviceID
    
        } #end of #foreach($itemWin32_LogicalDisk in $Win32_LogicalDisk)

    }

#### Verify DedicatedDumpFileIsConfigured Registry Key
    if($Analyze) {

        if($Object.PageFile -ne $null) { 

            #verify DumpFile is configured to C: drive for the correct operating system version
            if($Object.LogicalDiskDriveLetter -ne $Object.PageFile.Substring(0,2)) {
        
                #verify operating is Windows Server 2008 or Windows Vista
                if(($Win32_OperatingSystem.Caption -like "Microsoft Windows Server 2008 ") -or ($Win32_OperatingSystem.Caption -like "Microsoft Vista*")) {
            
                    #verify DedicatedDumpFile is configured because DumpFile location is not on C: drive
                    if($Object.DedicatedDumpFile) {
                
                        #In Windows Vista and in Windows Server 2008, to put a paging file on another partition, you must create a new registry entry that is named DedicatedDumpFile.
                        $Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value $True
            
                    }else{
                
                        #If DedicatedDumpFile is not configured, there will be no crash dump.
                        $Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value $False
            
                    } #end of #verify DedicatedDumpFile is configured because DumpFile location is not on C: drive
        
                } #end of #verify operating is Windows Server 2008 or Windows Vista
        
                #verify operating is Windows Server 2008 R2 or Windows 7
                elseif(($Win32_OperatingSystem.Caption -like "Microsoft Windows 7*") -or ($Win32_OperatingSystem.Caption -like "Microsoft Windows Server 2008*")) {
            
                    #In Windows 7 and in Windows Server 2008 R2, you do not have to use the DedicatedDumpFile registry entry to put a paging file onto another partition.
                    $Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value "NotRequired"
        
                }else{
            
                    #If operating system is not Windows Vista, Windows 7, Windows Server 2008, Windows Server 2008 R2, DedicatedDumpFile registry entry is not available. PageFile and DumpFile must be in boot volume.
                    $Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value "NotAvailable"
        
                } #end of #verify operating is Windows Server 2008 R2 or Windows 7
        
            }else{
        
                #set dedicateddumpfile is not required if dumpfile is configured to C: drive
                $Object | Add-Member -MemberType noteproperty -Name "DedicatedDumpFileIsConfigured" -value "NotRequired"
    
            } #end of #verify DumpFile is configured to C: drive for the correct operating system version
    
        }

        #verify CrashDumpEnabled configuration for analysis
        switch($Object.CrashDumpEnabled) {
    
            0 { $Object | Add-Member -MemberType noteproperty -Name "CrashDumpStatus" -value "Disabled" } #none
        
        
        
        
        
            1 { #complete memory dump
        
                #verify page file maximum size is greater than physical memory plus 1MB
                if($Object.PageFileMaximumSize -gt $($Object.PhysicalMemory + 1MB)) {
            
                    $Object | Add-Member -MemberType noteproperty -Name "SufficientPageFile" -value $True
            
                }else{
            
                    $Object | Add-Member -MemberType noteproperty -Name "SufficientPageFile" -value $False

                } #end of #verify page file maximum size is greater than physical memory plus 1MB
            
            
            
                #verify logical disk free space is greater than physical memory plus 1MB
                if($Object.LogicalDiskFreeSpace -gt $($Object.PhysicalMemory + 1MB)) {
                
                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
                
                }else{
                
                    #verify dump file exist and overwrite is enabled
                    switch($Object.DumpFileExists) {
                    
                        $True {
                        
                            #verify existing dump file can be overwritten
                            if($Object.Overwrite -eq 1) {
                        
                                #verify current free space plus existing dump file size is greater than physical memory plus 1MB
                                if(($Object.LogicalDiskFreeSpace + $DumpFile.Length) -gt $($Object.PhysicalMemory + 1MB)) {
                            
                                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
                            
                                }else{
                            
                                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
                            
                                }
                            
                            }else{
                        
                                $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
                        
                            } #end of #verify existing dump file can be overwritten and current free space plus existing dump file size is greater than physical memory plus 1MB
                    
                        } #end of #DumpFileExists is $True
                    
                    
                        $False {
                    
                            $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
                    
                        } #end of #DumpFileExists is $False
                    
                    } #end of #verify dump file exist and overwrite is enabled

                } #end of #verify logical disk free space is greater than physical memory plus 1MB
            
            
            
                #verify operating system is 32bit and physical memory is not greater than 2GB for complete memory dump
                if(($Win32_OperatingSystem.OSArchitecture -eq "32-Bit") -and ($Object.PhysicalMemory -gt 2GB)){
            
                    #The Complete memory dump option is not available on computers that are running a 32-bit operating system and that have 2 gigabytes (GB) or more of RAM.
                    $Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"
            
                } #end of #verify operating system is 32bit and physical memory is not greater than 2GB
            
            
                #verify Object.SufficientFreeSpace and Object.SufficientPageFile is true
                elseif(($Object.SufficientFreeSpace -eq $True) -and ($Object.SufficientPageFile -eq $True)) {
                
                    #verify Object.DedicatedDumpFileIsConfigured is not False or NotAvailable
                    if(($Object.DedicatedDumpFileIsConfigured -ne $False) -or ($Object.DedicatedDumpFileIsConfigured -ne "NotAvailable")) {
                    
                        $Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "Possible"
                
                    }else{
                
                        $Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"

                    } #end of #verify Object.DedicatedDumpFileIsConfigured is not False or NotAvailable
                
                }else{
                
                    $Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"
            
                } #end of #verify Object.SufficientFreeSpace and Object.SufficientPageFile is true
                    
            } #end of #complete memory dump
        
        
        
        
        
            2 { #kernel memory dump
            
                #verify page file maximum size is greater than physical memory plus 1MB
                if($Object.PageFileMaximumSize -gt (2GB + 1MB)) {
            
                    $Object | Add-Member -MemberType noteproperty -Name "SufficientPageFile" -value $True
            
                }else{
            
                    $Object | Add-Member -MemberType noteproperty -Name "SufficientPageFile" -value $False

                } #end of #verify page file maximum size is greater than physical memory plus 1MB
            
            
                #verify logical disk free space is greater than 2GB
                if($Object.LogicalDiskFreeSpace -gt (2GB + 1MB)) {
                
                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
                
                }else{
            
                    #verify dump file exist
                    switch($Object.DumpFileExists) {
                
                        $True {
                        
                            #verify existing dump file can be overwritten
                            if($Object.Overwrite -eq 1) {
                        
                                #verify current free space plus existing dump file size is greater than 2GB
                                if(($Object.LogicalDiskFreeSpace + $DumpFile.Length) -gt (2GB + 1MB)) {
                            
                                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
                            
                                }else{
                            
                                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
                            
                                } #end of #verify current free space plus existing dump file size is greater than 2GB
                            
                            }else{
                        
                                #verify current free space is greater than current kernel memory
                                if($Object.LogicalDiskFreeSpace -gt $($Object.KernelMemory + 1MB)) {
                                
                                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value "Plausible"
                            
                                }else{
                            
                                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
                            
                                } #end of #verify current free space is greater than current kernel memory
                        
                            } #end of #verify existing dump file can be overwritten
                        
                        } #end of #DumpFileExists is $True
                    
                        $False {
                    
                            $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
                    
                        } #end of #DumpFileExists is $False
                
                    } #end of #verify dump file exist
               
                } #end of #verify logical disk free space is greater than 2GB
            


                #verify Object.SufficientFreeSpace is true
                if(($Object.SufficientFreeSpace -eq $True) -and ($Object.SufficientPageFile -eq $True)) {
                
                    #verify Object.DedicatedDumpFileIsConfigured is not False or NotAvailable
                    if(($Object.DedicatedDumpFileIsConfigured -ne $False) -or ($Object.DedicatedDumpFileIsConfigured -ne "NotAvailable")) {
                    
                        $Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "Possible"
                
                    }else{
                
                        $Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"

                    } #end of #verify Object.DedicatedDumpFileIsConfigured is not False or NotAvailable
            
                }else{
                
                    $Object | Add-Member -MemberType noteproperty -Name "MemoryDumpAnalysis" -value "NotPossible"
            
                } #end of #verify Object.SufficientFreeSpace and Object.SufficientPageFile is true
            
            } #end of #kernel memory dump
        
        
        
        
        
            3 { 
             
                #verify logical disk free space is greater than total MinidumpsCount
                if(($Win32_OperatingSystem.OSArchitecture -eq "32-Bit") -and ($Object.LogicalDiskFreeSpace -gt ($Object.MinidumpsCount * 64KB))) {
                
                    #A small memory (aka Mini-dump) is a 64KB dump on 32-bit System
                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True
                
                }
            
                elseif(($Win32_OperatingSystem.OSArchitecture -eq "64-Bit") -and ($Object.LogicalDiskFreeSpace -gt ($Object.MinidumpsCount * 128KB))){

                    #A small memory (aka Mini-dump) is a 128KB dump on 64-bit System
                    $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $True            
                }
            
                else{
            
                    #verify dump file exist
                    switch($Object.DumpFileExists) {
                
                        $True { 
                    
                        } #end of #DumpFileExists is $True
                                        
                        $False {
                    
                            $Object | Add-Member -MemberType noteproperty -Name "SufficientFreeSpace" -value $False
                        
                        } #end of #DumpFileExists is $False
                    
                    } #end of #verify dump file exist
                
                } #end of #verify logical disk free space is greater than total MinidumpsCount
        
            } #small memory dump
    
        } #end of #verify CrashDumpEnabled configuration for analysis

    } #end of Analyze parameter

$Object | Sort-Object -Property Name -Descending;
if($Object.AutomaticManagePageFileSize -eq "True") { Write-Host "*** Unable to further analyze due to System Managed Pagefile size ***" }
}

END { }

} #end of #function Get-MemoryDump


#Beginning Logic
$computer = $env:COMPUTERNAME

#Report headings...	
$MyReport = Get-MyHTML "$computer Server Validation Report"
$MyReport += Get-myHeader0  "Report Data"

#General Information Section

Add-Content $logfile "`r` $(get-date) : Processing General Information Section"

Try
    {
    $ComputerSystem = Get-WmiObject Win32_ComputerSystem
    $OperatingSystems = Get-WmiObject Win32_OperatingSystem
    $Mem = Get-WmiObject Win32_physicalMemory; Foreach ($d in $Mem.capacity){$Real += $d}
    }
Catch
    {
    Add-Content $logfile "`r` $(get-date) : Error getting WMI data"
    Add-Content $logfile "`r` $(get-date) : $($_.Exception.Message)"
    }

$MyReport += Get-MyHeader "2" "General Information"
$MyReport += Get-HTMLDetail "Computer Name" ($Computer)
$MyReport += Get-HTMLDetail "Hardware Manufacturer" ($ComputerSystem.Manufacturer)
$MyReport += Get-HTMLDetail "Model" ($ComputerSystem.Model)
$MyReport += Get-HTMLDetail "Device Type" ($(Get-DeviceType))
$MyReport += Get-HTMLDetail "Number of Processors" ($ComputerSystem.NumberOfProcessors)
$MyReport += Get-HTMLDetail "Physical Memory" ([math]::Round(($real)/(1024*1024*1024)))
$MyReport += Get-HTMLDetail "OS Memory" ([math]::Round(($OperatingSystems.TotalVisibleMemorySize)/(1024*1024)))
$MyReport += Get-HTMLDetail "Operating System" ($OperatingSystems.Caption)
#$MyReport += Get-HTMLDetail "Service Pack" ($OperatingSystems.CSDVersion)
$MyReport += Get-HTMLDetail "Build Number" ($OperatingSystems.Version)
$MyReport += Get-HTMLDetail "Windows License Status" ((Get-ActivationStatus).licensestatus)
$MyReport += Get-HTMLDetail "Architecture" ($OperatingSystems.OSArchitecture)
$MyReport += Get-HTMLDetail "Install Date" (([WMI]'').ConvertToDateTime($OperatingSystems.InstallDate))
$MyReport += Get-HTMLDetail "Domain Membership" ($computersystem.Domain)
$MyReport += Get-HTMLDetail "Registered Organisation" ($OperatingSystems.Organization)
$MyReport += Get-HTMLDetail "PowerShell Version" ($((Get-Psinfo).version))
$MyReport += Get-HTMLDetail "OU" ($((Get-ou).OU))
$MyReport += Get-MyHeaderClose



#NIC Configuration
#-----------------

Add-Content $logfile "`r` $(get-date) : Getting NIC Configuration"
$Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration
$MyReport += Get-MyHeader "2" "NIC Configuration"
$IPInfo = @()
Foreach ($Adapter in ($Adapters | Where {$_.IPEnabled -eq $True})) 
    {
	$Details = "" | Select "NIC Priority", Description, "MAC address", "IP Address / Subnet Mask", "Default Gateway", "DHCP Enabled", DNS, "Small Rx Buffers","Rx Ring #1 Size","Threshold or Reference" ,"Actions to be Taken"
    $Details."NIC Priority" = "$($Adapter.Index)"
	$Details.Description = "$($Adapter.Description)"
	$Details."MAC address" = "$($Adapter.MACaddress)"
	If ($Adapter.IPAddress -ne $Null)
        {
		$Details."IP Address / Subnet Mask" = "$($Adapter.IPAddress)/$($Adapter.IPSubnet)"
		$Details."Default Gateway" = "$($Adapter.DefaultIPGateway)"
		}
	If ($Adapter.DHCPEnabled -eq "True")
        {
		$Details."DHCP Enabled" = "Yes"
		}
	Else
        {
		$Details."DHCP Enabled" = "No"
		}
	If ($Adapter.DNSServerSearchOrder -ne $Null)
        {
		$Details.DNS =  "$($Adapter.DNSServerSearchOrder)"
		}

    $RxBuffer = (Get-NetAdapterAdvancedProperty -InterfaceDescription "$($Adapter.Description)" -DisplayName "Small Rx Buffers").DisplayValue
    If($RxBuffer -eq $null)
    {
        $RxBuffer="Not Present"
    }
    $Details."Small Rx Buffers" = $RxBuffer
    
    $RxRingSize = (Get-NetAdapterAdvancedProperty -InterfaceDescription "$($Adapter.Description)" -DisplayName "Rx Ring #1 Size").DisplayValue
    If($RxRingSize -eq $null)
    {
        $RxRingSize="Not Present"
    }
    $Details."Rx Ring #1 Size" = $RxRingSize

    $Details."Threshold or Reference" = "Default Gateway should be configure on one NIC and that NIC should have high Priority.Small Rx Buffers value should be 8192.Rx Ring #1 Size value should be 4096."
    $Details."Actions to be Taken" ="If the value not set, then we have to set this manually on server"    
   
   	$IPInfo += $Details
	}
$MyReport += Get-HTMLTable ($IPInfo)
$MyReport += Get-MyHeaderClose
#-----------------

#Disk Configuration report
Add-Content $logfile "`r` $(get-date) : Disk Configuration"
$MyReport += Get-MyHeader "2" "Disk Configuration"
$DiskReport = @()

$LogicalDisks = Get-WMIObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select DeviceID,Size,Freespace,VolumeName
Foreach ($LogicalDisk in $LogicalDisks)
    {
    $Diskout = "" | Select MountPoint,"Volume Name","Capacity(GB)","Freespace(GB)", "Threshold or Reference", "Actions to be Taken"
    $Diskout.MountPoint = "$($Logicaldisk.DeviceID)"
    $Diskout."Volume Name" = "$($Logicaldisk.VolumeName)"
    $Diskout."Capacity(GB)" = "$([math]::Round(($Logicaldisk.Size)/(1024*1024*1024)))"
    $Diskout."Freespace(GB)" = "$([math]::Round(($Logicaldisk.FreeSpace)/(1024*1024*1024)))"
    
    $Diskout."Threshold or Reference" = "10% Free disk size of total drive size."
    $Diskout."Actions to be Taken" ="10% Free disk size of total drive size, If not then we have to delete some unwanted files / folders from respective drive"    
   
    $DiskReport += $Diskout
    }
$MyReport += Get-HTMLTable ($DiskReport)
$MyReport += Get-MyHeaderClose


#List enabled windows features
Add-Content $logfile "`r` $(get-date) : Listing enabled Windows features"    

#$FeatureReport += Get-WindowsOptionalFeature -Online | ? {$_.State -eq "Enabled"} | Select FeatureName,State
#$MyReport += Get-HTMLTable ($FeatureReport)
#$MyReport += Get-MyHeaderClose  


$winver = (Get-WmiObject -class Win32_OperatingSystem).Caption
If ($winver -match "Microsoft Windows Server 2008")
{ 
Import-module servermanager
$MyReport += Get-MyHeader "2" "Windows Features"
$FeatureReport = @()
$FeatureReport += Get-WindowsFeature | where-object {$_.Installed -eq $True} | Select DisplayName,Name
$MyReport += Get-HTMLTable ($FeatureReport)
$MyReport += Get-MyHeaderClose  
}
else 
{
Add-Content $logfile "`r` $(get-date) : Listing enabled Windows features"    
$MyReport += Get-MyHeader "2" "Windows Features"
$FeatureReport = @()
$FeatureReport += Get-WindowsOptionalFeature -Online | ? {$_.State -eq "Enabled"} | Select FeatureName,State
$MyReport += Get-HTMLTable ($FeatureReport)
$MyReport += Get-MyHeaderClose  
}


#Updates and Hotfixes
Add-Content $logfile "`r` $(get-date) : Listing Hotfixes and updates"

$MyReport += Get-MyHeader "2" "Updates and Hotfixes"
$uhreport = @()
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$HistoryCount = $Searcher.GetTotalHistoryCount()
$updates = $Searcher.QueryHistory(0, $historyCount) | ? {$_.Title -ne $null -and ($_.resultcode -eq "2" -or $_.resultcode -eq "3")}| Select-Object @{name="Name"; expression={[regex]::match($_.Title,'(KB[0-9]{6,7})').value}},@{name="Operation";expression={switch($_.operation){1{"Installation"};2{"Uninstallation"};3{"Other"}}}},Date
  
$bUpdateSelect =$true
foreach ($Update in $Updates)
   {
   $uout = ""| Select "KB Name","Type","Operation Type", Date,"Threshold or Reference" ,"Actions to be Taken"
   $uout."KB Name" = $update.Name
   $uout."Type" = "Update"
   $uout."Operation Type" = $update.Operation
   $uout."Date" = $update.Date
   If($bUpdateSelect -eq $true)
    {
    $uout."Threshold or Reference" = "Server should have latest update and security patch installed (Shows the date of latest update)"
    $uout."Actions to be Taken" ="If not then we need to patch the server with latest updates"    
    $bUpdateSelect = $false
    }
   $uhreport += $uout
   }
$HotFixes = Get-HotFix 
$bHotfixSelect =$true
foreach ($HotFix in $HotFixes)
    {
    $uout = ""| Select "KB Name","Type","Operation Type", Date,"Threshold or Reference" ,"Actions to be Taken"
    $uout."KB Name" = $Hotfix.HotFixID
    $uout."Type" = "Hotfix"
    $uout."Operation Type" = "Installation"
    $uout."Date" = $Hotfix.Installedon
    If($bHotfixSelect -eq $true)
    {
    $uout."Threshold or Reference" = "Server should have latest update and security patch installed (Shows the date of latest update)"
    $uout."Actions to be Taken" ="If not then we need to patch the server with latest updates"    
    $bHotfixSelect = $false
    }
    $uhreport += $uout
    }
$MyReport += Get-HTMLTable ($uhreport)
$MyReport += Get-MyHeaderClose

#Populating installed apps
$Installed = @()
$Installed += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*| ? {$_.DisplayName -ne $null} | Select Publisher,DisplayName,DisplayVersion,InstallDate,@{name="RValue";expression={$_.Publisher+" "+$_.DisplayName+" "+$_.DisplayVersion}}
$Installed += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*| ? {$_.DisplayName -ne $null} | Select Publisher,DisplayName,DisplayVersion,InstallDate,@{name="RValue";expression={$_.Publisher+" "+$_.DisplayName+" "+$_.DisplayVersion}}


$swireport = @()

Foreach ($install in $Installed)
    {
    $swiout = "" | Select Publisher,Name,Version,"Install Date",Compliant
    $swiout.Publisher = $install.Publisher
    $swiout.Name = $install.DisplayName
    $swiout.Version = $install.DisplayVersion
    $swiout."Install Date" = $install.Installdate
    $swiout.Compliant = "--"
    If($swdefintions.Name -contains $swiout.Name)
        {
        If($swdefintions.Compliant_value -contains $install.Rvalue)
            {
            $swiout.Compliant = "Yes"
            }
        Else
            {
            $swiout.Compliant = "No"
            }
        }
    $swireport += $swiout
    }
$swireport = $swireport | sort -Property Compliant,publisher,Name -Descending
If($swireport.compliant -match "No"){$MyReport += Get-MyHeader "4" "Software Inventory (Installed)"}Else{$MyReport += Get-MyHeader "2" "Software Inventory (Installed)"}
$MyReport += Get-HTMLTable ($swireport)
$MyReport += Get-MyHeaderClose


#

#Server Power Management Information" 

Add-Content $logfile "`r` $(get-date) : Server Power Management Information"

#Curent PhysicalDiskPerfCounters

$MyReport += Get-MyHeader "2" "Server Power Management Information"

$MyReport += Get-HTMLDetail "Power Management Information"
$PwrReport = @()

$PowerMgmts = @(gwmi -NS root\cimv2\power -Class win32_PowerPlan | select ElementName, IsActive)

foreach ($PowerMgmt in $PowerMgmts)
{
 $Pwrout = "" | Select ElementName,IsActive,"Threshold or Reference" ,"Actions to be Taken"
 $Pwrout.ElementName = $PowerMgmt.ElementName
 $Pwrout.IsActive = $PowerMgmt.IsActive
 $Pwrout."Threshold or Reference" = "High Performance Element should be true"
 $Pwrout."Actions to be Taken" ="If not then we have to change it manually"   
 $PwrReport += $Pwrout
}

$MyReport += Get-HTMLTable ($PwrReport)
$MyReport += Get-MyHeaderClose

# Get Firewall Profile  

Add-Content $logfile "`r` $(get-date) : Getting Windows firewall ON/OFF Status"

#Getting Local Firewall Profile Details

$winver = (Get-WmiObject -class Win32_OperatingSystem).Caption
If ($winver -notlike "*2008*")

{$MyReport += Get-MyHeader "2" "Windows firewall ON/OFF Status"

$MyReport += Get-HTMLDetail "Local Windows firewall ON/OFF Status"

$LFWReport = @()

$LocalFWReports = Get-NetFirewallProfile

foreach ($LocalFWReport in $LocalFWReports )
{
 $LFWout = "" | Select Name,Enabled,"Profile","Threshold or Reference" ,"Actions to be Taken" 
 $LFWout.Name = $LocalFWReport.Name
 $LFWout.Enabled = $LocalFWReport.Enabled
 $LFWout."Threshold or Reference" = "1. Firewall state should be Off. 2.Inbound Connection should be in Allow state. 3.Outbound Connection should be in Allow state"
 $LFWout."Actions to be Taken" ="If not then need to set."    
 
 $LFWReport += $LFWout 
}

$MyReport += Get-HTMLTable ($LFWReport)
$MyReport += Get-MyHeaderClose
}

# Get NIC Power Management Enabled\Disabled Information

$winver = (Get-WmiObject -class Win32_OperatingSystem).Caption
If ($winver -notlike "*2008*")

{Add-Content $logfile "`r` $(get-date) : Get NIC Power Management Enabled\Disabled Information"

$MyReport += Get-MyHeader "2" "NIC Power Management Information"

$MyReport += Get-HTMLDetail "NIC Power Management Information Details"

$NICPMReport = @()
$bNICRSelect =$true
foreach ($NIC in (Get-NetAdapter -Physical)){
    $NICPM = "" | Select NIC_Name,Enabled,"Threshold or Reference" ,"Actions to be Taken" 
    $NICPM.NIC_Name = $NIC.Name
    $PowerSaving = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi | ? {$_.InstanceName -match [Regex]::Escape($NIC.PnPDeviceID)}
  if ($PowerSaving.Enable){
     $NICPM.Enabled = "Save Power Enabled"
    } Else { $NICPM.Enabled = "Save Power Disabled" }
  If($bNICRSelect -eq $true)
    {
    $NICPM."Threshold or Reference" = "Save Power mode of all the NIC configured on the server should be enabled"
    $NICPM."Actions to be Taken" ="If not then need to set manually"    
    $bNICRSelect = $false
    }
    $NICPMReport += $NICPM
   }

$MyReport += Get-HTMLTable ($NICPMReport)
$MyReport += Get-MyHeaderClose

# Get Server page File Configuration Information

$winver = (Get-WmiObject -class Win32_OperatingSystem).Caption
If ($winver -notlike "*2008*")

{Add-Content $logfile "`r` $(get-date) : Get Server page File Configuration Information"

$MyReport += Get-MyHeader "2" "Server page File Configuration Information"

$MyReport += Get-HTMLDetail "Server page File Configuration Information Details"

$PageFileReport = @()

$PageFileInfos = Get-CimInstance Win32_PageFileUsage
$bPageSelect =$true
foreach ($PageFileInfo in $PageFileInfos)
{
 $PageFile = "" | Select Name,CurrentUsage_MB,InstallDate,AllocatedBaseSize_MB,PeakUsage,TempPageFile,"Threshold or Reference" ,"Actions to be Taken"
 $PageFile.Name = $PageFileInfo.Name
 $PageFile.CurrentUsage_MB = $PageFileInfo.CurrentUsage
 $PageFile.InstallDate = $PageFileInfo.InstallDate
 $PageFile.AllocatedBaseSize_MB = $PageFileInfo.AllocatedBaseSize
 $PageFile.PeakUsage = $PageFileInfo.PeakUsage
 $PageFile.TempPageFile = $PageFileInfo.TempPageFile
 If($bPageSelect -eq $true)
    {
    $PageFile."Threshold or Reference" = "PageFile Size should be RAM Size plus 1 GB"
    $PageFile."Actions to be Taken" ="If the page file size is not set to RAM+1 GB then we need to set it manually"    
    $bPageSelect = $false
    }
 $PageFileReport += $PageFile
}

$MyReport += Get-HTMLTable ($PageFileReport)
$MyReport += Get-MyHeaderClose
}
}
# Get Server Memory Dump Information

Add-Content $logfile "`r` $(get-date) : Getting Server Memory Dump Information Settings"

$MyReport += Get-MyHeader "2" "Server Memory Dump Information Settings Information"

$MyReport += Get-HTMLDetail "Server Memory Dump Information Setting Details"

$SrvMemoryDumpReport = @()

$MemDumpSettings = Get-MemoryDump
$bDumpSelect =$true
foreach ($MemDumpSetting  in $MemDumpSettings)
{

$SrvMemOut = "" | select HostName,OperatingSystem,LogEvent,Overwrite,AutoReboot,DumpFile,DisableEmoticon,MinidumpDir,MinidumpsCount,CrashDumpEnabled,"Threshold or Reference" ,"Actions to be Taken"
$SrvMemOut.HostName         =  $MemDumpSetting.HostName 
$SrvMemOut.OperatingSystem  =  $MemDumpSetting.OperatingSystem
$SrvMemOut.LogEvent         =  $MemDumpSetting.LogEvent 
$SrvMemOut.Overwrite        =  $MemDumpSetting.Overwrite 
$SrvMemOut.AutoReboot       =  $MemDumpSetting.AutoReboot 
$SrvMemOut.DumpFile         =  $MemDumpSetting.DumpFile 
$SrvMemOut.DisableEmoticon  =  $MemDumpSetting.DisableEmoticon 
$SrvMemOut.MinidumpDir      =  $MemDumpSetting.MinidumpDir  
$SrvMemOut.MinidumpsCount   =  $MemDumpSetting.MinidumpsCount 
$SrvMemOut.CrashDumpEnabled =  $MemDumpSetting.CrashDumpEnabled 
If($bDumpSelect -eq $true)
    {
    $SrvMemOut."Threshold or Reference" = "1. Dump generation should be set upon automatic restart of system.2. Overwrite of any existing file should be set.3. complete memory dump should be set
4. Crash dump should be enabled"
    $SrvMemOut."Actions to be Taken" ="If not then need to set manually"    
    $bDumpSelect = $false
    }
$SrvMemoryDumpReport += $SrvMemOut
}


$MyReport += Get-HTMLTable ($SrvMemoryDumpReport)
$MyReport += Get-MyHeaderClose


# Get Server Sys File version Information

Add-Content $logfile "`r` $(get-date) : Getting Server Sys File version Information"

$MyReport += Get-MyHeader "2" "Server Sys File version Information"

$MyReport += Get-HTMLDetail "Server Sys File version Information Details"


$DriverPath = "C:\Windows\System32\drivers\"

$TCPIPFileVersion = Get-FileVersion "tcpip.sys" 
$AFDFileVersion   = Get-FileVersion "afd.sys" 
$MRXSMBFileVersion = Get-FileVersion "MRXSMB.sys" 
$vsepfltFileVersion = Get-FileVersion ("vsepflt.sys")
$VnetfltFileVersion = Get-FileVersion ("Vnetflt.sys") 
$lsi_sasFileVersion = Get-FileVersion ("lsi_sas.sys")
$StorportFileVersion = Get-FileVersion ("Storport.sys")
$MPIOFileVersion= Get-FileVersion ("MPIO.sys")
$NTFSFileversion = Get-FileVersion ("Ntfs.Sys")


$MyReport += Get-HTMLNewDetail "TCP IP File Version" ($TCPIPFileVersion) "Latest Version should be there as per microsoft  (Show the driver version)" "If not there then need to update to latest version"
$MyReport += Get-HTMLNewDetail "AFD File Version"    ($AFDFileVersion) "Latest Version should be there as per microsoft  (Show the driver version)" "If not there then need to update to latest version"
$MyReport += Get-HTMLNewDetail "MRX SMB File Version" ($MRXSMBFileVersion) "Latest Version should be there as per microsoft  (Show the driver version)" "If not there then need to update to latest version"
$MyReport += Get-HTMLNewDetail "vsepflt File Version" ($vsepfltFileVersion) "This should not be present on the server (Show the driver version)" "If there need to take action for its removal"
$MyReport += Get-HTMLNewDetail "Vnetflt File Version" ($VnetfltFileVersion) "This should not be present on the server (Show the driver version)" "If there need to take action for its removal"
$MyReport += Get-HTMLNewDetail "lsi_sas File Version" ($lsi_sasFileVersion) "The version should be 1.34.03.82." "If the version is lower than this need to update it."
$MyReport += Get-HTMLNewDetail "Storport FileVersion" ($StorportFileVersion) "Latest Version should be there as per microsoft  (Show the driver version)" "If not there then need to update to latest version"
$MyReport += Get-HTMLNewDetail "MPIO File Version" ($MPIOFileVersion) "Latest Version should be there as per microsoft  (Show the driver version)" "If not there then need to update to latest version"
$MyReport += Get-HTMLNewDetail "NTFS File version" ($NTFSFileversion) "Latest Version should be there as per microsoft  (Show the driver version)" "If not there then need to update to latest version"
$MyReport += Get-MyHeaderClose


# TCP Chimney/RSS Settings

$winver = (Get-WmiObject -class Win32_OperatingSystem).Caption
If ($winver -notlike "*2008*")

{Add-Content $logfile "`r` $(get-date) : TCP Chimney/RSS Settings Information"

$MyReport += Get-MyHeader "2" "TCP Chimney/RSS Settings Information"

$MyReport += Get-HTMLDetail "TCP Chimney Setting Details"


$TCPChimnetReport = @()

$TCPChimneySettings = Get-NetOffloadGlobalSetting

Foreach ($TCPChimneySetting in $TCPChimneySettings)

{
$TCPChimney = "" | select ReceiveSideScaling, ReceiveSegmentCoalescing, Chimney, TaskOffload, NetworkDirect, NetworkDirectAcrossIPSubnets,PacketCoalescingFilter   
$TCPChimney.ReceiveSideScaling = $TCPChimneySetting.ReceiveSideScaling 
$TCPChimney.ReceiveSegmentCoalescing = $TCPChimneySetting.ReceiveSegmentCoalescing
$TCPChimney.Chimney = $TCPChimneySetting.Chimney
$TCPChimney.TaskOffload = $TCPChimneySetting.TaskOffload
$TCPChimney.NetworkDirect = $TCPChimneySetting.NetworkDirect
$TCPChimney.NetworkDirectAcrossIPSubnets = $TCPChimneySetting.NetworkDirectAcrossIPSubnets
$TCPChimney.PacketCoalescingFilter    = $TCPChimneySetting.PacketCoalescingFilter   
$TCPChimnetReport += $TCPChimney
}

$MyReport += Get-HTMLTable ($TCPChimnetReport)
$MyReport += Get-MyHeaderClose
}

#Clear Page File at Shutdown Validate Registry 

Add-Content $logfile "`r` $(get-date) : Clear Page File at Shutdown Validate Registry Information"

$MyReport += Get-MyHeader "2" "Clear Page File at Shutdown Validate Registry Information"

$MyReport += Get-HTMLDetail "Clear Page File at Shutdown Validate Registry Details"


$ClearPageFileAtShutdownValue = (Get-ItemProperty -path 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management').ClearPageFileAtShutdown

If ($ClearPageFileAtShutdownValue -eq 0)
{ 
$ClearPageFileAtShutdown = "Enabled"
}
Else 
{
$ClearPageFileAtShutdown = "Disabled"
}

$MyReport += Get-HTMLNewDetail "Clear PageFile at Shutdown:" ($ClearPageFileAtShutdown) "Clear Page File at Shutdown should be enabled" "If not then need to set manually"
$MyReport += Get-MyHeaderClose



#Disable 8.3 naming creation 

Add-Content $logfile "`r` $(get-date) : Disable 8.3 naming creation"

$MyReport += Get-MyHeader "2" "Disable 8.3 naming creation  Information"

$MyReport += Get-HTMLDetail "Disable 8.3 naming creation  Details"


$NtfsDisable8dot3NameCreationValue = (Get-ItemProperty -path 'hklm:\SYSTEM\CurrentControlSet\Control\FileSystem').NtfsDisable8dot3NameCreation 

switch ($NtfsDisable8dot3NameCreationValue) 
    { 
        0 {$ClearPage = "Disabled"} 
        1 {$ClearPage = "Enabled on all Volumes"} 
        2 {$ClearPage = "Enabled Per Volume"} 
        3 {$ClearPage = "Disabled on all volumes except System Volume"} 
     }

$MyReport += Get-HTMLDetail "Disable 8.3 naming creation:" ($ClearPage)
$MyReport += Get-MyHeaderClose


# Get Server Sys File version Information

Add-Content $logfile "`r` $(get-date) : Getting PageFile Memory Dump Settings"

$MyReport += Get-MyHeader "2" "Getting PageFile Memory Dump Settings Information"

$MyReport += Get-HTMLDetail "Getting PageFile Memory Dump Settings Details"

#region Memory and Page File
$Server= $Computer
 $OSVersion = get-wmiobject Win32_OperatingSystem -ComputerName $Server | SELECT -ExpandProperty Caption 
 $AutoPageFile = Get-WmiObject -ComputerName $Server -Class Win32_ComputerSystem | SELECT -ExpandProperty AutomaticManagedPagefile
 $PhysicalMemory = gwmi -computer $Server Win32_ComputerSystem | % {[Math]::round($_.TotalPhysicalMemory/1MB,0)}
 $STDPageFileSize = $PhysicalMemory + 500
 $PageFile=""
 $PageFileState=""

 If ($AutoPageFile -eq $false) 
 {
    $PageFile = gwmi -computer $Server Win32_PageFileUsage | SELECT -ExpandProperty AllocatedBaseSize
     
    IF ($STDPageFileSize -eq $PageFile)
    {
        $PageFileState="Complied"
    }
    ELSE
    {
        $PageFileState="Non Complied"
    }     
 } 
 Else
 {
 $PageFile="Set to Auto"
 $PageFileState="Set to Auto"
 }  

$MyReport += Get-HTMLDetail "Page File (MB):" ($PageFile)
$MyReport += Get-HTMLDetail "Page File State:"    ($PageFileState)
$MyReport += Get-HTMLDetail "Physical Memory (MB):" ($PhysicalMemory)
$MyReport += Get-HTMLDetail "Recommended PageFile Size (MB);" ($STDPageFileSize)
$MyReport += Get-MyHeaderClose


# Adding Pending Reboot Details


Add-Content $logfile "`r` $(get-date) : Pending Reboot Status"

$MyReport += Get-MyHeader "2" "Server Pending Reboot Status"
$MyReport += Get-HTMLDetail "Server Pending Reboot Status Details"


$RebootStatus = Get-pendingReboot

$MyReport += Get-HTMLNewDetail "CBServicing:" ($RebootStatus.CBServicing) "There should not be any server reboot pending" "If pending need to reboot the server manually"
$MyReport += Get-HTMLNewDetail "WindowsUpdate:" ($RebootStatus.WindowsUpdate) "There should not be any server reboot pending" "If pending need to reboot the server manually"
$MyReport += Get-HTMLNewDetail "PendFileRename:" ($RebootStatus.PendFileRename) "There should not be any server reboot pending" "If pending need to reboot the server manually"
$MyReport += Get-HTMLNewDetail "CCMClientSDK:" ($RebootStatus.CCMClientSDK) "There should not be any server reboot pending" "If pending need to reboot the server manually"
$MyReport += Get-HTMLNewDetail "RebootPending:" ($RebootStatus.RebootPending) "There should not be any server reboot pending" "If pending need to reboot the server manually"
$MyReport += Get-MyHeaderClose


# Mount Disk Details

Add-Content $logfile "`r` $(get-date) : Mount Disk Details"

$MyReport += Get-MyHeader "2" "DiskMountPoint/BlockSize"
$MyReport += Get-HTMLDetail "DiskMountPoint/BlockSize Details"

$MountDisks = @()

#$MountDisk = gwmi win32_Volume|where-object {$_.filesystem -match “ntfs”} | Select-Object driveletter,@{Name='freespace';Expression={$_.freespace/1GB}},@{Name='capacity';Expression={$_.capacity/1GB}},@{Name='BlockSize';Expression={$_.BlockSize}}, @{Name='Mount_Name';Expression={$_.DeviceID}} 


#$MyReport += Get-HTMLDetail "Mount Disk Details:" ($MountDisk)

$MountDisks = gwmi win32_Volume|where-object {$_.filesystem -match “ntfs”} 

Foreach ($mountdisk in $MountDisks)

{
    $DriveLetter = ($MountDisk.DriveLetter)
    $capacity   = ($mountdisk.capacity/1gb)
    $freespace  = ($mountdisk.freespace/1gb)
    $BlockSize  = $mountdisk.BlockSize
    $Mount_Name = $mountdisk.DeviceID

    $MyReport += Get-HTMLDetail "_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _"
    $MyReport += Get-HTMLDetail "DriveLetter        : " ($DriveLetter) 
    $MyReport += Get-HTMLDetail "Mount_Volume       : " ($Mount_Name)
    $MyReport += Get-HTMLDetail "capacity in GB     : " ($capacity)
    $MyReport += Get-HTMLDetail "freespace in GB    : " ($freespace)
    $MyReport += Get-HTMLDetail "BlockSize          : " ($BlockSize)
 }

$MyReport += Get-MyHeaderClose

# Stopped Autostart Service State

$winver = (Get-WmiObject -class Win32_OperatingSystem).Caption
If ($winver -notlike "*2008*")
{


Add-Content $logfile "`r` $(get-date) : Stopped Autostart Services stopped State"

$MyReport += Get-MyHeader "2" "Stopped Autostart Services stopped State"
$MyReport += Get-HTMLDetail "Stopped Autostart set stopped Services"
$StoppedServices = @()

$StoppedServices = Get-StoppedAutomaticService

Foreach ($StoppedService in $StoppedServices)

{ 
$MyReport += Get-HTMLDetail "_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _"
$MyReport += Get-HTMLDetail "ServiceName: " ($StoppedService.Name)
$MyReport += Get-HTMLDetail "Starttype: " ($StoppedService.Starttype)
$MyReport += Get-HTMLDetail "Status: " ($StoppedService.Status)

}
$MyReport += Get-MyHeaderClose 

}

# Cluster Info 

Try
{

Get-Cluster

$MyReport += Get-myHeader0  "Cluster Report"

$MyReport += Get-MyHeader "2" "Cluster Property"
$MyReport += Get-HTMLDetail "Cluster Property Details"
#$cluster_Prpty = @()
$cluster_Property = Get-Cluster | Select-Object *


$MyReport += Get-HTMLDetail "Add Evict Delay" ($cluster_Property.AddEvictDelay)
$MyReport += Get-HTMLDetail "Administrative AccessPoint" ($cluster_Property.AdministrativeAccessPoint)
$MyReport += Get-HTMLDetail "AutoAssignNodeSite" ($cluster_Property.AutoAssignNodeSite)
$MyReport += Get-HTMLDetail "AutoBalancerLevel" ($cluster_Property.AutoBalancerLevel)
$MyReport += Get-HTMLDetail "AutoBalancerMode" ($cluster_Property.AutoBalancerMode)
$MyReport += Get-HTMLDetail "BackupInProgress" ($cluster_Property.BackupInProgress)
$MyReport += Get-HTMLDetail "BlockCacheSize" ($cluster_Property.BlockCacheSize)
$MyReport += Get-HTMLDetail "ClusSvcHangTimeout" ($cluster_Property.ClusSvcHangTimeout)
$MyReport += Get-HTMLDetail "ClusSvcRegroupStageTimeout" ($cluster_Property.ClusSvcRegroupStageTimeout)
$MyReport += Get-HTMLDetail "ClusSvcRegroupTickInMilliseconds" ($cluster_Property.ClusSvcRegroupTickInMilliseconds)
$MyReport += Get-HTMLDetail "ClusterEnforcedAntiAffinity" ($cluster_Property.ClusterEnforcedAntiAffinity)
$MyReport += Get-HTMLDetail "ClusterFunctionalLevel" ($cluster_Property.ClusterFunctionalLevel)
$MyReport += Get-HTMLDetail "ClusterGroupWaitDelay" ($cluster_Property.ClusterGroupWaitDelay)
$MyReport += Get-HTMLDetail "ClusterLogLevel" ($cluster_Property.ClusterLogLevel)
$MyReport += Get-HTMLDetail "ClusterLogSize" ($cluster_Property.ClusterLogSize)
$MyReport += Get-HTMLDetail "ClusterUpgradeVersion" ($cluster_Property.ClusterUpgradeVersion)
$MyReport += Get-HTMLDetail "CrossSiteDelay" ($cluster_Property.CrossSiteDelay)
$MyReport += Get-HTMLDetail "CrossSiteThreshold" ($cluster_Property.CrossSiteThreshold)
$MyReport += Get-HTMLDetail "CrossSubnetDelay" ($cluster_Property.CrossSubnetDelay)
$MyReport += Get-HTMLDetail "CrossSubnetThreshold" ($cluster_Property.CrossSubnetThreshold)
$MyReport += Get-HTMLDetail "CsvBalancer" ($cluster_Property.CsvBalancer)
$MyReport += Get-HTMLDetail "DatabaseReadWriteMode" ($cluster_Property.DatabaseReadWriteMode)
$MyReport += Get-HTMLDetail "DefaultNetworkRole" ($cluster_Property.DefaultNetworkRole)
$MyReport += Get-HTMLDetail "Description" ($cluster_Property.Description)
$MyReport += Get-HTMLDetail "Domain" ($cluster_Property.Domain)
$MyReport += Get-HTMLDetail "DrainOnShutdown" ($cluster_Property.DrainOnShutdown)
$MyReport += Get-HTMLDetail "DumpPolicy" ($cluster_Property.DumpPolicy)
$MyReport += Get-HTMLDetail "DynamicQuorum" ($cluster_Property.DynamicQuorum)
$MyReport += Get-HTMLDetail "EnableSharedVolumes" ($cluster_Property.EnableSharedVolumes)
$MyReport += Get-HTMLDetail "FixQuorum" ($cluster_Property.FixQuorum)
$MyReport += Get-HTMLDetail "GroupDependencyTimeout" ($cluster_Property.GroupDependencyTimeout)
$MyReport += Get-HTMLDetail "HangRecoveryAction" ($cluster_Property.HangRecoveryAction)
$MyReport += Get-HTMLDetail "Id" ($cluster_Property.Id)
$MyReport += Get-HTMLDetail "IgnorePersistentStateOnStartup" ($cluster_Property.IgnorePersistentStateOnStartup)
$MyReport += Get-HTMLDetail "LogResourceControls" ($cluster_Property.LogResourceControls)
$MyReport += Get-HTMLDetail "LowerQuorumPriorityNodeId" ($cluster_Property.LowerQuorumPriorityNodeId)
$MyReport += Get-HTMLDetail "MessageBufferLength" ($cluster_Property.MessageBufferLength)
$MyReport += Get-HTMLDetail "MinimumNeverPreemptPriority" ($cluster_Property.MinimumNeverPreemptPriority)
$MyReport += Get-HTMLDetail "Name" ($cluster_Property.Name)
$MyReport += Get-HTMLDetail "NetftIPSecEnabled" ($cluster_Property.NetftIPSecEnabled)
$MyReport += Get-HTMLDetail "PlacementOptions" ($cluster_Property.PlacementOptions)
$MyReport += Get-HTMLDetail "PlumbAllCrossSubnetRoutes" ($cluster_Property.PlumbAllCrossSubnetRoutes)
$MyReport += Get-HTMLDetail "PreferredSite" ($cluster_Property.PreferredSite)
$MyReport += Get-HTMLDetail "PreventQuorum" ($cluster_Property.PreventQuorum)
$MyReport += Get-HTMLDetail "QuarantineDuration" ($cluster_Property.QuarantineDuration)
$MyReport += Get-HTMLDetail "QuarantineThreshold" ($cluster_Property.QuarantineThreshold)
$MyReport += Get-HTMLDetail "QuorumArbitrationTimeMax" ($cluster_Property.QuorumArbitrationTimeMax)
$MyReport += Get-HTMLDetail "RecentEventsResetTime" ($cluster_Property.RecentEventsResetTime)
$MyReport += Get-HTMLDetail "RequestReplyTimeout" ($cluster_Property.RequestReplyTimeout)
$MyReport += Get-HTMLDetail "ResiliencyDefaultPeriod" ($cluster_Property.ResiliencyDefaultPeriod)
$MyReport += Get-HTMLDetail "ResiliencyLevel" ($cluster_Property.ResiliencyLevel)
$MyReport += Get-HTMLDetail "RouteHistoryLength" ($cluster_Property.RouteHistoryLength)
$MyReport += Get-HTMLDetail "S2DBusTypes" ($cluster_Property.S2DBusTypes)
$MyReport += Get-HTMLDetail "S2DCacheBehavior" ($cluster_Property.S2DCacheBehavior)
$MyReport += Get-HTMLDetail "S2DCacheDesiredState" ($cluster_Property.S2DCacheDesiredState)
$MyReport += Get-HTMLDetail "S2DCacheMetadataReserveBytes" ($cluster_Property.S2DCacheMetadataReserveBytes)
$MyReport += Get-HTMLDetail "S2DCachePageSizeKBytes" ($cluster_Property.S2DCachePageSizeKBytes)
$MyReport += Get-HTMLDetail "S2DEnabled" ($cluster_Property.S2DEnabled)
$MyReport += Get-HTMLDetail "S2DIOLatencyThreshold" ($cluster_Property.S2DIOLatencyThreshold)
$MyReport += Get-HTMLDetail "S2DOptimizations" ($cluster_Property.S2DOptimizations)
$MyReport += Get-HTMLDetail "SameSubnetDelay" ($cluster_Property.SameSubnetDelay)
$MyReport += Get-HTMLDetail "SameSubnetThreshold" ($cluster_Property.SameSubnetThreshold)
$MyReport += Get-HTMLDetail "SecurityLevel" ($cluster_Property.SecurityLevel)
$MyReport += Get-HTMLDetail "SharedVolumeCompatibleFilters" ($cluster_Property.SharedVolumeCompatibleFilters)
$MyReport += Get-HTMLDetail "SharedVolumeIncompatibleFilters" ($cluster_Property.SharedVolumeIncompatibleFilters)
$MyReport += Get-HTMLDetail "SharedVolumeSecurityDescriptor" ($cluster_Property.SharedVolumeSecurityDescriptor)
$MyReport += Get-HTMLDetail "SharedVolumesRoot" ($cluster_Property.SharedVolumesRoot)
$MyReport += Get-HTMLDetail "SharedVolumeVssWriterOperationTimeout" ($cluster_Property.SharedVolumeVssWriterOperationTimeout)
$MyReport += Get-HTMLDetail "ShutdownTimeoutInMinutes" ($cluster_Property.ShutdownTimeoutInMinutes)
$MyReport += Get-HTMLDetail "UseClientAccessNetworksForSharedVolumes" ($cluster_Property.UseClientAccessNetworksForSharedVolumes)
$MyReport += Get-HTMLDetail "Witness Data baseWrite Timeout" ($cluster_Property.WitnessDatabaseWriteTimeout)
$MyReport += Get-HTMLDetail "Witness Dynamic Weight" ($cluster_Property.WitnessDynamicWeight)
$MyReport += Get-HTMLDetail "Witness Restart Interval" ($cluster_Property.WitnessRestartInterval)

#$MyReport += Get-HTMLTable ($cluster_Property)
$MyReport += Get-MyHeaderClose
$MyReport += Get-MyHeader "2" "Cluster State Information"
$MyReport += Get-HTMLDetail "Cluster_State"
$cluster_nodes = @()

$Getcluster = Get-cluster
$Cluster = $Getcluster.Name

$cluster_nodes = Get-ClusterNode | Select-Object -Property Name, State; 
$MyReport += Get-HTMLTable ($cluster_nodes)
$MyReport += Get-MyHeaderClose  

$MyReport += Get-MyHeader "2" "Cluster Group Information"
$MyReport += Get-HTMLDetail "Cluster_Group_Info"
$cluster_group = @()
$cluster_group = Get-ClusterGroup | Select-Object -Property Name, OwnerNode, State, DefaultOwner, AutoFailbackType; 
$MyReport += Get-HTMLTable ($cluster_group)
$MyReport += Get-MyHeaderClose  

$MyReport += Get-MyHeader "2" "Cluster Resource Information"
$MyReport += Get-HTMLDetail "Cluster_Resource_Details"
$cluster_resources = @()
$cluster_resources = Get-ClusterResource | Select-Object -Property Name, OwnerNode, OwnerGroup, State; 
$MyReport += Get-HTMLTable ($cluster_resources)
$MyReport += Get-MyHeaderClose  

$MyReport += Get-MyHeader "2" "Cluster Owner Node Information"
$MyReport += Get-HTMLDetail "Cluster_owner_node"
$cluster_owner_node = @()
$cluster_owner_node = Get-ClusterResource | Get-ClusterOwnerNode | Select-Object -Property ClusterObject -ExpandProperty OwnerNodes | Select-Object -Property ClusterObject, Name;; 
$MyReport += Get-HTMLTable ($cluster_owner_node)
$MyReport += Get-MyHeaderClose

$MyReport += Get-MyHeader "2" "Cluster Network Information"
$MyReport += Get-HTMLDetail "cluster_network"
$cluster_network = @()
$cluster_network = Get-ClusterNetwork | Select-Object -Property Name, Role, Address, State; 
$MyReport += Get-HTMLTable ($cluster_network)
$MyReport += Get-MyHeaderClose


$MyReport += Get-MyHeader "2" "Cluster Network Interface Information"
$MyReport += Get-HTMLDetail "Cluster_network_interface"
$cluster_network_interface = @()
$cluster_network_interface = Get-ClusterNetworkInterface | Select-Object -Property Name, Network, Node, State; 
$MyReport += Get-HTMLTable ($cluster_network_interface)
$MyReport += Get-MyHeaderClose

$MyReport += Get-MyHeader "2" "Cluster Access Information"
$MyReport += Get-HTMLDetail "Cluster_access"
$cluster_access = @()
$cluster_access = Get-ClusterAccess | Select-Object -Property IdentityReference, AccessControlType, ClusterRights;
$MyReport += Get-HTMLTable ($cluster_access)
$MyReport += Get-MyHeaderClose

$MyReport += Get-MyHeader "2" "Generating Cluster Log"
$MyReport += Get-HTMLDetail "Cluster Log File Created"
$cluster_access = @()
$ClusterLogFile = Get-ClusterLog -UseLocalTime -Destination C:\Windows\ServerScanner\$folderName | Select-Object NAME,Directory,CreationTime
$MyReport += Get-HTMLTable ($ClusterLogFile)
$MyReport += Get-MyHeaderClose
}
Catch
{

$MyReport += Get-MyHeader "2" "Cluster Property"
$MyReport += Get-HTMLDetail "Cluster Not Installed on this Server"
$MyReport += Get-MyHeaderClose

}

# Curent PhysicalDiskPerfCounters

$MyReport += Get-myHeader0  "Server Performance Report"


Add-Content $logfile "`r` $(get-date) : Server Physical Disk performance Counter Snapshot"

# Curent PhysicalDiskPerfCounters

$MyReport += Get-MyHeader "2" "Physical Disk Performance Counter Snapshot"
$MyReport += Get-HTMLDetail "Physical Disk Perf Counter Snapshot"

$Phydkreport = @()
$instance         = "_total" 

$PhydkValues = (@("\\$Computer\PhysicalDisk(*)\Current Disk Queue Length", 
  "\\$Computer\PhysicalDisk(*)\% Idle Time", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk Queue Length", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk Read Queue Length", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk Write Queue Length", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk sec/Transfer" 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk sec/Read", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk sec/Write") |% { 
    (Get-Counter $_.replace("*",$instance)).CounterSamples } | 
    Select-Object Path,CookedValue )

  foreach ($PhydkValue in $PhydkValues)
  
    {
    $Phydkout = "" | Select Path,CookedValue
    $Phydkout.Path = $PhydkValue.path
    $Phydkout.CookedValue = $PhydkValue.CookedValue
    $Phydkreport += $Phydkout
    
    }

$MyReport += Get-HTMLTable ($Phydkreport)
$MyReport += Get-MyHeaderClose

#current Processor performance counter information. 

Add-Content $logfile "`r` $(get-date) : Server Processor Performance Counter Snapshot"

#Curent PhysicalDiskPerfCounters

$MyReport += Get-MyHeader "2" "Server Processor Performance Counter Snapshot"
$MyReport += Get-HTMLDetail "Processor Perf Counter Snapshot"

$Procreport = @()
$instance         = "_total" 

$ProcPerfValues = (@("\\$Computer\Processor(*)\% Processor Time", 
  "\\$Computer\Processor(*)\% User Time", 
  "\\$Computer\Processor(*)\% Privileged Time", 
  "\\$Computer\Processor(*)\Interrupts/sec", 
  "\\$Computer\Processor(*)\% DPC Time", 
  "\\$Computer\Processor(*)\DPCs Queued/sec" 
  "\\$Computer\Processor(*)\% Idle Time", 
  "\\$Computer\Processor(*)\% Interrupt Time") |% { 
    (Get-Counter $_.replace("*",$instance)).CounterSamples } | 
    Select-Object Path,CookedValue)


foreach ($ProcPerfValue in $ProcPerfValues)
  
    {
    $Procout = "" | Select Path,CookedValue
    $Procout.Path = $ProcPerfValue.path
    $Procout.CookedValue = $ProcPerfValue.CookedValue
    $Procreport += $Procout
    
    }

$MyReport += Get-HTMLTable ($Procreport)
$MyReport += Get-MyHeaderClose


# Retreive the current Memory counter information 

Add-Content $logfile "`r` $(get-date) : Server Memory Performance Counter Snapshot"

#Curent PhysicalDiskPerfCounters

$MyReport += Get-MyHeader "2" "Server Memory Performance Counter Snapshot"

$MyReport += Get-HTMLDetail "Memory Perf Counter Snapshot"
$Memreport = @()

$instance         = "_total" 
$MemPerfValues = (@("\\$Computer\Memory\Page Faults/sec", 
  "\\$Computer\Memory\Available Bytes", 
  "\\$Computer\Memory\Committed Bytes", 
  "\\$Computer\Memory\Commit Limit", 
  "\\$Computer\Memory\Pages/sec", 
  "\\$Computer\Memory\Free System Page Table Entries" 
  "\\$Computer\Memory\Pool Paged Resident Bytes", 
  "\\$Computer\Memory\Available MBytes") |% { 
    (Get-Counter $_.replace("*",$instance)).CounterSamples } | 
    Select-Object Path,CookedValue )

foreach ($MemPerfValue in $MemPerfValues)
  
    {
    $Memout = "" | Select Path,CookedValue
    $Memout.Path = $MemPerfValue.path
    $Memout.CookedValue = $MemPerfValue.CookedValue
    $Memreport += $Memout
    
    }

$MyReport += Get-HTMLTable ($Memreport)
$MyReport += Get-MyHeaderClose

# Export Event Logs to CSV
$MyReport += Get-myHeader0  "Exporting Event Logs"

$MyReport += Get-MyHeader "2" "Exporting Last 7 Days Application and System Log to CSV file"
$MyReport += Get-HTMLDetail "Event Log file information"

Set-Variable -Name EventAgeDays -Value 7     #we will take events for the latest 7 days
Set-Variable -Name CompArr -Value @("localhost")   # replace it with your server names
Set-Variable -Name LogNames -Value @("Application", "System")  # Checking app and system logs
Set-Variable -Name EventTypes -Value @("Error", "Warning")  # Loading only Errors and Warnings
Set-Variable -Name ExportFolder -Value "C:\Windows\ServerScanner\$FolderName\"
 

$el_c = @()   #consolidated error log
$now=get-date
$startdate=$now.adddays(-$EventAgeDays)
 

foreach($comp in $CompArr)
{
  foreach($log in $LogNames)
  {
 
    $ExportFile = $ExportFolder + "EventLog-" + $log + "-" +  $now.ToString("yyyy-MM-dd-hh-mm-ss") + ".csv"  # we cannot use standard delimiteds like ":"
    #Write-Host Processing $comp\$log
    $el = get-eventlog -ComputerName $comp -log $log -After $startdate -EntryType $EventTypes
    $el_c += $el  #consolidating
    $el_sorted = $el_c | Sort-Object TimeGenerated    #sort by time
    $el_sorted|Select EntryType, TimeGenerated, Source, EventID, MachineName, message | Export-CSV $ExportFile -NoTypeInfo  #EXPORT
 
  }
 
 
}

$MyReport += Get-HTMLDetail "Event Log File name" ($ExportFile)


# Exporting to Event Logs to Evtx Format

$EventTypes = @('Application','System')

$start = (Get-date).AddDays(-10)
$end = (get-date)

function GetMilliseconds ($date) {
    $ts = New-TimeSpan -Start $date -End (Get-Date)
    [math]::Round($ts.TotalMilliseconds)
    } # end function

$startDate = GetMilliseconds(Get-Date $start)
$endDate = GetMilliseconds(Get-Date $end)

Foreach ($EventType in $EventTypes)

{

$FileEvtFilename = ($EventType + "-Log" + ".evtx")
#Write-host $FileEvtFilename 
$evtxfilepath = "C:\Windows\ServerScanner\$FolderName\$FileEvtFilename"
wevtutil epl $EventType $evtxfilepath /q:"*[System[TimeCreated[timediff(@SystemTime) >= $endDate] and TimeCreated[timediff(@SystemTime) <= $startDate]]]"

$MyReport += Get-HTMLDetail "Event Log File In Evtx" ($evtxfilepath)

}

$MyReport += Get-MyHeaderClose
#####################################################################################

#Report on LGPO Configuration
#Add-Content $logfile "`r` $(get-date) : Dumping LGPO Information"

#$MyReport += Get-MyHeader "2" "Local Group Policies (Registry)"

#$MyReport += Get-MyHeader "2" "Machine"
#$MyReport += Get-HTMLTable ($(Parse-LGPO -GP "Machine"))
#$MyReport += Get-MyHeaderClose

#$MyReport += Get-MyHeader "2" "User"
#$MyReport += Get-HTMLTable ($(Parse-LGPO -GP "User"))
#$MyReport += Get-MyHeaderClose

#$MyReport += Get-MyHeader "2" "Administrators"
#$MyReport += Get-HTMLTable ($(Parse-LGPO -GP "Administrators"))
#$MyReport += Get-MyHeaderClose

#$MyReport += Get-MyHeader "2" "Non Administrators"
#$MyReport += Get-HTMLTable ($(Parse-LGPO -GP "NonAdministrators"))
#$MyReport += Get-MyHeaderClose

# Saving the Output	

$Filename = "C:\Windows\ServerScanner\$folderName\" + $Computer + "_" + $date.Hour + $date.Minute + "_" + $Date.Day + "-" + $Date.Month + "-" + $Date.Year + ".htm"
$MyReport | out-file -encoding ASCII -filepath $Filename
Write "Report saved as $Filename"
Add-Content $logfile "`r` $(get-date) : End of Execution"

# Compress the Report File

$source = "C:\Windows\ServerScanner\$folderName"
$Compfilepath = "$source"
$destination = "$Compfilepath-zip.zip"

If(Test-path $destination) {Remove-item $destination}
Add-Type -assembly "system.io.compression.filesystem"
[io.compression.zipfile]::CreateFromDirectory($Source,$destination) 

#End of Report