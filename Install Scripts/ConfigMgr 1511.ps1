<#
    .SYNOPSIS
        This script will install ConfigMgr 1511 and then update it to the latest version (currently 1606)
 
    .DESCRIPTION
        If the domain is not Home and the admin password is not P@ssw0rd, change the two variables at the top of the script.
        File locations:
        .Net 3.5 - C:\ConfigMgr2012R2SP1\SXS
        ADK Install Files - C:\ConfigMgr2012R2SP1\ADK
        SQL Server 2014 Standard - C:\ConfigMgr2012R2SP1\SQL Server 2014 Standard
        ConfigMgr 2012 SP2 - C:\ConfigMgr2012R2SP1\ConfigMgr 2012 SP2
        ConfigMgr 2012 R2 SP1 - D:\LabSources\ConfigMgr2012R2SP1\ConfigMgr 2012 R2 SP1
        ConfigMgr 2012 SP2 Prereqs - C:\ConfigMgr2012R2SP1\PreReqs

    .EXAMPLE
        
  
    .NOTES
        AUTHOR: 
        LASTEDIT: 12/21/2015 22:07:50
 
   .LINK
        
#>

$DefaultUserName = "Home\Administrator"
$DefaultPassword = "P@ssw0rd"

$ConfigMgrServer = ([System.Net.Dns]::GetHostByName(($env:computerName))).HostName
$SiteCode = 'PS1'


#region Files
$SourceFiles = 'C:\ConfigMgr1511'
$SXSFiles = "$($SourceFiles)\SXS"
$ADKFiles = "$($SourceFiles)\ADK"
$SQLFiles = "$($SourceFiles)\SQL Server 2014 Standard"
$ConfigMgrFiles = "$($SourceFiles)\SC_Configmgr_1511"
#endregion
$DomainController = 'Lab-DC'  #required for extending the schema

$LatestUpdateName = 'Configuration Manager 1606'

Function AutoLogon {
<#
    .SYNOPSIS
        Will run this script again after reboot
 
    .DESCRIPTION
        
   
    .EXAMPLE
        AutoLogon -DefaultUserName 'Home\Administrator' -DefaultPassword 'P@ssw0rd'
  
    .NOTES
        AUTHOR: 
        LASTEDIT: 12/21/2015 22:06:33
 
   .LINK
        https://github.com/Ryan2065/EphingLab
#>
    Param ( $DefaultUserName, $DefaultPassword )
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "$DefaultUserName"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $DefaultPassword
    $ScriptName = $MyInvocation.ScriptName
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'EphingScript' -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -file `"$ScriptName`""
}

$TimesRan = (Get-ItemProperty -Path Registry::HKLM\Software\EphingScripts -ErrorAction SilentlyContinue).TimesRan
If ($TimesRan -eq $null) {
    $TimesRan = 0
    Get-Module servermanager
    Install-WindowsFeature Web-Windows-Auth
    Install-WindowsFeature Web-ISAPI-Ext
    Install-WindowsFeature Web-Metabase
    Install-WindowsFeature Web-WMI
    Install-WindowsFeature BITS
    Install-WindowsFeature RDC
    Install-WindowsFeature NET-Framework-Features -source $SXSFiles
    Install-WindowsFeature Web-Asp-Net
    Install-WindowsFeature Web-Asp-Net45
    Install-WindowsFeature NET-HTTP-Activation
    Install-WindowsFeature NET-Non-HTTP-Activ
    Install-WindowsFeature RSAT-AD-Powershell
    Import-Module ActiveDirectory
    try {
        $root = (Get-ADRootDSE).defaultNamingContext
        
        $ou = $null
        try {
            $ou = Get-ADObject "CN=System Management,CN=System,$root"
        }
        catch {  }
        if ($ou -eq $null) {
            $ou = New-ADObject -Type Container -name "System Management" -Path "CN=System,$root" -Passthru
        }
        $acl = Get-ACL "ad:CN=System Management,CN=System,$root"
        $computer = Get-ADComputer $env:ComputerName 
        $sid = [System.Security.Principal.SecurityIdentifier] $computer.SID
        $identity = [System.Security.Principal.IdentityReference] $computer.SID
        $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
        $type = [System.Security.AccessControl.AccessControlType] "Allow"
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
        $acl.AddAccessRule($ace)
        Set-ACL -aclobject $acl "ad:CN=System Management,CN=System,$root"
    }
    catch {  }
    AutoLogon -DefaultUserName $DefaultUserName -DefaultPassword $DefaultPassword
}
elseif ($TimesRan -eq 1) {
    $DeploymentToolsCommandLine = "$($ADKFiles)\adksetup.exe /quiet /features OptionID.DeploymentTools"
    Write-Host "Installing deployment tools"
    $InstallProcess = ([wmiclass]"root\cimv2:Win32_Process").Create( "$DeploymentToolsCommandLine" )
    While( Get-WmiObject Win32_Process -Filter "ProcessID='$($InstallProcess.ProcessID)'") { Start-Sleep 5 }

    $PEEnvironmentCommandLine = "$($ADKFiles)\adksetup.exe /quiet /features OptionID.WindowsPreinstallationEnvironment"
    Write-Host "Installing PE Enivonrment"
    $InstallProcess = ([wmiclass]"root\cimv2:Win32_Process").Create( "$PEEnvironmentCommandLine" )
    While( Get-WmiObject Win32_Process -Filter "ProcessID='$($InstallProcess.ProcessID)'") { Start-Sleep 5 }

    $USMTCommandLine = "$($ADKFiles)\adksetup.exe /quiet /features OptionID.UserStateMigrationTool"
    Write-Host "Installing USMT"
    $InstallProcess = ([wmiclass]"root\cimv2:Win32_Process").Create( "$USMTCommandLine" )
    While( Get-WmiObject Win32_Process -Filter "ProcessID='$($InstallProcess.ProcessID)'") { Start-Sleep 5 }

    Write-Host 'Installing SQL'
$SQLINI = @'
;SQL Server 2014 Configuration File
[OPTIONS]

; Specifies a Setup work flow, like INSTALL, UNINSTALL, or UPGRADE. This is a required parameter. 

ACTION="Install"

; Use the /ENU parameter to install the English version of SQL Server on your localized Windows operating system. 

ENU="True"

; Parameter that controls the user interface behavior. Valid values are Normal for the full UI,AutoAdvance for a simplied UI, and EnableUIOnServerCore for bypassing Server Core setup GUI block. 

; UIMODE="Normal"

; Setup will not display any user interface. 

QUIET="True"

IACCEPTSQLSERVERLICENSETERMS="True"

SKIPRULES="RebootRequiredCheck"

; Setup will display progress only, without any user interaction. 

QUIETSIMPLE="False"

; Specify whether SQL Server Setup should discover and include product updates. The valid values are True and False or 1 and 0. By default SQL Server Setup will include updates that are found. 

UpdateEnabled="False"

; Specify if errors can be reported to Microsoft to improve future SQL Server releases. Specify 1 or True to enable and 0 or False to disable this feature. 

ERRORREPORTING="False"

; If this parameter is provided, then this computer will use Microsoft Update to check for updates. 

USEMICROSOFTUPDATE="False"

; Specifies features to install, uninstall, or upgrade. The list of top-level features include SQL, AS, RS, IS, MDS, and Tools. The SQL feature will install the Database Engine, Replication, Full-Text, and Data Quality Services (DQS) server. The Tools feature will install Management Tools, Books online components, SQL Server Data Tools, and other shared components. 

FEATURES=SQLENGINE,RS,SSMS,ADV_SSMS

; Specify the location where SQL Server Setup will obtain product updates. The valid values are "MU" to search Microsoft Update, a valid folder path, a relative path such as .\MyUpdates or a UNC share. By default SQL Server Setup will search Microsoft Update or a Windows Update service through the Window Server Update Services. 

UpdateSource="MU"

; Displays the command line parameters usage 

HELP="False"

; Specifies that the detailed Setup log should be piped to the console. 

INDICATEPROGRESS="False"

; Specifies that Setup should install into WOW64. This command line argument is not supported on an IA64 or a 32-bit system. 

X86="False"

; Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed. 

INSTALLSHAREDDIR="C:\Program Files\Microsoft SQL Server"

; Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed. 

INSTALLSHAREDWOWDIR="C:\Program Files (x86)\Microsoft SQL Server"

; Specify a default or named instance. MSSQLSERVER is the default instance for non-Express editions and SQLExpress for Express editions. This parameter is required when installing the SQL Server Database Engine (SQL), Analysis Services (AS), or Reporting Services (RS). 

INSTANCENAME="MSSQLSERVER"

; Specify that SQL Server feature usage data can be collected and sent to Microsoft. Specify 1 or True to enable and 0 or False to disable this feature. 

SQMREPORTING="False"

; Specify the Instance ID for the SQL Server features you have specified. SQL Server directory structure, registry structure, and service names will incorporate the instance ID of the SQL Server instance. 

INSTANCEID="MSSQLSERVER"

; RSInputSettings_RSInstallMode_Description 

RSINSTALLMODE="DefaultNativeMode"

; Specify the installation directory. 

INSTANCEDIR="C:\Program Files\Microsoft SQL Server"

; Agent account name 

AGTSVCACCOUNT="NT AUTHORITY\SYSTEM"

; Auto-start service after installation.  

AGTSVCSTARTUPTYPE="Automatic"

; CM brick TCP communication port 

COMMFABRICPORT="0"

; How matrix will use private networks 

COMMFABRICNETWORKLEVEL="0"

; How inter brick communication will be protected 

COMMFABRICENCRYPTION="0"

; TCP port used by the CM brick 

MATRIXCMBRICKCOMMPORT="0"

; Startup type for the SQL Server service. 

SQLSVCSTARTUPTYPE="Automatic"

; Level to enable FILESTREAM feature at (0, 1, 2 or 3). 

FILESTREAMLEVEL="0"

; Set to "1" to enable RANU for SQL Server Express. 

ENABLERANU="False"

; Specifies a Windows collation or an SQL collation to use for the Database Engine. 

SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"

; Account for SQL Server service: Domain\User or system account. 

SQLSVCACCOUNT="NT AUTHORITY\SYSTEM"

; Windows account(s) to provision as SQL Server system administrators. 

SQLSYSADMINACCOUNTS="Home\Domain Admins" "Home\Administrator"

; Provision current user as a Database Engine system administrator for %SQL_PRODUCT_SHORT_NAME% Express. 

ADDCURRENTUSERASSQLADMIN="False"

; Specify 0 to disable or 1 to enable the TCP/IP protocol. 

TCPENABLED="1"

; Specify 0 to disable or 1 to enable the Named Pipes protocol. 

NPENABLED="0"

; Startup type for Browser Service. 

BROWSERSVCSTARTUPTYPE="Disabled"

; Specifies which account the report server NT service should execute under.  When omitted or when the value is empty string, the default built-in account for the current operating system.
; The username part of RSSVCACCOUNT is a maximum of 20 characters long and
; The domain part of RSSVCACCOUNT is a maximum of 254 characters long. 

RSSVCACCOUNT="NT AUTHORITY\SYSTEM"

; Specifies how the startup mode of the report server NT service.  When 
; Manual - Service startup is manual mode (default).
; Automatic - Service startup is automatic mode.
; Disabled - Service is disabled 

RSSVCSTARTUPTYPE="Automatic"

'@
    $SQLINI > "$($SourceFiles)\SQLConfig.ini"
    $InstallProcess = ([wmiclass]"root\cimv2:Win32_Process").Create( "`"$($SQLFiles)\Setup.exe`" /ConfigurationFile=$($SourceFiles)\SQLConfig.ini" )
    While( Get-WmiObject Win32_Process -Filter "ProcessID='$($InstallProcess.ProcessID)'") { Start-Sleep 5 }
    Copy-Item "$($ConfigMgrFiles)\SMSSETUP\BIN\X64\extadsch.exe" "\\$DomainController\C$\" -Force -ErrorAction SilentlyContinue
    $InstallProcess = ([wmiclass]"\\$DomainController\root\cimv2:Win32_Process").Create( "C:\Extadsch.exe" )

    Install-WindowsFeature -Name UpdateServices-Services,UpdateServices-DB -IncludeManagementTools
    mkdir C:\WSUS
    cd 'C:\Program Files\Update Services\Tools\'
    .\wsusutil.exe postinstall SQL_INSTANCE_NAME="$env:ComputerName" CONTENT_DIR=C:\WSUS
    AutoLogon -DefaultUserName $DefaultUserName -DefaultPassword $DefaultPassword
}
elseif ($TimesRan -eq 2) {
    $ConfigMgrINI = @"
[Identification]
Action=InstallPrimarySite

[Options]
ProductID=EVAL
PrerequisiteComp=1
PrerequisitePath="$($ConfigMgrFiles)\PreReqs"
SiteCode=$SiteCode
SMSInstallDir="C:\Program Files\Microsoft Configuration Manager"
SiteName="Home"
ManagementPoint=$ConfigMgrServer
ManagementPointProtocol=HTTP
SDKServer=$ConfigMgrServer
RoleCommunicationProtocol=HTTPorHTTPS
ClientsUsePKICertificate=0
DistributionPoint=$ConfigMgrServer
DistributionPointProtocol=HTTP
DistributionPointInstallIIS=0
MobileDeviceLanguage=0

[SQLConfigOptions]
SQLServerName=$ConfigMgrServer
DatabaseName=SMS_$($SiteCode)
SQLSSBPort=4022

[CloudConnectorOptions]
CloudConnector=1
CloudConnectorServer=$ConfigMgrServer
UseProxy=0
ProxyName=
ProxyPort=

"@
Write-Host "Installing ConfigMgr"
$ConfigMgrINI > C:\ConfigMgr.ini
$CommandLine = "`"$($ConfigMgrFiles)\SMSSETUP\BIN\X64\setup.exe`" /script C:\ConfigMgr.ini /nouserinput"
$InstallProcess = ([wmiclass]"root\cimv2:Win32_Process").Create( $CommandLine )
While( Get-WmiObject Win32_Process -Filter "ProcessID='$($InstallProcess.ProcessID)'") { Start-Sleep 5 }

$WmiObjectSiteClass = "SMS_SCI_SiteDefinition"
$WmiObjectClass = "SMS_SCI_Component"
$WmiComponentName = "ComponentName='SMS_DMP_DOWNLOADER'"
$WmiComponentNameUpdateRing = "UpdateRing" 
$WmiObject = Get-WmiObject -Namespace "root\sms\site_$($SiteCode)" -Class $WmiObjectClass -Filter $WmiComponentName | Where-Object { $_.SiteCode -eq $SiteCode }
#region Enable Fast RIng
$props = $WmiObject.Props
$props = $props | where {$_.PropertyName -eq $WmiComponentNameUpdateRing}
if (!$props) {
    #Create embedded property
    $EmbeddedProperty = ([WMICLASS]"root\SMS\site_$($SiteCode):SMS_EmbeddedProperty").CreateInstance()
    $EmbeddedProperty.PropertyName = $WmiComponentNameUpdateRing
    $EmbeddedProperty.Value = 2
    $EmbeddedProperty.Value1 = ""
    $EmbeddedProperty.Value2 = ""
    $WmiObject.Props += [System.Management.ManagementBaseObject] $EmbeddedProperty
    $WmiObject.put()
}
else
{
    $props = $WmiObject.Props
    $index = 0
    ForEach($oProp in $props)
    {
        if($oProp.PropertyName -eq $WmiComponentNameUpdateRing)
        {
            $oProp.Value=2
            $props[$index]=$oProp;
        }
        $index++
    }

    $WmiObject.Props = $props
    $WmiObject.put()
}
#endregion

AutoLogon -DefaultUserName $DefaultUserName -DefaultPassword $DefaultPassword
}
elseif ($TimesRan -eq 3) {
    Write-Host 'Configuring Site'
    Start-Process "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\Microsoft.ConfigurationManagement.exe"
    [void] [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    Start-Sleep 10
    [System.Windows.Forms.SendKeys]::SendWait('{Enter}')
    Start-Sleep 5
    [System.Windows.Forms.SendKeys]::SendWait('%F')
    Start-Sleep -Milliseconds 50
    [System.Windows.Forms.SendKeys]::SendWait('{Down}')
    Start-Sleep -Milliseconds 50
    [System.Windows.Forms.SendKeys]::SendWait('{Enter}')
    Start-Sleep 5
    [System.Windows.Forms.SendKeys]::SendWait('A')
    Start-Sleep -Milliseconds 50
    [System.Windows.Forms.SendKeys]::SendWait('{Enter}')
    Start-Sleep 5
    AutoLogon -DefaultUserName $DefaultUserName -DefaultPassword $DefaultPassword
}
elseif ($TimesRan -eq 4) {
    Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'
    cd "$($SiteCode):\"

    Add-CMApplicationCatalogWebServicePoint -WebsiteName 'Default Web Site' -WebApplicationName 'CMApplicationCatalogSvc' -PortNumber '80' -SiteSystemServerName $ConfigMgrServer -SiteCode $SiteCode -CommunicationType Http
    Add-CMApplicationCatalogWebsitePoint -ApplicationWebServicePointServerName $ConfigMgrServer -ConfiguredAsHttpConnection -SiteCode $SiteCode -SiteSystemServerName $ConfigMgrServer
    Add-CMAssetIntelligenceSynchronizationPoint -SiteSystemServerName $ConfigMgrServer
    Add-CMEndpointProtectionPoint -LicenseAgreed $true -ProtectionService AdvancedMembership -SiteCode $SiteCode -SiteSystemServerName $ConfigMgrServer
    Add-CMSoftwareUpdatePoint -SiteCode $SiteCode -SiteSystemServerName $ConfigMgrServer -WsusIisPort 8530 -WsusIisSslPort 8531 -ClientConnectionType Intranet -WsusSsl $false -UseProxy $false
    New-CMAccount -UserName 'Home\Administrator' -Password (ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force)
    Add-CMReportingServicePoint -ReportServerInstance "MSSQLSERVER" -DatabaseName "CM_$($SiteCode)" -DatabaseServerName $ConfigMgrServer -SiteCode $SiteCode -SiteSystemServerName $ConfigMgrServer -UserName 'Home\Administrator'

    New-CMBoundary -Name 'All IPs' -Type IPRange -Value '192.168.0.1-192.168.255.255'
    New-CMBoundaryGroup -Name 'All Devices' -DefaultSiteCode 'PS1'
    Add-CMBoundaryToGroup -BoundaryName 'All IPs' -BoundaryGroupName 'All Devices'
    Get-CMDistributionPoint | Set-CMDistributionPoint -AddBoundaryGroupName 'All Devices'

    Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -SiteCode PS1 -Enabled $true
    Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -SiteCode PS1 -Enabled $true
    $Sysdiscovery = Get-CimInstance -Namespace 'root\sms\site_ps1' -classname SMS_SCI_Component -filter 'componentname ="sms_ad_system_discovery_agent"'
    $ADContainerProp =$Sysdiscovery.PropLists | where {$_.PropertyListName -eq "AD Containers" }
    $ADContainerProp.Values = "LDAP://DC=Home,DC=Lab",0,0
    Get-CimInstance -Namespace 'root\sms\site_ps1' -classname SMS_SCI_Component -filter 'componentname ="sms_ad_system_discovery_agent"' | Set-CimInstance -Property @{PropLists=$Sysdiscovery.PropLists}
    Invoke-CMSystemDiscovery -SiteCode PS1

    $Discovery = Get-CimInstance -Namespace 'root\sms\site_ps1' -classname SMS_SCI_Component -filter 'componentname ="SMS_AD_USER_DISCOVERY_AGENT"'
    $ADContainerProp =$Sysdiscovery.PropLists | where {$_.PropertyListName -eq "AD Containers" }
    $ADContainerProp.Values = "LDAP://DC=Home,DC=Lab",0,0
    Get-CimInstance -Namespace 'root\sms\site_ps1' -classname SMS_SCI_Component -filter 'componentname ="SMS_AD_USER_DISCOVERY_AGENT"' | Set-CimInstance -Property @{PropLists=$Sysdiscovery.PropLists}
    
    $Update = $null
    do {
        $ParamHash = @{
            NameSpace = "root\sms\site_$($SiteCode)"
            Query = "Select * from SMS_CM_UpdatePackages where Name like '$($LatestUpdateName)' AND State = 262146"
        }
        $Update = Get-WmiObject @ParamHash
        if($update -eq $null) {
            Write-Host 'No Updates Found'
            $Update
        }
        else {
            Write-Host 'Update found!'
            $Update
        }
        Start-Sleep 5
    } while ($Update -eq $null)

    $ParamHash = @{
        NameSpace = "root\sms\site_$($SiteCode)"
        Query = "Select * from SMS_CM_UpdatePackages where Name like '$($LatestUpdateName)'"
    }
    $Update = Get-WmiObject @ParamHash
    $Update.UpdatePrereqAndStateFlags(0,2)
    Exit
}
$TimesRan++
New-Item -Path Registry::HKLM\Software\EphingScripts -ErrorAction SilentlyContinue
Set-ItemProperty -Path Registry::HKLM\Software\EphingScripts -Name 'TimesRan' -Value $TimesRan
shutdown /r /f /t 0
