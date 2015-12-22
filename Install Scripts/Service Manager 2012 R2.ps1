$SMServer = 'Lab-SM'
$SMServerIP = '192.168.1.6'
$DWServer = 'Lab-DW'
$DWServerIP = '192.168.1.8'
$DCServer = 'Lab-DC'
$DCServerIP = '192.168.1.4'
$SQLServer = 'Lab-SQL'
$SM2Server = 'Lab-SM2'

$MyInvocation.ScriptName
If ($env:COMPUTERNAME -ne "$DCServer") {
    $ScriptFile = $MyInvocation.MyCommand.path
}

$Net35 = {
    Install-WindowsFeature NET-Framework-Features -source 'C:\ServiceManagerR2\SXS'
}

$SQLPreReqs = {
    Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i c:\ServiceManagerR2\SQL_AS_AMO.msi /qb' -Wait
    Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i c:\ServiceManagerR2\sqlncli.msi IACCEPTSQLNCLILICENSETERMS=YES /qb' -Wait
}

$CreateUsers = {
    Import-Module ActiveDirectory
    New-ADOrganizationalUnit -Name '_Lab' -Path 'DC=Home,DC=Lab' -ErrorAction SilentlyContinue
    New-ADOrganizationalUnit -Name 'SM_Accounts' -Path 'OU=_Lab,DC=Home,DC=Lab' -ErrorAction SilentlyContinue
    New-ADUser -Name 'SM_Manager' -SamAccountName 'SM_Manager' -DisplayName 'SM_Manager' -Path 'OU=SM_Accounts,OU=_Lab,DC=Home,DC=Lab' -Enabled $true -ChangePasswordAtLogon $false -AccountPassword ( ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force ) -PassThru
    New-ADUser -Name 'SM_SQL' -SamAccountName 'SM_SQL' -DisplayName 'SM_SQL' -Path 'OU=SM_Accounts,OU=_Lab,DC=Home,DC=Lab' -Enabled $true -ChangePasswordAtLogon $false -AccountPassword ( ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force ) -PassThru
    New-ADUser -Name 'SM_WorkFlow' -SamAccountName 'SM_WorkFlow' -DisplayName 'SM_WorkFlow' -Path 'OU=SM_Accounts,OU=_Lab,DC=Home,DC=Lab' -Enabled $true -ChangePasswordAtLogon $false -AccountPassword ( ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force ) -PassThru
    New-ADUser -Name 'SM_Services' -SamAccountName 'SM_Services' -DisplayName 'SM_Services' -Path 'OU=SM_Accounts,OU=_Lab,DC=Home,DC=Lab' -Enabled $true -ChangePasswordAtLogon $false -AccountPassword ( ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force ) -PassThru
    New-ADUser -Name 'SM_Report' -SamAccountName 'SM_Report' -DisplayName 'SM_Report' -Path 'OU=SM_Accounts,OU=_Lab,DC=Home,DC=Lab' -Enabled $true -ChangePasswordAtLogon $false -AccountPassword ( ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force ) -PassThru
    Add-ADGroupMember 'Domain Admins' 'SM_Manager','SM_SQL','SM_WorkFlow','SM_Services','SM_Report'
}

Invoke-Command -ComputerName $DCServer -ScriptBlock $CreateUsers

Write-Host 'Created accounts on DC'

Start-Sleep 120 # Give other VMs time to get up and running...

Write-Host 'Installing .net 3.5'

Invoke-Command -ComputerName $SMServer,$DWServer,$SQLServer,$SM2Server -ScriptBlock $Net35

Write-Host 'Installing SQL prereqs'

Invoke-Command -ComputerName $SMServer,$DWServer,$SQLServer,$SM2Server -ScriptBlock $SQLPreReqs

#region Install SQL
    $ConfigFile = @'

;SQL Server 2012 Configuration File
[OPTIONS]

; Specifies a Setup work flow, like INSTALL, UNINSTALL, or UPGRADE. This is a required parameter. 

ACTION="Install"

; Detailed help for command line argument ENU has not been defined yet. 

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

; Specifies features to install, uninstall, or upgrade. The list of top-level features include SQL, AS, RS, IS, MDS, and Tools. The SQL feature will install the Database Engine, Replication, Full-Text, and Data Quality Services (DQS) server. The Tools feature will install Management Tools, Books online components, SQL Server Data Tools, and other shared components. 

FEATURES=SQLENGINE,FULLTEXT,AS,RS,SSMS,ADV_SSMS

; Specify the location where SQL Server Setup will obtain product updates. The valid values are "MU" to search Microsoft Update, a valid folder path, a relative path such as .\MyUpdates or a UNC share. By default SQL Server Setup will search Microsoft Update or a Windows Update service through the Window Server Update Services. 

UpdateSource="MU"

; Displays the command line parameters usage 

HELP="False"

; Specifies that the detailed Setup log should be piped to the console. 

INDICATEPROGRESS="False"

; Specifies that Setup should install into WOW64. This command line argument is not supported on an IA64 or a 32-bit system. 

X86="False"

; Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed. 

INSTALLSHAREDDIR="c:\Program Files\Microsoft SQL Server"

; Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed. 

INSTALLSHAREDWOWDIR="c:\Program Files (x86)\Microsoft SQL Server"

; Specify a default or named instance. MSSQLSERVER is the default instance for non-Express editions and SQLExpress for Express editions. This parameter is required when installing the SQL Server Database Engine (SQL), Analysis Services (AS), or Reporting Services (RS). 

INSTANCENAME="MSSQLSERVER"

; Specify the Instance ID for the SQL Server features you have specified. SQL Server directory structure, registry structure, and service names will incorporate the instance ID of the SQL Server instance. 

INSTANCEID="MSSQLSERVER"

; Specify that SQL Server feature usage data can be collected and sent to Microsoft. Specify 1 or True to enable and 0 or False to disable this feature. 

SQMREPORTING="False"

; RSInputSettings_RSInstallMode_Description 

RSINSTALLMODE="DefaultNativeMode"

; Specify if errors can be reported to Microsoft to improve future SQL Server releases. Specify 1 or True to enable and 0 or False to disable this feature. 

ERRORREPORTING="False"

; Specify the installation directory. 

INSTANCEDIR="C:\Program Files\Microsoft SQL Server"

; Agent account name 

AGTSVCACCOUNT="NT Service\SQLSERVERAGENT"

; Auto-start service after installation.  

AGTSVCSTARTUPTYPE="Automatic"

; The name of the account that the Analysis Services service runs under. 

ASSVCACCOUNT="NT Service\MSSQLServerOLAPService"

; Controls the service startup type setting after the service has been created. 

ASSVCSTARTUPTYPE="Automatic"

; The collation to be used by Analysis Services. 

ASCOLLATION="Latin1_General_CI_AS"

; The location for the Analysis Services data files. 

ASDATADIR="C:\Program Files\Microsoft SQL Server\MSAS11.MSSQLSERVER\OLAP\Data"

; The location for the Analysis Services log files. 

ASLOGDIR="C:\Program Files\Microsoft SQL Server\MSAS11.MSSQLSERVER\OLAP\Log"

; The location for the Analysis Services backup files. 

ASBACKUPDIR="C:\Program Files\Microsoft SQL Server\MSAS11.MSSQLSERVER\OLAP\Backup"

; The location for the Analysis Services temporary files. 

ASTEMPDIR="C:\Program Files\Microsoft SQL Server\MSAS11.MSSQLSERVER\OLAP\Temp"

; The location for the Analysis Services configuration files. 

ASCONFIGDIR="C:\Program Files\Microsoft SQL Server\MSAS11.MSSQLSERVER\OLAP\Config"

; Specifies whether or not the MSOLAP provider is allowed to run in process. 

ASPROVIDERMSOLAP="1"

; Specifies the list of administrator accounts that need to be provisioned. 

ASSYSADMINACCOUNTS="Home\Domain Admins"

; Specifies the server mode of the Analysis Services instance. Valid values are MULTIDIMENSIONAL and TABULAR. The default value is MULTIDIMENSIONAL. 

ASSERVERMODE="MULTIDIMENSIONAL"

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

SQLSVCACCOUNT="NT Service\MSSQLSERVER"

; Windows account(s) to provision as SQL Server system administrators. 

SQLSYSADMINACCOUNTS="Home\Domain Admins"

; Provision current user as a Database Engine system administrator for SQL Server 2012 Express. 

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

RSSVCACCOUNT="NT Service\ReportServer"

; Specifies how the startup mode of the report server NT service.  When 
; Manual - Service startup is manual mode (default).
; Automatic - Service startup is automatic mode.
; Disabled - Service is disabled 

RSSVCSTARTUPTYPE="Automatic"

; Add description of input argument FTSVCACCOUNT 

FTSVCACCOUNT="NT Service\MSSQLFDLauncher"


'@

$DWConfig = @'

;SQL Server 2012 Configuration File
[OPTIONS]

; Specifies a Setup work flow, like INSTALL, UNINSTALL, or UPGRADE. This is a required parameter. 

ACTION="Install"

; Detailed help for command line argument ENU has not been defined yet. 

ENU="True"

; Parameter that controls the user interface behavior. Valid values are Normal for the full UI,AutoAdvance for a simplied UI, and EnableUIOnServerCore for bypassing Server Core setup GUI block. 

;UIMODE="Normal"

; Setup will not display any user interface. 

QUIET="True"
IACCEPTSQLSERVERLICENSETERMS="True"

SKIPRULES="RebootRequiredCheck"

; Setup will display progress only, without any user interaction. 

QUIETSIMPLE="False"

; Specify whether SQL Server Setup should discover and include product updates. The valid values are True and False or 1 and 0. By default SQL Server Setup will include updates that are found. 

UpdateEnabled="False"

; Specifies features to install, uninstall, or upgrade. The list of top-level features include SQL, AS, RS, IS, MDS, and Tools. The SQL feature will install the Database Engine, Replication, Full-Text, and Data Quality Services (DQS) server. The Tools feature will install Management Tools, Books online components, SQL Server Data Tools, and other shared components. 

FEATURES=RS,SSMS,ADV_SSMS

; Specify the location where SQL Server Setup will obtain product updates. The valid values are "MU" to search Microsoft Update, a valid folder path, a relative path such as .\MyUpdates or a UNC share. By default SQL Server Setup will search Microsoft Update or a Windows Update service through the Window Server Update Services. 

UpdateSource="MU"

; Displays the command line parameters usage 

HELP="False"

; Specifies that the detailed Setup log should be piped to the console. 

INDICATEPROGRESS="False"

; Specifies that Setup should install into WOW64. This command line argument is not supported on an IA64 or a 32-bit system. 

X86="False"

; Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed. 

INSTALLSHAREDDIR="c:\Program Files\Microsoft SQL Server"

; Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed. 

INSTALLSHAREDWOWDIR="c:\Program Files (x86)\Microsoft SQL Server"

; Specify a default or named instance. MSSQLSERVER is the default instance for non-Express editions and SQLExpress for Express editions. This parameter is required when installing the SQL Server Database Engine (SQL), Analysis Services (AS), or Reporting Services (RS). 

INSTANCENAME="MSSQLSERVER"

; Specify the Instance ID for the SQL Server features you have specified. SQL Server directory structure, registry structure, and service names will incorporate the instance ID of the SQL Server instance. 

INSTANCEID="MSSQLSERVER"

; Specify that SQL Server feature usage data can be collected and sent to Microsoft. Specify 1 or True to enable and 0 or False to disable this feature. 

SQMREPORTING="False"

; RSInputSettings_RSInstallMode_Description 

RSINSTALLMODE="FilesOnlyMode"

; Specify if errors can be reported to Microsoft to improve future SQL Server releases. Specify 1 or True to enable and 0 or False to disable this feature. 

ERRORREPORTING="False"

; Specify the installation directory. 

INSTANCEDIR="C:\Program Files\Microsoft SQL Server"

; Specifies which account the report server NT service should execute under.  When omitted or when the value is empty string, the default built-in account for the current operating system.
; The username part of RSSVCACCOUNT is a maximum of 20 characters long and
; The domain part of RSSVCACCOUNT is a maximum of 254 characters long. 

RSSVCACCOUNT="Home\SM_Report"
RSSVCPASSWORD=”P@ssw0rd”

; Specifies how the startup mode of the report server NT service.  When 
; Manual - Service startup is manual mode (default).
; Automatic - Service startup is automatic mode.
; Disabled - Service is disabled 

RSSVCSTARTUPTYPE="Automatic"


'@

Write-Host "Installing SQL on $SQLServer"
$ConfigFile > "\\$SQLServer\C$\ServiceManagerR2\SQLConfig.ini"
$SMProcess = ([wmiclass]"\\$SQLServer\root\cimv2:Win32_Process").Create( 'C:\ServiceManagerR2\SQL2012SP1\Setup.exe /ConfigurationFile=C:\ServiceManagerR2\SQLConfig.ini' )

While( Get-WmiObject Win32_Process -ComputerName $SQLServer -Filter "ProcessID='$($SMProcess.ProcessID)'") { Start-Sleep 5 }

Restart-Computer -ComputerName $SQLServer -Force

Write-Host "Installing SQL on $DWConfig"

$DWConfig > "\\$DWServer\C$\ServiceManagerR2\SQLConfig.ini"
$SMProcess = ([wmiclass]"\\$DWServer\root\cimv2:Win32_Process").Create( 'C:\ServiceManagerR2\SQL2012SP1\Setup.exe /ConfigurationFile=C:\ServiceManagerR2\SQLConfig.ini' )

While( Get-WmiObject Win32_Process -ComputerName $DWServer -Filter "ProcessID='$($SMProcess.ProcessID)'") { Start-Sleep 5 }

Restart-Computer -ComputerName $DWServer -Force

#endregion

#region Install Service Manager Management Server
$ReportViewerCommandLine = 'C:\ServiceManagerR2\ServiceManager\amd64\Prerequisites\ReportViewer.exe /q'
$ServiceManagerCommandLine = 'C:\ServiceManagerR2\ServiceManager\amd64\Setup.exe /silent /Install:Server /RegisteredOwner:Admin /RegisterdOrganization:Home /AcceptEULA:Yes /SQLServerInstance:Lab-SQL /CreateNewDatabase /DatabaseName:ServiceManager /DatabaseSize:2000 /ManagementGroupName:SCSM /AdminRoleGroup:"Home\Domain Admins" /ServiceRunUnderAccount:Home\SM_Services\P@ssw0rd /WorkflowAccount:Home\SM_Workflow\P@ssw0rd /CustomerExperienceImprovementProgram:Yes /EnableErrorReporting:Yes'
$VSCommandLine = '"C:\ServiceManagerR2\VS 2008 Shell Redist\Isolated Mode\vs_shell_isolated.enu.exe" /q /norestart'
$SMAuthoringExt = '"C:\ServiceManagerR2\SC2012 R2 SCSM AUTHORING TOOL\setup.exe" /install /silent /AcceptEULA /CustomerExperienceImprovementProgram:Yes /EnableErrorReporting:Yes'
$SMLets = 'msiexec /i "C:\ServiceManagerR2\SMLETS.msi" /qn'
Write-Host "Installing report viewer"
$ReportViewerInstall = ([wmiclass]"\\$SMServer\root\cimv2:Win32_Process").Create( "$ReportViewerCommandLine" )
While( Get-WmiObject Win32_Process -ComputerName $SMServer -Filter "ProcessID='$($ReportViewerInstall.ProcessID)'") { Start-Sleep 5 }
Write-Host "Installing Service Manager"
$ServiceManagerInstall = ([wmiclass]"\\$SMServer\root\cimv2:Win32_Process").Create( "$ServiceManagerCommandLine" )
While( Get-WmiObject Win32_Process -ComputerName $SMServer -Filter "ProcessID='$($ServiceManagerInstall.ProcessID)'") { Start-Sleep 5 }
Write-Host "Installing prereqs for Authoring Extension"
$ServiceManagerVSInstall = ([wmiclass]"\\$SMServer\root\cimv2:Win32_Process").Create( "$VSCommandLine" )
While( Get-WmiObject Win32_Process -ComputerName $SMServer -Filter "ProcessID='$($ServiceManagerVSInstall.ProcessID)'") { Start-Sleep 5 }
Write-Host "Installing authoring extension"
$ServiceManagerVSInstall = ([wmiclass]"\\$SMServer\root\cimv2:Win32_Process").Create( "$SMAuthoringExt" )
While( Get-WmiObject Win32_Process -ComputerName $SMServer -Filter "ProcessID='$($SMAuthoringExt.ProcessID)'") { Start-Sleep 5 }
Write-Host "Installing smlets"
$ServiceManagerVSInstall = ([wmiclass]"\\$SMServer\root\cimv2:Win32_Process").Create( "$SMLets" )
While( Get-WmiObject Win32_Process -ComputerName $SMServer -Filter "ProcessID='$($SMLets.ProcessID)'") { Start-Sleep 5 }
#endregion

#region Customize SM
Write-Host "Customizing Service Manager"
Import-Module 'C:\Program Files\Microsoft System Center 2012 R2\Service Manager\Powershell\Microsoft.EnterpriseManagement.Core.Cmdlets\Microsoft.EnterpriseManagement.Core.Cmdlets.psd1'
Import-Module 'C:\Program Files\Common Files\SMLets\SMLets.psd1'
$RunAsAccount = Get-SCSMRunAsAccount -Name "Workflow Account"
$secpasswd = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("Home\SM_Workflow", $secpasswd)
New-SCADConnector -DisplayName "Root AD Connector" -Description "Root AD Connector" -QueryRoot "LDAP://DC=Home,DC=lab" -RunAsAccount $RunAsAccount -ADCredential $mycreds -Enable $True -SyncNow
#endregion
