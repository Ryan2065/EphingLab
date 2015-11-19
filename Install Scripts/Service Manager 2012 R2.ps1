$SQLServer = 'Lab-SMSQL'
$SQLServerIP = '192.168.1.7'
$SMServer = 'Lab-SM'
$SMServerIP = '192.168.1.6'
$DWServer = 'Lab-DW'
$DWServerIP = '192.168.1.8'
$WebServer = 'Lab-Web'
$WebServerIP = '192.168.1.9'
$DCServer = 'Lab-DC'
$DCServerIP = '192.168.1.4'


$Net35 = {
    Install-WindowsFeature NET-Framework-Features -source 'C:\ServiceManagerR2\SXS'
}

$SQLPreReqs = {
    Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i c:\ServiceManagerR2\SQL_AS_AMO.msi /qb'
    Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i c:\ServiceManagerR2\sqlncli.msi /qb'
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

Invoke-Command -ComputerName $DCServer -ScriptBlock $CreateUsers -AsJob

Start-Sleep 120

Invoke-Command -ComputerName $SQLServer,$SMServer,$DWServer,$WebServer -ScriptBlock $Net35 -AsJob

Invoke-Command -ComputerName $SMServer,$SQLServer,$DWServer -ScriptBlock $SQLPreReqs -AsJob
