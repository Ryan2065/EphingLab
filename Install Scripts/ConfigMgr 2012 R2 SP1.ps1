Function AutoLogon {
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "Home\Administrator"
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value P@ssw0rd
    $ScriptName = $MyInvocation.MyCommand.Source
    New-ItemProperty -Path -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noexit `"$ScriptName`""
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
    Install-WindowsFeature NET-Framework-Features -source 'C:\ConfigMgr2012R2SP1\SXS'
    Install-WindowsFeature Web-Asp-Net
    Install-WindowsFeature Web-Asp-Net45
    Install-WindowsFeature NET-HTTP-Activation
    Install-WindowsFeature NET-Non-HTTP-Activ
    AutoLogon
}
elseif ($TimesRan -eq 1) {
    
}
$TimesRan++
New-Item -Path Registry::HKLM\Software\EphingScripts -ErrorAction SilentlyContinue
Set-ItemProperty -Path Registry::HKLM\Software\EphingScripts -Name 'TimesRan' -Value $TimesRan
Restart-Computer -Force