
Function Write-EphingLog {
    Param (
        $Message,
        $ErrorMessage
    )
    Write-Host $Message 
    Write-Host $ErrorMessage
}

Function Mount-EphingDrive {
    Param ($Path)
    $DriveLetter=""
    $Drives = (Mount-VHD -Path $Path -ErrorAction SilentlyContinue -PassThru | Get-Disk | Get-Partition).DriveLetter
    If ($Drives.Count -gt 1) {
        $LargestDrive = 0
        For ($d = 0; $d -lt $Drives.Count; $d++) {
            If (($Drives[$d] -ne [char]0) -and ((Get-Partition -DriveLetter $Drives[$d]).Size -gt $LargestDrive)) {
                $DriveLetter = $Drives[$d]
                $LargestDrive = (Get-Partition -DriveLetter $Drives[$d]).Size
            }
        }
    } Else {
        $DriveLetter = $Drives
    }
    return $DriveLetter
}

Function Create-EphingUnattend {
    Param (
        $ComputerName,
        $FilePath,
        $WindowsProductKey,
        $IPMask,
        $IPGateway,
        $IPAddress,
        $DNSAddress,
        $Domain,
        $JoinDomainPassword,
        $JoinDomainUsername,
        $JoinDomainOrganizationalUnitFull,
        #$AutoLogon,
        $AdministratorPassword,
        $InstallerServiceAccount,
        $InstallerServiceAccountPassword,
        $TimeZone = 'Central Standard Time',
        $InstallerServiceAccountDomain,
        $InstallerServiceAccountUsername
    )

@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$ComputerName</ComputerName>
            <RegisteredOrganization></RegisteredOrganization>
            <RegisteredOwner></RegisteredOwner>
"@ | Out-File $FilePath -Encoding ASCII

If (!([string]::IsNullOrEmpty($WindowsProductKey))) {
@"
            <ProductKey>$WindowsProductKey</ProductKey>
"@ | Out-File $FilePath -Append -Encoding ASCII
}

@"
        </component>
"@ | Out-File $FilePath -Append -Encoding ASCII

@"
        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$IPAddress/$IPMask</IpAddress>
                    </UnicastIpAddresses>
                    <Identifier>Ethernet</Identifier>
                    <Routes>
                        <Route wcm:action="add">
                            <Identifier>1</Identifier>
                            <Prefix>0.0.0.0/0</Prefix>
                            <NextHopAddress>$IPGateway</NextHopAddress>
                        </Route>
                    </Routes>
                </Interface>
            </Interfaces>
        </component>
        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
"@ | Out-File $FilePath -Append -Encoding ASCII


@"
                        <IpAddress wcm:action="add" wcm:keyValue="1">$DNSAddress</IpAddress>
"@ | Out-File $FilePath -Append -Encoding ASCII

@"
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
            </Interfaces>
        </component>
"@ | Out-File $FilePath -Append -Encoding ASCII

If (!([string]::IsNullOrEmpty($Domain))) {
$SplitDomain = $Domain.Split('.')
$SplitDomain = $SplitDomain[0]
@"
        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Identification>
                <Credentials>
                    <Domain>$SplitDomain</Domain>
                    <Password>$JoinDomainPassword</Password>
                    <Username>$JoinDomainUsername</Username>
                </Credentials>
                <JoinDomain>$Domain</JoinDomain>
"@ | Out-File $FilePath -Append -Encoding ASCII
If (!([string]::IsNullOrEmpty($JoinDomainOrganizationalUnitFull))) {
@"
                <MachineObjectOU>$JoinDomainOrganizationalUnitFull</MachineObjectOU>
"@ | Out-File $FilePath -Append -Encoding ASCII
                            }
@"
            </Identification>
        </component>
"@ | Out-File $FilePath -Append -Encoding ASCII
}

@"
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAuthentication>0</UserAuthentication>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
"@ | Out-File $FilePath -Append -Encoding ASCII
<#
If (($AutoLogon -eq $true) -and [string]::IsNullOrEmpty($InstallerServiceAccount)) {

@"
            <AutoLogon>
                <Password>
                    <Value>$AdministratorPassword</Value>
                    <PlainText>true</PlainText>
                </Password>
                <LogonCount>1</LogonCount>
                <Username>Administrator</Username>
                <Enabled>true</Enabled>
            </AutoLogon>
"@ | Out-File $FilePath -Append -Encoding ASCII
} 
<#
ElseIf (($AutoLogon -eq $true) -and !([string]::IsNullOrEmpty($InstallerServiceAccount))) {

@"
            <AutoLogon>
                <Password>
                    <Value>$InstallerServiceAccountPassword</Value>
                    <PlainText>true</PlainText>
                </Password>
                <LogonCount>1</LogonCount>
                <Username>$InstallerServiceAccount</Username>
                <Enabled>true</Enabled>
            </AutoLogon>
"@ | Out-File $FilePath -Append -Encoding ASCII
}
#>

@"
            <TimeZone>$TimeZone</TimeZone>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$AdministratorPassword</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <RegisteredOrganization></RegisteredOrganization>
            <RegisteredOwner></RegisteredOwner>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <SkipMachineOOBE>true</SkipMachineOOBE>
            </OOBE>
"@ | Out-File $FilePath -Append -Encoding ASCII

@"
        </component>
    </settings>
</unattend>
"@ | Out-File $FilePath -Append -Encoding ASCII

}

Function Create-EphingSetupComplete {
    Param (
        $DriveLetter,
        $InstallDomain,
        $AdministratorPassword,
        $StartupScriptName,
        $Domain
    )

    $ScriptName = "C:\$StartupScriptName"

If (!(Test-Path "$DriveLetter`:\Windows\Setup\Scripts")) {New-Item -Path "$DriveLetter`:\Windows\Setup\Scripts" -ItemType Directory | Out-Null}
If (!(Test-Path "$DriveLetter`:\Temp")) {New-Item -Path "$DriveLetter`:\Temp" -ItemType Directory | Out-Null}
@"
@echo off
if exist %SystemDrive%\unattend.xml del %SystemDrive%\unattend.xml
reg add HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /t REG_SZ /d "Unrestricted" /f

ipconfig.exe /registerdns
powershell.exe -command %WinDir%\Setup\Scripts\SetupComplete.ps1
"@ | Out-File "$DriveLetter`:\Windows\Setup\Scripts\SetupComplete.cmd" -Encoding ASCII

$OnSetup = 0

@"
Enable-PSRemoting -Force
Remove-Item "`$env:WinDir\Setup\Scripts\SetupComplete.ps1"
Set-NetFirewallProfile -Profile Domain -Enabled False
Set-NetFirewallProfile -Profile Public -Enabled False
Set-NetFirewallProfile -Profile Private -Enabled False
"@ | Out-File "$DriveLetter`:\Windows\Setup\Scripts\SetupComplete.ps1" -Encoding ASCII

If ($InstallDomain -eq $true) {

$DomainShort = $Domain.Split(".")[0]

@"
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
`$password = ConvertTo-SecureString -AsPlainText -String "$AdministratorPassword" -Force
Import-Module ADDSDeployment
`$DatabasePath = "C:\Windows\NTDS"
`$LogPath = "C:\Windows\NTDS"
`$SysvolPath = "C:\Windows\SYSVOL"
Set-itemproperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ConfigureServer" -Value "shutdown /s /t 5"
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "Administrator" 
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value "$AdministratorPassword"
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1" 
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Value "1" 
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Value "$Domain"
Install-ADDSForest -DomainName "$Domain" -ForestMode "Win2012" -DomainMode "Win2012" -InstallDns:`$true -SafeModeAdministratorPassword `$password -CreateDnsDelegation:`$false -DomainNetbiosName "$DomainShort" -DatabasePath `$DatabasePath -LogPath `$LogPath -SysvolPath `$SysvolPath -Force:`$true

"@ | Out-File "$DriveLetter`:\Windows\Setup\Scripts\SetupComplete.ps1" -Append -Encoding ASCII

@"
shutdown /s /t 0
"@ | Out-File "$DriveLetter`:\Windows\Setup\Scripts\SetupComplete.cmd" -Encoding ASCII -Append

}
If ($AutoLogon -eq $true) {
@"
Set-itemproperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ConfigureServer" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File "$ScriptName"')
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "Administrator" 
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value "$AdministratorPassword"
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1" 
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Value "1" 
Set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Value "$Domain"

"@ | Out-File "$DriveLetter`:\Windows\Setup\Scripts\SetupComplete.ps1" -Append -Encoding ASCII
}


}

Function Create-EphingLabVM {
    Param (
        $VHDPath,
        $VHDParentPath,
        $VMName,
        $VMPath,
        $MemoryStartupBytes = 1GB,
        $SwitchName,
        $Generation = 2,
        $ProductKey,
        $IPMask = "24",
        $IPGateway = "192.168.1.1",
        $IPAddress,
        $DNSAddress,
        $Domain,
        $JoinDomainPassword = 'P@ssw0rd',
        $JoinDomainUsername = 'Administrator',
        $JoinDomainOrganizationalUnitFull,
        $AutoLogon = $true,
        $AdministratorPassword = 'P@ssw0rd',
        $InstallerServiceAccount,
        $InstallerServiceAccountPassword,
        $InstallerServiceAccountDomain,
        $InstallerServiceAccountUsername,
        $InstallDomain = $false,
        $SetupCompleteDomain,
        $Processors,
        $StartupScript
    )

    $NewVHDParams = @{
        'Path'="$VHDPath";
        'ParentPath'="$VHDParentPath";
        'Differencing'=$true;
    }
    $NewVMParams = @{
        'Name' = $VMName;
        'Path' = "$VMPath";
        'MemoryStartupBytes' = $MemoryStartupBytes;
        'SwitchName' = "$SwitchName";
        'VHDPath' = (New-VHD @NewVHDParams).Path;
        'Generation' = $Generation;
    }

    New-VM @NewVMParams
    Set-VM -Name $VMName -ProcessorCount $Processors -DynamicMemory:$false
    $Drive = Mount-EphingDrive -Path $VHDPath
    $DomainName = $Domain
    if ($IPAddress -eq $DNSAddress) { $DomainName = "" }
    $UnattendParams = @{
            'ComputerName'="$VMName";
            'FilePath'="$Drive`:\Unattend.xml";
            'WindowsProductKey'="$ProductKey";
            'IPMask'="$IPMask";
            'IPGateway'="$IPGateway";
            'IPAddress'="$IPAddress";
            'DNSAddress'="$DNSAddress";
            'Domain'="$DomainName";
            'JoinDomainPassword'="$JoinDomainPassword";
            'JoinDomainUsername'="$JoinDomainUsername";
            'JoinDomainOrganizationalUnitFull'="$JoinDomainOrganizationalUnitFull";
            'AutoLogon'=$AutoLogon;
            'AdministratorPassword'="$AdministratorPassword";
    }

    Create-EphingUnattend @UnattendParams
    $StartupScriptName = $StartupScript.Split('\')
    $StartupScriptName = $StartupScriptName[$StartupScriptName.Length - 1]
    $SetupCompleteParams = @{
            'DriveLetter'="$Drive";
            'InstallDomain'=$InstallDomain;
            'AdministratorPassword'="$AdministratorPassword";
            'Domain'="$SetupCompleteDomain";
            'StartupScriptName'=$StartupScriptName;
    }

    Create-EphingSetupComplete @SetupCompleteParams

    Dismount-VHD -Path $VHDPath

}

Function Create-EphingLab {
    Param ( $LabXML )
    [xml]$XML = Get-Content $LabXML

    $DomainName = $xml.Lab.General.Domain
    $AdminPassword = $xml.Lab.General.AdministratorPassword
    $Switch = $xml.Lab.General.Switch
    $DomainController = $xml.Lab.General.DomainController
    $DNSAddress = ""
    Foreach ($vm in $xml.Lab.VM) {
        If ($DomainController -eq $VM.VMName) { $DNSAddress = $VM.IPAddress }
    }
    Write-EphingLog -Message "Domain: $DomainName"
    Write-EphingLog -Message "Switch: $Switch"
    Write-EphingLog -Message "Domain Controller: $DomainController"
    Write-EphingLog -Message "Admin Password: $AdminPassword"
    Write-EphingLog -Message "DNS Address: $DNSAddress"
    If (!(Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue)) { 
        Write-Log -Message "Switch $Switch not found - creating..."
        New-VMSwitch -Name $Switch -SwitchType Internal
    }
    Foreach ($vm in $xml.Lab.VM) {
        If (!(Get-VM -Name $VM.VMName -ErrorAction SilentlyContinue)) {
            [int64]$OneGB = 1073741824
            $VMMemory = $VM.Memory
            $VMMemory = [int64]$VMMemory.ToUpper().Replace("GB","")
            $VMMemory = $VMMemory * $OneGB
            $InstallDomain = $false
            If ($DomainController -eq $VM.VMName) { $InstallDomain = $true }
            $StartupScript = $vm.StartupScript
            $AutoLogon = $false
            if (!([String]::IsNullOrEmpty($StartupScript))) { $AutoLogon = $true }
            $NewVMParams = @{
                VHDPath = $VM.VHDPath
                VHDParentPath = $VM.VHDParentPath
                VMName = $VM.VMName
                VMPath = $VM.VMPath
                MemoryStartupBytes = $VMMemory
                Processors = $VM.Processors
                SwitchName = $Switch
                Generation = $VM.Generation
                ProductKey = $Vm.ProductKey
                IPMask = "24"
                IPGateway = "192.168.1.1"
                IPAddress = $VM.IPAddress
                DNSAddress = $DNSAddress
                Domain = $DomainName
                JoinDomainPassword = $AdminPassword
                JoinDomainUsername = "Administrator"
                AutoLogon = $AutoLogon
                AdministratorPassword = $AdminPassword
                InstallDomain = $InstallDomain
                SetupCompleteDomain = $DomainName
                StartupScript = $VM.StartupScript
            }
            Create-EphingLabVM @NewVMParams

            $Mounted = $false
            $Drive = ""
            Foreach ($instance in $VM.FolderToCopy) {
                if($Mounted -eq $false) {
                    $Drive = Mount-EphingDrive -Path $VM.VHDPath
                    $Drive = $Drive + ":\"
                    $Mounted = $true
                }
                Copy-Item -Path $instance -Destination $Drive -Recurse
            }

            $StartScript = $VM.StartupScript
            if(!([String]::IsNullOrEmpty($StartScript))) {
                If ($Mounted -ne $true) { 
                    $Drive = Mount-EphingDrive -Path $VM.VHDPath
                    $Drive = $Drive + ":\"
                    $Mounted = $true
                }
                Copy-Item -Path $StartScript -Destination $Drive
            }

            If ($Mounted -eq $true) {
                Dismount-VHD -Path $VM.VHDPath
            }
            If ($DomainController -eq $VM.VMName) { Start-VM -Name $DomainController }
        } #if get-name
    }

    $Off = $false
    $count = 0
    while ($off -eq $false) {
        If ((Get-VM -Name $DomainController).State -ne 'Running') {
            if ($count -ne 0) { $off = $true }
            else { $count++ }
            Start-Sleep 10
        }
    }

    Start-VM -Name $DomainController
    Start-Sleep 10

    Foreach ($vm in $xml.Lab.VM) {
        Start-VM -Name $VM.VMName
    }
}

Function Remove-EphingLab {
    Param(
        [string]$LabXML
    )
    [xml]$XML = Get-Content $LabXML
    Foreach ($vm in $xml.Lab.VM) {
        $VMName = $VM.VMName
        $VHDPath = $VM.VHDPath
        Remove-VM -Name $VMName -Force
        Remove-Item -Path $VHDPath -Force
    }
}

#Create-EphingLab -LabXML 'D:\HomeLab.xml'

#Remove-EphingLab -LabXML 'D:\HomeLab.xml'
