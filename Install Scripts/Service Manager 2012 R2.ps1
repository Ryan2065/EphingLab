Install-WindowsFeature NET-Framework-Features -source 'C:\ServiceManagerR2\SXS'
Start-Sleep 10
msiexec /i c:\ServiceManagerR2\SQL_AS_AMO.msi /qb
msiexec /i c:\ServiceManagerR2\sqlncli.msi /qb
