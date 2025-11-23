# Windows Privilege Escalation Checklist

**DO NOT SKIP STEPS.** Check every box in order. This prevents missing obvious vectors.

## Initial Enumeration (Always Run First)

- [ ] Run WinPEAS: [[Windows Privilege Escalation#WinPEAS (Source)|WinPEAS (Source)]] then execute with [[Windows Privilege Escalation#PowerShell Tee|PowerShell Tee]]
- [ ] Check current user and privileges: `whoami /all`
- [ ] Check local users: `net user` and `net localgroup administrators`
- [ ] Check system info: `systeminfo`
- [ ] Check network config: `ipconfig /all` (multiple NICs? Note for pivoting)
- [ ] Check listening ports: `netstat -ano` (internal services to enumerate?)

## Immediate Win Checks (Check These FIRST)

- [ ] **SeImpersonatePrivilege enabled?** `whoami /priv` → If YES, use [[Windows Privilege Escalation#SweetPotato nc shell|SweetPotato nc shell]]
- [ ] **SeAssignPrimaryTokenPrivilege enabled?** → If YES, use [[Windows Privilege Escalation#SweetPotato nc shell|SweetPotato nc shell]]
- [ ] **In Administrators group?** `whoami /groups` → If YES, you may already have admin (UAC bypass?)
- [ ] AlwaysInstallElevated set? [[Windows Privilege Escalation#Check for AlwaysInstallElevated|Check for AlwaysInstallElevated]]

## Credential Hunting (DO NOT SKIP - Even If You Have Admin)

**Your biggest weakness: Skipping this after initial access. ALWAYS CHECK:**

- [ ] PowerShell history ALL users: [[Windows Privilege Escalation#Find PSReadline history|Find PSReadline history]] then `type` each file
- [ ] Search for interesting files: [[Windows Privilege Escalation#Search for files|Search for files]]
- [ ] Download and `strings` any unusual .exe files found (may contain hardcoded creds)
- [ ] Registry autologon creds: [[Windows Privilege Escalation#Check autologon registry|Check autologon registry]]
- [ ] Saved credentials: `cmdkey /list`
- [ ] Search for database files: [[Windows Privilege Escalation#Search for database files|Search for database files]]

## Web Application Enumeration (If Web Server Present)

**CRITICAL: Don't assume you found everything. Port 80/8000/8080 running?**

- [ ] Check for web directories: Review autorecon feroxbuster results thoroughly
- [ ] Look for databases: Check web app directory for .db, .sqlite, .sql files
- [ ] Check web configs: Find config files (web.config, config.php, settings.py) with DB creds
- [ ] Test DB access: If you find DB creds, connect and dump (MySQL, MSSQL, SQLite)
- [ ] Check for exposed directories: /admin, /backup, /db, /config, /setup (manual curl if needed)

## Database Access (If Database Service Running)

- [ ] Check netstat output: MySQL (3306/3307)? MSSQL (1433/1435)? SQLite files?
- [ ] Test default creds: `mysql -u root -p` (try empty password), MSSQL as current user
- [ ] If DB access works, enumerate all databases and tables for credentials
- [ ] Check for password hashes to crack offline

## Service Exploitation

- [ ] Check for unquoted service paths: [[Windows Privilege Escalation#Find unquoted services|Find unquoted services]]
- [ ] Check service permissions: Look in WinPEAS output for modifiable services
- [ ] Check writable service binaries: Can you replace any service .exe?
- [ ] Check scheduled tasks: [[Windows Privilege Escalation#List scheduled tasks|List scheduled tasks]] (writable task binaries?)

## After Getting SYSTEM (DO NOT SKIP THIS)

**EVEN WITH SYSTEM, enumerate for lateral movement credentials:**

- [ ] Run Mimikatz: [[Windows Privilege Escalation#Mimikatz logonpasswords|Mimikatz logonpasswords]]
- [ ] Review Mimikatz output: Extract all NTLM hashes and plaintext passwords
- [ ] Test credentials across domain/network: `netexec smb <targets> -u <users> -H <hashes>`
- [ ] Re-check PowerShell histories: [[Windows Privilege Escalation#Find PSReadline history|Find PSReadline history]]
- [ ] Check for additional unusual files/programs missed earlier
- [ ] Review network interfaces: `ipconfig /all` → Pivoting needed?

## Reference

For detailed commands, see [[Windows Privilege Escalation]]
