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

Example Terminal
user@tryhackme$ crackmapexec smb 10.211.11.10 --pass-pol

NB i prefer to use Netexec
crackmapexec smb 10.211.11.20 -u users.txt -p passwords.txt


## AD: Authenticated Enumeration 

## Windows Privilege Escalation


## Linux Privilege Escalation



