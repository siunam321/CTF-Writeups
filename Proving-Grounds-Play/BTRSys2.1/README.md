# BTRSys2.1

## Background

> The tragic history of a modern web application and client side approach. 

- Author: [İsmail Önder Kaya](https://www.vulnhub.com/entry/btrsys-v21,196/)

- Released on: Jul 20, 2020

- Difficulty: Intermediate

> Overall difficulty for me: Extremely easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a2.png)

According to `rustscan` result, we have 3 ports are opened:

Ports Open        | Service
------------------|------------------------
21                | vsftpd 3.0.3
22                | OpenSSH 7.2p2 Ubuntu
80                | Apache httpd 2.4.18

## HTTP on Port 80

Always check `robots.txt`. :D

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a3.png)

Found `/wordpress/` directory via `robots.txt`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a6.png)

Found `/upload/` directory via `gobuster`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a7.png)

Not sure about what is it.

***WordPress enumeration:***

**WPScan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a5.png)

`WordPress 3.9.14`, quite old.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a8.png)

Found 2 users: `admin` and `btrisk`

Randomly guessing `admin` password from WordPress login page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a9.png)

- Username:admin
- Password:admin

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a10.png)

Nice password. :D

# Initial Foothold

1. Login to http://192.168.129.50/wordpress/wp-login.php:

- Username:admin
- Password:admin

2. Modify a theme's template to [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a11.png)

3. Setup a `nc` listener and trigger the reverse shell via `curl` `http://192.168.129.50/wordpress/wp-content/themes/twentyfourteen/404.php`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a14.png)

**Stable Shell via `socat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a17.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a18.png)

# Privilege Escalation

## www-data to btrisk

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a19.png)

Found MySQL credentials via `/var/www/html/wordpress/wp-config.php`:

- Username:root
- Password:rootpassword!

**Enumerating MySQL:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a20.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a21.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a22.png)

Found `root` hash in WordPress. Let's crack it via [crackstation](https://crackstation.net/):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a23.png)

- Username:root
- Password:roottoor

**Test password reuse:**

- Username:btrisk
- Password:roottoor

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a24.png)

## btrisk to root

**sudo -l:**

User `btrisk` is able to **run any command as root**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a25.png)

And we're root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BTRSys2.1/images/a26.png)

# Conclusion

What we've learned:

1. Web Crawler (`robots.txt`)
2. Directory Enumeration
3. WordPress Enumeration
4. Guessing WordPress Login Credentials
5. WordPress Reverse Shell via Modfiying a Theme Template
6. MySQL Enumeration
7. Hash Cracking
8. Privilege Escalation via Password Reuse
9. Privilege Escalation via Misconfigured `sudo` Permission