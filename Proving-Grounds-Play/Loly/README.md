# Loly

## Background

> Come play with Loly. Loly is nice. 

- Author: [SunCSR Team](https://www.vulnhub.com/entry/loly-1,538/)

- Released on: Dec 10, 2020

- Difficulty: Intermediate

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a2.png)

According to `rustscan` result, we have one port is opened:

Ports Open        | Service
------------------|------------------------
80                | nginx 1.10.3

## HTTP on Port 80

Always brute force hidden directory in a web server via `gobuster`!

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a3.png)

Found `/wordpress` directory.

***WordPress Enumeration:***

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a4.png)

**Add `loly.lc` domain to `/etc/hosts`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a5.png)

**WPScan:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a7.png)

Found user `loly`.

**Brute forcing `wp-login.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a10.png)

Successfully brute forced `loly`'s password!

- Username:loly
- Password:fernando

# Initial Foothold

1. Login to http://loly.lc/wordpress/wp-login.php:

- Username:loly
- Password:fernando

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a11.png)

2. Upload a **ziped** PHP reverse shell via `AdRotate` plugin:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a16.png)

3. Setup a `nc` listener and trigger the PHP reverse shell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a18.png)

And I'm `www-data`!

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a19.png)

# Privilege Escalation

## www-data to loly

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a20.png)

Found MySQL credential in `/var/www/html/wordpress/wp-config.php`:

- Username:wordpress
- Password:lolyisabeautifulgirl

**MySQL Enumeration:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a21.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a22.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a23.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a24.png)

Nothing useful in MySQL.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a25.png)

Found user `loly` in this machine.

**Maybe password reuse??**

- Username:loly
- Password:lolyisabeautifulgirl

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a26.png)

And we're user `loly`!!

## loly to root

**Kernel Exploit:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a27.png)

As we can see, the kernel version is quite old, and may suffer some kernel exploits.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a28.png)

The `45010.c` exploit seems like is the perfect exploit for this machine! Let's mirror that C exploit.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a29.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a30.png)

Since the target machine has `gcc` installed, I'll transfer the C exploit and compile it from the target machine.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a31.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a32.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a33.png)

And we're root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Loly/images/a34.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. WordPress Enumeration (`wpscan`)
3. WordPress User Brute Forcing
4. Exploiting WordPress Plugin (`AdRotate`)
5. Privilege Escalation via Reused Password Which Found in `wp-config.php`
6. Privilege Escalation via Kernel Exploit