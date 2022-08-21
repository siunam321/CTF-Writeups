# SunsetMidnight

## Background

> A fun intermediate machine, enjoy. 

- Author: [whitecr0wz](https://www.vulnhub.com/entry/sunset-midnight,517/)

- Released on: Sep 04, 2020

- Difficulty: Intermediate

> Overall difficulty for me: Very easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a2.png)

According to `rustscan` result, we have 3 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.38
3306              | MySQL 5.5.5-10.3.22-MariaDB

## HTTP on Port 80

In the above `nmap` script scanning, it's redirecting to `http://sunset-midnight/`. Let's add this domain to `/etc/hosts`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a3.png)

We can also see that there is something interesting in `robots.txt`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a4.png)

In the `robots.txt`, it indicates that this web server has WordPress. We can use `wpscan` to enumerate the WordPress site:

**WPScan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a6.png)

Found 1 user: `admin`.

I tried to brute force the login page via `hydra`, but no dice.

**How about MySQL??**

## MySQL on Port 3306

Let's use `hydra` to brute force it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a7.png)

Found credentials for `root` in MySQL!

- Username:root
- Password:robert

Nice! Since the target machine has MySQL exposed, let's connect to it and exfiltrate all data in the databases!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a9.png)

Found `admin` hash! Let's crack it via `John The Ripper`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a10.png)

Hmm... Looks like it's uncrackable. Let's try another method.

# Initial Foothold

Since we have remote access to the target's MySQL DBMS, instead of cracking it, why not just change `admin`'s password? :D

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a11.png)

- Username:admin
- Password:pwnedpassword

Now we should able to login to WordPress with admin privilege:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a13.png)

**WordPress reverse shell:**

Can I modify the theme?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a14.png)

Nope.

How about upload a PHP reverse shell plugin?

1. Create a PHP reverse shell for WordPress plugin:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a15.png)

2. Upload it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a16.png)

3. Setup a `nc` listener and "Activate Plugin":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a18.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a19.png)

**Stable Shell via `socat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a20.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a21.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a22.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a23.png)

# Privilege Escalation

> There are 2 ways to escalate our privilege to root

## www-data to jose

In `/var/www/html/wordpress/wp-config.php`, there is a credentials for `jose`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a31.png)

**Let's test password reuse:**

- Username: jose
- Password: 645dc5a8871d2a4269d4cbe23f6ae103

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a32.png)

And we're `jose`!

## www-data/jose to root

**Weird SUID `status` binary:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a24.png)

Let's `strings` that to see what is it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a25.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a26.png)

Looks like this binary suffers a vulnerbility called **relative path**, and it's owned by root!

Let's exploit that!

1. Export our `PATH` environment variable to `/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`. This allows us to exploit relative path.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a27.png)

2. Create a Bash script called `service`, and it'll add SUID bit set to `/bin/bash`, then mark the Bash script as executable.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a28.png)

3. Trigger the exploit, verify `/bin/bash` has SUID bit set, and spawn bash shell with SUID privilege:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a29.png)

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SunsetMidnight/images/a30.png)

# Conclusion

What we've learned:

1. Web Crawler (`robots.txt`)
2. WordPress Enumeration
3. Brute Forcing MySQL Login
4. WordPress Reverse Shell via Injecting a Malicious Plugin
5. Privilege Escalation via Password Reuse
6. Privilege Escalation via Exploiting Relative Path in `status` Binary With SUID Bit Set