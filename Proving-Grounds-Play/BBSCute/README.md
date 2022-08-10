# BBSCute

## Introduction

Welcome to my another writeup! In this Offensive Security's Proving Grounds **BBSCute** machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Cuteness level over 9000!

- Author: [Fortunato 'foxlox' Lodari](https://www.vulnhub.com/entry/bbs-cute-101,567/)

- Released on: Feb 08, 2021

- Difficulty: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a4.png)

According to `rustscan` result, we have several ports are open:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.38
88                | nginx 1.14.2
110               | Courier pop3d (pop3)
995               | Courier pop3d (ssl/pop3)

## HTTP on Port 80

In the `index.html`, nothing seems to be interesting for us, thus we can enumerate hidden directory via `gobuster`.

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a5.png)

As we can see, we found two index page: `index.html` and `index.php`. The `php` one seems funny.

**http://192.168.145.128/index.php:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a6.png)

Ohh, it's the CuteNews CMS (Content Management System), and it's version is exposed: `CuteNews 2.1.2`

Let's use `searchsploit` to find public exploits.

**Searchsploit Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a7.png)

We found 4 exploits for `CuteNews 2.1.2`, the `CuteNews 2.1.2 - Remote Code Execution` looks good for us, we can mirror this exploit via `searchsploit -m 48800`.

# Initial Foothold

> I'll do the exploit in manully, as it's easier to do.

According to the 48800 python exploit, we need an authenticated user in order to have a remote code execution. Let's register a new user first.

1. Register a new user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a8.png)

However, we see the captcha is missing. If we inspect the form in Page Source, we'll see an interesting page, `captcha.php`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a10.png)

Looks like it's the captcha's value!

We can use the generate captcha button to refresh it's value.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a12.png)

2. Create a fake image file which contain PHP code:

In the exploit script, we can see it's using the `GIF8` GIF header to trick the server into thinking it's an image file. We can create a php file which contain a GIF header and a PHP code.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a15.png)

3. Upload the "image" file:

In the exploit script, we can see it's sending a POST request to avatar PHP to upload an "image". We can do this manully.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a16.png)

**Go to "Dashboard" -> "Avatar":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a17.png)

**Select our "image" and click "Save Changes":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a18.png)

**Go to `http://MACHINE_IP/uploads/avatar_{your_user_name}_{your_uploaded_file_name}.php?cmd={command}`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a19.png)

Looks like we have a webshell now :D

We can use this webshell to gain an initial foothold to the machine!

4. Reverse Shell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a20.png)

Looks like the machine has python installed! We can use a python reverse shell to gain initial foothold!

**Generate a python3 reverse shell:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a21.png)

**Setup a `nc` listener:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a22.png)

**Trigger the reverse shell:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a23.png)

**Reverse Shell call back:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a24.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a25.png)

# Privilege Escalation

## www-data to root

**sudo -l:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a26.png)

Looks like `www-data` can run `/usr/sbin/hping3 --icmp` **as root with no password**!

**SUID:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a27.png)

We can also see that `hping3` has **SUID bit set**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a28.png)

According to [GTFOBins](https://gtfobins.github.io/gtfobins/hping3/#suid), if `hping3` has SUID bit set, we can escalate our privilege! However, we can't use `sudo` to escalate our privilege, as we can only run `sudo hping` **with** the `--icmp` option.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a29.png)

I'm root now! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/BSSCute/images/a30.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. File Upload Bypass
3. Remote Code Execution
4. Privilege Escalation via `hping3`