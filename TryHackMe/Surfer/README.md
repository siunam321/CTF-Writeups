# Surfer

## Introduction

Welcome to my another writeup! In this TryHackMe [Surfer](https://tryhackme.com/room/surfer) room, you'll learn: Server-Side Request Forgery (SSRF), which you can access something internal or a web server that under the attacker's control! Without further ado, let's dive in.

## Background

> Surf some internal webpages to find the flag!

> Difficulty: Medium

```
Woah, check out this radical app! Isn't it narly dude? We've been surfing through some webpages and we want to get you on board too! They said this application has some functionality that is only available for internal usage -- but if you catch the right wave, you can probably find the sweet stuff!

Access this challenge by deploying both the vulnerable machine by pressing the green "Start Machine" button located within this task, and the TryHackMe AttackBox by pressing the "Start AttackBox" button located at the top-right of the page.

Navigate to the following URL using the AttackBox: HTTP://MACHINE_IP

Check out similar content on TryHackMe:

-   SSRF (https://tryhackme.com/room/ssrfqi)
```

- Overall difficulty for me: Very easy

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Surfer]
└─# export RHOSTS=10.10.214.74 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Surfer]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 12fa8cf967bcc4b0f9cfe4fb51513700 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGk2LPYFFWDRFPsdnk1k0eElzrMcZJ5bkX76r96vjIWYRe+WStDMNNlPuamTAE4rROMucywLIvG/jwVFAYCjp5ByD8OLe7ZPl5gX4NfDxgEaYH3JkrmM1hXlSb4jVcp7KfOnUyxqP5QN8lHnE5GIWgPFR1W+s+rfGS7mvUSeG4ULdqkhurF2KaYW28KDuasqrOP+b+6mnhYpA3Caqif9Rb2SH/gjzIxcidzT+EXKYRXu0tf6dyVeeiYpvkf5wh3X6VSK/MxuEVpXXy2yX+AE+7c5vnPO8wQE/qvt9hL/vsXaVI8er/brUUJar0X+FjdGK5Cs/UOB53mm7aya9w71GCf8zTHPq+WaoOan706ioYsQOlQ/kH2iDxGF6AHADwwUBhdvlTjrO3QdLnEDLAmHmRr8B37KANgaaupDz2ht2QlKNYVttr5M/MoN186YFwKeLGrlFLH6SBpj0GfhUJSS4v8AIwv9n5nQGABdH2UO2k+jRLXRLxuVJsy6re8tqsxMk=
|   256 c9d7ddba4077093310a247978068ee24 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFGt+ztx+F1assmAbG3SKW+fXqebjl5B33nQA7rXgee3q3sW0u4okWjz7vOUas16cHZ9bsxu1qW+ezg4sW7/pMw=
|   256 14018d5f19af3600fd7040d4ce14c628 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJXbcU/3lFrRLnoscqDt1zYjpmU8GfiSu6RwvMan7oT9
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/backup/chat.txt
| http-title: 24X7 System+
|_Requested resource was /login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: CFFCD51EFA49AB1AC1D8AC6E36462235
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | Apache 2.4.38 ((Debian))

### HTTP on Port 80

**Adding a domain to `/etc/hosts`:** (Optional, but it's a good practice to do so.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Surfer]
└─# echo "$RHOSTS surfer.thm" | tee -a /etc/hosts
```

**`robots.txt`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Surfer]
└─# curl http://surfer.thm/robots.txt    
User-Agent: *
Disallow: /backup/chat.txt
```

- Found an disallowed entry in `/backup/`.

**`/backup/chat.txt`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Surfer]
└─# curl http://surfer.thm/backup/chat.txt

Admin: I have finished setting up the new export2pdf tool.
Kate: Thanks, we will require daily system reports in pdf format.
Admin: Yes, I am updated about that.
Kate: Have you finished adding the internal server.
Admin: Yes, it should be serving flag from now.
Kate: Also Don't forget to change the creds, plz stop using your username as password.
Kate: Hello.. ?
```

**When I reach to `http://surfer.thm/`, it redirects me to `/login.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a1.png)

And armed with above information from the `/backup/chat.txt`, the login credentials is:

- Username: admin
- Password: admin

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a3.png)

I'm in!

Let's dig deeper on this page!

In the `Hosting Server Information` section, we can see that **the server ip is `172.17.0.2`, which is a container IP.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a4.png)

In the `Recent Activity` section, we can see that an **internal** page is being hosted at `/internal/admin.php`, which contains the flag.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a6.png)

**When we reach that `admin.php` page, it says `This page can only be accessed locally.`.**

**In the `Export Reports` section, we can generate a PDF report:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a8.png)

When you click the `Export to PDF`, **it'll send a POST request to `export2pdf.php`, with the `url` data.**

**Hmm... What if we can control the `url` data and reach something internal? Like the `/internal/admin.php`.**

**I'll do this via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Surfer/images/a10.png)

And we got the flag!

# Conclusion

What we've learned:

1. Web Crawler (`robots.txt`)
2. Server-Side Request Forgery (SSRF)