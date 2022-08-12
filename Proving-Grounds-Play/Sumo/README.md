# Sumo

## Introduction

Welcome to my another writeup! In this Offensive Security's Proving Grounds Play **Sumo** machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Enumeration is the name of the game.

- Author: [SunCSR Team](https://www.vulnhub.com/entry/sumo-1,480/)

- Released on: Sep 01, 2020

- Difficult: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a2.png)

According to `rustscan` result, we have several ports are open:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 5.9p1 Debian
80                | Apache httpd 2.2.22

## HTTP on Port 80

It's a good habit to scan the web server's vulnerabilities via `nikto`!

**Nikto Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a3.png)

In the `nikto` result, it said the web server is vulnerable to **Shellshock**.

> Shellshock is effectively a Remote Command Execution vulnerability in BASH. The vulnerability relies in the fact that BASH incorrectly executes trailing commands when it imports a function definition stored into an environment variable. It can be exploited via Apache with mod_cgi, CGI Scripts. (For more information about Shellshock, OWASP has a great [PDF](https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf) explaining this.)

# Initial Foothold

To exploit Shellshock vulnerability, we can use `curl` to inject a arbitrary OS command in the `User-Agent` HTTP header:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a4.png)

**Reverse Shell:**

We can use a BASH one-liner reverse shell to gain an initial foothold: (Generated from https://www.revshells.com/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a6.png)

And we're `www-data`!

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a7.png)

# Privilege Escalation

## www-data to root

By doing manual enumeration, I found that this machine's kernel is quiet old, and might faces some vulnerabilities that we can take an advantage of.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a8.png)

I'll use one of the dirtycow exploits, [`dirty.c`](https://github.com/firefart/dirtycow/blob/master/dirty.c), to escalate our privilege to root.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a9.png)

Since the victim machine has `gcc` installed, I'll compile the exploit in the victim machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a10.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a13.png)

Run the compiled exploit:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a15.png)

And I'm root now! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Sumo/images/a16.png)

# Conclusion

What we've learned:

1. Web Application Vulnerabilities Scanning (`nikto`)
2. Shellshock Remote Code Execution via Apache CGI
3. Privilege Escalation via Kernel Exploit (`dirtycow`)