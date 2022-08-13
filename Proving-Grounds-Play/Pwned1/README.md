# Pwned1

## Introduction

Welcome to my another writeup! In this Offensive Security's Proving Grounds Play **Pwned1** machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> This machine has been exploited already. What did the attacker leave behind? 

- Author: [Ajs Walker](https://www.vulnhub.com/entry/pwnlab-1,507/)

- Released on: Sep 16, 2020

- Difficulty: Intermediate

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a2.png)

According to `rustscan` result, we have several ports are open:

Ports Open        | Service
------------------|------------------------
21                | vsftpd 3.0.3
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.38

## HTTP on Port 80

**index.html:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a3.png)

**View Source:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a4.png)

**robots.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a5.png)

In the `robots.txt`, we found that there are 2 hidden directory: `/nothing` and `/hidden_text`.

**/nothing:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a7.png)

**/hidden_text:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a9.png)

Looks like the `secret.dic` is a wordlist. We can `wget` that.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a10.png)

This wordlist looks like some directories in the web server. Let's brute force it via `gobuster`.

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a11.png)

**`/pwned.vuln`** is the hidden directory...

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a12.png)

**View Source:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a13.png)

In the PHP code, we found credential for FTP:

- Username:ftpuser
- Password:B0ss_Pr!ncesS

## FTP on Port 21

**Armed with that information, we can try to login into FTP.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a14.png)

Found `share` directory.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a15.png)

Inside the `share` directory, we can see there are 2 files: `id_rsa`, `note.txt`. We can extract them via `mget` in FTP:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a17.png)

Looks like we found user `ariana` private SSH key!

# Initial Foothold

**Since we have `ariana` private SSH key, we can now SSH into `ariana`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a18.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a19.png)

# Privilege Escalation

## ariana to selena

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a20.png)

There are **3 users** in this machine.

**sudo -l:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a21.png)

`ariana` can run `sudo /home/messenger.sh` as user `selena`.

**messenger.sh:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a22.png)

`sudo -u selena /home/messenger.sh`

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a23.png)

Since the `messenger.sh` Bash script accepts anything that we typed, we can abuse the `msg` varible. We can type `bash -i` to get a shell that's belong to user `selena`.

```bash
# Read our input and store it as msg varible
read -p "Enter message for $name :" msg

# Errors will be redirected to /dev/null.
$msg 2> /dev/null
```

But what if we type `bash -i`? It'll become:

```bash
bash -i 2> /dev/null
```

Which can be abused for escalate our privilege to `selena`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a24.png)

## selena to root

We also saw `selena` is inside the `docker` group in the above `id` command! Let's list all docker images!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a25.png)

The `privesc` image seems weird... (All 3 docker images works perfect for privilege escalation, you can choose one of them to escalate to root.)

Let's spawn a shell inside the `privesc` container: (From [GTFOBins](https://gtfobins.github.io/gtfobins/docker/).)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a26.png)

Since we're root inside the docker container, we can add a new user with root privilege in the `/etc/passwd`! (You can just `cat` proof.txt in here. However, you're not really rooted this machine, as you're the root user inside the docker container (172.17.0.2), NOT the root user inside the machine (192.168.145.95).)

1. Generate a hash for `/etc/passwd`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a27.png)

2. Add a new user in the `/etc/passwd` file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a28.png)

3. Exit current docker container, and Switch User to the newly created user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a29.png)

And we're root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Pwned1/images/a30.png)

# Conclusion

What we've learned:

1. Web Crawler (`robots.txt`)
2. Directory Enumeration
3. Found Sensitive Information in View-Source
4. Private SSH Key
5. Privilege Escalation via Inseure Bash Script (Horizontal Privilege Escalation)
6. Privilege Escalation via Docker (Vertical Privilege Escalation)