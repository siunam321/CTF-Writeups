# Ha-natraj

## Introduction

Welcome to my another writeup! In this Offensive Security's Proving Grounds **Ha-natraj** machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Who is dancing now?

Author: Hacking Articles [view original submission](https://www.vulnhub.com/entry/ha-natraj,489/)
Released on: Sep 01, 2020

## Difficulty

> **Easy**

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a2.png)

According to `rustscan` result, we have several ports are open:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache httpd 2.4.29

## HTTP on Port 80

In the `index.html`, nothing seems to be interesting for us, thus we can enumerate hidden directory via `gobuster`.

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a3.png)

As we can see, there has an interesting directory: `/console`

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a5.png)

It seems like nothing here in `/console/file.php`. Maybe it has a hidden GET parameter??

Let's try `file` GET parameter, as the name of the PHP file looks like fetching files in the system.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a6.png)

Looks like we found a LFI (Local File Inclusion) vulnerability, as I can read `/etc/passwd`!

# Initial Foothold

**Local File Inclusion Log Posioning:**

Since we have a LFI vulnerability, we could leverage this to do **log posioning**.

To do so, I'll fuzz the value of `file` GET parameter via `ffuf` to see is there any interesting files that I can read.

**Ffuf Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a8.png)

Looks like we can read the `/var/log/auth.log`, which is SSH service logs!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a9.png)

Since we can read SSH service logs, we can now try to inject a PHP code via `ssh`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a10.png)

Now we can test if it's working or not.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a11.png)

Yes!! We now have Remote Code Execution! Let's have a reverse shell callback!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a12.png)

As we can see, the system has `python3` installed. Let's have a python reverse shell!

1. Setup a `nc` listener on port 443:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a13.png)

2. Use a python reverse shell and trigger it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a16.png)

We're now in `www-data`!

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a17.png)

`1b491ea5a66b6f041f937c2b8f7fca0f`

# Privilege Escalation

## www-data to mahakal

**sudo -l:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a18.png)

As we can see, `www-data` **has permission to start, stop and restart apache2**.

Also, the `/etc/apache2/apache2.conf` is **world-writable**, which means we can abuse this to escalate our privilege:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a19.png)

And this machine has 2 users: `mahakal` and `natraj`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a23.png)

To escalate our privilege, I'll:

1. Transfer the file via `base64`: (A cool trick to transfer file)

- `base64` **encode** the `apache2.conf` file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a20.png)

- Copy and paste to the attacker machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a21.png)

- `base64` **decode** the base64 file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a22.png)

2. Modify the `apache2.conf` file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a24.png)

3. Transfer the newly modified `apache2.conf` file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a25.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a26.png)

4. Transfer a PHP reverse shell in `/var/www/html`: (From [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php))

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a27.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a28.png)

5. Restart apache2:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a29.png)

6. Setup a `nc` listener on port 443 and trigger the PHP reverse shell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a30.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a31.png)

We're now in the `mahakal` user!

## mahakal to root

**sudo -l:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a32.png)

Looks like `mahakal` can run `nmap` **as root without password**! We can abuse this to escalate to root!!

According to [GTFOBins](https://gtfobins.github.io/gtfobins/nmap/), we can create a fake script to invoke a SH shell via `--script` option!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a33.png)

Let's copy and paste to our reverse shell session!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a34.png)

Wow!! We're root now! Let's `cat` the root flag!

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Ha-natraj/images/a35.png)

`2efc3f4c4cfa7cf92290433828b1f545`

# Conclusion

What we've learned:

1. Directory Enumeration
2. Fuzzing GET parameter
3. Local File Inclusion (LFI)
4. Log Posioning via LFI
5. Transfering Files via `base64`
6. Privilege Escalation via `apache2.conf`
7. Privilege Escalation via `nmap`