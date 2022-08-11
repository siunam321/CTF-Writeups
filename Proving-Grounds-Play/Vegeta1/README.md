# Vegeta1

## Introduction

Welcome to my another writeup! In this Offensive Security's Proving Grounds Play **Vegeta1** machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Don't be Alice.

- Author: [Hawks Team](https://www.vulnhub.com/entry/vegeta-1,501/)

- Released on: Aug 25, 2020

- Difficulty: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a2.png)

According to `rustscan` result, we have several ports are open:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.38

## HTTP on Port 80

As always, check `robots.txt`. In this machine, it has a interesting directory: `/find_me`

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a5.png)

It seems like empty, but when you view the source:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a6.png)

It looks like a `base64` string. Let's copy and paste to a new file and `base64` decode it.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a7.png)

More `base64` encoded string. Lol. Let's decode it again.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a8.png)

Hmm.. It's an **PNG** image, as it has the `PNG` magic header.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a9.png)

Let's open this PNG image via `eog`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a10.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a11.png)

A **QR code**... We can use `zbarimg` to scan it's content:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a12.png)

Boom!! We got a password!

- Password:topshellv

At this point, I tried to use this password and custom wordlist of Dragonball characters(Copied from [Wikipedia](https://en.wikipedia.org/wiki/List_of_Dragon_Ball_characters)) to brute force SSH, as this machine's theme is Dragonball. But no dice. Maybe it's a rabbit hole or something?? Anyway, let's move on.

Next, we can enumerate hidden directory in the web server, I'll use `gobuster` to do that with the custom wordlist of Dragonball characters.

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a13.png)

And we found a hidden directory called: `bulma`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a14.png)

That `hahahaha.wav` sounds interesting. Let's `wget` that wav file.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a16.png)

It's a `morse code` wav file! Let's find an [online morse code decoder](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) to decode it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a17.png)

This time we finally got a username and password!

# Initial Foothold

- Username:trunks
- Password:u$3r

Once we found a pair of username and password, we can SSH into that user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a18.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a19.png)

# Privilege Escalation

## trunks to root

By enumerating manually, we can found that **user `trunks` has permission to write stuff into `/etc/passwd`**, which basically means we can escalate our privilege to root!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a20.png)

To do so, we'll:

1. Generate a password hash for `passwd`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a21.png)

2. Add a new user with root privilege in `/etc/passwd`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a22.png)

3. Switch User to newly created user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a23.png)

And we're root!

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Vegeta1/images/a24.png)

# Conclusion

What we've learned:

1. Web Crawlers (`robots.txt`)
2. Base64 Decode
3. PNG Magic Header
4. Building Custom Wordlist
5. Directory Enumeration
6. Steganography in Audio File
7. Privilege Escalation via writable `/etc/passwd`