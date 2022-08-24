# Deception

## Background

> Deception always leads you straight to the goal. Only local.txt and proof.txt are valid flags.

- Author: [Yash Saxena](https://www.vulnhub.com/entry/haclabs-deception,427/)

- Released on: Jul 20, 2020

- Difficulty: Intermediate

- Overall difficulty for me: Medium
	- Initial foothold: Medium
	- Privilege Escalation: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a2.png)

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache httpd 2.4.29

## HTTP on Port 80

Always check HTTP first, as it has the largest attack vectors.

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a3.png)

Found `/phpmyadmin/`, `/wordpress/` directory.

***WordPress Enumeration:***

**WPScan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a5.png)

Found 2 users: `yash` and `haclabs`.

**Brute forcing WordPress login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a7.png)

I'll let that run, and continue the enumeration process.

We can also see that there is a `robots.txt` in `/wordpress/` directory:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a8.png)

**robots.html:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a10.png)

**View-source:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a11.png)

Looks like when we requested more than 15 times, we'll be redirected to `admindelete.html`. Let's check that out!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a12.png)

Maybe this could be a hint?

**hint.html:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a13.png)

API tokens in home page?

**View-source:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a14.png)

- API old0:5F4DCC3B5AA
- API old1:765D61D8
- API old2:327DEB
- API new:882CF99

- Complete API token:5F4DCC3B5AA765D61D8327DEB882CF99

Hmm... This looks like a hash. Let's crack that.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a18.png)

- Cracked token:password

# Initial Foothold

Armed with that cracked token, we can try to login to different places, like `ssh`, wordpress login page, phpmyadmin login page.

Let's try `ssh` first. Since we found 2 users in `wpscan`, let's try those users with the `password` password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a19.png)

Nope. Let's try the hash as the password?

- Username:yash
- Password:5F4DCC3B5AA765D61D8327DEB882CF99

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a20.png)

Wut? The hash is the password of the user `yash`?

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a21.png)

# Privilege Escalation

> There are 2 ways to escalate to root.

## yash to root

**SUID:**

As we enumerating the target machine, we can see `python2.7` has SUID sticky bit:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a22.png)

According to [GTFOBins](https://gtfobins.github.io/gtfobins/python/), we can use python to import the `os` library, and spawn a shell!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a24.png)

Let's copy and paste that to the target machine!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a23.png)

And I'm root! :D

## yash to haclabs

In the home directory, we can see there is a peculiar hidden file sitting there:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a26.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a27.png)

It looks a bunch of random strings jammed together, or something try to be hidden between those random strings?

If you look carefully, you will find that there are 3 double quotes:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a28.png)

```
haclabs
A=123456789
+A[::-1]
```

If you're familiar with python, you'll see the third item is a way to **reverse a string in python**. (`[::-1]`)

So it basically doing:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a31.png)

We found his password!

- Username:haclabs
- Password:haclabs987654321

Let's **Switch User** to `haclabs`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a29.png)

## haclabs to root

**Sudo permission:**

Oh... `haclabs` is able to run any command as root! Easy win.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a30.png)

I'm root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Deception/images/a25.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. WordPress Enumeration
3. Viewing Source to Find Comments
4. Privilege Escalation via `python2.7` SUID Sticky Bit
5. Privilege Escalation via Reverse Engineering a File
6. Privilege Escalation via Running Any Commands As Root With Misconfigured `sudo` Permission