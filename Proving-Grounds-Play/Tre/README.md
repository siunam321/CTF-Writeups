# Tre

## Background

> You probably do not want to climb this tre. 

- Author: [SunCSR Team](https://www.vulnhub.com/entry/tre-1,483/)

- Released on: Sep 01, 2020

- Difficulty: Intermediate

> Overall difficulty for me: Medium
	- Initial foothold: Easy
	- Privilege Escalation: Medium

# Service Enumeration

**Rustscan Result:**

As usual, scan the machine for open ports via `rustscan`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a2.png)

According to `rustscan` result, we have 3 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.38
8082              | nginx 1.14.2

## HTTP on Port 80

Always check HTTP first, as it has the largest attack vectors.

Found some interesting directories via `gobuster`: `/cms` and `/system`.

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a3.png)

**`/system`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a4.png)

It's a HTTP basic authentication. Maybe we can try to brute force it?? I'll try it later.

**`/cms`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a5.png)

Nothing interesting, as this is a template, nothing stands out.

So, back to the HTTP basic authentication, we could try to "guess" the credentials of the `/system` basic auth:

- Username:admin
- Password:admin

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a6.png)

It worked. Lol. (This is my first guess, ngl.)

**Mantis bug tracker**. Let's use `searchsploit` to search public exploits.

**Searchsploit result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a8.png)

Bunch of results, but how do we know the exact version of this machine's running?

Hmm... Idk, just pick a random exploit and read through the code and comments. I'll pick the "Password Reset" one:

**41890.txt:**
```
Security Issue:
================
Mantis account verification page 'verify.php' allows resetting ANY user's password.
Remote un-authenticated attackers can send HTTP GET requests to Hijack ANY Mantis accounts by guessing the ID / username.

Vulnerable code:

In verify.php line 66:

if( $f_confirm_hash != $t_token_confirm_hash ) {

trigger_error( ERROR_LOST_PASSWORD_CONFIRM_HASH_INVALID, ERROR );

}

This code attempts to verify a user account and compares hashes for a user request.
However, by supplying empty value we easily bypass the security check.

e.g.

http://127.0.0.1/mantisbt-2.3.0/verify.php?id=1&confirm_hash=

This will then allow you to change passwords and hijack ANY mantisbt accounts.

All version >= 1.3.0 as well as 2.3.0 are affected, 1.2.x versions are not affected.
```

So basically when I visit `http://192.168.129.84/system/verify.php?id=1&confirm_hash=`, I can hijack an account? Let's try this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a9.png)

It works?? Let's change admin's password!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a10.png)

- Password:admin

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a12.png)

It worked. :D

> Note: After resetted the admin's password, it might kick you out. You can log back in with `administrator:admin` credentials.

And now we can confirm it's version:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a13.png)

Also, it suffers a Remote Code Execution vulnerability!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a14.png)

# Initial Foothold

Since we have Mantis Bug Tracker administrator access, we can enumerate much deeper.

In the "Manage" -> "Manage Users", I found something that looks like a password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a15.png)

- Username:tre
- Password:Tr3@123456A!

Let's try to `ssh` into `tre` user!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a16.png)

Now I'm `tre`!

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a18.png)

# Privilege Escalation

## tre to root

**sudo -l:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a17.png)

We can see that `tre` is able to run `/sbin/shutdown` as root!

And I saw one weird process via `ps aux`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a19.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a20.png)

It's world-writable!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a21.png)

Looks like this Bash script is checking a service is up or not.

Now, we can modify this Bash script via `nano`, and add a line that'll add SUID bit set to `/bin/bash`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a22.png)

Then, reboot the target machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a23.png)

Finally, log back in as `tre` via `ssh`, verify `/bin/bash` has SUID bit set, and spawn a bash shell with SUID privilege:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a24.png)

And We're root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Tre/images/a25.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. Guessing HTTP Basic Authentication
3. Password Reset in Mantis Bug Tracker
3. Privilege Escalation via `sudo /sbin/shutdown` With World-writable `/usr/bin/check-system` Bash Script