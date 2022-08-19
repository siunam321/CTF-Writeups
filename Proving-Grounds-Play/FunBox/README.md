# FunBox

## Background

> Have fun! ;)  

- Author: [0815R2d2](https://www.vulnhub.com/entry/funbox-1,518/)

- Released on: Sep 02, 2020

- Difficulty: Intermediate

> Overall difficulty for me: Very easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a3.png)

According to `rustscan` result, we have 4 ports are opened:

Ports Open        | Service
------------------|------------------------
21                | ProFTPD
22                | OpenSSH 8.2p1 Ubuntu
80                | Apache httpd 2.4.41
33060             | MySQL?

## HTTP on Port 80

In the `rustscan`'s `nmap` `http-title:`, it redirected to `http://funbox.fritz.box/`. Let's add this domain to `/etc/hosts`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a4.png)

We also see there is a `robots.txt` that contains a `/secret/` directory!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a5.png)

Nothing in it...

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a7.png)

Some hint in the `index.php`.

We can also see that this site is using WordPress, we can use `wpscan` to enumerate this WordPress site!

**WPScan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a9.png)

Found 2 users: `admin` and `joe`.

**Brute forcing password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a10.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a11.png)

Found both users password:

- Username:joe
- Password:12345

- Username:admin
- Password:iubire

Armed with above information, we can now login into WordPress's admin page:

**Login to http://funbox.fritz.box/wp-login.php/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a12.png)

User `joe` is a **low privilege user** on WordPress, nothing useful.

# Initial Foothold

**Login to http://funbox.fritz.box/wp-login.php/ as admin:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a13.png)

User `admin` is a **high privilege user** on WordPress, which **could** gain an initial foothold on the target machine.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a15.png)

Looks like I wasn't able to upload a PHP reverse shell plugin.

How about modifying theme?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a16.png)

Nope. :(

Since the target machine has FTP port opened, let's try to use the above credentials to login into FTP!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a17.png)

Looks like we got `joe`'s FTP!

How about SSH??

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a18.png)

Looks like `joe` reuses his very weak password a LOT! XD

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a19.png)

Hmm... User `joe` is using a `rbash`, or restricted bash.

To escape `rbash`, we can use the `-t "bash --noprofile"` trick in `ssh`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a20.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a21.png)

# Privilege Escalation

## joe to funny

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a22.png)

It seems like there is a backup script in `funny`'s home directory, and it's running as a cronjob.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a23.png)

Unfortunately, the `.backup.sh` Bash script is **world-writable**! We can escalate our privilege to `funny`!

1. Append a Bash reverse shell to `.backup.sh`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a24.png)

2. Setup a `nc` listener and wait for the cronjob runs:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a25.png)

## funny to root

In the above image, we can see that user `funny` is inside the `lxd` group.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a26.png)

If the user is belong to `lxd` or `lxc` group, you can become **root**! (Similar to `docker` privilege escalation)

> A walkthrough can be found in [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation) article.

1. Build an `Alpine` image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a27.png)

2. Transfer the `Alpine` image to the target machine's **home** directory:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a28.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a29.png)

3. Import the `Alpine` image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a30.png)

**Since I'm not in a stable shell and those steps in below will cause some trouble, so I'll add my SSH public key to `funny`'s home directory:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a41.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a42.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a43.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a44.png)

4. Start and configure the `lxd` storage pool as default: (Make sure to not using IPv6, otherwise it'll throw you an error.)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a31.png)

5. Run the `Alpine` image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a32.png)

6. Mount the /root into the image:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a33.png)

7. Interact with the container:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a34.png)

I'm **root inside the container.**

8. Add a new user with root privilege in `/mnt/root/etc/passwd`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a35.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a36.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a37.png)

9. Exit the container and Switch User to the newly created user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a38.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a39.png)

Now I'm the **real `root`** in the target machine! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/FunBox/images/a40.png)

# Conclusion

What we've learned:

1. Web Crawler (`robots.txt`)
2. WordPress Enumeration
3. Exploiting WordPress
4. Password Reused in FTP and SSH
5. Privilege Escalation via World-Writable Bash Script That's Automatically Ran By Cronjob
6. Privilege Escalation via `lxd` Group, Running a Root Container and Modifying `/etc/passwd`