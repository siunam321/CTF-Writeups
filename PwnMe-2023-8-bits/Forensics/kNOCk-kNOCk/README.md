# kNOCk kNOCk

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 198 solves / 50 points
- Difficulty: Intro
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

> Author: Braguette#0169

We have to monitor our network every day to make sure our admins don't help players get out of the game.  
We are sending you a suspicious capture. Do your job !

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506134311.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/Forensics/kNOCk-kNOCk/Intro.pcapng):**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Forensics/kNOCk-kNOCk)-[2023.05.06|13:46:34(HKT)]
└> file Intro.pcapng 
Intro.pcapng: pcapng capture file - version 1.0
```

**It's a pcap (Packet capture) file! Let's open it via WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Forensics/kNOCk-kNOCk)-[2023.05.06|13:46:40(HKT)]
└> wireshark Intro.pcapng
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506134734.png)

We can see that there are 15144 packets.

**In "Statistics" -> "Protocol Hierarchy", we can see different protocols has been captured in this pcap file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506134933.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506134947.png)

In TCP protocol, there are 6 HTTP packets, and the "Media Type" is interesting to us.

**We can export that object:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506135623.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506135640.png)

```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Forensics/kNOCk-kNOCk)-[2023.05.06|13:52:11(HKT)]
└> file MalPack.deb             
MalPack.deb: Debian binary package (format 2.0), with control.tar.xz, data compression xz
```

As you can see, the `MalPack.deb` is a Debian package.

Hmm... That looks very, very sussy!

**Let's view it's contents without extracting it:**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Forensics/kNOCk-kNOCk)-[2023.05.06|13:57:06(HKT)]
└> dpkg -c MalPack.deb  
drwxrwxr-x remnux/remnux     0 2023-04-13 18:50 ./
drwxrwxr-x remnux/remnux     0 2023-04-13 18:50 ./usr/
drwxrwxr-x remnux/remnux     0 2023-04-13 18:50 ./usr/local/
drwxrwxr-x remnux/remnux     0 2023-04-13 21:16 ./usr/local/bin/
-rwxrwxr-x remnux/remnux    46 2023-04-13 21:16 ./usr/local/bin/simplescript.sh
```

**`simplescript.sh`... Let's take a look at that script by extracting the package!**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Forensics/kNOCk-kNOCk)-[2023.05.06|14:00:02(HKT)]
└> dpkg-deb -xv MalPack.deb .
./
./usr/
./usr/local/
./usr/local/bin/
./usr/local/bin/simplescript.sh
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Forensics/kNOCk-kNOCk)-[2023.05.06|14:00:24(HKT)]
└> cat usr/local/bin/simplescript.sh 
#!/bin/bash

echo "PWNME{P4ck4g3_1s_g00d_ID}"
```

Bam! We got the flag!

- **Flag: `PWNME{P4ck4g3_1s_g00d_ID}`**

## Conclusion

What we've learned:

1. Exporting HTTP Object & Inspecting Debian Package