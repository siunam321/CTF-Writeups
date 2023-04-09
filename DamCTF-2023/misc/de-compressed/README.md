# de-compressed

## Overview

- 111 solves / 368 points

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

> Author: Perchik

As an elite cyber security expert, you've been tasked with uncovering the secrets hidden within a message intercepted from a notorious spy.

We suspect there may be more to this message than meets the eye. Can you use your skills in steganography to uncover whatever else might be hiding?

The fate of national security is in your hands.

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408193844.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:39:02(HKT)]
└> file message.zip 
message.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:39:04(HKT)]
└> unzip message.zip 
Archive:  message.zip
  inflating: README.txt
```

**After decompressed, it inflated a `README.txt` file:**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:39:06(HKT)]
└> cat README.txt    
Dear Sylvia,

I wanted to let you know that I have decided to resign from the team, effective immediately. I have been offered a better opportunity elsewhere and I believe it is in my best interest to pursue it.

Please do not be concerned about the success of the mission. I have confidence in the remaining members of the team, and I am sure they will be able to complete it without any problems.

I apologize for any inconvenience my departure may cause, and I hope you will understand my decision.

Sincerely,

Twilight                                                                                                   
```

Hmm... Seems nothing?

In the challenge's description, it said: "use your skills in steganography to uncover whatever else might be hiding".

**Let's use `strings` to list out all the strings inside the ZIP file:**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:39:08(HKT)]
└> strings message.zip 
[jVn6b
README.txt=
46X6i
(MT>
P|9c
secret.txt
<q9K
 ^o4
U#q@
}Zpdlt
[jVn6b
README.txtPK
```

Hmm?? `secret.txt`?

**`hexdump`:**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:40:35(HKT)]
└> hexdump -C message.zip 
00000000  50 4b 03 04 14 00 00 00  08 00 12 5b 6a 56 6e 36  |PK.........[jVn6|
00000010  62 bf 37 01 00 00 15 02  00 00 0a 00 00 00 52 45  |b.7...........RE|
00000020  41 44 4d 45 2e 74 78 74  3d 91 4d 8e c3 30 08 85  |ADME.txt=.M..0..|
00000030  f7 95 7a 07 0e 50 f5 14  b3 e9 6e a4 ce 05 88 43  |..z..P....n....C|
00000040  12 34 36 58 36 69 e4 39  fd 60 47 ed ce 3f ef f1  |.46X6i.9.`G..?..|
00000050  3e e0 8b b0 c0 b3 c5 17  e3 ed 7a b9 5e 1e 70 a0  |>.........z.^.p.|
00000060  18 cd 60 0a 91 0c 9a ee  f0 2b 7a 80 6d 68 f0 80  |..`......+z.mh..|
00000070  0d 5f 04 33 05 9e 4f 4d  a1 ca ab c0 52 34 b9 84  |._.3..OM....R4..|
00000080  c0 08 d3 0d 68 59 28 18  bb 94 53 a2 99 d1 28 b6  |....hY(...S...(.|
00000090  fb db 3e 11 09 a8 4b 8a  d7 40 bf 9a 51 01 cd 59  |..>...K..@..Q..Y|
000000a0  8b ed c2 d6 80 62 a5 63  f3 7f 40 99 dd 36 51 64  |.....b.c..@..6Qd|
000000b0  ea d5 0c b8 02 0b a4 e6  6f d5 6f ce 5a fa c1 51  |........o.o.Z..Q|
000000c0  f2 5e ea de 35 f7 de c8  77 24 ac 8e aa 20 6a 2e  |.^..5...w$... j.|
000000d0  86 a0 12 a8 48 8f 9c 74  b7 41 5b f7 10 a8 56 87  |....H..t.A[...V.|
000000e0  19 d7 c4 b5 b2 ca 07 d4  2d 8b 37 ea be 9e d9 15  |........-.7.....|
000000f0  85 12 b2 b0 ac 90 28 4d  54 3e d6 b3 ef 93 16 93  |......(MT>......|
00000100  17 76 76 7f 6f 70 70 8c  3d 1e a7 48 9d 32 68 ca  |.vv.opp.=..H.2h.|
00000110  3e d8 d1 cb c1 b6 75 14  94 06 b9 a8 2b 52 bd 9f  |>.....u.....+R..|
00000120  5b c0 ac 51 57 fe 23 58  b4 0c 01 8b e3 bc 48 78  |[..QW.#X......Hx|
00000130  f0 f8 00 66 ca e8 03 f3  a0 84 0d 02 ee 95 de 04  |...f............|
00000140  9b 66 1a ab 1b e9 bb cc  4e 6a fd 6b d8 02 8f 2e  |.f......Nj.k....|
00000150  7b d0 93 fb 50 7c 39 63  f9 3f 2e e7 75 b3 7f 50  |{...P|9c.?..u..P|
00000160  4b 03 04 14 00 00 00 08  00 12 5b 6a 56 1a 3d 07  |K.........[jV.=.|
00000170  10 97 01 00 00 38 08 00  00 0a 00 00 00 73 65 63  |.....8.......sec|
00000180  72 65 74 2e 74 78 74 95  55 4b 72 83 30 0c dd 73  |ret.txt.UKr.0..s|
00000190  0a ed b2 c9 45 38 86 8b  d5 e0 86 98 0c 36 74 b2  |....E8.......6t.|
000001a0  eb 01 ec 9b 70 83 2e 7a  97 5c 20 57 a8 1c 08 69  |....p..z.\ W...i|
000001b0  b1 94 49 66 18 0f 83 ac  f7 f4 f4 e3 fc 15 fe 3c  |..If...........<|
000001c0  71 39 4b c8 2c e3 f5 89  1d 2a bd b2 5d be 7f e8  |q9K.,....*..]...|
000001d0  85 4e 60 0d e4 f7 86 fe  13 d1 b2 a0 f1 c6 bb fe  |.N`.............|
000001e0  4e de be 46 ce 14 72 97  85 0a 1a 63 d1 6d e1 70  |N..F..r....c.m.p|
000001f0  92 d8 c2 60 9c 69 ed e6  bf 39 dc 90 83 63 65 c4  |...`.i...9...ce.|
00000200  ec fa 92 93 20 10 c5 aa  41 d5 49 34 a0 ac ce 1c  |.... ...A.I4....|
00000210  e3 2c 62 4f d9 12 6a 13  8b 92 b3 a4 17 10 5c 82  |.,bO..j.......\.|
00000220  43 64 6c 93 2e ca 31 d4  46 6b 99 70 e5 9a 02 9c  |Cdl...1.Fk.p....|
00000230  d2 7d 40 65 8d dd 51 b6  25 91 09 dc 77 bd af 1d  |.}@e..Q.%...w...|
00000240  1b db 78 e5 57 5e 72 97  8a cf 94 76 12 a3 3a 84  |..x.W^r....v..:.|
00000250  de 92 5c 5b 48 98 25 e8  ac f8 f7 16 f6 af 16 3f  |..\[H.%........?|
00000260  0a a1 84 8f de 79 c9 f6  bc 5e ba 9f b9 2c 38 a3  |.....y...^...,8.|
00000270  84 03 5e ed 51 54 e2 eb  54 34 69 c2 83 f2 e2 9c  |..^.QT..T4i.....|
00000280  be ab 0a 61 50 4d 8f db  27 25 2c a4 22 66 5e 7f  |...aPM..'%,."f^.|
00000290  71 c8 97 32 0b 0d 39 6e  1c d8 d6 73 81 24 6d b4  |q..2..9n...s.$m.|
000002a0  13 84 20 5e 6f 34 e7 4f  0d 16 25 9b e3 bc c8 f7  |.. ^o4.O..%.....|
000002b0  34 68 b3 5b d1 dd 2e 8b  62 81 75 a0 53 23 1e d3  |4h.[....b.u.S#..|
000002c0  16 81 92 7a be 6a 07 ec  32 88 c8 f6 cf 12 cd 16  |...z.j..2.......|
000002d0  d2 80 0a 01 05 61 2b cc  98 7c ff b0 cd 3a 0f 3a  |.....a+..|...:.:|
000002e0  fd 3a 5c df a1 63 93 fd  08 91 6d 91 28 8d 06 db  |.:\..c....m.(...|
000002f0  8d 0f c7 38 bc 24 67 26  a6 55 23 71 40 d5 1e 8e  |...8.$g&.U#q@...|
00000300  a6 c1 7c bf cf 7d 5a 70  64 6c 74 0f 0a 28 a9 0c  |..|..}Zpdlt..(..|
00000310  17 71 61 84 b3 10 31 87  3f b2 df 27 97 5f 50 4b  |.qa...1.?..'._PK|
00000320  01 02 14 00 14 00 00 00  08 00 12 5b 6a 56 6e 36  |...........[jVn6|
00000330  62 bf 37 01 00 00 15 02  00 00 0a 00 00 00 00 00  |b.7.............|
00000340  00 00 00 00 00 00 00 00  00 00 00 00 52 45 41 44  |............READ|
00000350  4d 45 2e 74 78 74 50 4b  05 06 00 00 00 00 01 00  |ME.txtPK........|
00000360  01 00 38 00 00 00 1e 03  00 00 00 00              |..8.........|
0000036c
```

Hmm... Looks like there are 2 PK file signature (`50 4b 03 04`).

**Also [this blog about ZIP steganography](https://resources.infosecinstitute.com/topic/steganography-what-your-eyes-dont-see/) helped me a lot:**

|     |     |
| --- | --- |
| **Signature** | **The signature of the local file header  is always 0x504b0304** |
| **Version** | The PKZip version needed for archive extraction |
| **Flags** | Bit 00: encrypted fileBit 01: compression optionBit 02: compression option<br><br>Bit 03: data descriptor<br><br>Bit 04: enhanced deflation<br><br>Bit 05: compressed patched data<br><br>Bit 06: strong encryption<br><br>Bit 07-10: unused<br><br>Bit 11: language encoding<br><br>Bit 12: reserved<br><br>Bit 13: mask header values<br><br>Bit 14-15: reserved |
| **Compression method** | 00: no compression01: shrunk02: reduced with compression factor 1<br><br>03: reduced with compression factor 2<br><br>04: reduced with compression factor 3<br><br>05: reduced with compression factor 4<br><br>06: imploded<br><br>07: reserved<br><br>08: deflated<br><br>09: enhanced deflated<br><br>10: PKWare DCL imploded<br><br>11: reserved<br><br>12: compressed using BZIP2<br><br>13: reserved<br><br>14: LZMA<br><br>15-17: reserved<br><br>18: compressed using IBM TERSE<br><br>19: IBM LZ77 z<br><br>98: PPMd version I, Rev 1 |
| **File modification time** | Bits 00-04: seconds divided by 2Bits 05-10: minuteBits 11-15: hour |
| **File modification date** | Bits 00-04: day  <br>Bits 05-08: month  <br>Bits 09-15: years from 1980 |
| **Crc-32 checksum** | CRC-32 algorithm with ‘magic number’ 0xdebb20e3 (little endian) |
| **Compressed size** | If archive is in ZIP64 format, this filed is 0xffffffff and the length is stored in the extra field |
| **Uncompressed size** | If archive is in ZIP64 format, this filed is 0xffffffff and the length is stored in the extra field |
| **File name length** | The length of the file name field below |
| **Extra field length** | The length of the extra field below |
| **File name** | The name of the file including an optional relative path. All slashes in the path should be forward slashes ‘/’. |
| **Extra field** | Used to store additional information. The field consists of a sequence of header and data pairs, where the header has a 2 byte identifier and a 2 byte data size field. |

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408194540.png)

**Therefore, there are 2 ZIP file in `message.zip`:**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:40:35(HKT)]
└> hexdump -C message.zip
00000000  50 4b 03 04 14 00 00 00  08 00 12 5b 6a 56 6e 36  |PK.........[jVn6|
00000010  62 bf 37 01 00 00 15 02  00 00 0a 00 00 00 52 45  |b.7...........RE|
00000020  41 44 4d 45 2e 74 78 74  3d 91 4d 8e c3 30 08 85  |ADME.txt=.M..0..|
[...]
00000150  7b d0 93 fb 50 7c 39 63  f9 3f 2e e7 75 b3 7f 50  |{...P|9c.?..u..P|
00000160  4b 03 04 14 00 00 00 08  00 12 5b 6a 56 1a 3d 07  |K.........[jV.=.|
00000170  10 97 01 00 00 38 08 00  00 0a 00 00 00 73 65 63  |.....8.......sec|
00000180  72 65 74 2e 74 78 74 95  55 4b 72 83 30 0c dd 73  |ret.txt.UKr.0..s|
[...]
```

**We can use `dd` to retrieve the second ZIP file:**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:46:41(HKT)]
└> dd if=message.zip bs=1 skip=351 of=secret.zip 
525+0 records in
525+0 records out
525 bytes copied, 0.00145336 s, 361 kB/s
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:46:44(HKT)]
└> file secret.zip 
secret.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

**However, when we `unzip` it:**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|19:46:48(HKT)]
└> unzip secret.zip 
Archive:  secret.zip
error [secret.zip]:  missing 351 bytes in zipfile
  (attempting to process anyway)
error: invalid zip file with overlapped components (possible zip bomb)
```

Hmm... "missing 351 bytes in zipfile"?

**After some googling, I found [this blog](https://osxdaily.com/2019/05/12/how-to-fix-unzip-error-end-of-central-directory-signature-not-found/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408201200.png)

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|20:09:44(HKT)]
└> zip -FF secret.zip --out RepairedZip.zip 
Fix archive (-FF) - salvage what can
 Found end record (EOCDR) - says expect single disk archive
Scanning for entries...
 copying: secret.txt  (407 bytes)
Central Directory found...
no local entry: README.txt
EOCDR found ( 1    503)...
```

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|20:10:25(HKT)]
└> unzip RepairedZip.zip 
Archive:  RepairedZip.zip
  inflating: secret.txt
```

Oh! We inflated the `secret.txt`!

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|20:10:38(HKT)]
└> cat secret.txt 
I ‌‌‌‌‍‬‬‍read‌‌‌‌‍﻿‌﻿ ‌‌‌‌‍﻿‌‬between ‌‌‌‌‍‬‍‍‌‌the‌‌‌‌‍‬‌‍‌‌ lines, my ‌‌‌‌‍‬‍‌vision'‌‌‌‌‌‬‌‌s ‌‌‌‌‍﻿‍‌‌‌clear‌‌‌‌‌‬‌‌ and‌‌‌‌‍‍‌‬ keen‌‌‌‌‍‌‍‍
I‌‌‌‌‍‌‌‍ ‌‌‌‌‍‌‍‌see ‌‌‌‌‍‌﻿‍the hidden‌‌‌‌‍‌‍‍ ‌‌‌‌‌‬﻿‌meanings, ‌‌‌‌‌‬‌‌the truths ‌‌‌‌‍‌‬‍that‌‌‌‌‌‬‌‌‌‌ ‌‌‌‌‍‬﻿‍are unseen
I don'‌‌‌‌‍﻿‌﻿t ‌‌‌‌‍﻿‍‌‌‌just‌‌‌‌‍‬﻿‌‌‌ take ‌‌‌‌‍﻿‍‌things ‌‌‌‌‍‬‬‌at ‌‌‌‌‍‬‍‍face value,‌‌‌‌‌‬‌‌‌‌ ‌‌‌‌‍‬‍‍that‌‌‌‌‍‬‌‍‌‌'s not‌‌‌‌‌‌‬‬ my‌‌‌‌‍‬‍‌‌‌ ‌‌‌‌‍‬﻿‍style
I ‌‌‌‌‍﻿‬﻿‌‌dig‌‌‌‌‌﻿‌‍‌‌ ‌‌‌‌‌﻿‌﻿deep and I uncover‌‌‌‌‍‍﻿﻿‌‌, the ‌‌‌‌‌﻿‌‌hidden‌‌‌‌‍‍﻿﻿ ‌‌‌‌‍‬‬﻿‌‌treasures‌‌‌‌‍‬‌﻿ ‌‌‌‌‍‬‬﻿that‌‌‌‌‍‍﻿﻿‌‌ ‌‌‌‌‍‬‬﻿‌‌are‌‌‌‌‌﻿‍‌ compiled‌‌‌‌‍‬﻿‬
```

Umm... What?

```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|20:18:30(HKT)]
└> ls -lah secret.txt 
-rw-r--r-- 1 siunam nam 2.1K Mar 10 11:24 secret.txt
```

It's size is 2.1 KB, it must be hiding something weird.

**Let's use `file` to find it's file format:**
```
┌[siunam♥earth]-(~/ctf/DamCTF-2023/misc/de-compressed)-[2023.04.08|20:14:23(HKT)]
└> file secret.txt 
secret.txt: CSV text
```

CSV?

I tried to open it via Microsoft Excel, but nothing weird...

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408224427.png)

Hmm... What can I do with that...

Ahh!! Wait, I remember a room in TryHackMe!

> [The Impossible Challenge](https://tryhackme.com/room/theimpossiblechallenge), writeup: [https://siunam321.github.io/ctf/tryhackme/The-Impossible-Challenge/](https://siunam321.github.io/ctf/tryhackme/The-Impossible-Challenge/)

Does that `secret.txt` using the ***unicode steganography***??

If so, we can use [an online tool to decode those unicodes](https://330k.github.io/misc_tools/unicode_steganography.html)!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408224621.png)

Nice!!! We found the flag!

- **Flag: `dam{t1m3_t0_kick_b4ck_4nd_r3l4x}`**

## Conclusion

What we've learned:

1. Extract Hidden File In PKZip & Unicode Steganography With Zero-Width Characters