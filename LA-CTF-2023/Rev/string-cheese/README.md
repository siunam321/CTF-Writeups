# string-cheese

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- 644 solves / 112 points

## Background

> Author: aplet123

I'm something of a cheese connoisseur myself. If you can guess my favorite flavor of string cheese, I'll even give you a flag. Of course, since I'm lazy and socially inept, I slapped together a program to do the verification for me.

Connect to my service at `nc lac.tf 31131`

Note: The attached binary is the exact same as the one executing on the remote server.

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211153549.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/raw/main/LA-CTF-2023/Rev/caterpillar/string_cheese):**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Rev/string-cheese)-[2023.02.11|15:36:34(HKT)]
└> file string_cheese 
string_cheese: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=85f5294fa950449028c1ef7655304e4e873172d2, for GNU/Linux 3.2.0, not stripped
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Rev/string-cheese)-[2023.02.11|15:36:35(HKT)]
└> chmod +x string_cheese
```

It's a 64-bit ELF executable, and it's not stripped.

**Let's try to run it:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Rev/string-cheese)-[2023.02.11|15:36:37(HKT)]
└> ./string_cheese             
What's my favorite flavor of string cheese? idk
Hmm... I don't think that's quite it. Better luck next time!
```

So, we need to provide the correct favorite flavor of string cheese.

**Now, let's use `strings` to list out all the strings inside that binary:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Rev/string-cheese)-[2023.02.11|15:38:22(HKT)]
└> strings string_cheese 
[...]
flag.txt
Cannot read flag.txt.
What's my favorite flavor of string cheese? 
blueberry
...how did you know? That isn't even a real flavor...
Well I guess I should give you the flag now...
Hmm... I don't think that's quite it. Better luck next time!
[...]
```

Found it!

- Favorite flavor of string cheese: `blueberry`

**Or, you can use `ltrace` to display calls that are made to shared libraries:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Rev/string-cheese)-[2023.02.11|15:38:23(HKT)]
└> ltrace ./string_cheese
printf("What's my favorite flavor of str"...)                    = 44
fflush(0x7f4fcbc7b760What's my favorite flavor of string cheese? )                                           = 0
fgets(test
"test\n", 256, 0x7f4fcbc7aa80)                             = 0x7ffc4d00c500
strcspn("test\n", "\n")                                          = 4
strcmp("test", "blueberry")                                      = 18
puts("Hmm... I don't think that's quit"...Hmm... I don't think that's quite it. Better luck next time!
)                      = 61
+++ exited (status 0) +++
```

**Finally, `nc` to the challenge port, and read the flag:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Rev/string-cheese)-[2023.02.11|15:39:42(HKT)]
└> nc lac.tf 31131
What's my favorite flavor of string cheese? blueberry
...how did you know? That isn't even a real flavor...
Well I guess I should give you the flag now...
lactf{d0n7_m4k3_fun_0f_my_t4st3_1n_ch33s3}
```

- **Flag: `lactf{d0n7_m4k3_fun_0f_my_t4st3_1n_ch33s3}`**

# Conclusion

What we've learned:

1. Using `strings` & `ltrace` To Extract Hidden String