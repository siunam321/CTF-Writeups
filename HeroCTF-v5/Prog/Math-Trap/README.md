# Math Trap

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 279 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

In this challenge, you have to make a few simple calculations for me, but pretty quickely. Maybe the pwntools python library will help you ?  
  
PS: control your inputs.  
  
Host : **nc static-01.heroctf.fr 8000**  
Format : **Hero{flag}**  
Author : **Log_s**

## Find the flag

**In this challenge, we can `nc` into the instance machine:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Prog/Math-Trap)-[2023.05.13|16:49:53(HKT)]
└> nc static-01.heroctf.fr 8000
Can you calculate these for me ?

70 // 98
=0
Too slow
```

In here, we need to calculate some math equations.

**To automate that, we can write a Python script:**
```py
#!/usr/bin/env python3
from pwn import *

def solveTheFirstEquation(r):
    # Can you calculate these for me ?\n\n
    r.recvuntil(b'?\n\n')
    solveEquation(r)
    r.recvuntil(b'\n')

def solveEquation(r):
    # 78 * 72
    equation = r.recvline().decode()
    answer = str(eval(equation)).encode('utf-8')
    r.sendlineafter(b'=', answer)

if __name__ == '__main__':
    context.log_level = 'debug'
    HOST = 'static-01.heroctf.fr'
    PORT = 8000
    r = remote(HOST, PORT)

    for i in range(500):
        if i == 0:
            solveTheFirstEquation(r)
        else:
            solveEquation(r)
            print(r.recvline())
```

```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Prog/Math-Trap)-[2023.05.13|17:21:56(HKT)]
└> python3 solve.py 
[+] Opening connection to static-01.heroctf.fr on port 8000: Done
[DEBUG] Received 0x2b bytes:
    b'Can you calculate these for me ?\n'
    b'\n'
    b'51 - 53\n'
    b'='
[DEBUG] Sent 0x3 bytes:
    b'-2\n'
[DEBUG] Received 0xb bytes:
    b'\n'
    b'44 - 100\n'
    b'='
[DEBUG] Sent 0x4 bytes:
    b'-56\n'
[DEBUG] Received 0x9 bytes:
    b'\n'
    b'8 * 58\n'
    b'='
b'\n'
[DEBUG] Sent 0x4 bytes:
    b'464\n'
[DEBUG] Received 0xa bytes:
    b'\n'
    b'36 - 29\n'
    b'='
b'\n'
[DEBUG] Sent 0x2 bytes:
    b'7\n'
[...]
```

However, when I saw the flag, it shuts down my VM :(

**Then, I fired up OBS to record and catch the flag:**

https://github.com/siunam321/CTF-Writeups/assets/104430134/54acf4a3-de31-4f1f-b550-907a51129b05

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513172537.png)

Nice troll in the `shutdown` command lmao :D (This is because the evil equation was parsed to `eval()`)

- **Flag: `Hero{E4sy_ch4ll3ng3_bu7_tr4pp3d}`**

## Conclusion

What we've learned:

1. Using Python To Solve Math Problems
