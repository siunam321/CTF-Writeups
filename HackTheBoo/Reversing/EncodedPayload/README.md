# EncodedPayload

## Background

> Buried in your basement you've discovered an ancient tome. The pages are full of what look like warnings, but luckily you can't read the language! What will happen if you invoke the ancient spells here?

> Difficulty: Easy

- Overall difficulty for me: Easy

**In this challenge we can [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/EncodedPayload/rev_encodedpayload.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/EncodedPayload/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/EncodedPayload]
└─# unzip rev_encodedpayload.zip 
Archive:  rev_encodedpayload.zip
  inflating: encodedpayload

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/EncodedPayload]
└─# file encodedpayload                                       
encodedpayload: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, no section header

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/EncodedPayload]
└─# chmod +x encodedpayload
```

**It's a ELF 32-bit LSB executable!**

## Find the flag

**Let's try some low hanging fruits, like `strings`:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/EncodedPayload]
└─# strings encodedpayload  
[SYIIIIIIIIICCCCCCC7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI01iKzWHcScW3F3Pj6bOyHax0cVZmK0MCpYh0WO8Mk0PIbYYibHsOS0wp7qqxUReP5UfYmYhaLpCVV0PQF3LsfcOyIqZmMPF2ax0ndo1cE8e8fOvORBCYMYHcF2PSOyHaNPFkJmopRJ4KChmI3bU6e8Tme3ni8gCXFO2S1xC0U8VOsR59RNK9KSaByx4ZS0EPUPauPcphrOq0bh0Tg2cK2p0LSJso1ct43B51e31uSormFSGCTsSMgpV7rsLI9qJmmPAA
```

**How about in `hexdump`?**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/EncodedPayload]
└─# hexdump -C encodedpayload 
00000000  7f 45 4c 46 01 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 03 00 01 00 00 00  54 80 04 08 34 00 00 00  |........T...4...|
00000020  00 00 00 00 00 00 00 00  34 00 20 00 01 00 00 00  |........4. .....|
00000030  00 00 00 00 01 00 00 00  00 00 00 00 00 80 04 08  |................|
00000040  00 80 04 08 93 01 00 00  d2 02 00 00 07 00 00 00  |................|
00000050  00 10 00 00 d9 e8 d9 74  24 f4 5b 53 59 49 49 49  |.......t$.[SYIII|
00000060  49 49 49 49 49 49 43 43  43 43 43 43 43 37 51 5a  |IIIIIICCCCCCC7QZ|
00000070  6a 41 58 50 30 41 30 41  6b 41 41 51 32 41 42 32  |jAXP0A0AkAAQ2AB2|
00000080  42 42 30 42 42 41 42 58  50 38 41 42 75 4a 49 30  |BB0BBABXP8ABuJI0|
00000090  31 69 4b 7a 57 48 63 53  63 57 33 46 33 50 6a 36  |1iKzWHcScW3F3Pj6|
000000a0  62 4f 79 48 61 78 30 63  56 5a 6d 4b 30 4d 43 70  |bOyHax0cVZmK0MCp|
000000b0  59 68 30 57 4f 38 4d 6b  30 50 49 62 59 59 69 62  |Yh0WO8Mk0PIbYYib|
000000c0  48 73 4f 53 30 77 70 37  71 71 78 55 52 65 50 35  |HsOS0wp7qqxUReP5|
000000d0  55 66 59 6d 59 68 61 4c  70 43 56 56 30 50 51 46  |UfYmYhaLpCVV0PQF|
000000e0  33 4c 73 66 63 4f 79 49  71 5a 6d 4d 50 46 32 61  |3LsfcOyIqZmMPF2a|
000000f0  78 30 6e 64 6f 31 63 45  38 65 38 66 4f 76 4f 52  |x0ndo1cE8e8fOvOR|
00000100  42 43 59 4d 59 48 63 46  32 50 53 4f 79 48 61 4e  |BCYMYHcF2PSOyHaN|
00000110  50 46 6b 4a 6d 6f 70 52  4a 34 4b 43 68 6d 49 33  |PFkJmopRJ4KChmI3|
00000120  62 55 36 65 38 54 6d 65  33 6e 69 38 67 43 58 46  |bU6e8Tme3ni8gCXF|
00000130  4f 32 53 31 78 43 30 55  38 56 4f 73 52 35 39 52  |O2S1xC0U8VOsR59R|
00000140  4e 4b 39 4b 53 61 42 79  78 34 5a 53 30 45 50 55  |NK9KSaByx4ZS0EPU|
00000150  50 61 75 50 63 70 68 72  4f 71 30 62 68 30 54 67  |PauPcphrOq0bh0Tg|
00000160  32 63 4b 32 70 30 4c 53  4a 73 6f 31 63 74 34 33  |2cK2p0LSJso1ct43|
00000170  42 35 31 65 33 31 75 53  6f 72 6d 46 53 47 43 54  |B51e31uSormFSGCT|
00000180  73 53 4d 67 70 56 37 72  73 4c 49 39 71 4a 6d 6d  |sSMgpV7rsLI9qJmm|
00000190  50 41 41                                          |PAA|
00000193
```

Hmm... Some weird strings...

**`ltrace`?**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/EncodedPayload]
└─# ltrace ./encodedpayload 
Couldn't find .dynsym or .dynstr in "/proc/210534/exe"
```

**`strace`???**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/EncodedPayload]
└─# strace ./encodedpayload 
execve("./encodedpayload", ["./encodedpayload"], 0x7ffedea434c0 /* 57 vars */) = 0
[ Process PID=210344 runs in 32 bit mode. ]
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
dup2(3, 2)                              = 2
dup2(3, 1)                              = 1
dup2(3, 0)                              = 0
connect(3, {sa_family=AF_INET, sin_port=htons(1337), sin_addr=inet_addr("127.0.0.1")}, 102) = -1 ECONNREFUSED (Connection refused)
syscall_0xffffffffffffff0b(0xfff6b838, 0xfff6b830, 0, 0, 0, 0) = -1 ENOSYS (Function not implemented)
execve("/bin/sh", ["/bin/sh", "-c", "echo HTB{PLz_strace_M333}"], NULL) = 0
[...]
```

> Note: `strace` is used to monitor system calls, like `cat`, `ls`, `whoami` commands.

Ohh!! We found the flag! Lol

**flag:**
```
HTB{PLz_strace_M333}
```

# Conclusion

What we've learned:

1. Using `strace` to Monitor System Calls