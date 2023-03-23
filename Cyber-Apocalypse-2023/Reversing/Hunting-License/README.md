# Hunting License

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

STOP! Adventurer, have you got an up to date relic hunting license? If you don't, you'll need to take the exam again before you'll be allowed passage into the spacelanes!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319180937.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Reversing/Hunting-License/rev_hunting_license.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License)-[2023.03.19|18:10:17(HKT)]
└> file rev_hunting_license.zip 
rev_hunting_license.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License)-[2023.03.19|18:10:18(HKT)]
└> unzip rev_hunting_license.zip  
Archive:  rev_hunting_license.zip
   creating: rev_hunting_license/
  inflating: rev_hunting_license/license
```

**We can also `nc` to the instance machine:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License)-[2023.03.19|18:07:28(HKT)]
└> nc 46.101.95.78 30877
What is the file format of the executable?
> 
```

```
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/rev_hunting_license)-[2023.03.19|18:10:27(HKT)]
└> file license                
license: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5be88c3ed329c1570ab807b55c1875d429a581a7, for GNU/Linux 3.2.0, not stripped
```

It's an ELF 64-bit executable.

```
> ELF
[+] Correct!

What is the CPU architecture of the executable?
>
```

64-bit.

```
> 64-bit
[+] Correct!

What library is used to read lines for user answers? (`ldd` may help)
> 
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/rev_hunting_license)-[2023.03.19|18:10:58(HKT)]
└> ldd license
	linux-vdso.so.1 (0x00007ffcb24e7000)
	libreadline.so.8 => /lib/x86_64-linux-gnu/libreadline.so.8 (0x00007f92c4ae4000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f92c4903000)
	libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007f92c48d1000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f92c4b5d000)
```

`libreadline.so.8`.

```
> libreadline.so.8
[+] Correct!

What is the address of the `main` function?
> 
```

**We can use `gdb` to do that:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/rev_hunting_license)-[2023.03.19|18:12:15(HKT)]
└> gdb license
[...]
gef➤  p main
$1 = {<text variable, no debug info>} 0x401172 <main>
```

> Note: I'm using `gef` gdb plugin.

`0x401172`.

```
> 0x401172
[+] Correct!

How many calls to `puts` are there in `main`? (using a decompiler may help)
> 
```

**Again, use `gdb` to disassemble the `main()` function:**
```shell
gef➤  disassemble main 
Dump of assembler code for function main:
   0x0000000000401172 <+0>:	push   rbp
   0x0000000000401173 <+1>:	mov    rbp,rsp
   0x0000000000401176 <+4>:	sub    rsp,0x10
   0x000000000040117a <+8>:	mov    edi,0x402008
   0x000000000040117f <+13>:	call   0x401040 <puts@plt>
   0x0000000000401184 <+18>:	mov    edi,0x402030
   0x0000000000401189 <+23>:	call   0x401040 <puts@plt>
   0x000000000040118e <+28>:	mov    edi,0x402088
   0x0000000000401193 <+33>:	call   0x401040 <puts@plt>
   0x0000000000401198 <+38>:	call   0x401070 <getchar@plt>
   0x000000000040119d <+43>:	mov    BYTE PTR [rbp-0x1],al
   0x00000000004011a0 <+46>:	cmp    BYTE PTR [rbp-0x1],0x79
   0x00000000004011a4 <+50>:	je     0x4011c6 <main+84>
   0x00000000004011a6 <+52>:	cmp    BYTE PTR [rbp-0x1],0x59
   0x00000000004011aa <+56>:	je     0x4011c6 <main+84>
   0x00000000004011ac <+58>:	cmp    BYTE PTR [rbp-0x1],0xa
   0x00000000004011b0 <+62>:	je     0x4011c6 <main+84>
   0x00000000004011b2 <+64>:	mov    edi,0x4020dd
   0x00000000004011b7 <+69>:	call   0x401040 <puts@plt>
   0x00000000004011bc <+74>:	mov    edi,0xffffffff
   0x00000000004011c1 <+79>:	call   0x401080 <exit@plt>
   0x00000000004011c6 <+84>:	mov    eax,0x0
   0x00000000004011cb <+89>:	call   0x40128a <exam>
   0x00000000004011d0 <+94>:	mov    edi,0x4020f0
   0x00000000004011d5 <+99>:	call   0x401040 <puts@plt>
   0x00000000004011da <+104>:	mov    eax,0x0
   0x00000000004011df <+109>:	leave
   0x00000000004011e0 <+110>:	ret
End of assembler dump.
```

5.

```
> 5
[+] Correct!

What is the first password?
> 
```

**Now, we can run the `license` executable:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/rev_hunting_license)-[2023.03.19|18:13:39(HKT)]
└> ./license 
So, you want to be a relic hunter?
First, you're going to need your license, and for that you need to pass the exam.
It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
y
Okay, first, a warmup - what's the first password? This one's not even hidden: 
```

**In here, we can use a command called `strings` to list out all the strings in this executable:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/rev_hunting_license)-[2023.03.19|18:14:25(HKT)]
└> strings license
[...]
So, you want to be a relic hunter?
First, you're going to need your license, and for that you need to pass the exam.
It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
Not many are...
Well done hunter - consider yourself certified!
Okay, first, a warmup - what's the first password? This one's not even hidden: 
PasswordNumeroUno
Not even close!
Getting harder - what's the second password? 
You've got it all backwards...
Your final test - give me the third, and most protected, password: 
Failed at the final hurdle!
;*3$"
0wTdr0wss4P
G{zawR}wUz}r
[...]
```

**In here, we see there's some interesting strings:**
```
PasswordNumeroUno
0wTdr0wss4P
G{zawR}wUz}r
```

**The first one looks like the first password:**
```shell
Okay, first, a warmup - what's the first password? This one's not even hidden: PasswordNumeroUno
Getting harder - what's the second password? 
```

```
> PasswordNumeroUno
[+] Correct!

What is the reversed form of the second password?
> 
```

**In the `strings` output, we see `0wTdr0wss4P`, which looks like reversed:**
```
> 0wTdr0wss4P
[+] Correct!

What is the real second password?
> 
```

**To reverse it back, we can use a command called `rev`:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/rev_hunting_license)-[2023.03.19|18:14:27(HKT)]
└> echo '0wTdr0wss4P' | rev
P4ssw0rdTw0
```

```
Getting harder - what's the second password? P4ssw0rdTw0
Your final test - give me the third, and most protected, password: 
```

```
> P4ssw0rdTw0
[+] Correct!

What is the XOR key used to encode the third password?
> 
```

Now, we found the third on in `strings` output: `G{zawR}wUz}r`.

**In here, we can fireup Ghidra to reverse engineer it:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/rev_hunting_license)-[2023.03.19|18:17:34(HKT)]
└> ghidra
```

**In the `exam()` function we see this:**
```c
local_38 = 0;
local_30 = 0;
local_28 = 0;
xor(&local_38,t2,0x11,0x13);
local_10 = (char *)readline("Your final test - give me the third, and most protected, password: ")
;
iVar1 = strcmp(local_10,(char *)&local_38);
if (iVar1 != 0) {
puts("Failed at the final hurdle!");
                /* WARNING: Subroutine does not return */
exit(-1);
}
```

As you can see, **the `local_38` is being compared (`strcmp()`) with `local_10`**, which is our input. That being said, `local_38` is the correct password.

It also run a function called `xor()`.

**Function `xor()`:**
```c
void xor(long param_1,long param_2,ulong param_3,byte param_4)

{
  int local_c;
  
  for (local_c = 0; (ulong)(long)local_c < param_3; local_c = local_c + 1) {
    *(byte *)(param_1 + local_c) = *(byte *)(param_2 + local_c) ^ param_4;
  }
  return;
}
```

**In here, we see how the third password is being XOR'ed:**
```c
for (c=0;i<parameter_3;c++) {
    local_38[c] = (parameter_2 + c) ^ parameter_4;
}
```

With that said, the XOR key is `0x13` (19 in decimal).

```
> 19 
[+] Correct!

What is the third password?
> 
```

**To XOR it back, we can write a Python script:**
```py
#!/usr/bin/env python3

def main():
    afterXOR = 'G{zawR}wUz}r'

    for c in range(0x11):
        print(chr(ord(afterXOR[c]) ^ 0x13), end='')

if __name__ == '__main__':
    main()
```

**However, when we run that:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License)-[2023.03.19|18:35:33(HKT)]
└> python3 solve.py
ThirdAndFinaTraceback (most recent call last):
  File "/home/siunam/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/solve.py", line 12, in <module>
    main()
  File "/home/siunam/ctf/Cyber-Apocalypse-2023/Reversing/Hunting-License/solve.py", line 7, in main
    print(chr(ord(afterXOR[c]) ^ 0x13), end='')
                  ~~~~~~~~^^^
IndexError: string index out of range
```

We can only see some password? `ThirdAndFina`

Hmm... Let's run `gdb` again.

**This time, we'll set a breakpoint at the compare instruction:**
```shell
gef➤  disassemble exam 
[...]
   0x0000000000401357 <+205>:	mov    ecx,0x13
   0x000000000040135c <+210>:	mov    edx,0x11
   0x0000000000401361 <+215>:	mov    esi,0x404070
   0x0000000000401366 <+220>:	mov    rdi,rax
   0x0000000000401369 <+223>:	call   0x401237 <xor>
   0x000000000040136e <+228>:	mov    edi,0x4021e8
   0x0000000000401373 <+233>:	call   0x401050 <readline@plt>
   0x0000000000401378 <+238>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040137c <+242>:	lea    rdx,[rbp-0x30]
   0x0000000000401380 <+246>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401384 <+250>:	mov    rsi,rdx
   0x0000000000401387 <+253>:	mov    rdi,rax
   0x000000000040138a <+256>:	call   0x401060 <strcmp@plt>
   0x000000000040138f <+261>:	test   eax,eax
   0x0000000000401391 <+263>:	je     0x4013a7 <exam+285>
   0x0000000000401393 <+265>:	mov    edi,0x40222c
   0x0000000000401398 <+270>:	call   0x401040 <puts@plt>
   0x000000000040139d <+275>:	mov    edi,0xffffffff
   0x00000000004013a2 <+280>:	call   0x401080 <exit@plt>
   0x00000000004013a7 <+285>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004013ab <+289>:	mov    rdi,rax
   0x00000000004013ae <+292>:	call   0x401030 <free@plt>
   0x00000000004013b3 <+297>:	nop
   0x00000000004013b4 <+298>:	leave
   0x00000000004013b5 <+299>:	ret
```

**In here, we see there's a `test` instruction, let's set a breakpoint in there, and run it:**
```shell
gef➤  b *exam+261
Breakpoint 1 at 0x40138f
gef➤  r
[...]
So, you want to be a relic hunter?
First, you're going to need your license, and for that you need to pass the exam.
It's short, but it's not for the faint of heart. Are you up to the challenge?! (y/n)
y
Okay, first, a warmup - what's the first password? This one's not even hidden: PasswordNumeroUno
Getting harder - what's the second password? P4ssw0rdTw0
Your final test - give me the third, and most protected, password: ThirdAndFina

Breakpoint 1, 0x000000000040138f in exam ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xffffff94        
$rbx   : 0x007fffffffdcb8  →  0x007fffffffe03b  →  "/home/siunam/ctf/Cyber-Apocalypse-2023/Reversing/H[...]"
$rcx   : 0x6c              
$rdx   : 0x007fffffffdb50  →  "ThirdAndFinal!!!"
$rsp   : 0x007fffffffdb50  →  "ThirdAndFinal!!!"
$rbp   : 0x007fffffffdb80  →  0x007fffffffdba0  →  0x0000000000000001
$rsi   : 0x007fffffffdb50  →  "ThirdAndFinal!!!"
$rdi   : 0x00000000425510  →  "ThirdAndFina"
$rip   : 0x0000000040138f  →  <exam+261> test eax, eax
$r8    : 0x007fffffffda80  →  0x007ffff7f7e800  →   push rbx
$r9    : 0x10              
$r10   : 0x8               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdcc8  →  0x007fffffffe098  →  "TERMINATOR_DBUS_NAME=net.tenshu.Terminator21a9d5db[...]"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero CARRY parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────── stack ────
[...]
```

In the `rdx`, `rsp`, `rsi` registers, the correct password is being displayed!

Hence, the correct third password is `ThirdAndFinal!!!`.

```
Your final test - give me the third, and most protected, password: ThirdAndFinal!!!
Well done hunter - consider yourself certified!
```

```
> ThirdAndFinal!!!
[+] Correct!

[+] Here is the flag: `HTB{l1c3ns3_4cquir3d-hunt1ng_t1m3!}`
```

- **Flag: `HTB{l1c3ns3_4cquir3d-hunt1ng_t1m3!}`**

## Conclusion

What we've learned:

1. Basic Reverse Engineering