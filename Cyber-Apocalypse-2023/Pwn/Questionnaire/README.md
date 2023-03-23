# Questionnaire

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

It's time to learn some things about binaries and basic c. Connect to a remote server and answer some questions to get the flag.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319130613.png)

## Find the flag

**In the challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Pwn/Questionnaire/pwn_questionnaire.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:07:07(HKT)]
└> file pwn_questionnaire.zip 
pwn_questionnaire.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:07:08(HKT)]
└> unzip pwn_questionnaire.zip 
Archive:  pwn_questionnaire.zip
  inflating: test.c                  
  inflating: test
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:07:18(HKT)]
└> file test test.c
test:   ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5a83587fbda6ad7b1aeee2d59f027a882bf2a429, for GNU/Linux 3.2.0, not stripped
test.c: C source, ASCII text
```

**Let's `nc` to the instance machine!**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:08:02(HKT)]
└> nc 46.101.80.159 32022


This is a simple questionnaire to get started with the basics.

◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                                                       ◉
◉  When compiling C/C++ source code in Linux, an ELF (Executable and Linkable Format) file is created.  ◉
◉  The flags added when compiling can affect the binary in various ways, like the protections.          ◉
◉  Another thing affected can be the architecture and the way it's linked.                              ◉
◉                                                                                                       ◉
◉  If the system in which the challenge is compiled is x86_64 and no flag is specified,                 ◉
◉  the ELF would be x86-64 / 64-bit. If it's compiled with a flag to indicate the system,               ◉
◉  it can be x86 / 32-bit binary.                                                                       ◉
◉                                                                                                       ◉
◉  To reduce its size and make debugging more difficult, the binary can be stripped or not stripped.    ◉
◉                                                                                                       ◉
◉  Dynamic linking:                                                                                     ◉
◉                                                                                                       ◉
◉  A pointer to the linked file is included in the executable, and the file contents are not included   ◉
◉  at link time. These files are used when the program is run.                                          ◉
◉                                                                                                       ◉
◉  Static linking:                                                                                      ◉
◉                                                                                                       ◉
◉  The code for all the routines called by your program becomes part of the executable file.            ◉
◉                                                                                                       ◉
◉  Stripped:                                                                                            ◉
◉                                                                                                       ◉
◉  The binary does not contain debugging information.                                                   ◉
◉                                                                                                       ◉
◉  Not Stripped:                                                                                        ◉
◉                                                                                                       ◉
◉  The binary contains debugging information.                                                           ◉
◉                                                                                                       ◉
◉  The most common protections in a binary are:                                                         ◉
◉                                                                                                       ◉
◉  Canary: A random value that is generated, put on the stack, and checked before that function is      ◉
◉  left again. If the canary value is not correct-has been changed or overwritten, the application will ◉
◉  immediately stop.                                                                                    ◉
◉                                                                                                       ◉
◉  NX: Stands for non-executable segments, meaning we cannot write and execute code on the stack.       ◉
◉                                                                                                       ◉
◉  PIE: Stands for Position Independent Executable, which randomizes the base address of the binary     ◉
◉  as it tells the loader which virtual address it should use.                                          ◉
◉                                                                                                       ◉
◉  RelRO: Stands for Relocation Read-Only. The headers of the binary are marked as read-only.           ◉
◉                                                                                                       ◉
◉  Run the 'file' command in the terminal and 'checksec' inside the debugger.                           ◉
◉                                                                                                       ◉
◉  The output of 'file' command:                                                                        ◉
◉                                                                                                       ◉
◉  ✗ file test                                                                                          ◉
◉  test: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,                       ◉
◉  interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5a83587fbda6ad7b1aeee2d59f027a882bf2a429,     ◉
◉  for GNU/Linux 3.2.0, not stripped.                                                                   ◉
◉                                                                                                       ◉
◉  The output of 'checksec' command:                                                                    ◉
◉                                                                                                       ◉
◉  gef➤  checksec                                                                                       ◉
◉  Canary                        : ✘                                                                    ◉
◉  NX                            : ✓                                                                    ◉
◉  PIE                           : ✘                                                                    ◉
◉  Fortify                       : ✘                                                                    ◉
◉  RelRO                         : Partial                                                              ◉
◉                                                                                                       ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x1:

Is this a '32-bit' or '64-bit' ELF? (e.g. 1337-bit)

>> 
```

**We've found that it's a 64-bit ELF executable in `file`:**
```
>> 64-bit

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

[*] Question number 0x2:

What's the linking of the binary? (e.g. static, dynamic)

>> 
```

**It's dynamically linked:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:07:33(HKT)]
└> file test       
test: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5a83587fbda6ad7b1aeee2d59f027a882bf2a429, for GNU/Linux 3.2.0, not stripped
```

```
>> dynamic

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

[*] Question number 0x3:

Is the binary 'stripped' or 'not stripped'?

>> 
```

not stripped.

```
>> not stripped

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

[*] Question number 0x4:

Which protections are enabled (Canary, NX, PIE, Fortify)?

>> 
```

**In here, we can use pwntool's `checksec` to check memory protections:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:10:54(HKT)]
└> checksec test          
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/siunam/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire/test'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

As you can see, `NX` is enabled.

```
>> NX

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠


◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                                                       ◉
◉  Great job so far! Now it's time to see some C code and a binary file.                                ◉
◉                                                                                                       ◉
◉  In the pwn_questionnaire.zip there are two files:                                                    ◉
◉                                                                                                       ◉
◉  1. test.c                                                                                            ◉
◉  2. test                                                                                              ◉
◉                                                                                                       ◉
◉  The 'test.c' is the source code and 'test' is the output binary.                                     ◉
◉                                                                                                       ◉
◉  Let's start by analyzing the code.                                                                   ◉
◉  First of all, let's focus on the '#include <stdio.h>' line.                                          ◉
◉  It includes the 'stdio.h' header file to use some of the standard functions like 'printf()'.         ◉
◉  The same principle applies for the '#include <stdlib.h>' line, for other functions like 'system()'.  ◉
◉                                                                                                       ◉
◉  Now, let's take a closer look at:                                                                    ◉
◉                                                                                                       ◉
◉  void main(){                                                                                         ◉
◉      vuln();                                                                                          ◉
◉  }                                                                                                    ◉
◉                                                                                                       ◉
◉  By default, a binary file starts executing from the 'main()' function.                               ◉
◉                                                                                                       ◉
◉  In this case, 'main()' only calls another function, 'vuln()'.                                        ◉
◉  The function 'vuln()' has 3 lines.                                                                   ◉
◉                                                                                                       ◉
◉  void vuln(){                                                                                         ◉
◉      char buffer[0x20] = {0};                                                                         ◉
◉      fprintf(stdout, "\nEnter payload here: ");                                                       ◉
◉      fgets(buffer, 0x100, stdin);                                                                     ◉
◉  }                                                                                                    ◉
◉                                                                                                       ◉
◉  The first line declares a 0x20-byte buffer of characters and fills it with zeros.                    ◉
◉  The second line calls 'fprintf()' to print a message to stdout.                                      ◉
◉  Finally, the third line calls 'fgets()' to read 0x100 bytes from stdin and store them to the         ◉
◉  aformentioned buffer.                                                                                ◉
◉                                                                                                       ◉
◉  Then, there is a custom 'gg()' function which calls the standard 'system()' function to print the    ◉
◉  flag. This function is never called by default.                                                      ◉
◉                                                                                                       ◉
◉  void gg(){                                                                                           ◉
◉      system("cat flag.txt");                                                                          ◉
◉  }                                                                                                    ◉
◉                                                                                                       ◉
◉  Run the 'man <function_name>' command to see the manual page of a standard function (e.g. man fgets).◉
◉                                                                                                       ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x5:

What is the name of the custom function that gets called inside `main()`? (e.g. vulnerable_function())

>> 
```

```c
void main(){
	vuln();
}
```

So it's `vuln()`.

```
>> vuln()

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

[*] Question number 0x6:

What is the size of the 'buffer' (in hex or decimal)?

>> 

```

**In the `vuln()` function, we see:**
```c
char buffer[0x20] = {0};
```

So it's `0x20` bytes buffer, which is 32 in decimal.

```
>> 0x20

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

[*] Question number 0x7:

Which custom function is never called? (e.g. vuln())

>> 
```

```c
void gg(){
	system("cat flag.txt");
}
```

This `gg()` function is never called.

```
>> gg()

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠


◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                                                       ◉
◉  Excellent! Now it's time to talk about Buffer Overflows.                                             ◉
◉                                                                                                       ◉
◉  Buffer Overflow means there is a buffer of characters, integers or any other type of variables,      ◉
◉  and someone inserts into this buffer more bytes than it can store.                                   ◉
◉                                                                                                       ◉
◉  If the user inserts more bytes than the buffer's size, they will be stored somewhere in the memory   ◉
◉  after the address of the buffer, overwriting important addresses for the flow of the program.        ◉
◉  This, in most cases, will make the program crash.                                                    ◉
◉                                                                                                       ◉
◉  When a function is called, the program knows where to return because of the 'return address'. If the ◉
◉  player overwrites this address, they can redirect the flow of the program wherever they want.        ◉
◉  To print a function's address, run 'p <function_name>' inside 'gdb'. (e.g. p main)                   ◉
◉                                                                                                       ◉
◉  gef➤  p gg                                                                                           ◉
◉  $1 = {<text variable, no debug info>} 0x401176 <gg>                                                  ◉
◉                                                                                                       ◉
◉  To perform a Buffer Overflow in the simplest way, we take these things into consideration.           ◉
◉                                                                                                       ◉
◉  1. Canary is disabled so it won't quit after the canary address is overwritten.                      ◉
◉  2. PIE is disabled so the addresses of the binary functions are not randomized and the user knows    ◉
◉     where to return after overwritting the return address.                                            ◉
◉  3. There is a buffer with N size.                                                                    ◉
◉  4. There is a function that reads to this buffer more than N bytes.                                  ◉
◉                                                                                                       ◉
◉  Run printf 'A%.0s' {1..30} | ./test to enter 30*"A" into the program.                                ◉
◉                                                                                                       ◉
◉  Run the program manually with "./test" and insert 30*A, then 39, then 40 and see what happens.       ◉
◉                                                                                                       ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x8:

What is the name of the standard function that could trigger a Buffer Overflow? (e.g. fprintf())

>> 
```

**In the `vuln()` function, we see:**
```c
void vuln(){
	char buffer[0x20] = {0};
	fprintf(stdout, "\nEnter payload here: ");
	fgets(buffer, 0x100, stdin);
}
```

So it's `fgets()` function.

```
>> fgets()

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

[*] Question number 0x9:

Insert 30, then 39, then 40 'A's in the program and see the output.

After how many bytes a Segmentation Fault occurs (in hex or decimal)?

>> 
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:17:09(HKT)]
└> python3 -c "print('A' * 30)" | ./test

Enter payload here:                                                                                      
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:17:22(HKT)]
└> python3 -c "print('A' * 39)" | ./test

Enter payload here: 
Enter payload here:                                                                                      
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:17:25(HKT)]
└> python3 -c "print('A' * 40)" | ./test

[1]    57887 done                python3 -c "print('A' * 40)" | 
       57888 segmentation fault  ./test
```

40 bytes.

```
>> 40

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

[*] Question number 0xa:

What is the address of 'gg()' in hex? (e.g. 0x401337)

>> 
```

**In here, we can use `gdb` to view the address of `gg()` function:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Pwn/Questionnaire)-[2023.03.19|13:17:28(HKT)]
└> gdb test 
[...]
gef➤  p gg
$1 = {<text variable, no debug info>} 0x401176 <gg>
```

> Note: I'm using `gef` gdb plugin.

So function `gg()` is in memory address: `0x401176`.

```
>> 0x401176

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

Great job! It's high time you solved your first challenge! Here is the flag!

HTB{th30ry_bef0r3_4cti0n}
```

- **Flag: `HTB{th30ry_bef0r3_4cti0n}`**

## Conclusion

What we've learned:

1. Basic Binary Exploitation Concept