# Background
![background1](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Pwn/Space-Pirate:Entrypoint/images/background1.png)

![background2](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Pwn/Space-Pirate:Entrypoint/images/background2.png)

> Tbh, this challenge is one of the most easiest challenges in this CTF you can solved.

# Solution

As usual, download the [downloadable file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Pwn/Space-Pirate:Entrypoint/pwn_sp_entrypoint.zip) and unzip it.

After we unzipped the file, we have 4 files: `flag.txt`, `.gdb_history`, `glibc`, `sp_entrypoint`.

flag.txt: It's a fake flag to have a sanity check locally.
.gdb_history: It's GDB history, just like .bash_history.
glibc: Contains libc files.
**sp_entrypoint: 64-bit ELF executable.**

![solution1](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Pwn/Space-Pirate:Entrypoint/images/solution1.png)

When you're dealing with pwn, or binary exploitation, **it's a good hibit to use `checksec` in pwntools.** checksec allows you to see what memory protections are enabled.

In this challenge, we can see:

Arch: The CPU architecture of this executable.

RELRO: Full RELRO/Partial RELRO 

It means `Relocation Read-Only`. In this challenge, we see it has Full RELRO, makes the entire GOT read-only which **removes the ability to perform a "GOT overwrite" attack.** You'll often see Partial RELRO, which **might vulnerable to buffer overflows on a global variable overwriting GOT entries.**

Stack: Canary found/No canary

**Canary found** means a random value is placed on the stack. **No canary** means we could overflow to control the return pointer and the program crashes.

NX: NX enabled/No

NX means **No eXecute**, if it's enabled, it marks certain areas of the program as not executable, meaning that stored input or data cannot be executed as code. So we can't drop a **shellcode**.

PIE: PIE enabled/No PIE

PIE means **Position Independent Executables**. If PIE is enabled, every time you run the file it gets loaded into a different memory address.

Alright, enough talking, let's run the executable and see what it's doing!

![solution2](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Pwn/Space-Pirate:Entrypoint/images/solution2.png)

![solution3](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Pwn/Space-Pirate:Entrypoint/images/solution3.png)

What?? The fake flag is printed? Let's start the docker instance and get the flag??

![flag](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-CTF-2022/Pwn/Space-Pirate:Entrypoint/images/flag.png)

Wut...

# Flag
`HTB{th3_g4t35_4r3_0p3n!}`