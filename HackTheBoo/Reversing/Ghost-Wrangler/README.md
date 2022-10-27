# Ghost Wrangler

## Background

> Who you gonna call?

> Difficulty: Easy

- Overall difficulty for me: Very easy

**In this challenge, we can [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Ghost-Wrangler/rev_ghost_wrangler.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Ghost-Wrangler/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Ghost-Wrangler]
└─# unzip rev_ghost_wrangler.zip 
Archive:  rev_ghost_wrangler.zip
   creating: rev_ghost_wrangler/
  inflating: rev_ghost_wrangler/ghost  
                                                                                                         
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Ghost-Wrangler]
└─# file rev_ghost_wrangler/ghost 
rev_ghost_wrangler/ghost: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=810d0f9271ec04d80a2eee6ff2afd9367da3c3dd, for GNU/Linux 3.2.0, not stripped
                                                                                                         
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Ghost-Wrangler]
└─# chmod +x rev_ghost_wrangler/ghost
```

It's a ELF 64-bit LSB pie executable!

## Find the flag

**It's a good practice don't blindly run any executable you downloaded from online, I'll use `strings` to see anything weird:**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Reversing/Ghost-Wrangler/rev_ghost_wrangler]
└─# strings ghost                
[...]
[24m| I've managed to trap the flag ghost in this box, but it's turned invisible!
Can you figure out how to reveal them?
[...]
```

Looks good. Try to run it?

```
┌──(root🌸siunam)-[~/…/HackTheBoo/Reversing/Ghost-Wrangler/rev_ghost_wrangler]
└─# ./ghost 
|                                       _| I've managed to trap the flag ghost in this box, but it's turned invisible!
Can you figure out how to reveal them?
```

Hmm... It seems like the flag get loaded into memory, but it didn't print the flag out...

**How about using `ltrace` to trace all system calls from the executable? Like `cat`, `ls` commands.**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Reversing/Ghost-Wrangler/rev_ghost_wrangler]
└─# ltrace ./ghost         
malloc(41)                                                      = 0x55a62f1aa2a0
memset(0x55a62f1aa2a0, '\0', 41)                                = 0x55a62f1aa2a0
printf("%s\r|\033[4m%*.c\033[24m| I've managed "..., "HTB{h4unt3d_by_th3_gh0st5_0f_ctf"..., 40, '_'HTB{h4|                                       _| I've managed to trap the flag ghost in this box, but it's turned invisible!
Can you figure out how to reveal them?
) = 208
+++ exited (status 0) +++
```

Ohh! Hmm... But we only see half of the flag.

**Let's use `gdb` to find the full flag!**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Reversing/Ghost-Wrangler/rev_ghost_wrangler]
└─# gdb ./ghost
[...]
gef➤  
```

**Then, I'll use `info functions` to list all the functions in this executable:** 
```
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  printf@plt
0x0000000000001040  memset@plt
0x0000000000001050  malloc@plt
0x0000000000001060  __cxa_finalize@plt
0x0000000000001070  _start
0x00000000000010a0  deregister_tm_clones
0x00000000000010d0  register_tm_clones
0x0000000000001110  __do_global_dtors_aux
0x0000000000001150  frame_dummy
0x0000000000001155  get_flag
0x00000000000011c2  main
0x0000000000001210  __libc_csu_init
0x0000000000001270  __libc_csu_fini
0x0000000000001274  _fini
```

**The `get_flag` function looks sussy! Let's disassemble that function via `disas <function_name>`**
```
gef➤  disas get_flag
Dump of assembler code for function get_flag:
   0x0000000000001155 <+0>:	push   rbp
   0x0000000000001156 <+1>:	mov    rbp,rsp
   0x0000000000001159 <+4>:	sub    rsp,0x10
   0x000000000000115d <+8>:	mov    edi,0x29
   0x0000000000001162 <+13>:	call   0x1050 <malloc@plt>
   0x0000000000001167 <+18>:	mov    QWORD PTR [rbp-0x10],rax
   0x000000000000116b <+22>:	mov    rax,QWORD PTR [rbp-0x10]
   0x000000000000116f <+26>:	mov    edx,0x29
   0x0000000000001174 <+31>:	mov    esi,0x0
   0x0000000000001179 <+36>:	mov    rdi,rax
   0x000000000000117c <+39>:	call   0x1040 <memset@plt>
   0x0000000000001181 <+44>:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000001188 <+51>:	jmp    0x11b4 <get_flag+95>
   0x000000000000118a <+53>:	mov    eax,DWORD PTR [rbp-0x4]
   0x000000000000118d <+56>:	cdqe   
   0x000000000000118f <+58>:	lea    rdx,[rip+0xe8a]        # 0x2020 <_>
   0x0000000000001196 <+65>:	movzx  eax,BYTE PTR [rax+rdx*1]
   0x000000000000119a <+69>:	xor    eax,0x13
   0x000000000000119d <+72>:	mov    ecx,eax
   0x000000000000119f <+74>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000000011a2 <+77>:	movsxd rdx,eax
   0x00000000000011a5 <+80>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011a9 <+84>:	add    rax,rdx
   0x00000000000011ac <+87>:	mov    edx,ecx
   0x00000000000011ae <+89>:	mov    BYTE PTR [rax],dl
   0x00000000000011b0 <+91>:	add    DWORD PTR [rbp-0x4],0x1
   0x00000000000011b4 <+95>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000000011b7 <+98>:	cmp    eax,0x27
   0x00000000000011ba <+101>:	jbe    0x118a <get_flag+53>
   0x00000000000011bc <+103>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011c0 <+107>:	leave  
   0x00000000000011c1 <+108>:	ret    
End of assembler dump.
```

Bunch of XORs.

**Since I'm lazy to solving XOR puzzles, I'll just set a breakpoint at the `get_flag` function, and hopefully the full flag will be loaded:**
```
gef➤  break *get_flag
Breakpoint 1 at 0x1155
gef➤  run
Starting program: /root/ctf/HackTheBoo/Reversing/Ghost-Wrangler/rev_ghost_wrangler/ghost 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555555155 in get_flag ()
[...]
```

**Nothing weird in the first step, let's use `next` to run the next instruction:**
```
gef➤  next
Single stepping until exit from function get_flag,
which has no line number information.
0x00005555555551d4 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x005555555592a0  →  "HTB{h4unt3d_by_th3_gh0st5_0f_ctf5_p45t!}"
$rbx   : 0x0               
$rcx   : 0x7d              
$rdx   : 0x7d              
$rsp   : 0x007fffffffdc60  →  0x0000000000000000
$rbp   : 0x007fffffffdc70  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x005555555592a0  →  "HTB{h4unt3d_by_th3_gh0st5_0f_ctf5_p45t!}"
[...]
```

Boom! We got the full flag in the RDI, RAX registers!

# Conclusion

What we've learned:

1. Using `gdb` to Find Loaded Memory Strings