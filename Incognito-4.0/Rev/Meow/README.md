# Meow

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/images/Pasted%20image%2020230217203857.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Incognito-4.0/Rev/Meow/meow):**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Rev/Meow)-[2023.02.17|20:38:40(HKT)]
└> file meow                     
meow: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e5364dd913e17a0a897677ff1234cbd21547bdd8, for GNU/Linux 4.4.0, not stripped
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Rev/Meow)-[2023.02.17|20:38:41(HKT)]
└> chmod +x meow
```

Which is a 64-bit ELF executable!

**We can try to run it:**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Rev/Meow)-[2023.02.17|20:38:44(HKT)]
└> ./meow
```

Nothing?

**Can we use `strings` to list all the strings?**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Rev/Meow)-[2023.02.17|20:43:29(HKT)]
└> strings meow 
/lib64/ld-linux-x86-64.so.2
__libc_start_main
__cxa_finalize
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u3UH
GCC: (GNU) 12.2.1 20230201
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
_edata
_fini
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
[...]
```

Nothing weird...

**How about `ltrace`?**

> `ltrace` intercepts and records the dynamic library calls which are called by the executed process and the signals which are received by that process.  It can also intercept and print the system calls executed by the program.

```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Rev/Meow)-[2023.02.17|20:43:57(HKT)]
└> ltrace ./meow 
+++ exited (status 0) +++
```

**Hmm... `strace`?**

> `strace` intercepts and records the system calls which are called by a process and the signals which are received by a process.

```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Rev/Meow)-[2023.02.17|20:43:59(HKT)]
└> strace ./meow 
[...]
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0Ps\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0_CREATE TABLE USERS ( userId serial PRIMARY KEY, firstName TEXT )_\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
newfstatat(3, "", {st_mode=S_IFREG|0755, st_size=1922136, ...}, AT_EMPTY_PATH) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 1970000, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f45607ed000
mmap(0x7f4560813000, 1396736, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x26000) = 0x7f4560813000
mmap(0x7f4560968000, 339968, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x17b000) = 0x7f4560968000
mmap(0x7f45609bb000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ce000) = 0x7f45609bb000
mmap(0x7f45609c1000, 53072, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f45609c1000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f45607ea000
arch_prctl(ARCH_SET_FS, 0x7f45607ea740) = 0
set_tid_address(0x7f45607eaa10)         = 191642
set_robust_list(0x7f45607eaa20, 24)     = 0
rseq(0x7f45607eb060, 0x20, 0, 0x53053053) = 0
mprotect(0x7f45609bb000, 16384, PROT_READ) = 0
mprotect(0x557bd2ac0000, 4096, PROT_READ) = 0
mprotect(0x7f4560a1f000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f45609ce000, 123470)          = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

**Uhh... How about I use `xxd` to output all the hex value?**
```shell
┌[siunam♥earth]-(~/ctf/Incognito-4.0/Rev/Meow)-[2023.02.17|20:45:32(HKT)]
└> xxd meow
[...]
00001ff0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00002000: 0100 0200 0000 0000 0069 0063 0074 0066  .........i.c.t.f
00002010: 007b 0065 0061 0073 0069 0065 0073 0074  .{.e.a.s.i.e.s.t
00002020: 005f 0063 0068 0061 006c 006c 0065 006e  ._.c.h.a.l.l.e.n
00002030: 0067 0065 005f 006f 0066 005f 0074 0068  .g.e._.o.f._.t.h
00002040: 0065 006d 005f 0061 006c 006c 007d 0000  .e.m._.a.l.l.}..
00002050: 011b 033b 1c00 0000 0200 0000 d0ef ffff  ...;............
[...]
```

Nice! We found the flag!

- **Flag: `ictf{easiest_challenge_of_them_all}`**

# Conclusion

What we've learned:

1. Using `xxd` To View Hex Value