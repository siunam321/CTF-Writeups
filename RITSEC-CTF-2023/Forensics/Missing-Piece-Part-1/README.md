# Missing Piece Part 1

- 397 Points / 48 Solves

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Background

I got sent this memory dump, but I can't figure out how to read it. I wonder what they were doing?

Download here: [https://drive.google.com/file/d/1vX1M8zlNtC8L2FTSwnaJmLW-36wTACeS/view?usp=sharing](https://drive.google.com/file/d/1vX1M8zlNtC8L2FTSwnaJmLW-36wTACeS/view?usp=sharing) (This is a large file btw)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402163624.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1)-[2023.04.02|16:36:42(HKT)]
└> file dump.zip                                                           
dump.zip: Zip archive data, at least v4.5 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1)-[2023.04.02|16:36:43(HKT)]
└> unzip dump.zip        
Archive:  dump.zip
  inflating: dump.mem                
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1)-[2023.04.02|16:38:06(HKT)]
└> file dump.mem 
dump.mem: data
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1)-[2023.04.02|16:38:13(HKT)]
└> ls -lah dump.mem 
-rw-r--r-- 1 siunam nam 4.0G Mar 31 14:02 dump.mem
```

As you can see, it's extension is `.mem`, which means this is a memory dump file, and it's size is 4.0 GB.

To read a memory dump file, we can use a tool called "[Volatility](https://www.volatilityfoundation.org/)", which is a tool that do **memory forensics**, and I'll be using `volatility2` and `volatility3`.

> [Volatility HackTricks cheat sheet](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet)

**First, we need to find the OS, like the machine is Windows or Linux or MacOS:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1)-[2023.04.02|16:53:23(HKT)]
└> /opt/volatility3/vol.py -f dump.mem banners.Banners  
Volatility 3 Framework 2.3.0
Progress:  100.00		PDB scanning finished                  
Offset	Banner

0x752001a0	Linux version 5.4.0-84-generic (buildd@lcy01-amd64-007) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #94~18.04.1-Ubuntu SMP Thu Aug 26 23:17:46 UTC 2021 (Ubuntu 5.4.0-84.94~18.04.1-generic 5.4.133)
0x75d91d94	Linux version 5.4.0-84-generic (buildd@lcy01-amd64-007) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #94~18.04.1-Ubuntu SMP Thu Aug 26 23:17:46 UTC 2021 (Ubuntu 5.4.0-84.94~18.04.1-generic 5.4.133)
0x12ae51948	Linux version 5.4.0-144-generic (buildd@lcy02-amd64-069) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #161~18.04.1-Ubuntu SMP Fri Feb 10 15:55:22 UTC 2023 (Ubuntu 5.4.0-144.161~18.04.1-generic 5.4.229)
0x12af26c90	Linux version 5.4.0-84-generic (buildd@lcy01-amd64-007) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #94~18.04.1-Ubuntu SMP Thu Aug 26 23:17:46 UTC 2021 (Ubuntu 5.4.0-84.94~18.04.1-generic 5.4.133)
0x13fec78d0	Linux version 5.4.0-84-generic (buildd@lcy01-amd64-007) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #94~18.04.1-Ubuntu SMP Thu Aug 26 23:17:46 UTC 2021 (Ubuntu 5.4.0-84.94~18.04.1-generic 5.4.133)
```

- OS information: Linux version 5.4.0-84-generic (Ubuntu 18.04.1)

**Then, download the profile from [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) in `profiles/Linux/Ubuntu/x64/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402200350.png)

**Put that zip file to `<volatility_path>/volatility/plugins/overlays/linux`:**
```shell
┌[siunam♥earth]-(/opt/volatility/volatility/plugins/overlays/linux)-[2023.04.02|19:55:11(HKT)]-[git://master ✔]
└> mv /home/siunam/Downloads/Ubuntu18.04.1-4.18.0-25.zip .
```

Now we can use that profile.

**However, when we try to run other plugins, it'll show this error:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1)-[2023.04.02|19:56:17(HKT)]
└> python2 /opt/volatility/vol.py --profile=LinuxUbuntu18_04_1-4_18_0-25x64 -f dump.mem linux_netscan
Volatility Foundation Volatility Framework 2.6.1
No suitable address space mapping found
Tried to open image as:
[...]
 MachOAddressSpace: MachO Header signature invalid
 MachOAddressSpace: MachO Header signature invalid
[...]
```

Hmm?? Header signature invalid?

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1)-[2023.04.02|20:00:41(HKT)]
└> file dump.mem
dump.mem: data
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Missing-Piece-Part-1)-[2023.04.02|20:05:35(HKT)]
└> xxd dump.mem | head
00000000: 454d 694c 0100 0000 0010 0000 0000 0000  EMiL............
00000010: ffe7 0900 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

I tried to fix this error, but no dice...