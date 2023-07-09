# Attaaaaack 1 - 13

## Table of Contents

1. [Attaaaaack1](#attaaaaack1)
2. [Attaaaaack2](#attaaaaack2)
3. [Attaaaaack3](#attaaaaack3)
4. [Attaaaaack4](#attaaaaack4)
5. [Attaaaaack5](#attaaaaack5)
6. [Attaaaaack6](#attaaaaack6)
7. [Attaaaaack7](#attaaaaack7)
8. [Attaaaaack8](#attaaaaack8)
9. [Attaaaaack9](#attaaaaack9)
10. [Attaaaaack10](#attaaaaack10)
11. [Attaaaaack11](#attaaaaack11)
12. [Attaaaaack12](#attaaaaack12)
13. [Attaaaaack13](#attaaaaack13)
14. [Conclusion](#conclusion)

## Attaaaaack1

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

One of our employees at the company complained about suspicious behavior on the machine, our IR team took a memory dump from the machine and we need to investigate it.

Q1. What is the best profile for the the machine?

example : crew{Profile}

[Link](https://drive.google.com/file/d/1T8__WXOPcGqmkubyH-NBokEGk3N_H5hr/view?usp=share_link)

Author : 0xSh3rl0ck

### Find the flag

**In this challenge, we can download a [file](https://drive.google.com/file/d/1T8__WXOPcGqmkubyH-NBokEGk3N_H5hr/view?usp=share_link):**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|17:23:39(HKT)]
└> ls -lah memdump.raw && file memdump.raw 
-rw-r--r-- 1 siunam nam 1.0G Jul  8 16:06 memdump.raw
memdump.raw: Windows Event Trace Log
```

Now, the `raw` extension is a memory dump file.

To perform memory forensic, we can use a tool called **Volatility**. Through out this challenge, I'll use Volatility version 2 (volatility2), I don't know why volatility3 is broken for me...

**According to [HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet#discover-profile), we can discover profile via:**
```shell
volatility imageinfo -f file.dmp
```

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|17:26:15(HKT)]
└> python2 /opt/volatility/vol.py imageinfo -f memdump.raw
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/siunam/ctf/CrewCTF-2023/Forensics/Attaaaaack/memdump.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82b7ab78L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x80b96000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2023-02-20 19:10:54 UTC+0000
     Image local date and time : 2023-02-20 21:10:54 +0200
```

- Profile: `Win7SP1x86_23418`
- **Flag: `crew{Win7SP1x86_23418}`**

## Attaaaaack2

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Q2. How many processes were running ? (number)

Author : 0xSh3rl0ck

### Find the flag

After we discovered the suggested profile, we can use the `--profile` option to specify which profile we wanna use.

**Also, volatility2 has a plugin called `pslist`, which prints all running processes by following the EPROCESS lists:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|17:44:27(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86 -f memdump.raw pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x8419c020 System                    4      0     89      536 ------      0 2023-02-20 19:01:19 UTC+0000                                 
0x962f2020 smss.exe                268      4      2       29 ------      0 2023-02-20 19:01:19 UTC+0000                                 
0x860a8c78 csrss.exe               352    344      9      462      0      0 2023-02-20 19:01:20 UTC+0000                                 
0x855dfd20 wininit.exe             404    344      3       76      0      0 2023-02-20 19:01:20 UTC+0000                                 
0x8550b030 csrss.exe               416    396      9      268      1      0 2023-02-20 19:01:20 UTC+0000                                 
0x85ea2368 services.exe            480    404      8      220      0      0 2023-02-20 19:01:20 UTC+0000                                 
0x85ea8610 lsass.exe               488    404      6      568      0      0 2023-02-20 19:01:20 UTC+0000                                 
0x85eab718 lsm.exe                 496    404     10      151      0      0 2023-02-20 19:01:20 UTC+0000                                 
0x85eacb80 winlogon.exe            508    396      5      115      1      0 2023-02-20 19:01:20 UTC+0000                                 
0x85f4d030 svchost.exe             632    480     10      357      0      0 2023-02-20 19:01:21 UTC+0000                                 
0x85ef0a90 svchost.exe             700    480      8      280      0      0 2023-02-20 19:01:21 UTC+0000                                 
0x919e2958 svchost.exe             752    480     22      507      0      0 2023-02-20 19:01:21 UTC+0000                                 
0x85f9c3a8 svchost.exe             868    480     13      309      0      0 2023-02-20 19:01:21 UTC+0000                                 
0x85fae030 svchost.exe             908    480     18      715      0      0 2023-02-20 19:01:21 UTC+0000                                 
0x85fb7670 svchost.exe             952    480     34      995      0      0 2023-02-20 19:01:22 UTC+0000                                 
0x85ff1380 svchost.exe            1104    480     18      391      0      0 2023-02-20 19:01:22 UTC+0000                                 
0x8603a030 spoolsv.exe            1236    480     13      270      0      0 2023-02-20 19:01:22 UTC+0000                                 
0x86071818 svchost.exe            1280    480     19      312      0      0 2023-02-20 19:01:22 UTC+0000                                 
0x860b73c8 svchost.exe            1420    480     10      146      0      0 2023-02-20 19:01:22 UTC+0000                                 
0x860ba030 taskhost.exe           1428    480      9      205      1      0 2023-02-20 19:01:22 UTC+0000                                 
0x861321c8 dwm.exe                1576    868      5      114      1      0 2023-02-20 19:01:23 UTC+0000                                 
0x8613c030 explorer.exe           1596   1540     29      842      1      0 2023-02-20 19:01:23 UTC+0000                                 
0x841d7500 VGAuthService.         1636    480      3       84      0      0 2023-02-20 19:01:23 UTC+0000                                 
0x86189d20 vmtoolsd.exe           1736   1596      8      179      1      0 2023-02-20 19:01:23 UTC+0000                                 
0x8619dd20 vm3dservice.ex         1848    480      4       60      0      0 2023-02-20 19:01:24 UTC+0000                                 
0x861a9030 vmtoolsd.exe           1884    480     13      290      0      0 2023-02-20 19:01:24 UTC+0000                                 
0x861b5360 vm3dservice.ex         1908   1848      2       44      1      0 2023-02-20 19:01:24 UTC+0000                                 
0x861fc700 svchost.exe             580    480      6       91      0      0 2023-02-20 19:01:25 UTC+0000                                 
0x86261030 WmiPrvSE.exe           1748    632     10      204      0      0 2023-02-20 19:01:25 UTC+0000                                 
0x86251bf0 dllhost.exe             400    480     15      196      0      0 2023-02-20 19:01:26 UTC+0000                                 
0x8629e518 msdtc.exe              2168    480     14      158      0      0 2023-02-20 19:01:31 UTC+0000                                 
0x8629e188 SearchIndexer.         2276    480     12      581      0      0 2023-02-20 19:01:31 UTC+0000                                 
0x8630b228 wmpnetwk.exe           2404    480      9      212      0      0 2023-02-20 19:01:32 UTC+0000                                 
0x862cca38 svchost.exe            2576    480     15      232      0      0 2023-02-20 19:01:33 UTC+0000                                 
0x85351030 WmiPrvSE.exe           3020    632     11      242      0      0 2023-02-20 19:01:45 UTC+0000                                 
0x853faac8 ProcessHacker.         3236   1596      9      416      1      0 2023-02-20 19:02:37 UTC+0000                                 
0x843068f8 sppsvc.exe             2248    480      4      146      0      0 2023-02-20 19:03:25 UTC+0000                                 
0x85f89640 svchost.exe            2476    480     13      369      0      0 2023-02-20 19:03:25 UTC+0000                                 
0x843658d0 cmd.exe                2112   2876      1       20      1      0 2023-02-20 19:03:40 UTC+0000                                 
0x84368798 cmd.exe                2928   2876      1       20      1      0 2023-02-20 19:03:40 UTC+0000                                 
0x84365c90 conhost.exe            1952    416      2       49      1      0 2023-02-20 19:03:40 UTC+0000                                 
0x84384d20 conhost.exe            2924    416      2       49      1      0 2023-02-20 19:03:40 UTC+0000                                 
0x84398998 runddl32.exe            300   2876     10     2314      1      0 2023-02-20 19:03:40 UTC+0000                                 
0x84390030 notepad.exe            2556    300      2       58      1      0 2023-02-20 19:03:41 UTC+0000                                 
0x84df2458 audiodg.exe            1556    752      6      129      0      0 2023-02-20 19:10:50 UTC+0000                                 
0x84f1caf8 DumpIt.exe             2724   1596      2       38      1      0 2023-02-20 19:10:52 UTC+0000                                 
0x84f3d878 conhost.exe            3664    416      2       51      1      0 2023-02-20 19:10:52 UTC+0000
```

- Number of running processes: `47`
- **Flag: `47`**

## Attaaaaack3

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Q3. i think the user left note on the machine. can you find it ?

Author : 0xSh3rl0ck

### Find the flag

**In volatility2, there's a plugin called `clipboard`, which will dump all the clipboard buffer. (Only volatility2 has this)**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|18:06:22(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86 -f memdump.raw clipboard                        
Volatility Foundation Volatility Framework 2.6.1
Session    WindowStation Format                 Handle Object     Data                                              
---------- ------------- ------------------ ---------- ---------- --------------------------------------------------
         1 WinSta0       CF_UNICODETEXT        0xa00d9 0xfe897838 1_l0v3_M3m0ry_F0r3ns1cs_S0_muchhhhhhhhh           
         1 WinSta0       0x0L                     0x10 ----------                                                   
         1 WinSta0       0x2000L                   0x0 ----------                                                   
         1 WinSta0       0x0L                   0x3000 ----------                                                   
         1 ------------- ------------------   0x1a02a9 0xfe670a68                                                   
         1 ------------- ------------------   0x100067 0xffbab448                                                   
```

Nice! We found that weird text!

- **Flag: `crew{1_l0v3_M3m0ry_F0r3ns1cs_S0_muchhhhhhhhh}`**

## Attaaaaack4

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Q4. What is the name and PID of the suspicious process ?

example : crew{abcd.exe_111}

Author : 0xSh3rl0ck

### Find the flag

**In Attaaaaack2, we found all running processes, there's some processes look weird:**
```
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
[...]
0x84398998 runddl32.exe            300   2876     10     2314      1      0 2023-02-20 19:03:40 UTC+0000
0x84390030 notepad.exe            2556    300      2       58      1      0 2023-02-20 19:03:41 UTC+0000
0x84df2458 audiodg.exe            1556    752      6      129      0      0 2023-02-20 19:10:50 UTC+0000                                 
0x84f1caf8 DumpIt.exe             2724   1596      2       38      1      0 2023-02-20 19:10:52 UTC+0000
[...]
```

The `runddl32.exe` is weird to me, as its name is run**ddl**, not run**dll**.

- **Flag: `crew{runddl32.exe_300}`**

## Attaaaaack5

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Q5. What is the another process that is related to this process and it's strange ?

example : crew{spotify.exe}

Author : 0xSh3rl0ck

### Find the flag

In Attaaaaack4, we found that the `runddl32.exe` is sussy.

**Then, we can use its PID to track down which parent PID (PPID) is the same as the `runddl32.exe` PID:**
```
0x84398998 runddl32.exe            300   2876     10     2314      1      0 2023-02-20 19:03:40 UTC+0000
0x84390030 notepad.exe            2556    300      2       58      1      0 2023-02-20 19:03:41 UTC+0000
```

Found it!

- **Flag: `crew{notepad.exe}`**

## Attaaaaack6

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Q6. What is the full path (including executable name) of the hidden executable?

example : `crew{C:\Windows\System32\abc.exe}`

Author : 0xSh3rl0ck

### Find the flag

Just to sum up what we've found, we found a sussy executable `runddl.exe`.

**In volatility2, we can use plugin `cmdline` to display process command-line arguments:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|18:41:29(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86 -f memdump.raw cmdline          
[...]
runddl32.exe pid:    300
Command line : "C:\Users\0XSH3R~1\AppData\Local\Temp\MSDCSC\runddl32.exe" 
************************************************************************
notepad.exe pid:   2556
Command line : notepad
************************************************************************
[...]
```

As you can see, the `runddl32.exe`'s full path is `C:\Users\0XSH3R~1\AppData\Local\Temp\MSDCSC\runddl32.exe`.

- **Flag: `C:\Users\0XSH3R~1\AppData\Local\Temp\MSDCSC\runddl32.exe`**

## Attaaaaack7

### Overview

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

### Background

Q7. What is the API used by the malware to retrieve the status of a specified virtual key on the keyboard ?

flag format : crew{AbcDef}

Author : 0xSh3rl0ck

### Find the flag

**Since we found the sussy executable, we can dump that file:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|19:10:29(HKT)]
└> mkdir runddl
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|19:10:43(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86_23418 -f memdump.raw procdump --pid=300 --dump-dir=runddl  
[...]
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|19:10:58(HKT)]
└> ls -lah runddl 
total 668K
drwxr-xr-x 2 siunam nam 4.0K Jul  8 18:47 .
drwxr-xr-x 3 siunam nam 4.0K Jul  8 18:51 ..
-rw-r--r-- 1 siunam nam 659K Jul  8 18:47 executable.300.exe
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|19:11:06(HKT)]
└> file runddl/executable.300.exe 
runddl/executable.300.exe: PE32 executable (GUI) Intel 80386, for MS Windows, 9 sections
```

Since this challenge is asking for the API (**Not API key**) to retrieve status on the keyboard, we can use `strings` and `grep` to find `key` related strings:

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|19:12:12(HKT)]
└> strings runddl/executable.300.exe | grep -i 'key'
AutoHotkeysd-C
AutoHotkeys
AutoHotkeys
TWMKey
System\CurrentControlSet\Control\Keyboard Layouts\%.8x
	TKeyEvent
TKeyPressEvent
HelpKeyword nA
80211_SHARED_KEY
KEYNAME
KEYNAME
KEYNAME
KEYNAME
RegOpenKeyExA
RegCloseKey
GetKeyboardType
keybd_event
VkKeyScanA
MapVirtualKeyA
LoadKeyboardLayoutA
GetKeyboardState
GetKeyboardLayoutNameA
GetKeyboardLayoutList
GetKeyboardLayout
GetKeyState
GetKeyNameTextA
ActivateKeyboardLayout
RegQueryInfoKeyA
RegOpenKeyExA
RegOpenKeyA
RegFlushKey
RegEnumKeyExA
RegDeleteKeyA
RegCreateKeyExA
RegCreateKeyA
RegCloseKey
UntKeylogger
UntControlKey
```

As you can see, the `GetKeyboardState` and `GetKeyState` looks promising.

- **Flag: `crew{GetKeyState}`**

## Attaaaaack8

### Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

### Background

Q8. What is the Attacker's C2 domain name and port number ? (domain name:port number)

example : crew{abcd.com:8080}

Author : 0xSh3rl0ck

### Find the flag

Armed with Attaaaaack2 - 7's information, we could guess that the `runddl.exe` is a ***keylogger*** malware, as we found that it'll retrieve the status of the keyboard (Attaaaaack7).

If it's a keylogger, all the key strokes should send to a Command and Control (C2) server and exfiltrate all the key strokes.

So, we can try to find all outbound connections and see if it's any weird domains/IP addresses.

However, in volatility2, besides plugin `netscan` (Which is the output of `netstat`), other listing network connection related plugins are Windows XP and 2003 only.

I also tried to perform dynamic analysis, which running the `runddl.exe` in a sandbox environment. However, I got "Runtime error 216"...

**Then, I upload and run it in [any.run](https://any.run/) online malware sandbox:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708221440.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708221552.png)

But nothing weird...

**Finally, re-dumped the `runddl.exe` via `dumpfiles` (Not `procdump`), and uploaded to [virustotal.com](www.virustotal.com):**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|22:44:21(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86_23418 -f memdump.raw dumpfiles --dump-dir=runddl -Q 0x000000003ea44038
[...]
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.08|22:44:41(HKT)]
└> mv runddl/file.None.0x8436b6f0.img runddl/runddl.exe
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708224516.png)

**In the "Behavior" tab, we can see it's "Network Communication":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708224547.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708224603.png)

In "Memory Pattern Urls", it's an URL pattern found in the memory of the executable.

Hence, `test213.no-ip.info:1604` is the C2 server.

- **Flag: `crew{test213.no-ip.info:1604}`**

## Attaaaaack9

### Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

### Background

Q9. Seems that there is Keylogger, can you find it's path ?

example : `crew{C:\Windows\System32\abc.def}`

Author : 0xSh3rl0ck

### Find the flag

I was stucked at this challenge for a very long time.

I then decided to Google ""test213.no-ip.info" keylogger", and I found [this malware analysis blog](http://www.tekdefense.com/news/tag/malware-analysis):

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709124728.png)

So, this malware is DarkComet RAT (Remote Access Trojan).

In the blog, the bloger found that the keylogger has an offline option, so that the malware will continue to log keystroke to a **local file** that can then be picked up by the attacker as they want.

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709125155.png)

**In our volatility2 `filescan`, we can see that there's a weird `.dc` log file:**
```shell
0x000000003fcb3350      8      0 -W-r-- \Device\HarddiskVolume1\Users\0xSh3rl0ck\AppData\Roaming\dclogs\2023-02-20-2.dc
```

**We can also dump that file:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.09|12:53:01(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86_23418 -f memdump.raw dumpfiles --dump-dir=runddl -Q 0x000000003fcb3350                  
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3fcb3350   None   \Device\HarddiskVolume1\Users\0xSh3rl0ck\AppData\Roaming\dclogs\2023-02-20-2.dc
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.09|12:53:31(HKT)]
└> cat runddl/file.None.0x84273670.dat
:: Administrator: C:\Windows\System32\cmd.exe (9:04:57 PM)


:: Start menu (9:05:01 PM)
no

:: Untitled - Notepad (9:10:54 PM)
=[<-]



:: Clipboard Change : size = 27 Bytes (9:10:54 PM)
C:\Users\0xSh3rl0ck\Desktop
```

- **Flag: `crew{C:\Users\0xSh3rl0ck\AppData\Roaming\dclogs\2023-02-20-2.dc}`**

## Attaaaaack10

### Overview

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

### Background

Q10. we think that the malware uses persistence technique can you detect it ?

example : crew{Scheduled_tasks} (first letter of the first word is uppercase and the first letter of other is lowercase)

Author : 0xSh3rl0ck

### Find the flag

**In the [blog](http://www.tekdefense.com/news/tag/malware-analysis) that we've found in Attaaaaack9, the DarkComet malware has a persistence mechanism:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709213926.png)

With that said, the persistence mechanism is modifying the registry key, so that everytime when the victim logged in, it'll run `runddl32.exe`.

- **Flag: `crew{Registry_keys}`**

## Attaaaaack11

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Q11. can you find the key name and it's value ?

example : crew{CurrentVersion_ProductName}

Author : 0xSh3rl0ck

### Find the flag

**When I was searching ""test213.no-ip.info" keylogger" in Attaaaaack9, I also came across with [this Jupyter note](https://notebook.community/adricnet/dfirnotes/examples/Rekall%20demo%20-%20DarkComet%20analysis%20by%20TekDefense%20-%20Jupyter%20slides):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709130813.png)

**In there, the memory dump's registry key has something weird:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709130915.png)

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.09|13:05:47(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86_23418 -f memdump.raw printkey -K "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Volatility Foundation Volatility Framework 2.6.1
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \??\C:\Users\0xSh3rl0ck\ntuser.dat
Key name: Run (S)
Last updated: 2023-02-20 19:03:40 UTC+0000

Subkeys:

Values:
REG_SZ        MicroUpdate     : (S) C:\Users\0XSH3R~1\AppData\Local\Temp\MSDCSC\runddl32.exe
----------------------------
Registry: \REGISTRY\USER\S-1-5-20
Key name: Run (S)
Last updated: 2009-07-14 04:34:14 UTC+0000
[...]
```

The `HKCU` `Run` key has a value called `MicroUpdate`.

- **Flag: `crew{Run_MicroUpdate}`**

## Attaaaaack12

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Q12. What is the strange handle used by the malware ?

example : crew{the name of the handle}

Author : 0xSh3rl0ck

### Find the flag

**In the blog that we've found in Attaaaaack9, it has a section that finds the mutants:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709130104.png)

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Attaaaaack)-[2023.07.09|13:01:21(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86_23418 -f memdump.raw handles -p 300 -t Mutant
Volatility Foundation Volatility Framework 2.6.1
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0x843b0728    300       0x58   0x1f0001 Mutant           
0x843b0b28    300       0x5c   0x1f0001 Mutant           
0x842eb8b8    300      0x170   0x1f0001 Mutant           DC_MUTEX-KHNEW06
[...]
```

- **Flag: `crew{DC_MUTEX-KHNEW06}`**

## Attaaaaack13

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Q13. Now can you help us to know the Family of this malware ?

example : crew{Malware}

Author : 0xSh3rl0ck

### Find the flag

**Grab the SHA256 hash of the `runddl.exe` malware from [VirusTotal](https://www.virustotal.com/gui/file/9601b0c3b0991cb7ce1332a8501d79084822b3bdea1bfaac0f94b9a98be6769a/details):**

- SHA256 hash: `9601b0c3b0991cb7ce1332a8501d79084822b3bdea1bfaac0f94b9a98be6769a`

**Go to Cisco Talos Intelligence Group's [Talos File Reputation](https://www.talosintelligence.com/talos_file_reputation), and search for it's malware family via the SHA256 hash:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709132855.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709132923.png)

**According to [Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/malware-naming?view=o365-worldwide), the naming scheme is:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230709132958.png)

Hence, the `runddl.exe` malware family is `DarkKomet`.

- **Flag: `crew{DarkKomet}`**

## Conclusion

What we've learned:

1. Memory Forensic With Volatility
2. Static Malware Analysis