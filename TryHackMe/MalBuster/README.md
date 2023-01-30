# MalBuster

## Introduction

Welcome to my another writeup! In this TryHackMe [MalBuster](https://tryhackme.com/room/malbuster) room, you'll learn: Malware static analysis and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

> You are tasked to analyse unknown malware samples detected by your SOC team.
>  
> Difficulty: Medium

---

This room aims to be a practice room for Dissecting PE Headers and Static Analysis 1. In this scenario, you will act as one of the Reverse Engineers that will analyse malware samples based on the detections reported by your SOC team.

**Scenario**

You are currently working as a Malware Reverse Engineer for your organisation. Your team acts as a support for the SOC team when detections of unknown binaries occur. One of the SOC analysts triaged an alert triggered by binaries with unusual behaviour. Your task is to analyse the binaries detected by your SOC team and provide enough information to assist them in remediating the threat.

**Investigation Platforms**

The team has provided two investigation platforms, **a FLARE VM and a REMnux VM**. You may utilise the machines based on your preference.

If you prefer FLARE VM, you may start the machine attached to this task. Else, you may start the machine on the task below to start REMnux VM.

The machine will start in a split-screen view. In case the VM is not visible, use the blue Show Split View button at the top-right of the page.

You may also use the following credentials for alternative access via Remote Desktop (RDP):

- **Username**: administrator
- **Password**: letmein123!

Lastly, you may find the malware samples on `C:\Users\Administrator\Desktop\Samples`.

**WE ADVISE YOU NOT TO DOWNLOAD THE MALWARE SAMPLES TO YOUR HOST.**

## Task 2 - Challenge Questions

### Question 1 - Based on the ARCHITECTURE of the binary, is `malbuster_1` a 32-bit or a 64-bit application? (32-bit/64-bit)

**We can find the malware samples on `/home/ubuntu/Desktop/Samples`:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ ls -lah
total 1.8M
drwxrwxr-x 2 ubuntu ubuntu 4.0K Sep 21 12:11 .
drwxr-xr-x 3 ubuntu ubuntu 4.0K Sep 21 12:33 ..
-rw-rw-r-- 1 ubuntu ubuntu 152K Feb 20  2022 malbuster_1
-rw-rw-r-- 1 ubuntu ubuntu 835K Jul 24  2021 malbuster_2
-rw-r--r-- 1 ubuntu ubuntu 544K Sep 14 13:40 malbuster_3
-rw-r--r-- 1 ubuntu ubuntu 247K Sep 14 13:40 malbuster_4
```

**To view the architecture of the binary, we can use Linux command `file`:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ file malbuster_1 
malbuster_1: PE32 executable (GUI) Intel 80386, for MS Windows
```

As you can see, it's an PE32 executable, or Portable Executable 32-bit!

- Answer: `32-bit`

### Question 2 - What is the MD5 hash of `malbuster_1`?

**To view the MD5 hash of a file, we can use Linux command `md5sum`:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ md5sum malbuster_1
4348da65e4aeae6472c7f97d6dd8ad8f  malbuster_1
```

### Question 3 - Using the hash, what is the number of detections of `malbuster_1` in VirusTotal?

**Armed with previous question's answer, we can copy that MD5 hash to [VirusTotal's "Search"](https://www.virustotal.com/gui/home/search):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128135310.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128135330.png)

In here, we see **"51 security vendors and no sandboxes flagged this file as malicious"**.

- Answer: `51`

### Question 4 - Based on VirusTotal detection, what is the malware signature of `malbuster_2` according to Avira?

**Again, repeat question 2 and 3, but with executable `malbuster_2`:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ file malbuster_2
malbuster_2: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ md5sum malbuster_2
1d7ebed1baece67a31ce0a17a0320cb2  malbuster_2
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128135522.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128140109.png)

However, I found that this "Avira (no cloud)" signature is incorrect.

**After fumbling around, I was able to find the correct signature in [metadefender.opswat.com](https://metadefender.opswat.com/results/file/1d7ebed1baece67a31ce0a17a0320cb2/hash/multiscan):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128140232.png)

- Answer: `TR/AD.AgentTesla.jplkg`

### Question 5 - `malbuster_2` imports the function `_CorExeMain`. From which DLL file does it import this function?

**In VirusTotal's "Details", we can find all the imported DLLs:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128140501.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128140515.png)

- Answer: `mscoree.dll`

### Question 6 - Based on the `VS_VERSION_INFO` header, what is the original name of `malbuster_2`?

**In this question, we can use `pe-tree` to dissecting PE headers:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ pe-tree malbuster_2
```

**Then, you'll see the `VS_VERSION_INFO` header in `DOS_HEADER`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128140855.png)

- Answer: `7JYpE.exe`

### Question 7 - Using the hash of `malbuster_3`, what is its malware signature based on [abuse.ch](https://abuse.ch/)?

**Find the MD5 hash of `malbuster_3`:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ md5sum malbuster_3
47ba62ce119f28a55f90243a4dd8d324  malbuster_3
```

**In [abuse.ch](https://abuse.ch/), we can use the "[Malware Bazaar](https://bazaar.abuse.ch/browse/)" database to search through different malware:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128141233.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128141343.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128141424.png)

Found it!

- Answer: `TrickBot`

### Question 8 - Using the hash of `malbuster_4`, what is its malware signature based on [abuse.ch](https://abuse.ch/)?

**Same as previous question:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ md5sum malbuster_4
061057161259e3df7d12dccb363e56f9  malbuster_4
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128141537.png)

- Answer: `ZLoader`

### Question 9 - What is the message found in the `DOS_STUB` of `malbuster_4`?

**Again, same as question 6:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ pe-tree malbuster_4
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128141712.png)

- Answer: `!This Salfram cannot be run in DOS mode.`

### Question 10 - `malbuster_4` imports the function `ShellExecuteA`. From which DLL file does it import this function?

**Again, same as question 5:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128141936.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128141945.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MalBuster/images/Pasted%20image%2020230128141958.png)

- Answer: `shell32.dll`

### Question 11 - Using `capa`, how many anti-VM instructions were identified in `malbuster_1`?

In here, we can use `capa`:

> `capa` is an open-source tool to identify capabilities in executable files.

```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ capa malbuster_1
[...]
+------------------------+------------------------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                                   |
|------------------------+------------------------------------------------------------------------------------|
| DEFENSE EVASION        | Obfuscated Files or Information T1027                                              |
|                        | Virtualization/Sandbox Evasion::System Checks T1497.001                            |
+------------------------+------------------------------------------------------------------------------------+

+-----------------------------+-------------------------------------------------------------------------------+
| MBC Objective               | MBC Behavior                                                                  |
|-----------------------------+-------------------------------------------------------------------------------|
| ANTI-BEHAVIORAL ANALYSIS    | Virtual Machine Detection [B0009]                                             |
| COMMUNICATION               | HTTP Communication::Read Header [C0002.014]                                   |
| CRYPTOGRAPHY                | Encrypt Data::RC4 [C0027.009]                                                 |
|                             | Generate Pseudo-random Sequence [C0021]                                       |
|                             | Generate Pseudo-random Sequence::Mersenne Twister [C0021.005]                 |
|                             | Generate Pseudo-random Sequence::RC4 PRGA [C0021.004]                         |
| DATA                        | Checksum::CRC32 [C0032.001]                                                   |
|                             | Encode Data::XOR [C0026.002]                                                  |
| DEFENSE EVASION             | Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]      |
| DISCOVERY                   | Code Discovery::Enumerate PE Sections [B0046.001]                             |
+-----------------------------+-------------------------------------------------------------------------------+

+------------------------------------------------------+------------------------------------------------------+
| CAPABILITY                                           | NAMESPACE                                            |
|------------------------------------------------------+------------------------------------------------------|
| reference anti-VM strings                            | anti-analysis/anti-vm/vm-detection                   |
| check HTTP status code (2 matches)                   | communication/http/client                            |
| hash data with CRC32                                 | data-manipulation/checksum/crc32                     |
| encode data using XOR (10 matches)                   | data-manipulation/encoding/xor                       |
| encrypt data using RC4 PRGA (3 matches)              | data-manipulation/encryption/rc4                     |
| generate random numbers using the Delphi LCG         | data-manipulation/prng/lcg                           |
| generate random numbers using a Mersenne Twister     | data-manipulation/prng/mersenne                      |
| enumerate PE sections (2 matches)                    | load-code/pe                                         |
| resolve function by parsing PE exports               | load-code/pe                                         |
+------------------------------------------------------+------------------------------------------------------+
```

- Answer: `3`

### Question 12 - Using `capa`, which binary can log keystrokes?

```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ capa malbuster_3
[...]
+------------------------+------------------------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                                   |
|------------------------+------------------------------------------------------------------------------------|
| COLLECTION             | Input Capture::Keylogging T1056.001                                                |
[...]

+-----------------------------+-------------------------------------------------------------------------------+
| MBC Objective               | MBC Behavior                                                                  |
|-----------------------------+-------------------------------------------------------------------------------|
| COLLECTION                  | Keylogging::Application Hook [F0002.001]                                      |
|                             | Keylogging::Polling [F0002.002]                                               |
[...]

+------------------------------------------------------+------------------------------------------------------+
| CAPABILITY                                           | NAMESPACE                                            |
|------------------------------------------------------+------------------------------------------------------|
| log keystrokes via application hook                  | collection/keylog                                    |
| log keystrokes via polling                           | collection/keylog                                    |
[...]
```

As you can see, `malbuster_3` has a capability called log keystrokes.

- Answer: `malbuster_3`

### Question 13 - Using `capa`, what is the MITRE ID of the DISCOVERY technique used by `malbuster_4`?

```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ capa malbuster_4
[...]
+------------------------+------------------------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                                   |
|------------------------+------------------------------------------------------------------------------------|
| DISCOVERY              | File and Directory Discovery T1083                                                 |
+------------------------+------------------------------------------------------------------------------------+
[...]
```

Found it!

- Answer: `T1083`

### Question 14 - Which binary contains the string GodMode?

**In this question, we can use Linux command `strings` and `grep`:**
```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ strings malbuster_2 | grep -i 'GodMode'
get_GodMode
set_GodMode
GodMode
```

- Answer: `malbuster_2`

### Question 15 - Which binary contains the string **Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)**?

```shell
ubuntu@ip-10-10-8-127:~/Desktop/Samples$ strings malbuster_1 | grep -i 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)'
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)
```

- Answer: `malbuster_1`

# Conclusion

What we've learned:

1. Malware Static Analysis
2. Dissecting PE Headers