# PrintNightmare, thrice!

## Introduction

Welcome to my another writeup! In this TryHackMe [PrintNightmare, thrice!](https://tryhackme.com/room/printnightmarec3kj) room, you'll learn: PrintNightmare forensics via WireShark, Brim, Process Monitor and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

> The nightmare continues.. Search the artifacts on the endpoint, again, to determine if the employee used any of the Windows Printer Spooler vulnerabilities to elevate their privileges.

> Difficulty: Medium

**Scenario**: After discovering the PrintNightmare attack the security team pushed an emergency patch to all the endpoints. The PrintNightmare exploit used previously no longer works. All is well. Unfortunately, the same 2 employees discovered yet another exploit that can possibly work on a fully patched endpoint to elevate their privileges.

Task: Inspect the artifacts on the endpoint to detect the PrintNightmare exploit used.

## Task 1 - Detection

### Question 1 - What remote address did the employee navigate to?

**In this Desktop, we can see there is a pcap (Packet Capture) file and a Process Monitor log file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109030758.png)

**We can use Brim for better view:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109030915.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109031427.png)

**In the `Windows Networking Activity` query, we can there are some weird SMB connection:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109031657.png)

**Looks like the `20.188.56.147` is the attacker!**

- **Answer: `20.188.56.147`**

### Question 2 - Per the PCAP, which user returns a STATUS_LOGON_FAILURE error?

**To solve this, I'll open pcap file via WireShark:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109032005.png)

**Since `STATUS_LOGON_FAILURE` is a SMB login failed error, we can filter SMB connections:**
```
smb2.nt_status == 0xc000006d
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109034149.png)

Let's follow the **TCP stream**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109034217.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109034238.png)

That looks like the username!

- Answer: `THM-PRINTNIGHT0\rjones`

### Question 3 - Which user successfully connects to an SMB share?

**Again, let's filter `STATUS_SUCCESS`!**
```
smb2.nt_status == 0x00000000
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109034533.png)

**In the first `Session Setup Response`, we can see there is a `Session Id` header, which contains the account name, domain, host:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109035541.png)

- Answer: `THM-PRINTNIGHT0/gentilguest`

### Question 4 - What is the first remote SMB share the endpoint connected to? What was the first filename? What was the second? (format: answer,answer,answer)

**Now, back to Brim, we can use `_path=~smb* OR _path=dce_rpc | sort ts` filter to find the first share that `gentilguest` connected to:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109035940.png)

**First remote SMB share: `\\printnightmare.gentilkiwi.com\IPC$`**

**Then, we see `\PIPE\srvsvc` and `\pipe\spoolss` are the first and second filename:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109040711.png)

- Answer: `\\printnightmare.gentilkiwi.com\IPC$,srvsvc,spoolss`

### Question 5 - From which remote SMB share was malicious DLL obtained? What was the path to the remote folder for the first DLL? How about the second? (format: answer,answer,answer)

**In here, we can use this filter:**
```
_path=~smb* OR _path=dce_rpc AND name=*.dll | sort ts
```

**This filter will find all the `.dll` in SMB path:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109041136.png)

**We can see that the `mimispool.dll` looks very sussy, it sounds like mimikatz.**

- Answer: `\\printnightmare.gentilkiwi.com\print$,x64\3\mimispool.dll,W32X86\3\mimispool.dll`

### Question 6 - What was the first location the malicious DLL was downloaded to on the endpoint? What was the second?

**Now, we can use the FullEventLogView to solve this:**

**Go to "Advanced Options" to set the event days upto 999 days:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109043910.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109043958.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109044010.png)

**In here, we can use the `Find` (`Ctrl + F`) to find the `mimispool.dll`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109044031.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109044910.png)

- Answer: `C:\Windows\System32\spool\drivers\x64\3,C:\Windows\System32\spool\drivers\W32X86\3`

### Question 7 - What is the folder that has the name of the remote printer server the user connected to? (provide the full folder path)

**After I fumbling around, I found that there is a weird HKLM register:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109050146.png)

**Since we found all the malicious DLLs are in `C:\Windows\System32\spool\`, let's explore that directory:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109050334.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109050356.png)

Found it!

- **Answer: `C:\Windows\System32\spool\SERVERS\printnightmare.gentilkiwi.com`**

### Question 8 - What is the name of the printer the DLL added?

**While I was finding the full path of the malicious DLLs, I also found this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109050719.png)

This is a printer name!

- **Answer: `Kiwi Legit Printer`**

### Question 9 - What was the process ID for the elevated command prompt? What was its parent process? (format: answer,answer)

**In this question, we can use ProcMon (Process Monitor) to find the elevated command prompt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109051251.png)

**To find the command prompt, we can use the "Filter" (`Ctrl + L`):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109051537.png)

**Let's filter `cmd.exe`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109051650.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109051711.png)

**As you can see, all of the `cmd.exe` process PID is `5408`. Let's dig deeper to this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109051919.png)

**It's parent PID is `2640`.**

Let's filter that PID!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109052015.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109052042.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109052058.png)

It's the `spoolsv.exe`!

- **Answer: `5408,spoolsv.exe`**

### Question 10 - What command did the user perform to elevate privileges?

**Since we know `5408` is the `cmd.exe` process PID, we can throw it to FullEventLogView!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PrintNightmare-thrice/images/Pasted%20image%2020221109052525.png)

Found it!

- Answer: `net  localgroup administrators rjones /add`

# Conclusion

What we've learned:

1. PrintNightmare Forensics via WireShark, Brim, Process Monitor