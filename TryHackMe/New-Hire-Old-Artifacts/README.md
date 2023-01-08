# New Hire Old Artifacts

## Introduction

Welcome to my another writeup! In this TryHackMe [New Hire Old Artifacts](https://tryhackme.com/room/newhireoldartifacts) room, you'll learn: Investigate attack via Splunk and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

> Investigate the intrusion attack using Splunk.
>  
> Difficulty: Medium

---

A newly acquired customer (Widget LLC) was recently onboarded with the managed Splunk service. The sensor is live, and all the endpoint events are now visible on TryNotHackMe's end. Widget LLC has some concerns with the endpoints in the Finance Dept, especially an endpoint for a recently hired Financial Analyst. The concern is that there was a period (December 2021) when the endpoint security product was turned off, but an official investigation was never conducted.

Your manager has tasked you to sift through the events of Widget LLC's Splunk instance to see if there is anything that the customer needs to be alerted on.

Happy Hunting!

## Question 1 - A Web Browser Password Viewer executed on the infected machine. What is the name of the binary? Enter the full path.

We can go to the `http://MACHINE_IP:8000` to use Splunk:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106233558.png)

Then click "Search & Reporting" to use the search function of Splunk:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106233619.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106233707.png)

Now, we can go to the search bar to search everything (`*`), and search all time events:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106233836.png)

According to the question, we need to find a binary that infecting the machine.

**To do so, I'll use a filter query:**
```
Image="*.exe" | dedup Image | table Image
```

This will only show table `Image`, distinct values, and anything value that contains `.exe`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106234706.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106234728.png)

The `C:\Users\FINANC~1\AppData\Local\Temp\11111.exe` seems weird.

- **Answer: `C:\Users\FINANC~1\AppData\Local\Temp\11111.exe`**

## Question 2 - What is listed as the company name?

Let's view that event:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106234921.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106235030.png)

Hmm... Nothing stands out.

**Let's search for it's company name:**
```
Image="C:\\Users\\FINANC~1\\AppData\\Local\\Temp\\11111.exe" | table Company | dedup Company
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230106235644.png)

Found it!

- **Answer: `NirSoft`**

## Question 3 - Another suspicious binary running from the same folder was executed on the workstation. What was the name of the binary? What is listed as its original filename? (format: file.xyz,file.xyz)

**Filter query:**
```
Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\*.exe" | table Image | dedup Image
```

> Note: According to Microsoft [documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file), `FINANC~1` is the tilde substitution convention.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107002731.png)

Found it!

Let's find the original filename of that binary:

```
Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\IonicLarge.exe" | table OriginalFileName | dedup OriginalFileName
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107002928.png)

Nice!

- **Answer: `IonicLarge.exe,PalitExplorer.exe`**

## Question 4 - The binary from the previous question made two outbound connections to a malicious IP address. What was the IP address? Enter the answer in a defang format.

**Filter query:**
```
Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\IonicLarge.exe" | table DestinationIp | dedup DestinationIp
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107003043.png)

The `2[.]56[.]59[.]42` looks sussy.

- **Answer: `2[.]56[.]59[.]42`**

## Question 5 - The same binary made some change to a registry key. What was the key path?

**Filter query:**
```
Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\IonicLarge.exe" EventType="SetValue" | table TargetObject | dedup TargetObject
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230108003400.png)

- **Answer: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`**

## Question 6 - Some processes were killed and the associated binaries were deleted. What were the names of the two binaries? (format: file.xyz,file.xyz)

**Filter query:**
```
taskkill | table ParentCommandLine | dedup ParentCommandLine
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107005030.png)

- **Answer: `WvmIOrcfsuILdX6SNwIRmGOJ.exe,phcIAmLJMAIMSa9j9MpgJo1m.exe`**

## Question 7 - The attacker ran several commands within a PowerShell session to change the behaviour of Windows Defender. What was the last command executed in the series of similar commands?

**Filter query:**
```
powershell | table CommandLine,UtcTime | dedup CommandLine
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107005404.png)

- **Answer: `powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True`**

## Question 8 - Based on the previous answer, what were the four IDs set by the attacker? Enter the answer in order of execution. (format: 1st,2nd,3rd,4th)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107005752.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107005804.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107005816.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230107005825.png)

- **Answer: `2147737394,2147737007,2147737010,2147735503`**

## Question 9 - Another malicious binary was executed on the infected workstation from another AppData location. What was the full path to the binary?

**Filter query:**
```
Image="C:\\Users\\*\\AppData\\*.exe" | table Image | dedup Image
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230108003616.png)

- **Answer: `C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe`**

## Question 10 - What were the DLLs that were loaded from the binary from the previous question? Enter the answers in alphabetical order. (format: file1.dll,file2.dll,file3.dll)

```
Image="C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\EasyCalc.exe" ImageLoaded="*.dll" | table ImageLoaded | dedup ImageLoaded
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/New-Hire-Old-Artifacts/images/Pasted%20image%2020230108003914.png)

- **Answer: `ffmpeg.dll,nw.dll,nw_elf.dll`**

# Conclusion

What we've learned:

1. Investigate Intrusion Attack Using Splunk