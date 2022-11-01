# WarZone1

## Introduction

Welcome to my another writeup! In this TryHackMe [WarZone1](https://tryhackme.com/room/warzoneone) room, you'll learn: Inspecting malicious traffics in Brim and more! Without further ado, let's dive in.

## Background

> You received an IDS/IPS alert. Time to triage the alert to determine if its a true positive.

> Difficulty: Medium

- Overall difficulty for me: Medium

You work as a Tier 1 Security Analyst L1 for a Managed Security Service Provider (MSSP). Today you're tasked with monitoring network alerts.

A few minutes into your shift, you get your first network case: **Potentially Bad Traffic** and **Malware Command and Control Activity detected**. Your race against the clock starts. Inspect the PCAP and retrieve the artifacts to confirm this alert is a true positive.

**Your tools**:

- [Brim](https://tryhackme.com/room/brim)
- [Network Miner](https://tryhackme.com/room/networkminer)
- [Wireshark](https://tryhackme.com/room/wireshark)

## Task 1 - Your shift just started and your first network alert comes in.

### Question 1 - What was the alert signature for Malware Command and Control Activity Detected?

**In the Desktop directory, we have `Zone1.pcap` packet captured file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101073823.png)

Now, we can **use Brim to inspect that**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101074148.png)

**To view all alert signatures, we can use this filter:**
```
alert.signature
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101075507.png)

- **Answer: `ET MALWARE MirrorBlast CnC Activity M3`**

### Question 2 - What is the source IP address? Enter your answer in a defanged format.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101075639.png)

- **Answer: `172[.]16[.]1[.]102`**

### Question 3 - What IP address was the destination IP in the alert? Enter your answer in a defanged format.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101075743.png)

- **Answer: `169[.]239[.]128[.]11`**

### Question 4 - Inspect the IP address in VirsusTotal. Under Relations > Passive DNS Replication, which domain has the most detections? Enter your answer in a defanged format.

**Let's go to [VirusTotal](https://www.virustotal.com/gui/home/search) and submit the attacker IP address!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101080310.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101080327.png)

- **Answer: `fidufagios[.]com`**

### Question 5 - Still in VirusTotal, under Community, what threat group is attributed to this IP address?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101080453.png)

- **Answer: `TA505`**

### Question 6 - What is the malware family?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101080545.png)

- **Answer: `MirrorBlast`**

### Question 7 - Do a search in VirusTotal for the domain from question 4. What was the majority file type listed under Communicating Files?

**Go to [VirusTotal](https://www.virustotal.com/gui/home/search) Search:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101081709.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101081727.png)

- **Answer: `Windows Installer`**

### Question 8 - Inspect the web traffic for the flagged IP address; what is the user-agent in the traffic?

**Let's go back to Brim. Here, we can use the above domain `fidufagios.com` as the filter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101082152.png)

- **Answer: `REBOL View 2.7.8.3.1`**

### Question 9 - Retrace the attack; there were multiple IP addresses associated with this attack. What were two other IP addresses? Enter the IP addressed defanged and in numerical order. (format: IPADDR,IPADDR)

**Let's use the "HTTP Requests" query to filter all the HTTP requests!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101083115.png)

**Those 2 IPs look weird!**

- **Answer: `185[.]10[.]68[.]235,192[.]36[.]27[.]92`**

### Question 10 - What were the file names of the downloaded files? Enter the answer in the order to the IP addresses from the previous question. (format: file.xyz,file.xyz)

**We already saw 1 in the previous answer:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101083322.png)

**Next, we can use the "File Activity" query:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101083449.png)

- **Answer: `filter.msi,10opd3r_load.msi`**

### Question 11 - Inspect the traffic for the first downloaded file from the previous question. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? (format: `C:\path\file.xyz`,`C:\path\file.xyz`)

**Since Brim doesn't show file's full path, I'll inspect them in WireShark:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101084104.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101084352.png)

**Let's follow the TCP stream!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101084524.png)

Found it!

- **Answer: `C:\ProgramData\001\arab.bin,C:\ProgramData\001\arab.bin`**

### Question 12 - Now do the same and inspect the traffic from the second downloaded file. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? (format: `C:\path\file.xyz`,`C:\path\file.xyz`)

**Again, view the second downloaded file in WireShark:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101084738.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101084841.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WarZone1/images/Pasted%20image%2020221101085011.png)

Found it!

- Answer: `C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb`

# Conclusion

What we've learned:

1. Inspecting Malicious Traffics in Brim
2. Searching Malicious Domain/IP in VirusTotal
3. WireShark Packet Analysis