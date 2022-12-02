# Warzone 2

## Introduction

Welcome to my another writeup! In this TryHackMe [Warzone 2](https://tryhackme.com/room/warzonetwo) room, you'll learn: Inspecting network traffics via Brim and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

> You received another IDS/IPS alert. Time to triage the alert to determine if its a true positive.

---

You work as a Tier 1 Security Analyst L1 for a Managed Security Service Provider (MSSP). Again, you're tasked with monitoring network alerts.

An alert triggered: **Misc activity**, **A Network Trojan Was Detected**, and **Potential Corporate Privacy Violation**.

The case was assigned to you. Inspect the PCAP and retrieve the artifacts to confirm this alert is a true positive.

Your tools:

- [Brim](https://tryhackme.com/room/brim)
- [Network Miner](https://tryhackme.com/room/networkminer)
- [Wireshark](https://tryhackme.com/room/wireshark)

## Task 1 - Another day, another alert.

### Question 1 - What was the alert signature for A Network Trojan was Detected?

**In here, we can use Brim to inspect the PCAP file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202051257.png)

**Now, we can query a filter to extract the alert signature:**
```
event_type=="alert" | count() by alert.category,alert.signature
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202051825.png)

- **Answer: `ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2`**

### Question 2 - What was the alert signature for Potential Corporate Privacy Violation?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202051910.png)

- Answer: `ET POLICY PE EXE or DLL Windows file download HTTP`

### Question 3 - What was the IP to trigger either alert? Enter your answer in a defanged format.

**In here, we can just filter the `event_type` to `alert`:** 
```
event_type=="alert"
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202052517.png)

- **Answer: `185[.]118[.]164[.]8`**

### Question 4 - Provide the full URI for the malicious downloaded file. In your answer, defang the URI.

**Armed with the attacker IP address, we can use that as the filter query:**
```
_path=="http" | id.resp_h==185.118.164.8
```

- `_path="http"` means we only need HTTP requests.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202052949.png)

- **Answer: `awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab`**

### Question 5 - What is the name of the payload within the cab file?

Now, we can **find the hash value of that file**. To do so, I'll use the `File Activity` query filter:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202053248.png)

**Then, copy and paste it to [VirusTotal](https://www.virustotal.com/gui/home/search):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202053319.png)

**In the `Details` session, we can view the details of this malware:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202053333.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202053418.png)

- Answer: `draw.dll`

### Question 6 - What is the user-agent associated with this network traffic?

**Again, we can use the HTTP request filter query, and only find the `user_agent` column:**
```
_path=="http" | id.resp_h==185.118.164.8 | cut user_agent
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202053937.png)

- **Answer: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)`**

### Question 7 - What other domains do you see in the network traffic that are labelled as malicious by VirusTotal? Enter the domains defanged and in alphabetical order. (format: domain[.]zzz,domain[.]zzz)

**While I was finding alert signatures in question 1 and 2, I found a category called `Misc activity`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202054635.png)

**Let's find anythings that's related to `Misc activity`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202054832.png)

**Hmm... Let's filter HTTP requests that's matched with that source IP address!**
```
_path=="http" id.resp_h==176.119.156.128 | cut host,uri
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202055058.png)

Hmm... Those 2 domains looks sussy.

- **Answer: `a-zcorner[.]com,knockoutlights[.]com`**

### Question 8 - There are IP addresses flagged as Not Suspicious Traffic. What are the IP addresses? Enter your answer in numerical order and defanged. (format: IPADDR,IPADDR)

**In Brim, there is a query filter called `Suricata Alerts by Source and Destination`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202055330.png)

- **Answer: `64[.]225[.]65[.]166,142[.]93[.]211[.]176`**

### Question 9 - For the first IP address flagged as Not Suspicious Traffic. According to VirusTotal, there are several domains associated with this one IP address that was flagged as malicious. What were the domains you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format. Enter your answer in alphabetical order, in a defanged format. format: (domain[.]zzz,domain[.]zzz,etc)

**Now, we can use the first IP address as the filter:**
```
_path=="dns" 64.225.65.166 | cut query | uniq
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202060355.png)

Found 3 unique DNS queries.

- **Answer: `ulcertification[.]xyz,tocsicambar[.]xyz,safebanktest[.]top`**

### Question 10 - Now for the second IP marked as Not Suspicious Traffic. What was the domain you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format. (format: domain[.]zzz)

**Same as the previous question, we can use the second IP address as the filter:**
```
_path=="dns" 142.93.211.176 | cut query
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Warzone2/images/Pasted%20image%2020221202060815.png)

- **Answer: `2partscow[.]top`**

# Conclusion

What we've learned:

1. Inspecting Network Traffics via Brim
2. Monitoring Network Alerts
3. Searching Malware/IP Details via VirusTotal