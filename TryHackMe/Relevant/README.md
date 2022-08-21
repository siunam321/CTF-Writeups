# Relevant Penetration Testing Report

## Introduction

The Relevant penetration testing peport contains all efforts that were conducted in order to perform a penetration test on the client's virtual environment network.

## Objective

The objective of this assessment is to perform an internal penetration test against the client's virtual environment network.
I am tasked with following methodical approach in obtaining access to the objective goals. The main objective is to report as many vulnerabilities as the provided virtual environment possible. My goal is to obtain the highest possible privilege level (administrator/root) on the virtual environment.

## Scope of Work

- Any tools or techniques are permitted in this engagement, however the client ask that I should attempt manual exploitation first
- Locate and note all vulnerabilities found
- Submit the flags discovered to the dashboard
- Only the IP address assigned to the client machine is in scope
- Find and report ALL vulnerabilities

# High-Level Summary

I was tasked with performing an internal penetration test towards the virtual environment that the client has provided.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate the client's virtual environment.
My overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to the client.

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on the client's virtual environment.
When performing the attacks, I was able to gain access to the client's provided virtual environment machine, primarily due to outdated patches and poor security configurations.
During the testing, I had administrative level access to the system.
All system was successfully exploited and access granted.
These systems as well as a brief description on how access was obtained are listed below:

- 10.10.175.250 (Relevant) - Saved file insecurely, a service that should not be publicly available to anyone, misconfiguration in SMB, outdated version of SMB.

## Recommendations

I recommend patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodologies

I utilized a widely adopted approach to performing penetration testing that is effective in testing how well the provided virtual environment are secured.
Below is a breakout of how I was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, I was tasked with exploiting the client's provided virtual environment.
The specific IP addresse was: `10.10.175.250`.

## Penetration

The penetration testing portions of the assessment focus heavily on finding all vulnerabilities in the client's provided virtual environment machine.
During this penetration test, I was able to successfully gain complete control on the client's provided virtual environment machine.

### System IP: 10.10.175.250

#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.175.250     | **TCP**: 80,135,139,445,3389,49663

**Rustscan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a5.png)

##### SMB on Port 139, 445

In SMB, we can use `smbclient` to enumerate SMB shares:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a3.png)

Found `nt4wrksv` share, and it has `passwords.txt` file.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a6.png)

Found 2 users and their passwords:

- Username:bob
- Password:!P@$$W0rD!123

- Username:bill
- Password:Juw4nnaM4n420696969!$$$

**Vulnerability Explanation:**

SMB share `nt4wrksv` allows anyone to login, and critical file is saved insecurely.

**Vulnerability Fix:**

Configure SMB share `nt4wrksv` to be not available to guest, save critical file securely, such as don't save in an publicly available environment, encrypt the file if possible.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 9.8**
- Impact Subscore: 5.9
- Exploitability Subscore: 3.9
2. **CVSS Temporal Score: 9.4**
- CVSS Environmental Score: 9.4
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 9.4**

***Critical***

We also see that the client's virtual environment is vulnerable to `EternalBlue` or `ms17-010`:

**Nmap Script Scan Result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a7.png)

#### First Initial Foothold

**Explotating `EternalBlue` or `ms17-010`:**

We can use a python exploit from https://github.com/3ndG4me/AutoBlue-MS17-010 to gain an initial foothold to the client's virtual environment.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a8.png)

**Executing the python exploit using the following options:**

- `-port` to specify the SMB port
- The credential to connect. In this case I will use the `Bob` user’s credential

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a10.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a11.png)

As we can see, we are `nt authority\system`, which is have the administrator privilege in Windows. Since I am already have the administrator privilege in Windows, there is no need to do privilege escalation.

**Vulnerability Explanation:**

The Microsoft Server Message Block 1.0 (SMBv1) server handles certain requests. An attacker who successfully exploited this vulnerability could craft a special packet, which could lead to information disclosure from the server.

To exploit the vulnerability, in most situations, an unauthenticated attacker could send a specially crafted packet to a targeted SMBv1 server.

**Vulnerability Fix:**

Disable SMBv1.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 8.8**
- Impact Subscore: 5.9
- Exploitability Subscore: 2.8
2. **CVSS Temporal Score: 8.4**
- CVSS Environmental Score: 8.4
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 8.4**

***Critical***

#### Second Initial Foothold

In HTTP on port 49663, we can find that the SMB share named `nt4wrksv` is open in the HTTP port on 49663.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a12.png)

Which could allow attacker to upload malicious file on the SMB share, and gain an initial foothold.

First, I will check the `nt4wrksv` SMB share is allow upload any file or not:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a14.png)

If the SMB share allows anyone to upload any file, attackers can gain an initial foothold on the target machine.

Next, I will first generate a `ASPX` reverse shell, setup a `nc` listener, and upload it to the `nt4wrksv` SMB share:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a16.png)

Finally, trigger the reverse shell via `curl`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a18.png)

**Vulnerability Explanation:**

The SMB share named `nt4wrksv` is open to HTTP on port 49663, and the SMB share allows anyone to upload any files. Hence, an attacker could upload a malicious file to the SMB share and gain an initial foothold on the target machine via triggering the reverse shell on port 49663.

**Vulnerability Fix:**

HTTP on port 49663 should be visible internally, not publicly. Also, SMB share `nt4wrksv` should disallow guest to login, upload any files. If possible, please disable SMB share `nt4wrksv` to HTTP on port 49663, so no one can view any contents via port 49663.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 9.8**
- Impact Subscore: 5.9
- Exploitability Subscore: 3.9
2. **CVSS Temporal Score: 9.6**
- CVSS Environmental Score: 9.6
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 9.6**

***Critical***

**user.txt Contents**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a19.png)

#### Privilege Escalation

**System info:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a20.png)

By viewing the system info, we can see that the client's virtual environment machine is using `Windows Server 2016 Standard Evaluation 10.0.14393 N/A Build 14393`. 

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a21.png)

Since `iis apppool\defaultapppool` is a service account, it has privilege called `SeImpersonatePrivilege`, which could be abused for privilege escalation to `NT AUTHORITY\SYSTEM`, who has administrator privilege.

**PrintSpoofer:**

Armed with the above information, we can use [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) to escalate our privilege to `SYSTEM`.

First, upload [`PrintSpoofer64.exe`](https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0) to the target machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a22.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a23.png)

Then, run the exploit binary:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a24.png)

Now I am `nt authority\system`, who has administrator privilege.

**Vulnerability Explanation:**

If a user has `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`, attackers could leverage those privilege to escalate their privilege to administrator level. They allow you to run code or even create a new process in the context of another user. To do so, you can call `CreateProcessWithToken()` if you have `SeImpersonatePrivilege` or `CreateProcessAsUser()` if you have `SeAssignPrimaryTokenPrivilege`.

**Vulnerability Fix:**

You can specify that you don’t want to be impersonated or, at least, that you don’t want the server to run code in your security context. For more details about how to mitigate this vulnerability, a [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/#how-to-prevent-named-pipe-impersonation) has a complete walkthrough about this vulnerability.

**Severity:**

*The calculation is done via CVSS Version 3.1 Calculator(https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator):*

1. **CVSS Base Score: 7.8**
- Impact Subscore: 5.9
- Exploitability Subscore: 1.8
2. **CVSS Temporal Score: 7.6**
- CVSS Environmental Score: 7.6
- Modified Impact Subscore: 5.9
3. **Overall CVSS Score: 7.6**

***High***

**root.txt Contents:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Relevant/images/a25.png)

## Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

## House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the client's provided virtual environment was completed, I removed all user accounts and passwords as well as all malicious scripts installed on the system.
The client should not have to remove any user accounts or services from the system.