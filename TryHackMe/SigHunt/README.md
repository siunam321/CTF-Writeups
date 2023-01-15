# SigHunt

## Introduction

Welcome to my another writeup! In this TryHackMe [SigHunt](https://tryhackme.com/room/unbakedpie) room, you'll learn: Writing Sigma rules and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

> You are tasked to create detection rules based on a new threat intel.
>  
> Difficulty: Medium

---

This room aims to be a supplementary room for Sigma rule creation. In this scenario, you will act as one of the Detection Engineers that will craft Sigma Rules based on the Indicators of Compromise (IOCs) collected by your Incident Responders.

**Prerequisites**

This room requires basic knowledge of detection engineering and Sigma rule creation. We recommend going through the following rooms before attempting this challenge.

- Intro to Detection Engineering (coming soon)
- [Sigma](https://tryhackme.com/room/sigma)

**SigHunt Interface**

Before we proceed, deploy the attached machine in this task since it may take up to 3-5 minutes to initialize the services.

Then, use this link to access the interface - [http://MACHINE_IP](http://MACHINE_IP)

**How to use the SigHunt Interface:**

- **Run** - Submit your Sigma rule and see if it detects the malicious IOC.
- **Text Editor** - Write your Sigma rule in this section.
- **Create Rule** - Create a Sigma rule for the malicious IOC.
- **View Log** - View the log details associated with the malicious IOC.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114144110.png)

## Task 2 - Huntme Incident

**Scenario**

You are hired as a Detection Engineer for your organization. During your first week, a ransomware incident has just concluded, and the Incident Responders of your organization have successfully mitigated the threat. With their collective effort, the Incident Response (IR) Team provided the IOCs based on their investigation. Your task is to create Sigma rules to improve the detection capabilities of your organization and prevent future incidents similar to this.

**Indicators of Compromise**

Based on the given incident report, the Incident Responders discovered the following attack chain:

- Execution of malicious HTA payload from a phishing link.
- Execution of Certutil tool to download Netcat binary.
- Netcat execution to establish a reverse shell.
- Enumeration of privilege escalation vectors through PowerUp.ps1.
- Abused service modification privileges to achieve System privileges.
- Collected sensitive data by archiving via 7-zip.
- Exfiltrated sensitive data through **cURL** binary.
- Executed ransomware with **huntme** as the file extension.

In addition, the Incident Responders provided a table of IOCs at your disposal.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114145539.png)

**Rule Creation Standards**

The Detection Engineering Team follows a standard when creating a Sigma Rule. You may refer to the guidelines below.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114145603.png)

### Question 1 - What is the Challenge #1 flag?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114145709.png)

**In here, we can modify the Sigma rule to improve the detection:**
```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 1
    Image|endswith:
      - 'mshta.exe' #Search identifiers for the detection. Refer to the required fields provided in the task. 
    ParentImage|endswith:
      - 'chrome.exe'
  condition: selection #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

This Sigma rule will search:

1. `EventID` is equal to 1
2. `Image` (Binary/executable) name is ends with `mshta.exe`
3. The `ParentImage` (Binary/executable) name is ends with `chrome.exe`

Now we can run the Sigma rule:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114151819.png)

### Question 2 - What is the Challenge #2 flag?

**Again, create a Sigma rule:**
```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 1 #Search identifiers for the detection. Refer to the required fields provided in the task. 
    Image|endswith:
      - 'certutil.exe'
    CommandLine|contains|all:
      - 'certutil'
      - '-urlcache'
      - '-split'
      - '-f'
  condition: selection #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

This Sigma rule will search:

1. `EventID` is equal to 1
2. `Image` (Binary/executable) name is ends with `certutil.exe`
3. The executed `CommandLine` contains `certutil` and `-urlcache` and `-split` and `-f`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114152102.png)

### Question 3 - What is the Challenge #3 flag?

```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection1:
    EventID:
      - 1 #Search identifiers for the detection. Refer to the required fields provided in the task. 
    Image|endswith:
      - 'nc.exe'
    CommandLine|contains|all:
      - ' -e '
  selection2:
    Hashes|contains|all:
      - 'MD5=523613A7B9DFA398CBD5EBD2DD0F4F38'
      - 'SHA256=3E59379F585EBF0BECB6B4E06D0FBBF806DE28A4BB256E837B4555F1B4245571'
      - 'IMPHASH=567531F08180AB3963B70889578118A3'
  condition: selection1 OR selection2 #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

This Sigma rule will search:

- **Selection 1:**

1. `EventID` is equal to 1
2. `Image` (Binary/executable) name is ends with `nc.exe`
3. The executed `CommandLine` contains `-e` (It has spaces)

***Or***

- **Selection 2:**

1. File `Hash` matches the given MD5, SHA256, and IMPHASH hash value

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230115125140.png)

### Question 4 - What is the Challenge #4 flag?

```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 1 #Search identifiers for the detection. Refer to the required fields provided in the task. 
    Image|endswith:
      - 'powershell.exe'
    CommandLine|contains|all:
      - 'PowerUp'
      - 'Invoke-AllChecks'
  condition: selection #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

This Sigma rule will search:

1. `EventID` is equal to 1
2. `Image` (Binary/executable) name is ends with `powershell.exe`
3. The executed `CommandLine` contains `PowerUp` and `Invoke-AllChecks`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114154545.png)

### Question 5 - What is the Challenge #5 flag?

```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 1 #Search identifiers for the detection. Refer to the required fields provided in the task. 
    Image|endswith:
      - 'sc.exe'
    CommandLine|contains|all:
      - ' config '
      - ' binPath= '
  condition: selection #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

This Sigma rule will search:

1. `EventID` is equal to 1
2. `Image` (Binary/executable) name is ends with `sc.exe`
3. The executed `CommandLine` contains `config` and `binPath=` (They have spaces)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114160635.png)

### Question 6 - What is the Challenge #6 flag?

```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 1 #Search identifiers for the detection. Refer to the required fields provided in the task. 
    Image|endswith:
      - 'reg.exe'
    CommandLine|contains|all:
      - ' add '
      - 'RunOnce'
  condition: selection #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

This Sigma rule will search:

1. `EventID` is equal to 1
2. `Image` (Binary/executable) name is ends with `reg.exe`
3. The executed `CommandLine` contains `add` and `RunOnce` (it has spaces)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114160505.png)

### Question 7 -What is the Challenge #7 flag?

```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 1 #Search identifiers for the detection. Refer to the required fields provided in the task. 
    Image|endswith:
      - '7z.exe'
    CommandLine|contains|all:
      - ' a '
      - ' -p'
  condition: selection #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

This Sigma rule will search:

1. `EventID` is equal to 1
2. `Image` (Binary/executable) name is ends with `7z.exe`
3. The executed `CommandLine` contains `a` and `-p` (They have spaces)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114160001.png)

### Question 8 -What is the Challenge #8 flag?

```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 1 #Search identifiers for the detection. Refer to the required fields provided in the task. 
    Image|endswith:
      - 'curl.exe'
    CommandLine|contains|all:
      - ' -d '
  condition: selection #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

This Sigma rule will search:

1. `EventID` is equal to 1
2. `Image` (Binary/executable) name is ends with `curl.exe`
3. The executed `CommandLine` contains `-d` (it has spaces)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114160145.png)

### Question 9 -What is the Challenge #9 flag?

```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 11 #Search identifiers for the detection. Refer to the required fields provided in the task. 
    TargetFilename|contains|all:
      - '*.huntme'
  condition: selection #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SigHunt/images/Pasted%20image%2020230114160354.png)

This Sigma rule will search:

1. `EventID` is equal to 11
2. The `TargetFilename` contains `.huntme`

# Conclusion

What we've learned:

1. Writing Sigma Rules To Detect Malicious Activities