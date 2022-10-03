# Corridor

## Introduction:

Welcome to my another writeup! In this TryHackMe [Corridor](https://tryhackme.com/room/corridor) room, you'll learn: IDOR vulnerability, or Insecure Direct Object Reference! Without further ado, let's dive in.

## Background

> Can you escape the Corridor?

> Difficulty: Easy

```
You have found yourself in a strange corridor. Can you find your way back to where you came?  

In this challenge, you will explore potential IDOR vulnerabilities. Examine the URL endpoints you access as you navigate the website and note the hexadecimal values you find (they look an awful lot like a hash, don't they?). This could help you uncover website locations you were not expected to access.
```

- Overall difficulty for me: Very easy

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# export RHOSTS=corridor.thm 
                                                                                                          
┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 62 Werkzeug httpd 2.0.3 (Python 3.10.2)
|_http-server-header: Werkzeug/2.0.3 Python/3.10.2
|_http-title: Corridor
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
```

According to `rustscan` result, we have 1 port is opened:

Ports Open        | Service
------------------|------------------------
80                | Werkzeug httpd 2.0.3

## HTTP on Port 80

**First, let's add a domain to `/etc/hosts`: (Optional, but it's a good practice to do it.)**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# export RHOSTS=10.10.114.41

┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# echo '$RHOSTS corridor.thm' | tee -a /etc/hosts
```

In the home page, it seems like it's an empty page. **But, if you look at the View-Source page (`Ctrl + U`):**

**View-Source:**
```html
    <map name="image-map">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="257,893,258,332,325,351,325,860" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="469,766,503,747,501,405,474,394" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="585,698,598,691,593,429,584,421" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="650,658,644,437,658,652,655,437" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="692,637,690,455,695,628,695,467" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="719,620,719,458,728,471,728,609" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="857,612,933,610,936,456,852,455" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="1475,857,1473,354,1537,335,1541,901" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="1324,766,1300,752,1303,401,1325,397" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="1202,695,1217,704,1222,423,1203,423" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="1154,668,1146,661,1144,442,1157,442" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="1105,628,1116,633,1113,447,1102,447" shape="poly">
        <area target="" alt="{Redacted}" title="{Redacted}" href="[{Redacted}](view-source:http://corridor.thm/{Redacted})" coords="1073,609,1081,620,1082,459,1073,463" shape="poly">
    </map>
```

**Those hexadecimal values looks like a hash!** (Hash has a fixed length.)

**Before we crack them, let's clean those up!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# curl http://corridor.thm/ -o hash.txt

┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# cat hash.txt | cut -d '"' -f 4 | awk 'length($0) == 32' > cleaned_hash.txt
```

**Next, we can use `hash-identifier` to identify what is the hash algorithm:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# hash-identifier                            
[...]
 HASH: {Redacted}

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

It's **MD5 hash**!

**Armed with this information, we can crack them via `john`, or John The Ripper:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt --format=RAW-MD5 cleaned_hash.txt
[...]
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)     
{Redacted}                (?)
```

Hmm? It's all numbers.

After I fumbling around, I found that **this is an IDOR vulnerability, or Insecure Direct Object Reference.**

> IDOR vulnerability allows you to access some pages where you shouldn't able to access.

Now, my theory is: **what if I MD5 hashed number `0`, and then use that hash to access something I shouldn't access?**

**To do so, I'll:**

- Echos out `0` **without the newline character**, and pipe it to `md5sum`, which generates a MD5 hash:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# echo -n '0' | md5sum
{Redacted}  -
```

- Go to the MD5 hashed value page:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Corridor]
└─# curl -s 'http://corridor.thm/{Redacted}' | html2text


****** flag{Redacted} ******
```

Yes!! We got the flag!

# Conclusion

What we've learned:

1. Hash cracking
2. IDOR vulnerability (Insecure Direct Object Reference)