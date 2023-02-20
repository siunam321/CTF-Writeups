# The Mindful Zone

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

- 10 solves / 329 points

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230218220934.png)

The translated Latin is: "Who watches the watchers?"

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/Web/The-Mindful-Zone/handoout.zip):**
```shell
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/The-Mindful-Zone)-[2023.02.18|22:05:40(HKT)]
└> file handout.zip              
handout.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/The-Mindful-Zone)-[2023.02.18|22:05:41(HKT)]
└> unzip handout.zip 
Archive:  handout.zip
   creating: the-mindful-zone/
  inflating: the-mindful-zone/Dockerfile  
  inflating: the-mindful-zone/entrypoint.sh  
 extracting: the-mindful-zone/flag.txt  
  inflating: the-mindful-zone/readflag  
  inflating: the-mindful-zone/readflag.c
```

**Let's read the `Dockerfile` first:**
```bash
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/The-Mindful-Zone/the-mindful-zone)-[2023.02.18|22:05:53(HKT)]
└> cat Dockerfile 
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get -y --no-install-recommends install software-properties-common mysql-server apache2 php libapache2-mod-php php-mysql && \
    add-apt-repository ppa:iconnor/zoneminder-1.36 && \
    service mysql start && \
    apt-get install -y --no-install-recommends zoneminder=1.36.32-bionic1 && \
    apt-get clean

RUN sed -i 's/\[mysqld\]/[mysqld\]\nsql_mode = NO_ENGINE_SUBSTITUTION\n/' /etc/mysql/mysql.conf.d/mysqld.cnf

COPY flag.txt /flag.txt
COPY entrypoint.sh /entrypoint.sh
COPY readflag /readflag
RUN chmod 700 /flag.txt && chmod +sx /readflag

CMD bash -C '/entrypoint.sh';'bash'

# docker build -t mind .
# docker run --rm -it -p 8080:80 mind
# visit 127.0.0.1:8080/zm/
```

As you can see, it's using MySQL as the DBMS (Database Management System), Apache as the web server, PHP as the server language.

**But most importantly, it also installed `zoneminder` version 1.36.32-bionic1.**

Moreover, there is a `readflag` executable to read the flag.

That being said, **our final goal should be gain Remote Code Execution (RCE), and get a shell on the challenge's machine.**

**entrypoint.sh:**
```shell
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/The-Mindful-Zone/the-mindful-zone)-[2023.02.18|22:05:54(HKT)]
└> cat entrypoint.sh 
#!/bin/bash

service mysql start
service apache2 start

# admin pw = U6jJxLzEreSV1CjShdM4, different on real server
mysql -e "UPDATE zm.Config SET Value = '8kjQJQg7GB4vfu8yFE7WjzWfhHYMXYC3' WHERE Config.Name = 'ZM_AUTH_HASH_SECRET';"
mysql -e "UPDATE zm.Config SET Value = '1' WHERE Config.Name = 'ZM_OPT_USE_AUTH';"
mysql -e "UPDATE zm.Users SET Password = '\$2y\$10\$/S1zBzOnz8oUDQFlQvUqteZbs8EDErR8Y3mWZFeM03ZZUCeWVQdJm' WHERE Users.Username = 'admin';"

chmod 740 /etc/zm/zm.conf
chown root:www-data /etc/zm/zm.conf
chown -R www-data:www-data /usr/share/zoneminder/

a2enmod cgi
a2enmod rewrite
a2enconf zoneminder

service apache2 reload
service zoneminder start
```

In here, it runs a MySQL command to UPDATE `zoneminder`'s config, like admin password.

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230218221454.png)

A default Apache page. Nothing weird.

**Since we found a programe called `zoneminder`, let's google it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230218221556.png)

> ZoneMinder is a free, open-source software application for monitoring via closed-circuit television - developed to run under Linux and FreeBSD and released under the terms of the GNU General Public License. Users control ZoneMinder via a web-based interface. [Wikipedia](https://en.wikipedia.org/wiki/ZoneMinder)

**So, basically it's a web-based interface to monitor CCTVs or security cameras.**

**We also found it's version in `Dockerfile`, let's use `searchsploit` to search public exploits:**
```shell
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/The-Mindful-Zone)-[2023.02.18|22:19:12(HKT)]
└> searchsploit zoneminder
------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ZoneMinder 1.24.3 - Remote File Inclusion                                                                                      | php/webapps/17593.txt
Zoneminder 1.29/1.30 - Cross-Site Scripting / SQL Injection / Session Fixation / Cross-Site Request Forgery                    | php/webapps/41239.txt
ZoneMinder 1.32.3 - Cross-Site Scripting                                                                                       | php/webapps/47060.txt
ZoneMinder Video Server - packageControl Command Execution (Metasploit)                                                        | unix/remote/24310.rb
------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Hmm... The challenge ones is version 1.36... So nope??

**However, when we google that specific version:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230218222030.png)

Oh! Looks like ZoneMinder < 1.36.13 is vulnerable to RCE??

**But before we exploit it, we can read [ZoneMinder's documentation](https://zoneminder.readthedocs.io/en/stable/installationguide/ubuntu.html#make-sure-zoneminder-and-apis-work-with-security).**

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230218222456.png)

**In here, we can check this challenge's config is ok or not:**
```shell
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/The-Mindful-Zone)-[2023.02.18|22:25:12(HKT)]
└> curl http://the-mindful-zone.chal.perfect.blue/zm/api/host/getVersion.json
{"success":false,"data":{"name":"Not Authenticated","message":"Not Authenticated","url":"\/zm\/api\/host\/getVersion.json","exception":{"class":"UnauthorizedException","code":401,"message":"Not Authenticated"}}}
```

As you can see, it returns "401 Not Authenticated".

Also, we now know ZoneMinder's directory: `/zm`.

Now, let's go back to the RCE.

**In [this](https://github.com/advisories/GHSA-xr7v-8xc4-62vc) GitHub Advisory, it said:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230218222837.png)

So the vulnerable part is the invalid language?

**In that GitHub Advisory, there's also a [link](https://krastanoel.com/cve/2022-29806) that points to the people who discover it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230218223230.png)

> A Path Traversal vulnerability in debug log file and default language option in ZoneMinder version before 1.36.13 and 1.37.11 allows attackers to write and execute arbitrary code to achieve remote command execution.

***However, it's doesn't affect version 1.36.32-bionic1...***

Then, I decided to look at the source code of ZoneMinder:

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230219145402.png)

Hmm... Let's look at the `auth.php`, maybe we can find authentication bypass?

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230219181553.png)

In line 377 - 396, we see there is a parameter called `token`. This token wlll then be used in function `validateToken()`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230219181704.png)

This function will decode JWT (JSON Web Token) with algorithm HS256 (HMAC + SHA-256).

When I provide that parameter, something weird happened:

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230219181758.png)

As you can see, it'll redirect me to ZoneMinder's console page. However, we couldn't do anything in here, as we're not authenticated...

Then, I kept trying to find insecure code patterns, but still no luck...