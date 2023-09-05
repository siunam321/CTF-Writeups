# static file server

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 594 solves / 100 points
- Author: joseph
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Here's a simple Python app that lets you view some files on the server.

Author: joseph

[https://web-static-file-server-9af22c2b5640.2023.ductf.dev](https://web-static-file-server-9af22c2b5640.2023.ductf.dev)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903191218.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903191259.png)

**In here, we can view 2 static files: `/files/ductf.png` and `/files/not_the_flag.txt`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903191412.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903191417.png)

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/static-file-server/static-file-server.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/static-file-server)-[2023.09.03|19:14:54(HKT)]
└> file static-file-server.zip 
static-file-server.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/static-file-server)-[2023.09.03|19:14:55(HKT)]
└> unzip static-file-server.zip 
Archive:  static-file-server.zip
   creating: static-file-server/
  inflating: static-file-server/app.py  
  inflating: static-file-server/Dockerfile  
   creating: static-file-server/files/
  inflating: static-file-server/files/not_the_flag.txt  
  inflating: static-file-server/files/ductf.png  
```

**`Dockerfile`:**
```bash
FROM python:3.10

WORKDIR /app
COPY app.py .
COPY flag.txt /flag.txt
COPY files/ files/

RUN pip3 install aiohttp

RUN /usr/sbin/useradd --no-create-home -u 1000 ctf
USER ctf

CMD ["python3", "app.py"]
```

This Docker builder script file will copy the `flag.txt` to `/`.

**`app.py`:**
```python
from aiohttp import web

async def index(request):
    return web.Response(body='''
        <header><h1>static file server</h1></header>
        Here are some files:
        <ul>
            <li><img src="/files/ductf.png"></img></li>
            <li><a href="/files/not_the_flag.txt">not the flag</a></li>
        </ul>
    ''', content_type='text/html', status=200)

app = web.Application()
app.add_routes([
    web.get('/', index),

    # this is handled by https://github.com/aio-libs/aiohttp/blob/v3.8.5/aiohttp/web_urldispatcher.py#L654-L690
    web.static('/files', './files', follow_symlinks=True)
])
web.run_app(app)
```

In this web application, it's using Python's [aiohttp](https://docs.aiohttp.org/en/stable/) asynchronous HTTP Client/Server.

In the `/files` static route, the `follow_symlinks` is set to `True`.

According to [aiohttp documentation](https://docs.aiohttp.org/en/stable/web_reference.html) and [the source code](https://github.com/aio-libs/aiohttp/blob/v3.8.5/aiohttp/web_urldispatcher.py#L654-L690), **it doesn't prevent path traversal**.

## Exploitation

**Armed with above information, we can use the `/files` route to perform path traversal, so that we can get the flag file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903192402.png)

- **Flag: `DUCTF{../../../p4th/tr4v3rsal/as/a/s3rv1c3}`**

## Conclusion

What we've learned:

1. Exploiting path traversal vulnerability